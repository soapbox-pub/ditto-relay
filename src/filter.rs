//! NIP-01 filters: parsed once into sorted sets, then matched against stored
//! records without decoding them.

use std::cmp::Ordering;

use serde_json::Value;

use crate::event::is_hex64;
use crate::record::{Element, EventView, tag_value};
use crate::store::MAX_INDEXED_TAG;

/// The most values one field of a filter may list. Generous enough for a
/// big follow list.
pub const MAX_VALUES: usize = 5000;

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub ids: Option<Vec<[u8; 32]>>,
    pub authors: Option<Vec<[u8; 32]>>,
    pub kinds: Option<Vec<u16>>,
    /// By letter, each with its values in [`tag_value`] form. Sorted.
    pub tags: Vec<(u8, Vec<Vec<u8>>)>,
    pub since: u32,
    pub until: u32,
    pub limit: Option<u64>,
    /// Some field can match nothing (an empty list, say), so neither can
    /// the filter.
    pub never: bool,
}

impl Filter {
    /// Parse a filter. Errors are NIP-01 machine-readable messages. Fields
    /// NIP-01 doesn't define (`search`, say) are ignored.
    pub fn parse(value: &Value) -> Result<Filter, String> {
        let Value::Object(fields) = value else {
            return Err("invalid: a filter must be an object".into());
        };
        let mut filter = Filter {
            until: u32::MAX,
            ..Filter::default()
        };

        for (name, value) in fields {
            match name.as_str() {
                "ids" => filter.ids = Some(hex_list(name, value)?),
                "authors" => filter.authors = Some(hex_list(name, value)?),
                "kinds" => {
                    // Kinds are 0-65535; any other can match nothing.
                    let kinds = list(name, value)?.iter().map(|kind| {
                        kind.as_u64()
                            .ok_or_else(|| format!("invalid: {name} must be integers"))
                    });
                    let mut kinds: Vec<u16> = kinds
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .filter_map(|k| u16::try_from(k).ok())
                        .collect();
                    kinds.sort_unstable();
                    kinds.dedup();
                    filter.kinds = Some(kinds);
                }
                "since" => filter.since = timestamp(name, value)?,
                "until" => filter.until = timestamp(name, value)?,
                "limit" => {
                    filter.limit = Some(
                        value
                            .as_u64()
                            .ok_or("invalid: limit must be a non-negative integer")?,
                    )
                }
                _ => {
                    let &[b'#', letter] = name.as_bytes() else {
                        continue;
                    };
                    if !letter.is_ascii_alphabetic() {
                        continue;
                    }
                    let values = list(name, value)?.iter().map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| format!("invalid: {name} must be strings"))
                    });
                    let mut values: Vec<Vec<u8>> = values
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .map(tag_value)
                        // Too long to be indexed, so nothing stored has it.
                        .filter(|value| value.len() <= MAX_INDEXED_TAG)
                        .collect();
                    values.sort_unstable();
                    values.dedup();
                    filter.tags.push((letter, values));
                }
            }
        }

        filter.tags.sort_unstable_by_key(|(letter, _)| *letter);
        filter.never = filter.ids.as_ref().is_some_and(Vec::is_empty)
            || filter.authors.as_ref().is_some_and(Vec::is_empty)
            || filter.kinds.as_ref().is_some_and(Vec::is_empty)
            || filter.tags.iter().any(|(_, values)| values.is_empty())
            || filter.since > filter.until;
        Ok(filter)
    }

    pub fn matches(&self, event: &EventView) -> bool {
        if self.never || !self.matches_time(event.created_at()) {
            return false;
        }
        if self
            .ids
            .as_ref()
            .is_some_and(|ids| ids.binary_search(event.id()).is_err())
        {
            return false;
        }
        if self
            .authors
            .as_ref()
            .is_some_and(|authors| authors.binary_search(event.pubkey()).is_err())
        {
            return false;
        }
        if self
            .kinds
            .as_ref()
            .is_some_and(|kinds| kinds.binary_search(&event.kind()).is_err())
        {
            return false;
        }
        self.tags.iter().all(|(letter, values)| {
            event.indexed_tags().any(|(name, value)| {
                name == *letter && values.binary_search_by(|v| compare(v, &value)).is_ok()
            })
        })
    }

    pub fn matches_time(&self, created_at: u32) -> bool {
        self.since <= created_at && created_at <= self.until
    }
}

/// Compare an encoded tag value with an element, as if it were encoded too.
fn compare(encoded: &[u8], element: &Element) -> Ordering {
    let (flag, bytes) = match element {
        Element::Hex(bytes) => (1, &bytes[..]),
        Element::Text(text) => (0, text.as_bytes()),
    };
    match encoded.split_first() {
        None => Ordering::Less,
        Some((f, rest)) => f.cmp(&flag).then_with(|| rest.cmp(bytes)),
    }
}

fn list<'a>(name: &str, value: &'a Value) -> Result<&'a Vec<Value>, String> {
    let list = value
        .as_array()
        .ok_or_else(|| format!("invalid: {name} must be an array"))?;
    if list.len() > MAX_VALUES {
        return Err(format!(
            "invalid: {name} lists more than {MAX_VALUES} values"
        ));
    }
    Ok(list)
}

fn hex_list(name: &str, value: &Value) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for value in list(name, value)? {
        let hex = value
            .as_str()
            .filter(|hex| is_hex64(hex))
            .ok_or_else(|| format!("invalid: {name} must be 64-character lowercase hex"))?;
        let mut bytes = [0; 32];
        hex::decode_to_slice(hex, &mut bytes).expect("checked hex");
        out.push(bytes);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// A timestamp, clamped to what events can have.
fn timestamp(name: &str, value: &Value) -> Result<u32, String> {
    if let Some(n) = value.as_u64() {
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    } else if value.as_i64().is_some() {
        Ok(0)
    } else {
        Err(format!("invalid: {name} must be an integer"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::record::encode;
    use serde_json::json;

    fn matches(filter: Value, event: &Event) -> bool {
        let record = encode(event);
        Filter::parse(&filter)
            .unwrap()
            .matches(&EventView::new(&record).unwrap())
    }

    #[test]
    fn matches_each_field() {
        let hex = "ab".repeat(32);
        let event = signed(
            1,
            100,
            1,
            vec![
                vec!["e", &hex],
                vec!["t", "nostr"],
                vec!["t", "rust"],
                vec!["title", "x"],
            ],
            "",
        );
        let author = &event.pubkey;
        assert!(matches(json!({}), &event));
        assert!(matches(json!({"ids": [event.id]}), &event));
        assert!(matches(
            json!({"authors": [author], "kinds": [1, 2]}),
            &event
        ));
        assert!(!matches(json!({"authors": [hex]}), &event));
        assert!(!matches(json!({"kinds": [7]}), &event));
        assert!(matches(json!({"#e": [hex], "#t": ["rust", "go"]}), &event));
        assert!(!matches(json!({"#e": [hex], "#t": ["go"]}), &event));
        assert!(!matches(json!({"#e": [hex.to_uppercase()]}), &event));
        assert!(matches(json!({"since": 100, "until": 100}), &event));
        assert!(!matches(json!({"since": 101}), &event));
        assert!(!matches(json!({"until": 99}), &event));
        // Only single-letter tags are filters; anything else is ignored.
        assert!(matches(json!({"#title": ["y"], "search": "z"}), &event));
    }

    #[test]
    fn matches_nothing_when_a_field_is_empty() {
        let event = signed(2, 100, 1, vec![], "");
        for filter in [
            json!({"ids": []}),
            json!({"kinds": [70000]}),
            json!({"#t": []}),
            json!({"since": 5, "until": 4}),
        ] {
            assert!(Filter::parse(&filter).unwrap().never, "{filter}");
            assert!(!matches(filter, &event));
        }
    }

    #[test]
    fn refuses_malformed_filters() {
        for filter in [
            json!([]),
            json!({"ids": ["abc"]}),
            json!({"kinds": ["1"]}),
            json!({"limit": -1}),
            json!({"#t": [1]}),
        ] {
            assert!(Filter::parse(&filter).is_err(), "{filter}");
        }
        let filter = Filter::parse(&json!({"since": -5, "until": 1u64 << 40})).unwrap();
        assert_eq!((filter.since, filter.until), (0, u32::MAX));
    }
}
