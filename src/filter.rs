//! NIP-01 filters: parsed once into sorted sets, then matched against stored
//! records without decoding them.

use std::cmp::Ordering;

use serde_json::Value;

use crate::event::is_hex64;
use crate::record::{Element, EventView, tag_value};
use crate::search;
use crate::store::MAX_INDEXED_TAG;

/// The most values one field of a filter may list. Generous enough for a
/// big follow list.
pub const MAX_VALUES: usize = 5000;

/// The most terms a search may have.
pub const MAX_SEARCH_TERMS: usize = 32;

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
    pub search: Option<Search>,
    /// Some field can match nothing (an empty list, say), so neither can
    /// the filter.
    pub never: bool,
}

/// A NIP-50 search.
#[derive(Debug, Clone, Default)]
pub struct Search {
    /// What an event must have all of, as [`search::tokens`]. Sorted.
    pub terms: Vec<String>,
    /// `sort:new`: the newest matches rather than the most relevant.
    pub sort_new: bool,
    /// `autocomplete:true`: the terms are prefixes of names and titles.
    pub autocomplete: bool,
}

impl Filter {
    /// Parse a filter. Errors are NIP-01 machine-readable messages. Fields
    /// neither NIP-01 nor NIP-50 defines are ignored.
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
                "search" => filter.search = parse_search(value)?,
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
        self.matches_fields(event)
            && self
                .search
                .as_ref()
                .is_none_or(|search| match search.autocomplete {
                    true => search::matches_prefixes(&search.terms, event),
                    false => search::matches(&search.terms, event),
                })
    }

    /// Whether an event matches, its search aside.
    pub fn matches_fields(&self, event: &EventView) -> bool {
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

/// A search's terms and the extensions it understands. Any other `key:value`
/// is an extension it doesn't, which NIP-50 says to ignore. With no terms
/// left, it's no search at all.
fn parse_search(value: &Value) -> Result<Option<Search>, String> {
    let text = value.as_str().ok_or("invalid: search must be a string")?;
    let mut sort_new = false;
    let mut autocomplete = false;
    let mut words = Vec::new();
    for word in text.split_whitespace() {
        match extension(word) {
            Some(("sort", "new")) => sort_new = true,
            Some(("autocomplete", "true")) => autocomplete = true,
            Some(_) => {}
            None => words.push(word),
        }
    }
    let mut terms = search::tokens(&words.join(" "));
    terms.sort_unstable();
    terms.dedup();
    if terms.len() > MAX_SEARCH_TERMS {
        return Err(format!(
            "invalid: search has more than {MAX_SEARCH_TERMS} terms"
        ));
    }
    Ok((!terms.is_empty()).then_some(Search {
        terms,
        sort_new,
        autocomplete,
    }))
}

/// A NIP-50 extension's key and value. Not a URL's scheme and the rest.
fn extension(word: &str) -> Option<(&str, &str)> {
    let (key, value) = word.split_once(':')?;
    let key_ok = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'-');
    (key_ok && !value.is_empty() && !value.starts_with("//")).then_some((key, value))
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
        assert!(matches(json!({"#title": ["y"], "foo": "z"}), &event));
    }

    #[test]
    fn matches_every_search_term() {
        let event = signed(1, 100, 1, vec![vec!["title", "Café"]], "Hello, World");
        assert!(matches(json!({"search": "world HELLO"}), &event));
        assert!(matches(json!({"search": "cafe"}), &event));
        assert!(!matches(json!({"search": "hello there"}), &event));
        assert!(!matches(json!({"search": "hello", "kinds": [7]}), &event));
    }

    #[test]
    fn matches_autocomplete_prefixes_of_names() {
        let profile = json!({"name": "Jack Dorsey", "about": "bitcoin", "nip05": "jack@x.com"});
        let event = signed(1, 100, 0, vec![], &profile.to_string());
        let autocomplete = |text: &str| json!({"search": format!("{text} autocomplete:true")});
        assert!(matches(autocomplete("jac dor"), &event));
        assert!(matches(autocomplete("JACK"), &event));
        assert!(!matches(autocomplete("bitco"), &event));
        assert!(!matches(autocomplete("ack"), &event));
        let article = signed(
            1,
            100,
            30023,
            vec![vec!["title", "Ñandú Facts"]],
            "body text",
        );
        assert!(matches(autocomplete("nan fac"), &article));
        assert!(!matches(autocomplete("bod"), &article));
    }

    #[test]
    fn parses_search_extensions() {
        let search = |text: &str| Filter::parse(&json!({"search": text})).unwrap().search;
        let parsed = search("Nostr sort:new include:spam https://x.com nostr").unwrap();
        assert_eq!(parsed.terms, ["com", "https", "nostr", "x"]);
        assert!(parsed.sort_new);
        assert!(!search("rust").unwrap().sort_new);
        assert!(!parsed.autocomplete);
        let parsed = search("Jac autocomplete:true sort:new").unwrap();
        assert!(parsed.autocomplete && parsed.sort_new);
        assert_eq!(parsed.terms, ["jac"]);
        // Only extensions, or only punctuation: no search.
        assert!(search("sort:new language:en").is_none());
        assert!(search("  !! ").is_none());
        assert!(Filter::parse(&json!({"search": 1})).is_err());
        let many: Vec<String> = (0..40).map(|i| format!("w{i}")).collect();
        assert!(Filter::parse(&json!({"search": many.join(" ")})).is_err());
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
