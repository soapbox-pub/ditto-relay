//! `ditto-relay delete`: remove every stored event a filter matches, from
//! a process of its own beside the running relay, as `strfry delete` does.
//!
//! LMDB's writers take turns, whichever process they're in, so it removes
//! [`CHUNK`] events' worth per transaction, and the relay's writer waits no
//! longer than one of those. The search index has only one writer, the
//! relay's indexer, so what's removed is queued for it in the LMDB
//! instead (see [`Store::queue_for_search`]).
//!
//! It must open the store with the relay's configuration: opened with
//! another web of trust or other ranking parameters, the store rebuilds
//! them, under the running relay.
//!
//! Events are removed as a NIP-09 deletion removes them, with what's
//! derived from them; removing an address's current version takes the
//! versions kept in its history the filter matches too, and makes the
//! newest left current. Nothing is kept to refuse them if they're
//! published again, and the relay's subscribers aren't told.

use anyhow::{Context, bail};
use serde_json::Value;

use crate::filter::Filter;
use crate::query;
use crate::store::{IndexedTags, Store};

/// The most matches removed per write transaction.
pub const CHUNK: usize = 1000;

/// The filter to delete by: `json`, if given, and with `age`, only events
/// at least that many seconds older than `now`. One of them is needed.
pub fn filter(
    json: Option<&str>,
    age: Option<u64>,
    now: u32,
    indexed: &IndexedTags,
) -> anyhow::Result<Filter> {
    let value: Value = match json {
        Some(json) => serde_json::from_str(json).context("the filter isn't JSON")?,
        None if age.is_some() => Value::Object(Default::default()),
        None => bail!("delete needs --filter, --age, or both"),
    };
    let mut filter = Filter::parse(&value, indexed, usize::MAX).map_err(anyhow::Error::msg)?;
    if let Some(search) = &filter.search
        && (search.sort.is_ranked() || search.distinct_author)
    {
        bail!("a ranked sort or distinct:author picks events rather than matching them");
    }
    if let Some(age) = age {
        if value.get("until").is_some() {
            bail!("--age and a filter with until can't be used together");
        }
        filter.until = now.saturating_sub(age.try_into().unwrap_or(u32::MAX));
        filter.never |= filter.since > filter.until;
    }
    Ok(filter)
}

/// Remove every stored event `filter` matches, or with `dry_run`, only
/// count them. With `search`, queue what's removed for the search indexer.
/// Returns how many.
pub fn delete(
    store: &Store,
    filter: &Filter,
    search: bool,
    dry_run: bool,
) -> anyhow::Result<usize> {
    let seqs = {
        let txn = store.read()?;
        let seqs = query::every_match(store, &txn, filter)?;
        if dry_run {
            return Ok(store.count_matching(&txn, &seqs, filter)?);
        }
        seqs
    };
    let mut deleted = 0;
    for chunk in seqs.chunks(CHUNK) {
        let now = crate::event::now();
        let mut removed = Vec::new();
        let mut txn = store.write()?;
        for &seq in chunk {
            deleted += store.remove_matching(&mut txn, seq, filter, now, &mut removed)?;
        }
        if search {
            store.queue_for_search(&mut txn, &removed)?;
        }
        txn.commit()?;
        tracing::debug!("deleted {deleted} events so far");
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::store::tests::{open, put, test_tags};
    use serde_json::json;

    fn parse(filter: Value) -> Filter {
        super::filter(Some(&filter.to_string()), None, 1000, &test_tags()).unwrap()
    }

    fn has(store: &Store, event: &Event) -> bool {
        let id: [u8; 32] = hex::decode(&event.id).unwrap().try_into().unwrap();
        store.seq_of(&store.read().unwrap(), &id).unwrap().is_some()
    }

    /// What a query of `filter` finds now, as the relay would.
    fn found(store: &Store, filter: Value) -> usize {
        query::every_match(store, &store.read().unwrap(), &parse(filter))
            .unwrap()
            .len()
    }

    #[test]
    fn deletes_what_matches() {
        let (_dir, store) = open();
        let spam = signed(1, 100, 1, vec![vec!["t", "spam"]], "buy now");
        let more = signed(2, 200, 1, vec![vec!["t", "spam"]], "buy again");
        let fine = signed(3, 300, 1, vec![vec!["t", "nostr"]], "hello");
        for event in [&spam, &more, &fine] {
            put(&store, event);
        }
        let filter = parse(json!({"#t": ["spam"]}));
        assert_eq!(delete(&store, &filter, false, true).unwrap(), 2);
        assert!(has(&store, &spam));
        assert_eq!(delete(&store, &filter, false, false).unwrap(), 2);
        assert!(!has(&store, &spam) && !has(&store, &more) && has(&store, &fine));
        assert_eq!(found(&store, json!({"kinds": [1]})), 1);
        // Nothing keeps them out.
        assert_eq!(put(&store, &spam), crate::store::Outcome::Stored(4));
    }

    #[test]
    fn checks_what_the_index_doesnt_pin_down() {
        let (_dir, store) = open();
        let a = signed(1, 100, 1, vec![vec!["t", "x"]], "");
        let b = signed(1, 200, 1, vec![vec!["t", "y"]], "");
        let c = signed(2, 300, 1, vec![vec!["t", "x"]], "");
        for event in [&a, &b, &c] {
            put(&store, event);
        }
        let author = signed(1, 0, 1, vec![], "").pubkey;
        let filter = parse(json!({"authors": [author], "#t": ["x"]}));
        assert_eq!(delete(&store, &filter, false, false).unwrap(), 1);
        assert!(!has(&store, &a) && has(&store, &b) && has(&store, &c));
    }

    #[test]
    fn honours_a_limit() {
        let (_dir, store) = open();
        let events: Vec<Event> = (0..5).map(|i| signed(1, 100 + i, 1, vec![], "")).collect();
        for event in &events {
            put(&store, event);
        }
        let filter = parse(json!({"kinds": [1], "limit": 2}));
        assert_eq!(delete(&store, &filter, false, false).unwrap(), 2);
        assert!(has(&store, &events[2]) && !has(&store, &events[3]) && !has(&store, &events[4]));
    }

    #[test]
    fn takes_matching_history_and_promotes_the_rest() {
        let (_dir, store) = open();
        let v1 = signed(1, 100, 0, vec![], "v1");
        let v2 = signed(1, 200, 0, vec![vec!["t", "spam"]], "v2");
        let v3 = signed(1, 300, 0, vec![vec!["t", "spam"]], "v3");
        for event in [&v1, &v2, &v3] {
            put(&store, event);
        }
        // The current version and the history it matches go; what's left
        // is current again.
        let filter = parse(json!({"#t": ["spam"]}));
        assert_eq!(delete(&store, &filter, false, true).unwrap(), 2);
        assert_eq!(delete(&store, &filter, false, false).unwrap(), 2);
        assert!(has(&store, &v1) && !has(&store, &v2) && !has(&store, &v3));
        assert_eq!(found(&store, json!({"kinds": [0]})), 1);

        // By address, old versions alone.
        let v4 = signed(1, 400, 0, vec![], "v4");
        put(&store, &v4);
        let author = v4.pubkey.clone();
        let old = parse(json!({"kinds": [0], "authors": [author], "until": 399}));
        assert_eq!(delete(&store, &old, false, false).unwrap(), 1);
        assert!(!has(&store, &v1) && has(&store, &v4));

        // By author, every version.
        put(&store, &signed(1, 500, 0, vec![], "v5"));
        let all = parse(json!({"authors": [author]}));
        assert_eq!(delete(&store, &all, false, false).unwrap(), 2);
        assert!(!has(&store, &v4));
        assert_eq!(found(&store, json!({"kinds": [0]})), 0);
    }

    #[test]
    fn queues_for_search_only_when_asked() {
        let (_dir, store) = open();
        put(&store, &signed(1, 100, 1, vec![], "a"));
        put(&store, &signed(1, 200, 1, vec![], "b"));
        let queued = |store: &Store| store.search_queue(&store.read().unwrap(), 10).unwrap();
        delete(&store, &parse(json!({"until": 150})), false, false).unwrap();
        assert!(queued(&store).is_empty());
        delete(&store, &parse(json!({"until": 250})), true, false).unwrap();
        assert_eq!(queued(&store), [2]);
    }

    #[test]
    fn builds_the_filter() {
        let tags = test_tags();
        let aged = super::filter(Some(r#"{"kinds":[1]}"#), Some(100), 1000, &tags).unwrap();
        assert_eq!((aged.until, aged.kinds.as_deref()), (900, Some(&[1][..])));
        assert_eq!(
            super::filter(None, Some(100), 1000, &tags).unwrap().until,
            900
        );
        assert!(super::filter(None, None, 1000, &tags).is_err());
        assert!(super::filter(Some(r#"{"until":5}"#), Some(100), 1000, &tags).is_err());
        assert!(super::filter(Some(r#"{"search":"sort:hot"}"#), None, 1000, &tags).is_err());
        assert!(super::filter(Some("nope"), None, 1000, &tags).is_err());
        let never = super::filter(Some(r#"{"since":950}"#), Some(100), 1000, &tags).unwrap();
        assert!(never.never);
    }
}
