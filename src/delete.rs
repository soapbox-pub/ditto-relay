//! `ditto-relay delete`: delete every stored event a filter matches, as
//! `strfry delete` does, while the relay runs or not.
//!
//! The deletion is [queued](crate::pending): what the filter matches is
//! hidden at once, and [removed](crate::purge) after, at whatever pace the
//! writer's other work allows. While the relay runs, it's asked over its
//! [control socket](crate::control), and `delete` returns once it's queued.
//! Only when the relay isn't running does `delete` write the store, and the
//! search index, itself, removing everything then and there, and then it
//! must open them with the relay's configuration: opened with another web of
//! trust or other ranking parameters, the store rebuilds them. Counting what
//! would go, for `--dry-run`, only reads, which LMDB never makes wait.
//!
//! A filter matches as a REQ's does, search text and extensions too. One
//! that picks events rather than matching them, with a limit or
//! `distinct:author`, picks them once, when it's asked, by its sort, so
//! `sort:top` with a limit deletes the most engaged with as of then.
//!
//! Events are removed as a NIP-09 deletion removes them, with what's
//! derived from them; removing an address's current version takes the
//! versions kept in its history the filter matches too, and makes the
//! newest left current. Nothing is kept to refuse them if they're
//! published again, and the relay's subscribers aren't told.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, bail};
use roaring::RoaringTreemap;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::event::KindClass;
use crate::filter::Filter;
use crate::pending::Target;
use crate::query;
use crate::search::Indexer;
use crate::store::{IndexedTags, Store};

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
    if let Some(age) = age {
        if value.get("until").is_some() {
            bail!("--age and a filter with until can't be used together");
        }
        filter.until = now.saturating_sub(age.try_into().unwrap_or(u32::MAX));
        filter.never |= filter.since > filter.until;
    }
    Ok(filter)
}

/// Whether a filter picks events, rather than matching them: its limit, or
/// `distinct:author`, says which of what it matches.
pub fn picks(filter: &Filter) -> bool {
    filter.limit.is_some() || filter.distinct_author()
}

/// What deleting by `filter`, parsed from `json` with `age`, covers: what
/// it matches, or if it [picks](picks), the events it picks now.
pub fn target(
    store: &Store,
    filter: Filter,
    json: Option<&str>,
    age: Option<u64>,
) -> anyhow::Result<Target> {
    if picks(&filter) {
        return Ok(Target::Seqs(Arc::new(pick(store, &filter)?)));
    }
    Ok(Target::Filter {
        until: age.map(|_| filter.until),
        filter: Box::new(filter),
        json: json.unwrap_or("{}").to_string(),
    })
}

/// The events a filter that [picks](picks) picks, as of now: by its sort,
/// the best that many, or the newest; with `distinct:author`, the first of
/// each author's.
pub fn pick(store: &Store, filter: &Filter) -> anyhow::Result<RoaringTreemap> {
    let txn = store.read()?;
    let ranked = filter
        .search
        .as_ref()
        .is_some_and(|search| search.sort.is_ranked());
    if ranked && let Some(limit) = filter.limit {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let found = crate::rank::run(store, &txn, filter, limit, &CancellationToken::new())?;
        return Ok(found.into_iter().map(|(seq, _)| seq).collect());
    }
    if !filter.distinct_author() {
        return Ok(query::every_match(store, &txn, filter)?
            .into_iter()
            .collect());
    }
    // Each author's newest, then the newest of those.
    let every = Filter {
        limit: None,
        ..filter.every_event()
    };
    let mut newest: HashMap<[u8; 32], (u32, u64)> = HashMap::new();
    for seq in query::every_match(store, &txn, &every)? {
        if let Some(header) = store.header(&txn, seq)? {
            let at = (header.created_at(), seq);
            let kept = newest.entry(*header.pubkey()).or_insert(at);
            *kept = (*kept).max(at);
        }
    }
    let mut picked: Vec<(u32, u64)> = newest.into_values().collect();
    picked.sort_unstable_by(|a, b| b.cmp(a));
    if let Some(limit) = filter.limit {
        picked.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    }
    Ok(picked.into_iter().map(|(_, seq)| seq).collect())
}

/// How many events deleting by `filter` would remove, as of now. Only
/// matches that may have old versions to take along are read: those of
/// kinds without them, as the index says, count once each.
pub fn count(store: &Store, filter: &Filter) -> anyhow::Result<usize> {
    if picks(filter) {
        return Ok(pick(store, filter)?.len() as usize);
    }
    let txn = store.read()?;
    let mut alone = 0;
    let mut versioned = Vec::new();
    for (seq, kind) in query::every_match_kinded(store, &txn, filter)? {
        match kind.map(KindClass::of) {
            Some(KindClass::Regular | KindClass::Ephemeral) => alone += 1,
            _ => versioned.push(seq),
        }
    }
    Ok(alone + store.count_matching(&txn, &versioned, filter)?)
}

/// Delete what `target` covers from a store no running relay has open, and
/// from its search index, if there's one, now, telling `progress` how many
/// so far after each chunk. Any other deletions left pending are carried
/// out too. With `threads`, the store again, a sweep is read ahead of on
/// threads of its own. Returns how many events went.
pub fn delete(
    store: &Store,
    threads: Option<Arc<Store>>,
    target: Target,
    indexer: Option<&mut Indexer>,
    progress: impl FnMut(usize),
) -> anyhow::Result<usize> {
    let queued = (|| {
        let mut txn = store.write()?;
        let watermark = store.next_seq(&txn)?;
        store.queue_deletion(&mut txn, watermark, target)?;
        txn.commit()
    })();
    match queued {
        Ok(()) => store.committed_queued(),
        Err(err) => {
            store.forget_uncommitted();
            return Err(err.into());
        }
    }
    let indexer = RefCell::new(indexer);
    let mut progress = progress;
    let deleted = crate::purge::run(
        store,
        threads,
        &|(_, removed): crate::store::Written| {
            if let Some(indexer) = indexer.borrow_mut().as_deref_mut() {
                indexer.remove(&removed);
            }
        },
        |n| progress(n as usize),
    )?;
    store.forget()?;
    if let Some(indexer) = indexer.into_inner() {
        indexer.commit()?;
    }
    Ok(deleted as usize)
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

    /// Delete by `filter`, as with no relay running, returning how many.
    fn del(store: &Store, filter: Value) -> usize {
        let json = filter.to_string();
        let target = target(store, parse(filter), Some(&json), None).unwrap();
        delete(store, None, target, None, |_| {}).unwrap()
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
        assert_eq!(count(&store, &filter).unwrap(), 2);
        assert!(has(&store, &spam));
        assert_eq!(del(&store, json!({"#t": ["spam"]})), 2);
        assert!(!has(&store, &spam) && !has(&store, &more) && has(&store, &fine));
        assert_eq!(found(&store, json!({"kinds": [1]})), 1);
        assert!(store.pending().is_empty());
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
        assert_eq!(del(&store, json!({"authors": [author], "#t": ["x"]})), 1);
        assert!(!has(&store, &a) && has(&store, &b) && has(&store, &c));
    }

    #[test]
    fn deletes_by_search_text() {
        let (_dir, store) = open();
        let a = signed(1, 100, 1, vec![], "Buy cheap PILLS now");
        let b = signed(2, 200, 1, vec![], "pills are not candy");
        let c = signed(3, 300, 1, vec![], "hello");
        for event in [&a, &b, &c] {
            put(&store, event);
        }
        assert_eq!(del(&store, json!({"search": "pills -candy"})), 1);
        assert!(!has(&store, &a) && has(&store, &b) && has(&store, &c));
    }

    #[test]
    fn honours_a_limit() {
        let (_dir, store) = open();
        let events: Vec<Event> = (0..5).map(|i| signed(1, 100 + i, 1, vec![], "")).collect();
        for event in &events {
            put(&store, event);
        }
        assert_eq!(del(&store, json!({"kinds": [1], "limit": 2})), 2);
        assert!(has(&store, &events[2]) && !has(&store, &events[3]) && !has(&store, &events[4]));
    }

    /// `distinct:author` picks each author's newest, and with a limit, the
    /// newest of those.
    #[test]
    fn picks_one_of_each_author() {
        let (_dir, store) = open();
        let events = [
            signed(1, 100, 1, vec![], ""),
            signed(1, 200, 1, vec![], ""),
            signed(2, 150, 1, vec![], ""),
            signed(3, 120, 1, vec![], ""),
        ];
        for event in &events {
            put(&store, event);
        }
        let filter = json!({"kinds": [1], "search": "distinct:author", "limit": 2});
        assert_eq!(count(&store, &parse(filter.clone())).unwrap(), 2);
        assert_eq!(del(&store, filter), 2);
        let left: Vec<bool> = events.iter().map(|event| has(&store, event)).collect();
        assert_eq!(left, [true, false, false, true]);
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
        let filter = json!({"#t": ["spam"]});
        assert_eq!(count(&store, &parse(filter.clone())).unwrap(), 2);
        assert_eq!(del(&store, filter), 2);
        assert!(has(&store, &v1) && !has(&store, &v2) && !has(&store, &v3));
        assert_eq!(found(&store, json!({"kinds": [0]})), 1);

        // By address, old versions alone.
        let v4 = signed(1, 400, 0, vec![], "v4");
        put(&store, &v4);
        let author = v4.pubkey.clone();
        assert_eq!(
            del(
                &store,
                json!({"kinds": [0], "authors": [author], "until": 399})
            ),
            1
        );
        assert!(!has(&store, &v1) && has(&store, &v4));

        // By author, every version.
        put(&store, &signed(1, 500, 0, vec![], "v5"));
        assert_eq!(del(&store, json!({"authors": [author]})), 2);
        assert!(!has(&store, &v4));
        assert_eq!(found(&store, json!({"kinds": [0]})), 0);
    }

    #[test]
    fn deletes_by_an_extension() {
        let (_dir, store) = open();
        let note = signed(1, 100, 1, vec![vec!["proxy", "at://a", "atproto"]], "a");
        let other = signed(2, 200, 1, vec![vec!["proxy", "ap://b", "activitypub"]], "b");
        let v1 = signed(3, 100, 0, vec![vec!["proxy", "at://p1", "atproto"]], "v1");
        let v2 = signed(3, 200, 0, vec![vec!["proxy", "at://p2", "atproto"]], "v2");
        for event in [&note, &other, &v1, &v2] {
            put(&store, event);
        }
        // The note counted from the index alone, the profile with its
        // history.
        let filter = json!({"search": "protocol:atproto"});
        assert_eq!(count(&store, &parse(filter.clone())).unwrap(), 3);
        assert_eq!(del(&store, filter), 3);
        assert!(!has(&store, &note) && has(&store, &other));
        assert!(!has(&store, &v1) && !has(&store, &v2));
    }

    #[test]
    fn says_how_it_goes() {
        let (_dir, store) = open();
        let n = 300;
        for i in 0..n {
            put(&store, &signed(1, 100 + i, 1, vec![], ""));
        }
        let mut seen = Vec::new();
        let filter = parse(json!({"kinds": [1]}));
        let target = target(&store, filter, Some(r#"{"kinds":[1]}"#), None).unwrap();
        assert_eq!(
            delete(&store, None, target, None, |n| seen.push(n)).unwrap(),
            n as usize
        );
        assert!(seen.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(seen.last(), Some(&(n as usize)));
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
        assert!(super::filter(Some("nope"), None, 1000, &tags).is_err());
        let never = super::filter(Some(r#"{"since":950}"#), Some(100), 1000, &tags).unwrap();
        assert!(never.never);
        // A sort picks with a limit, and without one, changes nothing.
        let top = super::filter(Some(r#"{"search":"sort:top"}"#), None, 1000, &tags).unwrap();
        assert!(!picks(&top));
        let top = r#"{"search":"sort:top","limit":5}"#;
        assert!(picks(&super::filter(Some(top), None, 1000, &tags).unwrap()));
    }
}
