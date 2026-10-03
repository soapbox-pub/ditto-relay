//! Answering filters from the store.
//!
//! Each filter gets one index to scan. The candidates are the ones its
//! fields allow — author and kind together, author, each tag, kind — and
//! since every index key's stamps are counted by LMDB for free, the planner
//! simply adds up the counts of each candidate's keys and takes the
//! smallest. If that index pins down every field the filter has, its
//! entries need no further checking.
//!
//! A scan opens a cursor per key, each starting at `until` and walking back
//! in time, and merges them newest first until `since` or the limit.

use std::collections::{BinaryHeap, HashSet};

use crate::filter::Filter;
use crate::lmdb::{Cursor, Db, Result, Txn};
use crate::record::EventView;
use crate::store::{CREATED, MAX_SEQ, Stamp, Store, stamp, stamp_created_at, stamp_seq};

/// The most author × kind keys a filter may be planned over together.
const MAX_AUTHOR_KINDS: usize = 1024;

/// The most records one filter may examine. Only filters whose fields the
/// index can't pin down examine records that don't match, and this bounds
/// how long one of those can hold a reader.
const MAX_EXAMINED: usize = 100_000;

/// The most extra events read past the limit to order a tie at the boundary.
const MAX_TIES: usize = 1000;

pub struct Results {
    /// The sequence number the next event stored after this snapshot gets.
    /// Anything below it was visible to the query.
    pub next_seq: u64,
    /// Matching events as JSON, each filter's newest first.
    pub events: Vec<String>,
}

/// Run a REQ's filters. Each one's limit defaults to `default_limit` and is
/// capped at `max_limit`.
pub fn run(
    store: &Store,
    filters: &[Filter],
    default_limit: u64,
    max_limit: u64,
) -> Result<Results> {
    let txn = store.read()?;
    let next_seq = store.next_seq(&txn)?;
    let mut seen = HashSet::new();
    let mut events = Vec::new();
    for filter in filters {
        let limit = filter.limit.unwrap_or(default_limit).min(max_limit) as usize;
        if filter.never || limit == 0 {
            continue;
        }
        for (seq, view) in run_filter(store, &txn, filter, limit)? {
            if seen.insert(seq) {
                events.push(view.to_json());
            }
        }
    }
    Ok(Results { next_seq, events })
}

fn run_filter<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    limit: usize,
) -> Result<Vec<(u64, EventView<'t>)>> {
    let mut found = Vec::new();

    if let Some(ids) = &filter.ids {
        for id in ids {
            let Some(seq) = store.seq_of(txn, id)? else {
                continue;
            };
            if let Some(view) = store.load(txn, seq)?.filter(|view| filter.matches(view)) {
                found.push((seq, view));
            }
        }
    } else {
        let plan = plan(store, txn, filter)?;
        scan(store, txn, filter, &plan, limit, &mut found)?;
    }

    // Newest first; on a tie, the lowest id first (NIP-01).
    found.sort_unstable_by(|(_, a), (_, b)| {
        b.created_at()
            .cmp(&a.created_at())
            .then_with(|| a.id().cmp(b.id()))
    });
    found.truncate(limit);
    Ok(found)
}

#[derive(Debug)]
struct Plan {
    db: Db,
    /// Keys whose stamps to merge.
    keys: Vec<Vec<u8>>,
    /// Whether every entry found matches the filter, time aside.
    exact: bool,
}

fn plan(store: &Store, txn: &Txn, filter: &Filter) -> Result<Plan> {
    let t = store.tables;
    let mut candidates = Vec::new();
    let no_tags = filter.tags.is_empty();

    if let (Some(authors), Some(kinds)) = (&filter.authors, &filter.kinds)
        && authors.len() * kinds.len() <= MAX_AUTHOR_KINDS
    {
        let keys = authors
            .iter()
            .flat_map(|a| {
                kinds
                    .iter()
                    .map(move |k| [&a[..], &k.to_be_bytes()].concat())
            })
            .collect();
        candidates.push(Plan {
            db: t.author_kinds,
            keys,
            exact: no_tags,
        });
    }
    if let Some(authors) = &filter.authors {
        let keys = authors.iter().map(|a| a.to_vec()).collect();
        candidates.push(Plan {
            db: t.authors,
            keys,
            exact: filter.kinds.is_none() && no_tags,
        });
    }
    for (letter, values) in &filter.tags {
        let keys = values
            .iter()
            .map(|v| [&[*letter][..], v].concat())
            .collect();
        let exact = filter.authors.is_none() && filter.kinds.is_none() && filter.tags.len() == 1;
        candidates.push(Plan {
            db: t.tags,
            keys,
            exact,
        });
    }
    if let Some(kinds) = &filter.kinds {
        let keys = kinds.iter().map(|k| k.to_be_bytes().to_vec()).collect();
        candidates.push(Plan {
            db: t.kinds,
            keys,
            exact: filter.authors.is_none() && no_tags,
        });
    }

    let mut best: Option<(usize, Plan)> = None;
    for candidate in candidates {
        let bound = best.as_ref().map_or(usize::MAX, |(cost, _)| *cost);
        let cost = cost(txn, &candidate, bound)?;
        // Ties go to the earlier candidate, which pins down more fields.
        if cost < bound {
            best = Some((cost, candidate));
        }
    }
    Ok(best.map_or(
        Plan {
            db: t.created,
            keys: vec![CREATED.to_vec()],
            exact: true,
        },
        |(_, plan)| plan,
    ))
}

/// How many entries a plan would walk, at worst. Stops counting at `bound`.
fn cost(txn: &Txn, plan: &Plan, bound: usize) -> Result<usize> {
    let mut cursor = txn.cursor(plan.db)?;
    let mut total = 0usize;
    for key in &plan.keys {
        if cursor.set(key)?.is_some() {
            total = total.saturating_add(cursor.count()?);
            if total >= bound {
                break;
            }
        }
    }
    Ok(total)
}

/// One key's stamps, newest first.
struct Source<'t> {
    cursor: Cursor<'t>,
}

impl<'t> Source<'t> {
    /// Position at the newest stamp no later than `until`.
    fn start(txn: &'t Txn, db: Db, key: &[u8], until: u32) -> Result<Option<(Stamp, Source<'t>)>> {
        let mut cursor = txn.cursor(db)?;
        let entry = match cursor.get_both_range(key, &stamp(until, MAX_SEQ))? {
            Some(_) => cursor.prev_dup()?,
            None => match cursor.set(key)? {
                Some(_) => cursor.last_dup()?,
                None => None,
            },
        };
        Ok(stamp_of(entry).map(|stamp| (stamp, Source { cursor })))
    }

    fn next(&mut self) -> Result<Option<Stamp>> {
        Ok(stamp_of(self.cursor.prev_dup()?))
    }
}

fn stamp_of(entry: Option<(&[u8], &[u8])>) -> Option<Stamp> {
    entry?.1.try_into().ok()
}

fn scan<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    plan: &Plan,
    limit: usize,
    found: &mut Vec<(u64, EventView<'t>)>,
) -> Result<()> {
    let mut sources = Vec::new();
    let mut heap = BinaryHeap::new();
    for key in &plan.keys {
        if let Some((stamp, source)) = Source::start(txn, plan.db, key, filter.until)? {
            heap.push((stamp, sources.len()));
            sources.push(source);
        }
    }

    let mut last = None;
    let mut examined = 0;
    while let Some((stamp, i)) = heap.pop() {
        if let Some(next) = sources[i].next()? {
            heap.push((next, i));
        }
        let created_at = stamp_created_at(&stamp);
        if created_at < filter.since {
            // The newest left is too old, so all of them are.
            break;
        }
        // The same event under two keys pops twice in a row.
        if last == Some(stamp) {
            continue;
        }
        last = Some(stamp);
        // Past the limit, keep going only through a tie with the last one.
        if found.len() >= limit
            && (found.len() >= limit + MAX_TIES
                || found
                    .last()
                    .is_some_and(|(_, v)| created_at < v.created_at()))
        {
            break;
        }
        examined += 1;
        if examined > MAX_EXAMINED {
            break;
        }

        let seq = stamp_seq(&stamp);
        let Some(view) = store.load(txn, seq)? else {
            continue;
        };
        if plan.exact || filter.matches(&view) {
            found.push((seq, view));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::store::tests::{open, put};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use serde_json::{Value, json};

    fn ids(store: &Store, filters: &[Value], max_limit: u64) -> Vec<String> {
        let filters: Vec<Filter> = filters.iter().map(|f| Filter::parse(f).unwrap()).collect();
        let results = run(store, &filters, max_limit, max_limit).unwrap();
        results
            .events
            .iter()
            .map(|json| serde_json::from_str::<Event>(json).unwrap().id)
            .collect()
    }

    #[test]
    fn plans_by_counts() {
        let (_dir, store) = open();
        for i in 0..20 {
            put(
                &store,
                &signed(1, 100 + i, 1, vec![vec!["t", "common"]], ""),
            );
        }
        put(&store, &signed(2, 100, 1, vec![vec!["t", "rare"]], ""));
        let alice = signed(1, 0, 1, vec![], "").pubkey;

        let txn = store.read().unwrap();
        let plan_for =
            |filter: Value| plan(&store, &txn, &Filter::parse(&filter).unwrap()).unwrap();

        // The rare tag beats the author with twenty events, and needs checking.
        let p = plan_for(json!({"authors": [alice], "#t": ["rare"]}));
        assert_eq!(p.keys, vec![[&b"t"[..], &[0], b"rare"].concat()]);
        assert!(!p.exact);
        // Author and kind together, exactly.
        let p = plan_for(json!({"authors": [alice], "kinds": [1]}));
        assert_eq!(p.keys[0].len(), 34);
        assert!(p.exact);
        assert_eq!(plan_for(json!({"since": 5})).keys, [CREATED]);
    }

    #[test]
    fn pages_newest_first_breaking_ties_by_id() {
        let (_dir, store) = open();
        let mut events: Vec<Event> = (0..10)
            .map(|i| signed(1, 100 + i / 2, 1, vec![], &i.to_string()))
            .collect();
        for event in &events {
            put(&store, event);
        }
        events.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let expected: Vec<String> = events.iter().map(|e| e.id.clone()).collect();

        assert_eq!(ids(&store, &[json!({"kinds": [1]})], 100), expected);
        assert_eq!(ids(&store, &[json!({})], 100), expected);
        // A limit landing mid-tie still gets the lowest ids of the tie.
        assert_eq!(
            ids(&store, &[json!({"kinds": [1], "limit": 3})], 100),
            expected[..3]
        );
        assert_eq!(ids(&store, &[json!({"limit": 3})], 100), expected[..3]);
        // The relay's own cap.
        assert_eq!(ids(&store, &[json!({"kinds": [1]})], 4), expected[..4]);
        assert_eq!(
            ids(
                &store,
                &[json!({"kinds": [1], "until": 102, "since": 101})],
                100
            ),
            expected[4..8]
        );
        assert!(ids(&store, &[json!({"kinds": [1], "limit": 0})], 100).is_empty());
    }

    /// Random events and filters, checked against matching every event.
    #[test]
    fn agrees_with_brute_force() {
        let (_dir, store) = open();
        let mut rng = StdRng::seed_from_u64(7);
        let topics = ["a", "b", "c", "d"];
        let mut all = Vec::new();
        for i in 0..300 {
            let seed = rng.random_range(1..4);
            let kind = [1, 7, 1111][rng.random_range(0..3)];
            let mut tags = vec![];
            for _ in 0..rng.random_range(0..3) {
                tags.push(vec!["t", topics[rng.random_range(0..4)]]);
            }
            let event = signed(seed, rng.random_range(100..160), kind, tags, &i.to_string());
            put(&store, &event);
            all.push(event);
        }
        let pubkeys: Vec<String> = (1..4)
            .map(|seed| signed(seed, 0, 1, vec![], "").pubkey)
            .collect();

        for _ in 0..300 {
            let mut filter = serde_json::Map::new();
            if rng.random_bool(0.5) {
                filter.insert("authors".into(), json!(pubkeys[..rng.random_range(1..3)]));
            }
            if rng.random_bool(0.5) {
                let kind = [1, 7, 1111][rng.random_range(0..3)];
                filter.insert("kinds".into(), json!([kind, 9]));
            }
            if rng.random_bool(0.5) {
                filter.insert("#t".into(), json!(topics[..rng.random_range(1..4)]));
            }
            if rng.random_bool(0.3) {
                filter.insert("since".into(), json!(rng.random_range(100..160)));
            }
            if rng.random_bool(0.3) {
                filter.insert("until".into(), json!(rng.random_range(100..160)));
            }
            let limit = rng.random_range(1..40);
            filter.insert("limit".into(), json!(limit));
            let filter = Value::Object(filter);

            let parsed = Filter::parse(&filter).unwrap();
            let mut expected: Vec<&Event> = all
                .iter()
                .filter(|e| {
                    let record = crate::record::encode(e);
                    parsed.matches(&EventView::new(&record).unwrap())
                })
                .collect();
            expected.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let expected: Vec<String> = expected.iter().take(limit).map(|e| e.id.clone()).collect();
            assert_eq!(
                ids(&store, std::slice::from_ref(&filter), 500),
                expected,
                "{filter}"
            );
        }
    }

    #[test]
    fn merges_filters_without_repeats() {
        let (_dir, store) = open();
        let note = signed(1, 100, 1, vec![], "");
        put(&store, &note);
        let found = ids(
            &store,
            &[json!({"kinds": [1]}), json!({"ids": [note.id]})],
            100,
        );
        assert_eq!(found, vec![note.id.clone()]);
    }

    #[test]
    fn does_not_index_long_tag_values() {
        let (_dir, store) = open();
        let long = "x".repeat(1000);
        put(&store, &signed(1, 100, 1, vec![vec!["t", &long]], ""));
        assert!(ids(&store, &[json!({"#t": [long]})], 100).is_empty());
        assert_eq!(ids(&store, &[json!({})], 100).len(), 1);
    }
}
