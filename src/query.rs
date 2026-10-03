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
//!
//! The indexes hold only the current version of a replaceable event, but a
//! filter shaped like an address — one kind, one author, and one `d` tag if
//! the kind is addressable — scans that address's history instead, and so
//! finds every version kept. So do `ids`, which look events up directly.
//!
//! A filter with a NIP-50 search goes to the [search index](crate::search)
//! instead, unless it lists ids or its search only excludes words. Those
//! are planned like any other, and checked by hand.
//!
//! A NIP-45 count needs no events when the plan is exact: with no time
//! bounds, and keys no event is filed under twice, it's the sum of LMDB's
//! counts of the keys; otherwise the stamps between the bounds are walked,
//! a page at a time. Only filters no index pins down load events, and only
//! so many; past that, the relay declines.

use std::collections::{BinaryHeap, HashSet};

use crate::event::KindClass;
use crate::filter::Filter;
use crate::hll::{self, Registers};
use crate::lmdb::{Cursor, Db, Result, Txn};
use crate::record::EventView;
use crate::search::SearchIndex;
use crate::store::{
    CREATED, MAX_SEQ, Stamp, Store, address, each_stamp, stamp, stamp_created_at, stamp_seq,
    tag_key, tag_key_kind,
};

/// The most author × kind keys a filter may be planned over together.
const MAX_AUTHOR_KINDS: usize = 1024;

/// The most records one filter may examine. Only filters whose fields the
/// index can't pin down examine records that don't match, and this bounds
/// how long one of those can hold a reader.
pub const MAX_EXAMINED: usize = 100_000;

/// The most stamps a count may walk.
const MAX_WALKED: usize = 2_000_000;

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
/// capped at `max_limit`. Search filters find nothing without `search`.
/// Fails with [`Restricted`] if an event found isn't `visible`.
pub fn run(
    store: &Store,
    search: Option<&SearchIndex>,
    filters: &[Filter],
    default_limit: u64,
    max_limit: u64,
    visible: impl Fn(&EventView) -> bool,
) -> anyhow::Result<Results> {
    let txn = store.read()?;
    let next_seq = store.next_seq(&txn)?;
    let mut seen = HashSet::new();
    let mut events = Vec::new();
    for filter in filters {
        let limit = filter.limit.unwrap_or(default_limit).min(max_limit) as usize;
        if filter.never || limit == 0 {
            continue;
        }
        let found = match (&filter.search, &filter.ids) {
            (Some(query), None) if !query.terms.is_empty() => match search {
                Some(search) => search.run(store, &txn, filter, query, limit)?,
                None => Vec::new(),
            },
            _ => run_filter(store, &txn, filter, limit)?,
        };
        for (seq, view) in found {
            if !visible(&view) {
                return Err(Restricted.into());
            }
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
    /// Whether no event is filed under two of the keys.
    disjoint: bool,
}

/// The address an address-shaped filter asks for every version of: one
/// replaceable or addressable kind, one author, and for an addressable
/// kind, one `d` tag and no other. With it, whether every version there
/// matches: one with no `d` tag is at the address of an empty one, but
/// doesn't match `#d: [""]`.
fn history_address(filter: &Filter) -> Option<(Vec<u8>, bool)> {
    if filter.ids.is_some() || filter.search.is_some() {
        return None;
    }
    let ([author], [kind]) = (filter.authors.as_deref()?, filter.kinds.as_deref()?) else {
        return None;
    };
    // The empty `d` tag, in tag value form.
    const EMPTY: &[u8] = &[0];
    let (d, exact) = match (KindClass::of(*kind), filter.tags.as_slice()) {
        (KindClass::Replaceable, []) => (EMPTY, true),
        (KindClass::Addressable, [(name, values)]) if name == "d" => match values.as_slice() {
            [d] => (d.as_slice(), d != EMPTY),
            _ => return None,
        },
        _ => return None,
    };
    Some((address(author, *kind, d), exact))
}

fn plan(store: &Store, txn: &Txn, filter: &Filter) -> Result<Plan> {
    let t = store.tables;
    if let Some((address, exact)) = history_address(filter) {
        return Ok(Plan {
            db: t.history,
            keys: vec![address],
            exact,
            disjoint: true,
        });
    }
    let mut candidates = Vec::new();
    // A search is never pinned down by an index, nor are hidden kinds.
    let no_tags = filter.tags.is_empty() && filter.search.is_none();
    let no_hidden = filter.hidden_kinds.is_empty();

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
            disjoint: true,
        });
    }
    if let Some(authors) = &filter.authors {
        let keys = authors.iter().map(|a| a.to_vec()).collect();
        candidates.push(Plan {
            db: t.authors,
            keys,
            exact: filter.kinds.is_none() && no_tags && no_hidden,
            disjoint: true,
        });
    }
    for (name, values) in &filter.tags {
        // The keys of the kinds each value is filed under, as wanted.
        let mut keys = Vec::new();
        let mut cursor = txn.cursor(t.tags)?;
        for value in values {
            let prefix = tag_key(name, value, None);
            let mut entry = cursor.set_range(&prefix)?;
            while let Some((key, _)) = entry
                && key.starts_with(&prefix)
            {
                if filter.wants_kind(tag_key_kind(key)) {
                    keys.push(key.to_vec());
                }
                entry = cursor.next_nodup()?;
            }
        }
        let exact = filter.authors.is_none() && filter.tags.len() == 1 && filter.search.is_none();
        candidates.push(Plan {
            db: t.tags,
            keys,
            exact,
            // One value's keys are each for another kind.
            disjoint: values.len() == 1,
        });
    }
    // A search's extensions, those that can be looked up. Each event has
    // one value of each facet, so one key per kind.
    for condition in filter.search.iter().flat_map(|s| &s.conditions) {
        let Some((start, prefix)) = condition.lookup(&store.indexed_tags) else {
            continue;
        };
        let mut keys = Vec::new();
        let mut cursor = txn.cursor(t.facets)?;
        let mut entry = cursor.set_range(&start)?;
        while let Some((key, _)) = entry
            && key.starts_with(&prefix)
        {
            if filter.wants_kind(tag_key_kind(key)) {
                keys.push(key.to_vec());
            }
            entry = cursor.next_nodup()?;
        }
        candidates.push(Plan {
            db: t.facets,
            keys,
            exact: false,
            disjoint: true,
        });
    }
    if let Some(kinds) = &filter.kinds {
        let keys = kinds.iter().map(|k| k.to_be_bytes().to_vec()).collect();
        candidates.push(Plan {
            db: t.kinds,
            keys,
            exact: filter.authors.is_none() && no_tags,
            disjoint: true,
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
            exact: filter.search.is_none() && no_hidden,
            disjoint: true,
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

    let distinct = filter.search.as_ref().is_some_and(|s| s.distinct_author);
    let mut authors = HashSet::new();
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
        if (plan.exact || filter.matches(&view)) && (!distinct || authors.insert(*view.pubkey())) {
            found.push((seq, view));
        }
    }
    Ok(())
}

/// What a NIP-45 count found.
#[derive(Debug, PartialEq)]
pub struct Count {
    pub count: u64,
    /// For a single filter with a tag, a sketch of the events' authors.
    pub hll: Option<Registers>,
}

/// A count that would examine more than the relay allows.
#[derive(Debug)]
pub struct TooExpensive;

impl std::fmt::Display for TooExpensive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("too expensive to count")
    }
}

impl std::error::Error for TooExpensive {}

/// An event found that the connection may not see.
#[derive(Debug)]
pub struct Restricted;

impl std::fmt::Display for Restricted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("found an event the connection may not see")
    }
}

impl std::error::Error for Restricted {}

/// Count the events matching any of a COUNT's filters. Fails with
/// [`TooExpensive`] when that's too much work, and with [`Restricted`] if
/// an event looked up by id isn't `visible`; others are hidden already.
pub fn count(
    store: &Store,
    search: Option<&SearchIndex>,
    filters: &[Filter],
    visible: impl Fn(&EventView) -> bool,
) -> anyhow::Result<Count> {
    let txn = store.read()?;
    let [filter] = filters else {
        // Events matching two filters count once.
        let mut seqs = HashSet::new();
        for filter in filters.iter().filter(|f| !f.never) {
            collect(store, &txn, search, filter, &visible, &mut seqs)?;
        }
        return Ok(Count {
            count: seqs.len() as u64,
            hll: None,
        });
    };

    if filter.never {
        return Ok(Count {
            count: 0,
            hll: filter.first_tag.as_ref().map(|_| [0; hll::REGISTERS]),
        });
    }
    let indexed = filter.ids.is_none()
        && filter
            .search
            .as_ref()
            .is_none_or(|search| search.terms.is_empty());
    let plan = match indexed {
        true => Some(plan(store, &txn, filter)?),
        false => None,
    };
    let Some(plan) = plan.filter(|plan| plan.exact) else {
        let mut seqs = HashSet::new();
        collect(store, &txn, search, filter, &visible, &mut seqs)?;
        let hll = match &filter.first_tag {
            Some(value) => Some(sketch(store, &txn, value, &seqs)?),
            None => None,
        };
        return Ok(Count {
            count: seqs.len() as u64,
            hll,
        });
    };

    let unbounded = filter.since == 0 && filter.until == u32::MAX;
    let count = if plan.disjoint && unbounded {
        let mut cursor = txn.cursor(plan.db)?;
        let mut total = 0;
        for key in &plan.keys {
            if cursor.set(key)?.is_some() {
                total += cursor.count()? as u64;
            }
        }
        total
    } else if plan.disjoint {
        let mut total = 0;
        walk(&txn, filter, &plan, |_| total += 1)?;
        total
    } else {
        let mut seqs = HashSet::new();
        walk(&txn, filter, &plan, |seq| {
            seqs.insert(seq);
        })?;
        seqs.len() as u64
    };

    let hll = match &filter.first_tag {
        None => None,
        // Just the one tag value: its keys' sketches, kept or made.
        Some(_) if plan.db == store.tables.tags && plan.disjoint && unbounded => {
            let mut registers = [0; hll::REGISTERS];
            for key in &plan.keys {
                hll::merge(&mut registers, &store.key_sketch(&txn, key)?);
            }
            Some(registers)
        }
        Some(value) if count as usize <= MAX_EXAMINED => {
            let mut seqs = HashSet::new();
            walk(&txn, filter, &plan, |seq| {
                seqs.insert(seq);
            })?;
            Some(sketch(store, &txn, value, &seqs)?)
        }
        Some(_) => None,
    };
    Ok(Count { count, hll })
}

/// Call `f` with the sequence number of each stamp of a plan's keys within
/// the filter's time bounds, up to [`MAX_WALKED`] of them.
fn walk(txn: &Txn, filter: &Filter, plan: &Plan, mut f: impl FnMut(u64)) -> anyhow::Result<()> {
    let mut walked = 0;
    for key in &plan.keys {
        each_stamp(txn, plan.db, key, filter.since, filter.until, |stamp| {
            walked += 1;
            f(stamp_seq(stamp));
            walked <= MAX_WALKED
        })?;
        if walked > MAX_WALKED {
            return Err(TooExpensive.into());
        }
    }
    Ok(())
}

/// Add the sequence numbers of the events matching a filter to `out`.
fn collect(
    store: &Store,
    txn: &Txn,
    search: Option<&SearchIndex>,
    filter: &Filter,
    visible: impl Fn(&EventView) -> bool,
    out: &mut HashSet<u64>,
) -> anyhow::Result<()> {
    if let Some(ids) = &filter.ids {
        for id in ids {
            if let Some(seq) = store.seq_of(txn, id)?
                && let Some(view) = store.load(txn, seq)?
                && filter.matches(&view)
            {
                if !visible(&view) {
                    return Err(Restricted.into());
                }
                out.insert(seq);
            }
        }
        return Ok(());
    }
    if let Some(query) = filter.search.as_ref().filter(|s| !s.terms.is_empty()) {
        return match search {
            Some(search) => search.collect(store, txn, filter, query, out),
            None => Ok(()),
        };
    }
    let plan = plan(store, txn, filter)?;
    if plan.exact {
        return walk(txn, filter, &plan, |seq| {
            out.insert(seq);
        });
    }
    let mut seqs = Vec::new();
    walk(txn, filter, &plan, |seq| {
        if !out.contains(&seq) {
            seqs.push(seq);
        }
    })?;
    seqs.sort_unstable();
    seqs.dedup();
    if seqs.len() > MAX_EXAMINED {
        return Err(TooExpensive.into());
    }
    for seq in seqs {
        if store
            .load(txn, seq)?
            .is_some_and(|view| filter.matches(&view))
        {
            out.insert(seq);
        }
    }
    Ok(())
}

/// Sketch the authors of some events, for a filter whose first tag value
/// is `value`.
fn sketch(store: &Store, txn: &Txn, value: &str, seqs: &HashSet<u64>) -> Result<Registers> {
    let offset = hll::offset(value);
    let mut registers = [0; hll::REGISTERS];
    for &seq in seqs {
        if let Some(view) = store.load(txn, seq)? {
            hll::add(&mut registers, offset, view.pubkey());
        }
    }
    Ok(registers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::store::tests::{MAX_VALUES, open, put, put_at, test_tags};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use serde_json::{Value, json};

    fn ids(store: &Store, filters: &[Value], max_limit: u64) -> Vec<String> {
        let filters: Vec<Filter> = filters
            .iter()
            .map(|f| Filter::parse(f, &test_tags(), MAX_VALUES).unwrap())
            .collect();
        found(store, &filters, max_limit)
    }

    fn found(store: &Store, filters: &[Filter], max_limit: u64) -> Vec<String> {
        let results = run(store, None, filters, max_limit, max_limit, |_| true).unwrap();
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
        let plan_for = |filter: Value| {
            plan(
                &store,
                &txn,
                &Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap(),
            )
            .unwrap()
        };

        // The rare tag beats the author with twenty events, and needs checking.
        let p = plan_for(json!({"authors": [alice], "#t": ["rare"]}));
        assert_eq!(p.keys, [tag_key("t", b"\0rare", Some(1))]);
        assert!(!p.exact);
        // A tag is keyed by kind, so with kinds or without, it's exact.
        let p = plan_for(json!({"#t": ["common"], "kinds": [1, 7]}));
        assert_eq!(p.keys, [tag_key("t", b"\0common", Some(1))]);
        assert!(p.exact && p.disjoint);
        let p = plan_for(json!({"#t": ["rare", "common"]}));
        assert_eq!(p.keys.len(), 2);
        assert!(p.exact && !p.disjoint);
        assert!(
            plan_for(json!({"#t": ["common"], "kinds": [7]}))
                .keys
                .is_empty()
        );
        // Author and kind together, exactly.
        let p = plan_for(json!({"authors": [alice], "kinds": [1]}));
        assert_eq!(p.keys[0].len(), 34);
        assert!(p.exact);
        assert_eq!(plan_for(json!({"since": 5})).keys, [CREATED]);
        // A search is checked whatever the index.
        assert!(!plan_for(json!({"kinds": [1], "search": "-x"})).exact);
        assert!(!plan_for(json!({"search": "-x"})).exact);
        // Its extensions are looked up when that's cheapest.
        assert_eq!(plan_for(json!({"search": "tag:t"})).db, store.tables.facets);
        let p = plan_for(json!({"search": "tag:t", "#t": ["common"]}));
        assert_eq!(p.db, store.tables.tags);
        let p = plan_for(json!({"search": "media:true", "kinds": [1]}));
        assert!(p.db == store.tables.facets && p.keys.is_empty());
        assert!(!p.exact);
        assert_eq!(
            plan_for(json!({"search": "-media:true"})).db,
            store.tables.created
        );
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
    /// Some filters naming no kinds have kind 4 hidden.
    #[test]
    fn agrees_with_brute_force() {
        let (_dir, store) = open();
        let mut rng = StdRng::seed_from_u64(7);
        let topics = ["a", "b", "c", "d"];
        let mut all = Vec::new();
        for i in 0..300 {
            let seed = rng.random_range(1..4);
            let kind = [1, 4, 7, 1111][rng.random_range(0..4)];
            let mut tags = vec![];
            for _ in 0..rng.random_range(0..3) {
                tags.push(vec!["t", topics[rng.random_range(0..4)]]);
            }
            if rng.random_bool(0.3) {
                tags.push(vec!["title", topics[rng.random_range(0..4)]]);
            }
            // What search extensions look for.
            if rng.random_bool(0.3) {
                let m = ["m image/png", "m video/mp4"][rng.random_range(0..2)];
                tags.push(vec!["imeta", "url https://x.com/a", m]);
            }
            if rng.random_bool(0.1) {
                tags.push(vec!["t", "nsfw"]);
            }
            if rng.random_bool(0.2) {
                tags.push(vec!["content-warning"]);
            }
            if rng.random_bool(0.2) {
                tags.push(vec![
                    "proxy",
                    "x",
                    ["rss", "activitypub"][rng.random_range(0..2)],
                ]);
            }
            // Ids start with as many zeros as they happen to.
            if rng.random_bool(0.5) {
                tags.push(vec!["nonce", "1"]);
            }
            let content = match rng.random_bool(0.2) {
                true => format!("{i} https://x.com/{i}.mp4"),
                false => i.to_string(),
            };
            let event = signed(seed, rng.random_range(100..160), kind, tags, &content);
            put(&store, &event);
            all.push(event);
        }
        let pubkeys: Vec<String> = (1..4)
            .map(|seed| signed(seed, 0, 1, vec![], "").pubkey)
            .collect();

        let random_filter = |rng: &mut StdRng| {
            let mut filter = serde_json::Map::new();
            if rng.random_bool(0.5) {
                filter.insert("authors".into(), json!(pubkeys[..rng.random_range(1..3)]));
            }
            if rng.random_bool(0.5) {
                let kind = [1, 4, 7, 1111][rng.random_range(0..4)];
                filter.insert("kinds".into(), json!([kind, 9]));
            }
            if rng.random_bool(0.5) {
                filter.insert("#t".into(), json!(topics[..rng.random_range(1..4)]));
            }
            if rng.random_bool(0.2) {
                filter.insert("#title".into(), json!([topics[rng.random_range(0..4)]]));
            }
            if rng.random_bool(0.3) {
                filter.insert("since".into(), json!(rng.random_range(100..160)));
            }
            if rng.random_bool(0.3) {
                filter.insert("until".into(), json!(rng.random_range(100..160)));
            }
            if rng.random_bool(0.5) {
                let extensions = [
                    "media:true",
                    "-media:true",
                    "video:true",
                    "-video:true",
                    "pow:1",
                    "pow:2",
                    "-pow:1",
                    "tag:title",
                    "-tag:t",
                    "tag:content-warning",
                    "protocol:nostr",
                    "protocol:rss",
                    "-protocol:nostr",
                    "nsfw:false",
                    "-mp4",
                ];
                let search: Vec<&str> = (0..rng.random_range(1..3))
                    .map(|_| extensions[rng.random_range(0..extensions.len())])
                    .collect();
                filter.insert("search".into(), json!(search.join(" ")));
            }
            let limit = rng.random_range(1..40);
            filter.insert("limit".into(), json!(limit));
            (Value::Object(filter), limit, rng.random_bool(0.5))
        };
        let parse = |filter: &Value, hide: bool| {
            let mut parsed = Filter::parse(filter, &test_tags(), MAX_VALUES).unwrap();
            if hide && parsed.kinds.is_none() {
                parsed.hidden_kinds = vec![4];
            }
            parsed
        };
        let matching = |filter: &Value, hide: bool| -> Vec<&Event> {
            let parsed = parse(filter, hide);
            all.iter()
                .filter(|e| {
                    let record = crate::record::encode(e);
                    parsed.matches(&EventView::new(&record).unwrap())
                })
                .collect()
        };

        for _ in 0..300 {
            let (filter, limit, hide) = random_filter(&mut rng);
            let mut expected = matching(&filter, hide);

            // Counted, with every match's author sketched.
            let parsed = parse(&filter, hide);
            let counted = count(&store, None, std::slice::from_ref(&parsed), |_| true).unwrap();
            let hll = parsed.first_tag.as_ref().map(|value| {
                let mut registers = [0; hll::REGISTERS];
                for event in &expected {
                    let pubkey = hex::decode(&event.pubkey).unwrap().try_into().unwrap();
                    hll::add(&mut registers, hll::offset(value), &pubkey);
                }
                registers
            });
            let want = Count {
                count: expected.len() as u64,
                hll,
            };
            assert_eq!(counted, want, "{filter}");

            // Two filters count their union.
            let (other, _, hide_other) = random_filter(&mut rng);
            let union: HashSet<&str> = expected
                .iter()
                .chain(&matching(&other, hide_other))
                .map(|e| e.id.as_str())
                .collect();
            let filters = [parsed.clone(), parse(&other, hide_other)];
            let counted = count(&store, None, &filters, |_| true).unwrap();
            assert_eq!(counted.count, union.len() as u64, "{filter} {other}");

            expected.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let expected: Vec<String> = expected.iter().take(limit).map(|e| e.id.clone()).collect();
            assert_eq!(found(&store, &[parsed], 500), expected, "{filter}");
        }
    }

    fn count_of(store: &Store, filter: Value) -> Count {
        count(
            store,
            None,
            &[Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap()],
            |_| true,
        )
        .unwrap()
    }

    #[test]
    fn counts_followers_as_they_come_and_go() {
        let (_dir, store) = open();
        let alice = signed(9, 0, 1, vec![], "").pubkey;
        let bob = signed(8, 0, 1, vec![], "").pubkey;
        for seed in 1..=3 {
            put(
                &store,
                &signed(seed, 100, 3, vec![vec!["p", &alice], vec!["p", &bob]], ""),
            );
        }
        // A mention isn't a follow.
        put(&store, &signed(4, 100, 1, vec![vec!["p", &alice]], ""));
        let followers = json!({"#p": [alice], "kinds": [3]});
        assert_eq!(count_of(&store, followers.clone()).count, 3);
        assert_eq!(count_of(&store, json!({"#p": [alice]})).count, 4);
        assert_eq!(count_of(&store, json!({"#p": [alice, bob]})).count, 4);

        // Unfollowing replaces the list.
        put(&store, &signed(1, 200, 3, vec![vec!["p", &bob]], ""));
        assert_eq!(count_of(&store, followers.clone()).count, 2);
        assert_eq!(
            count_of(&store, json!({"#p": [bob], "kinds": [3]})).count,
            3
        );
        let recent = json!({"#p": [bob], "kinds": [3], "since": 150});
        assert_eq!(count_of(&store, recent).count, 1);
        assert_eq!(count_of(&store, json!({"kinds": [3]})).count, 3);
        assert_eq!(count_of(&store, json!({})).count, 4);
    }

    #[test]
    fn sketches_with_kept_registers() {
        let (_dir, store) = open();
        let target = "ab".repeat(32);
        let mut sketch = [0; hll::REGISTERS];
        let n = crate::store::HLL_THRESHOLD as u32 + 50;
        for i in 0..n {
            let mut secret = [2; 32];
            secret[28..].copy_from_slice(&i.to_be_bytes());
            let kind = if i % 2 == 0 { 7 } else { 6 };
            let tags = vec![vec!["e".to_string(), target.clone()]];
            let event = crate::event::tests::sign(secret, 100, kind, tags, "+");
            put(&store, &event);
            if kind == 7 {
                let pubkey = hex::decode(&event.pubkey).unwrap().try_into().unwrap();
                hll::add(&mut sketch, hll::offset(&target), &pubkey);
            }
        }
        // Kind 7's key is past the threshold, kind 6's isn't: one kept, one
        // made, merged.
        let both = count_of(&store, json!({"#e": [target], "kinds": [6, 7]}));
        assert_eq!(both.count, u64::from(n));
        let reactions = count_of(&store, json!({"#e": [target], "kinds": [7]}));
        assert_eq!(reactions.count, u64::from(n.div_ceil(2)));
        assert_eq!(reactions.hll, Some(sketch));
        let estimate = hll::estimate(&both.hll.unwrap());
        assert!((900.0..1200.0).contains(&estimate), "{estimate}");
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
    fn finds_history_by_address_or_id() {
        let (_dir, store) = open();
        let profiles: Vec<Event> = [100, 300, 200]
            .iter()
            .map(|&at| signed(1, at, 0, vec![vec!["t", "x"]], &at.to_string()))
            .collect();
        let articles: Vec<Event> = [100, 200]
            .iter()
            .map(|&at| signed(1, at, 30_023, vec![vec!["d", "a"]], &at.to_string()))
            .collect();
        let other = signed(1, 150, 30_023, vec![vec!["d", "b"]], "");
        for event in profiles.iter().chain(&articles).chain([&other]) {
            put(&store, event);
        }
        let alice = &profiles[0].pubkey;
        let [p100, p300, p200] = [0, 1, 2].map(|i| profiles[i].id.as_str());

        // Every version of the address, newest first.
        let address = json!({"kinds": [0], "authors": [alice]});
        assert_eq!(
            ids(&store, std::slice::from_ref(&address), 100),
            [p300, p200, p100]
        );
        assert_eq!(count_of(&store, address).count, 3);
        let limited = json!({"kinds": [0], "authors": [alice], "limit": 1});
        assert_eq!(ids(&store, &[limited], 100), [p300]);
        let since = json!({"kinds": [0], "authors": [alice], "since": 200});
        assert_eq!(ids(&store, &[since], 100), [p300, p200]);
        let article = json!({"kinds": [30_023], "authors": [alice], "#d": ["a"]});
        assert_eq!(
            ids(&store, &[article], 100),
            [articles[1].id.as_str(), &articles[0].id]
        );

        // Anything else sees the current versions only.
        assert_eq!(ids(&store, &[json!({"kinds": [0]})], 100), [p300]);
        assert_eq!(ids(&store, &[json!({"#t": ["x"]})], 100), [p300]);
        assert_eq!(count_of(&store, json!({"#t": ["x"]})).count, 1);
        let both = json!({"kinds": [30_023], "authors": [alice], "#d": ["a", "b"]});
        assert_eq!(
            ids(&store, &[both], 100),
            [articles[1].id.as_str(), &other.id]
        );
        let kinds = json!({"kinds": [0, 30_023], "authors": [alice]});
        assert_eq!(ids(&store, &[kinds], 100).len(), 3);

        // An old version by id.
        let by_id = json!({"ids": [p100]});
        assert_eq!(ids(&store, std::slice::from_ref(&by_id), 100), [p100]);
        assert_eq!(count_of(&store, by_id).count, 1);
    }

    #[test]
    fn hides_expired_events() {
        let (_dir, store) = open();
        let now = crate::event::now();
        let past = (now - 10).to_string();
        let expired = signed(1, 100, 1, vec![vec!["expiration", &past]], "");
        let kept = signed(1, 200, 1, vec![], "");
        put_at(&store, &expired, now - 20);
        put(&store, &kept);
        assert_eq!(
            ids(&store, &[json!({"kinds": [1]})], 100),
            [kept.id.as_str()]
        );
        assert!(ids(&store, &[json!({"ids": [expired.id]})], 100).is_empty());

        // A count from the index alone includes it until it's swept.
        assert_eq!(count_of(&store, json!({"kinds": [1]})).count, 2);
        let mut txn = store.write().unwrap();
        store.expire(&mut txn, now, 100).unwrap();
        txn.commit().unwrap();
        assert_eq!(count_of(&store, json!({"kinds": [1]})).count, 1);
    }

    #[test]
    fn refuses_events_found_that_are_not_visible() {
        let (_dir, store) = open();
        let dm = signed(1, 100, 4, vec![], "");
        let note = signed(1, 200, 1, vec![], "");
        put(&store, &dm);
        put(&store, &note);
        let visible = |view: &EventView| view.kind() != 4;
        let parse = |filter| Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap();

        let filters = [parse(json!({"ids": [dm.id, note.id]}))];
        let err = run(&store, None, &filters, 100, 100, visible)
            .err()
            .unwrap();
        assert!(err.is::<Restricted>());
        let err = count(&store, None, &filters, visible).err().unwrap();
        assert!(err.is::<Restricted>());

        let filters = [parse(json!({"ids": [note.id]}))];
        assert_eq!(
            run(&store, None, &filters, 100, 100, visible)
                .unwrap()
                .events
                .len(),
            1
        );
        assert_eq!(count(&store, None, &filters, visible).unwrap().count, 1);
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
