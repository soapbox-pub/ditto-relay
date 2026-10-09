//! Answering filters from the store.
//!
//! Each filter gets one index to scan. The candidates are the ones its
//! fields allow — author and kind together, author, each tag, kind — and
//! since every index key's stamps are counted by LMDB for free, the planner
//! simply adds up the counts of each candidate's keys and takes the
//! smallest. If that index pins down every field the filter has, its
//! entries need no further checking. `authors` entries carry their kind,
//! so it pins down kinds too, skipping the others' entries without loading
//! them: that's how authors with too many kinds for `author_kinds` are
//! answered.
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
//! so many; past that, the relay declines. With `distinct:author`, a count
//! is of the authors of the events found as without it, each read for its
//! author, up to a bound of its own.
//!
//! A query stops as soon as nobody wants its results — its subscription
//! closed or replaced, or its client gone — rather than running on to its
//! limits: scans and walks look every so often whether it's been
//! cancelled.

use std::collections::{BinaryHeap, HashSet};

use secp256k1::Keypair;
use tokio_util::sync::CancellationToken;

use crate::event::KindClass;
use crate::filter::Filter;
use crate::hll::{self, Registers};
use crate::lmdb::{Cursor, Db, Entry, Result, Txn};
use crate::metrics::METRICS;
use crate::record::EventView;
use crate::search::SearchIndex;
use crate::store::{
    CREATED, MAX_SEQ, STAMP_LEN, Stamp, Store, address, each_stamp, entry_kind, stamp,
    stamp_created_at, stamp_seq, tag_key, tag_key_kind,
};

/// The most author × kind keys a filter may be planned over together, if
/// it has more than one kind. With one, there are no more of them than
/// authors.
const MAX_AUTHOR_KINDS: usize = 4096;

/// The most records one filter may examine. Only filters whose fields the
/// index can't pin down examine records that don't match, and this bounds
/// how long one of those can hold a reader.
pub const MAX_EXAMINED: usize = 100_000;

/// The most stamps a count may walk.
const MAX_WALKED: usize = 2_000_000;

/// The most events a `distinct:author` count may read the authors of.
const MAX_AUTHORED: usize = 1_000_000;

/// How many records a scan examines, or stamps a walk goes through,
/// between looks at whether its query's been cancelled.
const CANCEL_CHECK: usize = 256;

/// A query stopped because nobody wants its results any more.
#[derive(Debug)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for Cancelled {}

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
/// With the relay's `keypair`, the [NIP-85](crate::nip85) assertions they
/// ask it for are made and follow what's stored. Fails with [`Cancelled`]
/// once `cancel` is.
pub fn run(
    store: &Store,
    search: Option<&SearchIndex>,
    keypair: Option<&Keypair>,
    filters: &[Filter],
    default_limit: u64,
    max_limit: u64,
    cancel: &CancellationToken,
) -> anyhow::Result<Results> {
    let txn = store.read()?;
    let next_seq = store.next_seq(&txn)?;
    let mut seen = HashSet::new();
    // Asked twice, an assertion is the same event.
    let mut asserted = HashSet::new();
    let now = crate::event::now();
    let mut events = Vec::new();
    for filter in filters {
        if cancel.is_cancelled() {
            return Err(Cancelled.into());
        }
        let limit = filter.limit.unwrap_or(default_limit).min(max_limit) as usize;
        if filter.never || limit == 0 {
            continue;
        }
        let filter = &*crate::rank::windowed(store, filter);
        let found = match (&filter.search, &filter.ids) {
            (Some(query), None) if !query.terms.is_empty() => match search {
                Some(search) => search.run(store, &txn, filter, query, limit)?,
                None => Vec::new(),
            },
            (Some(query), _) if query.sort.is_ranked() => {
                crate::rank::run(store, &txn, filter, limit, cancel)?
            }
            _ => run_filter(store, &txn, filter, limit, cancel)?,
        };
        let left = limit - found.len().min(limit);
        for (seq, view) in found {
            if seen.insert(seq) {
                events.push(view.to_json());
            }
        }
        if let Some(keypair) = keypair {
            for (id, json) in crate::nip85::run(store, &txn, keypair, filter, left, now)? {
                if asserted.insert(id) {
                    events.push(json);
                }
            }
        }
    }
    if cancel.is_cancelled() {
        return Err(Cancelled.into());
    }
    Ok(Results { next_seq, events })
}

/// A filter's newest matches, up to `limit` (and any tied with the last).
/// Stops early, with what it's found so far, once `cancel` is cancelled.
pub fn run_filter<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    limit: usize,
    cancel: &CancellationToken,
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
        if scan(
            store,
            txn,
            filter,
            &plan,
            limit,
            MAX_EXAMINED,
            cancel,
            &mut found,
        )? {
            METRICS.filters_cut_short.inc();
        }
    }
    Ok(newest_first(found, limit))
}

/// A filter's newest matches, as [`run_filter`] finds them, if it finds
/// them all by examining at most `budget` records. A search's text is
/// checked event by event, which for a common term is quicker than
/// looking it up, and finds what isn't searchable yet too.
pub fn newest<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    limit: usize,
    budget: usize,
    cancel: &CancellationToken,
) -> Result<Option<Vec<(u64, EventView<'t>)>>> {
    if filter.ids.is_some() {
        return run_filter(store, txn, filter, limit, cancel).map(Some);
    }
    let plan = plan(store, txn, filter)?;
    let mut found = Vec::new();
    if scan(store, txn, filter, &plan, limit, budget, cancel, &mut found)? {
        return Ok(None);
    }
    Ok(Some(newest_first(found, limit)))
}

/// Newest first; on a tie, the lowest id first (NIP-01). Up to `limit`.
fn newest_first(mut found: Vec<(u64, EventView<'_>)>, limit: usize) -> Vec<(u64, EventView<'_>)> {
    found.sort_unstable_by(|(_, a), (_, b)| {
        b.created_at()
            .cmp(&a.created_at())
            .then_with(|| a.id().cmp(b.id()))
    });
    found.truncate(limit);
    found
}

/// The sequence numbers of every event the index entries a filter would be
/// answered from point to, within its time bounds, without reading any
/// records: a superset of its matches, sorted. None if there are more than
/// `max`, or it names ids.
pub fn candidates(
    store: &Store,
    txn: &Txn,
    filter: &Filter,
    max: usize,
) -> Result<Option<Vec<u64>>> {
    if filter.ids.is_some() {
        return Ok(None);
    }
    let plan = plan(store, txn, filter)?;
    if cost(txn, &plan, max + 1)? > max {
        return Ok(None);
    }
    let mut seqs = Vec::new();
    for key in &plan.keys {
        each_stamp(txn, plan.db, key, filter.since, filter.until, |entry| {
            if plan.wants(entry) {
                seqs.push(stamp_seq(entry));
            }
            true
        })?;
    }
    seqs.sort_unstable();
    seqs.dedup();
    Ok(Some(seqs))
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
    /// The kinds wanted, checked against the kind in each entry: for
    /// `authors` with kinds.
    kinds: Option<Vec<u16>>,
}

impl Plan {
    fn wants(&self, entry: &[u8]) -> bool {
        wants(self.kinds.as_deref(), entry)
    }
}

fn wants(kinds: Option<&[u16]>, entry: &[u8]) -> bool {
    match (kinds, entry_kind(entry)) {
        (Some(kinds), Some(kind)) => kinds.binary_search(&kind).is_ok(),
        _ => true,
    }
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
            kinds: None,
        });
    }
    let mut candidates = Vec::new();
    // A search is never pinned down by an index.
    let no_tags = filter.tags.is_empty() && filter.search.is_none();

    if let (Some(authors), Some(kinds)) = (&filter.authors, &filter.kinds)
        && (kinds.len() == 1 || authors.len() * kinds.len() <= MAX_AUTHOR_KINDS)
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
            kinds: None,
        });
    }
    if let Some(authors) = &filter.authors {
        let keys = authors.iter().map(|a| a.to_vec()).collect();
        candidates.push(Plan {
            db: t.authors,
            keys,
            exact: no_tags,
            disjoint: true,
            kinds: filter.kinds.clone(),
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
            kinds: None,
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
            kinds: None,
        });
    }
    if let Some(kinds) = &filter.kinds {
        let keys = kinds.iter().map(|k| k.to_be_bytes().to_vec()).collect();
        candidates.push(Plan {
            db: t.kinds,
            keys,
            exact: filter.authors.is_none() && no_tags,
            disjoint: true,
            kinds: None,
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
            exact: filter.search.is_none(),
            disjoint: true,
            kinds: None,
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

/// One key's stamps, newest first, of the kinds wanted.
struct Source<'t, 'p> {
    cursor: Cursor<'t>,
    kinds: Option<&'p [u16]>,
}

impl<'t, 'p> Source<'t, 'p> {
    /// Position at the newest stamp no later than `until`.
    fn start(
        txn: &'t Txn,
        plan: &'p Plan,
        key: &[u8],
        until: u32,
    ) -> Result<Option<(Stamp, Source<'t, 'p>)>> {
        let mut cursor = txn.cursor(plan.db)?;
        let entry = match cursor.get_both_range(key, &stamp(until, MAX_SEQ))? {
            Some(_) => cursor.prev_dup()?,
            None => match cursor.set(key)? {
                Some(_) => cursor.last_dup()?,
                None => None,
            },
        };
        let mut source = Source {
            cursor,
            kinds: plan.kinds.as_deref(),
        };
        Ok(source.wanted(entry)?.map(|stamp| (stamp, source)))
    }

    fn next(&mut self) -> Result<Option<Stamp>> {
        let entry = self.cursor.prev_dup()?;
        self.wanted(entry)
    }

    /// The stamp of `entry`, or the newest before it, of a kind wanted.
    fn wanted(&mut self, mut entry: Option<Entry<'t>>) -> Result<Option<Stamp>> {
        while let Some((_, value)) = entry {
            if wants(self.kinds, value) {
                return Ok(value[..STAMP_LEN].try_into().ok());
            }
            entry = self.cursor.prev_dup()?;
        }
        Ok(None)
    }
}

/// Find a plan's newest matches, examining at most `max_examined` records.
/// Returns whether it stopped for that, short of the limit.
#[allow(clippy::too_many_arguments)]
fn scan<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    plan: &Plan,
    limit: usize,
    max_examined: usize,
    cancel: &CancellationToken,
    found: &mut Vec<(u64, EventView<'t>)>,
) -> Result<bool> {
    let mut sources = Vec::new();
    let mut heap = BinaryHeap::new();
    for key in &plan.keys {
        if let Some((stamp, source)) = Source::start(txn, plan, key, filter.until)? {
            heap.push((stamp, sources.len()));
            sources.push(source);
        }
    }

    let distinct = filter.search.as_ref().is_some_and(|s| s.distinct_author);
    let mut authors = HashSet::new();
    let mut last = None;
    let mut examined = 0;
    let mut cut_short = false;
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
        if examined > max_examined {
            cut_short = true;
            break;
        }
        if examined % CANCEL_CHECK == 0 && cancel.is_cancelled() {
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
    METRICS
        .events_examined
        .add(examined.min(max_examined) as u64);
    Ok(cut_short)
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

/// Count the events matching any of a COUNT's filters. Fails with
/// [`TooExpensive`] when that's too much work, and with [`Cancelled`] once
/// `cancel` is.
pub fn count(
    store: &Store,
    search: Option<&SearchIndex>,
    filters: &[Filter],
    cancel: &CancellationToken,
) -> anyhow::Result<Count> {
    let count = count_unless_cancelled(store, search, filters, cancel)?;
    match cancel.is_cancelled() {
        true => Err(Cancelled.into()),
        false => Ok(count),
    }
}

fn count_unless_cancelled(
    store: &Store,
    search: Option<&SearchIndex>,
    filters: &[Filter],
    cancel: &CancellationToken,
) -> anyhow::Result<Count> {
    let txn = store.read()?;
    if filters.iter().any(Filter::distinct_author) {
        return count_authors(store, &txn, search, filters, cancel);
    }
    let [filter] = filters else {
        // Events matching two filters count once.
        let mut seqs = HashSet::new();
        for filter in filters.iter().filter(|f| !f.never) {
            collect(store, &txn, search, filter, cancel, &mut seqs)?;
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
        collect(store, &txn, search, filter, cancel, &mut seqs)?;
        let hll = match &filter.first_tag {
            Some(value) => Some(sketch(store, &txn, value, &seqs)?),
            None => None,
        };
        return Ok(Count {
            count: seqs.len() as u64,
            hll,
        });
    };

    // LMDB's counts are of every kind.
    let unbounded = filter.since == 0 && filter.until == u32::MAX && plan.kinds.is_none();
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
        walk(&txn, filter, &plan, cancel, |_| total += 1)?;
        total
    } else {
        let mut seqs = HashSet::new();
        walk(&txn, filter, &plan, cancel, |seq| {
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
            walk(&txn, filter, &plan, cancel, |seq| {
                seqs.insert(seq);
            })?;
            Some(sketch(store, &txn, value, &seqs)?)
        }
        Some(_) => None,
    };
    Ok(Count { count, hll })
}

/// Call `f` with the sequence number of each stamp of a plan's keys within
/// the filter's time bounds, of the kinds it wants, walking up to
/// [`MAX_WALKED`] of them, until `cancel` is cancelled.
fn walk(
    txn: &Txn,
    filter: &Filter,
    plan: &Plan,
    cancel: &CancellationToken,
    mut f: impl FnMut(u64),
) -> anyhow::Result<()> {
    let mut walked = 0;
    for key in &plan.keys {
        each_stamp(txn, plan.db, key, filter.since, filter.until, |entry| {
            walked += 1;
            if plan.wants(entry) {
                f(stamp_seq(entry));
            }
            walked <= MAX_WALKED && (walked % CANCEL_CHECK != 0 || !cancel.is_cancelled())
        })?;
        if walked > MAX_WALKED {
            return Err(TooExpensive.into());
        }
        if cancel.is_cancelled() {
            return Err(Cancelled.into());
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
    cancel: &CancellationToken,
    out: &mut HashSet<u64>,
) -> anyhow::Result<()> {
    if let Some(ids) = &filter.ids {
        for id in ids {
            if let Some(seq) = store.seq_of(txn, id)?
                && let Some(view) = store.load(txn, seq)?
                && filter.matches(&view)
            {
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
        return walk(txn, filter, &plan, cancel, |seq| {
            out.insert(seq);
        });
    }
    let mut seqs = Vec::new();
    walk(txn, filter, &plan, cancel, |seq| {
        if !out.contains(&seq) {
            seqs.push(seq);
        }
    })?;
    seqs.sort_unstable();
    seqs.dedup();
    if seqs.len() > MAX_EXAMINED {
        return Err(TooExpensive.into());
    }
    METRICS.events_examined.add(seqs.len() as u64);
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

/// Count the authors of the events matching any of a COUNT's filters, for
/// one any of whose filters has `distinct:author`. Their events are found
/// as without it, so an index pins down as many filters as it would, and
/// only each event's header is read, for its author.
fn count_authors(
    store: &Store,
    txn: &Txn,
    search: Option<&SearchIndex>,
    filters: &[Filter],
    cancel: &CancellationToken,
) -> anyhow::Result<Count> {
    let mut seqs = HashSet::new();
    for filter in filters.iter().filter(|f| !f.never) {
        collect(store, txn, search, &filter.every_event(), cancel, &mut seqs)?;
    }
    if seqs.len() > MAX_AUTHORED {
        return Err(TooExpensive.into());
    }
    let mut seqs: Vec<u64> = seqs.into_iter().collect();
    seqs.sort_unstable();
    store.read_ahead(&seqs);
    METRICS.events_examined.add(seqs.len() as u64);

    // NIP-45 sketches a single filter's authors, which these all are.
    let offset = match filters {
        [filter] => filter.first_tag.as_deref().map(hll::offset),
        _ => None,
    };
    let mut registers = [0; hll::REGISTERS];
    let mut authors = HashSet::new();
    for (i, &seq) in seqs.iter().enumerate() {
        if i % CANCEL_CHECK == 0 && cancel.is_cancelled() {
            return Err(Cancelled.into());
        }
        let Some(header) = store.header(txn, seq)? else {
            continue;
        };
        if authors.insert(*header.pubkey())
            && let Some(offset) = offset
        {
            hll::add(&mut registers, offset, header.pubkey());
        }
    }
    Ok(Count {
        count: authors.len() as u64,
        hll: offset.map(|_| registers),
    })
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
        let results = run(
            store,
            None,
            None,
            filters,
            max_limit,
            max_limit,
            &Default::default(),
        )
        .unwrap();
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
        // Past what `author_kinds` takes, authors, with the kinds checked
        // in the index: still exact.
        let kinds: Vec<u16> = (1..=MAX_AUTHOR_KINDS as u16 + 1).collect();
        let p = plan_for(json!({"authors": [alice], "kinds": kinds}));
        assert_eq!(p.db, store.tables.authors);
        assert!(p.exact && p.kinds.is_some());
        // But one kind's keys are never more than the authors'.
        let authors: Vec<String> = (0..MAX_AUTHOR_KINDS + 1)
            .map(|i| format!("{i:064x}"))
            .chain([alice.clone()])
            .collect();
        let p = plan_for(json!({"authors": authors, "kinds": [1]}));
        assert_eq!(p.db, store.tables.author_kinds);
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
            } else if rng.random_bool(0.2) {
                // Too many for `author_kinds`, with authors.
                let kinds: Vec<u16> = (0..700).filter(|k| k % 7 != 0).collect();
                filter.insert("kinds".into(), json!(kinds));
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
            (Value::Object(filter), limit)
        };
        let parse = |filter: &Value| Filter::parse(filter, &test_tags(), MAX_VALUES).unwrap();
        let records: Vec<Vec<u8>> = all.iter().map(crate::record::encode).collect();
        let matching = |filter: &Value| -> Vec<&Event> {
            let parsed = parse(filter);
            all.iter()
                .zip(&records)
                .filter(|(_, record)| parsed.matches(&EventView::new(record).unwrap()))
                .map(|(e, _)| e)
                .collect()
        };

        for _ in 0..300 {
            let (filter, limit) = random_filter(&mut rng);
            let mut expected = matching(&filter);

            // Counted, with every match's author sketched.
            let parsed = parse(&filter);
            let counted = count(
                &store,
                None,
                std::slice::from_ref(&parsed),
                &Default::default(),
            )
            .unwrap();
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
            let (other, _) = random_filter(&mut rng);
            let union: HashSet<&str> = expected
                .iter()
                .chain(&matching(&other))
                .map(|e| e.id.as_str())
                .collect();
            let filters = [parsed.clone(), parse(&other)];
            let counted = count(&store, None, &filters, &Default::default()).unwrap();
            assert_eq!(counted.count, union.len() as u64, "{filter} {other}");

            // Asked for distinct authors, a count is of the authors.
            let mut distinct = filter.clone();
            let search = distinct.get("search").and_then(Value::as_str).unwrap_or("");
            distinct["search"] = json!(format!("{search} distinct:author"));
            let authors: HashSet<&str> = expected.iter().map(|e| e.pubkey.as_str()).collect();
            let counted = count_of(&store, distinct.clone());
            assert_eq!(counted.count, authors.len() as u64, "{distinct}");
            assert_eq!(counted.hll, want.hll, "{distinct}");
            let filters = [parse(&distinct), parse(&other)];
            let counted = count(&store, None, &filters, &Default::default()).unwrap();
            let authors: HashSet<&str> = expected
                .iter()
                .chain(&matching(&other))
                .map(|e| e.pubkey.as_str())
                .collect();
            assert_eq!(counted.count, authors.len() as u64, "{distinct} {other}");

            expected.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let expected: Vec<String> = expected.iter().take(limit).map(|e| e.id.clone()).collect();
            assert_eq!(found(&store, &[parsed], 500), expected, "{filter}");
        }
    }

    #[test]
    fn checks_kinds_in_the_authors_index() {
        let (_dir, store) = open();
        for i in 0..10 {
            put(
                &store,
                &signed(1, 100 + i, [1, 7][i as usize % 2], vec![], ""),
            );
        }
        // Others' notes make `kinds` the dearer index.
        for i in 0..20 {
            put(&store, &signed(2, 100 + i, 1, vec![], ""));
        }
        let alice = signed(1, 0, 1, vec![], "").pubkey;
        // Every kind but 7, too many for `author_kinds`.
        let kinds: Vec<u16> = (1..=MAX_AUTHOR_KINDS as u16 + 2)
            .filter(|&k| k != 7)
            .collect();
        let filter = json!({"authors": [alice], "kinds": kinds});
        let parsed = Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap();
        let p = plan(&store, &store.read().unwrap(), &parsed).unwrap();
        assert_eq!(p.db, store.tables.authors);

        assert_eq!(ids(&store, std::slice::from_ref(&filter), 100).len(), 5);
        assert_eq!(count_of(&store, filter.clone()).count, 5);
        let since = json!({"authors": [alice], "kinds": kinds, "since": 105});
        assert_eq!(ids(&store, std::slice::from_ref(&since), 100).len(), 2);
        assert_eq!(count_of(&store, since).count, 2);
    }

    fn count_of(store: &Store, filter: Value) -> Count {
        count(
            store,
            None,
            &[Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap()],
            &Default::default(),
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
    fn stops_when_cancelled() {
        let (_dir, store) = open();
        for i in 0..1000 {
            put(&store, &signed(1, 100 + i, 1, vec![], ""));
        }
        let filter = Filter::parse(&json!({"kinds": [1]}), &test_tags(), MAX_VALUES).unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let filters = std::slice::from_ref(&filter);
        let ran = run(&store, None, None, filters, 500, 500, &cancel);
        assert!(ran.err().unwrap().is::<Cancelled>());
        let counted = count(&store, None, filters, &cancel);
        assert!(counted.err().unwrap().is::<Cancelled>());
        // Stopped scanning a page in.
        let txn = store.read().unwrap();
        let found = run_filter(&store, &txn, &filter, 500, &cancel).unwrap();
        assert_eq!(found.len(), CANCEL_CHECK - 1);
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
    fn finds_by_language_and_sentiment() {
        let (_dir, store) = open();
        let happy = signed(
            1,
            100,
            1,
            vec![],
            "I love this, what a wonderful and happy day!",
        );
        let sad = signed(
            2,
            200,
            1,
            vec![],
            "This is terrible, I hate it and feel awful.",
        );
        let spanish = signed(1, 300, 1, vec![], "Buenos días, ¿cómo están todos?");
        let like = signed(3, 400, 7, vec![], "🤙");
        for event in [&happy, &sad, &spanish, &like] {
            put(&store, event);
        }
        let search = |text: &str| ids(&store, &[json!({"search": text})], 100);
        assert_eq!(search("language:es"), [spanish.id.as_str()]);
        assert_eq!(search("language:EN"), [sad.id.as_str(), &happy.id]);
        assert_eq!(search("sentiment:positive"), [like.id.as_str(), &happy.id]);
        assert_eq!(
            search("sentiment:positive language:en"),
            [happy.id.as_str()]
        );
        assert_eq!(
            search("-sentiment:positive"),
            [spanish.id.as_str(), &sad.id]
        );
        assert_eq!(count_of(&store, json!({"search": "-language:en"})).count, 2);
    }

    /// A reaction is found by the last `p` tag, its target's author, and
    /// not by those copied from what it reacts to, whichever index answers;
    /// any other event by every `p` tag.
    #[test]
    fn finds_reactions_by_their_targets_author() {
        let (_dir, store) = open();
        let [copied, other, target] = [1, 2, 3].map(|n| hex::encode([n; 32]));
        let tags = vec![
            vec!["p", copied.as_str()],
            vec!["e", "ab"],
            vec!["p", other.as_str()],
            vec!["p", target.as_str()],
        ];
        let reaction = signed(9, 100, 7, tags.clone(), "+");
        let note = signed(9, 100, 1, tags, "hi");
        put(&store, &reaction);
        put(&store, &note);
        // Others tagging each, so that a filter naming the author is
        // answered from the author's events, checked one by one.
        let mut others = Vec::new();
        for p in [&copied, &other, &target] {
            for n in 0..5 {
                let event = signed(8, 101 + n, 1, vec![vec!["p", p.as_str()]], "");
                put(&store, &event);
                others.push((p, event.id));
            }
        }
        let author = reaction.pubkey.clone();
        for (p, theirs) in [
            (&target, vec![&reaction.id, &note.id]),
            (&copied, vec![&note.id]),
            (&other, vec![&note.id]),
        ] {
            let everyones: Vec<&String> =
                others.iter().filter(|o| o.0 == p).map(|o| &o.1).collect();
            for (filter, want) in [
                (
                    json!({"#p": [p]}),
                    [theirs.clone(), everyones.clone()].concat(),
                ),
                (json!({"#p": [p], "authors": [author]}), theirs.clone()),
                (
                    json!({"#p": [p], "kinds": [1, 7]}),
                    [theirs.clone(), everyones.clone()].concat(),
                ),
            ] {
                let mut got = ids(&store, std::slice::from_ref(&filter), 100);
                got.sort();
                let mut want: Vec<String> = want.iter().map(|id| id.to_string()).collect();
                want.sort();
                assert_eq!(got, want, "{filter}");
                assert_eq!(count_of(&store, filter).count, want.len() as u64);
            }
        }
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
