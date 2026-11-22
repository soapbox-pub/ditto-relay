//! Index changes kept in memory until they're merged into LMDB.
//!
//! Storing an event puts its stamp under a dozen keys of the indexes, each
//! put a search of a B-tree and a copy of the pages on its way; a batch of
//! them merged into LMDB at once, in order, costs a fraction of that. So the
//! writer files changes to the indexes here, in the *active* [`Layer`], and
//! every so often freezes it and merges it into LMDB in one transaction.
//!
//! An entry added is a record with the id of the write transaction that
//! added it; one removed, the id of the one that removed it, too, and a
//! *tombstone* if what's removed is in an older layer or in LMDB. Values
//! carry sequence numbers, so an entry is only ever added once, and the
//! newest layer to say anything of it decides it.
//!
//! Commits are numbered by the store, not by LMDB's transaction ids, which
//! start again lower in a [repacked](crate::repack) copy. A reader takes
//! the layers, then its LMDB transaction, and sees through [`Snap`] what
//! was committed by the commit it reads: the records of the commits up to
//! it, in the layers not merged into LMDB by then. A layer merged by the
//! commit read is in LMDB already, so it's skipped; one merged later is
//! read here, as LMDB hasn't it yet for that reader.
//!
//! The writer files changes as it makes them, under the id its transaction
//! will commit as, so no reader sees them until it has; if the transaction
//! is aborted they're [rolled back](Memtable::rollback), found by that id.

use std::collections::{BTreeMap, BTreeSet, btree_map};

use smallvec::SmallVec;
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};

use arc_swap::ArcSwap;

use crate::lmdb::{Cursor, Db, Result, RwTxn, Txn};

/// The indexes kept here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ix {
    Ids,
    Created,
    Kinds,
    Authors,
    AuthorKinds,
    Tags,
    Facets,
}

const IXS: usize = 7;

impl Ix {
    /// As a byte, to keep.
    pub fn byte(self) -> u8 {
        ALL.iter().position(|&ix| ix == self).expect("an index") as u8
    }

    pub fn from_byte(byte: u8) -> Option<Ix> {
        ALL.get(usize::from(byte)).copied()
    }
}

/// Not removed, or a layer not merged.
const NEVER: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rec {
    /// The commit that added it here, 0 if it wasn't.
    added: u64,
    /// The commit that removed it, or [`NEVER`].
    removed: u64,
}

/// A value, kept inline: stamps, with a kind or not, and sequence numbers.
/// Its bytes, zeroes after, then its length: so they sort as one number,
/// as the bytes would, a shorter value before a longer it starts.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Val {
    bytes: [u8; VAL + 1],
}

const VAL: usize = 15;

impl Val {
    fn new(value: &[u8]) -> Val {
        assert!(value.len() <= VAL, "a value too long to keep");
        let mut bytes = [0; VAL + 1];
        bytes[..value.len()].copy_from_slice(value);
        bytes[VAL] = value.len() as u8;
        Val { bytes }
    }

    fn get(&self) -> &[u8] {
        &self.bytes[..usize::from(self.bytes[VAL])]
    }
}

impl Ord for Val {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u128::from_be_bytes(self.bytes).cmp(&u128::from_be_bytes(other.bytes))
    }
}

impl PartialOrd for Val {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Rec {
    /// Whether it's of an entry kept elsewhere, removed here.
    fn tombstone(&self) -> bool {
        self.added == 0
    }

    /// What it adds to its key's count of entries, once every commit it
    /// was changed by is read.
    fn net(rec: Option<Rec>) -> i64 {
        match rec {
            Some(rec) if rec.removed == NEVER => 1,
            Some(rec) if rec.tombstone() => -1,
            _ => 0,
        }
    }

    /// Whether a reader of the commit `at` sees it added, removed, or
    /// neither: then an older layer, or LMDB, decides.
    fn decided(&self, at: u64) -> Option<bool> {
        if self.removed <= at {
            Some(false)
        } else if !self.tombstone() && self.added <= at {
            Some(true)
        } else {
            None
        }
    }
}

/// A key's records in a layer.
#[derive(Default)]
struct Dups {
    vals: Vals,
    tombstones: u32,
    /// What the records add to the key's count, after each of the latest
    /// commits to change it, so that a reader a few commits behind needn't
    /// count them. Kept only once they're many, or a record was changed in
    /// a way it doesn't itself say: until then, as for most keys, they're
    /// counted.
    counts: Option<Box<Counts>>,
}

/// A key's records, in the order of their values: inline in a sorted list
/// while there are few, as most keys have, in a B-tree past [`SMALL`],
/// as values come out of order.
enum Vals {
    /// One kept inline, as most keys have one, every event's id.
    Small(SmallVec<[(Val, Rec); 1]>),
    Big(BTreeMap<Val, Rec>),
}

/// The most records a key keeps in a list. Few under test, to test both.
const SMALL: usize = if cfg!(test) { 4 } else { 32 };

impl Default for Vals {
    fn default() -> Self {
        Vals::Small(SmallVec::new())
    }
}

impl Vals {
    fn get(&self, value: &Val) -> Option<&Rec> {
        match self {
            Vals::Small(list) => list
                .binary_search_by(|(v, _)| v.cmp(value))
                .ok()
                .map(|i| &list[i].1),
            Vals::Big(map) => map.get(value),
        }
    }

    /// Set `value`'s record to what `f` makes of the one it has, if any,
    /// returning both.
    fn upsert(&mut self, value: Val, f: impl FnOnce(Option<Rec>) -> Rec) -> (Option<Rec>, Rec) {
        if let Vals::Small(list) = self
            && list.len() >= SMALL
        {
            *self = Vals::Big(std::mem::take(list).into_iter().collect());
        }
        match self {
            Vals::Small(list) => match list.binary_search_by(|(v, _)| v.cmp(&value)) {
                Ok(i) => {
                    let before = list[i].1;
                    let after = f(Some(before));
                    list[i].1 = after;
                    (Some(before), after)
                }
                Err(i) => {
                    let after = f(None);
                    list.insert(i, (value, after));
                    (None, after)
                }
            },
            Vals::Big(map) => match map.entry(value) {
                btree_map::Entry::Occupied(mut entry) => {
                    let before = *entry.get();
                    let after = f(Some(before));
                    *entry.get_mut() = after;
                    (Some(before), after)
                }
                btree_map::Entry::Vacant(entry) => {
                    let after = f(None);
                    entry.insert(after);
                    (None, after)
                }
            },
        }
    }

    fn len(&self) -> usize {
        match self {
            Vals::Small(list) => list.len(),
            Vals::Big(map) => map.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn values(&self) -> Box<dyn Iterator<Item = &Rec> + '_> {
        match self {
            Vals::Small(list) => Box::new(list.iter().map(|(_, rec)| rec)),
            Vals::Big(map) => Box::new(map.values()),
        }
    }

    fn iter(&self) -> Box<dyn DoubleEndedIterator<Item = (&Val, &Rec)> + '_> {
        match self {
            Vals::Small(list) => Box::new(list.iter().map(|(value, rec)| (value, rec))),
            Vals::Big(map) => Box::new(map.iter()),
        }
    }

    fn retain(&mut self, mut f: impl FnMut(&mut Rec) -> bool) {
        match self {
            Vals::Small(list) => list.retain_mut(|(_, rec)| f(rec)),
            Vals::Big(map) => map.retain(|_, rec| f(rec)),
        }
    }

    /// The records of values from `low` to `high`.
    fn range(
        &self,
        (low, high): (Bound<Val>, Bound<Val>),
    ) -> Box<dyn DoubleEndedIterator<Item = (&Val, &Rec)> + '_> {
        match self {
            Vals::Small(list) => {
                let start = match low {
                    Bound::Included(low) => list.partition_point(|(v, _)| *v < low),
                    Bound::Excluded(low) => list.partition_point(|(v, _)| *v <= low),
                    Bound::Unbounded => 0,
                };
                let end = match high {
                    Bound::Included(high) => list.partition_point(|(v, _)| *v <= high),
                    Bound::Excluded(high) => list.partition_point(|(v, _)| *v < high),
                    Bound::Unbounded => list.len(),
                };
                Box::new(
                    list[start..end.max(start)]
                        .iter()
                        .map(|(value, rec)| (value, rec)),
                )
            }
            // A range that's empty, as the B-tree won't take one.
            Vals::Big(_) if empty(low, high) => Box::new(std::iter::empty()),
            Vals::Big(map) => Box::new(map.range((low, high))),
        }
    }
}

/// Whether no value is between `low` and `high`, as they're ordered.
fn empty(low: Bound<Val>, high: Bound<Val>) -> bool {
    match (low, high) {
        (Bound::Included(low), Bound::Included(high)) => low > high,
        (
            Bound::Included(low) | Bound::Excluded(low),
            Bound::Included(high) | Bound::Excluded(high),
        ) => low >= high,
        _ => false,
    }
}

/// How many commits' counts a key keeps.
const COUNTS: usize = 4;

/// The counts of a key's latest commits, oldest first.
#[derive(Default)]
struct Counts {
    counts: [(u64, i64); COUNTS],
    len: usize,
    /// Whether the counts of older commits were let go of, or never kept.
    trimmed: bool,
}

impl Counts {
    fn as_slice(&self) -> &[(u64, i64)] {
        &self.counts[..self.len]
    }

    fn last(&self) -> Option<&(u64, i64)> {
        self.as_slice().last()
    }

    fn last_mut(&mut self) -> Option<&mut (u64, i64)> {
        self.counts[..self.len].last_mut()
    }

    fn iter(&self) -> std::slice::Iter<'_, (u64, i64)> {
        self.as_slice().iter()
    }

    /// Push a commit's count, letting go of the oldest to make room.
    fn push(&mut self, count: (u64, i64)) {
        if self.len == COUNTS {
            self.counts.rotate_left(1);
            self.len -= 1;
            self.trimmed = true;
        }
        self.counts[self.len] = count;
        self.len += 1;
    }

    fn pop(&mut self) {
        self.len = self.len.saturating_sub(1);
    }
}

impl Dups {
    /// Keep counts from now on, as of before `value`'s record was changed
    /// from `before` by the commit `at`, then after: those of the last few
    /// commits to change the count, as kept all along.
    fn start_counts(&mut self, at: u64, value: &Val, before: Option<Rec>) {
        let recs = || {
            self.vals
                .iter()
                .filter(|(v, _)| *v != value)
                .map(|(_, rec)| rec)
                .chain(before.as_ref())
        };
        let mut commits: Vec<u64> = recs()
            .flat_map(|rec| [rec.added, rec.removed])
            .filter(|&commit| commit != 0 && commit != NEVER && commit < at)
            .collect();
        commits.sort_unstable();
        commits.dedup();
        let mut counts = Counts::default();
        let mut last = 0;
        for commit in commits {
            let count = Self::counted(recs(), commit);
            if count != last {
                counts.push((commit, count));
                last = count;
            }
        }
        counts.push((at, Self::counted(self.vals.values(), at)));
        self.counts = Some(Box::new(counts));
    }

    /// What the records add to the key's count, for a reader of `at`.
    fn net(&self, at: u64) -> i64 {
        if let Some(counts) = &self.counts {
            match counts.iter().rev().find(|(commit, _)| *commit <= at) {
                Some(&(_, net)) => return net,
                None if !counts.trimmed => return 0,
                None => {}
            }
        }
        Self::counted(self.vals.values(), at)
    }

    /// What `recs` add to the key's count, for a reader of `at`, as they
    /// say.
    fn counted<'a>(recs: impl Iterator<Item = &'a Rec>, at: u64) -> i64 {
        recs.map(|rec| match rec.decided(at) {
            Some(true) => 1,
            Some(false) if rec.tombstone() => -1,
            _ => 0,
        })
        .sum()
    }

    /// Note that the commit `at` changed the record of `value` from
    /// `before` to `after`.
    fn count(&mut self, at: u64, value: &Val, before: Option<Rec>, after: Rec) {
        let Some(counts) = &mut self.counts else {
            // A record added, or a live one removed, still says when.
            let says = match before {
                None => true,
                Some(before) => before.removed == NEVER && after.added == before.added,
            };
            if !says || matches!(self.vals, Vals::Big(_)) {
                self.start_counts(at, value, before);
            }
            return;
        };
        let net = Rec::net(Some(after)) - Rec::net(before);
        if net == 0 {
            return;
        }
        match counts.last_mut() {
            Some((commit, count)) if *commit == at => *count += net,
            last => {
                let count = last.map_or(0, |(_, count)| *count) + net;
                counts.push((at, count));
            }
        }
    }
}

/// An index's records in a layer, by key, looked up by hashing. Readers
/// look through a range of keys only in `facets`, so its keys are kept in
/// order beside; and in `tags`, only for those of one value, of each kind
/// it's filed under, so those kinds are kept by value. A merge sorts the
/// rest when it comes to them. Keeping every key in order cost the writer
/// more than anything else it did, events bringing new keys all the time.
struct Table {
    ix: Ix,
    dups: hashbrown::HashMap<Arc<[u8]>, Dups>,
    order: Option<Mutex<Order>>,
    /// For `tags`, the kinds of the keys of each tag value, by the hash
    /// of its key without one: see [`tag_kinds`].
    kinds: Option<hashbrown::HashMap<u64, SmallVec<[u16; 2]>>>,
}

/// Whether `key` is a tag's name and value whole, as [`crate::store::tag_key`]
/// makes it without a kind: so that the keys starting with it are each
/// for one kind.
fn is_tag_value(key: &[u8]) -> bool {
    let Some(&name) = key.first() else {
        return false;
    };
    let at = 1 + usize::from(name);
    key.get(at)
        .is_some_and(|&value| key.len() == at + 1 + usize::from(value))
}

/// A `tags` key's tag name and value, its kind left off, and the kind.
fn split_kind(key: &[u8]) -> Option<(&[u8], u16)> {
    let (value, kind) = key.split_last_chunk::<2>()?;
    Some((value, u16::from_be_bytes(*kind)))
}

/// What a tag value's kinds are kept by: a hash of its key without a kind.
/// One shared by another value only has its keys looked up for nothing.
fn tag_kinds(value: &[u8]) -> u64 {
    use std::hash::BuildHasher;
    foldhash::fast::FixedState::with_seed(0).hash_one(value)
}

/// A table's keys in order: the newest, fewer than [`UNSORTED`], wait
/// unsorted, and the writer sorts them in once that many do, so that
/// neither filing a key nor reading them in order waits on many.
#[derive(Default)]
struct Order {
    sorted: BTreeSet<Arc<[u8]>>,
    unsorted: Vec<Arc<[u8]>>,
}

/// How many new keys wait unsorted at most. Few under test, to test both.
const UNSORTED: usize = if cfg!(test) { 4 } else { 1024 };

impl Order {
    fn sort(&mut self) -> &BTreeSet<Arc<[u8]>> {
        self.unsorted.sort_unstable();
        self.sorted.extend(self.unsorted.drain(..));
        &self.sorted
    }

    /// The keys from `from` that start with `prefix`, in no order.
    fn from(&self, from: &[u8], prefix: &[u8]) -> Vec<Arc<[u8]>> {
        let mut keys: Vec<Arc<[u8]>> = self
            .sorted
            .range::<[u8], _>((Bound::Included(from), Bound::Unbounded))
            .take_while(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        keys.extend(
            self.unsorted
                .iter()
                .filter(|key| key.starts_with(prefix) && &key[..] >= from)
                .cloned(),
        );
        keys
    }
}

impl Table {
    /// With room for `keys` keys.
    fn new(ix: Ix, keys: usize) -> Table {
        Table {
            ix,
            dups: hashbrown::HashMap::with_capacity_and_hasher(keys, Default::default()),
            order: (ix == Ix::Facets).then(|| {
                Mutex::new(Order {
                    sorted: BTreeSet::new(),
                    unsorted: Vec::with_capacity(keys),
                })
            }),
            kinds: (ix == Ix::Tags)
                .then(|| hashbrown::HashMap::with_capacity_and_hasher(keys, Default::default())),
        }
    }

    fn get(&self, key: &[u8]) -> Option<&Dups> {
        self.dups.get(key)
    }

    fn entry(&mut self, key: &[u8]) -> &mut Dups {
        let (order, kinds) = (&mut self.order, &mut self.kinds);
        self.dups.entry_ref(key).or_insert_with_key(|key| {
            if let Some(order) = order {
                let order = order.get_mut().expect("unpoisoned");
                order.unsorted.push(Arc::from(key));
                if order.unsorted.len() >= UNSORTED {
                    order.sort();
                }
            }
            if let Some(kinds) = kinds
                && let Some((value, kind)) = split_kind(key)
            {
                let of = kinds.entry(tag_kinds(value)).or_default();
                if !of.contains(&kind) {
                    of.push(kind);
                }
            }
            Dups::default()
        })
    }

    fn is_empty(&self) -> bool {
        self.dups.is_empty()
    }

    fn retain(&mut self, mut f: impl FnMut(&mut Dups) -> bool) {
        let mut gone = Vec::new();
        self.dups.retain(|key, dups| {
            let keep = f(dups);
            if !keep {
                gone.push(key.clone());
            }
            keep
        });
        if let Some(order) = &mut self.order
            && !gone.is_empty()
        {
            let order = order.get_mut().expect("unpoisoned");
            order.unsorted.retain(|key| !gone.contains(key));
            for key in &gone {
                order.sorted.remove(key);
            }
        }
        if let Some(kinds) = &mut self.kinds {
            for key in &gone {
                let Some((value, kind)) = split_kind(key) else {
                    continue;
                };
                let hash = tag_kinds(value);
                // Another value with the same hash may have the kind still.
                let mut probe = value.to_vec();
                probe.extend_from_slice(&kind.to_be_bytes());
                if self.dups.contains_key(&probe[..]) {
                    continue;
                }
                if let Some(of) = kinds.get_mut(&hash) {
                    of.retain(|k| *k != kind);
                    if of.is_empty() {
                        kinds.remove(&hash);
                    }
                }
            }
        }
    }

    /// Every key's records, in order.
    fn sorted(&self) -> Vec<(&[u8], &Dups)> {
        let mut all: Vec<(&[u8], &Dups)> = self
            .dups
            .iter()
            .map(|(key, dups)| (&key[..], dups))
            .collect();
        all.sort_unstable_by_key(|(key, _)| *key);
        all
    }

    /// The keys from `from` that start with `prefix`, with their records,
    /// in no order.
    fn keys_from(&self, from: &[u8], prefix: &[u8]) -> Vec<(Arc<[u8]>, &Dups)> {
        // A tag value's keys: one for each kind it's filed under.
        if let Some(kinds) = &self.kinds
            && from == prefix
            && is_tag_value(prefix)
        {
            let Some(of) = kinds.get(&tag_kinds(prefix)) else {
                return Vec::new();
            };
            let mut key = prefix.to_vec();
            return of
                .iter()
                .filter_map(|kind| {
                    key.truncate(prefix.len());
                    key.extend_from_slice(&kind.to_be_bytes());
                    self.dups.get_key_value(&key[..])
                })
                .map(|(key, dups)| (key.clone(), dups))
                .collect();
        }
        let Some(order) = &self.order else {
            return self
                .sorted()
                .into_iter()
                .filter(|(key, _)| *key >= from)
                .take_while(|(key, _)| key.starts_with(prefix))
                .map(|(key, dups)| (Arc::from(key), dups))
                .collect();
        };
        let keys = order.lock().expect("unpoisoned").from(from, prefix);
        keys.into_iter()
            .map(|key| {
                let dups = &self.dups[&key];
                (key, dups)
            })
            .collect()
    }
}

/// The changes of commits from one point to another.
pub struct Layer {
    tables: [RwLock<Table>; IXS],
    /// The commit that merged the last of it into LMDB, or [`NEVER`].
    merged_at: AtomicU64,
    /// The last key merged by each commit that merged some, in order:
    /// see [`Memtable::merge_slice`].
    marks: RwLock<Vec<(u64, Key)>>,
    records: AtomicUsize,
}

impl Layer {
    fn new() -> Layer {
        Self::sized(|_| 0)
    }

    /// With room for as many keys of each index as `keys` says.
    fn sized(keys: impl Fn(Ix) -> usize) -> Layer {
        Layer {
            tables: ALL.map(|ix| RwLock::new(Table::new(ix, keys(ix)))),
            merged_at: AtomicU64::new(NEVER),
            marks: RwLock::default(),
            records: AtomicUsize::new(0),
        }
    }

    /// The last of its keys a reader of `at` reads from LMDB, if any.
    fn merged_by(&self, at: u64) -> Option<Key> {
        let marks = self.marks.read().expect("unpoisoned");
        marks
            .iter()
            .rev()
            .find(|(commit, _)| *commit <= at)
            .map(|(_, key)| key.clone())
    }

    fn table(&self, ix: Ix) -> &RwLock<Table> {
        &self.tables[ix as usize]
    }
}

pub struct Memtable {
    /// Newest first: the active layer, then those frozen, not yet merged.
    layers: ArcSwap<Vec<Arc<Layer>>>,
    /// The write transaction filing changes, if one is, or [`NOT_FILING`].
    filing: AtomicU64,
    /// Its changes, as [`replay`](Self::replay) reads them.
    ops: Mutex<Vec<u8>>,
    /// The table each index is kept in, in LMDB.
    dbs: Arc<[(Db, Ix)]>,
    /// The frozen layer being merged, if one is.
    merging: Mutex<Option<Merging>>,
}

/// A key's values added in a layer being merged, packed, if they're all of
/// one size, as in a `DUP_FIXED` table they are.
#[derive(Default)]
struct Added {
    packed: Vec<u8>,
    size: usize,
    count: usize,
    uneven: Vec<Val>,
}

impl Added {
    fn push(&mut self, value: &[u8]) {
        if self.count == 0 {
            self.size = value.len();
        }
        if value.len() == self.size && self.uneven.is_empty() {
            self.packed.extend_from_slice(value);
        } else {
            self.uneven.push(Val::new(value));
        }
        self.count += 1;
    }

    /// Put them under `key`, those packed in one go if they're many.
    fn put(&self, txn: &mut RwTxn, db: Db, key: &[u8]) -> Result<()> {
        match self.count - self.uneven.len() {
            0 => {}
            1 => {
                txn.put_dup(db, key, &self.packed)?;
            }
            _ if self.size == 0 => {
                txn.put_dup(db, key, &[])?;
            }
            _ => txn.put_dups(db, key, &self.packed, self.size)?,
        }
        for value in &self.uneven {
            txn.put_dup(db, key, value.get())?;
        }
        Ok(())
    }
}

/// No write transaction is filing changes.
const NOT_FILING: u64 = 0;

/// A key of an index: a frozen layer's are merged in the order of their
/// index, then of the key.
pub type Key = (Ix, Arc<[u8]>);

fn after(a: (Ix, &[u8]), b: (Ix, &[u8])) -> bool {
    (a.0.byte(), a.1) > (b.0.byte(), b.1)
}

/// A frozen layer, merged into LMDB a slice of its keys at a time.
struct Merging {
    layer: Arc<Layer>,
    /// The last key merged, if any is.
    last: Option<Key>,
    /// The last commit whose changes are in it.
    through: u64,
    /// The keys of the table being merged, in order, if it doesn't keep
    /// them so.
    sorted: Option<(Ix, Vec<Arc<[u8]>>)>,
}

/// What a [slice](Memtable::merge_slice) merged.
pub struct Slice {
    /// How many entries.
    pub entries: usize,
    /// The last commit whose changes are in the layer it's of.
    pub through: u64,
    /// The last key it merged, or none if it merged the last.
    pub last: Option<Key>,
}

impl Default for Memtable {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl Memtable {
    /// With `dbs`, the table each index is kept in, in LMDB.
    pub fn new(dbs: Vec<(Db, Ix)>) -> Memtable {
        Memtable {
            layers: ArcSwap::from_pointee(vec![Arc::new(Layer::new())]),
            filing: AtomicU64::new(NOT_FILING),
            ops: Mutex::default(),
            dbs: dbs.into(),
            merging: Mutex::default(),
        }
    }

    /// The index kept in `db`, if it's one kept here.
    pub fn ix_of(&self, db: Db) -> Option<Ix> {
        self.dbs.iter().find(|(d, _)| *d == db).map(|(_, ix)| *ix)
    }

    /// What a reader whose transaction reads the commit `at`, begun after
    /// `layers` were [taken](Self::layers), sees.
    pub fn snap(&self, layers: &[Arc<Layer>], at: u64) -> Snap {
        let mut snap = Snap::new(layers, at);
        snap.dbs = self.dbs.clone();
        snap
    }

    /// The changes the transaction filing them made, to keep beside its
    /// commit, so that they're [replayed](Self::replay) if the relay stops
    /// before they're merged. Empty if it made none.
    pub fn take_ops(&self) -> Vec<u8> {
        let mut ops = self.ops.lock().expect("unpoisoned");
        let room = ops.len();
        std::mem::replace(&mut *ops, Vec::with_capacity(room))
    }

    /// File again changes [taken](Self::take_ops) from a commit, as of
    /// before any reader: they were committed.
    pub fn replay(&self, mut ops: &[u8]) -> Option<()> {
        let mut take = |n: usize| {
            let (head, tail) = ops.split_at_checked(n)?;
            ops = tail;
            Some(head)
        };
        while let Some(head) = take(4) {
            let ix = *ALL.get(usize::from(head[0]))?;
            let removed = head[1] == 1;
            let key = take(usize::from(u16::from_le_bytes([head[2], head[3]])))?.to_vec();
            let len = usize::from(*take(1)?.first()?);
            let value = take(len)?.to_vec();
            match removed {
                false => self.add(ix, &key, &value, 1),
                true => self.remove(ix, &key, &value, 1),
            }
        }
        self.commit();
        self.ops.lock().expect("unpoisoned").clear();
        Some(())
    }
    /// The layers, to take before the LMDB transaction a [`Snap`] goes
    /// with.
    pub fn layers(&self) -> Arc<Vec<Arc<Layer>>> {
        self.layers.load_full()
    }

    /// How many records the active layer holds.
    pub fn active_records(&self) -> usize {
        self.layers.load()[0].records.load(Ordering::Relaxed)
    }

    /// File an entry added by the write transaction `at`.
    pub fn add(&self, ix: Ix, key: &[u8], value: &[u8], at: u64) {
        let rec = Rec {
            added: at,
            removed: NEVER,
        };
        self.change(ix, key, value, at, false, |_| rec);
    }

    /// File an entry removed by the write transaction `at`: one added in
    /// the active layer is marked removed, anything else gets a tombstone.
    pub fn remove(&self, ix: Ix, key: &[u8], value: &[u8], at: u64) {
        self.change(ix, key, value, at, true, |before| Rec {
            added: before.map_or(0, |rec| rec.added),
            removed: at,
        });
    }

    fn change(
        &self,
        ix: Ix,
        key: &[u8],
        value: &[u8],
        at: u64,
        removing: bool,
        f: impl FnOnce(Option<Rec>) -> Rec,
    ) {
        self.filing.store(at, Ordering::Relaxed);
        {
            let mut ops = self.ops.lock().expect("unpoisoned");
            ops.push(ix.byte());
            ops.push(u8::from(removing));
            ops.extend_from_slice(&(key.len() as u16).to_le_bytes());
            ops.extend_from_slice(key);
            ops.push(value.len() as u8);
            ops.extend_from_slice(value);
        }
        let layers = self.layers.load();
        let active = &layers[0];
        let mut table = active.table(ix).write().expect("unpoisoned");
        let dups = table.entry(key);
        let val = Val::new(value);
        let (before, after) = dups.vals.upsert(val, f);
        if before.is_none() {
            // Only the writer changes it: no need to lock it.
            let records = active.records.load(Ordering::Relaxed);
            active.records.store(records + 1, Ordering::Relaxed);
        }
        if after.tombstone() && !before.is_some_and(|rec| rec.tombstone()) {
            dups.tombstones += 1;
        }
        dups.count(at, &val, before, after);
    }

    /// The transaction filing changes committed: keep them.
    pub fn commit(&self) {
        self.filing.store(NOT_FILING, Ordering::Relaxed);
    }

    /// The transaction filing changes was aborted: undo what it filed,
    /// known by its id.
    pub fn rollback(&self) {
        let at = self.filing.swap(NOT_FILING, Ordering::Relaxed);
        if at == NOT_FILING {
            return;
        }
        let layers = self.layers.load();
        let active = &layers[0];
        for ix in ALL {
            let mut table = active.table(ix).write().expect("unpoisoned");
            table.retain(|dups| {
                let counted = |dups: &Dups| {
                    dups.counts
                        .as_ref()
                        .and_then(|counts| counts.last())
                        .is_some_and(|(commit, _)| *commit == at)
                };
                if !counted(dups)
                    && !dups
                        .vals
                        .values()
                        .any(|rec| rec.added == at || rec.removed == at)
                {
                    return true;
                }
                dups.vals.retain(|rec| {
                    if rec.added == at || rec.tombstone() && rec.removed == at {
                        active.records.fetch_sub(1, Ordering::Relaxed);
                        return false;
                    }
                    if rec.removed == at {
                        rec.removed = NEVER;
                    }
                    true
                });
                if counted(dups)
                    && let Some(counts) = &mut dups.counts
                {
                    counts.pop();
                }
                dups.tombstones = dups.vals.values().filter(|rec| rec.tombstone()).count() as u32;
                !dups.vals.is_empty()
            });
        }
    }

    /// Whether a frozen layer is being merged.
    pub fn merging(&self) -> bool {
        self.merging.lock().expect("unpoisoned").is_some()
    }

    /// Freeze the active layer, with the changes of every commit through
    /// `through`, to be merged a slice at a time, behind a new one. Between
    /// write transactions; not while another is being merged.
    pub fn freeze(&self, through: u64) {
        let mut merging = self.merging.lock().expect("unpoisoned");
        assert!(merging.is_none(), "a layer is being merged");
        assert_eq!(self.filing.load(Ordering::Relaxed), NOT_FILING);
        let mut layers = Vec::clone(&self.layers.load());
        // As many keys as the last held, so it doesn't grow to them.
        let last = layers[0].clone();
        let keys = |ix| last.table(ix).read().expect("unpoisoned").dups.len();
        layers.insert(0, Arc::new(Layer::sized(keys)));
        self.layers.store(Arc::new(layers.clone()));
        *merging = Some(Merging {
            layer: layers[1].clone(),
            last: None,
            through,
            sorted: None,
        });
    }

    /// Merge into LMDB, with `txn`, the writer's, whose commit, `at`,
    /// they'll be merged by, the next keys of the frozen layer, whole,
    /// until about `budget` entries are: `db` is where each index is kept.
    /// Once `txn` commits, call [`sliced`](Self::sliced), or if it fails,
    /// [`unslice`](Self::unslice). None if no layer is frozen.
    pub fn merge_slice(
        &self,
        txn: &mut RwTxn,
        at: u64,
        budget: usize,
        db: impl Fn(Ix) -> Db,
    ) -> Result<Option<Slice>> {
        let mut merging = self.merging.lock().expect("unpoisoned");
        let Some(merging) = merging.as_mut() else {
            return Ok(None);
        };
        let layer = merging.layer.clone();
        let mut entries = 0;
        let mut last = merging.last.clone();
        let from = last.as_ref().map_or(0, |(ix, _)| usize::from(ix.byte()));
        // Whether it stopped for the budget, short of the end.
        let mut stopped = false;
        for ix in &ALL[from..] {
            let ix = *ix;
            let table = layer.table(ix).read().expect("unpoisoned");
            let past = last
                .as_ref()
                .filter(|(at, _)| *at == ix)
                .map(|(_, key)| key.clone());
            // The next keys, whole, till about `budget` entries are.
            let mut keys = Vec::new();
            let mut wanted = 0;
            let mut full = false;
            let mut take = |key: &Arc<[u8]>| {
                if wanted >= budget.saturating_sub(entries) && !(keys.is_empty() && entries == 0) {
                    full = true;
                    return false;
                }
                wanted += table.get(key).map_or(0, |dups| dups.vals.len());
                keys.push(key.clone());
                true
            };
            let from = match &past {
                Some(key) => Bound::Excluded(&key[..]),
                None => Bound::Unbounded,
            };
            match &table.order {
                Some(order) => {
                    let mut order = order.lock().expect("unpoisoned");
                    for key in order.sort().range::<[u8], _>((from, Bound::Unbounded)) {
                        if !take(key) {
                            break;
                        }
                    }
                }
                None => {
                    if merging.sorted.as_ref().is_none_or(|(of, _)| *of != ix) {
                        let mut keys: Vec<Arc<[u8]>> = table.dups.keys().cloned().collect();
                        keys.sort_unstable();
                        merging.sorted = Some((ix, keys));
                    }
                    let (_, sorted) = merging.sorted.as_ref().expect("just sorted");
                    let start = match &past {
                        Some(key) => sorted.partition_point(|k| k <= key),
                        None => 0,
                    };
                    for key in &sorted[start..] {
                        if !take(key) {
                            break;
                        }
                    }
                }
            }
            for key in keys {
                let dups = table.get(&key).expect("its key");
                // The values added, to put in one go: LMDB then finds the
                // key once rather than once a value.
                let mut added = Added::default();
                for (value, rec) in dups.vals.iter() {
                    let value = value.get();
                    match (rec.added != 0, rec.removed != NEVER) {
                        (true, false) if ix == Ix::Ids => {
                            txn.put(db(ix), &key, value)?;
                        }
                        (true, false) => added.push(value),
                        (false, true) if ix == Ix::Ids => {
                            txn.del(db(ix), &key, None)?;
                        }
                        (false, true) => {
                            txn.del(db(ix), &key, Some(value))?;
                        }
                        _ => {}
                    }
                    entries += 1;
                }
                added.put(txn, db(ix), &key)?;
                last = Some((ix, key));
            }
            if full || entries >= budget {
                stopped = true;
                break;
            }
        }
        let done = !stopped;
        // Readers of `at` on read what's merged from LMDB.
        match (&last, done) {
            (_, true) => layer.merged_at.store(at, Ordering::Release),
            (Some(last), false) => layer
                .marks
                .write()
                .expect("unpoisoned")
                .push((at, last.clone())),
            (None, false) => unreachable!("none merged, with some to"),
        }
        Ok(Some(Slice {
            entries,
            through: merging.through,
            last: (!done).then_some(last).flatten(),
        }))
    }

    /// The transaction [merging a slice](Self::merge_slice) committed.
    pub fn sliced(&self, slice: Slice) {
        let mut merging = self.merging.lock().expect("unpoisoned");
        let state = merging.as_mut().expect("merging");
        if slice.last.is_some() {
            state.last = slice.last;
        } else {
            let done = merging.take();
            let kept: Vec<Arc<Layer>> = self
                .layers
                .load()
                .iter()
                .filter(|layer| layer.merged_at.load(Ordering::Acquire) == NEVER)
                .cloned()
                .collect();
            let layers = self.layers.swap(Arc::new(kept));
            // Freeing a layer's records takes a tenth of a second: not the
            // writer's to wait on.
            std::thread::spawn(move || drop((done, layers)));
        }
    }

    /// The transaction [merging a slice](Self::merge_slice) failed: its
    /// commit is still to come, and its keys aren't in LMDB.
    pub fn unslice(&self) {
        let merging = self.merging.lock().expect("unpoisoned");
        let Some(merging) = merging.as_ref() else {
            return;
        };
        let layer = &merging.layer;
        let mut marks = layer.marks.write().expect("unpoisoned");
        if marks
            .last()
            .is_some_and(|(_, key)| Some(key) != merging.last.as_ref())
        {
            marks.pop();
        }
        layer.merged_at.store(NEVER, Ordering::Release);
    }

    /// The frozen layer's keys up to `last`, in the order they're merged,
    /// were merged before the store was last closed: LMDB has them.
    pub fn merged_through(&self, last: (Ix, &[u8])) {
        let mut merging = self.merging.lock().expect("unpoisoned");
        let merging = merging.as_mut().expect("merging");
        let last = (last.0, Arc::from(last.1));
        merging.last = Some(last.clone());
        merging
            .layer
            .marks
            .write()
            .expect("unpoisoned")
            .push((0, last));
    }

    /// How many records are kept in the active layer, and whether a frozen
    /// one is still being merged.
    pub fn unmerged(&self) -> (usize, bool) {
        (self.active_records(), self.merging())
    }
}

const ALL: [Ix; IXS] = [
    Ix::Ids,
    Ix::Created,
    Ix::Kinds,
    Ix::Authors,
    Ix::AuthorKinds,
    Ix::Tags,
    Ix::Facets,
];

/// The layers a reader whose LMDB transaction reads the commit `at` sees
/// through.
#[derive(Clone)]
pub struct Snap {
    layers: Vec<Arc<Layer>>,
    /// The last of each layer's keys read from LMDB, if any is.
    merged: Vec<Option<Key>>,
    at: u64,
    /// The table each index is kept in, in LMDB.
    dbs: Arc<[(Db, Ix)]>,
}

impl Snap {
    /// From layers [taken](Memtable::layers) before the transaction that
    /// reads `at` began.
    pub fn new(layers: &[Arc<Layer>], at: u64) -> Snap {
        let layers: Vec<Arc<Layer>> = layers
            .iter()
            .filter(|layer| layer.merged_at.load(Ordering::Acquire) > at)
            .cloned()
            .collect();
        Snap {
            merged: layers.iter().map(|layer| layer.merged_by(at)).collect(),
            layers,
            at,
            dbs: Arc::new([]),
        }
    }

    /// `key`'s records in the `i`th layer's `table`, unless they're read
    /// from LMDB: see [`Memtable::merge_slice`].
    fn of<'g>(&self, i: usize, table: &'g Table, key: &[u8]) -> Option<&'g Dups> {
        match self.shown(i, table.ix, key) {
            true => table.get(key),
            false => None,
        }
    }

    fn shown(&self, i: usize, ix: Ix, key: &[u8]) -> bool {
        match &self.merged[i] {
            None => true,
            Some((last, last_key)) => after((ix, key), (*last, last_key)),
        }
    }

    /// The commit it reads, or, writing, the one it will be.
    pub fn at(&self) -> u64 {
        self.at
    }

    /// The index kept in `db`, if the layers keep changes to it.
    pub fn ix_of(&self, db: Db) -> Option<Ix> {
        self.dbs.iter().find(|(d, _)| *d == db).map(|(_, ix)| *ix)
    }

    /// Whether the layers have nothing to say of `key`, so that LMDB alone
    /// has its entries.
    pub fn untouched(&self, ix: Ix, key: &[u8]) -> bool {
        self.layers.iter().enumerate().all(|(i, layer)| {
            self.of(i, &layer.table(ix).read().expect("unpoisoned"), key)
                .is_none()
        })
    }

    /// Whether the layers have anything to say of `ix` at all.
    fn quiet(&self, ix: Ix) -> bool {
        self.layers
            .iter()
            .all(|layer| layer.table(ix).read().expect("unpoisoned").is_empty())
    }

    /// The value of `key` in a table of one value a key, `ids`.
    pub fn get<'t>(&self, txn: &'t Txn, db: Db, ix: Ix, key: &[u8]) -> Result<Option<Value<'t>>> {
        if self.quiet(ix) {
            return Ok(txn.get(db, key)?.map(Value::Stored));
        }
        // One value a key, but an event stored again has a new one.
        let mut hidden = Vec::new();
        for (i, table) in self.tables(ix).iter().enumerate() {
            let Some(dups) = self.of(i, table, key) else {
                continue;
            };
            for (value, rec) in dups.vals.iter() {
                match rec.decided(self.at) {
                    Some(true) if !hidden.contains(value) => return Ok(Some(Value::Filed(*value))),
                    Some(false) => hidden.push(*value),
                    _ => {}
                }
            }
        }
        Ok(txn
            .get(db, key)?
            .filter(|value| value.len() > VAL || !hidden.contains(&Val::new(value)))
            .map(Value::Stored))
    }

    /// How many entries `key` has.
    pub fn count(&self, txn: &Txn, db: Db, ix: Ix, key: &[u8]) -> Result<usize> {
        let mut cursor = txn.cursor(db)?;
        let stored = match cursor.set(key)? {
            Some(_) => cursor.count()?,
            None => 0,
        };
        let net: i64 = self
            .layers
            .iter()
            .enumerate()
            .filter_map(|(i, layer)| {
                Some(
                    self.of(i, &layer.table(ix).read().expect("unpoisoned"), key)?
                        .net(self.at),
                )
            })
            .sum();
        Ok((stored as i64 + net).max(0) as usize)
    }

    /// The layers' tables of `ix`, newest first, to read.
    fn tables(&self, ix: Ix) -> Vec<RwLockReadGuard<'_, Table>> {
        self.layers
            .iter()
            .map(|layer| layer.table(ix).read().expect("unpoisoned"))
            .collect()
    }

    /// Whether the layers have `key` as having `value`, or not, or say
    /// nothing of it: then LMDB decides.
    fn decide(
        &self,
        tables: &[RwLockReadGuard<'_, Table>],
        key: &[u8],
        value: &Val,
    ) -> Option<bool> {
        tables
            .iter()
            .enumerate()
            .filter_map(|(i, table)| self.of(i, table, key)?.vals.get(value)?.decided(self.at))
            .next()
    }

    /// Whether `key` has the entry `value`.
    pub fn has(&self, txn: &Txn, db: Db, ix: Ix, key: &[u8], value: &[u8]) -> Result<bool> {
        if value.len() <= VAL
            && let Some(shown) = self.decide(&self.tables(ix), key, &Val::new(value))
        {
            return Ok(shown);
        }
        Ok(txn
            .cursor(db)?
            .get_both_range(key, value)?
            .is_some_and(|(_, found)| found == value))
    }

    /// Up to about `n` of `key`'s entries the layers add between `low` and
    /// `high`, in order, read from the top if `descending`, and where they
    /// stop short, if they do: more are past it.
    fn filed(
        &self,
        ix: Ix,
        key: &[u8],
        (low, high): (Bound<Val>, Bound<Val>),
        n: usize,
        descending: bool,
    ) -> (Vec<Val>, Option<Val>) {
        let tables = self.tables(ix);
        let mut found = Vec::new();
        let mut cut: Option<Val> = None;
        for (i, table) in tables.iter().enumerate() {
            let Some(dups) = self.of(i, table, key) else {
                continue;
            };
            // A newer layer may have removed what an older one added.
            let newer = &tables[..i];
            let checked = newer.iter().enumerate().any(|(j, table)| {
                self.of(j, table, key)
                    .is_some_and(|dups| dups.tombstones > 0)
            });
            let range = dups.vals.range((low, high));
            let entries: Box<dyn Iterator<Item = (&Val, &Rec)>> = match descending {
                true => Box::new(range.rev()),
                false => Box::new(range),
            };
            let mut taken = 0;
            for (value, rec) in entries {
                if rec.decided(self.at) != Some(true)
                    || checked && self.decide(newer, key, value) == Some(false)
                {
                    continue;
                }
                found.push(*value);
                taken += 1;
                if taken == n {
                    // Short of the rest: what's past here, of any layer,
                    // waits for the next read.
                    cut = Some(match (cut, descending) {
                        (Some(cut), true) => cut.max(*value),
                        (Some(cut), false) => cut.min(*value),
                        (None, _) => *value,
                    });
                    break;
                }
            }
        }
        if let Some(cut) = cut {
            found.retain(|value| match descending {
                true => *value >= cut,
                false => *value <= cut,
            });
        }
        found.sort_unstable();
        (found, cut)
    }

    /// Whether the layers have records of `key`, and whether they hide
    /// some of LMDB's entries of it.
    fn touched(&self, ix: Ix, key: &[u8]) -> (bool, bool) {
        let (mut touched, mut hiding) = (false, false);
        for (i, layer) in self.layers.iter().enumerate() {
            if let Some(dups) = self.of(i, &layer.table(ix).read().expect("unpoisoned"), key) {
                touched = true;
                hiding |= dups.tombstones > 0;
            }
        }
        (touched, hiding)
    }

    /// Whether the layers hide LMDB's entry `value` of `key`.
    fn hidden(&self, ix: Ix, key: &[u8], value: &[u8]) -> bool {
        value.len() <= VAL && self.decide(&self.tables(ix), key, &Val::new(value)) == Some(false)
    }

    /// `key`'s entries, newest first, from the last no greater than
    /// `from`.
    pub fn down<'t>(
        &'t self,
        txn: &'t Txn,
        db: Db,
        ix: Ix,
        key: &[u8],
        from: &[u8],
    ) -> Result<Down<'t>> {
        let mut cursor = txn.cursor(db)?;
        let entry = match cursor.get_both_range(key, from)? {
            Some((_, value)) if value == from => Some(value),
            Some(_) => cursor.prev_dup()?.map(|(_, value)| value),
            None => match cursor.set(key)? {
                Some(_) => cursor.last_dup()?.map(|(_, value)| value),
                None => None,
            },
        };
        let (touched, hiding) = self.touched(ix, key);
        Ok(Down {
            snap: self,
            ix,
            key: key.to_vec(),
            cursor,
            stored: entry,
            filed: Vec::new(),
            below: touched.then(|| Bound::Included(Val::new(from))),
            chunk: FIRST_CHUNK,
            hiding,
        })
    }

    /// Each of `key`'s entries from `low` to `high`, both included, oldest
    /// first, until `f` returns false.
    pub fn each(
        &self,
        txn: &Txn,
        db: Db,
        ix: Ix,
        key: &[u8],
        (low, high): (&[u8], &[u8]),
        mut f: impl FnMut(&[u8]) -> bool,
    ) -> Result<()> {
        let (touched, hiding) = self.touched(ix, key);
        let high_val = Bound::Included(Val::new(high));
        // Read from the top down, so the next to give is last.
        let mut filed: Vec<Val> = Vec::new();
        let mut above = touched.then(|| Bound::Included(Val::new(low)));
        let mut chunk = FIRST_CHUNK;
        let mut cursor = txn.cursor(db)?;
        let mut entry = cursor.get_both_range(key, low)?.map(|(_, value)| value);
        loop {
            if filed.is_empty()
                && let Some(from) = above.take()
            {
                let (found, cut) = self.filed(ix, key, (from, high_val), chunk, false);
                filed = found;
                filed.reverse();
                above = cut.map(Bound::Excluded);
                chunk = (chunk * 2).min(MAX_CHUNK);
            }
            let stored = entry.filter(|value| *value <= high);
            let take_filed = match (stored, filed.last()) {
                (None, None) => return Ok(()),
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (Some(stored), Some(next)) => next.get() < stored,
            };
            if take_filed {
                let value = filed.pop().expect("there's one");
                if !f(value.get()) {
                    return Ok(());
                }
            } else {
                let value = stored.expect("there's one");
                if !(hiding && self.hidden(ix, key, value)) && !f(value) {
                    return Ok(());
                }
                entry = cursor.next_dup()?.map(|(_, value)| value);
            }
        }
    }

    /// The keys from `from`, in order, up to the first that doesn't start
    /// with `prefix`, any with entries in the layers among them.
    pub fn keys(
        &self,
        txn: &Txn,
        db: Db,
        ix: Ix,
        from: &[u8],
        prefix: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        let mut cursor = txn.cursor(db)?;
        let mut entry = cursor.set_range(from)?;
        while let Some((key, _)) = entry {
            if !key.starts_with(prefix) {
                break;
            }
            keys.push(key.to_vec());
            entry = cursor.next_nodup()?;
        }
        if !self.quiet(ix) {
            for (i, layer) in self.layers.iter().enumerate() {
                let table = layer.table(ix).read().expect("unpoisoned");
                for (key, dups) in table.keys_from(from, prefix) {
                    let added = self.shown(i, ix, &key)
                        && dups
                            .vals
                            .values()
                            .any(|rec| rec.decided(self.at) == Some(true));
                    if added {
                        keys.push(key.to_vec());
                    }
                }
            }
            keys.sort_unstable();
            keys.dedup();
        }
        Ok(keys)
    }
}

/// A value, as LMDB has it, or as filed in a layer.
pub enum Value<'t> {
    Stored(&'t [u8]),
    Filed(Val),
}

impl std::ops::Deref for Value<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Value::Stored(value) => value,
            Value::Filed(value) => value.get(),
        }
    }
}

/// How many of a key's entries in the layers are read at first, then
/// twice as many each time, up to [`MAX_CHUNK`]: most reads want few.
// Small under test, to read across chunks.
const FIRST_CHUNK: usize = if cfg!(test) { 2 } else { 16 };
const MAX_CHUNK: usize = 1024;

/// A key's entries, newest first: see [`Snap::down`].
pub struct Down<'t> {
    snap: &'t Snap,
    ix: Ix,
    key: Vec<u8>,
    cursor: Cursor<'t>,
    stored: Option<&'t [u8]>,
    /// Entries the layers add, read so far, the next to give last.
    filed: Vec<Val>,
    /// Where the layers are to be read on from, down; none once they're
    /// read to the bottom.
    below: Option<Bound<Val>>,
    chunk: usize,
    /// Whether the layers hide some of LMDB's entries.
    hiding: bool,
}

impl<'t> Down<'t> {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Value<'t>>> {
        loop {
            if self.filed.is_empty()
                && let Some(from) = self.below.take()
            {
                let (found, cut) = self.snap.filed(
                    self.ix,
                    &self.key,
                    (Bound::Unbounded, from),
                    self.chunk,
                    true,
                );
                self.filed = found;
                self.below = cut.map(Bound::Excluded);
                self.chunk = (self.chunk * 2).min(MAX_CHUNK);
            }
            let take_filed = match (self.stored, self.filed.last()) {
                (None, None) => return Ok(None),
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (Some(stored), Some(filed)) => filed.get() > stored,
            };
            if take_filed {
                let value = self.filed.pop().expect("there's one");
                return Ok(Some(Value::Filed(value)));
            }
            let stored = self.stored.expect("there's one");
            self.stored = self.cursor.prev_dup()?.map(|(_, value)| value);
            if !(self.hiding && self.snap.hidden(self.ix, &self.key, stored)) {
                return Ok(Some(Value::Stored(stored)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb::{DbFlags, Env};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::collections::{BTreeMap, BTreeSet};

    type Model = BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>>;

    fn key(k: u8) -> Vec<u8> {
        vec![b'k', k / 4, k]
    }

    fn value(n: u64) -> Vec<u8> {
        // Ten bytes, as a stamp: mostly rising, some out of order.
        let mut value = vec![0; 10];
        value[..8].copy_from_slice(&(n * 7 % 1000).to_be_bytes());
        value[8..].copy_from_slice(&(n as u16).to_be_bytes());
        value
    }

    /// Merge a slice of the frozen layer in a transaction of its own, which
    /// fails if it's to.
    fn slice(env: &Env, memtable: &Memtable, db: impl Fn(Ix) -> Db, budget: usize, fail: bool) {
        let mut txn = env.write_txn().unwrap();
        let at = txn.id();
        let slice = memtable
            .merge_slice(&mut txn, at, budget, db)
            .unwrap()
            .unwrap();
        match fail {
            true => {
                drop(txn);
                memtable.unslice();
            }
            false => {
                txn.commit().unwrap();
                memtable.sliced(slice);
            }
        }
    }

    /// What a reader sees, every way it reads, against what it should.
    fn check(snap: &Snap, txn: &Txn, db: Db, model: &Model, rng: &mut StdRng) {
        for k in 0..24u8 {
            let key = key(k);
            let want: Vec<Vec<u8>> = model
                .get(&key)
                .map_or_else(Vec::new, |set| set.iter().cloned().collect());
            assert_eq!(
                snap.count(txn, db, Ix::Tags, &key).unwrap(),
                want.len(),
                "count {k}"
            );
            for n in 0..20 {
                let value = value(rng.random_range(0..400) + n);
                assert_eq!(
                    snap.has(txn, db, Ix::Tags, &key, &value).unwrap(),
                    want.contains(&value),
                    "has {k}"
                );
            }
            if let Some(value) = want.get(rng.random_range(0..want.len().max(1))) {
                assert!(snap.has(txn, db, Ix::Tags, &key, value).unwrap(), "has {k}");
            }
            let from = value(rng.random_range(0..400));
            let mut down = snap.down(txn, db, Ix::Tags, &key, &from).unwrap();
            let mut got = Vec::new();
            while let Some(value) = down.next().unwrap() {
                got.push(value.to_vec());
            }
            let expected: Vec<Vec<u8>> =
                want.iter().rev().filter(|v| **v <= from).cloned().collect();
            assert_eq!(got, expected, "down {k}");
            let (a, b) = (
                value(rng.random_range(0..400)),
                value(rng.random_range(0..400)),
            );
            let (low, high) = if a <= b { (a, b) } else { (b, a) };
            let mut got = Vec::new();
            snap.each(txn, db, Ix::Tags, &key, (&low, &high), |value| {
                got.push(value.to_vec());
                true
            })
            .unwrap();
            let expected: Vec<Vec<u8>> = want
                .iter()
                .filter(|v| **v >= low && **v <= high)
                .cloned()
                .collect();
            assert_eq!(got, expected, "each {k}");
        }
        let prefix = vec![b'k', rng.random_range(0..6u8)];
        let got = snap.keys(txn, db, Ix::Tags, &prefix, &prefix).unwrap();
        let expected: Vec<Vec<u8>> = model
            .iter()
            .filter(|(key, set)| key.starts_with(&prefix) && !set.is_empty())
            .map(|(key, _)| key.clone())
            .collect();
        // Keys LMDB has may have nothing left; the rest must all be there.
        let got_live: Vec<Vec<u8>> = got
            .into_iter()
            .filter(|key| snap.count(txn, db, Ix::Tags, key).unwrap() > 0)
            .collect();
        assert_eq!(got_live, expected, "keys");
    }

    /// Values sort as their bytes do, whatever their lengths.
    #[test]
    fn values_sort_as_their_bytes() {
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..20_000 {
            let mut bytes = || -> Vec<u8> {
                let len = rng.random_range(0..=VAL);
                (0..len).map(|_| rng.random_range(0..3u8)).collect()
            };
            let (a, b) = (bytes(), bytes());
            assert_eq!(Val::new(&a).cmp(&Val::new(&b)), a.cmp(&b), "{a:?} {b:?}");
            assert_eq!(Val::new(&a).get(), &a[..]);
        }
    }

    /// A reader that takes the layers just before a merge commits, then
    /// its transaction just after, reads the merged layer from LMDB, not
    /// twice; and one whose transaction began before reads it here.
    #[test]
    fn skips_layers_merged_before_its_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        let tags = env.create_db("tags", DbFlags::DUP_FIXED).unwrap();
        let memtable = Memtable::default();
        let mut txn = env.write_txn().unwrap();
        let at = txn.id();
        txn.put_dup(tags, b"k", &value(1)).unwrap();
        memtable.add(Ix::Tags, b"j", &value(3), at);
        memtable.add(Ix::Tags, b"k", &value(2), at);
        txn.commit().unwrap();
        memtable.commit();

        // A slice of one key, then the rest.
        memtable.freeze(0);
        for budget in [1, usize::MAX] {
            let before = memtable.layers();
            let early = env.read_txn().unwrap();
            let mut txn = env.write_txn().unwrap();
            let at = txn.id();
            let slice = memtable.merge_slice(&mut txn, at, budget, |_| tags);
            txn.commit().unwrap();
            let late = env.read_txn().unwrap();
            memtable.sliced(slice.unwrap().unwrap());
            for txn in [&early, &late] {
                let snap = Snap::new(&before, txn.id());
                assert_eq!(snap.count(txn, tags, Ix::Tags, b"j").unwrap(), 1);
                assert_eq!(snap.count(txn, tags, Ix::Tags, b"k").unwrap(), 2);
            }
        }
        assert!(!memtable.merging());
    }

    /// Entries added, removed, then added again, and tombstones moved,
    /// count as of each commit for readers of each of the last few.
    #[test]
    fn counts_entries_put_back_as_of_each_commit() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        let tags = env.create_db("tags", DbFlags::DUP_FIXED).unwrap();
        let meta = env.create_db("meta", DbFlags::PLAIN).unwrap();
        let memtable = Memtable::default();
        let mut txn = env.write_txn().unwrap();
        txn.put_dup(tags, b"k", &value(1)).unwrap();
        txn.put_dup(tags, b"t", &value(1)).unwrap();
        txn.commit().unwrap();
        type Step = fn(&Memtable, u64);
        let steps: [(Step, usize, usize); 8] = [
            (|m, at| m.add(Ix::Tags, b"k", &value(2), at), 2, 1),
            (|m, at| m.remove(Ix::Tags, b"k", &value(2), at), 1, 1),
            (|m, at| m.add(Ix::Tags, b"k", &value(2), at), 2, 1),
            (|m, at| m.remove(Ix::Tags, b"k", &value(1), at), 1, 1),
            (|m, at| m.remove(Ix::Tags, b"t", &value(1), at), 1, 0),
            // Removed again: as of the first, it already was.
            (|m, at| m.remove(Ix::Tags, b"t", &value(1), at), 1, 0),
            (|m, at| m.remove(Ix::Tags, b"k", &value(2), at), 0, 0),
            (|m, at| m.add(Ix::Tags, b"k", &value(2), at), 1, 0),
        ];
        let mut readers = Vec::new();
        for (step, k, t) in steps {
            let mut txn = env.write_txn().unwrap();
            let at = txn.id();
            txn.put(meta, b"at", &at.to_be_bytes()).unwrap();
            step(&memtable, at);
            txn.commit().unwrap();
            memtable.commit();
            readers.push((at, k, t));
            let txn = env.read_txn().unwrap();
            for &(at, k, t) in readers.iter().rev().take(COUNTS) {
                let snap = Snap::new(&memtable.layers(), at);
                let count = |key: &[u8]| snap.count(&txn, tags, Ix::Tags, key).unwrap();
                assert_eq!(count(b"k"), k, "k at {at}");
                assert_eq!(count(b"t"), t, "t at {at}");
            }
        }
    }

    /// The changes of the commits, replayed into another memtable, read as
    /// they did; those rolled back aren't among them.
    #[test]
    fn replays_what_was_committed() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        let tags = env.create_db("tags", DbFlags::DUP_FIXED).unwrap();
        let meta = env.create_db("meta", DbFlags::PLAIN).unwrap();
        let memtable = Memtable::default();
        let mut rng = StdRng::seed_from_u64(2);
        let mut kept = Vec::new();
        let mut live: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for round in 0..60u64 {
            let mut txn = env.write_txn().unwrap();
            let at = txn.id();
            txn.put(meta, b"round", &round.to_be_bytes()).unwrap();
            let mut added = Vec::new();
            for i in 0..5 {
                if !live.is_empty() && rng.random_bool(0.3) {
                    let (k, v) = live.swap_remove(rng.random_range(0..live.len()));
                    memtable.remove(Ix::Tags, &k, &v, at);
                } else {
                    let (k, v) = (key(rng.random_range(0..24)), value(round * 10 + i));
                    memtable.add(Ix::Tags, &k, &v, at);
                    added.push((k, v));
                }
            }
            if round % 4 == 3 {
                drop(txn);
                memtable.rollback();
                memtable.take_ops();
                live.retain(|e| !added.contains(e));
            } else {
                kept.push(memtable.take_ops());
                txn.commit().unwrap();
                memtable.commit();
                live.extend(added);
            }
        }
        // The rolled back removals: live again in both.
        let again = Memtable::default();
        for ops in &kept {
            again.replay(ops).unwrap();
        }
        let txn = env.read_txn().unwrap();
        let (a, b) = (
            Snap::new(&memtable.layers(), txn.id()),
            Snap::new(&again.layers(), txn.id()),
        );
        for k in 0..24 {
            let key = key(k);
            assert_eq!(
                a.count(&txn, tags, Ix::Tags, &key).unwrap(),
                b.count(&txn, tags, Ix::Tags, &key).unwrap(),
                "{k}"
            );
            let (mut da, mut db) = (
                a.down(&txn, tags, Ix::Tags, &key, &[0xff; 10]).unwrap(),
                b.down(&txn, tags, Ix::Tags, &key, &[0xff; 10]).unwrap(),
            );
            loop {
                let (x, y) = (
                    da.next().unwrap().map(|v| v.to_vec()),
                    db.next().unwrap().map(|v| v.to_vec()),
                );
                assert_eq!(x, y);
                if x.is_none() {
                    break;
                }
            }
        }
    }

    /// Readers at every point, kept open across commits, rollbacks and
    /// merges, see what was committed by the commit they read, every way.
    #[test]
    fn reads_as_of_each_commit_through_merges() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), 1 << 26, 4, 126).unwrap();
        let tags = env.create_db("tags", DbFlags::DUP_FIXED).unwrap();
        let ids = env.create_db("ids", DbFlags::PLAIN).unwrap();
        let meta = env.create_db("meta", DbFlags::PLAIN).unwrap();
        let db = |ix| match ix {
            Ix::Ids => ids,
            _ => tags,
        };
        let memtable = Memtable::default();
        let mut rng = StdRng::seed_from_u64(1);
        let mut model = Model::new();
        let mut ids_model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut next = 0u64;
        let mut readers = Vec::new();
        for round in 0..400 {
            let mut txn = env.write_txn().unwrap();
            let at = txn.id();
            txn.put(meta, b"round", &(round as u64).to_be_bytes())
                .unwrap();
            let mut staged = model.clone();
            let mut staged_ids = ids_model.clone();
            for _ in 0..rng.random_range(0..12) {
                let k = key(rng.random_range(0..24));
                let live: Vec<Vec<u8>> = staged
                    .get(&k)
                    .map_or_else(Vec::new, |s| s.iter().cloned().collect());
                if !live.is_empty() && rng.random_bool(0.3) {
                    let v = live[rng.random_range(0..live.len())].clone();
                    memtable.remove(Ix::Tags, &k, &v, at);
                    staged.get_mut(&k).unwrap().remove(&v);
                } else {
                    next += 1;
                    let v = value(next);
                    memtable.add(Ix::Tags, &k, &v, at);
                    let id = next.to_be_bytes().to_vec();
                    memtable.add(Ix::Ids, &id, &v[..8], at);
                    staged_ids.insert(id, v[..8].to_vec());
                    staged.entry(k).or_default().insert(v);
                }
            }
            if rng.random_bool(0.15) {
                drop(txn);
                memtable.rollback();
            } else {
                txn.commit().unwrap();
                memtable.commit();
                model = staged;
                ids_model = staged_ids;
            }
            // A slice at a time, of a few keys, some failing, while
            // readers read through the layer being merged.
            if round % 23 == 22 && !memtable.merging() {
                memtable.freeze(0);
            }
            if memtable.merging() {
                let budget = rng.random_range(1..30);
                let fail = rng.random_bool(0.2);
                slice(&env, &memtable, db, budget, fail);
            }
            let layers = memtable.layers();
            let txn = env.read_txn().unwrap();
            let snap = Snap::new(&layers, txn.id());
            readers.push((snap, txn, model.clone(), ids_model.clone()));
            if readers.len() > 5 {
                readers.remove(rng.random_range(0..readers.len()));
            }
            for (snap, txn, model, ids_model) in &readers {
                check(snap, txn, tags, model, &mut rng);
                for (id, seq) in ids_model.iter().rev().take(5) {
                    let got = snap.get(txn, ids, Ix::Ids, id).unwrap().map(|v| v.to_vec());
                    assert_eq!(got.as_ref(), Some(seq));
                }
                assert!(
                    snap.get(txn, ids, Ix::Ids, &u64::MAX.to_be_bytes())
                        .unwrap()
                        .is_none()
                );
            }
        }
        // Everything merged, LMDB alone holds it all.
        while memtable.merging() {
            slice(&env, &memtable, db, 50, false);
        }
        memtable.freeze(0);
        slice(&env, &memtable, db, usize::MAX, false);
        assert_eq!(memtable.layers().len(), 1);
        assert_eq!(memtable.active_records(), 0);
        let txn = env.read_txn().unwrap();
        let empty = Snap::new(&[], txn.id());
        check(&empty, &txn, tags, &model, &mut rng);
    }
}
