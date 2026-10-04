//! The relay's LMDB: events, their indexes, and NIP-01's rules for which
//! replaceable events to keep.
//!
//! Each stored event gets a sequence number, never reused, under which its
//! [record](crate::record) is kept. The indexes point at events by a 10-byte
//! *stamp*: `created_at` (u32) then the sequence number (48 bits), both
//! big-endian, so a key's stamps sort oldest to newest. The indexes are
//! `DUPSORT | DUPFIXED` tables — the key once, then its stamps packed
//! together — so an index entry costs 10 bytes rather than a key, a value,
//! and a node header.
//!
//! | table           | key                          | value                  |
//! |-----------------|------------------------------|------------------------|
//! | `events`        | seq (native u64)             | record                 |
//! | `ids`           | id prefix (8 bytes)          | seqs (u64 BE)          |
//! | `created`       | `CREATED`                    | stamps                 |
//! | `kinds`         | kind (u16 BE)                | stamps                 |
//! | `authors`       | pubkey                       | stamps                 |
//! | `author_kinds`  | pubkey ‖ kind                | stamps                 |
//! | `tags`          | tag key (below)              | stamps                 |
//! | `hll`           | tag key                      | HLL registers          |
//! | `facets`        | facet key (see [`facets`])   | stamps                 |
//! | `wot`           | pubkey                       | trust state ([`wot`])  |
//! | `wot_queue`     | pubkey                       | nothing                |
//! | `engagement`    | engager ‖ target id          | count ([`rank`])       |
//! | `scores`        | target id                    | score and whereabouts  |
//! | `ranked`        | mode ‖ kind                  | rank ‖ seq (48 bits)   |
//! | `applied`       | pubkey                       | weight applied         |
//! | `rank_queue`    | pubkey                       | nothing                |
//! | `replaceable`   | address                      | seq (u64 BE)           |
//! | `history`       | address                      | stamps                 |
//! | `expiring`      | `EXPIRING`                   | expiry stamps          |
//! | `meta`          | name                         | value                  |
//!
//! `ids` is keyed by a prefix of the id, a quarter its size; the record has
//! the whole id, so a lookup checks there, and the rare prefix shared by two
//! ids just means reading both records. `created` files every stamp under
//! one key, packed like the other indexes.
//!
//! Tag values are indexed in [`record::tag_value`] form; an *address* is
//! pubkey ‖ kind ‖ the `d` tag in that form (always empty for replaceable
//! kinds).
//!
//! An address's current version is in `replaceable`. The versions it
//! replaced are kept as *history*, for the kinds [`History`] keeps: in
//! `events` and `ids`, so they can be fetched by id, and with every version
//! of the address, current too, in `history`, but out of every other index,
//! so that queries, counts, and search see only the current one. A version
//! older than the current one when it arrives goes straight to history.
//! Each address keeps at most so many versions, current included: past
//! that, the oldest are removed as new ones arrive, and one older than them
//! all isn't kept. If the cap is lowered, [`Store::open`] prunes to it.
//!
//! An event with a NIP-40 expiration is refused once it has expired, and
//! [`Store::load`] treats a stored one as gone from then on, so no query
//! returns it. `expiring` files each such event under one key by a stamp
//! of its expiration rather than its `created_at`, so the [`Writer`] can
//! sweep away those that have expired, oldest first. Until it does, counts
//! that need no events loaded still include them.
//!
//! A NIP-09 deletion removes what it names when it arrives, and is kept, so
//! that what it names is refused if it arrives later: its `e` and `a` tags
//! are indexed like any other, so whether an event has been deleted is a
//! lookup or two of `tags` under kind 5. Deleting an address's current
//! version by id makes the newest version left in its history current.
//!
//! A NIP-62 request to vanish removes everything its author published up
//! to it, history and all, and the gift wraps addressed to them; kept, it
//! refuses those again, by one lookup of `author_kinds` under kind 62. The
//! relay only stores the requests addressed to it.
//!
//! A tag key is name length ‖ name ‖ value length ‖ value ‖ kind, so a tag
//! is counted per kind — followers, reactions — by LMDB for free, and all
//! of one value's kinds sit together. Every single-letter tag is indexed,
//! and the longer names [`IndexedTags`] lists.
//!
//! What NIP-50 search extensions look up — proof of work, media, and the
//! like — is filed in `facets`, keyed much like tags.
//!
//! With a [web of trust](wot), each author's trust is kept in `wot`, and
//! moved along in the same transaction as a follow list that changes it.
//!
//! Engagement is counted, scored, and [ranked](rank) for `sort:top` and
//! `sort:hot` as events are indexed and unindexed.
//!
//! Each tag key with at least [`HLL_THRESHOLD`] events has a NIP-45
//! [HyperLogLog](crate::hll) sketch of their authors in `hll`, kept up as
//! events arrive; smaller ones are sketched when asked. Sketches can't
//! forget, so one counts authors whose events have since gone too.

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::event::KindClass;
use crate::event::decode_hex;
use crate::facets;
use crate::hll::{self, Registers};
use crate::lmdb::{Db, DbFlags, Env, Result, RoTxn, RwTxn, Txn, Usage};
use crate::metrics::METRICS;
use crate::rank::{self, Rank};
use crate::record::{Element, EventView, tag_value};
use crate::wot::{self, Wot};

/// Bumped when the layout changes incompatibly.
const VERSION: u32 = 6;

pub const STAMP_LEN: usize = 10;
pub type Stamp = [u8; STAMP_LEN];

/// The largest sequence number a stamp holds.
pub const MAX_SEQ: u64 = (1 << 48) - 1;

/// Tag values longer than this, encoded, aren't indexed: LMDB keys top out
/// at 511 bytes, and nobody filters by an essay. Its length is a byte.
pub const MAX_INDEXED_TAG: usize = 255;

/// The longest tag name that may be indexed.
pub const MAX_TAG_NAME: usize = 64;

/// How many events a tag key has before its HyperLogLog is kept.
pub const HLL_THRESHOLD: usize = 1000;

/// Longer `d` tags are hashed in addresses, to fit in a key.
const MAX_ADDRESS_D: usize = 256;

/// The one key of the `created` table.
pub const CREATED: &[u8] = &[0];

/// NIP-09 deletion requests.
const DELETION: u16 = 5;

/// NIP-62 requests to vanish.
const VANISH: u16 = 62;

/// NIP-59 gift wraps.
const GIFT_WRAP: u16 = 1059;

/// The `meta` key of the history cap the store was last pruned to.
const HISTORY_MAX_VERSIONS: &[u8] = b"history_max_versions";

/// The most addresses pruned in one write transaction at startup.
const PRUNE_CHUNK: usize = 1000;

/// The one key of the `expiring` table.
const EXPIRING: &[u8] = &[0];

/// How often the writer sweeps away expired events.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// The bytes of an id the `ids` table is keyed by.
const ID_PREFIX: usize = 8;

/// The most events committed in one write transaction.
const MAX_WRITE_BATCH: usize = 1000;

pub fn stamp(created_at: u32, seq: u64) -> Stamp {
    let mut out = [0; STAMP_LEN];
    out[..4].copy_from_slice(&created_at.to_be_bytes());
    out[4..].copy_from_slice(&seq.to_be_bytes()[2..]);
    out
}

pub fn stamp_created_at(stamp: &[u8]) -> u32 {
    u32::from_be_bytes(stamp[..4].try_into().unwrap())
}

pub fn stamp_seq(stamp: &[u8]) -> u64 {
    let mut seq = [0; 8];
    seq[2..].copy_from_slice(&stamp[4..STAMP_LEN]);
    u64::from_be_bytes(seq)
}

/// A key of the `tags` table, for a value in [`record::tag_value`] form no
/// longer than [`MAX_INDEXED_TAG`]. Without a kind, the prefix every kind's
/// key for the value starts with.
pub fn tag_key(name: &str, value: &[u8], kind: Option<u16>) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + name.len() + value.len() + 2);
    key.push(name.len() as u8);
    key.extend_from_slice(name.as_bytes());
    key.push(value.len() as u8);
    key.extend_from_slice(value);
    if let Some(kind) = kind {
        key.extend_from_slice(&kind.to_be_bytes());
    }
    key
}

/// The kind a tag key is for.
pub fn tag_key_kind(key: &[u8]) -> u16 {
    u16::from_be_bytes(key[key.len() - 2..].try_into().unwrap())
}

/// The value of a tag key, as the text it was in the event.
fn tag_key_value(key: &[u8]) -> String {
    let name_len = usize::from(key[0]);
    let value = &key[name_len + 2..key.len() - 2];
    match value.split_first() {
        Some((1, bytes)) => hex::encode(bytes),
        Some((_, text)) => String::from_utf8_lossy(text).into_owned(),
        None => String::new(),
    }
}

/// Which tags are indexed, and so can be filtered by: every single letter,
/// and the longer names configured.
#[derive(Debug, Clone, Default)]
pub struct IndexedTags {
    /// Sorted.
    names: Vec<String>,
}

impl IndexedTags {
    pub fn new(names: impl IntoIterator<Item = String>) -> anyhow::Result<IndexedTags> {
        let mut names: Vec<String> = names.into_iter().collect();
        for name in &names {
            if name.len() < 2 || name.len() > MAX_TAG_NAME {
                bail!("Tag names to index must be 2 to {MAX_TAG_NAME} bytes, not {name:?}");
            }
        }
        names.sort_unstable();
        names.dedup();
        Ok(IndexedTags { names })
    }

    pub fn contains(&self, name: &str) -> bool {
        match name.as_bytes() {
            [letter] => letter.is_ascii_alphabetic(),
            _ => self
                .names
                .binary_search_by(|n| n.as_str().cmp(name))
                .is_ok(),
        }
    }
}

/// Which replaceable and addressable kinds keep the versions they replace,
/// and how many.
#[derive(Debug, Clone)]
pub struct History {
    enabled: bool,
    /// Sorted.
    excluded: Vec<u16>,
    /// The most versions an address keeps, current included. At least 1.
    max_versions: usize,
}

impl History {
    pub fn new(enabled: bool, mut excluded: Vec<u16>, max_versions: usize) -> History {
        excluded.sort_unstable();
        excluded.dedup();
        History {
            enabled,
            excluded,
            max_versions: max_versions.max(1),
        }
    }

    pub fn keeps(&self, kind: u16) -> bool {
        self.enabled && self.excluded.binary_search(&kind).is_err()
    }
}

/// What a write transaction did.
#[derive(Debug, Default)]
pub struct Batch {
    /// What became of each event, in order.
    pub outcomes: Vec<Outcome>,
    /// The sequence numbers of events no longer searchable: removed, or
    /// replaced and kept as history.
    pub removed: Vec<u64>,
}

/// What became of an event offered to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Stored, under this sequence number.
    Stored(u64),
    /// Older than the version already here, so kept as history only.
    Archived(u64),
    /// Already here.
    Duplicate,
    /// A newer version of it is already here, and history isn't kept, or
    /// it's older than every version kept.
    Replaced,
    /// Its NIP-40 expiration has passed.
    Expired,
    /// A NIP-09 deletion or NIP-62 request to vanish covering it is here.
    Deleted,
}

#[derive(Clone, Copy)]
pub struct Tables {
    pub events: Db,
    pub ids: Db,
    pub created: Db,
    pub kinds: Db,
    pub authors: Db,
    pub author_kinds: Db,
    pub tags: Db,
    pub hll: Db,
    pub facets: Db,
    pub wot: Db,
    pub wot_queue: Db,
    pub engagement: Db,
    pub scores: Db,
    pub ranked: Db,
    pub applied: Db,
    pub rank_queue: Db,
    pub replaceable: Db,
    pub history: Db,
    pub expiring: Db,
    pub meta: Db,
}

pub struct Store {
    env: Env,
    pub tables: Tables,
    pub indexed_tags: IndexedTags,
    history: History,
    wot: Option<Wot>,
    rank: Rank,
}

impl Store {
    pub fn open(
        dir: &Path,
        map_size: usize,
        indexed_tags: IndexedTags,
        history: History,
        wot: Option<Wot>,
        rank: Rank,
    ) -> anyhow::Result<Store> {
        std::fs::create_dir_all(dir).with_context(|| {
            format!("Could not create the database directory {}", dir.display())
        })?;
        let env = Env::open(dir, map_size, 32, 1024)
            .with_context(|| format!("Could not open the database at {}", dir.display()))?;
        let tables = Tables {
            events: env.create_db("events", DbFlags::INTEGER_KEY)?,
            ids: env.create_db("ids", DbFlags::DUP_FIXED)?,
            created: env.create_db("created", DbFlags::DUP_FIXED)?,
            kinds: env.create_db("kinds", DbFlags::DUP_FIXED)?,
            authors: env.create_db("authors", DbFlags::DUP_FIXED)?,
            author_kinds: env.create_db("author_kinds", DbFlags::DUP_FIXED)?,
            tags: env.create_db("tags", DbFlags::DUP_FIXED)?,
            hll: env.create_db("hll", DbFlags::PLAIN)?,
            facets: env.create_db("facets", DbFlags::DUP_FIXED)?,
            wot: env.create_db("wot", DbFlags::PLAIN)?,
            wot_queue: env.create_db("wot_queue", DbFlags::PLAIN)?,
            engagement: env.create_db("engagement", DbFlags::PLAIN)?,
            scores: env.create_db("scores", DbFlags::PLAIN)?,
            ranked: env.create_db("ranked", DbFlags::DUP_FIXED)?,
            applied: env.create_db("applied", DbFlags::PLAIN)?,
            rank_queue: env.create_db("rank_queue", DbFlags::PLAIN)?,
            replaceable: env.create_db("replaceable", DbFlags::PLAIN)?,
            history: env.create_db("history", DbFlags::DUP_FIXED)?,
            expiring: env.create_db("expiring", DbFlags::DUP_FIXED)?,
            meta: env.create_db("meta", DbFlags::PLAIN)?,
        };

        let mut txn = env.write_txn()?;
        match txn.get(tables.meta, b"version")? {
            None => {
                txn.put(tables.meta, b"version", &VERSION.to_be_bytes())?;
            }
            Some(version) if version == VERSION.to_be_bytes() => {}
            Some(version) => bail!(
                "The database at {} is format {version:?}, not {VERSION}.",
                dir.display()
            ),
        }
        txn.commit()?;
        let store = Store {
            env,
            tables,
            indexed_tags,
            history,
            wot,
            rank,
        };
        store.prune_all()?;
        wot::open(&store, store.wot.as_ref())?;
        rank::open(&store)?;
        Ok(store)
    }

    /// If the history cap is lower than when the store was last opened (or
    /// it has never been recorded), prune every address to it. Only old
    /// versions go, which aren't searchable, so search needn't hear of it.
    fn prune_all(&self) -> anyhow::Result<()> {
        let t = self.tables;
        let max = self.history.max_versions;
        let recorded = self
            .read()?
            .get(t.meta, HISTORY_MAX_VERSIONS)?
            .map(|v| u64::from_be_bytes(v.try_into().unwrap_or_default()));
        if recorded.is_none_or(|recorded| recorded > max as u64) {
            let mut over = Vec::new();
            let txn = self.read()?;
            let mut cursor = txn.cursor(t.history)?;
            let mut entry = cursor.first()?;
            while let Some((address, _)) = entry {
                if cursor.count()? > max {
                    over.push(address.to_vec());
                }
                entry = cursor.next_nodup()?;
            }
            drop(cursor);
            drop(txn);
            let mut pruned = 0;
            for chunk in over.chunks(PRUNE_CHUNK) {
                let mut txn = self.write()?;
                for address in chunk {
                    pruned += self.prune(&mut txn, address, &mut Vec::new())?;
                }
                txn.commit()?;
            }
            if pruned > 0 {
                tracing::info!("pruned {pruned} old versions to keep {max} per address");
            }
        }
        if recorded != Some(max as u64) {
            let mut txn = self.write()?;
            txn.put(t.meta, HISTORY_MAX_VERSIONS, &(max as u64).to_be_bytes())?;
            txn.commit()?;
        }
        Ok(())
    }

    /// Remove an address's oldest versions past the history cap, never its
    /// current one, noting them in `removed`. Returns how many went.
    fn prune(&self, txn: &mut RwTxn, address: &[u8], removed: &mut Vec<u64>) -> Result<usize> {
        let mut cursor = txn.cursor(self.tables.history)?;
        if cursor.set(address)?.is_none() {
            return Ok(0);
        }
        let excess = cursor.count()?.saturating_sub(self.history.max_versions);
        drop(cursor);
        if excess == 0 {
            return Ok(0);
        }
        let current = self.replaceable_seq(txn, address)?;
        let mut seqs = Vec::with_capacity(excess);
        each_stamp(txn, self.tables.history, address, 0, u32::MAX, |stamp| {
            let seq = stamp_seq(stamp);
            if Some(seq) != current {
                seqs.push(seq);
            }
            seqs.len() < excess
        })?;
        for &seq in &seqs {
            if self.remove(txn, seq)? {
                removed.push(seq);
            }
        }
        Ok(seqs.len())
    }

    /// Whether an address's history is full, and a version from
    /// `created_at` would be older than every version in it.
    fn too_old(&self, txn: &Txn, address: &[u8], created_at: u32) -> Result<bool> {
        let mut cursor = txn.cursor(self.tables.history)?;
        let Some((_, oldest)) = cursor.set(address)? else {
            return Ok(false);
        };
        let oldest = stamp_created_at(oldest);
        Ok(cursor.count()? >= self.history.max_versions && created_at < oldest)
    }

    #[cfg(test)]
    pub fn copy_compact(&self, path: &Path) -> Result<()> {
        self.env.copy_compact(path)
    }

    pub fn usage(&self) -> Result<Usage> {
        self.env.usage()
    }

    pub fn read(&self) -> Result<RoTxn<'_>> {
        self.env.read_txn()
    }

    pub fn write(&self) -> Result<RwTxn<'_>> {
        self.env.write_txn()
    }

    /// How much an author's engagement counts, from 0 to 1: their weight
    /// in the web of trust, or 1 without one.
    // Not yet read outside tests: engagement counting is next.
    #[allow(dead_code)]
    pub fn trust(&self, txn: &Txn, pubkey: &[u8; 32]) -> Result<f32> {
        match &self.wot {
            Some(wot) => wot.weight(self, txn, pubkey),
            None => Ok(1.0),
        }
    }

    pub fn wot(&self) -> Option<&Wot> {
        self.wot.as_ref()
    }

    pub fn rank(&self) -> &Rank {
        &self.rank
    }

    /// Do a turn's worth of background work, in a transaction of its own:
    /// push trust along, or once that's done, apply engagers' new weights
    /// to the scores of what they've engaged with. Returns whether there
    /// was any to do.
    pub fn turn(&self) -> Result<bool> {
        // Most of the time there's nothing to do: don't take the lock.
        let (push, walk) = {
            let txn = self.read()?;
            let push = self.wot.is_some() && txn.cursor(self.tables.wot_queue)?.first()?.is_some();
            (push, !push && rank::due(self, &txn)?)
        };
        let mut txn = self.write()?;
        match (&self.wot, push, walk) {
            (Some(wot), true, _) => {
                wot::turn(self, &mut txn, wot)?;
            }
            (_, false, true) => rank::turn(self, &mut txn)?,
            _ => return Ok(false),
        }
        txn.commit()?;
        Ok(true)
    }

    /// The sequence number the next stored event will get.
    pub fn next_seq(&self, txn: &Txn) -> Result<u64> {
        Ok(txn
            .get(self.tables.meta, b"next_seq")?
            .map_or(1, |v| u64::from_be_bytes(v.try_into().unwrap_or_default())))
    }

    pub fn contains(&self, txn: &Txn, id: &[u8; 32]) -> Result<bool> {
        Ok(self.seq_of(txn, id)?.is_some())
    }

    pub fn seq_of(&self, txn: &Txn, id: &[u8; 32]) -> Result<Option<u64>> {
        let mut cursor = txn.cursor(self.tables.ids)?;
        let mut entry = cursor.set(&id[..ID_PREFIX])?;
        while let Some((_, value)) = entry {
            let seq = u64::from_be_bytes(value.try_into().unwrap_or_default());
            if self.load(txn, seq)?.is_some_and(|view| view.id() == id) {
                return Ok(Some(seq));
            }
            entry = cursor.next_dup()?;
        }
        Ok(None)
    }

    /// A stored event, unless it has expired.
    pub fn load<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<EventView<'t>>> {
        let now = crate::event::now();
        Ok(txn
            .get(self.tables.events, &seq.to_ne_bytes())?
            .and_then(EventView::new)
            .filter(|view| !view.is_expired(now)))
    }

    /// How many events are stored.
    #[cfg(test)]
    pub fn len(&self, txn: &Txn) -> Result<usize> {
        txn.len(self.tables.events)
    }

    /// Store a batch of encoded records in one transaction, as of `now`.
    pub fn write_batch<'a>(
        &self,
        records: impl IntoIterator<Item = &'a [u8]>,
        now: u32,
    ) -> Result<Batch> {
        let mut txn = self.write()?;
        let mut batch = Batch::default();
        for record in records {
            let outcome = self.insert(&mut txn, record, now, &mut batch.removed)?;
            batch.outcomes.push(outcome);
        }
        txn.commit()?;
        Ok(batch)
    }

    /// Offer an encoded event to the store at `now`, applying replacement,
    /// and note in `removed` any event it replaces. The caller has checked
    /// it's valid.
    pub fn insert(
        &self,
        txn: &mut RwTxn,
        record: &[u8],
        now: u32,
        removed: &mut Vec<u64>,
    ) -> Result<Outcome> {
        let view = EventView::new(record).expect("an encoded record");
        let t = self.tables;
        let (id, created_at) = (view.id(), view.created_at());

        if view.is_expired(now) {
            return Ok(Outcome::Expired);
        }

        if self.contains(txn, id)? {
            return Ok(Outcome::Duplicate);
        }
        if self.is_deleted(txn, &view)? {
            return Ok(Outcome::Deleted);
        }

        let address = address_of(&view);
        let keeps = self.history.keeps(view.kind());
        let mut replaces = None;
        if let Some(address) = &address
            && let Some(seq) = self.replaceable_seq(txn, address)?
        {
            // NIP-01: the newest wins, and on a tie, the lowest id.
            if let Some(old) = self.load(txn, seq)?
                && (old.created_at(), std::cmp::Reverse(old.id()))
                    >= (created_at, std::cmp::Reverse(id))
            {
                if !keeps || self.too_old(txn, address, created_at)? {
                    return Ok(Outcome::Replaced);
                }
                let seq = self.put_record(txn, &view, record)?;
                txn.put_dup(t.history, address, &stamp(created_at, seq))?;
                self.prune(txn, address, removed)?;
                return Ok(Outcome::Archived(seq));
            }
            replaces = Some(seq);
        }

        let seq = self.put_record(txn, &view, record)?;
        let stamp = stamp(created_at, seq);
        txn.put_dup(t.created, CREATED, &stamp)?;
        for (db, key) in self.index_keys(&view) {
            txn.put_dup(db, &key, &stamp)?;
        }
        for (key, value) in self.tag_keys(&view) {
            self.sketch(txn, &key, &value, view.pubkey())?;
        }
        rank::index(self, txn, seq, &view)?;
        if let Some(address) = &address {
            txn.put(t.replaceable, address, &seq.to_be_bytes())?;
            txn.put_dup(t.history, address, &stamp)?;
        }
        if let Some(wot) = &self.wot
            && view.kind() == wot::FOLLOWS
        {
            let old = match replaces {
                Some(old) => self.record(txn, old)?,
                None => None,
            };
            let old = old
                .as_deref()
                .and_then(EventView::new)
                .map_or_else(Vec::new, |old| wot::follows(&old));
            wot::relist(self, txn, wot, view.pubkey(), &old, &wot::follows(&view))?;
        }

        if let Some(old) = replaces {
            let gone = match keeps {
                true => self.unindex(txn, old)?,
                false => self.remove(txn, old)?,
            };
            if gone {
                removed.push(old);
            }
        }
        if keeps && let Some(address) = &address {
            self.prune(txn, address, removed)?;
        }
        match view.kind() {
            DELETION => self.delete(txn, &view, now, removed)?,
            VANISH => self.vanish(txn, &view, seq, removed)?,
            _ => {}
        }
        Ok(Outcome::Stored(seq))
    }

    /// The `created_at` of the newest NIP-62 request to vanish by `pubkey`.
    fn vanished_at(&self, txn: &Txn, pubkey: &[u8; 32]) -> Result<Option<u32>> {
        let key = [&pubkey[..], &VANISH.to_be_bytes()].concat();
        let mut cursor = txn.cursor(self.tables.author_kinds)?;
        if cursor.set(&key)?.is_none() {
            return Ok(None);
        }
        Ok(cursor.last_dup()?.map(|(_, stamp)| stamp_created_at(stamp)))
    }

    /// Carry out a NIP-62 request to vanish, stored under `seq`: remove
    /// every other event by its author up to its `created_at`, history too,
    /// and the gift wraps addressed to them.
    fn vanish(
        &self,
        txn: &mut RwTxn,
        request: &EventView,
        seq: u64,
        removed: &mut Vec<u64>,
    ) -> Result<()> {
        let t = self.tables;
        let (pubkey, until) = (request.pubkey(), request.created_at());
        let mut seqs = Vec::new();
        let mut push = |stamp: &[u8]| {
            seqs.push(stamp_seq(stamp));
            true
        };
        each_stamp(txn, t.authors, pubkey, 0, until, &mut push)?;
        let mut recipient = Vec::with_capacity(33);
        Element::Hex(pubkey).encode(&mut recipient);
        let wraps = tag_key("p", &recipient, Some(GIFT_WRAP));
        each_stamp(txn, t.tags, &wraps, 0, until, &mut push)?;
        // Every address starts with its author.
        let mut cursor = txn.cursor(t.history)?;
        let mut entry = cursor.set_range(pubkey)?;
        while let Some((key, stamp)) = entry
            && key.starts_with(pubkey)
        {
            if stamp_created_at(stamp) <= until {
                seqs.push(stamp_seq(stamp));
            }
            entry = cursor.next()?;
        }
        drop(cursor);

        seqs.sort_unstable();
        seqs.dedup();
        for old in seqs {
            if old != seq && self.remove(txn, old)? {
                removed.push(old);
            }
        }
        Ok(())
    }

    /// Whether a stored NIP-09 deletion covers an event: one that names its
    /// id, by someone who [may delete](may_delete) it, or that names its
    /// address, by its author, at or after its `created_at`. Or whether a
    /// NIP-62 request to vanish does: its author's, or for a gift wrap, a
    /// recipient's, at or after its `created_at`.
    fn is_deleted(&self, txn: &Txn, view: &EventView) -> Result<bool> {
        let created_at = view.created_at();
        if self
            .vanished_at(txn, view.pubkey())?
            .is_some_and(|at| created_at <= at)
        {
            return Ok(true);
        }
        if view.kind() == GIFT_WRAP {
            for (name, value) in view.tag_values() {
                if let ("p", Element::Hex(recipient)) = (name, value)
                    && self
                        .vanished_at(txn, recipient)?
                        .is_some_and(|at| created_at <= at)
                {
                    return Ok(true);
                }
            }
        }

        let mut id = Vec::with_capacity(33);
        Element::Hex(view.id()).encode(&mut id);
        let key = tag_key("e", &id, Some(DELETION));
        if self.any_deletion(txn, &key, 0, |deletion| may_delete(deletion.pubkey(), view))? {
            return Ok(true);
        }
        if let Some(text) = address_text(view) {
            let value = tag_value(&text);
            if value.len() <= MAX_INDEXED_TAG {
                let key = tag_key("a", &value, Some(DELETION));
                return self.any_deletion(txn, &key, view.created_at(), |deletion| {
                    deletion.pubkey() == view.pubkey()
                });
            }
        }
        Ok(false)
    }

    /// Whether any deletion filed under a `tags` key, from `since` on,
    /// passes `f`.
    fn any_deletion(
        &self,
        txn: &Txn,
        key: &[u8],
        since: u32,
        f: impl Fn(&EventView) -> bool,
    ) -> Result<bool> {
        let mut seqs = Vec::new();
        each_stamp(txn, self.tables.tags, key, since, u32::MAX, |stamp| {
            seqs.push(stamp_seq(stamp));
            true
        })?;
        for seq in seqs {
            if self.load(txn, seq)?.is_some_and(|deletion| f(&deletion)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Carry out a NIP-09 deletion: remove the events it names by id that
    /// its author [may delete](may_delete), and every version of the
    /// addresses it names, of its author's, up to its `created_at`. Removing
    /// an address's current version makes the newest left current.
    fn delete(
        &self,
        txn: &mut RwTxn,
        deletion: &EventView,
        now: u32,
        removed: &mut Vec<u64>,
    ) -> Result<()> {
        let author = deletion.pubkey();
        let mut ids = Vec::new();
        let mut addresses = Vec::new();
        for (name, value) in deletion.tag_values() {
            match (name, value) {
                ("e", Element::Hex(id)) => ids.push(id),
                ("a", Element::Text(text)) => addresses.extend(parse_address(text, author)),
                _ => {}
            }
        }

        for id in ids {
            let Some(seq) = self.seq_of(txn, id)? else {
                continue;
            };
            let Some(target) = self.load(txn, seq)? else {
                continue;
            };
            if !may_delete(author, &target) {
                continue;
            }
            let promote = match self.is_current(txn, seq, &target)? {
                true => address_of(&target),
                false => None,
            };
            self.remove(txn, seq)?;
            removed.push(seq);
            if let Some(address) = promote {
                self.promote(txn, &address, now, removed)?;
            }
        }

        for address in addresses {
            // The current version is the newest, so if it goes, all go.
            let mut seqs = Vec::new();
            each_stamp(
                txn,
                self.tables.history,
                &address,
                0,
                deletion.created_at(),
                |stamp| {
                    seqs.push(stamp_seq(stamp));
                    true
                },
            )?;
            for seq in seqs {
                if self.remove(txn, seq)? {
                    removed.push(seq);
                }
            }
        }
        Ok(())
    }

    /// Make the newest version left at an address current, if there is one.
    /// It's stored again under a new sequence number, so it's indexed,
    /// search too, as if it had just arrived.
    fn promote(
        &self,
        txn: &mut RwTxn,
        address: &[u8],
        now: u32,
        removed: &mut Vec<u64>,
    ) -> Result<()> {
        let mut seqs = Vec::new();
        each_stamp(txn, self.tables.history, address, 0, u32::MAX, |stamp| {
            seqs.push(stamp_seq(stamp));
            true
        })?;
        // NIP-01: the newest, and on a tie, the lowest id.
        let mut newest = None;
        for seq in seqs {
            if let Some(view) = self.load(txn, seq)? {
                let rank = (view.created_at(), std::cmp::Reverse(*view.id()), seq);
                if newest.is_none_or(|newest| rank > newest) {
                    newest = Some(rank);
                }
            }
        }
        let Some((_, _, seq)) = newest else {
            return Ok(());
        };
        let record = self.record(txn, seq)?.expect("a stored record");
        self.remove(txn, seq)?;
        removed.push(seq);
        self.insert(txn, &record, now, removed)?;
        Ok(())
    }

    /// Keep a record under the next sequence number, findable by id.
    fn put_record(&self, txn: &mut RwTxn, view: &EventView, record: &[u8]) -> Result<u64> {
        let t = self.tables;
        let seq = self.next_seq(txn)?;
        assert!(seq <= MAX_SEQ, "the relay has run out of sequence numbers");
        txn.put(t.events, &seq.to_ne_bytes(), record)?;
        txn.put_dup(t.ids, &view.id()[..ID_PREFIX], &seq.to_be_bytes())?;
        if let Some(expiration) = view.expiration() {
            txn.put_dup(t.expiring, EXPIRING, &stamp(expiration, seq))?;
        }
        txn.put(t.meta, b"next_seq", &(seq + 1).to_be_bytes())?;
        Ok(seq)
    }

    /// Remove up to `max` events that have expired by `now`, the earliest
    /// to expire first, returning their sequence numbers.
    pub fn expire(&self, txn: &mut RwTxn, now: u32, max: usize) -> Result<Vec<u64>> {
        let mut seqs = Vec::new();
        each_stamp(txn, self.tables.expiring, EXPIRING, 0, now, |stamp| {
            seqs.push(stamp_seq(stamp));
            seqs.len() < max
        })?;
        for &seq in &seqs {
            self.remove(txn, seq)?;
        }
        Ok(seqs)
    }

    fn replaceable_seq(&self, txn: &Txn, address: &[u8]) -> Result<Option<u64>> {
        Ok(txn
            .get(self.tables.replaceable, address)?
            .map(|v| u64::from_be_bytes(v.try_into().unwrap_or_default())))
    }

    /// Whether a stored event is its address's current version, or has no
    /// address: not an old version kept as history.
    pub fn is_current(&self, txn: &Txn, seq: u64, view: &EventView) -> Result<bool> {
        match address_of(view) {
            None => Ok(true),
            Some(address) => Ok(self.replaceable_seq(txn, &address)? == Some(seq)),
        }
    }

    /// Every (index, key) an event's stamp is filed under, besides
    /// `created`. Each at most once, since a stamp is only stored once per
    /// key anyway.
    fn index_keys(&self, view: &EventView) -> Vec<(Db, Vec<u8>)> {
        let t = self.tables;
        let kind = view.kind().to_be_bytes();
        let mut keys = vec![
            (t.kinds, kind.to_vec()),
            (t.authors, view.pubkey().to_vec()),
            (t.author_kinds, [&view.pubkey()[..], &kind].concat()),
        ];
        keys.extend(
            self.tag_keys(view)
                .into_iter()
                .map(|(key, _)| (t.tags, key)),
        );
        keys.extend(
            facets::keys(view, &self.indexed_tags)
                .into_iter()
                .map(|key| (t.facets, key)),
        );
        keys
    }

    /// The `tags` keys an event is filed under, each with its value as text.
    fn tag_keys(&self, view: &EventView) -> Vec<(Vec<u8>, String)> {
        let mut keys = Vec::new();
        for (name, value) in view.tag_values() {
            if !self.indexed_tags.contains(name) || value.encoded_len() > MAX_INDEXED_TAG {
                continue;
            }
            let mut encoded = Vec::with_capacity(value.encoded_len());
            value.encode(&mut encoded);
            let text = match value {
                Element::Hex(bytes) => hex::encode(bytes),
                Element::Text(text) => text.to_string(),
            };
            keys.push((tag_key(name, &encoded, Some(view.kind())), text));
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    /// Count an author into a tag key's HyperLogLog, starting it if the key
    /// has grown big enough.
    fn sketch(&self, txn: &mut RwTxn, key: &[u8], value: &str, pubkey: &[u8; 32]) -> Result<()> {
        let t = self.tables;
        let registers = match txn.get(t.hll, key)? {
            Some(stored) => {
                let mut registers: Registers = stored.try_into().unwrap_or([0; hll::REGISTERS]);
                if !hll::add(&mut registers, hll::offset(value), pubkey) {
                    return Ok(());
                }
                registers
            }
            None => {
                let mut cursor = txn.cursor(t.tags)?;
                if cursor.set(key)?.is_none() || cursor.count()? < HLL_THRESHOLD {
                    return Ok(());
                }
                self.sketch_from_events(txn, key)?
            }
        };
        txn.put(t.hll, key, &registers)?;
        Ok(())
    }

    /// Sketch a tag key's authors from its events.
    fn sketch_from_events(&self, txn: &Txn, key: &[u8]) -> Result<Registers> {
        let offset = hll::offset(&tag_key_value(key));
        let mut registers = [0; hll::REGISTERS];
        let mut seqs = Vec::new();
        each_stamp(txn, self.tables.tags, key, 0, u32::MAX, |stamp| {
            seqs.push(stamp_seq(stamp));
            true
        })?;
        for seq in seqs {
            if let Some(view) = self.load(txn, seq)? {
                hll::add(&mut registers, offset, view.pubkey());
            }
        }
        Ok(registers)
    }

    /// A tag key's HyperLogLog: kept, or sketched now.
    pub fn key_sketch(&self, txn: &Txn, key: &[u8]) -> Result<Registers> {
        match txn.get(self.tables.hll, key)? {
            Some(stored) => Ok(stored.try_into().unwrap_or([0; hll::REGISTERS])),
            None => self.sketch_from_events(txn, key),
        }
    }

    /// Delete a stored event, current or history, and every index entry
    /// pointing at it.
    pub fn remove(&self, txn: &mut RwTxn, seq: u64) -> Result<bool> {
        let t = self.tables;
        let Some(record) = self.record(txn, seq)? else {
            return Ok(false);
        };
        let view = EventView::new(&record).expect("a stored record");
        self.unindex_view(txn, seq, &view)?;
        if let Some(address) = address_of(&view) {
            txn.del(t.history, &address, Some(&stamp(view.created_at(), seq)))?;
        }
        if let Some(expiration) = view.expiration() {
            txn.del(t.expiring, EXPIRING, Some(&stamp(expiration, seq)))?;
        }
        txn.del(t.ids, &view.id()[..ID_PREFIX], Some(&seq.to_be_bytes()))?;
        txn.del(t.events, &seq.to_ne_bytes(), None)?;
        Ok(true)
    }

    /// Take a stored event out of the indexes queries use, keeping it by id
    /// and in its address's history.
    fn unindex(&self, txn: &mut RwTxn, seq: u64) -> Result<bool> {
        let Some(record) = self.record(txn, seq)? else {
            return Ok(false);
        };
        let view = EventView::new(&record).expect("a stored record");
        self.unindex_view(txn, seq, &view)?;
        Ok(true)
    }

    fn record(&self, txn: &Txn, seq: u64) -> Result<Option<Vec<u8>>> {
        Ok(txn
            .get(self.tables.events, &seq.to_ne_bytes())?
            .map(<[u8]>::to_vec))
    }

    fn unindex_view(&self, txn: &mut RwTxn, seq: u64, view: &EventView) -> Result<()> {
        let t = self.tables;
        let stamp = stamp(view.created_at(), seq);
        rank::unindex(self, txn, seq, view)?;
        for (db, key) in self.index_keys(view) {
            txn.del(db, &key, Some(&stamp))?;
        }
        // A sketch outlives its events, but not its key.
        for (key, _) in self.tag_keys(view) {
            if txn.cursor(t.tags)?.set(&key)?.is_none() {
                txn.del(t.hll, &key, None)?;
            }
        }
        if let Some(address) = address_of(view)
            && self.replaceable_seq(txn, &address)? == Some(seq)
        {
            txn.del(t.replaceable, &address, None)?;
            // The current follow list gone: following no one, until
            // another version is promoted.
            if let Some(wot) = &self.wot
                && view.kind() == wot::FOLLOWS
            {
                wot::relist(self, txn, wot, view.pubkey(), &wot::follows(view), &[])?;
            }
        }
        txn.del(t.created, CREATED, Some(&stamp))?;
        Ok(())
    }
}

/// Call `f` with each of `key`'s stamps from `since` to `until`, oldest
/// first, until it returns false. Reads a page of them at a time.
pub fn each_stamp(
    txn: &Txn,
    db: Db,
    key: &[u8],
    since: u32,
    until: u32,
    mut f: impl FnMut(&[u8]) -> bool,
) -> Result<()> {
    let (low, high) = (stamp(since, 0), stamp(until, MAX_SEQ));
    let mut cursor = txn.cursor(db)?;
    let Some((_, first)) = cursor.get_both_range(key, &low)? else {
        return Ok(());
    };
    let mut page = cursor.get_multiple()?;
    if page.is_empty() {
        page = first;
    }
    loop {
        for stamp in page.as_chunks::<STAMP_LEN>().0 {
            if *stamp > high {
                return Ok(());
            }
            if *stamp >= low && !f(stamp) {
                return Ok(());
            }
        }
        match cursor.next_multiple()? {
            Some(next) => page = next,
            None => return Ok(()),
        }
    }
}

/// The address a replaceable or addressable event is kept under.
fn address_of(view: &EventView) -> Option<Vec<u8>> {
    let kind = view.kind();
    let mut d = Vec::new();
    match KindClass::of(kind) {
        KindClass::Addressable => view.tag("d").unwrap_or(Element::Text("")).encode(&mut d),
        KindClass::Replaceable => Element::Text("").encode(&mut d),
        _ => return None,
    }
    Some(address(view.pubkey(), kind, &d))
}

/// The address an `a` tag names, as an address of the store's, if it's of
/// a replaceable or addressable event by `author`.
fn parse_address(text: &str, author: &[u8; 32]) -> Option<Vec<u8>> {
    let mut parts = text.splitn(3, ':');
    let kind: u16 = parts.next()?.parse().ok()?;
    let pubkey = decode_hex::<32>(parts.next()?)?;
    let d = match KindClass::of(kind) {
        KindClass::Addressable => parts.next().unwrap_or(""),
        KindClass::Replaceable => "",
        _ => return None,
    };
    (&pubkey == author).then(|| address(&pubkey, kind, &tag_value(d)))
}

/// An event's address as an `a` tag names it: `kind:pubkey:d`.
fn address_text(view: &EventView) -> Option<String> {
    let d = match KindClass::of(view.kind()) {
        KindClass::Addressable => match view.tag("d") {
            Some(Element::Text(text)) => text.to_string(),
            Some(Element::Hex(bytes)) => hex::encode(bytes),
            None => String::new(),
        },
        KindClass::Replaceable => String::new(),
        _ => return None,
    };
    Some(format!(
        "{}:{}:{d}",
        view.kind(),
        hex::encode(view.pubkey())
    ))
}

/// Whether a NIP-09 deletion by `author` can delete `target`: its own
/// event, or a gift wrap addressed to it, but never a deletion or a vanish
/// request.
fn may_delete(author: &[u8; 32], target: &EventView) -> bool {
    let kind = target.kind();
    if kind == DELETION || kind == VANISH {
        return false;
    }
    target.pubkey() == author
        || kind == GIFT_WRAP
            && target
                .tag_values()
                .any(|(name, value)| name == "p" && value == Element::Hex(author))
}

/// The address of `kind` by `pubkey` with the `d` tag `d`, in
/// [`record::tag_value`] form (empty, `[0]`, for replaceable kinds).
pub fn address(pubkey: &[u8; 32], kind: u16, d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 2 + 33);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&kind.to_be_bytes());
    if d.len() > MAX_ADDRESS_D {
        // Can't collide with a short one: those start with 0 or 1.
        out.push(2);
        out.extend_from_slice(&Sha256::digest(d));
    } else {
        out.extend_from_slice(d);
    }
    out
}

type WriteJob = (Arc<Vec<u8>>, oneshot::Sender<anyhow::Result<Outcome>>);

/// Remove every event that has expired, a transaction at a time, returning
/// their sequence numbers.
fn sweep(store: &Store) -> Result<Vec<u64>> {
    let mut removed = Vec::new();
    loop {
        let mut txn = store.write()?;
        let seqs = store.expire(&mut txn, crate::event::now(), MAX_SWEEP)?;
        txn.commit()?;
        let done = seqs.len() < MAX_SWEEP;
        removed.extend(seqs);
        if done {
            return Ok(removed);
        }
    }
}

/// The most expired events removed in one write transaction.
const MAX_SWEEP: usize = 10_000;

/// LMDB allows one writer at a time, so all writes go through a dedicated
/// thread that batches whatever is queued into a single transaction. Every
/// [`SWEEP_INTERVAL`] it also removes the events that have expired. After
/// each batch, and whenever nothing's queued, it pushes the web of trust
/// along a turn at a time until there's nothing left to push.
#[derive(Clone)]
pub struct Writer {
    tx: std::sync::mpsc::Sender<WriteJob>,
}

impl Writer {
    /// Start the writer. With `indexer`, the search indexer is told after
    /// each write that changed anything, and what it removed.
    pub fn spawn(store: Arc<Store>, indexer: Option<std::sync::mpsc::Sender<Vec<u64>>>) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<WriteJob>();
        let tell = move |removed: Vec<u64>, stored: bool| {
            if let Some(indexer) = &indexer
                && (stored || !removed.is_empty())
            {
                let _ = indexer.send(removed);
            }
        };

        std::thread::Builder::new()
            .name("lmdb-writer".into())
            .spawn(move || {
                let mut next_sweep = Instant::now();
                // Whether the web of trust may have pushing to do.
                let mut trust = true;
                let turn = |trust: &mut bool| {
                    *trust = store.turn().unwrap_or_else(|err| {
                        tracing::error!("a background turn failed: {err}");
                        false
                    });
                };
                loop {
                    if Instant::now() >= next_sweep {
                        match sweep(&store) {
                            Ok(removed) => tell(removed, false),
                            Err(err) => tracing::error!("sweeping expired events failed: {err}"),
                        }
                        // Expired follow lists move trust.
                        trust = true;
                        next_sweep = Instant::now() + SWEEP_INTERVAL;
                    }
                    let wait = match trust {
                        true => Duration::ZERO,
                        false => next_sweep.saturating_duration_since(Instant::now()),
                    };
                    let first = match rx.recv_timeout(wait) {
                        Ok(job) => {
                            METRICS.write_queue.dec();
                            job
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            if trust {
                                turn(&mut trust);
                            }
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    let mut batch = vec![first];
                    while batch.len() < MAX_WRITE_BATCH {
                        match rx.try_recv() {
                            Ok(job) => {
                                METRICS.write_queue.dec();
                                batch.push(job);
                            }
                            Err(_) => break,
                        }
                    }

                    let records = batch.iter().map(|(record, _)| record.as_slice());
                    match store.write_batch(records, crate::event::now()) {
                        Ok(Batch { outcomes, removed }) => {
                            let stored = outcomes.iter().any(|o| matches!(o, Outcome::Stored(_)));
                            tell(removed, stored);
                            for ((_, reply), outcome) in batch.into_iter().zip(outcomes) {
                                let _ = reply.send(Ok(outcome));
                            }
                        }
                        Err(err) => {
                            tracing::error!("write batch failed: {err}");
                            for (_, reply) in batch {
                                let _ = reply.send(Err(anyhow!("{err}")));
                            }
                        }
                    }
                    // A follow list in the batch may have moved trust; a
                    // turn between batches keeps it from falling behind.
                    turn(&mut trust);
                }
            })
            .expect("failed to spawn writer thread");

        Self { tx }
    }

    /// Store an encoded record.
    pub async fn write(&self, record: Arc<Vec<u8>>) -> anyhow::Result<Outcome> {
        let start = Instant::now();
        let (reply, rx) = oneshot::channel();
        METRICS.write_queue.inc();
        if self.tx.send((record, reply)).is_err() {
            METRICS.write_queue.dec();
            bail!("writer thread is gone");
        }
        let outcome = rx
            .await
            .map_err(|_| anyhow!("writer thread dropped the request"))?;
        METRICS.writes.since(start);
        outcome
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::record;

    /// What tests index: single letters and `title`.
    pub fn test_tags() -> IndexedTags {
        IndexedTags::new(["title".to_string()]).unwrap()
    }

    /// The most values a filter field may list in tests.
    pub const MAX_VALUES: usize = 20_000;

    /// A store keeping every kind's history.
    pub fn open() -> (tempfile::TempDir, Store) {
        open_with(1 << 26, History::new(true, vec![], 20))
    }

    fn open_with(map_size: usize, history: History) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(
            dir.path(),
            map_size,
            test_tags(),
            history,
            None,
            Rank::default(),
        )
        .unwrap();
        (dir, store)
    }

    pub fn put(store: &Store, event: &Event) -> Outcome {
        put_at(store, event, crate::event::now())
    }

    /// Offer an event as if it were `now`.
    pub fn put_at(store: &Store, event: &Event, now: u32) -> Outcome {
        store
            .write_batch([record::encode(event).as_slice()], now)
            .unwrap()
            .outcomes[0]
    }

    fn has(store: &Store, event: &Event) -> bool {
        let txn = store.read().unwrap();
        let id: [u8; 32] = hex::decode(&event.id).unwrap().try_into().unwrap();
        store.contains(&txn, &id).unwrap()
    }

    /// Every index entry of every table, to check removals leave nothing.
    fn entries(store: &Store) -> usize {
        let t = store.tables;
        let txn = store.read().unwrap();
        [
            t.events,
            t.ids,
            t.created,
            t.kinds,
            t.authors,
            t.author_kinds,
            t.tags,
            t.hll,
            t.facets,
            t.replaceable,
            t.history,
            t.expiring,
        ]
        .iter()
        .map(|&db| txn.len(db).unwrap())
        .sum()
    }

    #[test]
    fn stores_once_and_removes_cleanly() {
        let (_dir, store) = open();
        let hex = "ab".repeat(32);
        let event = signed(
            1,
            100,
            1,
            vec![
                vec!["t", "x"],
                vec!["t", "x"],
                vec!["p", &hex],
                vec!["title", "T"],
                vec!["alt", "no"],
                vec!["7", "nor this"],
            ],
            "hi",
        );
        assert_eq!(put(&store, &event), Outcome::Stored(1));
        assert_eq!(put(&store, &event), Outcome::Duplicate);
        // events, ids, created, kinds, authors, author_kinds, three tags,
        // and the names of those three as facets.
        assert_eq!(entries(&store), 12);

        let mut txn = store.write().unwrap();
        assert!(store.remove(&mut txn, 1).unwrap());
        txn.commit().unwrap();
        assert_eq!(entries(&store), 0);

        // Sequence numbers aren't reused.
        let other = signed(1, 100, 1, vec![], "again");
        assert_eq!(put(&store, &other), Outcome::Stored(2));
    }

    #[test]
    fn keys_tags_by_name_value_and_kind() {
        let hex = "cd".repeat(32);
        let key = tag_key("e", &crate::record::tag_value(&hex), Some(7));
        assert_eq!(key.len(), 1 + 1 + 1 + 33 + 2);
        assert_eq!(tag_key_kind(&key), 7);
        assert_eq!(tag_key_value(&key), hex);
        let key = tag_key("title", &crate::record::tag_value("Hi"), Some(30023));
        assert_eq!(tag_key_value(&key), "Hi");
        // A value can't run into a longer one.
        let short = tag_key("t", &crate::record::tag_value("a"), None);
        let long = tag_key("t", &crate::record::tag_value("ab"), Some(1));
        assert!(!long.starts_with(&short));

        let tags = IndexedTags::new(["title".into(), "title".into()]).unwrap();
        assert!(tags.contains("t") && tags.contains("Q") && tags.contains("title"));
        assert!(!tags.contains("alt") && !tags.contains("1") && !tags.contains(""));
        assert!(IndexedTags::new(["x".into()]).is_err());
    }

    #[test]
    fn sketches_big_tag_keys() {
        let (_dir, store) = open();
        let target = "ef".repeat(32);
        let reactions: Vec<Event> = (0..HLL_THRESHOLD as u32 + 5)
            .map(|n| {
                let mut secret = [1; 32];
                secret[28..].copy_from_slice(&n.to_be_bytes());
                let tags = vec![vec!["e".to_string(), target.clone()]];
                crate::event::tests::sign(secret, 100, 7, tags, "+")
            })
            .collect();
        let key = tag_key("e", &crate::record::tag_value(&target), Some(7));
        let stored = |store: &Store| {
            store
                .read()
                .unwrap()
                .get(store.tables.hll, &key)
                .unwrap()
                .is_some()
        };
        for (i, event) in reactions.iter().enumerate() {
            put(&store, event);
            assert_eq!(stored(&store), i + 1 >= HLL_THRESHOLD, "{i}");
        }
        // Kept up as events arrive: the same as sketching them all now.
        let txn = store.read().unwrap();
        let kept = store.key_sketch(&txn, &key).unwrap();
        assert_eq!(kept, store.sketch_from_events(&txn, &key).unwrap());
        let estimate = hll::estimate(&kept);
        assert!((800.0..1250.0).contains(&estimate), "{estimate}");
        drop(txn);

        // Gone with the last of its events.
        let mut txn = store.write().unwrap();
        for seq in 1..=reactions.len() as u64 {
            store.remove(&mut txn, seq).unwrap();
        }
        txn.commit().unwrap();
        assert!(!stored(&store));
    }

    fn open_without_history() -> (tempfile::TempDir, Store) {
        open_with(1 << 26, History::new(false, vec![], 20))
    }

    /// The sequence number of an event's address's current version.
    fn current(store: &Store, event: &Event) -> Option<u64> {
        let record = record::encode(event);
        let view = EventView::new(&record).unwrap();
        let txn = store.read().unwrap();
        store
            .replaceable_seq(&txn, &address_of(&view).unwrap())
            .unwrap()
    }

    #[test]
    fn keeps_the_newest_replaceable() {
        let (_dir, store) = open_without_history();
        let old = signed(1, 100, 0, vec![], "old");
        let new = signed(1, 200, 0, vec![], "new");
        put(&store, &old);
        assert!(matches!(put(&store, &new), Outcome::Stored(_)));
        assert!(!has(&store, &old));
        assert_eq!(put(&store, &old), Outcome::Replaced);
        // Another author's is separate.
        assert!(matches!(
            put(&store, &signed(2, 50, 0, vec![], "")),
            Outcome::Stored(_)
        ));

        // On a tie, the lower id wins.
        let a = signed(1, 300, 3, vec![], "a");
        let b = signed(1, 300, 3, vec![], "b");
        let (low, high) = if a.id < b.id { (a, b) } else { (b, a) };
        put(&store, &high);
        assert!(matches!(put(&store, &low), Outcome::Stored(_)));
        assert_eq!(put(&store, &high), Outcome::Replaced);
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 3);
    }

    #[test]
    fn keeps_the_newest_addressable_per_d_tag() {
        let (_dir, store) = open_without_history();
        let one = signed(1, 100, 30_000, vec![vec!["d", "one"]], "");
        let two = signed(1, 100, 30_000, vec![vec!["d", "two"]], "");
        let none = signed(1, 100, 30_000, vec![], "");
        let empty = signed(1, 200, 30_000, vec![vec!["d", ""]], "");
        for event in [&one, &two, &none] {
            assert!(matches!(put(&store, event), Outcome::Stored(_)));
        }
        // No d tag and an empty one are the same address.
        put(&store, &empty);
        assert!(!has(&store, &none) && has(&store, &one) && has(&store, &two));

        // Long d tags are hashed, and still replace.
        let long = "x".repeat(1000);
        let v1 = signed(1, 100, 30_000, vec![vec!["d", &long]], "v1");
        let v2 = signed(1, 200, 30_000, vec![vec!["d", &long]], "v2");
        put(&store, &v1);
        put(&store, &v2);
        assert!(!has(&store, &v1) && has(&store, &v2));
    }

    #[test]
    fn keeps_replaced_versions_as_history() {
        let (_dir, store) = open();
        let v1 = signed(1, 100, 30_000, vec![vec!["d", "x"], vec!["t", "a"]], "v1");
        let v2 = signed(1, 200, 30_000, vec![vec!["d", "x"], vec!["t", "b"]], "v2");
        let v3 = signed(1, 300, 30_000, vec![vec!["d", "x"], vec!["t", "c"]], "v3");
        assert_eq!(put(&store, &v1), Outcome::Stored(1));
        assert_eq!(put(&store, &v3), Outcome::Stored(2));
        // Older than the current version: straight to history.
        assert_eq!(put(&store, &v2), Outcome::Archived(3));
        assert_eq!(put(&store, &v2), Outcome::Duplicate);
        assert!(has(&store, &v1) && has(&store, &v2) && has(&store, &v3));
        assert_eq!(current(&store, &v3), Some(2));

        let t = store.tables;
        let txn = store.read().unwrap();
        // Only the current version is indexed, but every one has history.
        assert_eq!(txn.len(t.created).unwrap(), 1);
        assert_eq!(txn.len(t.kinds).unwrap(), 1);
        // d and t, of the current version.
        assert_eq!(txn.len(t.tags).unwrap(), 2);
        assert_eq!(txn.len(t.history).unwrap(), 3);
        for (seq, current) in [(1, false), (2, true), (3, false)] {
            let view = store.load(&txn, seq).unwrap().unwrap();
            assert_eq!(store.is_current(&txn, seq, &view).unwrap(), current);
        }
        drop(txn);

        // Removing the lot leaves nothing behind.
        let mut txn = store.write().unwrap();
        for seq in 1..=3 {
            assert!(store.remove(&mut txn, seq).unwrap());
        }
        txn.commit().unwrap();
        assert_eq!(entries(&store), 0);
    }

    #[test]
    fn caps_history() {
        let (dir, store) = open_with(1 << 26, History::new(true, vec![], 20));
        let version = |at: u64| signed(1, at, 0, vec![vec!["t", "x"]], &at.to_string());
        let versions: Vec<Event> = (0..25).map(|i| version(1000 + i * 10)).collect();
        for event in &versions {
            put(&store, event);
        }
        let history_len = |store: &Store| store.read().unwrap().len(store.tables.history).unwrap();
        assert_eq!(history_len(&store), 20);
        assert!(versions[..5].iter().all(|event| !has(&store, event)));
        assert!(versions[5..].iter().all(|event| has(&store, event)));

        // Older than all twenty kept: not kept either.
        assert_eq!(put(&store, &version(500)), Outcome::Replaced);
        // Among them: kept, and the oldest goes instead.
        let between = version(1055);
        let batch = store
            .write_batch([record::encode(&between).as_slice()], 0)
            .unwrap();
        assert!(matches!(batch.outcomes[0], Outcome::Archived(_)));
        assert_eq!(batch.removed, [6]);
        assert!(has(&store, &between) && !has(&store, &versions[5]));
        assert_eq!(history_len(&store), 20);
        assert_eq!(current(&store, &versions[24]), Some(25));
        drop(store);

        // Reopened with a lower cap, pruned to it.
        let history = History::new(true, vec![], 5);
        let store = Store::open(
            dir.path(),
            1 << 26,
            test_tags(),
            history,
            None,
            Rank::default(),
        )
        .unwrap();
        assert_eq!(history_len(&store), 5);
        assert!(versions[20..].iter().all(|event| has(&store, event)));
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 5);
        assert_eq!(current(&store, &versions[24]), Some(25));
        // The current version is still the one indexed.
        assert_eq!(store.read().unwrap().len(store.tables.tags).unwrap(), 1);
        drop(store);

        // A higher cap prunes nothing, and keeps more from then on.
        let history = History::new(true, vec![], 7);
        let store = Store::open(
            dir.path(),
            1 << 26,
            test_tags(),
            history,
            None,
            Rank::default(),
        )
        .unwrap();
        assert_eq!(history_len(&store), 5);
        put(&store, &version(2000));
        put(&store, &version(2010));
        assert_eq!(history_len(&store), 7);
        put(&store, &version(2020));
        assert_eq!(history_len(&store), 7);
    }

    #[test]
    fn keeps_no_history_of_excluded_kinds() {
        let (_dir, store) = open_with(1 << 26, History::new(true, vec![30_382], 20));
        let old = signed(1, 100, 30_382, vec![vec!["d", "x"]], "");
        let new = signed(1, 200, 30_382, vec![vec!["d", "x"]], "");
        put(&store, &old);
        put(&store, &new);
        assert!(!has(&store, &old));
        assert_eq!(put(&store, &old), Outcome::Replaced);
        // History is still kept of other kinds.
        put(&store, &signed(1, 100, 0, vec![], "old"));
        put(&store, &signed(1, 200, 0, vec![], "new"));
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 3);
    }

    #[test]
    fn expires_events() {
        let (_dir, store) = open();
        let now = crate::event::now();
        let expiring = |at: u32, content: &str| {
            signed(
                1,
                100,
                1,
                vec![vec!["expiration", &at.to_string()]],
                content,
            )
        };
        assert_eq!(put(&store, &expiring(now - 10, "late")), Outcome::Expired);
        assert_eq!(put(&store, &expiring(now, "now")), Outcome::Expired);

        // Stored before they expired, they're gone once they have.
        let stale: Vec<Event> = (0..3)
            .map(|i| expiring(now - 10 + i, &i.to_string()))
            .collect();
        for event in &stale {
            assert!(matches!(
                put_at(&store, event, now - 20),
                Outcome::Stored(_)
            ));
        }
        let fresh = signed(
            1,
            100,
            0,
            vec![vec!["expiration", &(now + 1000).to_string()]],
            "",
        );
        assert_eq!(put(&store, &fresh), Outcome::Stored(4));
        assert!(stale.iter().all(|event| !has(&store, event)));
        assert!(has(&store, &fresh));

        // Swept away, the earliest to expire first.
        let mut txn = store.write().unwrap();
        assert_eq!(store.expire(&mut txn, now, 2).unwrap(), [1, 2]);
        assert_eq!(store.expire(&mut txn, now, 100).unwrap(), [3]);
        assert!(store.expire(&mut txn, now, 100).unwrap().is_empty());
        assert_eq!(store.expire(&mut txn, now + 1000, 100).unwrap(), [4]);
        txn.commit().unwrap();
        assert_eq!(entries(&store), 0);
    }

    #[test]
    fn deletes_by_id() {
        let (_dir, store) = open();
        let note = signed(1, 100, 1, vec![], "note");
        put(&store, &note);
        let deleting = |seed, target: &Event| signed(seed, 200, 5, vec![vec!["e", &target.id]], "");

        // Only by its author.
        put(&store, &deleting(2, &note));
        assert!(has(&store, &note));
        let deletion = deleting(1, &note);
        let batch = store
            .write_batch([record::encode(&deletion).as_slice()], 0)
            .unwrap();
        assert_eq!(batch.removed, [1]);
        assert!(!has(&store, &note) && has(&store, &deletion));
        assert_eq!(put(&store, &note), Outcome::Deleted);

        // Before it arrives, too.
        let later = signed(1, 300, 1, vec![], "later");
        put(&store, &deleting(1, &later));
        assert_eq!(put(&store, &later), Outcome::Deleted);
        let others = signed(2, 300, 1, vec![], "others");
        put(&store, &deleting(1, &others));
        assert!(matches!(put(&store, &others), Outcome::Stored(_)));

        // Not deletions, though.
        put(&store, &deleting(1, &deletion));
        assert!(has(&store, &deletion));
    }

    #[test]
    fn lets_recipients_delete_gift_wraps() {
        let (_dir, store) = open();
        let bob = signed(2, 0, 1, vec![], "").pubkey;
        let wrap = signed(9, 100, 1059, vec![vec!["p", &bob]], "sealed");
        put(&store, &wrap);
        put(&store, &signed(3, 200, 5, vec![vec!["e", &wrap.id]], ""));
        assert!(has(&store, &wrap));
        put(&store, &signed(2, 200, 5, vec![vec!["e", &wrap.id]], ""));
        assert!(!has(&store, &wrap));
        assert_eq!(put(&store, &wrap), Outcome::Deleted);
    }

    #[test]
    fn deletes_addresses_up_to_a_time() {
        let (_dir, store) = open();
        let version = |at| signed(1, at, 30_023, vec![vec!["d", "x"]], &at.to_string());
        let (v1, v2) = (version(100), version(200));
        put(&store, &v1);
        put(&store, &v2);
        let address = format!("30023:{}:x", v1.pubkey);
        let deleting = |seed, at| signed(seed, at, 5, vec![vec!["a", &address]], "");

        put(&store, &deleting(2, 300));
        assert!(has(&store, &v1) && has(&store, &v2));
        put(&store, &deleting(1, 150));
        assert!(!has(&store, &v1) && has(&store, &v2));
        assert_eq!(current(&store, &v2), Some(2));
        assert_eq!(put(&store, &v1), Outcome::Deleted);

        put(&store, &deleting(1, 250));
        assert!(!has(&store, &v2));
        assert_eq!(current(&store, &v2), None);
        assert_eq!(put(&store, &v2), Outcome::Deleted);
        assert_eq!(put(&store, &version(250)), Outcome::Deleted);
        // A newer version is untouched.
        let v3 = version(300);
        assert!(matches!(put(&store, &v3), Outcome::Stored(_)));
        assert!(has(&store, &v3));

        // Replaceable kinds are named with an empty d.
        let profile = signed(1, 100, 0, vec![], "");
        put(&store, &profile);
        let address = format!("0:{}:", profile.pubkey);
        put(&store, &signed(1, 200, 5, vec![vec!["a", &address]], ""));
        assert!(!has(&store, &profile));
        assert_eq!(put(&store, &profile), Outcome::Deleted);
    }

    #[test]
    fn promotes_the_previous_version() {
        let (_dir, store) = open();
        let old = signed(1, 100, 0, vec![vec!["t", "old"]], "old");
        let new = signed(1, 200, 0, vec![vec!["t", "new"]], "new");
        put(&store, &old);
        put(&store, &new);
        let deletion = signed(1, 300, 5, vec![vec!["e", &new.id]], "");
        let batch = store
            .write_batch([record::encode(&deletion).as_slice()], 0)
            .unwrap();
        // The new one, and the old one under its old sequence number.
        assert_eq!(batch.removed, [2, 1]);
        assert!(!has(&store, &new) && has(&store, &old));
        // Stored again, after the deletion.
        assert_eq!(current(&store, &old), Some(4));
        let txn = store.read().unwrap();
        let key = tag_key("t", &tag_value("old"), Some(0));
        assert!(
            txn.cursor(store.tables.tags)
                .unwrap()
                .set(&key)
                .unwrap()
                .is_some()
        );
        drop(txn);

        // With nothing left, the address is empty.
        put(&store, &signed(1, 300, 5, vec![vec!["e", &old.id]], ""));
        assert_eq!(current(&store, &old), None);
    }

    #[test]
    fn vanishes() {
        let (_dir, store) = open();
        let alice = signed(1, 0, 1, vec![], "").pubkey;
        let note = signed(1, 100, 1, vec![], "note");
        let old_profile = signed(1, 100, 0, vec![], "old");
        let profile = signed(1, 150, 0, vec![], "profile");
        let article = signed(1, 100, 30_023, vec![vec!["d", "x"]], "");
        let wrap = signed(9, 100, 1059, vec![vec!["p", &alice]], "to alice");
        let others = signed(2, 100, 1, vec![], "others");
        let later = signed(1, 300, 1, vec![], "later");
        let later_wrap = signed(9, 300, 1059, vec![vec!["p", &alice]], "later");
        let gone = [&note, &old_profile, &profile, &article, &wrap];
        for event in gone.iter().chain(&[&others, &later, &later_wrap]) {
            assert!(matches!(put(&store, event), Outcome::Stored(_)));
        }

        let request = signed(1, 200, 62, vec![vec!["relay", "ALL_RELAYS"]], "");
        let batch = store
            .write_batch([record::encode(&request).as_slice()], 0)
            .unwrap();
        assert_eq!(batch.removed, [1, 2, 3, 4, 5]);
        assert!(gone.iter().all(|event| !has(&store, event)));
        for event in [&others, &later, &later_wrap, &request] {
            assert!(has(&store, event));
        }
        assert_eq!(current(&store, &profile), None);

        // Refused from now on.
        for event in gone {
            assert_eq!(put(&store, event), Outcome::Deleted);
        }
        let wrap_again = signed(8, 150, 1059, vec![vec!["p", &alice]], "again");
        assert_eq!(put(&store, &wrap_again), Outcome::Deleted);
        let older_request = signed(1, 150, 62, vec![vec!["relay", "ALL_RELAYS"]], "");
        assert_eq!(put(&store, &older_request), Outcome::Deleted);
        // But not what's newer.
        let newer = signed(1, 250, 1, vec![], "newer");
        assert!(matches!(put(&store, &newer), Outcome::Stored(_)));

        // A deletion can't bring it all back.
        put(&store, &signed(1, 300, 5, vec![vec!["e", &request.id]], ""));
        assert!(has(&store, &request));
    }

    /// How big the database is, compacted, against the events' JSON. Slow,
    /// so run by hand: `cargo test --release disk_usage -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn disk_usage() {
        let (_dir, store) = open_with(1 << 32, History::new(true, vec![], 20));
        let events = crate::event::tests::feed(100_000);
        let json: usize = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap().len())
            .sum();
        for chunk in events.chunks(10_000) {
            let records: Vec<_> = chunk.iter().map(record::encode).collect();
            store
                .write_batch(records.iter().map(Vec::as_slice), 0)
                .unwrap();
        }
        let compact = tempfile::tempdir().unwrap();
        store.copy_compact(compact.path()).unwrap();
        let disk = std::fs::metadata(compact.path().join("data.mdb"))
            .unwrap()
            .len() as usize;
        let count = events.len();
        println!(
            "{count} events: {json} bytes of JSON, {disk} bytes on disk ({:.2}x), {} per event",
            disk as f64 / json as f64,
            disk / count
        );
    }

    #[test]
    fn stamps_sort_by_time_then_sequence() {
        assert!(stamp(1, MAX_SEQ) < stamp(2, 0));
        assert!(stamp(5, 1) < stamp(5, 2));
        assert_eq!(stamp_seq(&stamp(7, MAX_SEQ)), MAX_SEQ);
        assert_eq!(stamp_created_at(&stamp(u32::MAX, 3)), u32::MAX);
    }
}
