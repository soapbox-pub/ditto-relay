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
//! | `ids`           | id                           | seq (u64 BE)           |
//! | `created`       | `CREATED`                    | stamps                 |
//! | `kinds`         | kind (u16 BE)                | stamps                 |
//! | `authors`       | pubkey                       | stamp ‖ kind           |
//! | `author_kinds`  | pubkey ‖ kind                | stamps                 |
//! | `tags`          | tag key (below)              | stamps                 |
//! | `hll`           | tag key                      | HLL registers          |
//! | `facets`        | facet key (see [`facets`])   | stamps                 |
//! | `wot`           | pubkey                       | trust state ([`wot`])  |
//! | `wot_queue`     | pubkey                       | nothing                |
//! | `engagement`    | engager ‖ target id          | counts ([`rank`])      |
//! | `scores`        | target id                    | score and whereabouts  |
//! | `ranked`        | mode ‖ kind                  | rank ‖ seq (48 bits)   |
//! | `applied`       | pubkey                       | weight applied         |
//! | `rank_queue`    | pubkey                       | nothing                |
//! | `zaps`          | zapped id ([`rank::zapped`]) | count ‖ msats          |
//! | `replaceable`   | address                      | seq (u64 BE)           |
//! | `history`       | address                      | stamps                 |
//! | `expiring`      | `EXPIRING`                   | expiry stamps          |
//! | `pending`       | id ‖ field ([`pending`])     | a pending deletion     |
//! | `unlinked`      | seq (native u64)             | nothing                |
//! | `meta`          | name                         | value                  |
//!
//! `events` is in an environment of its own, `bodies/` inside the database's
//! directory, and every other table in the main one. Records are most of
//! the data, written once, and read only to be sent or checked, so apart,
//! the indexes the writer works on all the time stay small enough to stay
//! in memory, and records are appended a commit at a time, in one write.
//! See [`crate::lmdb`] for how the two are kept consistent; [`Store::open`]
//! drops records a crash left behind, under sequence numbers never
//! committed. `bodies` commits first, so a record is never removed in the
//! transaction that takes it out of the indexes: a crash between the
//! commits would leave index entries pointing at nothing. The event's
//! sequence number goes in `unlinked` instead, which reads it as gone, and
//! the writer removes the record in a transaction of its own after. After a crash
//! of the machine, the store is put back at its last
//! [checkpoint](crate::checkpoint), made every few seconds as it's written.
//!
//! `ids` is keyed by the whole id, so that whether an event is here doesn't
//! need its record read. `created` files every stamp under
//! one key, packed like the other indexes. `authors` follows each stamp with
//! the event's kind (u16 BE), so authors with more kinds than `author_kinds`
//! can be asked for at once are still answered from the index alone.
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
//! A NIP-09 deletion hides what it names as it's stored, and leaves
//! removing it to the writer, after (see [`crate::pending`]). It's kept, so
//! that what it names is refused if it arrives later: its `e` and `a` tags
//! are indexed like any other, so whether an event has been deleted is a
//! lookup or two of `tags` under kind 5. Deleting an address's current
//! version by id makes the newest version left in its history current.
//!
//! A NIP-62 request to vanish hides, then removes, everything its author
//! published up to it, history and all, and the gift wraps addressed to
//! them; kept, it refuses those again, by one lookup of `author_kinds`
//! under kind 62. The relay only stores the requests addressed to it.
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
//! Engagement is counted, scored, and [ranked](rank) for the ranked sorts
//! as events are indexed and unindexed.
//!
//! Another process only ever opens the store [to read](Store::open_read_only)
//! while the relay runs: the relay's writer hardly ever lets go of LMDB's
//! writer lock, so one that asked for it would wait on it indefinitely.
//! What `ditto-relay delete` asks for, the writer [queues](Writer::delete)
//! for it.
//!
//! Each tag key with at least [`HLL_THRESHOLD`] events has a NIP-45
//! [HyperLogLog](crate::hll) sketch of their authors in `hll`, kept up as
//! events arrive; smaller ones are sketched when asked. Sketches can't
//! forget, so one counts authors whose events have since gone too.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use arc_swap::ArcSwap;
use roaring::RoaringTreemap;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::checkpoint::{self, Recovered};
use crate::deletions;
use crate::event::KindClass;
use crate::event::decode_hex;
use crate::facets;
use crate::filter::Filter;
use crate::hll::{self, Registers};
use crate::lmdb::{Db, DbFlags, Env, Result, RoTxn, RwTxn, Txn, Usage};
use crate::metrics::{METRICS, Phase};
use crate::pending::{self, Hidden, Target};
use crate::purge::Purger;
use crate::rank::{self, Rank};
use crate::record::{self, Element, EventView, Header, tag_value};
use crate::storage;
use crate::wot::{self, Wot};

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

/// How far short of [`HLL_THRESHOLD`] a key's events are read ahead, as
/// the events filed before it in the writer's queue may bring it there.
const HLL_PREFETCH_MARGIN: usize = 50;

/// Longer `d` tags are hashed in addresses, to fit in a key.
const MAX_ADDRESS_D: usize = 256;

/// The one key of the `created` table.
pub const CREATED: &[u8] = &[0];

/// NIP-09 deletion requests.
pub const DELETION: u16 = 5;

/// NIP-62 requests to vanish.
pub const VANISH: u16 = 62;

/// Records [`Store::read_ahead`] reads on each thread, at least.
const PREFETCH_CHUNK: usize = if cfg!(test) { 2 } else { 32 };

/// The most threads [`Store::read_ahead`] reads on.
const PREFETCH_THREADS: usize = 8;

/// LMDB's page size, as far as reading a record's every page goes.
const PAGE: usize = 4096;

/// NIP-59 gift wraps.
pub const GIFT_WRAP: u16 = 1059;

/// The `meta` key of the store's [id](Store::id).
const STORE_ID: &[u8] = b"store_id";

/// The `meta` key of the history cap the store was last pruned to.
const HISTORY_MAX_VERSIONS: &[u8] = b"history_max_versions";

/// The most addresses pruned in one write transaction at startup.
const PRUNE_CHUNK: usize = 1000;

/// The one key of the `expiring` table.
pub(crate) const EXPIRING: &[u8] = &[0];

/// The deletion filter's size: 256 MiB, enough for some 200 million keys
/// before it rules out much less than 99% of the rest.
const DELETION_FILTER_BITS: u64 = 1 << 31;

/// The directory, in the database's, of the environment records are kept in.
pub const BODIES_DIR: &str = "bodies";

/// How many events and addresses a NIP-09 deletion names, at most, for
/// [`insert`](Store::insert) to look them all up, and so not queue it if
/// none is stored.
pub(crate) const SETTLED_AT_ONCE: usize = 64;

/// The deletion filter's file, in the database's directory.
const DELETION_FILTER_FILE: &str = "deletions.bloom";

/// How many deletions the filter is caught up with per read transaction.
const CATCH_UP_CHUNK: usize = if cfg!(test) { 2 } else { 10_000 };

/// How often the writer saves the deletion filter.
const DELETION_FILTER_SAVE_INTERVAL: Duration = Duration::from_secs(600);

/// How often the writer sweeps away expired events.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// The most events committed in one write transaction. A batch is only what
/// is already queued, so a big one doesn't keep events waiting that small
/// ones wouldn't, and a page many of its events touch is copied once rather
/// than once a commit.
const MAX_WRITE_BATCH: usize = 10_000;

/// The length of an `authors` entry: a stamp, then the event's kind.
pub const KINDED_LEN: usize = STAMP_LEN + 2;

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

/// An `authors` entry.
pub fn kinded(stamp: &Stamp, kind: u16) -> [u8; KINDED_LEN] {
    let mut out = [0; KINDED_LEN];
    out[..STAMP_LEN].copy_from_slice(stamp);
    out[STAMP_LEN..].copy_from_slice(&kind.to_be_bytes());
    out
}

/// The kind an index entry carries, if it's an `authors` entry.
pub fn entry_kind(entry: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(
        entry.get(STAMP_LEN..KINDED_LEN)?.try_into().ok()?,
    ))
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
    record::tag_value_element(value).map_or_else(String::new, |value| value.to_text().into_owned())
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
    pub zaps: Db,
    pub replaceable: Db,
    pub history: Db,
    pub expiring: Db,
    pub pending: Db,
    pub unlinked: Db,
    pub meta: Db,
}

impl Tables {
    fn open(env: &Env, bodies: usize) -> Result<Tables> {
        Ok(Tables {
            events: env.create_db_in(bodies, "events", DbFlags::INTEGER_KEY)?,
            ids: env.create_db("ids", DbFlags::PLAIN)?,
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
            zaps: env.create_db("zaps", DbFlags::PLAIN)?,
            replaceable: env.create_db("replaceable", DbFlags::PLAIN)?,
            history: env.create_db("history", DbFlags::DUP_FIXED)?,
            expiring: env.create_db("expiring", DbFlags::DUP_FIXED)?,
            pending: env.create_db("pending", DbFlags::PLAIN)?,
            unlinked: env.create_db("unlinked", DbFlags::INTEGER_KEY)?,
            meta: env.create_db("meta", DbFlags::PLAIN)?,
        })
    }
}

pub struct Store {
    /// Shared with the thread that makes a checkpoint durable.
    env: Arc<Env>,
    pub tables: Tables,
    pub indexed_tags: IndexedTags,
    history: History,
    wot: Option<Wot>,
    rank: Rank,
    /// Which of `env`'s environments `events` is in.
    bodies: usize,
    /// What [`is_deleted`](Self::is_deleted) can skip looking up.
    deletions: deletions::Filter,
    deletions_path: PathBuf,
    /// The sequence number from which deletions are missing from the
    /// filter, until it's [caught up](Self::catch_up_deletions).
    deletions_from: u64,
    /// The database's directory, where its checkpoint is kept.
    dir: PathBuf,
    /// The id of the boot of the machine the store was opened in.
    boot_id: Option<String>,
    checkpoints: Mutex<Checkpoints>,
    /// The pending deletions, whose events reads hide: see [`pending`].
    pub(crate) hidden: ArcSwap<Hidden>,
    /// Those queued in the write transaction being made, to unhide if it
    /// doesn't commit.
    pub(crate) uncommitted: Mutex<Vec<u64>>,
    /// What the [sweep](crate::purge) under way removes, which
    /// [`remove`](Self::remove) leaves to it.
    pub(crate) sweeping: Mutex<Option<Arc<RoaringTreemap>>>,
    /// Whether anything may be in `unlinked`, so that the writer needn't
    /// look when nothing's been removed.
    unlinking: AtomicBool,
    /// Whether a [repack](crate::repack) is under way.
    pub(crate) repacking: AtomicBool,
}

/// When the store's [checkpoints](crate::checkpoint) are made.
struct Checkpoints {
    /// When the last was begun.
    last: Instant,
    /// The one being made durable, if any.
    finishing: Option<JoinHandle<()>>,
}

impl Store {
    /// Open the store at `dir`, creating it if need be. If the machine has
    /// crashed since it was last open, it's put back as it was at its last
    /// [checkpoint](crate::checkpoint) first. A checkpoint of it as it is
    /// is made before anything's written.
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
        let bodies = dir.join(BODIES_DIR);
        std::fs::create_dir_all(&bodies).with_context(|| {
            format!(
                "Could not create the database directory {}",
                bodies.display()
            )
        })?;
        crate::repack::clear_leftovers(dir)
            .with_context(|| format!("Could not remove what a repack left in {}", dir.display()))?;
        let boot_id = checkpoint::boot_id();
        let files = checkpoint::files(dir, &[&bodies]);
        let recovering = || format!("Could not restore the database at {}", dir.display());
        match checkpoint::recover(dir, &files, boot_id.as_deref()).with_context(recovering)? {
            Recovered::Nothing | Recovered::SameBoot => {}
            Recovered::Restored(commits) => {
                let commits: Vec<String> = commits
                    .iter()
                    .map(|(at, latest)| match latest {
                        Some(latest) => format!("{at}, dropping {}", latest.saturating_sub(*at)),
                        None => format!("{at}, its later meta pages unreadable"),
                    })
                    .collect();
                tracing::warn!(
                    "the machine went down since the database was last open: put it back as it was at its last checkpoint (commit {}), losing what was written after, which may or may not have been intact",
                    commits.join("; bodies commit ")
                )
            }
            Recovered::Ignored(why) => {
                tracing::warn!("not restoring the database's checkpoint, as {why}")
            }
        }
        let mut env = Env::open(dir, map_size, 32, 1024)
            .with_context(|| format!("Could not open the database at {}", dir.display()))?;
        let bodies = env
            .attach(&bodies, map_size, 1, 1024)
            .with_context(|| format!("Could not open the database at {}", bodies.display()))?;
        // Before anything's written: until it's durable, LMDB may write
        // over the last checkpoint's pages.
        let metas = checkpoint::begin(&env)?;
        checkpoint::finish(&env, dir, &files, boot_id.as_deref(), &metas).with_context(|| {
            format!(
                "Could not save the database's checkpoint in {}",
                dir.display()
            )
        })?;
        for mismatch in storage::check(&files) {
            tracing::warn!("{mismatch}");
        }
        let tables = Tables::open(&env, bodies)?;
        // Where an older `ditto-relay delete`, which wrote the store itself,
        // left what it removed for the search indexer to delete.
        if let Some(queued) = env.remove_db("search_queue")?
            && queued > 0
        {
            tracing::warn!(
                "dropped {queued} removed events queued for the search index; searches skip them, but they're kept in the index until it's rebuilt"
            );
        }

        let deletions = deletions::Filter::new(DELETION_FILTER_BITS);
        let deletions_path = dir.join(DELETION_FILTER_FILE);
        let covered = deletions.load(&deletions_path).with_context(|| {
            format!(
                "Could not read the deletion filter {}",
                deletions_path.display()
            )
        })?;
        let store = Store {
            env: Arc::new(env),
            bodies,
            tables,
            indexed_tags,
            history,
            wot,
            rank,
            deletions,
            deletions_path,
            deletions_from: covered.unwrap_or(1),
            dir: dir.to_path_buf(),
            boot_id,
            checkpoints: Mutex::new(Checkpoints {
                last: Instant::now(),
                finishing: None,
            }),
            hidden: ArcSwap::default(),
            uncommitted: Mutex::default(),
            sweeping: Mutex::default(),
            unlinking: AtomicBool::new(true),
            repacking: AtomicBool::new(false),
        };
        let next = store.drop_uncommitted()?;
        store.load_pending()?;
        store.name()?;
        // Saved since the last event was stored, or a new database.
        if store.deletions_from >= next {
            store.deletions.set_ready();
        }
        store.prune_all()?;
        store.forget()?;
        wot::open(&store, store.wot.as_ref())?;
        rank::open(&store)?;
        Ok(store)
    }

    /// Open the store at `dir` only to read, from another process than the
    /// relay, which may be running: no write transaction is begun, so
    /// nothing waits on the relay's writer, and none of what the relay does
    /// as it opens the store is done.
    pub fn open_read_only(
        dir: &Path,
        map_size: usize,
        indexed_tags: IndexedTags,
        history: History,
        wot: Option<Wot>,
        rank: Rank,
    ) -> anyhow::Result<Store> {
        let opening = || format!("Could not open the database at {}", dir.display());
        let mut env = Env::open_read_only(dir, map_size, 32, 1024).with_context(opening)?;
        let bodies = env
            .attach(&dir.join(BODIES_DIR), map_size, 1, 1024)
            .with_context(opening)?;
        let tables = Tables::open(&env, bodies).with_context(opening)?;
        Ok(Store {
            env: Arc::new(env),
            bodies,
            tables,
            indexed_tags,
            history,
            wot,
            rank,
            // Never ready, so never consulted.
            deletions: deletions::Filter::new(DELETION_FILTER_BITS),
            deletions_path: dir.join(DELETION_FILTER_FILE),
            deletions_from: 1,
            dir: dir.to_path_buf(),
            boot_id: None,
            checkpoints: Mutex::new(Checkpoints {
                last: Instant::now(),
                finishing: None,
            }),
            hidden: ArcSwap::default(),
            uncommitted: Mutex::default(),
            sweeping: Mutex::default(),
            unlinking: AtomicBool::new(false),
            repacking: AtomicBool::new(false),
        })
    }

    /// The data files of the store's environments.
    pub(crate) fn files(&self) -> Vec<PathBuf> {
        checkpoint::files(&self.dir, &[&self.dir.join(BODIES_DIR)])
    }

    /// The database's directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Which of the store's environments `bodies` is.
    pub(crate) fn bodies_env(&self) -> usize {
        self.bodies
    }

    /// The id of the boot of the machine the store was opened in.
    pub(crate) fn boot_id(&self) -> Option<&str> {
        self.boot_id.as_deref()
    }

    /// Run `f` with no [checkpoint](crate::checkpoint) being made but the
    /// one it may make itself: one finishing is waited for, and a write
    /// [begun](Self::write) meanwhile waits for `f`.
    pub(crate) fn without_checkpoints<T>(&self, f: impl FnOnce() -> T) -> T {
        let mut checkpoints = self.checkpoints.lock().expect("unpoisoned");
        if let Some(finishing) = checkpoints.finishing.take() {
            let _ = finishing.join();
        }
        let out = f();
        checkpoints.last = Instant::now();
        out
    }

    /// Begin a [checkpoint](crate::checkpoint) of the latest commit if one's
    /// due and the last is durable, and make it durable on a thread of its
    /// own. Called before each write transaction begins, between commits.
    fn checkpoint_if_due(&self) {
        let mut checkpoints = self.checkpoints.lock().expect("unpoisoned");
        if checkpoints.last.elapsed() < checkpoint::INTERVAL
            || checkpoints
                .finishing
                .as_ref()
                .is_some_and(|f| !f.is_finished())
        {
            return;
        }
        checkpoints.last = Instant::now();
        let metas = match checkpoint::begin(&self.env) {
            Ok(metas) => metas,
            Err(err) => {
                tracing::error!("beginning a checkpoint failed: {err:#}");
                return;
            }
        };
        let (env, dir, files, boot_id) = (
            self.env.clone(),
            self.dir.clone(),
            self.files(),
            self.boot_id.clone(),
        );
        checkpoints.finishing = Some(std::thread::spawn(move || {
            let start = Instant::now();
            let finished = checkpoint::finish(&env, &dir, &files, boot_id.as_deref(), &metas);
            METRICS.checkpoints.since(start);
            match finished {
                Ok(()) if start.elapsed() > checkpoint::INTERVAL => tracing::warn!(
                    "a checkpoint took {:.1?}, longer than the time between them",
                    start.elapsed()
                ),
                Ok(()) => tracing::debug!("checkpointed in {:.1?}", start.elapsed()),
                Err(err) => tracing::error!("a checkpoint failed: {err:#}"),
            }
        }));
    }

    /// Make a checkpoint of the latest commit, durably, before returning,
    /// as before stopping, so a crash of the machine after loses nothing.
    pub fn checkpoint(&self) -> anyhow::Result<()> {
        let mut checkpoints = self.checkpoints.lock().expect("unpoisoned");
        if let Some(finishing) = checkpoints.finishing.take() {
            let _ = finishing.join();
        }
        checkpoints.last = Instant::now();
        let metas = checkpoint::begin(&self.env)?;
        checkpoint::finish(
            &self.env,
            &self.dir,
            &self.files(),
            self.boot_id.as_deref(),
            &metas,
        )
    }

    /// Remove the records a crash left in `bodies` under sequence numbers
    /// the main environment never committed, so they're appended to again.
    /// Returns the next sequence number.
    fn drop_uncommitted(&self) -> Result<u64> {
        let mut txn = self.write()?;
        let next = self.next_seq(&txn)?;
        let mut orphans = Vec::new();
        let mut cursor = txn.cursor(self.tables.events)?;
        let mut entry = cursor.set_range(&next.to_ne_bytes())?;
        while let Some((key, _)) = entry {
            orphans.push(key.to_vec());
            entry = cursor.next()?;
        }
        drop(cursor);
        if !orphans.is_empty() {
            tracing::warn!("dropping {} records never committed", orphans.len());
            for key in &orphans {
                txn.del(self.tables.events, key, None)?;
            }
            txn.commit()?;
        }
        Ok(next)
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

    /// Compacted copies of the main environment and `bodies`, into the
    /// directories `main` and `bodies`.
    #[cfg(test)]
    pub fn copy_compact(&self, main: &Path, bodies: &Path) -> Result<()> {
        self.env.copy_compact(0, main)?;
        self.env.copy_compact(self.bodies, bodies)
    }

    /// Have the kernel start reading the `len` bytes of records from where
    /// `record` is, for reading records on in order of their sequence
    /// numbers, which is mostly the order they're in on disk.
    pub fn will_need_records(&self, record: &[u8], len: usize) {
        self.env.will_need(self.bodies, record, len);
    }

    /// The store's environments, for reading ahead of the writer.
    pub(crate) fn env(&self) -> &Env {
        &self.env
    }

    /// The main environment's usage, and `bodies`'.
    pub fn usage(&self) -> Result<(Usage, Usage)> {
        Ok((self.env.usage(0)?, self.env.usage(self.bodies)?))
    }

    pub fn read(&self) -> Result<RoTxn<'_>> {
        self.env.read_txn()
    }

    pub fn write(&self) -> Result<RwTxn<'_>> {
        self.checkpoint_if_due();
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

    /// Never give out a sequence number below `next`. A crash of the
    /// machine loses the commits since the last checkpoint while what's kept beside
    /// the store, like the search index, knows of the events they stored:
    /// their sequence numbers mustn't be given to others.
    pub fn skip_to(&self, next: u64) -> Result<()> {
        let mut txn = self.write()?;
        if next > self.next_seq(&txn)? {
            txn.put(self.tables.meta, b"next_seq", &next.to_be_bytes())?;
            txn.commit()?;
        }
        Ok(())
    }

    /// The store's id, made at random the first time it's asked for, by
    /// which what's kept beside it can tell it from another.
    pub fn id(&self, txn: &Txn) -> Result<Option<String>> {
        Ok(txn.get(self.tables.meta, STORE_ID)?.map(hex::encode))
    }

    /// Make the store's [id](Self::id) if it has none.
    fn name(&self) -> Result<()> {
        if self.id(&*self.read()?)?.is_some() {
            return Ok(());
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).expect("the OS has randomness");
        let mut txn = self.write()?;
        txn.put(self.tables.meta, STORE_ID, &id)?;
        txn.commit()
    }

    /// Whether an event is stored, expired or not.
    pub fn contains(&self, txn: &Txn, id: &[u8; 32]) -> Result<bool> {
        Ok(self.seq_of(txn, id)?.is_some())
    }

    /// The sequence number an event is stored under, expired or not.
    pub fn seq_of(&self, txn: &Txn, id: &[u8; 32]) -> Result<Option<u64>> {
        Ok(txn
            .get(self.tables.ids, id)?
            .map(|value| u64::from_be_bytes(value.try_into().unwrap_or_default())))
    }

    /// A stored event's signature.
    pub fn sig_of(&self, txn: &Txn, id: &[u8; 32]) -> Result<Option<[u8; 64]>> {
        match self.seq_of(txn, id)? {
            Some(seq) => Ok(self.load(txn, seq)?.map(|view| *view.sig())),
            None => Ok(None),
        }
    }

    /// A stored event, as clients may see it: unless it has expired, or a
    /// pending deletion covers it.
    pub fn load<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<EventView<'t>>> {
        let now = crate::event::now();
        Ok(self
            .stored(txn, seq)?
            .filter(|view| !view.is_expired(now) && !self.hides(seq, view)))
    }

    /// A stored event, expired or not, and whether or not a pending
    /// deletion covers it.
    pub fn stored<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<EventView<'t>>> {
        Ok(self.raw(txn, seq)?.and_then(EventView::new))
    }

    /// A stored event's record: not one removed, its record left until the
    /// writer gets to it (see `unlinked`).
    fn raw<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<&'t [u8]>> {
        let key = seq.to_ne_bytes();
        let Some(record) = txn.get(self.tables.events, &key)? else {
            return Ok(None);
        };
        // A small table, in memory: cheaper than wondering whether it's
        // empty as of `txn`.
        if txn.get(self.tables.unlinked, &key)?.is_some() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Read the records of `seqs` on several threads at once, each in a
    /// transaction of its own, so that reading them after, one at a time,
    /// doesn't wait on the disk for each in turn. Only a hint: those that
    /// can't be read, or aren't worth threads, are left for then.
    pub fn read_ahead(&self, seqs: &[u64]) {
        let threads = (seqs.len() / PREFETCH_CHUNK).min(PREFETCH_THREADS);
        if threads < 2 {
            return;
        }
        let txns: Vec<_> = (0..threads).map_while(|_| self.read().ok()).collect();
        let Some(chunk) = seqs.len().checked_div(txns.len()) else {
            return;
        };
        std::thread::scope(|scope| {
            for (txn, seqs) in txns.into_iter().zip(seqs.chunks(chunk + 1)) {
                scope.spawn(move || {
                    for &seq in seqs {
                        if let Ok(Some(record)) = txn.get(self.tables.events, &seq.to_ne_bytes()) {
                            // A byte of every page it's on.
                            let bytes = record.iter().step_by(PAGE).fold(0, |a, &b| a ^ b);
                            std::hint::black_box(bytes);
                        }
                    }
                });
            }
        });
    }

    /// A stored, unexpired event's [`Header`], read without its tags or
    /// content.
    pub fn header<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<Header<'t>>> {
        let now = crate::event::now();
        let Some(record) = self.raw(txn, seq)? else {
            return Ok(None);
        };
        // What a deletion covers can take the whole event to say.
        if self.may_hide(seq) && EventView::new(record).is_some_and(|view| self.hides(seq, &view)) {
            return Ok(None);
        }
        Ok(Header::new(record).filter(|header| !header.is_expired(now)))
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
        let written = (|| {
            let mut txn = self.write()?;
            let mut batch = Batch::default();
            for record in records {
                let outcome = self.insert(&mut txn, record, now, &mut batch.removed)?;
                batch.outcomes.push(outcome);
            }
            txn.commit()?;
            Ok(batch)
        })();
        match &written {
            Ok(_) => self.committed_queued(),
            // What deletions it queued are hidden no longer.
            Err(_) => self.forget_uncommitted(),
        }
        written
    }

    /// Read, in a read transaction, what [`insert`](Self::insert)ing a
    /// record will, so the pages it needs are in memory by the time the
    /// writer gets to it. The writer is one thread, and waits on each page
    /// it finds missing in turn; prefetching from many threads at once
    /// keeps the disk busy with many reads in flight instead. Only a
    /// deletion's or a vanish request's targets, and the web of trust,
    /// aren't read ahead.
    pub fn prefetch(&self, txn: &Txn, record: &[u8]) -> Result<()> {
        let Some(view) = EventView::new(record) else {
            return Ok(());
        };
        if self.contains(txn, view.id())? || self.is_deleted(txn, &view)? {
            return Ok(());
        }
        let t = self.tables;
        let at = stamp(view.created_at(), 0);
        // Each key's entries, around where this one goes. A missing key or
        // entry is still found missing by reading the pages it'd be on.
        let seek = |db: Db, key: &[u8], entry: &[u8]| -> Result<()> {
            txn.cursor(db)?.get_both_range(key, entry).map(drop)
        };
        if let Some(address) = address_of(&view) {
            txn.cursor(t.history)?.set(&address)?;
            // What it replaces is taken out of the indexes.
            if let Some(seq) = self.replaceable_seq(txn, &address)?
                && let Some(old) = self.load(txn, seq)?
            {
                let old_at = stamp(old.created_at(), seq);
                for (db, key) in self.index_keys(&old) {
                    seek(db, &key, &old_at)?;
                }
                seek(t.authors, old.pubkey(), &kinded(&old_at, old.kind()))?;
            }
        }
        seek(t.authors, view.pubkey(), &kinded(&at, view.kind()))?;
        for (db, key) in self.index_keys(&view) {
            seek(db, &key, &at)?;
            // A key about to reach the threshold has its events read to
            // sketch them: read them too.
            if db == t.tags && txn.get(t.hll, &key)?.is_none() {
                let mut cursor = txn.cursor(t.tags)?;
                if cursor.set(&key)?.is_some()
                    && cursor.count()? + HLL_PREFETCH_MARGIN >= HLL_THRESHOLD
                {
                    self.sketch_from_events(txn, &key)?;
                }
            }
        }
        rank::prefetch(self, txn, &view)
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
        txn.put_dup(t.authors, view.pubkey(), &kinded(&stamp, view.kind()))?;
        for (db, key) in self.index_keys(&view) {
            txn.put_dup(db, &key, &stamp)?;
            if db == t.tags {
                self.sketch(txn, &key, view.pubkey())?;
            }
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
        for key in self.deletion_keys(&view) {
            self.deletions.add(&key);
        }
        // What they cover is hidden now, and removed later.
        let target = match view.kind() {
            DELETION => Some(Target::Deletion(pending::Deletion::of(&view))),
            VANISH => Some(Target::Vanish {
                author: *view.pubkey(),
                until: created_at,
            }),
            _ => None,
        };
        // A NIP-09 deletion naming a few events, none of them stored, as
        // most do, is done with: what's stored after it can't be what it
        // covers, which the deletion filter refuses. Queueing it would cost
        // a commit, and another to drop it.
        let settled = match &target {
            Some(Target::Deletion(deletion)) => {
                deletion.ids.len() + deletion.addresses.len() <= SETTLED_AT_ONCE
                    && self.deleting(txn, deletion, seq)?.is_empty()
            }
            _ => false,
        };
        if let Some(target) = target
            && !settled
        {
            self.queue_deletion(txn, seq, target)?;
        }
        Ok(Outcome::Stored(seq))
    }

    /// The `created_at` of the newest NIP-62 request to vanish by `pubkey`.
    fn vanished_at(&self, txn: &Txn, pubkey: &[u8; 32]) -> Result<Option<u32>> {
        let key = vanish_key(pubkey);
        if self.deletions.rules_out(&key) {
            return Ok(None);
        }
        let mut cursor = txn.cursor(self.tables.author_kinds)?;
        if cursor.set(&key)?.is_none() {
            return Ok(None);
        }
        Ok(cursor.last_dup()?.map(|(_, stamp)| stamp_created_at(stamp)))
    }

    /// What a NIP-62 request to vanish by `pubkey` at `until` removes,
    /// below `watermark`: every event by its author up to then, history
    /// too, and the gift wraps addressed to them.
    pub(crate) fn vanishing(
        &self,
        txn: &Txn,
        pubkey: &[u8; 32],
        until: u32,
        watermark: u64,
    ) -> Result<RoaringTreemap> {
        let t = self.tables;
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

        Ok(seqs.into_iter().filter(|&seq| seq < watermark).collect())
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
        if !self.deletions.rules_out(&key)
            && self.any_deletion(txn, &key, 0, |deletion| may_delete(deletion.pubkey(), view))?
        {
            return Ok(true);
        }
        if let Some(text) = address_text(view) {
            let value = tag_value(&text);
            if value.len() <= MAX_INDEXED_TAG {
                let key = tag_key("a", &value, Some(DELETION));
                if self.deletions.rules_out(&key) {
                    return Ok(false);
                }
                return self.any_deletion(txn, &key, view.created_at(), |deletion| {
                    deletion.pubkey() == view.pubkey()
                });
            }
        }
        Ok(false)
    }

    /// The keys [`is_deleted`](Self::is_deleted) looks a deletion or a
    /// request to vanish up by, which the deletion filter is told of.
    fn deletion_keys(&self, view: &EventView) -> Vec<Vec<u8>> {
        match view.kind() {
            DELETION => self
                .tag_keys(view)
                .into_iter()
                .filter(|key| key.starts_with(&[1, b'e']) || key.starts_with(&[1, b'a']))
                .collect(),
            VANISH => vec![vanish_key(view.pubkey())],
            _ => Vec::new(),
        }
    }

    /// Add to the deletion filter the deletions and requests to vanish it
    /// lacks, those stored since it was last saved, and let it rule keys
    /// out. Until then, every deletion check searches LMDB. Deletions the
    /// writer stores meanwhile it adds itself.
    pub fn catch_up_deletions(&self) -> Result<u64> {
        let mut added = 0;
        if self.deletions.is_ready() {
            return Ok(added);
        }
        for kind in [DELETION, VANISH] {
            // A read transaction at a time keeps what's freed meanwhile
            // from being reused, so the map grows, and the pages are
            // reused later, once they've left memory: a chunk at a time.
            let mut after: Option<Stamp> = None;
            loop {
                let txn = self.read()?;
                let (mut last, mut steps, mut failed) = (None, 0, None);
                let since = after.map_or(0, |after| stamp_created_at(&after));
                each_stamp(
                    &txn,
                    self.tables.kinds,
                    &kind.to_be_bytes(),
                    since,
                    u32::MAX,
                    |entry| {
                        let stamp: Stamp = entry[..STAMP_LEN].try_into().expect("a stamp");
                        if after.is_some_and(|after| stamp <= after) {
                            return true;
                        }
                        last = Some(stamp);
                        steps += 1;
                        let seq = stamp_seq(&stamp);
                        if seq >= self.deletions_from {
                            match txn.get(self.tables.events, &seq.to_ne_bytes()) {
                                Ok(record) => {
                                    if let Some(view) = record.and_then(EventView::new) {
                                        for key in self.deletion_keys(&view) {
                                            self.deletions.add(&key);
                                        }
                                        added += 1;
                                    }
                                }
                                Err(err) => failed = Some(err),
                            }
                        }
                        failed.is_none() && steps < CATCH_UP_CHUNK
                    },
                )?;
                if let Some(err) = failed {
                    return Err(err);
                }
                match last {
                    Some(last) => after = Some(last),
                    None => break,
                }
            }
        }
        self.deletions.set_ready();
        Ok(added)
    }

    /// Save the deletion filter as complete below `covered`, if it's caught
    /// up. Call it with the next sequence number as the writer last
    /// committed it, so every deletion below has been added.
    pub fn save_deletions(&self, covered: u64) -> std::io::Result<()> {
        if !self.deletions.is_ready() {
            return Ok(());
        }
        self.deletions.save(&self.deletions_path, covered)
    }

    /// How many keys the deletion filter has had added, and whether it's
    /// caught up.
    pub fn deletion_filter(&self) -> (u64, bool) {
        (self.deletions.keys(), self.deletions.is_ready())
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

    /// What a NIP-09 deletion removes, below `watermark`: the events it
    /// names by id that its author [may delete](may_delete), and every
    /// version of the addresses it names, of its author's, up to when it
    /// was made.
    pub(crate) fn deleting(
        &self,
        txn: &Txn,
        deletion: &pending::Deletion,
        watermark: u64,
    ) -> Result<RoaringTreemap> {
        let mut seqs = RoaringTreemap::new();
        for id in &deletion.ids {
            if let Some(seq) = self.seq_of(txn, id)?
                && let Some(target) = self.stored(txn, seq)?
                && may_delete(&deletion.author, &target)
            {
                seqs.insert(seq);
            }
        }
        for address in &deletion.addresses {
            // The current version is the newest, so if it goes, all go.
            each_stamp(
                txn,
                self.tables.history,
                address,
                0,
                deletion.until,
                |stamp| {
                    seqs.insert(stamp_seq(stamp));
                    true
                },
            )?;
        }
        seqs.remove_range(watermark..);
        Ok(seqs)
    }

    /// Remove a stored event, as a deletion does: if it's its address's
    /// current version, the newest version left that no deletion covers is
    /// made current. Notes in `removed` what search no longer has.
    pub(crate) fn remove_version(
        &self,
        txn: &mut RwTxn,
        seq: u64,
        now: u32,
        removed: &mut Vec<u64>,
    ) -> Result<bool> {
        self.remove_version_unless(txn, seq, now, removed, true)
    }

    /// [`remove_version`](Self::remove_version), with `guarded` false
    /// whether or not a sweep is to remove it: for the sweep itself.
    pub(crate) fn remove_version_unless(
        &self,
        txn: &mut RwTxn,
        seq: u64,
        now: u32,
        removed: &mut Vec<u64>,
        guarded: bool,
    ) -> Result<bool> {
        let Some(view) = self.stored(txn, seq)? else {
            return Ok(false);
        };
        let promote = match self.is_current(txn, seq, &view)? {
            true => address_of(&view),
            false => None,
        };
        if !self.remove_unless(txn, seq, guarded)? {
            return Ok(false);
        }
        removed.push(seq);
        if let Some(address) = promote {
            self.promote(txn, &address, now, removed)?;
        }
        Ok(true)
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

    /// The events deleting by `filter` removes for `seq`: it, if `filter`
    /// matches it, and if it's its address's current version, the versions
    /// kept in its history that `filter` matches. With the address, if so.
    pub(crate) fn matching_versions(
        &self,
        txn: &Txn,
        seq: u64,
        filter: &Filter,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>)> {
        let Some(view) = self.stored(txn, seq)?.filter(|view| filter.matches(view)) else {
            return Ok((Vec::new(), None));
        };
        let address = match address_of(&view) {
            Some(address) if self.replaceable_seq(txn, &address)? == Some(seq) => address,
            _ => return Ok((vec![seq], None)),
        };
        let mut history = Vec::new();
        each_stamp(txn, self.tables.history, &address, 0, u32::MAX, |stamp| {
            history.push(stamp_seq(stamp));
            true
        })?;
        let mut seqs = vec![seq];
        for old in history {
            if old != seq
                && self
                    .stored(txn, old)?
                    .is_some_and(|view| filter.matches(&view))
            {
                seqs.push(old);
            }
        }
        Ok((seqs, Some(address)))
    }

    /// How many events deleting by `filter` would remove for each of
    /// `seqs`, all told.
    pub fn count_matching(&self, txn: &Txn, seqs: &[u64], filter: &Filter) -> Result<usize> {
        let mut all = std::collections::HashSet::new();
        for &seq in seqs {
            all.extend(self.matching_versions(txn, seq, filter)?.0);
        }
        Ok(all.len())
    }

    /// Keep a record under the next sequence number, findable by id.
    fn put_record(&self, txn: &mut RwTxn, view: &EventView, record: &[u8]) -> Result<u64> {
        let t = self.tables;
        let seq = self.next_seq(txn)?;
        assert!(seq <= MAX_SEQ, "the relay has run out of sequence numbers");
        // Sequence numbers only grow, so a record always goes at the end.
        if !txn.append(t.events, &seq.to_ne_bytes(), record)? {
            txn.put(t.events, &seq.to_ne_bytes(), record)?;
        }
        txn.put(t.ids, view.id(), &seq.to_be_bytes())?;
        if let Some(expiration) = view.expiration() {
            txn.put_dup(t.expiring, EXPIRING, &stamp(expiration, seq))?;
        }
        txn.put(t.meta, b"next_seq", &(seq + 1).to_be_bytes())?;
        Ok(seq)
    }

    /// Remove up to `max` events that have expired by `now`, the earliest
    /// to expire first, returning their sequence numbers. One a sweep is
    /// to remove is left to it, but no longer filed as expiring.
    pub fn expire(&self, txn: &mut RwTxn, now: u32, max: usize) -> Result<Vec<u64>> {
        let mut stamps = Vec::new();
        each_stamp(txn, self.tables.expiring, EXPIRING, 0, now, |stamp| {
            stamps.push(stamp.to_vec());
            stamps.len() < max
        })?;
        let mut seqs = Vec::with_capacity(stamps.len());
        for stamp in stamps {
            let seq = stamp_seq(&stamp);
            if !self.remove(txn, seq)? {
                txn.del(self.tables.expiring, EXPIRING, Some(&stamp))?;
            }
            seqs.push(seq);
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
    /// `created` and `authors`. Each at most once, since a stamp is only
    /// stored once per key anyway.
    fn index_keys(&self, view: &EventView) -> Vec<(Db, Vec<u8>)> {
        let t = self.tables;
        let kind = view.kind().to_be_bytes();
        let mut keys = vec![
            (t.kinds, kind.to_vec()),
            (t.author_kinds, [&view.pubkey()[..], &kind].concat()),
        ];
        keys.extend(self.tag_keys(view).into_iter().map(|key| (t.tags, key)));
        keys.extend(
            facets::keys(view, &self.indexed_tags)
                .into_iter()
                .map(|key| (t.facets, key)),
        );
        keys
    }

    /// The `tags` keys an event is filed under.
    fn tag_keys(&self, view: &EventView) -> Vec<Vec<u8>> {
        self.keys_of(view.kind(), view.filed_tag_values())
    }

    /// The `tags` keys an event was filed under before its filed tag values
    /// left some of its tag values out (see
    /// [`EventView::filed_tag_values`]), that it no longer is.
    pub fn stale_tag_keys(&self, view: &EventView) -> Vec<Vec<u8>> {
        let filed = self.tag_keys(view);
        let mut keys = self.keys_of(view.kind(), view.tag_values());
        keys.retain(|key| filed.binary_search(key).is_err());
        keys
    }

    /// Take a stored event out of the `tags` keys it's no longer filed
    /// under, if it's still filed under any, returning how many it was.
    pub fn drop_stale_tag_keys(&self, txn: &mut RwTxn, seq: u64) -> Result<usize> {
        let t = self.tables;
        let Some(record) = self.record(txn, seq)? else {
            return Ok(0);
        };
        let view = EventView::new(&record).expect("a stored record");
        let stamp = stamp(view.created_at(), seq);
        let mut dropped = 0;
        for key in self.stale_tag_keys(&view) {
            if txn.del(t.tags, &key, Some(&stamp))? {
                dropped += 1;
                if txn.cursor(t.tags)?.set(&key)?.is_none() {
                    txn.del(t.hll, &key, None)?;
                }
            }
        }
        Ok(dropped)
    }

    /// The `tags` keys of an event of `kind` with these tag values.
    fn keys_of<'a>(
        &self,
        kind: u16,
        values: impl Iterator<Item = (&'a str, Element<'a>)>,
    ) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        for (name, value) in values {
            if !self.indexed_tags.contains(name) || value.encoded_len() > MAX_INDEXED_TAG {
                continue;
            }
            let mut encoded = Vec::with_capacity(value.encoded_len());
            value.encode(&mut encoded);
            keys.push(tag_key(name, &encoded, Some(kind)));
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    /// Count an author into a tag key's HyperLogLog, starting it if the key
    /// has grown big enough.
    fn sketch(&self, txn: &mut RwTxn, key: &[u8], pubkey: &[u8; 32]) -> Result<()> {
        let t = self.tables;
        let registers = match txn.get(t.hll, key)? {
            Some(stored) => {
                let mut registers: Registers = stored.try_into().unwrap_or([0; hll::REGISTERS]);
                let offset = hll::offset(&tag_key_value(key));
                if !hll::add(&mut registers, offset, pubkey) {
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

    /// Sketch a tag key's authors from its events. Only their headers are
    /// read: a key reaching the threshold has a thousand events, often big
    /// ones, scattered about, and the writer waits on each.
    fn sketch_from_events(&self, txn: &Txn, key: &[u8]) -> Result<Registers> {
        let offset = hll::offset(&tag_key_value(key));
        let now = crate::event::now();
        let mut registers = [0; hll::REGISTERS];
        let mut seqs = Vec::new();
        each_stamp(txn, self.tables.tags, key, 0, u32::MAX, |stamp| {
            seqs.push(stamp_seq(stamp));
            true
        })?;
        for seq in seqs {
            let record = txn.get(self.tables.events, &seq.to_ne_bytes())?;
            if let Some(author) = record.and_then(|r| record::author_unless_expired(r, now)) {
                hll::add(&mut registers, offset, author);
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
    /// pointing at it. Its record is only [unlinked](Self::forget): the
    /// writer removes it after this transaction commits. One the sweep
    /// under way is to remove is left to it.
    pub fn remove(&self, txn: &mut RwTxn, seq: u64) -> Result<bool> {
        self.remove_unless(txn, seq, true)
    }

    fn remove_unless(&self, txn: &mut RwTxn, seq: u64, guarded: bool) -> Result<bool> {
        let t = self.tables;
        if guarded
            && let Some(sweeping) = &*self.sweeping.lock().expect("unpoisoned")
            && sweeping.contains(seq)
        {
            return Ok(false);
        }
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
        txn.del(t.ids, view.id(), None)?;
        txn.put(t.unlinked, &seq.to_ne_bytes(), &[])?;
        self.unlinking.store(true, Ordering::Relaxed);
        Ok(true)
    }

    /// Remove the records of the events [removed](Self::remove) since this
    /// was last done, in a transaction of its own after theirs, and so after
    /// they're out of the indexes. Returns how many went.
    pub fn forget(&self) -> Result<usize> {
        let t = self.tables;
        let mut forgotten = 0;
        while self.unlinking.load(Ordering::Relaxed) {
            let mut txn = self.write()?;
            let mut seqs = Vec::new();
            let mut cursor = txn.cursor(t.unlinked)?;
            let mut entry = cursor.first()?;
            while let Some((key, _)) = entry
                && seqs.len() < MAX_SWEEP
            {
                seqs.push(key.to_vec());
                entry = cursor.next()?;
            }
            drop(cursor);
            let left = entry.is_some();
            for key in &seqs {
                txn.del(t.events, key, None)?;
                txn.del(t.unlinked, key, None)?;
            }
            if !seqs.is_empty() {
                txn.commit()?;
            }
            forgotten += seqs.len();
            if !left {
                self.unlinking.store(false, Ordering::Relaxed);
            }
        }
        Ok(forgotten)
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

    pub(crate) fn record(&self, txn: &Txn, seq: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.raw(txn, seq)?.map(<[u8]>::to_vec))
    }

    fn unindex_view(&self, txn: &mut RwTxn, seq: u64, view: &EventView) -> Result<()> {
        let t = self.tables;
        let stamp = stamp(view.created_at(), seq);
        rank::unindex(self, txn, seq, view)?;
        txn.del(t.authors, view.pubkey(), Some(&kinded(&stamp, view.kind())))?;
        for (db, key) in self.index_keys(view) {
            txn.del(db, &key, Some(&stamp))?;
            // A sketch outlives its events, but not its key.
            if db == t.tags && txn.cursor(t.tags)?.set(&key)?.is_none() {
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

/// Call `f` with each of `key`'s entries from `since` to `until`, oldest
/// first, until it returns false. Reads a page of them at a time. An entry
/// is a stamp, and in `authors`, a kind after it.
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
    // Every entry of a table is as long.
    let len = first.len();
    let mut page = cursor.get_multiple()?;
    if page.is_empty() {
        page = first;
    }
    loop {
        for entry in page.chunks_exact(len) {
            let stamp = &entry[..STAMP_LEN];
            if stamp > &high[..] {
                return Ok(());
            }
            if stamp >= &low[..] && !f(entry) {
                return Ok(());
            }
        }
        match cursor.next_multiple()? {
            Some(next) => page = next,
            None => return Ok(()),
        }
    }
}

/// The `author_kinds` key of an author's requests to vanish.
fn vanish_key(pubkey: &[u8; 32]) -> Vec<u8> {
    [&pubkey[..], &VANISH.to_be_bytes()].concat()
}

/// The address a replaceable or addressable event is kept under.
pub(crate) fn address_of(view: &EventView) -> Option<Vec<u8>> {
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
pub(crate) fn parse_address(text: &str, author: &[u8; 32]) -> Option<Vec<u8>> {
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
        KindClass::Addressable => view
            .tag("d")
            .map_or_else(String::new, |d| d.to_text().into_owned()),
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
pub(crate) fn may_delete(author: &[u8; 32], target: &EventView) -> bool {
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
        // Can't collide with a short one: those start with 0, 1, or 2.
        out.push(u8::MAX);
        out.extend_from_slice(&Sha256::digest(d));
    } else {
        out.extend_from_slice(d);
    }
    out
}

type WriteJob = (Arc<Vec<u8>>, oneshot::Sender<anyhow::Result<Outcome>>);

/// Remove up to `max` events that have expired, in a transaction, returning
/// their sequence numbers, and whether there may be more.
fn sweep(store: &Store, max: usize) -> Result<(Vec<u64>, bool)> {
    let mut txn = store.write()?;
    let seqs = store.expire(&mut txn, crate::event::now(), max)?;
    txn.commit()?;
    let more = seqs.len() == max;
    Ok((seqs, more))
}

/// The events a write stored, by sequence number, and what it removed.
pub type Written = (Vec<(u64, Arc<Vec<u8>>)>, Vec<u64>);

/// Store a batch of jobs in one transaction, answer each, and `tell` what
/// was written. One event's failure fails the transaction, and with it
/// every other event in it, so a batch that fails is tried again an event
/// at a time: only the event that can't be stored is refused.
fn write(store: &Store, batch: Vec<WriteJob>, tell: &impl Fn(Written)) {
    let now = crate::event::now();
    let records = batch.iter().map(|(record, _)| record.as_slice());
    let err = match store.write_batch(records, now) {
        Ok(Batch { outcomes, removed }) => {
            let mut stored = Vec::new();
            for ((record, reply), outcome) in batch.into_iter().zip(outcomes) {
                if let Outcome::Stored(seq) = outcome {
                    stored.push((seq, record));
                }
                let _ = reply.send(Ok(outcome));
            }
            tell((stored, removed));
            return;
        }
        Err(err) => err,
    };
    if batch.len() == 1 {
        tracing::error!("write failed: {err}");
        let (_, reply) = batch.into_iter().next().expect("one job");
        let _ = reply.send(Err(anyhow!("{err}")));
        return;
    }
    tracing::warn!(
        "a batch of {} events failed, storing them one at a time: {err}",
        batch.len()
    );
    for job in batch {
        write(store, vec![job], tell);
    }
}

/// The sequence number the next event will be stored under, as last
/// committed.
fn committed(store: &Store) -> Result<u64> {
    let txn = store.read()?;
    store.next_seq(&txn)
}

fn save_deletions(store: &Store, covered: u64) {
    let start = Instant::now();
    match store.save_deletions(covered) {
        Ok(()) => tracing::debug!("saved the deletion filter in {:.1?}", start.elapsed()),
        Err(err) => tracing::error!("saving the deletion filter failed: {err}"),
    }
}

/// The most expired events removed in one write transaction, and how many
/// the first removes: as for deleting, the transactions are sized by how
/// long the last took. After days stopped, there can be tens of thousands
/// to remove, which, cold, took minutes in one go, holding up every write.
const MAX_SWEEP: usize = 10_000;
const FIRST_SWEEP: usize = 64;

/// LMDB allows one writer at a time, so all writes go through a dedicated
/// thread that batches whatever is queued into a single transaction. Every
/// [`SWEEP_INTERVAL`] it also removes the events that have expired, a
/// chunk at a time between batches, until none are left. After
/// each batch, and whenever nothing's queued, it pushes the web of trust
/// along a turn at a time until there's nothing left to push, and carries
/// out the [pending deletions](crate::purge) a chunk at a time.
///
/// Each event's pages are [prefetched](Store::prefetch) on the blocking
/// pool before it's queued, so events arriving together have their pages
/// read in parallel rather than one after another by the writer.
#[derive(Clone)]
pub struct Writer {
    tx: std::sync::mpsc::Sender<Request>,
    store: Arc<Store>,
    thread: Arc<Mutex<Option<JoinHandle<()>>>>,
}

enum Request {
    Write(WriteJob),
    Delete(Box<DeleteJob>),
    Cancel(CancelJob),
    /// Store what's queued before this, then stop.
    Stop,
}

/// A deletion `ditto-relay delete` asks for, and where to say it's queued.
type DeleteJob = (
    Target,
    oneshot::Sender<anyhow::Result<Arc<pending::Pending>>>,
);

/// A deletion `ditto-relay cancel` cancels, and where to say it's done.
type CancelJob = (u64, oneshot::Sender<anyhow::Result<()>>);

/// Queue a deletion of what `target` covers of what's stored now.
fn queue(store: &Store, target: Target) -> anyhow::Result<Arc<pending::Pending>> {
    let queued = (|| {
        let mut txn = store.write()?;
        let watermark = store.next_seq(&txn)?;
        let pending = store.queue_deletion(&mut txn, watermark, target)?;
        txn.commit()?;
        Ok::<_, crate::lmdb::Error>(pending)
    })();
    match queued {
        Ok(pending) => {
            store.committed_queued();
            tracing::info!("{} queued, below {}", pending.describe(), pending.watermark);
            Ok(pending)
        }
        Err(err) => {
            store.forget_uncommitted();
            Err(err.into())
        }
    }
}

impl Writer {
    /// Start the writer. With `indexer`, the search indexer is told after
    /// each write that changed anything, and what it removed. `stored` is
    /// handed every batch of events stored, once they're committed.
    pub fn spawn(
        store: Arc<Store>,
        indexer: Option<std::sync::mpsc::Sender<Vec<u64>>>,
        stored: impl Fn(Vec<(u64, Arc<Vec<u8>>)>) + Send + 'static,
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<Request>();
        let tell = move |(events, removed): Written| {
            if let Some(indexer) = &indexer
                && (!events.is_empty() || !removed.is_empty())
            {
                let _ = indexer.send(removed);
            }
            if !events.is_empty() {
                stored(events);
            }
        };

        if !store.deletion_filter().1 {
            let store = store.clone();
            std::thread::Builder::new()
                .name("deletion-filter".into())
                .spawn(move || {
                    let start = Instant::now();
                    tracing::info!("catching the deletion filter up");
                    match store.catch_up_deletions() {
                        Ok(n) => tracing::info!(
                            "caught the deletion filter up with {n} deletions in {:.1?}",
                            start.elapsed()
                        ),
                        Err(err) => {
                            tracing::error!("catching the deletion filter up failed: {err}")
                        }
                    }
                })
                .expect("failed to spawn the deletion filter thread");
        }

        // Before anything's written, so a sweep under way is left alone.
        let mut purger = Purger::new(&store, Some(store.clone()), true).unwrap_or_else(|err| {
            panic!("couldn't read the pending deletions: {err:#}");
        });
        let prefetching = store.clone();
        crate::metrics::watch_writer();
        let thread = std::thread::Builder::new()
            .name("lmdb-writer".into())
            .spawn(move || {
                METRICS.writer.started();
                let phase = |phase| METRICS.writer.phase(phase);
                let mut next_sweep = Instant::now();
                let mut sweep_chunk = FIRST_SWEEP;
                let mut next_save = Instant::now() + DELETION_FILTER_SAVE_INTERVAL;
                let mut saving: Option<JoinHandle<()>> = None;
                // Whether the web of trust may have pushing to do.
                let mut trust = true;
                let turn = |trust: &mut bool| {
                    let _turn = phase(Phase::Turn);
                    *trust = store.turn().unwrap_or_else(|err| {
                        tracing::error!("a background turn failed: {err}");
                        false
                    });
                };
                let forget = || {
                    let _forget = phase(Phase::Forget);
                    if let Err(err) = store.forget() {
                        tracing::error!("removing the records of removed events failed: {err}");
                    }
                };
                loop {
                    forget();
                    if Instant::now() >= next_sweep {
                        let start = Instant::now();
                        let expiry = phase(Phase::Expiry);
                        let more = match sweep(&store, sweep_chunk) {
                            Ok((removed, more)) => {
                                tell((Vec::new(), removed));
                                more
                            }
                            Err(err) => {
                                tracing::error!("sweeping expired events failed: {err}");
                                false
                            }
                        };
                        drop(expiry);
                        sweep_chunk =
                            crate::purge::next_chunk(sweep_chunk, start.elapsed(), MAX_SWEEP);
                        forget();
                        // Expired follow lists move trust.
                        trust = true;
                        // The rest after what's queued.
                        next_sweep = match more {
                            true => Instant::now(),
                            false => Instant::now() + SWEEP_INTERVAL,
                        };
                    }
                    if Instant::now() >= next_save
                        && saving.as_ref().is_none_or(|saving| saving.is_finished())
                    {
                        // Taken here, between commits, so every deletion
                        // below it has been added.
                        match committed(&store) {
                            Ok(covered) => {
                                let store = store.clone();
                                saving = Some(std::thread::spawn(move || {
                                    save_deletions(&store, covered)
                                }));
                            }
                            Err(err) => tracing::error!("reading the next seq failed: {err}"),
                        }
                        next_save = Instant::now() + DELETION_FILTER_SAVE_INTERVAL;
                    }
                    let mut wait = match trust {
                        true => Duration::ZERO,
                        false => next_sweep.saturating_duration_since(Instant::now()),
                    };
                    if let Some(due) = purger.due(&store) {
                        wait = wait.min(due.saturating_duration_since(Instant::now()));
                    }
                    let first = match rx.recv_timeout(wait) {
                        Ok(Request::Write(job)) => {
                            METRICS.write_queue.dec();
                            job
                        }
                        Ok(Request::Delete(job)) => {
                            let _queue = phase(Phase::Queue);
                            let (target, reply) = *job;
                            let _ = reply.send(queue(&store, target));
                            continue;
                        }
                        Ok(Request::Cancel((id, reply))) => {
                            let _queue = phase(Phase::Queue);
                            let _ = reply.send(purger.cancel(&store, id));
                            continue;
                        }
                        Ok(Request::Stop) => break,
                        Err(RecvTimeoutError::Timeout) => {
                            phase(Phase::Purge).run(|| purger.step(&store, &tell));
                            if trust {
                                turn(&mut trust);
                            }
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    let mut batch = vec![first];
                    let mut stop = false;
                    let mut deletes = Vec::new();
                    let mut cancels = Vec::new();
                    while batch.len() < MAX_WRITE_BATCH {
                        match rx.try_recv() {
                            Ok(Request::Write(job)) => {
                                METRICS.write_queue.dec();
                                batch.push(job);
                            }
                            Ok(Request::Delete(job)) => deletes.push(job),
                            Ok(Request::Cancel(job)) => cancels.push(job),
                            Ok(Request::Stop) => {
                                stop = true;
                                break;
                            }
                            Err(_) => break,
                        }
                    }

                    phase(Phase::Batch).run(|| write(&store, batch, &tell));
                    let queueing = phase(Phase::Queue);
                    for job in deletes {
                        let (target, reply) = *job;
                        let _ = reply.send(queue(&store, target));
                    }
                    for (id, reply) in cancels {
                        let _ = reply.send(purger.cancel(&store, id));
                    }
                    drop(queueing);
                    if stop {
                        break;
                    }
                    // Writes come first: what runs between them waits as
                    // long as it last took.
                    purger.wrote();
                    // A follow list in the batch may have moved trust; a
                    // turn between batches keeps it from falling behind. A
                    // chunk of deleting between them keeps it going however
                    // busy the relay is.
                    turn(&mut trust);
                    phase(Phase::Purge).run(|| purger.step(&store, &tell));
                }
                forget();
                if let Some(saving) = saving {
                    let _ = saving.join();
                }
                match committed(&store) {
                    Ok(covered) => save_deletions(&store, covered),
                    Err(err) => tracing::error!("reading the next seq failed: {err}"),
                }
                // So a crash of the machine after it stops loses nothing.
                if let Err(err) = store.checkpoint() {
                    tracing::error!("the last checkpoint failed: {err:#}");
                }
            })
            .expect("failed to spawn writer thread");

        Self {
            tx,
            store: prefetching,
            thread: Arc::new(Mutex::new(Some(thread))),
        }
    }

    /// Store what's been queued, then stop: later writes fail. Blocks until
    /// the writer has stopped.
    pub fn stop(&self) {
        let _ = self.tx.send(Request::Stop);
        let thread = self.thread.lock().expect("unpoisoned").take();
        if let Some(thread) = thread
            && thread.join().is_err()
        {
            tracing::error!("the writer thread panicked");
        }
    }

    /// Queue a deletion of what `target` covers of what's stored now, as
    /// `ditto-relay delete` asks. It's hidden once this returns; the writer
    /// removes it after, between its other work, and tells the search
    /// indexer what went.
    pub async fn delete(&self, target: Target) -> anyhow::Result<Arc<pending::Pending>> {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(Request::Delete(Box::new((target, reply))))
            .is_err()
        {
            bail!("writer thread is gone");
        }
        rx.await
            .map_err(|_| anyhow!("writer thread dropped the request"))?
    }

    /// Cancel deletion `id`, as `ditto-relay cancel` asks: see
    /// [`Purger::cancel`].
    pub async fn cancel(&self, id: u64) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Request::Cancel((id, reply))).is_err() {
            bail!("writer thread is gone");
        }
        rx.await
            .map_err(|_| anyhow!("writer thread dropped the request"))?
    }

    /// Store an encoded record.
    pub async fn write(&self, record: Arc<Vec<u8>>) -> anyhow::Result<Outcome> {
        let start = Instant::now();
        let (store, prefetched) = (self.store.clone(), record.clone());
        let prefetch = tokio::task::spawn_blocking(move || {
            let txn = store.read()?;
            store.prefetch(&txn, &prefetched)
        });
        // Only a hint: the writer reads whatever it must anyway.
        if let Ok(Err(err)) = prefetch.await {
            tracing::debug!("prefetching failed: {err}");
        }
        let outcome = self
            .queue(record)?
            .await
            .map_err(|_| anyhow!("writer thread dropped the request"))?;
        METRICS.writes.since(start);
        METRICS.write_latency.observe(start.elapsed());
        outcome
    }

    /// Queue a record to be stored, now, without prefetching what storing it
    /// reads, and return where its outcome will be said. Records queued
    /// one after another are stored in that order, however many are queued
    /// before the first is stored.
    pub fn queue(
        &self,
        record: Arc<Vec<u8>>,
    ) -> anyhow::Result<oneshot::Receiver<anyhow::Result<Outcome>>> {
        let (reply, rx) = oneshot::channel();
        METRICS.write_queue.inc();
        if self.tx.send(Request::Write((record, reply))).is_err() {
            METRICS.write_queue.dec();
            bail!("writer thread is gone");
        }
        Ok(rx)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::record;

    /// An event that can't be stored is refused alone, not with the rest
    /// of its batch.
    #[test]
    fn one_failure_fails_only_its_own_event() {
        // Room for small events, not for a big one.
        let (_dir, store) = open_with(1 << 21, History::new(true, vec![], 20));
        let events = [
            signed(1, 100, 1, vec![], "small"),
            signed(1, 100, 1, vec![], &"x".repeat(4 << 20)),
            signed(1, 100, 1, vec![], "also small"),
        ];
        let (jobs, replies): (Vec<_>, Vec<_>) = events
            .iter()
            .map(|event| {
                let (reply, rx) = oneshot::channel();
                ((Arc::new(record::encode(event)), reply), rx)
            })
            .unzip();
        write(&store, jobs, &|_| {});
        let outcomes: Vec<_> = replies
            .into_iter()
            .map(|mut rx| rx.try_recv().unwrap().ok())
            .collect();
        assert!(matches!(outcomes[0], Some(Outcome::Stored(_))));
        assert!(outcomes[1].is_none());
        assert!(matches!(outcomes[2], Some(Outcome::Stored(_))));
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 2);
    }

    /// What tests index: single letters and `title`.
    pub fn test_tags() -> IndexedTags {
        IndexedTags::new(["title".to_string()]).unwrap()
    }

    /// The most values a filter field may list in tests.
    pub const MAX_VALUES: usize = 20_000;

    /// A store keeping every kind's history.
    pub fn open() -> (tempfile::TempDir, Store) {
        open_with(1 << 30, History::new(true, vec![], 20))
    }

    fn open_with(map_size: usize, history: History) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = open_in_with(dir.path(), map_size, history);
        (dir, store)
    }

    /// The store in `dir`, as [`open`] opens it.
    pub fn open_in(dir: &Path) -> Store {
        open_in_with(dir, 1 << 30, History::new(true, vec![], 20))
    }

    fn open_in_with(dir: &Path, map_size: usize, history: History) -> Store {
        Store::open(dir, map_size, test_tags(), history, None, Rank::default()).unwrap()
    }

    pub fn put(store: &Store, event: &Event) -> Outcome {
        put_at(store, event, crate::event::now())
    }

    /// Offer an event as if it were `now`, and carry out any deletion it
    /// asks for, as the writer would soon after.
    pub fn put_at(store: &Store, event: &Event, now: u32) -> Outcome {
        let outcome = store
            .write_batch([record::encode(event).as_slice()], now)
            .unwrap()
            .outcomes[0];
        settle(store);
        outcome
    }

    /// Carry out the pending deletions, and remove the records of what's
    /// been removed, as the writer would.
    pub fn settle(store: &Store) {
        crate::purge::run(store, None, &|_| {}, |_| {}).unwrap();
        store.forget().unwrap();
    }

    /// Whether an event is stored, and not expired.
    fn has(store: &Store, event: &Event) -> bool {
        let txn = store.read().unwrap();
        let id: [u8; 32] = hex::decode(&event.id).unwrap().try_into().unwrap();
        let seq = store.seq_of(&txn, &id).unwrap();
        seq.is_some_and(|seq| store.load(&txn, seq).unwrap().is_some())
    }

    /// Every entry of every table but `meta`, to compare stores.
    pub fn everything(store: &Store) -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
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
            t.wot,
            t.wot_queue,
            t.engagement,
            t.scores,
            t.ranked,
            t.applied,
            t.rank_queue,
            t.zaps,
            t.replaceable,
            t.history,
            t.expiring,
            t.pending,
            t.unlinked,
        ]
        .iter()
        .map(|&db| {
            let mut cursor = txn.cursor(db).unwrap();
            let mut entries = Vec::new();
            let mut entry = cursor.first().unwrap();
            while let Some((key, value)) = entry {
                entries.push((key.to_vec(), value.to_vec()));
                entry = cursor.next().unwrap();
            }
            entries
        })
        .collect()
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
            t.unlinked,
            t.pending,
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
        // Its record reads as gone, though it's only unlinked, until it's
        // forgotten in a transaction of its own.
        assert!(store.stored(&store.read().unwrap(), 1).unwrap().is_none());
        assert_eq!(entries(&store), 2);
        assert_eq!(store.forget().unwrap(), 1);
        assert_eq!(entries(&store), 0);

        // Sequence numbers aren't reused.
        let other = signed(1, 100, 1, vec![], "again");
        assert_eq!(put(&store, &other), Outcome::Stored(2));
    }

    /// A record unlinked when the relay stops before its writer gets to
    /// it is removed when the store's opened again.
    #[test]
    fn forgets_what_was_unlinked_when_reopened() {
        let (dir, store) = open();
        put(&store, &signed(1, 100, 1, vec![], "gone"));
        put(&store, &signed(1, 200, 1, vec![], "kept"));
        let mut txn = store.write().unwrap();
        assert!(store.remove(&mut txn, 1).unwrap());
        // Not twice.
        assert!(!store.remove(&mut txn, 1).unwrap());
        txn.commit().unwrap();
        drop(store);
        let store = open_in(dir.path());
        let txn = store.read().unwrap();
        assert_eq!(txn.len(store.tables.unlinked).unwrap(), 0);
        assert_eq!(store.len(&txn).unwrap(), 1);
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

    /// Prefetching reads what storing will, and changes nothing.
    #[test]
    fn prefetches_without_changing_anything() {
        let (_dir, store) = open();
        let note = signed(1, 100, 1, vec![vec!["t", "x"]], "hi");
        let reply = signed(
            2,
            110,
            1,
            vec![vec!["e", &note.id], vec!["p", &note.pubkey]],
            "",
        );
        let reaction = signed(3, 120, 7, vec![vec!["e", &note.id]], "+");
        let profiles = [100, 200].map(|at| signed(1, at, 0, vec![], &at.to_string()));
        let deletion = signed(1, 300, 5, vec![vec!["e", &reply.id]], "");
        let events = [
            &note,
            &reply,
            &reaction,
            &profiles[0],
            &profiles[1],
            &deletion,
        ];
        for event in events.iter().chain(&events) {
            let record = record::encode(event);
            let before = entries(&store);
            let txn = store.read().unwrap();
            store.prefetch(&txn, &record).unwrap();
            drop(txn);
            assert_eq!(entries(&store), before);
            put(&store, event);
        }
        assert!(has(&store, &profiles[1]) && has(&store, &reaction));
    }

    /// A reaction filed under every `p` tag, as once they were, is taken
    /// out of all but its last's; anything else is left as it is.
    #[test]
    fn drops_stale_tag_keys() {
        let (_dir, store) = open();
        let [copied, target] = [1, 2].map(|n| hex::encode([n; 32]));
        let tags = vec![vec!["p", copied.as_str()], vec!["p", target.as_str()]];
        let reaction = signed(9, 100, 7, tags.clone(), "+");
        let note = signed(9, 100, 1, tags, "hi");
        put(&store, &reaction);
        put(&store, &note);
        let t = store.tables;
        let key = |kind| tag_key("p", &tag_value(&copied), Some(kind));
        let mut txn = store.write().unwrap();
        let seq = |txn: &RwTxn, id: &str| {
            store
                .seq_of(txn, &decode_hex(id).unwrap())
                .unwrap()
                .unwrap()
        };
        let reaction_seq = seq(&txn, &reaction.id);
        let note_seq = seq(&txn, &note.id);
        // As it was filed before.
        txn.put_dup(t.tags, &key(7), &stamp(100, reaction_seq))
            .unwrap();
        txn.put(t.hll, &key(7), &[0; hll::REGISTERS]).unwrap();
        let view = EventView::new(
            txn.get(t.events, &reaction_seq.to_ne_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(store.stale_tag_keys(&view), [key(7)]);

        assert_eq!(
            store.drop_stale_tag_keys(&mut txn, reaction_seq).unwrap(),
            1
        );
        assert_eq!(
            store.drop_stale_tag_keys(&mut txn, reaction_seq).unwrap(),
            0
        );
        assert_eq!(store.drop_stale_tag_keys(&mut txn, note_seq).unwrap(), 0);
        assert!(txn.cursor(t.tags).unwrap().set(&key(7)).unwrap().is_none());
        assert!(txn.get(t.hll, &key(7)).unwrap().is_none());
        assert!(txn.cursor(t.tags).unwrap().set(&key(1)).unwrap().is_some());
        let target_key = tag_key("p", &tag_value(&target), Some(7));
        assert!(
            txn.cursor(t.tags)
                .unwrap()
                .set(&target_key)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn sketches_big_tag_keys() {
        sketches_big_tag_key("e", &"ef".repeat(32));
        // Packed in the key, and read back from it, as `kind:pubkey:d`.
        sketches_big_tag_key("a", &format!("30023:{}:post", "ef".repeat(32)));
    }

    fn sketches_big_tag_key(name: &str, target: &str) {
        let (_dir, store) = open();
        let reactions: Vec<Event> = (0..HLL_THRESHOLD as u32 + 5)
            .map(|n| {
                let mut secret = [1; 32];
                secret[28..].copy_from_slice(&n.to_be_bytes());
                let tags = vec![vec![name.to_string(), target.to_string()]];
                crate::event::tests::sign(secret, 100, 7, tags, "+")
            })
            .collect();
        let key = tag_key(name, &crate::record::tag_value(target), Some(7));
        let stored = |store: &Store| {
            store
                .read()
                .unwrap()
                .get(store.tables.hll, &key)
                .unwrap()
                .is_some()
        };
        for (i, event) in reactions.iter().enumerate() {
            // Reading the key's events ahead as it nears the threshold.
            let txn = store.read().unwrap();
            store.prefetch(&txn, &record::encode(event)).unwrap();
            drop(txn);
            put(&store, event);
            assert_eq!(stored(&store), i + 1 >= HLL_THRESHOLD, "{i}");
        }
        // Kept up as events arrive: the same as sketching them all now, at
        // the offset NIP-45 derives from the value.
        let mut expected = [0; hll::REGISTERS];
        for event in &reactions {
            let pubkey = crate::event::decode_hex(&event.pubkey).unwrap();
            hll::add(&mut expected, hll::offset(target), &pubkey);
        }
        let txn = store.read().unwrap();
        let kept = store.key_sketch(&txn, &key).unwrap();
        assert_eq!(kept, expected);
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
        store.forget().unwrap();
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
        store.forget().unwrap();
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
        // Hidden at once, removed after.
        assert!(batch.removed.is_empty());
        assert!(!has(&store, &note) && has(&store, &deletion));
        assert!(store.stored(&store.read().unwrap(), 1).unwrap().is_some());
        settle(&store);
        assert!(store.stored(&store.read().unwrap(), 1).unwrap().is_none());
        assert!(store.pending().is_empty());
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
        store
            .write_batch([record::encode(&deletion).as_slice()], 0)
            .unwrap();
        assert!(!has(&store, &new) && has(&store, &old));
        settle(&store);
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
        store
            .write_batch([record::encode(&request).as_slice()], 0)
            .unwrap();
        // Hidden at once, removed after.
        assert!(gone.iter().all(|event| !has(&store, event)));
        for event in [&others, &later, &later_wrap, &request] {
            assert!(has(&store, event));
        }
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 9);
        settle(&store);
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 4);
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

    /// Deletions stored since the filter was last saved are still found
    /// after a restart, in LMDB until the filter has caught up with them.
    #[test]
    fn catches_the_deletion_filter_up() {
        let (dir, store) = open();
        let reopen = || {
            let history = History::new(true, vec![], 20);
            Store::open(
                dir.path(),
                1 << 26,
                test_tags(),
                history,
                None,
                Rank::default(),
            )
            .unwrap()
        };
        let note = signed(1, 100, 1, vec![], "note");
        let profile = signed(1, 100, 0, vec![], "profile");
        let bobs = signed(2, 100, 1, vec![], "bob's");
        let address = format!("0:{}:", profile.pubkey);
        put(&store, &signed(1, 200, 5, vec![vec!["e", &note.id]], ""));
        store.save_deletions(committed(&store).unwrap()).unwrap();
        put(&store, &signed(1, 200, 5, vec![vec!["a", &address]], ""));
        put(
            &store,
            &signed(2, 200, 62, vec![vec!["relay", "ALL_RELAYS"]], ""),
        );
        // More than a chunk of them at one time.
        let others: Vec<Event> = (0..3)
            .map(|n| signed(3, 100, 1, vec![], &n.to_string()))
            .collect();
        for other in &others {
            put(&store, &signed(3, 200, 5, vec![vec!["e", &other.id]], ""));
        }
        drop(store);

        let refused = |store: &Store| {
            for event in [&note, &profile, &bobs].into_iter().chain(&others) {
                assert_eq!(put(store, event), Outcome::Deleted);
            }
        };
        let store = reopen();
        assert_eq!(store.deletion_filter(), (1, false));
        refused(&store);
        // Only what was stored since it was saved.
        assert_eq!(store.catch_up_deletions().unwrap(), 5);
        assert_eq!(store.deletion_filter(), (6, true));
        refused(&store);
        assert!(matches!(
            put(&store, &signed(3, 100, 1, vec![], "fine")),
            Outcome::Stored(_)
        ));

        // Saved up to date, it's ready at once.
        store.save_deletions(committed(&store).unwrap()).unwrap();
        drop(store);
        let store = reopen();
        assert_eq!(store.deletion_filter(), (6, true));
        refused(&store);
    }

    /// A crash after `bodies` committed but before the main environment
    /// did leaves records under sequence numbers never used, which are
    /// dropped when it's next opened, and the numbers used again.
    #[test]
    fn drops_records_never_committed() {
        let (dir, store) = open();
        let note = signed(1, 100, 1, vec![], "note");
        assert_eq!(put(&store, &note), Outcome::Stored(1));
        // What a crash between the commits leaves.
        let orphan = record::encode(&signed(2, 100, 1, vec![], "orphan"));
        let mut txn = store.write().unwrap();
        for seq in [2u64, 3] {
            txn.put(store.tables.events, &seq.to_ne_bytes(), &orphan)
                .unwrap();
        }
        txn.commit().unwrap();
        drop(store);

        let history = History::new(true, vec![], 20);
        let store = Store::open(
            dir.path(),
            1 << 26,
            test_tags(),
            history,
            None,
            Rank::default(),
        )
        .unwrap();
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 1);
        let next = signed(3, 100, 1, vec![], "next");
        assert_eq!(put(&store, &next), Outcome::Stored(2));
        assert!(has(&store, &note) && has(&store, &next));
        let txn = store.read().unwrap();
        assert_eq!(
            store.load(&txn, 2).unwrap().unwrap().content().to_text(),
            "next"
        );
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
        let (main, bodies) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        store.copy_compact(main.path(), bodies.path()).unwrap();
        let size = |dir: &tempfile::TempDir| {
            std::fs::metadata(dir.path().join("data.mdb"))
                .unwrap()
                .len() as usize
        };
        let disk = size(&main) + size(&bodies);
        println!(
            "{} bytes of indexes, {} of records",
            size(&main),
            size(&bodies)
        );
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
