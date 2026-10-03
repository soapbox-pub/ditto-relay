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
//! | `tags`          | letter ‖ value               | stamps                 |
//! | `replaceable`   | address                      | seq (u64 BE)           |
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

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::event::KindClass;
use crate::lmdb::{Db, DbFlags, Env, Result, RoTxn, RwTxn, Txn};
use crate::record::{Element, EventView};

/// Bumped when the layout changes incompatibly.
const VERSION: u32 = 1;

pub const STAMP_LEN: usize = 10;
pub type Stamp = [u8; STAMP_LEN];

/// The largest sequence number a stamp holds.
pub const MAX_SEQ: u64 = (1 << 48) - 1;

/// Tag values longer than this, encoded, aren't indexed: LMDB keys top out
/// at 511 bytes, and nobody filters by an essay.
pub const MAX_INDEXED_TAG: usize = 256;

/// Longer `d` tags are hashed in addresses, to fit in a key.
const MAX_ADDRESS_D: usize = 256;

/// The one key of the `created` table.
pub const CREATED: &[u8] = &[0];

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

/// What became of an event offered to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Stored, under this sequence number.
    Stored(u64),
    /// Already here.
    Duplicate,
    /// A newer version of it is already here.
    Replaced,
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
    pub replaceable: Db,
    pub meta: Db,
}

pub struct Store {
    env: Env,
    pub tables: Tables,
}

impl Store {
    pub fn open(dir: &Path, map_size: usize) -> anyhow::Result<Store> {
        std::fs::create_dir_all(dir).with_context(|| {
            format!("Could not create the database directory {}", dir.display())
        })?;
        let env = Env::open(dir, map_size, 16, 1024)
            .with_context(|| format!("Could not open the database at {}", dir.display()))?;
        let tables = Tables {
            events: env.create_db("events", DbFlags::INTEGER_KEY)?,
            ids: env.create_db("ids", DbFlags::DUP_FIXED)?,
            created: env.create_db("created", DbFlags::DUP_FIXED)?,
            kinds: env.create_db("kinds", DbFlags::DUP_FIXED)?,
            authors: env.create_db("authors", DbFlags::DUP_FIXED)?,
            author_kinds: env.create_db("author_kinds", DbFlags::DUP_FIXED)?,
            tags: env.create_db("tags", DbFlags::DUP_FIXED)?,
            replaceable: env.create_db("replaceable", DbFlags::PLAIN)?,
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
        Ok(Store { env, tables })
    }

    #[cfg(test)]
    pub fn copy_compact(&self, path: &Path) -> Result<()> {
        self.env.copy_compact(path)
    }

    pub fn read(&self) -> Result<RoTxn<'_>> {
        self.env.read_txn()
    }

    pub fn write(&self) -> Result<RwTxn<'_>> {
        self.env.write_txn()
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

    pub fn load<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<EventView<'t>>> {
        Ok(txn
            .get(self.tables.events, &seq.to_ne_bytes())?
            .and_then(EventView::new))
    }

    /// How many events are stored.
    #[cfg(test)]
    pub fn len(&self, txn: &Txn) -> Result<usize> {
        txn.len(self.tables.events)
    }

    /// Store a batch of encoded records in one transaction.
    pub fn write_batch<'a>(
        &self,
        records: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<Outcome>> {
        let mut txn = self.write()?;
        let outcomes = records
            .into_iter()
            .map(|record| self.insert(&mut txn, record))
            .collect::<Result<_>>()?;
        txn.commit()?;
        Ok(outcomes)
    }

    /// Offer an encoded event to the store, applying replacement. The caller
    /// has checked it's valid.
    pub fn insert(&self, txn: &mut RwTxn, record: &[u8]) -> Result<Outcome> {
        let view = EventView::new(record).expect("an encoded record");
        let t = self.tables;
        let (id, created_at) = (view.id(), view.created_at());

        if self.contains(txn, id)? {
            return Ok(Outcome::Duplicate);
        }

        let address = address_of(&view);
        let mut replaces = None;
        if let Some(address) = &address
            && let Some(seq) = self.replaceable_seq(txn, address)?
        {
            // NIP-01: the newest wins, and on a tie, the lowest id.
            if let Some(old) = self.load(txn, seq)?
                && (old.created_at(), std::cmp::Reverse(old.id()))
                    >= (created_at, std::cmp::Reverse(id))
            {
                return Ok(Outcome::Replaced);
            }
            replaces = Some(seq);
        }

        let seq = self.next_seq(txn)?;
        assert!(seq <= MAX_SEQ, "the relay has run out of sequence numbers");
        let stamp = stamp(created_at, seq);
        txn.put(t.events, &seq.to_ne_bytes(), record)?;
        txn.put_dup(t.ids, &id[..ID_PREFIX], &seq.to_be_bytes())?;
        txn.put_dup(t.created, CREATED, &stamp)?;
        for (db, key) in self.index_keys(&view) {
            txn.put_dup(db, &key, &stamp)?;
        }
        if let Some(address) = &address {
            txn.put(t.replaceable, address, &seq.to_be_bytes())?;
        }
        txn.put(t.meta, b"next_seq", &(seq + 1).to_be_bytes())?;

        if let Some(old) = replaces {
            self.remove(txn, old)?;
        }
        Ok(Outcome::Stored(seq))
    }

    fn replaceable_seq(&self, txn: &Txn, address: &[u8]) -> Result<Option<u64>> {
        Ok(txn
            .get(self.tables.replaceable, address)?
            .map(|v| u64::from_be_bytes(v.try_into().unwrap_or_default())))
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
        let mut tags: Vec<Vec<u8>> = Vec::new();
        for (letter, value) in view.indexed_tags() {
            if value.encoded_len() > MAX_INDEXED_TAG {
                continue;
            }
            let mut key = vec![letter];
            value.encode(&mut key);
            tags.push(key);
        }
        tags.sort_unstable();
        tags.dedup();
        keys.extend(tags.into_iter().map(|key| (t.tags, key)));
        keys
    }

    /// Delete a stored event and every index entry pointing at it.
    pub fn remove(&self, txn: &mut RwTxn, seq: u64) -> Result<bool> {
        let t = self.tables;
        let Some(record) = txn.get(t.events, &seq.to_ne_bytes())?.map(<[u8]>::to_vec) else {
            return Ok(false);
        };
        let view = EventView::new(&record).expect("a stored record");
        let stamp = stamp(view.created_at(), seq);

        for (db, key) in self.index_keys(&view) {
            txn.del(db, &key, Some(&stamp))?;
        }
        if let Some(address) = address_of(&view)
            && self.replaceable_seq(txn, &address)? == Some(seq)
        {
            txn.del(t.replaceable, &address, None)?;
        }
        txn.del(t.created, CREATED, Some(&stamp))?;
        txn.del(t.ids, &view.id()[..ID_PREFIX], Some(&seq.to_be_bytes()))?;
        txn.del(t.events, &seq.to_ne_bytes(), None)?;
        Ok(true)
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

fn address(pubkey: &[u8; 32], kind: u16, d: &[u8]) -> Vec<u8> {
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

/// LMDB allows one writer at a time, so all writes go through a dedicated
/// thread that batches whatever is queued into a single transaction.
#[derive(Clone)]
pub struct Writer {
    tx: std::sync::mpsc::Sender<WriteJob>,
}

impl Writer {
    pub fn spawn(store: Arc<Store>) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<WriteJob>();

        std::thread::Builder::new()
            .name("lmdb-writer".into())
            .spawn(move || {
                while let Ok(first) = rx.recv() {
                    let mut batch = vec![first];
                    while batch.len() < MAX_WRITE_BATCH {
                        match rx.try_recv() {
                            Ok(job) => batch.push(job),
                            Err(_) => break,
                        }
                    }

                    match store.write_batch(batch.iter().map(|(record, _)| record.as_slice())) {
                        Ok(outcomes) => {
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
                }
            })
            .expect("failed to spawn writer thread");

        Self { tx }
    }

    /// Store an encoded record.
    pub async fn write(&self, record: Arc<Vec<u8>>) -> anyhow::Result<Outcome> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send((record, reply))
            .map_err(|_| anyhow!("writer thread is gone"))?;
        rx.await
            .map_err(|_| anyhow!("writer thread dropped the request"))?
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::record;

    pub fn open() -> (tempfile::TempDir, Store) {
        open_sized(1 << 26)
    }

    fn open_sized(map_size: usize) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), map_size).unwrap();
        (dir, store)
    }

    pub fn put(store: &Store, event: &Event) -> Outcome {
        store
            .write_batch([record::encode(event).as_slice()])
            .unwrap()[0]
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
            t.replaceable,
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
            vec![vec!["t", "x"], vec!["t", "x"], vec!["p", &hex]],
            "hi",
        );
        assert_eq!(put(&store, &event), Outcome::Stored(1));
        assert_eq!(put(&store, &event), Outcome::Duplicate);
        // events, ids, created, kinds, authors, author_kinds, two tags.
        assert_eq!(entries(&store), 8);

        let mut txn = store.write().unwrap();
        assert!(store.remove(&mut txn, 1).unwrap());
        txn.commit().unwrap();
        assert_eq!(entries(&store), 0);

        // Sequence numbers aren't reused.
        let other = signed(1, 100, 1, vec![], "again");
        assert_eq!(put(&store, &other), Outcome::Stored(2));
    }

    #[test]
    fn keeps_the_newest_replaceable() {
        let (_dir, store) = open();
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
        let (_dir, store) = open();
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

    /// How big the database is, compacted, against the events' JSON. Slow,
    /// so run by hand: `cargo test --release disk_usage -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn disk_usage() {
        let (_dir, store) = open_sized(1 << 32);
        let events = crate::event::tests::feed(100_000);
        let json: usize = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap().len())
            .sum();
        for chunk in events.chunks(10_000) {
            let records: Vec<_> = chunk.iter().map(record::encode).collect();
            store
                .write_batch(records.iter().map(Vec::as_slice))
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
