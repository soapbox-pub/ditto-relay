//! `ditto-relay export`: stored events as JSON, a line each, as clients
//! would see them: not those expired, nor those a pending deletion covers.
//!
//! They're written in the order they were stored, so that importing them
//! elsewhere stores each replaceable event's versions, and each deletion,
//! in the order they were first. Without a filter, that's every event in
//! the store, old versions kept as history too; with one, what it matches,
//! or picks, as `ditto-relay delete` would find it.
//!
//! With `--history`, it's every version of each replaceable or addressable
//! event's address the store keeps, current and replaced, still in the
//! order they were stored: what a filter leaves out, as replaced versions
//! are in no index but `history`.
//!
//! It only reads, from a store opened [only to read](Store::open_read_only),
//! so it never holds up the relay, and it reads in transactions of
//! [`CHUNK`] events at most, so that a long export doesn't keep the relay's
//! writer from reusing pages, as a transaction held all along would.

use std::io::Write;
use std::path::Path;

use crate::delete;
use crate::filter::Filter;
use crate::lmdb::{DbFlags, Env};
use crate::record::EventView;
use crate::store::{STAMP_LEN, Store, stamp_seq};

/// The most events read in a transaction.
const CHUNK: usize = 10_000;

/// How far ahead of the records being read the kernel is asked to read.
const READ_AHEAD: usize = 64 << 20;

/// Write to `out` every version of every address the store keeps history
/// of, current and replaced, in the order stored, telling `progress` how
/// many so far after each chunk. Returns how many were written.
pub fn export_history(
    store: &Store,
    out: &mut impl Write,
    mut progress: impl FnMut(u64),
) -> anyhow::Result<u64> {
    let mut seqs = Vec::new();
    {
        let txn = store.read()?;
        let mut cursor = txn.cursor(store.tables.history)?;
        let mut entry = cursor.first()?;
        while let Some((_, stamp)) = entry {
            if stamp.len() >= STAMP_LEN {
                seqs.push(stamp_seq(stamp));
            }
            entry = cursor.next()?;
        }
    }
    seqs.sort_unstable();
    seqs.dedup();
    let written = write_seqs(store, &seqs, out, &mut progress)?;
    out.flush()?;
    Ok(written)
}

/// Write the events stored under `seqs` to `out`, a chunk at a time.
fn write_seqs(
    store: &Store,
    seqs: &[u64],
    out: &mut impl Write,
    progress: &mut impl FnMut(u64),
) -> anyhow::Result<u64> {
    let mut written = 0;
    for chunk in seqs.chunks(CHUNK) {
        store.read_ahead(chunk);
        let txn = store.read()?;
        for &seq in chunk {
            if let Some(view) = store.load(&txn, seq)? {
                writeln!(out, "{}", view.to_json())?;
                written += 1;
            }
        }
        progress(written);
    }
    Ok(written)
}

/// Write to `out` what `filter` matches, or everything, telling `progress`
/// how many so far after each chunk. Returns how many were written.
pub fn export(
    store: &Store,
    filter: Option<&Filter>,
    out: &mut impl Write,
    mut progress: impl FnMut(u64),
) -> anyhow::Result<u64> {
    let mut written = 0;
    match filter {
        Some(filter) => {
            let seqs: Vec<u64> = delete::pick(store, filter)?.into_iter().collect();
            written = write_seqs(store, &seqs, out, &mut progress)?;
        }
        None => {
            let mut from = 0u64;
            loop {
                let txn = store.read()?;
                let mut cursor = txn.cursor(store.tables.events)?;
                let mut entry = cursor.set_range(&from.to_ne_bytes())?;
                let mut read_ahead = 0usize;
                let mut read = 0;
                while let Some((key, record)) = entry {
                    let seq = u64::from_ne_bytes(key.try_into()?);
                    let at = record.as_ptr() as usize;
                    if at.abs_diff(read_ahead) > READ_AHEAD / 2 {
                        store.will_need_records(record, READ_AHEAD);
                        read_ahead = at;
                    }
                    if let Some(view) = store.load(&txn, seq)? {
                        writeln!(out, "{}", view.to_json())?;
                        written += 1;
                    }
                    from = seq + 1;
                    read += 1;
                    if read == CHUNK {
                        break;
                    }
                    entry = cursor.next()?;
                }
                progress(written);
                if read < CHUNK {
                    break;
                }
            }
        }
    }
    out.flush()?;
    Ok(written)
}

/// Write to `out` every event in the records file in `dir`, a store's
/// `bodies`, in the order stored, reading nothing else of the store: so
/// that a store whose main file is lost or damaged can be stored anew by
/// importing them. Old versions, expired events, and what deletions cover
/// are among them, as the store kept them; importing sorts that out again.
/// Tells `progress` how many so far, and the last sequence number read,
/// every so often. Returns how many it wrote, and how many records it
/// couldn't read. A damaged table can lead the walk back to where it's
/// been: sequence numbers only rise, so one that doesn't stops it.
pub fn salvage(
    dir: &Path,
    map_size: usize,
    from: u64,
    out: &mut impl Write,
    mut progress: impl FnMut(u64, u64),
) -> anyhow::Result<(u64, u64)> {
    let env = Env::open_read_only(dir, map_size, 2, 16)?;
    let events = env.create_db("events", DbFlags::INTEGER_KEY)?;
    let (mut written, mut unreadable) = (0, 0);
    let mut read_ahead = 0usize;
    let mut last: Option<u64> = None;
    // A chunk of records a read, as the file may be a running relay's.
    loop {
        let txn = env.read_txn()?;
        let mut cursor = txn.cursor(events)?;
        let start = last.map_or(from, |last| last + 1);
        let mut entry = cursor.set_range(&start.to_ne_bytes())?;
        let mut read = 0;
        while let Some((key, record)) = entry {
            let seq = u64::from_ne_bytes(key.try_into()?);
            if last.is_some_and(|last| seq <= last) {
                anyhow::bail!(
                    "the records are damaged: after {} came {seq}, having written {written}",
                    last.unwrap_or_default()
                );
            }
            last = Some(seq);
            let at = record.as_ptr() as usize;
            if at.abs_diff(read_ahead) > READ_AHEAD / 2 {
                env.will_need(0, record, READ_AHEAD);
                read_ahead = at;
            }
            match EventView::new(record) {
                Some(view) => {
                    writeln!(out, "{}", view.to_json())?;
                    written += 1;
                    if written % CHUNK as u64 == 0 {
                        progress(written, seq);
                    }
                }
                None => unreadable += 1,
            }
            read += 1;
            if read == CHUNK {
                break;
            }
            entry = cursor.next()?;
        }
        if read < CHUNK {
            break;
        }
    }
    out.flush()?;
    Ok((written, unreadable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::store::tests::{open, put, test_tags};
    use serde_json::{Value, json};

    fn export_all(store: &Store, filter: Option<Value>) -> Vec<Value> {
        let filter = filter.map(|filter| Filter::parse(&filter, &test_tags(), 1000).unwrap());
        let mut out = Vec::new();
        let written = export(store, filter.as_ref(), &mut out, |_| {}).unwrap();
        let lines: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len() as u64, written);
        lines
    }

    #[test]
    fn salvages_every_record_from_the_records_file_alone() {
        let (dir, store) = open();
        let profile = signed(1, 100, 0, vec![], "old profile");
        let newer = signed(1, 200, 0, vec![], "new profile");
        let note = signed(2, 100, 1, vec![], "note");
        for event in [&profile, &newer, &note] {
            put(&store, event);
        }
        store.checkpoint().unwrap();
        drop(store);
        // Without the main file at all.
        std::fs::remove_file(dir.path().join("data.mdb")).unwrap();
        let mut out = Vec::new();
        let (written, unreadable) = salvage(
            &dir.path().join(crate::store::BODIES_DIR),
            1 << 30,
            0,
            &mut out,
            |_, _| {},
        )
        .unwrap();
        assert_eq!((written, unreadable), (3, 0));
        let ids: Vec<String> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<Value>(line).unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(ids, [profile.id, newer.id, note.id]);
        // From the third on.
        let mut out = Vec::new();
        let bodies = dir.path().join(crate::store::BODIES_DIR);
        assert_eq!(
            salvage(&bodies, 1 << 30, 3, &mut out, |_, _| {}).unwrap(),
            (1, 0)
        );
    }

    #[test]
    fn exports_what_clients_would_see_in_the_order_stored() {
        let (_dir, store) = open();
        let first = signed(1, 300, 1, vec![vec!["t", "a"]], "first");
        let second = signed(2, 100, 1, vec![], "second");
        let expired = signed(3, 200, 1, vec![vec!["expiration", "1"]], "gone");
        let profile = signed(1, 100, 0, vec![], "old profile");
        let newer = signed(1, 200, 0, vec![], "new profile");
        for event in [&first, &second, &expired, &profile, &newer] {
            put(&store, event);
        }
        let ids = |lines: Vec<Value>| -> Vec<String> {
            lines
                .iter()
                .map(|line| line["id"].as_str().unwrap().to_string())
                .collect()
        };
        // History too, without a filter.
        assert_eq!(
            ids(export_all(&store, None)),
            [
                first.id.as_str(),
                second.id.as_str(),
                profile.id.as_str(),
                newer.id.as_str()
            ]
        );
        assert_eq!(
            ids(export_all(&store, Some(json!({"kinds": [1]})))),
            [first.id.as_str(), second.id.as_str()]
        );
        assert_eq!(
            ids(export_all(&store, Some(json!({"#t": ["a"]})))),
            [first.id.as_str()]
        );
        // What a limit picks, still in the order stored.
        assert_eq!(
            ids(export_all(&store, Some(json!({"kinds": [1], "limit": 1})))),
            [first.id.as_str()]
        );

        let line = &export_all(&store, Some(json!({"ids": [second.id]})))[0];
        assert_eq!(line, &serde_json::to_value(&second).unwrap());
    }

    /// Every version of each address, replaced ones too, in the order
    /// stored, and nothing else.
    #[test]
    fn exports_history() {
        let (_dir, store) = open();
        let note = signed(1, 300, 1, vec![], "note");
        let profile = signed(1, 100, 0, vec![], "old profile");
        let newer = signed(1, 200, 0, vec![], "new profile");
        let list = signed(2, 100, 30000, vec![vec!["d", "x"]], "old list");
        let later = signed(2, 150, 30000, vec![vec!["d", "x"]], "new list");
        for event in [&note, &profile, &list, &newer, &later] {
            put(&store, event);
        }
        let mut out = Vec::new();
        let written = export_history(&store, &mut out, |_| {}).unwrap();
        let ids: Vec<String> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<Value>(line).unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(written, 4);
        assert_eq!(
            ids,
            [&profile.id, &list.id, &newer.id, &later.id].map(String::clone)
        );
    }

    /// More than a chunk, read across transactions.
    #[test]
    fn exports_across_chunks() {
        let (_dir, store) = open();
        let events: Vec<_> = (0..CHUNK as u64 + 5)
            .map(|i| signed(1, 1000 + i, 1, vec![], "x"))
            .collect();
        store
            .write_batch(
                events
                    .iter()
                    .map(crate::record::encode)
                    .collect::<Vec<_>>()
                    .iter()
                    .map(Vec::as_slice),
                0,
            )
            .unwrap();
        assert_eq!(export_all(&store, None).len(), events.len());
        assert_eq!(
            export_all(&store, Some(json!({"kinds": [1]}))).len(),
            events.len()
        );
    }
}
