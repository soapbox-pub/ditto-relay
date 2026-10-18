//! `ditto-relay export`: stored events as JSON, a line each, as clients
//! would see them: not those expired, nor those a pending deletion covers.
//!
//! They're written in the order they were stored, so that importing them
//! elsewhere stores each replaceable event's versions, and each deletion,
//! in the order they were first. Without a filter, that's every event in
//! the store, old versions kept as history too; with one, what it matches,
//! or picks, as `ditto-relay delete` would find it.
//!
//! It only reads, from a store opened [only to read](Store::open_read_only),
//! so it never holds up the relay, and it reads in transactions of
//! [`CHUNK`] events at most, so that a long export doesn't keep the relay's
//! writer from reusing pages, as a transaction held all along would.

use std::io::Write;

use crate::delete;
use crate::filter::Filter;
use crate::store::Store;

/// The most events read in a transaction.
const CHUNK: usize = 10_000;

/// How far ahead of the records being read the kernel is asked to read.
const READ_AHEAD: usize = 64 << 20;

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
