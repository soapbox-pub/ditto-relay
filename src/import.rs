//! `ditto-relay import`: events, as JSON lines, stored as a client's would
//! be, through the relay's writer: by the running relay's, asked over its
//! [control socket](crate::control), or else by one of `import`'s own.
//!
//! Each event's id and signature are checked, unless the store has it
//! already, with the same signature, as the relay checks what it's sent;
//! on the blocking pool, a batch at a time. Then it's queued to the writer,
//! in the order it was read, so that a replaceable event's versions, and a
//! deletion and what it deletes, are stored in the order they come: many
//! are queued at once, which the writer stores in batches.
//!
//! Unlike a client's, an import isn't put to the write policy plugin: the
//! operator is vouching for it. Ephemeral events aren't stored, so they're
//! refused.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::event::{self, Event, KindClass};
use crate::record;
use crate::store::{Outcome, Store, Writer};

/// How many lines are checked at a time.
const BATCH: usize = 1000;
/// How many events may be queued to the writer and not yet stored.
const IN_FLIGHT: usize = 10_000;

/// What became of what was imported.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    /// Stored, as the current version if replaceable.
    pub stored: u64,
    /// Older than the version stored, so kept as history only.
    pub archived: u64,
    /// Here already.
    pub duplicate: u64,
    /// Refused, by why.
    pub refused: BTreeMap<String, u64>,
}

impl Tally {
    /// How many lines there were.
    pub fn total(&self) -> u64 {
        self.stored + self.archived + self.duplicate + self.refused.values().sum::<u64>()
    }

    fn refuse(&mut self, why: impl Into<String>) {
        *self.refused.entry(why.into()).or_default() += 1;
    }

    fn count(&mut self, outcome: anyhow::Result<Outcome>) {
        match outcome {
            Ok(Outcome::Stored(_)) => self.stored += 1,
            Ok(Outcome::Archived(_)) => self.archived += 1,
            Ok(Outcome::Duplicate) => self.duplicate += 1,
            Ok(Outcome::Replaced) => self.refuse("a newer version is stored"),
            Ok(Outcome::Expired) => self.refuse("expired"),
            Ok(Outcome::Deleted) => self.refuse("deleted"),
            Err(err) => {
                tracing::error!("importing an event failed: {err:#}");
                self.refuse(format!("failed to store: {err:#}"));
            }
        }
    }
}

/// An import under way, into the store `writer` writes.
pub struct Importer {
    store: Arc<Store>,
    writer: Writer,
    verify: bool,
    batch: Vec<String>,
    in_flight: VecDeque<oneshot::Receiver<anyhow::Result<Outcome>>>,
    tally: Tally,
}

/// A line, checked: the record to store, unless it's here already, or why
/// it's refused.
enum Checked {
    Record(Arc<Vec<u8>>),
    Duplicate,
    Refused(String),
}

impl Importer {
    /// With `verify` false, ids and signatures are taken on trust.
    pub fn new(store: Arc<Store>, writer: Writer, verify: bool) -> Importer {
        Importer {
            store,
            writer,
            verify,
            batch: Vec::with_capacity(BATCH),
            in_flight: VecDeque::new(),
            tally: Tally::default(),
        }
    }

    /// Import a line. Blank ones are skipped.
    pub async fn line(&mut self, line: &str) -> anyhow::Result<()> {
        if line.trim().is_empty() {
            return Ok(());
        }
        self.batch.push(line.to_string());
        if self.batch.len() >= BATCH {
            self.flush().await?;
        }
        Ok(())
    }

    /// What's become of what's been imported, as far as it's known.
    pub fn tally(&self) -> &Tally {
        &self.tally
    }

    /// Wait for everything to be stored, and say what became of it.
    pub async fn finish(mut self) -> anyhow::Result<Tally> {
        self.flush().await?;
        while let Some(rx) = self.in_flight.pop_front() {
            self.tally.count(received(rx.await));
        }
        Ok(self.tally)
    }

    /// Check the batch, and queue what's to be stored.
    async fn flush(&mut self) -> anyhow::Result<()> {
        let lines = std::mem::take(&mut self.batch);
        let (store, verify) = (self.store.clone(), self.verify);
        let checked = tokio::task::spawn_blocking(move || check(&store, verify, &lines)).await?;
        for checked in checked {
            match checked {
                Checked::Record(record) => {
                    if self.in_flight.len() >= IN_FLIGHT
                        && let Some(rx) = self.in_flight.pop_front()
                    {
                        self.tally.count(received(rx.await));
                    }
                    self.in_flight.push_back(self.writer.queue(record)?);
                }
                Checked::Duplicate => self.tally.duplicate += 1,
                Checked::Refused(why) => self.tally.refuse(why),
            }
        }
        Ok(())
    }
}

fn received(
    outcome: Result<anyhow::Result<Outcome>, oneshot::error::RecvError>,
) -> anyhow::Result<Outcome> {
    outcome.map_err(|_| anyhow::anyhow!("the writer dropped the event"))?
}

fn check(store: &Store, verify: bool, lines: &[String]) -> Vec<Checked> {
    let txn = store.read();
    lines
        .iter()
        .map(|line| {
            let ev: Event = match serde_json::from_str(line) {
                Ok(ev) => ev,
                Err(_) => return Checked::Refused("not a NIP-01 event".into()),
            };
            if ev.kind_class() == KindClass::Ephemeral {
                return Checked::Refused("ephemeral".into());
            }
            // As the relay checks what it's sent: one with the stored
            // copy's signature is that event, checked when it was stored.
            if let (Ok(txn), Some(id), Some(sig)) = (
                &txn,
                event::decode_hex::<32>(&ev.id),
                event::decode_hex::<64>(&ev.sig),
            ) && store.sig_of(txn, &id).ok().flatten() == Some(sig)
            {
                return Checked::Duplicate;
            }
            if verify && let Err(why) = ev.verify() {
                return Checked::Refused(why);
            }
            Checked::Record(Arc::new(record::encode(&ev)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::store::tests::open;

    #[tokio::test(flavor = "multi_thread")]
    async fn imports_in_order_and_says_what_became_of_it() {
        let (_dir, store) = open();
        let store = Arc::new(store);
        let writer = Writer::spawn(store.clone(), None, |_| {});
        let note = signed(1, 100, 1, vec![], "hello");
        let old = signed(1, 100, 0, vec![], "old profile");
        let new = signed(1, 200, 0, vec![], "new profile");
        let deletion = signed(1, 300, 5, vec![vec!["e", &note.id]], "");
        let mut forged = signed(2, 100, 1, vec![], "forged");
        forged.content = "changed".into();
        let ephemeral = signed(2, 100, 20001, vec![], "");
        let json = |ev: &Event| serde_json::to_string(ev).unwrap();
        let mut importer = Importer::new(store.clone(), writer.clone(), true);
        for line in [
            json(&note),
            json(&new),
            json(&old),
            json(&note),
            "".into(),
            "not json".into(),
            json(&forged),
            json(&ephemeral),
            json(&deletion),
        ] {
            importer.line(&line).await.unwrap();
        }
        let tally = importer.finish().await.unwrap();
        assert_eq!((tally.stored, tally.archived, tally.duplicate), (3, 1, 1));
        assert_eq!(
            tally.refused,
            BTreeMap::from([
                ("ephemeral".to_string(), 1),
                ("invalid: event id does not match".to_string(), 1),
                ("not a NIP-01 event".to_string(), 1),
            ])
        );
        assert_eq!(tally.total(), 8);

        // Stored in order: the deletion, after the note, deleted it: hidden,
        // or by now gone.
        let txn = store.read().unwrap();
        let seq = store.seq_of(&txn, &event::decode_hex(&note.id).unwrap());
        assert!(
            seq.unwrap()
                .is_none_or(|seq| store.load(&txn, seq).unwrap().is_none())
        );
        drop(txn);

        // Already here, it's not checked again.
        let mut importer = Importer::new(store.clone(), writer.clone(), true);
        importer.line(&json(&new)).await.unwrap();
        assert_eq!(importer.finish().await.unwrap().duplicate, 1);
        tokio::task::spawn_blocking(move || writer.stop())
            .await
            .unwrap();
    }
}
