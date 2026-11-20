//! Watching the reads that keep LMDB from reusing pages.
//!
//! LMDB never writes over a page an open read transaction may still see, so
//! no page freed since the oldest open read is reused: while one stays open,
//! every page written meanwhile goes on the end of the file, which never
//! shrinks. The relay's own reads are short, and a checkpoint pins one for
//! ten or twenty seconds, but a repack's copy reads for as long as it takes,
//! and a process that dies mid-read, as a `ditto-relay` command killed from
//! a shell can, leaves its slot in the reader table reading on until every
//! process has closed the environment.
//!
//! So the writer's process notes each environment's latest commit every few
//! seconds, to tell how long the oldest read has held pages back (since the
//! commit after the one it reads); warns while one has for long; and every
//! minute frees the slots of processes that died.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::lmdb::Readers;
use crate::store::Store;

/// How often each environment's readers are looked at.
const SAMPLE_EVERY: Duration = Duration::from_secs(5);

/// How often the slots of processes that died are freed.
const CLEAR_EVERY: Duration = Duration::from_secs(60);

/// How far back the commits sampled go, which is as old as a read can be
/// told to be: older ones are said to be at least this old.
const KEPT: Duration = Duration::from_secs(2 * 24 * 60 * 60);

/// A read holding pages back this long is warned of, at most this often
/// while it lasts.
const LONG_READ: Duration = Duration::from_secs(10 * 60);

/// The environments watched, by the names metrics and the log give them.
pub const ENVS: [&str; 2] = ["main", "bodies"];

/// What's known of one environment's reads.
pub struct EnvReads {
    /// Its latest commit, every [`SAMPLE_EVERY`], oldest first.
    samples: Mutex<VecDeque<(u64, Instant)>>,
    /// How long the oldest open read has kept LMDB from reusing pages, in
    /// seconds, as f64 bits.
    oldest_secs: AtomicU64,
    /// How many reads are open.
    open: AtomicU64,
    /// Slots freed of processes that died.
    pub cleared: AtomicU64,
}

impl EnvReads {
    const fn new() -> EnvReads {
        EnvReads {
            samples: Mutex::new(VecDeque::new()),
            oldest_secs: AtomicU64::new(0),
            open: AtomicU64::new(0),
            cleared: AtomicU64::new(0),
        }
    }

    /// How long the oldest open read has kept LMDB from reusing pages, in
    /// seconds (0 with none open, or none older than the latest commit),
    /// and how many reads are open.
    pub fn oldest(&self) -> (f64, u64) {
        (
            f64::from_bits(self.oldest_secs.load(Ordering::Relaxed)),
            self.open.load(Ordering::Relaxed),
        )
    }

    /// Note the readers seen at `now`, and return how long the oldest open
    /// read has kept LMDB from reusing pages, and the commit it reads.
    fn note(&self, readers: &Readers, now: Instant) -> Option<(Duration, u64)> {
        let mut samples = self.samples.lock().expect("unpoisoned");
        if samples
            .back()
            .is_none_or(|&(latest, _)| latest != readers.latest)
        {
            samples.push_back((readers.latest, now));
        }
        while samples
            .front()
            .is_some_and(|&(_, at)| now.duration_since(at) > KEPT)
        {
            samples.pop_front();
        }
        let oldest = readers.reading.iter().min().copied();
        let age = oldest.map(|txnid| (blocking(&samples, txnid, now), txnid));
        let secs = age.map_or(0.0, |(age, _)| age.as_secs_f64());
        self.oldest_secs.store(secs.to_bits(), Ordering::Relaxed);
        self.open
            .store(readers.reading.len() as u64, Ordering::Relaxed);
        age
    }
}

/// How long a read of commit `txnid` has kept LMDB from reusing pages, from
/// `samples` of the latest commit, oldest first: since the first sample of
/// a later commit, as nothing's freed until one. A read older than every
/// sample is said to have done so since the first.
fn blocking(samples: &VecDeque<(u64, Instant)>, txnid: u64, now: Instant) -> Duration {
    let later = samples.partition_point(|&(latest, _)| latest <= txnid);
    match samples.get(later) {
        Some(&(_, at)) => now.duration_since(at),
        None => Duration::ZERO,
    }
}

/// Each watched environment's, in the order of [`ENVS`].
pub static READS: [EnvReads; 2] = [EnvReads::new(), EnvReads::new()];

/// Watch `store`'s readers on a thread of its own, for as long as the
/// process runs. Only once, however often it's called.
pub fn watch(store: Arc<Store>) {
    static WATCHING: std::sync::Once = std::sync::Once::new();
    WATCHING.call_once(|| {
        let spawned = std::thread::Builder::new()
            .name("reader-watch".into())
            .spawn(move || run(&store));
        if let Err(err) = spawned {
            tracing::warn!("couldn't start watching LMDB's readers: {err}");
        }
    });
}

fn run(store: &Store) {
    let envs = [0, store.bodies_env()];
    let mut warned = [None::<Instant>; 2];
    let mut next_clear = Instant::now();
    loop {
        let now = Instant::now();
        let clearing = now >= next_clear;
        if clearing {
            next_clear = now + CLEAR_EVERY;
        }
        for (i, &env) in envs.iter().enumerate() {
            let name = ENVS[i];
            if clearing {
                match store.env().clear_dead_readers(env) {
                    Ok(0) => {}
                    Ok(n) => {
                        READS[i].cleared.fetch_add(n as u64, Ordering::Relaxed);
                        let slots = if n == 1 { "slot" } else { "slots" };
                        tracing::warn!(
                            "freed {n} {slots} in the {name} environment's reader table of processes that died mid-read, which kept LMDB from reusing pages freed since"
                        );
                    }
                    Err(err) => {
                        tracing::warn!("checking the {name} environment's readers failed: {err}")
                    }
                }
            }
            let readers = match store.env().readers(env) {
                Ok(readers) => readers,
                Err(err) => {
                    tracing::warn!("listing the {name} environment's readers failed: {err}");
                    continue;
                }
            };
            let long = READS[i]
                .note(&readers, now)
                .filter(|&(age, _)| age >= LONG_READ);
            if let Some((age, txnid)) = long
                && warned[i].is_none_or(|at| now.duration_since(at) >= LONG_READ)
            {
                warned[i] = Some(now);
                tracing::warn!(
                    "a read of the {name} environment, of commit {txnid}, has kept LMDB from reusing pages for {:.0?}, {} commits: every page written meanwhile goes on the end of its file",
                    Duration::from_secs(age.as_secs()),
                    readers.latest.saturating_sub(txnid)
                );
            }
        }
        std::thread::sleep(SAMPLE_EVERY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_how_long_a_read_has_held_pages_back() {
        let start = Instant::now();
        let s = |secs| start + Duration::from_secs(secs);
        let samples: VecDeque<_> = [(10, s(0)), (20, s(5)), (30, s(10))].into();
        let now = s(60);
        // Since the first later commit sampled.
        assert_eq!(blocking(&samples, 10, now), Duration::from_secs(55));
        assert_eq!(blocking(&samples, 25, now), Duration::from_secs(50));
        // Of the latest commit, or a newer one: nothing's held back.
        assert_eq!(blocking(&samples, 30, now), Duration::ZERO);
        assert_eq!(blocking(&samples, 40, now), Duration::ZERO);
        // Older than every sample: since the first, at least.
        assert_eq!(blocking(&samples, 3, now), Duration::from_secs(60));
    }

    #[test]
    fn notes_the_oldest_open_read() {
        let reads = EnvReads::new();
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let readers = |latest, reading: &[u64]| Readers {
            latest,
            reading: reading.to_vec(),
        };
        assert_eq!(reads.note(&readers(5, &[]), at(0)), None);
        assert_eq!(reads.oldest(), (0.0, 0));
        // Reading the latest commit holds nothing back.
        assert_eq!(
            reads.note(&readers(5, &[5]), at(10)),
            Some((Duration::ZERO, 5))
        );
        assert_eq!(reads.oldest(), (0.0, 1));
        // Once there's a later one, since then.
        reads.note(&readers(6, &[5]), at(20));
        assert_eq!(
            reads.note(&readers(9, &[9, 5]), at(50)),
            Some((Duration::from_secs(30), 5))
        );
        assert_eq!(reads.oldest(), (30.0, 2));
    }
}
