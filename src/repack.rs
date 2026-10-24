//! `ditto-relay repack`: [compacting](crate::compact) the database while
//! the relay runs.
//!
//! The copy is made as `compact` makes it, of the environment as it was
//! when it began, read in one transaction throughout. Meanwhile the relay
//! goes on reading and writing the old file, and what it commits to it is
//! kept in a [`Journal`], replayed into the copy once it's made, round
//! after round, until a round takes little time. Then, holding the
//! writer's lock, so that the writer waits, the rest is replayed, the copy
//! is checked to hold as many entries in each table as the store, and it's
//! put in the old file's place: on disk, by renaming it over the old, and
//! in the store, by [replacing](Env::replace) the environment. Reads under
//! way go on in the old file, whose space is freed once the last ends.
//!
//! The copy, and the journal, are made in `repack/` beside the file, and
//! need room for about what's live, and for what's written meanwhile. The
//! old file grows meanwhile too, as the copy's transaction keeps LMDB from
//! reusing the pages it reads.
//!
//! A crash before the copy's in place leaves the store as it was, and what
//! was made in `repack/` is removed when the store next opens. Before the
//! copy's renamed into place, both files are flushed to disk, so that each
//! is the store as it is then, and a [checkpoint](crate::checkpoint) of
//! the store with the copy in place of the old file is saved: until the
//! copy's renamed, the checkpoint is of no file there, and isn't used, and
//! after, it's of the files there.

use std::fs::File;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};

use crate::checkpoint;
use crate::compact::{self, Progress};
use crate::lmdb::{Env, Journal};
use crate::store::{BODIES_DIR, Store};

/// Where the copy and the journal are made, beside the file repacked.
pub const WORK_DIR: &str = "repack";

const JOURNAL_FILE: &str = "journal";
const DATA_FILE: &str = "data.mdb";
const LOCK_FILE: &str = "lock.mdb";

/// A round of catching up that takes less is the last before the writer
/// waits for the rest, which should take about as long.
const CAUGHT_UP: Duration = Duration::from_secs(1);

/// The most rounds of catching up, after which the writer waits for the
/// rest however long it takes.
const MAX_ROUNDS: usize = 20;

/// What a repack did.
#[derive(Debug, Serialize, Deserialize)]
pub struct Repacked {
    /// Every table copied, and how many entries it had as the copy was
    /// made.
    pub tables: Vec<(String, u64)>,
    /// The size of the file repacked, and of its copy.
    pub before: u64,
    pub after: u64,
    pub elapsed: Duration,
    /// How long the writer waited, of it.
    pub paused: Duration,
}

/// Remove what a repack that didn't finish left in the database in `dir`.
pub fn clear_leftovers(dir: &Path) -> std::io::Result<()> {
    for dir in [dir.to_path_buf(), dir.join(BODIES_DIR)] {
        match std::fs::remove_dir_all(dir.join(WORK_DIR)) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
    }
    Ok(())
}

/// Repack the main environment of `store`, or with `bodies`, `bodies`,
/// reading ahead on `threads` threads, as [`compact`] does, while it's
/// read and written: see [`self`]. `say` is told how it's going.
pub fn repack(
    store: &Store,
    bodies: bool,
    threads: usize,
    say: &mut dyn FnMut(&str),
) -> anyhow::Result<Repacked> {
    ensure!(
        !store.repacking.swap(true, Ordering::SeqCst),
        "a repack is under way already"
    );
    let repacked = run(store, bodies, threads, say);
    store.repacking.store(false, Ordering::SeqCst);
    repacked
}

fn run(
    store: &Store,
    bodies: bool,
    threads: usize,
    say: &mut dyn FnMut(&str),
) -> anyhow::Result<Repacked> {
    let start = Instant::now();
    let env = store.env();
    let (which, dir, name) = match bodies {
        true => (store.bodies_env(), store.dir().join(BODIES_DIR), "bodies"),
        false => (0, store.dir().to_path_buf(), "the indexes"),
    };
    let unopened = env.unopened_tables(which)?;
    ensure!(
        unopened.is_empty(),
        "{} has tables the relay doesn't use ({}): with the relay stopped, `ditto-relay compact` copies them too",
        dir.join(DATA_FILE).display(),
        unopened.join(", ")
    );
    let work = dir.join(WORK_DIR);
    match std::fs::remove_dir_all(&work) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            return Err(err).with_context(|| format!("Could not remove {}", work.display()));
        }
        _ => {}
    }
    std::fs::create_dir(&work).with_context(|| format!("Could not create {}", work.display()))?;
    let before = env.usage(which)?.used;
    let repacked = (|| {
        let dest = env
            .create_like(which, &work)
            .with_context(|| format!("Could not create a database at {}", work.display()))?;
        let (journal, reading) = env
            .journal(which, &work.join(JOURNAL_FILE))
            .context("Could not begin keeping a journal")?;
        let _stop = StopJournal(env);
        tell(
            say,
            format!("copying {name}, {:.1} GB", before as f64 / 1e9),
        );
        let tables =
            compact::copy_live(env, which, &reading, &dest, threads, &mut |p: &Progress| {
                say(&p.to_string())
            })?;
        drop(reading);
        let mut at = 0;
        for _ in 0..MAX_ROUNDS {
            let began = Instant::now();
            let to = dest.replay(&journal, at, false)?;
            tell(
                say,
                format!(
                    "caught up with {:.1} MB written meanwhile, in {:.1?}",
                    (to - at) as f64 / 1e6,
                    began.elapsed()
                ),
            );
            at = to;
            if began.elapsed() < CAUGHT_UP {
                break;
            }
        }
        let (after, paused) = swap(store, which, &dir, &work, dest, &journal, at)?;
        tell(
            say,
            format!(
                "put the copy of {name} in place, the writer waiting {paused:.1?}: {:.1} GB, from {:.1} GB",
                after as f64 / 1e9,
                before as f64 / 1e9
            ),
        );
        Ok(Repacked {
            tables,
            before,
            after,
            elapsed: start.elapsed(),
            paused,
        })
    })();
    // The journal, and the copy if it isn't in place. If it can't be
    // removed, it is when the store next opens.
    if let Err(err) = std::fs::remove_dir_all(&work) {
        tracing::warn!("couldn't remove {}: {err}", work.display());
    }
    repacked
}

/// Say `line`, and log it.
fn tell(say: &mut dyn FnMut(&str), line: String) {
    tracing::info!("repack: {line}");
    say(&line);
}

/// Stops the journal when dropped, however the repack ends.
struct StopJournal<'a>(&'a Env);

impl Drop for StopJournal<'_> {
    fn drop(&mut self) {
        self.0.stop_journal();
    }
}

/// Put `dest`, a copy of environment `which` of `store`, kept in `dir`, as
/// it was up to `at` in `journal`, in its place, holding the writer's lock
/// while the rest is replayed. Returns the copy's size, and how long the
/// writer waited.
fn swap(
    store: &Store,
    which: usize,
    dir: &Path,
    work: &Path,
    dest: Env,
    journal: &Journal,
    at: u64,
) -> anyhow::Result<(u64, Duration)> {
    let env = store.env();
    store.without_checkpoints(|| {
        let writing = env.write_txn()?;
        let paused = Instant::now();
        dest.replay(journal, at, true)?;
        env.stop_journal();
        // As many entries as the store's tables have now, in the same ones.
        let copy = dest.read_txn()?;
        let (theirs, ours) = (env.tables_of(which), dest.tables_of(0));
        ensure!(
            theirs.len() == ours.len(),
            "tables were opened as the copy was made"
        );
        for ((name, db, _), (_, copied, _)) in theirs.iter().zip(&ours) {
            let (want, got) = (writing.len(*db)?, copy.len(*copied)?);
            ensure!(
                want == got,
                "the copy of the table {name} has {got} entries, not {want}"
            );
        }
        drop(copy);
        // Both files the store as it is now, on disk.
        env.sync()?;
        dest.sync()?;
        let after = dest.usage(0)?.used;
        let old = env.replace(which, dest);
        if let Err(err) = put_in_place(store, which, dir, work) {
            drop(env.replace(which, old));
            // The checkpoint saved may be the copy's: one of the old file.
            let checkpointed = checkpoint::begin(env).and_then(|metas| {
                checkpoint::finish(env, store.dir(), &store.files(), store.boot_id(), &metas)
            });
            if let Err(err) = checkpointed {
                tracing::error!("a checkpoint after the repack failed: {err:#}");
            }
            return Err(err);
        }
        drop(writing);
        Ok((after, paused.elapsed()))
    })
}

/// With the copy in the store in place of environment `which`, flushed to
/// disk, save a checkpoint of it, then rename it, from `work`, over the
/// file in `dir`.
fn put_in_place(store: &Store, which: usize, dir: &Path, work: &Path) -> anyhow::Result<()> {
    let env = store.env();
    let metas = checkpoint::begin(env)?;
    env.sync()?;
    let mut files = store.files();
    files[which] = work.join(DATA_FILE);
    checkpoint::save(store.dir(), store.boot_id(), &files, &metas)
        .context("Could not save a checkpoint of the copy")?;
    // The lock file first: another process opening the store between the
    // two renames reads the old file, written no more, rather than the
    // copy, whose writer wouldn't know of it.
    let rename = |file: &str| {
        std::fs::rename(work.join(file), dir.join(file))
            .with_context(|| format!("Could not put {} in place", work.join(file).display()))
    };
    rename(LOCK_FILE)?;
    rename(DATA_FILE)?;
    if let Err(err) = File::open(dir).and_then(|dir| dir.sync_all()) {
        tracing::warn!("couldn't flush {} to disk: {err}", dir.display());
    }
    env.confirm_checkpoint();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    use super::*;
    use crate::event::tests::signed;
    use crate::store::tests::{everything, open_in, put};

    /// A store with many events, most of them removed.
    fn filled(dir: &Path) -> Store {
        let store = open_in(dir);
        let topics: Vec<String> = (0..7).map(|n| format!("t{n}")).collect();
        for n in 0..400u64 {
            let tags = vec![vec!["t", topics[n as usize % 7].as_str()]];
            put(
                &store,
                &signed(
                    1 + (n % 5) as u8,
                    1000 + n,
                    1,
                    tags,
                    &"x".repeat(n as usize * 20),
                ),
            );
        }
        let mut txn = store.write().unwrap();
        for seq in (1..=400).filter(|seq| seq % 4 != 0) {
            store.remove(&mut txn, seq).unwrap();
        }
        txn.commit().unwrap();
        store.forget().unwrap();
        store.checkpoint().unwrap();
        store
    }

    /// Write events, and remove some, until told to stop, counting them in
    /// `writes`.
    fn keep_writing(store: &Store, stop: &AtomicBool, writes: &AtomicU64) {
        while !stop.load(Ordering::Relaxed) {
            let n = writes.load(Ordering::Relaxed);
            put(
                store,
                &signed(9, 5000 + n, 1, vec![vec!["t", "new"]], "meanwhile"),
            );
            if n.is_multiple_of(3) {
                let mut txn = store.write().unwrap();
                let last = store.next_seq(&txn).unwrap() - 1;
                store.remove(&mut txn, last).unwrap();
                txn.commit().unwrap();
                store.forget().unwrap();
            }
            writes.store(n + 1, Ordering::Relaxed);
        }
    }

    fn repacks_while_written(bodies: bool) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(filled(dir.path()));
        let file = match bodies {
            true => dir.path().join(BODIES_DIR).join(DATA_FILE),
            false => dir.path().join(DATA_FILE),
        };
        let inode = std::fs::metadata(&file).unwrap().ino();
        let reader = store.clone();
        // Held from before, throughout: it reads the old file still.
        let txn = reader.read().unwrap();
        let held = everything(&store);
        let stop = AtomicBool::new(false);
        let writes = AtomicU64::new(0);
        let (repacked, during) = std::thread::scope(|scope| {
            let writing = scope.spawn(|| keep_writing(&store, &stop, &writes));
            // Some written before, so the journal has something to keep.
            while !writing.is_finished() && store.len(&store.read().unwrap()).unwrap() < 110 {
                std::thread::yield_now();
            }
            let mut said = Vec::new();
            let began = writes.load(Ordering::Relaxed);
            let repacked = repack(&store, bodies, 4, &mut |line| said.push(line.to_string()));
            let during = writes.load(Ordering::Relaxed) - began;
            stop.store(true, Ordering::Relaxed);
            writing.join().unwrap();
            assert!(
                said.iter().any(|line| line.starts_with("caught up")),
                "{said:?}"
            );
            (repacked.unwrap(), during)
        });
        assert!(during > 0);
        assert!(repacked.after < repacked.before, "{repacked:?}");
        assert_ne!(std::fs::metadata(&file).unwrap().ino(), inode);
        assert!(!file.parent().unwrap().join(WORK_DIR).exists());
        // What was read before is read still.
        let t = store.tables;
        let seqs = |txn: &crate::lmdb::Txn| {
            let mut cursor = txn.cursor(t.events).unwrap();
            let mut seqs = Vec::new();
            let mut entry = cursor.first().unwrap();
            while let Some((key, _)) = entry {
                seqs.push(key.to_vec());
                entry = cursor.next().unwrap();
            }
            seqs
        };
        assert_eq!(seqs(&txn).len(), held[0].len());
        drop(txn);

        // Written to as before, then as it is, opened again.
        put(&store, &signed(3, 9000, 1, vec![], "after"));
        let now = everything(&store);
        let len = store.len(&store.read().unwrap()).unwrap();
        drop(reader);
        drop(Arc::into_inner(store).unwrap());
        let store = open_in(dir.path());
        assert_eq!(everything(&store), now);
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), len);
        put(&store, &signed(3, 9001, 1, vec![], "and again"));
    }

    #[test]
    fn repacks_the_indexes_while_written() {
        repacks_while_written(false);
    }

    #[test]
    fn repacks_bodies_while_written() {
        repacks_while_written(true);
    }

    /// A crash of the machine after the copy's in place puts the store
    /// back as it was then, in the copy.
    #[test]
    fn recovers_into_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let store = filled(dir.path());
        repack(&store, false, 2, &mut |_| {}).unwrap();
        let then = everything(&store);
        // Written, and not checkpointed, then lost.
        for n in 0..50 {
            put(&store, &signed(4, 7000 + n, 1, vec![], "lost"));
        }
        assert_ne!(everything(&store), then);
        let files = store.files();
        drop(store);
        let recovered = checkpoint::recover(dir.path(), &files, Some("another boot")).unwrap();
        assert!(
            matches!(recovered, checkpoint::Recovered::Restored(_)),
            "{recovered:?}"
        );
        let store = open_in(dir.path());
        assert_eq!(everything(&store), then);
    }

    /// One at a time, and what one left is cleared.
    #[test]
    fn repacks_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let store = filled(dir.path());
        store.repacking.store(true, Ordering::SeqCst);
        assert!(repack(&store, false, 2, &mut |_| {}).is_err());
        store.repacking.store(false, Ordering::SeqCst);
        drop(store);
        let left = dir.path().join(WORK_DIR);
        std::fs::create_dir(&left).unwrap();
        std::fs::write(left.join(DATA_FILE), b"half a copy").unwrap();
        let store = open_in(dir.path());
        assert!(!left.exists());
        repack(&store, false, 2, &mut |_| {}).unwrap();
    }
}
