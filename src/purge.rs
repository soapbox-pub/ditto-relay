//! Carrying out [pending deletions](crate::pending): finding what each
//! removes, then removing it, a chunk at a time between the writer's other
//! work. What they cover is hidden meanwhile, so none of this is hurried.
//!
//! What a deletion removes is found once, against a snapshot of the store,
//! as the events it covers below its watermark, with, for a filter, the old
//! versions it matches of an address whose current version it matches.
//! Their sequence numbers are kept as its *plan*, and only those are
//! removed: found again after some of their index entries had gone, they
//! wouldn't all be. Plans that may be slow to find, a filter's or a request
//! to vanish's, are found on threads of their own (see [`Lane`]), so that a
//! search of every event's text holds up no other deletion.
//!
//! NIP-09 deletions are taken together. What each removes is a lookup of
//! its ids and addresses, so a chunk finds and removes as many as fit,
//! oldest first, in one transaction, and drops them, keeping no plan: one
//! cut short is found again, whole. They and the rest take chunks by
//! turns, so a stream of them holds up no other deletion. One that removes
//! more than [`MAX_CHUNK`] events is kept a plan, as the rest are.
//!
//! A plan of fewer than [`SWEEP_AT`] events is removed an event at a time,
//! as removing always was: each event out of the twenty or so index entries
//! it's filed under, a page of each table wherever its keys fall. A bigger
//! one would be days of reading and writing pages at random, so it's swept
//! instead, in three passes:
//!
//! 1. The plan's records, in order, for what isn't kept as index entries:
//!    the scores, engagement and zaps each counted toward, which are undone,
//!    and its expiration. An address's version is removed whole, as it
//!    would be one at a time, and the newest left made current.
//! 2. Each index table, `ids` among them, walked once, in order, dropping
//!    every entry of an event in the plan, and the sketch of a tag key left
//!    with none: each page is read and written once, however many of them
//!    it holds, and read in order, ahead of the walk, on threads of their
//!    own.
//! 3. The plan's records, removed.
//!
//! While a sweep is under way, [`Store::remove`] leaves what it removes to
//! it, so nothing is undone twice. Each chunk saves how far it's got in its
//! own transaction, so after a restart, the deletion goes on from there.
//!
//! Each chunk is sized to take about [`TARGET`], by how long the last took.
//! Once the writer has stored anything, the next waits at least as long as
//! the last took, so a busy writer spends at most half its time deleting;
//! with nothing to store, it deletes flat out. Once a deletion is done, what
//! it covered stays hidden for [`GRACE`], for readers that began before.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use roaring::RoaringTreemap;

use crate::compact::TableAhead;
use crate::event::KindClass;
use crate::filter::Filter;
use crate::lmdb::{Db, DbFlags, Result, RwTxn, Txn};
use crate::pending::{Pending, Progress, Target, counted};
use crate::query;
use crate::record::EventView;
use crate::store::{EXPIRING, STAMP_LEN, Store, Written, address_of, stamp, stamp_seq};

/// How many events make sweeping cheaper than removing them one at a time:
/// a sweep reads every index entry once.
pub const SWEEP_AT: u64 = if cfg!(test) { 40 } else { 200_000 };

/// How long a chunk should take, commit and all, as the writer holds up
/// every write meanwhile. What removing an event costs varies by thousands
/// of times: with its pages on disk, or in an environment whose freelist
/// has grown huge.
pub const TARGET: Duration = Duration::from_millis(50);

/// How long what a deletion covered stays hidden once it's gone.
const GRACE: Duration = Duration::from_secs(60);

/// How many events the first chunk removes one at a time, and the most.
const FIRST_CHUNK: usize = 64;
const MAX_CHUNK: usize = 1000;

/// How many index entries the first chunk of a sweep visits, and the most.
const FIRST_SWEEP_CHUNK: usize = 1 << 12;
const MAX_SWEEP_CHUNK: usize = 1 << 22;

/// The most records a sweep's first pass reads in a chunk.
const RECORDS: usize = 1 << 14;

/// How many threads read what records counted toward, ahead of a sweep's
/// first pass undoing it, and how many records ahead of it they keep, read
/// a batch at a time.
const THREADS: usize = 64;
const RECORDS_AHEAD: usize = 1 << 16;
const AHEAD_BATCH: usize = 1 << 12;

/// How many threads read a table ahead of a sweep of it.
const READERS: usize = 16;

/// How long to wait after a chunk fails before trying again.
const RETRY: Duration = Duration::from_secs(10);

/// How often the writer looks whether a plan's been found, with nothing
/// else to delete meanwhile.
const PLAN_POLL: Duration = Duration::from_millis(20);

/// How often the writer looks whether a repack that holds up the sweeps
/// is done.
const SWEEPS_HELD: Duration = Duration::from_secs(1);

/// How often a long deletion says how it's going.
const SAY_EVERY: Duration = Duration::from_secs(30);

/// What a deletion removes: the sequence numbers of the events it covers
/// below its watermark, as of a snapshot of the store.
pub fn plan(store: &Store, pending: &Pending) -> anyhow::Result<RoaringTreemap> {
    let txn = store.read()?;
    let watermark = pending.watermark;
    Ok(match &pending.target {
        Target::Filter { filter, .. } => plan_filter(store, &txn, filter, watermark)?,
        Target::Seqs(seqs) => (**seqs).clone(),
        Target::Deletion(deletion) => store.deleting(&txn, deletion, watermark)?,
        Target::Vanish { author, until } => store.vanishing(&txn, author, *until, watermark)?,
    })
}

/// What deleting by `filter` removes below `watermark`: what it matches,
/// and the old versions it matches of an address whose current version it
/// matches. Matches of kinds without old versions, as the index says, are
/// taken without reading them.
fn plan_filter(
    store: &Store,
    txn: &Txn,
    filter: &Filter,
    watermark: u64,
) -> Result<RoaringTreemap> {
    let mut plan = RoaringTreemap::new();
    for (seq, kind) in query::every_match_kinded(store, txn, filter)? {
        if seq >= watermark {
            continue;
        }
        match kind.map(KindClass::of) {
            Some(KindClass::Regular | KindClass::Ephemeral) => {
                plan.insert(seq);
            }
            _ => plan.extend(
                store
                    .matching_versions(txn, seq, filter)?
                    .0
                    .into_iter()
                    .filter(|&seq| seq < watermark),
            ),
        }
    }
    Ok(plan)
}

/// Carry out every pending deletion now, flat out, as `ditto-relay delete`
/// does with no relay running, telling `tell` what went, and `progress`
/// how many events so far. Returns how many. With `threads`, the store
/// again, a sweep is read ahead of on threads of their own.
pub fn run(
    store: &Store,
    threads: Option<Arc<Store>>,
    tell: &impl Fn(Written),
    mut progress: impl FnMut(u64),
) -> anyhow::Result<u64> {
    let mut purger = Purger::new(store, threads, false)?;
    while purger.work(store, tell)? {
        store.forget()?;
        progress(purger.total);
    }
    for (_, id) in purger.finished.drain(..) {
        store.unhide(id);
    }
    Ok(purger.total)
}

/// The writer's pending deletions, and how far each has got.
pub struct Purger {
    /// Oldest first.
    jobs: Vec<Job>,
    /// The store again, with which to read ahead on threads of their own.
    background: Option<Arc<Store>>,
    /// Whether to find slow plans on threads of their own, going on
    /// meanwhile, as the writer does, rather than then and there. What's
    /// done stays hidden for [`GRACE`] only then, for the readers of a
    /// running relay.
    aside: bool,
    /// The plans being found on threads of their own: one of each
    /// [`Lane`]'s at most.
    planning: Vec<Planning>,
    /// Deletions done, to unhide once their grace is up.
    finished: VecDeque<(Instant, u64)>,
    chunk: usize,
    sweep_chunk: usize,
    /// How long the last chunk took, when it ended, and when the next may
    /// start.
    took: Duration,
    ended: Instant,
    resume: Instant,
    said: Instant,
    /// How many events it's removed, all told.
    total: u64,
    /// How many events make a plan swept: [`SWEEP_AT`], but in tests.
    sweep_at: u64,
    /// In tests, how many index entries each chunk of a sweep visits.
    fixed_chunk: Option<usize>,
    /// Whether the next chunk is the NIP-09 deletions' turn.
    nip09_turn: bool,
    /// How many events make a NIP-09 deletion kept a plan: [`MAX_CHUNK`],
    /// but in tests.
    nip09_at: u64,
}

/// A plan being found on a thread of its own.
struct Planning {
    id: u64,
    lane: Lane,
    found: mpsc::Receiver<anyhow::Result<RoaringTreemap>>,
}

/// The deletions whose plans may take a while to find, each found on a
/// thread of its own, oldest first, one at a time of each lane. A filter's
/// may take hours, as a search of every event's text does, and a request to
/// vanish's reads all its author published; neither waits on the other.
/// The rest are never waiting on either: events already picked are found
/// then and there, and NIP-09 deletions are found and removed together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Filter,
    Vanish,
}

impl Lane {
    /// The lane of a deletion of `target`, if its plan may be slow to find.
    fn of(target: &Target) -> Option<Lane> {
        match target {
            Target::Filter { .. } => Some(Lane::Filter),
            Target::Vanish { .. } => Some(Lane::Vanish),
            Target::Seqs(_) | Target::Deletion(_) => None,
        }
    }
}

struct Job {
    pending: Arc<Pending>,
    work: Work,
    /// How many events it's removed, here.
    removed: u64,
    began: Instant,
}

impl Job {
    /// Whether it's a NIP-09 deletion to be taken with the others, as one
    /// is unless it's been kept a plan.
    fn is_nip09(&self) -> bool {
        matches!(self.work, Work::Unplanned) && matches!(self.pending.target, Target::Deletion(_))
    }
}

enum Work {
    /// Its plan not yet found.
    Unplanned,
    /// Removing them one at a time, done up to and including `after`.
    Each {
        plan: Arc<RoaringTreemap>,
        after: Option<u64>,
    },
    Sweep(Box<Sweep>),
}

impl Purger {
    /// The pending deletions, as far as each has got. A sweep that had got
    /// going goes on, and [`Store::remove`] leaves what it removes to it.
    pub fn new(
        store: &Store,
        background: Option<Arc<Store>>,
        aside: bool,
    ) -> anyhow::Result<Purger> {
        let mut purger = Purger {
            jobs: Vec::new(),
            background,
            aside,
            planning: Vec::new(),
            finished: VecDeque::new(),
            chunk: FIRST_CHUNK,
            sweep_chunk: FIRST_SWEEP_CHUNK,
            took: Duration::ZERO,
            ended: Instant::now(),
            resume: Instant::now(),
            said: Instant::now(),
            total: 0,
            sweep_at: SWEEP_AT,
            fixed_chunk: None,
            nip09_turn: true,
            nip09_at: MAX_CHUNK as u64,
        };
        purger.sync(store)?;
        Ok(purger)
    }

    /// Take up the deletions queued since, as far as each has got.
    fn sync(&mut self, store: &Store) -> anyhow::Result<()> {
        let pending = store.pending();
        if pending.len() == self.jobs.len() + self.finished.len() {
            return Ok(());
        }
        let txn = store.read()?;
        for pending in pending {
            let known = self.jobs.iter().any(|job| job.pending.id == pending.id)
                || self.finished.iter().any(|(_, id)| *id == pending.id);
            if known {
                continue;
            }
            let id = pending.id;
            let work = match (store.plan_of(&txn, id)?, store.progress_of(&txn, id)?) {
                (Some(plan), Some(Progress::Each { after })) => Work::Each {
                    plan: Arc::new(plan),
                    after,
                },
                (Some(plan), Some(progress)) => {
                    let sweep = Sweep::resume(Arc::new(plan), progress, self.ahead());
                    if sweep.is_started() {
                        *store.sweeping.lock().expect("unpoisoned") = Some(sweep.plan.clone());
                    }
                    Work::Sweep(Box::new(sweep))
                }
                _ => Work::Unplanned,
            };
            self.jobs.push(Job {
                pending,
                work,
                removed: 0,
                began: Instant::now(),
            });
        }
        Ok(())
    }

    fn ahead(&self) -> Option<Arc<Store>> {
        self.background.clone()
    }

    /// When the writer should next call [`step`](Self::step), if it has
    /// anything to do.
    pub fn due(&self, store: &Store) -> Option<Instant> {
        let finishing = self.finished.front().map(|(at, _)| *at);
        let queued = store.pending().len() > self.jobs.len() + self.finished.len();
        let working = if self.jobs.is_empty() && !queued {
            None
        } else if !queued && !self.planning.is_empty() && !self.can_work() {
            // Looked at every so often until a plan's found.
            Some(Instant::now() + PLAN_POLL)
        } else {
            Some(self.resume)
        };
        [finishing, working].into_iter().flatten().min()
    }

    /// Whether some job has a plan to work on, or one quick to find, or
    /// one slow to find that's not being found yet.
    fn can_work(&self) -> bool {
        self.jobs.iter().any(|job| match job.work {
            Work::Unplanned => match Lane::of(&job.pending.target) {
                Some(lane) => !self.planning.iter().any(|planning| planning.lane == lane),
                None => true,
            },
            _ => true,
        })
    }

    /// The writer has stored something: the next chunk waits as long as the
    /// last took, from when it ended. From then, not from now: writes come
    /// more often than a chunk takes, and each would put it off again.
    pub fn wrote(&mut self) {
        self.resume = self.resume.max(self.ended + self.took);
    }

    /// Do a chunk of what's pending, if it's due, as the writer does between
    /// writes.
    pub fn step(&mut self, store: &Store, tell: &impl Fn(Written)) {
        let now = Instant::now();
        while let Some(&(at, id)) = self.finished.front()
            && at <= now
        {
            store.unhide(id);
            self.finished.pop_front();
        }
        if now < self.resume {
            return;
        }
        if let Err(err) = self.work(store, tell) {
            tracing::error!("deleting failed, to be tried again: {err:#}");
            self.resume = Instant::now() + RETRY;
        }
    }

    /// Do a chunk of what's pending. Returns whether there's more to do.
    fn work(&mut self, store: &Store, tell: &impl Fn(Written)) -> anyhow::Result<bool> {
        self.sync(store)?;
        self.plan_next(store)?;
        // One at a time first: they're small, and a sweep can take an hour.
        // The fewest left first, so a deletion of a few events never waits
        // on a deletion of a hundred thousand events one at a time.
        let each = self
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(i, job)| match &job.work {
                Work::Each { plan, after } => {
                    let done = after.map_or(0, |after| plan.rank(after));
                    Some((plan.len() - done, i))
                }
                _ => None,
            })
            .min()
            .map(|(_, i)| i);
        // None while a repack's under way: a sweep removes millions of
        // index entries, each kept in the repack's journal, which the copy
        // may then never catch up with. Only the running relay's writer
        // waits: carried out flat out, they'd never be done.
        let repacking = self.aside && store.repacking.load(Ordering::Relaxed);
        let sweep = || {
            self.jobs.iter().position(|job| match &job.work {
                Work::Sweep(sweep) => !repacking && sweep.is_started(),
                _ => false,
            })
        };
        let first_sweep = || {
            self.jobs
                .iter()
                .position(|job| !repacking && matches!(job.work, Work::Sweep(_)))
        };
        let other = each.or_else(sweep).or_else(first_sweep);
        let nip09 = self.jobs.iter().any(Job::is_nip09);
        if nip09 && (self.nip09_turn || other.is_none()) {
            self.nip09_turn = false;
            let start = Instant::now();
            self.nip09_chunk(store, tell)?;
            self.timed(start, false);
            return Ok(true);
        }
        self.nip09_turn = true;
        let Some(i) = other else {
            if repacking {
                // Looked at again now and then, until the repack's done.
                self.resume = Instant::now() + SWEEPS_HELD;
            }
            return Ok(!self.planning.is_empty() || !self.jobs.is_empty());
        };
        let start = Instant::now();
        let sweeping = matches!(self.jobs[i].work, Work::Sweep(_));
        let done = self.chunk_of(store, i, tell)?;
        self.timed(start, sweeping);
        let job = &self.jobs[i];
        if done {
            tracing::info!(
                "{}: removed {} events in {:.0?}",
                job.pending.describe(),
                job.removed,
                job.began.elapsed()
            );
            let job = self.jobs.remove(i);
            self.finished
                .push_back((Instant::now() + self.grace(), job.pending.id));
        } else if self.said.elapsed() >= SAY_EVERY {
            let how = match &job.work {
                Work::Sweep(sweep) => sweep.progress_text(),
                _ => format!("{} events removed so far", job.removed),
            };
            tracing::info!("{}: {how}", job.pending.describe());
            self.said = Instant::now();
        }
        Ok(true)
    }

    /// Note how long a chunk begun at `start` took, sizing the next one
    /// by it.
    fn timed(&mut self, start: Instant, sweeping: bool) {
        self.took = start.elapsed();
        match sweeping {
            true => self.sweep_chunk = next_chunk(self.sweep_chunk, self.took, MAX_SWEEP_CHUNK),
            false => self.chunk = next_chunk(self.chunk, self.took, MAX_CHUNK),
        }
        if self.took > TARGET * 10 {
            tracing::warn!("a chunk of deleting took {:.1?}", self.took);
        }
        // Only once something's written: see `wrote`.
        self.ended = Instant::now();
        self.resume = self.ended;
    }

    /// How long what a deletion covered stays hidden once it's gone.
    fn grace(&self) -> Duration {
        match self.aside {
            true => GRACE,
            false => Duration::ZERO,
        }
    }

    /// Find and remove what the NIP-09 deletions waiting remove, oldest
    /// first, as many as fit a chunk, and drop them, in one transaction.
    /// The first, if it removes more than [`MAX_CHUNK`] events, is kept a
    /// plan instead, and removed as the rest are.
    fn nip09_chunk(&mut self, store: &Store, tell: &impl Fn(Written)) -> anyhow::Result<()> {
        let now = crate::event::now();
        let mut removed = Vec::new();
        let mut done = HashSet::new();
        let mut big = None;
        let mut count = 0;
        // A lookup each, and the events each removes.
        let mut cost = 0;
        let mut txn = store.write()?;
        let outcome = (|| -> anyhow::Result<()> {
            for job in self.jobs.iter().filter(|job| job.is_nip09()) {
                let Target::Deletion(deletion) = &job.pending.target else {
                    continue;
                };
                if cost >= self.chunk {
                    break;
                }
                let plan = store.deleting(&txn, deletion, job.pending.watermark)?;
                if plan.len() > self.nip09_at {
                    if done.is_empty() {
                        big = Some((job.pending.id, plan));
                    }
                    break;
                }
                for seq in &plan {
                    count += u64::from(store.remove_version(&mut txn, seq, now, &mut removed)?);
                }
                store.drop_pending(&mut txn, job.pending.id)?;
                cost += 1 + plan.len() as usize;
                done.insert(job.pending.id);
            }
            Ok(())
        })();
        if let (Ok(()), Some((id, plan))) = (&outcome, big) {
            drop(txn);
            return self.planned(store, id, Ok(plan));
        }
        if let Err(err) = outcome.and_then(|()| Ok(txn.commit()?)) {
            store.forget_uncommitted();
            return Err(err);
        }
        store.committed_queued();
        self.total += count;
        let finish = Instant::now() + self.grace();
        self.jobs.retain(|job| !done.contains(&job.pending.id));
        // Oldest first, as the rest are.
        let mut done: Vec<u64> = done.into_iter().collect();
        done.sort_unstable();
        self.finished.extend(done.iter().map(|&id| (finish, id)));
        tracing::info!(
            "{}: removed {}",
            counted(done.len(), "NIP-09 deletion", "NIP-09 deletions"),
            counted(count as usize, "event", "events")
        );
        if !removed.is_empty() {
            tell((Vec::new(), removed));
        }
        Ok(())
    }

    /// Cancel deletion `id`: what it's removed stays removed, and what it
    /// hasn't is shown again. A sweep under way can't be stopped: it's
    /// taken some of its events out of some indexes and not others, and
    /// only finishing puts that right.
    pub fn cancel(&mut self, store: &Store, id: u64) -> anyhow::Result<()> {
        self.sync(store)?;
        let Some(i) = self.jobs.iter().position(|job| job.pending.id == id) else {
            if self.finished.iter().any(|&(_, done)| done == id) {
                anyhow::bail!("deletion {id} is done already");
            }
            anyhow::bail!("no deletion {id} is pending");
        };
        if let Work::Sweep(sweep) = &self.jobs[i].work
            && sweep.is_started()
        {
            anyhow::bail!(
                "deletion {id} is partway through sweeping the indexes, and can't be stopped until it's done: {}",
                sweep.progress_text()
            );
        }
        let mut txn = store.write()?;
        store.drop_pending(&mut txn, id)?;
        txn.commit()?;
        let job = self.jobs.remove(i);
        // Its plan, if it's being found, is let go of when it is.
        self.planning.retain(|planning| planning.id != id);
        store.unhide(id);
        let how = match &job.work {
            Work::Each {
                plan,
                after: Some(after),
            } => format!("{} of {} events removed", plan.rank(*after), plan.len()),
            Work::Each { plan, .. } => format!("none of {} events removed", plan.len()),
            Work::Sweep(sweep) => format!("none of {} events removed", sweep.plan.len()),
            Work::Unplanned => "before finding what it removes".into(),
        };
        tracing::info!("{}: cancelled, {how}", job.pending.describe());
        Ok(())
    }

    /// Keep the plans found on threads of their own; find the quick ones
    /// left, for about [`TARGET`]; and start finding the oldest slow one of
    /// each [`Lane`] not being found, on a thread of its own, or with no
    /// threads, find the oldest slow one now.
    fn plan_next(&mut self, store: &Store) -> anyhow::Result<()> {
        let mut i = 0;
        while i < self.planning.len() {
            let found = match self.planning[i].found.try_recv() {
                Ok(found) => found,
                Err(mpsc::TryRecvError::Empty) => {
                    i += 1;
                    continue;
                }
                Err(mpsc::TryRecvError::Disconnected) => Err(anyhow::anyhow!("planning panicked")),
            };
            let planning = self.planning.remove(i);
            self.planned(store, planning.id, found)?;
        }

        let start = Instant::now();
        let quick: Vec<Arc<Pending>> = self
            .jobs
            .iter()
            .filter(|job| {
                matches!(job.work, Work::Unplanned)
                    && Lane::of(&job.pending.target).is_none()
                    && !job.is_nip09()
            })
            .map(|job| job.pending.clone())
            .collect();
        for pending in quick {
            let found = plan(store, &pending);
            self.planned(store, pending.id, found)?;
            if start.elapsed() >= TARGET {
                break;
            }
        }

        for lane in [Lane::Filter, Lane::Vanish] {
            if self.planning.iter().any(|planning| planning.lane == lane) {
                continue;
            }
            let Some(job) = self.jobs.iter().find(|job| {
                matches!(job.work, Work::Unplanned) && Lane::of(&job.pending.target) == Some(lane)
            }) else {
                continue;
            };
            let pending = job.pending.clone();
            let id = pending.id;
            let (true, Some(store)) = (self.aside, self.background.clone()) else {
                let found = plan(store, &pending);
                return self.planned(store, id, found);
            };
            let (tx, found) = mpsc::channel();
            std::thread::Builder::new()
                .name("deletion-plan".into())
                .spawn(move || {
                    let _ = tx.send(plan(&store, &pending));
                })?;
            self.planning.push(Planning { id, lane, found });
        }
        Ok(())
    }

    /// Keep the plan found for deletion `id`, and how it's to be removed,
    /// unless it's been cancelled meanwhile.
    fn planned(
        &mut self,
        store: &Store,
        id: u64,
        found: anyhow::Result<RoaringTreemap>,
    ) -> anyhow::Result<()> {
        let plan = found?;
        if !self.jobs.iter().any(|job| job.pending.id == id) {
            return Ok(());
        }
        let progress = match plan.len() >= self.sweep_at {
            true => Progress::Records { after: None },
            false => Progress::Each { after: None },
        };
        let mut txn = store.write()?;
        store.put_plan(&mut txn, id, &plan)?;
        store.put_progress(&mut txn, id, &progress)?;
        txn.commit()?;
        let ahead = self.ahead();
        let Some(job) = self.jobs.iter_mut().find(|job| job.pending.id == id) else {
            return Ok(());
        };
        tracing::info!(
            "{}: removing {} events{}",
            job.pending.describe(),
            plan.len(),
            match progress {
                Progress::Each { .. } => "",
                _ => ", by sweeping the indexes",
            }
        );
        let plan = Arc::new(plan);
        job.work = match progress {
            Progress::Each { after } => Work::Each { plan, after },
            progress => Work::Sweep(Box::new(Sweep::resume(plan, progress, ahead))),
        };
        Ok(())
    }

    /// Do a chunk of job `i`, in a transaction of its own. Returns whether
    /// that's all of it.
    fn chunk_of(
        &mut self,
        store: &Store,
        i: usize,
        tell: &impl Fn(Written),
    ) -> anyhow::Result<bool> {
        let now = crate::event::now();
        let mut removed = Vec::new();
        let job = &mut self.jobs[i];
        let id = job.pending.id;
        let mut count = 0;
        let mut txn = store.write()?;
        let outcome = (|| -> Result<bool> {
            match &mut job.work {
                Work::Unplanned => Ok(false),
                Work::Each { plan, after } => {
                    let seqs = next(plan, *after, self.chunk);
                    for &seq in &seqs {
                        count +=
                            u64::from(store.remove_version(&mut txn, seq, now, &mut removed)?);
                    }
                    let done = seqs.len() < self.chunk;
                    *after = seqs.last().copied().or(*after);
                    match done {
                        true => store.drop_pending(&mut txn, id)?,
                        false => {
                            store.put_progress(&mut txn, id, &Progress::Each { after: *after })?
                        }
                    }
                    Ok(done)
                }
                Work::Sweep(sweep) => {
                    if !sweep.is_started() {
                        *store.sweeping.lock().expect("unpoisoned") = Some(sweep.plan.clone());
                    }
                    let budget = self.fixed_chunk.unwrap_or(self.sweep_chunk);
                    count += sweep.step(store, &mut txn, budget, now, &mut removed)?;
                    match sweep.is_done() {
                        true => store.drop_pending(&mut txn, id)?,
                        false => store.put_progress(&mut txn, id, &sweep.progress())?,
                    }
                    Ok(sweep.is_done())
                }
            }
        })();
        let committed = outcome.and_then(|done| txn.commit().map(|()| done));
        let done = match committed {
            Ok(done) => {
                store.committed_queued();
                done
            }
            Err(err) => {
                store.forget_uncommitted();
                // What the failed chunk did is undone: a sweep goes on from
                // where it was saved.
                if let Work::Sweep(sweep) = &mut job.work
                    && let Ok(txn) = store.read()
                    && let Ok(Some(progress)) = store.progress_of(&txn, id)
                {
                    let plan = sweep.plan.clone();
                    **sweep = Sweep::resume(plan, progress, self.background.clone());
                }
                if let Work::Each { after, .. } = &mut job.work
                    && let Ok(txn) = store.read()
                {
                    *after = match store.progress_of(&txn, id) {
                        Ok(Some(Progress::Each { after })) => after,
                        _ => None,
                    };
                }
                return Err(err.into());
            }
        };
        job.removed += count;
        self.total += count;
        if done && matches!(job.work, Work::Sweep(_)) {
            *store.sweeping.lock().expect("unpoisoned") = None;
        }
        if !removed.is_empty() {
            tell((Vec::new(), removed));
        }
        Ok(done)
    }
}

/// The size of a chunk after one of `chunk` that took `took`, sized for
/// [`TARGET`], up to `max`.
pub fn next_chunk(chunk: usize, took: Duration, max: usize) -> usize {
    if took > TARGET {
        (chunk / 2).max(1)
    } else if took < TARGET / 2 {
        (chunk * 2).min(max)
    } else {
        chunk
    }
}

/// Up to `max` of a plan's sequence numbers after `after`, in order.
fn next(plan: &RoaringTreemap, after: Option<u64>, max: usize) -> Vec<u64> {
    let mut iter = plan.iter();
    if let Some(after) = after {
        iter.advance_to(after + 1);
    }
    iter.take(max).collect()
}

/// A sweep of a plan, as far as it's got: see the [module](self).
pub struct Sweep {
    plan: Arc<RoaringTreemap>,
    pass: Pass,
    /// Index entries looked at, and records passed, so far here.
    visited: u64,
    /// With the store, what reads ahead of the table being swept.
    ahead: Option<(Arc<Store>, Option<Reading>)>,
    /// What reads ahead of the first pass, once begun.
    records_ahead: Option<RecordsAhead>,
}

/// Which table is read ahead of, and what reads it.
type Reading = (usize, TableAhead);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pass {
    /// Records from after this sequence number.
    Records(Option<u64>),
    /// Table `n` of [`swept`], from this key and value, if any.
    Tables(usize, Option<(Vec<u8>, Vec<u8>)>),
    /// Removing records, from after this sequence number.
    Forget(Option<u64>),
    Done,
}

/// The tables a sweep goes through, their names, and whether their entries
/// are duplicates holding a stamp, or `ids`, whose value is a sequence
/// number.
fn swept(store: &Store) -> [(Db, &'static str, bool); 7] {
    let t = store.tables;
    [
        (t.ids, "ids", false),
        (t.created, "created", true),
        (t.kinds, "kinds", true),
        (t.authors, "authors", true),
        (t.author_kinds, "author_kinds", true),
        (t.tags, "tags", true),
        (t.facets, "facets", true),
    ]
}

impl Sweep {
    /// A sweep of `plan` from where `progress` says, read ahead of with
    /// `ahead`'s threads, if given.
    pub fn resume(
        plan: Arc<RoaringTreemap>,
        progress: Progress,
        ahead: Option<Arc<Store>>,
    ) -> Sweep {
        let pass = match progress {
            Progress::Each { .. } | Progress::Records { after: None } => Pass::Records(None),
            Progress::Records { after } => Pass::Records(after),
            Progress::Table { table, at } => Pass::Tables(
                table,
                at.and_then(|(key, value)| {
                    Some((hex::decode(key).ok()?, hex::decode(value).ok()?))
                }),
            ),
            Progress::Forget { after } => Pass::Forget(after),
        };
        Sweep {
            plan,
            pass,
            visited: 0,
            ahead: ahead.map(|store| (store, None)),
            records_ahead: None,
        }
    }

    /// Whether it's done anything, so that what it removes is its alone.
    pub fn is_started(&self) -> bool {
        self.pass != Pass::Records(None)
    }

    pub fn is_done(&self) -> bool {
        self.pass == Pass::Done
    }

    /// How far it's got, to be kept.
    pub fn progress(&self) -> Progress {
        match &self.pass {
            Pass::Records(after) => Progress::Records { after: *after },
            Pass::Tables(table, at) => Progress::Table {
                table: *table,
                at: at
                    .as_ref()
                    .map(|(key, value)| (hex::encode(key), hex::encode(value))),
            },
            Pass::Forget(after) => Progress::Forget { after: *after },
            Pass::Done => Progress::Forget {
                after: self.plan.max(),
            },
        }
    }

    /// How it's going, to say.
    pub fn progress_text(&self) -> String {
        match &self.pass {
            Pass::Records(after) => format!(
                "undoing what {} of {} events counted toward",
                after.map_or(0, |after| self.plan.rank(after)),
                self.plan.len()
            ),
            Pass::Tables(n, _) => format!(
                "sweeping {}, {} index entries looked at so far",
                swept_name(*n),
                self.visited
            ),
            Pass::Forget(after) => format!(
                "removing records, {} of {}",
                after.map_or(0, |after| self.plan.rank(after)),
                self.plan.len()
            ),
            Pass::Done => "done".into(),
        }
    }

    /// The sweep is at `key` of table `n`: have what's after it read.
    fn reading(&mut self, n: usize, key: &[u8]) {
        let Some((store, current)) = &mut self.ahead else {
            return;
        };
        if current.as_ref().is_none_or(|(at, _)| *at != n) {
            let (db, _, dups) = swept(store)[n];
            let flags = match dups {
                true => DbFlags::DUP_FIXED,
                false => DbFlags::PLAIN,
            };
            *current = Some((n, TableAhead::start(store.clone(), db, flags, READERS)));
        }
        if let Some((_, ahead)) = current {
            ahead.at(key);
        }
    }

    /// Go on, visiting about `budget` entries, in `txn`, noting in
    /// `removed` what search no longer has.
    pub fn step(
        &mut self,
        store: &Store,
        txn: &mut RwTxn,
        budget: usize,
        now: u32,
        removed: &mut Vec<u64>,
    ) -> Result<u64> {
        match std::mem::replace(&mut self.pass, Pass::Done) {
            Pass::Records(after) => self.records(store, txn, after, budget, now, removed),
            Pass::Tables(n, at) => self.table(store, txn, n, at, budget).map(|()| 0),
            Pass::Forget(after) => self.forget(store, txn, after, budget, removed),
            Pass::Done => Ok(0),
        }
    }

    fn records(
        &mut self,
        store: &Store,
        txn: &mut RwTxn,
        after: Option<u64>,
        budget: usize,
        now: u32,
        removed: &mut Vec<u64>,
    ) -> Result<u64> {
        let budget = budget.min(RECORDS);
        let seqs = next(&self.plan, after, budget);
        let mut count = 0;
        if let Some((store, _)) = &self.ahead {
            let (plan, store) = (self.plan.clone(), store.clone());
            self.records_ahead
                .get_or_insert_with(|| RecordsAhead::start(store, plan, after));
        }
        for &seq in &seqs {
            let Some(record) = store.record(txn, seq)? else {
                continue;
            };
            let view = EventView::new(&record).expect("a stored record");
            if address_of(&view).is_some() {
                // History and all, as one at a time.
                count += u64::from(store.remove_version_unless(txn, seq, now, removed, false)?);
                continue;
            }
            let expiration = view.expiration();
            crate::rank::unindex(store, txn, seq, &view)?;
            if let Some(expiration) = expiration {
                txn.del(
                    store.tables.expiring,
                    EXPIRING,
                    Some(&stamp(expiration, seq)),
                )?;
            }
        }
        if let Some(ahead) = &self.records_ahead {
            ahead.passed.fetch_add(seqs.len(), Ordering::Relaxed);
        }
        self.visited += seqs.len() as u64;
        self.pass = match (seqs.last(), seqs.len() < budget) {
            (Some(&last), false) => Pass::Records(Some(last)),
            _ => {
                self.records_ahead = None;
                self.visited = 0;
                Pass::Tables(0, None)
            }
        };
        Ok(count)
    }

    fn table(
        &mut self,
        store: &Store,
        txn: &mut RwTxn,
        n: usize,
        at: Option<(Vec<u8>, Vec<u8>)>,
        budget: usize,
    ) -> Result<()> {
        let tables = swept(store);
        let Some(&(db, _, dups)) = tables.get(n) else {
            if let Some((_, reading)) = &mut self.ahead {
                *reading = None;
            }
            self.pass = Pass::Forget(None);
            return Ok(());
        };
        let tags = db == store.tables.tags;
        // Tag keys something went from, whose sketch goes if nothing's left.
        let mut emptied: Vec<Vec<u8>> = Vec::new();
        let mut next = None;
        let mut visited = 0;
        let mut cursor = txn.sweeper(db)?;
        // Where to go on from: `at`, then the next entry, or after one
        // deleted, by seeking it again: what LMDB's cursor returns next
        // after a delete isn't reliable when it was the last on its page.
        let mut seek = Some(at);
        loop {
            let (gone, key) = {
                let entry = match seek.take() {
                    Some(at) => position(&mut cursor, at.as_ref(), dups)?,
                    None => cursor.next()?,
                };
                let Some((key, value)) = entry else {
                    break;
                };
                if visited >= budget {
                    next = Some((key.to_vec(), value.to_vec()));
                    break;
                }
                visited += 1;
                if dups && value.len() < STAMP_LEN {
                    tracing::error!(
                        "sweeping {} met a value of {} bytes, under {key:02x?}",
                        swept_name(n),
                        value.len()
                    );
                    return Err(crate::lmdb::Error::corrupted());
                }
                let seq = match dups {
                    true => Some(stamp_seq(value)),
                    false => value.try_into().ok().map(u64::from_be_bytes),
                };
                let gone = seq.is_some_and(|seq| self.plan.contains(seq));
                if gone {
                    seek = Some(Some((key.to_vec(), value.to_vec())));
                }
                let wanted = (visited % 256 == 1)
                    || (gone && tags && emptied.last().is_none_or(|last| last[..] != *key));
                (gone, wanted.then(|| key.to_vec()))
            };
            if let Some(key) = key {
                self.reading(n, &key);
                if gone && tags && emptied.last() != Some(&key) {
                    emptied.push(key);
                }
            }
            if gone {
                cursor.del()?;
            }
        }
        drop(cursor);
        self.visited += visited as u64;
        // A sketch outlives its events, but not its key.
        for key in emptied {
            if txn.cursor(db)?.set(&key)?.is_none() {
                txn.del(store.tables.hll, &key, None)?;
            }
        }
        self.pass = match next {
            Some(at) => Pass::Tables(n, Some(at)),
            None => Pass::Tables(n + 1, None),
        };
        Ok(())
    }

    fn forget(
        &mut self,
        store: &Store,
        txn: &mut RwTxn,
        after: Option<u64>,
        budget: usize,
        removed: &mut Vec<u64>,
    ) -> Result<u64> {
        let budget = budget.min(RECORDS);
        let seqs = next(&self.plan, after, budget);
        let mut count = 0;
        for &seq in &seqs {
            // Those removed in the first pass are gone by now.
            count += u64::from(txn.del(store.tables.events, &seq.to_ne_bytes(), None)?);
        }
        removed.extend(&seqs);
        self.pass = match (seqs.last(), seqs.len() < budget) {
            (Some(&last), false) => Pass::Forget(Some(last)),
            _ => Pass::Done,
        };
        Ok(count)
    }
}

/// The name of index table `n` of a sweep.
pub fn swept_name(n: usize) -> &'static str {
    [
        "ids",
        "created",
        "kinds",
        "authors",
        "author_kinds",
        "tags",
        "facets",
    ]
    .get(n)
    .copied()
    .unwrap_or("?")
}

/// Put `cursor` on `at`, or after it if it's gone, or on the first entry:
/// with `at` an entry just deleted, on the one after it.
fn position<'c>(
    cursor: &'c mut crate::lmdb::Sweeper<'_>,
    at: Option<&(Vec<u8>, Vec<u8>)>,
    dups: bool,
) -> Result<Option<crate::lmdb::Entry<'c>>> {
    let Some((key, value)) = at else {
        return cursor.first();
    };
    if !dups {
        return cursor.set_range(key);
    }
    if cursor.get_both_range(key, value)?.is_some() {
        return cursor.current();
    }
    // The rest of the key went: the next key.
    let found = cursor.set_range(key)?.map(|(found, _)| found == &key[..]);
    match found {
        None => Ok(None),
        Some(true) => cursor.next_nodup(),
        Some(false) => cursor.current(),
    }
}

/// A thread reading the records of a plan, and what they counted toward,
/// ahead of a sweep's first pass undoing it, on [`THREADS`] more. It stops
/// when dropped.
struct RecordsAhead {
    /// How many records the first pass has passed.
    passed: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl RecordsAhead {
    fn start(store: Arc<Store>, plan: Arc<RoaringTreemap>, after: Option<u64>) -> RecordsAhead {
        let passed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, stopped) = (passed.clone(), stop.clone());
        let spawned = std::thread::Builder::new()
            .name("sweep-records".into())
            .spawn(move || {
                let (mut after, mut read) = (after, 0usize);
                while !stopped.load(Ordering::Relaxed) {
                    if read > seen.load(Ordering::Relaxed) + RECORDS_AHEAD {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    let seqs = next(&plan, after, AHEAD_BATCH);
                    let Some(&last) = seqs.last() else {
                        return;
                    };
                    after = Some(last);
                    read += seqs.len();
                    prefetch(&store, &seqs);
                }
            });
        if let Err(err) = spawned {
            tracing::debug!("no thread to read ahead of a sweep: {err}");
        }
        RecordsAhead { passed, stop }
    }
}

impl Drop for RecordsAhead {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Read the records of `seqs`, and the scores and engagement they counted
/// toward, on many threads at once, each in a read transaction of its own,
/// so that undoing them doesn't wait on the disk for each in turn. Only a
/// hint.
fn prefetch(store: &Store, seqs: &[u64]) {
    let chunk = seqs.len().div_ceil(THREADS).max(1);
    std::thread::scope(|scope| {
        for part in seqs.chunks(chunk) {
            scope.spawn(move || {
                let Ok(txn) = store.read() else {
                    return;
                };
                for &seq in part {
                    if let Ok(Some(view)) = store.stored(&txn, seq) {
                        let _ = crate::rank::prefetch(store, &txn, &view);
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::store::tests::{everything, open, open_in, put, test_tags};
    use serde_json::json;

    /// Notes, reactions and replies to them, profiles in versions, an
    /// article, and notes that expire, by a few authors on a few topics, so
    /// that what's deleted shares keys and pages with what isn't.
    fn events(count: u64) -> Vec<Event> {
        let topics = ["a", "b", "spam"];
        let far = (crate::event::now() + 100_000).to_string();
        let mut events: Vec<Event> = Vec::new();
        let mut notes: Vec<Event> = Vec::new();
        for n in 0..count {
            let seed = (n % 4) as u8 + 1;
            let at = 1000 + n;
            let topic = topics[n as usize % 3];
            let event = match (n % 9, notes.last()) {
                (4, Some(note)) => {
                    let tags = vec![vec!["e", note.id.as_str()], vec!["p", note.pubkey.as_str()]];
                    signed(seed, at, 7, tags, "+")
                }
                (5, Some(note)) => {
                    let tags = vec![vec!["e", note.id.as_str()], vec!["p", note.pubkey.as_str()]];
                    signed(seed, at, 1, tags, "a reply")
                }
                (6, _) => signed(seed, at, 0, vec![vec!["t", topic]], &format!("v{n}")),
                (7, _) => signed(seed, at, 30_023, vec![vec!["d", "x"], vec!["t", topic]], ""),
                (8, _) => signed(seed, at, 1, vec![vec!["expiration", &far]], "brief"),
                _ => {
                    let note = signed(seed, at, 1, vec![vec!["t", topic]], "x");
                    notes.push(note.clone());
                    note
                }
            };
            events.push(event);
        }
        // Someone reacting twice to a note, once on a topic that goes: an
        // engagement counted twice, to be undone once.
        if let Some(note) = notes.first() {
            for (n, topic) in ["spam", "a"].iter().enumerate() {
                let tags = vec![
                    vec!["e", note.id.as_str()],
                    vec!["p", note.pubkey.as_str()],
                    vec!["t", topic],
                ];
                events.push(signed(3, 5000 + n as u64, 7, tags, "+"));
            }
        }
        events
    }

    /// A store of `events` with deletions queued by each of `filters`.
    fn store_with(events: &[Event], filters: &[serde_json::Value]) -> (tempfile::TempDir, Store) {
        let (dir, store) = open();
        for event in events {
            put(&store, event);
        }
        for filter in filters {
            let json = filter.to_string();
            let parsed = crate::delete::filter(Some(&json), None, 0, &test_tags()).unwrap();
            let target = crate::delete::target(&store, parsed, Some(&json), None).unwrap();
            let mut txn = store.write().unwrap();
            let watermark = store.next_seq(&txn).unwrap();
            store.queue_deletion(&mut txn, watermark, target).unwrap();
            txn.commit().unwrap();
            store.committed_queued();
        }
        (dir, store)
    }

    /// Carry out what's pending, sweeping plans of `sweep_at` events or
    /// more, `chunk` index entries at a time, stopping after `steps`
    /// chunks if given. Returns whether it finished.
    fn purge(store: &Store, sweep_at: u64, chunk: Option<usize>, steps: Option<usize>) -> bool {
        purge_counting(store, sweep_at, chunk, steps).0
    }

    /// [`purge`], and how many chunks it did.
    fn purge_counting(
        store: &Store,
        sweep_at: u64,
        chunk: Option<usize>,
        steps: Option<usize>,
    ) -> (bool, usize) {
        let mut purger = Purger::new(store, None, false).unwrap();
        purger.sweep_at = sweep_at;
        purger.fixed_chunk = chunk;
        let mut done = 0;
        while steps.is_none_or(|steps| done < steps) {
            if !purger.work(store, &|_| {}).unwrap() {
                for (_, id) in purger.finished.drain(..) {
                    store.unhide(id);
                }
                store.forget().unwrap();
                return (true, done);
            }
            store.forget().unwrap();
            done += 1;
        }
        (false, done)
    }

    fn filters() -> Vec<serde_json::Value> {
        let author = signed(1, 0, 1, vec![], "").pubkey;
        // An author's every event, and a topic, which takes current
        // versions and leaves older ones to be made current.
        vec![json!({"authors": [author]}), json!({"#t": ["spam"]})]
    }

    /// A swept store is entry for entry what removing one at a time
    /// leaves, scores and engagement too, from a chunk of one entry up.
    #[test]
    fn sweeps_as_removing_one_at_a_time_would() {
        let events = events(120);
        let (_a, each) = store_with(&events, &filters());
        assert!(purge(&each, u64::MAX, None, None));
        assert!(each.pending().is_empty());
        let removed = everything(&each);
        for chunk in [1, 3, 1000] {
            let (_b, swept) = store_with(&events, &filters());
            assert!(purge(&swept, 0, Some(chunk), None));
            assert!(swept.sweeping.lock().unwrap().is_none());
            assert_eq!(everything(&swept), removed, "chunk {chunk}");
        }
    }

    /// Stopped partway, as by a restart, a deletion goes on from where it
    /// got to, and undoes nothing twice.
    #[test]
    fn goes_on_after_a_restart() {
        let events = events(120);
        let (_a, each) = store_with(&events, &filters());
        assert!(purge(&each, u64::MAX, None, None));
        let removed = everything(&each);
        let mut stops = Vec::new();
        for sweep_at in [0, u64::MAX] {
            let (_b, store) = store_with(&events, &filters());
            let (_, steps) = purge_counting(&store, sweep_at, Some(7), None);
            // Stopped all through: in each pass of each deletion.
            stops.extend(
                (1..steps)
                    .step_by(steps / 100 + 1)
                    .map(|stop| (sweep_at, stop)),
            );
        }
        for (sweep_at, steps) in stops {
            let (dir, store) = store_with(&events, &filters());
            assert!(!purge(&store, sweep_at, Some(7), Some(steps)), "{steps}");
            drop(store);
            let store = open_in(dir.path());
            // Still hidden.
            assert!(!store.pending().is_empty());
            assert!(purge(&store, sweep_at, Some(7), None));
            assert_eq!(everything(&store), removed, "{sweep_at} {steps}");
        }
    }

    /// While a sweep's under way, what it removes is left to it.
    #[test]
    fn leaves_a_sweeps_events_to_it() {
        let events = events(60);
        let (_dir, store) = store_with(&events, &filters()[..1]);
        assert!(!purge(&store, 0, Some(1), Some(3)));
        // Its first pass noted the first event (seq 1) as its.
        let mut txn = store.write().unwrap();
        assert!(!store.remove(&mut txn, 1).unwrap());
        drop(txn);
        // Purged by a fresh purger, as after a restart.
        assert!(purge(&store, 0, None, None));
        assert!(store.stored(&store.read().unwrap(), 1).unwrap().is_none());
    }

    /// The running relay's sweeps wait while a repack's under way, the
    /// rest go on, and they're taken up again once it's done.
    #[test]
    fn sweeps_wait_out_a_repack() {
        let events = events(60);
        let (_dir, store) = store_with(&events, &filters()[..1]);
        let before = store.len(&store.read().unwrap()).unwrap();
        let mut purger = Purger::new(&store, None, true).unwrap();
        purger.sweep_at = 0;
        store.repacking.store(true, Ordering::Relaxed);
        for _ in 0..5 {
            purger.resume = Instant::now();
            assert!(purger.work(&store, &|_| {}).unwrap());
            store.forget().unwrap();
        }
        assert!(matches!(purger.jobs[0].work, Work::Sweep(_)));
        assert!(store.sweeping.lock().unwrap().is_none());
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), before);
        // Not looked at again at once, which would spin the writer.
        assert!(purger.resume > Instant::now() + SWEEPS_HELD / 2);
        store.repacking.store(false, Ordering::Relaxed);
        while purger.work(&store, &|_| {}).unwrap() {
            store.forget().unwrap();
        }
        store.forget().unwrap();
        assert!(store.len(&store.read().unwrap()).unwrap() < before);
    }

    /// Enough pages that what's deleted often ends one: after deleting the
    /// last entry on a page, what LMDB's cursor returns next can be read
    /// past its end, which a sweep of production met.
    #[test]
    fn sweeps_across_many_pages() {
        let events: Vec<Event> = (0..3000u64)
            .map(|n| {
                let mut secret = [1; 32];
                secret[24..].copy_from_slice(&(n % 50).to_be_bytes());
                let tags = vec![vec!["t".to_string(), format!("t{}", n % 97)]];
                crate::event::tests::sign(secret, 1000 + n, 1, tags, "x")
            })
            .collect();
        // Scattered, and whole keys: two authors.
        let topics: Vec<String> = (0..97).step_by(3).map(|n| format!("t{n}")).collect();
        let scattered = json!({ "#t": topics });
        let authors: Vec<String> = [7u64, 8]
            .iter()
            .map(|&n| {
                let mut secret = [1; 32];
                secret[24..].copy_from_slice(&n.to_be_bytes());
                crate::event::tests::sign(secret, 0, 1, vec![], "").pubkey
            })
            .collect();
        let whole = json!({ "authors": authors });
        let filters = [scattered, whole];
        let (_a, each) = store_with(&events, &filters);
        assert!(purge(&each, u64::MAX, None, None));
        let (_b, swept) = store_with(&events, &filters);
        assert!(purge(&swept, 0, Some(7), None));
        assert_eq!(everything(&swept), everything(&each));
        let left = swept.len(&swept.read().unwrap()).unwrap();
        assert!(left > 1000 && left < 2000, "{left}");
    }

    /// A filter's plan, which may take hours to find, holds up no deletion
    /// queued after it whose plan is quick to find: they're found, and
    /// removed, while it's still being found.
    #[test]
    fn a_slow_plan_holds_up_no_quick_one() {
        let events = events(60);
        let picked = json!({"kinds": [1], "limit": 3});
        let (_dir, store) = store_with(&events, &[json!({"#t": ["spam"]}), picked]);
        let store = Arc::new(store);
        let ids: Vec<u64> = store.pending().iter().map(|pending| pending.id).collect();
        let mut purger = Purger::new(&store, Some(store.clone()), true).unwrap();
        assert!(purger.work(&store, &|_| {}).unwrap());
        assert_eq!(purger.planning.len(), 1);
        assert_eq!(purger.planning[0].id, ids[0]);
        assert!(purger.jobs.iter().all(|job| job.pending.id == ids[0]));
        assert_eq!(purger.finished.len(), 1);
        assert_eq!(purger.finished[0].1, ids[1]);
    }

    /// Of the deletions removed one at a time, the one with the fewest
    /// events left goes first, however long the others have waited.
    #[test]
    fn removes_the_smallest_first() {
        let events = events(60);
        let big = json!({"kinds": [1], "limit": 30});
        let small = json!({"kinds": [7], "limit": 1});
        let (_dir, store) = store_with(&events, &[big, small]);
        let ids: Vec<u64> = store.pending().iter().map(|pending| pending.id).collect();
        let mut purger = Purger::new(&store, None, false).unwrap();
        purger.chunk = 1;
        while purger.finished.is_empty() {
            assert!(purger.work(&store, &|_| {}).unwrap());
            purger.chunk = 1;
        }
        assert_eq!(purger.finished[0].1, ids[1]);
        assert_eq!(purger.jobs.len(), 1);
        assert_eq!(purger.jobs[0].removed, 0);
    }

    /// A store of a note by each of `notes` authors, each deleted by its
    /// author, and `missing` NIP-09 deletions of events it doesn't have,
    /// all queued and none carried out.
    fn with_nip09(notes: u8, missing: u8) -> (tempfile::TempDir, Store, Vec<Event>) {
        let (dir, store) = open();
        let notes: Vec<Event> = (1..=notes)
            .map(|seed| signed(seed, 100, 1, vec![], "note"))
            .collect();
        for note in &notes {
            put(&store, note);
        }
        let mut deletions: Vec<Event> = notes
            .iter()
            .enumerate()
            .map(|(n, note)| signed(n as u8 + 1, 200, 5, vec![vec!["e", &note.id]], ""))
            .collect();
        for n in 0..missing {
            let id = format!("{n:064x}");
            deletions.push(signed(1, 200, 5, vec![vec!["e", &id]], ""));
        }
        for deletion in &deletions {
            let record = crate::record::encode(deletion);
            store.write_batch([record.as_slice()], 0).unwrap();
        }
        (dir, store, notes)
    }

    /// NIP-09 deletions are found and removed together, in a chunk, and
    /// after a restart, with nothing kept but what they name. Those of what's
    /// not stored are never queued.
    #[test]
    fn takes_nip09_deletions_together() {
        let (dir, store, notes) = with_nip09(10, 5);
        assert_eq!(store.pending().len(), 10);
        drop(store);
        let store = open_in(dir.path());
        let mut purger = Purger::new(&store, None, false).unwrap();
        assert!(purger.work(&store, &|_| {}).unwrap());
        assert!(purger.jobs.is_empty());
        assert_eq!(purger.finished.len(), 10);
        assert_eq!(purger.total, 10);
        assert!(store.list_pending().unwrap().is_empty());
        let txn = store.read().unwrap();
        for note in &notes {
            let id = crate::event::decode_hex::<32>(&note.id).unwrap();
            assert!(store.seq_of(&txn, &id).unwrap().is_none());
        }
    }

    /// A deletion stored in the same batch as what it deletes sees it, and
    /// is queued: only one of nothing stored is settled as it's stored.
    #[test]
    fn queues_a_deletion_of_what_its_batch_stores() {
        let (_dir, store) = open();
        let note = signed(3, 100, 1, vec![], "note");
        let deletion = signed(3, 200, 5, vec![vec!["e", &note.id]], "");
        let records = [
            crate::record::encode(&note),
            crate::record::encode(&deletion),
        ];
        store
            .write_batch(records.iter().map(Vec::as_slice), 0)
            .unwrap();
        assert_eq!(store.pending().len(), 1);
        crate::store::tests::settle(&store);
        let id = crate::event::decode_hex::<32>(&note.id).unwrap();
        assert!(store.seq_of(&store.read().unwrap(), &id).unwrap().is_none());
    }

    /// NIP-09 deletions and the rest take chunks by turns, so however many
    /// come, a deletion removed one at a time goes on.
    #[test]
    fn nip09_deletions_and_the_rest_take_turns() {
        let picked = json!({"kinds": [1], "limit": 30});
        let (_dir, store) = store_with(&events(60), &[picked]);
        let big = store.pending()[0].clone();
        // Naming too many to be looked up as they're stored, so queued.
        let many = crate::store::SETTLED_AT_ONCE as u32 + 1;
        for n in 0..5u32 {
            let tags = (0..many)
                .map(|m| vec!["e".to_string(), format!("{:064x}", n * 1000 + m)])
                .collect::<Vec<_>>();
            let tags = tags
                .iter()
                .map(|tag| tag.iter().map(String::as_str).collect())
                .collect();
            let deletion = signed(1, 200, 5, tags, "");
            store
                .write_batch([crate::record::encode(&deletion).as_slice()], 0)
                .unwrap();
        }
        let mut purger = Purger::new(&store, None, false).unwrap();
        let mut left = Vec::new();
        for _ in 0..4 {
            // One NIP-09 deletion a chunk, or one event of the rest.
            purger.chunk = 1;
            assert!(purger.work(&store, &|_| {}).unwrap());
            let nip09 = purger.jobs.iter().filter(|job| job.is_nip09()).count();
            let job = purger.jobs.iter().find(|job| job.pending.id == big.id);
            left.push((nip09, job.unwrap().removed));
        }
        assert_eq!(left, [(4, 0), (4, 1), (3, 1), (3, 2)]);
    }

    /// A NIP-09 deletion of more than a chunk's events is kept a plan, and
    /// removed as the rest are.
    #[test]
    fn keeps_a_big_nip09_deletion_a_plan() {
        let (_dir, store) = open();
        let notes: Vec<Event> = (0..3)
            .map(|n| signed(1, 100 + n, 1, vec![], "note"))
            .collect();
        for note in &notes {
            put(&store, note);
        }
        let tags = notes
            .iter()
            .map(|note| vec!["e", note.id.as_str()])
            .collect();
        let deletion = signed(1, 200, 5, tags, "");
        store
            .write_batch([crate::record::encode(&deletion).as_slice()], 0)
            .unwrap();
        let mut purger = Purger::new(&store, None, false).unwrap();
        purger.nip09_at = 2;
        assert!(purger.work(&store, &|_| {}).unwrap());
        assert!(matches!(purger.jobs[0].work, Work::Each { .. }));
        let listed = store.list_pending().unwrap();
        assert_eq!(listed[0].events, Some(3));
        assert_eq!(
            listed[0].covers,
            format!(
                "a NIP-09 deletion by {} of 3 ids and 0 addresses",
                notes[0].pubkey
            )
        );
        while purger.work(&store, &|_| {}).unwrap() {}
        assert_eq!(purger.total, 3);
        assert!(store.list_pending().unwrap().is_empty());
    }

    /// A NIP-09 deletion waiting its turn can be cancelled, showing what it
    /// covers again.
    #[test]
    fn cancels_a_nip09_deletion() {
        let (_dir, store, notes) = with_nip09(2, 0);
        let ids: Vec<u64> = store.pending().iter().map(|pending| pending.id).collect();
        let listed = store.list_pending().unwrap();
        assert_eq!(listed[0].progress(), "waiting its turn");
        assert!(listed[0].covers.ends_with(" of 1 id and 0 addresses"));
        let mut purger = Purger::new(&store, None, false).unwrap();
        purger.cancel(&store, ids[0]).unwrap();
        while purger.work(&store, &|_| {}).unwrap() {}
        assert_eq!(purger.total, 1);
        let txn = store.read().unwrap();
        let id = crate::event::decode_hex::<32>(&notes[0].id).unwrap();
        let seq = store.seq_of(&txn, &id).unwrap().unwrap();
        assert!(store.load(&txn, seq).unwrap().is_some());
    }

    /// Cancelled partway, what a deletion removed stays removed, the rest
    /// is shown again, and the others go on; one that's begun sweeping is
    /// refused, and goes on.
    #[test]
    fn cancels_one_deletion() {
        let events = events(60);
        let picked = json!({"kinds": [1], "limit": 10});
        let (dir, store) = store_with(&events, &[filters()[1].clone(), picked]);
        let ids: Vec<u64> = store.pending().iter().map(|pending| pending.id).collect();
        let visible = |store: &Store| {
            let txn = store.read().unwrap();
            (1..=events.len() as u64)
                .filter(|&seq| store.load(&txn, seq).unwrap().is_some())
                .count()
        };
        let stored = |store: &Store| store.len(&store.read().unwrap()).unwrap();
        let hidden = visible(&store);
        let mut purger = Purger::new(&store, None, false).unwrap();
        purger.sweep_at = u64::MAX;
        purger.chunk = 4;
        // Both planned, and four of the picked removed: the fewest left.
        assert!(purger.work(&store, &|_| {}).unwrap());
        purger.chunk = 4;
        let before = stored(&store);
        purger.cancel(&store, ids[1]).unwrap();
        assert!(purger.jobs.iter().all(|job| job.pending.id == ids[0]));
        assert_eq!(store.pending().len(), 1);
        // The six left of the picked are shown again, unless the filter
        // covers them too.
        assert!(visible(&store) > hidden);
        assert_eq!(stored(&store), before);
        let err = purger.cancel(&store, ids[1]).unwrap_err().to_string();
        assert_eq!(err, format!("no deletion {} is pending", ids[1]));
        // Gone from what's kept, so not taken up again after a restart.
        drop(purger);
        drop(store);
        let store = open_in(dir.path());
        assert_eq!(store.pending().len(), 1);
    }

    /// Begun sweeping, a deletion can't be cancelled until it's done.
    #[test]
    fn wont_cancel_a_sweep_under_way() {
        let (_dir, store) = store_with(&events(60), &filters()[1..]);
        let id = store.pending()[0].id;
        let mut purger = Purger::new(&store, None, false).unwrap();
        purger.sweep_at = 0;
        purger.fixed_chunk = Some(2);
        for _ in 0..3 {
            assert!(purger.work(&store, &|_| {}).unwrap());
        }
        let err = purger.cancel(&store, id).unwrap_err().to_string();
        assert!(err.contains("can't be stopped until it's done"), "{err}");
        assert_eq!(store.pending().len(), 1);
        drop(purger);
        assert!(purge(&store, 0, Some(2), None));
        assert!(store.pending().is_empty());
    }

    /// However often the writer writes, a chunk waits only as long as the
    /// last took.
    #[test]
    fn writes_put_off_the_next_chunk_once() {
        let (_dir, store) = open();
        let mut purger = Purger::new(&store, None, false).unwrap();
        purger.took = Duration::from_millis(600);
        purger.ended = Instant::now();
        purger.resume = purger.ended;
        for _ in 0..5 {
            purger.wrote();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(purger.resume, purger.ended + purger.took);
    }

    #[test]
    fn sizes_chunks_by_how_long_they_take() {
        let ms = Duration::from_millis;
        assert_eq!(next_chunk(64, ms(1), MAX_CHUNK), 128);
        assert_eq!(next_chunk(800, ms(1), MAX_CHUNK), MAX_CHUNK);
        assert_eq!(next_chunk(64, ms(40), MAX_CHUNK), 64);
        assert_eq!(next_chunk(64, ms(200), MAX_CHUNK), 32);
        assert_eq!(next_chunk(1, Duration::from_secs(30), MAX_CHUNK), 1);
    }
}
