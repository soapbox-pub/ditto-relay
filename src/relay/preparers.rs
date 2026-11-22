//! The threads that ready new events for the writer: check their
//! signatures, as many at once as are waiting (see [`crate::batch`]), and
//! encode them. One takes every event waiting, up to [`MAX_BATCH`], so
//! under a flood of events the batches grow, and one event alone is
//! checked alone. Reading ahead what storing them will is left to the
//! writer, which does it where many wait on the disk at once.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};

use tokio::sync::oneshot;

use crate::batch;
use crate::event::Event;
use crate::metrics::METRICS;
use crate::record;

/// The most events a thread takes at once.
pub const MAX_BATCH: usize = 256;

/// How many events waiting call on one more thread: half a batch's worth,
/// so a thread takes many at once, and more join once one can't keep up,
/// before what waits for it waits long.
const WAKE_PER: usize = MAX_BATCH / 2;

pub struct Preparers {
    shared: Arc<Shared>,
}

struct Shared {
    queue: Mutex<Queue>,
    waiting: Condvar,
}

#[derive(Default)]
struct Queue {
    jobs: VecDeque<Job>,
    /// How many threads are readying a batch.
    busy: usize,
    closed: bool,
}

struct Job {
    ev: Event,
    check: bool,
    encode: bool,
    reply: Reply,
}

/// Where a job's result goes: to one waiting on it, or to be done with
/// there and then, on the preparing thread.
enum Reply {
    Wait(oneshot::Sender<Result<Done, Cow<'static, str>>>),
    Then(Box<dyn FnOnce(Result<Done, Cow<'static, str>>) + Send>),
}

impl Reply {
    fn send(self, done: Result<Done, Cow<'static, str>>) {
        match self {
            Reply::Wait(reply) => {
                let _ = reply.send(done);
            }
            Reply::Then(then) => then(done),
        }
    }
}

enum Done {
    Checked(Event),
    Ready(Arc<Vec<u8>>),
}

impl Preparers {
    pub fn new(threads: usize) -> Preparers {
        let shared = Arc::new(Shared {
            queue: Mutex::default(),
            waiting: Condvar::new(),
        });
        for i in 0..threads.max(1) {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name(format!("prepare-{i}"))
                .spawn(move || shared.run())
                .expect("failed to spawn a preparing thread");
        }
        Preparers { shared }
    }

    /// The event if its signature is good, or why not.
    pub async fn check(&self, ev: Event) -> Result<Event, Cow<'static, str>> {
        match self.send(ev, true, false).await? {
            Done::Checked(ev) => Ok(ev),
            Done::Ready(_) => unreachable!("not encoded"),
        }
    }

    /// The event encoded, its signature checked unless it has been.
    pub async fn ready(&self, ev: Event, checked: bool) -> Result<Arc<Vec<u8>>, Cow<'static, str>> {
        match self.send(ev, !checked, true).await? {
            Done::Ready(record) => Ok(record),
            Done::Checked(_) => unreachable!("encoded"),
        }
    }

    /// Check and encode the event, then call `then` with it, or why not,
    /// on the thread that did: it should be quick. Unless the preparers
    /// are shutting down.
    pub fn ready_then(
        &self,
        ev: Event,
        then: impl FnOnce(Result<Arc<Vec<u8>>, Cow<'static, str>>) + Send + 'static,
    ) -> Result<(), Cow<'static, str>> {
        let then = Box::new(move |done: Result<Done, Cow<'static, str>>| {
            then(done.map(|done| match done {
                Done::Ready(record) => record,
                Done::Checked(_) => unreachable!("encoded"),
            }))
        });
        self.push(Job {
            ev,
            check: true,
            encode: true,
            reply: Reply::Then(then),
        })
    }

    async fn send(&self, ev: Event, check: bool, encode: bool) -> Result<Done, Cow<'static, str>> {
        let (reply, done) = oneshot::channel();
        self.push(Job {
            ev,
            check,
            encode,
            reply: Reply::Wait(reply),
        })?;
        done.await
            .unwrap_or_else(|_| Err("error: shutting down".into()))
    }

    fn push(&self, job: Job) -> Result<(), Cow<'static, str>> {
        let waiting = {
            let mut queue = self.shared.queue.lock().expect("unpoisoned");
            if queue.closed {
                return Err("error: shutting down".into());
            }
            queue.jobs.push_back(job);
            queue.jobs.len()
        };
        // The first waits for a thread, which takes every one that's come
        // by the time it's free; only so many more call on another, so
        // that batches grow rather than split among threads.
        if waiting == 1 || waiting % WAKE_PER == 0 {
            self.shared.waiting.notify_one();
        }
        Ok(())
    }
}

impl Drop for Preparers {
    fn drop(&mut self) {
        self.shared.queue.lock().expect("unpoisoned").closed = true;
        self.shared.waiting.notify_all();
    }
}

/// A thread readying a batch, until it's dropped.
struct Busy<'a>(&'a Shared);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        if let Ok(mut queue) = self.0.queue.lock() {
            queue.busy -= 1;
        }
    }
}

impl Shared {
    fn run(&self) {
        loop {
            let jobs: Vec<Job> = {
                let mut queue = self.queue.lock().expect("unpoisoned");
                // Another thread takes these when it's done, unless enough
                // wait for two to be quicker.
                while (queue.jobs.is_empty() || queue.busy > 0 && queue.jobs.len() < WAKE_PER)
                    && !queue.closed
                {
                    queue = self.waiting.wait(queue).expect("unpoisoned");
                }
                if queue.jobs.is_empty() {
                    return;
                }
                queue.busy += 1;
                let n = queue.jobs.len().min(MAX_BATCH);
                queue.jobs.drain(..n).collect()
            };
            let _busy = Busy(self);
            self.prepare(jobs);
        }
    }

    fn prepare(&self, jobs: Vec<Job>) {
        let verdicts = verdicts(jobs.iter().map(|job| job.check.then_some(&job.ev)));
        for (job, verdict) in jobs.into_iter().zip(verdicts) {
            let Job {
                ev, encode, reply, ..
            } = job;
            let done = match (verdict, encode) {
                (Err(err), _) => Err(Cow::Owned(err)),
                (Ok(()), false) => Ok(Done::Checked(ev)),
                (Ok(()), true) => encoded(&ev).map(Done::Ready),
            };
            reply.send(done);
        }
    }
}

/// Whether each event's signature is good, checking as many at once as
/// there are: those given as `None` aren't checked.
fn verdicts<'a>(events: impl Iterator<Item = Option<&'a Event>>) -> Vec<Result<(), String>> {
    let mut verdicts = Vec::new();
    let mut signed = Vec::new();
    let mut checked = Vec::new();
    for (i, ev) in events.enumerate() {
        verdicts.push(Ok(()));
        if let Some(ev) = ev {
            match ev.signed() {
                Ok(one) => {
                    signed.push(one);
                    checked.push(i);
                }
                Err(err) => verdicts[i] = Err(err),
            }
        }
    }
    if !signed.is_empty() {
        METRICS.signature_batches.inc();
        METRICS.signatures_batched.add(signed.len() as u64);
        match catch_unwind(AssertUnwindSafe(|| batch::check_all(&signed))) {
            Ok(checks) => {
                for (i, check) in checked.into_iter().zip(checks) {
                    verdicts[i] = check;
                }
            }
            Err(_) => {
                tracing::error!("checking {} signatures panicked", signed.len());
                METRICS.errors_panic.inc();
                for i in checked {
                    verdicts[i] = Err("error: failed to check event".into());
                }
            }
        }
    }
    verdicts
}

/// Encode an event, which guesses its language and sentiment.
fn encoded(ev: &Event) -> Result<Arc<Vec<u8>>, Cow<'static, str>> {
    match catch_unwind(|| record::encode(ev)) {
        Ok(record) => Ok(Arc::new(record)),
        Err(_) => {
            tracing::error!("encoding event {} panicked", ev.id);
            METRICS.errors_panic.inc();
            Err("error: failed to store event".into())
        }
    }
}
