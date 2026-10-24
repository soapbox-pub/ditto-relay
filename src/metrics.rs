//! What an operator checks on a running relay, served in Prometheus's text
//! format on its own address, away from clients.
//!
//! Each metric answers a question about the relay's health: whether the
//! writer is keeping up, whether background work is, how close the LMDB is
//! to full, and whether clients are getting wrong answers or errors.
//! Durations are kept as totals beside counts, so their average is one
//! division away.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::search::SearchIndex;
use crate::store::Store;

pub struct Counter(AtomicU64);

impl Counter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct Gauge(AtomicI64);

impl Gauge {
    const fn new() -> Self {
        Self(AtomicI64::new(0))
    }

    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// How many times something took how long, in total.
pub struct Timer {
    count: Counter,
    micros: Counter,
}

impl Timer {
    const fn new() -> Self {
        Self {
            count: Counter::new(),
            micros: Counter::new(),
        }
    }

    /// Record one, which began at `start`.
    pub fn since(&self, start: Instant) {
        self.count.inc();
        self.micros.add(start.elapsed().as_micros() as u64);
    }
}

pub struct Metrics {
    pub connections: Gauge,
    pub events_accepted: Counter,
    pub events_duplicate: Counter,
    pub events_rejected: Counter,
    pub events_failed: Counter,
    /// Refused by the write policy plugin, but said to be accepted.
    pub events_shadow_rejected: Counter,
    /// Time spent waiting on the write policy plugin.
    pub plugin: Timer,
    /// Time from handing an event to the writer to hearing back.
    pub writes: Timer,
    pub write_latency: Histogram,
    /// Write transactions committed, and how long committing each took.
    pub commits: Histogram,
    pub writer: Writer,
    /// Events waiting for the writer.
    pub write_queue: Gauge,
    /// Time spent making checkpoints durable, writes going on meanwhile.
    pub checkpoints: Timer,
    /// Time spent querying for REQs, not sending what's found.
    pub reqs: Timer,
    pub counts: Timer,
    /// Time spent finding NIP-77 syncs' events and answering their messages.
    pub syncs: Timer,
    /// Filters that examined as many events as they may before finding
    /// their limit, so may have missed some.
    pub filters_cut_short: Counter,
    /// Stored events loaded to answer REQs and COUNTs, matching or not.
    pub events_examined: Counter,
    pub counts_refused: Counter,
    pub errors_write: Counter,
    pub errors_query: Counter,
    pub errors_panic: Counter,
    /// The write policy plugin dying, hanging, or answering nonsense.
    pub errors_plugin: Counter,
    /// Batches of new events waiting for the live subscription threads.
    pub live_queue: Gauge,
    /// Clients dropped for falling too far behind on their live events.
    pub dropped_behind: Counter,
    /// Clients dropped for not reading what was written to them.
    pub dropped_stalled: Counter,
    /// Clients dropped for going silent without closing.
    pub dropped_silent: Counter,
}

pub static METRICS: Metrics = Metrics {
    connections: Gauge::new(),
    events_accepted: Counter::new(),
    events_duplicate: Counter::new(),
    events_rejected: Counter::new(),
    events_failed: Counter::new(),
    events_shadow_rejected: Counter::new(),
    plugin: Timer::new(),
    writes: Timer::new(),
    write_latency: Histogram::new(),
    commits: Histogram::new(),
    writer: Writer::new(),
    write_queue: Gauge::new(),
    checkpoints: Timer::new(),
    reqs: Timer::new(),
    counts: Timer::new(),
    syncs: Timer::new(),
    filters_cut_short: Counter::new(),
    events_examined: Counter::new(),
    counts_refused: Counter::new(),
    errors_write: Counter::new(),
    errors_query: Counter::new(),
    errors_panic: Counter::new(),
    errors_plugin: Counter::new(),
    live_queue: Gauge::new(),
    dropped_behind: Counter::new(),
    dropped_stalled: Counter::new(),
    dropped_silent: Counter::new(),
};

/// Counts a connection open for as long as it's held.
pub struct Connected;

impl Connected {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        METRICS.connections.inc();
        Self
    }
}

/// How many times something took how long, counted into buckets, as a
/// Prometheus histogram: for what has to answer "how slow is the worst of
/// it", which a total can't.
pub struct Histogram {
    /// Each bucket counts those that took no more than its bound.
    buckets: [Counter; BOUNDS.len()],
    count: Counter,
    micros: Counter,
}

/// The upper bounds of a [`Histogram`]'s buckets, in seconds, past the last
/// of which is `+Inf`.
const BOUNDS: [f64; 12] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0, 5.0, 15.0, 60.0,
];

impl Histogram {
    const fn new() -> Self {
        Self {
            buckets: [const { Counter::new() }; BOUNDS.len()],
            count: Counter::new(),
            micros: Counter::new(),
        }
    }

    /// Record one that took `took`.
    pub fn observe(&self, took: Duration) {
        let seconds = took.as_secs_f64();
        if let Some(n) = BOUNDS.iter().position(|&bound| seconds <= bound) {
            self.buckets[n].inc();
        }
        self.count.inc();
        self.micros.add(took.as_micros() as u64);
    }
}

/// What the writer's thread does between waiting for work: see
/// [`Writer::phase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Removing the records of events removed.
    Forget = 1,
    /// Removing expired events.
    Expiry,
    /// Storing a batch of events.
    Batch,
    /// Pushing trust, or a rank walk.
    Turn,
    /// A chunk of a deletion.
    Purge,
    /// Queueing or cancelling a deletion asked for.
    Queue,
}

impl Phase {
    const ALL: [Phase; 6] = [
        Phase::Forget,
        Phase::Expiry,
        Phase::Batch,
        Phase::Turn,
        Phase::Purge,
        Phase::Queue,
    ];

    fn name(self) -> &'static str {
        match self {
            Phase::Forget => "forget",
            Phase::Expiry => "expiry",
            Phase::Batch => "batch",
            Phase::Turn => "turn",
            Phase::Purge => "purge",
            Phase::Queue => "queue",
        }
    }
}

/// What the writer's thread is doing, and has done.
pub struct Writer {
    phases: [Timer; Phase::ALL.len()],
    /// The phase under way, 0 if none, and when it began, in microseconds
    /// since [`EPOCH`].
    phase: AtomicU8,
    since: AtomicU64,
    /// The thread's id, for its CPU time, 0 until it starts.
    tid: AtomicI32,
}

/// What the writer's busy-since is counted from.
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn micros_since_epoch() -> u64 {
    EPOCH.elapsed().as_micros() as u64
}

impl Writer {
    const fn new() -> Self {
        Self {
            phases: [const { Timer::new() }; Phase::ALL.len()],
            phase: AtomicU8::new(0),
            since: AtomicU64::new(0),
            tid: AtomicI32::new(0),
        }
    }

    /// Note that the calling thread is the writer.
    pub fn started(&self) {
        // SAFETY: gettid takes nothing, and can't fail.
        self.tid.store(unsafe { libc::gettid() }, Ordering::Relaxed);
    }

    /// Note `phase` begun, until what's returned is dropped, timing it.
    pub fn phase(&self, phase: Phase) -> InPhase<'_> {
        self.since.store(micros_since_epoch(), Ordering::Relaxed);
        self.phase.store(phase as u8, Ordering::Relaxed);
        InPhase {
            writer: self,
            phase,
            start: Instant::now(),
        }
    }

    /// The phase under way, and how long it's taken so far.
    pub fn busy(&self) -> Option<(Phase, Duration)> {
        let phase = self.phase.load(Ordering::Relaxed);
        let phase = *Phase::ALL.iter().find(|p| **p as u8 == phase)?;
        let since = self.since.load(Ordering::Relaxed);
        Some((
            phase,
            Duration::from_micros(micros_since_epoch().saturating_sub(since)),
        ))
    }

    /// The writer thread's CPU time, in user space and in the kernel, in
    /// seconds.
    fn cpu(&self) -> Option<(f64, f64)> {
        let tid = self.tid.load(Ordering::Relaxed);
        if tid == 0 {
            return None;
        }
        let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
        // Past the name, which may hold spaces, in parentheses; utime and
        // stime are the 14th and 15th fields, the 12th and 13th after it.
        let mut fields = stat.rsplit_once(')')?.1.split_whitespace().skip(11);
        let (user, system): (u64, u64) =
            (fields.next()?.parse().ok()?, fields.next()?.parse().ok()?);
        // SAFETY: plain query of a constant.
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
        Some((user as f64 / ticks, system as f64 / ticks))
    }
}

/// A [phase](Writer::phase) of the writer's under way.
pub struct InPhase<'a> {
    writer: &'a Writer,
    phase: Phase,
    start: Instant,
}

impl InPhase<'_> {
    /// Run `f` in this phase.
    pub fn run<T>(self, f: impl FnOnce() -> T) -> T {
        f()
    }
}

impl Drop for InPhase<'_> {
    fn drop(&mut self) {
        self.writer.phases[self.phase as usize - 1].since(self.start);
        self.writer.phase.store(0, Ordering::Relaxed);
    }
}

/// How long a phase of the writer's may take before it's warned of.
const STUCK: Duration = Duration::from_secs(5);

/// Warn, every so often, while the writer's been in one phase longer than
/// [`STUCK`], with every write waiting on it: so that a stalled writer is
/// in the log within seconds, saying where it's stuck.
pub fn watch_writer() {
    static WATCHING: std::sync::Once = std::sync::Once::new();
    WATCHING.call_once(start_watching);
}

fn start_watching() {
    let watch = || {
        let mut warned: Option<(u64, Instant)> = None;
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let Some((phase, took)) = METRICS.writer.busy() else {
                warned = None;
                continue;
            };
            if took < STUCK {
                continue;
            }
            // Once a phase, then every so often while it lasts.
            let since = METRICS.writer.since.load(Ordering::Relaxed);
            if warned.is_some_and(|(at, when)| at == since && when.elapsed() < STUCK * 2) {
                continue;
            }
            tracing::warn!(
                "the writer has been in its {} phase for {took:.0?}, with {} writes waiting",
                phase.name(),
                METRICS.write_queue.get()
            );
            warned = Some((since, Instant::now()));
        }
    };
    if let Err(err) = std::thread::Builder::new()
        .name("writer-watch".into())
        .spawn(watch)
    {
        tracing::warn!("couldn't start watching the writer: {err}");
    }
}

/// When the last of the slowest commits was, and how long it took, for
/// the log: see [`note_commit`].
static SLOWEST: Mutex<Option<Instant>> = Mutex::new(None);

/// Record a commit of a write transaction that took `took`, warning of one
/// slow enough to hold writes up, at most once a minute.
pub fn note_commit(took: Duration) {
    METRICS.commits.observe(took);
    if took < Duration::from_secs(1) {
        return;
    }
    let mut last = SLOWEST.lock().expect("unpoisoned");
    if last.is_none_or(|at| at.elapsed() >= Duration::from_secs(60)) {
        tracing::warn!("a commit took {took:.1?}");
        *last = Some(Instant::now());
    }
}

impl Drop for Connected {
    fn drop(&mut self) {
        METRICS.connections.dec();
    }
}

/// The exposition being written.
struct Out(String);

impl Out {
    fn metric(&mut self, name: &str, kind: &str, help: &str, values: &[(&str, f64)]) {
        let _ = writeln!(self.0, "# HELP ditto_relay_{name} {help}");
        let _ = writeln!(self.0, "# TYPE ditto_relay_{name} {kind}");
        for (labels, value) in values {
            let _ = match labels.is_empty() {
                true => writeln!(self.0, "ditto_relay_{name} {value}"),
                false => writeln!(self.0, "ditto_relay_{name}{{{labels}}} {value}"),
            };
        }
    }

    fn one(&mut self, name: &str, kind: &str, help: &str, value: f64) {
        self.metric(name, kind, help, &[("", value)]);
    }

    fn histogram(&mut self, name: &str, help: &str, histogram: &Histogram) {
        let _ = writeln!(self.0, "# HELP ditto_relay_{name} {help}");
        let _ = writeln!(self.0, "# TYPE ditto_relay_{name} histogram");
        let mut below = 0;
        for (bound, bucket) in BOUNDS.iter().zip(&histogram.buckets) {
            below += bucket.get();
            let _ = writeln!(
                self.0,
                "ditto_relay_{name}_bucket{{le=\"{bound}\"}} {below}"
            );
        }
        let count = histogram.count.get();
        let _ = writeln!(self.0, "ditto_relay_{name}_bucket{{le=\"+Inf\"}} {count}");
        let sum = histogram.micros.get() as f64 / 1e6;
        let _ = writeln!(self.0, "ditto_relay_{name}_sum {sum}");
        let _ = writeln!(self.0, "ditto_relay_{name}_count {count}");
    }

    fn timer(&mut self, name: &str, what: &str, timer: &Timer) {
        let count = timer.count.get() as f64;
        let seconds = timer.micros.get() as f64 / 1e6;
        self.one(
            &format!("{name}s_total"),
            "counter",
            &format!("{what}."),
            count,
        );
        let help = format!("Time spent on {what}, in total.");
        self.one(&format!("{name}_seconds_total"), "counter", &help, seconds);
    }
}

/// Every metric, reading what's cheap to look up from the store and the
/// search index now.
pub fn render(store: &Store, search: Option<&SearchIndex>) -> anyhow::Result<String> {
    let m = &METRICS;
    let mut out = Out(String::new());

    out.one(
        "connections",
        "gauge",
        "Open WebSocket connections.",
        m.connections.get() as f64,
    );
    out.metric(
        "events_total",
        "counter",
        "Events received, by what became of them.",
        &[
            (r#"result="accepted""#, m.events_accepted.get() as f64),
            (r#"result="duplicate""#, m.events_duplicate.get() as f64),
            (r#"result="rejected""#, m.events_rejected.get() as f64),
            (r#"result="failed""#, m.events_failed.get() as f64),
            (
                r#"result="shadow_rejected""#,
                m.events_shadow_rejected.get() as f64,
            ),
        ],
    );
    out.timer("plugin_call", "Write policy plugin calls", &m.plugin);
    out.timer("write", "Events handed to the writer", &m.writes);
    out.histogram(
        "write_latency_seconds",
        "Time from handing an event to the writer to hearing back.",
        &m.write_latency,
    );
    out.histogram(
        "commit_seconds",
        "Time committing each write transaction took, every writer's work among them.",
        &m.commits,
    );
    let labels: Vec<String> = Phase::ALL
        .iter()
        .map(|phase| format!(r#"phase="{}""#, phase.name()))
        .collect();
    let phases = |f: &dyn Fn(&Timer) -> f64| -> Vec<(&str, f64)> {
        labels
            .iter()
            .zip(&m.writer.phases)
            .map(|(label, timer)| (label.as_str(), f(timer)))
            .collect()
    };
    out.metric(
        "writer_phases_total",
        "counter",
        "Times the writer's thread did each kind of work.",
        &phases(&|timer| timer.count.get() as f64),
    );
    out.metric(
        "writer_phase_seconds_total",
        "counter",
        "Time the writer's thread spent on each kind of work, in total. Writes wait on all of it.",
        &phases(&|timer| timer.micros.get() as f64 / 1e6),
    );
    out.one(
        "writer_busy_seconds",
        "gauge",
        "How long the writer's thread has been on what it's doing now, 0 if it's waiting for work. Seconds or more means every write is waiting.",
        m.writer.busy().map_or(0.0, |(_, took)| took.as_secs_f64()),
    );
    if let Some((user, system)) = m.writer.cpu() {
        out.metric(
            "writer_cpu_seconds_total",
            "counter",
            "CPU time of the writer's thread, in user space and in the kernel.",
            &[(r#"mode="user""#, user), (r#"mode="system""#, system)],
        );
    }
    out.one(
        "write_queue",
        "gauge",
        "Events waiting for the writer.",
        m.write_queue.get() as f64,
    );
    out.timer("checkpoint", "Checkpoints made durable", &m.checkpoints);
    out.timer("req", "REQ queries", &m.reqs);
    out.timer("count", "COUNT queries", &m.counts);
    out.timer("sync", "NIP-77 sync messages answered", &m.syncs);
    out.one(
        "filters_cut_short_total",
        "counter",
        "REQ filters that gave up examining events before reaching their limit, so may have missed some.",
        m.filters_cut_short.get() as f64,
    );
    out.one(
        "events_examined_total",
        "counter",
        "Stored events loaded to answer REQs and COUNTs, matching or not. Far more than are sent means the indexes aren't narrowing filters down.",
        m.events_examined.get() as f64,
    );
    out.one(
        "counts_refused_total",
        "counter",
        "COUNTs refused as too expensive.",
        m.counts_refused.get() as f64,
    );
    out.metric(
        "errors_total",
        "counter",
        "Failures on the relay's side, by where.",
        &[
            (r#"source="write""#, m.errors_write.get() as f64),
            (r#"source="query""#, m.errors_query.get() as f64),
            (r#"source="panic""#, m.errors_panic.get() as f64),
            (r#"source="plugin""#, m.errors_plugin.get() as f64),
        ],
    );
    out.one(
        "live_queue",
        "gauge",
        "Batches of new events waiting to be matched against live subscriptions.",
        m.live_queue.get() as f64,
    );
    out.metric(
        "clients_dropped_total",
        "counter",
        "Connections the relay dropped, by why.",
        &[
            (r#"reason="behind""#, m.dropped_behind.get() as f64),
            (r#"reason="stalled""#, m.dropped_stalled.get() as f64),
            (r#"reason="silent""#, m.dropped_silent.get() as f64),
        ],
    );

    let usage = store.usage()?;
    let txn = store.read()?;
    let t = store.tables;
    out.one(
        "stored_events",
        "gauge",
        "Events stored, old versions included.",
        txn.len(t.events)? as f64,
    );
    let mut backlog = vec![
        (r#"work="wot""#, txn.len(t.wot_queue)? as f64),
        (r#"work="rank""#, txn.len(t.rank_queue)? as f64),
    ];
    if let Some(search) = search {
        let behind = store.next_seq(&txn)?.saturating_sub(search.indexed());
        backlog.push((r#"work="search""#, behind as f64));
    }
    out.metric(
        "backlog",
        "gauge",
        "Work waiting in the background: authors to push trust from, engagers to rescore what they engaged with, and events to make searchable.",
        &backlog,
    );
    let (keys, ready) = store.deletion_filter();
    out.one(
        "deletion_filter_keys",
        "gauge",
        "Keys added to the filter that spares deletion checks from LMDB. Past about 200 million, it spares fewer.",
        keys as f64,
    );
    out.one(
        "deletion_filter_ready",
        "gauge",
        "Whether the deletion filter has caught up since startup; until then every deletion check searches LMDB.",
        f64::from(u8::from(ready)),
    );
    let (main, bodies) = usage;
    out.metric(
        "lmdb_used_bytes",
        "gauge",
        "How much of each LMDB environment's map is used: the indexes', and the event records'. Writes fail once one is full.",
        &[
            (r#"env="main""#, main.used as f64),
            (r#"env="bodies""#, bodies.used as f64),
        ],
    );
    out.metric(
        "lmdb_map_bytes",
        "gauge",
        "How big each LMDB environment's map is (map_size).",
        &[
            (r#"env="main""#, main.map as f64),
            (r#"env="bodies""#, bodies.map as f64),
        ],
    );
    Ok(out.0)
}

#[derive(Clone)]
struct MetricsState {
    store: Arc<Store>,
    search: Option<Arc<SearchIndex>>,
}

pub fn router(store: Arc<Store>, search: Option<Arc<SearchIndex>>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(MetricsState { store, search })
}

async fn metrics(State(state): State<MetricsState>) -> Response {
    let rendered =
        tokio::task::spawn_blocking(move || render(&state.store, state.search.as_deref())).await;
    match rendered {
        Ok(Ok(text)) => (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            text,
        )
            .into_response(),
        Ok(Err(err)) => {
            tracing::error!("rendering metrics failed: {err:#}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(err) => {
            tracing::error!("rendering metrics panicked: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::store::tests::{open, put};

    /// A sample's value, from the rendered exposition.
    fn sample(text: &str, name: &str) -> f64 {
        let line = text
            .lines()
            .find(|line| line.split_once(' ').is_some_and(|(n, _)| n == name))
            .unwrap_or_else(|| panic!("no {name} in\n{text}"));
        line.rsplit_once(' ').unwrap().1.parse().unwrap()
    }

    #[test]
    fn renders_the_store() {
        let (_dir, store) = open();
        put(&store, &signed(1, 100, 1, vec![], "hi"));
        put(&store, &signed(1, 101, 1, vec![], "there"));
        let text = render(&store, None).unwrap();

        assert_eq!(sample(&text, "ditto_relay_stored_events"), 2.0);
        assert_eq!(sample(&text, r#"ditto_relay_backlog{work="wot"}"#), 0.0);
        assert!(!text.contains(r#"work="search""#));
        for env in ["main", "bodies"] {
            let used = sample(
                &text,
                &format!(r#"ditto_relay_lmdb_used_bytes{{env="{env}"}}"#),
            );
            let map = sample(
                &text,
                &format!(r#"ditto_relay_lmdb_map_bytes{{env="{env}"}}"#),
            );
            assert!(0.0 < used && used <= map, "{env}");
        }
        // Every sample is introduced by its HELP and TYPE.
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            let name = ["_bucket", "_sum", "_count"]
                .iter()
                .filter_map(|suffix| name.strip_suffix(suffix))
                .find(|base| text.contains(&format!("# TYPE {base} histogram")))
                .unwrap_or(name);
            assert!(
                text.contains(&format!("# TYPE {name} ")),
                "{name} has no TYPE"
            );
        }
    }

    #[test]
    fn counts_into_buckets() {
        let histogram = Histogram::new();
        for ms in [0, 3, 3, 200, 120_000] {
            histogram.observe(Duration::from_millis(ms));
        }
        let mut out = Out(String::new());
        out.histogram("h", "A test.", &histogram);
        let text = out.0;
        assert_eq!(sample(&text, r#"ditto_relay_h_bucket{le="0.001"}"#), 1.0);
        assert_eq!(sample(&text, r#"ditto_relay_h_bucket{le="0.005"}"#), 3.0);
        assert_eq!(sample(&text, r#"ditto_relay_h_bucket{le="0.25"}"#), 4.0);
        assert_eq!(sample(&text, r#"ditto_relay_h_bucket{le="60"}"#), 4.0);
        assert_eq!(sample(&text, r#"ditto_relay_h_bucket{le="+Inf"}"#), 5.0);
        assert_eq!(sample(&text, "ditto_relay_h_count"), 5.0);
        assert!(sample(&text, "ditto_relay_h_sum") > 120.0);
    }

    #[test]
    fn times_the_writers_phases() {
        let writer = Writer::new();
        assert!(writer.busy().is_none());
        assert!(writer.cpu().is_none());
        {
            let _batch = writer.phase(Phase::Batch);
            std::thread::sleep(Duration::from_millis(20));
            let (phase, took) = writer.busy().unwrap();
            assert_eq!(phase, Phase::Batch);
            assert!(took >= Duration::from_millis(20));
        }
        assert!(writer.busy().is_none());
        assert_eq!(writer.phases[Phase::Batch as usize - 1].count.get(), 1);
        writer.started();
        let (user, system) = writer.cpu().unwrap();
        assert!(user >= 0.0 && system >= 0.0);
    }

    #[test]
    fn times_add_up() {
        let timer = Timer::new();
        let start = Instant::now() - std::time::Duration::from_millis(1500);
        timer.since(start);
        timer.since(start);
        assert_eq!(timer.count.get(), 2);
        assert!(timer.micros.get() >= 3_000_000);
    }
}
