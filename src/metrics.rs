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
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

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
    /// Events waiting for the writer.
    pub write_queue: Gauge,
    /// Time spent querying for REQs, not sending what's found.
    pub reqs: Timer,
    pub counts: Timer,
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
    write_queue: Gauge::new(),
    reqs: Timer::new(),
    counts: Timer::new(),
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
    out.one(
        "write_queue",
        "gauge",
        "Events waiting for the writer.",
        m.write_queue.get() as f64,
    );
    out.timer("req", "REQ queries", &m.reqs);
    out.timer("count", "COUNT queries", &m.counts);
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
    out.one(
        "lmdb_used_bytes",
        "gauge",
        "How much of the LMDB map is used. Writes fail once it's full.",
        usage.used as f64,
    );
    out.one(
        "lmdb_map_bytes",
        "gauge",
        "How big the LMDB map is (RELAY_MAP_SIZE).",
        usage.map as f64,
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
        let used = sample(&text, "ditto_relay_lmdb_used_bytes");
        assert!(0.0 < used && used <= sample(&text, "ditto_relay_lmdb_map_bytes"));
        // Every sample is introduced by its HELP and TYPE.
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(
                text.contains(&format!("# TYPE {name} ")),
                "{name} has no TYPE"
            );
        }
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
