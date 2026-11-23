//! The live numbers the landing page shows, served as JSON at `/stats`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::metrics::{METRICS, STARTED};
use crate::store::Store;

/// How long an answer is reused for, so many pages polling at once cost
/// one look at the store.
const FRESH: Duration = Duration::from_secs(1);

/// The average answer time is over the last one to two of these.
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct Stats {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The last answer, and when it was made.
    cached: Option<(Instant, String)>,
    /// Queries answered by the start of the last window, and the one
    /// before it: the average is from the older.
    older: Option<Sample>,
    newer: Option<Sample>,
}

/// Queries answered by a moment.
#[derive(Clone, Copy)]
struct Sample {
    at: Instant,
    count: u64,
    took: Duration,
}

impl Sample {
    fn now() -> Self {
        let (reqs, req_took) = METRICS.reqs.totals();
        let (counts, count_took) = METRICS.counts.totals();
        Self {
            at: Instant::now(),
            count: reqs + counts,
            took: req_took + count_took,
        }
    }
}

impl Stats {
    /// The numbers, as JSON. Reads the store, so it blocks.
    pub fn json(&self, store: &Store) -> anyhow::Result<String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, json)) = &inner.cached
            && at.elapsed() < FRESH
        {
            return Ok(json.clone());
        }
        let txn = store.read()?;
        let events = txn.len(store.tables.events)?;
        drop(txn);

        let now = Sample::now();
        if inner.newer.is_none_or(|newer| newer.at.elapsed() >= WINDOW) {
            inner.older = inner.newer.replace(now);
        }
        // Since the older window began, or since startup.
        let since = inner
            .older
            .map_or((0, Duration::ZERO), |s| (s.count, s.took));
        let (count, took) = (now.count - since.0, now.took.saturating_sub(since.1));
        let (count, took) = match count {
            0 => (now.count, now.took),
            _ => (count, took),
        };
        let answer_ms = match count {
            0 => 0.0,
            _ => took.as_secs_f64() * 1e3 / count as f64,
        };

        let json = json!({
            "events": events,
            "connections": METRICS.connections.get().max(0),
            "answer_ms": answer_ms,
            "requests": now.count,
            "uptime_secs": STARTED.elapsed().as_secs(),
        })
        .to_string();
        inner.cached = Some((Instant::now(), json.clone()));
        Ok(json)
    }
}
