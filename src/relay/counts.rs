//! NIP-45 counts shared between connections asking the same thing.
//!
//! A client showing the same count to everyone, like Ditto's chart of each
//! client's users, has every visitor ask for it with the same filters. A
//! count asked for while the same one's running waits for it rather than
//! running again, and one that took a while to make is kept for a few
//! minutes, so the next visitors are told it at once. Cheap counts aren't
//! kept: they're made again when asked, and never go stale.
//!
//! Two counts are the same when their parsed filters are, with the kinds
//! the connection may not read already hidden. Filters listing ids aren't
//! shared, since whether the events they find may be seen depends on who
//! asks.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tokio::time::Instant;

use crate::filter::Filter;
use crate::metrics::METRICS;
use crate::query::Count;

/// A count that takes at least this long to make is kept.
const KEEP_AFTER: Duration = Duration::from_secs(1);

/// How long a count is kept.
const KEEP_FOR: Duration = Duration::from_secs(5 * 60);

/// The most counts kept or running at once. Past it, new ones aren't
/// shared until some expire.
const MAX_ENTRIES: usize = 4096;

type Key = [u8; 32];

#[derive(Default)]
struct Entry {
    count: OnceCell<Count>,
    /// When a count that's kept expires. Unset while it's being made.
    expires: OnceLock<Instant>,
}

impl Entry {
    fn fresh(&self, now: Instant) -> bool {
        self.expires.get().is_none_or(|expires| now < *expires)
    }
}

#[derive(Clone, Default)]
pub struct Counts {
    entries: Arc<Mutex<HashMap<Key, Arc<Entry>>>>,
}

impl Counts {
    /// A count of `filters`: one kept, or the one being made, or else made
    /// by `make`. Fails as `make` does, and if it fails for another
    /// connection waited on, is made by `make` here instead.
    pub async fn get<F, Fut>(&self, filters: &[Filter], make: F) -> anyhow::Result<Count>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Count>>,
    {
        let Some(key) = key(filters) else {
            return make().await;
        };
        let Some(entry) = self.entry(key) else {
            return make().await;
        };
        let mut made = false;
        let result = entry
            .count
            .get_or_try_init(|| {
                made = true;
                let entry = &entry;
                async move {
                    let start = Instant::now();
                    let count = make().await?;
                    if start.elapsed() >= KEEP_AFTER {
                        let _ = entry.expires.set(Instant::now() + KEEP_FOR);
                    }
                    Ok::<_, anyhow::Error>(count)
                }
            })
            .await
            .cloned();
        match made {
            false => METRICS.counts_shared.inc(),
            // Those waiting have it; later ones make their own.
            true if result.is_err() || entry.expires.get().is_none() => self.forget(key, &entry),
            true => {}
        }
        result
    }

    /// The entry for a count, made if there's no fresh one, unless there
    /// are too many already.
    fn entry(&self, key: Key) -> Option<Arc<Entry>> {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("unpoisoned");
        if let Some(entry) = entries.get(&key).filter(|entry| entry.fresh(now)) {
            return Some(entry.clone());
        }
        if entries.len() >= MAX_ENTRIES {
            entries.retain(|_, entry| entry.fresh(now));
            if entries.len() >= MAX_ENTRIES {
                return None;
            }
        }
        let entry = Arc::new(Entry::default());
        entries.insert(key, entry.clone());
        Some(entry)
    }

    fn forget(&self, key: Key, entry: &Arc<Entry>) {
        let mut entries = self.entries.lock().expect("unpoisoned");
        if entries.get(&key).is_some_and(|e| Arc::ptr_eq(e, entry)) {
            entries.remove(&key);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().expect("unpoisoned").len()
    }
}

/// What identifies a count, if it may be shared.
fn key(filters: &[Filter]) -> Option<Key> {
    if filters.iter().any(|filter| filter.ids.is_some()) {
        return None;
    }
    Some(Sha256::digest(format!("{filters:?}")).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{MAX_VALUES, test_tags};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn filters(value: serde_json::Value) -> Vec<Filter> {
        vec![Filter::parse(&value, &test_tags(), MAX_VALUES).unwrap()]
    }

    fn count(n: u64) -> Count {
        Count {
            count: n,
            hll: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shares_a_running_count() {
        let counts = Counts::default();
        let made = AtomicUsize::new(0);
        let f = filters(json!({"kinds": [1], "search": "distinct:author"}));
        let make = || async {
            made.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(count(7))
        };
        let (a, b) = tokio::join!(counts.get(&f, make), counts.get(&f, make));
        assert_eq!((a.unwrap().count, b.unwrap().count), (7, 7));
        assert_eq!(made.load(Ordering::SeqCst), 1);
        // Quick, so not kept.
        assert_eq!(counts.len(), 0);
        counts.get(&f, make).await.unwrap();
        assert_eq!(made.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_a_slow_count_a_while() {
        let counts = Counts::default();
        let made = AtomicUsize::new(0);
        let f = filters(json!({"kinds": [1], "#t": ["nostr"]}));
        let make = || async {
            let n = made.fetch_add(1, Ordering::SeqCst) as u64;
            tokio::time::sleep(KEEP_AFTER).await;
            Ok(count(n))
        };
        assert_eq!(counts.get(&f, make).await.unwrap().count, 0);
        tokio::time::advance(KEEP_FOR - Duration::from_secs(1)).await;
        assert_eq!(counts.get(&f, make).await.unwrap().count, 0);
        // Others aren't it.
        let other = filters(json!({"kinds": [1], "#t": ["bitcoin"]}));
        assert_eq!(counts.get(&other, make).await.unwrap().count, 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(counts.get(&f, make).await.unwrap().count, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn makes_its_own_if_the_shared_one_fails() {
        let counts = Counts::default();
        let f = filters(json!({"kinds": [1]}));
        let fail = || async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Err(anyhow::anyhow!("cancelled"))
        };
        let succeed = || async { Ok(count(3)) };
        let (a, b) = tokio::join!(counts.get(&f, fail), async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            counts.get(&f, succeed).await
        });
        assert!(a.is_err());
        assert_eq!(b.unwrap().count, 3);
    }

    #[tokio::test]
    async fn never_shares_ids() {
        let counts = Counts::default();
        let id = "a".repeat(64);
        let f = filters(json!({"ids": [id]}));
        counts.get(&f, || async { Ok(count(1)) }).await.unwrap();
        assert_eq!(counts.len(), 0);
    }
}
