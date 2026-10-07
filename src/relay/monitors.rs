//! Live subscriptions, and which of them each new event goes to.
//!
//! Every open filter is filed in a reverse index under one of its fields:
//! its ids if it has them, else its authors, else the values of its
//! narrowest tag, else its kinds. A new event then only has to be checked
//! against the filters filed under its own id, author, tags, and kind (plus
//! the few with none of those) rather than against every subscription.
//!
//! The writer hands committed events straight here, so they go out as soon
//! as they're durable, and each event's JSON is written once however many
//! subscriptions get it.
//!
//! The matching runs on a few shard threads, each owning the subscriptions
//! of its share of the connections, so the writer only queues a batch and
//! gets on with the next commit. Everything a shard does — connections
//! coming and going, subscriptions opening and closing, new events — arrives
//! on one queue, in order, so there's nothing to lock.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::filter::Filter;
use crate::metrics::METRICS;
use crate::record::EventView;
use crate::store::{MAX_INDEXED_TAG, tag_key};

pub type ConnId = u64;

/// A new event for one of a connection's subscriptions.
#[derive(Debug)]
pub struct Outbound {
    pub sub: Arc<str>,
    /// Its sequence number, if it was stored (ephemeral events aren't).
    pub seq: Option<u64>,
    pub json: Arc<str>,
}

/// The way to a connection. Its queue is bounded: a connection that falls
/// so far behind that it fills up is told to go, rather than buffering
/// without end.
#[derive(Clone)]
pub struct Link {
    tx: mpsc::Sender<Outbound>,
    overflow: CancellationToken,
}

impl Link {
    pub fn new(capacity: usize) -> (Link, mpsc::Receiver<Outbound>, CancellationToken) {
        let (tx, rx) = mpsc::channel(capacity);
        let overflow = CancellationToken::new();
        let link = Link {
            tx,
            overflow: overflow.clone(),
        };
        (link, rx, overflow)
    }

    fn send(&self, message: Outbound) {
        if self.tx.try_send(message).is_err() {
            self.overflow.cancel();
        }
    }
}

/// Commands a shard may fall behind by before whoever sends the next one
/// waits. The writer waiting is the point: fan-out that can't keep up slows
/// writing rather than queueing without end.
const SHARD_QUEUE: usize = 256;

/// A new event on its way to live subscriptions.
pub struct Live {
    pub record: Arc<Vec<u8>>,
    /// Its sequence number, if it was stored (ephemeral events aren't).
    pub seq: Option<u64>,
    /// Its JSON, written by whichever shard needs it first.
    json: OnceLock<Arc<str>>,
}

impl Live {
    pub fn new(record: Arc<Vec<u8>>, seq: Option<u64>) -> Live {
        Live {
            record,
            seq,
            json: OnceLock::new(),
        }
    }
}

enum Command {
    Connect(ConnId, Link),
    Disconnect(ConnId),
    Subscribe {
        conn: ConnId,
        sub: Arc<str>,
        filters: Vec<Filter>,
        installed: oneshot::Sender<()>,
    },
    Unsubscribe(ConnId, String),
    Events(Arc<Vec<Live>>),
}

/// The way to the shards. A connection always goes to the same one.
#[derive(Clone)]
pub struct Hub {
    shards: Arc<[mpsc::Sender<Command>]>,
}

impl Hub {
    /// Start `shards` threads. They run until every `Hub` is dropped.
    pub fn spawn(shards: usize) -> Hub {
        let shards = (0..shards.max(1))
            .map(|i| {
                let (tx, mut rx) = mpsc::channel(SHARD_QUEUE);
                std::thread::Builder::new()
                    .name(format!("live-{i}"))
                    .spawn(move || {
                        let mut monitors = Monitors::default();
                        while let Some(command) = rx.blocking_recv() {
                            if let Command::Events(_) = command {
                                METRICS.live_queue.dec();
                            }
                            monitors.handle(command);
                        }
                    })
                    .expect("failed to spawn a live subscription thread");
                tx
            })
            .collect();
        Hub { shards }
    }

    fn shard(&self, conn: ConnId) -> &mpsc::Sender<Command> {
        &self.shards[(conn % self.shards.len() as u64) as usize]
    }

    pub async fn connect(&self, conn: ConnId, link: Link) {
        let _ = self.shard(conn).send(Command::Connect(conn, link)).await;
    }

    pub async fn disconnect(&self, conn: ConnId) {
        let _ = self.shard(conn).send(Command::Disconnect(conn)).await;
    }

    /// Open a subscription, replacing any of the same id. The receiver
    /// fires once it's live: every event published after that reaches it.
    pub async fn subscribe(
        &self,
        conn: ConnId,
        sub: Arc<str>,
        filters: Vec<Filter>,
    ) -> oneshot::Receiver<()> {
        let (installed, done) = oneshot::channel();
        let command = Command::Subscribe {
            conn,
            sub,
            filters,
            installed,
        };
        let _ = self.shard(conn).send(command).await;
        done
    }

    pub async fn unsubscribe(&self, conn: ConnId, sub: &str) {
        let command = Command::Unsubscribe(conn, sub.to_string());
        let _ = self.shard(conn).send(command).await;
    }

    /// Hand events to every shard, waiting if one is behind. Not for async
    /// code: the writer calls it from its own thread.
    pub fn broadcast(&self, events: Vec<Live>) {
        if events.is_empty() {
            return;
        }
        let events = Arc::new(events);
        for shard in self.shards.iter() {
            METRICS.live_queue.inc();
            if shard
                .blocking_send(Command::Events(events.clone()))
                .is_err()
            {
                METRICS.live_queue.dec();
            }
        }
    }

    /// [`Hub::broadcast`], from async code.
    pub async fn publish(&self, events: Vec<Live>) {
        let events = Arc::new(events);
        for shard in self.shards.iter() {
            METRICS.live_queue.inc();
            if shard.send(Command::Events(events.clone())).await.is_err() {
                METRICS.live_queue.dec();
            }
        }
    }
}

struct Installed {
    /// Unique to the subscription, so an event matching several of its
    /// filters is sent once.
    sub_key: u64,
    conn: ConnId,
    sub: Arc<str>,
    filter: Filter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Bucket {
    Id([u8; 32]),
    Author([u8; 32]),
    Kind(u16),
    Other,
}

struct Connection {
    link: Link,
    /// Subscription id → the keys of its installed filters.
    subs: HashMap<Arc<str>, Vec<u64>>,
}

/// One shard's subscriptions.
#[derive(Default)]
struct Monitors {
    conns: HashMap<ConnId, Connection>,
    filters: HashMap<u64, Installed>,
    next_key: u64,
    buckets: HashMap<Bucket, HashSet<u64>>,
    /// Keyed by [`tag_key`] without a kind.
    tags: HashMap<Vec<u8>, HashSet<u64>>,
}

/// Where a filter is filed: the field the fewest events can match, of
/// those it has.
enum Filed {
    Buckets(Vec<Bucket>),
    Tags(Vec<Vec<u8>>),
}

fn filed(filter: &Filter) -> Filed {
    match filter {
        Filter { ids: Some(ids), .. } => {
            Filed::Buckets(ids.iter().map(|id| Bucket::Id(*id)).collect())
        }
        Filter {
            authors: Some(authors),
            ..
        } => Filed::Buckets(authors.iter().map(|a| Bucket::Author(*a)).collect()),
        Filter { tags, .. } if !tags.is_empty() => {
            let (name, values) = tags
                .iter()
                .min_by_key(|(_, values)| values.len())
                .expect("a tag");
            Filed::Tags(
                values
                    .iter()
                    .map(|value| tag_key(name, value, None))
                    .collect(),
            )
        }
        Filter {
            kinds: Some(kinds), ..
        } => Filed::Buckets(kinds.iter().map(|k| Bucket::Kind(*k)).collect()),
        _ => Filed::Buckets(vec![Bucket::Other]),
    }
}

impl Monitors {
    fn handle(&mut self, command: Command) {
        match command {
            Command::Connect(conn, link) => self.connect(conn, link),
            Command::Disconnect(conn) => self.disconnect(conn),
            Command::Subscribe {
                conn,
                sub,
                filters,
                installed,
            } => {
                self.subscribe(conn, sub, filters);
                let _ = installed.send(());
            }
            Command::Unsubscribe(conn, sub) => self.unsubscribe(conn, &sub),
            Command::Events(events) => {
                for live in events.iter() {
                    let view = EventView::new(&live.record).expect("an encoded record");
                    self.broadcast(&view, live.seq, &live.json);
                }
            }
        }
    }

    fn connect(&mut self, conn: ConnId, link: Link) {
        let subs = HashMap::new();
        self.conns.insert(conn, Connection { link, subs });
    }

    fn disconnect(&mut self, conn: ConnId) {
        if let Some(connection) = self.conns.remove(&conn) {
            for keys in connection.subs.into_values() {
                self.uninstall(keys);
            }
        }
    }

    /// Open a subscription, replacing any of the same id.
    fn subscribe(&mut self, conn: ConnId, sub: Arc<str>, filters: Vec<Filter>) {
        self.unsubscribe(conn, &sub);
        if !self.conns.contains_key(&conn) {
            return;
        }
        self.next_key += 1;
        let sub_key = self.next_key;
        let mut keys = Vec::new();
        for filter in filters.into_iter().filter(|f| !f.never) {
            self.next_key += 1;
            let key = self.next_key;
            match filed(&filter) {
                Filed::Buckets(buckets) => {
                    for bucket in buckets {
                        self.buckets.entry(bucket).or_default().insert(key);
                    }
                }
                Filed::Tags(tags) => {
                    for tag in tags {
                        self.tags.entry(tag).or_default().insert(key);
                    }
                }
            }
            let installed = Installed {
                sub_key,
                conn,
                sub: sub.clone(),
                filter,
            };
            self.filters.insert(key, installed);
            keys.push(key);
        }
        let connection = self.conns.get_mut(&conn).expect("connected");
        connection.subs.insert(sub, keys);
    }

    fn unsubscribe(&mut self, conn: ConnId, sub: &str) {
        if let Some(keys) = self.conns.get_mut(&conn).and_then(|c| c.subs.remove(sub)) {
            self.uninstall(keys);
        }
    }

    fn uninstall(&mut self, keys: Vec<u64>) {
        for key in keys {
            let Some(installed) = self.filters.remove(&key) else {
                continue;
            };
            match filed(&installed.filter) {
                Filed::Buckets(buckets) => {
                    for bucket in buckets {
                        unfile(&mut self.buckets, bucket, key);
                    }
                }
                Filed::Tags(tags) => {
                    for tag in tags {
                        unfile(&mut self.tags, tag, key);
                    }
                }
            }
        }
    }

    /// Send a new event to every subscription it matches, writing its JSON
    /// into `json` if no one has yet. Returns how many.
    fn broadcast(&self, event: &EventView, seq: Option<u64>, json: &OnceLock<Arc<str>>) -> usize {
        let mut candidates: Vec<u64> = Vec::new();
        let buckets = [
            Bucket::Id(*event.id()),
            Bucket::Author(*event.pubkey()),
            Bucket::Kind(event.kind()),
            Bucket::Other,
        ];
        for bucket in buckets {
            if let Some(set) = self.buckets.get(&bucket) {
                candidates.extend(set);
            }
        }
        if !self.tags.is_empty() {
            let mut value = Vec::new();
            for (name, element) in event.filed_tag_values() {
                if element.encoded_len() > MAX_INDEXED_TAG {
                    continue;
                }
                value.clear();
                element.encode(&mut value);
                if let Some(set) = self.tags.get(&tag_key(name, &value, None)) {
                    candidates.extend(set);
                }
            }
        }
        if candidates.is_empty() {
            return 0;
        }
        candidates.sort_unstable();
        candidates.dedup();

        let mut sent = HashSet::new();
        for key in candidates {
            let Some(installed) = self.filters.get(&key) else {
                continue;
            };
            if sent.contains(&installed.sub_key) || !installed.filter.matches(event) {
                continue;
            }
            let Some(connection) = self.conns.get(&installed.conn) else {
                continue;
            };
            sent.insert(installed.sub_key);
            let json = json.get_or_init(|| event.to_json().into()).clone();
            let sub = installed.sub.clone();
            connection.link.send(Outbound { sub, seq, json });
        }
        sent.len()
    }
}

/// Take `key` out of the set filed under `at`, and the set with it once
/// it's empty.
fn unfile<K: Eq + std::hash::Hash>(index: &mut HashMap<K, HashSet<u64>>, at: K, key: u64) {
    if let Some(set) = index.get_mut(&at) {
        set.remove(&key);
        if set.is_empty() {
            index.remove(&at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::record::encode;
    use crate::store::tests::{MAX_VALUES, test_tags};
    use serde_json::{Value, json};

    fn filters(values: &[Value]) -> Vec<Filter> {
        values
            .iter()
            .map(|v| Filter::parse(v, &test_tags(), MAX_VALUES).unwrap())
            .collect()
    }

    fn deliver(monitors: &Monitors, event: &Event) -> usize {
        let record = encode(event);
        let view = EventView::new(&record).unwrap();
        monitors.broadcast(&view, Some(1), &OnceLock::new())
    }

    fn received(rx: &mut mpsc::Receiver<Outbound>) -> Vec<String> {
        let mut subs = Vec::new();
        while let Ok(outbound) = rx.try_recv() {
            subs.push(outbound.sub.to_string());
        }
        subs
    }

    #[test]
    fn sends_each_subscription_an_event_once() {
        let mut monitors = Monitors::default();
        let (link, mut rx, _) = Link::new(16);
        monitors.connect(1, link);

        let tags = vec![vec!["t", "a"], vec!["t", "b"], vec!["title", "Hi"]];
        let note = signed(1, 100, 1, tags, "");
        let author = &note.pubkey;
        let other = "ab".repeat(32);
        monitors.subscribe(1, "everything".into(), filters(&[json!({})]));
        let twice = [json!({"#t": ["a", "b"]}), json!({"authors": [author]})];
        monitors.subscribe(1, "twice".into(), filters(&twice));
        let kinds = [json!({"kinds": [1], "since": 50})];
        monitors.subscribe(1, "kinds".into(), filters(&kinds));
        let titled = [json!({"#title": ["Hi"], "#t": ["a", "c", "d"]})];
        monitors.subscribe(1, "titled".into(), filters(&titled));
        let others = [json!({"kinds": [7]}), json!({"ids": [other]})];
        monitors.subscribe(1, "other".into(), filters(&others));
        monitors.subscribe(1, "never".into(), filters(&[json!({"authors": []})]));

        assert_eq!(deliver(&monitors, &note), 4);
        let mut subs = received(&mut rx);
        subs.sort();
        assert_eq!(subs, ["everything", "kinds", "titled", "twice"]);

        // Closing and replacing take effect.
        monitors.unsubscribe(1, "everything");
        let later = [json!({"kinds": [1], "since": 500})];
        monitors.subscribe(1, "kinds".into(), filters(&later));
        monitors.unsubscribe(1, "titled");
        assert_eq!(deliver(&monitors, &note), 1);
        assert_eq!(received(&mut rx), ["twice"]);
        assert_eq!(monitors.conns[&1].subs.len(), 4);

        monitors.disconnect(1);
        assert_eq!(deliver(&monitors, &signed(2, 100, 7, vec![], "")), 0);
        assert!(monitors.filters.is_empty());
        assert!(monitors.buckets.is_empty() && monitors.tags.is_empty());
    }

    #[test]
    fn matches_search_text() {
        let mut monitors = Monitors::default();
        let (link, mut rx, _) = Link::new(16);
        monitors.connect(1, link);
        let search = [json!({"kinds": [1], "search": "hello"})];
        monitors.subscribe(1, "s".into(), filters(&search));
        assert_eq!(deliver(&monitors, &signed(1, 100, 1, vec![], "goodbye")), 0);
        assert_eq!(deliver(&monitors, &signed(1, 100, 1, vec![], "Hello!")), 1);
        assert_eq!(received(&mut rx), ["s"]);
    }

    #[tokio::test]
    async fn routes_through_shards() {
        let hub = Hub::spawn(2);
        let mut receivers = Vec::new();
        for conn in 1..=3 {
            let (link, rx, _) = Link::new(16);
            hub.connect(conn, link).await;
            let kinds = filters(&[json!({"kinds": [1]})]);
            hub.subscribe(conn, "s".into(), kinds).await.await.unwrap();
            receivers.push(rx);
        }
        hub.unsubscribe(3, "s").await;

        let note = signed(1, 100, 1, vec![], "");
        let reaction = signed(2, 100, 7, vec![], "");
        let events = vec![
            Live::new(Arc::new(encode(&note)), Some(1)),
            Live::new(Arc::new(encode(&reaction)), Some(2)),
        ];
        let broadcaster = hub.clone();
        tokio::task::spawn_blocking(move || broadcaster.broadcast(events))
            .await
            .unwrap();

        for rx in &mut receivers[..2] {
            let outbound = rx.recv().await.unwrap();
            assert_eq!((&*outbound.sub, outbound.seq), ("s", Some(1)));
            assert_eq!(serde_json::from_str::<Event>(&outbound.json).unwrap(), note);
        }
        // Once the shards have caught up, nothing else came.
        for conn in 1..=3 {
            hub.subscribe(conn, "sync".into(), vec![])
                .await
                .await
                .unwrap();
        }
        assert!(receivers.iter_mut().all(|rx| rx.try_recv().is_err()));
    }

    #[test]
    fn signals_a_connection_that_falls_behind() {
        let mut monitors = Monitors::default();
        let (link, _rx, overflow) = Link::new(1);
        monitors.connect(1, link);
        monitors.subscribe(1, "s".into(), filters(&[json!({})]));
        deliver(&monitors, &signed(1, 1, 1, vec![], ""));
        assert!(!overflow.is_cancelled());
        deliver(&monitors, &signed(1, 2, 1, vec![], ""));
        assert!(overflow.is_cancelled());
    }
}
