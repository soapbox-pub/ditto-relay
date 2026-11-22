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
//! The matching runs on a few shard threads, each with the subscriptions
//! of its share of the connections, so the writer only queues a batch and
//! gets on with the next commit. A connection opens and closes its
//! subscriptions itself, under the shard's lock, rather than queueing that
//! for the shard's thread and waiting on it: a REQ needs its subscription
//! live before its query reads the store, and handing that to another
//! thread and back cost more than the rest of a small query.

use std::collections::{HashMap, HashSet};

use smallvec::SmallVec;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tokio::sync::mpsc;

use crate::auth::Viewer;
use crate::filter::Filter;
use crate::metrics::METRICS;
use crate::record::EventView;
use crate::store::{MAX_INDEXED_TAG, tag_key};

use super::queue::Queue;
use super::ws::Direct;

pub type ConnId = u64;

/// A new event for one of a connection's subscriptions.
#[derive(Debug)]
pub struct Outbound {
    pub sub: Arc<str>,
    /// Its sequence number, if it was stored (ephemeral events aren't).
    pub seq: Option<u64>,
    pub json: Arc<String>,
}

/// The way to a connection. Its queue is bounded: a connection that falls
/// so far behind that it fills up is told to go, rather than buffering
/// without end.
///
/// With a [`Direct`] way to its client too, an event for a subscription
/// that's [live](Hub::go_live) is sent from the shard's thread, rather
/// than handed to the connection's task to send, as long as nothing else
/// is in its queue: waking the tasks of all those an event goes to, one
/// after another, took longer than sending it.
#[derive(Clone)]
pub struct Link {
    queue: Arc<Queue<Outbound>>,
    capacity: usize,
    direct: Option<Direct>,
}

impl Link {
    /// With the queue the connection reads, whose end says it fell behind.
    pub fn new(capacity: usize, direct: Option<Direct>) -> (Link, Arc<Queue<Outbound>>) {
        let queue = Queue::new();
        let link = Link {
            queue: queue.clone(),
            capacity,
            direct,
        };
        (link, queue)
    }

    fn send(&self, installed: &Installed, seq: Option<u64>, json: &Arc<String>) {
        if let (Some(floor), Some(direct)) = (installed.live, &self.direct)
            && self.queue.all_handled()
        {
            // Stored events its query could see were sent with it.
            if seq.is_none_or(|seq| seq >= floor) && !direct.event(&installed.quoted, json) {
                self.queue.overflow();
            }
            return;
        }
        let sub = installed.sub.clone();
        let json = json.clone();
        self.queue
            .push_within(Outbound { sub, seq, json }, self.capacity);
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
    json: OnceLock<Arc<String>>,
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

/// One shard: its connections' subscriptions, and the queue of new events
/// its thread matches against them.
struct Shard {
    events: mpsc::Sender<Arc<Vec<Live>>>,
    monitors: Arc<Mutex<Monitors>>,
}

/// The way to the shards. A connection always goes to the same one.
#[derive(Clone)]
pub struct Hub {
    shards: Arc<[Shard]>,
}

impl Hub {
    /// Start `shards` threads. They run until every `Hub` is dropped.
    pub fn spawn(shards: usize) -> Hub {
        let shards = (0..shards.max(1))
            .map(|i| {
                let (events, mut rx) = mpsc::channel::<Arc<Vec<Live>>>(SHARD_QUEUE);
                let monitors = Arc::new(Mutex::new(Monitors::default()));
                let theirs = monitors.clone();
                std::thread::Builder::new()
                    .name(format!("live-{i}"))
                    .spawn(move || {
                        while let Some(events) = rx.blocking_recv() {
                            METRICS.live_queue.dec();
                            for live in events.iter() {
                                let view = EventView::new(&live.record).expect("an encoded record");
                                // A lock per event, so a subscription
                                // waits on one event's matching at most.
                                lock(&theirs).broadcast(&view, live.seq, &live.json);
                            }
                        }
                    })
                    .expect("failed to spawn a live subscription thread");
                Shard { events, monitors }
            })
            .collect();
        Hub { shards }
    }

    fn monitors(&self, conn: ConnId) -> MutexGuard<'_, Monitors> {
        lock(&self.shards[(conn % self.shards.len() as u64) as usize].monitors)
    }

    pub fn connect(&self, conn: ConnId, link: Link) {
        self.monitors(conn).connect(conn, link);
    }

    pub fn disconnect(&self, conn: ConnId) {
        self.monitors(conn).disconnect(conn);
    }

    /// Open a subscription, replacing any of the same id, for a connection
    /// that may see only what `viewer` lets it, if there's one. It's live
    /// once this returns: every event published after that reaches it.
    pub fn subscribe(
        &self,
        conn: ConnId,
        sub: Arc<str>,
        filters: Vec<Filter>,
        viewer: Option<Viewer>,
    ) {
        self.monitors(conn).subscribe(conn, sub, filters, viewer);
    }

    pub fn unsubscribe(&self, conn: ConnId, sub: &str) {
        self.monitors(conn).unsubscribe(conn, sub);
    }

    /// Note that a subscription's query's results are sent, those stored
    /// from `floor` on not among them: what comes for it next may be sent
    /// [directly](Link).
    pub fn go_live(&self, conn: ConnId, sub: &Arc<str>, floor: u64) {
        self.monitors(conn).go_live(conn, sub, floor);
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
            if shard.events.blocking_send(events.clone()).is_err() {
                METRICS.live_queue.dec();
            }
        }
    }

    /// [`Hub::broadcast`], from async code.
    pub async fn publish(&self, events: Vec<Live>) {
        let events = Arc::new(events);
        for shard in self.shards.iter() {
            METRICS.live_queue.inc();
            if shard.events.send(events.clone()).await.is_err() {
                METRICS.live_queue.dec();
            }
        }
    }
}

/// A shard's subscriptions, locked. Nothing panics holding the lock but a
/// bug, and the subscriptions are still whole after one, so a poisoned lock
/// is taken anyway.
fn lock(monitors: &Mutex<Monitors>) -> MutexGuard<'_, Monitors> {
    monitors
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Installed {
    /// Unique to the subscription, so an event matching several of its
    /// filters is sent once.
    sub_key: u64,
    conn: ConnId,
    sub: Arc<str>,
    /// `sub`, as JSON.
    quoted: Arc<str>,
    filter: Filter,
    viewer: Option<Viewer>,
    /// Once its query's results are sent, the sequence number from which
    /// stored events weren't among them.
    live: Option<u64>,
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
    buckets: Index<Bucket>,
    /// Keyed by [`tag_key`] without a kind.
    tags: Index<Vec<u8>>,
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
    fn subscribe(
        &mut self,
        conn: ConnId,
        sub: Arc<str>,
        filters: Vec<Filter>,
        viewer: Option<Viewer>,
    ) {
        self.unsubscribe(conn, &sub);
        if !self.conns.contains_key(&conn) {
            return;
        }
        self.next_key += 1;
        let sub_key = self.next_key;
        let quoted: Arc<str> = super::quoted(&sub).into();
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
                quoted: quoted.clone(),
                filter,
                viewer: viewer.clone(),
                live: None,
            };
            self.filters.insert(key, installed);
            keys.push(key);
        }
        let connection = self.conns.get_mut(&conn).expect("connected");
        connection.subs.insert(sub, keys);
    }

    /// Note that `sub`'s query's results are sent, those from `floor` on
    /// not among them, if it's still open.
    fn go_live(&mut self, conn: ConnId, sub: &Arc<str>, floor: u64) {
        let Some(keys) = self.conns.get(&conn).and_then(|c| c.subs.get(sub)) else {
            return;
        };
        for key in keys {
            if let Some(installed) = self.filters.get_mut(key)
                && Arc::ptr_eq(&installed.sub, sub)
            {
                installed.live = Some(floor);
            }
        }
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
    fn broadcast(
        &self,
        event: &EventView,
        seq: Option<u64>,
        json: &OnceLock<Arc<String>>,
    ) -> usize {
        let mut candidates: Vec<u64> = Vec::new();
        let buckets = [
            Bucket::Id(*event.id()),
            Bucket::Author(*event.pubkey()),
            Bucket::Kind(event.kind()),
            Bucket::Other,
        ];
        for bucket in buckets {
            if let Some(keys) = self.buckets.get(&bucket) {
                keys.extend_into(&mut candidates);
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
                if let Some(keys) = self.tags.get(&tag_key(name, &value, None)) {
                    keys.extend_into(&mut candidates);
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
            if sent.contains(&installed.sub_key)
                || !installed.filter.matches(event)
                || installed.viewer.as_ref().is_some_and(|v| !v.may_see(event))
            {
                continue;
            }
            let Some(connection) = self.conns.get(&installed.conn) else {
                continue;
            };
            sent.insert(installed.sub_key);
            let json = json.get_or_init(|| event.to_json().into());
            connection.link.send(installed, seq, json);
        }
        sent.len()
    }
}

/// Filters' keys, by where they're filed. A REQ for many ids or authors
/// files under each, and most are filed under alone: a few are kept in a
/// list, as many in a set.
type Index<K> = HashMap<K, Keys, foldhash::fast::RandomState>;

enum Keys {
    Few(SmallVec<[u64; 2]>),
    Many(HashSet<u64, foldhash::fast::RandomState>),
}

/// The most keys kept in a list.
const FEW: usize = 16;

impl Default for Keys {
    fn default() -> Self {
        Keys::Few(SmallVec::new())
    }
}

impl Keys {
    fn insert(&mut self, key: u64) {
        match self {
            Keys::Few(few) if few.contains(&key) => {}
            Keys::Few(few) if few.len() < FEW => few.push(key),
            Keys::Few(few) => {
                let mut many: HashSet<u64, _> = few.drain(..).collect();
                many.insert(key);
                *self = Keys::Many(many);
            }
            Keys::Many(many) => {
                many.insert(key);
            }
        }
    }

    fn remove(&mut self, key: u64) {
        match self {
            Keys::Few(few) => few.retain(|k| *k != key),
            Keys::Many(many) => {
                many.remove(&key);
            }
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Keys::Few(few) => few.is_empty(),
            Keys::Many(many) => many.is_empty(),
        }
    }

    fn extend_into(&self, out: &mut Vec<u64>) {
        match self {
            Keys::Few(few) => out.extend_from_slice(few),
            Keys::Many(many) => out.extend(many),
        }
    }
}

/// Take `key` out of those filed under `at`, and `at` with it once none
/// are.
fn unfile<K: Eq + std::hash::Hash>(index: &mut Index<K>, at: K, key: u64) {
    if let Some(keys) = index.get_mut(&at) {
        keys.remove(key);
        if keys.is_empty() {
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

    fn received(rx: &mut Arc<Queue<Outbound>>) -> Vec<String> {
        let mut subs = Vec::new();
        while let Some(outbound) = rx.pop() {
            subs.push(outbound.sub.to_string());
        }
        subs
    }

    #[test]
    fn sends_each_subscription_an_event_once() {
        let mut monitors = Monitors::default();
        let (link, mut rx) = Link::new(16, None);
        monitors.connect(1, link);

        let tags = vec![vec!["t", "a"], vec!["t", "b"], vec!["title", "Hi"]];
        let note = signed(1, 100, 1, tags, "");
        let author = &note.pubkey;
        let other = "ab".repeat(32);
        monitors.subscribe(1, "everything".into(), filters(&[json!({})]), None);
        let twice = [json!({"#t": ["a", "b"]}), json!({"authors": [author]})];
        monitors.subscribe(1, "twice".into(), filters(&twice), None);
        let kinds = [json!({"kinds": [1], "since": 50})];
        monitors.subscribe(1, "kinds".into(), filters(&kinds), None);
        let titled = [json!({"#title": ["Hi"], "#t": ["a", "c", "d"]})];
        monitors.subscribe(1, "titled".into(), filters(&titled), None);
        let others = [json!({"kinds": [7]}), json!({"ids": [other]})];
        monitors.subscribe(1, "other".into(), filters(&others), None);
        monitors.subscribe(1, "never".into(), filters(&[json!({"authors": []})]), None);

        assert_eq!(deliver(&monitors, &note), 4);
        let mut subs = received(&mut rx);
        subs.sort();
        assert_eq!(subs, ["everything", "kinds", "titled", "twice"]);

        // Closing and replacing take effect.
        monitors.unsubscribe(1, "everything");
        let later = [json!({"kinds": [1], "since": 500})];
        monitors.subscribe(1, "kinds".into(), filters(&later), None);
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
    fn files_many_subscriptions_under_one_key() {
        let mut monitors = Monitors::default();
        let (link, mut rx) = Link::new(64, None);
        monitors.connect(1, link);
        for n in 0..FEW + 4 {
            let filter = filters(&[json!({"kinds": [1], "since": n})]);
            monitors.subscribe(1, format!("s{n}").into(), filter, None);
        }
        assert_eq!(deliver(&monitors, &signed(1, 100, 1, vec![], "")), FEW + 4);
        assert_eq!(received(&mut rx).len(), FEW + 4);
        for n in 0..FEW + 4 {
            monitors.unsubscribe(1, &format!("s{n}"));
            assert_eq!(
                deliver(&monitors, &signed(1, 100, 1, vec![], "")),
                FEW + 3 - n
            );
        }
        assert!(monitors.buckets.is_empty());
    }

    #[test]
    fn matches_search_text() {
        let mut monitors = Monitors::default();
        let (link, mut rx) = Link::new(16, None);
        monitors.connect(1, link);
        let search = [json!({"kinds": [1], "search": "hello"})];
        monitors.subscribe(1, "s".into(), filters(&search), None);
        assert_eq!(deliver(&monitors, &signed(1, 100, 1, vec![], "goodbye")), 0);
        assert_eq!(deliver(&monitors, &signed(1, 100, 1, vec![], "Hello!")), 1);
        assert_eq!(received(&mut rx), ["s"]);
    }

    #[tokio::test]
    async fn routes_through_shards() {
        let hub = Hub::spawn(2);
        let mut receivers = Vec::new();
        for conn in 1..=3 {
            let (link, rx) = Link::new(16, None);
            hub.connect(conn, link);
            let kinds = filters(&[json!({"kinds": [1]})]);
            hub.subscribe(conn, "s".into(), kinds, None);
            receivers.push(rx);
        }
        hub.unsubscribe(3, "s");

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
            let outbound = rx.next().await.unwrap();
            assert_eq!((&*outbound.sub, outbound.seq), ("s", Some(1)));
            assert_eq!(serde_json::from_str::<Event>(&outbound.json).unwrap(), note);
        }
        // A shard takes events in order, so once a later one has reached
        // every connection, nothing else came before it.
        let marker = signed(3, 100, 9, vec![], "");
        for conn in 1..=3 {
            hub.subscribe(conn, "sync".into(), filters(&[json!({"kinds": [9]})]), None);
        }
        let broadcaster = hub.clone();
        let events = vec![Live::new(Arc::new(encode(&marker)), Some(3))];
        tokio::task::spawn_blocking(move || broadcaster.broadcast(events))
            .await
            .unwrap();
        for rx in &mut receivers {
            assert_eq!(&*rx.next().await.unwrap().sub, "sync");
            assert!(rx.pop().is_none());
        }
    }

    #[tokio::test]
    async fn sends_directly_once_live_and_caught_up() {
        use tokio::io::AsyncReadExt;
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let writer = super::super::ws::Writer::new(Box::new(server));
        let mut monitors = Monitors::default();
        let (link, rx) = Link::new(16, Some(writer.direct()));
        monitors.connect(1, link);
        let sub: Arc<str> = "s".into();
        monitors.subscribe(1, sub.clone(), filters(&[json!({"kinds": [1]})]), None);
        let send = |monitors: &Monitors, n: u64, seq: u64| {
            let record = encode(&signed(1, n, 1, vec![], ""));
            let view = EventView::new(&record).unwrap();
            monitors.broadcast(&view, Some(seq), &OnceLock::new());
        };

        // Not live: queued.
        send(&monitors, 1, 1);
        monitors.go_live(1, &sub, 5);
        // Live, but one's queued yet: queued behind it.
        send(&monitors, 2, 6);
        assert_eq!(rx.pop().map(|o| o.seq), Some(Some(1)));
        rx.handled();
        assert_eq!(rx.pop().map(|o| o.seq), Some(Some(6)));
        rx.handled();
        // Caught up: sent, but for what its query saw.
        send(&monitors, 3, 4);
        send(&monitors, 4, 7);
        assert!(rx.pop().is_none());
        drop(monitors);
        drop(writer);
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        let text = String::from_utf8_lossy(&got[4..]);
        assert_eq!(got[..2], [0x81, 126]);
        assert!(text.starts_with("[\"EVENT\",\"s\",{"), "{text}");
        assert_eq!(text.matches("EVENT").count(), 1);
        assert!(text.contains("\"created_at\":4"), "{text}");
    }

    #[test]
    fn signals_a_connection_that_falls_behind() {
        let mut monitors = Monitors::default();
        let (link, rx) = Link::new(1, None);
        monitors.connect(1, link);
        monitors.subscribe(1, "s".into(), filters(&[json!({})]), None);
        deliver(&monitors, &signed(1, 1, 1, vec![], ""));
        assert!(!rx.state_overflowed());
        deliver(&monitors, &signed(1, 2, 1, vec![], ""));
        assert!(rx.state_overflowed());
    }
}
