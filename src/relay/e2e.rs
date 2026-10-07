//! The relay end to end, over real WebSockets.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::{AppState, router};
use crate::config::Config;
use crate::event::tests::signed;
use crate::event::{self, Event};
use crate::store;

/// How long to wait for a message that should come.
const WAIT: Duration = Duration::from_secs(5);

/// How long to wait to be sure a message won't come.
const QUIET: Duration = Duration::from_millis(200);

fn config() -> Config {
    Config {
        bind: "127.0.0.1:0".into(),
        metrics_bind: None,
        db_path: PathBuf::new(),
        map_size: 1 << 26,
        lmdb_sync: true,
        url: "ws://relay.test".into(),
        public_url: "http://relay.test".into(),
        name: "test".into(),
        description: String::new(),
        pubkey: None,
        contact: None,
        keypair: None,
        trends_interval: 0,
        trends_expiration: 0,
        max_message_size: 1 << 20,
        max_subscriptions: 20,
        max_filters: 100,
        max_subid_length: 100,
        default_limit: 100,
        max_limit: 1000,
        max_filter_values: store::tests::MAX_VALUES,
        max_future_seconds: 900,
        indexed_tags: vec!["title".into()],
        history: true,
        history_excluded_kinds: vec![],
        history_max_versions: 20,
        search: false,
        search_path: PathBuf::new(),
        search_kinds: vec![],
        search_commit_ms: 1000,
        nsfw_hashtags: vec![],
        wot_seeds: vec![],
        wot_damping: 0.85,
        wot_full_trust: 100_000,
        wot_min_weight: 0.01,
        wot_budget: 10_000,
        hot_half_life: 86_400,
        rank_step: 0.05,
        write_policy_plugin: None,
        write_policy_timeout_seconds: 10,
        real_ip_header: None,
    }
}

/// A relay serving a fresh store on a free port.
struct Relay {
    addr: SocketAddr,
    state: AppState,
    _dir: tempfile::TempDir,
}

impl Relay {
    async fn start() -> Relay {
        let (dir, store) = store::tests::open();
        let state = AppState::new(config(), Arc::new(store), None);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        Relay {
            addr,
            state,
            _dir: dir,
        }
    }

    async fn connect(&self) -> Client {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{}", self.addr))
            .await
            .unwrap();
        Client { ws }
    }
}

struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl Client {
    async fn send(&mut self, msg: Value) {
        self.ws.send(Message::text(msg.to_string())).await.unwrap();
    }

    /// The next message, or None if the relay sends nothing for `within`.
    async fn next_within(&mut self, within: Duration) -> Option<Value> {
        loop {
            let msg = tokio::time::timeout(within, self.ws.next()).await.ok()?;
            match msg.expect("connection open").unwrap() {
                Message::Text(text) => return Some(serde_json::from_str(&text).unwrap()),
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("unexpected message {other:?}"),
            }
        }
    }

    async fn next(&mut self) -> Value {
        self.next_within(WAIT).await.expect("a message")
    }

    async fn quiet(&mut self) {
        if let Some(msg) = self.next_within(QUIET).await {
            panic!("unexpected message {msg}");
        }
    }

    /// Publishes an event and returns its OK's status and message.
    async fn publish(&mut self, ev: &Event) -> (bool, String) {
        self.send(json!(["EVENT", ev])).await;
        let ok = self.next().await;
        assert_eq!(ok[0], "OK", "{ok}");
        assert_eq!(ok[1], ev.id.as_str());
        (
            ok[2].as_bool().unwrap(),
            ok[3].as_str().unwrap().to_string(),
        )
    }

    /// Sends a REQ and returns the ids of the events up to its EOSE.
    async fn req(&mut self, sub: &str, filters: &[Value]) -> Vec<String> {
        let mut msg = vec![json!("REQ"), json!(sub)];
        msg.extend(filters.iter().cloned());
        self.send(Value::Array(msg)).await;
        let mut ids = vec![];
        loop {
            let msg = self.next().await;
            match msg[0].as_str() {
                Some("EVENT") if msg[1] == sub => ids.push(msg[2]["id"].as_str().unwrap().into()),
                Some("EOSE") if msg[1] == sub => return ids,
                _ => panic!("unexpected message {msg}"),
            }
        }
    }

    /// The id of the next event sent to `sub`.
    async fn event(&mut self, sub: &str) -> String {
        let msg = self.next().await;
        assert_eq!(msg[0], "EVENT", "{msg}");
        assert_eq!(msg[1], sub, "{msg}");
        msg[2]["id"].as_str().unwrap().into()
    }
}

fn note(seed: u8, content: &str) -> Event {
    signed(seed, event::now().into(), 1, vec![], content)
}

#[tokio::test]
async fn stores_and_finds_events() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    let ev = note(1, "hello");
    assert_eq!(client.publish(&ev).await, (true, String::new()));
    let (accepted, msg) = client.publish(&ev).await;
    assert!(accepted && msg.starts_with("duplicate:"), "{msg}");

    assert_eq!(
        client.req("a", &[json!({"kinds": [1]})]).await,
        std::slice::from_ref(&ev.id)
    );
    assert_eq!(
        client.req("b", &[json!({"kinds": [7]})]).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn takes_messages_bigger_than_its_read_buffer() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    let big = note(1, &"long post ".repeat(10 * super::READ_BUFFER / 8));
    assert_eq!(client.publish(&big).await, (true, String::new()));
    // And one small after, from what's left in the buffer.
    let small = note(2, "short");
    assert_eq!(client.publish(&small).await, (true, String::new()));
    assert_eq!(client.req("a", &[json!({"kinds": [1]})]).await.len(), 2);
}

#[tokio::test]
async fn refuses_bad_signatures() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    let mut ev = note(1, "hello");
    ev.content = "tampered".into();
    let (accepted, msg) = client.publish(&ev).await;
    assert!(!accepted && msg.starts_with("invalid:"), "{msg}");
}

#[tokio::test]
async fn checks_the_signatures_of_stored_ids() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    let ev = note(1, "hello");
    client.publish(&ev).await;
    // Another event's signature, which finds the stored event but isn't
    // its own.
    let mut forged = ev.clone();
    forged.sig = note(1, "other").sig;
    let (accepted, msg) = client.publish(&forged).await;
    assert!(!accepted && msg.starts_with("invalid:"), "{msg}");
    forged.sig = "zz".into();
    let (accepted, msg) = client.publish(&forged).await;
    assert!(!accepted && msg.starts_with("invalid:"), "{msg}");
}

#[tokio::test]
async fn sends_new_events_to_subscriptions() {
    let relay = Relay::start().await;
    let mut reader = relay.connect().await;
    let mut writer = relay.connect().await;
    assert!(
        reader
            .req("notes", &[json!({"kinds": [1]})])
            .await
            .is_empty()
    );

    let ev = note(1, "live");
    writer.publish(&ev).await;
    assert_eq!(reader.event("notes").await, ev.id);
    // Not matching.
    writer
        .publish(&signed(1, event::now().into(), 7, vec![], "+"))
        .await;
    reader.quiet().await;
}

#[tokio::test]
async fn sends_ephemeral_events_without_storing_them() {
    let relay = Relay::start().await;
    let mut reader = relay.connect().await;
    let mut writer = relay.connect().await;
    reader.req("e", &[json!({"kinds": [20001]})]).await;
    let ev = signed(1, event::now().into(), 20001, vec![], "");
    assert!(writer.publish(&ev).await.0);
    assert_eq!(reader.event("e").await, ev.id);
    assert!(
        writer
            .req("q", &[json!({"kinds": [20001]})])
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn closed_and_replaced_subscriptions_stop() {
    let relay = Relay::start().await;
    let mut reader = relay.connect().await;
    let mut writer = relay.connect().await;
    reader.req("s", &[json!({"kinds": [1]})]).await;
    // Replacing it with another filter.
    reader.req("s", &[json!({"kinds": [7]})]).await;
    writer.publish(&note(1, "not wanted")).await;
    reader.quiet().await;
    let reaction = signed(1, event::now().into(), 7, vec![], "+");
    writer.publish(&reaction).await;
    assert_eq!(reader.event("s").await, reaction.id);

    reader.send(json!(["CLOSE", "s"])).await;
    writer
        .publish(&signed(2, event::now().into(), 7, vec![], "+"))
        .await;
    reader.quiet().await;
}

#[tokio::test]
async fn sends_each_event_once() {
    let relay = Relay::start().await;
    let mut reader = relay.connect().await;
    let mut writer = relay.connect().await;
    let ev = note(1, "both");
    let author = ev.pubkey.clone();
    reader
        .req("s", &[json!({"kinds": [1]}), json!({"authors": [author]})])
        .await;
    writer.publish(&ev).await;
    assert_eq!(reader.event("s").await, ev.id);
    reader.quiet().await;
}

#[tokio::test]
async fn answers_every_req_sent_at_once() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    let notes: Vec<Event> = (1..=10).map(|seed| note(seed, "n")).collect();
    for ev in &notes {
        client.publish(ev).await;
    }
    for (i, ev) in notes.iter().enumerate() {
        let sub = format!("s{i}");
        client
            .send(json!(["REQ", sub, {"authors": [ev.pubkey]}]))
            .await;
    }
    client.send(json!(["COUNT", "c", {"kinds": [1]}])).await;

    let mut found = std::collections::HashMap::new();
    let mut ended = 0;
    let mut counted = false;
    while ended < notes.len() || !counted {
        let msg = client.next().await;
        match msg[0].as_str().unwrap() {
            "EVENT" => {
                let sub = msg[1].as_str().unwrap().to_string();
                assert!(found.insert(sub, msg[2]["id"].clone()).is_none());
            }
            "EOSE" => ended += 1,
            "COUNT" => {
                assert_eq!(msg[2]["count"], notes.len());
                counted = true;
            }
            _ => panic!("unexpected message {msg}"),
        }
    }
    for (i, ev) in notes.iter().enumerate() {
        assert_eq!(found[&format!("s{i}")], ev.id.as_str());
    }
}

/// An event stored while a REQ's query waits to run is sent once: with
/// the stored results, which see it, and not again as a live event.
#[tokio::test]
async fn sends_events_stored_while_a_query_waits_once() {
    let relay = Relay::start().await;
    let mut reader = relay.connect().await;
    let mut writer = relay.connect().await;
    // Every core busy, so the REQ's query waits its turn.
    let queries = relay.state.queries.clone();
    let busy = queries.acquire_many(super::cores() as u32).await.unwrap();
    reader.send(json!(["REQ", "s", {"kinds": [1]}])).await;
    // Live by now.
    tokio::time::sleep(QUIET).await;
    let waited = note(1, "stored while the query waited");
    writer.publish(&waited).await;
    drop(busy);

    assert_eq!(reader.event("s").await, waited.id);
    let eose = reader.next().await;
    assert_eq!(eose[0], "EOSE", "{eose}");
    reader.quiet().await;
    let after = note(2, "after");
    writer.publish(&after).await;
    assert_eq!(reader.event("s").await, after.id);
    reader.quiet().await;
}

#[tokio::test]
async fn closes_the_subscription_a_bad_req_would_replace() {
    let relay = Relay::start().await;
    let mut reader = relay.connect().await;
    let mut writer = relay.connect().await;
    reader.req("s", &[json!({"kinds": [1]})]).await;
    reader
        .send(json!(["REQ", "s", {"#unindexed": ["x"]}]))
        .await;
    let closed = reader.next().await;
    assert_eq!(closed[0], "CLOSED", "{closed}");
    writer.publish(&note(1, "after")).await;
    reader.quiet().await;
}

#[tokio::test]
async fn sends_what_the_relay_publishes_itself() {
    let relay = Relay::start().await;
    let mut reader = relay.connect().await;
    reader.req("s", &[json!({"kinds": [1]})]).await;
    let ev = note(3, "from within");
    relay.state.publish(ev.clone()).await.unwrap();
    assert_eq!(reader.event("s").await, ev.id);
}

#[tokio::test]
async fn shuts_down_cleanly() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    let ev = note(1, "before");
    client.publish(&ev).await;
    relay.state.shut_down().await;

    // Closed.
    let closed = tokio::time::timeout(WAIT, client.ws.next()).await.unwrap();
    assert!(
        matches!(closed, None | Some(Ok(Message::Close(_))) | Some(Err(_))),
        "{closed:?}"
    );
    // Stored, and the writer is gone.
    let txn = relay.state.store.read().unwrap();
    let id = event::decode_hex(&ev.id).unwrap();
    assert!(relay.state.store.contains(&txn, &id).unwrap());
    let record = Arc::new(crate::record::encode(&note(2, "after")));
    assert!(relay.state.writer.write(record).await.is_err());
}

#[tokio::test]
async fn counts() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    for seed in 1..=3 {
        client.publish(&note(seed, "n")).await;
    }
    client.send(json!(["COUNT", "c", {"kinds": [1]}])).await;
    let msg = client.next().await;
    assert_eq!(msg[0], "COUNT");
    assert_eq!(msg[2]["count"], 3);
}
