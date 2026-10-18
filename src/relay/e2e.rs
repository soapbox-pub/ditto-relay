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

use super::{AppState, onion_router, router};
use crate::config::{Config, Image};
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
        url: "ws://relay.test".into(),
        public_url: "http://relay.test".into(),
        name: "test".into(),
        description: String::new(),
        pubkey: None,
        contact: None,
        software: Some(crate::landing::REPOSITORY.into()),
        icon: Image::Builtin,
        banner: Image::Builtin,
        secret_key_file: PathBuf::new(),
        nip85: true,
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
        auth_kinds: vec![],
        search: false,
        search_path: PathBuf::new(),
        search_excluded_kinds: vec![],
        search_commit_ms: 1000,
        nsfw_hashtags: vec![],
        negentropy: true,
        negentropy_max_events: 1000,
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
        log: String::new(),
        tls: None,
        tor: None,
    }
}

/// A relay serving a fresh store on a free port.
struct Relay {
    addr: SocketAddr,
    /// Where the relay's onion router is served, if it's an onion service.
    onion: Option<SocketAddr>,
    state: AppState,
    _dir: tempfile::TempDir,
}

impl Relay {
    async fn start() -> Relay {
        Relay::start_with(config()).await
    }

    async fn start_with(config: Config) -> Relay {
        Relay::start_onion(config, None).await
    }

    /// With `onion`, an onion service at that URL too, whose router is served
    /// on a port of its own, as it would be on Tor's streams.
    async fn start_onion(config: Config, onion: Option<&str>) -> Relay {
        let (dir, store) = store::tests::open();
        let keypair = secp256k1::Keypair::from_secret_bytes([1; 32]).unwrap();
        let state = AppState::new(
            config,
            keypair,
            Arc::new(store),
            None,
            onion.map(String::from),
        );
        let onion = match onion {
            Some(_) => {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let app = onion_router(state.clone());
                tokio::spawn(async move { axum::serve(listener, app).await });
                Some(addr)
            }
            None => None,
        };
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
            onion,
            state,
            _dir: dir,
        }
    }

    async fn connect(&self) -> Client {
        Client::connect(self.addr).await
    }
}

/// What a GET of `/` at `addr` that accepts `accept` is answered with: its
/// head, lowercased, and its body.
async fn get(addr: SocketAddr, accept: &str) -> (String, String) {
    request(addr, "GET", accept).await
}

async fn request(addr: SocketAddr, method: &str, accept: &str) -> (String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request =
        format!("{method} / HTTP/1.1\r\nHost: x\r\nAccept: {accept}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.to_ascii_lowercase(), body.into())
}

struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Client {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        Client { ws }
    }

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
async fn serves_wss() {
    use crate::tls::tests::{connect, issue, listener, trusting};
    use axum::serve::ListenerExt;
    let (_dir, store) = store::tests::open();
    let keypair = secp256k1::Keypair::from_secret_bytes([1; 32]).unwrap();
    let state = AppState::new(config(), keypair, Arc::new(store), None, None);
    let issued = issue(None);
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = listener(&issued, tcp).tap_io(|_| {});
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let stream = connect(addr, trusting(&issued.ca, &[b"http/1.1"])).await;
    let (mut ws, _) = tokio_tungstenite::client_async("wss://localhost/", stream)
        .await
        .unwrap();
    let ev = note(1, "hello");
    ws.send(Message::text(json!(["EVENT", ev]).to_string()))
        .await
        .unwrap();
    let ok = tokio::time::timeout(WAIT, ws.next()).await.unwrap();
    let ok: Value = serde_json::from_str(&ok.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(ok, json!(["OK", ev.id, true, ""]));
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

/// The pubkey `seed` signs as, in hex.
fn pubkey(seed: u8) -> String {
    signed(seed, 0, 1, vec![], "").pubkey
}

#[tokio::test]
async fn reads_are_open_without_auth_kinds() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    let dm = signed(1, event::now().into(), 4, vec![vec!["p", &pubkey(2)]], "");
    client.publish(&dm).await;
    assert_eq!(
        client.req("dms", &[json!({"kinds": [4]})]).await,
        [dm.id.as_str()]
    );
    assert_eq!(client.req("all", &[json!({})]).await, [dm.id.as_str()]);
}

#[tokio::test]
async fn keeps_auth_kinds_to_their_parties() {
    let relay = Relay::start_with(Config {
        auth_kinds: vec![4],
        ..config()
    })
    .await;
    let mut writer = relay.connect().await;
    let mut reader = relay.connect().await;
    let now = u64::from(event::now());
    let dm = signed(1, now - 10, 4, vec![vec!["p", &pubkey(2)]], "");
    let ev = note(1, "public");
    writer.publish(&dm).await;
    writer.publish(&ev).await;

    // Hidden from filters that don't name kinds, live too.
    assert_eq!(reader.req("all", &[json!({})]).await, [ev.id.as_str()]);
    let later = signed(1, now - 5, 4, vec![vec!["p", &pubkey(2)]], "");
    writer.publish(&later).await;
    reader.quiet().await;
    reader.send(json!(["CLOSE", "all"])).await;

    // Named, they need their parties authenticated: the first refusal
    // comes with a challenge.
    reader
        .send(json!(["REQ", "dms", {"kinds": [4], "#p": [pubkey(2)]}]))
        .await;
    let challenge = reader.next().await;
    assert_eq!(challenge[0], "AUTH", "{challenge}");
    let closed = reader.next().await;
    assert_eq!(closed[0], "CLOSED", "{closed}");
    assert!(
        closed[2].as_str().unwrap().starts_with("auth-required:"),
        "{closed}"
    );
    // Looked up by id, and counted or synced.
    reader.send(json!(["REQ", "id", {"ids": [dm.id]}])).await;
    let closed = reader.next().await;
    assert_eq!(closed[0], "CLOSED", "{closed}");
    reader.send(json!(["COUNT", "c", {"ids": [dm.id]}])).await;
    assert_eq!(reader.next().await[0], "CLOSED");
    reader
        .send(json!(["NEG-OPEN", "s", {"kinds": [4]}, "61"]))
        .await;
    let err = reader.next().await;
    assert_eq!(err[0], "NEG-ERR", "{err}");
    assert!(
        err[2].as_str().unwrap().starts_with("auth-required:"),
        "{err}"
    );
    assert_eq!(
        reader.req("note", &[json!({"ids": [ev.id]})]).await,
        [ev.id.as_str()]
    );

    let auth = signed(
        2,
        event::now().into(),
        crate::auth::AUTH,
        vec![
            vec!["challenge", challenge[1].as_str().unwrap()],
            vec!["relay", "ws://relay.test"],
        ],
        "",
    );
    reader.send(json!(["AUTH", auth])).await;
    assert_eq!(reader.next().await, json!(["OK", auth.id, true, ""]));
    let dms = reader
        .req("dms", &[json!({"kinds": [4], "#p": [pubkey(2)]})])
        .await;
    assert_eq!(dms, [later.id.as_str(), dm.id.as_str()]);
    assert_eq!(
        reader.req("id", &[json!({"ids": [dm.id]})]).await,
        [dm.id.as_str()]
    );
    // Others' still aren't.
    let other = signed(1, event::now().into(), 4, vec![vec!["p", &pubkey(3)]], "");
    writer.publish(&other).await;
    reader.send(json!(["REQ", "id", {"ids": [other.id]}])).await;
    let closed = reader.next().await;
    assert_eq!(closed[0], "CLOSED", "{closed}");
    assert!(
        closed[2].as_str().unwrap().starts_with("restricted:"),
        "{closed}"
    );
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

#[tokio::test]
async fn answers_queries_while_its_events_are_stored() {
    // A write policy that takes its time, as a busy writer does.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slow.sh");
    let body = r#"#!/bin/sh
while read -r line; do
  id=$(echo "$line" | sed 's/.*"id":"\([0-9a-f]*\)".*/\1/')
  sleep 1
  echo "{\"id\":\"$id\",\"action\":\"accept\"}"
done
"#;
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let relay = Relay::start_with(Config {
        write_policy_plugin: Some(path.display().to_string()),
        ..config()
    })
    .await;
    let mut client = relay.connect().await;

    let ev = note(1, "slow");
    client.send(json!(["EVENT", ev])).await;
    // Answered while the event is still being judged.
    assert_eq!(
        client.req("a", &[json!({"kinds": [7]})]).await,
        Vec::<String>::new()
    );
    let ok = client.next().await;
    assert_eq!(ok, json!(["OK", ev.id, true, ""]));
}

#[tokio::test]
async fn nip85_can_be_turned_off() {
    for nip85 in [true, false] {
        let relay = Relay::start_with(Config { nip85, ..config() }).await;
        let mut client = relay.connect().await;
        let ev = note(2, "hello");
        client.publish(&ev).await;
        let relay_pubkey = crate::key::pubkey(&relay.state.keypair);
        let filter = json!({"kinds": [30382], "authors": [relay_pubkey], "#d": [ev.pubkey]});
        let found = client.req("a", &[filter]).await;
        assert_eq!(found.len(), usize::from(nip85), "nip85 = {nip85}");

        // The key is the relay's all the same.
        let (_, body) = get(relay.addr, "application/nostr+json").await;
        let info: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(info["self"], relay_pubkey);
    }
}

#[tokio::test]
async fn nip11_links_the_configured_images() {
    let relay = Relay::start().await;
    let (head, body) = get(relay.addr, "application/nostr+json").await;
    let info: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["software"], crate::landing::REPOSITORY);
    assert_eq!(info["banner"], "http://relay.test/banner.jpg");
    let (preflight, _) = request(relay.addr, "OPTIONS", "*/*").await;
    for head in [head, preflight] {
        assert!(head.starts_with("http/1.1 200"), "{head}");
        for cors in [
            "access-control-allow-origin: *",
            "access-control-allow-headers: *",
            "access-control-allow-methods: get, options",
        ] {
            assert!(head.contains(cors), "{head}");
        }
    }

    let relay = Relay::start_with(Config {
        software: None,
        icon: Image::Url("https://img.example/i.png".into()),
        banner: Image::None,
        ..config()
    })
    .await;
    let (_, body) = get(relay.addr, "application/nostr+json").await;
    let info: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["icon"], "https://img.example/i.png");
    assert!(info.get("banner").is_none() && info.get("software").is_none());
    let (_, body) = get(relay.addr, "text/html").await;
    assert!(body.contains("https://img.example/i.png"), "{body}");
}

/// An onion service's clients are told the onion, and may authenticate
/// with it, while clearnet's are told where to find it.
#[tokio::test]
async fn serves_the_onion_as_the_onion() {
    let dir = tempfile::tempdir().unwrap();
    let tor = crate::config::Tor {
        dir: dir.path().into(),
        key_file: dir.path().join("key"),
        port: 80,
        onion_location: true,
        client: crate::tor::client_config(dir.path(), Default::default()).unwrap(),
        service: crate::tor::service_config(Default::default()).unwrap(),
        arti_table: Default::default(),
        service_table: Default::default(),
    };
    let config = Config {
        url: "wss://relay.test/".into(),
        public_url: "https://relay.test/".into(),
        tor: Some(tor),
        ..config()
    };
    let relay = Relay::start_onion(config, Some("ws://relay.onion/")).await;
    let onion = relay.onion.unwrap();

    let (head, body) = get(onion, "application/nostr+json").await;
    let info: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["icon"], "http://relay.onion/icon.png");
    assert!(!head.contains("onion-location"), "{head}");
    let (head, body) = get(onion, "text/html").await;
    assert!(body.contains("ws://relay.onion/"), "{body}");
    assert!(!head.contains("onion-location"), "{head}");

    let (head, body) = get(relay.addr, "application/nostr+json").await;
    let info: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["icon"], "https://relay.test/icon.png");
    assert!(!head.contains("onion-location"), "{head}");
    let (head, body) = get(relay.addr, "text/html").await;
    assert!(!body.contains("relay.onion"), "{body}");
    assert!(
        head.contains("onion-location: http://relay.onion/\r\n"),
        "{head}"
    );

    // NIP-70: a protected event needs its author to authenticate, which
    // over the onion may name the onion.
    let mut client = Client::connect(onion).await;
    let ev = signed(1, event::now().into(), 1, vec![vec!["-"]], "hidden");
    client.send(json!(["EVENT", ev])).await;
    let challenge = client.next().await;
    assert_eq!(challenge[0], "AUTH", "{challenge}");
    let ok = client.next().await;
    assert_eq!(ok[2], false, "{ok}");
    let challenge = challenge[1].as_str().unwrap();
    let auth = signed(
        1,
        event::now().into(),
        crate::auth::AUTH,
        vec![
            vec!["challenge", challenge],
            vec!["relay", "ws://relay.onion"],
        ],
        "",
    );
    client.send(json!(["AUTH", auth])).await;
    assert_eq!(client.next().await, json!(["OK", auth.id, true, ""]));
    assert_eq!(client.publish(&ev).await, (true, String::new()));
}

/// NIP-77: a sync, from the client's side, of the events it has that
/// match `filter`. What the client has that the relay doesn't, and what
/// the relay has that the client doesn't, by id.
async fn sync(client: &mut Client, filter: Value, mine: &[Event]) -> (Vec<String>, Vec<String>) {
    use crate::negentropy::{Item, Items, Negentropy};
    let items = mine.iter().map(|ev| Item {
        timestamp: ev.created_at,
        id: event::decode_hex(&ev.id).unwrap(),
    });
    let items = Items::new(items.collect());
    let mut neg = Negentropy::new(&items, 0);
    let msg = hex::encode(neg.initiate());
    client.send(json!(["NEG-OPEN", "s", filter, msg])).await;
    let (mut have, mut need) = (vec![], vec![]);
    loop {
        let msg = client.next().await;
        assert_eq!(msg[0], "NEG-MSG", "{msg}");
        assert_eq!(msg[1], "s", "{msg}");
        let msg = hex::decode(msg[2].as_str().unwrap()).unwrap();
        match neg.reconcile_with_ids(&msg, &mut have, &mut need).unwrap() {
            Some(next) => {
                client
                    .send(json!(["NEG-MSG", "s", hex::encode(next)]))
                    .await
            }
            None => break,
        }
    }
    client.send(json!(["NEG-CLOSE", "s"])).await;
    let hex = |ids: Vec<[u8; 32]>| {
        let mut ids: Vec<String> = ids.iter().map(hex::encode).collect();
        ids.sort();
        ids
    };
    (hex(have), hex(need))
}

#[tokio::test]
async fn syncs_with_negentropy() {
    let relay = Relay::start().await;
    let mut client = relay.connect().await;
    // Enough for the ranges to be split, and fingerprinted, over rounds.
    let notes: Vec<Event> = (0..300)
        .map(|i| signed(1, 1000 + i / 3, 1, vec![], &i.to_string()))
        .collect();
    let (theirs, rest) = notes.split_at(100);
    let (shared, mine) = rest.split_at(100);
    for ev in theirs.iter().chain(shared) {
        client.publish(ev).await;
    }
    // Not matching the filter.
    client.publish(&signed(1, 1000, 7, vec![], "+")).await;
    let ids = |events: &[Event]| {
        let mut ids: Vec<String> = events.iter().map(|ev| ev.id.clone()).collect();
        ids.sort();
        ids
    };
    let mine_and_shared = [shared, mine].concat();

    let (have, need) = sync(&mut client, json!({"kinds": [1]}), &mine_and_shared).await;
    assert_eq!((have, need), (ids(mine), ids(theirs)));
    // Within time bounds, and with a limit, as a REQ.
    let (have, need) = sync(&mut client, json!({"kinds": [1], "since": 1050}), &[]).await;
    assert_eq!((have, need), (vec![], ids(&notes[150..200])));
    let (_, need) = sync(&mut client, json!({"kinds": [1], "limit": 29}), &[]).await;
    assert_eq!(need, ids(&notes[171..200]));
    let (_, need) = sync(&mut client, json!({"ids": [notes[0].id]}), &[]).await;
    assert_eq!(need, [notes[0].id.clone()]);
    client.quiet().await;

    // Asked about a sync it doesn't have.
    client.send(json!(["NEG-MSG", "x", "61"])).await;
    let err = client.next().await;
    assert_eq!(err[0], "NEG-ERR", "{err}");
    assert!(err[2].as_str().unwrap().starts_with("closed:"), "{err}");
    // A message of another protocol version is answered with its own.
    client.send(json!(["NEG-OPEN", "v", {}, "62"])).await;
    assert_eq!(client.next().await, json!(["NEG-MSG", "v", "61"]));
    // A range of no mode there is.
    client.send(json!(["NEG-OPEN", "v", {}, "61000005"])).await;
    let err = client.next().await;
    assert!(err[2].as_str().unwrap().starts_with("invalid:"), "{err}");
    // A list of 2^34 ids, with none there, which the crate alone would
    // reserve a terabyte for.
    client
        .send(json!(["NEG-OPEN", "v", {}, "61000002c080808000"]))
        .await;
    let err = client.next().await;
    assert!(err[2].as_str().unwrap().starts_with("invalid:"), "{err}");
    client
        .send(json!(["NEG-OPEN", "v", {"search": "x"}, "61"]))
        .await;
    assert_eq!(client.next().await[0], "NEG-ERR");
}

#[tokio::test]
async fn refuses_syncs_too_big_or_turned_off() {
    let relay = Relay::start_with(Config {
        negentropy_max_events: 2,
        ..config()
    })
    .await;
    let mut client = relay.connect().await;
    for i in 0..3 {
        client.publish(&note(1, &i.to_string())).await;
    }
    let msg = hex::encode([0x61]);
    client
        .send(json!(["NEG-OPEN", "s", {"kinds": [1]}, msg]))
        .await;
    let err = client.next().await;
    assert_eq!(
        err,
        json!(["NEG-ERR", "s", "blocked: too many events to sync", 2])
    );
    client
        .send(json!(["NEG-OPEN", "s", {"kinds": [1], "limit": 2}, msg]))
        .await;
    assert_eq!(client.next().await[0], "NEG-MSG");

    let relay = Relay::start_with(Config {
        negentropy: false,
        ..config()
    })
    .await;
    let (_, body) = get(relay.addr, "application/nostr+json").await;
    let info: Value = serde_json::from_str(&body).unwrap();
    assert!(
        !info["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(77))
    );
    let mut client = relay.connect().await;
    client.send(json!(["NEG-OPEN", "s", {}, msg])).await;
    let err = client.next().await;
    assert_eq!(
        err,
        json!(["NEG-ERR", "s", "blocked: negentropy is disabled"])
    );
}
