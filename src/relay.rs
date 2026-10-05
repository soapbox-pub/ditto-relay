use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};

use crate::auth;
use crate::config::Config;
use crate::event::{self, Event, KindClass};
use crate::filter::Filter;
use crate::landing;
use crate::metrics::{Connected, METRICS};
use crate::plugin::{self, Plugin, Verdict};
use crate::query::{self, TooExpensive};
use crate::record::{self, EventView};
use crate::search::SearchIndex;
use crate::store::{Outcome, Store, Writer};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub writer: Writer,
    /// For NIP-50 search, if it's on.
    pub search: Option<Arc<SearchIndex>>,
    /// Every accepted event, for live subscriptions.
    pub live: broadcast::Sender<Arc<LiveEvent>>,
    /// Decides which events to take, if there is one.
    plugin: Option<Plugin>,
    /// The NIP-11 information document, and the landing page made from it.
    nip11: Arc<str>,
    landing: Arc<str>,
}

/// An accepted event, encoded once for every subscription it's sent to.
pub struct LiveEvent {
    /// Its sequence number, if it was stored (ephemeral events aren't).
    seq: Option<u64>,
    record: Arc<Vec<u8>>,
    json: String,
}

impl AppState {
    /// With `search`, the index and the channel to its indexer.
    pub fn new(
        config: Config,
        store: Arc<Store>,
        search: Option<(Arc<SearchIndex>, std::sync::mpsc::Sender<Vec<u64>>)>,
    ) -> Self {
        let (search, indexer) = search.unzip();
        let info = nip11(&config);
        let landing = landing::render(&info, &config.url).into();
        let plugin = config.write_policy_plugin.clone().map(|command| {
            let timeout = Duration::from_secs(config.write_policy_timeout_seconds);
            Plugin::spawn(command, timeout)
        });
        Self {
            plugin,
            nip11: info.to_string().into(),
            landing,
            config: Arc::new(config),
            writer: Writer::spawn(store.clone(), indexer),
            store,
            search,
            live: broadcast::channel(8192).0,
        }
    }
}

pub fn router(state: AppState) -> Router {
    let asset = |content_type: &'static str, body: &'static [u8]| {
        get(move || async move { ([(header::CONTENT_TYPE, content_type)], body) })
    };
    Router::new()
        .route("/", get(root))
        .route("/favicon.ico", asset("image/x-icon", landing::FAVICON))
        .route("/icon.png", asset("image/png", landing::ICON))
        .route("/banner.jpg", asset("image/jpeg", landing::BANNER))
        .with_state(state)
}

async fn root(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if let Ok(ws) = ws {
        let max = state.config.max_message_size;
        let ip = client_ip(&state.config, &headers, peer);
        return ws
            .max_message_size(max)
            .max_frame_size(max)
            .on_upgrade(move |socket| Connection::run(socket, state, ip))
            .into_response();
    }

    let wants_nip11 = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/nostr+json"));
    if wants_nip11 {
        return (
            [
                (header::CONTENT_TYPE, "application/nostr+json"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            ],
            state.nip11.to_string(),
        )
            .into_response();
    }

    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        state.landing.to_string(),
    )
        .into_response()
}

/// The client's IP: from the configured header if it's set and makes sense,
/// else the peer's. Proxies append to `X-Forwarded-For`, so the last address
/// in a list is the one the nearest proxy saw.
fn client_ip(config: &Config, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    let Some(name) = &config.real_ip_header else {
        return peer.ip();
    };
    let header = headers.get(name.as_str()).and_then(|v| v.to_str().ok());
    let ip = header.and_then(|v| v.rsplit(',').next()?.trim().parse().ok());
    if ip.is_none() {
        tracing::warn!("couldn't parse an IP from {name}: {header:?}");
    }
    ip.unwrap_or(peer.ip())
}

fn nip11(config: &Config) -> Value {
    let mut nips = vec![1, 9, 11, 40, 42, 45, 62, 70];
    if config.search {
        nips.push(50);
        nips.sort_unstable();
    }
    let mut info = json!({
        "name": config.name,
        "description": config.description,
        "supported_nips": nips,
        "software": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "icon": landing::asset_url(&config.public_url, "/icon.png"),
        "banner": landing::asset_url(&config.public_url, "/banner.jpg"),
        "limitation": {
            "max_message_length": config.max_message_size,
            "max_subscriptions": config.max_subscriptions,
            "max_filters": config.max_filters,
            "max_subid_length": config.max_subid_length,
            "max_limit": config.max_limit,
            "default_limit": config.default_limit,
            "created_at_upper_limit": config.max_future_seconds,
            "min_pow_difficulty": 0,
            "auth_required": false,
            "payment_required": false,
            // Not standard: so clients can split big filters before sending.
            "max_filter_values": config.max_filter_values,
        },
    });
    if let Some(pubkey) = &config.pubkey {
        info["pubkey"] = pubkey.as_str().into();
    }
    if let Some(contact) = &config.contact {
        info["contact"] = contact.as_str().into();
    }
    // The key its NIP-85 assertions are signed with.
    if let Some(keypair) = &config.keypair {
        info["self"] = hex::encode(keypair.x_only_public_key().0.to_byte_array()).into();
    }
    info
}

const EXPIRED: &str = "invalid: event has expired";

/// NIP-62 requests to vanish.
const VANISH: u16 = 62;

/// Whether a NIP-62 request to vanish is addressed to this relay, which is
/// at `url`: to every relay, or to this one.
fn addressed_to(ev: &Event, url: &str) -> bool {
    ev.tags
        .iter()
        .filter(|tag| tag.len() >= 2 && tag[0] == "relay")
        .any(|tag| tag[1] == "ALL_RELAYS" || auth::same_relay(&tag[1], url))
}

/// Whether an event is NIP-70 protected: only its author may publish it.
fn is_protected(ev: &Event) -> bool {
    ev.tags
        .iter()
        .any(|tag| tag.first().is_some_and(|name| name == "-"))
}

/// Outgoing queue depth per connection before we apply backpressure.
const OUTBOX_SIZE: usize = 1024;

struct Subscription {
    filters: Vec<Filter>,
    /// Stored events below this sequence number were visible to the initial
    /// query, so they've been sent already (or didn't match).
    next_seq: u64,
}

struct Connection {
    state: AppState,
    subs: HashMap<String, Subscription>,
    outbox: mpsc::Sender<String>,
    ip: IpAddr,
    /// What this connection signs to authenticate (NIP-42), once it's
    /// been asked to: only to publish a NIP-70 protected event.
    challenge: Option<String>,
    /// The pubkeys the connection has authenticated as.
    authed: HashSet<[u8; 32]>,
}

/// The connection should be torn down.
struct Disconnect;

impl Connection {
    async fn run(socket: WebSocket, state: AppState, ip: IpAddr) {
        let _connected = Connected::new();
        let (mut sink, mut stream) = socket.split();
        let (outbox, mut outbox_rx) = mpsc::channel::<String>(OUTBOX_SIZE);

        let sender = tokio::spawn(async move {
            while let Some(msg) = outbox_rx.recv().await {
                if sink.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let mut live = state.live.subscribe();
        let mut conn = Connection {
            state,
            subs: HashMap::new(),
            outbox,
            ip,
            challenge: None,
            authed: HashSet::new(),
        };

        loop {
            let result = tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(text))) => conn.on_message(text.as_str()).await,
                    Some(Ok(Message::Binary(_))) => conn.notice("error: binary messages are not supported").await,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(()),
                    Some(Ok(Message::Close(_)) | Err(_)) | None => Err(Disconnect),
                },
                ev = live.recv() => match ev {
                    Ok(ev) => conn.on_live_event(&ev).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("connection lagged, dropped {n} live events");
                        METRICS.live_dropped.add(n);
                        Ok(())
                    }
                    Err(broadcast::error::RecvError::Closed) => Err(Disconnect),
                },
            };
            if result.is_err() {
                break;
            }
        }

        drop(conn);
        let _ = sender.await;
    }

    async fn send_raw(&self, text: String) -> Result<(), Disconnect> {
        self.outbox.send(text).await.map_err(|_| Disconnect)
    }

    async fn send(&self, msg: &impl Serialize) -> Result<(), Disconnect> {
        let text = serde_json::to_string(msg).expect("relay message serialization cannot fail");
        self.send_raw(text).await
    }

    /// `["EVENT", sub_id, event]`, with the event already serialized.
    async fn send_event(&self, sub_id: &str, json: &str) -> Result<(), Disconnect> {
        let sub_id = serde_json::to_string(sub_id).expect("strings serialize");
        self.send_raw(format!("[\"EVENT\",{sub_id},{json}]")).await
    }

    async fn notice(&self, msg: &str) -> Result<(), Disconnect> {
        self.send(&("NOTICE", msg)).await
    }

    async fn ok(&self, id: &str, accepted: bool, msg: &str) -> Result<(), Disconnect> {
        self.send(&("OK", id, accepted, msg)).await
    }

    async fn closed(&self, sub_id: &str, msg: &str) -> Result<(), Disconnect> {
        self.send(&("CLOSED", sub_id, msg)).await
    }

    async fn on_message(&mut self, text: &str) -> Result<(), Disconnect> {
        let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(text) else {
            return self.notice("invalid: message must be a JSON array").await;
        };

        match msg.first().and_then(Value::as_str) {
            Some("EVENT") => self.on_event(msg.get(1)).await,
            Some("REQ") => self.on_req(&msg[1..]).await,
            Some("COUNT") => self.on_count(&msg[1..]).await,
            Some("AUTH") => self.on_auth(msg.get(1)).await,
            Some("CLOSE") => match msg.get(1).and_then(Value::as_str) {
                Some(sub_id) => {
                    self.subs.remove(sub_id);
                    Ok(())
                }
                None => {
                    self.notice("invalid: CLOSE requires a subscription id")
                        .await
                }
            },
            _ => self.notice("invalid: unknown message type").await,
        }
    }

    async fn on_event(&mut self, value: Option<&Value>) -> Result<(), Disconnect> {
        let Some(value) = value else {
            return self.notice("invalid: EVENT requires an event").await;
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let (accepted, msg) = match self.check(value) {
            Err(msg) => (false, msg),
            Ok(ev) => match self.ask_plugin(&ev).await {
                Verdict::Accept => self.accept(&id, ev).await,
                Verdict::Reject(msg) => (false, msg.into()),
                Verdict::ShadowReject(msg) => {
                    METRICS.events_shadow_rejected.inc();
                    return self.ok(&id, true, &msg).await;
                }
            },
        };
        if msg.starts_with("auth-required:") && self.challenge.is_none() {
            let challenge = auth::challenge();
            self.send(&("AUTH", &challenge)).await?;
            self.challenge = Some(challenge);
        }
        let counter = match (accepted, msg.split_once(':').map(|(prefix, _)| prefix)) {
            (_, Some("duplicate")) => &METRICS.events_duplicate,
            (true, _) => &METRICS.events_accepted,
            (false, Some("error")) => &METRICS.events_failed,
            (false, _) => &METRICS.events_rejected,
        };
        counter.inc();
        self.ok(&id, accepted, &msg).await
    }

    /// An event, if it's one the relay could take, or a NIP-01 OK message
    /// saying why not.
    fn check(&self, value: &Value) -> Result<Event, Cow<'static, str>> {
        let ev: Event = serde_json::from_value(value.clone())
            .map_err(|err| Cow::Owned(format!("invalid: {err}")))?;
        ev.verify()?;
        if !event::is_relayed(ev.kind) {
            return Err(format!("blocked: kind {} is not relayed", ev.kind).into());
        }
        let author = event::decode_hex(&ev.pubkey).expect("verified");
        if is_protected(&ev) && !self.authed.contains(&author) {
            return Err("auth-required: this event may only be published by its author".into());
        }
        if ev.created_at > u64::from(event::now()) + self.state.config.max_future_seconds {
            return Err("invalid: created_at is too far in the future".into());
        }
        if ev.kind == VANISH && !addressed_to(&ev, &self.state.config.url) {
            return Err("invalid: this request to vanish is for other relays".into());
        }
        Ok(ev)
    }

    /// What the write policy plugin makes of an event, if there is one.
    async fn ask_plugin(&self, ev: &Event) -> Verdict {
        let Some(plugin) = &self.state.plugin else {
            return Verdict::Accept;
        };
        // strfry names one pubkey: the author's, if it's among them.
        let author = event::decode_hex(&ev.pubkey).expect("verified");
        let authed = match self.authed.contains(&author) {
            true => Some(author),
            false => self.authed.iter().next().copied(),
        }
        .map(hex::encode);
        let source = plugin::Source {
            ip: self.ip,
            authed: authed.as_deref(),
        };
        let start = Instant::now();
        let verdict = plugin.judge(ev, &source).await;
        METRICS.plugin.since(start);
        if let Verdict::Reject(msg) | Verdict::ShadowReject(msg) = &verdict
            && !msg.is_empty()
        {
            tracing::debug!("write policy blocked event {}: {msg}", ev.id);
        }
        verdict
    }

    /// Stores an event, or sends it to live subscriptions, with a NIP-01
    /// OK message.
    async fn accept(&mut self, id: &str, ev: Event) -> (bool, Cow<'static, str>) {
        let now = event::now();
        let ephemeral = ev.kind_class() == KindClass::Ephemeral;
        // Encoding guesses the event's language and sentiment, which takes
        // a while for long text.
        let record = match tokio::task::spawn_blocking(move || record::encode(&ev)).await {
            Ok(record) => Arc::new(record),
            Err(err) => {
                tracing::error!("encoding event {id} panicked: {err}");
                METRICS.errors_panic.inc();
                return (false, "error: failed to store event".into());
            }
        };
        let view = EventView::new(&record).expect("an encoded record");
        if view.is_expired(now) {
            return (false, EXPIRED.into());
        }
        let json = view.to_json();
        if ephemeral {
            let _ = self.state.live.send(Arc::new(LiveEvent {
                seq: None,
                record,
                json,
            }));
            return (true, "".into());
        }

        match self.state.writer.write(record.clone()).await {
            Ok(Outcome::Stored(seq)) => {
                let live = LiveEvent {
                    seq: Some(seq),
                    record,
                    json,
                };
                let _ = self.state.live.send(Arc::new(live));
                (true, "".into())
            }
            // Kept, but old news: not sent to live subscriptions.
            Ok(Outcome::Archived(_)) => (true, "".into()),
            Ok(Outcome::Duplicate) => (true, "duplicate: already have this event".into()),
            Ok(Outcome::Expired) => (false, EXPIRED.into()),
            Ok(Outcome::Deleted) => (false, "blocked: this event has been deleted".into()),
            Ok(Outcome::Replaced) => (
                false,
                "duplicate: have a newer version of this event".into(),
            ),
            Err(err) => {
                tracing::error!("failed to store event {id}: {err:#}");
                METRICS.errors_write.inc();
                (false, "error: failed to store event".into())
            }
        }
    }

    async fn on_req(&mut self, args: &[Value]) -> Result<(), Disconnect> {
        let config = self.state.config.clone();

        let Some(sub_id) = args.first().and_then(Value::as_str) else {
            return self.notice("invalid: REQ requires a subscription id").await;
        };
        if sub_id.is_empty() || sub_id.len() > config.max_subid_length {
            return self.closed(sub_id, "invalid: bad subscription id").await;
        }

        let filters = match self.filters(&args[1..]) {
            Ok(filters) => filters,
            Err(msg) => return self.closed(sub_id, &msg).await,
        };
        if !self.subs.contains_key(sub_id) && self.subs.len() >= config.max_subscriptions {
            return self.closed(sub_id, "error: too many subscriptions").await;
        }
        // A REQ reusing an id replaces that subscription.
        self.subs.remove(sub_id);

        // Live events published while this runs wait in the broadcast
        // receiver, and are checked against the subscription after it's added.
        let store = self.state.store.clone();
        let search = self.state.search.clone();
        let query_filters = filters.clone();
        let start = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            query::run(
                &store,
                search.as_deref(),
                config.keypair.as_ref(),
                &query_filters,
                config.default_limit,
                config.max_limit,
            )
        })
        .await;
        METRICS.reqs.since(start);

        let results = match result {
            Ok(Ok(results)) => results,
            Ok(Err(err)) => {
                tracing::error!("query failed: {err:#}");
                METRICS.errors_query.inc();
                return self.closed(sub_id, "error: query failed").await;
            }
            Err(err) => {
                tracing::error!("query task panicked: {err}");
                METRICS.errors_panic.inc();
                return self.closed(sub_id, "error: query failed").await;
            }
        };

        self.subs.insert(
            sub_id.to_string(),
            Subscription {
                filters,
                next_seq: results.next_seq,
            },
        );
        for json in &results.events {
            self.send_event(sub_id, json).await?;
        }
        self.send(&("EOSE", sub_id)).await
    }

    /// A REQ's or COUNT's filters, or why they're refused.
    fn filters(&self, args: &[Value]) -> Result<Vec<Filter>, String> {
        let indexed = &self.state.store.indexed_tags;
        let max_values = self.state.config.max_filter_values;
        let mut filters = args
            .iter()
            .map(|value| Filter::parse(value, indexed, max_values))
            .collect::<Result<Vec<_>, _>>()?;
        if filters.len() > self.state.config.max_filters {
            return Err("invalid: too many filters".into());
        }
        // Only text needs the search index: extensions are looked up in
        // the LMDB.
        for filter in filters
            .iter_mut()
            .filter(|f| f.search.as_ref().is_some_and(|s| s.has_text()))
        {
            match &self.state.search {
                Some(search) => search.restrict(filter),
                None => return Err("unsupported: search is not enabled".into()),
            }
        }
        Ok(filters)
    }

    /// NIP-42: `["AUTH", event]`.
    async fn on_auth(&mut self, value: Option<&Value>) -> Result<(), Disconnect> {
        let Some(value) = value else {
            return self.notice("invalid: AUTH requires an event").await;
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let ev: Event = match serde_json::from_value(value.clone()) {
            Ok(ev) => ev,
            Err(err) => return self.ok(&id, false, &format!("invalid: {err}")).await,
        };
        let Some(challenge) = &self.challenge else {
            let msg = "invalid: no challenge has been issued";
            return self.ok(&id, false, msg).await;
        };
        match auth::verify(&ev, challenge, &self.state.config.url, event::now()) {
            Ok(pubkey) => {
                self.authed.insert(pubkey);
                self.ok(&id, true, "").await
            }
            Err(msg) => self.ok(&id, false, &msg).await,
        }
    }

    /// NIP-45: `["COUNT", id, filters...]`.
    async fn on_count(&mut self, args: &[Value]) -> Result<(), Disconnect> {
        let Some(id) = args.first().and_then(Value::as_str) else {
            return self.notice("invalid: COUNT requires a query id").await;
        };
        if id.is_empty() || id.len() > self.state.config.max_subid_length {
            return self.closed(id, "invalid: bad query id").await;
        }
        let filters = match self.filters(&args[1..]) {
            Ok(filters) => filters,
            Err(msg) => return self.closed(id, &msg).await,
        };

        let store = self.state.store.clone();
        let search = self.state.search.clone();
        let start = Instant::now();
        let result =
            tokio::task::spawn_blocking(move || query::count(&store, search.as_deref(), &filters))
                .await;
        METRICS.counts.since(start);
        match result {
            Ok(Ok(count)) => {
                let mut body = json!({"count": count.count});
                if let Some(registers) = count.hll {
                    body["hll"] = hex::encode(registers).into();
                }
                self.send(&("COUNT", id, body)).await
            }
            Ok(Err(err)) if err.is::<TooExpensive>() => {
                METRICS.counts_refused.inc();
                self.closed(id, "unsupported: too expensive to count").await
            }
            Ok(Err(err)) => {
                tracing::error!("count failed: {err:#}");
                METRICS.errors_query.inc();
                self.closed(id, "error: count failed").await
            }
            Err(err) => {
                tracing::error!("count task panicked: {err}");
                METRICS.errors_panic.inc();
                self.closed(id, "error: count failed").await
            }
        }
    }

    async fn on_live_event(&self, ev: &LiveEvent) -> Result<(), Disconnect> {
        let view = EventView::new(&ev.record).expect("an encoded record");
        for (sub_id, sub) in &self.subs {
            // Already covered by the subscription's initial query.
            if ev.seq.is_some_and(|seq| seq < sub.next_seq) {
                continue;
            }
            if sub.filters.iter().any(|f| f.matches(&view)) {
                self.send_event(sub_id, &ev.json).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;

    #[test]
    fn knows_which_vanish_requests_are_its_own() {
        let to = |relay: &str| signed(1, 100, VANISH, vec![vec!["relay", relay]], "");
        let url = "wss://relay.example.com";
        assert!(addressed_to(&to("ALL_RELAYS"), url));
        assert!(addressed_to(&to("wss://relay.example.com"), url));
        assert!(addressed_to(&to("WSS://Relay.Example.com/"), url));
        assert!(!addressed_to(&to("wss://other.example.com"), url));
        assert!(!addressed_to(&signed(1, 100, VANISH, vec![], ""), url));
    }
}
