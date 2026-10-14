use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use secp256k1::Keypair;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::auth;
use crate::config::{Config, Image};
use crate::event::{self, Event, KindClass};
use crate::filter::Filter;
use crate::metrics::{Connected, METRICS};
use crate::negentropy::{self, Item, Items, Negentropy};
use crate::plugin::{self, Peer, Plugin, Verdict};
use crate::query::{self, Cancelled, Count, Results, TooExpensive};
use crate::record::{self, EventView};
use crate::search::SearchIndex;
use crate::store::{Outcome, Store, Writer};
use crate::{key, landing};
use monitors::{ConnId, Hub, Link, Live, Outbound};

mod monitors;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// The relay's own key, which signs the NIP-85 assertions it serves and
    /// the trends it labels.
    pub keypair: Keypair,
    pub store: Arc<Store>,
    pub writer: Writer,
    /// For NIP-50 search, if it's on.
    pub search: Option<Arc<SearchIndex>>,
    /// Live subscriptions, which every new event is matched against.
    hub: Hub,
    /// The next connection's id.
    next_conn: Arc<AtomicU64>,
    /// Cancelled to shut the relay down.
    pub shutdown: CancellationToken,
    /// Every open connection, to wait for at shutdown.
    connections: TaskTracker,
    /// Decides which events to take, if there is one.
    plugin: Option<Plugin>,
    /// A place per core for checking signatures, which keeps a flood of
    /// events from taking over the blocking pool.
    verifiers: Arc<Semaphore>,
    /// A place per core for queries. A REQ or COUNT waits its turn, rather
    /// than being refused, when every core is busy.
    queries: Arc<Semaphore>,
    /// What the relay is called by: its URL, and its onion's.
    urls: Arc<[String]>,
    /// What's served to clients at the relay's URL, and at its onion's, if
    /// it's an onion service too.
    clearnet: Arc<Pages>,
    onion: Option<Arc<Pages>>,
    /// Where Tor Browser is told to find the onion.
    onion_location: Option<HeaderValue>,
}

/// The NIP-11 information document, and the landing page made from it.
struct Pages {
    nip11: Arc<str>,
    landing: Arc<str>,
}

impl Pages {
    /// For the relay at `url`, whose images are at `public_url`.
    fn new(config: &Config, keypair: &Keypair, url: &str, public_url: &str) -> Self {
        let info = nip11(config, keypair, public_url);
        Self {
            landing: landing::render(&info, url).into(),
            nip11: info.to_string().into(),
        }
    }
}

impl AppState {
    /// With the relay's own `keypair`, with `search`, the index and the
    /// channel to its indexer, and with `onion`, the URL of the relay's
    /// onion service.
    pub fn new(
        config: Config,
        keypair: Keypair,
        store: Arc<Store>,
        search: Option<(Arc<SearchIndex>, std::sync::mpsc::Sender<Vec<u64>>)>,
        onion: Option<String>,
    ) -> Self {
        let (search, indexer) = search.unzip();
        let clearnet = Pages::new(&config, &keypair, &config.url, &config.public_url);
        // Images on the onion come from the onion, not from clearnet.
        let onion_http = onion.as_ref().map(|url| url.replacen("ws", "http", 1));
        let onion_pages = onion
            .as_deref()
            .zip(onion_http.as_deref())
            .map(|(url, http)| Arc::new(Pages::new(&config, &keypair, url, http)));
        // Tor Browser only heeds the header over HTTPS.
        let advertise = config.tor.as_ref().is_some_and(|tor| tor.onion_location)
            && config.public_url.starts_with("https://");
        let onion_location = onion_http
            .filter(|_| advertise)
            .and_then(|url| HeaderValue::from_str(&url).ok());
        let urls = [config.url.clone()].into_iter().chain(onion).collect();
        let plugin = config.write_policy_plugin.clone().map(|command| {
            let timeout = Duration::from_secs(config.write_policy_timeout_seconds);
            Plugin::spawn(command, timeout)
        });
        let hub = Hub::spawn((cores() / 2).clamp(1, 8));
        let live = hub.clone();
        let stored = move |events: Vec<(u64, Arc<Vec<u8>>)>| {
            let events = events.into_iter();
            live.broadcast(
                events
                    .map(|(seq, record)| Live::new(record, Some(seq)))
                    .collect(),
            );
        };
        Self {
            plugin,
            urls,
            clearnet: Arc::new(clearnet),
            onion: onion_pages,
            onion_location,
            config: Arc::new(config),
            keypair,
            writer: Writer::spawn(store.clone(), indexer, stored),
            store,
            search,
            hub,
            next_conn: Arc::new(AtomicU64::new(1)),
            shutdown: CancellationToken::new(),
            connections: TaskTracker::new(),
            verifiers: Arc::new(Semaphore::new(cores())),
            queries: Arc::new(Semaphore::new(cores())),
        }
    }

    /// Shut down: close every connection, each once it's done with the
    /// message it's on, then store what's queued and stop the writer.
    pub async fn shut_down(&self) {
        self.shutdown.cancel();
        self.connections.close();
        if tokio::time::timeout(CLOSE_TIMEOUT, self.connections.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                "{} connections didn't close in time",
                self.connections.len()
            );
        }
        let writer = self.writer.clone();
        let _ = tokio::task::spawn_blocking(move || writer.stop()).await;
    }

    /// Store an event of the relay's own, which the writer sends to live
    /// subscriptions like any other.
    pub async fn publish(&self, ev: Event) -> anyhow::Result<Outcome> {
        let record = Arc::new(tokio::task::spawn_blocking(move || record::encode(&ev)).await?);
        self.writer.write(record).await
    }
}

/// How many threads can run at once.
fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

/// What serves clients that reach the relay at its URL.
pub fn router(state: AppState) -> Router {
    let asset = |content_type: &'static str, body: &'static [u8]| {
        get(move || async move { ([(header::CONTENT_TYPE, content_type)], body) })
    };
    Router::new()
        .route("/", get(root).options(|| async { CORS }))
        .route("/favicon.ico", asset("image/x-icon", landing::FAVICON))
        .route("/icon.png", asset("image/png", landing::ICON))
        .route("/banner.jpg", asset("image/jpeg", landing::BANNER))
        .with_state(state)
}

/// What serves clients that reach the relay at its onion, which have no
/// address to give.
pub fn onion_router(state: AppState) -> Router {
    router(state).layer(Extension(OverTor))
}

/// Marks a request that came over Tor.
#[derive(Clone, Copy)]
struct OverTor;

/// How a request reached the relay.
#[derive(Clone, Copy)]
enum Via {
    /// From the peer at an address, which may be a proxy.
    Socket(SocketAddr),
    Tor,
}

impl<S: Send + Sync> FromRequestParts<S> for Via {
    type Rejection = <ConnectInfo<SocketAddr> as FromRequestParts<S>>::Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if parts.extensions.get::<OverTor>().is_some() {
            return Ok(Via::Tor);
        }
        let ConnectInfo(peer) = ConnectInfo::from_request_parts(parts, state).await?;
        Ok(Via::Socket(peer))
    }
}

/// What NIP-11 has the relay's page answer browsers on any origin with,
/// and a preflight too.
const CORS: [(header::HeaderName, &str); 3] = [
    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
    (header::ACCESS_CONTROL_ALLOW_HEADERS, "*"),
    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"),
];

/// How much of a connection's read buffer is filled at a time. tungstenite
/// zeroes all of it before every read, and messages are mostly a few hundred
/// bytes: at its default of 128 KiB, that was a twentieth of what the relay
/// did. A bigger frame gets room of its own.
const READ_BUFFER: usize = 8 << 10;

async fn root(
    State(state): State<AppState>,
    via: Via,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if let Ok(ws) = ws {
        let max = state.config.max_message_size;
        // A header over Tor is the client's own, and can't be trusted.
        let peer = match via {
            Via::Socket(peer) => Peer::Ip(client_ip(&state.config, &headers, peer)),
            Via::Tor => Peer::Tor,
        };
        return ws
            .max_message_size(max)
            .max_frame_size(max)
            .read_buffer_size(READ_BUFFER)
            .on_upgrade(move |socket| {
                let connections = state.connections.clone();
                connections.track_future(Connection::run(socket, state, peer))
            })
            .into_response();
    }

    let pages = match via {
        Via::Tor => state.onion.as_ref().unwrap_or(&state.clearnet),
        Via::Socket(_) => &state.clearnet,
    };
    let wants_nip11 = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/nostr+json"));
    if wants_nip11 {
        return (
            CORS,
            [(header::CONTENT_TYPE, "application/nostr+json")],
            pages.nip11.to_string(),
        )
            .into_response();
    }

    let mut response = (
        CORS,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        pages.landing.to_string(),
    )
        .into_response();
    if let (Via::Socket(_), Some(onion)) = (via, &state.onion_location) {
        response
            .headers_mut()
            .insert("onion-location", onion.clone());
    }
    response
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

/// For the relay whose key is `keypair` and whose images are at `public_url`.
fn nip11(config: &Config, keypair: &Keypair, public_url: &str) -> Value {
    let mut nips = vec![1, 9, 11, 40, 42, 45, 62, 70];
    if config.search {
        nips.push(50);
    }
    if config.negentropy {
        nips.push(77);
    }
    nips.sort_unstable();
    let mut info = json!({
        "name": config.name,
        "description": config.description,
        "supported_nips": nips,
        "version": env!("CARGO_PKG_VERSION"),
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
    if let Some(software) = &config.software {
        info["software"] = software.as_str().into();
    }
    for (key, image, path) in [
        ("icon", &config.icon, "/icon.png"),
        ("banner", &config.banner, "/banner.jpg"),
    ] {
        match image {
            Image::Builtin => info[key] = landing::asset_url(public_url, path).into(),
            Image::Url(url) => info[key] = url.as_str().into(),
            Image::None => {}
        }
    }
    // The key its NIP-85 assertions and trends are signed with.
    info["self"] = key::pubkey(keypair).into();
    info
}

const EXPIRED: &str = "invalid: event has expired";
const DUPLICATE: &str = "duplicate: already have this event";

/// NIP-62 requests to vanish.
const VANISH: u16 = 62;

/// Whether a NIP-62 request to vanish is addressed to this relay, which is
/// at `urls`: to every relay, or to this one.
fn addressed_to(ev: &Event, urls: &[impl AsRef<str>]) -> bool {
    ev.tags
        .iter()
        .filter(|tag| tag.len() >= 2 && tag[0] == "relay")
        .any(|tag| tag[1] == "ALL_RELAYS" || auth::is_one_of(&tag[1], urls))
}

/// Whether an event is NIP-70 protected: only its author may publish it.
fn is_protected(ev: &Event) -> bool {
    ev.tags
        .iter()
        .any(|tag| tag.first().is_some_and(|name| name == "-"))
}

/// How long one write to a client may take — one message, or a query's
/// results all together — before it's taken to have stopped reading and
/// is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long connections get to close at shutdown.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a client is pinged. One not heard from in two of these, pong
/// or otherwise, has gone without closing, and is dropped. Kept well under
/// the 60 seconds a reverse proxy like nginx waits on a quiet connection
/// before closing it.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Live events waiting to go out to one client. One that falls this far
/// behind is dropped: holding more for it would be without end.
const OUTBOUND: usize = 16_384;

/// The most live events held for a subscription while its query runs.
/// Past this it's closed, and its client can ask again.
const MAX_PENDING: usize = OUTBOUND;

/// Events a connection may have waiting to be stored at once. Past this,
/// its next message waits until one is answered, so a flood of events slows
/// only the connection sending it.
const MAX_PUBLISHING: usize = 64;

/// How an event a connection published was answered, once it's been
/// verified, judged, and stored.
struct Published {
    id: String,
    accepted: bool,
    msg: Cow<'static, str>,
    /// Shadow-rejected: told it was accepted, but not counted as such.
    shadow: bool,
}

struct Subscription {
    /// This REQ's own name: a later REQ of the same id gets a new one, so
    /// results meant for the one it replaced can be told apart.
    name: Arc<str>,
    /// Live events that arrived while the query ran, by sequence number,
    /// held until its EOSE. None once it's sent.
    pending: Option<Vec<(Option<u64>, Arc<str>)>>,
    /// Stored events below this sequence number were visible to the
    /// initial query, so they've been sent already (or didn't match).
    floor: u64,
    /// Stops its query.
    cancel: CancellationToken,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A NIP-77 sync.
struct NegSync {
    /// As a [`Subscription`]'s.
    name: Arc<str>,
    /// The `created_at` and id of every event its filter matched, once
    /// they've been found. Kept for its every message.
    storage: Option<Arc<Items>>,
    /// Stops its query.
    cancel: CancellationToken,
}

impl Drop for NegSync {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// The most bytes of a negentropy message the relay sends, before it's
/// hex-encoded: strfry's.
const NEG_FRAME_SIZE: usize = 500_000;

/// A sync's answer to a message, and the events it covers.
struct Reconciled {
    storage: Arc<Items>,
    msg: Vec<u8>,
}

/// A finished query: a REQ's, by its subscription's name, a COUNT's, by
/// its id, or a sync's, by its name.
enum Done {
    Req(Arc<str>, anyhow::Result<Results>),
    /// Boxed: a count's HyperLogLog is big.
    Count(String, anyhow::Result<Box<Count>>),
    Sync(Arc<str>, anyhow::Result<Reconciled>),
}

/// Run a query on the blocking pool when a core is free, unless `cancel`
/// is cancelled first.
async fn run_query<T: Send + 'static>(
    state: &AppState,
    cancel: &CancellationToken,
    query: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    let run = async {
        let place = state.queries.clone().acquire_owned().await?;
        tokio::task::spawn_blocking(move || {
            // Held until the query stops, which may be a moment after
            // it's cancelled.
            let _place = place;
            query()
        })
        .await
        .unwrap_or_else(|err| {
            METRICS.errors_panic.inc();
            Err(anyhow::anyhow!("query task panicked: {err}"))
        })
    };
    cancel
        .run_until_cancelled(run)
        .await
        .unwrap_or_else(|| Err(Cancelled.into()))
}

struct Connection {
    state: AppState,
    id: ConnId,
    /// By subscription id.
    subs: HashMap<String, Subscription>,
    /// By their own ids, apart from subscriptions'.
    syncs: HashMap<String, NegSync>,
    /// Stops every query of the connection's once it's gone, or the relay
    /// is shutting down.
    cancel: CancellationToken,
    sink: SplitSink<WebSocket, Message>,
    peer: Peer,
    /// What this connection signs to authenticate (NIP-42), once it's
    /// been asked to: only to publish a NIP-70 protected event.
    challenge: Option<String>,
    /// The pubkeys the connection has authenticated as.
    authed: HashSet<[u8; 32]>,
}

/// The connection should be torn down.
#[derive(Debug, PartialEq, Eq)]
enum Disconnect {
    /// It's closed, or broken.
    Gone,
    /// A write to it didn't finish in time.
    Stalled,
}

impl Connection {
    async fn run(socket: WebSocket, state: AppState, peer: Peer) {
        let _connected = Connected::new();
        let (sink, mut stream) = socket.split();
        let id = state.next_conn.fetch_add(1, Ordering::Relaxed);
        let (link, mut outbound, overflow) = Link::new(OUTBOUND);
        state.hub.connect(id, link).await;
        let start = tokio::time::Instant::now() + PING_INTERVAL;
        let mut ping = tokio::time::interval_at(start, PING_INTERVAL);
        let mut heard = Instant::now();
        let mut queries = JoinSet::new();
        // Events being stored apart from the loop, so a slow write holds up
        // only its own OK, not the connection's queries and live events.
        let mut publishing = JoinSet::new();
        let shutdown = state.shutdown.clone();
        let mut conn = Connection {
            cancel: shutdown.child_token(),
            state,
            id,
            subs: HashMap::new(),
            syncs: HashMap::new(),
            sink,
            peer,
            challenge: None,
            authed: HashSet::new(),
        };

        loop {
            let result = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = overflow.cancelled() => {
                    tracing::debug!("dropping a client that fell too far behind");
                    METRICS.dropped_behind.inc();
                    break;
                }
                _ = ping.tick() => {
                    // One waiting on its own events to be stored isn't silent.
                    if heard.elapsed() > 2 * PING_INTERVAL && publishing.is_empty() {
                        tracing::debug!("dropping a client that went silent");
                        METRICS.dropped_silent.inc();
                        break;
                    }
                    write_within(conn.sink.send(Message::Ping(Default::default()))).await
                }
                msg = stream.next(), if publishing.len() < MAX_PUBLISHING => {
                    heard = Instant::now();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            conn.on_message(text.as_str(), &mut queries, &mut publishing).await
                        }
                        Some(Ok(Message::Binary(_))) => conn.notice("error: binary messages are not supported").await,
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(()),
                        Some(Ok(Message::Close(_)) | Err(_)) | None => Err(Disconnect::Gone),
                    }
                }
                Some(outbound) = outbound.recv() => conn.on_outbound(outbound).await,
                Some(done) = queries.join_next(), if !queries.is_empty() => match done {
                    Ok(Done::Req(name, results)) => conn.on_results(name, results).await,
                    Ok(Done::Count(id, count)) => conn.on_count_done(&id, count).await,
                    Ok(Done::Sync(name, reconciled)) => conn.on_reconciled(name, reconciled).await,
                    // Cancelled tasks aren't aborted, and the others catch
                    // their panics.
                    Err(_) => Ok(()),
                },
                Some(done) = publishing.join_next(), if !publishing.is_empty() => match done {
                    Ok(published) => conn.on_published(published).await,
                    // Only aborted when the connection's gone.
                    Err(_) => Ok(()),
                },
            };
            if let Err(disconnect) = result {
                if disconnect == Disconnect::Stalled {
                    tracing::debug!("dropping a client that stopped reading");
                    METRICS.dropped_stalled.inc();
                }
                break;
            }
        }

        // At shutdown, answer the events being stored before closing.
        if conn.state.shutdown.is_cancelled() {
            let answer = async {
                while let Some(Ok(published)) = publishing.join_next().await {
                    if conn.on_published(published).await.is_err() {
                        break;
                    }
                }
            };
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, answer).await;
        }

        // Dropping `queries` drops their tasks, but not what they left
        // running on the blocking pool.
        conn.cancel.cancel();
        conn.state.hub.disconnect(id).await;
        let _ = tokio::time::timeout(WRITE_TIMEOUT, conn.sink.close()).await;
    }

    async fn send_raw(&mut self, text: String) -> Result<(), Disconnect> {
        write_within(self.sink.send(Message::Text(text.into()))).await
    }

    async fn send(&mut self, msg: &impl Serialize) -> Result<(), Disconnect> {
        let text = serde_json::to_string(msg).expect("relay message serialization cannot fail");
        self.send_raw(text).await
    }

    async fn send_event(&mut self, sub_id: &str, json: &str) -> Result<(), Disconnect> {
        self.send_raw(event_message(sub_id, json)).await
    }

    async fn notice(&mut self, msg: &str) -> Result<(), Disconnect> {
        self.send(&("NOTICE", msg)).await
    }

    async fn ok(&mut self, id: &str, accepted: bool, msg: &str) -> Result<(), Disconnect> {
        self.send(&("OK", id, accepted, msg)).await
    }

    async fn closed(&mut self, sub_id: &str, msg: &str) -> Result<(), Disconnect> {
        self.send(&("CLOSED", sub_id, msg)).await
    }

    async fn on_message(
        &mut self,
        text: &str,
        queries: &mut JoinSet<Done>,
        publishing: &mut JoinSet<Published>,
    ) -> Result<(), Disconnect> {
        let Ok(Value::Array(mut msg)) = serde_json::from_str::<Value>(text) else {
            return self.notice("invalid: message must be a JSON array").await;
        };

        match msg.first().and_then(Value::as_str) {
            Some("EVENT") => {
                self.on_event(msg.get_mut(1).map(Value::take), publishing)
                    .await
            }
            Some("REQ") => self.on_req(&msg[1..], queries).await,
            Some("COUNT") => self.on_count(&msg[1..], queries).await,
            Some("AUTH") => self.on_auth(msg.get_mut(1).map(Value::take)).await,
            Some("NEG-OPEN") => self.on_neg_open(&msg[1..], queries).await,
            Some("NEG-MSG") => self.on_neg_msg(&msg[1..], queries).await,
            Some("NEG-CLOSE") => match msg.get(1).and_then(Value::as_str) {
                Some(id) => {
                    self.syncs.remove(id);
                    Ok(())
                }
                None => {
                    self.notice("invalid: NEG-CLOSE requires a subscription id")
                        .await
                }
            },
            Some("CLOSE") => match msg.get(1).and_then(Value::as_str) {
                Some(sub_id) => {
                    self.end(sub_id).await;
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

    /// Check an event, then verify, judge, and store it apart from the
    /// connection's loop, which answers it once that's done.
    async fn on_event(
        &mut self,
        value: Option<Value>,
        publishing: &mut JoinSet<Published>,
    ) -> Result<(), Disconnect> {
        let Some(value) = value else {
            return self.notice("invalid: EVENT requires an event").await;
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let ev = match self.check(value) {
            Ok(ev) => ev,
            Err(msg) => {
                let refused = Published {
                    id,
                    accepted: false,
                    msg,
                    shadow: false,
                };
                return self.on_published(refused).await;
            }
        };
        let (state, peer, authed) = (self.state.clone(), self.peer, self.authed.clone());
        publishing.spawn(async move {
            let (accepted, msg, shadow) = match verify(&state, ev).await {
                Err(msg) => (false, msg, false),
                Ok(None) => (true, DUPLICATE.into(), false),
                Ok(Some(ev)) => match ask_plugin(&state, peer, &authed, &ev).await {
                    Verdict::Accept => {
                        let (accepted, msg) = accept(&state, &id, ev).await;
                        (accepted, msg, false)
                    }
                    Verdict::Reject(msg) => (false, msg.into(), false),
                    Verdict::ShadowReject(msg) => (true, msg.into(), true),
                },
            };
            Published {
                id,
                accepted,
                msg,
                shadow,
            }
        });
        Ok(())
    }

    /// Answer an event the connection published.
    async fn on_published(&mut self, published: Published) -> Result<(), Disconnect> {
        let Published {
            id,
            accepted,
            msg,
            shadow,
        } = published;
        if shadow {
            METRICS.events_shadow_rejected.inc();
            return self.ok(&id, true, &msg).await;
        }
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
    /// saying why not. Its signature is checked apart, by [`Self::verify`].
    fn check(&self, value: Value) -> Result<Event, Cow<'static, str>> {
        let ev: Event =
            serde_json::from_value(value).map_err(|err| Cow::Owned(format!("invalid: {err}")))?;
        if !event::is_relayed(ev.kind) {
            return Err(format!("blocked: kind {} is not relayed", ev.kind).into());
        }
        let author = event::decode_hex(&ev.pubkey)
            .ok_or("invalid: pubkey must be 64 lowercase hex chars")?;
        if is_protected(&ev) && !self.authed.contains(&author) {
            return Err("auth-required: this event may only be published by its author".into());
        }
        if ev.created_at > u64::from(event::now()) + self.state.config.max_future_seconds {
            return Err("invalid: created_at is too far in the future".into());
        }
        if ev.kind == VANISH && !addressed_to(&ev, &self.state.urls) {
            return Err("invalid: this request to vanish is for other relays".into());
        }
        Ok(ev)
    }

    async fn on_req(
        &mut self,
        args: &[Value],
        queries: &mut JoinSet<Done>,
    ) -> Result<(), Disconnect> {
        let config = self.state.config.clone();

        let Some(sub_id) = args.first().and_then(Value::as_str) else {
            return self.notice("invalid: REQ requires a subscription id").await;
        };
        if sub_id.is_empty() || sub_id.len() > config.max_subid_length {
            return self.closed(sub_id, "invalid: bad subscription id").await;
        }

        let filters = match self.filters(&args[1..]) {
            Ok(filters) => filters,
            Err(msg) => {
                // Whatever it would have replaced is closed too.
                self.end(sub_id).await;
                return self.closed(sub_id, &msg).await;
            }
        };
        if !self.subs.contains_key(sub_id) && self.subs.len() >= config.max_subscriptions {
            return self.closed(sub_id, "error: too many subscriptions").await;
        }

        // A REQ reusing an id replaces that subscription, stopping its
        // query. It goes live before its own query reads the store: every
        // event stored after the query's snapshot reaches it. Those that
        // arrive while the query runs are held until its EOSE, and those
        // the query saw are dropped, then and after.
        let name: Arc<str> = sub_id.into();
        let cancel = self.cancel.child_token();
        self.subs.insert(
            sub_id.to_string(),
            Subscription {
                name: name.clone(),
                pending: Some(Vec::new()),
                floor: 0,
                cancel: cancel.clone(),
            },
        );
        let installed = self
            .state
            .hub
            .subscribe(self.id, name.clone(), filters.clone())
            .await;
        let state = self.state.clone();
        queries.spawn(async move {
            let (store, search) = (state.store.clone(), state.search.clone());
            let start = Instant::now();
            let stop = cancel.clone();
            if cancel.run_until_cancelled(installed).await.is_none() {
                return Done::Req(name, Err(Cancelled.into()));
            }
            let results = run_query(&state, &cancel, move || {
                query::run(
                    &store,
                    search.as_deref(),
                    config.nip85.then_some(&state.keypair),
                    &filters,
                    config.default_limit,
                    config.max_limit,
                    &stop,
                )
            })
            .await;
            METRICS.reqs.since(start);
            Done::Req(name, results)
        });
        Ok(())
    }

    /// A REQ's results: its stored events, EOSE, then the live events that
    /// came while it ran.
    async fn on_results(
        &mut self,
        name: Arc<str>,
        results: anyhow::Result<Results>,
    ) -> Result<(), Disconnect> {
        // Closed or replaced while it ran.
        let Some(sub) = self
            .subs
            .get_mut(&*name)
            .filter(|sub| Arc::ptr_eq(&sub.name, &name))
        else {
            return Ok(());
        };
        let results = match results {
            Ok(results) => results,
            Err(err) => {
                tracing::error!("query failed: {err:#}");
                METRICS.errors_query.inc();
                self.end(&name).await;
                return self.closed(&name, "error: query failed").await;
            }
        };
        sub.floor = results.next_seq;
        let pending = sub.pending.take().unwrap_or_default();
        let sink = &mut self.sink;
        // All of it within one timeout, so a client reading just fast enough
        // to keep each message from timing out can't hold its results long.
        write_within(async move {
            for json in &results.events {
                sink.feed(Message::Text(event_message(&name, json).into()))
                    .await?;
            }
            let eose = serde_json::to_string(&("EOSE", &*name)).expect("strings serialize");
            sink.feed(Message::Text(eose.into())).await?;
            for (seq, json) in pending {
                // Stored events the query could see were sent with it.
                if seq.is_none_or(|seq| seq >= results.next_seq) {
                    sink.feed(Message::Text(event_message(&name, &json).into()))
                        .await?;
                }
            }
            sink.flush().await
        })
        .await
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
    async fn on_auth(&mut self, value: Option<Value>) -> Result<(), Disconnect> {
        let Some(value) = value else {
            return self.notice("invalid: AUTH requires an event").await;
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let ev: Event = match serde_json::from_value(value) {
            Ok(ev) => ev,
            Err(err) => return self.ok(&id, false, &format!("invalid: {err}")).await,
        };
        let Some(challenge) = &self.challenge else {
            let msg = "invalid: no challenge has been issued";
            return self.ok(&id, false, msg).await;
        };
        match auth::verify(&ev, challenge, &self.state.urls, event::now()) {
            Ok(pubkey) => {
                self.authed.insert(pubkey);
                self.ok(&id, true, "").await
            }
            Err(msg) => self.ok(&id, false, &msg).await,
        }
    }

    /// NIP-45: `["COUNT", id, filters...]`.
    async fn on_count(
        &mut self,
        args: &[Value],
        queries: &mut JoinSet<Done>,
    ) -> Result<(), Disconnect> {
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

        let (state, id) = (self.state.clone(), id.to_string());
        let cancel = self.cancel.clone();
        queries.spawn(async move {
            let (store, search) = (state.store.clone(), state.search.clone());
            let start = Instant::now();
            let stop = cancel.clone();
            let count = run_query(&state, &cancel, move || {
                query::count(&store, search.as_deref(), &filters, &stop).map(Box::new)
            })
            .await;
            METRICS.counts.since(start);
            Done::Count(id, count)
        });
        Ok(())
    }

    async fn on_count_done(
        &mut self,
        id: &str,
        count: anyhow::Result<Box<Count>>,
    ) -> Result<(), Disconnect> {
        match count {
            Ok(count) => {
                let mut body = json!({"count": count.count});
                if let Some(registers) = count.hll {
                    body["hll"] = hex::encode(registers).into();
                }
                self.send(&("COUNT", id, body)).await
            }
            Err(err) if err.is::<TooExpensive>() => {
                METRICS.counts_refused.inc();
                self.closed(id, "unsupported: too expensive to count").await
            }
            Err(err) => {
                tracing::error!("count failed: {err:#}");
                METRICS.errors_query.inc();
                self.closed(id, "error: count failed").await
            }
        }
    }

    /// NIP-77: `["NEG-OPEN", id, filter, message]`. Finds the events the
    /// filter matches, then answers the message with them.
    async fn on_neg_open(
        &mut self,
        args: &[Value],
        queries: &mut JoinSet<Done>,
    ) -> Result<(), Disconnect> {
        let config = self.state.config.clone();
        let Some(id) = args.first().and_then(Value::as_str) else {
            return self
                .notice("invalid: NEG-OPEN requires a subscription id")
                .await;
        };
        if id.is_empty() || id.len() > config.max_subid_length {
            return self.neg_err(id, "invalid: bad subscription id").await;
        }
        // One reusing an id replaces that sync.
        self.syncs.remove(id);
        if !config.negentropy {
            return self.neg_err(id, "blocked: negentropy is disabled").await;
        }
        let filter = match args.get(1) {
            Some(value @ Value::Object(_)) => self.filters(std::slice::from_ref(value)),
            _ => Err("invalid: NEG-OPEN requires a filter".into()),
        };
        let filter = match filter.map(|mut filters| filters.pop()) {
            Ok(Some(filter)) if filter.search.is_none() => filter,
            Ok(_) => {
                return self
                    .neg_err(id, "unsupported: search can't be synced")
                    .await;
            }
            Err(msg) => return self.neg_err(id, &msg).await,
        };
        let Some(msg) = args
            .get(2)
            .and_then(Value::as_str)
            .and_then(|m| hex::decode(m).ok())
        else {
            return self
                .neg_err(id, "invalid: NEG-OPEN requires a hex message")
                .await;
        };
        if self.syncs.len() >= config.max_subscriptions {
            return self.neg_err(id, "blocked: too many syncs").await;
        }

        let name: Arc<str> = id.into();
        let cancel = self.cancel.child_token();
        self.syncs.insert(
            id.to_string(),
            NegSync {
                name: name.clone(),
                storage: None,
                cancel: cancel.clone(),
            },
        );
        let state = self.state.clone();
        queries.spawn(async move {
            let store = state.store.clone();
            let start = Instant::now();
            let stop = cancel.clone();
            let reconciled = run_query(&state, &cancel, move || {
                let txn = store.read()?;
                let found =
                    query::every_id(&store, &txn, &filter, config.negentropy_max_events, &stop)?;
                drop(txn);
                let items = found.into_iter().map(|(created_at, id)| Item {
                    timestamp: created_at.into(),
                    id,
                });
                reconcile(Arc::new(Items::new(items.collect())), &msg)
            })
            .await;
            METRICS.syncs.since(start);
            Done::Sync(name, reconciled)
        });
        Ok(())
    }

    /// NIP-77: `["NEG-MSG", id, message]`.
    async fn on_neg_msg(
        &mut self,
        args: &[Value],
        queries: &mut JoinSet<Done>,
    ) -> Result<(), Disconnect> {
        let Some(id) = args.first().and_then(Value::as_str) else {
            return self
                .notice("invalid: NEG-MSG requires a subscription id")
                .await;
        };
        let Some(sync) = self.syncs.get(id) else {
            return self.neg_err(id, "closed: no such sync").await;
        };
        let Some(storage) = sync.storage.clone() else {
            self.syncs.remove(id);
            return self
                .neg_err(id, "invalid: NEG-MSG before NEG-OPEN was answered")
                .await;
        };
        let Some(msg) = args
            .get(1)
            .and_then(Value::as_str)
            .and_then(|m| hex::decode(m).ok())
        else {
            self.syncs.remove(id);
            return self
                .neg_err(id, "invalid: NEG-MSG requires a hex message")
                .await;
        };
        let (state, name, cancel) = (self.state.clone(), sync.name.clone(), sync.cancel.clone());
        queries.spawn(async move {
            let start = Instant::now();
            let reconciled = run_query(&state, &cancel, move || reconcile(storage, &msg)).await;
            METRICS.syncs.since(start);
            Done::Sync(name, reconciled)
        });
        Ok(())
    }

    /// A sync's answer to the last message, or why there isn't one.
    async fn on_reconciled(
        &mut self,
        name: Arc<str>,
        reconciled: anyhow::Result<Reconciled>,
    ) -> Result<(), Disconnect> {
        // Closed or replaced while it ran.
        let Some(sync) = self
            .syncs
            .get_mut(&*name)
            .filter(|sync| Arc::ptr_eq(&sync.name, &name))
        else {
            return Ok(());
        };
        let err = match reconciled {
            Ok(Reconciled { storage, msg }) => {
                sync.storage = Some(storage);
                return self.send(&("NEG-MSG", &*name, hex::encode(msg))).await;
            }
            Err(err) => err,
        };
        self.syncs.remove(&*name);
        if err.is::<TooExpensive>() {
            let max = self.state.config.negentropy_max_events;
            let msg = "blocked: too many events to sync";
            return self.send(&("NEG-ERR", &*name, msg, max)).await;
        }
        if let Some(err) = err.downcast_ref::<negentropy::Error>() {
            return self.neg_err(&name, &format!("invalid: {err}")).await;
        }
        tracing::error!("sync failed: {err:#}");
        METRICS.errors_query.inc();
        self.neg_err(&name, "error: sync failed").await
    }

    async fn neg_err(&mut self, id: &str, msg: &str) -> Result<(), Disconnect> {
        self.send(&("NEG-ERR", id, msg)).await
    }

    /// Close a subscription, stopping its query. One the connection doesn't
    /// have costs nothing, so a flood of them can't crowd the shards' queues.
    async fn end(&mut self, sub_id: &str) {
        if self.subs.remove(sub_id).is_some() {
            self.state.hub.unsubscribe(self.id, sub_id).await;
        }
    }

    /// A new event for one of the connection's subscriptions.
    async fn on_outbound(&mut self, outbound: Outbound) -> Result<(), Disconnect> {
        let Outbound { sub, seq, json } = outbound;
        let Some(state) = self
            .subs
            .get_mut(&*sub)
            .filter(|state| Arc::ptr_eq(&state.name, &sub))
        else {
            return Ok(());
        };
        match &mut state.pending {
            Some(pending) if pending.len() >= MAX_PENDING => {
                self.end(&sub).await;
                let msg = "error: too many new events arrived while the query ran; ask again";
                self.closed(&sub, msg).await
            }
            Some(pending) => {
                pending.push((seq, json));
                Ok(())
            }
            // Already covered by the subscription's initial query.
            None if seq.is_some_and(|seq| seq < state.floor) => Ok(()),
            None => self.send_event(&sub, &json).await,
        }
    }
}

/// The event if its id and signature are good, or None if it's stored
/// already. Both checks run on the blocking pool: the lookup can stall
/// on disk, and the signature takes a while.
async fn verify(state: &AppState, ev: Event) -> Result<Option<Event>, Cow<'static, str>> {
    let Ok(_place) = state.verifiers.acquire().await else {
        return Err("error: shutting down".into());
    };
    let store = state.store.clone();
    let verified = tokio::task::spawn_blocking(move || {
        // Events are resent all the time, and each would cost a
        // signature check, so look first: one with the stored copy's
        // signature is that event, verified when it was stored.
        let id = event::decode_hex::<32>(&ev.id);
        let sig = event::decode_hex::<64>(&ev.sig);
        if let (Some(id), Some(sig)) = (id, sig) {
            let stored = store.read().and_then(|txn| store.sig_of(&txn, &id));
            if stored.ok().flatten() == Some(sig) {
                return Ok(None);
            }
        }
        ev.verify()?;
        Ok(Some(ev))
    })
    .await;
    verified.unwrap_or_else(|err| {
        tracing::error!("verifying an event panicked: {err}");
        METRICS.errors_panic.inc();
        Err("error: failed to check event".into())
    })
}

/// What the write policy plugin makes of an event, if there is one.
async fn ask_plugin(
    state: &AppState,
    peer: Peer,
    authed: &HashSet<[u8; 32]>,
    ev: &Event,
) -> Verdict {
    let Some(plugin) = &state.plugin else {
        return Verdict::Accept;
    };
    // strfry names one pubkey: the author's, if it's among them.
    let author = event::decode_hex(&ev.pubkey).expect("verified");
    let authed = match authed.contains(&author) {
        true => Some(author),
        false => authed.iter().next().copied(),
    }
    .map(hex::encode);
    let source = plugin::Source {
        peer,
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
async fn accept(state: &AppState, id: &str, ev: Event) -> (bool, Cow<'static, str>) {
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
    if ephemeral {
        state.hub.publish(vec![Live::new(record, None)]).await;
        return (true, "".into());
    }

    // The writer sends what it stores to live subscriptions.
    match state.writer.write(record).await {
        Ok(Outcome::Stored(_)) => (true, "".into()),
        // Kept, but old news: not sent to live subscriptions.
        Ok(Outcome::Archived(_)) => (true, "".into()),
        Ok(Outcome::Duplicate) => (true, DUPLICATE.into()),
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

/// Answer a sync's message from the events it covers.
fn reconcile(storage: Arc<Items>, msg: &[u8]) -> anyhow::Result<Reconciled> {
    let msg = Negentropy::new(&storage, NEG_FRAME_SIZE).reconcile(msg)?;
    Ok(Reconciled { storage, msg })
}

/// `["EVENT", sub_id, event]`, with the event already serialized.
fn event_message(sub_id: &str, json: &str) -> String {
    let sub_id = serde_json::to_string(sub_id).expect("strings serialize");
    format!("[\"EVENT\",{sub_id},{json}]")
}

/// A write to a client, within [`WRITE_TIMEOUT`].
async fn write_within<T, E>(write: impl Future<Output = Result<T, E>>) -> Result<T, Disconnect> {
    match tokio::time::timeout(WRITE_TIMEOUT, write).await {
        Ok(Ok(written)) => Ok(written),
        Ok(Err(_)) => Err(Disconnect::Gone),
        Err(_) => Err(Disconnect::Stalled),
    }
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;

    #[test]
    fn knows_which_vanish_requests_are_its_own() {
        let to = |relay: &str| signed(1, 100, VANISH, vec![vec!["relay", relay]], "");
        let urls = ["wss://relay.example.com", "ws://relay.onion/"];
        assert!(addressed_to(&to("ALL_RELAYS"), &urls));
        assert!(addressed_to(&to("wss://relay.example.com"), &urls));
        assert!(addressed_to(&to("WSS://Relay.Example.com/"), &urls));
        assert!(addressed_to(&to("ws://relay.onion"), &urls));
        assert!(!addressed_to(&to("wss://other.example.com"), &urls));
        assert!(!addressed_to(&signed(1, 100, VANISH, vec![], ""), &urls));
    }
}
