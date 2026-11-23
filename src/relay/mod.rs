use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use secp256k1::Keypair;
use serde::Serialize;
use serde::de::IgnoredAny;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::auth::{self, Access, Authed, Refusal, Viewer};
use crate::config::{Config, Image};
use crate::event::{self, Event, KindClass};
use crate::filter::Filter;
use crate::metrics::{Connected, METRICS};
use crate::negentropy::{self, Item, Items, Negentropy};
use crate::plugin::{self, Peer, Plugin, Verdict};
use crate::query::{self, Cancelled, Count, Restricted, Results, TooExpensive};
use crate::record::{self, EventView};
use crate::search::SearchIndex;
use crate::store::{Outcome, Store, Writer};
use crate::{key, landing};
use counts::Counts;
use monitors::{ConnId, Hub, Link, Live, Outbound};
use preparers::Preparers;
use queue::Queue;

mod counts;
mod monitors;
mod preparers;
mod queue;
mod stats;
mod ws;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// Who may read what.
    access: Arc<Access>,
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
    /// The threads that ready events to store.
    preparers: Arc<Preparers>,
    /// A place per core for queries. A REQ or COUNT waits its turn, rather
    /// than being refused, when every core is busy.
    queries: Arc<Semaphore>,
    /// Counts being made, or kept, for every connection asking for them.
    counts: Counts,
    /// The most records a REQ answered where it's asked may examine: see
    /// [`query::quick`].
    quick_budget: usize,
    /// What the relay is called by: its URL, and its onion's.
    urls: Arc<[String]>,
    /// What's served to clients at the relay's URL, and at its onion's, if
    /// it's an onion service too.
    clearnet: Arc<Pages>,
    onion: Option<Arc<Pages>>,
    /// Where Tor Browser is told to find the onion.
    onion_location: Option<HeaderValue>,
    /// The live numbers the landing page shows.
    stats: Arc<stats::Stats>,
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
        // A banner of the operator's own previews the page, else the silk.
        let og_image = match &config.banner {
            Image::Url(url) => url.clone(),
            _ => landing::asset_url(public_url, "/og.jpg"),
        };
        Self {
            landing: landing::render(&info, url, Some(&og_image)).into(),
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
        search: Option<(
            Arc<SearchIndex>,
            std::sync::mpsc::Sender<crate::store::Written>,
        )>,
        onion: Option<String>,
    ) -> Self {
        let (search, indexer) = search.unzip();
        std::sync::LazyLock::force(&crate::metrics::STARTED);
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
        let writer = Writer::spawn(store.clone(), indexer, stored);
        Self {
            plugin,
            urls,
            clearnet: Arc::new(clearnet),
            onion: onion_pages,
            onion_location,
            access: Arc::new(Access::new(&config)),
            config: Arc::new(config),
            keypair,
            writer,
            preparers: Arc::new(Preparers::new(cores())),
            store,
            search,
            hub,
            next_conn: Arc::new(AtomicU64::new(1)),
            shutdown: CancellationToken::new(),
            connections: TaskTracker::new(),
            queries: Arc::new(Semaphore::new(cores())),
            counts: Counts::default(),
            quick_budget: query::QUICK_BUDGET,
            stats: Arc::default(),
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
        .route("/stats", get(stats).options(|| async { CORS }))
        .route("/favicon.ico", asset("image/x-icon", landing::FAVICON))
        .route("/icon.png", asset("image/png", landing::ICON))
        .route("/banner.jpg", asset("image/jpeg", landing::BANNER))
        .route("/og.jpg", asset("image/jpeg", landing::OG_IMAGE))
        .with_state(Arc::new(state))
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

async fn root(
    State(state): State<Arc<AppState>>,
    via: Via,
    headers: HeaderMap,
    ws: Result<ws::Upgrade, axum::http::StatusCode>,
) -> Response {
    if let Ok(ws) = ws {
        let max = state.config.max_message_size;
        // A header over Tor is the client's own, and can't be trusted.
        let peer = match via {
            Via::Socket(peer) => Peer::Ip(client_ip(&state.config, &headers, peer)),
            Via::Tor => Peer::Tor,
        };
        return ws.on_upgrade(max, move |reader, writer| {
            let connections = state.connections.clone();
            connections.track_future(Connection::run(reader, writer, state, peer))
        });
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

/// The live numbers the landing page shows: events stored, connections
/// open, queries answered and how long they've lately taken, and uptime.
async fn stats(State(state): State<Arc<AppState>>) -> Response {
    let (stats, store) = (state.stats.clone(), state.store.clone());
    match tokio::task::spawn_blocking(move || stats.json(&store)).await {
        Ok(Ok(json)) => (
            CORS,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            json,
        )
            .into_response(),
        Ok(Err(err)) => {
            tracing::error!("reading stats failed: {err:#}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
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
/// The longest message parsed on the connection's task, rather than on the
/// blocking pool.
const PARSE_HERE: usize = 64 * 1024;

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

/// How many events a sync may cover for its messages to be answered on the
/// connection's thread, for each record a REQ answered there may examine:
/// an event is an id, summed into fingerprints.
const SYNC_ITEMS_PER_RECORD: usize = 32;

/// How an event a connection published was answered, once it's been
/// verified, judged, and stored.
struct Published {
    id: String,
    accepted: bool,
    msg: Cow<'static, str>,
    /// Shadow-rejected: told it was accepted, but not counted as such.
    shadow: bool,
}

/// An event the connection published, stored without a task of its own,
/// to be answered to it: with an error, if it's dropped unanswered, as by
/// a thread that panicked.
struct Unanswered {
    id: Option<String>,
    answers: Arc<Queue<Published>>,
}

impl Unanswered {
    fn id(&self) -> &str {
        self.id.as_deref().unwrap_or_default()
    }

    fn answer(mut self, (accepted, msg): (bool, Cow<'static, str>)) {
        let id = self.id.take().unwrap_or_default();
        self.answers.push(Published {
            id,
            accepted,
            msg,
            shadow: false,
        });
    }
}

impl Drop for Unanswered {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.answers.push(Published {
                id,
                accepted: false,
                msg: "error: failed to store event".into(),
                shadow: false,
            });
        }
    }
}

struct Subscription {
    /// This REQ's own name: a later REQ of the same id gets a new one, so
    /// results meant for the one it replaced can be told apart.
    name: Arc<str>,
    /// Live events that arrived while the query ran, by sequence number,
    /// held until its EOSE. None once it's sent.
    pending: Option<Vec<(Option<u64>, Arc<String>)>>,
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
    /// Shared with every other: a connection's own copy was 320 bytes.
    state: Arc<AppState>,
    id: ConnId,
    /// By subscription id.
    subs: HashMap<String, Subscription>,
    /// By their own ids, apart from subscriptions'.
    syncs: HashMap<String, NegSync>,
    /// Stops every query of the connection's once it's gone, or the relay
    /// is shutting down.
    cancel: CancellationToken,
    sink: ws::Writer,
    peer: Peer,
    /// What this connection signs to authenticate (NIP-42), once it's
    /// been asked to: when it's refused something for want of it.
    challenge: Option<String>,
    /// The pubkeys the connection has authenticated as.
    authed: Authed,
    /// Whether what's sent waits in the sink to be flushed with more.
    corked: bool,
    /// What the connection's closed with: normally, or as it broke the
    /// protocol.
    close_code: u16,
    /// Where the events it publishes are answered, when they're stored
    /// without a task of their own: see [`Self::publish`].
    answers: Arc<Queue<Published>>,
    /// How many of those are being stored.
    in_flight: usize,
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
    async fn run(mut stream: ws::Reader, sink: ws::Writer, state: Arc<AppState>, peer: Peer) {
        let _connected = Connected::new();
        let id = state.next_conn.fetch_add(1, Ordering::Relaxed);
        let (link, outbound) = Link::new(OUTBOUND, Some(sink.direct()));
        state.hub.connect(id, link);
        let start = tokio::time::Instant::now() + PING_INTERVAL;
        let mut ping = tokio::time::interval_at(start, PING_INTERVAL);
        let mut heard = Instant::now();
        let mut queries = JoinSet::new();
        // Events being stored apart from the loop, so a slow write holds up
        // only its own OK, not the connection's queries and live events.
        let mut publishing = JoinSet::new();
        let answers = Queue::new();
        let answered = answers.clone();
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
            authed: Authed::new(),
            corked: false,
            close_code: 1000,
            answers,
            in_flight: 0,
        };

        loop {
            let result = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ping.tick() => {
                    // One waiting on its own events to be stored isn't silent.
                    if heard.elapsed() > 2 * PING_INTERVAL && publishing.is_empty() && conn.in_flight == 0 {
                        tracing::debug!("dropping a client that went silent");
                        METRICS.dropped_silent.inc();
                        break;
                    }
                    conn.sink.ping();
                    write_within(conn.sink.flush()).await
                }
                msg = stream.next(), if publishing.len() + conn.in_flight < MAX_PUBLISHING => {
                    heard = Instant::now();
                    // Boxed: what handling a message takes is most of what
                    // a connection would hold all the time.
                    let mut result =
                        Box::pin(conn.on_frame(msg, &mut queries, &mut publishing)).await;
                    // The rest read with it.
                    while result.is_ok()
                        && publishing.len() + conn.in_flight < MAX_PUBLISHING
                        && let Some(msg) = stream.try_next()
                    {
                        result =
                            Box::pin(conn.on_frame(Some(msg), &mut queries, &mut publishing))
                                .await;
                    }
                    result
                }
                next = outbound.next() => match next {
                    Some(next) => {
                        let result = conn.on_outbound(next).await;
                        outbound.handled();
                        result
                    }
                    None => {
                        tracing::debug!("dropping a client that fell too far behind");
                        METRICS.dropped_behind.inc();
                        break;
                    }
                },
                // What a shard sent directly, and the socket didn't take.
                _ = conn.sink.wanted() => write_within(conn.sink.flush()).await,
                Some(done) = queries.join_next(), if !queries.is_empty() => match done {
                    Ok(Done::Req(name, results)) => conn.on_results(name, results).await,
                    Ok(Done::Count(id, count)) => conn.on_count_done(&id, count).await,
                    Ok(Done::Sync(name, reconciled)) => conn.on_reconciled(name, reconciled).await,
                    // Cancelled tasks aren't aborted, and the others catch
                    // their panics.
                    Err(_) => Ok(()),
                },
                Some(published) = answered.next() => {
                    // Every one stored by now, sent at once.
                    conn.corked = true;
                    let mut next = Some(published);
                    let mut result = Ok(());
                    while let Some(published) = next.take()
                        && result.is_ok()
                    {
                        conn.in_flight -= 1;
                        result = conn.on_published(published).await;
                        next = answered.pop();
                    }
                    conn.corked = false;
                    match result {
                        Ok(()) => write_within(conn.sink.flush()).await,
                        Err(err) => Err(err),
                    }
                }
                Some(done) = publishing.join_next(), if !publishing.is_empty() => {
                    // The OKs of every event stored by now, sent at once:
                    // the writer stores many in a batch.
                    conn.corked = true;
                    let mut done = Some(done);
                    let mut result = Ok(());
                    while let Some(next) = done.take()
                        && result.is_ok()
                    {
                        result = match next {
                            Ok(published) => conn.on_published(published).await,
                            // Only aborted when the connection's gone.
                            Err(_) => Ok(()),
                        };
                        done = publishing.try_join_next();
                    }
                    conn.corked = false;
                    match result {
                        Ok(()) => write_within(conn.sink.flush()).await,
                        Err(err) => Err(err),
                    }
                }
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
                        return;
                    }
                }
                while conn.in_flight > 0
                    && let Some(published) = answered.next().await
                {
                    conn.in_flight -= 1;
                    if conn.on_published(published).await.is_err() {
                        return;
                    }
                }
            };
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, answer).await;
        }

        // Dropping `queries` drops their tasks, but not what they left
        // running on the blocking pool.
        conn.cancel.cancel();
        conn.state.hub.disconnect(id);
        conn.sink.close(conn.close_code);
        let _ = tokio::time::timeout(WRITE_TIMEOUT, conn.sink.shutdown()).await;
    }

    /// A message from the client, or the end of them.
    async fn on_frame(
        &mut self,
        msg: Option<Result<ws::Message, ws::Error>>,
        queries: &mut JoinSet<Done>,
        publishing: &mut JoinSet<Published>,
    ) -> Result<(), Disconnect> {
        match msg {
            Some(Ok(ws::Message::Text(text))) => self.on_message(text, queries, publishing).await,
            Some(Ok(ws::Message::Binary)) => {
                self.notice("error: binary messages are not supported")
                    .await
            }
            Some(Ok(ws::Message::Ping(payload))) => {
                self.sink.pong(&payload);
                self.flush_uncorked().await
            }
            Some(Ok(ws::Message::Pong)) => Ok(()),
            Some(Ok(ws::Message::Close)) | None => Err(Disconnect::Gone),
            Some(Err(err)) => {
                tracing::debug!("dropping a client: {err}");
                self.close_code = err.code();
                Err(Disconnect::Gone)
            }
        }
    }

    async fn send_raw(&mut self, text: String) -> Result<(), Disconnect> {
        self.sink.text(&text);
        self.flush_uncorked().await
    }

    /// Send what's framed, unless more is to go with it.
    async fn flush_uncorked(&mut self) -> Result<(), Disconnect> {
        match self.corked {
            true => Ok(()),
            false => write_within(self.sink.flush()).await,
        }
    }

    async fn send(&mut self, msg: &impl Serialize) -> Result<(), Disconnect> {
        let text = serde_json::to_string(msg).expect("relay message serialization cannot fail");
        self.send_raw(text).await
    }

    async fn send_event(&mut self, sub_id: &str, json: &str) -> Result<(), Disconnect> {
        self.sink.event(&quoted(sub_id), json);
        self.flush_uncorked().await
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

    /// Challenge the connection to authenticate, if it hasn't been yet and
    /// `msg` refuses it something for want of that.
    async fn challenge_for(&mut self, msg: &str) -> Result<(), Disconnect> {
        if msg.starts_with("auth-required:") && self.challenge.is_none() {
            let challenge = auth::challenge();
            self.send(&("AUTH", &challenge)).await?;
            self.challenge = Some(challenge);
        }
        Ok(())
    }

    /// Refuse a REQ or COUNT.
    async fn refuse(&mut self, id: &str, refusal: Refusal) -> Result<(), Disconnect> {
        let msg = refusal.message(&self.authed);
        self.challenge_for(msg).await?;
        self.closed(id, msg).await
    }

    async fn on_message(
        &mut self,
        text: ws::Text,
        queries: &mut JoinSet<Done>,
        publishing: &mut JoinSet<Published>,
    ) -> Result<(), Disconnect> {
        // Most are events: read straight into one, if it's well formed,
        // rather than into JSON values first.
        if text.len() <= PARSE_HERE
            && text.trim_start().starts_with("[\"EVENT\"")
            && let Ok((_, ev)) = serde_json::from_str::<(IgnoredAny, Event)>(&text)
        {
            return self.on_event_parsed(ev, publishing).await;
        }
        // A big message takes milliseconds to parse: on the blocking pool,
        // so it holds up only the connection that sent it.
        let parsed = match text.len() <= PARSE_HERE {
            true => serde_json::from_str::<Value>(&text).ok(),
            false => tokio::task::spawn_blocking(move || serde_json::from_str::<Value>(&text).ok())
                .await
                .ok()
                .flatten(),
        };
        let Some(Value::Array(mut msg)) = parsed else {
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
        let ev = serde_json::from_value(value)
            .map_err(|err| Cow::Owned(format!("invalid: {err}")))
            .and_then(|ev| self.check(ev));
        self.publish(id, ev, publishing).await
    }

    /// As [`on_event`](Self::on_event), with the event read.
    async fn on_event_parsed(
        &mut self,
        ev: Event,
        publishing: &mut JoinSet<Published>,
    ) -> Result<(), Disconnect> {
        let id = ev.id.clone();
        let ev = self.check(ev);
        self.publish(id, ev, publishing).await
    }

    /// Store an event checked, apart from the loop, or say why it isn't.
    async fn publish(
        &mut self,
        id: String,
        ev: Result<Event, Cow<'static, str>>,
        publishing: &mut JoinSet<Published>,
    ) -> Result<(), Disconnect> {
        let ev = match ev {
            Ok(ev) if self.state.plugin.is_none() => return self.publish_now(id, ev).await,
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
            let (accepted, msg, shadow) = publish(&state, peer, &authed, &id, ev).await;
            Published {
                id,
                accepted,
                msg,
                shadow,
            }
        });
        Ok(())
    }

    /// Publish an event without a task of its own: checked and encoded by
    /// the preparers, which hand it to the writer, which answers it to the
    /// connection, with others stored with it, or, if it's ephemeral, to
    /// live subscriptions themselves. With no plugin to ask.
    async fn publish_now(&mut self, id: String, ev: Event) -> Result<(), Disconnect> {
        if is_stored(&self.state, &ev) {
            let published = Published {
                id,
                accepted: true,
                msg: DUPLICATE.into(),
                shadow: false,
            };
            return self.on_published(published).await;
        }
        let unanswered = Unanswered {
            id: Some(id.clone()),
            answers: self.answers.clone(),
        };
        let (writer, hub) = (self.state.writer.clone(), self.state.hub.clone());
        let readied = self.state.preparers.ready_then(ev, move |ready| {
            let record = match ready {
                Ok(record) => record,
                Err(msg) => return unanswered.answer((false, msg)),
            };
            let view = EventView::new(&record).expect("an encoded record");
            if view.is_expired(event::now()) {
                return unanswered.answer((false, EXPIRED.into()));
            }
            if KindClass::of(view.kind()) == KindClass::Ephemeral {
                hub.broadcast(vec![Live::new(record, None)]);
                return unanswered.answer((true, "".into()));
            }
            writer.write_now(
                record,
                Instant::now(),
                Box::new(move |outcome| {
                    let said = said(outcome, unanswered.id());
                    unanswered.answer(said)
                }),
            );
        });
        match readied {
            Ok(()) => {
                self.in_flight += 1;
                Ok(())
            }
            Err(msg) => {
                let refused = Published {
                    id,
                    accepted: false,
                    msg,
                    shadow: false,
                };
                self.on_published(refused).await
            }
        }
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
        self.challenge_for(&msg).await?;
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
    fn check(&self, ev: Event) -> Result<Event, Cow<'static, str>> {
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
        if let Err(refusal) = self.may_run(&filters) {
            self.end(sub_id).await;
            return self.refuse(sub_id, refusal).await;
        }
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
        let viewer = self.viewer();
        self.state
            .hub
            .subscribe(self.id, name.clone(), filters.clone(), viewer.clone());
        // Events go out live just before they're committed: what's gone out
        // before the subscription was made is read once it is.
        self.state.store.settle().await;
        // A small query is answered here and now. The live events that
        // arrive meanwhile wait in the connection's queue, and those it
        // saw are dropped from there.
        let start = Instant::now();
        let relay = config
            .nip85
            .then(|| self.state.keypair.x_only_public_key().0.to_byte_array());
        let quick = query::quick(
            &self.state.store,
            relay.as_ref(),
            &filters,
            config.default_limit,
            config.max_limit,
            visible(viewer.clone()),
            self.state.quick_budget,
        );
        match quick {
            Ok(None) => {}
            Ok(Some(results)) => {
                METRICS.reqs.since(start);
                return self.on_results(name, Ok(results)).await;
            }
            Err(err) => return self.on_results(name, Err(err)).await,
        }
        let state = self.state.clone();
        queries.spawn(async move {
            let (store, search) = (state.store.clone(), state.search.clone());
            let stop = cancel.clone();
            let keys = state.clone();
            let results = run_query(&state, &cancel, move || {
                query::run(
                    &store,
                    search.as_deref(),
                    config.nip85.then_some(&keys.keypair),
                    &filters,
                    config.default_limit,
                    config.max_limit,
                    visible(viewer),
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
            Err(err) if err.is::<Restricted>() => {
                self.end(&name).await;
                return self.refuse(&name, Refusal::Results).await;
            }
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
        let quoted = quoted(&name);
        for json in &results.events {
            sink.event(&quoted, json);
        }
        let eose = serde_json::to_string(&("EOSE", &*name)).expect("strings serialize");
        sink.text(&eose);
        for (seq, json) in pending {
            // Stored events the query could see were sent with it.
            if seq.is_none_or(|seq| seq >= results.next_seq) {
                sink.event(&quoted, &json);
            }
        }
        // What comes next may be sent straight from the shards, after this.
        self.state.hub.go_live(self.id, &name, results.next_seq);
        // All of it within one timeout, so a client reading just fast enough
        // to keep each message from timing out can't hold its results long.
        write_within(sink.flush()).await
    }

    /// A REQ's, COUNT's, or sync's filters, with the kinds the connection
    /// may not read hidden, or why they're refused.
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
        // Before a search is kept from the excluded kinds, which adds to
        // the hidden ones.
        for filter in &mut filters {
            self.state.access.hide(filter);
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

    /// Whether the connection may run some filters.
    fn may_run(&self, filters: &[Filter]) -> Result<(), Refusal> {
        filters
            .iter()
            .try_for_each(|filter| self.state.access.check(filter, &self.authed))
    }

    /// Which events the connection may see, unless it may see them all.
    fn viewer(&self) -> Option<Viewer> {
        self.state.access.viewer(&self.authed)
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
        if let Err(refusal) = self.may_run(&filters) {
            return self.refuse(id, refusal).await;
        }

        // Every event that's gone out live, counted.
        self.state.store.settle().await;
        // A count LMDB keeps, or of a few entries, is answered here and now.
        let start = Instant::now();
        let budget = self.state.quick_budget * query::COUNT_LOADS_PER_RECORD;
        match query::quick_count(&self.state.store, &filters, budget) {
            Ok(None) => {}
            Ok(Some(count)) => {
                METRICS.counts.since(start);
                return self.on_count_done(id, Ok(Box::new(count))).await;
            }
            Err(err) => return self.on_count_done(id, Err(err)).await,
        }
        let (state, id, viewer) = (self.state.clone(), id.to_string(), self.viewer());
        let cancel = self.cancel.clone();
        queries.spawn(async move {
            let (store, search) = (state.store.clone(), state.search.clone());
            let stop = cancel.clone();
            let shared = filters.clone();
            let make = || {
                run_query(&state, &cancel, move || {
                    query::count(&store, search.as_deref(), &filters, visible(viewer), &stop)
                })
            };
            let count = cancel
                .run_until_cancelled(state.counts.get(&shared, make))
                .await
                .unwrap_or_else(|| Err(Cancelled.into()))
                .map(Box::new);
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
            Err(err) if err.is::<Restricted>() => self.refuse(id, Refusal::Results).await,
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
        if let Err(refusal) = self.may_run(std::slice::from_ref(&filter)) {
            let msg = refusal.message(&self.authed);
            self.challenge_for(msg).await?;
            return self.neg_err(id, msg).await;
        }
        let Some(msg) = args
            .get(2)
            .and_then(Value::as_str)
            .and_then(event::decode_hex_vec)
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
        // Every event that's gone out live, synced.
        self.state.store.settle().await;
        // A sync of a few thousand events is answered here and now.
        let start = Instant::now();
        let max = config.negentropy_max_events;
        let budget =
            self.state.quick_budget * SYNC_ITEMS_PER_RECORD / query::COUNT_LOADS_PER_RECORD;
        let viewer = self.viewer();
        match query::quick_ids(
            &self.state.store,
            &filter,
            max,
            visible(viewer.clone()),
            budget,
        ) {
            Ok(None) => {}
            Ok(Some(found)) => {
                let items = found.into_iter().map(|(created_at, id)| Item {
                    timestamp: created_at.into(),
                    id,
                });
                let reconciled = reconcile(Arc::new(Items::new(items.collect())), &msg);
                METRICS.syncs.since(start);
                return self.on_reconciled(name, reconciled).await;
            }
            Err(err) => return self.on_reconciled(name, Err(err)).await,
        }
        let state = self.state.clone();
        queries.spawn(async move {
            let store = state.store.clone();
            let stop = cancel.clone();
            let reconciled = run_query(&state, &cancel, move || {
                let txn = store.read()?;
                let found = query::every_id(&store, &txn, &filter, max, visible(viewer), &stop)?;
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
            .and_then(event::decode_hex_vec)
        else {
            self.syncs.remove(id);
            return self
                .neg_err(id, "invalid: NEG-MSG requires a hex message")
                .await;
        };
        // A sync of a few thousand events is answered here and now.
        if storage.len() <= self.state.quick_budget * SYNC_ITEMS_PER_RECORD {
            let (name, start) = (sync.name.clone(), Instant::now());
            let reconciled = reconcile(storage, &msg);
            METRICS.syncs.since(start);
            return self.on_reconciled(name, reconciled).await;
        }
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
                return self
                    .send(&("NEG-MSG", &*name, record::encode_hex(&msg)))
                    .await;
            }
            Err(err) => err,
        };
        self.syncs.remove(&*name);
        if err.is::<Restricted>() {
            let msg = Refusal::Results.message(&self.authed);
            self.challenge_for(msg).await?;
            return self.neg_err(&name, msg).await;
        }
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
    /// have costs nothing, so a flood of them can't keep its shard locked.
    async fn end(&mut self, sub_id: &str) {
        if self.subs.remove(sub_id).is_some() {
            self.state.hub.unsubscribe(self.id, sub_id);
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

/// Verify, judge, and store an event: whether it's accepted, the OK
/// message's text, and whether it was shadow-rejected.
async fn publish(
    state: &AppState,
    peer: Peer,
    authed: &Authed,
    id: &str,
    ev: Event,
) -> (bool, Cow<'static, str>, bool) {
    if is_stored(state, &ev) {
        return (true, DUPLICATE.into(), false);
    }
    // Checking the signature, many at once, and encoding, which guesses
    // the language and sentiment, are done by the preparers, off the
    // runtime's threads, where they'd hold up every other connection's
    // reads. With a plugin to ask, the signature is checked first, on a
    // trip of its own.
    let ev = match &state.plugin {
        None => ev,
        Some(_) => {
            let ev = match state.preparers.check(ev).await {
                Ok(ev) => ev,
                Err(msg) => return (false, msg, false),
            };
            match ask_plugin(state, peer, authed, &ev).await {
                Verdict::Accept => ev,
                Verdict::Reject(msg) => return (false, msg.into(), false),
                Verdict::ShadowReject(msg) => return (true, msg.into(), true),
            }
        }
    };
    match state.preparers.ready(ev, state.plugin.is_some()).await {
        Ok(record) => {
            let (accepted, msg) = accept(state, id, record, Instant::now()).await;
            (accepted, msg, false)
        }
        Err(msg) => (false, msg, false),
    }
}

/// Whether an event is stored already: events are resent all the time,
/// and each would cost a signature check, so this is looked up first, and
/// here and now, as small queries are (see [`query::quick`]). One with
/// the stored copy's signature is that event, verified when it was stored.
fn is_stored(state: &AppState, ev: &Event) -> bool {
    let id = event::decode_hex::<32>(&ev.id);
    let sig = event::decode_hex::<64>(&ev.sig);
    let (Some(id), Some(sig)) = (id, sig) else {
        return false;
    };
    let store = &state.store;
    let stored = store.read().and_then(|txn| store.sig_of(&txn, &id));
    stored.ok().flatten() == Some(sig)
}

/// What the write policy plugin makes of an event, if there is one.
async fn ask_plugin(state: &AppState, peer: Peer, authed: &Authed, ev: &Event) -> Verdict {
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

/// Stores an encoded event, its write begun at `start`, or sends it to
/// live subscriptions, with a NIP-01 OK message.
async fn accept(
    state: &AppState,
    id: &str,
    record: Arc<Vec<u8>>,
    start: Instant,
) -> (bool, Cow<'static, str>) {
    let view = EventView::new(&record).expect("an encoded record");
    if view.is_expired(event::now()) {
        return (false, EXPIRED.into());
    }
    if KindClass::of(view.kind()) == KindClass::Ephemeral {
        state.hub.publish(vec![Live::new(record, None)]).await;
        return (true, "".into());
    }

    // The writer sends what it stores to live subscriptions.
    said(state.writer.write_from(record, start).await, id)
}

/// What to say of a write's outcome, in an OK message.
fn said(outcome: anyhow::Result<Outcome>, id: &str) -> (bool, Cow<'static, str>) {
    match outcome {
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

/// Whether a query may return an event, for a connection that may see only
/// what `viewer` lets it, if there's one.
fn visible(viewer: Option<Viewer>) -> impl Fn(&EventView) -> bool {
    move |event| viewer.as_ref().is_none_or(|viewer| viewer.may_see(event))
}

/// A subscription id as JSON.
fn quoted(sub_id: &str) -> String {
    serde_json::to_string(sub_id).expect("strings serialize")
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
