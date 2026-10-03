use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};

use crate::auth::{self, Access, Authed, Refusal};
use crate::config::Config;
use crate::event::{self, Event, KindClass};
use crate::filter::Filter;
use crate::query::{self, Restricted, TooExpensive};
use crate::record::{self, EventView};
use crate::search::SearchIndex;
use crate::store::{Outcome, Store, Writer};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// Who may read what.
    pub access: Arc<Access>,
    pub store: Arc<Store>,
    pub writer: Writer,
    /// For NIP-50 search, if it's on.
    pub search: Option<Arc<SearchIndex>>,
    /// Every accepted event, for live subscriptions.
    pub live: broadcast::Sender<Arc<LiveEvent>>,
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
        Self {
            access: Arc::new(Access::new(&config)),
            config: Arc::new(config),
            writer: Writer::spawn(store.clone(), indexer),
            store,
            search,
            live: broadcast::channel(8192).0,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new().route("/", get(root)).with_state(state)
}

async fn root(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if let Ok(ws) = ws {
        let max = state.config.max_message_size;
        return ws
            .max_message_size(max)
            .max_frame_size(max)
            .on_upgrade(move |socket| Connection::run(socket, state))
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
            nip11(&state.config).to_string(),
        )
            .into_response();
    }

    "Please use a Nostr client to connect.\n".into_response()
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
    /// What this connection signs to authenticate (NIP-42).
    challenge: String,
    authed: Authed,
}

/// The connection should be torn down.
struct Disconnect;

impl Connection {
    async fn run(socket: WebSocket, state: AppState) {
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
            challenge: auth::challenge(),
            authed: Authed::new(),
        };
        if conn.send(&("AUTH", &conn.challenge)).await.is_err() {
            return;
        }

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

        let ev: Event = match serde_json::from_value(value.clone()) {
            Ok(ev) => ev,
            Err(err) => return self.ok(&id, false, &format!("invalid: {err}")).await,
        };
        if let Err(msg) = ev.verify() {
            return self.ok(&id, false, &msg).await;
        }
        if !event::is_relayed(ev.kind) {
            let msg = format!("blocked: kind {} is not relayed", ev.kind);
            return self.ok(&id, false, &msg).await;
        }
        let author = event::decode_hex(&ev.pubkey).expect("verified");
        if is_protected(&ev) && !self.authed.contains(&author) {
            let msg = "auth-required: this event may only be published by its author";
            return self.ok(&id, false, msg).await;
        }
        let now = event::now();
        if ev.created_at > u64::from(now) + self.state.config.max_future_seconds {
            return self
                .ok(&id, false, "invalid: created_at is too far in the future")
                .await;
        }

        if ev.kind == VANISH && !addressed_to(&ev, &self.state.config.url) {
            return self
                .ok(
                    &id,
                    false,
                    "invalid: this request to vanish is for other relays",
                )
                .await;
        }

        let record = Arc::new(record::encode(&ev));
        let view = EventView::new(&record).expect("an encoded record");
        if view.is_expired(now) {
            return self.ok(&id, false, EXPIRED).await;
        }
        let json = view.to_json();
        if ev.kind_class() == KindClass::Ephemeral {
            let _ = self.state.live.send(Arc::new(LiveEvent {
                seq: None,
                record,
                json,
            }));
            return self.ok(&id, true, "").await;
        }

        match self.state.writer.write(record.clone()).await {
            Ok(Outcome::Stored(seq)) => {
                let live = LiveEvent {
                    seq: Some(seq),
                    record,
                    json,
                };
                let _ = self.state.live.send(Arc::new(live));
                self.ok(&id, true, "").await
            }
            // Kept, but old news: not sent to live subscriptions.
            Ok(Outcome::Archived(_)) => self.ok(&id, true, "").await,
            Ok(Outcome::Duplicate) => {
                self.ok(&id, true, "duplicate: already have this event")
                    .await
            }
            Ok(Outcome::Expired) => self.ok(&id, false, EXPIRED).await,
            Ok(Outcome::Deleted) => {
                self.ok(&id, false, "blocked: this event has been deleted")
                    .await
            }
            Ok(Outcome::Replaced) => {
                self.ok(&id, false, "duplicate: have a newer version of this event")
                    .await
            }
            Err(err) => {
                tracing::error!("failed to store event {id}: {err:#}");
                self.ok(&id, false, "error: failed to store event").await
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
        if let Err(refusal) = self.check(&filters) {
            return self.refuse(sub_id, refusal).await;
        }
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
        let visible = self.visible();
        let result = tokio::task::spawn_blocking(move || {
            query::run(
                &store,
                search.as_deref(),
                &query_filters,
                config.default_limit,
                config.max_limit,
                visible,
            )
        })
        .await;

        let results = match result {
            Ok(Ok(results)) => results,
            Ok(Err(err)) if err.is::<Restricted>() => {
                return self.refuse(sub_id, Refusal::Results).await;
            }
            Ok(Err(err)) => {
                tracing::error!("query failed: {err:#}");
                return self.closed(sub_id, "error: query failed").await;
            }
            Err(err) => {
                tracing::error!("query task panicked: {err}");
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
        for filter in &mut filters {
            self.state.access.hide(filter, &self.authed);
        }
        for filter in filters.iter_mut().filter(|f| f.search.is_some()) {
            match &self.state.search {
                Some(search) => search.restrict(filter),
                None => return Err("unsupported: search is not enabled".into()),
            }
        }
        Ok(filters)
    }

    /// Whether the connection may run some filters.
    fn check(&self, filters: &[Filter]) -> Result<(), Refusal> {
        filters
            .iter()
            .try_for_each(|filter| self.state.access.check(filter, &self.authed))
    }

    /// Which events the connection may see, for a query.
    fn visible(&self) -> impl Fn(&EventView) -> bool + Send + 'static {
        let access = self.state.access.clone();
        let authed = self.authed.clone();
        move |event| access.may_see(event, &authed)
    }

    /// Refuse a REQ or COUNT.
    async fn refuse(&self, id: &str, refusal: Refusal) -> Result<(), Disconnect> {
        self.closed(id, refusal.message(&self.authed)).await
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
        match auth::verify(&ev, &self.challenge, &self.state.config.url, event::now()) {
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
        if let Err(refusal) = self.check(&filters) {
            return self.refuse(id, refusal).await;
        }

        let store = self.state.store.clone();
        let search = self.state.search.clone();
        let visible = self.visible();
        let result = tokio::task::spawn_blocking(move || {
            query::count(&store, search.as_deref(), &filters, visible)
        })
        .await;
        match result {
            Ok(Ok(count)) => {
                let mut body = json!({"count": count.count});
                if let Some(registers) = count.hll {
                    body["hll"] = hex::encode(registers).into();
                }
                self.send(&("COUNT", id, body)).await
            }
            Ok(Err(err)) if err.is::<Restricted>() => self.refuse(id, Refusal::Results).await,
            Ok(Err(err)) if err.is::<TooExpensive>() => {
                self.closed(id, "unsupported: too expensive to count").await
            }
            Ok(Err(err)) => {
                tracing::error!("count failed: {err:#}");
                self.closed(id, "error: count failed").await
            }
            Err(err) => {
                tracing::error!("count task panicked: {err}");
                self.closed(id, "error: count failed").await
            }
        }
    }

    async fn on_live_event(&self, ev: &LiveEvent) -> Result<(), Disconnect> {
        let view = EventView::new(&ev.record).expect("an encoded record");
        if !self.state.access.may_see(&view, &self.authed) {
            return Ok(());
        }
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
