use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

use crate::config::Config;
use crate::event::{Event, KindClass};
use crate::filter::Filter;
use crate::query;
use crate::record::{self, EventView};
use crate::store::{Outcome, Store, Writer};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub writer: Writer,
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
    pub fn new(config: Config, store: Arc<Store>) -> Self {
        Self {
            config: Arc::new(config),
            writer: Writer::spawn(store.clone()),
            store,
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
    json!({
        "name": config.name,
        "description": config.description,
        "supported_nips": [1, 11],
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
        },
    })
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
        if ev.created_at > now() + self.state.config.max_future_seconds {
            return self
                .ok(&id, false, "invalid: created_at is too far in the future")
                .await;
        }

        let record = Arc::new(record::encode(&ev));
        let json = EventView::new(&record)
            .expect("an encoded record")
            .to_json();
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
            Ok(Outcome::Duplicate) => {
                self.ok(&id, true, "duplicate: already have this event")
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

        let filters = match args[1..]
            .iter()
            .map(Filter::parse)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(filters) => filters,
            Err(msg) => return self.closed(sub_id, &msg).await,
        };
        if filters.len() > config.max_filters {
            return self.closed(sub_id, "invalid: too many filters").await;
        }
        if !self.subs.contains_key(sub_id) && self.subs.len() >= config.max_subscriptions {
            return self.closed(sub_id, "error: too many subscriptions").await;
        }
        // A REQ reusing an id replaces that subscription.
        self.subs.remove(sub_id);

        // Live events published while this runs wait in the broadcast
        // receiver, and are checked against the subscription after it's added.
        let store = self.state.store.clone();
        let query_filters = filters.clone();
        let result = tokio::task::spawn_blocking(move || {
            query::run(
                &store,
                &query_filters,
                config.default_limit,
                config.max_limit,
            )
        })
        .await;

        let results = match result {
            Ok(Ok(results)) => results,
            Ok(Err(err)) => {
                tracing::error!("query failed: {err}");
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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
