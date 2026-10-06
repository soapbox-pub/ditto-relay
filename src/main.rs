use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::serve::ListenerExt;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use ditto_relay_rs::config::Config;
use ditto_relay_rs::rank::Rank;
use ditto_relay_rs::relay::AppState;
use ditto_relay_rs::search::SearchIndex;
use ditto_relay_rs::store::{History, IndexedTags, Store};
use ditto_relay_rs::wot::Wot;
use ditto_relay_rs::{facets, metrics, relay, trends};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tantivy=warn".into()),
        )
        .init();

    let config = Config::from_env()?;
    facets::set_nsfw_hashtags(config.nsfw_hashtags.clone());
    let indexed_tags = IndexedTags::new(config.indexed_tags.clone())?;
    let history = History::new(
        config.history,
        config.history_excluded_kinds.clone(),
        config.history_max_versions,
    );
    let store = Arc::new(Store::open(
        &config.db_path,
        config.map_size,
        config.lmdb_sync,
        indexed_tags,
        history,
        Wot::new(
            config.wot_seeds.clone(),
            config.wot_damping,
            config.wot_full_trust,
            config.wot_min_weight,
            config.wot_budget,
        ),
        Rank::new(config.hot_half_life, config.rank_step, config.wot_budget),
    )?);
    tracing::info!("opened LMDB at {}", config.db_path.display());

    let search = if config.search {
        let (index, indexer) =
            SearchIndex::open(&config.search_path, config.search_kinds.clone(), &store)?;
        tracing::info!(
            "opened the search index at {}",
            config.search_path.display()
        );
        let interval = Duration::from_millis(config.search_commit_ms);
        Some((index, indexer.spawn(store.clone(), interval)))
    } else {
        None
    };

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!("listening on ws://{}", listener.local_addr()?);
    // A REQ's events and its EOSE go out as they're ready: Nagle's
    // algorithm would hold the last back until the client acknowledged
    // the rest, which with delayed ACKs is some 40 ms.
    let listener = listener.tap_io(|tcp| {
        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!("couldn't set TCP_NODELAY: {err}");
        }
    });

    let metrics = match &config.metrics_bind {
        Some(bind) => {
            let listener = TcpListener::bind(bind).await?;
            tracing::info!(
                "serving metrics on http://{}/metrics",
                listener.local_addr()?
            );
            let index = search.as_ref().map(|(index, _)| index.clone());
            let app = metrics::router(store.clone(), index);
            Some(tokio::spawn(
                async move { axum::serve(listener, app).await },
            ))
        }
        None => None,
    };

    let state = AppState::new(config, store, search);
    trends::spawn(state.clone());
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        signal().await;
        tracing::info!("shutting down");
        shutdown.cancel();
    });
    let app = relay::router(state.clone());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(state.shutdown.clone().cancelled_owned())
    .await?;
    state.shut_down().await;
    if let Some(metrics) = metrics {
        metrics.abort();
    }
    tracing::info!("shut down");

    Ok(())
}

/// Ctrl-C, or SIGTERM from a service manager.
async fn signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("a SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}
