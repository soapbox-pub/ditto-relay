mod config;
mod event;
mod filter;
mod lmdb;
mod query;
mod record;
mod relay;
mod search;
mod store;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::relay::AppState;
use crate::search::SearchIndex;
use crate::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tantivy=warn".into()),
        )
        .init();

    let config = Config::from_env()?;
    let store = Arc::new(Store::open(&config.db_path, config.map_size)?);
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

    let app = relay::router(AppState::new(config, store, search));
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
