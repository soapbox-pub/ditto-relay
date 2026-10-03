mod config;
mod event;
mod filter;
mod lmdb;
mod query;
mod record;
mod relay;
mod store;

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::relay::AppState;
use crate::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env()?;
    let store = Arc::new(Store::open(&config.db_path, config.map_size)?);
    tracing::info!("opened LMDB at {}", config.db_path.display());

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!("listening on ws://{}", listener.local_addr()?);

    let app = relay::router(AppState::new(config, store));
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
