use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;

/// Relay configuration, read from `RELAY_*` environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub db_path: PathBuf,
    /// LMDB map size in bytes. This is virtual address space, not disk usage.
    pub map_size: usize,
    pub name: String,
    pub description: String,
    pub max_message_size: usize,
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_subid_length: usize,
    pub default_limit: u64,
    pub max_limit: u64,
    /// Reject events with `created_at` further than this many seconds in the future.
    pub max_future_seconds: u64,
    /// Whether NIP-50 search is on.
    pub search: bool,
    pub search_path: PathBuf,
    /// The kinds whose text is searchable. Autocomplete covers every kind.
    pub search_kinds: Vec<u16>,
    /// How often, at most, new events become searchable.
    pub search_commit_ms: u64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            bind: env("RELAY_BIND", "127.0.0.1:7777".to_string())?,
            db_path: env("RELAY_DB_PATH", PathBuf::from("./data/db"))?,
            map_size: env("RELAY_MAP_SIZE", 1 << 40)?,
            name: env("RELAY_NAME", "ditto-relay-rs".to_string())?,
            description: env("RELAY_DESCRIPTION", String::new())?,
            max_message_size: env("RELAY_MAX_MESSAGE_SIZE", 128 * 1024)?,
            max_subscriptions: env("RELAY_MAX_SUBSCRIPTIONS", 20)?,
            max_filters: env("RELAY_MAX_FILTERS", 10)?,
            max_subid_length: env("RELAY_MAX_SUBID_LENGTH", 64)?,
            default_limit: env("RELAY_DEFAULT_LIMIT", 500)?,
            max_limit: env("RELAY_MAX_LIMIT", 500)?,
            max_future_seconds: env("RELAY_MAX_FUTURE_SECONDS", 900)?,
            search: env("RELAY_SEARCH", true)?,
            search_path: env("RELAY_SEARCH_PATH", PathBuf::from("./data/search"))?,
            search_kinds: kinds("RELAY_SEARCH_KINDS", &[0, 1, 20, 1111, 9802, 30023])?,
            search_commit_ms: env("RELAY_SEARCH_COMMIT_MS", 1000)?,
        })
    }
}

fn env<T: FromStr>(key: &str, default: T) -> anyhow::Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match std::env::var(key) {
        Ok(v) => v
            .parse()
            .with_context(|| format!("invalid value for {key}: {v:?}")),
        Err(_) => Ok(default),
    }
}

/// A comma-separated list of kinds.
fn kinds(key: &str, default: &[u16]) -> anyhow::Result<Vec<u16>> {
    match std::env::var(key) {
        Ok(v) => v
            .split(',')
            .map(|kind| kind.trim().parse())
            .collect::<Result<_, _>>()
            .with_context(|| format!("invalid value for {key}: {v:?}")),
        Err(_) => Ok(default.to_vec()),
    }
}
