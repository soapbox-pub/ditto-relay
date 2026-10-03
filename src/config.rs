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
    /// The relay's own URL, which NIP-62 requests to vanish name it by.
    pub url: Option<String>,
    pub name: String,
    pub description: String,
    /// The operator's pubkey, for NIP-11.
    pub pubkey: Option<String>,
    /// How to reach the operator, for NIP-11.
    pub contact: Option<String>,
    pub max_message_size: usize,
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_subid_length: usize,
    pub default_limit: u64,
    pub max_limit: u64,
    /// The most values one field of a filter may list.
    pub max_filter_values: usize,
    /// Reject events with `created_at` further than this many seconds in the future.
    pub max_future_seconds: u64,
    /// Tags with longer names than a letter to index, so filter by.
    pub indexed_tags: Vec<String>,
    /// Whether replaceable and addressable events keep the versions they
    /// replace, fetchable by id or by address.
    pub history: bool,
    /// Kinds whose old versions aren't kept.
    pub history_excluded_kinds: Vec<u16>,
    /// The most versions of an address kept, current included.
    pub history_max_versions: usize,
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
            bind: env("RELAY_BIND", "127.0.0.1:13131".to_string())?,
            db_path: env("RELAY_DB_PATH", PathBuf::from("./data/db"))?,
            map_size: env("RELAY_MAP_SIZE", 1 << 40)?,
            url: optional("RELAY_URL"),
            name: env("RELAY_NAME", "Ditto Relay".to_string())?,
            description: env("RELAY_DESCRIPTION", String::new())?,
            pubkey: optional("RELAY_PUBKEY"),
            contact: optional("RELAY_CONTACT"),
            max_message_size: env("RELAY_MAX_MESSAGE_SIZE", 4_000_000)?,
            max_subscriptions: env("RELAY_MAX_SUBSCRIPTIONS", 20)?,
            max_filters: env("RELAY_MAX_FILTERS", 100)?,
            max_subid_length: env("RELAY_MAX_SUBID_LENGTH", 100)?,
            default_limit: env("RELAY_DEFAULT_LIMIT", 100)?,
            max_limit: env("RELAY_MAX_LIMIT", 1000)?,
            // Generous enough for a big follow list.
            max_filter_values: env("RELAY_MAX_FILTER_VALUES", 20_000)?,
            max_future_seconds: env("RELAY_MAX_FUTURE_SECONDS", 900)?,
            // NIP-48 proxies and NIP-89 clients.
            indexed_tags: env("RELAY_INDEXED_TAGS", "proxy,client".to_string())?
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(String::from)
                .collect(),
            history: env("RELAY_HISTORY", true)?,
            // NIP-85 assertions, which change constantly.
            history_excluded_kinds: kinds(
                "RELAY_HISTORY_EXCLUDED_KINDS",
                &[30382, 30383, 30384, 30385],
            )?,
            history_max_versions: env("RELAY_HISTORY_MAX_VERSIONS", 20)?,
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

/// A variable that's unset when empty.
fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
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
