use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;

use crate::event::decode_hex;
use crate::facets;

/// Relay configuration, read from `RELAY_*` environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub db_path: PathBuf,
    /// LMDB map size in bytes. This is virtual address space, not disk usage.
    pub map_size: usize,
    /// The relay's own URL, which NIP-42 authentication and NIP-62 requests
    /// to vanish name it by.
    pub url: String,
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
    /// Kinds only parties to an event may read, once they've authenticated
    /// (NIP-42): its author, or a pubkey it tags.
    pub auth_kinds: Vec<u16>,
    /// Auth kinds anyone may read by naming their authors.
    pub auth_author_exempt_kinds: Vec<u16>,
    /// Pubkeys that, once authenticated, may read anything.
    pub master_pubkeys: Vec<[u8; 32]>,
    /// Whether NIP-50 search is on.
    pub search: bool,
    pub search_path: PathBuf,
    /// The kinds whose text is searchable. Autocomplete covers every kind.
    pub search_kinds: Vec<u16>,
    /// How often, at most, new events become searchable.
    pub search_commit_ms: u64,
    /// Hashtags that mark media as adult, for the `nsfw:` search extension.
    pub nsfw_hashtags: Vec<String>,
    /// Whom the web of trust is rooted at. None turns it off.
    pub wot_seeds: Vec<[u8; 32]>,
    /// How likely trust is to pass along a follow rather than stop.
    pub wot_damping: f64,
    /// How many people's worth of trust weighs fully.
    pub wot_full_trust: u64,
    /// The least weight counted; less is 0.
    pub wot_min_weight: f64,
    /// About how many follows to push trust along per turn of the writer.
    pub wot_budget: usize,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let pubkey = optional("RELAY_PUBKEY");
        let wot_damping = env("RELAY_WOT_DAMPING", 0.85)?;
        anyhow::ensure!(
            0.0 < wot_damping && wot_damping < 1.0,
            "RELAY_WOT_DAMPING must be between 0 and 1"
        );
        let wot_min_weight = env("RELAY_WOT_MIN_WEIGHT", 0.01)?;
        anyhow::ensure!(
            0.0 < wot_min_weight && wot_min_weight <= 1.0,
            "RELAY_WOT_MIN_WEIGHT must be above 0 and at most 1"
        );
        Ok(Self {
            bind: env("RELAY_BIND", "127.0.0.1:13131".to_string())?,
            db_path: env("RELAY_DB_PATH", PathBuf::from("./data/db"))?,
            map_size: env("RELAY_MAP_SIZE", 1 << 40)?,
            url: optional("RELAY_URL").context("RELAY_URL is required")?,
            name: env("RELAY_NAME", "Ditto Relay".to_string())?,
            description: env("RELAY_DESCRIPTION", String::new())?,
            // The operator's own follows, unless told otherwise.
            wot_seeds: match std::env::var("RELAY_WOT_SEEDS") {
                Ok(_) => pubkeys("RELAY_WOT_SEEDS")?,
                Err(_) => pubkey.as_deref().and_then(decode_hex).into_iter().collect(),
            },
            wot_damping,
            wot_full_trust: env("RELAY_WOT_FULL_TRUST", 100_000)?,
            wot_min_weight,
            wot_budget: env("RELAY_WOT_BUDGET", 10_000)?,
            pubkey,
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
            // NIP-48 proxies, NIP-89 clients, and NIP-36 content warnings.
            indexed_tags: items(&env(
                "RELAY_INDEXED_TAGS",
                "proxy,client,content-warning".to_string(),
            )?)
            .map(String::from)
            .collect(),
            history: env("RELAY_HISTORY", true)?,
            // NIP-85 assertions, which change constantly.
            history_excluded_kinds: kinds(
                "RELAY_HISTORY_EXCLUDED_KINDS",
                &[30382, 30383, 30384, 30385],
            )?,
            history_max_versions: env("RELAY_HISTORY_MAX_VERSIONS", 20)?,
            // DMs, app data, and gift wraps.
            auth_kinds: kinds("RELAY_AUTH_KINDS", &[4, 78, 1059, 30078])?,
            // Gift wraps are signed by throwaway keys, so naming the author
            // gives nothing away.
            auth_author_exempt_kinds: kinds("RELAY_AUTH_AUTHOR_EXEMPT_KINDS", &[1059])?,
            master_pubkeys: pubkeys("RELAY_MASTER_PUBKEYS")?,
            search: env("RELAY_SEARCH", true)?,
            search_path: env("RELAY_SEARCH_PATH", PathBuf::from("./data/search"))?,
            search_kinds: kinds("RELAY_SEARCH_KINDS", &[0, 1, 20, 1111, 9802, 30023])?,
            search_commit_ms: env("RELAY_SEARCH_COMMIT_MS", 1000)?,
            nsfw_hashtags: match std::env::var("RELAY_NSFW_HASHTAGS") {
                Ok(v) => items(&v).map(String::from).collect(),
                Err(_) => facets::DEFAULT_NSFW_HASHTAGS
                    .iter()
                    .map(|t| t.to_string())
                    .collect(),
            },
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

/// A comma-separated list of kinds. Empty for none.
fn kinds(key: &str, default: &[u16]) -> anyhow::Result<Vec<u16>> {
    match std::env::var(key) {
        Ok(v) => items(&v)
            .map(str::parse)
            .collect::<Result<_, _>>()
            .with_context(|| format!("invalid value for {key}: {v:?}")),
        Err(_) => Ok(default.to_vec()),
    }
}

/// A comma-separated list of hex pubkeys.
fn pubkeys(key: &str) -> anyhow::Result<Vec<[u8; 32]>> {
    let v = std::env::var(key).unwrap_or_default();
    items(&v)
        .map(|pubkey| {
            decode_hex(pubkey).with_context(|| format!("invalid pubkey in {key}: {pubkey:?}"))
        })
        .collect()
}

fn items(list: &str) -> impl Iterator<Item = &str> {
    list.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}
