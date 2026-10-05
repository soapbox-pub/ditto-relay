use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use secp256k1::Keypair;

use crate::event::decode_hex;
use crate::facets;

/// Relay configuration, read from `RELAY_*` environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    /// Where to serve metrics, apart from clients. None turns them off.
    pub metrics_bind: Option<String>,
    pub db_path: PathBuf,
    /// LMDB map size in bytes. This is virtual address space, not disk usage.
    pub map_size: usize,
    /// The relay's own URL, which NIP-42 authentication (to publish NIP-70
    /// protected events) and NIP-62 requests to vanish name it by.
    pub url: String,
    /// Where the relay is reached over HTTP(S), which its icon and banner
    /// are linked from.
    pub public_url: String,
    pub name: String,
    pub description: String,
    /// The operator's pubkey, for NIP-11.
    pub pubkey: Option<String>,
    /// How to reach the operator, for NIP-11.
    pub contact: Option<String>,
    /// The relay's own key, which signs the NIP-85 assertions it serves
    /// and the trends it labels. None turns them off.
    pub keypair: Option<Keypair>,
    /// How many seconds apart trends are labeled. 0 turns them off.
    pub trends_interval: u64,
    /// How many seconds a trend label is kept.
    pub trends_expiration: u32,
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
    /// About how many follows to push trust along, or targets to rescore,
    /// per turn of the writer.
    pub wot_budget: usize,
    /// How many seconds it takes `sort:hot` to halve an event's worth.
    pub hot_half_life: u32,
    /// How far an engager's weight must move before what they've engaged
    /// with is rescored.
    pub rank_step: f64,
    /// A strfry write policy plugin's command, run with `sh -c`.
    pub write_policy_plugin: Option<String>,
    /// How long the plugin may take to answer before it's restarted.
    pub write_policy_timeout_seconds: u64,
    /// The header a reverse proxy puts the client's IP in, such as
    /// `x-real-ip` or `x-forwarded-for`.
    pub real_ip_header: Option<String>,
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
        let url = optional("RELAY_URL").context("RELAY_URL is required")?;
        // ws://host is served at http://host, and wss://host at https://host.
        let public_url = optional("RELAY_PUBLIC_URL").unwrap_or_else(|| {
            url.strip_prefix("ws")
                .map_or(url.clone(), |rest| format!("http{rest}"))
        });
        anyhow::ensure!(
            public_url.starts_with("http://") || public_url.starts_with("https://"),
            "RELAY_PUBLIC_URL must be an http or https URL"
        );
        Ok(Self {
            bind: env("RELAY_BIND", "127.0.0.1:13131".to_string())?,
            metrics_bind: match std::env::var("RELAY_METRICS_BIND") {
                Ok(v) => Some(v).filter(|v| !v.is_empty()),
                Err(_) => Some("127.0.0.1:13133".to_string()),
            },
            db_path: env("RELAY_DB_PATH", PathBuf::from("./data/db"))?,
            map_size: env("RELAY_MAP_SIZE", 1 << 40)?,
            url,
            public_url,
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
            hot_half_life: env("RELAY_HOT_HALF_LIFE", 86_400)?,
            rank_step: env("RELAY_RANK_STEP", 0.05)?,
            write_policy_plugin: optional("RELAY_WRITE_POLICY_PLUGIN"),
            write_policy_timeout_seconds: env("RELAY_WRITE_POLICY_TIMEOUT_SECONDS", 10)?,
            real_ip_header: optional("RELAY_REAL_IP_HEADER"),
            pubkey,
            contact: optional("RELAY_CONTACT"),
            keypair: match optional("RELAY_SECRET_KEY") {
                Some(key) => Some(
                    decode_hex(&key)
                        .and_then(|key| Keypair::from_secret_bytes(key).ok())
                        .context("RELAY_SECRET_KEY must be a secret key in 64 lowercase hex")?,
                ),
                None => None,
            },
            trends_interval: env("RELAY_TRENDS_INTERVAL", 900)?,
            // A week of sparklines, and a day to spare.
            trends_expiration: env("RELAY_TRENDS_EXPIRATION", 8 * 86_400)?,
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
