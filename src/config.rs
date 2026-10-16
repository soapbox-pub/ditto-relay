//! The configuration file: TOML, from the path `--config` names, or else the
//! first of `$XDG_CONFIG_HOME/ditto-relay/ditto-relay.toml`
//! (`~/.config/...`) and [`SYSTEM_PATH`] that exists. A file `--config`
//! names has to exist, since naming it meant something.
//!
//! `ditto-relay.example.toml` lists every key with its default. Only `url`
//! is required.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use crate::event::decode_hex;
use crate::{facets, landing};

/// Where a system-wide relay's configuration is.
pub const SYSTEM_PATH: &str = "/etc/ditto-relay/ditto-relay.toml";
/// `data_dir` when the file doesn't say, for root.
const SYSTEM_DATA_DIR: &str = "/var/lib/ditto-relay";
/// `log` when the file doesn't say. Arti narrates its routine at info, and
/// warns of each failure of an onion service's that it retries, of which a
/// working service has dozens an hour; the relay says itself when Tor is up,
/// and when the onion has been unreachable for long.
const DEFAULT_LOG: &str =
    "info,tantivy=warn,arti_client=warn,tor_=warn,tor_hsservice=error,tor_circmgr::hspool=error";

/// The relay's configuration, resolved and validated.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    /// Where to serve metrics, apart from clients. None turns them off.
    pub metrics_bind: Option<String>,
    pub db_path: PathBuf,
    /// LMDB map size in bytes. This is virtual address space, not disk usage.
    pub map_size: usize,
    /// The relay's own URL, which NIP-42 authentication and NIP-62 requests
    /// to vanish name it by.
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
    /// The URL of the relay software's homepage, for NIP-11.
    pub software: Option<String>,
    pub icon: Image,
    pub banner: Image,
    /// Where the relay's own key is kept, which signs the NIP-85 assertions
    /// it serves and the trends it labels. Made if it's missing.
    pub secret_key_file: PathBuf,
    /// Whether NIP-85 assertions are served.
    pub nip85: bool,
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
    /// Kinds only parties to an event may read, once they've authenticated
    /// (NIP-42): its author, or a pubkey it tags. None by default.
    pub auth_kinds: Vec<u16>,
    /// Whether NIP-50 search is on.
    pub search: bool,
    pub search_path: PathBuf,
    /// The kinds whose text is searchable. Autocomplete covers every kind.
    pub search_kinds: Vec<u16>,
    /// How often, at most, new events become searchable.
    pub search_commit_ms: u64,
    /// Hashtags that mark media as adult, for the `nsfw:` search extension.
    pub nsfw_hashtags: Vec<String>,
    /// Whether NIP-77 negentropy syncing is on.
    pub negentropy: bool,
    /// The most events one sync may cover.
    pub negentropy_max_events: usize,
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
    /// What to log, as `tracing_subscriber`'s `EnvFilter` directives.
    pub log: String,
    /// Serving HTTPS itself, with a certificate it gets over ACME. None
    /// leaves TLS to a reverse proxy.
    pub tls: Option<Tls>,
    /// Serving the relay as a Tor onion service too. None turns it off.
    pub tor: Option<Tor>,
}

/// An image NIP-11 links to, as the icon or the banner.
#[derive(Debug, Clone, PartialEq)]
pub enum Image {
    /// The relay's own, linked wherever the relay is reached.
    Builtin,
    Url(String),
    None,
}

impl Image {
    /// From the key `name`'s value: unset is the relay's own, and "" none.
    fn from_file(value: Option<String>, name: &str) -> anyhow::Result<Self> {
        match value {
            None => Ok(Image::Builtin),
            Some(url) if url.is_empty() => Ok(Image::None),
            Some(url) => Ok(Image::Url(http_url(url, name)?)),
        }
    }
}

/// `url`, if it's an http or https URL, as the key `name` has to be.
fn http_url(url: String, name: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        url.starts_with("http://") || url.starts_with("https://"),
        "{name} must be an http or https URL"
    );
    Ok(url)
}

/// Serving HTTPS on `bind`, with a certificate for `public_url`'s domain
/// from an ACME CA: see [`crate::tls`].
#[derive(Debug, Clone)]
pub struct Tls {
    /// The domain the certificate is for.
    pub domain: String,
    /// Where the ACME account and the certificate are kept.
    pub dir: PathBuf,
    /// An address the CA may write to about the certificate.
    pub email: Option<String>,
    /// The URL of the CA's ACME directory.
    pub directory: String,
    /// Where plain HTTP is redirected to HTTPS, and HTTP-01 challenges are
    /// answered. None turns it off, leaving only TLS-ALPN-01.
    pub http_bind: Option<String>,
}

/// Let's Encrypt's ACME directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Serving the relay as a Tor onion service, with Tor built in: see
/// [`crate::tor`].
#[derive(Debug, Clone)]
pub struct Tor {
    /// Where Tor keeps its state and its cache.
    pub dir: PathBuf,
    /// The onion's secret key, as C Tor keeps it. Made if it's missing.
    pub key_file: PathBuf,
    /// The port the onion answers on.
    pub port: u16,
    /// Whether the landing page, over HTTPS, names the onion in an
    /// `Onion-Location` header, which Tor Browser offers to go to.
    pub onion_location: bool,
    pub client: arti_client::config::TorClientConfig,
    pub service: arti_client::config::onion_service::OnionServiceConfig,
}

/// The file as written. Every key is optional but `url`, and a key the
/// relay doesn't know is refused rather than ignored, since it's a typo.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    bind: Option<String>,
    metrics_bind: Option<String>,
    data_dir: Option<PathBuf>,
    map_size: Option<usize>,
    /// No longer used: the store is never flushed a commit at a time, and
    /// survives a crash of the machine by its checkpoints. Accepted, so a
    /// file that still sets it loads.
    #[serde(rename = "lmdb_sync")]
    _lmdb_sync: Option<serde::de::IgnoredAny>,
    url: Option<String>,
    public_url: Option<String>,
    name: Option<String>,
    description: Option<String>,
    pubkey: Option<String>,
    contact: Option<String>,
    software: Option<String>,
    icon: Option<String>,
    banner: Option<String>,
    secret_key_file: Option<PathBuf>,
    nip85: Option<bool>,
    trends_interval: Option<u64>,
    trends_expiration: Option<u32>,
    max_message_size: Option<usize>,
    max_subscriptions: Option<usize>,
    max_filters: Option<usize>,
    max_subid_length: Option<usize>,
    default_limit: Option<u64>,
    max_limit: Option<u64>,
    max_filter_values: Option<usize>,
    max_future_seconds: Option<u64>,
    indexed_tags: Option<Vec<String>>,
    history: Option<bool>,
    history_excluded_kinds: Option<Vec<u16>>,
    history_max_versions: Option<usize>,
    auth_kinds: Option<Vec<u16>>,
    search: Option<bool>,
    search_kinds: Option<Vec<u16>>,
    search_commit_ms: Option<u64>,
    nsfw_hashtags: Option<Vec<String>>,
    negentropy: Option<bool>,
    negentropy_max_events: Option<usize>,
    wot_seeds: Option<Vec<String>>,
    wot_damping: Option<f64>,
    wot_full_trust: Option<u64>,
    wot_min_weight: Option<f64>,
    wot_budget: Option<usize>,
    hot_half_life: Option<u32>,
    rank_step: Option<f64>,
    write_policy_plugin: Option<String>,
    write_policy_timeout_seconds: Option<u64>,
    real_ip_header: Option<String>,
    log: Option<String>,
    tls: Option<TlsFile>,
    tor: Option<TorFile>,
}

/// The `[tls]` table as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsFile {
    enabled: Option<bool>,
    dir: Option<PathBuf>,
    email: Option<String>,
    directory: Option<String>,
    http_bind: Option<String>,
}

/// The `[tor]` table as written. `arti` and `service` are Arti's own
/// settings, which it checks.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TorFile {
    enabled: Option<bool>,
    dir: Option<PathBuf>,
    key_file: Option<PathBuf>,
    port: Option<u16>,
    onion_location: Option<bool>,
    arti: Option<toml::Table>,
    service: Option<toml::Table>,
}

/// What the defaults depend on, read once so that tests can supply their own.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    pub root: bool,
    pub home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
}

impl Environment {
    pub fn current() -> Environment {
        // The XDG spec has relative values ignored, and an empty one is unset.
        let absolute = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        Environment {
            // SAFETY: geteuid has no preconditions and cannot fail.
            root: unsafe { libc::geteuid() } == 0,
            home: absolute("HOME"),
            xdg_config_home: absolute("XDG_CONFIG_HOME"),
            xdg_data_home: absolute("XDG_DATA_HOME"),
        }
    }

    /// The files looked for when `--config` names none, in the order tried.
    pub fn config_candidates(&self) -> Vec<PathBuf> {
        let user = self
            .xdg_config_home
            .clone()
            .or_else(|| self.home.as_ref().map(|home| home.join(".config")));
        user.map(|dir| dir.join("ditto-relay/ditto-relay.toml"))
            .into_iter()
            .chain([PathBuf::from(SYSTEM_PATH)])
            .collect()
    }

    fn default_data_dir(&self) -> anyhow::Result<PathBuf> {
        if self.root {
            return Ok(PathBuf::from(SYSTEM_DATA_DIR));
        }
        match self
            .xdg_data_home
            .clone()
            .or_else(|| self.home.as_ref().map(|home| home.join(".local/share")))
        {
            Some(dir) => Ok(dir.join("ditto-relay")),
            None => bail!(
                "neither HOME nor XDG_DATA_HOME is set, so there's no default place to keep data; set data_dir"
            ),
        }
    }
}

impl Config {
    /// Read the file `path` names, or else the first of the candidates that
    /// exists.
    pub fn load(path: Option<&Path>, env: &Environment) -> anyhow::Result<Self> {
        let source = match path {
            Some(path) => path.to_path_buf(),
            // One this user can't look into is there all the same: reading
            // it says so, where skipping it would quietly find another.
            None => env
                .config_candidates()
                .into_iter()
                .find(|candidate| match candidate.metadata() {
                    Ok(metadata) => metadata.is_file(),
                    Err(error) => error.kind() == std::io::ErrorKind::PermissionDenied,
                })
                .ok_or_else(|| not_found(env))?,
        };
        let text = std::fs::read_to_string(&source)
            .with_context(|| format!("couldn't read the config file {}", source.display()))?;
        let file: File = toml::from_str(&text)
            .with_context(|| format!("{} is not a valid config file", source.display()))?;
        Self::from_file(file, &source, env).with_context(|| format!("in {}", source.display()))
    }

    fn from_file(file: File, source: &Path, env: &Environment) -> anyhow::Result<Self> {
        // Relative paths are against the file, so they mean one place however
        // the relay was started.
        let dir = absolute(source.parent().unwrap_or(Path::new("")));
        let resolve = |path: PathBuf| absolute(&dir.join(path));

        let pubkey = file.pubkey;
        if let Some(pubkey) = &pubkey {
            decode_hex::<32>(pubkey).context("pubkey must be a pubkey in 64 lowercase hex")?;
        }
        let wot_damping = file.wot_damping.unwrap_or(0.85);
        anyhow::ensure!(
            0.0 < wot_damping && wot_damping < 1.0,
            "wot_damping must be between 0 and 1"
        );
        let wot_min_weight = file.wot_min_weight.unwrap_or(0.01);
        anyhow::ensure!(
            0.0 < wot_min_weight && wot_min_weight <= 1.0,
            "wot_min_weight must be above 0 and at most 1"
        );
        let url = file
            .url
            .context("url must be set, eg url = \"wss://relay.example.com/\"")?;
        // ws://host is served at http://host, and wss://host at https://host.
        let public_url = http_url(
            file.public_url.unwrap_or_else(|| {
                url.strip_prefix("ws")
                    .map_or(url.clone(), |rest| format!("http{rest}"))
            }),
            "public_url",
        )?;
        // An empty one leaves it out.
        let software = match file.software {
            Some(software) if software.is_empty() => None,
            Some(software) => Some(http_url(software, "software")?),
            None => Some(landing::REPOSITORY.into()),
        };
        let icon = Image::from_file(file.icon, "icon")?;
        let banner = Image::from_file(file.banner, "banner")?;
        let data_dir = match file.data_dir {
            Some(path) => resolve(path),
            None => env.default_data_dir()?,
        };
        let secret_key_file = match file.secret_key_file {
            Some(path) => resolve(path),
            None => data_dir.join("secret.key"),
        };
        // Checked when it's off too, so turning it on can't be what finds a
        // mistake.
        let tor = file.tor.unwrap_or_default();
        let tor_dir = match tor.dir {
            Some(dir) => resolve(dir),
            None => data_dir.join("tor"),
        };
        let tor_port = tor.port.unwrap_or(80);
        anyhow::ensure!(tor_port != 0, "tor.port must be a port");
        let enabled = tor.enabled.unwrap_or(false);
        let tor = Tor {
            key_file: match tor.key_file {
                Some(path) => resolve(path),
                None => tor_dir.join("hs_ed25519_secret_key"),
            },
            client: crate::tor::client_config(&tor_dir, tor.arti.unwrap_or_default())?,
            service: crate::tor::service_config(tor.service.unwrap_or_default())?,
            dir: tor_dir,
            port: tor_port,
            onion_location: tor.onion_location.unwrap_or(true),
        };
        // Checked when it's off too, as [tor] is, but for the domain, which
        // only matters with it on.
        let tls = file.tls.unwrap_or_default();
        let directory = tls.directory.unwrap_or_else(|| LETS_ENCRYPT.into());
        anyhow::ensure!(
            url::Url::parse(&directory)
                .is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some()),
            "tls.directory must be the https URL of an ACME directory, eg {LETS_ENCRYPT}"
        );
        if let Some(email) = &tls.email {
            anyhow::ensure!(
                email.contains('@') && !email.contains(char::is_whitespace),
                "tls.email must be an email address"
            );
        }
        let tls = match tls.enabled.unwrap_or(false) {
            false => None,
            true => Some(Tls {
                domain: tls_domain(&public_url)?,
                dir: match tls.dir {
                    Some(dir) => resolve(dir),
                    None => data_dir.join("tls"),
                },
                email: tls.email,
                directory,
                // An empty one turns it off.
                http_bind: match tls.http_bind {
                    Some(bind) => Some(bind).filter(|bind| !bind.is_empty()),
                    None => Some("[::]:80".into()),
                },
            }),
        };
        // Facing the internet, with TLS: `[::]` takes IPv4 as well on Linux
        // unless the host has turned that off.
        let bind = file.bind.unwrap_or_else(|| match tls {
            Some(_) => "[::]:443".into(),
            None => "127.0.0.1:13131".into(),
        });
        if let Some(http_bind) = tls.as_ref().and_then(|tls| tls.http_bind.as_ref()) {
            anyhow::ensure!(
                *http_bind != bind,
                "tls.http_bind and bind can't be the same address"
            );
        }
        Ok(Self {
            bind,
            // An empty one turns them off.
            metrics_bind: match file.metrics_bind {
                Some(bind) => Some(bind).filter(|bind| !bind.is_empty()),
                None => Some("127.0.0.1:13133".into()),
            },
            db_path: data_dir.join("db"),
            map_size: file.map_size.unwrap_or(1 << 40),
            url,
            public_url,
            name: file.name.unwrap_or_else(|| "Ditto Relay".into()),
            description: file.description.unwrap_or_default(),
            // The operator's own follows, unless told otherwise.
            wot_seeds: match file.wot_seeds {
                Some(seeds) => seeds
                    .iter()
                    .map(|seed| {
                        decode_hex(seed)
                            .with_context(|| format!("invalid pubkey in wot_seeds: {seed:?}"))
                    })
                    .collect::<anyhow::Result<_>>()?,
                None => pubkey.as_deref().and_then(decode_hex).into_iter().collect(),
            },
            wot_damping,
            wot_full_trust: file.wot_full_trust.unwrap_or(100_000),
            wot_min_weight,
            wot_budget: file.wot_budget.unwrap_or(10_000),
            hot_half_life: file.hot_half_life.unwrap_or(86_400),
            rank_step: file.rank_step.unwrap_or(0.05),
            write_policy_plugin: file.write_policy_plugin,
            write_policy_timeout_seconds: file.write_policy_timeout_seconds.unwrap_or(10),
            real_ip_header: file.real_ip_header,
            pubkey,
            contact: file.contact,
            software,
            icon,
            banner,
            secret_key_file,
            nip85: file.nip85.unwrap_or(true),
            trends_interval: file.trends_interval.unwrap_or(900),
            // A week of sparklines, and a day to spare.
            trends_expiration: file.trends_expiration.unwrap_or(8 * 86_400),
            max_message_size: file.max_message_size.unwrap_or(4_000_000),
            max_subscriptions: file.max_subscriptions.unwrap_or(20),
            max_filters: file.max_filters.unwrap_or(100),
            max_subid_length: file.max_subid_length.unwrap_or(100),
            default_limit: file.default_limit.unwrap_or(100),
            max_limit: file.max_limit.unwrap_or(1000),
            // Generous enough for a big follow list.
            max_filter_values: file.max_filter_values.unwrap_or(20_000),
            max_future_seconds: file.max_future_seconds.unwrap_or(900),
            // NIP-48 proxies, NIP-89 clients, and NIP-36 content warnings.
            indexed_tags: file.indexed_tags.unwrap_or_else(|| {
                ["proxy", "client", "content-warning"]
                    .map(String::from)
                    .into()
            }),
            history: file.history.unwrap_or(true),
            // NIP-85 assertions, which change constantly.
            history_excluded_kinds: file
                .history_excluded_kinds
                .unwrap_or_else(|| vec![30382, 30383, 30384, 30385]),
            history_max_versions: file.history_max_versions.unwrap_or(20),
            auth_kinds: file.auth_kinds.unwrap_or_default(),
            search: file.search.unwrap_or(true),
            search_path: data_dir.join("search"),
            search_kinds: file
                .search_kinds
                .unwrap_or_else(|| vec![0, 1, 20, 1111, 9802, 30023]),
            search_commit_ms: file.search_commit_ms.unwrap_or(1000),
            nsfw_hashtags: file.nsfw_hashtags.unwrap_or_else(|| {
                facets::DEFAULT_NSFW_HASHTAGS
                    .iter()
                    .map(|t| t.to_string())
                    .collect()
            }),
            negentropy: file.negentropy.unwrap_or(true),
            negentropy_max_events: file.negentropy_max_events.unwrap_or(1_000_000),
            log: file.log.unwrap_or_else(|| DEFAULT_LOG.into()),
            tls,
            tor: enabled.then_some(tor),
        })
    }
}

/// The domain `public_url` names, which a certificate can be had for if
/// it's https on the default port, and a name rather than an address.
fn tls_domain(public_url: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(public_url).ok();
    url.as_ref()
        .filter(|url| url.scheme() == "https" && url.port().is_none())
        .and_then(|url| url.domain())
        .filter(|domain| domain.contains('.'))
        .map(String::from)
        .with_context(|| {
            format!(
                "[tls] needs public_url, or url, to be https:// (wss://) on the default port at a domain name, which the certificate is for, not {public_url}"
            )
        })
}

fn not_found(env: &Environment) -> anyhow::Error {
    let tried: Vec<String> = env
        .config_candidates()
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    anyhow!(
        "no config file at {}; write one with url set (ditto-relay.example.toml lists every setting), or name one with --config",
        tried.join(" or ")
    )
}

/// `path` made absolute, lexically: it needn't exist yet.
fn absolute(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Environment {
        Environment {
            root: false,
            home: Some("/home/someone".into()),
            ..Default::default()
        }
    }

    fn config(text: &str) -> anyhow::Result<Config> {
        let file: File = toml::from_str(text)?;
        Config::from_file(file, Path::new(SYSTEM_PATH), &env())
    }

    #[test]
    fn defaults() {
        let c = config(r#"url = "wss://relay.example.com/""#).unwrap();
        assert_eq!(c.bind, "127.0.0.1:13131");
        assert_eq!(c.metrics_bind.as_deref(), Some("127.0.0.1:13133"));
        assert_eq!(c.public_url, "https://relay.example.com/");
        assert_eq!(
            c.db_path,
            Path::new("/home/someone/.local/share/ditto-relay/db")
        );
        assert_eq!(
            c.search_path,
            Path::new("/home/someone/.local/share/ditto-relay/search")
        );
        assert_eq!(
            c.secret_key_file,
            Path::new("/home/someone/.local/share/ditto-relay/secret.key")
        );
        assert!(c.nip85);
        assert!(c.wot_seeds.is_empty());
        assert_eq!(c.indexed_tags, ["proxy", "client", "content-warning"]);
        assert!(c.tor.is_none());
        assert!(c.negentropy);
        assert!(c.auth_kinds.is_empty());
        assert_eq!(c.software.as_deref(), Some(landing::REPOSITORY));
        assert_eq!((c.icon, c.banner), (Image::Builtin, Image::Builtin));
    }

    /// `lmdb_sync`, gone, is still accepted from older configs.
    #[test]
    fn loads_an_old_lmdb_sync() {
        for sync in ["true", "false"] {
            assert!(config(&format!("url = \"wss://x/\"\nlmdb_sync = {sync}")).is_ok());
        }
    }

    #[test]
    fn images_and_software_can_be_replaced_or_left_out() {
        let c = config(
            "url = \"ws://x\"\nsoftware = \"https://s.example\"\n\
             icon = \"https://i.example/i.png\"\nbanner = \"\"",
        )
        .unwrap();
        assert_eq!(c.software.as_deref(), Some("https://s.example"));
        assert_eq!(c.icon, Image::Url("https://i.example/i.png".into()));
        assert_eq!(c.banner, Image::None);
        assert!(
            config("url = \"ws://x\"\nsoftware = \"\"")
                .unwrap()
                .software
                .is_none()
        );
        assert!(config("url = \"ws://x\"\nsoftware = \"ditto-relay\"").is_err());
        assert!(config("url = \"ws://x\"\nicon = \"javascript:x\"").is_err());
    }

    #[test]
    fn tor_is_off_until_enabled() {
        let c = config("url = \"ws://x\"\n[tor]\nport = 8080").unwrap();
        assert!(c.tor.is_none());
        // Checked all the same.
        assert!(config("url = \"ws://x\"\n[tor]\nport = 0").is_err());
        assert!(config("url = \"ws://x\"\n[tor.arti]\nnope = 1").is_err());

        let c = config("url = \"ws://x\"\n[tor]\nenabled = true").unwrap();
        let tor = c.tor.unwrap();
        let dir = Path::new("/home/someone/.local/share/ditto-relay/tor");
        assert_eq!(tor.dir, dir);
        assert_eq!(tor.key_file, dir.join("hs_ed25519_secret_key"));
        assert_eq!((tor.port, tor.onion_location), (80, true));

        let c = config(
            "url = \"ws://x\"\n[tor]\nenabled = true\ndir = \"tor\"\nkey_file = \"/k\"\n\
             [tor.service]\nnum_intro_points = 5\n[tor.arti]\nvanguards.mode = \"full\"",
        )
        .unwrap();
        let tor = c.tor.unwrap();
        assert_eq!(tor.dir, Path::new("/etc/ditto-relay/tor"));
        assert_eq!(tor.key_file, Path::new("/k"));
        assert!(config("url = \"ws://x\"\n[tor]\nenabled = true\nonion = true").is_err());
    }

    #[test]
    fn tls_is_off_until_enabled() {
        let c = config("url = \"wss://relay.example.com/\"\n[tls]\nemail = \"a@b.c\"").unwrap();
        assert!(c.tls.is_none());
        assert_eq!(c.bind, "127.0.0.1:13131");
        // Checked all the same.
        assert!(config("url = \"ws://x\"\n[tls]\ndirectory = \"http://ca.example\"").is_err());
        assert!(config("url = \"ws://x\"\n[tls]\nemail = \"nope\"").is_err());

        let c = config("url = \"wss://Relay.Example.com/\"\n[tls]\nenabled = true").unwrap();
        let tls = c.tls.unwrap();
        assert_eq!(tls.domain, "relay.example.com");
        assert_eq!(
            tls.dir,
            Path::new("/home/someone/.local/share/ditto-relay/tls")
        );
        assert_eq!(tls.directory, LETS_ENCRYPT);
        assert_eq!(tls.http_bind.as_deref(), Some("[::]:80"));
        assert_eq!(c.bind, "[::]:443");

        let c = config(
            "url = \"ws://x\"\npublic_url = \"https://relay.example.com/\"\nbind = \"[::]:8443\"\n\
             [tls]\nenabled = true\ndir = \"certs\"\nhttp_bind = \"\"",
        )
        .unwrap();
        let tls = c.tls.unwrap();
        assert_eq!(tls.dir, Path::new("/etc/ditto-relay/certs"));
        assert!(tls.http_bind.is_none());
        assert_eq!(c.bind, "[::]:8443");

        // The certificate is for a domain, which clients reach over HTTPS.
        for url in [
            "ws://relay.example.com/",
            "wss://relay.example.com:8443/",
            "wss://203.0.113.1/",
            "wss://localhost/",
        ] {
            assert!(
                config(&format!("url = \"{url}\"\n[tls]\nenabled = true")).is_err(),
                "{url}"
            );
        }
        assert!(
            config("url = \"wss://relay.example.com/\"\nbind = \"[::]:80\"\n[tls]\nenabled = true")
                .is_err()
        );
    }

    #[test]
    fn seeds_default_to_the_operator() {
        let pubkey = "0461fcbecc4c3374439932d6b8f11269ccdb7cc973ad7a50ae362db135a474dd";
        let c = config(&format!("url = \"ws://x\"\npubkey = \"{pubkey}\"")).unwrap();
        assert_eq!(c.wot_seeds, [decode_hex::<32>(pubkey).unwrap()]);
        let c = config(&format!(
            "url = \"ws://x\"\npubkey = \"{pubkey}\"\nwot_seeds = []"
        ))
        .unwrap();
        assert!(c.wot_seeds.is_empty());
    }

    #[test]
    fn paths_are_relative_to_the_file() {
        let c = config("url = \"ws://x\"\ndata_dir = \"data\"").unwrap();
        assert_eq!(c.db_path, Path::new("/etc/ditto-relay/data/db"));
        let root = Environment {
            root: true,
            ..env()
        };
        let file: File = toml::from_str("url = \"ws://x\"").unwrap();
        let c = Config::from_file(file, Path::new("/x/ditto-relay.toml"), &root).unwrap();
        assert_eq!(c.db_path, Path::new("/var/lib/ditto-relay/db"));
    }

    #[test]
    fn the_secret_key_is_kept_with_the_data() {
        let c = config("url = \"ws://x\"\ndata_dir = \"data\"").unwrap();
        assert_eq!(
            c.secret_key_file,
            Path::new("/etc/ditto-relay/data/secret.key")
        );
        let c = config("url = \"ws://x\"\nsecret_key_file = \"k\"\nnip85 = false").unwrap();
        assert_eq!(c.secret_key_file, Path::new("/etc/ditto-relay/k"));
        assert!(!c.nip85);
    }

    #[test]
    fn refuses_mistakes() {
        assert!(config("").is_err());
        assert!(config("url = \"ws://x\"\npublic_url = \"ftp://x\"").is_err());
        assert!(config("url = \"ws://x\"\nwot_damping = 1.0").is_err());
        assert!(config("url = \"ws://x\"\nwot_seeds = [\"npub1\"]").is_err());
        assert!(config("url = \"ws://x\"\npubkey = \"x\"").is_err());
        assert!(config("url = \"ws://x\"\nmax_limit = \"1000\"").is_err());
        assert!(config("url = \"ws://x\"\nsearch_kinds = \"1,2\"").is_err());
        // Unknown keys, and the old environment variables' names.
        assert!(config("url = \"ws://x\"\nmax_limt = 1000").is_err());
        assert!(config("RELAY_URL = \"ws://x\"").is_err());
    }

    #[test]
    fn the_example_is_valid() {
        let c = config(include_str!("../ditto-relay.example.toml")).unwrap();
        assert_eq!(c.url, "wss://relay.example.com/");
    }

    #[test]
    fn finds_the_user_config_first() {
        let dir = tempfile::tempdir().unwrap();
        let env = Environment {
            xdg_config_home: Some(dir.path().into()),
            ..env()
        };
        assert_eq!(
            env.config_candidates(),
            [
                dir.path().join("ditto-relay/ditto-relay.toml"),
                PathBuf::from(SYSTEM_PATH)
            ]
        );
        std::fs::create_dir(dir.path().join("ditto-relay")).unwrap();
        std::fs::write(
            dir.path().join("ditto-relay/ditto-relay.toml"),
            "url = \"ws://mine\"\ndata_dir = \"d\"",
        )
        .unwrap();
        let c = Config::load(None, &env).unwrap();
        assert_eq!(c.url, "ws://mine");
        assert_eq!(c.db_path, dir.path().join("ditto-relay/d/db"));
    }

    #[test]
    fn a_named_file_has_to_exist() {
        let dir = tempfile::tempdir().unwrap();
        let error = Config::load(Some(&dir.path().join("missing.toml")), &env()).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("couldn't read the config file"),
            "{error}"
        );
    }
}
