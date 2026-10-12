//! Serving the relay as a Tor onion service, with Tor built in: Arti, the Tor
//! Project's own implementation in Rust, runs inside the relay, so there is
//! no daemon to install and no control port to secure.
//!
//! The relay keeps the onion's key, in a file of C Tor's format, and Tor
//! keeps nothing. Arti's keystore is the in-memory one, and the service is
//! launched with the key from the file, which is what makes the address
//! survive a restart, and what lets a `HiddenServiceDir`'s address move here
//! with its key. What Arti does keep on disk, its directory cache and its
//! guards, makes it faster and safer to come back, but losing it costs no
//! address.
//!
//! Streams arrive as Arti's, not as sockets, and are served by the same
//! router as clearnet clients, through [`OnionListener`].

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use arti_client::config::onion_service::{OnionServiceConfig, OnionServiceConfigBuilder};
use arti_client::config::{TorClientConfig, TorClientConfigBuilder};
use arti_client::{DataStream, TorClient};
use axum::Router;
use futures_util::{Stream, StreamExt};
use safelog::DisplayRedacted;
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_config::ExplicitOrAuto;
use tor_config_path::CfgPath;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsservice::status::{OnionServiceStatusStream, Problem};
use tor_hsservice::{HsIdKeypairSpecifier, HsNickname, RunningOnionService, StreamRequest};
use tor_keymgr::KeystoreSelector;
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519;
use tor_proto::stream::IncomingStreamRequest;

use crate::config;

type Client = TorClient<tor_rtcompat::PreferredRuntime>;

/// What Arti knows the service by: where its state is kept, and how its key
/// is found in the keystore.
const NICKNAME: &str = "ditto-relay";

/// What starts C Tor's `hs_ed25519_secret_key`, before the key.
const KEY_HEADER: &[u8; 32] = b"== ed25519v1-secret: type0 ==\0\0\0";

const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(60);

/// How long the onion may go unreachable before that's logged. Arti takes
/// minutes to publish a new service, and a working one dips out for a while
/// whenever an introduction point dies or a directory won't take its
/// descriptor, and recovers from both on its own.
const UNREACHABLE_GRACE: Duration = Duration::from_secs(10 * 60);

/// Arti's configuration: `arti`, as `arti.toml` would have it, keeping its
/// state and cache in `dir` and its keys in memory.
pub fn client_config(dir: &Path, arti: toml::Table) -> anyhow::Result<TorClientConfig> {
    if let Some(toml::Value::Table(storage)) = arti.get("storage") {
        for key in ["state_dir", "cache_dir", "keystore"] {
            ensure!(
                !storage.contains_key(key),
                "tor.arti.storage.{key} can't be set: tor.dir is where Tor keeps its state, and tor.key_file the onion's key"
            );
        }
    }
    let mut builder: TorClientConfigBuilder = known(arti, "tor.arti")?;
    builder
        .storage()
        .state_dir(CfgPath::new_literal(dir.join("state")))
        .cache_dir(CfgPath::new_literal(dir.join("cache")));
    // The key file is the only place the onion's key is kept. Arti's own
    // keystore would be a second copy, which nothing would keep in step.
    builder
        .storage()
        .keystore()
        .primary()
        .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
    builder.build().context("invalid tor.arti")
}

/// The onion service's configuration: `service`, as `arti.toml` would have
/// it under `[onion_services.<nickname>]`.
pub fn service_config(service: toml::Table) -> anyhow::Result<OnionServiceConfig> {
    for (key, instead) in [("nickname", "it has one"), ("enabled", "set tor.enabled")] {
        ensure!(
            !service.contains_key(key),
            "tor.service.{key} can't be set: {instead}"
        );
    }
    let mut builder: OnionServiceConfigBuilder = known(service, "tor.service")?;
    builder.nickname(HsNickname::new(NICKNAME.into()).expect("a valid nickname"));
    builder.build().context("invalid tor.service")
}

/// `table` as a `T`, refusing what `T` has no place for, as the rest of the
/// config file does.
fn known<T: DeserializeOwned>(table: toml::Table, name: &str) -> anyhow::Result<T> {
    let mut unknown = Vec::new();
    let value = serde_ignored::deserialize(toml::Value::Table(table), |path| {
        unknown.push(path.to_string())
    })
    .with_context(|| format!("invalid {name}"))?;
    if let Some(path) = unknown.first() {
        bail!("unknown setting {name}.{path}");
    }
    Ok(value)
}

/// The onion's URL, as clients name the relay over Tor.
pub fn url(address: &str, port: u16) -> String {
    match port {
        80 => format!("ws://{address}/"),
        port => format!("ws://{address}:{port}/"),
    }
}

/// An onion service's key, and the address it makes.
pub struct OnionKey {
    keypair: ed25519::ExpandedKeypair,
    /// With its `.onion`.
    pub address: String,
}

impl OnionKey {
    /// The key in the file at `path`, which is made, with a new key, if
    /// there's nothing there.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(key) = Self::read(path)? {
            return Ok(key);
        }
        let key = Self::generate();
        key.create(path)
            .with_context(|| format!("couldn't write a new onion key to {}", path.display()))?;
        tracing::info!("made a new onion key in {}", path.display());
        Ok(key)
    }

    /// The key in the file at `path`, if there's one.
    pub fn read(path: &Path) -> anyhow::Result<Option<Self>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("couldn't read the onion key {}", path.display()));
            }
        };
        Self::parse(&bytes).map(Some).with_context(|| {
            format!(
                "{} is not an onion key: it must be C Tor's hs_ed25519_secret_key",
                path.display()
            )
        })
    }

    fn generate() -> Self {
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).expect("the OS has randomness");
        Self::new(ed25519::ExpandedKeypair::from(
            &ed25519::Keypair::from_bytes(&seed),
        ))
    }

    fn new(keypair: ed25519::ExpandedKeypair) -> Self {
        let address = HsIdKey::from(*keypair.public())
            .id()
            .display_unredacted()
            .to_string();
        Self { keypair, address }
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let key = bytes.strip_prefix(KEY_HEADER)?.try_into().ok()?;
        ed25519::ExpandedKeypair::from_secret_key_bytes(key).map(Self::new)
    }

    fn encode(&self) -> Vec<u8> {
        [&KEY_HEADER[..], &self.keypair.to_secret_key_bytes()].concat()
    }

    /// Write the key to a new file at `path`, which only its owner may read,
    /// in a directory only they may enter, if it has to be made.
    fn create(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&self.encode())?;
        file.sync_all()
    }
}

/// The onion service, while it runs.
pub struct Tor {
    /// Dropping these is what takes the service down.
    _client: Arc<Client>,
    _service: Arc<RunningOnionService>,
    tasks: Vec<JoinHandle<()>>,
}

impl Tor {
    /// Launch the onion service `key` makes, and serve `app` on it until
    /// `shutdown`. Tor joins the network, and publishes the service, in the
    /// background: what fails here is what trying again wouldn't fix.
    pub async fn start(
        config: &config::Tor,
        key: OnionKey,
        app: Router,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // What Arti recorded about the service's introduction points is only
        // half of them: the keys they were made with were in memory, and
        // went with the last run. Left in place, the service would start out
        // reviving points it can no longer prove it owns.
        match std::fs::remove_dir_all(config.dir.join("state/hss")) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error).context("couldn't clear Tor's onion service state");
            }
            _ => {}
        }
        let client = TorClient::builder()
            .config(config.client.clone())
            .create_unbootstrapped_async()
            .await
            .with_context(|| {
                format!(
                    "Tor couldn't start. It keeps its state in {}, which the relay's user must be able to write and no other user may",
                    config.dir.display()
                )
            })?;

        let nickname = HsNickname::new(NICKNAME.into()).expect("a valid nickname");
        client.keymgr()?.insert(
            HsIdKeypair::from(key.keypair),
            &HsIdKeypairSpecifier::new(nickname),
            KeystoreSelector::Primary,
            true,
        )?;
        let (service, requests) = client
            .launch_onion_service(config.service.clone())?
            .context("Tor wouldn't launch the onion service")?;
        // Launched without its key, the service would have made one up: an
        // address nobody was given.
        let launched = service
            .onion_address()
            .map(|id| id.display_unredacted().to_string());
        if launched.as_deref() != Some(key.address.as_str()) {
            bail!("Tor launched {} as {launched:?}", key.address);
        }

        let url = url(&key.address, config.port);
        tracing::info!("serving on {url} once Tor has published it");
        let listener = OnionListener {
            requests: Box::pin(tor_hsservice::handle_rend_requests(requests)),
            port: config.port,
        };
        let serving = tokio::spawn(async move {
            let serve =
                axum::serve(listener, app).with_graceful_shutdown(shutdown.cancelled_owned());
            if let Err(error) = serve.await {
                tracing::error!("serving the onion failed: {error}");
            }
        });
        let tasks = vec![
            tokio::spawn(bootstrap(client.clone())),
            tokio::spawn(watch(service.status_events(), url)),
            serving,
        ];
        Ok(Self {
            _client: client,
            _service: service,
            tasks,
        })
    }

    /// Take the service down.
    pub fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Join the Tor network, trying again until it works.
async fn bootstrap(client: Arc<Client>) {
    let mut delay = RETRY_MIN;
    while let Err(error) = client.bootstrap().await {
        tracing::warn!(
            "couldn't join the Tor network, trying again in {}s: {error}",
            delay.as_secs()
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(RETRY_MAX);
    }
    tracing::info!("joined the Tor network");
}

/// Say when the onion at `url` can first be reached, and when it has been
/// unreachable for longer than [`UNREACHABLE_GRACE`]. Arti's view of the
/// service decides: it knows whether its descriptor is published and its
/// introduction points are up, which no single failure does.
async fn watch(mut events: OnionServiceStatusStream, url: String) {
    // When it stopped being reachable, and whether that's been said.
    let mut down = Some((tokio::time::Instant::now(), false));
    let mut reached = false;
    let mut current = None;
    loop {
        let overdue = async {
            match down {
                Some((since, false)) => tokio::time::sleep_until(since + UNREACHABLE_GRACE).await,
                _ => std::future::pending().await,
            }
        };
        tokio::select! {
            next = events.next() => {
                let Some(status) = next else { return };
                if status.state().is_fully_reachable() {
                    match down {
                        _ if !reached => tracing::info!("{url} is reachable"),
                        Some((since, true)) => tracing::info!(
                            "{url} is reachable again, after {}s",
                            since.elapsed().as_secs()
                        ),
                        _ => {}
                    }
                    reached = true;
                    down = None;
                } else if down.is_none() {
                    down = Some((tokio::time::Instant::now(), false));
                }
                current = Some(status);
            }
            () = overdue => {
                let Some((since, _)) = down else { continue };
                let problem = current
                    .as_ref()
                    .and_then(|status| status.current_problem())
                    .map_or_else(|| "Tor hasn't said why".into(), describe);
                tracing::warn!(
                    "{url} has been unreachable for {}s: {problem}",
                    since.elapsed().as_secs()
                );
                down = Some((since, true));
            }
        }
    }
}

/// What's wrong with the service, as Arti's errors put it.
fn describe(problem: &Problem) -> String {
    fn join<E: std::fmt::Display>(errors: &[E]) -> String {
        let errors: Vec<String> = errors.iter().map(|error| error.to_string()).collect();
        errors.join("; ")
    }
    match problem {
        Problem::Runtime(error) => error.to_string(),
        Problem::DescriptorUpload(errors) => format!("publishing its descriptor: {}", join(errors)),
        Problem::Ipt(errors) => format!("its introduction points: {}", join(errors)),
        other => format!("{other:?}"),
    }
}

/// The onion's streams, as a listener for `axum::serve`.
struct OnionListener {
    requests: Pin<Box<dyn Stream<Item = StreamRequest> + Send>>,
    /// The only port streams are accepted for.
    port: u16,
}

impl axum::serve::Listener for OnionListener {
    type Io = DataStream;
    /// There's no address to give: the peer is Tor.
    type Addr = ();

    async fn accept(&mut self) -> (DataStream, ()) {
        loop {
            let Some(request) = self.requests.next().await else {
                // The service is gone, and so is everything it would serve.
                return std::future::pending().await;
            };
            // Only a BEGIN for the port is answered, and the rest only with
            // DONE, as C Tor does, so that nothing about the refusal tells
            // this service apart from any other.
            let wanted = matches!(
                request.request(),
                IncomingStreamRequest::Begin(begin) if begin.port() == self.port
            );
            if !wanted {
                let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
                continue;
            }
            match request.accept(Connected::new_empty()).await {
                Ok(stream) => return (stream, ()),
                Err(error) => tracing::debug!("couldn't accept a stream over Tor: {error}"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Made by C Tor 0.4.8 from a `HiddenServiceDir`: its `hostname`, and
    /// the 64 bytes of `hs_ed25519_secret_key` after the header, in base64.
    const C_TOR_ADDRESS: &str = "dl6nglbofs66w2ctcqp3hdgw7lgql7b5xc3dqtj3oqjrcihztrqrkjyd.onion";
    const C_TOR_KEY: &str =
        "MEaMJctlsgmU3HCYqZAda76Xvu0XFmMELLWNDm/8qWq6AYZW0AiNB8uF0+BTPKF/8eFTfIr9ZBF/TGWo1waDcA==";

    fn c_tor_file() -> Vec<u8> {
        let key = base64::engine::general_purpose::STANDARD
            .decode(C_TOR_KEY)
            .unwrap();
        [&KEY_HEADER[..], &key].concat()
    }

    #[test]
    fn reads_keys_c_tor_made() {
        let key = OnionKey::parse(&c_tor_file()).unwrap();
        assert_eq!(key.address, C_TOR_ADDRESS);
        // Arti reduces the scalar C Tor left unreduced: the same key.
        let again = OnionKey::parse(&key.encode()).unwrap();
        assert_eq!(again.address, C_TOR_ADDRESS);

        let mut truncated = c_tor_file();
        truncated.pop();
        assert!(OnionKey::parse(&truncated).is_none());
        assert!(OnionKey::parse(&c_tor_file()[32..]).is_none());
    }

    #[test]
    fn makes_a_key_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tor/hs_ed25519_secret_key");
        let made = OnionKey::open(&path).unwrap();
        assert!(made.address.ends_with(".onion") && made.address.len() == 62);
        let mode = |path: &Path| {
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path).unwrap().permissions())
                & 0o777
        };
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(OnionKey::open(&path).unwrap().address, made.address);

        std::fs::write(&path, "nope").unwrap();
        assert!(OnionKey::open(&path).is_err());
    }

    #[test]
    fn names_the_onion() {
        assert_eq!(url("x.onion", 80), "ws://x.onion/");
        assert_eq!(url("x.onion", 8080), "ws://x.onion:8080/");
    }

    #[test]
    fn takes_arti_settings() {
        let table = |text: &str| text.parse::<toml::Table>().unwrap();
        let dir = Path::new("/var/lib/ditto-relay/tor");
        assert!(client_config(dir, table("")).is_ok());
        assert!(client_config(dir, table("vanguards.mode = \"full\"")).is_ok());
        assert!(
            client_config(
                dir,
                table("storage.permissions.dangerously_trust_everyone = true")
            )
            .is_ok()
        );
        for bad in [
            "vanguards.mood = \"full\"",
            "nope = 1",
            "storage.state_dir = \"/tmp\"",
            "vanguards.mode = \"most\"",
        ] {
            assert!(client_config(dir, table(bad)).is_err(), "{bad}");
        }

        assert!(service_config(table("")).is_ok());
        let ok = "num_intro_points = 5\nenable_pow = true\nrate_limit_at_intro = { rate = 10, burst = 20 }";
        assert!(service_config(table(ok)).is_ok());
        for bad in [
            "num_intro_points = 50",
            "nickname = \"x\"",
            "enabled = false",
            "nope = 1",
        ] {
            assert!(service_config(table(bad)).is_err(), "{bad}");
        }
    }
}
