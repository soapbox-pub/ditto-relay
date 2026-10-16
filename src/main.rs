use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use axum::serve::ListenerExt;
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::EnvFilter;

use ditto_relay::config::{Config, Environment};
use ditto_relay::lmdb::Opening;
use ditto_relay::rank::Rank;
use ditto_relay::relay::AppState;
use ditto_relay::search::SearchIndex;
use ditto_relay::store::{History, IndexedTags, Store};
use ditto_relay::tls::{self, Tls};
use ditto_relay::tor::{self, OnionKey, Tor};
use ditto_relay::wot::Wot;
use ditto_relay::{control, delete, facets, key, metrics, relay, trends};

const USAGE: &str = "usage: ditto-relay [--config <path>] \
                     [check | delete [--filter <json>] [--age <seconds>] [--dry-run]]";

/// The command [`open_store`] runs itself with to check the store.
const CHECK_STORE: &str = "__check-store";

/// How the store check exits: readable, corrupt, or couldn't say.
const READABLE: i32 = 0;
const CORRUPT: i32 = 2;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut raw = std::env::args_os().skip(1).peekable();
    if raw.peek().is_some_and(|arg| arg == CHECK_STORE) {
        check_store(raw.skip(1));
    }
    let args = Args::parse(raw)?;
    let config = Config::load(args.config.as_deref(), &Environment::current())?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&config.log).context("invalid log directives")?)
        .init();

    facets::set_nsfw_hashtags(config.nsfw_hashtags.clone());
    match args.command {
        Command::Serve => {
            let _lock = control::Lock::acquire(&config.db_path)?;
            let store = open_store(&config)?;
            serve(config, Arc::new(store)).await?;
            // Everything of the relay's is closed by now. Arti leaves a
            // thread behind, in a loop that never ends, which dropping the
            // runtime would wait on, or panic in.
            std::process::exit(0)
        }
        Command::Check => check(&config),
        Command::Delete {
            filter,
            age,
            dry_run,
        } => delete(&config, filter.as_deref(), age, dry_run),
    }
}

/// Open the store as the relay does, holding the [`control::Lock`]. If a
/// crash of the machine has left the latest commit corrupt, the one before
/// it is opened instead, which drops the latest.
fn open_store(config: &Config) -> anyhow::Result<Store> {
    let (indexed_tags, history, wot, rank) = store_settings(config)?;
    let previous = match readable(config, false) {
        Some(false) => {
            tracing::error!(
                "the database's latest commit can't be read, as a crash of the machine can leave it: trying the one before"
            );
            if readable(config, true) != Some(true) {
                bail!(
                    "neither the database's latest commit nor the one before it can be read: restore {} from a backup",
                    config.db_path.display()
                );
            }
            tracing::warn!("opening the commit before the latest, which is dropped");
            true
        }
        Some(true) | None => false,
    };
    let opening = Opening {
        sync: config.lmdb_sync,
        previous,
    };
    let store = Store::open(
        &config.db_path,
        config.map_size,
        opening,
        indexed_tags,
        history,
        wot,
        rank,
    )?;
    tracing::info!("opened LMDB at {}", config.db_path.display());
    Ok(store)
}

/// Whether the store, or with `previous` the commit before its latest, can
/// be read, checked by this binary in a process of its own, as reading a
/// corrupt one can crash. None if it couldn't be checked.
fn readable(config: &Config, previous: bool) -> Option<bool> {
    let status = std::env::current_exe().and_then(|exe| {
        std::process::Command::new(exe)
            .arg(CHECK_STORE)
            .arg(&config.db_path)
            .arg(config.map_size.to_string())
            .args(previous.then_some("--previous"))
            .status()
    });
    match status {
        Ok(status) if status.code() == Some(READABLE) => Some(true),
        // Killed by a signal, as by a bad page read, has no code.
        Ok(status) if matches!(status.code(), Some(CORRUPT) | None) => Some(false),
        Ok(status) => {
            tracing::warn!("couldn't check the database: the check {status}");
            None
        }
        Err(err) => {
            tracing::warn!("couldn't check the database: {err}");
            None
        }
    }
}

/// `__check-store <dir> <map size> [--previous]`, which [`readable`] runs:
/// exit [`READABLE`], [`CORRUPT`], or otherwise if it couldn't say.
fn check_store(mut args: impl Iterator<Item = OsString>) -> ! {
    let dir = args.next().map(PathBuf::from);
    let map_size = args
        .next()
        .and_then(|size| size.into_string().ok()?.parse().ok());
    let previous = args.next().is_some_and(|arg| arg == "--previous");
    let (Some(dir), Some(map_size)) = (dir, map_size) else {
        eprintln!("usage: ditto-relay {CHECK_STORE} <dir> <map size> [--previous]");
        std::process::exit(1);
    };
    match Store::check_readable(&dir, map_size, previous) {
        Ok(()) => std::process::exit(READABLE),
        Err(err) => {
            eprintln!("checking {}: {err}", dir.display());
            std::process::exit(if err.is_corruption() { CORRUPT } else { 1 })
        }
    }
}

/// What the store is opened with.
fn store_settings(config: &Config) -> anyhow::Result<(IndexedTags, History, Option<Wot>, Rank)> {
    Ok((
        IndexedTags::new(config.indexed_tags.clone())?,
        History::new(
            config.history,
            config.history_excluded_kinds.clone(),
            config.history_max_versions,
        ),
        Wot::new(
            config.wot_seeds.clone(),
            config.wot_damping,
            config.wot_full_trust,
            config.wot_min_weight,
            config.wot_budget,
        ),
        Rank::new(config.hot_half_life, config.rank_step, config.wot_budget),
    ))
}

/// Say whether the configuration would start a relay, without starting one
/// or opening its database: it's been read, and its log directives checked,
/// by now.
fn check(config: &Config) -> anyhow::Result<()> {
    println!("url: {}", config.url);
    println!("database: {}", config.db_path.display());
    let path = config.secret_key_file.display();
    match key::read(&config.secret_key_file)? {
        Some(keypair) => println!("key: {}, in {path}", key::pubkey(&keypair)),
        None => println!("key: a new one to be made in {path}"),
    }
    println!("nip85: {}", if config.nip85 { "on" } else { "off" });
    match &config.tls {
        Some(tls_config) => match tls::stored(tls_config) {
            Ok(Some(certificate)) => println!(
                "tls: {}, with a certificate that expires in {} days, in {}",
                tls_config.domain,
                certificate.days_left(),
                tls_config.dir.display()
            ),
            Ok(None) => println!(
                "tls: {}, with a certificate to be got from {}",
                tls_config.domain, tls_config.directory
            ),
            Err(error) => println!(
                "tls: {}, with a new certificate to be got, since {error:#}",
                tls_config.domain
            ),
        },
        None => println!("tls: off"),
    }
    match &config.tor {
        Some(tor) => match OnionKey::read(&tor.key_file)? {
            Some(key) => println!(
                "tor: {}, with the key in {}",
                tor::url(&key.address, tor.port),
                tor.key_file.display()
            ),
            None => println!(
                "tor: on, with a new key to be made in {}",
                tor.key_file.display()
            ),
        },
        None => println!("tor: off"),
    }
    println!("the configuration is valid");
    Ok(())
}

/// `ditto-relay delete`: see [`delete`]. The running relay is asked to do
/// it, if there is one; else it's done here, holding the [`control::Lock`]
/// so that no relay starts meanwhile.
fn delete(
    config: &Config,
    json: Option<&str>,
    age: Option<u64>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let (indexed_tags, history, wot, rank) = store_settings(config)?;
    // Checked here, so a mistake is told before anything's asked.
    let filter = delete::filter(json, age, ditto_relay::event::now(), &indexed_tags)?;
    if dry_run {
        let store = Store::open_read_only(
            &config.db_path,
            config.map_size,
            indexed_tags,
            history,
            wot,
            rank,
        )?;
        println!("would delete {} events", delete::count(&store, &filter)?);
        return Ok(());
    }

    let mut said = Instant::now();
    let mut progress = |deleted| {
        if said.elapsed() >= Duration::from_secs(1) {
            eprintln!("deleted {deleted} events so far");
            said = Instant::now();
        }
    };
    let socket = control::socket_path(&config.db_path);
    if let Some(deleted) = control::request_delete(&socket, json, age, &mut progress)? {
        println!("deleted {deleted} events");
        return Ok(());
    }
    let Some(_lock) = control::Lock::try_acquire(&config.db_path)? else {
        bail!(
            "the relay is using the database but isn't answering on {}: it may be starting or stopping, so try again",
            socket.display()
        );
    };
    let store = open_store(config)?;
    let mut indexer = match config.search {
        true => {
            Some(SearchIndex::open(&config.search_path, config.search_kinds.clone(), &store)?.1)
        }
        false => None,
    };
    let deleted = delete::delete(&store, &filter, indexer.as_mut(), &mut progress)?;
    println!("deleted {deleted} events");
    Ok(())
}

async fn serve(config: Config, store: Arc<Store>) -> anyhow::Result<()> {
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

    let listener = bind(&config.bind).await?;
    // With [tls], its certificate is loaded, and port 80 bound, before
    // anything is served.
    let tls = match &config.tls {
        Some(tls_config) => {
            let tls = Tls::open(tls_config)?;
            let redirect = match &tls_config.http_bind {
                Some(http_bind) => Some(bind(http_bind).await?),
                None => None,
            };
            Some((tls, redirect))
        }
        None => None,
    };
    let scheme = if tls.is_some() { "wss" } else { "ws" };
    tracing::info!("listening on {scheme}://{}", listener.local_addr()?);
    if let Some((_, Some(redirect))) = &tls {
        tracing::info!("redirecting http://{} to HTTPS", redirect.local_addr()?);
    }

    let metrics = match &config.metrics_bind {
        Some(metrics_bind) => {
            let listener = bind(metrics_bind).await?;
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

    // Read, or made, before anything is served, so a key that's no good
    // stops the relay rather than leaving it without its onion.
    let keypair = key::open(&config.secret_key_file)?;
    tracing::info!("the relay's pubkey is {}", key::pubkey(&keypair));
    let onion = match &config.tor {
        Some(tor_config) => Some((tor_config.clone(), OnionKey::open(&tor_config.key_file)?)),
        None => None,
    };
    let onion_url = onion
        .as_ref()
        .map(|(tor_config, key)| tor::url(&key.address, tor_config.port));
    let state = AppState::new(config, keypair, store, search, onion_url);
    let socket = control::socket_path(&state.config.db_path);
    let control = control::serve(
        &socket,
        state.store.clone(),
        state.writer.clone(),
        state.shutdown.clone(),
    )?;
    let tor = match onion {
        Some((tor_config, key)) => {
            let app = relay::onion_router(state.clone());
            Some(Tor::start(&tor_config, key, app, state.shutdown.clone()).await?)
        }
        None => None,
    };
    trends::spawn(state.clone());
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        signal().await;
        tracing::info!("shutting down");
        shutdown.cancel();
    });
    let app = relay::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let shutdown = state.shutdown.clone().cancelled_owned();
    match tls {
        Some((tls, redirect)) => {
            if let Some(redirect) = redirect {
                let app = tls.redirect_router();
                let shutdown = state.shutdown.clone().cancelled_owned();
                tokio::spawn(async move {
                    let serve = axum::serve(redirect, app).with_graceful_shutdown(shutdown);
                    if let Err(error) = serve.await {
                        tracing::error!("serving the redirect to HTTPS failed: {error}");
                    }
                });
            }
            let listener = tls
                .listener(listener)?
                .tap_io(|tls| nodelay(tls.get_ref().0));
            tls.start(state.shutdown.clone());
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await?;
        }
        None => {
            axum::serve(listener.tap_io(|tcp| nodelay(tcp)), app)
                .with_graceful_shutdown(shutdown)
                .await?
        }
    }
    state.shut_down().await;
    control.abort();
    let _ = std::fs::remove_file(&socket);
    if let Some(tor) = tor {
        tor.stop();
    }
    if let Some(metrics) = metrics {
        metrics.abort();
    }
    tracing::info!("shut down");

    Ok(())
}

/// Listen on `address`.
async fn bind(address: &str) -> anyhow::Result<TcpListener> {
    TcpListener::bind(address).await.map_err(|error| {
        let hint = match error.kind() {
            std::io::ErrorKind::PermissionDenied => {
                ": ports below 1024 need root, or CAP_NET_BIND_SERVICE (AmbientCapabilities=CAP_NET_BIND_SERVICE under systemd)"
            }
            _ => "",
        };
        anyhow::Error::new(error).context(format!("couldn't listen on {address}{hint}"))
    })
}

/// A REQ's events and its EOSE go out as they're ready: Nagle's algorithm
/// would hold the last back until the client acknowledged the rest, which
/// with delayed ACKs is some 40 ms.
fn nodelay(tcp: &TcpStream) {
    if let Err(err) = tcp.set_nodelay(true) {
        tracing::debug!("couldn't set TCP_NODELAY: {err}");
    }
}

/// The command line.
struct Args {
    /// The file `--config` (`-c`) names, if any.
    config: Option<PathBuf>,
    command: Command,
}

enum Command {
    /// Run the relay.
    Serve,
    /// Check the configuration.
    Check,
    /// Remove what a filter matches: see [`delete`].
    Delete {
        filter: Option<String>,
        age: Option<u64>,
        dry_run: bool,
    },
}

impl Args {
    /// Options are `--name value` or `--name=value`, before the command
    /// or after.
    fn parse(mut args: impl Iterator<Item = OsString>) -> anyhow::Result<Args> {
        let mut parsed = Args {
            config: None,
            command: Command::Serve,
        };
        let (mut filter, mut age, mut dry_run) = (None, None, false);
        while let Some(arg) = args.next() {
            let arg = arg.into_string().map_err(|_| anyhow!(USAGE))?;
            let (name, inline) = match arg.split_once('=') {
                Some((name, value)) if name.starts_with("--") => (name, Some(value.to_string())),
                _ => (arg.as_str(), None),
            };
            let mut value = || match &inline {
                Some(value) => Ok(value.clone()),
                None => args
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .with_context(|| format!("{name} needs a value")),
            };
            match name {
                "-c" | "--config" => parsed.config = Some(value()?.into()),
                "check" if matches!(parsed.command, Command::Serve) => {
                    parsed.command = Command::Check
                }
                "delete" if matches!(parsed.command, Command::Serve) => {
                    parsed.command = Command::Delete {
                        filter: None,
                        age: None,
                        dry_run: false,
                    }
                }
                "--filter" => filter = Some(value()?),
                "--age" => age = Some(value()?.parse().context("--age must be seconds")?),
                "--dry-run" if inline.is_none() => dry_run = true,
                _ => bail!(USAGE),
            }
        }
        match &mut parsed.command {
            Command::Delete {
                filter: f,
                age: a,
                dry_run: d,
            } => (*f, *a, *d) = (filter, age, dry_run),
            Command::Serve | Command::Check if filter.is_some() || age.is_some() || dry_run => {
                bail!(USAGE)
            }
            Command::Serve | Command::Check => {}
        }
        Ok(parsed)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &str) -> anyhow::Result<Args> {
        Args::parse(args.split_whitespace().map(OsString::from))
    }

    #[test]
    fn parses_the_command_line() {
        let args = parse("").unwrap();
        assert!(args.config.is_none() && matches!(args.command, Command::Serve));
        let args = parse("--config=a.toml").unwrap();
        assert_eq!(args.config, Some(PathBuf::from("a.toml")));
        let args = parse("check -c a.toml").unwrap();
        assert!(matches!(args.command, Command::Check) && args.config.is_some());

        let args = parse("delete --filter {\"kinds\":[1]} -c a.toml --age 60 --dry-run").unwrap();
        assert_eq!(args.config, Some(PathBuf::from("a.toml")));
        let Command::Delete {
            filter,
            age,
            dry_run,
        } = args.command
        else {
            panic!("not delete");
        };
        assert_eq!(
            (filter.as_deref(), age, dry_run),
            (Some("{\"kinds\":[1]}"), Some(60), true)
        );
        let Command::Delete { filter, .. } =
            parse("--filter={\"a\":\"=\"} delete").unwrap().command
        else {
            panic!("not delete");
        };
        assert_eq!(filter.as_deref(), Some("{\"a\":\"=\"}"));

        for bad in [
            "--dry-run",
            "--age 5",
            "delete delete",
            "delete --age x",
            "delete --filter",
            "delete --dry-run=yes",
            "serve",
            "check delete",
            "delete check",
            "check --dry-run",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
