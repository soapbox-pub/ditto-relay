use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use axum::serve::ListenerExt;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use ditto_relay::config::{Config, Environment};
use ditto_relay::rank::Rank;
use ditto_relay::relay::AppState;
use ditto_relay::search::SearchIndex;
use ditto_relay::store::{History, IndexedTags, Store};
use ditto_relay::tor::{self, OnionKey, Tor};
use ditto_relay::wot::Wot;
use ditto_relay::{control, delete, facets, metrics, relay, trends};

const USAGE: &str = "usage: ditto-relay [--config <path>] \
                     [check | delete [--filter <json>] [--age <seconds>] [--dry-run]]";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;
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

/// Open the store as the relay does, holding the [`control::Lock`].
fn open_store(config: &Config) -> anyhow::Result<Store> {
    let (indexed_tags, history, wot, rank) = store_settings(config)?;
    let store = Store::open(
        &config.db_path,
        config.map_size,
        config.lmdb_sync,
        indexed_tags,
        history,
        wot,
        rank,
    )?;
    tracing::info!("opened LMDB at {}", config.db_path.display());
    Ok(store)
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

    // Read, or made, before anything is served, so a key that's no good
    // stops the relay rather than leaving it without its onion.
    let onion = match &config.tor {
        Some(tor_config) => Some((tor_config.clone(), OnionKey::open(&tor_config.key_file)?)),
        None => None,
    };
    let onion_url = onion
        .as_ref()
        .map(|(tor_config, key)| tor::url(&key.address, tor_config.port));
    let state = AppState::new(config, store, search, onion_url);
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
    let app = relay::router(state.clone());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(state.shutdown.clone().cancelled_owned())
    .await?;
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
