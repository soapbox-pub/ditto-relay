use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use axum::serve::ListenerExt;
use clap::{Parser, Subcommand};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::EnvFilter;

use ditto_relay::config::{Config, Environment};
use ditto_relay::rank::Rank;
use ditto_relay::relay::AppState;
use ditto_relay::search::SearchIndex;
use ditto_relay::store::{BODIES_DIR, History, IndexedTags, Store};
use ditto_relay::tls::{self, Tls};
use ditto_relay::tor::{self, OnionKey, Tor};
use ditto_relay::wot::Wot;
use ditto_relay::{compact, control, delete, facets, key, metrics, relay, trends};

/// How many threads `compact` reads ahead on, unless told.
const COMPACT_THREADS: usize = 32;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = Config::load(args.config.as_deref(), &Environment::current())?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&config.log).context("invalid log directives")?)
        .init();

    facets::set_nsfw_hashtags(config.nsfw_hashtags.clone());
    match args.command.unwrap_or(Command::Serve) {
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
        Command::Compact {
            from,
            into,
            threads,
        } => compact(&config, from, into, threads),
    }
}

/// Open the store as the relay does, holding the [`control::Lock`].
fn open_store(config: &Config) -> anyhow::Result<Store> {
    let (indexed_tags, history, wot, rank) = store_settings(config)?;
    let store = Store::open(
        &config.db_path,
        config.map_size,
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
    let path = config.secret_key_file.display();
    match key::read(&config.secret_key_file)? {
        Some(keypair) => println!("key: {}, in {path}", key::pubkey(&keypair)),
        None => println!("key: a new one to be made in {path}"),
    }
    let files =
        ditto_relay::checkpoint::files(&config.db_path, &[&config.db_path.join(BODIES_DIR)]);
    let mismatches = ditto_relay::storage::check(&files);
    if mismatches.is_empty() {
        println!("storage: suits LMDB");
    }
    for mismatch in mismatches {
        println!("storage: {mismatch}");
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

/// `ditto-relay delete`: see [`delete`]. The running relay is asked to
/// queue it, if there is one, and does it in the background; else it's done
/// here and now, holding the [`control::Lock`] so that no relay starts
/// meanwhile.
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

    let socket = control::socket_path(&config.db_path);
    if let Some(id) = control::request_delete(&socket, json, age)? {
        println!(
            "queued deletion {id}: what it matches is hidden now, and the relay removes it in the background, saying how it goes in its log"
        );
        return Ok(());
    }
    let Some(_lock) = control::Lock::try_acquire(&config.db_path)? else {
        bail!(
            "the relay is using the database but isn't answering on {}: it may be starting or stopping, so try again",
            socket.display()
        );
    };
    let store = Arc::new(open_store(config)?);
    let target = delete::target(&store, filter, json, age)?;
    let mut said = Instant::now();
    let progress = |deleted| {
        if said.elapsed() >= Duration::from_secs(1) {
            eprintln!("deleted {deleted} events so far");
            said = Instant::now();
        }
    };
    let mut indexer = match config.search {
        true => {
            Some(SearchIndex::open(&config.search_path, config.search_kinds.clone(), &store)?.1)
        }
        false => None,
    };
    let deleted = delete::delete(
        &store,
        Some(store.clone()),
        target,
        indexer.as_mut(),
        progress,
    )?;
    store.checkpoint()?;
    println!("deleted {deleted} events");
    Ok(())
}

/// `ditto-relay compact`: see [`compact`]. With `--from` and `--into`, the
/// database in `--from` (stopped, or a snapshot) is copied into `--into`,
/// and nothing else is done. Else the relay's own database is compacted in
/// place, with no relay running.
fn compact(
    config: &Config,
    from: Option<PathBuf>,
    into: Option<PathBuf>,
    threads: usize,
) -> anyhow::Result<()> {
    let mut progress = |p: &compact::Progress| {
        let left = match p.done {
            0 => String::new(),
            done => {
                let secs =
                    p.elapsed.as_secs_f64() * (p.total.saturating_sub(done)) as f64 / done as f64;
                format!(", about {:.0} minutes left", secs / 60.0)
            }
        };
        eprintln!(
            "{}: {} of {} {}, {:.1} GB, in {:.0?}{left}",
            p.table,
            p.done,
            p.total,
            p.unit,
            p.bytes as f64 / 1e9,
            p.elapsed,
        );
    };
    let copied = match (from, into) {
        (Some(from), Some(into)) => {
            compact::copy(&from, &into, config.map_size, threads, &mut progress)?
        }
        _ => {
            let db = &config.db_path;
            let Some(_lock) = control::Lock::try_acquire(db)? else {
                bail!("the relay is using the database: stop it first");
            };
            // As the relay opens it, so that it's as it was at its last
            // checkpoint if the machine went down, then flushed to disk:
            // the copy replaces the checkpoint.
            let store = open_store(config)?;
            store.checkpoint()?;
            drop(store);
            let copied = compact::in_place(db, config.map_size, threads, &mut progress)?;
            let mut old = vec![db.join(compact::OLD_FILE)];
            match copied.bodies {
                compact::Bodies::Left => {}
                compact::Bodies::Rewritten(bytes, took) => {
                    println!(
                        "wrote bodies anew, in smaller records: {:.1} GB in {took:.0?}",
                        bytes as f64 / 1e9
                    );
                    old.push(db.join(BODIES_DIR).join(compact::OLD_FILE));
                }
                compact::Bodies::NoRoom(need, free) => println!(
                    "bodies would be kept in smaller records written anew, but that needs {:.1} GB free, and there's {:.1} GB",
                    need as f64 / 1e9,
                    free as f64 / 1e9
                ),
            }
            for old in old {
                println!(
                    "the old file is {}: remove it once the relay runs well on the new one",
                    old.display()
                );
            }
            copied
        }
    };
    for (table, entries) in &copied.tables {
        println!("{table}: {entries} entries");
    }
    println!(
        "compacted {:.1} GB into {:.1} GB in {:.0?}, {:.0?} of it splitting the tables",
        copied.before as f64 / 1e9,
        copied.after as f64 / 1e9,
        copied.elapsed,
        copied.split,
    );
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
#[derive(Parser)]
#[command(
    name = "ditto-relay",
    version,
    about = "A high-performance Nostr relay on LMDB, with search and a web of trust",
    long_about = "A high-performance Nostr relay on LMDB, with search and a web of trust.

With no command, it runs the relay, as `serve` does. The other commands \
manage it: most of them work whether or not the relay is running, and run \
as the relay's own user, with its config.",
    after_help = CONFIG_HELP,
    after_long_help = CONFIG_HELP,
    subcommand_value_name = "COMMAND",
)]
struct Args {
    /// The config file [default: ~/.config/ditto-relay/ditto-relay.toml,
    /// else /etc/ditto-relay/ditto-relay.toml]
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

const CONFIG_HELP: &str = "\
The config file is TOML, and only `url` must be set. \
ditto-relay.example.toml lists every setting with its default.

Run `ditto-relay help <COMMAND>` for more on each command.";

#[derive(Subcommand)]
enum Command {
    /// Run the relay (the default)
    #[command(long_about = "Run the relay, until SIGTERM or Ctrl-C.

The relay's key is made in `secret_key_file` the first time it starts. \
With [tls] or [tor] turned on, it gets its certificate, or makes its onion \
key, before serving anything.")]
    Serve,

    /// Say whether the config is valid, and what it would serve
    #[command(long_about = "Say whether the config is valid, and what it \
would serve: its URL, database, key, storage, NIP-85, TLS and Tor.

It doesn't start the relay or open its database, so it's safe to run \
beside a running relay, before restarting it with a changed config.")]
    Check,

    /// Delete the events a filter matches
    #[command(
        long_about = "Delete every stored event a NIP-01 filter matches, as \
`strfry delete` does.

The filter matches as a REQ's would, NIP-50 search text and extensions \
included, so {\"search\":\"protocol:atproto\"} deletes every bridged \
Bluesky event. A filter with a `limit` or `distinct:author` deletes the \
events it picks as of now: with `sort:top` and a limit, the most engaged \
with.

While the relay runs, `delete` returns as soon as the relay has queued \
the deletion. From then on no client sees what it matches, and the relay \
removes it in the background, saying how it goes in its log. With the relay stopped, `delete` removes the \
events itself, there and then, and a relay started meanwhile waits for \
it.

Only events stored before the deletion was asked for are deleted, and \
nothing stops them from being published again.",
        after_help = "Examples:
  ditto-relay delete --filter '{\"#t\":[\"spam\"]}' --dry-run
  ditto-relay delete --filter '{\"kinds\":[1]}' --age 7776000
  ditto-relay delete --filter '{\"kinds\":[1],\"search\":\"sort:top\",\"limit\":100}'"
    )]
    Delete {
        /// A NIP-01 filter, as JSON
        #[arg(long, value_name = "JSON", required_unless_present = "age")]
        filter: Option<String>,
        /// Only events at least this many seconds old
        #[arg(long, value_name = "SECONDS")]
        age: Option<u64>,
        /// Only count what would be deleted. It only reads, so it never
        /// holds up the relay
        #[arg(long)]
        dry_run: bool,
    },

    /// Compact the database, with the relay stopped
    #[command(
        long_about = "Compact the database: write its indexes anew into a \
new file, packed in order, and put it in place.

LMDB never shrinks its file, so after deleting much of the database, \
what's left is spread thinly through it, less of it stays in memory, and \
the relay reads the disk more. Compacting needs the relay stopped, and \
room for the new file, about the size of what's live. The old file is \
kept beside it, as db/data.mdb.old: remove it once the relay runs well \
on the new one. Event records are left as they are, unless a file \
written anew would suit ZFS better.

With --from and --into, it only copies the database in --from, which \
must be stopped or a snapshot, into --into, to see how long it takes.",
        after_help = "Example:
  systemctl stop ditto-relay
  sudo -u ditto-relay ditto-relay compact
  systemctl start ditto-relay"
    )]
    Compact {
        /// Copy the database in this directory, rather than the relay's
        #[arg(long, value_name = "DIR", requires = "into")]
        from: Option<PathBuf>,
        /// Into this directory
        #[arg(long, value_name = "DIR", requires = "from")]
        into: Option<PathBuf>,
        /// How many threads read ahead
        #[arg(long, value_name = "N", default_value_t = COMPACT_THREADS)]
        threads: usize,
    },
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
    use clap::CommandFactory;

    fn parse(args: &str) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("ditto-relay").chain(args.split_whitespace()))
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Args::command().debug_assert();
    }

    #[test]
    fn parses_the_command_line() {
        let args = parse("").unwrap();
        assert!(args.config.is_none() && args.command.is_none());
        let args = parse("--config=a.toml").unwrap();
        assert_eq!(args.config, Some(PathBuf::from("a.toml")));
        let args = parse("serve").unwrap();
        assert!(matches!(args.command, Some(Command::Serve)));
        let args = parse("check -c a.toml").unwrap();
        assert!(matches!(args.command, Some(Command::Check)) && args.config.is_some());

        let args = parse("delete --filter {\"kinds\":[1]} -c a.toml --age 60 --dry-run").unwrap();
        assert_eq!(args.config, Some(PathBuf::from("a.toml")));
        let Some(Command::Delete {
            filter,
            age,
            dry_run,
        }) = args.command
        else {
            panic!("not delete");
        };
        assert_eq!(
            (filter.as_deref(), age, dry_run),
            (Some("{\"kinds\":[1]}"), Some(60), true)
        );
        let Some(Command::Delete { filter, .. }) =
            parse("delete --filter={\"a\":\"=\"}").unwrap().command
        else {
            panic!("not delete");
        };
        assert_eq!(filter.as_deref(), Some("{\"a\":\"=\"}"));

        let Some(Command::Compact {
            from,
            into,
            threads,
        }) = parse("compact --from /a --into=/b --threads 8")
            .unwrap()
            .command
        else {
            panic!("not compact");
        };
        assert_eq!(
            (from, into, threads),
            (Some("/a".into()), Some("/b".into()), 8)
        );
        let Some(Command::Compact { threads, .. }) = parse("compact").unwrap().command else {
            panic!("not compact");
        };
        assert_eq!(threads, COMPACT_THREADS);

        for bad in [
            "--dry-run",
            "--age 5",
            "delete",
            "delete delete",
            "delete --age x",
            "delete --filter",
            "delete --dry-run",
            "delete --dry-run=yes --age 5",
            "check delete",
            "check --dry-run",
            "compact --dry-run",
            "compact --from x",
            "delete --threads 4",
            "--from x",
            "compact --threads x",
            "compact delete",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
