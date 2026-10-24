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
use ditto_relay::import::{Importer, Tally};
use ditto_relay::pending::Target;
use ditto_relay::purge::Purger;
use ditto_relay::rank::Rank;
use ditto_relay::relay::AppState;
use ditto_relay::search::SearchIndex;
use ditto_relay::store::{BODIES_DIR, History, IndexedTags, Store, Writer};
use ditto_relay::tls::{self, Tls};
use ditto_relay::tor::{self, OnionKey, Tor};
use ditto_relay::wot::Wot;
use ditto_relay::{compact, control, delete, facets, key, metrics, relay, repack, trends};

/// How many threads `compact` reads ahead on, unless told.
const COMPACT_THREADS: usize = 32;

/// How many threads `repack` reads ahead on, unless told: fewer, to leave
/// the disk to the relay.
const REPACK_THREADS: usize = 8;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let env = Environment::current();
    // Said before the file's read, so it can say which file isn't right.
    if let Some(Command::Config {
        command: ConfigCommand::Path,
    }) = args.command
    {
        let source = Config::source(args.config.as_deref(), &env)?;
        println!("{}", std::path::absolute(&source)?.display());
        return Ok(());
    }
    let config = Config::load(args.config.as_deref(), &env)?;
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
        Command::Check { json } => check(&config, json),
        Command::Config { command } => match command {
            ConfigCommand::Path => unreachable!("said before the file was read"),
            ConfigCommand::Show => {
                let source = Config::source(args.config.as_deref(), &env)?;
                let source = std::path::absolute(&source)?;
                println!("# The settings in effect, from {}", source.display());
                print!("{}", config.to_toml());
                Ok(())
            }
        },
        Command::Delete {
            filter,
            age,
            ids: Some(file),
            dry_run,
        } => {
            debug_assert!(filter.is_none() && age.is_none());
            delete_ids(&config, file, dry_run)
        }
        Command::Delete {
            filter,
            age,
            ids: None,
            dry_run,
        } => delete(&config, filter.as_deref(), age, dry_run),
        Command::Deletions { json } => deletions(&config, json),
        Command::Cancel { id } => cancel(&config, id),
        Command::Export { filter } => export(&config, filter.as_deref()),
        Command::Import { file, no_verify } => import(&config, file, !no_verify).await,
        Command::Compact {
            from,
            into,
            threads,
            bodies,
        } => compact(&config, from, into, threads, bodies),
        Command::Repack { threads, bodies } => repack(&config, threads, bodies),
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

/// Open the store only to read, as it is, whether or not the relay is
/// running: see [`Store::open_read_only`].
fn open_read_only(config: &Config) -> anyhow::Result<Store> {
    if !config.db_path.join("data.mdb").exists() {
        bail!(
            "there's no database in {} yet: the relay makes it when it first starts",
            config.db_path.display()
        );
    }
    let (indexed_tags, history, wot, rank) = store_settings(config)?;
    Store::open_read_only(
        &config.db_path,
        config.map_size,
        indexed_tags,
        history,
        wot,
        rank,
    )
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
fn check(config: &Config, json: bool) -> anyhow::Result<()> {
    let key = key::read(&config.secret_key_file)?.map(|keypair| key::pubkey(&keypair));
    let files =
        ditto_relay::checkpoint::files(&config.db_path, &[&config.db_path.join(BODIES_DIR)]);
    let mismatches = ditto_relay::storage::check(&files);
    let tls = config
        .tls
        .as_ref()
        .map(|tls_config| (tls_config, tls::stored(tls_config)));
    let tor = match &config.tor {
        Some(tor) => Some((tor, OnionKey::read(&tor.key_file)?)),
        None => None,
    };

    if json {
        let report = serde_json::json!({
            "valid": true,
            "url": config.url,
            "database": config.db_path,
            "key": {"pubkey": key, "file": config.secret_key_file},
            "storage": mismatches.iter().map(|mismatch| serde_json::json!({
                "file": mismatch.file,
                "record_size": mismatch.record,
                "dataset": mismatch.dataset,
                "problem": mismatch.to_string(),
            })).collect::<Vec<_>>(),
            "nip85": config.nip85,
            "tls": tls.as_ref().map(|(tls_config, stored)| serde_json::json!({
                "domain": tls_config.domain,
                "dir": tls_config.dir,
                "directory": tls_config.directory,
                "days_left": stored.as_ref().ok().and_then(Option::as_ref).map(|cert| cert.days_left()),
                "error": stored.as_ref().err().map(|error| format!("{error:#}")),
            })),
            "tor": tor.as_ref().map(|(tor, key)| serde_json::json!({
                "url": key.as_ref().map(|key| tor::url(&key.address, tor.port)),
                "key_file": tor.key_file,
            })),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("url: {}", config.url);
    println!("database: {}", config.db_path.display());
    let path = config.secret_key_file.display();
    match key {
        Some(pubkey) => println!("key: {pubkey}, in {path}"),
        None => println!("key: a new one to be made in {path}"),
    }
    if mismatches.is_empty() {
        println!("storage: suits LMDB");
    }
    for mismatch in mismatches {
        println!("storage: {mismatch}");
    }
    println!("nip85: {}", if config.nip85 { "on" } else { "off" });
    match tls {
        Some((tls_config, stored)) => match stored {
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
    match tor {
        Some((tor, Some(key))) => println!(
            "tor: {}, with the key in {}",
            tor::url(&key.address, tor.port),
            tor.key_file.display()
        ),
        Some((tor, None)) => println!(
            "tor: on, with a new key to be made in {}",
            tor.key_file.display()
        ),
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
    let indexed_tags = IndexedTags::new(config.indexed_tags.clone())?;
    // Checked here, so a mistake is told before anything's asked.
    let filter = delete::filter(json, age, ditto_relay::event::now(), &indexed_tags)?;
    if dry_run {
        let store = open_read_only(config)?;
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
    delete_now(config, &store, target)
}

/// Delete what `target` covers here and now, with no relay running,
/// holding the [`control::Lock`].
fn delete_now(config: &Config, store: &Arc<Store>, target: Target) -> anyhow::Result<()> {
    let mut said = Instant::now();
    let progress = |deleted| {
        if said.elapsed() >= Duration::from_secs(1) {
            eprintln!("deleted {deleted} events so far");
            said = Instant::now();
        }
    };
    let mut indexer = match config.search {
        true => Some(
            SearchIndex::open(
                &config.search_path,
                config.search_excluded_kinds.clone(),
                store,
            )?
            .1,
        ),
        false => None,
    };
    let deleted = delete::delete(
        store,
        Some(store.clone()),
        target,
        indexer.as_mut(),
        progress,
    )?;
    store.checkpoint()?;
    println!("deleted {deleted} events");
    Ok(())
}

/// `ditto-relay delete --ids`: as [`delete`], of the events whose ids are
/// read from `file`, or stdin, picked as they're stored now.
fn delete_ids(config: &Config, file: PathBuf, dry_run: bool) -> anyhow::Result<()> {
    let ids = match file.as_os_str() == "-" {
        true => delete::read_ids(std::io::stdin().lock())?,
        false => delete::read_ids(std::io::BufReader::new(
            std::fs::File::open(&file)
                .with_context(|| format!("couldn't open {}", file.display()))?,
        ))?,
    };
    if dry_run {
        let store = open_read_only(config)?;
        println!(
            "would delete {} events",
            delete::pick_ids(&store, &ids)?.len()
        );
        return Ok(());
    }

    let socket = control::socket_path(&config.db_path);
    if let Some(id) = control::request_delete_ids(&socket, &ids)? {
        println!(
            "queued deletion {id}: what it picked is hidden now, and the relay removes it in the background, saying how it goes in its log"
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
    let target = Target::Seqs(Arc::new(delete::pick_ids(&store, &ids)?));
    delete_now(config, &store, target)
}

/// `ditto-relay deletions`: what's pending, as kept, which the relay
/// commits as it goes, so that it's read as well with the relay running.
fn deletions(config: &Config, json: bool) -> anyhow::Result<()> {
    let listed = open_read_only(config)?.list_pending()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&listed)?);
        return Ok(());
    }
    if listed.is_empty() {
        println!("no deletions pending");
    }
    for listed in listed {
        println!("{}: {}", listed.id, listed.covers);
        println!("  {}", listed.progress());
    }
    Ok(())
}

/// `ditto-relay cancel`: the running relay is asked to cancel it, if there
/// is one; else it's done here, holding the [`control::Lock`].
fn cancel(config: &Config, id: u64) -> anyhow::Result<()> {
    let socket = control::socket_path(&config.db_path);
    if !control::request_cancel(&socket, id)? {
        let Some(_lock) = control::Lock::try_acquire(&config.db_path)? else {
            bail!(
                "the relay is using the database but isn't answering on {}: it may be starting or stopping, so try again",
                socket.display()
            );
        };
        let store = open_store(config)?;
        Purger::new(&store, None, false)?.cancel(&store, id)?;
    }
    println!("cancelled deletion {id}: what it hadn't removed yet is shown again");
    Ok(())
}

/// `ditto-relay export`: see [`export`].
fn export(config: &Config, json: Option<&str>) -> anyhow::Result<()> {
    let store = open_read_only(config)?;
    let filter = match json {
        Some(json) => Some(delete::filter(
            Some(json),
            None,
            ditto_relay::event::now(),
            &store.indexed_tags,
        )?),
        None => None,
    };
    store.hide_pending()?;
    let mut said = Instant::now();
    let progress = |written| {
        if said.elapsed() >= Duration::from_secs(1) {
            eprintln!("exported {written} events so far");
            said = Instant::now();
        }
    };
    let mut out = std::io::BufWriter::with_capacity(1 << 20, std::io::stdout().lock());
    match ditto_relay::export::export(&store, filter.as_ref(), &mut out, progress) {
        Ok(written) => {
            eprintln!("exported {written} events");
            Ok(())
        }
        // Read by something that's had enough, as `head`.
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// `ditto-relay import`: see [`import`]. The running relay is asked to
/// store the events, if there is one; else they're stored here, holding
/// the [`control::Lock`] so that no relay starts meanwhile.
async fn import(config: &Config, file: Option<PathBuf>, verify: bool) -> anyhow::Result<()> {
    let file = file.filter(|file| file.as_os_str() != "-");
    let socket = control::socket_path(&config.db_path);
    let asked = {
        let (socket, file) = (socket.clone(), file.clone());
        tokio::task::spawn_blocking(move || {
            let input: Box<dyn std::io::BufRead> = match &file {
                Some(file) => Box::new(std::io::BufReader::new(
                    std::fs::File::open(file)
                        .with_context(|| format!("couldn't open {}", file.display()))?,
                )),
                None => Box::new(std::io::BufReader::new(std::io::stdin())),
            };
            control::request_import(&socket, input, verify, |sent| {
                eprintln!("sent the relay {sent} events so far")
            })
        })
        .await??
    };
    if let Some(tally) = asked {
        say_imported(&tally);
        return Ok(());
    }

    let Some(_lock) = control::Lock::try_acquire(&config.db_path)? else {
        bail!(
            "the relay is using the database but isn't answering on {}: it may be starting or stopping, so try again",
            socket.display()
        );
    };
    let input: Box<dyn tokio::io::AsyncBufRead + Unpin> = match &file {
        Some(file) => Box::new(tokio::io::BufReader::new(
            tokio::fs::File::open(file)
                .await
                .with_context(|| format!("couldn't open {}", file.display()))?,
        )),
        None => Box::new(tokio::io::BufReader::new(tokio::io::stdin())),
    };
    let store = Arc::new(open_store(config)?);
    // What NIP-09 deletions among them remove, for the search index. What
    // they store, it finds itself, catching up when the relay starts.
    let (removed, told) = std::sync::mpsc::channel();
    let writer = Writer::spawn(store.clone(), config.search.then_some(removed), |_| {});
    let mut importer = Importer::new(store.clone(), writer.clone(), verify);
    let mut lines = tokio::io::AsyncBufReadExt::lines(input);
    let mut said = Instant::now();
    while let Some(line) = lines
        .next_line()
        .await
        .context("couldn't read the events")?
    {
        importer.line(&line).await?;
        if said.elapsed() >= Duration::from_secs(1) {
            eprintln!("imported {} events so far", importer.tally().total());
            said = Instant::now();
        }
    }
    let tally = importer.finish().await?;
    tokio::task::spawn_blocking(move || writer.stop()).await?;
    let removed: Vec<u64> = told.try_iter().flatten().collect();
    if !removed.is_empty() {
        let (_, mut indexer) = SearchIndex::open(
            &config.search_path,
            config.search_excluded_kinds.clone(),
            &store,
        )?;
        indexer.remove(&removed);
        indexer.commit()?;
    }
    store.checkpoint()?;
    say_imported(&tally);
    Ok(())
}

fn say_imported(tally: &Tally) {
    println!(
        "imported {} events: {} stored, {} kept as history only, {} here already, {} refused",
        tally.total(),
        tally.stored,
        tally.archived,
        tally.duplicate,
        tally.refused.values().sum::<u64>()
    );
    for (why, count) in &tally.refused {
        println!("  {count} refused: {why}");
    }
}

/// `ditto-relay compact`: see [`compact`]. With `--from` and `--into`, the
/// database in `--from` (stopped, or a snapshot) is copied into `--into`,
/// and nothing else is done. Else the relay's own database is compacted in
/// place, with no relay running, and with `bodies`, its event records too.
fn compact(
    config: &Config,
    from: Option<PathBuf>,
    into: Option<PathBuf>,
    threads: usize,
    bodies: bool,
) -> anyhow::Result<()> {
    let mut progress = |p: &compact::Progress| eprintln!("{p}");
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
            let copied = compact::in_place(db, config.map_size, threads, bodies, &mut progress)?;
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
                compact::Bodies::Compacted(before, after, took) => {
                    println!(
                        "compacted bodies, {:.1} GB into {:.1} GB in {took:.0?}",
                        before as f64 / 1e9,
                        after as f64 / 1e9
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

/// `ditto-relay repack`: see [`repack`]. The running relay is asked to do
/// it; with none running, it's done here, and a relay started meanwhile
/// waits.
fn repack(config: &Config, threads: usize, bodies: bool) -> anyhow::Result<()> {
    let socket = control::socket_path(&config.db_path);
    let mut say = |line: &str| eprintln!("{line}");
    let repacked = match control::request_repack(&socket, bodies, threads, say)? {
        Some(repacked) => repacked,
        None => {
            let Some(_lock) = control::Lock::try_acquire(&config.db_path)? else {
                bail!(
                    "the relay is using the database but isn't answering on {}: it may be starting or stopping, so try again",
                    socket.display()
                );
            };
            let store = open_store(config)?;
            let repacked = repack::repack(&store, bodies, threads, &mut say)?;
            store.checkpoint()?;
            repacked
        }
    };
    for (table, entries) in &repacked.tables {
        println!("{table}: {entries} entries");
    }
    println!(
        "repacked {:.1} GB into {:.1} GB in {:.0?}, the writer waiting {:.1?} of it",
        repacked.before as f64 / 1e9,
        repacked.after as f64 / 1e9,
        repacked.elapsed,
        repacked.paused,
    );
    Ok(())
}

async fn serve(config: Config, store: Arc<Store>) -> anyhow::Result<()> {
    let search = if config.search {
        let (index, indexer) = SearchIndex::open(
            &config.search_path,
            config.search_excluded_kinds.clone(),
            &store,
        )?;
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
beside a running relay, before restarting it with a changed config. An \
invalid config is said on stderr, and exits with status 1.")]
    Check {
        /// Print it as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show the config file in use, or the settings in effect
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Delete the events a filter matches, or those of a list of ids
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
removes it in the background, saying how it goes in its log and in \
`ditto-relay deletions`. With the relay stopped, `delete` removes the \
events itself, there and then, and a relay started meanwhile waits for \
it.

With --ids, it deletes the events whose ids are listed, in hex, a line \
each, in a file or on stdin, however many: as one deletion, which with \
hundreds of thousands or more sweeps each index once, rather than taking \
each event out of every index in turn.

Only events stored before the deletion was asked for are deleted, and \
nothing stops them from being published again.",
        after_help = "Examples:
  ditto-relay delete --filter '{\"#t\":[\"spam\"]}' --dry-run
  ditto-relay delete --filter '{\"kinds\":[1]}' --age 7776000
  ditto-relay delete --filter '{\"kinds\":[1],\"search\":\"sort:top\",\"limit\":100}'
  ditto-relay delete --ids spam.txt"
    )]
    Delete {
        /// A NIP-01 filter, as JSON
        #[arg(long, value_name = "JSON", required_unless_present_any = ["age", "ids"])]
        filter: Option<String>,
        /// Only events at least this many seconds old
        #[arg(long, value_name = "SECONDS")]
        age: Option<u64>,
        /// The events whose ids are in this file, a line each, or - for
        /// stdin
        #[arg(long, value_name = "FILE", conflicts_with_all = ["filter", "age"])]
        ids: Option<PathBuf>,
        /// Only count what would be deleted. It only reads, so it never
        /// holds up the relay
        #[arg(long)]
        dry_run: bool,
    },

    /// Write stored events to stdout, as JSON lines
    #[command(
        long_about = "Write stored events to stdout, as JSON, an event a \
line, as clients would see them: not those expired, nor those a pending \
deletion covers.

They're written in the order they were stored, so that `ditto-relay \
import`, or another relay, stores them in the order they first were. \
Without --filter, that's every event, old versions of replaceable events \
kept as history too. With it, it's what the filter matches, as \
`ditto-relay delete` would find it: search text and extensions too, and \
with a `limit`, the events it picks.

It only reads the database, so it's safe to run while the relay runs. \
How it's going is said on stderr.",
        after_help = "Examples:
  ditto-relay export > backup.jsonl
  ditto-relay export --filter '{\"authors\":[\"<hex pubkey>\"]}' | gzip > alice.jsonl.gz
  ditto-relay -c old.toml export | ditto-relay -c new.toml import"
    )]
    Export {
        /// Only what this NIP-01 filter matches, as JSON
        #[arg(long, value_name = "JSON")]
        filter: Option<String>,
    },

    /// Store events read as JSON lines, from a file or stdin
    #[command(
        long_about = "Store events read as JSON, an event a line, from a \
file or stdin, as `ditto-relay export` writes them.

They're stored as a client's would be, in the order they're read, so \
that a replaceable event's versions, and NIP-09 deletions and what they \
delete, come out as they would have. Each event's id and signature are \
checked, unless it's stored already. Unlike a client's, they aren't put \
to the write policy plugin. Ephemeral events aren't stored.

While the relay runs, it's sent the events and stores them itself, and \
its subscribers see them as they're stored. With the relay stopped, \
`import` stores them there and then, and a relay started meanwhile waits \
for it. Run it with the relay's own config, as the relay's user.

It says, at the end, how many were stored, and why any were refused.",
        after_help = "Examples:
  ditto-relay import backup.jsonl
  zcat alice.jsonl.gz | ditto-relay import
  ditto-relay -c old.toml export | ditto-relay -c new.toml import"
    )]
    Import {
        /// The file to read, or - for stdin [default: stdin]
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Don't check events' ids and signatures. Only for events from a
        /// source you trust, as your own export
        #[arg(long)]
        no_verify: bool,
    },

    /// List the deletions queued and not yet done
    #[command(long_about = "List the deletions queued and not yet done, \
with how far removing each has got: those `ditto-relay delete` asked \
for, NIP-09 deletions, and NIP-62 requests to vanish.

What a queued deletion covers is hidden from clients already. This only \
reads the database, so it's safe to run while the relay runs.")]
    Deletions {
        /// Print them as JSON
        #[arg(long)]
        json: bool,
    },

    /// Cancel a queued deletion
    #[command(
        long_about = "Cancel a queued deletion, by the id `ditto-relay \
deletions` lists it under, leaving the rest queued.

What it's removed already stays removed, and what it hasn't is shown to \
clients again. A NIP-09 deletion or a request to vanish can be cancelled \
too, though the relay goes on refusing what it names if it's published \
again. A deletion sweeping the indexes can't be stopped partway, since \
only finishing leaves them whole: `deletions` says when one is.

While the relay runs, it's asked to cancel it. With the relay stopped, \
it's done here, and a relay started meanwhile waits.",
        after_help = "Example:
  ditto-relay deletions
  ditto-relay cancel 32253"
    )]
    Cancel {
        /// The deletion's id, as `ditto-relay deletions` lists it
        #[arg(value_name = "ID")]
        id: u64,
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
written anew would suit ZFS better, or --bodies is given.

With --bodies, event records (db/bodies) are compacted too, their old \
file kept as db/bodies/data.mdb.old. Deleting many events fragments \
them: what's freed is scattered single pages, which records bigger than \
a page can't use.

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
        /// Compact the event records too
        #[arg(long, conflicts_with = "from")]
        bodies: bool,
    },

    /// Compact the database while the relay runs
    #[command(
        long_about = "Compact the database while the relay runs, as \
`compact` does with it stopped, and put the copy in place of the old file, \
which is then freed a little at a time, as freeing it at once holds up \
writes on ZFS.

The relay goes on reading and writing the old file meanwhile, and what it \
writes is kept in a journal beside the copy, then made in the copy too. \
Once the copy has caught up, the relay's writes wait while the last of \
them is made, about a second, and the copy is put in place. Reads under \
way go on in the old file, whose space is freed once they end. Sweeps of \
big deletions wait meanwhile. If the copy can't catch up with what's \
written, the repack gives up, leaving the old file in place.

It needs room for the copy, about the size of what's live, for what's \
written meanwhile, and for the old file to grow meanwhile: LMDB can't \
reuse the pages of the old file the copy is reading. If the relay or the \
machine stops before the copy's in place, the database is as it was, and \
what the repack made is freed when the relay next starts.

The indexes (db/data.mdb) are compacted, or with --bodies, the event \
records (db/bodies) instead. With the relay stopped, it's done here, and \
a relay started meanwhile waits.",
        after_help = "Example:
  sudo -u ditto-relay ditto-relay repack
  sudo -u ditto-relay ditto-relay repack --bodies"
    )]
    Repack {
        /// How many threads read ahead
        #[arg(long, value_name = "N", default_value_t = REPACK_THREADS)]
        threads: usize,
        /// Compact the event records, rather than the indexes
        #[arg(long)]
        bodies: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print the path of the config file in use
    #[command(long_about = "Print the path of the config file in use: the \
one --config names, or else the first of \
~/.config/ditto-relay/ditto-relay.toml and \
/etc/ditto-relay/ditto-relay.toml that exists. It's printed whether or \
not the file is valid.")]
    Path,
    /// Print the settings in effect, defaults filled in, as TOML
    #[command(long_about = "Print the settings in effect, defaults filled \
in, as TOML: what the relay would run with. Relative paths are shown \
resolved, against the file's directory. [tls] and [tor] settings are \
shown only when they're turned on, and Arti's settings, under [tor.arti] \
and [tor.service], only as written.")]
    Show,
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
        let args = parse("deletions --json").unwrap();
        assert!(matches!(
            args.command,
            Some(Command::Deletions { json: true })
        ));
        let args = parse("export --filter {}").unwrap();
        assert!(matches!(
            args.command,
            Some(Command::Export { filter: Some(_) })
        ));
        let Some(Command::Import { file, no_verify }) =
            parse("import --no-verify a.jsonl").unwrap().command
        else {
            panic!("not import");
        };
        assert_eq!((file, no_verify), (Some("a.jsonl".into()), true));
        let args = parse("check -c a.toml").unwrap();
        assert!(matches!(args.command, Some(Command::Check { json: false })));
        assert!(args.config.is_some());
        let args = parse("config show").unwrap();
        assert!(matches!(
            args.command,
            Some(Command::Config {
                command: ConfigCommand::Show
            })
        ));

        let args = parse("delete --filter {\"kinds\":[1]} -c a.toml --age 60 --dry-run").unwrap();
        assert_eq!(args.config, Some(PathBuf::from("a.toml")));
        let Some(Command::Delete {
            filter,
            age,
            ids: None,
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
        let Some(Command::Delete { ids, .. }) = parse("delete --ids -").unwrap().command else {
            panic!("not delete");
        };
        assert_eq!(ids, Some("-".into()));
        assert!(parse("delete").is_err());
        assert!(parse("delete --ids a.txt --filter {}").is_err());
        assert!(parse("delete --ids a.txt --age 60").is_err());
        let Some(Command::Cancel { id }) = parse("cancel 12").unwrap().command else {
            panic!("not cancel");
        };
        assert_eq!(id, 12);

        let Some(Command::Compact {
            from,
            into,
            threads,
            bodies,
        }) = parse("compact --from /a --into=/b --threads 8")
            .unwrap()
            .command
        else {
            panic!("not compact");
        };
        assert_eq!(
            (from, into, threads, bodies),
            (Some("/a".into()), Some("/b".into()), 8, false)
        );
        let Some(Command::Compact {
            threads, bodies, ..
        }) = parse("compact").unwrap().command
        else {
            panic!("not compact");
        };
        assert_eq!((threads, bodies), (COMPACT_THREADS, false));
        let Some(Command::Compact { bodies, .. }) = parse("compact --bodies").unwrap().command
        else {
            panic!("not compact");
        };
        assert!(bodies);
        assert!(parse("compact --bodies --from /a --into /b").is_err());

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
            "config",
            "config frob",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
