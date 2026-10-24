//! The relay's control socket, and the lock that says it's running.
//!
//! The running relay holds an exclusive `flock` on [`LOCK_FILE`] in the
//! database's directory, and answers on the Unix socket [`SOCKET_FILE`]
//! beside it, which only its own user may connect to. `ditto-relay delete`
//! and `ditto-relay import` ask it there to delete and to store, so that the
//! relay's own writer does it (see [`crate::delete`] and [`crate::import`]).
//! When nothing answers, they take the lock themselves, and a relay starting
//! meanwhile waits for them.
//!
//! A request is a line of JSON, answered with a line of JSON. A deletion is
//! answered once it's [queued](crate::pending), and what it covers hidden,
//! with its id; the relay removes it after, in the background. A deletion
//! by ids, and an import, are followed by the ids or the events, a line
//! each, until the client shuts its side down: a deletion's is answered
//! once it's queued, an import's once they're all stored.
//!
//! ```text
//! → {"delete":{"filter":"{\"kinds\":[1]}","age":86400}}
//! ← {"queued":12}    or    {"error":"..."}
//!
//! → {"delete":{"ids":true}}
//! → <hex id>
//! → ...
//! ← {"queued":13}    or    {"error":"..."}
//!
//! → {"cancel":{"id":12}}
//! ← {"cancelled":12}    or    {"error":"..."}
//!
//! → {"import":{"verify":true}}
//! → {"id":"...","pubkey":"...",...}
//! → ...
//! ← {"imported":{"stored":2,"archived":0,"duplicate":1,"refused":{}}}
//! ```

use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::delete;
use crate::import::{Importer, Tally};
use crate::pending::Target;
use crate::repack::Repacked;
use crate::store::{Store, Writer};

/// Held by the running relay, in the database's directory.
pub const LOCK_FILE: &str = "ditto-relay.lock";
/// Where the running relay answers, in the database's directory.
pub const SOCKET_FILE: &str = "control.sock";

/// The longest request read.
const MAX_REQUEST: u64 = 1 << 20;
/// The longest event imported.
const MAX_EVENT: u64 = 64 << 20;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Request {
    /// Delete what a filter matches, as [`delete::filter`] takes it, or
    /// with `ids`, the events whose ids follow.
    Delete {
        filter: Option<String>,
        age: Option<u64>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        ids: bool,
    },
    /// Cancel a pending deletion: see [`crate::purge::Purger::cancel`].
    Cancel { id: u64 },
    /// Store the events that follow, a line each: see [`crate::import`].
    Import { verify: bool },
    /// Compact the database as it runs: see [`crate::repack`].
    Repack { bodies: bool, threads: usize },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Reply {
    /// The deletion's queued, under this id.
    Queued(u64),
    /// The deletion with this id is cancelled.
    Cancelled(u64),
    /// The import's done, and this is what became of it.
    Imported(Tally),
    /// How a repack's going, a line at a time.
    Progress(String),
    /// The repack's done, and this is what it did.
    Repacked(Repacked),
    Error(String),
}

/// The socket the relay with its database at `db` answers on.
pub fn socket_path(db: &Path) -> PathBuf {
    db.join(SOCKET_FILE)
}

/// The lock on a database, held while it's in use by a relay, or by a
/// `delete` while no relay runs. It's let go when dropped, or when the
/// process ends however it ends.
pub struct Lock {
    _file: std::fs::File,
}

impl Lock {
    /// Take the lock on the database at `db`, waiting for whoever holds it.
    pub fn acquire(db: &Path) -> anyhow::Result<Lock> {
        let (file, path) = open(db)?;
        if !flock(&file, libc::LOCK_EX | libc::LOCK_NB)? {
            tracing::info!(
                "waiting for the lock on {}: a ditto-relay delete, or another relay, is using the database",
                path.display()
            );
            flock(&file, libc::LOCK_EX)?;
        }
        Ok(Lock { _file: file })
    }

    /// Take the lock on the database at `db`, if nobody holds it.
    pub fn try_acquire(db: &Path) -> anyhow::Result<Option<Lock>> {
        let (file, _) = open(db)?;
        Ok(flock(&file, libc::LOCK_EX | libc::LOCK_NB)?.then_some(Lock { _file: file }))
    }
}

fn open(db: &Path) -> anyhow::Result<(std::fs::File, PathBuf)> {
    std::fs::create_dir_all(db)
        .with_context(|| format!("Could not create the database directory {}", db.display()))?;
    let path = db.join(LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    Ok((file, path))
}

/// Whether `file` got locked, as `operation` asks: without `LOCK_NB`, it
/// waits until it does.
fn flock(file: &std::fs::File, operation: i32) -> anyhow::Result<bool> {
    loop {
        // SAFETY: an open file's descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => return Ok(false),
            Some(libc::EINTR) => continue,
            _ => return Err(error).context("couldn't lock the database"),
        }
    }
}

/// Answer on the socket at `path` until `shutdown`. Only call it holding
/// the [`Lock`]: whatever's at `path` is a socket some relay left behind.
pub fn serve(
    path: &Path,
    store: Arc<Store>,
    writer: Writer,
    shutdown: CancellationToken,
) -> anyhow::Result<JoinHandle<()>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("Could not listen on {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(err) => {
                        tracing::warn!("couldn't accept on the control socket: {err}");
                        continue;
                    }
                },
            };
            tokio::spawn(answer(stream, store.clone(), writer.clone()));
        }
    }))
}

async fn answer(stream: UnixStream, store: Arc<Store>, writer: Writer) {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    let mut read = BufReader::new(read);
    let outcome = match read_line(&mut read, &mut line, MAX_REQUEST).await {
        Ok(_) => match serde_json::from_str(&line) {
            Ok(Request::Delete { ids: true, .. }) => {
                delete_ids(&mut read, store, writer, &mut write).await
            }
            Ok(Request::Delete { filter, age, .. }) => {
                delete(filter, age, store, writer, &mut write).await
            }
            Ok(Request::Cancel { id }) => match writer.cancel(id).await {
                Ok(()) => send(&mut write, &Reply::Cancelled(id))
                    .await
                    .map_err(Into::into),
                Err(err) => Err(err),
            },
            Ok(Request::Import { verify }) => {
                import(&mut read, verify, store, writer, &mut write).await
            }
            Ok(Request::Repack { bodies, threads }) => {
                repack(bodies, threads, store, &mut write).await
            }
            Err(err) => Err(anyhow::anyhow!("not a request: {err}")),
        },
        Err(err) => Err(err),
    };
    if let Err(err) = outcome {
        let _ = send(&mut write, &Reply::Error(format!("{err:#}"))).await;
    }
}

/// Read a line of at most `max` bytes into `line`, returning how many, 0
/// at the end.
async fn read_line(
    read: &mut (impl AsyncBufRead + Unpin),
    line: &mut String,
    max: u64,
) -> anyhow::Result<usize> {
    line.clear();
    let n = (&mut *read).take(max).read_line(line).await?;
    if n as u64 == max && !line.ends_with('\n') {
        bail!("a line is longer than {max} bytes");
    }
    Ok(n)
}

async fn send(write: &mut (impl AsyncWriteExt + Unpin), reply: &Reply) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(reply).expect("a reply serializes");
    line.push(b'\n');
    write.write_all(&line).await
}

/// Have the writer queue a deletion of what the filter matches, or picks,
/// and say it's queued.
async fn delete(
    json: Option<String>,
    age: Option<u64>,
    store: Arc<Store>,
    writer: Writer,
    write: &mut (impl AsyncWriteExt + Unpin),
) -> anyhow::Result<()> {
    let filter = delete::filter(
        json.as_deref(),
        age,
        crate::event::now(),
        &store.indexed_tags,
    )?;
    // Picking reads, maybe for a while: not on the runtime's threads.
    let target =
        tokio::task::spawn_blocking(move || delete::target(&store, filter, json.as_deref(), age))
            .await??;
    let pending = writer.delete(target).await?;
    send(write, &Reply::Queued(pending.id)).await?;
    Ok(())
}

/// Have the writer queue a deletion of the events whose ids follow, a line
/// each, as picked, and say it's queued.
async fn delete_ids(
    read: &mut (impl AsyncBufRead + Unpin),
    store: Arc<Store>,
    writer: Writer,
    write: &mut (impl AsyncWriteExt + Unpin),
) -> anyhow::Result<()> {
    let mut ids = Vec::new();
    let mut line = String::new();
    while read_line(read, &mut line, MAX_REQUEST).await? > 0 {
        let id = line.trim();
        if !id.is_empty() {
            ids.push(delete::parse_id(id)?);
        }
    }
    let seqs = tokio::task::spawn_blocking(move || delete::pick_ids(&store, &ids)).await??;
    let pending = writer.delete(Target::Seqs(Arc::new(seqs))).await?;
    send(write, &Reply::Queued(pending.id)).await?;
    Ok(())
}

/// Have the writer store the events that follow, a line each, and say
/// what became of them once they're stored.
async fn import(
    read: &mut (impl AsyncBufRead + Unpin),
    verify: bool,
    store: Arc<Store>,
    writer: Writer,
    write: &mut (impl AsyncWriteExt + Unpin),
) -> anyhow::Result<()> {
    tracing::info!("importing events");
    let mut importer = Importer::new(store, writer, verify);
    let mut line = String::new();
    while read_line(read, &mut line, MAX_EVENT).await? > 0 {
        importer.line(&line).await?;
    }
    let tally = importer.finish().await?;
    tracing::info!(
        "imported {} events: {} stored, {} as history, {} here already, {} refused",
        tally.total(),
        tally.stored,
        tally.archived,
        tally.duplicate,
        tally.refused.values().sum::<u64>()
    );
    send(write, &Reply::Imported(tally)).await?;
    Ok(())
}

/// Repack the database, saying how it's going, then what it did. It goes
/// on if whoever asked hangs up.
async fn repack(
    bodies: bool,
    threads: usize,
    store: Arc<Store>,
    write: &mut (impl AsyncWriteExt + Unpin),
) -> anyhow::Result<()> {
    let (said, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let repacking = tokio::task::spawn_blocking(move || {
        crate::repack::repack(&store, bodies, threads, &mut |line| {
            let _ = said.send(line.to_string());
        })
    });
    let mut listening = true;
    while let Some(line) = lines.recv().await {
        if listening && send(write, &Reply::Progress(line)).await.is_err() {
            listening = false;
        }
    }
    let repacked = repacking.await??;
    send(write, &Reply::Repacked(repacked)).await?;
    Ok(())
}

/// Connect to the relay answering at `path`, or None if no relay is
/// answering there.
fn connect(path: &Path) -> anyhow::Result<Option<std::os::unix::net::UnixStream>> {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(stream) => Ok(Some(stream)),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "couldn't reach the relay at {}; run this as the relay's user",
                path.display()
            )
        }),
    }
}

/// The relay's answer, read from `stream`.
fn reply(stream: std::os::unix::net::UnixStream) -> anyhow::Result<Reply> {
    match std::io::BufReader::new(stream).lines().next() {
        Some(line) => serde_json::from_str(&line?).context("the relay answered nonsense"),
        None => bail!("the relay hung up before answering"),
    }
}

/// Have the relay answering at `path` store the events in `input`, a line
/// each, telling `progress` how many lines it's been sent, every so often.
/// Returns what became of them, or None if no relay is answering there.
pub fn request_import(
    path: &Path,
    input: impl BufRead,
    verify: bool,
    mut progress: impl FnMut(u64),
) -> anyhow::Result<Option<Tally>> {
    let Some(stream) = connect(path)? else {
        return Ok(None);
    };
    let mut line = serde_json::to_vec(&Request::Import { verify }).expect("a request serializes");
    line.push(b'\n');
    // Whatever goes wrong sending, the relay may have said why.
    let sent = (|| -> anyhow::Result<()> {
        let mut out = std::io::BufWriter::with_capacity(1 << 20, &stream);
        out.write_all(&line)?;
        let mut sent = 0u64;
        for line in input.lines() {
            let line = line.context("couldn't read the events")?;
            out.write_all(line.as_bytes())?;
            out.write_all(b"\n")?;
            sent += 1;
            if sent.is_multiple_of(10_000) {
                progress(sent);
            }
        }
        out.flush()?;
        Ok(())
    })();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let reply = reply(stream);
    match (reply, sent) {
        (Ok(Reply::Imported(tally)), Ok(())) => Ok(Some(tally)),
        (Ok(Reply::Error(err)), _) => bail!("the relay couldn't import: {err}"),
        (_, Err(err)) => Err(err),
        (Ok(_), Ok(())) => bail!("the relay answered something else"),
        (Err(err), Ok(())) => Err(err),
    }
}

/// Ask the relay answering at `path` to delete what the filter matches.
/// Returns the id it's queued under, or None if no relay is answering
/// there.
pub fn request_delete(
    path: &Path,
    filter: Option<&str>,
    age: Option<u64>,
) -> anyhow::Result<Option<u64>> {
    let Some(mut stream) = connect(path)? else {
        return Ok(None);
    };
    let request = Request::Delete {
        filter: filter.map(String::from),
        age,
        ids: false,
    };
    let mut line = serde_json::to_vec(&request).expect("a request serializes");
    line.push(b'\n');
    stream.write_all(&line)?;
    match reply(stream)? {
        Reply::Queued(id) => Ok(Some(id)),
        Reply::Error(err) => bail!("the relay couldn't delete: {err}"),
        _ => bail!("the relay answered something else"),
    }
}

/// Ask the relay answering at `path` to delete the events of `ids`.
/// Returns the id it's queued under, or None if no relay is answering
/// there.
pub fn request_delete_ids(path: &Path, ids: &[[u8; 32]]) -> anyhow::Result<Option<u64>> {
    let Some(stream) = connect(path)? else {
        return Ok(None);
    };
    let request = Request::Delete {
        filter: None,
        age: None,
        ids: true,
    };
    let mut line = serde_json::to_vec(&request).expect("a request serializes");
    line.push(b'\n');
    // Whatever goes wrong sending, the relay may have said why.
    let sent = (|| -> std::io::Result<()> {
        let mut out = std::io::BufWriter::with_capacity(1 << 20, &stream);
        out.write_all(&line)?;
        for id in ids {
            out.write_all(hex::encode(id).as_bytes())?;
            out.write_all(b"\n")?;
        }
        out.flush()
    })();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    match (reply(stream), sent) {
        (Ok(Reply::Queued(id)), Ok(())) => Ok(Some(id)),
        (Ok(Reply::Error(err)), _) => bail!("the relay couldn't delete: {err}"),
        (_, Err(err)) => Err(err.into()),
        (Ok(_), Ok(())) => bail!("the relay answered something else"),
        (Err(err), Ok(())) => Err(err),
    }
}

/// Ask the relay answering at `path` to cancel deletion `id`. Returns
/// whether a relay answered there; one that can't cancel it says why.
pub fn request_cancel(path: &Path, id: u64) -> anyhow::Result<bool> {
    let Some(mut stream) = connect(path)? else {
        return Ok(false);
    };
    let mut line = serde_json::to_vec(&Request::Cancel { id }).expect("a request serializes");
    line.push(b'\n');
    stream.write_all(&line)?;
    match reply(stream)? {
        Reply::Cancelled(_) => Ok(true),
        Reply::Error(err) => bail!("{err}"),
        _ => bail!("the relay answered something else"),
    }
}

/// Ask the relay answering at `path` to repack its database, or with
/// `bodies`, its event records, handing `say` each line it says of how it's
/// going. Returns what it did, or None if no relay is answering there.
pub fn request_repack(
    path: &Path,
    bodies: bool,
    threads: usize,
    mut say: impl FnMut(&str),
) -> anyhow::Result<Option<Repacked>> {
    let Some(mut stream) = connect(path)? else {
        return Ok(None);
    };
    let request = Request::Repack { bodies, threads };
    let mut line = serde_json::to_vec(&request).expect("a request serializes");
    line.push(b'\n');
    stream.write_all(&line)?;
    for line in std::io::BufReader::new(stream).lines() {
        match serde_json::from_str(&line?).context("the relay answered nonsense")? {
            Reply::Progress(line) => say(&line),
            Reply::Repacked(repacked) => return Ok(Some(repacked)),
            Reply::Error(err) => bail!("the relay couldn't repack: {err}"),
            _ => bail!("the relay answered something else"),
        }
    }
    bail!("the relay hung up before it was done")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_a_second_holder() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db");
        let held = Lock::try_acquire(&db).unwrap().expect("free");
        assert!(Lock::try_acquire(&db).unwrap().is_none());
        drop(held);
        assert!(Lock::try_acquire(&db).unwrap().is_some());
    }

    /// The relay's writer queues a deletion, hiding what it covers at once,
    /// removes it between its own writes, and tells the search indexer what
    /// went.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_deletes_when_asked() {
        use crate::event::tests::signed;
        use crate::store::tests::{open, put};

        let (dir, store) = open();
        let store = Arc::new(store);
        let count = 1010;
        for i in 0..count {
            put(&store, &signed(1, 100 + i, 1, vec![], "spam"));
        }
        put(&store, &signed(2, 100, 1, vec![], "ham"));
        let (indexer, told) = std::sync::mpsc::channel();
        let writer = Writer::spawn(store.clone(), Some(indexer), |_| {});
        let path = socket_path(dir.path());
        let shutdown = CancellationToken::new();
        let serving = serve(&path, store.clone(), writer.clone(), shutdown.clone()).unwrap();

        let author = signed(1, 0, 1, vec![], "").pubkey;
        let filter = format!(r#"{{"authors":["{author}"]}}"#);
        let asked = path.clone();
        let id = tokio::task::spawn_blocking(move || request_delete(&asked, Some(&filter), None))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(id, Some(1));
        // Hidden at once.
        let visible = |store: &Store| {
            let txn = store.read().unwrap();
            (1..=count + 1)
                .filter(|&seq| store.load(&txn, seq).unwrap().is_some())
                .count()
        };
        assert_eq!(visible(&store), 1);
        // Gone soon after.
        for _ in 0..500 {
            if store.pending().is_empty() && store.len(&store.read().unwrap()).unwrap() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 1);
        let removed: usize = told.try_iter().map(|seqs| seqs.len()).sum();
        assert_eq!(removed, count as usize);

        // A bad filter is the relay's to refuse, and says why.
        let asked = path.clone();
        let refused = tokio::task::spawn_blocking(move || {
            request_delete(&asked, Some("{\"kinds\":\"x\"}"), None)
        })
        .await
        .unwrap();
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .starts_with("the relay couldn't delete")
        );

        // As is cancelling what isn't pending.
        let asked = path.clone();
        let refused = tokio::task::spawn_blocking(move || request_cancel(&asked, 99))
            .await
            .unwrap();
        assert_eq!(
            refused.unwrap_err().to_string(),
            "no deletion 99 is pending"
        );

        shutdown.cancel();
        serving.await.unwrap();
        tokio::task::spawn_blocking(move || writer.stop())
            .await
            .unwrap();
    }

    /// Sent ids, the relay deletes the events of those stored, as one
    /// deletion; and says why it won't, sent something that isn't an id.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_deletes_by_ids() {
        use crate::event::tests::signed;
        use crate::store::tests::{open, put};

        let (dir, store) = open();
        let store = Arc::new(store);
        let events: Vec<_> = (0..5).map(|i| signed(1, 100 + i, 1, vec![], "")).collect();
        for event in &events {
            put(&store, event);
        }
        let writer = Writer::spawn(store.clone(), None, |_| {});
        let path = socket_path(dir.path());
        let shutdown = CancellationToken::new();
        let serving = serve(&path, store.clone(), writer.clone(), shutdown.clone()).unwrap();

        let mut ids: Vec<[u8; 32]> = events[..3]
            .iter()
            .map(|event| delete::parse_id(&event.id).unwrap())
            .collect();
        ids.push([7; 32]);
        let asked = path.clone();
        let id = tokio::task::spawn_blocking(move || request_delete_ids(&asked, &ids))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(id, Some(1));
        let visible = |store: &Store| {
            let txn = store.read().unwrap();
            (1..=5)
                .filter(|&seq| store.load(&txn, seq).unwrap().is_some())
                .count()
        };
        assert_eq!(visible(&store), 2);

        let asked = path.clone();
        let refused = tokio::task::spawn_blocking(move || {
            let Some(mut stream) = connect(&asked)? else {
                bail!("no relay");
            };
            stream.write_all(b"{\"delete\":{\"ids\":true}}\nnope\n")?;
            stream.shutdown(std::net::Shutdown::Write)?;
            match reply(stream)? {
                Reply::Error(err) => Ok(err),
                _ => bail!("not refused"),
            }
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(refused, "\"nope\" isn't an event id: 64 hex digits");

        shutdown.cancel();
        serving.await.unwrap();
        tokio::task::spawn_blocking(move || writer.stop())
            .await
            .unwrap();
    }

    /// The relay's writer stores what's sent, and says what became of it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_imports_what_its_sent() {
        use crate::event::tests::signed;
        use crate::store::tests::open;

        let (dir, store) = open();
        let store = Arc::new(store);
        let writer = Writer::spawn(store.clone(), None, |_| {});
        let path = socket_path(dir.path());
        let shutdown = CancellationToken::new();
        let serving = serve(&path, store.clone(), writer.clone(), shutdown.clone()).unwrap();

        let events: String = (0..3)
            .map(|i| serde_json::to_string(&signed(1, 100 + i, 1, vec![], "x")).unwrap() + "\n")
            .chain(["nonsense\n".to_string()])
            .collect();
        let asked = path.clone();
        let tally = tokio::task::spawn_blocking(move || {
            request_import(&asked, events.as_bytes(), true, |_| {})
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!((tally.stored, tally.total()), (3, 4));
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 3);

        shutdown.cancel();
        serving.await.unwrap();
        tokio::task::spawn_blocking(move || writer.stop())
            .await
            .unwrap();
    }

    /// The relay repacks as it runs, saying how it's going.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_repacks_when_asked() {
        use crate::event::tests::signed;
        use crate::store::tests::{open, put};

        let (dir, store) = open();
        let store = Arc::new(store);
        for i in 0..50 {
            put(&store, &signed(1, 100 + i, 1, vec![], "x"));
        }
        let writer = Writer::spawn(store.clone(), None, |_| {});
        let path = socket_path(dir.path());
        let shutdown = CancellationToken::new();
        let serving = serve(&path, store.clone(), writer.clone(), shutdown.clone()).unwrap();

        let asked = path.clone();
        let (repacked, said) = tokio::task::spawn_blocking(move || {
            let mut said = Vec::new();
            let repacked = request_repack(&asked, false, 2, |line| said.push(line.to_string()));
            (repacked, said)
        })
        .await
        .unwrap();
        let repacked = repacked.unwrap().expect("a relay answered");
        assert!(
            repacked
                .tables
                .iter()
                .any(|(name, n)| name == "ids" && *n == 50)
        );
        assert!(
            said.iter().any(|line| line.starts_with("put the copy")),
            "{said:?}"
        );
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 50);

        shutdown.cancel();
        serving.await.unwrap();
        tokio::task::spawn_blocking(move || writer.stop())
            .await
            .unwrap();
    }

    #[test]
    fn nobody_answering_is_no_relay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SOCKET_FILE);
        assert!(request_delete(&path, None, Some(1)).unwrap().is_none());
        // One a relay left behind.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(request_delete(&path, None, Some(1)).unwrap().is_none());
    }
}
