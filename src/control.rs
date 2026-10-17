//! The relay's control socket, and the lock that says it's running.
//!
//! The running relay holds an exclusive `flock` on [`LOCK_FILE`] in the
//! database's directory, and answers on the Unix socket [`SOCKET_FILE`]
//! beside it, which only its own user may connect to. `ditto-relay delete`
//! asks it there to delete, so that the relay's own writer does it (see
//! [`crate::delete`]). When nothing answers, `delete` takes the lock itself,
//! and a relay starting meanwhile waits for it.
//!
//! A request is a line of JSON, answered with a line of JSON. A deletion is
//! answered once it's [queued](crate::pending), and what it covers hidden,
//! with its id; the relay removes it after, in the background.
//!
//! ```text
//! → {"delete":{"filter":"{\"kinds\":[1]}","age":86400}}
//! ← {"queued":12}    or    {"error":"..."}
//! ```

use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::delete;
use crate::store::{Store, Writer};

/// Held by the running relay, in the database's directory.
pub const LOCK_FILE: &str = "ditto-relay.lock";
/// Where the running relay answers, in the database's directory.
pub const SOCKET_FILE: &str = "control.sock";

/// The longest request read.
const MAX_REQUEST: u64 = 1 << 20;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Request {
    /// Delete what a filter matches, as [`delete::filter`] takes it.
    Delete {
        filter: Option<String>,
        age: Option<u64>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Reply {
    /// The deletion's queued, under this id.
    Queued(u64),
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
    let mut read = BufReader::new(read.take(MAX_REQUEST));
    let outcome = match read.read_line(&mut line).await {
        Ok(_) => match serde_json::from_str(&line) {
            Ok(Request::Delete { filter, age }) => {
                delete(filter, age, store, writer, &mut write).await
            }
            Err(err) => Err(anyhow::anyhow!("not a request: {err}")),
        },
        Err(err) => Err(err.into()),
    };
    if let Err(err) = outcome {
        let _ = send(&mut write, &Reply::Error(format!("{err:#}"))).await;
    }
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

/// Ask the relay answering at `path` to delete what the filter matches.
/// Returns the id it's queued under, or None if no relay is answering
/// there.
pub fn request_delete(
    path: &Path,
    filter: Option<&str>,
    age: Option<u64>,
) -> anyhow::Result<Option<u64>> {
    let mut stream = match std::os::unix::net::UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "couldn't reach the relay at {}; run delete as the relay's user",
                    path.display()
                )
            });
        }
    };
    let request = Request::Delete {
        filter: filter.map(String::from),
        age,
    };
    let mut line = serde_json::to_vec(&request).expect("a request serializes");
    line.push(b'\n');
    stream.write_all(&line)?;
    if let Some(line) = std::io::BufReader::new(stream).lines().next() {
        match serde_json::from_str(&line?).context("the relay answered nonsense")? {
            Reply::Queued(id) => return Ok(Some(id)),
            Reply::Error(err) => bail!("the relay couldn't delete: {err}"),
        }
    }
    bail!("the relay hung up before answering")
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
