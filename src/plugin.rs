//! Write policy plugins, compatible with strfry's: a long-running process
//! that's sent each event as a line of JSON on its stdin, and says whether
//! to take it in a line of JSON on its stdout.
//!
//! Unlike strfry, which waits for each answer before asking again, requests
//! are pipelined, and answers matched to them by event id. strfry's docs ask
//! plugins to allow for that, and a plugin that answers in order can't tell.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::Instant;

use crate::event::{self, Event};
use crate::metrics::METRICS;

/// What the plugin made of an event.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Refused, with what to tell the client.
    Reject(String),
    /// Refused, but the client's told it was accepted.
    ShadowReject(String),
}

/// What's said of events the plugin couldn't judge, as strfry says it.
const INTERNAL_ERROR: &str = "error: internal error";

/// The most requests written to the plugin before flushing.
const BATCH: usize = 256;

/// Who's on the other end of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    Ip(IpAddr),
    /// Someone over Tor, whose address the relay never sees.
    Tor,
}

/// Where an event came from.
pub struct Source<'a> {
    pub peer: Peer,
    /// The pubkey the connection authenticated as, in hex.
    pub authed: Option<&'a str>,
}

/// A handle to the plugin, which runs for as long as any are held.
#[derive(Clone)]
pub struct Plugin {
    requests: mpsc::Sender<Request>,
}

struct Request {
    id: String,
    line: String,
    reply: oneshot::Sender<Verdict>,
}

impl Plugin {
    /// Runs `command` with `sh -c`, restarting it when it dies, takes longer
    /// than `timeout` to answer, or, if it's a path to a script (it has no
    /// spaces), the script changes.
    pub fn spawn(command: String, timeout: Duration) -> Self {
        let (requests, rx) = mpsc::channel(4 * BATCH);
        tokio::spawn(manage(command, timeout, rx));
        Self { requests }
    }

    pub async fn judge(&self, ev: &Event, source: &Source<'_>) -> Verdict {
        let line = request_line(ev, source, u64::from(event::now()));
        let (reply, verdict) = oneshot::channel();
        let request = Request {
            id: ev.id.clone(),
            line,
            reply,
        };
        if self.requests.send(request).await.is_err() {
            return Verdict::Reject(INTERNAL_ERROR.into());
        }
        // Dropped unanswered when the plugin fails.
        verdict
            .await
            .unwrap_or_else(|_| Verdict::Reject(INTERNAL_ERROR.into()))
    }
}

/// strfry's input message, with its newline.
fn request_line(ev: &Event, source: &Source<'_>, now: u64) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Input<'a> {
        r#type: &'static str,
        event: &'a Event,
        received_at: u64,
        source_type: &'static str,
        source_info: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        authed: Option<&'a str>,
    }
    // strfry has no type for Tor, and an address would be one the plugin
    // could mistake for a client's own.
    let (source_type, source_info) = match source.peer {
        Peer::Ip(ip) => match ip.to_canonical() {
            ip if ip.is_ipv4() => ("IP4", ip.to_string()),
            ip => ("IP6", ip.to_string()),
        },
        Peer::Tor => ("Tor", String::new()),
    };
    let input = Input {
        r#type: "new",
        event: ev,
        received_at: now,
        source_type,
        source_info,
        authed: source.authed,
    };
    let mut line = serde_json::to_string(&input).expect("plugin input serializes");
    line.push('\n');
    line
}

/// Hands requests to the running plugin, starting one as needed.
async fn manage(command: String, timeout: Duration, mut requests: mpsc::Receiver<Request>) {
    let script = (!command.contains(' ')).then(|| command.clone());
    let mut running: Option<Running> = None;
    let mut batch = Vec::with_capacity(BATCH);

    while requests.recv_many(&mut batch, BATCH).await > 0 {
        if let (Some(path), Some(r)) = (&script, &running)
            && modified(path) != r.modified
        {
            tracing::info!("write policy plugin changed, restarting it");
            running = None;
        }

        for Request { id, line, reply } in batch.drain(..) {
            let deadline = Instant::now() + timeout;
            let mut reply = Some(reply);
            // A plugin that's just died won't take it, but a new one will.
            for _ in 0..2 {
                if running.is_none() {
                    running = Running::spawn(&command, script.as_deref());
                }
                let Some(r) = &mut running else { break };
                match r.pending.wait(id.clone(), deadline, reply.take().unwrap()) {
                    Ok(()) => {
                        if r.stdin.write_all(line.as_bytes()).await.is_err() {
                            running = None;
                        }
                        break;
                    }
                    Err(back) => {
                        reply = Some(back);
                        running = None;
                    }
                }
            }
        }

        if let Some(r) = &mut running
            && r.stdin.flush().await.is_err()
        {
            running = None;
        }
    }
}

fn modified(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// A plugin process, which is retired when this is dropped: its stdin is
/// closed, and it's stopped once it's answered what it was asked.
struct Running {
    stdin: BufWriter<ChildStdin>,
    pending: Arc<Pending>,
    /// When the script was last changed, if the command is one.
    modified: Option<SystemTime>,
    _retire: oneshot::Sender<()>,
}

impl Running {
    fn spawn(command: &str, script: Option<&str>) -> Option<Self> {
        tracing::info!("starting write policy plugin: {command}");
        let spawned = Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(err) => {
                tracing::error!("failed to start write policy plugin: {err}");
                METRICS.errors_plugin.inc();
                return None;
            }
        };
        let stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        let pending = Arc::new(Pending::default());
        let (retire, retired) = oneshot::channel();
        tokio::spawn(read(child, stdout, pending.clone(), retired));
        Some(Self {
            stdin: BufWriter::new(stdin),
            pending,
            modified: script.and_then(modified),
            _retire: retire,
        })
    }
}

/// Requests a plugin hasn't answered yet, oldest first.
#[derive(Default)]
struct Pending {
    state: Mutex<PendingState>,
    added: Notify,
}

#[derive(Default)]
struct PendingState {
    /// The plugin is gone, so won't answer anything more.
    closed: bool,
    waiting: VecDeque<Waiting>,
}

struct Waiting {
    id: String,
    deadline: Instant,
    reply: oneshot::Sender<Verdict>,
}

impl Pending {
    /// Waits for an answer about `id`, unless the plugin's gone, when the
    /// reply is handed back.
    fn wait(
        &self,
        id: String,
        deadline: Instant,
        reply: oneshot::Sender<Verdict>,
    ) -> Result<(), oneshot::Sender<Verdict>> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(reply);
        }
        state.waiting.push_back(Waiting {
            id,
            deadline,
            reply,
        });
        drop(state);
        self.added.notify_one();
        Ok(())
    }

    fn oldest_deadline(&self) -> Option<Instant> {
        let state = self.state.lock().unwrap();
        state.waiting.front().map(|w| w.deadline)
    }

    /// Hands one of the plugin's output lines to whom it answers.
    fn answer(&self, line: &str) {
        #[derive(Deserialize)]
        struct Output {
            id: String,
            action: String,
            #[serde(default)]
            msg: Option<String>,
        }
        let Ok(output) = serde_json::from_str::<Output>(line) else {
            tracing::warn!("unparseable line from write policy plugin: {line}");
            return;
        };
        let waiting = {
            let mut state = self.state.lock().unwrap();
            let Some(at) = state.waiting.iter().position(|w| w.id == output.id) else {
                drop(state);
                tracing::warn!("write policy plugin answered for an unknown event: {line}");
                return;
            };
            state.waiting.remove(at).expect("found")
        };
        let msg = output.msg.unwrap_or_default();
        let verdict = match output.action.as_str() {
            "accept" => Verdict::Accept,
            "reject" => Verdict::Reject(msg),
            "shadowReject" => Verdict::ShadowReject(msg),
            _ => {
                tracing::error!("unknown action from write policy plugin: {line}");
                METRICS.errors_plugin.inc();
                Verdict::Reject(INTERNAL_ERROR.into())
            }
        };
        let _ = waiting.reply.send(verdict);
    }

    /// Fails whatever's still waiting.
    fn close(&self) -> usize {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        std::mem::take(&mut state.waiting).len()
    }
}

/// Reads a plugin's answers until it exits, takes too long, or is retired
/// with nothing left to answer, then stops it.
async fn read(
    mut child: Child,
    stdout: ChildStdout,
    pending: Arc<Pending>,
    mut retired: oneshot::Receiver<()>,
) {
    let mut lines = BufReader::new(stdout).lines();
    let mut is_retired = false;
    loop {
        let deadline = pending.oldest_deadline();
        if is_retired && deadline.is_none() {
            break;
        }
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(line)) => pending.answer(&line),
                Ok(None) => {
                    if !is_retired {
                        tracing::error!("write policy plugin exited");
                        METRICS.errors_plugin.inc();
                    }
                    break;
                }
                Err(err) => {
                    tracing::error!("failed to read from write policy plugin: {err}");
                    METRICS.errors_plugin.inc();
                    break;
                }
            },
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                tracing::error!("write policy plugin timed out");
                METRICS.errors_plugin.inc();
                break;
            }
            _ = pending.added.notified() => {}
            _ = &mut retired, if !is_retired => is_retired = true,
        }
    }

    let failed = pending.close();
    if failed > 0 {
        tracing::error!("{failed} events failed for want of a write policy plugin");
    }
    // Asked nicely, as strfry does, then not.
    if let Some(pid) = child.id() {
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;

    fn source() -> Source<'static> {
        Source {
            peer: Peer::Ip("::ffff:1.2.3.4".parse().unwrap()),
            authed: None,
        }
    }

    #[test]
    fn asks_as_strfry_does() {
        let ev = signed(1, 100, 1, vec![], "hi");
        let line = request_line(&ev, &source(), 123);
        assert!(line.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["type"], "new");
        assert_eq!(value["event"]["id"], ev.id.as_str());
        assert_eq!(value["receivedAt"], 123);
        assert_eq!(value["sourceType"], "IP4");
        assert_eq!(value["sourceInfo"], "1.2.3.4");
        assert!(value.get("authed").is_none());

        let authed = Source {
            peer: Peer::Ip("2001:db8::1".parse().unwrap()),
            authed: Some(&ev.pubkey),
        };
        let value: serde_json::Value =
            serde_json::from_str(&request_line(&ev, &authed, 123)).unwrap();
        assert_eq!(value["sourceType"], "IP6");
        assert_eq!(value["sourceInfo"], "2001:db8::1");
        assert_eq!(value["authed"], ev.pubkey.as_str());

        let tor = Source {
            peer: Peer::Tor,
            authed: None,
        };
        let value: serde_json::Value = serde_json::from_str(&request_line(&ev, &tor, 123)).unwrap();
        assert_eq!(value["sourceType"], "Tor");
        assert_eq!(value["sourceInfo"], "");
    }

    /// A plugin written in shell, which judges events by their content.
    fn plugin(dir: &tempfile::TempDir, body: &str, timeout: Duration) -> Plugin {
        let path = dir.path().join("plugin.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        Plugin::spawn(path.to_str().unwrap().into(), timeout)
    }

    /// Answers by echoing the id with the event's content as the action.
    const BY_CONTENT: &str = r#"
while read -r line; do
  id=$(echo "$line" | sed 's/.*"id":"\([0-9a-f]*\)".*/\1/')
  action=$(echo "$line" | sed 's/.*"content":"\([A-Za-z]*\)".*/\1/')
  echo "{\"id\":\"$id\",\"action\":\"$action\",\"msg\":\"blocked: no\"}"
done
"#;

    #[tokio::test]
    async fn follows_the_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let plugin = plugin(&dir, BY_CONTENT, Duration::from_secs(10));
        let judge = |content: &str| {
            let ev = signed(1, 100, 1, vec![], content);
            let plugin = plugin.clone();
            async move { plugin.judge(&ev, &source()).await }
        };
        assert_eq!(judge("accept").await, Verdict::Accept);
        assert_eq!(judge("reject").await, Verdict::Reject("blocked: no".into()));
        assert_eq!(
            judge("shadowReject").await,
            Verdict::ShadowReject("blocked: no".into())
        );
        assert_eq!(judge("bogus").await, Verdict::Reject(INTERNAL_ERROR.into()));
    }

    #[tokio::test]
    async fn pipelines_and_matches_answers_by_id() {
        let dir = tempfile::tempdir().unwrap();
        // Holds every other answer back, so they come out of order.
        let body = r#"
held=""
while read -r line; do
  id=$(echo "$line" | sed 's/.*"id":"\([0-9a-f]*\)".*/\1/')
  if [ -z "$held" ]; then
    held=$id
  else
    echo "{\"id\":\"$id\",\"action\":\"accept\"}"
    echo "{\"id\":\"$held\",\"action\":\"reject\",\"msg\":\"held\"}"
    held=""
  fi
done
"#;
        let plugin = plugin(&dir, body, Duration::from_secs(10));
        let a = signed(1, 100, 1, vec![], "a");
        let b = signed(1, 100, 1, vec![], "b");
        let source = source();
        let (va, vb) = tokio::join!(plugin.judge(&a, &source), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            plugin.judge(&b, &source).await
        });
        assert_eq!(va, Verdict::Reject("held".into()));
        assert_eq!(vb, Verdict::Accept);
    }

    #[tokio::test]
    async fn restarts_a_plugin_that_times_out_or_dies() {
        let dir = tempfile::tempdir().unwrap();
        // Hangs on its first event, then dies after answering one.
        let body = r#"
if [ ! -e "$0.ran" ]; then touch "$0.ran"; sleep 60; fi
read -r line
id=$(echo "$line" | sed 's/.*"id":"\([0-9a-f]*\)".*/\1/')
echo "{\"id\":\"$id\",\"action\":\"accept\"}"
"#;
        let plugin = plugin(&dir, body, Duration::from_millis(300));
        let ev = signed(1, 100, 1, vec![], "");
        let error = Verdict::Reject(INTERNAL_ERROR.into());
        assert_eq!(plugin.judge(&ev, &source()).await, error);
        assert_eq!(plugin.judge(&ev, &source()).await, Verdict::Accept);
        // Time to notice it's gone.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(plugin.judge(&ev, &source()).await, Verdict::Accept);
    }

    #[tokio::test]
    async fn reloads_a_changed_script() {
        let dir = tempfile::tempdir().unwrap();
        let answer = |action: &str| {
            format!(
                r#"
while read -r line; do
  id=$(echo "$line" | sed 's/.*"id":"\([0-9a-f]*\)".*/\1/')
  echo "{{\"id\":\"$id\",\"action\":\"{action}\"}}"
done
"#
            )
        };
        let plugin = plugin(&dir, &answer("accept"), Duration::from_secs(10));
        let ev = signed(1, 100, 1, vec![], "");
        assert_eq!(plugin.judge(&ev, &source()).await, Verdict::Accept);

        // Far enough on that the change shows on coarse clocks.
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Swapped in whole: sh reads the script it's running as it goes.
        let path = dir.path().join("plugin.sh");
        let new = dir.path().join("new.sh");
        std::fs::write(&new, format!("#!/bin/sh\n{}", answer("shadowReject"))).unwrap();
        std::fs::set_permissions(&new, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        std::fs::rename(&new, &path).unwrap();
        assert_eq!(
            plugin.judge(&ev, &source()).await,
            Verdict::ShadowReject(String::new())
        );
    }
}
