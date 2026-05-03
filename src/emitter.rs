/// emitter.rs
///
/// Collects WireEvents from all monitors and forwards them to heal-brain
/// over a Unix domain socket as newline-delimited JSON.
/// Reconnects automatically if heal-brain restarts.

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::types::WireEvent;

/// Path of the Unix socket heal-brain listens on
pub const HEAL_BRAIN_SOCKET: &str = "/tmp/heal-brain.sock";

/// How long to wait before retrying a failed connection
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// How many events to buffer if heal-brain is temporarily unavailable
const BUFFER_CAP: usize = 512;

pub struct Emitter {
    rx:          mpsc::Receiver<WireEvent>,
    socket_path: String,
}

impl Emitter {
    pub fn new(rx: mpsc::Receiver<WireEvent>) -> Self {
        Self { rx, socket_path: HEAL_BRAIN_SOCKET.to_string() }
    }

    pub fn with_socket(mut self, path: &str) -> Self {
        self.socket_path = path.to_string();
        self
    }

    pub async fn run(mut self) {
        info!("Emitter started — connecting to heal-brain at {}", self.socket_path);

        // local buffer for events that arrive while we're reconnecting
        let mut pending: Vec<WireEvent> = Vec::with_capacity(BUFFER_CAP);

        loop {
            // ── Connect ───────────────────────────────────────────────
            let mut stream = loop {
                match UnixStream::connect(&self.socket_path).await {
                    Ok(s)  => { info!("Connected to heal-brain"); break s; }
                    Err(e) => {
                        warn!("Cannot connect to heal-brain ({e}) — retrying in {}s",
                              RECONNECT_DELAY.as_secs());
                        tokio::time::sleep(RECONNECT_DELAY).await;
                    }
                }
            };

            // ── Flush any buffered events first ───────────────────────
            let mut failed = None;
            for event in pending.drain(..) {
                if send_event(&mut stream, &event).await.is_err() {
                    failed = Some(event);
                    break;
                }
            }
            if let Some(event) = failed {
                pending.push(event);
            }

            // ── Stream live events ────────────────────────────────────
            loop {
                match self.rx.recv().await {
                    None => {
                        info!("Event channel closed — emitter stopping");
                        return;
                    }
                    Some(event) => {
                        if send_event(&mut stream, &event).await.is_err() {
                            warn!("Lost connection to heal-brain — buffering event");
                            pending.push(event);
                            // cap the buffer so we don't grow without bound
                            if pending.len() > BUFFER_CAP {
                                warn!("Buffer full — dropping oldest event");
                                pending.remove(0);
                            }
                            break; // break inner loop → reconnect
                        }
                    }
                }
            }
        }
    }
}

/// Serialise a WireEvent as a single JSON line and write it to the stream
async fn send_event(stream: &mut UnixStream, event: &WireEvent) -> std::io::Result<()> {
    let mut line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    stream.write_all(line.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OsEvent;
    use tokio::io::AsyncBufReadExt;
    use tokio::net::UnixListener;
    use tempfile::tempdir;

    #[tokio::test]
    async fn emitter_sends_json_lines() {
        let dir    = tempdir().unwrap();
        let path   = dir.path().join("test.sock");
        let path_s = path.to_str().unwrap().to_string();

        // start a mini listener
        let listener = UnixListener::bind(&path).unwrap();
        let path_clone = path_s.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let reader = tokio::io::BufReader::new(stream);
            let mut lines = reader.lines();
            let mut received = vec![];
            while let Ok(Some(line)) = lines.next_line().await {
                received.push(line);
                if received.len() == 2 { break; }
            }
            received
        });

        // give the listener a moment to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (tx, rx) = mpsc::channel(10);
        let emitter  = Emitter::new(rx).with_socket(&path_clone);
        tokio::spawn(emitter.run());

        // send two events
        tx.send(WireEvent::new(OsEvent::SyscallViolation {
            pid: 100, comm: "bash".into(), syscall: 105, uid: 1001,
        })).await.unwrap();

        tx.send(WireEvent::new(OsEvent::IntegrityViolation {
            path:     "/usr/bin/passwd".into(),
            old_hash: "abc".into(),
            new_hash: "def".into(),
        })).await.unwrap();

        let lines = server.await.unwrap();
        assert_eq!(lines.len(), 2);

        // each line must be valid JSON containing our event types
        let v0: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert!(v0["event"]["SyscallViolation"].is_object());

        let v1: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert!(v1["event"]["IntegrityViolation"].is_object());
    }
}
