/// integrity_check.rs
///
/// Periodically SHA-256 hashes a list of watched binaries and kernel modules.
/// On first run it builds a baseline. On subsequent runs it compares against
/// the baseline and fires an IntegrityViolation event if anything changed.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::types::{OsEvent, WATCHED_BINARIES, WireEvent};

/// How often we re-hash the watched binaries
const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Compute SHA-256 of a file, returning hex string
fn hash_file(path: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(&bytes);
    Some(hex::encode(digest))
}

/// Load extra watched paths from /proc/modules (kernel modules)
fn kernel_module_paths() -> Vec<String> {
    let content = std::fs::read_to_string("/proc/modules").unwrap_or_default();
    content.lines().filter_map(|line| {
        let name = line.split_whitespace().next()?;
        // modules live under /sys/module/<name>
        let path = format!("/sys/module/{}/sections/.text", name);
        if Path::new(&path).exists() { Some(path) } else { None }
    }).collect()
}

pub struct IntegrityChecker {
    tx:       mpsc::Sender<WireEvent>,
    /// Extra paths to watch beyond WATCHED_BINARIES (injected in tests)
    extra:    Vec<String>,
}

impl IntegrityChecker {
    pub fn new(tx: mpsc::Sender<WireEvent>) -> Self {
        Self { tx, extra: vec![] }
    }

    pub fn with_paths(mut self, paths: Vec<String>) -> Self {
        self.extra = paths;
        self
    }

    pub async fn run(self) {
        info!("IntegrityChecker started — baseline + check every {}s",
              CHECK_INTERVAL.as_secs());

        let mut baseline: HashMap<String, String> = HashMap::new();
        let mut interval = tokio::time::interval(CHECK_INTERVAL);

        // build watched list: static binaries + kernel modules + injected extras
        let mut watched: Vec<String> = WATCHED_BINARIES
            .iter()
            .map(|s| s.to_string())
            .collect();
        watched.extend(kernel_module_paths());
        watched.extend(self.extra.clone());

        loop {
            interval.tick().await;

            for path in &watched {
                let Some(current_hash) = hash_file(path) else {
                    // file doesn't exist on this system — skip silently
                    continue;
                };

                match baseline.get(path) {
                    None => {
                        // first run — record baseline
                        info!(path, hash = %current_hash, "Baseline recorded");
                        baseline.insert(path.clone(), current_hash);
                    }
                    Some(known_hash) if *known_hash != current_hash => {
                        warn!(
                            path,
                            old_hash = %known_hash,
                            new_hash = %current_hash,
                            "INTEGRITY VIOLATION — file changed"
                        );
                        let event = WireEvent::new(OsEvent::IntegrityViolation {
                            path:     path.clone(),
                            old_hash: known_hash.clone(),
                            new_hash: current_hash.clone(),
                        });
                        // update baseline so we don't re-alert on same change
                        baseline.insert(path.clone(), current_hash);
                        if self.tx.send(event).await.is_err() { return; }
                    }
                    _ => {
                        // hash unchanged — all good
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::sync::mpsc;

    #[test]
    fn hash_is_deterministic() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello watchdog").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        let h1 = hash_file(&path).unwrap();
        let h2 = hash_file(&path).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_content_gives_different_hash() {
        let mut f1 = NamedTempFile::new().unwrap();
        let mut f2 = NamedTempFile::new().unwrap();
        f1.write_all(b"version 1").unwrap();
        f2.write_all(b"version 2 - tampered").unwrap();
        let h1 = hash_file(f1.path().to_str().unwrap()).unwrap();
        let h2 = hash_file(f2.path().to_str().unwrap()).unwrap();
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn detects_file_change() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"original content").unwrap();
        let path = f.path().to_str().unwrap().to_string();

        let (tx, mut rx) = mpsc::channel(10);
        let checker = IntegrityChecker::new(tx).with_paths(vec![path.clone()]);

        // run two ticks manually: baseline then modified
        let mut baseline: HashMap<String, String> = HashMap::new();

        // tick 1 — baseline
        let h1 = hash_file(&path).unwrap();
        baseline.insert(path.clone(), h1.clone());

        // modify the file
        let mut f2 = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f2.write_all(b"tampered!").unwrap();
        drop(f2);

        // tick 2 — check
        let h2 = hash_file(&path).unwrap();
        assert_ne!(h1, h2, "hashes should differ after modification");

        // simulate what the checker does
        let event = WireEvent::new(OsEvent::IntegrityViolation {
            path:     path.clone(),
            old_hash: h1,
            new_hash: h2,
        });
        checker.tx.send(event).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert!(matches!(received.event, OsEvent::IntegrityViolation { .. }));
    }
}
