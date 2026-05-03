/// process_guard.rs
///
/// Monitors /proc/<pid>/maps for memory region changes that indicate
/// code injection (e.g. a previously read-only .text section becoming
/// writable, or a new anonymous executable mapping appearing).

use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::types::{OsEvent, WireEvent};

const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Snapshot of a single memory mapping
#[derive(Debug, Clone, PartialEq, Eq)]
struct MemRegion {
    start:  u64,
    end:    u64,
    perms:  String,  // e.g. "r-xp", "rwxp"
    name:   String,  // path or [heap]/[stack]/anon
}

/// Parse /proc/<pid>/maps into a list of MemRegions
fn parse_maps(pid: u32) -> Vec<MemRegion> {
    let path    = format!("/proc/{}/maps", pid);
    let content = match std::fs::read_to_string(&path) {
        Ok(c)  => c,
        Err(_) => return vec![],
    };

    content.lines().filter_map(|line| {
        let mut parts = line.splitn(6, ' ');
        let range = parts.next()?;
        let perms = parts.next()?.to_string();
        let _off  = parts.next();
        let _dev  = parts.next();
        let _ino  = parts.next();
        let name  = parts.next().unwrap_or("").trim().to_string();

        let mut addr = range.splitn(2, '-');
        let start = u64::from_str_radix(addr.next()?, 16).ok()?;
        let end   = u64::from_str_radix(addr.next()?, 16).ok()?;

        Some(MemRegion { start, end, perms, name })
    }).collect()
}

/// Returns true if a mapping is executable and anonymous (strong injection signal)
fn is_anon_exec(r: &MemRegion) -> bool {
    r.perms.contains('x') && (r.name.is_empty() || r.name == "anon")
}

/// Returns true if a named region has become writable+executable (W^X violation)
fn is_wx_violation(r: &MemRegion) -> bool {
    r.perms.contains('w') && r.perms.contains('x') && !r.name.is_empty()
}

/// Compute a simple fingerprint for a set of regions (count + total size)
fn fingerprint(regions: &[MemRegion]) -> (usize, u64) {
    let total: u64 = regions.iter().map(|r| r.end - r.start).sum();
    (regions.len(), total)
}

pub struct ProcessGuard {
    tx: mpsc::Sender<WireEvent>,
}

impl ProcessGuard {
    pub fn new(tx: mpsc::Sender<WireEvent>) -> Self { Self { tx } }

    pub async fn run(self) {
        info!("ProcessGuard started — watching /proc/*/maps every {}ms",
              POLL_INTERVAL.as_millis());

        // pid → fingerprint of last known maps
        let mut snapshots: HashMap<u32, (usize, u64)> = HashMap::new();
        let mut interval = tokio::time::interval(POLL_INTERVAL);

        loop {
            interval.tick().await;

            // collect live pids
            let pids: Vec<u32> = std::fs::read_dir("/proc")
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .collect();

            // remove stale snapshots
            snapshots.retain(|pid, _| pids.contains(pid));

            for pid in pids {
                let regions = parse_maps(pid);
                if regions.is_empty() { continue; }

                // ── Check for anon-exec and W^X violations ────────────
                for region in &regions {
                    if is_anon_exec(region) || is_wx_violation(region) {
                        warn!(
                            pid,
                            region_name  = %region.name,
                            perms        = %region.perms,
                            start        = region.start,
                            "Suspicious memory mapping detected"
                        );
                        // encode the permission string as a pseudo-hash for the event
                        let perm_bytes = region.perms.as_bytes();
                        let mut old_hash = [0u8; 32];
                        let mut new_hash = [0u8; 32];
                        old_hash[..4].copy_from_slice(b"r-xp");
                        new_hash[..perm_bytes.len().min(32)]
                            .copy_from_slice(&perm_bytes[..perm_bytes.len().min(32)]);

                        let event = WireEvent::new(OsEvent::MemoryTamper {
                            pid,
                            region: region.name.clone(),
                            old_hash,
                            new_hash,
                        });
                        if self.tx.send(event).await.is_err() { return; }
                    }
                }

                // ── Fingerprint change detection ──────────────────────
                let fp = fingerprint(&regions);
                if let Some(&prev_fp) = snapshots.get(&pid) {
                    if prev_fp != fp {
                        info!(
                            pid,
                            old_regions = prev_fp.0,
                            new_regions = fp.0,
                            "Memory map changed — possible injection"
                        );
                        let event = WireEvent::new(OsEvent::MemoryTamper {
                            pid,
                            region: "maps-changed".to_string(),
                            old_hash: {
                                let mut h = [0u8; 32];
                                h[..8].copy_from_slice(&prev_fp.1.to_le_bytes());
                                h
                            },
                            new_hash: {
                                let mut h = [0u8; 32];
                                h[..8].copy_from_slice(&fp.1.to_le_bytes());
                                h
                            },
                        });
                        if self.tx.send(event).await.is_err() { return; }
                    }
                }
                snapshots.insert(pid, fp);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_anon_exec() {
        let r = MemRegion {
            start: 0x7f000000,
            end:   0x7f001000,
            perms: "rwxp".to_string(),
            name:  "".to_string(),
        };
        assert!(is_anon_exec(&r));
    }

    #[test]
    fn detects_wx_violation() {
        let r = MemRegion {
            start: 0x400000,
            end:   0x401000,
            perms: "rwxp".to_string(),
            name:  "/usr/bin/evil".to_string(),
        };
        assert!(is_wx_violation(&r));
    }

    #[test]
    fn clean_region_passes() {
        let r = MemRegion {
            start: 0x400000,
            end:   0x401000,
            perms: "r-xp".to_string(),
            name:  "/usr/bin/sshd".to_string(),
        };
        assert!(!is_anon_exec(&r));
        assert!(!is_wx_violation(&r));
    }
}
