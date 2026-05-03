/// syscall_monitor.rs
///
/// Polls /proc/<pid>/status and /proc/<pid>/syscall for all running processes
/// and flags any that invoke banned syscalls or run as unexpected UIDs.
///
/// Note: Full eBPF via `aya` requires kernel headers and a separate eBPF
/// program compiled with `bpf-linker`. This module uses the /proc interface
/// as a portable fallback that works on any Linux kernel >= 3.5.
/// The eBPF upgrade path is documented at the bottom of this file.

use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::types::{BANNED_SYSCALLS, OsEvent, SUSPICIOUS_COMMS, WireEvent};

/// How often we scan all /proc entries
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Tracks which (pid, syscall) pairs we have already alerted on
/// so we don't flood heal-brain with duplicates
struct AlertCache {
    seen: HashSet<(u32, u32)>,
}

impl AlertCache {
    fn new() -> Self { Self { seen: HashSet::new() } }

    /// Returns true if this is the first time we see this (pid, syscall)
    fn is_new(&mut self, pid: u32, syscall: u32) -> bool {
        self.seen.insert((pid, syscall))
    }

    /// Remove stale entries for PIDs that no longer exist
    fn prune(&mut self, live_pids: &HashSet<u32>) {
        self.seen.retain(|(pid, _)| live_pids.contains(pid));
    }
}

/// Read the current syscall number a process is blocked in, if any.
/// /proc/<pid>/syscall format: "<syscall_nr> <args...> <sp> <pc>"
/// Returns None if the process is not in a syscall or the file is unreadable.
fn read_current_syscall(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}/syscall", pid);
    let content = std::fs::read_to_string(&path).ok()?;
    let first = content.split_whitespace().next()?;
    // "running" means not blocked in a syscall
    if first == "running" { return None; }
    first.parse::<u32>().ok()
}

/// Read the real UID of a process from /proc/<pid>/status
fn read_uid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if line.starts_with("Uid:") {
            // Uid: real effective saved fs
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

/// Read the process name (comm) from /proc/<pid>/comm
fn read_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

/// Read the parent PID from /proc/<pid>/status
fn read_ppid(pid: u32) -> u32 {
    let path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    for line in content.lines() {
        if line.starts_with("PPid:") {
            return line.split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

/// Enumerate all numeric entries in /proc (each is a PID)
fn enumerate_pids() -> HashSet<u32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect()
}

pub struct SyscallMonitor {
    tx: mpsc::Sender<WireEvent>,
}

impl SyscallMonitor {
    pub fn new(tx: mpsc::Sender<WireEvent>) -> Self {
        Self { tx }
    }

    pub async fn run(self) {
        info!("SyscallMonitor started — polling /proc every {}ms",
              POLL_INTERVAL.as_millis());

        let mut cache    = AlertCache::new();
        let mut interval = tokio::time::interval(POLL_INTERVAL);

        loop {
            interval.tick().await;

            let pids = enumerate_pids();
            cache.prune(&pids);

            for &pid in &pids {
                // ── Banned syscall check ──────────────────────────────
                if let Some(syscall_nr) = read_current_syscall(pid) {
                    if let Some(&(_, name)) = BANNED_SYSCALLS
                        .iter()
                        .find(|&&(nr, _)| nr == syscall_nr)
                    {
                        if cache.is_new(pid, syscall_nr) {
                            let uid  = read_uid(pid).unwrap_or(0);
                            let comm = read_comm(pid);

                            // root calling ptrace is normal (debuggers, strace)
                            // non-root calling ptrace or setuid is not
                            let is_suspicious = uid != 0
                                || syscall_nr == 317  // seccomp always suspicious
                                || syscall_nr == 281; // perf_event_open always suspicious

                            if is_suspicious {
                                info!(pid, syscall = name, uid, comm, "Banned syscall detected");
                                let event = WireEvent::new(OsEvent::SyscallViolation {
                                    pid,
                                    comm: comm.clone(),
                                    syscall: syscall_nr,
                                    uid,
                                });
                                if self.tx.send(event).await.is_err() { return; }
                            }
                        }
                    }
                }

                // ── Suspicious process spawn check ────────────────────
                let comm = read_comm(pid);
                if SUSPICIOUS_COMMS.iter().any(|&s| comm == s) {
                    let uid  = read_uid(pid).unwrap_or(0);
                    let ppid = read_ppid(pid);

                    // flag if spawned by a non-interactive parent (pid 1 or a service)
                    if ppid == 1 || ppid == 0 {
                        if cache.is_new(pid, 0xFFFF) { // 0xFFFF = sentinel for "spawn" alerts
                            warn!(pid, comm, uid, ppid, "Suspicious process spawned from init");
                            let event = WireEvent::new(OsEvent::UnexpectedProcess {
                                pid,
                                comm: comm.clone(),
                                parent_pid: ppid,
                                uid,
                            });
                            if self.tx.send(event).await.is_err() { return; }
                        }
                    }
                }

                debug!(pid, comm, "scanned");
            }
        }
    }
}

// ── eBPF upgrade path ────────────────────────────────────────────────────────
//
// To replace this /proc poller with a real eBPF tracepoint probe:
//
// 1. Add to Cargo.toml:
//      aya       = { version = "0.12", features = ["async_tokio"] }
//      aya-log   = "0.2"
//
// 2. Write an eBPF program in src/bpf/syscall_enter.bpf.c:
//      SEC("tracepoint/raw_syscalls/sys_enter")
//      int sys_enter(struct trace_event_raw_sys_enter *ctx) {
//          u32 pid     = bpf_get_current_pid_tgid() >> 32;
//          u32 syscall = ctx->id;
//          // push (pid, syscall) into a BPF ring buffer
//      }
//
// 3. Load and attach in Rust:
//      let bpf  = Bpf::load(include_bytes_aligned!("../../target/bpfel/syscall_enter.o"))?;
//      let prog = bpf.program_mut("sys_enter").unwrap();
//      let tp: &mut TracePoint = prog.try_into()?;
//      tp.load()?;
//      tp.attach("raw_syscalls", "sys_enter")?;
//
// This gives us zero-overhead syscall interception vs the 250ms poll above.
