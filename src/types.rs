use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Mirror of heal-brain's SourceLayer — kept in sync manually
/// until we extract shared types into a workspace crate
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SourceLayer {
    OsKernel,
}

/// Subset of heal-brain's EventPayload relevant to the OS layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OsEvent {
    SyscallViolation {
        pid:     u32,
        comm:    String,
        syscall: u32,
        uid:     u32,
    },
    MemoryTamper {
        pid:      u32,
        region:   String,
        old_hash: [u8; 32],
        new_hash: [u8; 32],
    },
    UnexpectedProcess {
        pid:        u32,
        comm:       String,
        parent_pid: u32,
        uid:        u32,
    },
    IntegrityViolation {
        path:     String,
        old_hash: String,
        new_hash: String,
    },
}

/// Wire format sent to heal-brain over the Unix socket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEvent {
    pub id:        u64,
    pub source:    SourceLayer,
    pub timestamp: u64,
    pub event:     OsEvent,
}

impl WireEvent {
    pub fn new(event: OsEvent) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            source: SourceLayer::OsKernel,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            event,
        }
    }
}

/// Banned syscall numbers — any process invoking these triggers an alert.
/// Derived from common attack patterns on Linux.
pub const BANNED_SYSCALLS: &[(u32, &str)] = &[
    (101, "ptrace"),          // process tracing — injection vector
    (105, "setuid"),          // privilege escalation
    (317, "seccomp"),         // disabling security filters
    (331, "close_range"),     // bulk fd close — sandbox escape pattern
    (281, "perf_event_open"), // kernel profiling — side-channel risk
];

/// Processes that should never appear outside their expected context.
/// Seeing these spawned from unusual parents triggers an alert.
pub const SUSPICIOUS_COMMS: &[&str] = &[
    "nc", "ncat", "netcat",
    "bash", "sh", "zsh",
    "python", "python3",
    "perl", "ruby",
    "curl", "wget",
    "socat", "nmap",
];

/// Critical binaries whose hashes are checked periodically
pub const WATCHED_BINARIES: &[&str] = &[
    "/usr/bin/ids-agent",
    "/usr/bin/firewall-agent",
    "/usr/sbin/sshd",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/bin/login",
];
