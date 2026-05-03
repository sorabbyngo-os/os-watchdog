mod types;
mod syscall_monitor;
mod process_guard;
mod integrity_check;
mod emitter;

use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

use types::WireEvent;

/// Capacity of the internal event fan-in channel
const CHANNEL_CAP: usize = 1024;

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("os_watchdog=debug".parse().unwrap()))
        .with_target(false)
        .init();

    info!("os-watchdog starting");

    // ── Fan-in channel: all monitors → emitter ────────────────────────────
    //
    //   [SyscallMonitor] ──┐
    //   [ProcessGuard]   ──┼──► fan_tx → [Emitter] → heal-brain (Unix socket)
    //   [IntegrityChecker]─┘
    //
    let (fan_tx, fan_rx) = mpsc::channel::<WireEvent>(CHANNEL_CAP);

    // ── Spawn monitors ────────────────────────────────────────────────────
    let syscall_mon = syscall_monitor::SyscallMonitor::new(fan_tx.clone());
    let proc_guard  = process_guard::ProcessGuard::new(fan_tx.clone());
    let integrity   = integrity_check::IntegrityChecker::new(fan_tx.clone());

    tokio::spawn(syscall_mon.run());
    tokio::spawn(proc_guard.run());
    tokio::spawn(integrity.run());

    // ── Spawn emitter ─────────────────────────────────────────────────────
    let emit = emitter::Emitter::new(fan_rx);
    tokio::spawn(emit.run());

    info!("All monitors active — forwarding events to heal-brain at {}",
          emitter::HEAL_BRAIN_SOCKET);

    // Keep the runtime alive until ctrl+c
    tokio::signal::ctrl_c().await.ok();
    info!("os-watchdog shutting down");
}
