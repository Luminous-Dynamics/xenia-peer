// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The background worker thread: owns its own tokio runtime and is the
//! only place that touches `xenia_launcher_core`'s async APIs. See
//! `protocol.rs` for why this is a separate thread from the GUI.

use crate::protocol::{Command, DaemonStatus, Event};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::Duration;
use xenia_launcher_core::config::DaemonConfig;
use xenia_launcher_core::discovery::{self, Binary};
use xenia_launcher_core::health;
use xenia_launcher_core::process::DaemonProcess;

/// How often the worker re-checks daemon liveness/health when no command
/// is pending -- bounds how stale the tray's status display can be.
const POLL_INTERVAL: Duration = Duration::from_millis(1000);
const HEALTH_TIMEOUT: Duration = Duration::from_millis(800);
const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn spawn(
    profile_dir: PathBuf,
    initial_config: DaemonConfig,
    cmd_rx: Receiver<Command>,
    event_tx: Sender<Event>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(err) => {
                let message = format!("failed to start launcher async runtime: {err}");
                let _ = event_tx.send(Event::StatusChanged(DaemonStatus::Error(message.clone())));
                let _ = event_tx.send(Event::Notify {
                    title: "Xenia launcher failed to start".to_string(),
                    message,
                });
                return;
            }
        };
        rt.block_on(run(profile_dir, initial_config, cmd_rx, event_tx));
    })
}

async fn run(
    profile_dir: PathBuf,
    mut config: DaemonConfig,
    cmd_rx: Receiver<Command>,
    event_tx: Sender<Event>,
) {
    let identity_path = profile_dir.join("daemon.identity.json");
    let mut daemon: Option<DaemonProcess> = None;
    let mut last_status = DaemonStatus::Stopped;

    // Reattach to a daemon a *previous* launcher session started, if one
    // is still genuinely running -- see DaemonProcess::try_reattach's own
    // doc comment for why this is safe against pid reuse.
    match DaemonProcess::try_reattach(&identity_path).await {
        Ok(Some(process)) => {
            tracing::info!(
                pid = process.pid(),
                "reattached to an already-running daemon"
            );
            daemon = Some(process);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "could not reattach to a prior daemon (identity mismatch)");
            let _ = event_tx.send(Event::Notify {
                title: "Xenia".into(),
                message: format!("Couldn't reattach to the previous session: {e}"),
            });
        }
    }

    loop {
        match cmd_rx.recv_timeout(POLL_INTERVAL) {
            Ok(Command::Start) => {
                handle_start(&mut daemon, &config, &identity_path, &event_tx).await
            }
            Ok(Command::Stop) => handle_stop(&mut daemon, &event_tx).await,
            Ok(Command::UpdateConfig(new_config)) => config = *new_config,
            Ok(Command::Shutdown) => {
                // Deliberately does NOT stop the daemon -- closing the
                // tray shell isn't the same as asking the daemon to stop;
                // it should keep serving sessions, and the next launcher
                // run reattaches to it (see try_reattach above).
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        refresh_status(&mut daemon, &config, &event_tx, &mut last_status).await;
    }
}

async fn handle_start(
    daemon: &mut Option<DaemonProcess>,
    config: &DaemonConfig,
    identity_path: &std::path::Path,
    event_tx: &Sender<Event>,
) {
    if daemon.is_some() {
        return;
    }
    let _ = event_tx.send(Event::StatusChanged(DaemonStatus::Starting));

    let binary_path = match discovery::discover(Binary::Peer, None) {
        Ok(p) => p,
        Err(e) => {
            let _ = event_tx.send(Event::Notify {
                title: "Xenia -- couldn't start".into(),
                message: format!("{e}"),
            });
            let _ = event_tx.send(Event::StatusChanged(DaemonStatus::Stopped));
            return;
        }
    };

    match DaemonProcess::spawn(&binary_path, &config.to_args(), identity_path).await {
        Ok(process) => {
            tracing::info!(pid = process.pid(), "started the daemon");
            *daemon = Some(process);
            let _ = event_tx.send(Event::Notify {
                title: "Xenia".into(),
                message: "Daemon started.".into(),
            });
        }
        Err(e) => {
            let _ = event_tx.send(Event::Notify {
                title: "Xenia -- couldn't start".into(),
                message: format!("{e}"),
            });
            let _ = event_tx.send(Event::StatusChanged(DaemonStatus::Stopped));
        }
    }
}

async fn handle_stop(daemon: &mut Option<DaemonProcess>, event_tx: &Sender<Event>) {
    let Some(process) = daemon.take() else {
        return;
    };
    let _ = event_tx.send(Event::StatusChanged(DaemonStatus::Stopping));
    match process.stop(GRACEFUL_STOP_TIMEOUT).await {
        Ok(()) => {
            let _ = event_tx.send(Event::Notify {
                title: "Xenia".into(),
                message: "Daemon stopped.".into(),
            });
        }
        Err(e) => {
            let _ = event_tx.send(Event::Notify {
                title: "Xenia -- error while stopping".into(),
                message: format!("{e}"),
            });
        }
    }
    let _ = event_tx.send(Event::StatusChanged(DaemonStatus::Stopped));
}

/// Re-check liveness (and, if alive, health) and emit a
/// [`Event::StatusChanged`] only when the status actually changed --
/// avoids flooding the GUI thread with a redundant event every poll tick.
async fn refresh_status(
    daemon: &mut Option<DaemonProcess>,
    config: &DaemonConfig,
    event_tx: &Sender<Event>,
    last_status: &mut DaemonStatus,
) {
    let status = match daemon {
        None => DaemonStatus::Stopped,
        Some(process) => match process.is_alive() {
            Ok(true) => {
                let pid = process.pid();
                match health::probe(&config.health_base_url(), HEALTH_TIMEOUT).await {
                    Ok(health) => DaemonStatus::Running {
                        pid,
                        uptime_secs: Some(health.uptime_secs),
                    },
                    // Alive at the OS level but not answering /health yet
                    // (e.g. still starting up) -- not an error.
                    Err(_) => DaemonStatus::Running {
                        pid,
                        uptime_secs: None,
                    },
                }
            }
            Ok(false) => {
                // Reached only when `daemon` was `Some` going into this
                // match -- a deliberate stop via handle_stop() always
                // clears `daemon` to `None` itself (and runs, in the main
                // loop, before this function is called again), so getting
                // here always means the process exited on its own.
                *daemon = None;
                let _ = event_tx.send(Event::Notify {
                    title: "Xenia".into(),
                    message: "The daemon exited unexpectedly.".into(),
                });
                DaemonStatus::ExitedUnexpectedly
            }
            Err(e) => {
                *daemon = None;
                DaemonStatus::Error(e.to_string())
            }
        },
    };

    if status != *last_status {
        *last_status = status.clone();
        let _ = event_tx.send(Event::StatusChanged(status));
    }
}
