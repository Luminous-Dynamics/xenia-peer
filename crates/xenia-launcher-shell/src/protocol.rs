// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command/event protocol between the GUI thread (owns the platform event
//! loop, the tray icon, and the settings window) and the worker thread
//! (owns a tokio runtime and drives `xenia_launcher_core`).
//!
//! Split across two threads because the platform's own native GUI event
//! loop and `xenia_launcher_core`'s async process/health/log-tail APIs
//! each want to own their own event loop -- rather than force one into
//! the other, the GUI thread sends [`Command`]s and polls for [`Event`]s
//! via plain `std::sync::mpsc` channels (not tokio channels: the GUI side
//! is deliberately synchronous, driven by the platform event loop's own
//! timer/message ticks, not an async runtime of its own).

use std::path::PathBuf;
use xenia_launcher_core::config::DaemonConfig;

#[derive(Debug, Clone)]
pub enum Command {
    Start,
    Stop,
    /// The user saved new settings; apply them (stopping/restarting the
    /// daemon is the caller's job via separate Stop/Start commands, this
    /// just updates what a subsequent Start uses).
    UpdateConfig(Box<DaemonConfig>),
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum Event {
    StatusChanged(DaemonStatus),
    /// Something worth surfacing to the user via a system notification --
    /// deliberately a separate event from `StatusChanged`: not every
    /// status change deserves an interruption, but some do (e.g. the
    /// daemon exiting unexpectedly).
    Notify {
        title: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum DaemonStatus {
    Stopped,
    Starting,
    Running {
        pid: u32,
        uptime_secs: Option<u64>,
    },
    Stopping,
    /// The daemon process is gone but wasn't stopped via our own `Stop`
    /// command -- distinguished from `Stopped` so the worker can emit a
    /// `Notify` event the first time this is observed, matching "the
    /// daemon exited/crashed" rather than silently going quiet.
    ExitedUnexpectedly,
    Error(String),
}

impl DaemonStatus {
    pub fn menu_label(&self) -> String {
        match self {
            DaemonStatus::Stopped => "Status: Stopped".to_string(),
            DaemonStatus::Starting => "Status: Starting...".to_string(),
            DaemonStatus::Running { pid, uptime_secs } => match uptime_secs {
                Some(secs) => format!("Status: Running (pid {pid}, up {secs}s)"),
                None => format!("Status: Running (pid {pid})"),
            },
            DaemonStatus::Stopping => "Status: Stopping...".to_string(),
            DaemonStatus::ExitedUnexpectedly => "Status: Exited unexpectedly".to_string(),
            DaemonStatus::Error(e) => format!("Status: Error ({e})"),
        }
    }
}

/// Where this profile's launcher-level (non-secret) config and the
/// daemon's own identity/consent state live -- one directory per profile,
/// matching [`DaemonConfig::state_dir`]'s own "one root, everything
/// derived" shape. Per-platform convention: `%APPDATA%\Xenia` on Windows,
/// XDG_CONFIG_HOME (or `~/.config`) on Linux/macOS -- both fall back to a
/// temp dir if the platform's usual variable isn't set, rather than
/// panicking.
pub fn default_profile_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("Xenia")
            .join("default-profile")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .unwrap_or_else(std::env::temp_dir)
            .join("xenia")
            .join("default-profile")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_label_is_stable_and_human_readable() {
        assert_eq!(DaemonStatus::Stopped.menu_label(), "Status: Stopped");
        assert_eq!(
            DaemonStatus::Running {
                pid: 1234,
                uptime_secs: Some(42)
            }
            .menu_label(),
            "Status: Running (pid 1234, up 42s)"
        );
        assert_eq!(
            DaemonStatus::Running {
                pid: 1234,
                uptime_secs: None
            }
            .menu_label(),
            "Status: Running (pid 1234)"
        );
    }

    #[test]
    fn default_profile_dir_is_non_empty_and_ends_in_default_profile() {
        let dir = default_profile_dir();
        assert_eq!(dir.file_name().unwrap(), "default-profile");
    }
}
