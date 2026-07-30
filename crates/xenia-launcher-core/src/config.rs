// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Typed configuration for a supervised `xenia-peer` daemon instance, and
//! strict construction of the argument vector used to launch it.
//!
//! **Deliberately not a 1:1 mirror of every `xenia-peer` CLI flag** (there
//! are 50+, including pre-production fixtures, evidence-bundle audit
//! modes, and one-shot verification subcommands that a day-to-day
//! start/stop/status launcher has no reason to expose). This models the
//! practical subset an operator actually configures per profile; the rest
//! keep their daemon-side defaults. If a real need for more fields shows
//! up, add them then -- don't pre-model the whole surface speculatively.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// One daemon instance's configuration. Mirrors `xenia-peer`'s own CLI
/// defaults where it has a corresponding field, so `DaemonConfig::default()`
/// launches equivalently to running `xenia-peer` with no arguments.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DaemonConfig {
    /// `--listen`. `host:port` the daemon accepts incoming sessions on.
    pub listen: String,
    /// `--codec`.
    pub codec: Codec,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// `--admin-port`. The port the launcher's own [`crate::health`] client
    /// and the operator console talk to. `0` lets the OS pick an ephemeral
    /// port -- fine for the daemon itself, but the launcher needs to know
    /// the real bound port to poll health, so prefer a fixed, non-zero
    /// value for anything the launcher supervises.
    pub admin_port: u16,
    pub consent_port: u16,
    pub telemetry_level: TelemetryLevel,
    pub audio: AudioMode,
    pub input_backend: InputBackend,
    pub clipboard: ClipboardMode,
    /// Root directory for this profile's persistent state (identity keys,
    /// the consent ledger, the HTTP auth key). [`DaemonConfig::to_args`]
    /// derives the daemon's individual `--operator-key-path` /
    /// `--consent-ledger-path` / `--m1-consent-key-path` /
    /// `--host-identity-key-path` / `--http-auth-ml-dsa-key-path` flags
    /// from this one root rather than exposing five separate fields --
    /// matches how a real installer/launcher UI would present "where does
    /// this profile keep its state," not the daemon's own more granular
    /// CLI shape. The directory itself is created with owner-only
    /// permissions by `xenia-secure-file` on the daemon's first run (not
    /// by this crate) -- the launcher never touches these files directly.
    pub state_dir: PathBuf,
    /// `--log-file`. Written to a real file (not just stdout) so
    /// [`crate::log_tail`] can subscribe to it regardless of whether the
    /// daemon is running attached to a console. Requires a daemon build
    /// with `--log-file` support (xenia-peer PR #113 at time of writing --
    /// not yet merged to `main`); `to_args` omits the flag entirely when
    /// this is `None`, so pointing at an older daemon binary without it
    /// still works, just without a durable log the launcher can tail.
    pub log_file: Option<PathBuf>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".to_string(),
            codec: Codec::Passthrough,
            width: 320,
            height: 200,
            fps: 30,
            admin_port: 8081,
            consent_port: 8082,
            telemetry_level: TelemetryLevel::Basic,
            audio: AudioMode::Off,
            input_backend: InputBackend::Noop,
            clipboard: ClipboardMode::Off,
            state_dir: PathBuf::from("xenia-peer-state"),
            log_file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Codec {
    Passthrough,
    Hdc,
    H264,
}

impl Codec {
    fn as_flag(self) -> &'static str {
        match self {
            Codec::Passthrough => "passthrough",
            Codec::Hdc => "hdc",
            Codec::H264 => "h264",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryLevel {
    Off,
    Basic,
    Detailed,
}

impl TelemetryLevel {
    fn as_flag(self) -> &'static str {
        match self {
            TelemetryLevel::Off => "off",
            TelemetryLevel::Basic => "basic",
            TelemetryLevel::Detailed => "detailed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AudioMode {
    Off,
    HostToViewer,
}

impl AudioMode {
    fn as_flag(self) -> &'static str {
        match self {
            AudioMode::Off => "off",
            AudioMode::HostToViewer => "host-to-viewer",
        }
    }
}

/// Mirrors `xenia-inject`'s backend choices. `Noop`/`Log` need no extra
/// system deps or consent flow; `XdgPortal`/`Uinput`/`Windows`/`Macos`
/// each require the daemon binary to have been built with the matching
/// feature -- this crate doesn't verify that (it can't, short of asking
/// the binary), so an unsupported choice surfaces as a daemon-side clap
/// error at spawn time, not a silent no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputBackend {
    Noop,
    Log,
    XdgPortal,
    Uinput,
    Windows,
    Macos,
}

impl InputBackend {
    fn as_flag(self) -> &'static str {
        match self {
            InputBackend::Noop => "noop",
            InputBackend::Log => "log",
            InputBackend::XdgPortal => "xdg-portal",
            InputBackend::Uinput => "uinput",
            InputBackend::Windows => "windows",
            InputBackend::Macos => "macos",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClipboardMode {
    Off,
    HostToViewer,
    Bidirectional,
}

impl ClipboardMode {
    fn as_flag(self) -> &'static str {
        match self {
            ClipboardMode::Off => "off",
            ClipboardMode::HostToViewer => "host-to-viewer",
            ClipboardMode::Bidirectional => "bidirectional",
        }
    }
}

impl DaemonConfig {
    /// Build the daemon's argument vector. Every value is a typed field or
    /// an allowlisted enum variant -- there is no string concatenation, no
    /// shell, and nothing here ever passes user-controlled free text
    /// through as a raw command-line fragment. Secrets never appear here:
    /// none of this crate's typed fields hold key material, and the paths
    /// this derives point *at* where the daemon keeps its keys, they don't
    /// carry the key bytes themselves.
    pub fn to_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            "--listen".into(),
            self.listen.clone().into(),
            "--codec".into(),
            self.codec.as_flag().into(),
            "--width".into(),
            self.width.to_string().into(),
            "--height".into(),
            self.height.to_string().into(),
            "--fps".into(),
            self.fps.to_string().into(),
            "--admin-port".into(),
            self.admin_port.to_string().into(),
            "--consent-port".into(),
            self.consent_port.to_string().into(),
            "--telemetry-level".into(),
            self.telemetry_level.as_flag().into(),
            "--audio".into(),
            self.audio.as_flag().into(),
            "--input-backend".into(),
            self.input_backend.as_flag().into(),
            "--clipboard".into(),
            self.clipboard.as_flag().into(),
            "--operator-key-path".into(),
            state_path(&self.state_dir, "operator.key").into(),
            "--consent-ledger-path".into(),
            state_path(&self.state_dir, "consent.ledger").into(),
            "--m1-consent-key-path".into(),
            state_path(&self.state_dir, "consent-ledger.key").into(),
            "--host-identity-key-path".into(),
            state_path(&self.state_dir, "host-identity.key").into(),
            "--http-auth-ml-dsa-key-path".into(),
            state_path(&self.state_dir, "operator-http-ml-dsa.key").into(),
        ];
        if let Some(log_file) = &self.log_file {
            args.push("--log-file".into());
            args.push(log_file.clone().into());
        }
        args
    }

    /// The base URL the launcher's [`crate::health`] client should poll --
    /// derived from `admin_port`, matching the daemon's own
    /// `--operator-bind` default (loopback).
    pub fn health_base_url(&self) -> String {
        format!("127.0.0.1:{}", self.admin_port)
    }
}

fn state_path(state_dir: &Path, file_name: &str) -> PathBuf {
    state_dir.join(file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_xenia_peer_s_own_cli_defaults() {
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.listen, "127.0.0.1:8080");
        assert_eq!(cfg.admin_port, 8081);
        assert_eq!(cfg.consent_port, 8082);
    }

    #[test]
    fn to_args_derives_state_paths_from_the_single_state_dir_root() {
        let state_dir = PathBuf::from("state-root").join("profile-a");
        let cfg = DaemonConfig {
            state_dir: state_dir.clone(),
            ..DaemonConfig::default()
        };
        let args = cfg.to_args();
        let joined: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // Built via Path::join (like to_args itself), not a hardcoded
        // forward-slash string -- the whole point is to prove the derived
        // path is correct on this platform's own separator, not to assert
        // one particular separator.
        let expect = |file: &str| state_dir.join(file).to_string_lossy().into_owned();
        assert!(joined.contains(&expect("operator.key")));
        assert!(joined.contains(&expect("consent.ledger")));
        assert!(joined.contains(&expect("consent-ledger.key")));
        assert!(joined.contains(&expect("host-identity.key")));
        assert!(joined.contains(&expect("operator-http-ml-dsa.key")));
    }

    #[test]
    fn to_args_omits_log_file_flag_when_not_set() {
        let cfg = DaemonConfig::default();
        let args = cfg.to_args();
        assert!(!args.iter().any(|a| a == "--log-file"));
    }

    #[test]
    fn to_args_includes_log_file_flag_when_set() {
        let cfg = DaemonConfig {
            log_file: Some(PathBuf::from("/tmp/profile-a/daemon.log")),
            ..DaemonConfig::default()
        };
        let args = cfg.to_args();
        let idx = args
            .iter()
            .position(|a| a == "--log-file")
            .expect("flag present");
        assert_eq!(args[idx + 1], "/tmp/profile-a/daemon.log");
    }

    #[test]
    fn health_base_url_uses_the_admin_port() {
        let cfg = DaemonConfig {
            admin_port: 9999,
            ..DaemonConfig::default()
        };
        assert_eq!(cfg.health_base_url(), "127.0.0.1:9999");
    }
}
