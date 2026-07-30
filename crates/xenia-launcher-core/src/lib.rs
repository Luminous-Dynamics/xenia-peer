// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Platform-neutral supervisor core for a local Xenia launcher.
//!
//! This crate is the shared logic between whatever native shell(s) get
//! built on top of it (a Windows tray app first; see
//! `docs/roadmap` for the sequencing decision and why Tauri is deferred
//! until real UI complexity justifies it). It owns:
//!
//! - [`config`] -- typed daemon configuration, strict argument construction
//! - [`discovery`] -- resolving the daemon/agent binaries by an explicit
//!   installed path, never `$PATH`
//! - [`process`] -- spawn, liveness, graceful-then-forced shutdown,
//!   reattaching across a launcher restart
//! - [`health`] -- polling the daemon's real `/health` endpoint (never log
//!   scraping)
//! - [`log_tail`] -- subscribing to the daemon's log file for a UI log pane
//! - [`single_instance`] -- one launcher per profile
//!
//! ## Security posture (binding constraints on this crate's own design,
//! not just documentation)
//!
//! - Never invokes a shell; [`process::DaemonProcess::spawn`] always takes
//!   an explicit binary path and a typed argument vector.
//! - Never resolves a binary via `$PATH`/`%PATH%` -- see [`discovery`].
//! - Never accepts or constructs secrets as command-line arguments --
//!   [`config::DaemonConfig`] holds no key material, only paths to where
//!   the daemon keeps its own (which it manages itself via
//!   `xenia-secure-file`).
//! - Never infers daemon health from log content -- [`health`] is a real
//!   structured endpoint; [`log_tail`] is for human eyes only.
//! - Its own local state (process identity records, the single-instance
//!   lock) goes through `xenia-secure-file`'s owner-only, atomic,
//!   TOCTOU-safe primitives -- the same guarantees this crate depends on
//!   for the daemon's own secrets apply to the launcher's coordination
//!   state too, rather than a second, ad-hoc file-handling path.

pub mod config;
pub mod discovery;
pub mod health;
pub mod log_tail;
pub mod process;
pub mod single_instance;
