// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Platform-agnostic plumbing shared by every native Xenia launcher shell
//! (`xenia-launcher-windows`, `xenia-launcher-linux`, and eventually a
//! macOS counterpart): the command/event protocol between the GUI thread
//! and the worker thread, the worker thread itself, the tray icon + menu
//! (`tray-icon`/`muda` are already cross-platform), and config
//! persistence. What's deliberately NOT here -- because it genuinely
//! differs per platform and has no honest shared abstraction -- is the
//! settings window, system notifications, and start-at-login
//! integration; each launcher crate owns those using its own platform's
//! real native APIs.

pub mod config_store;
pub mod protocol;
pub mod tray;
pub mod worker;
