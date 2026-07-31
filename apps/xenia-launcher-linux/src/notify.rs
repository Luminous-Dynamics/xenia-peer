// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Desktop notifications via `notify-rust` (freedesktop D-Bus
//! Notifications spec). Unlike Windows' `Shell_NotifyIcon`-based balloons
//! (`xenia-launcher-windows/src/notify.rs`), there's no persistent icon
//! or handle to register up front -- each notification is a self-contained
//! D-Bus call, so this is just a function, not a type.

use notify_rust::Notification;

/// Show a desktop notification. Best-effort: a failure here (no D-Bus
/// session running, notification daemon not registered, etc.) is logged,
/// not propagated -- a missed notification should never take down the
/// launcher.
pub fn show(title: &str, message: &str) {
    let result = Notification::new()
        .appname("Xenia")
        .summary(title)
        .body(message)
        .show();
    match result {
        Ok(_) => tracing::debug!(title, message, "showed a desktop notification"),
        Err(e) => {
            tracing::warn!(error = %e, title, message, "couldn't show a desktop notification")
        }
    }
}
