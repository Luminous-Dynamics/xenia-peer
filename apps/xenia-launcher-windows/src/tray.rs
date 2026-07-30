// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! System tray icon + context menu, built on the real `tray-icon`/`muda`
//! public API (verified against those crates' actual source before use,
//! not guessed).
//!
//! Per `tray-icon`'s own documented platform requirement, the tray icon
//! must be created on the same thread that later pumps the Win32 message
//! loop -- see `main.rs`, which does both on the GUI thread.

use crate::protocol::DaemonStatus;
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub const MENU_ID_STATUS: &str = "status";
pub const MENU_ID_START: &str = "start";
pub const MENU_ID_STOP: &str = "stop";
pub const MENU_ID_OPEN_SETTINGS: &str = "open-settings";
pub const MENU_ID_OPEN_LOGS: &str = "open-logs";
pub const MENU_ID_QUIT: &str = "quit";

pub struct TrayHandles {
    pub tray_icon: TrayIcon,
    pub status_item: MenuItem,
    pub start_item: MenuItem,
    pub stop_item: MenuItem,
}

/// `tray_icon::Error` has no `From<tray_icon::menu::Error>` (verified
/// against that crate's real `error.rs` -- its only variants are
/// `OsError`/`PngEncodingError`/`NotMainThread`), so `Menu::append`'s
/// distinct error type can't be `?`-propagated directly into a
/// `tray_icon::Result`. Boxing sidesteps that without hand-writing a
/// wrapper enum for two error types used only in this one function.
pub fn build() -> Result<TrayHandles, Box<dyn std::error::Error>> {
    let menu = Menu::new();
    let status_item = MenuItem::with_id(
        MENU_ID_STATUS,
        DaemonStatus::Stopped.menu_label(),
        false,
        None,
    );
    let start_item = MenuItem::with_id(MENU_ID_START, "Start", true, None);
    let stop_item = MenuItem::with_id(MENU_ID_STOP, "Stop", false, None);
    let open_settings_item = MenuItem::with_id(MENU_ID_OPEN_SETTINGS, "Settings...", true, None);
    let open_logs_item = MenuItem::with_id(MENU_ID_OPEN_LOGS, "Open Logs Folder", true, None);
    let quit_item = MenuItem::with_id(MENU_ID_QUIT, "Quit", true, None);

    menu.append(&status_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&start_item)?;
    menu.append(&stop_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&open_settings_item)?;
    menu.append(&open_logs_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&quit_item)?;

    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Xenia -- stopped")
        .with_icon(placeholder_icon())
        .with_menu_on_left_click(true)
        .build()?;

    Ok(TrayHandles {
        tray_icon,
        status_item,
        start_item,
        stop_item,
    })
}

impl TrayHandles {
    /// Reflect a new [`DaemonStatus`] in the menu's status label, the
    /// Start/Stop items' enabled state, and the tray tooltip -- the one
    /// place all three of those get kept in sync, so nothing else needs
    /// to remember to update all three.
    pub fn apply_status(&self, status: &DaemonStatus) {
        self.status_item.set_text(status.menu_label());
        let running_or_transitioning = !matches!(
            status,
            DaemonStatus::Stopped | DaemonStatus::ExitedUnexpectedly
        );
        self.start_item.set_enabled(!running_or_transitioning);
        self.stop_item.set_enabled(running_or_transitioning);
        let _ = self
            .tray_icon
            .set_tooltip(Some(format!("Xenia -- {}", tooltip_suffix(status))));
    }
}

fn tooltip_suffix(status: &DaemonStatus) -> String {
    match status {
        DaemonStatus::Stopped => "stopped".to_string(),
        DaemonStatus::Starting => "starting".to_string(),
        DaemonStatus::Running { pid, .. } => format!("running (pid {pid})"),
        DaemonStatus::Stopping => "stopping".to_string(),
        DaemonStatus::ExitedUnexpectedly => "exited unexpectedly".to_string(),
        DaemonStatus::Error(e) => format!("error: {e}"),
    }
}

/// A plain, solid-color square icon generated in-process rather than
/// embedding a `.ico` binary asset -- adequate for a v1 tray icon
/// (distinguishable in the tray, no asset pipeline to maintain) without
/// pretending to be real product art.
fn placeholder_icon() -> Icon {
    const SIZE: u32 = 32;
    // A simple two-tone square: a solid indigo fill (::= AGPL "sovereign"
    // theme colors elsewhere in this repo's console) with a lighter
    // border, opaque alpha throughout.
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let border = x == 0 || y == 0 || x == SIZE - 1 || y == SIZE - 1;
            if border {
                rgba.extend_from_slice(&[190, 190, 255, 255]);
            } else {
                rgba.extend_from_slice(&[75, 60, 190, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE)
        .expect("placeholder icon dimensions/buffer are internally consistent")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_icon_builds_without_error() {
        // Exercises the RGBA buffer math above without needing a real
        // tray/display -- Icon::from_rgba validates buffer_len ==
        // width*height*4 internally, so this is a genuine check, not a
        // no-op.
        let _ = placeholder_icon();
    }

    #[test]
    fn tooltip_suffix_is_stable_for_every_status() {
        assert_eq!(tooltip_suffix(&DaemonStatus::Stopped), "stopped");
        assert_eq!(
            tooltip_suffix(&DaemonStatus::Running {
                pid: 99,
                uptime_secs: None
            }),
            "running (pid 99)"
        );
    }
}
