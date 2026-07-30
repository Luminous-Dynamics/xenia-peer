// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Balloon notifications, via a dedicated, hidden `Shell_NotifyIcon` entry
//! -- deliberately NOT reusing the visible tray icon's own identity.
//!
//! `tray-icon` doesn't expose balloon support (its own `NOTIFYICONDATAW`
//! usage never sets `NIF_INFO`, confirmed by reading that crate's actual
//! Windows backend source), and it doesn't expose the `uID` it registers
//! its own icon under -- only its owning `HWND` (via `window_handle()`).
//! Piggybacking a second icon onto that hwnd with a guessed, possibly-
//! colliding `uID` would risk corrupting tray-icon's own icon state.
//! Registering an entirely separate icon -- on this module's own,
//! independently-created message-only window, `NIS_HIDDEN` so it never
//! actually appears in the tray -- has no such risk: Windows tracks
//! `Shell_NotifyIcon` entries per `(hWnd, uID)` pair, and this owns both
//! ends of that pair outright.

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_STATE, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NIS_HIDDEN, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{HICON, LoadIconW, WM_APP};

/// This notify icon's own `uID` -- only needs to be unique among entries
/// *this window* registers (Windows scopes uniqueness to `(hWnd, uID)`),
/// so `1` is fine; this module never registers more than one.
const NOTIFY_UID: u32 = 1;
/// Callback message id Windows would send for interaction with this icon
/// (clicks, etc.) -- unused in practice, since this icon is always
/// `NIS_HIDDEN` and exists purely to originate balloons, but
/// `Shell_NotifyIcon` requires *some* value here when `NIF_MESSAGE` is set.
const NOTIFY_CALLBACK_MSG: u32 = WM_APP + 100;

pub struct NotifyIcon {
    hwnd: HWND,
}

impl NotifyIcon {
    /// Register the hidden notification-only icon against `hwnd` (a
    /// window this module's caller owns -- see `native_window.rs`). Must
    /// be paired with [`NotifyIcon::unregister`] before `hwnd` itself is
    /// destroyed.
    pub fn register(hwnd: HWND) -> windows::core::Result<Self> {
        let mut nid = base_nid(hwnd);
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_STATE;
        nid.uCallbackMessage = NOTIFY_CALLBACK_MSG;
        nid.hIcon = default_icon()?;
        nid.dwState = NIS_HIDDEN;
        nid.dwStateMask = NIS_HIDDEN;
        unsafe {
            Shell_NotifyIconW(NIM_ADD, &nid).ok()?;
        }
        Ok(Self { hwnd })
    }

    /// Show a balloon. Best-effort: a failure here (e.g. notifications
    /// disabled in Windows settings) is logged, not propagated -- a
    /// missed notification should never take down the launcher.
    pub fn show(&self, title: &str, message: &str) {
        let mut nid = base_nid(self.hwnd);
        nid.uFlags = NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO;
        copy_into(&mut nid.szInfoTitle, title);
        copy_into(&mut nid.szInfo, message);
        let ok = unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
        if ok.as_bool() {
            tracing::debug!(title, message, "showed a balloon notification");
        } else {
            tracing::warn!(
                title,
                message,
                "Shell_NotifyIconW(NIM_MODIFY) failed for a balloon"
            );
        }
    }
}

impl Drop for NotifyIcon {
    fn drop(&mut self) {
        let nid = base_nid(self.hwnd);
        unsafe {
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
        }
    }
}

fn base_nid(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: NOTIFY_UID,
        ..Default::default()
    }
}

fn default_icon() -> windows::core::Result<HICON> {
    // IDI_APPLICATION (32512), the stock "generic application" icon --
    // this notify icon is always hidden (see NIS_HIDDEN above), so its
    // actual appearance never matters; Shell_NotifyIcon still requires a
    // valid HICON to accept NIF_ICON.
    const IDI_APPLICATION: windows::core::PCWSTR = windows::core::PCWSTR(32512 as *const u16);
    unsafe { LoadIconW(None, IDI_APPLICATION) }
}

/// Copy `s` (UTF-16, null-terminated, truncated to fit) into a fixed-size
/// `NOTIFYICONDATAW` text field.
fn copy_into<const N: usize>(field: &mut [u16; N], s: &str) {
    let wide: Vec<u16> = s.encode_utf16().collect();
    let copy_len = wide.len().min(N - 1);
    field[..copy_len].copy_from_slice(&wide[..copy_len]);
    field[copy_len] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_into_truncates_and_null_terminates() {
        let mut buf = [0u16; 4];
        copy_into(&mut buf, "hello");
        // 3 real chars + null terminator, within a 4-element buffer.
        assert_eq!(buf, [b'h' as u16, b'e' as u16, b'l' as u16, 0]);
    }

    #[test]
    fn copy_into_handles_short_strings() {
        let mut buf = [0u16; 8];
        copy_into(&mut buf, "hi");
        assert_eq!(&buf[..3], &[b'h' as u16, b'i' as u16, 0]);
    }
}
