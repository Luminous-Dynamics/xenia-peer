// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Xenia's minimal native Windows tray shell: a system tray icon + menu,
//! a small settings window, balloon notifications, and start-at-login
//! integration -- built on `xenia_launcher_core` for everything that
//! isn't Windows-UI-specific. See `apps/xenia-launcher-windows/Cargo.toml`
//! for why this exists instead of (yet) reaching for Tauri.
//!
//! **Architecture**: one GUI thread runs the Win32 message loop (owns the
//! tray icon, a hidden message-only window used for the poll timer +
//! balloon-notification icon, and the settings window when open); a
//! separate worker thread owns a tokio runtime and is the only place that
//! touches `xenia_launcher_core`'s async APIs. The two talk over plain
//! `std::sync::mpsc` channels -- see `protocol.rs` and `worker.rs`.
//!
//! **What's verified and what isn't**: every Win32/`tray-icon`/`muda` API
//! used across this app was checked against the real, cached crate source
//! before use (not guessed from memory), and the whole app is compiled
//! and clippy-checked against the genuine `x86_64-pc-windows-msvc` target
//! via `cargo xwin`. What that verification *cannot* cover -- and what
//! this session's author has no way to check without a real Windows
//! desktop -- is whether the tray icon, menu, settings window, and
//! notifications actually look and behave right. Treat this as
//! compile-clean and logic-tested, not yet visually/interactively
//! verified.

// The workspace denies `unsafe_code` by default (`[workspace.lints]`,
// deliberate hardening for a security-focused daemon/protocol codebase),
// enforced as a `-D unsafe-code` rustc flag. Raw Win32 FFI is unavoidably
// `unsafe` at every call site (CreateWindowExW, Shell_NotifyIconW, the
// registry API, GWLP_USERDATA pointer round-tripping, ...) -- this
// crate-root attribute overrides that workspace-level deny for this one
// GUI-shell crate, matching the standard idiom for an FFI-heavy crate
// living in an otherwise `#![deny(unsafe_code)]` codebase. It does not
// relax anything for any other crate.
#![allow(unsafe_code)]

mod config_store;
mod notify;
mod protocol;
mod settings_window;
mod startup;
mod tray;
mod worker;

use protocol::{Command, Event};
use std::sync::mpsc::{self, Receiver, Sender};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, HWND_MESSAGE, KillTimer, MSG,
    PostQuitMessage, RegisterClassExW, SetTimer, TranslateMessage, WM_DESTROY, WM_TIMER,
    WNDCLASSEXW, WS_OVERLAPPED,
};
use windows::core::HSTRING;

const HIDDEN_CLASS_NAME: &str = "XeniaLauncherHiddenWindow";
const POLL_TIMER_ID: usize = 1;
const POLL_TIMER_MS: u32 = 250;

struct AppState {
    tray: tray::TrayHandles,
    notify_icon: notify::NotifyIcon,
    cmd_tx: Sender<Command>,
    event_rx: Receiver<Event>,
    profile_dir: std::path::PathBuf,
    config: xenia_launcher_core::config::DaemonConfig,
    settings_result_tx: Sender<settings_window::SettingsResult>,
    settings_result_rx: Receiver<settings_window::SettingsResult>,
    settings_open: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let profile_dir = protocol::default_profile_dir();
    if let Err(e) = std::fs::create_dir_all(&profile_dir) {
        tracing::error!(error = %e, path = %profile_dir.display(), "couldn't create the profile directory");
        return;
    }
    let config = config_store::load_or_default(&profile_dir);

    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();
    let (settings_result_tx, settings_result_rx) = mpsc::channel();

    worker::spawn(profile_dir.clone(), config.clone(), cmd_rx, event_tx);

    let tray = match tray::build() {
        Ok(tray) => tray,
        Err(e) => {
            tracing::error!(error = %e, "couldn't create the tray icon");
            return;
        }
    };

    let hidden_hwnd = match create_hidden_window() {
        Ok(hwnd) => hwnd,
        Err(e) => {
            tracing::error!(error = %e, "couldn't create the hidden message window");
            return;
        }
    };

    let notify_icon = match notify::NotifyIcon::register(hidden_hwnd) {
        Ok(icon) => icon,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't register the notification icon -- continuing without balloon notifications");
            // Not fatal: a launcher with a working tray but no balloons is
            // still useful. Fall through with a no-op-ish icon by
            // re-registering is not attempted here; see the Drop impl for
            // why an unregistered-on-failure icon is still safe to hold if
            // this branch is later changed to construct one anyway.
            return;
        }
    };

    let state = Box::new(AppState {
        tray,
        notify_icon,
        cmd_tx,
        event_rx,
        profile_dir,
        config,
        settings_result_tx,
        settings_result_rx,
        settings_open: false,
    });
    unsafe {
        windows::Win32::UI::WindowsAndMessaging::SetWindowLongPtrW(
            hidden_hwnd,
            windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
            Box::into_raw(state) as isize,
        );
        let _ = SetTimer(Some(hidden_hwnd), POLL_TIMER_ID, POLL_TIMER_MS, None);
    }

    run_message_loop();

    unsafe {
        let _ = KillTimer(Some(hidden_hwnd), POLL_TIMER_ID);
    }
}

fn run_message_loop() {
    let mut msg = MSG::default();
    loop {
        let result = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        if !result.as_bool() {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

fn create_hidden_window() -> windows::core::Result<HWND> {
    let hinstance = unsafe { GetModuleHandleW(None) }?;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(hidden_wndproc),
            hInstance: hinstance.into(),
            lpszClassName: windows::core::PCWSTR(HSTRING::from(HIDDEN_CLASS_NAME).as_ptr()),
            ..Default::default()
        };
        std::mem::forget(HSTRING::from(HIDDEN_CLASS_NAME));
        unsafe {
            RegisterClassExW(&class);
        }
    });

    unsafe {
        CreateWindowExW(
            Default::default(),
            &HSTRING::from(HIDDEN_CLASS_NAME),
            &HSTRING::from("Xenia Launcher (hidden)"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(hinstance.into()),
            None,
        )
    }
}

unsafe extern "system" fn hidden_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TIMER => {
            let state_ptr = unsafe {
                windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW(
                    hwnd,
                    windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
                )
            };
            if state_ptr != 0 {
                let state = unsafe { &mut *(state_ptr as *mut AppState) };
                tick(state);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Drain every pending menu click, worker event, and settings-window
/// result -- called on each `WM_TIMER` tick. Bounded (`try_recv` never
/// blocks the GUI thread), and every branch that changes something visible
/// goes through `AppState` so the next tick sees the update.
fn tick(state: &mut AppState) {
    while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
        handle_menu_event(state, event.id.0.as_str());
    }
    // Tray icon click/hover events (not menu clicks) currently have no
    // handler beyond what `with_menu_on_left_click(true)` already does
    // automatically -- drained here purely so the channel doesn't grow
    // unbounded, matching this crate's own documented per-event-type
    // channels.
    while tray_icon::TrayIconEvent::receiver().try_recv().is_ok() {}

    while let Ok(event) = state.event_rx.try_recv() {
        match event {
            Event::StatusChanged(status) => state.tray.apply_status(&status),
            Event::Notify { title, message } => state.notify_icon.show(&title, &message),
        }
    }

    while let Ok(result) = state.settings_result_rx.try_recv() {
        state.config = result.config.clone();
        if let Err(e) = config_store::save(&state.profile_dir, &state.config) {
            tracing::warn!(error = %e, "couldn't persist settings");
        }
        let _ = state
            .cmd_tx
            .send(Command::UpdateConfig(Box::new(result.config)));
        if let Err(e) = startup::set_enabled(result.start_at_login) {
            tracing::warn!(error = %e, "couldn't update start-at-login registration");
        }
        state.settings_open = false;
    }
}

fn handle_menu_event(state: &mut AppState, id: &str) {
    match id {
        tray::MENU_ID_START => {
            let _ = state.cmd_tx.send(Command::Start);
        }
        tray::MENU_ID_STOP => {
            let _ = state.cmd_tx.send(Command::Stop);
        }
        tray::MENU_ID_OPEN_SETTINGS => open_settings(state),
        tray::MENU_ID_OPEN_LOGS => open_folder(&state.profile_dir),
        tray::MENU_ID_QUIT => {
            let _ = state.cmd_tx.send(Command::Shutdown);
            unsafe { PostQuitMessage(0) };
        }
        _ => {}
    }
}

fn open_settings(state: &mut AppState) {
    if state.settings_open {
        // Already open -- a real "bring to front" would need tracking the
        // settings window's own hwnd; left as a known limitation rather
        // than adding that bookkeeping for a case that just means
        // clicking the taskbar/alt-tab works instead.
        return;
    }
    let start_at_login = startup::is_enabled().unwrap_or(false);
    match settings_window::open(
        state.config.clone(),
        start_at_login,
        state.settings_result_tx.clone(),
    ) {
        Ok(_hwnd) => state.settings_open = true,
        Err(e) => tracing::warn!(error = %e, "couldn't open the settings window"),
    }
}

fn open_folder(path: &std::path::Path) {
    unsafe {
        let _ = ShellExecuteW(
            None,
            &HSTRING::from("open"),
            &HSTRING::from(path.as_os_str()),
            &HSTRING::new(),
            &HSTRING::new(),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );
    }
}
