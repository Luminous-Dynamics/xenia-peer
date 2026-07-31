// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Xenia's minimal native macOS tray shell: a system tray icon + menu, a
//! small AppKit settings window, UserNotifications-based desktop
//! notifications, and LaunchAgent-based start-at-login integration --
//! the macOS half of item 8 (macOS/Linux launcher parity), mirroring
//! `xenia-launcher-windows`/`xenia-launcher-linux`'s architecture: the
//! GUI thread runs the platform's native event loop (here,
//! `NSApplication`'s), a separate worker thread owns a tokio runtime and
//! is the only place that touches `xenia_launcher_core`'s async APIs,
//! the two talk over plain `std::sync::mpsc` channels. The protocol/
//! worker/tray/config plumbing is shared with the other two launchers
//! via `xenia_launcher_shell`; only the settings window, notifications,
//! and startup integration are macOS-specific here.
//!
//! **What's verified and what isn't -- read this before trusting
//! anything in this crate.** Unlike Windows (`cargo-xwin` cross-compiles
//! against a freely redistributable subset of the real MSVC toolchain)
//! or Linux (builds natively on this very host), there is no
//! freely-redistributable way to get a real Apple SDK/linker on this
//! Linux development machine, and osxcross was not set up for this
//! session. What *was* verified, empirically, before writing a line of
//! this crate: `objc2`/`objc2-app-kit`/`objc2-foundation`/
//! `objc2-user-notifications` are pure, pre-generated Rust FFI bindings
//! with no C-compiling build script, so `cargo check --target
//! x86_64-apple-darwin` genuinely type-checks this crate's real
//! AppKit/UserNotifications API usage without needing the SDK (`cargo
//! check` never invokes the linker). That is real, load-bearing
//! verification -- every method signature used across this crate was
//! checked against real cached source and, where possible, against
//! `objc2`'s own complete working example (`hello_world_app.rs`) before
//! being written, and the whole crate has been iterated against that
//! local type-check loop. What it fundamentally cannot cover, and what
//! only a real `macos-latest` CI run (or a real Mac) can: whether the
//! generated Objective-C runtime calls actually succeed at runtime,
//! Objective-C retain-count/ownership correctness (see
//! `settings_window.rs`'s own doc comment for the specific risk there),
//! and -- as with the other two launchers -- whether the tray icon,
//! menu, settings window, and notifications actually look and behave
//! right on a real desktop session.

// The workspace denies `unsafe_code` by default (`[workspace.lints]`,
// deliberate hardening for a security-focused daemon/protocol codebase),
// enforced as a `-D unsafe-code` rustc flag. Real Objective-C message
// sends (msg_send!, initWithContentRect_styleMask_backing_defer,
// NSTimer's block-based scheduler, ...) are unavoidably `unsafe` -- this
// crate-root attribute overrides that workspace-level deny for this one
// GUI-shell crate, matching the standard idiom already used by
// xenia-launcher-windows for the same reason. It does not relax anything
// for any other crate.
#![allow(unsafe_code)]

mod notify;
mod settings_window;
mod startup;

use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use xenia_launcher_core::config::DaemonConfig;
use xenia_launcher_shell::protocol::{Command, Event};
use xenia_launcher_shell::{config_store, tray, worker};

struct AppState {
    tray: tray::TrayHandles,
    cmd_tx: mpsc::Sender<Command>,
    event_rx: mpsc::Receiver<Event>,
    profile_dir: std::path::PathBuf,
    config: DaemonConfig,
    settings_open: bool,
    mtm: MainThreadMarker,
}

const POLL_INTERVAL_SECS: f64 = 0.25;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Per tray-icon's own documented macOS requirement ("an event loop
    // must be running on the main thread so you also need to create the
    // tray icon on the main thread"), and AppKit's own general
    // requirement for any UI work -- `main()` genuinely does run on the
    // real OS main thread for a plain `fn main()` binary, so this should
    // never actually return `None` here in practice.
    let Some(mtm) = MainThreadMarker::new() else {
        tracing::error!("not running on the main thread -- cannot initialize AppKit");
        return;
    };

    let app = NSApplication::sharedApplication(mtm);
    // No Dock icon / app switcher entry -- this is a background tray
    // utility, not a regular foreground app.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    let profile_dir = xenia_launcher_shell::protocol::default_profile_dir();
    if let Err(e) = std::fs::create_dir_all(&profile_dir) {
        tracing::error!(error = %e, path = %profile_dir.display(), "couldn't create the profile directory");
        return;
    }
    let config = config_store::load_or_default(&profile_dir);

    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    worker::spawn(profile_dir.clone(), config.clone(), cmd_rx, event_tx);

    let tray = match tray::build() {
        Ok(tray) => tray,
        Err(e) => {
            tracing::error!(error = %e, "couldn't create the tray icon");
            return;
        }
    };

    let state = Rc::new(RefCell::new(AppState {
        tray,
        cmd_tx,
        event_rx,
        profile_dir,
        config,
        settings_open: false,
        mtm,
    }));

    // `NSTimer`'s block-based scheduler is the AppKit analog of Win32's
    // `SetTimer`/glib's `timeout_add_local` -- fires repeatedly on the
    // main run loop, which is exactly where the tray/menu/window work
    // below needs to happen.
    let tick_state = Rc::clone(&state);
    let timer_block = block2::RcBlock::new(
        move |_timer: std::ptr::NonNull<objc2_foundation::NSTimer>| {
            tick(&tick_state);
        },
    );
    let _timer = unsafe {
        objc2_foundation::NSTimer::scheduledTimerWithTimeInterval_repeats_block(
            POLL_INTERVAL_SECS,
            true,
            &timer_block,
        )
    };

    app.run();
}

/// Drain every pending menu click and worker event -- called on each
/// timer tick. Bounded (`try_recv` never blocks the main run loop).
fn tick(state: &Rc<RefCell<AppState>>) {
    while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
        handle_menu_event(state, event.id.0.as_str());
    }
    // Tray icon click/hover events (not menu clicks) currently have no
    // handler beyond what `with_menu_on_left_click(true)` already does
    // automatically -- drained here purely so the channel doesn't grow
    // unbounded, matching this crate's own documented per-event-type
    // channels.
    while tray_icon::TrayIconEvent::receiver().try_recv().is_ok() {}

    while let Ok(event) = state.borrow().event_rx.try_recv() {
        match event {
            Event::StatusChanged(status) => state.borrow().tray.apply_status(&status),
            Event::Notify { title, message } => notify::show(&title, &message),
        }
    }
}

fn handle_menu_event(state: &Rc<RefCell<AppState>>, id: &str) {
    match id {
        tray::MENU_ID_START => {
            let _ = state.borrow().cmd_tx.send(Command::Start);
        }
        tray::MENU_ID_STOP => {
            let _ = state.borrow().cmd_tx.send(Command::Stop);
        }
        tray::MENU_ID_OPEN_SETTINGS => open_settings(state),
        tray::MENU_ID_OPEN_LOGS => open_folder(&state.borrow().profile_dir),
        tray::MENU_ID_QUIT => {
            let _ = state.borrow().cmd_tx.send(Command::Shutdown);
            let mtm = state.borrow().mtm;
            NSApplication::sharedApplication(mtm).terminate(None);
        }
        _ => {}
    }
}

fn open_settings(state: &Rc<RefCell<AppState>>) {
    if state.borrow().settings_open {
        // Already open -- a real "bring to front" would need tracking
        // the settings window's own handle in `AppState`, not just
        // whether one exists; left as a known limitation rather than
        // adding that bookkeeping for a case that just means Cmd-Tab/
        // clicking the window works instead.
        return;
    }
    state.borrow_mut().settings_open = true;

    let (mtm, initial_config, initial_start_at_login) = {
        let s = state.borrow();
        (
            s.mtm,
            s.config.clone(),
            startup::is_enabled().unwrap_or(false),
        )
    };

    let save_state = Rc::clone(state);
    let close_state = Rc::clone(state);
    settings_window::open(
        mtm,
        initial_config,
        initial_start_at_login,
        move |config, start_at_login| {
            let mut s = save_state.borrow_mut();
            s.config = config.clone();
            if let Err(e) = config_store::save(&s.profile_dir, &s.config) {
                tracing::warn!(error = %e, "couldn't persist settings");
            }
            let _ = s.cmd_tx.send(Command::UpdateConfig(Box::new(config)));
            if let Err(e) = startup::set_enabled(start_at_login) {
                tracing::warn!(error = %e, "couldn't update start-at-login registration");
            }
        },
        move || {
            close_state.borrow_mut().settings_open = false;
        },
    );
}

fn open_folder(path: &std::path::Path) {
    // `open` is the standard macOS way to open a path with its default
    // handler (Finder, for a directory) -- the macOS analog of Windows'
    // `ShellExecuteW` / Linux's `xdg-open`.
    match std::process::Command::new("open").arg(path).spawn() {
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, path = %path.display(), "couldn't run `open`"),
    }
}
