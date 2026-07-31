// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Xenia's minimal native Linux tray shell: a system tray icon + menu, a
//! small GTK settings window, desktop notifications, and XDG autostart
//! integration -- the Linux half of item 8 (macOS/Linux launcher parity),
//! mirroring `xenia-launcher-windows`'s architecture: a GUI thread runs
//! the platform's native event loop (here, GTK's), a separate worker
//! thread owns a tokio runtime and is the only place that touches
//! `xenia_launcher_core`'s async APIs, the two talk over plain
//! `std::sync::mpsc` channels. The protocol/worker/tray/config plumbing
//! is shared with the Windows launcher via `xenia_launcher_shell`; only
//! the settings window, notifications, and startup integration are
//! Linux-specific here.
//!
//! **What's verified and what isn't**: every `gtk-rs`/`notify-rust`/
//! `tray-icon` API used across this app was checked against the real,
//! cached crate source before use (not guessed from memory), and the
//! whole app builds and runs natively on this Linux host -- no
//! cross-compilation needed, unlike the Windows launcher. What that
//! can't cover is whether the tray icon, menu, settings window, and
//! notifications actually look and behave right under a real desktop
//! environment (GNOME/KDE/XFCE all differ in tray-icon-protocol and
//! notification-daemon support) -- treat this as compile-clean and
//! logic-tested, not yet visually/interactively verified on a real
//! desktop session.

mod notify;
mod settings_window;
mod startup;

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
}

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(e) = gtk::init() {
        tracing::error!(error = %e, "couldn't initialize GTK");
        return;
    }

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
    }));

    let tick_state = Rc::clone(&state);
    glib::source::timeout_add_local(POLL_INTERVAL, move || {
        tick(&tick_state);
        glib::ControlFlow::Continue
    });

    gtk::main();
}

/// Drain every pending menu click and worker event -- called on each
/// timer tick. Bounded (`try_recv` never blocks the GTK main loop).
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
            gtk::main_quit();
        }
        _ => {}
    }
}

fn open_settings(state: &Rc<RefCell<AppState>>) {
    if state.borrow().settings_open {
        // Already open -- a real "bring to front" would need tracking the
        // settings window's own handle; left as a known limitation
        // rather than adding that bookkeeping for a case that just means
        // alt-tab/clicking the taskbar entry works instead.
        return;
    }
    state.borrow_mut().settings_open = true;

    let (initial_config, initial_start_at_login) = {
        let s = state.borrow();
        (s.config.clone(), startup::is_enabled().unwrap_or(false))
    };

    let save_state = Rc::clone(state);
    let close_state = Rc::clone(state);
    settings_window::open(
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
    // `xdg-open` is the standard cross-desktop-environment way to open a
    // path with its default handler (a file manager, for a directory) --
    // the Linux/freedesktop analog of Windows' `ShellExecuteW`. Spawned
    // and immediately detached: whether the file manager opens is worth
    // logging on failure, not worth blocking the GUI thread over.
    match std::process::Command::new("xdg-open").arg(path).spawn() {
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, path = %path.display(), "couldn't run xdg-open"),
    }
}
