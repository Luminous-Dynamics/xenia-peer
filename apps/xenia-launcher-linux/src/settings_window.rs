// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A small, native settings window: listen address, admin port, state
//! directory, and a "start at login" checkbox, with Save/Cancel.
//!
//! Built directly on gtk-rs (already a transitive dependency via
//! tray-icon's own Linux backend -- see that crate's README) rather than
//! a higher-level toolkit: every API this module calls was verified
//! against the real cached `gtk-0.18.2`/`glib-0.18.5` source before use,
//! the same discipline `xenia-launcher-windows` used for raw Win32 --
//! except gtk-rs's bindings are actually-safe Rust, so nothing in this
//! module needs `unsafe`. "Narrowly featured," matching the Windows
//! settings window -- four fields and two buttons, not a general form
//! framework.
//!
//! Modeless and self-contained: [`open`] builds and shows the window,
//! then returns immediately. The result of a Save click (or that the
//! window closed at all, Save or otherwise) arrives later via the two
//! callbacks, both invoked on the GTK main thread.

use gtk::prelude::*;
use xenia_launcher_core::config::DaemonConfig;

/// Open the settings window. `on_save` fires once, only if the user
/// clicks Save, with the edited config and checkbox state. `on_close`
/// fires once the window is actually destroyed, on every path (Save,
/// Cancel, or the window manager's close button) -- callers use it to
/// know it's safe to open another settings window again.
pub fn open(
    initial_config: DaemonConfig,
    initial_start_at_login: bool,
    on_save: impl Fn(DaemonConfig, bool) + 'static,
    on_close: impl Fn() + 'static,
) {
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("Xenia Settings");
    window.set_default_size(420, 220);

    let root = gtk::Box::new(gtk::Orientation::Vertical, 8);
    root.set_border_width(12);

    let listen_entry = labeled_entry(&root, "Listen address:", &initial_config.listen);
    let admin_port_entry =
        labeled_entry(&root, "Admin port:", &initial_config.admin_port.to_string());
    let state_dir_entry = labeled_entry(
        &root,
        "State directory:",
        &initial_config.state_dir.display().to_string(),
    );

    let startup_check = gtk::CheckButton::with_label("Start automatically at login");
    startup_check.set_active(initial_start_at_login);
    root.pack_start(&startup_check, false, false, 4);

    let button_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let save_button = gtk::Button::with_label("Save");
    let cancel_button = gtk::Button::with_label("Cancel");
    button_row.pack_start(&save_button, false, false, 0);
    button_row.pack_start(&cancel_button, false, false, 0);
    root.pack_start(&button_row, false, false, 8);

    window.add(&root);

    {
        let window = window.clone();
        let base_config = initial_config.clone();
        let listen_entry = listen_entry.clone();
        let admin_port_entry = admin_port_entry.clone();
        let state_dir_entry = state_dir_entry.clone();
        let startup_check = startup_check.clone();
        save_button.connect_clicked(move |_| {
            let listen = listen_entry.text().to_string();
            let admin_port = admin_port_entry
                .text()
                .trim()
                .parse()
                .unwrap_or(base_config.admin_port);
            let state_dir = std::path::PathBuf::from(state_dir_entry.text().to_string());
            let config = DaemonConfig {
                listen,
                admin_port,
                state_dir,
                ..base_config.clone()
            };
            on_save(config, startup_check.is_active());
            window.close();
        });
    }
    {
        let window = window.clone();
        cancel_button.connect_clicked(move |_| {
            window.close();
        });
    }

    window.connect_destroy(move |_| {
        on_close();
    });

    window.show_all();
}

fn labeled_entry(container: &gtk::Box, label: &str, initial: &str) -> gtk::Entry {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let label_widget = gtk::Label::new(Some(label));
    label_widget.set_width_chars(16);
    let entry = gtk::Entry::new();
    entry.set_text(initial);
    row.pack_start(&label_widget, false, false, 0);
    row.pack_start(&entry, true, true, 0);
    container.pack_start(&row, false, false, 0);
    entry
}
