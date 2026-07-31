// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A small, native settings window: listen address, admin port, state
//! directory, and a "start at login" checkbox, with Save/Cancel.
//!
//! Built directly on `objc2`/`objc2-app-kit` (already a transitive
//! dependency via `tray-icon`'s own macOS backend): every API this
//! module calls was verified against the real cached `objc2-app-kit`
//! 0.3.2 source, and against `objc2`'s own real, complete
//! `examples/hello_world_app.rs` (an NSApplication+NSWindow program)
//! before use -- the same discipline the Windows (raw Win32) and Linux
//! (gtk-rs) settings windows used, adapted to what's actually
//! type-checkable here (see this crate's `Cargo.toml` doc comment for
//! why `objc2-*` was chosen over a higher-level toolkit).
//!
//! **Ownership note (unverifiable without a real Mac, disclosed
//! honestly)**: `NSWindow.delegate` is a non-owning (`weak`/`assign` in
//! AppKit terms) property -- the window does NOT keep the delegate
//! object alive. This module keeps the one active settings window's
//! delegate (which itself owns the window, the field handles, and the
//! save/close callbacks) alive in a thread-local slot, cleared exactly
//! when `windowWillClose:` fires. This is the standard idiom for a
//! one-off, non-window-controller-owned Cocoa window, and type-checks,
//! but its actual runtime correctness (no dangling delegate, no
//! double-free) has not been exercised on real AppKit -- flagged
//! explicitly as the highest-risk-if-wrong piece of this whole app.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSBackingStoreType, NSButton, NSButtonType, NSControlStateValue, NSStackView, NSTextField,
    NSUserInterfaceLayoutOrientation, NSView, NSWindow, NSWindowDelegate, NSWindowStyleMask,
};
use objc2_foundation::{
    NSArray, NSNotification, NSObject, NSObjectProtocol, NSPoint, NSRect, NSSize, NSString,
    ns_string,
};
use std::cell::RefCell;

/// `NSControlStateValueOn` (see objc2-app-kit's `NSCell.rs`) -- `NSButton`'s
/// checkbox-checked state.
const CONTROL_STATE_ON: NSControlStateValue = 1;
const SAVE_TAG: isize = 1;
const CANCEL_TAG: isize = 2;

thread_local! {
    /// The one currently-open settings window's delegate, if any -- see
    /// this module's own doc comment for why this exists. `main.rs`'s own
    /// `settings_open` flag already enforces "at most one at a time," so
    /// this slot is never contended.
    static ACTIVE: RefCell<Option<Retained<SettingsDelegate>>> = const { RefCell::new(None) };
}

struct SettingsIvars {
    window: Retained<NSWindow>,
    listen_field: Retained<NSTextField>,
    admin_port_field: Retained<NSTextField>,
    state_dir_field: Retained<NSTextField>,
    startup_checkbox: Retained<NSButton>,
    base_config: xenia_launcher_core::config::DaemonConfig,
    #[allow(clippy::type_complexity)]
    on_save: RefCell<Box<dyn FnMut(xenia_launcher_core::config::DaemonConfig, bool)>>,
    on_close: RefCell<Box<dyn FnMut()>>,
}

define_class!(
    // SAFETY:
    // - The superclass NSObject has no subclassing requirements.
    // - `SettingsDelegate` does not implement `Drop`.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = SettingsIvars]
    struct SettingsDelegate;

    // SAFETY: `NSObjectProtocol` has no safety requirements.
    unsafe impl NSObjectProtocol for SettingsDelegate {}

    // SAFETY: `NSWindowDelegate` has no safety requirements.
    unsafe impl NSWindowDelegate for SettingsDelegate {
        #[unsafe(method(windowWillClose:))]
        fn window_will_close(&self, _notification: &NSNotification) {
            (self.ivars().on_close.borrow_mut())();
            // Drop this delegate (and, transitively, the window/fields it
            // owns) now that AppKit is done with it for this event -- see
            // the module doc comment.
            ACTIVE.with(|active| *active.borrow_mut() = None);
        }
    }

    impl SettingsDelegate {
        // Shared target-action handler for both Save and Cancel --
        // distinguished by `sender.tag()`, the standard AppKit pattern
        // for "one handler, several buttons."
        #[unsafe(method(buttonClicked:))]
        fn button_clicked(&self, sender: &NSButton) {
            let ivars = self.ivars();
            if sender.tag() == SAVE_TAG {
                let listen = ivars.listen_field.stringValue().to_string();
                let admin_port = ivars
                    .admin_port_field
                    .stringValue()
                    .to_string()
                    .trim()
                    .parse()
                    .unwrap_or(ivars.base_config.admin_port);
                let state_dir =
                    std::path::PathBuf::from(ivars.state_dir_field.stringValue().to_string());
                let start_at_login = ivars.startup_checkbox.state() == CONTROL_STATE_ON;
                let config = xenia_launcher_core::config::DaemonConfig {
                    listen,
                    admin_port,
                    state_dir,
                    ..ivars.base_config.clone()
                };
                (ivars.on_save.borrow_mut())(config, start_at_login);
            }
            ivars.window.close();
        }
    }
);

impl SettingsDelegate {
    #[allow(clippy::too_many_arguments)]
    fn new(
        mtm: MainThreadMarker,
        window: Retained<NSWindow>,
        listen_field: Retained<NSTextField>,
        admin_port_field: Retained<NSTextField>,
        state_dir_field: Retained<NSTextField>,
        startup_checkbox: Retained<NSButton>,
        base_config: xenia_launcher_core::config::DaemonConfig,
        on_save: Box<dyn FnMut(xenia_launcher_core::config::DaemonConfig, bool)>,
        on_close: Box<dyn FnMut()>,
    ) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(SettingsIvars {
            window,
            listen_field,
            admin_port_field,
            state_dir_field,
            startup_checkbox,
            base_config,
            on_save: RefCell::new(on_save),
            on_close: RefCell::new(on_close),
        });
        // SAFETY: NSObject's `init` has no extra requirements.
        unsafe { msg_send![super(this), init] }
    }
}

/// Open the settings window. `on_save` fires once, only if the user
/// clicks Save, with the edited config (spread-updated from
/// `initial_config`, matching the Windows/Linux settings windows'
/// contract exactly) and checkbox state. `on_close` fires once the
/// window is actually destroyed, on every path (Save, Cancel, or the
/// traffic-light close button).
pub fn open(
    mtm: MainThreadMarker,
    initial_config: xenia_launcher_core::config::DaemonConfig,
    initial_start_at_login: bool,
    on_save: impl FnMut(xenia_launcher_core::config::DaemonConfig, bool) + 'static,
    on_close: impl FnMut() + 'static,
) {
    let window = build_window(mtm);

    let listen_field = labeled_field(mtm, &initial_config.listen);
    let admin_port_field = labeled_field(mtm, &initial_config.admin_port.to_string());
    let state_dir_field = labeled_field(mtm, &initial_config.state_dir.display().to_string());
    let startup_checkbox = build_checkbox(mtm, initial_start_at_login);
    let (save_button, cancel_button) = build_buttons(mtm);

    let root = NSStackView::stackViewWithViews(
        &NSArray::from_slice(&[
            row(mtm, "Listen address:", &listen_field).as_ref(),
            row(mtm, "Admin port:", &admin_port_field).as_ref(),
            row(mtm, "State directory:", &state_dir_field).as_ref(),
            startup_checkbox.as_ref() as &NSView,
            button_row(mtm, &save_button, &cancel_button).as_ref(),
        ]),
        mtm,
    );
    root.setOrientation(NSUserInterfaceLayoutOrientation::Vertical);
    root.setSpacing(8.0);

    window.setContentView(Some(&root));

    let delegate = SettingsDelegate::new(
        mtm,
        window.clone(),
        listen_field,
        admin_port_field,
        state_dir_field,
        startup_checkbox,
        initial_config,
        Box::new(on_save),
        Box::new(on_close),
    );

    let target: &AnyObject = &delegate;
    let action = sel!(buttonClicked:);
    save_button.setTag(SAVE_TAG as _);
    cancel_button.setTag(CANCEL_TAG as _);
    unsafe {
        save_button.setTarget(Some(target));
        save_button.setAction(Some(action));
        cancel_button.setTarget(Some(target));
        cancel_button.setAction(Some(action));
    }

    window.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    ACTIVE.with(|active| *active.borrow_mut() = Some(delegate));

    window.center();
    window.makeKeyAndOrderFront(None);
}

fn build_window(mtm: MainThreadMarker) -> Retained<NSWindow> {
    let window = unsafe {
        NSWindow::initWithContentRect_styleMask_backing_defer(
            NSWindow::alloc(mtm),
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(420.0, 260.0)),
            NSWindowStyleMask::Titled
                | NSWindowStyleMask::Closable
                | NSWindowStyleMask::Miniaturizable,
            NSBackingStoreType::Buffered,
            false,
        )
    };
    // Required when creating an `NSWindow` outside a window controller --
    // see objc2's own `hello_world_app.rs` example for the identical
    // pattern/reasoning.
    unsafe { window.setReleasedWhenClosed(false) };
    window.setTitle(ns_string!("Xenia Settings"));
    window
}

fn labeled_field(mtm: MainThreadMarker, initial: &str) -> Retained<NSTextField> {
    let field = NSTextField::new(mtm);
    field.setStringValue(&NSString::from_str(initial));
    field.setEditable(true);
    field
}

fn build_checkbox(mtm: MainThreadMarker, initial_checked: bool) -> Retained<NSButton> {
    let checkbox = NSButton::new(mtm);
    checkbox.setButtonType(NSButtonType::Switch);
    checkbox.setTitle(ns_string!("Start automatically at login"));
    if initial_checked {
        checkbox.setState(CONTROL_STATE_ON);
    }
    checkbox
}

fn build_buttons(mtm: MainThreadMarker) -> (Retained<NSButton>, Retained<NSButton>) {
    let save = NSButton::new(mtm);
    save.setTitle(ns_string!("Save"));
    let cancel = NSButton::new(mtm);
    cancel.setTitle(ns_string!("Cancel"));
    (save, cancel)
}

fn row(mtm: MainThreadMarker, label: &str, field: &NSTextField) -> Retained<NSStackView> {
    let label_field = NSTextField::labelWithString(&NSString::from_str(label), mtm);
    let stack = NSStackView::stackViewWithViews(
        &NSArray::from_slice(&[label_field.as_ref() as &NSView, field.as_ref() as &NSView]),
        mtm,
    );
    stack.setOrientation(NSUserInterfaceLayoutOrientation::Horizontal);
    stack.setSpacing(8.0);
    stack
}

fn button_row(mtm: MainThreadMarker, save: &NSButton, cancel: &NSButton) -> Retained<NSStackView> {
    let stack = NSStackView::stackViewWithViews(
        &NSArray::from_slice(&[save.as_ref() as &NSView, cancel.as_ref() as &NSView]),
        mtm,
    );
    stack.setOrientation(NSUserInterfaceLayoutOrientation::Horizontal);
    stack.setSpacing(8.0);
    stack
}
