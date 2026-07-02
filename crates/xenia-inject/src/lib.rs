// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Ported from `symthaea/src/swarm/rdp_input.rs`. Relicensed to
// Apache-2.0 OR MIT for this crate by the copyright holder (same
// author); see ADR-002. The X11 backend present in the upstream
// was dropped per ADR-001 Decision 2 (Wayland-only). `InputEvent`
// was sourced from `symthaea/src/swarm/rdp_protocol.rs::InputEvent`
// and is defined locally here as the normative typed shape the
// injector trait consumes.

//! # xenia-inject
//!
//! Input-injection abstraction for the Xenia remote-session stack.
//!
//! The viewer side produces [`InputEvent`]s from the user's pointer
//! / keyboard / touch actions and ships them as
//! `xenia_peer_core::frame::RawInput` payloads to the daemon. The
//! daemon side feeds those events into an [`InputInjector`] which
//! delivers them to the host compositor.
//!
//! ## Coordinate convention
//!
//! Pointer / touch coordinates are **normalized** to `[0.0, 1.0]`
//! over the full captured screen. Backends multiply by screen
//! dimensions to get pixel coordinates. This matches
//! `xenia-capture::CapturedFrame` — whatever the capture's
//! `(width, height)` is, that's the coordinate frame for injected
//! input.
//!
//! ## Backends (in this crate)
//!
//! | Name | Feature | Status |
//! |---|---|---|
//! | `NoopInjector` | always available | ✅ discards all events |
//! | `LoggingInjector` | always available | ✅ records events for test verification |
//! | `WaylandInputInjector` | `wayland-virtual` | 🚧 scaffold — returns Unavailable |
//! | `UinputInjector` | `uinput` | 🚧 scaffold — returns Unavailable |
//!
//! X11 injection (via XTest) is deliberately out of scope per
//! ADR-001 Decision 2 (Wayland-only).

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "xdg-portal")]
mod xdg_portal;
#[cfg(feature = "xdg-portal")]
pub use xdg_portal::XdgPortalInjector;

/// Errors from an input backend.
#[derive(Debug, Error)]
pub enum InjectError {
    /// Backend is compiled but runtime-unavailable (no Wayland
    /// display, no /dev/uinput access, etc.).
    #[error("inject unavailable: {0}")]
    Unavailable(String),

    /// Backend-level failure (e.g., compositor returned an error).
    /// Wrapped for logs; drop the event and carry on.
    #[error("inject backend: {0}")]
    Backend(String),
}

/// Normalized input events flowing viewer → daemon.
///
/// This enum mirrors Symthaea's `rdp_protocol::InputEvent`. A
/// stable, typed shape beats opaque bytes for something users will
/// actually define a taxonomy around. `RawInput.payload` can
/// carry the bincode-encoded form of this enum, or a different
/// typed shape if an integrator wants their own.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InputEvent {
    /// Mouse / pointer motion or button.
    Pointer {
        /// Normalized x in `[0.0, 1.0]`.
        x: f32,
        /// Normalized y in `[0.0, 1.0]`.
        y: f32,
        /// Button id (0 = left, 1 = middle, 2 = right, 3+ = aux).
        /// Pointer-motion-only events use `button = 0` with
        /// `pressed = false`.
        button: u8,
        /// `true` = press, `false` = release or motion.
        pressed: bool,
    },
    /// Keyboard.
    Key {
        /// XKB keycode, Linux keycode, or other platform-specific
        /// scancode. Backends translate.
        code: u32,
        /// `true` = press, `false` = release.
        pressed: bool,
        /// Modifier bitmask: bit 0 = Shift, 1 = Ctrl, 2 = Alt,
        /// 3 = Meta/Super/Win. Higher bits reserved.
        modifiers: u8,
    },
    /// Touch gesture (multi-touch supported via `index`).
    Touch {
        /// Touch point index (0..=MAX_TOUCH_POINTS, typically 0..=9).
        index: u8,
        /// Normalized x in `[0.0, 1.0]`.
        x: f32,
        /// Normalized y in `[0.0, 1.0]`.
        y: f32,
        /// Phase: 0 = Down, 1 = Move, 2 = Up, 3 = Cancel.
        phase: u8,
        /// Normalized pressure in `[0.0, 1.0]`, or `0.0` if the
        /// device doesn't report pressure.
        pressure: f32,
    },
}

/// A recorded injection — useful for `LoggingInjector` + tests.
#[derive(Debug, Clone, PartialEq)]
pub enum InjectedEvent {
    /// Pointer event with denormalized (pixel) coordinates.
    Pointer {
        /// Screen x in pixels.
        screen_x: i32,
        /// Screen y in pixels.
        screen_y: i32,
        /// Button id (see [`InputEvent::Pointer::button`]).
        button: u8,
        /// Press / release.
        pressed: bool,
    },
    /// Keyboard event.
    Key {
        /// Platform scancode.
        code: u32,
        /// Press / release.
        pressed: bool,
        /// Modifier bitmask.
        modifiers: u8,
    },
    /// Touch event with denormalized coordinates.
    Touch {
        /// Touch point index.
        index: u8,
        /// Screen x in pixels.
        screen_x: i32,
        /// Screen y in pixels.
        screen_y: i32,
        /// Phase (0 Down, 1 Move, 2 Up, 3 Cancel).
        phase: u8,
        /// Normalized pressure in `[0.0, 1.0]`.
        pressure: f32,
    },
}

/// Platform-agnostic input-injection interface. `Send` so the
/// daemon's receive-and-inject loop can own it on a dedicated
/// task.
pub trait InputInjector: Send {
    /// Inject a pointer event. `x` / `y` are in `[0.0, 1.0]`.
    fn inject_pointer(
        &mut self,
        x: f32,
        y: f32,
        button: u8,
        pressed: bool,
    ) -> Result<(), InjectError>;

    /// Inject a keyboard event.
    fn inject_key(&mut self, code: u32, pressed: bool, modifiers: u8) -> Result<(), InjectError>;

    /// Inject a touch event. `x` / `y` are in `[0.0, 1.0]`,
    /// `pressure` likewise.
    fn inject_touch(
        &mut self,
        index: u8,
        x: f32,
        y: f32,
        phase: u8,
        pressure: f32,
    ) -> Result<(), InjectError>;

    /// Drive a batch of [`InputEvent`]s. Default impl dispatches
    /// each one; backends needing batch semantics can override.
    fn process_events(&mut self, events: &[InputEvent]) -> Result<(), InjectError> {
        for event in events {
            match event {
                InputEvent::Pointer {
                    x,
                    y,
                    button,
                    pressed,
                } => self.inject_pointer(*x, *y, *button, *pressed)?,
                InputEvent::Key {
                    code,
                    pressed,
                    modifiers,
                } => self.inject_key(*code, *pressed, *modifiers)?,
                InputEvent::Touch {
                    index,
                    x,
                    y,
                    phase,
                    pressure,
                } => self.inject_touch(*index, *x, *y, *phase, *pressure)?,
            }
        }
        Ok(())
    }

    /// Backend identifier for observability.
    fn backend_name(&self) -> &str;
}

// ───────────────────────── NoopInjector ────────────────────────────

/// Silently drops every event. Useful for view-only sessions and
/// for unit tests where you want to drive the daemon's event
/// path without actually touching the host.
pub struct NoopInjector;

impl InputInjector for NoopInjector {
    fn inject_pointer(
        &mut self,
        _x: f32,
        _y: f32,
        _button: u8,
        _pressed: bool,
    ) -> Result<(), InjectError> {
        Ok(())
    }
    fn inject_key(
        &mut self,
        _code: u32,
        _pressed: bool,
        _modifiers: u8,
    ) -> Result<(), InjectError> {
        Ok(())
    }
    fn inject_touch(
        &mut self,
        _index: u8,
        _x: f32,
        _y: f32,
        _phase: u8,
        _pressure: f32,
    ) -> Result<(), InjectError> {
        Ok(())
    }
    fn backend_name(&self) -> &str {
        "noop"
    }
}

// ───────────────────────── LoggingInjector ─────────────────────────

/// Records every injection into an in-memory buffer, denormalizing
/// coordinates against the configured screen size. Primary test
/// vehicle for the inject path.
pub struct LoggingInjector {
    /// Every event that's flowed through. Grows unbounded; this
    /// is a test helper, not a production backend.
    pub events: Vec<InjectedEvent>,
    screen_width: u32,
    screen_height: u32,
}

impl LoggingInjector {
    /// New logger sized for `screen_width × screen_height`.
    pub fn new(screen_width: u32, screen_height: u32) -> Self {
        Self {
            events: Vec::new(),
            screen_width,
            screen_height,
        }
    }

    fn denorm_x(&self, x: f32) -> i32 {
        (x.clamp(0.0, 1.0) * self.screen_width as f32) as i32
    }

    fn denorm_y(&self, y: f32) -> i32 {
        (y.clamp(0.0, 1.0) * self.screen_height as f32) as i32
    }
}

impl InputInjector for LoggingInjector {
    fn inject_pointer(
        &mut self,
        x: f32,
        y: f32,
        button: u8,
        pressed: bool,
    ) -> Result<(), InjectError> {
        self.events.push(InjectedEvent::Pointer {
            screen_x: self.denorm_x(x),
            screen_y: self.denorm_y(y),
            button,
            pressed,
        });
        Ok(())
    }

    fn inject_key(&mut self, code: u32, pressed: bool, modifiers: u8) -> Result<(), InjectError> {
        self.events.push(InjectedEvent::Key {
            code,
            pressed,
            modifiers,
        });
        Ok(())
    }

    fn inject_touch(
        &mut self,
        index: u8,
        x: f32,
        y: f32,
        phase: u8,
        pressure: f32,
    ) -> Result<(), InjectError> {
        self.events.push(InjectedEvent::Touch {
            index,
            screen_x: self.denorm_x(x),
            screen_y: self.denorm_y(y),
            phase,
            pressure: pressure.clamp(0.0, 1.0),
        });
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "log"
    }
}

// ───────────────────────── Wayland virtual input ───────────────────

/// Wayland virtual-pointer + virtual-keyboard injection for
/// wlroots-based compositors (Sway, Hyprland, labwc).
///
/// **Scaffold only** today. Real `wayland-client` + `wlr-virtual-*`
/// plumbing lands alongside `xenia-capture::WlrootsCapture`
/// (they share the wayland-client eventloop).
///
/// Requires the `wayland-virtual` feature.
#[cfg(feature = "wayland-virtual")]
pub struct WaylandInputInjector {
    screen_width: u32,
    screen_height: u32,
}

#[cfg(feature = "wayland-virtual")]
impl WaylandInputInjector {
    /// Connect to the compositor, bind `zwlr_virtual_pointer_manager_v1`
    /// + `zwp_virtual_keyboard_manager_v1`, and create virtual
    /// devices. **Currently unimplemented.**
    pub fn new(_screen_width: u32, _screen_height: u32) -> Result<Self, InjectError> {
        Err(InjectError::Unavailable(
            "wayland-virtual backend lands with xenia-capture::WlrootsCapture".into(),
        ))
    }
}

#[cfg(feature = "wayland-virtual")]
impl InputInjector for WaylandInputInjector {
    fn inject_pointer(
        &mut self,
        _x: f32,
        _y: f32,
        _button: u8,
        _pressed: bool,
    ) -> Result<(), InjectError> {
        Err(InjectError::Unavailable(
            "wayland-virtual backend not yet implemented".into(),
        ))
    }
    fn inject_key(
        &mut self,
        _code: u32,
        _pressed: bool,
        _modifiers: u8,
    ) -> Result<(), InjectError> {
        Err(InjectError::Unavailable(
            "wayland-virtual backend not yet implemented".into(),
        ))
    }
    fn inject_touch(
        &mut self,
        _index: u8,
        _x: f32,
        _y: f32,
        _phase: u8,
        _pressure: f32,
    ) -> Result<(), InjectError> {
        Err(InjectError::Unavailable(
            "wayland-virtual backend not yet implemented".into(),
        ))
    }
    fn backend_name(&self) -> &str {
        "wayland-virtual"
    }
}

// ───────────────────────── uinput backend ──────────────────────────

/// Kernel-level `uinput` injection. Creates a virtual evdev device
/// that pipes synthetic events into the kernel's input subsystem.
///
/// **Scaffold only** today. Requires `/dev/uinput` access: root,
/// membership in the `input` group, or a `udev` rule granting the
/// daemon's user access.
///
/// Requires the `uinput` feature.
#[cfg(feature = "uinput")]
pub struct UinputInjector {
    screen_width: u32,
    screen_height: u32,
}

#[cfg(feature = "uinput")]
impl UinputInjector {
    /// Open `/dev/uinput` and register a virtual device with
    /// pointer + keyboard + touch capabilities. **Currently
    /// unimplemented.**
    pub fn new(_screen_width: u32, _screen_height: u32) -> Result<Self, InjectError> {
        Err(InjectError::Unavailable(
            "uinput backend not yet implemented".into(),
        ))
    }
}

#[cfg(feature = "uinput")]
impl InputInjector for UinputInjector {
    fn inject_pointer(
        &mut self,
        _x: f32,
        _y: f32,
        _button: u8,
        _pressed: bool,
    ) -> Result<(), InjectError> {
        Err(InjectError::Unavailable(
            "uinput backend not yet implemented".into(),
        ))
    }
    fn inject_key(
        &mut self,
        _code: u32,
        _pressed: bool,
        _modifiers: u8,
    ) -> Result<(), InjectError> {
        Err(InjectError::Unavailable(
            "uinput backend not yet implemented".into(),
        ))
    }
    fn inject_touch(
        &mut self,
        _index: u8,
        _x: f32,
        _y: f32,
        _phase: u8,
        _pressure: f32,
    ) -> Result<(), InjectError> {
        Err(InjectError::Unavailable(
            "uinput backend not yet implemented".into(),
        ))
    }
    fn backend_name(&self) -> &str {
        "uinput"
    }
}

// ───────────────────────── Tests ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_accepts_everything() {
        let mut inj = NoopInjector;
        assert!(inj.inject_pointer(0.5, 0.5, 0, true).is_ok());
        assert!(inj.inject_key(65, true, 0).is_ok());
        assert!(inj.inject_touch(0, 0.0, 0.0, 0, 1.0).is_ok());
    }

    #[test]
    fn logging_denormalizes_coordinates() {
        let mut log = LoggingInjector::new(1920, 1080);
        log.inject_pointer(0.5, 0.25, 0, true).unwrap();
        assert_eq!(log.events.len(), 1);
        match &log.events[0] {
            InjectedEvent::Pointer {
                screen_x, screen_y, ..
            } => {
                assert_eq!(*screen_x, 960);
                assert_eq!(*screen_y, 270);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn logging_clamps_out_of_range_coords() {
        let mut log = LoggingInjector::new(1000, 500);
        log.inject_pointer(-0.5, 2.0, 0, true).unwrap();
        log.inject_pointer(1.5, -0.1, 0, true).unwrap();
        assert_eq!(log.events.len(), 2);
        // -0.5 → clamp(0, 1) = 0 → screen_x = 0.
        // 2.0  → clamp(0, 1) = 1 → screen_y = 500.
        assert!(matches!(
            log.events[0],
            InjectedEvent::Pointer {
                screen_x: 0,
                screen_y: 500,
                ..
            }
        ));
        assert!(matches!(
            log.events[1],
            InjectedEvent::Pointer {
                screen_x: 1000,
                screen_y: 0,
                ..
            }
        ));
    }

    #[test]
    fn process_events_dispatches_all_variants() {
        let mut log = LoggingInjector::new(100, 100);
        let events = vec![
            InputEvent::Pointer {
                x: 0.1,
                y: 0.2,
                button: 1,
                pressed: true,
            },
            InputEvent::Key {
                code: 42,
                pressed: true,
                modifiers: 0b0001,
            },
            InputEvent::Touch {
                index: 0,
                x: 0.5,
                y: 0.5,
                phase: 0,
                pressure: 0.9,
            },
        ];
        log.process_events(&events).unwrap();
        assert_eq!(log.events.len(), 3);
        assert!(matches!(log.events[0], InjectedEvent::Pointer { .. }));
        assert!(matches!(
            log.events[1],
            InjectedEvent::Key {
                code: 42,
                modifiers: 1,
                ..
            }
        ));
        assert!(matches!(log.events[2], InjectedEvent::Touch { .. }));
    }

    #[test]
    fn input_event_roundtrips_bincode() {
        let events = [
            InputEvent::Pointer {
                x: 0.5,
                y: 0.7,
                button: 1,
                pressed: true,
            },
            InputEvent::Key {
                code: 42,
                pressed: false,
                modifiers: 5,
            },
            InputEvent::Touch {
                index: 2,
                x: 0.1,
                y: 0.9,
                phase: 1,
                pressure: 0.5,
            },
        ];
        for original in &events {
            let bytes = bincode::serialize(original).unwrap();
            let decoded: InputEvent = bincode::deserialize(&bytes).unwrap();
            assert_eq!(*original, decoded);
        }
    }
}
