// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! CoreGraphics `CGEvent` backend.
//!
//! **Verification status: code review only, not compiler-verified.**
//! This environment has no macOS SDK (`osxcross`/Xcode) available, so
//! unlike the Windows backend (built + Wine-smoke-tested this session)
//! this module has not been built or run. It's written carefully
//! against the `core-graphics` crate's public API and Apple's
//! published `kVK_*` virtual-key constants (`HIToolbox/Events.h`,
//! stable for decades), but a real macOS build + run is the first
//! thing to do before trusting it in production. Flagging this
//! explicitly rather than letting a passing `cargo check` (which this
//! *can't* even get, on this host) imply more than it verified.
//!
//! macOS's own gate on this is the Accessibility permission the OS
//! prompts for on first real `CGEvent::post` call from an
//! unprivileged process -- this backend doesn't (and can't) bypass
//! that; `xenia-peer`'s M1 consent flow is the layer above it.
//!
//! ## Coordinate convention
//!
//! `CGEvent`'s mouse position is in real screen points, not a
//! normalized range like Windows' `MOUSEEVENTF_ABSOLUTE`. This
//! backend denormalizes `[0.0, 1.0]` against the constructor's
//! `screen_width`/`screen_height`, same as `UinputInjector`.
//!
//! ## Touch
//!
//! Real macOS touch/trackpad-gesture synthesis needs private APIs,
//! out of scope. Single-point touch (index 0 only, matching
//! `UinputInjector`'s limitation) is emulated via mouse down/move/up,
//! same approach as the Windows backend.

use crate::{InjectError, InputInjector};
use core_graphics::event::{CGEvent, CGEventTapLocation, CGEventType, CGKeyCode, CGMouseButton};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;

/// Map a Linux evdev keycode (the wire-level convention every
/// `xenia-inject` backend receives) to a macOS Carbon virtual-key
/// code (`kVK_*`). Covers the same key set `egui_key_to_evdev`
/// (`apps/xenia-viewer/src/gui.rs`) produces, **except Insert**
/// (evdev 110) -- standard Mac keyboards have no Insert key and no
/// unambiguous equivalent, so it's intentionally left unmapped rather
/// than guessed at.
fn evdev_to_kvk(code: u32) -> Option<CGKeyCode> {
    Some(match code {
        1 => 0x35,   // KEY_ESC -> kVK_Escape
        2 => 0x12,   // KEY_1 -> kVK_ANSI_1
        3 => 0x13,   // KEY_2
        4 => 0x14,   // KEY_3
        5 => 0x15,   // KEY_4
        6 => 0x17,   // KEY_5
        7 => 0x16,   // KEY_6
        8 => 0x1A,   // KEY_7
        9 => 0x1C,   // KEY_8
        10 => 0x19,  // KEY_9
        11 => 0x1D,  // KEY_0 -> kVK_ANSI_0
        12 => 0x1B,  // KEY_MINUS -> kVK_ANSI_Minus
        13 => 0x18,  // KEY_EQUAL -> kVK_ANSI_Equal
        14 => 0x33,  // KEY_BACKSPACE -> kVK_Delete
        15 => 0x30,  // KEY_TAB
        16 => 0x0C,  // KEY_Q -> kVK_ANSI_Q
        17 => 0x0D,  // KEY_W
        18 => 0x0E,  // KEY_E
        19 => 0x0F,  // KEY_R
        20 => 0x11,  // KEY_T
        21 => 0x10,  // KEY_Y
        22 => 0x20,  // KEY_U
        23 => 0x22,  // KEY_I
        24 => 0x1F,  // KEY_O
        25 => 0x23,  // KEY_P
        26 => 0x21,  // KEY_LEFTBRACE -> kVK_ANSI_LeftBracket
        27 => 0x1E,  // KEY_RIGHTBRACE -> kVK_ANSI_RightBracket
        28 => 0x24,  // KEY_ENTER -> kVK_Return
        30 => 0x00,  // KEY_A -> kVK_ANSI_A
        31 => 0x01,  // KEY_S
        32 => 0x02,  // KEY_D
        33 => 0x03,  // KEY_F
        34 => 0x05,  // KEY_G
        35 => 0x04,  // KEY_H
        36 => 0x26,  // KEY_J
        37 => 0x28,  // KEY_K
        38 => 0x25,  // KEY_L
        39 => 0x29,  // KEY_SEMICOLON -> kVK_ANSI_Semicolon
        40 => 0x27,  // KEY_APOSTROPHE -> kVK_ANSI_Quote
        41 => 0x32,  // KEY_GRAVE -> kVK_ANSI_Grave
        43 => 0x2A,  // KEY_BACKSLASH -> kVK_ANSI_Backslash
        44 => 0x06,  // KEY_Z -> kVK_ANSI_Z
        45 => 0x07,  // KEY_X
        46 => 0x08,  // KEY_C
        47 => 0x09,  // KEY_V
        48 => 0x0B,  // KEY_B
        49 => 0x2D,  // KEY_N
        50 => 0x2E,  // KEY_M
        51 => 0x2B,  // KEY_COMMA -> kVK_ANSI_Comma
        52 => 0x2F,  // KEY_DOT -> kVK_ANSI_Period
        53 => 0x2C,  // KEY_SLASH -> kVK_ANSI_Slash
        57 => 0x31,  // KEY_SPACE
        59 => 0x7A,  // KEY_F1 -> kVK_F1
        60 => 0x78,  // KEY_F2
        61 => 0x63,  // KEY_F3
        62 => 0x76,  // KEY_F4
        63 => 0x60,  // KEY_F5
        64 => 0x61,  // KEY_F6
        65 => 0x62,  // KEY_F7
        66 => 0x64,  // KEY_F8
        67 => 0x65,  // KEY_F9
        68 => 0x6D,  // KEY_F10
        87 => 0x67,  // KEY_F11
        88 => 0x6F,  // KEY_F12
        102 => 0x73, // KEY_HOME
        103 => 0x7E, // KEY_UP
        104 => 0x74, // KEY_PAGEUP -> kVK_PageUp
        105 => 0x7B, // KEY_LEFT
        106 => 0x7C, // KEY_RIGHT
        107 => 0x77, // KEY_END
        108 => 0x7D, // KEY_DOWN
        109 => 0x79, // KEY_PAGEDOWN -> kVK_PageDown
        111 => 0x75, // KEY_DELETE -> kVK_ForwardDelete
        _ => return None,
    })
}

/// Map a `xenia_inject::InputEvent::Pointer.button` id (0=left,
/// 1=middle, 2=right, 3+=aux) to `(down_type, up_type, cg_button)`.
/// `core-graphics`'s `CGMouseButton` only names Left/Right/Center --
/// aux buttons beyond middle fall back to Center, a documented
/// limitation, not a crash.
fn button_types(button: u8) -> (CGEventType, CGEventType, CGMouseButton) {
    match button {
        0 => (
            CGEventType::LeftMouseDown,
            CGEventType::LeftMouseUp,
            CGMouseButton::Left,
        ),
        2 => (
            CGEventType::RightMouseDown,
            CGEventType::RightMouseUp,
            CGMouseButton::Right,
        ),
        _ => (
            CGEventType::OtherMouseDown,
            CGEventType::OtherMouseUp,
            CGMouseButton::Center,
        ),
    }
}

/// `CGEvent`-based injector for macOS.
///
/// Deliberately does **not** hold a `CGEventSource` as a field:
/// `core-graphics`'s `CGEventSource` isn't `Send` (it wraps a
/// CoreFoundation object the binding doesn't assert cross-thread
/// safety for), but `InputInjector: Send` is required since the
/// daemon owns injectors on a dedicated task (see `lib.rs`). Rather
/// than assert `unsafe impl Send` for a claim this environment can't
/// verify (no macOS SDK to test against), each call constructs its
/// own source -- a cheap, stateless value read, not a persistent
/// resource, so there's no real cost to this beyond avoiding the
/// unverifiable claim.
pub struct MacosInjector {
    screen_width: u32,
    screen_height: u32,
    /// Bitset of pointer buttons currently held by this backend. Used only to
    /// select CoreGraphics drag event types for pure pointer motion.
    pressed_buttons: u8,
}

impl MacosInjector {
    /// Construct a new injector. `screen_width`/`screen_height` are
    /// used to denormalize `[0.0, 1.0]` coordinates into real screen
    /// points; the HID event source itself is (re)constructed per
    /// call, see the struct doc comment.
    pub fn new(screen_width: u32, screen_height: u32) -> Result<Self, InjectError> {
        // Fail fast at construction if the source is unavailable at
        // all (e.g. no HID access), even though each real call also
        // constructs its own.
        CGEventSource::new(CGEventSourceStateID::HIDSystemState).map_err(|()| {
            InjectError::Unavailable("CGEventSource::new(HIDSystemState) failed".into())
        })?;
        Ok(Self {
            screen_width,
            screen_height,
            pressed_buttons: 0,
        })
    }

    fn point(&self, x: f32, y: f32) -> CGPoint {
        CGPoint::new(
            f64::from(x.clamp(0.0, 1.0) * self.screen_width as f32),
            f64::from(y.clamp(0.0, 1.0) * self.screen_height as f32),
        )
    }

    fn event_source() -> Result<CGEventSource, InjectError> {
        CGEventSource::new(CGEventSourceStateID::HIDSystemState)
            .map_err(|()| InjectError::Backend("CGEventSource::new(HIDSystemState) failed".into()))
    }

    fn post_mouse(
        &self,
        event_type: CGEventType,
        point: CGPoint,
        button: CGMouseButton,
    ) -> Result<(), InjectError> {
        let source = Self::event_source()?;
        let event = CGEvent::new_mouse_event(source, event_type, point, button)
            .map_err(|()| InjectError::Backend("CGEvent::new_mouse_event failed".into()))?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }
}

impl InputInjector for MacosInjector {
    fn inject_pointer_move(&mut self, x: f32, y: f32) -> Result<(), InjectError> {
        let point = self.point(x, y);
        let (event_type, button) = if self.pressed_buttons & (1 << 0) != 0 {
            (CGEventType::LeftMouseDragged, CGMouseButton::Left)
        } else if self.pressed_buttons & (1 << 2) != 0 {
            (CGEventType::RightMouseDragged, CGMouseButton::Right)
        } else if self.pressed_buttons != 0 {
            (CGEventType::OtherMouseDragged, CGMouseButton::Center)
        } else {
            (CGEventType::MouseMoved, CGMouseButton::Left)
        };
        self.post_mouse(event_type, point, button)
    }

    fn inject_pointer_button(
        &mut self,
        x: f32,
        y: f32,
        button: u8,
        pressed: bool,
    ) -> Result<(), InjectError> {
        let point = self.point(x, y);
        let (down, up, cg_button) = button_types(button);
        self.post_mouse(if pressed { down } else { up }, point, cg_button)?;
        let bit = 1u8 << button.min(7);
        if pressed {
            self.pressed_buttons |= bit;
        } else {
            self.pressed_buttons &= !bit;
        }
        Ok(())
    }

    fn inject_key(&mut self, code: u32, pressed: bool, _modifiers: u8) -> Result<(), InjectError> {
        let Some(kvk) = evdev_to_kvk(code) else {
            return Err(InjectError::Unavailable(format!(
                "no macOS virtual-key mapping for evdev code {code}"
            )));
        };
        let source = Self::event_source()?;
        let event = CGEvent::new_keyboard_event(source, kvk, pressed)
            .map_err(|()| InjectError::Backend("CGEvent::new_keyboard_event failed".into()))?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    fn inject_touch(
        &mut self,
        index: u8,
        x: f32,
        y: f32,
        phase: u8,
        _pressure: f32,
    ) -> Result<(), InjectError> {
        if index != 0 {
            return Err(InjectError::Unavailable(
                "macos-cgevent backend supports single-point touch only (index 0); \
                 real multi-touch/trackpad synthesis needs private APIs, not implemented"
                    .into(),
            ));
        }
        let point = self.point(x, y);
        match phase {
            0 => self.post_mouse(CGEventType::LeftMouseDown, point, CGMouseButton::Left),
            1 => self.post_mouse(CGEventType::MouseMoved, point, CGMouseButton::Left),
            _ => self.post_mouse(CGEventType::LeftMouseUp, point, CGMouseButton::Left),
        }
    }

    fn backend_name(&self) -> &str {
        "macos-cgevent"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evdev_to_kvk_covers_the_egui_key_set_except_insert() {
        // Same set as windows.rs's equivalent test, minus 110 (Insert)
        // which is intentionally unmapped -- see module doc comment.
        let egui_evdev_codes: &[u32] = &[
            30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47,
            17, 45, 21, 44, // A-Z
            11, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 0-9
            57, 28, 1, 14, 15, // space, enter, esc, backspace, tab
            103, 108, 105, 106, // arrows
            102, 107, 104, 109, 111, // home/end/pgup/pgdn/del (no insert)
            12, 13, 39, 40, 41, 43, 51, 52, 53, 26, 27, // punctuation
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 87, 88, // F1-F12
        ];
        for &code in egui_evdev_codes {
            assert!(
                evdev_to_kvk(code).is_some(),
                "evdev code {code} has no kVK mapping"
            );
        }
    }

    #[test]
    fn evdev_to_kvk_leaves_insert_unmapped() {
        assert_eq!(evdev_to_kvk(110), None);
    }

    #[test]
    fn evdev_to_kvk_matches_known_carbon_constants() {
        assert_eq!(evdev_to_kvk(30), Some(0x00)); // A -> kVK_ANSI_A
        assert_eq!(evdev_to_kvk(57), Some(0x31)); // space -> kVK_Space
        assert_eq!(evdev_to_kvk(28), Some(0x24)); // enter -> kVK_Return
        assert_eq!(evdev_to_kvk(1), Some(0x35)); // esc -> kVK_Escape
        assert_eq!(evdev_to_kvk(11), Some(0x1D)); // '0' -> kVK_ANSI_0
    }

    #[test]
    fn evdev_to_kvk_rejects_unknown_codes() {
        assert_eq!(evdev_to_kvk(0), None);
        assert_eq!(evdev_to_kvk(999), None);
    }

    #[test]
    fn evdev_to_kvk_has_no_duplicate_targets() {
        let mut seen = std::collections::HashMap::new();
        for code in 0u32..200 {
            if let Some(kvk) = evdev_to_kvk(code) {
                if let Some(prev) = seen.insert(kvk, code) {
                    panic!("kVK {kvk:#x} mapped from both evdev {prev} and {code}");
                }
            }
        }
    }
}
