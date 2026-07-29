// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Win32 `SendInput` backend.
//!
//! Windows has no portal/consent-dialog layer analogous to
//! `xdg-desktop-portal`'s `RemoteDesktop` interface — any process
//! with an interactive desktop session can call `SendInput`. This
//! backend's trust boundary is therefore the same as `uinput`'s:
//! host-level process access is the only gate, and `xenia-peer`'s
//! own M1 consent flow is what stands between "connected" and
//! "can move your mouse."
//!
//! ## Coordinate convention
//!
//! `MOUSEEVENTF_ABSOLUTE` interprets `dx`/`dy` as `[0, 65535]` across
//! the target display, which is exactly `xenia_inject`'s own
//! `[0.0, 1.0]` normalized convention scaled up — no screen-pixel
//! query needed, unlike `uinput`'s `ABS_X`/`ABS_Y` device-capability
//! range.
//!
//! ## Touch
//!
//! Real Windows touch injection is a separate subsystem
//! (`InitializeTouchInjection` / `InjectTouchInput`) with its own
//! session/digitizer setup, out of scope here. Single-point touch
//! (index 0 only, matching `UinputInjector`'s own limitation) is
//! emulated via the same absolute-mouse primitive: down = move +
//! left-button-down, move = move only, up = left-button-up. This is
//! a real, common "touch via mouse emulation" technique — not a
//! substitute for genuine multi-touch.

use crate::{InjectError, InputInjector};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
};
// XBUTTON1/XBUTTON2 (the aux-mouse-button IDs used in MOUSEINPUT.mouseData
// for MOUSEEVENTF_XDOWN/XUP) live under WindowsAndMessaging in this crate,
// not KeyboardAndMouse -- they're defined alongside the WM_XBUTTON* message
// constants in the real Win32 headers, not the SendInput-adjacent ones.
use windows::Win32::UI::WindowsAndMessaging::{XBUTTON1, XBUTTON2};

/// Full-scale value for `MOUSEEVENTF_ABSOLUTE`'s `[0, 65535]` axis.
const ABS_MAX: f32 = 65_535.0;

/// Denormalize a `[0.0, 1.0]` coordinate into Windows' absolute-mouse range.
fn denorm(v: f32) -> i32 {
    (v.clamp(0.0, 1.0) * ABS_MAX) as i32
}

/// Map a `xenia_inject::InputEvent::Pointer.button` id (0=left,
/// 1=middle, 2=right, 3+=aux) to a `(down_flag, up_flag, mouse_data)`
/// triple. `mouse_data` is only meaningful for the X-button flags.
fn button_flags(button: u8) -> (u32, u32, u32) {
    match button {
        0 => (MOUSEEVENTF_LEFTDOWN.0, MOUSEEVENTF_LEFTUP.0, 0),
        1 => (MOUSEEVENTF_MIDDLEDOWN.0, MOUSEEVENTF_MIDDLEUP.0, 0),
        2 => (MOUSEEVENTF_RIGHTDOWN.0, MOUSEEVENTF_RIGHTUP.0, 0),
        3 => (MOUSEEVENTF_XDOWN.0, MOUSEEVENTF_XUP.0, XBUTTON1 as u32),
        _ => (MOUSEEVENTF_XDOWN.0, MOUSEEVENTF_XUP.0, XBUTTON2 as u32),
    }
}

/// Map a Linux evdev keycode (the wire-level convention every
/// `xenia-inject` backend receives — see `xenia-viewer`'s
/// `egui_key_to_evdev`) to a Win32 virtual-key code. Covers the same
/// key set `egui_key_to_evdev` produces; unmapped codes return `None`
/// and the event is dropped rather than guessed at.
fn evdev_to_vk(code: u32) -> Option<u16> {
    Some(match code {
        1 => 0x1B,   // KEY_ESC -> VK_ESCAPE
        2 => 0x31,   // KEY_1 -> VK_1
        3 => 0x32,   // KEY_2
        4 => 0x33,   // KEY_3
        5 => 0x34,   // KEY_4
        6 => 0x35,   // KEY_5
        7 => 0x36,   // KEY_6
        8 => 0x37,   // KEY_7
        9 => 0x38,   // KEY_8
        10 => 0x39,  // KEY_9
        11 => 0x30,  // KEY_0 -> VK_0
        12 => 0xBD,  // KEY_MINUS -> VK_OEM_MINUS
        13 => 0xBB,  // KEY_EQUAL -> VK_OEM_PLUS
        14 => 0x08,  // KEY_BACKSPACE -> VK_BACK
        15 => 0x09,  // KEY_TAB
        16 => 0x51,  // KEY_Q -> VK_Q
        17 => 0x57,  // KEY_W
        18 => 0x45,  // KEY_E
        19 => 0x52,  // KEY_R
        20 => 0x54,  // KEY_T
        21 => 0x59,  // KEY_Y
        22 => 0x55,  // KEY_U
        23 => 0x49,  // KEY_I
        24 => 0x4F,  // KEY_O
        25 => 0x50,  // KEY_P
        26 => 0xDB,  // KEY_LEFTBRACE -> VK_OEM_4
        27 => 0xDD,  // KEY_RIGHTBRACE -> VK_OEM_6
        28 => 0x0D,  // KEY_ENTER -> VK_RETURN
        30 => 0x41,  // KEY_A -> VK_A
        31 => 0x53,  // KEY_S
        32 => 0x44,  // KEY_D
        33 => 0x46,  // KEY_F
        34 => 0x47,  // KEY_G
        35 => 0x48,  // KEY_H
        36 => 0x4A,  // KEY_J
        37 => 0x4B,  // KEY_K
        38 => 0x4C,  // KEY_L
        39 => 0xBA,  // KEY_SEMICOLON -> VK_OEM_1
        40 => 0xDE,  // KEY_APOSTROPHE -> VK_OEM_7
        41 => 0xC0,  // KEY_GRAVE -> VK_OEM_3
        43 => 0xDC,  // KEY_BACKSLASH -> VK_OEM_5
        44 => 0x5A,  // KEY_Z -> VK_Z
        45 => 0x58,  // KEY_X
        46 => 0x43,  // KEY_C
        47 => 0x56,  // KEY_V
        48 => 0x42,  // KEY_B
        49 => 0x4E,  // KEY_N
        50 => 0x4D,  // KEY_M
        51 => 0xBC,  // KEY_COMMA -> VK_OEM_COMMA
        52 => 0xBE,  // KEY_DOT -> VK_OEM_PERIOD
        53 => 0xBF,  // KEY_SLASH -> VK_OEM_2
        57 => 0x20,  // KEY_SPACE
        59 => 0x70,  // KEY_F1 -> VK_F1
        60 => 0x71,  // KEY_F2
        61 => 0x72,  // KEY_F3
        62 => 0x73,  // KEY_F4
        63 => 0x74,  // KEY_F5
        64 => 0x75,  // KEY_F6
        65 => 0x76,  // KEY_F7
        66 => 0x77,  // KEY_F8
        67 => 0x78,  // KEY_F9
        68 => 0x79,  // KEY_F10
        87 => 0x7A,  // KEY_F11
        88 => 0x7B,  // KEY_F12
        102 => 0x24, // KEY_HOME
        103 => 0x26, // KEY_UP
        104 => 0x21, // KEY_PAGEUP -> VK_PRIOR
        105 => 0x25, // KEY_LEFT
        106 => 0x27, // KEY_RIGHT
        107 => 0x23, // KEY_END
        108 => 0x28, // KEY_DOWN
        109 => 0x22, // KEY_PAGEDOWN -> VK_NEXT
        110 => 0x2D, // KEY_INSERT
        111 => 0x2E, // KEY_DELETE
        _ => return None,
    })
}

/// `SendInput`-based injector. Stateless beyond the constructor's
/// screen dimensions, which are accepted for API parity with other
/// backends but unused -- `MOUSEEVENTF_ABSOLUTE`'s `[0, 65535]` range
/// already *is* xenia's own `[0.0, 1.0]` convention scaled up, so no
/// pixel-space conversion is needed.
pub struct WindowsInjector {
    #[allow(dead_code)]
    screen_width: u32,
    #[allow(dead_code)]
    screen_height: u32,
}

impl WindowsInjector {
    /// Construct a new injector. Never fails at construction time --
    /// `SendInput` itself reports per-call failures (e.g. the desktop
    /// is locked, or another process's `BlockInput` is active).
    pub fn new(screen_width: u32, screen_height: u32) -> Result<Self, InjectError> {
        Ok(Self {
            screen_width,
            screen_height,
        })
    }

    fn send_one(&self, input: INPUT) -> Result<(), InjectError> {
        let sent = unsafe { SendInput(&[input], std::mem::size_of::<INPUT>() as i32) };
        if sent == 1 {
            Ok(())
        } else {
            // GetLastError isn't queried here: SendInput's own docs
            // note the only well-defined failure causes (UIPI
            // blocking, another thread's BlockInput) don't set a
            // more actionable error than "0 events accepted."
            Err(InjectError::Backend(
                "SendInput accepted 0 of 1 events".into(),
            ))
        }
    }

    fn mouse_input(dx: i32, dy: i32, mouse_data: u32, flags: u32) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: mouse_data,
                    dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS(flags),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }
}

impl InputInjector for WindowsInjector {
    fn inject_pointer(
        &mut self,
        x: f32,
        y: f32,
        button: u8,
        pressed: bool,
    ) -> Result<(), InjectError> {
        let (dx, dy) = (denorm(x), denorm(y));
        self.send_one(Self::mouse_input(
            dx,
            dy,
            0,
            MOUSEEVENTF_MOVE.0 | MOUSEEVENTF_ABSOLUTE.0,
        ))?;
        let (down, up, mouse_data) = button_flags(button);
        let flag = if pressed { down } else { up };
        self.send_one(Self::mouse_input(0, 0, mouse_data, flag))
    }

    fn inject_key(&mut self, code: u32, pressed: bool, _modifiers: u8) -> Result<(), InjectError> {
        let Some(vk) = evdev_to_vk(code) else {
            return Err(InjectError::Unavailable(format!(
                "no Windows virtual-key mapping for evdev code {code}"
            )));
        };
        let flags = if pressed { 0 } else { KEYEVENTF_KEYUP.0 };
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(vk),
                    wScan: 0,
                    dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(flags),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        self.send_one(input)
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
                "windows-sendinput backend supports single-point touch only (index 0); \
                 real multi-touch needs InjectTouchInput, not implemented"
                    .into(),
            ));
        }
        let (dx, dy) = (denorm(x), denorm(y));
        self.send_one(Self::mouse_input(
            dx,
            dy,
            0,
            MOUSEEVENTF_MOVE.0 | MOUSEEVENTF_ABSOLUTE.0,
        ))?;
        // Phase convention matches other backends: 0=down, 1=motion,
        // anything else=up.
        match phase {
            0 => self.send_one(Self::mouse_input(0, 0, 0, MOUSEEVENTF_LEFTDOWN.0)),
            1 => Ok(()),
            _ => self.send_one(Self::mouse_input(0, 0, 0, MOUSEEVENTF_LEFTUP.0)),
        }
    }

    fn backend_name(&self) -> &str {
        "windows-sendinput"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evdev_to_vk_covers_the_full_egui_key_set() {
        // Every code egui_key_to_evdev (apps/xenia-viewer/src/gui.rs)
        // can produce must resolve to a VK code here, or real keyboard
        // input silently drops on Windows.
        let egui_evdev_codes: &[u32] = &[
            30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47,
            17, 45, 21, 44, // A-Z
            11, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 0-9
            57, 28, 1, 14, 15, // space, enter, esc, backspace, tab
            103, 108, 105, 106, // arrows
            102, 107, 104, 109, 110, 111, // home/end/pgup/pgdn/ins/del
            12, 13, 39, 40, 41, 43, 51, 52, 53, 26, 27, // punctuation
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 87, 88, // F1-F12
        ];
        for &code in egui_evdev_codes {
            assert!(
                evdev_to_vk(code).is_some(),
                "evdev code {code} has no VK mapping"
            );
        }
    }

    #[test]
    fn evdev_to_vk_matches_known_win32_constants() {
        assert_eq!(evdev_to_vk(30), Some(0x41)); // A -> VK_A
        assert_eq!(evdev_to_vk(57), Some(0x20)); // space -> VK_SPACE
        assert_eq!(evdev_to_vk(28), Some(0x0D)); // enter -> VK_RETURN
        assert_eq!(evdev_to_vk(1), Some(0x1B)); // esc -> VK_ESCAPE
        assert_eq!(evdev_to_vk(11), Some(0x30)); // '0' -> VK_0
        assert_eq!(evdev_to_vk(2), Some(0x31)); // '1' -> VK_1
    }

    #[test]
    fn evdev_to_vk_rejects_unknown_codes() {
        assert_eq!(evdev_to_vk(0), None);
        assert_eq!(evdev_to_vk(999), None);
    }

    #[test]
    fn evdev_to_vk_has_no_duplicate_targets() {
        // Two different evdev codes silently mapping to the same VK
        // code would mean one physical key on the viewer's side is
        // unreachable on the injected side.
        let mut seen = std::collections::HashMap::new();
        for code in 0u32..200 {
            if let Some(vk) = evdev_to_vk(code) {
                if let Some(prev) = seen.insert(vk, code) {
                    panic!("VK {vk:#x} mapped from both evdev {prev} and {code}");
                }
            }
        }
    }

    #[test]
    fn denorm_clamps_out_of_range() {
        assert_eq!(denorm(-1.0), 0);
        assert_eq!(denorm(2.0), 65_535);
        assert_eq!(denorm(0.5), 32_767);
    }

    #[test]
    fn button_flags_covers_all_button_ids() {
        assert_eq!(
            button_flags(0),
            (MOUSEEVENTF_LEFTDOWN.0, MOUSEEVENTF_LEFTUP.0, 0)
        );
        assert_eq!(
            button_flags(1),
            (MOUSEEVENTF_MIDDLEDOWN.0, MOUSEEVENTF_MIDDLEUP.0, 0)
        );
        assert_eq!(
            button_flags(2),
            (MOUSEEVENTF_RIGHTDOWN.0, MOUSEEVENTF_RIGHTUP.0, 0)
        );
        assert_eq!(
            button_flags(3),
            (MOUSEEVENTF_XDOWN.0, MOUSEEVENTF_XUP.0, XBUTTON1 as u32)
        );
        assert_eq!(
            button_flags(4),
            (MOUSEEVENTF_XDOWN.0, MOUSEEVENTF_XUP.0, XBUTTON2 as u32)
        );
    }
}
