// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A small, native settings window: listen address, admin port, state
//! directory, and a "start at login" checkbox, with Save/Cancel.
//!
//! Deliberately raw Win32 (`CreateWindowExW` + the built-in `STATIC`/
//! `EDIT`/`BUTTON` system control classes) rather than a GUI toolkit crate
//! (`native-windows-gui` was one option on the table -- see this app's
//! module-level plan doc): every API this module calls was verified
//! against the real cached `windows` crate source before use, the same
//! discipline as the rest of this app, which a toolkit dependency I
//! couldn't pre-verify would have broken. "Narrowly featured," per the
//! original scoping -- four fields and two buttons, not a general form
//! framework.
//!
//! Runs on the same GUI thread as the tray icon and main message loop
//! (one window, one loop, `DispatchMessageW` routes by `hwnd` to whichever
//! window's own `WndProc` -- see `main.rs`). Per-window state (the initial
//! config, and where to send the result) is stored via `GWLP_USERDATA`,
//! the standard Win32-in-Rust pattern for this, not a shared global.

use std::sync::mpsc::Sender;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::BST_CHECKED;
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_PUSHBUTTON, CW_USEDEFAULT, CreateWindowExW,
    DefWindowProcW, DestroyWindow, ES_AUTOHSCROLL, GWLP_USERDATA, GetDlgItemTextW,
    GetWindowLongPtrW, HMENU, RegisterClassExW, SW_SHOW, SendMessageW, SetForegroundWindow,
    SetWindowLongPtrW, ShowWindow, WM_COMMAND, WM_CREATE, WM_DESTROY, WNDCLASSEXW, WS_BORDER,
    WS_CHILD, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE,
};
use windows::core::HSTRING;
use xenia_launcher_core::config::DaemonConfig;

const CLASS_NAME: &str = "XeniaLauncherSettingsWindow";

const ID_LISTEN_EDIT: i32 = 101;
const ID_ADMIN_PORT_EDIT: i32 = 102;
const ID_STATE_DIR_EDIT: i32 = 103;
const ID_STARTUP_CHECK: i32 = 104;
const ID_SAVE_BUTTON: i32 = 105;
const ID_CANCEL_BUTTON: i32 = 106;

/// What a Save click reports back to the caller.
#[derive(Debug, Clone)]
pub struct SettingsResult {
    pub config: DaemonConfig,
    pub start_at_login: bool,
}

struct WindowState {
    initial_config: DaemonConfig,
    initial_start_at_login: bool,
    result_tx: Sender<SettingsResult>,
}

/// Open the settings window (or, if already open, bring it to front --
/// see `main.rs`, which tracks the single live instance). Modeless: this
/// returns immediately, the result arrives later via `result_tx` when/if
/// the user clicks Save.
pub fn open(
    initial_config: DaemonConfig,
    initial_start_at_login: bool,
    result_tx: Sender<SettingsResult>,
) -> windows::core::Result<HWND> {
    register_class_once();

    let state = Box::new(WindowState {
        initial_config,
        initial_start_at_login,
        result_tx,
    });
    let state_ptr = Box::into_raw(state);

    let hwnd = unsafe {
        CreateWindowExW(
            Default::default(),
            &HSTRING::from(CLASS_NAME),
            &HSTRING::from("Xenia Settings"),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            420,
            260,
            None,
            None,
            Some(module_handle()?.into()),
            Some(state_ptr as *const _),
        )
    };
    let hwnd = match hwnd {
        Ok(hwnd) => hwnd,
        Err(e) => {
            // CreateWindowExW failed before WM_CREATE ever ran, so the
            // state was never adopted by the window -- reclaim it here or
            // it leaks.
            drop(unsafe { Box::from_raw(state_ptr) });
            return Err(e);
        }
    };

    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
    Ok(hwnd)
}

fn module_handle() -> windows::core::Result<windows::Win32::Foundation::HMODULE> {
    unsafe { GetModuleHandleW(None) }
}

fn register_class_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let hinstance = module_handle().expect("GetModuleHandleW(None) should never fail");
        let class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance.into(),
            lpszClassName: windows::core::PCWSTR(HSTRING::from(CLASS_NAME).as_ptr()),
            ..Default::default()
        };
        // Leak the HSTRING deliberately: RegisterClassExW stores the raw
        // pointer for the lifetime of the process (a single, one-time
        // registration, matching Once above), not just for this call.
        std::mem::forget(HSTRING::from(CLASS_NAME));
        unsafe {
            RegisterClassExW(&class);
        }
    });
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            // The pointer passed to CreateWindowExW's lpparam arrives here
            // via lparam's CREATESTRUCT; adopt it into GWLP_USERDATA so
            // every later message can find it.
            let create_struct =
                lparam.0 as *const windows::Win32::UI::WindowsAndMessaging::CREATESTRUCTW;
            let state_ptr = unsafe { (*create_struct).lpCreateParams } as isize;
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr);
            }
            let state = unsafe { &*(state_ptr as *const WindowState) };
            build_controls(hwnd, state);
            LRESULT(0)
        }
        WM_COMMAND => {
            let control_id = (wparam.0 & 0xffff) as i32;
            if control_id == ID_SAVE_BUTTON {
                on_save(hwnd);
                unsafe {
                    let _ = DestroyWindow(hwnd);
                }
            } else if control_id == ID_CANCEL_BUTTON {
                unsafe {
                    let _ = DestroyWindow(hwnd);
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            let state_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
            if state_ptr != 0 {
                // Reclaim and drop the state this window owned -- it's
                // being destroyed either way (Save and Cancel both fall
                // through to DestroyWindow above).
                drop(unsafe { Box::from_raw(state_ptr as *mut WindowState) });
                unsafe {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn build_controls(hwnd: HWND, state: &WindowState) {
    let hinstance = module_handle().ok();
    let label = |text: &str, y: i32| unsafe {
        let _ = CreateWindowExW(
            Default::default(),
            &HSTRING::from("STATIC"),
            &HSTRING::from(text),
            // No explicit SS_LEFT: it's value 0 (STATIC's own default
            // alignment), not a named constant in this windows crate
            // version -- contributes nothing to the bitwise-OR below.
            WS_CHILD | WS_VISIBLE,
            10,
            y,
            140,
            18,
            Some(hwnd),
            None,
            hinstance.map(Into::into),
            None,
        );
    };
    let edit = |id: i32, text: &str, y: i32| unsafe {
        let _ = CreateWindowExW(
            WS_EX_CLIENTEDGE(),
            &HSTRING::from("EDIT"),
            &HSTRING::from(text),
            WS_CHILD
                | WS_VISIBLE
                | WS_BORDER
                | WS_TABSTOP
                | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(ES_AUTOHSCROLL as u32),
            160,
            y - 2,
            230,
            20,
            Some(hwnd),
            Some(HMENU(id as *mut _)),
            hinstance.map(Into::into),
            None,
        );
    };

    label("Listen address:", 15);
    edit(ID_LISTEN_EDIT, &state.initial_config.listen, 15);

    label("Admin port:", 45);
    edit(
        ID_ADMIN_PORT_EDIT,
        &state.initial_config.admin_port.to_string(),
        45,
    );

    label("State directory:", 75);
    edit(
        ID_STATE_DIR_EDIT,
        &state.initial_config.state_dir.display().to_string(),
        75,
    );

    unsafe {
        let checkbox = CreateWindowExW(
            Default::default(),
            &HSTRING::from("BUTTON"),
            &HSTRING::from("Start automatically at login"),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
            10,
            110,
            300,
            20,
            Some(hwnd),
            Some(HMENU(ID_STARTUP_CHECK as *mut _)),
            hinstance.map(Into::into),
            None,
        );
        if let Ok(checkbox) = checkbox {
            let checked = if state.initial_start_at_login {
                BST_CHECKED.0
            } else {
                0
            };
            SendMessageW(checkbox, BM_SETCHECK, Some(WPARAM(checked as usize)), None);
        }

        let _ = CreateWindowExW(
            Default::default(),
            &HSTRING::from("BUTTON"),
            &HSTRING::from("Save"),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(BS_PUSHBUTTON as u32),
            160,
            150,
            100,
            26,
            Some(hwnd),
            Some(HMENU(ID_SAVE_BUTTON as *mut _)),
            hinstance.map(Into::into),
            None,
        );
        let _ = CreateWindowExW(
            Default::default(),
            &HSTRING::from("BUTTON"),
            &HSTRING::from("Cancel"),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(BS_PUSHBUTTON as u32),
            270,
            150,
            100,
            26,
            Some(hwnd),
            Some(HMENU(ID_CANCEL_BUTTON as *mut _)),
            hinstance.map(Into::into),
            None,
        );
    }
}

#[allow(non_snake_case)]
fn WS_EX_CLIENTEDGE() -> windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE {
    windows::Win32::UI::WindowsAndMessaging::WS_EX_CLIENTEDGE
}

fn on_save(hwnd: HWND) {
    let state_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
    if state_ptr == 0 {
        return;
    }
    let state = unsafe { &*(state_ptr as *const WindowState) };

    let listen = read_edit_text(hwnd, ID_LISTEN_EDIT, &state.initial_config.listen);
    let admin_port_text = read_edit_text(
        hwnd,
        ID_ADMIN_PORT_EDIT,
        &state.initial_config.admin_port.to_string(),
    );
    let admin_port = admin_port_text
        .trim()
        .parse()
        .unwrap_or(state.initial_config.admin_port);
    let state_dir_text = read_edit_text(
        hwnd,
        ID_STATE_DIR_EDIT,
        &state.initial_config.state_dir.display().to_string(),
    );

    let start_at_login = unsafe {
        match windows::Win32::UI::WindowsAndMessaging::GetDlgItem(Some(hwnd), ID_STARTUP_CHECK) {
            Ok(checkbox) => {
                SendMessageW(checkbox, BM_GETCHECK, None, None).0 as u32 == BST_CHECKED.0
            }
            Err(_) => state.initial_start_at_login,
        }
    };

    let config = DaemonConfig {
        listen,
        admin_port,
        state_dir: std::path::PathBuf::from(state_dir_text),
        ..state.initial_config.clone()
    };

    let _ = state.result_tx.send(SettingsResult {
        config,
        start_at_login,
    });
}

fn read_edit_text(hwnd: HWND, control_id: i32, fallback: &str) -> String {
    let Ok(control) =
        (unsafe { windows::Win32::UI::WindowsAndMessaging::GetDlgItem(Some(hwnd), control_id) })
    else {
        return fallback.to_string();
    };
    let mut buf = [0u16; 512];
    let len = unsafe { GetDlgItemTextW(hwnd, control_id, &mut buf) };
    let _ = control; // only used to confirm the control resolved above
    if len == 0 {
        fallback.to_string()
    } else {
        String::from_utf16_lossy(&buf[..len as usize])
    }
}
