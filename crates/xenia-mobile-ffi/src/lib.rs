// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! C-ABI bridge for the Xenia Android viewer app.
//!
//! [`engine`] is the portable, JNI-free viewer core (safe Rust,
//! directly testable/usable on the host). This module is the thin,
//! `unsafe`-necessary boundary that exposes it as `extern "C"`
//! functions an Android JNI shim (or any other C-ABI caller) can call.
//! Handles are opaque `u64`s (a boxed [`engine::ViewerEngine`] pointer
//! cast to an integer) — never dereferenced except by the matching
//! `xenia_*` function, and only for a handle this module itself
//! allocated.
//!
//! Deliberately does **not** opt into `[lints] workspace = true`
//! (see `Cargo.toml`) — the workspace's `unsafe_code = "deny"` lint
//! would otherwise reject the raw-pointer casts a C-ABI boundary
//! inherently needs, matching the precedent already set in
//! `xenia-capture-scrcpy`.

pub mod engine;

use std::ffi::{CStr, CString, c_char};
use std::sync::OnceLock;

use engine::{MobileCodec, SessionState, ViewerEngine};

/// One shared multi-thread tokio runtime for the process lifetime —
/// every connected session's background task runs on it. Matches
/// `xenia-viewer`'s own pattern (one runtime alongside the GUI event
/// loop), just process-lifetime instead of per-window.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to start xenia-mobile-ffi tokio runtime")
    })
}

/// Session-state codes returned by [`xenia_session_state`]. Kept as
/// small integers (not an enum crossing the FFI boundary) for the
/// simplest possible Kotlin-side mapping.
pub const XENIA_STATE_CONNECTING: i32 = 0;
pub const XENIA_STATE_CONNECTED: i32 = 1;
pub const XENIA_STATE_DISCONNECTED: i32 = 2;
pub const XENIA_STATE_ERROR: i32 = 3;
/// Returned by [`xenia_session_state`] for an invalid/unknown handle.
pub const XENIA_STATE_INVALID_HANDLE: i32 = -1;

/// Codec codes accepted by [`xenia_connect`]. Matches [`MobileCodec`].
pub const XENIA_CODEC_PASSTHROUGH: i32 = 0;
pub const XENIA_CODEC_HDC: i32 = 1;

/// Connect to a real `xenia-peer` daemon at `host:port` (e.g.
/// `"192.168.1.20:7900"`) over TCP. Returns an opaque, non-zero
/// session handle on success, or `0` if `host_port` isn't valid UTF-8.
/// The connection itself happens asynchronously in the background —
/// poll [`xenia_session_state`] to observe progress.
///
/// # Safety
/// `host_port` must be a valid, NUL-terminated C string pointer, live
/// for the duration of this call (it is copied, not retained).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_connect(host_port: *const c_char, codec: i32) -> u64 {
    if host_port.is_null() {
        return 0;
    }
    // SAFETY: caller contract above guarantees a valid NUL-terminated
    // string for the duration of this call.
    let host_port = match unsafe { CStr::from_ptr(host_port) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return 0,
    };
    let codec = match codec {
        XENIA_CODEC_HDC => MobileCodec::Hdc,
        _ => MobileCodec::Passthrough,
    };
    let engine = ViewerEngine::connect(runtime().handle(), host_port, codec);
    Box::into_raw(Box::new(engine)) as u64
}

/// Current session state for `handle`. Returns
/// [`XENIA_STATE_INVALID_HANDLE`] for `0`.
///
/// # Safety
/// `handle` must be a value previously returned by [`xenia_connect`]
/// and not yet passed to [`xenia_disconnect`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_session_state(handle: u64) -> i32 {
    if handle == 0 {
        return XENIA_STATE_INVALID_HANDLE;
    }
    // SAFETY: caller contract above.
    let engine = unsafe { &*(handle as *const ViewerEngine) };
    match engine.state() {
        SessionState::Connecting => XENIA_STATE_CONNECTING,
        SessionState::Connected => XENIA_STATE_CONNECTED,
        SessionState::Disconnected => XENIA_STATE_DISCONNECTED,
        SessionState::Error => XENIA_STATE_ERROR,
    }
}

/// Human-readable detail for the most recent error, or `NULL` if none.
/// Caller must free the returned pointer with [`xenia_string_free`].
///
/// # Safety
/// `handle` must be a value previously returned by [`xenia_connect`]
/// and not yet passed to [`xenia_disconnect`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_last_error(handle: u64) -> *mut c_char {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    // SAFETY: caller contract above.
    let engine = unsafe { &*(handle as *const ViewerEngine) };
    match engine.last_error() {
        Some(msg) => CString::new(msg).map(CString::into_raw).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by an `xenia_*` function. Safe to call with
/// `NULL` (no-op).
///
/// # Safety
/// `s` must either be `NULL` or a pointer previously returned by an
/// `xenia_*` function in this crate, not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: caller contract above.
    drop(unsafe { CString::from_raw(s) });
}

/// A decoded frame's metadata + a caller-owned copy of its RGBA
/// pixels. Populated by [`xenia_poll_frame`]; `rgba`/`rgba_len` must
/// be freed with [`xenia_frame_free`] once the caller (e.g. a Kotlin
/// `Bitmap`) has copied the pixels out.
#[repr(C)]
pub struct XeniaFrame {
    pub width: u32,
    pub height: u32,
    pub pts_ms: u64,
    pub rgba: *mut u8,
    pub rgba_len: usize,
}

/// Pop the oldest queued decoded frame for `handle`. Returns a
/// `XeniaFrame` with `rgba == NULL` / `rgba_len == 0` if none is
/// available yet.
///
/// # Safety
/// `handle` must be a value previously returned by [`xenia_connect`]
/// and not yet passed to [`xenia_disconnect`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_poll_frame(handle: u64) -> XeniaFrame {
    let empty = XeniaFrame {
        width: 0,
        height: 0,
        pts_ms: 0,
        rgba: std::ptr::null_mut(),
        rgba_len: 0,
    };
    if handle == 0 {
        return empty;
    }
    // SAFETY: caller contract above.
    let engine = unsafe { &*(handle as *const ViewerEngine) };
    let Some(frame) = engine.poll_frame() else {
        return empty;
    };
    let mut rgba = frame.rgba.into_boxed_slice();
    let rgba_len = rgba.len();
    let rgba_ptr = rgba.as_mut_ptr();
    std::mem::forget(rgba);
    XeniaFrame {
        width: frame.width,
        height: frame.height,
        pts_ms: frame.pts_ms,
        rgba: rgba_ptr,
        rgba_len,
    }
}

/// Free the pixel buffer inside a [`XeniaFrame`] returned by
/// [`xenia_poll_frame`]. Safe to call on an "empty" frame (`rgba ==
/// NULL`) — no-op.
///
/// # Safety
/// `frame.rgba`/`frame.rgba_len` must be exactly as returned by
/// [`xenia_poll_frame`] (same pointer, same length), not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_frame_free(frame: XeniaFrame) {
    if frame.rgba.is_null() {
        return;
    }
    // SAFETY: caller contract above reconstructs exactly the boxed
    // slice `xenia_poll_frame` leaked via `mem::forget`.
    drop(unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(frame.rgba, frame.rgba_len))
    });
}

/// Send a normalized pointer event (`x`/`y` in `[0.0, 1.0]` against the
/// captured-screen frame, `button` 0=left/1=middle/2=right).
///
/// # Safety
/// `handle` must be a value previously returned by [`xenia_connect`]
/// and not yet passed to [`xenia_disconnect`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_send_pointer(handle: u64, x: f32, y: f32, button: u8, pressed: bool) {
    if handle == 0 {
        return;
    }
    // SAFETY: caller contract above.
    let engine = unsafe { &*(handle as *const ViewerEngine) };
    engine.send_pointer(x, y, button, pressed);
}

/// Send a normalized touch event. `phase`: 0=Down, 1=Move, 2=Up,
/// 3=Cancel.
///
/// # Safety
/// `handle` must be a value previously returned by [`xenia_connect`]
/// and not yet passed to [`xenia_disconnect`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_send_touch(
    handle: u64,
    index: u8,
    x: f32,
    y: f32,
    phase: u8,
    pressure: f32,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: caller contract above.
    let engine = unsafe { &*(handle as *const ViewerEngine) };
    engine.send_touch(index, x, y, phase, pressure);
}

/// Send a key event (`code` is an evdev/Linux keycode — see
/// `xenia_inject::InputEvent::Key`'s doc comment for the mapping
/// convention; `modifiers` bit0=Shift, bit1=Ctrl, bit2=Alt, bit3=Meta).
///
/// # Safety
/// `handle` must be a value previously returned by [`xenia_connect`]
/// and not yet passed to [`xenia_disconnect`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_send_key(handle: u64, code: u32, pressed: bool, modifiers: u8) {
    if handle == 0 {
        return;
    }
    // SAFETY: caller contract above.
    let engine = unsafe { &*(handle as *const ViewerEngine) };
    engine.send_key(code, pressed, modifiers);
}

/// Disconnect and free the session. `handle` must not be used again
/// after this call.
///
/// # Safety
/// `handle` must be a value previously returned by [`xenia_connect`],
/// not already passed to this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_disconnect(handle: u64) {
    if handle == 0 {
        return;
    }
    // SAFETY: caller contract above -- reconstructs exactly the Box
    // `xenia_connect` produced via `Box::into_raw`, and the caller
    // contract guarantees this runs at most once per handle.
    drop(unsafe { Box::from_raw(handle as *mut ViewerEngine) });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_handle_is_safe_on_every_entry_point() {
        // handle == 0 must never dereference anything -- exercise every
        // FFI function's null-handle path directly.
        unsafe {
            assert_eq!(xenia_session_state(0), XENIA_STATE_INVALID_HANDLE);
            assert!(xenia_last_error(0).is_null());
            let empty = xenia_poll_frame(0);
            assert!(empty.rgba.is_null());
            assert_eq!(empty.rgba_len, 0);
            xenia_send_pointer(0, 0.5, 0.5, 0, true);
            xenia_send_touch(0, 0, 0.5, 0.5, 0, 1.0);
            xenia_send_key(0, 30, true, 0);
            xenia_disconnect(0); // must not panic/double-free
        }
    }

    #[test]
    fn null_host_port_rejected_without_connecting() {
        unsafe {
            assert_eq!(xenia_connect(std::ptr::null(), XENIA_CODEC_PASSTHROUGH), 0);
        }
    }

    #[test]
    fn connect_disconnect_round_trip_does_not_crash() {
        let host_port = CString::new("127.0.0.1:3").unwrap();
        unsafe {
            let handle = xenia_connect(host_port.as_ptr(), XENIA_CODEC_HDC);
            assert_ne!(handle, 0);
            // Immediately tear down -- the background task may or may
            // not have started connecting yet; this must be safe
            // either way (matches how a Kotlin Activity's onDestroy
            // could race a just-started connection).
            xenia_disconnect(handle);
        }
    }
}
