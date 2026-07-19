// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! C-ABI bridge for the Xenia Android viewer app.
//!
//! [`engine`] is the portable, JNI-free viewer core (safe Rust,
//! directly testable/usable on the host). This module is the thin,
//! `unsafe`-necessary boundary that exposes it as `extern "C"`
//! functions an Android JNI shim (or any other C-ABI caller) can call.
//! Handles are opaque process-local `u64` registry ids. They are never raw
//! addresses, so fabricated, stale, or double-disconnected handles are rejected
//! without dereferencing freed memory. A lookup clones an `Arc`, allowing an
//! in-flight call to finish safely while another thread disconnects the session.
//!
//! Deliberately does **not** opt into `[lints] workspace = true`
//! (see `Cargo.toml`) — the workspace's `unsafe_code = "deny"` lint
//! would otherwise reject the raw C-string and buffer operations a C-ABI
//! boundary inherently needs, matching the precedent already set in
//! `xenia-capture-scrcpy`.

pub mod engine;

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use engine::{FileTransferEvent, MobileCodec, SessionState, ViewerEngine};

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

/// Process-local registry for active viewer sessions. Registry ids are never
/// reused during normal process lifetime, so a stale id cannot alias a later
/// session. The `Arc` clone returned by [`engine_for`] also makes lookup vs.
/// disconnect races memory-safe.
fn engine_registry() -> &'static Mutex<HashMap<u64, Arc<ViewerEngine>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<ViewerEngine>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_engine(engine: ViewerEngine) -> u64 {
    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    let Ok(mut registry) = engine_registry().lock() else {
        return 0;
    };
    loop {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        if handle == 0 || registry.contains_key(&handle) {
            continue;
        }
        registry.insert(handle, Arc::new(engine));
        return handle;
    }
}

fn engine_for(handle: u64) -> Option<Arc<ViewerEngine>> {
    if handle == 0 {
        return None;
    }
    engine_registry().lock().ok()?.get(&handle).cloned()
}

fn unregister_engine(handle: u64) -> Option<Arc<ViewerEngine>> {
    if handle == 0 {
        return None;
    }
    engine_registry().lock().ok()?.remove(&handle)
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
pub const XENIA_CODEC_H264: i32 = 2;

/// Connect to a real `xenia-peer` daemon at `host:port` (e.g.
/// `"192.168.1.20:7900"`) over TCP. Returns an opaque, non-zero
/// session handle on success, or `0` if `host_port` isn't valid UTF-8.
/// The connection itself happens asynchronously in the background —
/// poll [`xenia_session_state`] to observe progress.
///
/// `recv_dir`: `NULL` disables receiving files (every incoming offer
/// is auto-rejected); non-null must be a real, writable filesystem
/// path -- on Android this should be an app-private directory (e.g.
/// `context.getExternalFilesDir(...)`), since received files are
/// written via plain `std::fs::write`, not Storage Access Framework.
/// `max_file_bytes` caps both directions and is also a hard in-memory
/// buffering cap (the whole file lives in memory on both ends).
///
/// # Safety
/// `host_port` must be a valid, NUL-terminated C string pointer, live
/// for the duration of this call (it is copied, not retained).
/// `recv_dir`, if non-null, must likewise be a valid NUL-terminated C
/// string pointer, live for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_connect(
    host_port: *const c_char,
    codec: i32,
    recv_dir: *const c_char,
    max_file_bytes: u64,
) -> u64 {
    if host_port.is_null() {
        return 0;
    }
    // SAFETY: caller contract above guarantees a valid NUL-terminated
    // string for the duration of this call.
    let host_port = match unsafe { CStr::from_ptr(host_port) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return 0,
    };
    let recv_dir = if recv_dir.is_null() {
        None
    } else {
        // SAFETY: caller contract above.
        match unsafe { CStr::from_ptr(recv_dir) }.to_str() {
            Ok(s) => Some(std::path::PathBuf::from(s)),
            Err(_) => return 0,
        }
    };
    let codec = match codec {
        XENIA_CODEC_HDC => MobileCodec::Hdc,
        XENIA_CODEC_H264 => MobileCodec::H264,
        _ => MobileCodec::Passthrough,
    };
    let engine = ViewerEngine::connect(
        runtime().handle(),
        host_port,
        codec,
        recv_dir,
        max_file_bytes,
    );
    register_engine(engine)
}

/// Current session state for `handle`. Returns
/// [`XENIA_STATE_INVALID_HANDLE`] for `0`.
///
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_session_state(handle: u64) -> i32 {
    let Some(engine) = engine_for(handle) else {
        return XENIA_STATE_INVALID_HANDLE;
    };
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
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_last_error(handle: u64) -> *mut c_char {
    let Some(engine) = engine_for(handle) else {
        return std::ptr::null_mut();
    };
    match engine.last_error() {
        Some(msg) => CString::new(msg)
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
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
    /// `true`: `rgba` holds raw Annex-B H.264 NAL bytes for the caller
    /// to feed into its own hardware decoder (e.g. Android's
    /// `MediaCodec`). `false`: `rgba` holds decoded RGBA8 pixels
    /// (`width * height * 4` bytes). See `engine::MobileFrame`'s doc.
    pub is_encoded: bool,
    pub rgba: *mut u8,
    pub rgba_len: usize,
}

/// Pop the oldest queued decoded frame for `handle`. Returns a
/// `XeniaFrame` with `rgba == NULL` / `rgba_len == 0` if none is
/// available yet.
///
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_poll_frame(handle: u64) -> XeniaFrame {
    let empty = XeniaFrame {
        width: 0,
        height: 0,
        pts_ms: 0,
        is_encoded: false,
        rgba: std::ptr::null_mut(),
        rgba_len: 0,
    };
    let Some(engine) = engine_for(handle) else {
        return empty;
    };
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
        is_encoded: frame.is_encoded,
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
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            frame.rgba,
            frame.rgba_len,
        ))
    });
}

/// Send a normalized pointer event (`x`/`y` in `[0.0, 1.0]` against the
/// captured-screen frame, `button` 0=left/1=middle/2=right).
///
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_send_pointer(
    handle: u64,
    x: f32,
    y: f32,
    button: u8,
    pressed: bool,
) {
    let Some(engine) = engine_for(handle) else {
        return;
    };
    engine.send_pointer(x, y, button, pressed);
}

/// Send a normalized touch event. `phase`: 0=Down, 1=Move, 2=Up,
/// 3=Cancel.
///
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_send_touch(
    handle: u64,
    index: u8,
    x: f32,
    y: f32,
    phase: u8,
    pressure: f32,
) {
    let Some(engine) = engine_for(handle) else {
        return;
    };
    engine.send_touch(index, x, y, phase, pressure);
}

/// Send a key event (`code` is an evdev/Linux keycode — see
/// `xenia_inject::InputEvent::Key`'s doc comment for the mapping
/// convention; `modifiers` bit0=Shift, bit1=Ctrl, bit2=Alt, bit3=Meta).
///
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_send_key(handle: u64, code: u32, pressed: bool, modifiers: u8) {
    let Some(engine) = engine_for(handle) else {
        return;
    };
    engine.send_key(code, pressed, modifiers);
}

/// Take the latest host-to-viewer clipboard text update, if any.
/// Returns `NULL` if nothing new has arrived *or* if the host cleared
/// its clipboard -- this FFI boundary deliberately doesn't distinguish
/// those two cases (unlike the safe `engine::ViewerEngine::poll_clipboard`,
/// which returns `Option<Option<String>>` to a Rust caller that wants
/// the full fidelity); propagating a *clear* to the Android system
/// clipboard is a real but marginal feature not worth the extra FFI
/// surface for v1. Caller must free with [`xenia_string_free`].
///
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_poll_clipboard(handle: u64) -> *mut c_char {
    let Some(engine) = engine_for(handle) else {
        return std::ptr::null_mut();
    };
    match engine.poll_clipboard() {
        Some(Some(text)) => CString::new(text)
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

/// Send a viewer-to-host clipboard update. `text == NULL` means
/// "cleared." Requires the daemon to be running with `--clipboard
/// bidirectional`; a `host-to-viewer`-only daemon just logs and drops
/// it.
///
/// # Safety
/// `text`, if non-null, must be a valid NUL-terminated C string pointer,
/// live for the duration of this call (it is copied, not retained).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_send_clipboard(handle: u64, text: *const c_char) {
    let Some(engine) = engine_for(handle) else {
        return;
    };
    if text.is_null() {
        engine.send_clipboard(None);
        return;
    }
    // SAFETY: caller contract above guarantees a valid NUL-terminated
    // string for the duration of this call.
    if let Ok(s) = unsafe { CStr::from_ptr(text) }.to_str() {
        engine.send_clipboard(Some(s.to_owned()));
    }
}

/// Offer `data` (`data_len` bytes) to the host under `name`. The
/// caller must have already read the whole file into memory (e.g. via
/// Android's `ContentResolver` against a Storage Access Framework
/// `Uri`, since arbitrary user-picked files aren't necessarily
/// reachable by a plain filesystem path). Only one outgoing transfer
/// is in flight at a time -- calling this while one is already active
/// surfaces a failed [`XeniaFileTransferEvent`] (kind
/// [`XENIA_FT_EVENT_DONE`], `ok == false`) rather than queuing a
/// second one.
///
/// # Safety
/// `name` must be a valid NUL-terminated C string pointer, live for the
/// duration of this call. `data` must be a valid pointer to `data_len` readable bytes,
/// live for the duration of this call (it is copied, not retained).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_send_file(
    handle: u64,
    name: *const c_char,
    data: *const u8,
    data_len: usize,
) {
    if name.is_null() || (data.is_null() && data_len > 0) {
        return;
    }
    let Some(engine) = engine_for(handle) else {
        return;
    };
    // SAFETY: caller contract above guarantees a valid NUL-terminated
    // string for the duration of this call.
    let Ok(name) = (unsafe { CStr::from_ptr(name) }).to_str() else {
        return;
    };
    // SAFETY: caller contract above guarantees `data_len` readable
    // bytes for the duration of this call; this copies them out.
    let bytes = if data_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
    };
    engine.send_file(name.to_owned(), bytes);
}

/// Event kinds for [`XeniaFileTransferEvent::kind`].
pub const XENIA_FT_EVENT_NONE: i32 = 0;
pub const XENIA_FT_EVENT_INCOMING_OFFER: i32 = 1;
pub const XENIA_FT_EVENT_PROGRESS: i32 = 2;
pub const XENIA_FT_EVENT_DONE: i32 = 3;

/// One file-transfer event, packed for the C ABI. `name`/`detail` are
/// `NULL` when not meaningful for `kind`; both, if non-null, must be
/// freed via [`xenia_file_transfer_event_free`]. `accepted` is only
/// meaningful for [`XENIA_FT_EVENT_INCOMING_OFFER`]; `ok` only for
/// [`XENIA_FT_EVENT_DONE`].
#[repr(C)]
pub struct XeniaFileTransferEvent {
    pub kind: i32,
    pub transfer_id: u64,
    pub outgoing: bool,
    pub accepted: bool,
    pub ok: bool,
    pub done_bytes: u64,
    pub total_bytes: u64,
    pub name: *mut c_char,
    pub detail: *mut c_char,
}

fn opt_cstring(s: String) -> *mut c_char {
    CString::new(s)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Pop the oldest queued file-transfer event for `handle`. Returns a
/// event with `kind == XENIA_FT_EVENT_NONE` if none is available yet.
///
/// Invalid, fabricated, or stale handles are rejected without accessing
/// session memory.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_poll_file_transfer_event(handle: u64) -> XeniaFileTransferEvent {
    let empty = XeniaFileTransferEvent {
        kind: XENIA_FT_EVENT_NONE,
        transfer_id: 0,
        outgoing: false,
        accepted: false,
        ok: false,
        done_bytes: 0,
        total_bytes: 0,
        name: std::ptr::null_mut(),
        detail: std::ptr::null_mut(),
    };
    let Some(engine) = engine_for(handle) else {
        return empty;
    };
    match engine.poll_file_transfer_event() {
        None => empty,
        Some(FileTransferEvent::IncomingOffer {
            transfer_id,
            name,
            total_bytes,
            accepted,
            reason,
        }) => XeniaFileTransferEvent {
            kind: XENIA_FT_EVENT_INCOMING_OFFER,
            transfer_id,
            outgoing: false,
            accepted,
            ok: false,
            done_bytes: 0,
            total_bytes,
            name: opt_cstring(name),
            detail: opt_cstring(reason),
        },
        Some(FileTransferEvent::Progress {
            transfer_id,
            name,
            done_bytes,
            total_bytes,
            outgoing,
        }) => XeniaFileTransferEvent {
            kind: XENIA_FT_EVENT_PROGRESS,
            transfer_id,
            outgoing,
            accepted: false,
            ok: false,
            done_bytes,
            total_bytes,
            name: opt_cstring(name),
            detail: std::ptr::null_mut(),
        },
        Some(FileTransferEvent::Done {
            transfer_id,
            name,
            outgoing,
            ok,
            detail,
        }) => XeniaFileTransferEvent {
            kind: XENIA_FT_EVENT_DONE,
            transfer_id,
            outgoing,
            accepted: false,
            ok,
            done_bytes: 0,
            total_bytes: 0,
            name: opt_cstring(name),
            detail: opt_cstring(detail),
        },
    }
}

/// Free the strings inside a [`XeniaFileTransferEvent`] returned by
/// [`xenia_poll_file_transfer_event`]. Safe to call on a `kind ==
/// XENIA_FT_EVENT_NONE` event (both fields are already `NULL` --
/// no-op).
///
/// # Safety
/// `event.name`/`event.detail` must be exactly as returned by
/// [`xenia_poll_file_transfer_event`], not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xenia_file_transfer_event_free(event: XeniaFileTransferEvent) {
    // SAFETY: caller contract above -- `xenia_string_free` itself
    // handles NULL as a no-op.
    unsafe {
        xenia_string_free(event.name);
        xenia_string_free(event.detail);
    }
}

/// Disconnect the session and remove its registry id. Unknown, stale, and
/// already-disconnected ids are safe no-ops.
#[unsafe(no_mangle)]
pub extern "C" fn xenia_disconnect(handle: u64) {
    // Removing an unknown, stale, or already-removed id is a safe no-op.
    // Any in-flight call holds its own `Arc` and may finish before the engine
    // is dropped; the id is immediately unavailable to new lookups.
    drop(unregister_engine(handle));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_handle_is_safe_on_every_entry_point() {
        // Both the reserved zero id and a fabricated non-zero id must be
        // rejected without touching session memory.
        unsafe {
            assert_eq!(xenia_session_state(0), XENIA_STATE_INVALID_HANDLE);
            assert_eq!(xenia_session_state(u64::MAX), XENIA_STATE_INVALID_HANDLE);
            assert!(xenia_last_error(u64::MAX).is_null());
            assert!(xenia_last_error(0).is_null());
            let empty = xenia_poll_frame(0);
            assert!(empty.rgba.is_null());
            assert_eq!(empty.rgba_len, 0);
            xenia_send_pointer(0, 0.5, 0.5, 0, true);
            xenia_send_touch(0, 0, 0.5, 0.5, 0, 1.0);
            xenia_send_key(0, 30, true, 0);
            let name = CString::new("test.txt").unwrap();
            xenia_send_file(0, name.as_ptr(), std::ptr::null(), 0);
            let empty_ft = xenia_poll_file_transfer_event(0);
            assert_eq!(empty_ft.kind, XENIA_FT_EVENT_NONE);
            assert!(empty_ft.name.is_null());
            assert!(empty_ft.detail.is_null());
            xenia_disconnect(0); // must not panic/double-free
        }
    }

    #[test]
    fn null_host_port_rejected_without_connecting() {
        unsafe {
            assert_eq!(
                xenia_connect(
                    std::ptr::null(),
                    XENIA_CODEC_PASSTHROUGH,
                    std::ptr::null(),
                    0
                ),
                0
            );
        }
    }

    #[test]
    fn connect_disconnect_round_trip_does_not_crash() {
        let host_port = CString::new("127.0.0.1:3").unwrap();
        unsafe {
            let handle = xenia_connect(
                host_port.as_ptr(),
                XENIA_CODEC_HDC,
                std::ptr::null(),
                100 * 1024 * 1024,
            );
            assert_ne!(handle, 0);
            // Immediately tear down -- the background task may or may
            // not have started connecting yet; this must be safe
            // either way (matches how a Kotlin Activity's onDestroy
            // could race a just-started connection).
            xenia_disconnect(handle);
            assert_eq!(xenia_session_state(handle), XENIA_STATE_INVALID_HANDLE);
            // Double-disconnect and post-disconnect actions are intentionally
            // harmless rather than a use-after-free contract violation.
            xenia_disconnect(handle);
            xenia_send_pointer(handle, 0.5, 0.5, 0, true);
        }
    }

    #[test]
    fn connect_with_recv_dir_round_trip_does_not_crash() {
        let host_port = CString::new("127.0.0.1:5").unwrap();
        let recv_dir = CString::new("/tmp").unwrap();
        unsafe {
            let handle = xenia_connect(
                host_port.as_ptr(),
                XENIA_CODEC_PASSTHROUGH,
                recv_dir.as_ptr(),
                100 * 1024 * 1024,
            );
            assert_ne!(handle, 0);
            xenia_disconnect(handle);
            assert_eq!(xenia_session_state(handle), XENIA_STATE_INVALID_HANDLE);
            xenia_disconnect(handle);
        }
    }
}
