#!/usr/bin/env python3
"""Source-shape contract for Xenia application teardown / producer semantics V15.

This is intentionally a no-Rust-toolchain gate. It does not replace cargo test;
it catches accidental removal of the specific fail-closed wiring V15 introduces.
"""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]

def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

checks: list[tuple[str, bool]] = []

def require(name: str, cond: bool) -> None:
    checks.append((name, cond))

inject = text("crates/xenia-inject/src/lib.rs")
xdg = text("crates/xenia-inject/src/xdg_portal.rs")
win = text("crates/xenia-inject/src/windows.rs")
mac = text("crates/xenia-inject/src/macos.rs")
daemon = text("apps/xenia-peer/src/main.rs")
flow = text("crates/xenia-peer-core/src/producer_flow.rs")
mobile = text("crates/xenia-mobile-ffi/src/engine.rs")
ffi = text("crates/xenia-mobile-ffi/src/lib.rs")
jni = text("apps/xenia-viewer-android/src/main/cpp/xenia_jni.c")
kotlin = text("apps/xenia-viewer-android/src/main/kotlin/io/luminousdynamics/xenia/NativeBindings.kt")

require("injector_split_move", "fn inject_pointer_move(&mut self, x: f32, y: f32)" in inject)
require("injector_split_button", "fn inject_pointer_button(" in inject)
require(
    "pointer_move_dispatch_is_pure",
    "InputEvent::PointerMove { x, y } => self.inject_pointer_move(*x, *y)?" in inject,
)
require("session_state_wrapper", "pub struct SessionInputInjector" in inject)
require("session_release_api", "pub fn release_all(&mut self) -> InputReleaseReport" in inject)
require(
    "drag_release_tracks_latest_position",
    "for position in self.pressed_buttons.values_mut()" in inject
    and "*position = (x, y);" in inject,
)
require("drop_release_fallback", "impl Drop for SessionInputInjector" in inject and "let _ = self.release_all();" in inject)
require("uinput_cancel_releases", "matches!(phase, 0 | 1)" in inject)
require("xdg_split_commands", "Command::PointerMove" in xdg and "Command::PointerButton" in xdg)
require("windows_split_backend", "fn inject_pointer_move" in win and "fn inject_pointer_button" in win)
require("macos_split_backend", "fn inject_pointer_move" in mac and "fn inject_pointer_button" in mac)
require("daemon_wraps_injector", "Option<SessionInputInjector>" in daemon)
require("daemon_explicit_release", "released session-owned injected input state during teardown" in daemon)
require("clipboard_policy", "MOBILE_CLIPBOARD_OUTBOUND_V1" in flow and 'overflow: ProducerOverflowPolicy::CoalesceLatest' in flow)
require("file_command_policy", "MOBILE_FILE_TRANSFER_COMMAND_V1" in flow and 'overflow: ProducerOverflowPolicy::Reject' in flow)
require("clipboard_watch_slot", "watch::Sender<Option<ClipboardContent>>" in mobile and "watch::channel(None)" in mobile)
require("clipboard_send_replace", "clipboard_tx.send_replace(Some(content))" in mobile)
require("file_enqueue_result", "pub enum FileTransferEnqueueError" in mobile and "TrySendError::Full" in mobile)
require("ffi_explicit_file_result", "pub unsafe extern \"C\" fn xenia_try_send_file" in ffi and "XENIA_SEND_FILE_QUEUE_FULL" in ffi)
for name, value in [
    ("XENIA_SEND_FILE_OK", 0),
    ("XENIA_SEND_FILE_INVALID_ARGUMENT", 1),
    ("XENIA_SEND_FILE_INVALID_HANDLE", 2),
    ("XENIA_SEND_FILE_QUEUE_FULL", 3),
    ("XENIA_SEND_FILE_SESSION_CLOSED", 4),
]:
    require(f"ffi_status_{name.lower()}", f"pub const {name}: i32 = {value};" in ffi)
require("jni_uses_explicit_file_result", "xenia_try_send_file" in jni and "JNIEXPORT jboolean JNICALL" in jni)
require("kotlin_observes_file_enqueue", "external fun sendFile(handle: Long, name: String, data: ByteArray): Boolean" in kotlin)


vector_path = ROOT / "docs/security/XENIA_APPLICATION_SESSION_TEARDOWN_V15_VECTOR.json"
vector = json.loads(vector_path.read_text(encoding="utf-8"))
expected_hash = vector.pop("canonical_sha256")
canonical = json.dumps(vector, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
require("vector_canonical_sha256", hashlib.sha256(canonical).hexdigest() == expected_hash)
require("vector_input_schema_v2", vector.get("input_event_schema_version") == 2)
require(
    "vector_file_statuses",
    vector.get("file_enqueue_status")
    == {
        "ok": 0,
        "invalid_argument": 1,
        "invalid_handle": 2,
        "queue_full": 3,
        "session_closed": 4,
    },
)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'} {name}")
if failed:
    print("application teardown V15 source contract FAILED: " + ", ".join(failed), file=sys.stderr)
    raise SystemExit(1)
print(f"application teardown V15 source contract passed: checks={len(checks)}")
