#!/usr/bin/env python3
from pathlib import Path
import json, hashlib, re

root = Path(__file__).resolve().parents[1]
engine = (root/'crates/xenia-mobile-ffi/src/engine.rs').read_text()
ffi = (root/'crates/xenia-mobile-ffi/src/lib.rs').read_text()
cargo = (root/'crates/xenia-mobile-ffi/Cargo.toml').read_text()
jni = (root/'apps/xenia-viewer-android/src/main/cpp/xenia_jni.c').read_text()
bindings = (root/'apps/xenia-viewer-android/src/main/kotlin/io/luminousdynamics/xenia/NativeBindings.kt').read_text()
session = (root/'apps/xenia-viewer-android/src/main/kotlin/io/luminousdynamics/xenia/XeniaSession.kt').read_text()
activity = (root/'apps/xenia-viewer-android/src/main/kotlin/io/luminousdynamics/xenia/XeniaViewerActivity.kt').read_text()
vector = json.loads((root/'docs/security/XENIA_APPLICATION_RUNTIME_ASSURANCE_V19_VECTOR.json').read_text())

checks=[]
def req(name, cond):
    if not cond:
        raise SystemExit(f'FAIL {name}')
    checks.append(name)

req('tokio_clock', 'use tokio::time::Instant;' in engine)
req('test_util', 'features = ["test-util"]' in cargo)
req('sleep_until_current_deadline', 'tokio::time::sleep_until(deadline).await' in engine)
req('expiry_rechecks_live_deadline', 'Instant::now() >= reservation.expires_at' in engine)
req('paused_near_expiry_test', '#[tokio::test(start_paused = true)]' in engine and 'reservation_expiry_tracks_claimed_copy_lease_and_restores_capacity' in engine)
req('paused_repeat_claim_test', 'repeated_claim_does_not_extend_copy_lease_under_paused_time' in engine)
req('snapshot_engine', 'pub struct FileTransferAdmissionSnapshotV1' in engine and 'pub fn file_transfer_admission_snapshot' in engine)
req('snapshot_ffi', 'pub struct XeniaFileTransferAdmissionSnapshot' in ffi and 'xenia_file_transfer_admission_snapshot' in ffi)
req('snapshot_jni', 'NativeBindings_fileTransferAdmissionSnapshot' in jni)
req('snapshot_kotlin', 'data class FileTransferAdmissionSnapshot' in session and 'fun fileTransferAdmissionSnapshot()' in session)

codes = {
    'OK':0, 'INVALID_ARGUMENT':1, 'INVALID_HANDLE':2, 'QUEUE_FULL':3,
    'SESSION_CLOSED':4, 'TOO_LARGE':5, 'INVALID_RESERVATION':6,
    'RESERVATION_SIZE_MISMATCH':7,
}
for name, value in codes.items():
    req(f'rust_status_{name.lower()}', f'XENIA_SEND_FILE_{name}: i32 = {value};' in ffi)
    req(f'c_status_{name.lower()}', re.search(rf'XENIA_SEND_FILE_{name}\s*=\s*{value}\b', jni) is not None)
    req(f'kotlin_status_{name.lower()}', f'SEND_FILE_{name}: Int = {value}' in bindings)

req('jni_exact_status_api', 'JNIEXPORT jint JNICALL' in jni and 'NativeBindings_trySendFile' in jni)
req('jni_legacy_boolean', 'NativeBindings_sendFile' in jni and 'JNIEXPORT jboolean JNICALL' in jni)
req('kotlin_exact_status_api', 'external fun trySendFile' in bindings and 'enum class FileSendResult' in session)
for variant in ['ACCEPTED','INVALID_ARGUMENT','INVALID_HANDLE','QUEUE_FULL','SESSION_CLOSED','TOO_LARGE','INVALID_RESERVATION','RESERVATION_SIZE_MISMATCH','UNKNOWN']:
    req(f'kotlin_result_{variant.lower()}', variant in session)
req('ui_distinguishes_queue_full', 'File transfer queue is busy' in activity)
req('ui_distinguishes_too_large', '100 MiB mobile transfer limit' in activity)
req('ui_distinguishes_session_closed', 'Xenia session is disconnected' in activity)

expected_sha = vector.pop('canonical_sha256')
canonical = json.dumps(vector, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
req('vector_sha256', hashlib.sha256(canonical).hexdigest() == expected_sha)
req('vector_clock', vector['reservation_clock']['clock'] == 'tokio::time::Instant')
req('vector_codes', vector['file_send_status']['codes'] == {
    'ok':0,'invalid_argument':1,'invalid_handle':2,'queue_full':3,
    'session_closed':4,'too_large':5,'invalid_reservation':6,'reservation_size_mismatch':7
})
req('vector_local_diagnostics', vector['admission_snapshot']['authenticated_protocol_state'] is False)
print(f'application runtime assurance V19 source contract passed: {len(checks)} checks')
