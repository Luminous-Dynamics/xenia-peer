#!/usr/bin/env python3
from pathlib import Path
import json, hashlib

root = Path(__file__).resolve().parents[1]
engine = (root/'crates/xenia-mobile-ffi/src/engine.rs').read_text()
ffi = (root/'crates/xenia-mobile-ffi/src/lib.rs').read_text()
jni = (root/'apps/xenia-viewer-android/src/main/cpp/xenia_jni.c').read_text()
flow = (root/'crates/xenia-peer-core/src/producer_flow.rs').read_text()
gui = (root/'apps/xenia-viewer/src/gui.rs').read_text()
host = (root/'apps/xenia-peer/src/main.rs').read_text()
ci = (root/'.github/workflows/ci.yml').read_text()
vector = json.loads((root/'docs/security/XENIA_APPLICATION_RUNTIME_EVIDENCE_V18_VECTOR.json').read_text())

checks=[]
def req(name, cond):
    if not cond:
        raise SystemExit(f'FAIL {name}')
    checks.append(name)

req('admission_ttl', 'FILE_TRANSFER_RESERVATION_TTL_MS: u64 = 30_000' in engine)
req('copy_lease', 'FILE_TRANSFER_COPY_LEASE_MS: u64 = 60_000' in engine)
req('reservation_states', 'FileTransferReservationState' in engine and 'Reserved' in engine and 'Copying' in engine)
req('reservation_deadline', 'expires_at: Instant' in engine)
req('claim_api', 'pub fn claim_file_transfer_reservation' in engine)
req('claim_idempotent', 'if self.state == FileTransferReservationState::Reserved' in engine)
req('claim_does_not_extend_copying', engine.count('self.expires_at = now + Duration::from_millis(FILE_TRANSFER_COPY_LEASE_MS)') == 1)
req('timer_rereads_deadline', (('reservation.expires_at.saturating_duration_since(Instant::now())' in engine) or ('tokio::time::sleep_until(deadline).await' in engine)) and 'Instant::now() >= reservation.expires_at' in engine)
req('commit_requires_copying', 'reservation.state != FileTransferReservationState::Copying' in engine)
req('ffi_claim_export', 'pub extern "C" fn xenia_claim_send_file_reservation' in ffi)
req('ffi_commit_claims_before_copy', ffi.find('claim_file_transfer_reservation(token, data_len)') < ffi.find('std::slice::from_raw_parts(data, data_len)'))
req('jni_claim_declared', 'xenia_claim_send_file_reservation' in jni)
claim = jni.find('xenia_claim_send_file_reservation(')
copy = jni.find('GetByteArrayElements(env, data, NULL)')
req('jni_claim_before_java_copy', 0 <= claim < copy)
req('jni_copy_failure_cancels', 'xenia_cancel_send_file_reservation' in jni[jni.find('if (bytes == NULL)'):jni.find('if (bytes == NULL)')+300])
req('jni_header_single_name_len_store', jni.count('memcpy(&header[28], &name_len16, 2);') == 1)
req('jni_header_detail_len_offset', jni.count('memcpy(&header[30], &detail_len16, 2);') == 1)
req('pressure_aggregate_helpers', 'pub fn total_events' in flow and 'pub fn has_pressure' in flow)
req('viewer_pressure_visible', 'ingress superseded:' in gui and 'ingress rejected:' in gui)
req('host_pressure_summary', 'host video semantic-pressure summary' in host)
req('ci_contract_runner', 'scripts/run_transport_session_contracts.sh' in ci)
expected_sha = vector.pop('canonical_sha256')
canonical = json.dumps(vector, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
req('vector_sha256', hashlib.sha256(canonical).hexdigest() == expected_sha)
req('vector_copy_lease', vector['file_transfer_reservation']['copy_lease_ms'] == 60000)
req('vector_no_repeat_extension', vector['file_transfer_reservation']['repeated_claim_extends_lease'] is False)
req('vector_header', vector['android_file_event_header_v1']['name_len_offset'] == 28 and vector['android_file_event_header_v1']['detail_len_offset'] == 30)
print(f'application runtime evidence V18 source contract passed: {len(checks)} checks')
