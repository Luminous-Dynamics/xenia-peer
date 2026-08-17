#!/usr/bin/env python3
"""Static contract for V21 bounded receive staging and corrected activation semantics."""
from pathlib import Path
import hashlib
import json
import re

root = Path(__file__).resolve().parents[1]
core = (root / "crates/xenia-peer-core/src/file_transfer.rs").read_text()
lib = (root / "crates/xenia-peer-core/src/lib.rs").read_text()
peer = (root / "apps/xenia-peer/src/file_transfer.rs").read_text()
peer_main = (root / "apps/xenia-peer/src/main.rs").read_text()
viewer = (root / "apps/xenia-viewer/src/main.rs").read_text()
mobile = (root / "crates/xenia-mobile-ffi/src/engine.rs").read_text()
activity = (root / "apps/xenia-viewer-android/src/main/kotlin/io/luminousdynamics/xenia/XeniaViewerActivity.kt").read_text()
vector = json.loads((root / "docs/security/XENIA_APPLICATION_RECEIVE_STAGING_V21_VECTOR.json").read_text())
checks = []

def req(name, cond):
    if not cond:
        raise SystemExit(f"FAIL {name}")
    checks.append(name)

def incoming_struct(source):
    match = re.search(r"struct IncomingTransfer\s*\{(?P<body>.*?)\n\}", source, re.S)
    if not match:
        raise SystemExit("FAIL incoming_transfer_struct")
    return match.group("body")

req("shared_stager", "pub struct IncomingFileStager" in core)
req("shared_export", "IncomingFileStager" in lib and "cleanup_orphaned_receive_staging" in lib)
req("sequential_offsets", "if offset != self.received" in core)
req("incremental_hash", "self.hasher.update(bytes)" in core)
req("receive_overrun", "if attempted_end > self.expected_size" in core)
req("exact_finish_size", "if self.received != self.expected_size" in core)
req("hash_finish", "self.hasher.finalize().as_bytes() != &self.expected_hash" in core)
req("sync_before_publish", "file.sync_all()?" in core)
req("no_clobber_publish", "std::fs::hard_link(&self.staging_path, &self.final_path)?" in core)
req("drop_cleanup", "impl Drop for IncomingFileStager" in core and "remove_file(&self.staging_path)" in core)
req("orphan_matcher", "owned_receive_staging_pid" in core and "token.len() != 32" in core)
req("orphan_preserves_live_pid", "if owner_pid == current_pid" in core)
req("orphan_cleanup_test", "orphan_cleanup_only_removes_owned_receive_staging_names" in core)

for name, source in [("peer", peer), ("viewer", viewer), ("mobile", mobile)]:
    body = incoming_struct(source)
    req(f"{name}_incoming_stager", "stager: IncomingFileStager" in body)
    req(f"{name}_no_incoming_vec", "Vec<u8>" not in body and "buffer:" not in body)
    req(f"{name}_append", ".stager.append(offset, &data)" in source)
    req(f"{name}_finish", ".stager.finish()" in source)

req("peer_cap_8", "MAX_CONCURRENT_INCOMING_TRANSFERS: usize = 8" in peer)
req("viewer_cap_8", "MAX_CONCURRENT_INCOMING_TRANSFERS: usize = 8" in viewer)
req("mobile_cap_4", "MAX_CONCURRENT_INCOMING_TRANSFERS: usize = 4" in mobile)
req("peer_startup_cleanup", "cleanup_orphaned_receive_staging(recv_dir)" in peer_main)
req("viewer_startup_cleanup", "cleanup_orphaned_receive_staging(recv_dir)" in viewer)
req("mobile_startup_cleanup", "cleanup_orphaned_receive_staging(recv_dir)" in mobile)
req("mobile_receive_internal", 'filesDir.resolve("received")' in activity)
req("mobile_outbound_nobackup", 'noBackupFilesDir.resolve("outbound-staging")' in activity)
req("activation_helper", "fn can_activate_file_transfer_command(authenticated: bool, outgoing_active: bool)" in mobile)
req("activation_requires_auth_idle", "authenticated && !outgoing_active" in mobile)
req(
    "activation_select_guard",
    re.search(
        r"ft_cmd_rx\.recv\(\),\s*if can_activate_file_transfer_command\(\s*authenticated_surface\.is_some\(\),\s*outgoing\.is_some\(\)",
        mobile,
        re.S,
    ) is not None,
)
req("activation_unit_test", "file_command_activation_requires_authentication_and_an_idle_sender" in mobile)

expected = vector.pop("canonical_sha256")
canonical = json.dumps(vector, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
req("vector_sha", hashlib.sha256(canonical).hexdigest() == expected)
req("vector_wire_unchanged", vector["wire_protocol_changed"] is False)
req("vector_no_free_space_claim", vector["receive_free_space_reservation"] is False)
req("vector_caps", vector["receive_paths"]["xenia-peer"]["max_concurrent"] == 8 and vector["receive_paths"]["xenia-viewer"]["max_concurrent"] == 8 and vector["receive_paths"]["xenia-mobile-ffi"]["max_concurrent"] == 4)
req("vector_chunk", vector["wire_chunk_bytes"] == 64 * 1024)

print(f"application receive staging V21 source contract passed: {len(checks)} checks")
