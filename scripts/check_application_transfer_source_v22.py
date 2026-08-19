#!/usr/bin/env python3
"""Static contract for V22 shared outbound sources and receive reservations."""

from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]

transfer_source = (root / "crates/xenia-peer-core/src/transfer_source.rs").read_text()
reservation = (root / "crates/xenia-peer-core/src/receive_reservation.rs").read_text()
lib = (root / "crates/xenia-peer-core/src/lib.rs").read_text()

peer = (
    (root / "apps/xenia-peer/src/file_transfer.rs").read_text()
    + "\n"
    + (root / "apps/xenia-peer/src/main.rs").read_text()
)
viewer = (root / "apps/xenia-viewer/src/main.rs").read_text()
mobile = (root / "crates/xenia-mobile-ffi/src/engine.rs").read_text()

checks = []


def req(name, condition):
    if not condition:
        raise SystemExit(f"FAIL {name}")
    checks.append(name)


req("shared_transfer_source", "pub struct TransferSource" in transfer_source)
req("shared_transfer_chunk", "pub struct TransferChunk" in transfer_source)
req("shared_source_export", "TransferSource" in lib and "TransferChunk" in lib)
req("memory_source", "pub fn from_memory(data: Vec<u8>)" in transfer_source)
req("bounded_file_source", "pub async fn open_file_limited" in transfer_source)
req("prehashed_file_source", "pub async fn open_prehashed_file" in transfer_source)
req("bounded_next_chunk", "pub async fn next_chunk" in transfer_source)
req(
    "second_streaming_hash",
    "self.send_hasher.finalize().as_bytes() != &self.blake3_hash"
    in transfer_source,
)
req(
    "owned_staged_cleanup",
    "struct CleanupPath" in transfer_source
    and "cleanup_on_drop.then_some(path.clone())" in transfer_source
    and "std::fs::remove_file(&path)" in transfer_source,
)

req("shared_receive_pool", "pub struct ReceiveReservationPool" in reservation)
req("shared_receive_lease", "pub struct ReceiveReservation" in reservation)
req("receive_raii_release", "impl Drop for ReceiveReservation" in reservation)
req(
    "receive_exports",
    "ReceiveReservationPool" in lib and "ReceiveReservation" in lib,
)

for name, source in [
    ("peer", peer),
    ("viewer", viewer),
    ("mobile", mobile),
]:
    req(f"{name}_uses_transfer_source", "TransferSource" in source)
    req(
        f"{name}_streams_protocol_chunks",
        re.search(
            r"\.next_chunk\(\s*(?:xenia_peer_core::)?FILE_TRANSFER_CHUNK_SIZE\s*\)",
            source,
            re.S,
        )
        is not None,
    )
    req(f"{name}_uses_receive_pool", "ReceiveReservationPool" in source)
    req(f"{name}_reserves_before_accept", "try_reserve(size)" in source)

req("mobile_no_private_source", "OutgoingTransferSource" not in mobile)
req("mobile_memory_compat", "TransferSource::from_memory(data)" in mobile)
req(
    "mobile_prehashed_saf",
    re.search(
        r"TransferSource::open_prehashed_file\(\s*"
        r"path,\s*size,\s*blake3_hash,\s*true\s*,?\s*\)",
        mobile,
        re.S,
    )
    is not None,
)
req(
    "mobile_receive_capacity",
    re.search(
        r"ReceiveReservationPool::new\(\s*"
        r"max_file_bytes\.saturating_mul\("
        r"MAX_CONCURRENT_INCOMING_TRANSFERS as u64\)",
        mobile,
        re.S,
    )
    is not None,
)
req(
    "mobile_incoming_owns_reservation",
    "_reservation: ReceiveReservation" in mobile
    and "_reservation: reservation" in mobile,
)

reserve_pos = mobile.find("receive_reservations.try_reserve(size)")
stager_pos = mobile.find(
    "IncomingFileStager::create(&dest, size, blake3_hash)",
    max(reserve_pos, 0),
)
req(
    "mobile_reserves_before_staging",
    reserve_pos >= 0 and stager_pos > reserve_pos,
)

req(
    "wire_offer_preserved",
    "FileTransferMessage::Offer {" in mobile,
)
req(
    "wire_chunk_preserved",
    "FileTransferMessage::Chunk {" in mobile,
)
req(
    "wire_complete_preserved",
    "FileTransferMessage::Complete { transfer_id }" in mobile,
)

print(
    "application transfer source V22 source contract passed: "
    f"checks={len(checks)}"
)
