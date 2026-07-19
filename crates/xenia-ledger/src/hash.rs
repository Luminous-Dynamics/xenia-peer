// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::SystemTime;

use serde::Serialize;

use crate::entry::ConsentEventRecord;
use crate::errors::LedgerError;

// ─────────────────────────── internals ─────────────────────────────

/// Canonical pre-image for the entry hash. `bincode` v1 with default
/// options produces a deterministic, length-prefixed big-endian
/// encoding. Locked to the crate's bincode version (1.3 in the
/// workspace).
#[derive(Serialize)]
struct EntryPreimage<'a> {
    seq: u64,
    prev_hash: [u8; 32],
    timestamp: &'a SystemTime,
    event: &'a ConsentEventRecord,
}

pub(crate) fn compute_entry_hash(
    seq: u64,
    prev_hash: &[u8; 32],
    timestamp: &SystemTime,
    event: &ConsentEventRecord,
) -> Result<[u8; 32], LedgerError> {
    let preimage = EntryPreimage {
        seq,
        prev_hash: *prev_hash,
        timestamp,
        event,
    };
    let bytes = bincode::serialize(&preimage)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
