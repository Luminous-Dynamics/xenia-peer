// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verified, durable persistence for the live consent ledger
//! (`shared_ledger` in `main.rs`, backing `/v1/audit/*`).
//!
//! Two gaps existed here before this module: (1) `main.rs` never wrote the
//! ledger to disk at all -- every `Chain::append` (a consent decision, or
//! an operator-action audit event) lived only in the in-process
//! `Arc<Mutex<Chain>>` and was lost on restart, silently discarding the
//! audit trail `docs/security/POST_DELEGATION_HARDENING_PLAN.md` item 3's
//! checkpoint/export design assumes exists; (2) the one place a persisted
//! ledger *was* read back (if a `consent.ledger` file happened to already
//! exist) never verified it -- `xenia_ledger::Chain::from_entries`'s own
//! doc comment says as much ("Does NOT verify the rehydrated entries").
//! A tampered or corrupted on-disk file would have been silently trusted
//! and served as genuine signed history.
//!
//! This module closes both: [`load_verified`] refuses to trust a persisted
//! ledger that doesn't verify under the operator's signing key (fail
//! closed -- the daemon won't start rather than serve a ledger it can't
//! authenticate), and [`persist_entries_atomic`] gives callers (via
//! `xenia_ledger::Chain::append_transactional`) a real durable-write
//! primitive: temp file, `fsync` the data, atomic rename, `fsync` the
//! containing directory. The on-disk format is now an explicit, magic-tagged
//! v1 envelope with entry-count/head metadata and hard byte/entry limits;
//! historical bare `Vec<LedgerEntry>` files remain readable and migrate on
//! the next append. Skipping the final directory fsync is the most common way
//! "atomic" file replacement code is still not actually crash-safe -- a rename
//! can be lost on a crash even after the renamed file's own contents are
//! durable, until the directory entry pointing at it is fsync'd too.

// Consent-ledger checkpoint/witness/archive continuity helpers below
// (`verify_retained_checkpoint*`, `verify_retained_witness_bundle`,
// `verify_retained_key_successor`, `export_archive_segment_atomic`,
// `advance_retained_checkpoint`, `read_bounded_json*`,
// `persist_owner_only_atomic`, plus their MAX_*_BYTES consts) are real,
// tested prerequisites the consent-ledger maintenance ceremony modules
// (`consent_purge*.rs`, `consent_retirement.rs`, `consent_compaction.rs`,
// `consent_final_destruction.rs`) depend on, ported ahead of their own CLI
// wiring, as part of a 4-phase re-derivation of PR #99's consent-ledger
// maintenance subsystem (Phase 1 vs Phase 2). Nothing calls them yet;
// that's Phase 2's job.
#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use xenia_ledger::{
    Chain, CheckpointContinuityError, CheckpointFreshnessPolicy, CheckpointWitnessBundle,
    CheckpointWitnessError, LedgerArchiveError, LedgerArchiveSegment, LedgerCheckpoint,
    LedgerEntry, LedgerKeyTransition, LedgerKeyTransitionError, Verifier, VerifyError,
};

/// Errors surfaced while loading or persisting the live audit ledger.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AuditLedgerStoreError {
    /// Reading, writing, renaming, or syncing the ledger file failed.
    #[error("audit ledger I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The persisted file exceeded the daemon's explicit resource bounds.
    #[error("audit ledger resource limit exceeded: {0}")]
    LimitExceeded(String),
    /// A versioned persistence envelope used an unsupported schema.
    #[error("unsupported audit ledger persistence schema: {0}")]
    UnsupportedSchema(u16),
    /// Envelope metadata did not match the authenticated entry vector.
    #[error("audit ledger persistence metadata mismatch: {0}")]
    MetadataMismatch(&'static str),
    /// The persisted bincode payload could not be decoded (or, when
    /// persisting, could not be encoded).
    #[error("audit ledger codec error: {0}")]
    Codec(#[from] bincode::Error),
    /// The persisted chain failed sequence, hash-link, entry-hash, or
    /// signature verification -- it exists on disk but this daemon will
    /// not trust it.
    #[error("persisted audit ledger failed verification: {0}")]
    Verify(#[from] VerifyError),
    /// A retained continuity artifact could not be decoded.
    #[error("audit continuity artifact JSON error: {0}")]
    ContinuityJson(#[from] serde_json::Error),
    /// The current ledger failed to contain the independently retained
    /// checkpoint as an exact authenticated prefix.
    #[error("retained audit checkpoint continuity failure: {0}")]
    CheckpointContinuity(#[from] CheckpointContinuityError),
    /// A dual-signed ledger-key succession proof was invalid.
    #[error("retained ledger key transition failure: {0}")]
    KeyTransition(#[from] LedgerKeyTransitionError),
    /// An independently witnessed checkpoint bundle failed quorum policy.
    #[error("retained checkpoint witness failure: {0}")]
    CheckpointWitness(#[from] CheckpointWitnessError),
    /// A bounded archive segment could not be produced or verified.
    #[error("consent ledger archive failure: {0}")]
    LedgerArchive(#[from] LedgerArchiveError),
    /// An activated compacted ledger failed structural, cryptographic, or
    /// recovery-index verification.
    #[error("compacted consent state failure: {0}")]
    CompactedState(#[from] crate::consent_compaction::ConsentRecoveryError),
}

const PERSISTED_AUDIT_LEDGER_MAGIC: &[u8] = b"XENIA-AUDIT-LEDGER\0";
const PERSISTED_AUDIT_LEDGER_SCHEMA_V1: u16 = 1;
const PERSISTED_AUDIT_LEDGER_HEADER_LEN: usize = PERSISTED_AUDIT_LEDGER_MAGIC.len() + 2 + 8 + 32;
pub(crate) const MAX_AUDIT_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_AUDIT_LEDGER_ENTRIES: usize = 100_000;
pub(crate) const MAX_RETAINED_CHECKPOINT_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_CONTINUITY_ARTIFACT_BYTES: u64 = 1024 * 1024;

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn head_hash(entries: &[LedgerEntry]) -> [u8; 32] {
    entries
        .last()
        .map(|entry| entry.entry_hash)
        .unwrap_or([0u8; 32])
}

fn validate_entry_count(count: usize) -> Result<(), AuditLedgerStoreError> {
    if count > MAX_AUDIT_LEDGER_ENTRIES {
        return Err(AuditLedgerStoreError::LimitExceeded(format!(
            "{count} entries exceeds maximum {MAX_AUDIT_LEDGER_ENTRIES}"
        )));
    }
    Ok(())
}

fn read_u64_be(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

fn read_u16_be(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn declared_bincode_vec_len(bytes: &[u8]) -> Result<usize, AuditLedgerStoreError> {
    let encoded = bytes
        .get(..8)
        .ok_or(AuditLedgerStoreError::MetadataMismatch(
            "truncated bincode vector length",
        ))?;
    let count = u64::from_le_bytes(
        encoded
            .try_into()
            .map_err(|_| AuditLedgerStoreError::MetadataMismatch("bincode vector length"))?,
    );
    let count = usize::try_from(count)
        .map_err(|_| AuditLedgerStoreError::LimitExceeded("entry count overflow".into()))?;
    validate_entry_count(count)?;
    Ok(count)
}

/// Load `path` and verify every persisted entry under `signing_key` before
/// trusting it; if `path` doesn't exist yet, return a fresh empty chain.
/// Fails closed: a present-but-corrupt-or-tampered file is an error, never
/// silently discarded or partially trusted.
pub(crate) fn load_verified(
    path: &Path,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Chain, AuditLedgerStoreError> {
    if !path.exists() {
        return Ok(Chain::new(signing_key.clone()));
    }
    let file_len = std::fs::metadata(path)?.len();
    if file_len > MAX_AUDIT_LEDGER_BYTES {
        return Err(AuditLedgerStoreError::LimitExceeded(format!(
            "{} bytes exceeds maximum {}",
            file_len, MAX_AUDIT_LEDGER_BYTES
        )));
    }
    let bytes = std::fs::read(path)?;
    let entries = if bytes.starts_with(PERSISTED_AUDIT_LEDGER_MAGIC) {
        if bytes.len() < PERSISTED_AUDIT_LEDGER_HEADER_LEN {
            return Err(AuditLedgerStoreError::MetadataMismatch("truncated header"));
        }
        let mut offset = PERSISTED_AUDIT_LEDGER_MAGIC.len();
        let schema_version = read_u16_be(&bytes[offset..offset + 2])
            .ok_or(AuditLedgerStoreError::MetadataMismatch("schema_version"))?;
        offset += 2;
        if schema_version != PERSISTED_AUDIT_LEDGER_SCHEMA_V1 {
            return Err(AuditLedgerStoreError::UnsupportedSchema(schema_version));
        }
        let entry_count = read_u64_be(&bytes[offset..offset + 8])
            .ok_or(AuditLedgerStoreError::MetadataMismatch("entry_count"))?;
        offset += 8;
        let entry_count = usize::try_from(entry_count)
            .map_err(|_| AuditLedgerStoreError::LimitExceeded("entry count overflow".into()))?;
        validate_entry_count(entry_count)?;
        let mut expected_head_hash = [0u8; 32];
        expected_head_hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        let encoded_entry_count = declared_bincode_vec_len(&bytes[offset..])?;
        if encoded_entry_count != entry_count {
            return Err(AuditLedgerStoreError::MetadataMismatch(
                "encoded_entry_count",
            ));
        }
        let entries: Vec<LedgerEntry> = bincode::deserialize(&bytes[offset..])?;
        if entry_count != entries.len() {
            return Err(AuditLedgerStoreError::MetadataMismatch("entry_count"));
        }
        if expected_head_hash != head_hash(&entries) {
            return Err(AuditLedgerStoreError::MetadataMismatch("head_hash"));
        }
        entries
    } else {
        // Legacy releases persisted the bare bincode Vec<LedgerEntry>. Keep it
        // readable for migration; the next successful append rewrites it in
        // the explicit v1 envelope. The total file-size bound is applied before
        // this compatibility decoder is reached.
        let declared_entry_count = declared_bincode_vec_len(&bytes)?;
        let entries: Vec<LedgerEntry> = bincode::deserialize(&bytes)?;
        if entries.len() != declared_entry_count {
            return Err(AuditLedgerStoreError::MetadataMismatch(
                "legacy encoded_entry_count",
            ));
        }
        entries
    };
    Verifier::verify_chain(&entries, &signing_key.verifying_key())?;
    Ok(Chain::from_entries(entries, signing_key.clone()))
}

fn verify_checkpoint_against_chain(
    checkpoint: &LedgerCheckpoint,
    chain: &Chain,
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), AuditLedgerStoreError> {
    if chain.base_checkpoint().is_none() {
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        Verifier::verify_checkpoint_prefix(checkpoint, &entries, public_key)?;
        return Ok(());
    }

    Verifier::verify_checkpoint(checkpoint).map_err(CheckpointContinuityError::from)?;
    if checkpoint.ledger_public_key != public_key.to_bytes() {
        return Err(AuditLedgerStoreError::CheckpointContinuity(
            CheckpointContinuityError::TrustedKeyMismatch,
        ));
    }
    let base = chain.base_checkpoint().ok_or(
        AuditLedgerStoreError::MetadataMismatch("compacted chain anchor is missing"),
    )?;
    Verifier::verify_checkpoint(base).map_err(CheckpointContinuityError::from)?;
    if checkpoint.entry_count < base.entry_count {
        return Err(AuditLedgerStoreError::MetadataMismatch(
            "retained checkpoint predates compacted ledger anchor",
        ));
    }
    if checkpoint.entry_count > chain.entry_count() {
        return Err(AuditLedgerStoreError::CheckpointContinuity(
            CheckpointContinuityError::CheckpointAheadOfLedger {
                checkpoint: checkpoint.entry_count,
                ledger: chain.entry_count(),
            },
        ));
    }
    let observed_head = if checkpoint.entry_count == base.entry_count {
        base.head_hash
    } else {
        let resident_index = usize::try_from(checkpoint.entry_count - base.entry_count - 1)
            .map_err(|_| {
                AuditLedgerStoreError::LimitExceeded(
                    "retained checkpoint resident index overflow".into(),
                )
            })?;
        chain
            .iter()
            .nth(resident_index)
            .map(|entry| entry.entry_hash)
            .ok_or_else(|| {
                AuditLedgerStoreError::CheckpointContinuity(
                    CheckpointContinuityError::CheckpointAheadOfLedger {
                        checkpoint: checkpoint.entry_count,
                        ledger: chain.entry_count(),
                    },
                )
            })?
    };
    if observed_head != checkpoint.head_hash {
        return Err(AuditLedgerStoreError::CheckpointContinuity(
            CheckpointContinuityError::PrefixHeadMismatch {
                entry_count: checkpoint.entry_count,
            },
        ));
    }
    let entries = chain.iter().cloned().collect::<Vec<_>>();
    let timestamp = unix_now_secs().max(base.timestamp_unix_secs);
    let current = chain.sign_checkpoint(timestamp);
    Verifier::verify_checkpoint_extension(base, &current, &entries)?;
    Ok(())
}

/// Load an independently retained public checkpoint and prove that the current
/// verified ledger contains it as an exact prefix.
///
/// The checkpoint should live outside the state directory being restored. If a
/// complete older state snapshot rolls back the ledger, this comparison fails
/// even though that older ledger remains internally well-signed.
pub(crate) fn verify_retained_checkpoint(
    checkpoint_path: &Path,
    chain: &Chain,
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<LedgerCheckpoint, AuditLedgerStoreError> {
    verify_retained_checkpoint_with_policy(
        checkpoint_path,
        chain,
        public_key,
        unix_now_secs(),
        CheckpointFreshnessPolicy::default(),
    )
}

/// Load and verify one retained checkpoint with an explicit host-local
/// freshness SLA in addition to signature and exact-prefix continuity.
pub(crate) fn verify_retained_checkpoint_with_policy(
    checkpoint_path: &Path,
    chain: &Chain,
    public_key: &ed25519_dalek::VerifyingKey,
    now_unix_secs: u64,
    freshness: CheckpointFreshnessPolicy,
) -> Result<LedgerCheckpoint, AuditLedgerStoreError> {
    let checkpoint: LedgerCheckpoint = read_bounded_json(
        checkpoint_path,
        MAX_RETAINED_CHECKPOINT_BYTES,
        "retained checkpoint",
    )?;
    Verifier::verify_checkpoint_freshness(&checkpoint, now_unix_secs, freshness)?;
    verify_checkpoint_against_chain(&checkpoint, chain, public_key)?;
    Ok(checkpoint)
}

/// Verify a witnessed checkpoint restore anchor. The checkpoint must both be
/// an exact prefix of the current ledger and satisfy the caller's distinct
/// trusted-witness quorum.
pub(crate) fn verify_retained_witness_bundle(
    bundle_path: &Path,
    chain: &Chain,
    public_key: &ed25519_dalek::VerifyingKey,
    trusted_witness_keys: &[[u8; 32]],
    minimum_quorum: usize,
    now_unix_secs: u64,
    freshness: CheckpointFreshnessPolicy,
) -> Result<CheckpointWitnessBundle, AuditLedgerStoreError> {
    let bundle: CheckpointWitnessBundle = read_bounded_json(
        bundle_path,
        MAX_CONTINUITY_ARTIFACT_BYTES,
        "checkpoint witness bundle",
    )?;
    Verifier::verify_checkpoint_freshness(&bundle.checkpoint, now_unix_secs, freshness)?;
    verify_checkpoint_against_chain(&bundle.checkpoint, chain, public_key)?;
    Verifier::verify_checkpoint_witness_quorum(&bundle, trusted_witness_keys, minimum_quorum)?;
    Ok(bundle)
}

/// Verify an explicit old-key/new-key epoch handover when the current ledger
/// intentionally begins a fresh epoch under a successor signing key.
pub(crate) fn verify_retained_key_successor(
    checkpoint_path: &Path,
    transition_path: &Path,
    chain: &Chain,
    current_public_key: &ed25519_dalek::VerifyingKey,
    now_unix_secs: u64,
) -> Result<LedgerKeyTransition, AuditLedgerStoreError> {
    let retained: LedgerCheckpoint = read_bounded_json(
        checkpoint_path,
        MAX_RETAINED_CHECKPOINT_BYTES,
        "retained checkpoint",
    )?;
    let transition: LedgerKeyTransition = read_bounded_json(
        transition_path,
        MAX_CONTINUITY_ARTIFACT_BYTES,
        "ledger key transition",
    )?;
    let candidate = chain.sign_checkpoint(now_unix_secs);
    let entries = chain.iter().cloned().collect::<Vec<_>>();
    Verifier::verify_ledger_key_successor(&retained, &transition, &candidate, &entries)?;
    if candidate.ledger_public_key != current_public_key.to_bytes() {
        return Err(AuditLedgerStoreError::MetadataMismatch(
            "successor checkpoint key",
        ));
    }
    Ok(transition)
}

pub(crate) fn read_bounded_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<T, AuditLedgerStoreError> {
    read_bounded_json_with_size(path, maximum_bytes, label).map(|(value, _)| value)
}

pub(crate) fn read_bounded_json_with_size<T: serde::de::DeserializeOwned>(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<(T, u64), AuditLedgerStoreError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(AuditLedgerStoreError::LimitExceeded(format!(
            "{label} is larger than {maximum_bytes} bytes"
        )));
    }
    let byte_count = bytes.len() as u64;
    Ok((serde_json::from_slice(&bytes)?, byte_count))
}

/// Export a bounded, verifiable archive segment without mutating or truncating
/// the live ledger. The supplied base checkpoint must be an exact prefix of the
/// current chain.
pub(crate) fn export_archive_segment_atomic(
    output_path: &Path,
    base_checkpoint_path: &Path,
    chain: &Chain,
    timestamp_unix_secs: u64,
) -> Result<LedgerArchiveSegment, AuditLedgerStoreError> {
    let base_checkpoint: LedgerCheckpoint = read_bounded_json(
        base_checkpoint_path,
        MAX_RETAINED_CHECKPOINT_BYTES,
        "archive base checkpoint",
    )?;
    let segment = LedgerArchiveSegment::from_chain(chain, base_checkpoint, timestamp_unix_secs)?;
    let mut bytes = serde_json::to_vec_pretty(&segment)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_AUDIT_LEDGER_BYTES {
        return Err(AuditLedgerStoreError::LimitExceeded(format!(
            "serialized archive segment is {} bytes; maximum is {}",
            bytes.len(),
            MAX_AUDIT_LEDGER_BYTES
        )));
    }
    persist_owner_only_atomic(output_path, &bytes)?;
    Ok(segment)
}

/// Atomically advance an externally retained checkpoint, refusing to overwrite
/// an existing pin unless the current ledger contains it as an exact prefix.
///
/// This is intentionally a one-shot maintenance operation rather than a file
/// stored inside the ordinary daemon state directory. Keeping the pin on
/// independent storage is what makes complete state-directory rollback
/// detectable.
pub(crate) fn advance_retained_checkpoint(
    checkpoint_path: &Path,
    chain: &Chain,
    public_key: &ed25519_dalek::VerifyingKey,
    timestamp_unix_secs: u64,
) -> Result<LedgerCheckpoint, AuditLedgerStoreError> {
    let previous = if checkpoint_path.exists() {
        Some(verify_retained_checkpoint(
            checkpoint_path,
            chain,
            public_key,
        )?)
    } else {
        None
    };
    let candidate = chain.sign_checkpoint(timestamp_unix_secs);
    if let Some(previous) = previous.as_ref() {
        Verifier::verify_checkpoint_monotonic(previous, &candidate)?;
    }
    let mut bytes = serde_json::to_vec_pretty(&candidate)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RETAINED_CHECKPOINT_BYTES {
        return Err(AuditLedgerStoreError::LimitExceeded(format!(
            "serialized retained checkpoint is {} bytes; maximum is {}",
            bytes.len(),
            MAX_RETAINED_CHECKPOINT_BYTES
        )));
    }
    persist_owner_only_atomic(checkpoint_path, &bytes)?;
    Ok(candidate)
}

pub(crate) fn persist_owner_only_atomic(
    path: &Path,
    bytes: &[u8],
) -> Result<(), AuditLedgerStoreError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temp_path = temporary_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result: Result<(), AuditLedgerStoreError> = (|| {
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

/// Serialize and atomically replace `path` with `entries`: write a temp
/// file in the same directory (owner-only permissions on Unix), `fsync`
/// its data, rename it over `path`, then `fsync` the containing directory
/// so the rename itself survives a crash. A failed write leaves the
/// previous ledger file untouched.
pub(crate) fn persist_entries_atomic(
    path: &Path,
    entries: &[LedgerEntry],
) -> Result<(), AuditLedgerStoreError> {
    validate_entry_count(entries.len())?;
    let payload = bincode::serialize(entries)?;
    let mut bytes = Vec::with_capacity(PERSISTED_AUDIT_LEDGER_HEADER_LEN + payload.len());
    bytes.extend_from_slice(PERSISTED_AUDIT_LEDGER_MAGIC);
    bytes.extend_from_slice(&PERSISTED_AUDIT_LEDGER_SCHEMA_V1.to_be_bytes());
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&head_hash(entries));
    bytes.extend_from_slice(&payload);
    if bytes.len() as u64 > MAX_AUDIT_LEDGER_BYTES {
        return Err(AuditLedgerStoreError::LimitExceeded(format!(
            "{} serialized bytes exceeds maximum {}",
            bytes.len(),
            MAX_AUDIT_LEDGER_BYTES
        )));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let temp_path = temporary_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let write_result: Result<(), AuditLedgerStoreError> = (|| {
        let mut file = options.open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        sync_directory(parent)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

fn temporary_path(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("consent.ledger");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{name}.tmp-{}-{nanos}", std::process::id()))
}

/// `fsync` a directory so a prior `rename` into it is durable across a
/// crash -- POSIX only; opening a directory for this purpose isn't a
/// portable operation, and Windows' `rename` durability model differs.
fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xenia_ledger::{ConsentEventRecord, ConsentKind};

    fn event() -> ConsentEventRecord {
        ConsentEventRecord {
            source_id: [0xAB; 32],
            session_id: Uuid::from_bytes([1u8; 16]),
            request_id: Uuid::from_bytes([2u8; 16]),
            kind: ConsentKind::Approval,
            scope: "view screen".to_string(),
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xenia-audit-ledger-store-test-{label}-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_loads_as_an_empty_chain() {
        let dir = temp_dir("missing");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let chain = load_verified(&path, &sk).unwrap();
        assert_eq!(chain.len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn round_trip_persist_then_load_verifies_history() {
        let dir = temp_dir("round-trip");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        chain.append(event()).unwrap();
        let entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        persist_entries_atomic(&path, &entries).unwrap();
        let persisted_bytes = std::fs::read(&path).unwrap();
        assert!(persisted_bytes.starts_with(PERSISTED_AUDIT_LEDGER_MAGIC));
        let count_offset = PERSISTED_AUDIT_LEDGER_MAGIC.len() + 2;
        assert_eq!(
            read_u64_be(&persisted_bytes[count_offset..count_offset + 8]),
            Some(2)
        );

        let reloaded = load_verified(&path, &sk).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.last_hash(), chain.last_hash());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_bare_vector_loads_and_migrates_on_next_persist() {
        let dir = temp_dir("legacy");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        let entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        std::fs::write(&path, bincode::serialize(&entries).unwrap()).unwrap();

        let loaded = load_verified(&path, &sk).unwrap();
        assert_eq!(loaded.len(), 1);
        let loaded_entries = loaded.iter().cloned().collect::<Vec<_>>();
        persist_entries_atomic(&path, &loaded_entries).unwrap();
        assert!(
            std::fs::read(&path)
                .unwrap()
                .starts_with(PERSISTED_AUDIT_LEDGER_MAGIC)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn versioned_envelope_rejects_metadata_tampering_before_chain_load() {
        let dir = temp_dir("metadata-tamper");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        let entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        persist_entries_atomic(&path, &entries).unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let head_offset = PERSISTED_AUDIT_LEDGER_MAGIC.len() + 2 + 8;
        bytes[head_offset] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            load_verified(&path, &sk),
            Err(AuditLedgerStoreError::MetadataMismatch("head_hash"))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unsupported_envelope_schema_is_rejected_explicitly() {
        let dir = temp_dir("unsupported-schema");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        let entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        persist_entries_atomic(&path, &entries).unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let schema_offset = PERSISTED_AUDIT_LEDGER_MAGIC.len();
        bytes[schema_offset..schema_offset + 2].copy_from_slice(&2u16.to_be_bytes());
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            load_verified(&path, &sk),
            Err(AuditLedgerStoreError::UnsupportedSchema(2))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bounded_json_reader_enforces_the_limit_on_bytes_actually_read() {
        let dir = temp_dir("bounded-json");
        let path = dir.join("artifact.json");
        std::fs::write(&path, br#"{"value":1}"#).unwrap();
        assert!(matches!(
            read_bounded_json::<serde_json::Value>(&path, 4, "test artifact"),
            Err(AuditLedgerStoreError::LimitExceeded(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_ledger_is_refused_before_reading_or_decoding() {
        let dir = temp_dir("oversized");
        let path = dir.join("consent.ledger");
        File::create(&path)
            .unwrap()
            .set_len(MAX_AUDIT_LEDGER_BYTES + 1)
            .unwrap();
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        assert!(matches!(
            load_verified(&path, &sk),
            Err(AuditLedgerStoreError::LimitExceeded(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malicious_legacy_vector_length_is_bounded_before_decode() {
        let dir = temp_dir("declared-count");
        let path = dir.join("consent.ledger");
        std::fs::write(&path, u64::MAX.to_le_bytes()).unwrap();
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        assert!(matches!(
            load_verified(&path, &sk),
            Err(AuditLedgerStoreError::LimitExceeded(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn entry_count_limit_is_enforced_without_allocating_a_ledger() {
        assert!(matches!(
            validate_entry_count(MAX_AUDIT_LEDGER_ENTRIES + 1),
            Err(AuditLedgerStoreError::LimitExceeded(_))
        ));
    }

    #[test]
    fn tampered_persisted_history_is_rejected_before_rehydration() {
        let dir = temp_dir("tampered");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        let mut entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        entries[0].signature[0] ^= 0xFF;
        // Bypass persist_entries_atomic's own (correct) signing to write a
        // deliberately-tampered file directly, simulating on-disk
        // corruption or an attacker with filesystem access.
        std::fs::write(&path, bincode::serialize(&entries).unwrap()).unwrap();

        let err = load_verified(&path, &sk).err().unwrap();
        assert!(matches!(err, AuditLedgerStoreError::Verify(_)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_verified_rejects_a_ledger_signed_by_a_different_key() {
        let dir = temp_dir("wrong-key");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk);
        chain.append(event()).unwrap();
        let entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        persist_entries_atomic(&path, &entries).unwrap();

        let other = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let err = load_verified(&path, &other).err().unwrap();
        assert!(matches!(err, AuditLedgerStoreError::Verify(_)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persist_is_atomic_a_failed_write_leaves_the_previous_file_intact() {
        let dir = temp_dir("atomic-failure");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        let first_entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        persist_entries_atomic(&path, &first_entries).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();

        // Make the destination directory read-only so the rename step
        // fails -- persist_entries_atomic must leave `path` untouched.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            chain.append(event()).unwrap();
            let second_entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
            let result = persist_entries_atomic(&path, &second_entries);
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(
                result.is_err(),
                "write into a read-only directory must fail"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                original_bytes,
                "a failed persist must not touch the previously-committed file"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn persisted_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let path = dir.join("consent.ledger");
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut chain = Chain::new(sk);
        chain.append(event()).unwrap();
        let entries: Vec<LedgerEntry> = chain.iter().cloned().collect();
        persist_entries_atomic(&path, &entries).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retained_checkpoint_verifies_inside_an_anchored_suffix() {
        let dir = temp_dir("retained-checkpoint-anchored-suffix");
        let checkpoint_path = dir.join("retained-checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[70u8; 32]);
        let mut complete = Chain::new(sk.clone());
        complete.append(event()).unwrap();
        let base = complete.sign_checkpoint(100);
        complete.append(event()).unwrap();
        let retained = complete.sign_checkpoint(101);
        let resident = complete.iter().skip(1).cloned().collect::<Vec<_>>();
        let compacted = Chain::from_checkpoint_suffix(base, resident, sk.clone());
        std::fs::write(&checkpoint_path, serde_json::to_vec(&retained).unwrap()).unwrap();

        verify_retained_checkpoint(&checkpoint_path, &compacted, &sk.verifying_key()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retained_checkpoint_before_compacted_anchor_requires_archive_proof() {
        let dir = temp_dir("retained-checkpoint-before-anchor");
        let checkpoint_path = dir.join("retained-checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[69u8; 32]);
        let mut complete = Chain::new(sk.clone());
        let genesis = complete.sign_checkpoint(99);
        complete.append(event()).unwrap();
        let base = complete.sign_checkpoint(100);
        let compacted = Chain::from_checkpoint_suffix(base, Vec::new(), sk.clone());
        std::fs::write(&checkpoint_path, serde_json::to_vec(&genesis).unwrap()).unwrap();

        assert!(matches!(
            verify_retained_checkpoint(&checkpoint_path, &compacted, &sk.verifying_key(),),
            Err(AuditLedgerStoreError::MetadataMismatch(
                "retained checkpoint predates compacted ledger anchor"
            ))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retained_checkpoint_accepts_a_later_ledger_with_the_same_prefix() {
        let dir = temp_dir("retained-checkpoint-prefix");
        let checkpoint_path = dir.join("retained-checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[71u8; 32]);
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        let retained = chain.sign_checkpoint(100);
        std::fs::write(&checkpoint_path, serde_json::to_vec(&retained).unwrap()).unwrap();
        chain.append(event()).unwrap();

        let loaded =
            verify_retained_checkpoint(&checkpoint_path, &chain, &sk.verifying_key()).unwrap();
        assert_eq!(loaded, retained);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retained_checkpoint_refuses_a_rolled_back_ledger() {
        let dir = temp_dir("retained-checkpoint-rollback");
        let checkpoint_path = dir.join("retained-checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[72u8; 32]);
        let mut newer = Chain::new(sk.clone());
        newer.append(event()).unwrap();
        newer.append(event()).unwrap();
        let retained = newer.sign_checkpoint(100);
        std::fs::write(&checkpoint_path, serde_json::to_vec(&retained).unwrap()).unwrap();

        let mut rolled_back = Chain::new(sk.clone());
        rolled_back.append(event()).unwrap();
        assert!(matches!(
            verify_retained_checkpoint(&checkpoint_path, &rolled_back, &sk.verifying_key(),),
            Err(AuditLedgerStoreError::CheckpointContinuity(
                CheckpointContinuityError::CheckpointAheadOfLedger { .. }
            ))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retained_checkpoint_advances_atomically_after_prefix_verification() {
        let dir = temp_dir("retained-checkpoint-advance");
        let checkpoint_path = dir.join("external/checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[73u8; 32]);
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        let first = advance_retained_checkpoint(&checkpoint_path, &chain, &sk.verifying_key(), 100)
            .unwrap();
        chain.append(event()).unwrap();
        let second =
            advance_retained_checkpoint(&checkpoint_path, &chain, &sk.verifying_key(), 101)
                .unwrap();
        assert!(second.entry_count > first.entry_count);
        let stored: LedgerCheckpoint =
            serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
        assert_eq!(stored, second);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checkpoint_advance_refuses_rollback_without_overwriting_the_pin() {
        let dir = temp_dir("retained-checkpoint-no-rollback");
        let checkpoint_path = dir.join("checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[74u8; 32]);
        let mut newer = Chain::new(sk.clone());
        newer.append(event()).unwrap();
        newer.append(event()).unwrap();
        advance_retained_checkpoint(&checkpoint_path, &newer, &sk.verifying_key(), 100).unwrap();
        let original = std::fs::read(&checkpoint_path).unwrap();

        let mut rolled_back = Chain::new(sk.clone());
        rolled_back.append(event()).unwrap();
        assert!(
            advance_retained_checkpoint(&checkpoint_path, &rolled_back, &sk.verifying_key(), 101,)
                .is_err()
        );
        assert_eq!(std::fs::read(&checkpoint_path).unwrap(), original);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn retained_checkpoint_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("retained-checkpoint-permissions");
        let checkpoint_path = dir.join("checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[75u8; 32]);
        let chain = Chain::new(sk.clone());
        advance_retained_checkpoint(&checkpoint_path, &chain, &sk.verifying_key(), 100).unwrap();
        let mode = std::fs::metadata(&checkpoint_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retained_checkpoint_freshness_policy_rejects_stale_anchor() {
        let dir = temp_dir("checkpoint-freshness");
        let checkpoint_path = dir.join("checkpoint.json");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[81u8; 32]);
        let mut chain = Chain::new(sk.clone());
        chain.append(event()).unwrap();
        std::fs::write(
            &checkpoint_path,
            serde_json::to_vec(&chain.sign_checkpoint(100)).unwrap(),
        )
        .unwrap();

        let error = verify_retained_checkpoint_with_policy(
            &checkpoint_path,
            &chain,
            &sk.verifying_key(),
            200,
            CheckpointFreshnessPolicy {
                max_age_secs: Some(50),
                max_future_skew_secs: 5,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AuditLedgerStoreError::CheckpointContinuity(
                CheckpointContinuityError::CheckpointTooOld { .. }
            )
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn witnessed_restore_requires_the_configured_quorum() {
        let dir = temp_dir("witnessed-restore");
        let bundle_path = dir.join("witnesses.json");
        let ledger_key = ed25519_dalek::SigningKey::from_bytes(&[82u8; 32]);
        let witness_a = ed25519_dalek::SigningKey::from_bytes(&[83u8; 32]);
        let witness_b = ed25519_dalek::SigningKey::from_bytes(&[84u8; 32]);
        let mut chain = Chain::new(ledger_key.clone());
        chain.append(event()).unwrap();
        let mut bundle =
            xenia_ledger::CheckpointWitnessBundle::new(chain.sign_checkpoint(100)).unwrap();
        bundle.sign_with(&witness_a, 101).unwrap();
        bundle.sign_with(&witness_b, 102).unwrap();
        std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();

        let trusted = [
            witness_a.verifying_key().to_bytes(),
            witness_b.verifying_key().to_bytes(),
        ];
        let verified = verify_retained_witness_bundle(
            &bundle_path,
            &chain,
            &ledger_key.verifying_key(),
            &trusted,
            2,
            102,
            CheckpointFreshnessPolicy {
                max_age_secs: Some(10),
                max_future_skew_secs: 5,
            },
        )
        .unwrap();
        assert_eq!(verified.witnesses.len(), 2);
        assert!(
            verify_retained_witness_bundle(
                &bundle_path,
                &chain,
                &ledger_key.verifying_key(),
                &trusted,
                3,
                102,
                CheckpointFreshnessPolicy {
                    max_age_secs: Some(10),
                    max_future_skew_secs: 5,
                },
            )
            .is_err()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dual_signed_transition_allows_a_new_ledger_epoch() {
        let dir = temp_dir("key-successor");
        let checkpoint_path = dir.join("previous.json");
        let transition_path = dir.join("transition.json");
        let old_key = ed25519_dalek::SigningKey::from_bytes(&[85u8; 32]);
        let new_key = ed25519_dalek::SigningKey::from_bytes(&[86u8; 32]);
        let mut previous_chain = Chain::new(old_key.clone());
        previous_chain.append(event()).unwrap();
        let previous = previous_chain.sign_checkpoint(100);
        let transition =
            xenia_ledger::LedgerKeyTransition::sign(previous.clone(), &old_key, &new_key, 101)
                .unwrap();
        std::fs::write(&checkpoint_path, serde_json::to_vec(&previous).unwrap()).unwrap();
        std::fs::write(&transition_path, serde_json::to_vec(&transition).unwrap()).unwrap();

        let mut successor = Chain::new(new_key.clone());
        successor.append(event()).unwrap();
        let verified = verify_retained_key_successor(
            &checkpoint_path,
            &transition_path,
            &successor,
            &new_key.verifying_key(),
            102,
        )
        .unwrap();
        assert_eq!(
            verified.new_ledger_public_key,
            new_key.verifying_key().to_bytes()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn archive_export_is_atomic_and_independently_verifiable() {
        let dir = temp_dir("archive-export");
        let base_path = dir.join("base.json");
        let output_path = dir.join("archive/segment.json");
        let key = ed25519_dalek::SigningKey::from_bytes(&[87u8; 32]);
        let mut chain = Chain::new(key);
        let base = chain.sign_checkpoint(100);
        chain.append(event()).unwrap();
        std::fs::write(&base_path, serde_json::to_vec(&base).unwrap()).unwrap();

        let segment = export_archive_segment_atomic(&output_path, &base_path, &chain, 101).unwrap();
        xenia_ledger::Verifier::verify_ledger_archive_segment(&segment).unwrap();
        let stored: xenia_ledger::LedgerArchiveSegment =
            serde_json::from_slice(&std::fs::read(&output_path).unwrap()).unwrap();
        assert_eq!(stored, segment);
        std::fs::remove_dir_all(&dir).ok();
    }
}
