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

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use xenia_ledger::{Chain, LedgerEntry, Verifier, VerifyError};

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
}

const PERSISTED_AUDIT_LEDGER_MAGIC: &[u8] = b"XENIA-AUDIT-LEDGER\0";
const PERSISTED_AUDIT_LEDGER_SCHEMA_V1: u16 = 1;
const PERSISTED_AUDIT_LEDGER_HEADER_LEN: usize =
    PERSISTED_AUDIT_LEDGER_MAGIC.len() + 2 + 8 + 32;
pub(crate) const MAX_AUDIT_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_AUDIT_LEDGER_ENTRIES: usize = 100_000;

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
        let entries: Vec<LedgerEntry> = bincode::deserialize(&bytes)?;
        validate_entry_count(entries.len())?;
        entries
    };
    Verifier::verify_chain(&entries, &signing_key.verifying_key())?;
    Ok(Chain::from_entries(entries, signing_key.clone()))
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
            bytes.len(), MAX_AUDIT_LEDGER_BYTES
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
}
