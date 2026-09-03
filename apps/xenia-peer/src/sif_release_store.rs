// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable compare-and-swap persistence for the SIF release journal.
//!
//! Every transition owns a stable sibling lock file created through
//! `xenia-secure-file`'s atomic first-writer-wins primitive. The lock contains a
//! fresh random owner token; only the caller that reads back its own token enters
//! the critical section. The durable journal is then verified under the configured
//! ledger key before comparing the signed frontier and atomically replacing it.
//!
//! A crash can leave a stale lock. v0.1 deliberately treats that as fail-closed
//! operator recovery rather than guessing that a lock is stale and risking two
//! simultaneous writers. This trades availability for the one-lineage invariant.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use xenia_ledger::{
    DisclosureReleaseEntry, DisclosureReleaseFrontier, DisclosureReleaseState,
    DisclosureReleaseStore, verify_disclosure_release_entries,
};

const RELEASE_STORE_MAGIC: &[u8] = b"XENIA-SIF-RELEASE\0";
const RELEASE_STORE_SCHEMA: u16 = 1;
const RELEASE_STORE_HEADER_LEN: usize = RELEASE_STORE_MAGIC.len() + 2 + 8 + 32;
const MAX_RELEASE_STORE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RELEASE_STORE_ENTRIES: usize = 100_000;
const LOCK_TOKEN_BYTES: usize = 32;

/// Durable SIF release-journal storage failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SifReleaseStoreError {
    /// Filesystem read/write/sync/rename operation failed.
    #[error("SIF release store I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Secure-file locking primitive rejected the path or operation.
    #[error("SIF release store secure lock error: {0}")]
    SecureLock(String),
    /// Another process owns the release-journal CAS lock, including a stale lock
    /// left after a crash that requires explicit operator recovery.
    #[error("SIF release journal is locked by another writer")]
    LockHeld,
    /// Bincode framing could not be encoded or decoded.
    #[error("SIF release store codec error: {0}")]
    Codec(#[from] bincode::Error),
    /// Persisted envelope schema is unsupported.
    #[error("unsupported SIF release store schema: {0}")]
    UnsupportedSchema(u16),
    /// Persisted envelope metadata disagrees with signed entries.
    #[error("SIF release store metadata mismatch: {0}")]
    MetadataMismatch(&'static str),
    /// Resource bound was exceeded.
    #[error("SIF release store resource limit exceeded: {0}")]
    LimitExceeded(String),
    /// Persisted signed release entries did not verify.
    #[error("persisted SIF release journal failed verification: {0}")]
    JournalVerification(#[from] xenia_ledger::AccountabilityDisclosureError),
    /// Atomic CAS observed a different durable frontier than the caller expected.
    #[error("SIF release journal durable frontier changed concurrently")]
    StaleFrontier,
    /// Proposed transition did not append exactly one signed journal entry.
    #[error("SIF release journal CAS transition must append exactly one entry")]
    InvalidTransitionLength,
}

/// Filesystem-backed CAS store for the signed release journal.
pub(crate) struct FileSifReleaseStore {
    path: PathBuf,
    ledger_public_key: [u8; 32],
}

impl FileSifReleaseStore {
    /// Create a store handle. No on-disk state is trusted until [`Self::load_state`].
    pub(crate) fn new(path: PathBuf, ledger_public_key: [u8; 32]) -> Self {
        Self {
            path,
            ledger_public_key,
        }
    }

    /// Load, decode and cryptographically verify durable release state.
    pub(crate) fn load_state(&self) -> Result<DisclosureReleaseState, SifReleaseStoreError> {
        let entries = read_entries(&self.path)?;
        Ok(DisclosureReleaseState::from_verified_entries(
            entries,
            &self.ledger_public_key,
        )?)
    }

    fn compare_and_swap_locked(
        &self,
        expected: DisclosureReleaseFrontier,
        next_entries: &[DisclosureReleaseEntry],
    ) -> Result<(), SifReleaseStoreError> {
        let current = read_entries(&self.path)?;
        verify_disclosure_release_entries(&current, &self.ledger_public_key)?;
        let observed = frontier(&current);
        if observed != expected {
            return Err(SifReleaseStoreError::StaleFrontier);
        }
        if next_entries.len() != current.len().saturating_add(1) {
            return Err(SifReleaseStoreError::InvalidTransitionLength);
        }
        verify_disclosure_release_entries(next_entries, &self.ledger_public_key)?;
        persist_entries_atomic(&self.path, next_entries)?;
        Ok(())
    }
}

impl DisclosureReleaseStore for FileSifReleaseStore {
    type Error = SifReleaseStoreError;

    fn compare_and_swap(
        &mut self,
        expected: DisclosureReleaseFrontier,
        next_entries: &[DisclosureReleaseEntry],
    ) -> Result<(), Self::Error> {
        let _guard = ReleaseStoreLock::acquire(&lock_path(&self.path))?;
        self.compare_and_swap_locked(expected, next_entries)
    }
}

struct ReleaseStoreLock {
    path: PathBuf,
    token: [u8; LOCK_TOKEN_BYTES],
}

impl ReleaseStoreLock {
    fn acquire(path: &Path) -> Result<Self, SifReleaseStoreError> {
        let token: [u8; LOCK_TOKEN_BYTES] = rand::random();
        let observed = xenia_secure_file::load_or_create_secure_file(path, || token.to_vec())
            .map_err(|error| SifReleaseStoreError::SecureLock(error.to_string()))?;
        if observed.as_slice() != token {
            return Err(SifReleaseStoreError::LockHeld);
        }
        Ok(Self {
            path: path.to_path_buf(),
            token,
        })
    }
}

impl Drop for ReleaseStoreLock {
    fn drop(&mut self) {
        // Only remove the lock if it still contains this guard's owner token. The
        // secure parent directory is owner-only; a mismatched/missing file is left
        // untouched and causes future acquisition to fail closed rather than this
        // guard deleting another writer's marker.
        let still_ours = xenia_secure_file::read_secure_file_if_exists(&self.path)
            .ok()
            .flatten()
            .is_some_and(|bytes| bytes.as_slice() == self.token);
        if still_ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn frontier(entries: &[DisclosureReleaseEntry]) -> DisclosureReleaseFrontier {
    DisclosureReleaseFrontier {
        entry_count: entries.len() as u64,
        head_hash: entries
            .last()
            .map(DisclosureReleaseEntry::entry_hash)
            .unwrap_or([0u8; 32]),
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".lock");
    PathBuf::from(os)
}

fn read_entries(path: &Path) -> Result<Vec<DisclosureReleaseEntry>, SifReleaseStoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let len = std::fs::metadata(path)?.len();
    if len > MAX_RELEASE_STORE_BYTES {
        return Err(SifReleaseStoreError::LimitExceeded(format!(
            "{len} bytes exceeds maximum {MAX_RELEASE_STORE_BYTES}"
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    std::fs::File::open(path)?.read_to_end(&mut bytes)?;
    if bytes.len() < RELEASE_STORE_HEADER_LEN || !bytes.starts_with(RELEASE_STORE_MAGIC) {
        return Err(SifReleaseStoreError::MetadataMismatch("magic/header"));
    }

    let mut offset = RELEASE_STORE_MAGIC.len();
    let schema = u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .map_err(|_| SifReleaseStoreError::MetadataMismatch("schema"))?,
    );
    offset += 2;
    if schema != RELEASE_STORE_SCHEMA {
        return Err(SifReleaseStoreError::UnsupportedSchema(schema));
    }
    let count_u64 = u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| SifReleaseStoreError::MetadataMismatch("entry_count"))?,
    );
    offset += 8;
    let count = usize::try_from(count_u64)
        .map_err(|_| SifReleaseStoreError::LimitExceeded("entry count overflow".into()))?;
    if count > MAX_RELEASE_STORE_ENTRIES {
        return Err(SifReleaseStoreError::LimitExceeded(format!(
            "{count} entries exceeds maximum {MAX_RELEASE_STORE_ENTRIES}"
        )));
    }
    let mut declared_head = [0u8; 32];
    declared_head.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let entries: Vec<DisclosureReleaseEntry> = bincode::deserialize(&bytes[offset..])?;
    if entries.len() != count {
        return Err(SifReleaseStoreError::MetadataMismatch("entry_count"));
    }
    if frontier(&entries).head_hash != declared_head {
        return Err(SifReleaseStoreError::MetadataMismatch("head_hash"));
    }
    Ok(entries)
}

fn persist_entries_atomic(
    path: &Path,
    entries: &[DisclosureReleaseEntry],
) -> Result<(), SifReleaseStoreError> {
    if entries.len() > MAX_RELEASE_STORE_ENTRIES {
        return Err(SifReleaseStoreError::LimitExceeded(format!(
            "{} entries exceeds maximum {MAX_RELEASE_STORE_ENTRIES}",
            entries.len()
        )));
    }
    let encoded = bincode::serialize(entries)?;
    let mut bytes = Vec::with_capacity(RELEASE_STORE_HEADER_LEN + encoded.len());
    bytes.extend_from_slice(RELEASE_STORE_MAGIC);
    bytes.extend_from_slice(&RELEASE_STORE_SCHEMA.to_be_bytes());
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&frontier(entries).head_hash);
    bytes.extend_from_slice(&encoded);
    if bytes.len() as u64 > MAX_RELEASE_STORE_BYTES {
        return Err(SifReleaseStoreError::LimitExceeded(format!(
            "{} encoded bytes exceeds maximum {MAX_RELEASE_STORE_BYTES}",
            bytes.len()
        )));
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sif-release-journal");
    let tmp = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));

    let result = (|| -> Result<(), SifReleaseStoreError> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_missing_store_loads_as_genesis() {
        let path = std::env::temp_dir().join(format!(
            "xenia-sif-release-missing-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = FileSifReleaseStore::new(path, [7u8; 32]);
        let state = store.load_state().unwrap();
        assert_eq!(state.frontier(), DisclosureReleaseFrontier::GENESIS);
    }

    #[test]
    fn second_lock_owner_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-sif-release-lock-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("release.journal.lock");
        let first = ReleaseStoreLock::acquire(&path).unwrap();
        assert!(matches!(
            ReleaseStoreLock::acquire(&path),
            Err(SifReleaseStoreError::LockHeld)
        ));
        drop(first);
        let second = ReleaseStoreLock::acquire(&path).unwrap();
        drop(second);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_present_store_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-sif-release-malformed-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("release.journal");
        std::fs::write(&path, b"not-a-release-journal").unwrap();
        let store = FileSifReleaseStore::new(path, [7u8; 32]);
        assert!(store.load_state().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
