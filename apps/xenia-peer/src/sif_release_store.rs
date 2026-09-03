// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable compare-and-swap persistence for the SIF release journal.
//!
//! The data file is verified under the configured Xenia ledger key before it is
//! trusted. On Unix, every transition holds an advisory exclusive lock on a stable
//! sibling lock file while comparing the durable signed frontier and atomically
//! replacing the journal. No racy read-then-rename fallback is provided on platforms
//! without a locking backend.

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

/// Durable SIF release-journal storage failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SifReleaseStoreError {
    /// Filesystem read/write/sync/rename/lock operation failed.
    #[error("SIF release store I/O error: {0}")]
    Io(#[from] std::io::Error),
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
    /// This platform has no qualified interprocess locking backend yet.
    #[error("SIF release CAS store is unavailable on this platform")]
    UnsupportedPlatform,
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
}

impl DisclosureReleaseStore for FileSifReleaseStore {
    type Error = SifReleaseStoreError;

    fn compare_and_swap(
        &mut self,
        expected: DisclosureReleaseFrontier,
        next_entries: &[DisclosureReleaseEntry],
    ) -> Result<(), Self::Error> {
        #[cfg(unix)]
        {
            self.compare_and_swap_unix(expected, next_entries)
        }
        #[cfg(not(unix))]
        {
            let _ = (expected, next_entries);
            Err(SifReleaseStoreError::UnsupportedPlatform)
        }
    }
}

#[cfg(unix)]
impl FileSifReleaseStore {
    fn compare_and_swap_unix(
        &self,
        expected: DisclosureReleaseFrontier,
        next_entries: &[DisclosureReleaseEntry],
    ) -> Result<(), SifReleaseStoreError> {
        use std::os::unix::fs::OpenOptionsExt;

        use rustix::fs::{FlockOperation, flock};

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let lock_path = lock_path(&self.path);
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)?;
        flock(&lock, FlockOperation::LockExclusive)
            .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;

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

#[cfg(unix)]
fn persist_entries_atomic(
    path: &Path,
    entries: &[DisclosureReleaseEntry],
) -> Result<(), SifReleaseStoreError> {
    use std::os::unix::fs::OpenOptionsExt;

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
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
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

#[cfg(not(unix))]
fn persist_entries_atomic(
    _path: &Path,
    _entries: &[DisclosureReleaseEntry],
) -> Result<(), SifReleaseStoreError> {
    Err(SifReleaseStoreError::UnsupportedPlatform)
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
