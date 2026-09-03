// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Crash-durable publication helpers for protected received files.
//!
//! The ordinary receive path already writes into a private same-directory staging
//! inode, verifies the complete file, calls `sync_all()` on that inode, and publishes
//! it with a no-clobber hard link. That is strong application-level persistence, but
//! on Unix-like filesystems the final directory entry is not necessarily durable
//! across sudden power loss until the containing directory itself has been synced.
//!
//! SIF protected custody uses this stricter wrapper. Success means both the verified
//! file inode and the directory namespace containing its final path have crossed the
//! local filesystem sync boundary supported by this implementation. Platforms where
//! Xenia does not yet have an explicit directory-sync implementation fail closed
//! rather than silently upgrading an application-persistence result into a
//! crash-durability claim.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::file_transfer::{
    IncomingFileStageError, IncomingFileStager, persist_received_file,
};

/// Local filesystem durability achieved by a successful protected publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveDurability {
    /// The complete verified file was synced and its containing directory was
    /// explicitly synced after final-name publication.
    FileAndNamespaceSynced,
}

/// Move-only proof token returned only after the local crash-durability boundary.
///
/// This is local runtime evidence, not a portable cryptographic proof that a storage
/// device obeyed its flush contract. Higher layers may use possession of this token as
/// the prerequisite for issuing a `PersistedVerified` SIF receipt.
#[derive(Debug)]
pub struct CrashDurableReceivePublication {
    final_path: PathBuf,
    durability: ReceiveDurability,
}

impl CrashDurableReceivePublication {
    /// Final no-clobber path whose directory namespace was synchronized.
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Local durability class reached before this token was constructed.
    pub const fn durability(&self) -> ReceiveDurability {
        self.durability
    }
}

/// Disk-backed protected receiver that adds directory durability to
/// [`IncomingFileStager`]'s verified no-clobber publication.
///
/// Chunk ordering, size bounds, whole-file BLAKE3 verification and inode `sync_all()`
/// remain delegated to the existing stager. [`Self::finish`] then synchronizes the
/// containing directory before returning a positive publication token.
pub struct CrashDurableIncomingFileStager {
    inner: IncomingFileStager,
    final_path: PathBuf,
}

impl CrashDurableIncomingFileStager {
    /// Create a private same-directory staging inode for one authenticated offer.
    pub fn create(
        final_path: &Path,
        expected_size: u64,
        expected_hash: [u8; 32],
    ) -> Result<Self, IncomingFileStageError> {
        let inner = IncomingFileStager::create(final_path, expected_size, expected_hash)?;
        Ok(Self {
            inner,
            final_path: final_path.to_path_buf(),
        })
    }

    /// Append the next exact contiguous chunk.
    pub fn append(
        &mut self,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u64, IncomingFileStageError> {
        self.inner.append(offset, bytes)
    }

    /// Number of file-content bytes durably staged so far.
    pub fn received_bytes(&self) -> u64 {
        self.inner.received_bytes()
    }

    /// Verify the complete file, sync its inode, publish without clobbering, then
    /// sync the containing directory before reporting crash-durable custody.
    pub fn finish(self) -> Result<CrashDurableReceivePublication, CrashDurableReceiveError> {
        let Self { inner, final_path } = self;
        inner.finish()?;
        sync_receive_parent_directory(&final_path).map_err(|source| {
            CrashDurableReceiveError::NamespaceSync {
                path: final_path.clone(),
                source,
            }
        })?;
        Ok(CrashDurableReceivePublication {
            final_path,
            durability: ReceiveDurability::FileAndNamespaceSynced,
        })
    }
}

/// Persist an already-verified in-memory file and cross the same crash-durability
/// boundary used by [`CrashDurableIncomingFileStager`].
///
/// The legacy helper remains unchanged; protected callers can opt into this stricter
/// contract without altering ordinary file-transfer behavior.
pub fn persist_received_file_crash_durable(
    path: &Path,
    contents: &[u8],
) -> Result<CrashDurableReceivePublication, CrashDurableReceiveError> {
    persist_received_file(path, contents)?;
    sync_receive_parent_directory(path).map_err(|source| {
        CrashDurableReceiveError::NamespaceSync {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(CrashDurableReceivePublication {
        final_path: path.to_path_buf(),
        durability: ReceiveDurability::FileAndNamespaceSynced,
    })
}

fn receive_parent(path: &Path) -> io::Result<&Path> {
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "received-file destination has no filename",
        ));
    }
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        _ => Ok(Path::new(".")),
    }
}

/// Synchronize the directory containing a published received file.
///
/// Unix is implemented explicitly because opening and syncing a directory is a stable
/// primitive there. Other target families remain fail-closed until their equivalent
/// durable-directory semantics are implemented and qualified rather than assuming that
/// a successful file close implies durable namespace publication.
#[cfg(unix)]
pub fn sync_receive_parent_directory(path: &Path) -> io::Result<()> {
    let parent = receive_parent(path)?;
    std::fs::File::open(parent)?.sync_all()
}

/// Fail closed where Xenia has not yet qualified a directory-sync implementation.
#[cfg(not(unix))]
pub fn sync_receive_parent_directory(path: &Path) -> io::Result<()> {
    let _ = receive_parent(path)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "crash-durable receive directory sync is not implemented on this platform",
    ))
}

/// Protected receive publication failures.
#[derive(Debug, Error)]
pub enum CrashDurableReceiveError {
    /// Incremental verification, file synchronization, or no-clobber publication failed.
    #[error(transparent)]
    Stage(#[from] IncomingFileStageError),
    /// In-memory verified-file publication failed before directory synchronization.
    #[error(transparent)]
    Publish(#[from] io::Error),
    /// Final pathname publication could not be made crash-durable.
    #[error("failed to synchronize receive namespace for {path}: {source}")]
    NamespaceSync {
        /// Final protected receive path.
        path: PathBuf,
        /// Directory synchronization failure.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xenia-crash-durable-receive-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).expect("create test directory");
        path
    }

    #[cfg(unix)]
    #[test]
    fn in_memory_publish_crosses_file_and_namespace_sync_boundary() {
        let dir = temp_dir();
        let path = dir.join("evidence.bin");
        let publication = persist_received_file_crash_durable(&path, b"evidence")
            .expect("crash-durable publish");
        assert_eq!(publication.final_path(), path.as_path());
        assert_eq!(
            publication.durability(),
            ReceiveDurability::FileAndNamespaceSynced
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"evidence");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn incremental_publish_requires_verified_complete_content_before_namespace_sync() {
        let dir = temp_dir();
        let path = dir.join("streamed.bin");
        let payload = b"abcdefgh";
        let hash = *blake3::hash(payload).as_bytes();
        let mut stager = CrashDurableIncomingFileStager::create(
            &path,
            payload.len() as u64,
            hash,
        )
        .unwrap();
        assert_eq!(stager.append(0, &payload[..3]).unwrap(), 3);
        assert_eq!(stager.append(3, &payload[3..]).unwrap(), 8);
        let publication = stager.finish().expect("verified durable publish");
        assert_eq!(publication.final_path(), path.as_path());
        assert_eq!(std::fs::read(&path).unwrap(), payload);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn durable_publish_preserves_no_clobber_contract() {
        let dir = temp_dir();
        let path = dir.join("existing.bin");
        std::fs::write(&path, b"original").unwrap();
        assert!(persist_received_file_crash_durable(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn unsupported_platform_refuses_crash_durability_claim() {
        let path = Path::new("evidence.bin");
        let err = sync_receive_parent_directory(path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
