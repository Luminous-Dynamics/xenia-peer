// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private staged snapshots for strict SIF protected-file disclosure.
//!
//! Hashing a live file and later streaming the same open inode narrows pathname TOCTOU,
//! but another writer can still modify that inode while bytes are being emitted. A final
//! second-pass BLAKE3 catches the mutation before successful completion, yet it cannot
//! retroactively prevent already-emitted changed bytes.
//!
//! This module therefore stages the selected source into a fresh Xenia-owned private
//! snapshot **before** release authority is bound. The snapshot bytes themselves become
//! the object whose length/BLAKE3 are authorized. On Unix, after `TransferSource` opens
//! the completed snapshot, the staging pathname is immediately unlinked and its private
//! directory is removed. The bytes remain reachable only through Xenia's owned file
//! descriptor. On platforms where unlink-while-open is unavailable, the snapshot keeps
//! one random private pathname until the owned source is dropped; this is a weaker
//! same-user isolation posture and is reported explicitly by [`SifStagedSourceIsolation`].

use std::fs::{DirBuilder, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use xenia_ledger::{Chain, MAX_SIF_PROTECTED_FILE_NAME_BYTES, ProfileBoundFileOfferAuthority};
use xenia_peer_core::{TransferSource, TransferSourceError};

use crate::sif_accountable_transfer::ReadyAccountableSifSession;
use crate::sif_profile_bound_source::{ProfileBoundOwnedSource, ProfileBoundOwnedSourceError};

const SNAPSHOT_BUFFER_BYTES: usize = 64 * 1024;
const SNAPSHOT_ATTEMPTS: usize = 16;

/// Filesystem isolation achieved for the staged snapshot after it is opened for send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SifStagedSourceIsolation {
    /// Unix snapshot pathname was removed after opening; only the owned descriptor remains.
    UnixUnlinkedHandle,
    /// Snapshot remains under one random private pathname until the source is dropped.
    PrivateNamedSnapshot,
}

#[derive(Debug)]
struct SnapshotPathGuard {
    file: Option<PathBuf>,
    dir: Option<PathBuf>,
}

impl SnapshotPathGuard {
    fn disarm_file(&mut self) {
        self.file = None;
    }

    fn disarm_dir(&mut self) {
        self.dir = None;
    }
}

impl Drop for SnapshotPathGuard {
    fn drop(&mut self) {
        if let Some(path) = self.file.take() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(path) = self.dir.take() {
            let _ = std::fs::remove_dir(path);
        }
    }
}

/// A private, pre-authorizable SIF source snapshot.
///
/// `size` and `content_blake3` describe the staged bytes, not mutable source-path
/// metadata. The inner `TransferSource` later performs an independent second streaming
/// verification over the same staged object.
#[derive(Debug)]
pub struct SifStagedSource {
    source: TransferSource,
    display_name: String,
    size: u64,
    content_blake3: [u8; 32],
    isolation: SifStagedSourceIsolation,
}

impl SifStagedSource {
    /// Copy one local file into a fresh private Xenia staging snapshot.
    ///
    /// `display_name` is the exact authenticated wire-visible basename that downstream
    /// release authority must commit. The staged byte count is enforced while copying,
    /// so source growth cannot bypass `max_bytes` after an initial metadata check.
    pub async fn stage_file(
        path: &Path,
        display_name: impl Into<String>,
        max_bytes: u64,
    ) -> Result<Self, SifStagedSourceError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;

        let mut input = tokio::fs::File::open(path).await?;
        let metadata_len = input.metadata().await?.len();
        if metadata_len > max_bytes {
            return Err(SifStagedSourceError::SizeLimitExceeded {
                max_bytes,
                observed_bytes: metadata_len,
            });
        }

        let (snapshot_dir, snapshot_path, std_output) = create_private_snapshot_path()?;
        let mut guard = SnapshotPathGuard {
            file: Some(snapshot_path.clone()),
            dir: snapshot_dir.clone(),
        };
        let mut output = tokio::fs::File::from_std(std_output);
        let mut hasher = blake3::Hasher::new();
        let mut size = 0_u64;
        let mut buffer = vec![0_u8; SNAPSHOT_BUFFER_BYTES];

        loop {
            let read = input.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            let read_u64 = u64::try_from(read).map_err(|_| SifStagedSourceError::SizeOverflow)?;
            let next = size
                .checked_add(read_u64)
                .ok_or(SifStagedSourceError::SizeOverflow)?;
            if next > max_bytes {
                return Err(SifStagedSourceError::SizeLimitExceeded {
                    max_bytes,
                    observed_bytes: next,
                });
            }
            output.write_all(&buffer[..read]).await?;
            hasher.update(&buffer[..read]);
            size = next;
        }

        output.flush().await?;
        output.sync_all().await?;
        drop(output);
        drop(input);

        let content_blake3 = *hasher.finalize().as_bytes();
        let source = TransferSource::open_prehashed_file(
            snapshot_path.clone(),
            size,
            content_blake3,
            true,
        )
        .await?;

        // TransferSource now owns cleanup of the named snapshot on platforms that keep
        // it. Avoid a second guard deletion of the same path.
        guard.disarm_file();

        #[cfg(unix)]
        let isolation = {
            std::fs::remove_file(&snapshot_path)?;
            if let Some(dir) = snapshot_dir {
                std::fs::remove_dir(&dir)?;
                guard.disarm_dir();
            }
            SifStagedSourceIsolation::UnixUnlinkedHandle
        };

        #[cfg(not(unix))]
        let isolation = SifStagedSourceIsolation::PrivateNamedSnapshot;

        Ok(Self {
            source,
            display_name,
            size,
            content_blake3,
            isolation,
        })
    }

    /// Exact authenticated display name to bind into upstream file authority.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Exact staged byte length to bind into upstream file authority.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Exact staged BLAKE3 to bind into upstream file authority.
    pub const fn content_blake3(&self) -> [u8; 32] {
        self.content_blake3
    }

    /// Isolation achieved after the completed snapshot was opened for streaming.
    pub const fn isolation(&self) -> SifStagedSourceIsolation {
        self.isolation
    }

    /// Consume the staged snapshot directly into the profile-bound source/journal path.
    ///
    /// The authority-derived Offer must use the same display name, size and BLAKE3.
    /// [`ProfileBoundOwnedSource::new`] then independently rechecks size/hash and reads
    /// the authenticated negotiated profile from `session` rather than accepting a free
    /// profile digest.
    pub fn bind_profile_authority(
        self,
        authority: ProfileBoundFileOfferAuthority,
        session: &ReadyAccountableSifSession,
        chain: &Chain,
    ) -> Result<ProfileBoundOwnedSource, SifStagedSourceBindError> {
        if authority.offer().display_name() != self.display_name {
            return Err(SifStagedSourceBindError::DisplayNameMismatch);
        }
        if authority.offer().size() != self.size {
            return Err(SifStagedSourceBindError::SizeMismatch);
        }
        if authority.offer().content_blake3() != self.content_blake3 {
            return Err(SifStagedSourceBindError::HashMismatch);
        }
        Ok(ProfileBoundOwnedSource::new(
            authority,
            self.source,
            session,
            chain,
        )?)
    }

    /// Consume into the lower-level owned transfer source.
    ///
    /// Prefer [`Self::bind_profile_authority`] for high-assurance SIF. This escape hatch
    /// exists for compatibility/testing and does not by itself prove profile-bound
    /// disclosure authority.
    pub fn into_transfer_source(self) -> TransferSource {
        self.source
    }
}

/// Failure while creating a private staged source snapshot.
#[derive(Debug, Error)]
pub enum SifStagedSourceError {
    /// Wire-visible display name is not a bounded bare filename.
    #[error("SIF staged-source display name must be a bounded bare filename")]
    InvalidDisplayName,
    /// Source exceeded the staging byte limit.
    #[error("SIF staged source exceeds {max_bytes}-byte limit (observed {observed_bytes})")]
    SizeLimitExceeded {
        /// Configured maximum staged bytes.
        max_bytes: u64,
        /// Observed bytes before refusal.
        observed_bytes: u64,
    },
    /// Staged byte arithmetic overflowed.
    #[error("SIF staged-source byte count overflow")]
    SizeOverflow,
    /// A unique private staging path could not be allocated.
    #[error("could not allocate a unique private SIF staged-source path")]
    StagingPathExhausted,
    /// Filesystem I/O failed while snapshotting or unlinking.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The completed snapshot could not become a `TransferSource`.
    #[error(transparent)]
    TransferSource(#[from] TransferSourceError),
}

/// Failure while joining a staged snapshot to durable profile-bound file authority.
#[derive(Debug, Error)]
pub enum SifStagedSourceBindError {
    /// Authority uses a different authenticated display name.
    #[error("staged source display name does not match profile-bound Offer authority")]
    DisplayNameMismatch,
    /// Authority uses a different staged byte length.
    #[error("staged source size does not match profile-bound Offer authority")]
    SizeMismatch,
    /// Authority uses a different staged BLAKE3.
    #[error("staged source BLAKE3 does not match profile-bound Offer authority")]
    HashMismatch,
    /// Lower profile-bound source/journal composition failed.
    #[error(transparent)]
    OwnedSource(#[from] ProfileBoundOwnedSourceError),
}

fn validate_display_name(name: &str) -> Result<(), SifStagedSourceError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.len() > MAX_SIF_PROTECTED_FILE_NAME_BYTES
    {
        return Err(SifStagedSourceError::InvalidDisplayName);
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_snapshot_path(
) -> Result<(Option<PathBuf>, PathBuf, std::fs::File), SifStagedSourceError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    for _ in 0..SNAPSHOT_ATTEMPTS {
        let token = Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!(
            ".xenia-sif-source-{}-{token}",
            std::process::id()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }

        let path = dir.join("source.snapshot");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&path) {
            Ok(file) => return Ok((Some(dir), path, file)),
            Err(error) => {
                let _ = std::fs::remove_dir(&dir);
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error.into());
            }
        }
    }
    Err(SifStagedSourceError::StagingPathExhausted)
}

#[cfg(not(unix))]
fn create_private_snapshot_path(
) -> Result<(Option<PathBuf>, PathBuf, std::fs::File), SifStagedSourceError> {
    for _ in 0..SNAPSHOT_ATTEMPTS {
        let path = std::env::temp_dir().join(format!(
            ".xenia-sif-source-{}-{}.snapshot",
            std::process::id(),
            Uuid::new_v4()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(&path) {
            Ok(file) => return Ok((None, path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(SifStagedSourceError::StagingPathExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "xenia-sif-stage-test-{}-{}-{name}",
            std::process::id(),
            Uuid::new_v4()
        ))
    }

    #[tokio::test]
    async fn staged_source_is_decoupled_from_later_original_path_mutation() {
        let path = source_path("original.bin");
        let original = b"authorized snapshot bytes".to_vec();
        std::fs::write(&path, &original).unwrap();

        let staged = SifStagedSource::stage_file(&path, "evidence.bin", 1024)
            .await
            .unwrap();
        assert_eq!(staged.size(), original.len() as u64);
        assert_eq!(staged.content_blake3(), *blake3::hash(&original).as_bytes());

        // Mutating the original pathname after staging must not alter the staged object.
        std::fs::write(&path, b"different live source bytes").unwrap();
        let mut source = staged.into_transfer_source();
        let mut rebuilt = Vec::new();
        while let Some(chunk) = source.next_chunk(5).await.unwrap() {
            rebuilt.extend_from_slice(&chunk.data);
        }
        assert_eq!(rebuilt, original);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_staged_source_unlinks_snapshot_path_before_return() {
        let path = source_path("unlink.bin");
        std::fs::write(&path, b"abc").unwrap();
        let staged = SifStagedSource::stage_file(&path, "evidence.bin", 16)
            .await
            .unwrap();
        assert_eq!(
            staged.isolation(),
            SifStagedSourceIsolation::UnixUnlinkedHandle
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn staging_enforces_source_limit() {
        let path = source_path("limit.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let error = SifStagedSource::stage_file(&path, "evidence.bin", 4)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            SifStagedSourceError::SizeLimitExceeded { .. }
        ));
        std::fs::remove_file(path).unwrap();
    }
}
