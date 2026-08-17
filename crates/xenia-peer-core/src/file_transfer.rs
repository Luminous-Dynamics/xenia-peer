// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Filesystem helpers for received-file delivery.
//!
//! A remote peer controls the offered basename, so a receiver must not turn a
//! successful integrity check into permission to overwrite an arbitrary
//! pre-existing file in the configured receive directory. [`persist_received_file`]
//! stages verified bytes under a private temporary name and then publishes the
//! completed inode with a no-clobber hard link. The final basename is therefore
//! either absent or points at a fully written file; a crash during the write
//! cannot expose a partial file under the final name.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const STAGING_ATTEMPTS: usize = 32;
const RECEIVE_STAGING_PREFIX: &str = ".xenia-receive-";
const RECEIVE_STAGING_SUFFIX: &str = ".tmp";

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

fn open_staging_file(parent: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..STAGING_ATTEMPTS {
        let staging_path = parent.join(format!(
            ".xenia-receive-{}-{:016x}{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>(),
            rand::random::<u64>()
        ));

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&staging_path) {
            Ok(file) => return Ok((staging_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique received-file staging path",
    ))
}

fn owned_receive_staging_pid(name: &str) -> Option<u32> {
    let Some(body) = name
        .strip_prefix(RECEIVE_STAGING_PREFIX)
        .and_then(|body| body.strip_suffix(RECEIVE_STAGING_SUFFIX))
    else {
        return None;
    };
    let Some((pid, token)) = body.split_once('-') else {
        return None;
    };
    if pid.is_empty()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || token.len() != 32
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    pid.parse().ok()
}

/// Remove stale receive-staging paths left behind by an earlier process crash.
///
/// The matcher accepts only Xenia's reserved private staging namespace
/// (`.xenia-receive-<pid>-<32 hex>.tmp`), so unrelated dot files are never
/// selected. Entries owned by the current process ID are preserved so starting
/// another session in the same process cannot delete a live transfer. Individual
/// removal failures are warned and do not prevent the remaining stale entries
/// from being considered.
///
/// Returns the number of staging directory entries successfully removed. A
/// missing directory is treated as an empty directory; other `read_dir`
/// failures are returned to the caller.
pub fn cleanup_orphaned_receive_staging(dir: &Path) -> io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut removed = 0;
    let current_pid = std::process::id();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(error = %err, "received-file staging directory entry could not be read");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(owner_pid) = owned_receive_staging_pid(name) else {
            continue;
        };
        if owner_pid == current_pid {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => tracing::warn!(
                path = %entry.path().display(),
                error = %err,
                "orphaned received-file staging path could not be removed"
            ),
        }
    }
    Ok(removed)
}

/// Incremental receive-staging failure.
#[derive(Debug, thiserror::Error)]
pub enum IncomingFileStageError {
    /// A chunk did not begin exactly where the previous accepted chunk ended.
    #[error("unexpected file chunk offset: expected {expected}, got {actual}")]
    UnexpectedOffset {
        /// Next required byte offset.
        expected: u64,
        /// Offset supplied by the peer.
        actual: u64,
    },
    /// A chunk would extend beyond the size committed by the authenticated offer.
    #[error("file chunk exceeds offered size {expected_size}: end offset {attempted_end}")]
    SizeExceeded {
        /// Size committed by the offer.
        expected_size: u64,
        /// Exclusive end offset the chunk would produce.
        attempted_end: u64,
    },
    /// `Complete` arrived before exactly the offered byte count was staged.
    #[error("received file size mismatch: expected {expected}, got {actual}")]
    SizeMismatch {
        /// Size committed by the offer.
        expected: u64,
        /// Bytes staged before completion.
        actual: u64,
    },
    /// The incrementally computed BLAKE3 digest did not match the offer.
    #[error("received file failed BLAKE3 verification")]
    HashMismatch,
    /// Filesystem staging or publication failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Disk-backed, strictly sequential receiver for one authenticated file offer.
///
/// The stager writes each accepted chunk directly into a private same-directory
/// temporary inode, updates BLAKE3 incrementally, and requires `offset` to equal
/// the exact number of bytes already accepted. [`Self::finish`] verifies both
/// the committed size and hash, syncs the inode, then publishes it with the same
/// no-clobber hard-link rule as [`persist_received_file`]. Dropping an unfinished
/// stager removes its private temporary path best-effort.
pub struct IncomingFileStager {
    final_path: PathBuf,
    staging_path: PathBuf,
    file: Option<File>,
    hasher: blake3::Hasher,
    expected_size: u64,
    expected_hash: [u8; 32],
    received: u64,
}

impl IncomingFileStager {
    /// Create private receive staging for an authenticated file offer.
    pub fn create(
        final_path: &Path,
        expected_size: u64,
        expected_hash: [u8; 32],
    ) -> Result<Self, IncomingFileStageError> {
        let parent = receive_parent(final_path)?;
        let (staging_path, file) = open_staging_file(parent)?;
        Ok(Self {
            final_path: final_path.to_path_buf(),
            staging_path,
            file: Some(file),
            hasher: blake3::Hasher::new(),
            expected_size,
            expected_hash,
            received: 0,
        })
    }

    /// Append the next exact sequential chunk and return total staged bytes.
    pub fn append(&mut self, offset: u64, bytes: &[u8]) -> Result<u64, IncomingFileStageError> {
        if offset != self.received {
            return Err(IncomingFileStageError::UnexpectedOffset {
                expected: self.received,
                actual: offset,
            });
        }
        let chunk_len =
            u64::try_from(bytes.len()).map_err(|_| IncomingFileStageError::SizeExceeded {
                expected_size: self.expected_size,
                attempted_end: u64::MAX,
            })?;
        let attempted_end =
            self.received
                .checked_add(chunk_len)
                .ok_or(IncomingFileStageError::SizeExceeded {
                    expected_size: self.expected_size,
                    attempted_end: u64::MAX,
                })?;
        if attempted_end > self.expected_size {
            return Err(IncomingFileStageError::SizeExceeded {
                expected_size: self.expected_size,
                attempted_end,
            });
        }
        let file = self.file.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "receive stager is already closed",
            )
        })?;
        file.write_all(bytes)?;
        self.hasher.update(bytes);
        self.received = attempted_end;
        Ok(self.received)
    }

    /// Verify size/hash, sync staged bytes, and publish without clobbering.
    pub fn finish(mut self) -> Result<(), IncomingFileStageError> {
        if self.received != self.expected_size {
            return Err(IncomingFileStageError::SizeMismatch {
                expected: self.expected_size,
                actual: self.received,
            });
        }
        if self.hasher.finalize().as_bytes() != &self.expected_hash {
            return Err(IncomingFileStageError::HashMismatch);
        }
        if let Some(file) = self.file.take() {
            file.sync_all()?;
            drop(file);
        }
        std::fs::hard_link(&self.staging_path, &self.final_path)?;
        Ok(())
    }

    /// Number of bytes successfully staged so far.
    pub fn received_bytes(&self) -> u64 {
        self.received
    }
}

impl Drop for IncomingFileStager {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Err(err) = std::fs::remove_file(&self.staging_path) {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.staging_path.display(),
                    error = %err,
                    "received-file staging path could not be removed"
                );
            }
        }
    }
}

/// Persist a verified received file without clobbering an existing path.
///
/// Bytes are first written and synced to a private staging file in the same
/// directory. `hard_link` then publishes that completed inode at `path`; link
/// creation is atomic and fails when the destination already exists, including
/// when the final component is a symlink. This gives receivers both no-clobber
/// behavior and crash-atomic final-name publication without relying on
/// platform-specific rename flags.
///
/// On Unix the staging inode is private to the receiving user at creation
/// (`0600`). Any staging file is cleaned up best-effort on failure. Once the
/// final hard link has been created, failure to remove the hidden staging name
/// does not turn a successful delivery into a negative receipt.
///
/// Callers should only report transfer success after this function returns
/// `Ok(())`.
pub fn persist_received_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = receive_parent(path)?;
    let (staging_path, mut staging_file) = open_staging_file(parent)?;

    if let Err(err) = staging_file
        .write_all(contents)
        .and_then(|()| staging_file.sync_all())
    {
        drop(staging_file);
        let _ = std::fs::remove_file(&staging_path);
        return Err(err);
    }
    drop(staging_file);

    if let Err(err) = std::fs::hard_link(&staging_path, path) {
        let _ = std::fs::remove_file(&staging_path);
        return Err(err);
    }

    if let Err(err) = std::fs::remove_file(&staging_path) {
        tracing::warn!(
            path = %staging_path.display(),
            error = %err,
            "received-file staging link could not be removed after successful publication"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xenia-peer-core-receive-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).expect("create test receive directory");
        path
    }

    fn staging_files(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .expect("read test receive directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".xenia-receive-"))
            })
            .collect()
    }

    #[test]
    fn orphan_cleanup_only_removes_owned_receive_staging_names() {
        let dir = temp_dir();
        let stale_pid = std::process::id().wrapping_add(1).max(1);
        let owned = dir.join(format!(
            ".xenia-receive-{stale_pid}-0123456789abcdef0123456789abcdef.tmp"
        ));
        let live = dir.join(format!(
            ".xenia-receive-{}-fedcba9876543210fedcba9876543210.tmp",
            std::process::id()
        ));
        let unrelated = [
            dir.join(".xenia-receive-not-a-pid-0123456789abcdef0123456789abcdef.tmp"),
            dir.join(".xenia-receive-1234-short.tmp"),
            dir.join(".xenia-receive-1234-0123456789abcdef0123456789abcdef.txt"),
            dir.join("notes.tmp"),
        ];
        std::fs::write(&owned, b"partial").unwrap();
        std::fs::write(&live, b"active").unwrap();
        for path in &unrelated {
            std::fs::write(path, b"keep").unwrap();
        }

        assert_eq!(cleanup_orphaned_receive_staging(&dir).unwrap(), 1);
        assert!(!owned.exists());
        assert!(live.exists());
        for path in &unrelated {
            assert!(
                path.exists(),
                "unrelated path was removed: {}",
                path.display()
            );
        }

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn incremental_stager_requires_exact_offsets_and_publishes_verified_bytes() {
        let dir = temp_dir();
        let path = dir.join("streamed.bin");
        let payload = b"abcdefgh";
        let hash = *blake3::hash(payload).as_bytes();
        let mut stager = IncomingFileStager::create(&path, payload.len() as u64, hash)
            .expect("create receive staging");

        assert_eq!(stager.append(0, &payload[..3]).unwrap(), 3);
        assert!(matches!(
            stager.append(4, &payload[3..4]),
            Err(IncomingFileStageError::UnexpectedOffset {
                expected: 3,
                actual: 4
            })
        ));
        assert_eq!(
            stager.append(3, &payload[3..]).unwrap(),
            payload.len() as u64
        );
        stager.finish().expect("verified publish");

        assert_eq!(std::fs::read(&path).unwrap(), payload);
        assert!(staging_files(&dir).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn incremental_stager_rejects_overrun_hash_mismatch_and_cleans_partial_files() {
        let dir = temp_dir();
        let overrun_path = dir.join("overrun.bin");
        let mut overrun =
            IncomingFileStager::create(&overrun_path, 2, *blake3::hash(b"ok").as_bytes()).unwrap();
        assert!(matches!(
            overrun.append(0, b"toolong"),
            Err(IncomingFileStageError::SizeExceeded { .. })
        ));
        drop(overrun);
        assert!(!overrun_path.exists());
        assert!(staging_files(&dir).is_empty());

        let hash_path = dir.join("hash.bin");
        let mut hash =
            IncomingFileStager::create(&hash_path, 3, *blake3::hash(b"abc").as_bytes()).unwrap();
        hash.append(0, b"abd").unwrap();
        assert!(matches!(
            hash.finish(),
            Err(IncomingFileStageError::HashMismatch)
        ));
        assert!(!hash_path.exists());
        assert!(staging_files(&dir).is_empty());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persists_new_file_and_refuses_clobber() {
        let dir = temp_dir();
        let path = dir.join("received.txt");

        persist_received_file(&path, b"first").expect("first delivery succeeds");
        assert!(staging_files(&dir).is_empty());

        let err = persist_received_file(&path, b"second").expect_err("clobber must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read delivered file"), b"first");
        assert!(staging_files(&dir).is_empty());

        std::fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir();
        let target = dir.join("target.txt");
        let offered = dir.join("offered.txt");
        std::fs::write(&target, b"safe").expect("write target fixture");
        symlink(&target, &offered).expect("create symlink fixture");

        persist_received_file(&offered, b"attacker").expect_err("symlink delivery must fail");
        assert_eq!(std::fs::read(&target).expect("read target"), b"safe");
        assert!(staging_files(&dir).is_empty());

        std::fs::remove_dir_all(dir).expect("remove test directory");
    }
}
