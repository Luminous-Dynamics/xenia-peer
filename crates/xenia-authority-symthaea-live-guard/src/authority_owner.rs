// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-process ownership for a live Symthaea authority storage root.
//!
//! The in-process LiveAuthorityGuard serializes authority operations within
//! one daemon. This type establishes the outer ownership theorem: exactly one
//! live process may own a configured authority root at a time.
//!
//! The lock is deliberately held by an owned std::fs::File for the lifetime
//! of AuthorityOwnerLock. Rust's standard-library file locking is used rather
//! than a PID file: the kernel releases the lock when the owner closes the
//! handle or the process exits.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Durable cross-process owner lock for one live authority storage root.
#[derive(Debug)]
pub struct AuthorityOwnerLock {
    file: File,
    path: PathBuf,
}

impl AuthorityOwnerLock {
    /// Acquire the exclusive owner lock for root.
    ///
    /// root must already exist and be a directory. The lock file is created
    /// inside that directory and is never replaced while this type is alive.
    /// Failure to acquire the lock is fatal to authority initialization.
    pub fn acquire(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("authority storage root is not a directory: {}", root.display()),
            ));
        }

        let path = root.join(".xenia-symthaea-authority.owner.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("authority storage root is already owned: {}", root.display()),
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;

        Ok(Self { file, path })
    }

    /// Acquire ownership using the parent directory of a generation ledger path.\n    ///\n    /// This keeps generation state and its live owner in the same storage root.\n    pub fn acquire_for_generation_path(path: impl AsRef<Path>) -> io::Result<Self> {\n        let path = path.as_ref();\n        let root = path.parent().unwrap_or_else(|| Path::new("."));\n        Self::acquire(root)\n    }\n\n    /// Return the exact lock path held by this owner.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly release the kernel lock.
    ///
    /// Dropping the owner also releases it; this method exists for tests and
    /// controlled shutdown paths that want an explicit release point.
    pub fn release(self) -> io::Result<()> {
        self.file.unlock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_owner_cannot_acquire_same_root() {
        let root = tempfile::tempdir().unwrap();
        let first = AuthorityOwnerLock::acquire(root.path()).unwrap();
        let second = AuthorityOwnerLock::acquire(root.path());
        assert!(matches!(second, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
        drop(first);
        AuthorityOwnerLock::acquire(root.path()).unwrap();
    }

    #[test]
    fn rejects_non_directory_root() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("not-a-directory");
        std::fs::write(&file, b"x").unwrap();
        let error = AuthorityOwnerLock::acquire(&file).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotADirectory);
    }

    #[test]
    fn lock_path_is_stable_and_root_scoped() {
        let root = tempfile::tempdir().unwrap();
        let owner = AuthorityOwnerLock::acquire(root.path()).unwrap();
        assert_eq!(
            owner.path(),
            root.path().join(".xenia-symthaea-authority.owner.lock")
        );
    }
}
