// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trusted storage-root boundary for live Symthaea authority sources.
//!
//! The owner lock establishes exclusive process ownership. This module
//! establishes the separate storage theorem: the authority root and configured
//! policy/revocation source paths must resolve to objects the daemon can treat
//! as trusted. It intentionally does not implement a second identity system.

#![warn(missing_docs)]

use std::io;
use std::path::{Path, PathBuf};

/// Identity of a filesystem object captured for a long-lived source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoritySourceIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl AuthoritySourceIdentity {
    /// Capture the identity of an existing, non-symlink source file.
    pub fn capture(path: &Path) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("authority source must not be a symlink: {}", path.display()),
            ));
        }
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("authority source is not a regular file: {}", path.display()),
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            return Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            // Windows live-authority startup is rejected by validate() until
            // ACL ownership verification is qualified. Keeping this value
            // constructible preserves the legacy revocation API outside the
            // live-authority feature boundary.
            Ok(Self {})
        }
    }

    /// Re-check that the named source is still the same filesystem object.
    pub fn verify(&self, path: &Path) -> io::Result<()> {
        let current = Self::capture(path)?;
        if current != *self {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("authority source object identity changed: {}", path.display()),
            ));
        }
        Ok(())
    }
}

/// Validated trust boundary for one live Symthaea authority storage root.
#[derive(Debug, Clone)]
pub struct AuthorityStorageTrust {
    root: PathBuf,
    #[cfg(unix)]
    owner_uid: u32,
}

impl AuthorityStorageTrust {
    /// Validate and capture a trusted authority root.
    ///
    /// On Unix this requires a real directory owned by the current effective
    /// uid with no group/world write permission. On Windows the ACL/owner
    /// theorem is intentionally not guessed: until an explicit ACL ownership
    /// implementation is added, live authority startup fails closed.
    pub fn validate(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        let metadata = std::fs::symlink_metadata(root)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("authority storage root must not be a symlink: {}", root.display()),
            ));
        }
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("authority storage root is not a directory: {}", root.display()),
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "authority storage root is group/world writable: {}",
                        root.display()
                    ),
                ));
            }
            // libc is used only for the process identity comparison. The
            // filesystem metadata itself is obtained through safe std APIs.
            let owner_uid = unsafe { libc::geteuid() };
            if metadata.uid() != owner_uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "authority storage root owner uid {} does not match daemon uid {}",
                        metadata.uid(),
                        owner_uid
                    ),
                ));
            }
            return Ok(Self {
                root: root.to_path_buf(),
                owner_uid,
            });
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "live Symthaea authority storage trust is not qualified on Windows: explicit ACL ownership verification is required",
            ))
        }
    }

    /// Return the trusted root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Validate that a configured source is a direct child of the trusted
    /// root and is not a symlink. A missing source is allowed here so callers
    /// can preserve their existing initial-load semantics; capture its
    /// identity when the source must exist.
    pub fn validate_source_path(&self, path: &Path) -> io::Result<()> {
        if path.parent() != Some(self.root.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "authority source must be directly inside trusted root {}: {}",
                    self.root.display(),
                    path.display()
                ),
            ));
        }

        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("authority source must not be a symlink: {}", path.display()),
                ));
            }
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("authority source is not a regular file: {}", path.display()),
                ));
            }
        }

        Ok(())
    }

    /// Validate a generation ledger path against this root.
    pub fn validate_generation_path(&self, path: &Path) -> io::Result<()> {
        self.validate_child_path(path, "generation ledger")
    }

    /// Validate an issuance journal path against this root.
    pub fn validate_issuance_path(&self, path: &Path) -> io::Result<()> {
        self.validate_child_path(path, "issuance journal")
    }

    fn validate_child_path(&self, path: &Path, label: &str) -> io::Result<()> {
        if path.parent() != Some(self.root.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{label} must be directly inside trusted root {}: {}",
                    self.root.display(),
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    /// Return the Unix owner uid captured at validation time.
    #[cfg(unix)]
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_private_owned_root() {
        let root = tempfile::tempdir().unwrap();
        let trust = AuthorityStorageTrust::validate(root.path()).unwrap();
        assert_eq!(trust.root(), root.path());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_root() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = AuthorityStorageTrust::validate(root.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_root() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = AuthorityStorageTrust::validate(&link).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn source_must_be_direct_child_and_not_symlink() {
        let root = tempfile::tempdir().unwrap();
        let trust = AuthorityStorageTrust::validate(root.path()).unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let source = nested.join("operators.json");
        assert_eq!(
            trust.validate_source_path(&source).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let source = root.path().join("operators.json");
        std::fs::write(&source, b"{}").unwrap();
        let identity = AuthoritySourceIdentity::capture(&source).unwrap();
        identity.verify(&source).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn source_replacement_is_detected() {
        let root = tempfile::tempdir().unwrap();
        let trust = AuthorityStorageTrust::validate(root.path()).unwrap();
        let source = root.path().join("revoked.txt");
        std::fs::write(&source, b"alice\\n").unwrap();
        let identity = AuthoritySourceIdentity::capture(&source).unwrap();

        let replacement = root.path().join("replacement.txt");
        std::fs::write(&replacement, b"bob\\n").unwrap();
        std::fs::rename(&replacement, &source).unwrap();

        assert_eq!(
            identity.verify(&source).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(trust);
    }
}
