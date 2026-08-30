// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Descriptor-relative directory trust for Xenia security-sensitive filesystem state.
//!
//! The Unix implementation walks every pathname component relative to an already-open
//! directory descriptor and opens each component with `O_DIRECTORY | O_NOFOLLOW`.
//! `..` traversal is rejected. Missing components are created descriptor-relative and
//! then reopened through the same no-follow path. The final directory must be owned by
//! the current uid and is tightened to mode `0700` through the verified descriptor.
//!
//! This closes a narrower but important gap in a one-shot
//! `openat(CWD, "a/b/c", O_NOFOLLOW, ...)`: POSIX `O_NOFOLLOW` protects the trailing
//! component, not every earlier component.
//!
//! # Important claim boundary
//!
//! A [`TrustedDirectory`] is strongest when subsequent sensitive operations remain
//! descriptor-relative to [`TrustedDirectory::as_file`]. Merely validating a pathname
//! here and later reopening the same pathname through an unrelated path-based API does
//! **not** eliminate a second path-resolution race. Path-based consumers such as a stock
//! SQLite VFS therefore need an additional deployment-controlled authority-root policy
//! (or a separately qualified descriptor-aware/platform-specific strategy).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use thiserror::Error;

#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::Component;
#[cfg(unix)]
use rustix::fs::{CWD, Mode, OFlags, mkdirat, openat};

/// A directory whose final component has been opened and verified under the V1 trust rules.
#[derive(Debug)]
pub struct TrustedDirectory {
    path: PathBuf,
    #[cfg(unix)]
    file: File,
}

impl TrustedDirectory {
    /// Original caller-supplied path represented by this trusted directory descriptor.
    ///
    /// This path is evidence/debug metadata only. Security-sensitive leaf operations should
    /// remain relative to [`Self::as_file`] instead of re-resolving this path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrow the verified directory descriptor for descriptor-relative child operations.
    #[cfg(unix)]
    pub fn as_file(&self) -> &File {
        &self.file
    }

    /// Synchronize the verified directory descriptor.
    #[cfg(unix)]
    pub fn sync_all(&self) -> Result<(), PathTrustError> {
        self.file.sync_all()?;
        Ok(())
    }
}

/// Open or create a private directory without following a symlink in any traversed Unix
/// pathname component.
///
/// V1 requires at least one normal directory component, rejects `..`, opens each component
/// descriptor-relative with `O_NOFOLLOW`, and requires the final directory to be owned by
/// the current uid. The final directory is tightened to `0700` through the verified fd.
pub fn open_or_create_private_directory(
    path: impl AsRef<Path>,
) -> Result<TrustedDirectory, PathTrustError> {
    #[cfg(unix)]
    {
        open_or_create_private_directory_unix(path.as_ref())
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err(PathTrustError::UnsupportedPlatform)
    }
}

/// Path-trust validation or filesystem failure.
#[derive(Debug, Error)]
pub enum PathTrustError {
    /// This first contract only qualifies Unix descriptor-relative traversal.
    #[error("xenia-path-trust V1 is only implemented for Unix")]
    UnsupportedPlatform,
    /// A private directory target must identify at least one normal path component.
    #[error("private directory path must contain at least one normal component")]
    NoDirectoryComponents,
    /// Parent traversal would escape the descriptor chain and is rejected.
    #[error("parent traversal '..' is not allowed in trusted directory path: {0}")]
    ParentTraversal(String),
    /// A platform/path component form is outside this V1 contract.
    #[error("unsupported trusted path component in: {0}")]
    UnsupportedPathComponent(String),
    /// A traversed component was a symlink and was refused by `O_NOFOLLOW`.
    #[error("symlink component refused while opening trusted path: {0}")]
    SymlinkComponent(String),
    /// A traversed component was not a directory.
    #[error("non-directory component encountered while opening trusted path: {0}")]
    NotDirectory(String),
    /// The final private directory is not owned by the current uid.
    #[error("final trusted directory owner uid {owner_uid} does not match current uid {current_uid}: {path}")]
    OwnerMismatch {
        /// Final directory path for diagnostics.
        path: String,
        /// Owner uid observed on the opened directory descriptor.
        owner_uid: u32,
        /// Current process uid required by the V1 policy.
        current_uid: u32,
    },
    /// Underlying I/O failure.
    #[error("filesystem I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(unix)]
fn open_or_create_private_directory_unix(path: &Path) -> Result<TrustedDirectory, PathTrustError> {
    let original = path.to_path_buf();
    let (absolute, components) = normalized_components(path)?;

    let start = if absolute { Path::new("/") } else { Path::new(".") };
    let mut current = File::from(
        openat(
            CWD,
            start,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno_to_io)?,
    );

    let mut display_path = if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };

    for component in &components {
        display_path.push(component);
        current = open_or_create_directory_component(&current, component, &display_path)?;
    }

    let metadata = current.metadata()?;
    if !metadata.is_dir() {
        return Err(PathTrustError::NotDirectory(path_string(&original)));
    }
    let current_uid = rustix::process::getuid().as_raw();
    if !owner_is_trusted(metadata.uid(), current_uid) {
        return Err(PathTrustError::OwnerMismatch {
            path: path_string(&original),
            owner_uid: metadata.uid(),
            current_uid,
        });
    }

    current.set_permissions(std::fs::Permissions::from_mode(0o700))?;

    Ok(TrustedDirectory {
        path: original,
        file: current,
    })
}

#[cfg(unix)]
fn normalized_components(path: &Path) -> Result<(bool, Vec<OsString>), PathTrustError> {
    let absolute = path.is_absolute();
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            Component::ParentDir => {
                return Err(PathTrustError::ParentTraversal(path_string(path)));
            }
            Component::Prefix(_) => {
                return Err(PathTrustError::UnsupportedPathComponent(path_string(path)));
            }
        }
    }

    if components.is_empty() {
        return Err(PathTrustError::NoDirectoryComponents);
    }
    Ok((absolute, components))
}

#[cfg(unix)]
fn open_or_create_directory_component(
    parent: &File,
    component: &OsStr,
    display_path: &Path,
) -> Result<File, PathTrustError> {
    match open_directory_component(parent, component, display_path) {
        Ok(file) => Ok(file),
        Err(PathTrustError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            match mkdirat(parent, component, Mode::from(0o700)) {
                Ok(()) => parent.sync_all()?,
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => return Err(PathTrustError::Io(errno_to_io(error))),
            }
            open_directory_component(parent, component, display_path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn open_directory_component(
    parent: &File,
    component: &OsStr,
    display_path: &Path,
) -> Result<File, PathTrustError> {
    let fd = openat(
        parent,
        component,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            PathTrustError::SymlinkComponent(path_string(display_path))
        } else if error == rustix::io::Errno::NOTDIR {
            PathTrustError::NotDirectory(path_string(display_path))
        } else {
            PathTrustError::Io(errno_to_io(error))
        }
    })?;

    let file = File::from(fd);
    if !file.metadata()?.is_dir() {
        return Err(PathTrustError::NotDirectory(path_string(display_path)));
    }
    Ok(file)
}

#[cfg(unix)]
fn errno_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from(error)
}

#[cfg(unix)]
fn owner_is_trusted(owner_uid: u32, current_uid: u32) -> bool {
    owner_uid == current_uid
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn creates_and_tightens_final_private_directory() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("one/two/private");
        let trusted = open_or_create_private_directory(&private).unwrap();

        assert_eq!(trusted.path(), private.as_path());
        let metadata = trusted.as_file().metadata().unwrap();
        assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn retightens_existing_final_directory() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();

        let trusted = open_or_create_private_directory(&private).unwrap();
        assert_eq!(
            trusted.as_file().metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn rejects_intermediate_symlink_even_to_same_uid_directory() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let alias = root.path().join("alias");
        symlink(&target, &alias).unwrap();

        let error = open_or_create_private_directory(alias.join("private")).unwrap_err();
        assert!(matches!(error, PathTrustError::SymlinkComponent(_)));
        assert!(!target.join("private").exists());
    }

    #[test]
    fn rejects_final_symlink() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let alias = root.path().join("private");
        symlink(&target, &alias).unwrap();

        let error = open_or_create_private_directory(&alias).unwrap_err();
        assert!(matches!(error, PathTrustError::SymlinkComponent(_)));
    }

    #[test]
    fn rejects_parent_traversal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a/../private");
        let error = open_or_create_private_directory(path).unwrap_err();
        assert!(matches!(error, PathTrustError::ParentTraversal(_)));
    }

    #[test]
    fn descriptor_remains_bound_after_path_is_renamed() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("private");
        let moved = root.path().join("moved");
        let trusted = open_or_create_private_directory(&original).unwrap();
        std::fs::rename(&original, &moved).unwrap();

        let child = OsStr::new("descriptor-child");
        mkdirat(trusted.as_file(), child, Mode::from(0o700)).unwrap();
        trusted.sync_all().unwrap();

        assert!(moved.join(child).is_dir());
        assert!(!original.exists());
    }

    #[test]
    fn descriptor_relative_child_open_refuses_leaf_symlink() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private");
        let trusted = open_or_create_private_directory(&private).unwrap();
        let target = private.join("target");
        let mut target_file = std::fs::File::create(&target).unwrap();
        target_file.write_all(b"target").unwrap();
        let alias = private.join("alias");
        symlink(&target, &alias).unwrap();

        let result = openat(
            trusted.as_file(),
            OsStr::new("alias"),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        assert_eq!(result.unwrap_err(), rustix::io::Errno::LOOP);
    }

    #[test]
    fn exact_uid_ownership_rule_has_no_root_exception() {
        assert!(owner_is_trusted(1000, 1000));
        assert!(!owner_is_trusted(1000, 0));
        assert!(!owner_is_trusted(0, 1000));
    }
}
