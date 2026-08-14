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
