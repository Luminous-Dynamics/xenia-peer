// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Filesystem helpers for received-file delivery.
//!
//! A remote peer controls the offered basename, so a receiver must not turn a
//! successful integrity check into permission to overwrite an arbitrary
//! pre-existing file in the configured receive directory. [`persist_received_file`]
//! therefore uses exclusive creation: an existing regular file or symlink is a
//! hard failure, not an overwrite target.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

/// Persist a verified received file without clobbering an existing path.
///
/// The destination is created exclusively (`create_new`), which makes a
/// pre-existing file or final-component symlink fail rather than be followed
/// or overwritten. On Unix the file is private to the receiving user at
/// creation (`0600`). A normal write/sync failure is cleaned up best-effort so
/// a failed receive does not leave an ordinary partial file behind.
///
/// Callers should only report transfer success after this function returns
/// `Ok(())`.
pub fn persist_received_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    let result = file.write_all(contents).and_then(|()| file.sync_all());
    if let Err(err) = result {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(err);
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

    #[test]
    fn persists_new_file_and_refuses_clobber() {
        let dir = temp_dir();
        let path = dir.join("received.txt");

        persist_received_file(&path, b"first").expect("first delivery succeeds");
        let err = persist_received_file(&path, b"second").expect_err("clobber must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read delivered file"), b"first");

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

        std::fs::remove_dir_all(dir).expect("remove test directory");
    }
}
