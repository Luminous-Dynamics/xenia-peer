// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Resolve the daemon/agent binaries the launcher supervises.
//!
//! **Never `$PATH`/`%PATH%`.** A launcher that resolves its child binary by
//! name through the ambient search path is trusting every directory on
//! that path equally -- any of them, if writable by a lower-privileged
//! user or already compromised, can plant a same-named binary the launcher
//! then executes with whatever privilege it runs at. This is exactly the
//! same class of gap `xenia-secure-file`'s owner-only ACL/reparse-point
//! checks close for *files*; the equivalent for *the binary a supervisor
//! spawns* is resolving it by an explicit, known-good path instead of an
//! ambient search.

use std::io;
use std::path::{Path, PathBuf};

/// Which binary to resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    Peer,
    OperatorAgent,
}

impl Binary {
    fn file_stem(self) -> &'static str {
        match self {
            Binary::Peer => "xenia-peer",
            Binary::OperatorAgent => "xenia-operator-agent",
        }
    }

    fn file_name(self) -> String {
        if cfg!(windows) {
            format!("{}.exe", self.file_stem())
        } else {
            self.file_stem().to_string()
        }
    }
}

/// Resolve `binary`'s path, by convention: it must sit alongside the
/// launcher's own executable (`std::env::current_exe()`'s parent
/// directory) -- the shape a real installer produces (launcher + daemon +
/// agent all copied into one install directory together), not a
/// system-wide install this crate would otherwise have to guess a
/// per-platform convention for. `override_dir`, if given, is checked
/// first -- for a profile that explicitly points at a different install
/// (e.g. a dev build under `target/debug/`), still never falling back to
/// `$PATH`.
///
/// Fails closed: returns an error (never silently substitutes a
/// differently-named or ambient binary) if neither location has the
/// expected file.
pub fn discover(binary: Binary, override_dir: Option<&Path>) -> io::Result<PathBuf> {
    let file_name = binary.file_name();

    if let Some(dir) = override_dir {
        let candidate = dir.join(&file_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{file_name} not found in the configured install directory {}",
                dir.display()
            ),
        ));
    }

    let launcher_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            io::Error::other("could not determine the launcher's own executable directory")
        })?;
    let candidate = launcher_dir.join(&file_name);
    if candidate.is_file() {
        return Ok(candidate);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{file_name} not found alongside the launcher ({}) -- expected an install directory \
             containing both, not a system PATH lookup",
            launcher_dir.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_from_an_explicit_override_directory() {
        let dir = tempfile::tempdir().unwrap();
        let expected_name = Binary::Peer.file_name();
        std::fs::write(dir.path().join(&expected_name), b"not a real binary").unwrap();

        let resolved = discover(Binary::Peer, Some(dir.path())).unwrap();
        assert_eq!(resolved, dir.path().join(expected_name));
    }

    #[test]
    fn fails_closed_when_the_override_directory_lacks_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let err = discover(Binary::Peer, Some(dir.path())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn never_falls_back_to_a_path_style_lookup() {
        // Even if some *other* directory on the real $PATH happened to
        // contain a same-named file, an override directory that doesn't
        // have it must still fail -- there is no fallback search anywhere
        // in `discover`.
        let dir = tempfile::tempdir().unwrap();
        let result = discover(Binary::OperatorAgent, Some(dir.path()));
        assert!(result.is_err());
    }
}
