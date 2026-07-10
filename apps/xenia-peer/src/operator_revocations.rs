// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live operator revocation — refuse a compromised operator *without* restarting
//! the daemon.
//!
//! The `--operators-file` enrollment set is loaded once at startup, so revoking
//! a leaked key otherwise means editing that file and restarting (dropping every
//! live session). This module adds a separate, hot-reloadable **revocation list**
//! of `operator_id`s that the sealed operator channel consults *after* the
//! handshake authenticates the peer: a revoked operator is refused fail-closed
//! even though its key is still enrolled.
//!
//! Operationally: add an id to the `--revoked-operators-file` (one id per line;
//! blank lines and `#` comments ignored) and send the daemon `SIGHUP` — the set
//! is re-read atomically, no restart, existing legitimate sessions untouched.
//! Revoking by `operator_id` (not raw key) means one line disables an operator
//! regardless of how many keys it enrolled.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// A shared, hot-reloadable set of revoked `operator_id`s. Cheap to clone
/// (`Arc`), safe to share across the sealed endpoint and a SIGHUP reload task.
#[derive(Clone, Default)]
pub(crate) struct OperatorRevocations {
    revoked: Arc<RwLock<HashSet<String>>>,
    /// The file the set is (re)loaded from, if any — kept so a SIGHUP handler
    /// can reload without re-plumbing the path.
    path: Option<PathBuf>,
}

impl OperatorRevocations {
    /// An empty revocation list with no backing file (nothing is ever revoked
    /// unless `revoke` is called).
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Load a revocation list from `path` (creating an empty set if the file is
    /// absent — an absent file simply means "nothing revoked yet"). Records the
    /// path for later [`OperatorRevocations::reload`].
    pub(crate) fn from_file(path: &Path) -> std::io::Result<Self> {
        let set = read_revocations(path)?;
        Ok(Self {
            revoked: Arc::new(RwLock::new(set)),
            path: Some(path.to_path_buf()),
        })
    }

    /// Whether `operator_id` is currently revoked. Cheap read-lock; the lock is
    /// never held across an `.await`.
    pub(crate) fn is_revoked(&self, operator_id: &str) -> bool {
        self.revoked
            .read()
            .map(|s| s.contains(operator_id))
            .unwrap_or(true) // poisoned lock -> fail closed (treat as revoked)
    }

    /// Revoke `operator_id` in-process — the entry point for the authenticated
    /// admin `POST /operator/revoke` endpoint (and used by tests). The backing
    /// file is not written, so a subsequent SIGHUP reload from the file would
    /// overwrite an in-process-only revocation; persist it to the file for
    /// durability across reloads.
    pub(crate) fn revoke(&self, operator_id: &str) {
        if let Ok(mut s) = self.revoked.write() {
            s.insert(operator_id.to_string());
        }
    }

    /// Re-read the backing file and replace the set atomically. Returns the new
    /// revoked count. No-op (Ok(current count)) if there is no backing file.
    pub(crate) fn reload(&self) -> std::io::Result<usize> {
        let Some(path) = &self.path else {
            return Ok(self.revoked.read().map(|s| s.len()).unwrap_or(0));
        };
        let fresh = read_revocations(path)?;
        let count = fresh.len();
        if let Ok(mut s) = self.revoked.write() {
            *s = fresh;
        }
        Ok(count)
    }

    /// The number of currently-revoked operators.
    pub(crate) fn len(&self) -> usize {
        self.revoked.read().map(|s| s.len()).unwrap_or(0)
    }
}

/// Read a revocation file into a set of `operator_id`s. Missing file -> empty
/// set. Blank lines and `#` comments are ignored; ids are trimmed.
fn read_revocations(path: &Path) -> std::io::Result<HashSet<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(e),
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn empty_revokes_nothing_until_revoke_is_called() {
        let r = OperatorRevocations::empty();
        assert!(!r.is_revoked("alice"));
        r.revoke("alice");
        assert!(r.is_revoked("alice"));
        assert!(!r.is_revoked("bob"));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn parses_file_ignoring_blanks_and_comments() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "# revoked operators").unwrap();
        writeln!(f, "alice").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "  bob  ").unwrap();
        let r = OperatorRevocations::from_file(f.path()).unwrap();
        assert!(r.is_revoked("alice"));
        assert!(r.is_revoked("bob"));
        assert!(!r.is_revoked("carol"));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn reload_picks_up_new_revocations() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "alice").unwrap();
        let r = OperatorRevocations::from_file(f.path()).unwrap();
        assert!(!r.is_revoked("bob"));
        // Append bob and reload (simulating edit-file + SIGHUP).
        writeln!(f, "bob").unwrap();
        f.flush().unwrap();
        let count = r.reload().unwrap();
        assert_eq!(count, 2);
        assert!(r.is_revoked("bob"));
        assert!(r.is_revoked("alice"));
    }

    #[test]
    fn absent_file_is_empty_not_an_error() {
        let r = OperatorRevocations::from_file(Path::new("/nonexistent/xenia/revoked")).unwrap();
        assert_eq!(r.len(), 0);
        assert!(!r.is_revoked("anyone"));
    }
}
