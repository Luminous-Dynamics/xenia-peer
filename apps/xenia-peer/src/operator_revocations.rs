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

/// Whether an operation changed the **effective** revoked-operator set.
///
/// This is intentionally semantic rather than file/operation based: inserting
/// an already-revoked id or reloading differently-formatted bytes that parse to
/// the same set is `Unchanged`. XENIA-SYM-001D3A can therefore advance its
/// authority generation only when the authority state itself changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevocationMutation {
    /// The effective set did not change.
    Unchanged { count: usize },
    /// The effective set changed atomically.
    Changed { count: usize },
}

impl RevocationMutation {
    /// Number of revoked operator ids after the operation.
    pub(crate) const fn count(self) -> usize {
        match self {
            Self::Unchanged { count } | Self::Changed { count } => count,
        }
    }

    /// Whether the effective authority state changed.
    pub(crate) const fn changed(self) -> bool {
        matches!(self, Self::Changed { .. })
    }
}

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

    /// Revoke `operator_id` and report whether the effective set changed.
    ///
    /// Unlike the compatibility [`Self::revoke`] wrapper, lock poisoning is an
    /// explicit error here. Authority-generation integration must use this
    /// method so it never mistakes an unperformed mutation for an unchanged
    /// authority state.
    pub(crate) fn revoke_with_outcome(
        &self,
        operator_id: &str,
    ) -> std::io::Result<RevocationMutation> {
        let mut revoked = self
            .revoked
            .write()
            .map_err(|_| std::io::Error::other("operator revocation lock poisoned"))?;
        let changed = revoked.insert(operator_id.to_string());
        let count = revoked.len();
        Ok(if changed {
            RevocationMutation::Changed { count }
        } else {
            RevocationMutation::Unchanged { count }
        })
    }

    /// Revoke `operator_id` in-process — the compatibility entry point for the
    /// authenticated admin endpoint and existing tests.
    ///
    /// New authority-generation code must use [`Self::revoke_with_outcome`]
    /// instead, because this legacy wrapper deliberately preserves the old
    /// fire-and-forget API. The backing file is not written, so a subsequent
    /// SIGHUP reload from the file can overwrite an in-process-only revocation.
    pub(crate) fn revoke(&self, operator_id: &str) {
        let _ = self.revoke_with_outcome(operator_id);
    }

    /// Re-read the backing file, atomically install its effective set, and
    /// report whether the effective authority state changed.
    ///
    /// File byte changes, ordering changes, comments, or duplicate lines that
    /// parse to the same set are `Unchanged`. Lock poisoning is explicit.
    pub(crate) fn reload_with_outcome(&self) -> std::io::Result<RevocationMutation> {
        let Some(path) = &self.path else {
            let count = self
                .revoked
                .read()
                .map_err(|_| std::io::Error::other("operator revocation lock poisoned"))?
                .len();
            return Ok(RevocationMutation::Unchanged { count });
        };

        // A configured file disappearing after successful startup is a real
        // error. Do not route through `read_revocations`, whose initial-load
        // semantics intentionally treat an absent file as an empty set.
        let text = std::fs::read_to_string(path)?;
        let fresh = parse_revocations(&text);
        let mut current = self
            .revoked
            .write()
            .map_err(|_| std::io::Error::other("operator revocation lock poisoned"))?;
        if *current == fresh {
            return Ok(RevocationMutation::Unchanged {
                count: current.len(),
            });
        }

        *current = fresh;
        Ok(RevocationMutation::Changed {
            count: current.len(),
        })
    }

    /// Re-read the backing file and replace the set atomically. Returns the new
    /// revoked count. No-op (Ok(current count)) if there is no backing file
    /// configured at all.
    ///
    /// This compatibility API preserves the historical return type. New
    /// authority-generation integration must use [`Self::reload_with_outcome`]
    /// so semantic no-ops do not advance the authority generation.
    ///
    /// Fails closed if a *previously-configured* file has since gone missing
    /// (deleted, unmounted, bad deploy): unlike the initial [`Self::from_file`]
    /// load -- where "absent" legitimately means "nothing revoked yet" --
    /// a file vanishing between loads is treated as a real error and the
    /// current in-memory set is left untouched, never silently replaced
    /// with an empty one.
    pub(crate) fn reload(&self) -> std::io::Result<usize> {
        self.reload_with_outcome().map(RevocationMutation::count)
    }

    /// Deterministic owned snapshot of the effective revoked-operator IDs.
    ///
    /// This is the narrow read boundary used by D3B commitment generation;
    /// callers never receive the internal `HashSet` or lock guard.
    pub(crate) fn snapshot_sorted(&self) -> std::io::Result<Vec<String>> {
        let revoked = self
            .revoked
            .read()
            .map_err(|_| std::io::Error::other("operator revocation lock poisoned"))?;
        let mut ids: Vec<String> = revoked.iter().cloned().collect();
        ids.sort();
        Ok(ids)
    }

    /// The number of currently-revoked operators.
    pub(crate) fn len(&self) -> usize {
        self.revoked.read().map(|s| s.len()).unwrap_or(0)
    }
}

/// Read a revocation file into a set of `operator_id`s for the *initial*
/// load. Missing file -> empty set (there is nothing to have been revoked
/// yet). [`OperatorRevocations::reload`] deliberately does not use this --
/// see its doc comment for why "missing" means something different there.
fn read_revocations(path: &Path) -> std::io::Result<HashSet<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(e),
    };
    Ok(parse_revocations(&text))
}

/// Parse revocation-file text into a set of `operator_id`s. Blank lines and
/// `#` comments are ignored; ids are trimmed.
fn parse_revocations(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
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
    fn revoke_outcome_distinguishes_change_from_semantic_noop() {
        let r = OperatorRevocations::empty();
        assert_eq!(
            r.revoke_with_outcome("alice").unwrap(),
            RevocationMutation::Changed { count: 1 }
        );
        assert_eq!(
            r.revoke_with_outcome("alice").unwrap(),
            RevocationMutation::Unchanged { count: 1 }
        );
        assert_eq!(
            r.revoke_with_outcome("bob").unwrap(),
            RevocationMutation::Changed { count: 2 }
        );
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
    fn reload_outcome_uses_effective_set_not_file_bytes() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "alice").unwrap();
        writeln!(f, "bob").unwrap();
        let r = OperatorRevocations::from_file(f.path()).unwrap();

        // Different ordering/comments/duplicates, identical effective set.
        std::fs::write(f.path(), "# reordered\nbob\nalice\nalice\n").unwrap();
        assert_eq!(
            r.reload_with_outcome().unwrap(),
            RevocationMutation::Unchanged { count: 2 }
        );

        std::fs::write(f.path(), "alice\nbob\ncarol\n").unwrap();
        assert_eq!(
            r.reload_with_outcome().unwrap(),
            RevocationMutation::Changed { count: 3 }
        );
    }

    #[test]
    fn sorted_snapshot_is_deterministic_and_owned() {
        let r = OperatorRevocations::empty();
        r.revoke_with_outcome("charlie").unwrap();
        r.revoke_with_outcome("alice").unwrap();
        r.revoke_with_outcome("bob").unwrap();
        assert_eq!(
            r.snapshot_sorted().unwrap(),
            vec!["alice".to_string(), "bob".to_string(), "charlie".to_string()]
        );
    }

    #[test]
    fn reload_fails_closed_and_keeps_prior_revocations_when_file_vanishes() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "alice\n").unwrap();
        let r = OperatorRevocations::from_file(f.path()).unwrap();
        assert!(r.is_revoked("alice"));

        // The revocation source disappears (deleted, unmounted, bad deploy)
        // between loads.
        std::fs::remove_file(f.path()).unwrap();

        let err = r.reload().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        // The prior revocation must NOT have been silently wiped -- alice
        // stays revoked even though the reload itself failed.
        assert!(r.is_revoked("alice"));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn absent_file_is_empty_not_an_error() {
        let r = OperatorRevocations::from_file(Path::new("/nonexistent/xenia/revoked")).unwrap();
        assert_eq!(r.len(), 0);
        assert!(!r.is_revoked("anyone"));
    }
}
