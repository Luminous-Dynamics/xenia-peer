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
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

/// A shared, hot-reloadable set of revoked `operator_id`s. Cheap to clone
/// (`Arc`), safe to share across the sealed endpoint and a SIGHUP reload task.
#[derive(Clone)]
pub(crate) struct OperatorRevocations {
    revoked: Arc<RwLock<HashSet<String>>>,
    /// Whether the configured revocation source is currently trustworthy. A
    /// reload I/O failure flips this false and makes every authorization check
    /// fail closed until a later successful reload restores health.
    healthy: Arc<AtomicBool>,
    /// Monotonic change notification for active-session authorization checks.
    changes: watch::Sender<u64>,
    /// The file the set is (re)loaded from, if any — kept so a SIGHUP handler
    /// can reload without re-plumbing the path.
    path: Option<PathBuf>,
}

impl Default for OperatorRevocations {
    fn default() -> Self {
        let (changes, _rx) = watch::channel(0);
        Self {
            revoked: Arc::new(RwLock::new(HashSet::new())),
            healthy: Arc::new(AtomicBool::new(true)),
            changes,
            path: None,
        }
    }
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
    ///
    /// Every current daemon startup path uses [`Self::from_required_file`]
    /// instead (a missing configured source should fail closed, not silently
    /// mean "nothing revoked"); this constructor is only exercised by tests
    /// today. Disclosed rather than silently allowed away.
    #[allow(dead_code)]
    pub(crate) fn from_file(path: &Path) -> std::io::Result<Self> {
        let set = read_revocations(path)?;
        let (changes, _rx) = watch::channel(0);
        Ok(Self {
            revoked: Arc::new(RwLock::new(set)),
            healthy: Arc::new(AtomicBool::new(true)),
            changes,
            path: Some(path.to_path_buf()),
        })
    }

    /// Load an explicitly configured revocation source and require it to be
    /// present and readable. Privileged daemon surfaces use this constructor so
    /// a missing configured trust source cannot silently mean "nothing
    /// revoked" at startup.
    pub(crate) fn from_required_file(path: &Path) -> std::io::Result<Self> {
        let set = read_revocations_required(path)?;
        let (changes, _rx) = watch::channel(0);
        Ok(Self {
            revoked: Arc::new(RwLock::new(set)),
            healthy: Arc::new(AtomicBool::new(true)),
            changes,
            path: Some(path.to_path_buf()),
        })
    }

    /// Whether `operator_id` is currently revoked. Cheap read-lock; the lock is
    /// never held across an `.await`.
    pub(crate) fn is_revoked(&self, operator_id: &str) -> bool {
        if !self.healthy.load(Ordering::SeqCst) {
            return true;
        }
        self.revoked
            .read()
            .map(|s| s.contains(operator_id))
            .unwrap_or(true) // poisoned lock -> fail closed (treat as revoked)
    }

    /// Whether the configured revocation source is currently trustworthy.
    /// Primarily surfaced for diagnostics and focused fail-closed tests.
    #[cfg(test)]
    pub(crate) fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// Revoke `operator_id` in-process. This is intentionally monotonic: there
    /// is no implicit "un-revoke" when the backing file is reloaded. Tests use
    /// this path directly today; no production caller (e.g. an admin API for
    /// file-less deployments) exists yet. Disclosed rather than silently
    /// allowed away.
    #[allow(dead_code)]
    pub(crate) fn revoke(&self, operator_id: &str) {
        if self.insert(operator_id) {
            self.notify_changed();
        }
    }

    /// Revoke `operator_id` and atomically persist the complete monotonic set
    /// when a backing file is configured. The live set is updated first so a
    /// disk failure never leaves a compromised operator active in the current
    /// daemon process; the error tells the admin endpoint that durability was
    /// not achieved and must be repaired before restart.
    pub(crate) fn revoke_durable(&self, operator_id: &str) -> std::io::Result<bool> {
        let changed = self.insert(operator_id);
        if changed {
            self.notify_changed();
        }
        let Some(path) = &self.path else {
            return Ok(changed);
        };
        let snapshot = self.snapshot()?;
        persist_revocations_atomic(path, &snapshot)?;
        Ok(changed)
    }

    fn insert(&self, operator_id: &str) -> bool {
        match self.revoked.write() {
            Ok(mut set) => set.insert(operator_id.to_string()),
            Err(_) => {
                // `is_revoked` treats a poisoned set as universally revoked;
                // wake active-session watchers so that fail-closed state is
                // propagated rather than remaining visible only to new calls.
                self.notify_changed();
                false
            }
        }
    }

    fn snapshot(&self) -> std::io::Result<HashSet<String>> {
        self.revoked
            .read()
            .map(|set| set.clone())
            .map_err(|_| std::io::Error::other("operator revocation lock poisoned"))
    }

    /// Re-read the backing file and monotonically union it into live state. Returns the new
    /// revoked count. No-op (Ok(current count)) if there is no backing file.
    pub(crate) fn reload(&self) -> std::io::Result<usize> {
        let Some(path) = &self.path else {
            return Ok(self.revoked.read().map(|s| s.len()).unwrap_or(0));
        };
        let fresh = match read_revocations_required(path) {
            Ok(fresh) => fresh,
            Err(err) => {
                // Loss of the revocation source is an authorization failure,
                // not merely a logging problem. Wake every live approver-bound
                // session and make all subsequent checks fail closed until an
                // operator repairs the source and a reload succeeds.
                let was_healthy = self.healthy.swap(false, Ordering::SeqCst);
                if was_healthy {
                    self.notify_changed();
                }
                return Err(err);
            }
        };
        let (count, changed) = match self.revoked.write() {
            Ok(mut set) => {
                let before = set.len();
                set.extend(fresh);
                (set.len(), set.len() != before)
            }
            Err(_) => {
                self.healthy.store(false, Ordering::SeqCst);
                self.notify_changed();
                return Err(std::io::Error::other("operator revocation lock poisoned"));
            }
        };
        let recovered = !self.healthy.swap(true, Ordering::SeqCst);
        if changed || recovered {
            self.notify_changed();
        }
        Ok(count)
    }

    /// Subscribe to changes in the live revocation set.
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// The number of currently-revoked operators.
    pub(crate) fn len(&self) -> usize {
        self.revoked.read().map(|s| s.len()).unwrap_or(0)
    }

    fn notify_changed(&self) {
        let next = (*self.changes.borrow()).wrapping_add(1);
        self.changes.send_replace(next);
    }
}

/// Atomically persist the complete revocation set. The sorted newline format
/// remains operator-editable while temp-file + data fsync + rename + directory
/// fsync makes the update crash-consistent on POSIX filesystems.
fn persist_revocations_atomic(path: &Path, revoked: &HashSet<String>) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let mut ids: Vec<&str> = revoked.iter().map(String::as_str).collect();
    ids.sort_unstable();
    let mut bytes = ids.join("\n").into_bytes();
    if !bytes.is_empty() {
        bytes.push(b'\n');
    }

    let temp_path = temporary_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let result = (|| {
        let mut file = options.open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("revoked-operators");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{name}.tmp-{}-{nanos}", std::process::id()))
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Read a revocation file into a set of `operator_id`s. Missing file -> empty
/// set. Blank lines and `#` comments are ignored; ids are trimmed.
///
/// Only [`OperatorRevocations::from_file`] calls this, and that constructor
/// itself has no production caller today -- see its doc comment.
#[allow(dead_code)]
fn read_revocations(path: &Path) -> std::io::Result<HashSet<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err),
    };
    Ok(parse_revocations(&text))
}

/// Reloads are strict: once a path is configured, disappearance of that source
/// is an authorization-health failure rather than an implicit empty list.
fn read_revocations_required(path: &Path) -> std::io::Result<HashSet<String>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_revocations(&text))
}

fn parse_revocations(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
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

    #[tokio::test]
    async fn subscribers_wake_only_when_the_set_changes() {
        let r = OperatorRevocations::empty();
        let mut changes = r.subscribe();
        r.revoke("alice");
        changes.changed().await.unwrap();
        assert_eq!(*changes.borrow(), 1);

        r.revoke("alice");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), changes.changed())
                .await
                .is_err()
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
    fn durable_revoke_survives_reload_and_restart() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-revocations-durable-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.txt");
        let r = OperatorRevocations::from_file(&path).unwrap();
        assert!(r.revoke_durable("alice").unwrap());
        assert!(r.is_revoked("alice"));

        let restarted = OperatorRevocations::from_file(&path).unwrap();
        assert!(restarted.is_revoked("alice"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "alice\n");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reload_is_monotonic_and_cannot_unrevoke_live_state() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-revocations-monotonic-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.txt");
        std::fs::write(&path, "alice\n").unwrap();
        let r = OperatorRevocations::from_file(&path).unwrap();
        r.revoke("bob");
        std::fs::write(&path, "alice\n").unwrap();
        r.reload().unwrap();
        assert!(r.is_revoked("alice"));
        assert!(r.is_revoked("bob"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn absent_file_is_empty_not_an_error() {
        let r = OperatorRevocations::from_file(Path::new("/nonexistent/xenia/revoked")).unwrap();
        assert_eq!(r.len(), 0);
        assert!(!r.is_revoked("anyone"));
    }

    #[test]
    fn explicitly_required_source_must_exist_at_startup() {
        let path = std::env::temp_dir().join(format!(
            "xenia-required-revocations-missing-{}",
            rand::random::<u64>()
        ));
        assert!(OperatorRevocations::from_required_file(&path).is_err());
    }
    #[test]
    fn reload_failure_revokes_every_operator_until_source_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoked.txt");
        std::fs::write(&path, "alice\n").unwrap();
        let r = OperatorRevocations::from_file(&path).unwrap();
        let changes = r.subscribe();

        assert!(r.is_healthy());
        assert!(r.is_revoked("alice"));
        assert!(!r.is_revoked("bob"));

        std::fs::remove_file(&path).unwrap();
        assert!(r.reload().is_err());
        assert!(!r.is_healthy());
        assert!(r.is_revoked("bob"), "source loss must fail closed");
        assert!(changes.has_changed().unwrap());

        std::fs::write(&path, "alice\n").unwrap();
        r.reload().unwrap();
        assert!(r.is_healthy());
        assert!(!r.is_revoked("bob"), "successful reload restores health");
    }
}
