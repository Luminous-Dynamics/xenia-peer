// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Ensure only one launcher process manages a given profile at a time.
//!
//! Reuses [`xenia_secure_file`]'s atomic, owner-only file primitives for
//! the lock record itself -- the same TOCTOU-safe, no-partial-write
//! guarantees this session's security work landed for daemon secrets
//! apply equally well to a launcher's own coordination state, and it
//! avoids a second, ad-hoc file-locking implementation.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct LockRecord {
    pid: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error(
        "another launcher instance (pid {existing_pid}) already manages this profile ({lock_path})"
    )]
    AlreadyRunning {
        existing_pid: u32,
        lock_path: PathBuf,
    },
    #[error("reading/writing the lock file: {0}")]
    Io(String),
}

/// A held single-instance lock. Dropping it removes the lock file --
/// best-effort; a launcher that's killed with `SIGKILL`/hard-terminated
/// leaves a stale lock behind, which the next [`acquire`] call detects and
/// clears itself (see that function's doc comment), so this isn't a
/// correctness requirement, just tidiness on the clean-exit path.
pub struct Lock {
    path: PathBuf,
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Acquire the single-instance lock at `lock_path` for the current
/// process. If a lock record already exists, it's honored only if the pid
/// it names is still actually alive -- a launcher that crashed or was
/// killed without cleaning up leaves a *stale* lock, which this treats as
/// absent (re-created for the current process) rather than a permanent
/// "this profile is stuck" state a user would have to manually clear.
pub fn acquire(lock_path: &Path) -> Result<Lock, LockError> {
    if let Some(existing) = read_existing(lock_path)?
        && pid_is_alive(existing.pid)
    {
        return Err(LockError::AlreadyRunning {
            existing_pid: existing.pid,
            lock_path: lock_path.to_path_buf(),
        });
    }
    // Either no existing lock, or its recorded pid is dead (stale) --
    // fall through and overwrite either way.

    let record = LockRecord {
        pid: std::process::id(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|e| LockError::Io(e.to_string()))?;
    xenia_secure_file::secure_overwrite(lock_path, &bytes)
        .map_err(|e| LockError::Io(e.to_string()))?;
    Ok(Lock {
        path: lock_path.to_path_buf(),
    })
}

fn read_existing(lock_path: &Path) -> Result<Option<LockRecord>, LockError> {
    let Some(raw) = xenia_secure_file::read_secure_file_if_exists(lock_path)
        .map_err(|e| LockError::Io(e.to_string()))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|e| LockError::Io(e.to_string()))
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    let Some(rustix_pid) = rustix::process::Pid::from_raw(pid as i32) else {
        return false;
    };
    // `test_kill_process` is rustix's wrapper for `kill(pid, 0)` -- no
    // actual signal sent, just an existence/permission check.
    rustix::process::test_kill_process(rustix_pid).is_ok()
}

#[cfg(windows)]
#[allow(unsafe_code)] // Real Win32 process-handle FFI; see this crate's lib.rs doc comment.
fn pid_is_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, per-test subdirectory, not a flat path directly under the
    /// system temp dir -- see `process.rs`'s `identity_path` test helper
    /// for why (`/tmp` itself is root-owned and correctly refused by
    /// `xenia-secure-file`'s ownership check).
    fn lock_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "xenia-launcher-core-lock-test-{label}-{}",
                std::process::id()
            ))
            .join("lock")
    }

    #[test]
    fn acquires_cleanly_when_no_lock_exists() {
        let path = lock_path("fresh");
        std::fs::remove_file(&path).ok();
        let lock = acquire(&path).unwrap();
        assert!(path.exists());
        drop(lock);
        assert!(!path.exists(), "lock file should be removed on drop");
    }

    #[test]
    fn refuses_a_second_acquire_while_the_owning_pid_is_alive() {
        let path = lock_path("held");
        std::fs::remove_file(&path).ok();
        let _lock = acquire(&path).unwrap();
        // This process's own pid is, definitionally, alive.
        let result = acquire(&path);
        assert!(matches!(result, Err(LockError::AlreadyRunning { .. })));
    }

    #[test]
    fn a_stale_lock_from_a_dead_pid_is_reclaimed_not_left_stuck() {
        let path = lock_path("stale");
        let stale = LockRecord { pid: 999_999 };
        let bytes = serde_json::to_vec(&stale).unwrap();
        xenia_secure_file::secure_overwrite(&path, &bytes).unwrap();

        let lock = acquire(&path).unwrap();
        drop(lock);
    }
}
