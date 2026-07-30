// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Daemon process lifecycle: spawn (strict, no shell), liveness, graceful
//! shutdown with a bounded escalation to force-termination, and reattaching
//! to an already-running process this launcher spawned in a prior run
//! (surviving the launcher itself restarting or crashing without taking
//! the daemon down with it).
//!
//! **Graceful signal choice, and why it's not the POSIX-conventional
//! SIGTERM**: `apps/xenia-operator-agent`'s own shutdown handler is
//! `tokio::signal::ctrl_c().await` -- which listens for **SIGINT** on
//! Unix, not SIGTERM. This crate's graceful stop sends SIGINT to match
//! what this project's own cooperative-shutdown code actually catches,
//! not the generic Unix convention. `apps/xenia-peer` doesn't install any
//! shutdown handler at all as of this writing (verified: no
//! `ctrl_c`/`SIGTERM`/`with_graceful_shutdown` anywhere in its
//! `main.rs`) -- sending it SIGINT still terminates it (the OS default
//! disposition for an unhandled signal), just without today's binary
//! exploiting the grace window for cleanup. That's an opportunity this
//! launcher offers, not a guarantee any given daemon build uses it.
//!
//! **Windows has no per-process SIGINT/SIGTERM equivalent at all.**
//! `GenerateConsoleCtrlEvent(CTRL_C_EVENT, ...)` can only target *every*
//! process sharing the caller's console (its `dwProcessGroupId` must be
//! `0` for `CTRL_C_EVENT` specifically) -- there is no way to send it to
//! one chosen process. `CTRL_BREAK_EVENT` is the one console-control event
//! Windows lets you target by process group id, which is why this spawns
//! the daemon with `CREATE_NEW_PROCESS_GROUP` and sends `CTRL_BREAK_EVENT`
//! to that group (== the child's pid) for the graceful step. Note this
//! means a future Windows-side graceful-shutdown handler in `xenia-peer`
//! would need to listen for `tokio::signal::windows::ctrl_break()`, not
//! `ctrl_c()`, for this launcher's graceful stop to reach it at all --
//! `ctrl_c()`'s Windows implementation only reacts to `CTRL_C_EVENT`.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Which binary a [`ProcessIdentity`]/[`DaemonProcess`] refers to, purely
/// for error messages and the persisted identity record -- not used for
/// any dispatch.
pub use crate::discovery::Binary;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("spawning {binary_path}: {source}")]
    Spawn {
        binary_path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("waiting for the daemon to exit: {0}")]
    Wait(#[source] std::io::Error),
    #[error("signaling the daemon: {0}")]
    Signal(#[source] std::io::Error),
    #[error(
        "pid {pid} exists but its executable identity doesn't match \
         {expected} (found {found:?}) -- refusing to treat it as our daemon, \
         it's likely an unrelated process that reused this pid"
    )]
    IdentityMismatch {
        pid: u32,
        expected: PathBuf,
        found: Option<PathBuf>,
    },
    #[error("no process is currently running for this identity record")]
    NotRunning,
}

/// Durable record of a spawned process, written to disk (via
/// `xenia-secure-file`, owner-only) so a *later* launcher invocation --
/// after a restart or a crash of the launcher itself, not the daemon --
/// can find and safely reattach to it. `binary_path` is what makes
/// reattachment safe: pids get reused by the OS, so before treating any
/// live pid as "our daemon," [`DaemonProcess::try_reattach`] verifies the
/// live process at that pid is still actually running this exact binary.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub binary_path: PathBuf,
}

/// A supervised daemon process -- either one this launcher just spawned
/// (`Owned`, holding the real `tokio::process::Child` so `wait`/`try_wait`
/// report a genuine exit status), or one it reattached to from a persisted
/// [`ProcessIdentity`] (`Reattached`, pid-only -- an exit status isn't
/// observable for a process this launcher instance didn't itself spawn;
/// only liveness is).
pub struct DaemonProcess {
    identity: ProcessIdentity,
    kind: ProcessKind,
}

enum ProcessKind {
    // Boxed: on Windows, tokio::process::Child is large enough relative to
    // the data-less Reattached variant that clippy's large_enum_variant
    // fires -- boxing keeps DaemonProcess itself small regardless of which
    // variant is live.
    Owned(Box<tokio::process::Child>),
    Reattached,
}

impl DaemonProcess {
    /// Spawn `binary_path` with `args` -- never through a shell, and
    /// `args` is always the typed, allowlisted output of
    /// [`crate::config::DaemonConfig::to_args`], not caller-assembled
    /// free text. `identity_path` is where the resulting
    /// [`ProcessIdentity`] is durably recorded (see that type's doc
    /// comment) via [`xenia_secure_file::secure_overwrite`].
    pub async fn spawn(
        binary_path: &Path,
        args: &[std::ffi::OsString],
        identity_path: &Path,
    ) -> Result<Self, ProcessError> {
        let mut command = tokio::process::Command::new(binary_path);
        command.args(args);
        // See this module's doc comment: CTRL_BREAK_EVENT is the only
        // console-control event Windows lets a caller target at a
        // specific process (group) rather than every process sharing its
        // console, and it only works for processes started in their own
        // process group.
        #[cfg(windows)]
        {
            // `tokio::process::Command::creation_flags` is inherent (tokio
            // re-implements the relevant Windows extension methods
            // directly rather than requiring `std::os::windows::process::CommandExt`).
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            command.creation_flags(CREATE_NEW_PROCESS_GROUP);
        }
        let child = command.spawn().map_err(|source| ProcessError::Spawn {
            binary_path: binary_path.to_path_buf(),
            source,
        })?;
        let pid = child.id().ok_or_else(|| ProcessError::Spawn {
            binary_path: binary_path.to_path_buf(),
            source: std::io::Error::other(
                "spawned child has no pid -- it must have already exited",
            ),
        })?;

        let identity = ProcessIdentity {
            pid,
            binary_path: binary_path.to_path_buf(),
        };
        Self::persist_identity(&identity, identity_path).map_err(|source| ProcessError::Spawn {
            binary_path: binary_path.to_path_buf(),
            source,
        })?;

        Ok(Self {
            identity,
            kind: ProcessKind::Owned(Box::new(child)),
        })
    }

    /// Read `identity_path` (if present) and, only if a live process at
    /// that pid genuinely still is the recorded binary, return a
    /// [`DaemonProcess`] for it. Returns `Ok(None)` -- not an error -- for
    /// "no identity file" and "the recorded pid isn't running anymore"
    /// alike: both are the ordinary, expected state after a clean prior
    /// shutdown, not a fault. Returns [`ProcessError::IdentityMismatch`]
    /// specifically (not silently `None`) when a live process exists at
    /// that pid but is a *different* binary -- the one case that
    /// genuinely deserves the caller's attention, since it means the pid
    /// got reused.
    pub async fn try_reattach(identity_path: &Path) -> Result<Option<Self>, ProcessError> {
        let Some(raw) = xenia_secure_file::read_secure_file_if_exists(identity_path)
            .map_err(|e| ProcessError::Wait(std::io::Error::other(e.to_string())))?
        else {
            return Ok(None);
        };
        let identity: ProcessIdentity = serde_json::from_slice(&raw)
            .map_err(|e| ProcessError::Wait(std::io::Error::other(e.to_string())))?;

        match identity_still_matches(&identity) {
            IdentityCheck::Alive => Ok(Some(Self {
                identity,
                kind: ProcessKind::Reattached,
            })),
            IdentityCheck::NotRunning => Ok(None),
            IdentityCheck::Mismatch { found } => Err(ProcessError::IdentityMismatch {
                pid: identity.pid,
                expected: identity.binary_path,
                found,
            }),
        }
    }

    pub fn pid(&self) -> u32 {
        self.identity.pid
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Whether the process is still running. For an `Owned` process this
    /// also reaps it via `try_wait` if it has exited (matching
    /// `tokio::process::Child`'s own contract); for a `Reattached` one
    /// it's a pure liveness check with no exit-status observation.
    pub fn is_alive(&mut self) -> Result<bool, ProcessError> {
        match &mut self.kind {
            ProcessKind::Owned(child) => {
                Ok(child.try_wait().map_err(ProcessError::Wait)?.is_none())
            }
            ProcessKind::Reattached => Ok(matches!(
                identity_still_matches(&self.identity),
                IdentityCheck::Alive
            )),
        }
    }

    /// Graceful signal first (see this module's doc comment for which one
    /// and why), a bounded wait, then force-termination only if it's
    /// still alive after `graceful_timeout`. Never the reverse order.
    pub async fn stop(mut self, graceful_timeout: Duration) -> Result<(), ProcessError> {
        if !self.is_alive()? {
            return Ok(());
        }

        send_graceful_signal(self.identity.pid)?;

        let deadline = tokio::time::Instant::now() + graceful_timeout;
        while tokio::time::Instant::now() < deadline {
            if !self.is_alive()? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if self.is_alive()? {
            force_kill(&mut self)?;
        }
        Ok(())
    }

    fn persist_identity(identity: &ProcessIdentity, identity_path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(identity)?;
        xenia_secure_file::secure_overwrite(identity_path, &bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

enum IdentityCheck {
    Alive,
    NotRunning,
    Mismatch { found: Option<PathBuf> },
}

#[cfg(unix)]
fn identity_still_matches(identity: &ProcessIdentity) -> IdentityCheck {
    let exe_link = format!("/proc/{}/exe", identity.pid);
    let Ok(actual) = std::fs::read_link(&exe_link) else {
        return IdentityCheck::NotRunning;
    };
    let expected = identity
        .binary_path
        .canonicalize()
        .unwrap_or_else(|_| identity.binary_path.clone());
    if actual == expected {
        IdentityCheck::Alive
    } else {
        IdentityCheck::Mismatch {
            found: Some(actual),
        }
    }
}

#[cfg(unix)]
fn send_graceful_signal(pid: u32) -> Result<(), ProcessError> {
    use rustix::process::{Pid, Signal};
    let Some(rustix_pid) = Pid::from_raw(pid as i32) else {
        return Err(ProcessError::Signal(std::io::Error::other("invalid pid")));
    };
    rustix::process::kill_process(rustix_pid, Signal::Int)
        .map_err(|e| ProcessError::Signal(std::io::Error::from(e)))
}

#[cfg(unix)]
fn force_kill(process: &mut DaemonProcess) -> Result<(), ProcessError> {
    use rustix::process::{Pid, Signal};
    let Some(rustix_pid) = Pid::from_raw(process.identity.pid as i32) else {
        return Err(ProcessError::Signal(std::io::Error::other("invalid pid")));
    };
    rustix::process::kill_process(rustix_pid, Signal::Kill)
        .map_err(|e| ProcessError::Signal(std::io::Error::from(e)))
}

#[cfg(windows)]
#[allow(unsafe_code)] // Real Win32 process-handle FFI; see this crate's lib.rs doc comment.
fn identity_still_matches(identity: &ProcessIdentity) -> IdentityCheck {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    let handle: HANDLE = unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, identity.pid) {
            Ok(h) => h,
            Err(_) => return IdentityCheck::NotRunning,
        }
    };

    let mut buf = [0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    if ok.is_err() {
        return IdentityCheck::NotRunning;
    }
    let actual = PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]));
    // Deliberately NOT canonicalize()'d, unlike the Unix side: on Windows
    // that adds the `\\?\` verbatim-path prefix (a real, confirmed bug --
    // it made a genuinely-identical path compare as a mismatch), while
    // `QueryFullProcessImageNameW(PROCESS_NAME_WIN32)` always returns a
    // plain win32-format path with no such prefix. `identity.binary_path`
    // is already absolute and non-symlinked in real usage (it comes from
    // `discovery::discover`, which resolves an explicit installed path,
    // never a relative or symlinked one), so a raw comparison is both
    // correct and simpler than the canonicalize+fallback dance this
    // replaced.
    if actual == identity.binary_path {
        IdentityCheck::Alive
    } else {
        IdentityCheck::Mismatch {
            found: Some(actual),
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn send_graceful_signal(pid: u32) -> Result<(), ProcessError> {
    use windows::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) }
        .map_err(|e| ProcessError::Signal(std::io::Error::other(e.to_string())))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn force_kill(process: &mut DaemonProcess) -> Result<(), ProcessError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, process.identity.pid)
            .map_err(|e| ProcessError::Signal(std::io::Error::other(e.to_string())))?;
        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        result.map_err(|e| ProcessError::Signal(std::io::Error::other(e.to_string())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path inside a *fresh, per-test subdirectory* -- not a flat path
    /// directly under the system temp dir. `xenia-secure-file`'s parent-
    /// directory ownership check correctly refuses to trust `/tmp` itself
    /// (root-owned, shared, sticky-bit) as a place to create state; it
    /// only trusts directories the caller's own process created. A fresh
    /// subdirectory this test process creates (indirectly, via
    /// `xenia-secure-file`'s own `create_dir_all` on first access) is
    /// exactly what real callers of this crate do too.
    fn identity_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("xenia-launcher-core-test-{}", rand_suffix()))
            .join("identity.json")
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    /// Resolve a real, short-lived Unix binary (`sleep`, `true`, `sh`) via
    /// `$PATH` for test fixtures only -- this crate's own
    /// [`crate::discovery`] deliberately never does this for the real
    /// daemon it supervises (see that module's doc comment); a test
    /// picking its own throwaway fixture process is a different thing
    /// than the crate resolving what it's actually going to spawn in
    /// production. Needed because this isn't a fixed-FHS-path guarantee
    /// across every Unix this crate's tests might run on (e.g. NixOS has
    /// no `/bin/sleep`).
    #[cfg(unix)]
    fn resolve_test_binary(name: &str) -> PathBuf {
        let path_var = std::env::var_os("PATH").expect("PATH must be set to run these tests");
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!("test fixture binary {name:?} not found on $PATH");
    }

    #[tokio::test]
    async fn spawn_persists_identity_and_reports_alive() {
        let identity_path = identity_path();
        #[cfg(unix)]
        let binary = resolve_test_binary("sleep");
        #[cfg(windows)]
        let binary = PathBuf::from("C:\\Windows\\System32\\timeout.exe");
        #[cfg(unix)]
        let args = vec!["30".into()];
        #[cfg(windows)]
        let args = vec!["/T".into(), "30".into(), "/NOBREAK".into()];

        let mut process = DaemonProcess::spawn(&binary, &args, &identity_path)
            .await
            .unwrap();
        assert!(process.is_alive().unwrap());

        let persisted = xenia_secure_file::read_secure_file_if_exists(&identity_path)
            .unwrap()
            .unwrap();
        let identity: ProcessIdentity = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(identity.pid, process.pid());

        process.stop(Duration::from_secs(2)).await.unwrap();
        std::fs::remove_file(&identity_path).ok();
    }

    #[tokio::test]
    async fn stop_on_an_already_exited_process_is_a_no_op() {
        let identity_path = identity_path();
        #[cfg(unix)]
        let binary = resolve_test_binary("true");
        #[cfg(windows)]
        let binary = PathBuf::from("C:\\Windows\\System32\\cmd.exe");
        #[cfg(unix)]
        let args: Vec<std::ffi::OsString> = vec![];
        #[cfg(windows)]
        let args: Vec<std::ffi::OsString> = vec!["/C".into(), "exit".into(), "0".into()];

        let mut process = DaemonProcess::spawn(&binary, &args, &identity_path)
            .await
            .unwrap();
        // Give it a moment to actually exit before we ask.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!process.is_alive().unwrap());
        process.stop(Duration::from_secs(1)).await.unwrap();
        std::fs::remove_file(&identity_path).ok();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stop_escalates_to_force_kill_when_the_graceful_signal_is_ignored() {
        let identity_path = identity_path();
        // A deliberate, narrow exception to "never invoke a shell": this
        // is a *test fixture* process (ignores SIGINT so the escalation
        // path is actually exercised), not the crate's own spawn() being
        // handed caller-assembled shell text -- spawn() itself still
        // never touches a shell for real callers.
        let binary = resolve_test_binary("sh");
        let args: Vec<std::ffi::OsString> = vec!["-c".into(), "trap '' INT; sleep 30".into()];

        let mut process = DaemonProcess::spawn(&binary, &args, &identity_path)
            .await
            .unwrap();
        assert!(process.is_alive().unwrap());
        // Let the shell actually reach and execute `trap '' INT` before
        // testing what happens when it's signaled -- a real daemon binary
        // installs its signal handler essentially at process start, but
        // this fixture is a shell script that has to parse and run a
        // statement first. Without this, the signal can race ahead of the
        // trap being installed, killing the fixture via SIGINT's *default*
        // disposition and making the test pass for the wrong reason (or,
        // as first written, fail spuriously) -- a test-fixture timing
        // artifact, not something about `stop()` itself.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = std::time::Instant::now();
        process.stop(Duration::from_millis(300)).await.unwrap();
        // Must have taken at least the graceful window (SIGINT was
        // ignored, so it couldn't have exited before the escalation) --
        // proves force-kill actually fired rather than the graceful
        // signal coincidentally working.
        assert!(started.elapsed() >= Duration::from_millis(300));
        std::fs::remove_file(&identity_path).ok();
    }

    #[tokio::test]
    async fn try_reattach_returns_none_when_no_identity_file_exists() {
        let identity_path = identity_path();
        let result = DaemonProcess::try_reattach(&identity_path).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn try_reattach_returns_none_for_a_stale_dead_pid() {
        let identity_path = identity_path();
        // A pid vanishingly unlikely to be alive and, if it somehow were,
        // vanishingly unlikely to be this exact fabricated binary path.
        let identity = ProcessIdentity {
            pid: 999_999,
            binary_path: PathBuf::from("/does/not/exist/xenia-peer"),
        };
        let bytes = serde_json::to_vec(&identity).unwrap();
        xenia_secure_file::secure_overwrite(&identity_path, &bytes).unwrap();

        let result = DaemonProcess::try_reattach(&identity_path).await.unwrap();
        assert!(result.is_none());
        std::fs::remove_file(&identity_path).ok();
    }

    #[tokio::test]
    async fn try_reattach_finds_a_genuinely_still_running_owned_process() {
        let identity_path = identity_path();
        #[cfg(unix)]
        let binary = resolve_test_binary("sleep");
        #[cfg(windows)]
        let binary = PathBuf::from("C:\\Windows\\System32\\timeout.exe");
        #[cfg(unix)]
        let args = vec!["30".into()];
        #[cfg(windows)]
        let args = vec!["/T".into(), "30".into(), "/NOBREAK".into()];

        let spawned = DaemonProcess::spawn(&binary, &args, &identity_path)
            .await
            .unwrap();
        let expected_pid = spawned.pid();

        let reattached = DaemonProcess::try_reattach(&identity_path)
            .await
            .unwrap()
            .expect("the just-spawned process should be reattachable");
        assert_eq!(reattached.pid(), expected_pid);

        spawned.stop(Duration::from_secs(2)).await.unwrap();
        std::fs::remove_file(&identity_path).ok();
    }

    #[tokio::test]
    async fn try_reattach_detects_a_reused_pid_pointing_at_a_different_binary() {
        let identity_path = identity_path();
        #[cfg(unix)]
        let real_binary = resolve_test_binary("sleep");
        #[cfg(windows)]
        let real_binary = PathBuf::from("C:\\Windows\\System32\\timeout.exe");
        #[cfg(unix)]
        let args = vec!["30".into()];
        #[cfg(windows)]
        let args = vec!["/T".into(), "30".into(), "/NOBREAK".into()];

        let spawned = DaemonProcess::spawn(&real_binary, &args, &identity_path)
            .await
            .unwrap();

        // Overwrite the persisted identity to claim this live pid is a
        // *different* binary -- simulating "the pid got reused since we
        // last recorded it" without needing to actually wait for a real
        // reuse to happen.
        let fabricated = ProcessIdentity {
            pid: spawned.pid(),
            binary_path: PathBuf::from("/definitely/not/the/real/binary"),
        };
        let bytes = serde_json::to_vec(&fabricated).unwrap();
        xenia_secure_file::secure_overwrite(&identity_path, &bytes).unwrap();

        let result = DaemonProcess::try_reattach(&identity_path).await;
        assert!(matches!(result, Err(ProcessError::IdentityMismatch { .. })));

        spawned.stop(Duration::from_secs(2)).await.unwrap();
        std::fs::remove_file(&identity_path).ok();
    }
}
