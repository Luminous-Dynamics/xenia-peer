// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed live mutation guard for Xenia authority state consumed by Symthaea.
//!
//! The lower-level authority-generation coordinator already serializes stable
//! snapshots and mutations and poisons itself when durable generation
//! persistence fails. This wrapper closes one remaining live-integration gap:
//! callers can explicitly distinguish a failure that happened **before** any
//! authority state changed from one that happened **after** authority changed
//! but before a canonical post-state commitment could be produced.
//!
//! A post-change failure poisons this guard immediately. Production code must
//! route all Symthaea authority snapshots and mutations through one shared guard
//! and must not retain a parallel raw `AuthorityStateCoordinator` handle.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;
use std::sync::{Arc, RwLock};

use xenia_symthaea_authority_generation::{
    AuthorityGenerationError, AuthorityMutation, AuthorityStateCoordinator, AuthorityVersionV1,
    SHA256_LEN, StableAuthoritySnapshot,
};

/// Semantic result of one live authority mutation attempt.
#[derive(Debug)]
pub enum LiveAuthorityMutation<T, E> {
    /// Operation completed without changing effective authority state.
    Unchanged(T),
    /// Effective authority state changed and a canonical post-state commitment
    /// was successfully produced.
    Changed {
        /// Operation result.
        value: T,
        /// Canonical commitment to the post-mutation effective authority state.
        post_state_commitment_sha256: [u8; SHA256_LEN],
    },
    /// Operation failed before effective authority state changed.
    FailedBeforeChange(E),
    /// Effective authority state changed, but a later step required to describe
    /// that state failed. Portable authority issuance must fail closed.
    FailedAfterChange(E),
}

impl<T, E> LiveAuthorityMutation<T, E> {
    /// Successful semantic no-op.
    pub fn unchanged(value: T) -> Self {
        Self::Unchanged(value)
    }

    /// Successful semantic change with its post-state commitment.
    pub fn changed(value: T, post_state_commitment_sha256: [u8; SHA256_LEN]) -> Self {
        Self::Changed {
            value,
            post_state_commitment_sha256,
        }
    }

    /// Failure before any effective authority state change.
    pub fn failed_before_change(error: E) -> Self {
        Self::FailedBeforeChange(error)
    }

    /// Failure after effective authority state changed.
    pub fn failed_after_change(error: E) -> Self {
        Self::FailedAfterChange(error)
    }
}

/// Errors from the guarded live authority boundary.
#[derive(Debug)]
pub enum LiveAuthorityGuardError<E> {
    /// Lower-level generation/ledger failure before a caller-reported semantic
    /// authority change.
    Generation(AuthorityGenerationError),
    /// Lower-level generation/ledger failure after the caller reported that
    /// effective authority state changed. The guard is poisoned.
    GenerationAfterChange(AuthorityGenerationError),
    /// Caller failed before authority state changed.
    MutationBeforeChange(E),
    /// Caller failed after authority state changed. The guard is poisoned.
    MutationAfterChange(E),
    /// Snapshot callback could not read/construct authoritative state.
    Snapshot(E),
    /// A prior post-change or persistence failure poisoned this guard.
    GuardPoisoned,
    /// Guard synchronization lock itself was poisoned.
    GuardLockPoisoned,
}

#[derive(Debug, Default)]
struct GuardState {
    poisoned: bool,
}

/// Sole live runtime boundary for Symthaea-relevant Xenia authority state.
///
/// This type intentionally constructs its private lower-level coordinator
/// itself rather than accepting a caller-provided clone. Production code should
/// keep only this guard so a post-change failure cannot be bypassed by reading
/// from a raw coordinator that still appears healthy.
#[derive(Clone, Debug)]
pub struct LiveAuthorityGuard {
    inner: AuthorityStateCoordinator,
    gate: Arc<RwLock<GuardState>>,
}

impl LiveAuthorityGuard {
    /// Explicitly bootstrap a new durable authority generation and guard.
    pub fn bootstrap_new(
        ledger_path: impl AsRef<Path>,
        daemon_host_fingerprint: [u8; SHA256_LEN],
        initial_state_commitment_sha256: [u8; SHA256_LEN],
    ) -> Result<Self, LiveAuthorityGuardError<std::convert::Infallible>> {
        let inner = AuthorityStateCoordinator::bootstrap_new(
            ledger_path,
            daemon_host_fingerprint,
            initial_state_commitment_sha256,
        )
        .map_err(LiveAuthorityGuardError::Generation)?;
        Ok(Self {
            inner,
            gate: Arc::new(RwLock::new(GuardState::default())),
        })
    }

    /// Open and reconcile an existing durable authority generation under the
    /// guard boundary.
    pub fn open_existing(
        ledger_path: impl AsRef<Path>,
        expected_daemon_host_fingerprint: [u8; SHA256_LEN],
        current_state_commitment_sha256: [u8; SHA256_LEN],
    ) -> Result<Self, LiveAuthorityGuardError<std::convert::Infallible>> {
        let inner = AuthorityStateCoordinator::open_existing(
            ledger_path,
            expected_daemon_host_fingerprint,
            current_state_commitment_sha256,
        )
        .map_err(LiveAuthorityGuardError::Generation)?;
        Ok(Self {
            inner,
            gate: Arc::new(RwLock::new(GuardState::default())),
        })
    }

    /// Return the current durable authority version if both guard layers are
    /// healthy.
    pub fn current_version(
        &self,
    ) -> Result<AuthorityVersionV1, LiveAuthorityGuardError<std::convert::Infallible>> {
        let guard = self
            .gate
            .read()
            .map_err(|_| LiveAuthorityGuardError::GuardLockPoisoned)?;
        if guard.poisoned {
            return Err(LiveAuthorityGuardError::GuardPoisoned);
        }
        self.inner
            .current_version()
            .map_err(LiveAuthorityGuardError::Generation)
    }

    /// Read authoritative state while both the outer guard read barrier and
    /// lower-level generation read barrier are held.
    ///
    /// A snapshot callback failure does not poison the guard because it does not
    /// mutate authority state; it simply prevents issuance for that attempt.
    pub fn with_stable_snapshot<T, E, F>(
        &self,
        snapshot_fn: F,
    ) -> Result<StableAuthoritySnapshot<T>, LiveAuthorityGuardError<E>>
    where
        F: FnOnce(AuthorityVersionV1) -> Result<T, E>,
    {
        let guard = self
            .gate
            .read()
            .map_err(|_| LiveAuthorityGuardError::GuardLockPoisoned)?;
        if guard.poisoned {
            return Err(LiveAuthorityGuardError::GuardPoisoned);
        }

        let mut callback_error = None;
        let result = self.inner.with_stable_snapshot(|version| match snapshot_fn(version) {
            Ok(value) => Ok(value),
            Err(error) => {
                callback_error = Some(error);
                Err(AuthorityGenerationError::MutationFailed(
                    "live authority snapshot callback failed".to_string(),
                ))
            }
        });

        match result {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => match callback_error {
                Some(callback_error) => Err(LiveAuthorityGuardError::Snapshot(callback_error)),
                None => Err(LiveAuthorityGuardError::Generation(error)),
            },
        }
    }

    /// Execute one live authority mutation with explicit pre/post-change failure
    /// semantics.
    ///
    /// The outer write barrier remains held from before the caller mutation
    /// starts until any required guard poisoning is recorded, so another guard
    /// user cannot observe a post-change failure window as healthy.
    pub fn with_mutation<T, E, F>(&self, mutation_fn: F) -> Result<T, LiveAuthorityGuardError<E>>
    where
        F: FnOnce() -> LiveAuthorityMutation<T, E>,
    {
        let mut guard = self
            .gate
            .write()
            .map_err(|_| LiveAuthorityGuardError::GuardLockPoisoned)?;
        if guard.poisoned {
            return Err(LiveAuthorityGuardError::GuardPoisoned);
        }

        let mut before_error = None;
        let mut after_error = None;
        let mut caller_reported_change = false;

        let result = self.inner.with_mutation(|| match mutation_fn() {
            LiveAuthorityMutation::Unchanged(value) => Ok(AuthorityMutation::unchanged(value)),
            LiveAuthorityMutation::Changed {
                value,
                post_state_commitment_sha256,
            } => {
                caller_reported_change = true;
                AuthorityMutation::changed(value, post_state_commitment_sha256)
            }
            LiveAuthorityMutation::FailedBeforeChange(error) => {
                before_error = Some(error);
                Err(AuthorityGenerationError::MutationFailed(
                    "live authority mutation failed before change".to_string(),
                ))
            }
            LiveAuthorityMutation::FailedAfterChange(error) => {
                caller_reported_change = true;
                after_error = Some(error);
                Err(AuthorityGenerationError::MutationFailed(
                    "live authority mutation failed after change".to_string(),
                ))
            }
        });

        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if let Some(error) = after_error {
                    guard.poisoned = true;
                    return Err(LiveAuthorityGuardError::MutationAfterChange(error));
                }
                if let Some(error) = before_error {
                    return Err(LiveAuthorityGuardError::MutationBeforeChange(error));
                }
                if caller_reported_change {
                    // Includes invalid post-state commitments, generation
                    // overflow, and durable persistence failure after a real
                    // authority mutation. The inner coordinator may also be
                    // poisoned, but the outer guard records the fail-closed
                    // theorem independently.
                    guard.poisoned = true;
                    return Err(LiveAuthorityGuardError::GenerationAfterChange(error));
                }
                Err(LiveAuthorityGuardError::Generation(error))
            }
        }
    }

    /// Whether either guard layer is fail-closed/poisoned.
    pub fn is_poisoned(&self) -> bool {
        let outer = self.gate.read().map(|guard| guard.poisoned).unwrap_or(true);
        outer || self.inner.is_poisoned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const HOST: [u8; SHA256_LEN] = [0x11; SHA256_LEN];
    const STATE_A: [u8; SHA256_LEN] = [0x22; SHA256_LEN];
    const STATE_B: [u8; SHA256_LEN] = [0x33; SHA256_LEN];

    fn ledger_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("authority-generation.bin")
    }

    fn guard(dir: &tempfile::TempDir) -> LiveAuthorityGuard {
        LiveAuthorityGuard::bootstrap_new(ledger_path(dir), HOST, STATE_A).unwrap()
    }

    #[test]
    fn semantic_change_advances_and_noop_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(&dir);

        let value: u32 = guard
            .with_mutation(|| LiveAuthorityMutation::<_, &'static str>::unchanged(7))
            .unwrap();
        assert_eq!(value, 7);
        assert_eq!(guard.current_version().unwrap().generation, 1);

        let value: u32 = guard
            .with_mutation(|| LiveAuthorityMutation::<_, &'static str>::changed(9, STATE_B))
            .unwrap();
        assert_eq!(value, 9);
        assert_eq!(guard.current_version().unwrap().generation, 2);
        assert_eq!(
            guard.current_version().unwrap().state_commitment_sha256,
            STATE_B
        );
    }

    #[test]
    fn failure_before_change_does_not_poison_or_advance() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(&dir);
        let result: Result<(), LiveAuthorityGuardError<&'static str>> = guard.with_mutation(|| {
            LiveAuthorityMutation::failed_before_change("validation failed")
        });
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::MutationBeforeChange("validation failed"))
        ));
        assert!(!guard.is_poisoned());
        assert_eq!(guard.current_version().unwrap().generation, 1);
    }

    #[test]
    fn failure_after_change_poisons_before_another_snapshot_can_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(&dir);
        let result: Result<(), LiveAuthorityGuardError<&'static str>> = guard.with_mutation(|| {
            LiveAuthorityMutation::failed_after_change("post-state snapshot failed")
        });
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::MutationAfterChange(
                "post-state snapshot failed"
            ))
        ));
        assert!(guard.is_poisoned());

        let snapshot: Result<StableAuthoritySnapshot<()>, LiveAuthorityGuardError<&'static str>> =
            guard.with_stable_snapshot(|_| Ok(()));
        assert!(matches!(snapshot, Err(LiveAuthorityGuardError::GuardPoisoned)));
    }

    #[test]
    fn invalid_commitment_after_reported_change_poisons() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(&dir);
        let result: Result<(), LiveAuthorityGuardError<&'static str>> = guard.with_mutation(|| {
            LiveAuthorityMutation::changed((), [0; SHA256_LEN])
        });
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::GenerationAfterChange(
                AuthorityGenerationError::ZeroStateCommitment
            ))
        ));
        assert!(guard.is_poisoned());
    }

    #[test]
    fn snapshot_callback_failure_does_not_poison() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(&dir);
        let result: Result<StableAuthoritySnapshot<()>, LiveAuthorityGuardError<&'static str>> =
            guard.with_stable_snapshot(|_| Err("snapshot unavailable"));
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::Snapshot("snapshot unavailable"))
        ));
        assert!(!guard.is_poisoned());
        assert_eq!(guard.current_version().unwrap().generation, 1);
    }

    #[test]
    fn persistence_failure_after_change_poisons_both_layers() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        let guard = LiveAuthorityGuard::bootstrap_new(&path, HOST, STATE_A).unwrap();

        // Remove the backing directory after bootstrap so the underlying
        // coordinator's post-change persistence fails.
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(dir.path()).unwrap();

        let result: Result<(), LiveAuthorityGuardError<&'static str>> =
            guard.with_mutation(|| LiveAuthorityMutation::changed((), STATE_B));
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::GenerationAfterChange(_))
        ));
        assert!(guard.is_poisoned());
    }
}
