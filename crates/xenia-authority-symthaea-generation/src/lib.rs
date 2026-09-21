// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable authority-state generation for Xenia decisions consumed by Symthaea.
//!
//! XENIA-SYM-001D1 binds portable positive authorization receipts to a
//! monotonically increasing `authority_state_epoch`. This crate gives that
//! field a concrete v1 meaning without pretending wall-clock time, process
//! uptime, or an unrelated audit sequence is authority state.
//!
//! The ledger is explicitly bootstrapped once, is bound to one daemon host
//! fingerprint, persists the canonical effective-authority-state commitment,
//! and advances only when semantic authority state changes. After bootstrap a
//! missing, malformed, host-mismatched, or unpersistable ledger fails closed.
//! Runtime snapshots and mutations share one coordinator lock so integrated
//! callers cannot issue a snapshot across two generations.
//!
//! This crate deliberately does **not** mutate `OperatorPolicy` or
//! `OperatorRevocations` itself. The live daemon adapter must perform every
//! authority-relevant mutation inside [`AuthorityStateCoordinator::with_mutation`]
//! and every portable-receipt snapshot inside
//! [`AuthorityStateCoordinator::with_stable_snapshot`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Ledger format version.
pub const AUTHORITY_GENERATION_LEDGER_VERSION_V1: u16 = 1;
/// Domain prefix for the durable authority-generation ledger bytes.
pub const AUTHORITY_GENERATION_LEDGER_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-authority-generation-ledger-v1\0";
/// SHA-256 byte length.
pub const SHA256_LEN: usize = 32;
/// First valid authority generation after explicit bootstrap.
pub const FIRST_AUTHORITY_GENERATION_V1: u64 = 1;

const CHECKSUM_LEN: usize = SHA256_LEN;
const FIXED_RECORD_LEN: usize =
    2 + SHA256_LEN + 8 + SHA256_LEN + CHECKSUM_LEN;

/// Stable authority version represented by the durable ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityVersionV1 {
    /// Xenia daemon host identity this generation sequence belongs to.
    pub daemon_host_fingerprint: [u8; SHA256_LEN],
    /// Monotonic authority generation.
    pub generation: u64,
    /// Canonical effective-policy commitment represented by this generation.
    pub state_commitment_sha256: [u8; SHA256_LEN],
}

impl AuthorityVersionV1 {
    fn validate(&self) -> Result<(), AuthorityGenerationError> {
        if self.daemon_host_fingerprint == [0; SHA256_LEN] {
            return Err(AuthorityGenerationError::ZeroHostFingerprint);
        }
        if self.generation < FIRST_AUTHORITY_GENERATION_V1 {
            return Err(AuthorityGenerationError::ZeroGeneration);
        }
        if self.state_commitment_sha256 == [0; SHA256_LEN] {
            return Err(AuthorityGenerationError::ZeroStateCommitment);
        }
        Ok(())
    }
}

/// Value returned from one read-lock-protected authority snapshot.
#[derive(Debug)]
pub struct StableAuthoritySnapshot<T> {
    version: AuthorityVersionV1,
    value: T,
}

impl<T> StableAuthoritySnapshot<T> {
    /// Exact generation/state identity that was held stable while `value` was read.
    pub const fn version(&self) -> AuthorityVersionV1 {
        self.version
    }

    /// Snapshot payload read while the authority coordinator's read lock was held.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consume the wrapper and return its payload.
    pub fn into_value(self) -> T {
        self.value
    }
}

/// Outcome returned by an authority mutation closure.
///
/// `Changed` requires the caller to provide the canonical commitment of the
/// **post-mutation effective authority state**. `Unchanged` leaves the durable
/// generation untouched.
#[derive(Debug)]
pub enum AuthorityMutation<T> {
    /// The attempted operation succeeded without changing effective authority state.
    Unchanged(T),
    /// Effective authority state changed and must advance to a new generation.
    Changed {
        /// Operation result.
        value: T,
        /// Canonical post-mutation effective-policy commitment.
        state_commitment_sha256: [u8; SHA256_LEN],
    },
}

impl<T> AuthorityMutation<T> {
    /// Construct a successful no-op authority mutation.
    pub fn unchanged(value: T) -> Self {
        Self::Unchanged(value)
    }

    /// Construct a semantic authority change.
    pub fn changed(
        value: T,
        state_commitment_sha256: [u8; SHA256_LEN],
    ) -> Result<Self, AuthorityGenerationError> {
        if state_commitment_sha256 == [0; SHA256_LEN] {
            return Err(AuthorityGenerationError::ZeroStateCommitment);
        }
        Ok(Self::Changed {
            value,
            state_commitment_sha256,
        })
    }
}

#[derive(Debug)]
struct CoordinatorState {
    version: AuthorityVersionV1,
    poisoned: bool,
}

/// Shared runtime coordinator for coherent authority snapshots and mutations.
///
/// Every live authority-relevant writer must execute under `with_mutation`, and
/// every receipt snapshot must execute under `with_stable_snapshot`. The write
/// lock is held across the caller's mutation closure and ledger persistence;
/// the read lock is held across the caller's snapshot closure.
#[derive(Clone, Debug)]
pub struct AuthorityStateCoordinator {
    ledger_path: Arc<PathBuf>,
    state: Arc<RwLock<CoordinatorState>>,
}

impl AuthorityStateCoordinator {
    /// Explicitly bootstrap a **new** authority generation ledger.
    ///
    /// This fails if a ledger already exists. Production startup must not call
    /// bootstrap as a fallback for a missing existing ledger, because silently
    /// resetting the generation would destroy rollback semantics.
    pub fn bootstrap_new(
        ledger_path: impl AsRef<Path>,
        daemon_host_fingerprint: [u8; SHA256_LEN],
        initial_state_commitment_sha256: [u8; SHA256_LEN],
    ) -> Result<Self, AuthorityGenerationError> {
        let path = ledger_path.as_ref().to_path_buf();
        if path.exists() {
            return Err(AuthorityGenerationError::LedgerAlreadyExists);
        }
        let version = AuthorityVersionV1 {
            daemon_host_fingerprint,
            generation: FIRST_AUTHORITY_GENERATION_V1,
            state_commitment_sha256: initial_state_commitment_sha256,
        };
        version.validate()?;
        persist_new(&path, version)?;
        Ok(Self::from_version(path, version))
    }

    /// Open an existing ledger and reconcile it with current effective state.
    ///
    /// A missing ledger fails closed. If the current canonical authority-state
    /// commitment differs from the durable commitment (for example after an
    /// offline config edit while the daemon was stopped), generation advances
    /// and the new commitment is persisted before this coordinator is returned.
    pub fn open_existing(
        ledger_path: impl AsRef<Path>,
        expected_daemon_host_fingerprint: [u8; SHA256_LEN],
        current_state_commitment_sha256: [u8; SHA256_LEN],
    ) -> Result<Self, AuthorityGenerationError> {
        if expected_daemon_host_fingerprint == [0; SHA256_LEN] {
            return Err(AuthorityGenerationError::ZeroHostFingerprint);
        }
        if current_state_commitment_sha256 == [0; SHA256_LEN] {
            return Err(AuthorityGenerationError::ZeroStateCommitment);
        }

        let path = ledger_path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(AuthorityGenerationError::LedgerMissing);
        }
        let mut version = read_record(&path)?;
        if version.daemon_host_fingerprint != expected_daemon_host_fingerprint {
            return Err(AuthorityGenerationError::HostFingerprintMismatch);
        }

        if version.state_commitment_sha256 != current_state_commitment_sha256 {
            version.generation = version
                .generation
                .checked_add(1)
                .ok_or(AuthorityGenerationError::GenerationOverflow)?;
            version.state_commitment_sha256 = current_state_commitment_sha256;
            persist_replace(&path, version)?;
        }

        Ok(Self::from_version(path, version))
    }

    fn from_version(path: PathBuf, version: AuthorityVersionV1) -> Self {
        Self {
            ledger_path: Arc::new(path),
            state: Arc::new(RwLock::new(CoordinatorState {
                version,
                poisoned: false,
            })),
        }
    }

    /// Return the current version if the coordinator is healthy.
    pub fn current_version(&self) -> Result<AuthorityVersionV1, AuthorityGenerationError> {
        let state = self
            .state
            .read()
            .map_err(|_| AuthorityGenerationError::LockPoisoned)?;
        ensure_healthy(&state)?;
        Ok(state.version)
    }

    /// Read a coherent authority snapshot under the coordinator's read lock.
    ///
    /// Live integration must read enrollment, revocation and policy state only
    /// inside `snapshot_fn`. Integrated writers using `with_mutation` cannot
    /// interleave until this closure returns.
    pub fn with_stable_snapshot<T, F>(
        &self,
        snapshot_fn: F,
    ) -> Result<StableAuthoritySnapshot<T>, AuthorityGenerationError>
    where
        F: FnOnce(AuthorityVersionV1) -> Result<T, AuthorityGenerationError>,
    {
        let state = self
            .state
            .read()
            .map_err(|_| AuthorityGenerationError::LockPoisoned)?;
        ensure_healthy(&state)?;
        let version = state.version;
        let value = snapshot_fn(version)?;
        Ok(StableAuthoritySnapshot { version, value })
    }

    /// Execute one authority mutation under the coordinator's write lock.
    ///
    /// A failed closure does not advance generation. An `Unchanged` result does
    /// not advance generation. A `Changed` result increments exactly once and
    /// persists the post-mutation state commitment before returning success.
    ///
    /// If the external mutation succeeds but durable generation persistence
    /// fails, this coordinator is permanently poisoned for the process. That is
    /// fail-closed: no later snapshot/receipt may claim a generation that was
    /// not durably recorded. Restart/open reconciliation is then required.
    pub fn with_mutation<T, F>(&self, mutation_fn: F) -> Result<T, AuthorityGenerationError>
    where
        F: FnOnce() -> Result<AuthorityMutation<T>, AuthorityGenerationError>,
    {
        let mut state = self
            .state
            .write()
            .map_err(|_| AuthorityGenerationError::LockPoisoned)?;
        ensure_healthy(&state)?;

        let mutation = mutation_fn()?;
        match mutation {
            AuthorityMutation::Unchanged(value) => Ok(value),
            AuthorityMutation::Changed {
                value,
                state_commitment_sha256,
            } => {
                let next_generation = state
                    .version
                    .generation
                    .checked_add(1)
                    .ok_or(AuthorityGenerationError::GenerationOverflow)?;
                let next = AuthorityVersionV1 {
                    daemon_host_fingerprint: state.version.daemon_host_fingerprint,
                    generation: next_generation,
                    state_commitment_sha256,
                };
                next.validate()?;

                if let Err(error) = persist_replace(&self.ledger_path, next) {
                    state.poisoned = true;
                    return Err(error);
                }
                state.version = next;
                Ok(value)
            }
        }
    }

    /// Whether this process has failed closed after an unrecoverable coordinator
    /// or persistence fault. A poisoned coordinator refuses both reads and writes.
    pub fn is_poisoned(&self) -> bool {
        self.state.read().map(|state| state.poisoned).unwrap_or(true)
    }
}

fn ensure_healthy(state: &CoordinatorState) -> Result<(), AuthorityGenerationError> {
    if state.poisoned {
        Err(AuthorityGenerationError::CoordinatorPoisoned)
    } else {
        Ok(())
    }
}

fn encode_record(version: AuthorityVersionV1) -> Result<Vec<u8>, AuthorityGenerationError> {
    version.validate()?;
    let mut body = Vec::with_capacity(AUTHORITY_GENERATION_LEDGER_DOMAIN_V1.len() + FIXED_RECORD_LEN);
    body.extend_from_slice(AUTHORITY_GENERATION_LEDGER_DOMAIN_V1);
    body.extend_from_slice(&AUTHORITY_GENERATION_LEDGER_VERSION_V1.to_be_bytes());
    body.extend_from_slice(&version.daemon_host_fingerprint);
    body.extend_from_slice(&version.generation.to_be_bytes());
    body.extend_from_slice(&version.state_commitment_sha256);
    let checksum: [u8; SHA256_LEN] = Sha256::digest(&body).into();
    body.extend_from_slice(&checksum);
    Ok(body)
}

fn decode_record(bytes: &[u8]) -> Result<AuthorityVersionV1, AuthorityGenerationError> {
    let expected_len = AUTHORITY_GENERATION_LEDGER_DOMAIN_V1.len() + FIXED_RECORD_LEN;
    if bytes.len() != expected_len || !bytes.starts_with(AUTHORITY_GENERATION_LEDGER_DOMAIN_V1) {
        return Err(AuthorityGenerationError::MalformedLedger);
    }

    let checksum_offset = bytes.len() - CHECKSUM_LEN;
    let expected_checksum: [u8; SHA256_LEN] = Sha256::digest(&bytes[..checksum_offset]).into();
    if bytes[checksum_offset..] != expected_checksum {
        return Err(AuthorityGenerationError::ChecksumMismatch);
    }

    let mut offset = AUTHORITY_GENERATION_LEDGER_DOMAIN_V1.len();
    let version = u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .map_err(|_| AuthorityGenerationError::MalformedLedger)?,
    );
    offset += 2;
    if version != AUTHORITY_GENERATION_LEDGER_VERSION_V1 {
        return Err(AuthorityGenerationError::UnsupportedLedgerVersion(version));
    }

    let daemon_host_fingerprint = bytes[offset..offset + SHA256_LEN]
        .try_into()
        .map_err(|_| AuthorityGenerationError::MalformedLedger)?;
    offset += SHA256_LEN;
    let generation = u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| AuthorityGenerationError::MalformedLedger)?,
    );
    offset += 8;
    let state_commitment_sha256 = bytes[offset..offset + SHA256_LEN]
        .try_into()
        .map_err(|_| AuthorityGenerationError::MalformedLedger)?;

    let value = AuthorityVersionV1 {
        daemon_host_fingerprint,
        generation,
        state_commitment_sha256,
    };
    value.validate()?;
    Ok(value)
}

fn read_record(path: &Path) -> Result<AuthorityVersionV1, AuthorityGenerationError> {
    let mut file = File::open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => AuthorityGenerationError::LedgerMissing,
        _ => AuthorityGenerationError::Io(error.to_string()),
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| AuthorityGenerationError::Io(error.to_string()))?;
    decode_record(&bytes)
}

fn persist_new(path: &Path, version: AuthorityVersionV1) -> Result<(), AuthorityGenerationError> {
    let bytes = encode_record(version)?;
    let parent = parent_directory(path)?;
    let mut options = secure_open_options();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => AuthorityGenerationError::LedgerAlreadyExists,
        _ => AuthorityGenerationError::Io(error.to_string()),
    })?;
    file.write_all(&bytes)
        .map_err(|error| AuthorityGenerationError::Io(error.to_string()))?;
    file.sync_all()
        .map_err(|error| AuthorityGenerationError::Io(error.to_string()))?;
    sync_directory(parent)?;
    Ok(())
}

fn persist_replace(
    path: &Path,
    version: AuthorityVersionV1,
) -> Result<(), AuthorityGenerationError> {
    let bytes = encode_record(version)?;
    let parent = parent_directory(path)?;
    if !parent.exists() {
        return Err(AuthorityGenerationError::LedgerStorageUnavailable);
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(AuthorityGenerationError::InvalidLedgerPath)?;
    let temp_path = parent.join(format!(
        ".{file_name}.authority-generation.tmp-{}-{nanos}",
        std::process::id()
    ));

    let write_result = (|| -> Result<(), AuthorityGenerationError> {
        let mut options = secure_open_options();
        options.write(true).create_new(true);
        let mut file = options
            .open(&temp_path)
            .map_err(|error| AuthorityGenerationError::Io(error.to_string()))?;
        file.write_all(&bytes)
            .map_err(|error| AuthorityGenerationError::Io(error.to_string()))?;
        file.sync_all()
            .map_err(|error| AuthorityGenerationError::Io(error.to_string()))?;
        std::fs::rename(&temp_path, path)
            .map_err(|error| AuthorityGenerationError::Io(error.to_string()))?;
        sync_directory(parent)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

fn parent_directory(path: &Path) -> Result<&Path, AuthorityGenerationError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(AuthorityGenerationError::InvalidLedgerPath)
}

fn secure_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn sync_directory(path: &Path) -> Result<(), AuthorityGenerationError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| AuthorityGenerationError::Io(error.to_string()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Fail-closed errors from the authority-generation boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorityGenerationError {
    /// Existing ledger was required but not found.
    #[error("authority generation ledger is missing")]
    LedgerMissing,
    /// Bootstrap was attempted over an existing ledger.
    #[error("authority generation ledger already exists")]
    LedgerAlreadyExists,
    /// Ledger bytes were malformed or had the wrong fixed layout.
    #[error("authority generation ledger is malformed")]
    MalformedLedger,
    /// Ledger checksum did not match its contents.
    #[error("authority generation ledger checksum mismatch")]
    ChecksumMismatch,
    /// Ledger schema version is unsupported.
    #[error("unsupported authority generation ledger version {0}")]
    UnsupportedLedgerVersion(u16),
    /// Ledger belongs to a different Xenia daemon host identity.
    #[error("authority generation ledger host fingerprint mismatch")]
    HostFingerprintMismatch,
    /// Host fingerprint used an all-zero sentinel rather than a real identity.
    #[error("daemon host fingerprint must not be all zero")]
    ZeroHostFingerprint,
    /// Generation zero is reserved and never a valid persisted state.
    #[error("authority generation must be at least one")]
    ZeroGeneration,
    /// Canonical state commitment used an all-zero sentinel.
    #[error("authority state commitment must not be all zero")]
    ZeroStateCommitment,
    /// Monotonic generation reached `u64::MAX`.
    #[error("authority generation overflow")]
    GenerationOverflow,
    /// Coordinator lock was poisoned by a panic.
    #[error("authority generation coordinator lock poisoned")]
    LockPoisoned,
    /// A prior mutation changed authority state but its new generation could not
    /// be durably persisted, so this process refuses further authority use.
    #[error("authority generation coordinator is fail-closed/poisoned")]
    CoordinatorPoisoned,
    /// Ledger storage path disappeared or became unavailable after startup.
    #[error("authority generation ledger storage unavailable")]
    LedgerStorageUnavailable,
    /// Ledger path lacks a usable parent/file name.
    #[error("invalid authority generation ledger path")]
    InvalidLedgerPath,
    /// Caller mutation failed before any generation transition was committed.
    #[error("authority mutation failed: {0}")]
    MutationFailed(String),
    /// Filesystem persistence/read error.
    #[error("authority generation ledger I/O error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    const HOST: [u8; SHA256_LEN] = [0x11; SHA256_LEN];
    const STATE_A: [u8; SHA256_LEN] = [0x22; SHA256_LEN];
    const STATE_B: [u8; SHA256_LEN] = [0x33; SHA256_LEN];
    const STATE_C: [u8; SHA256_LEN] = [0x44; SHA256_LEN];

    fn ledger_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("authority-generation-v1.bin")
    }

    #[test]
    fn bootstrap_is_explicit_and_restart_preserves_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        let coordinator = AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap();
        assert_eq!(
            coordinator.current_version().unwrap().generation,
            FIRST_AUTHORITY_GENERATION_V1
        );
        assert_eq!(
            AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap_err(),
            AuthorityGenerationError::LedgerAlreadyExists
        );

        let reopened = AuthorityStateCoordinator::open_existing(&path, HOST, STATE_A).unwrap();
        assert_eq!(reopened.current_version().unwrap().generation, 1);
        assert_eq!(
            reopened.current_version().unwrap().state_commitment_sha256,
            STATE_A
        );
    }

    #[test]
    fn missing_existing_ledger_never_silently_reboots_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        assert_eq!(
            AuthorityStateCoordinator::open_existing(&path, HOST, STATE_A).unwrap_err(),
            AuthorityGenerationError::LedgerMissing
        );
    }

    #[test]
    fn offline_state_drift_advances_before_coordinator_is_returned() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        drop(AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap());

        let reopened = AuthorityStateCoordinator::open_existing(&path, HOST, STATE_B).unwrap();
        let version = reopened.current_version().unwrap();
        assert_eq!(version.generation, 2);
        assert_eq!(version.state_commitment_sha256, STATE_B);

        drop(reopened);
        let second_restart = AuthorityStateCoordinator::open_existing(&path, HOST, STATE_B).unwrap();
        assert_eq!(second_restart.current_version().unwrap().generation, 2);
    }

    #[test]
    fn host_identity_mismatch_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        drop(AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap());
        assert_eq!(
            AuthorityStateCoordinator::open_existing(&path, [0x99; 32], STATE_A).unwrap_err(),
            AuthorityGenerationError::HostFingerprintMismatch
        );
    }

    #[test]
    fn semantic_change_advances_once_and_noop_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        let coordinator = AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap();

        let result = coordinator
            .with_mutation(|| AuthorityMutation::changed("rotated", STATE_B))
            .unwrap();
        assert_eq!(result, "rotated");
        assert_eq!(coordinator.current_version().unwrap().generation, 2);
        assert_eq!(
            coordinator.current_version().unwrap().state_commitment_sha256,
            STATE_B
        );

        let result = coordinator
            .with_mutation(|| Ok(AuthorityMutation::unchanged("same")))
            .unwrap();
        assert_eq!(result, "same");
        assert_eq!(coordinator.current_version().unwrap().generation, 2);
    }

    #[test]
    fn failed_mutation_does_not_advance() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        let coordinator = AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap();

        let error = coordinator
            .with_mutation::<(), _>(|| {
                Err(AuthorityGenerationError::MutationFailed(
                    "policy rejected change".to_string(),
                ))
            })
            .unwrap_err();
        assert_eq!(
            error,
            AuthorityGenerationError::MutationFailed("policy rejected change".to_string())
        );
        assert_eq!(coordinator.current_version().unwrap().generation, 1);
    }

    #[test]
    fn snapshot_holds_read_barrier_against_integrated_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        let coordinator = AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap();
        let writer = coordinator.clone();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let writer_finished = Arc::new(AtomicBool::new(false));

        let entered_writer = entered.clone();
        let release_writer = release.clone();
        let finished = writer_finished.clone();
        let handle = thread::spawn(move || {
            entered_writer.wait();
            writer
                .with_mutation(|| AuthorityMutation::changed((), STATE_B))
                .unwrap();
            finished.store(true, Ordering::SeqCst);
            release_writer.wait();
        });

        let snapshot = coordinator
            .with_stable_snapshot(|version| {
                entered.wait();
                thread::sleep(Duration::from_millis(30));
                assert!(!writer_finished.load(Ordering::SeqCst));
                assert_eq!(version.generation, 1);
                Ok("snapshot")
            })
            .unwrap();
        assert_eq!(snapshot.version().generation, 1);
        assert_eq!(snapshot.value(), &"snapshot");

        release.wait();
        handle.join().unwrap();
        assert_eq!(coordinator.current_version().unwrap().generation, 2);
    }

    #[test]
    fn persistence_failure_after_semantic_mutation_poisons_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        let coordinator = AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(dir.path()).unwrap();

        let error = coordinator
            .with_mutation(|| AuthorityMutation::changed((), STATE_C))
            .unwrap_err();
        assert_eq!(error, AuthorityGenerationError::LedgerStorageUnavailable);
        assert!(coordinator.is_poisoned());
        assert_eq!(
            coordinator.current_version().unwrap_err(),
            AuthorityGenerationError::CoordinatorPoisoned
        );
    }

    #[test]
    fn checksum_corruption_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger_path(&dir);
        drop(AuthorityStateCoordinator::bootstrap_new(&path, HOST, STATE_A).unwrap());

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();

        assert_eq!(
            AuthorityStateCoordinator::open_existing(&path, HOST, STATE_A).unwrap_err(),
            AuthorityGenerationError::ChecksumMismatch
        );
    }

    #[test]
    fn ledger_encoding_round_trips_and_binds_all_fields() {
        let base = AuthorityVersionV1 {
            daemon_host_fingerprint: HOST,
            generation: 7,
            state_commitment_sha256: STATE_A,
        };
        let encoded = encode_record(base).unwrap();
        assert_eq!(decode_record(&encoded).unwrap(), base);

        let mut changed = base;
        changed.generation += 1;
        assert_ne!(encode_record(base).unwrap(), encode_record(changed).unwrap());
        changed = base;
        changed.daemon_host_fingerprint = [0x55; 32];
        assert_ne!(encode_record(base).unwrap(), encode_record(changed).unwrap());
        changed = base;
        changed.state_commitment_sha256 = STATE_B;
        assert_ne!(encode_record(base).unwrap(), encode_record(changed).unwrap());
    }
}
