// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Experimental conservative SQLite backend for Xenia privileged-operation admissions.
//!
//! This tranche persists immutable operation admissions and grant-use reservations only.
//! It deliberately does not persist receipt events or enable any privileged side effect.
//! The security goal is to qualify the authority-spending transaction before adding the
//! next effect-bearing layer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use xenia_operation_receipt_finalization::{ReceiptAdmissionBindingV1, ReceiptFinalizationError};

/// Stable identifier for the first conservative SQLite durability profile.
pub const SQLITE_STORE_PROFILE_V1: &str = "sqlite-delete-extra-v1";
/// Exact schema version stored in the database metadata singleton.
pub const SQLITE_STORE_SCHEMA_VERSION_V1: i64 = 1;
/// Sidecar suffix used for fail-stop unclean-writer detection.
pub const UNCLEAN_WRITER_MARKER_SUFFIX_V1: &str = ".xenia-operation-store-open-v1";

const STORE_SCHEMA_SQL_V1: &str = r#"
CREATE TABLE store_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    store_id BLOB NOT NULL CHECK(length(store_id) = 16),
    generation INTEGER NOT NULL CHECK(generation >= 0),
    store_schema_digest BLOB NOT NULL CHECK(length(store_schema_digest) = 32),
    next_admission_sequence INTEGER NOT NULL CHECK(next_admission_sequence >= 0)
) STRICT;

CREATE TABLE admissions (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
    admission_digest BLOB NOT NULL CHECK(length(admission_digest) = 32),
    grant_digest BLOB NOT NULL CHECK(length(grant_digest) = 32),
    use_index INTEGER NOT NULL CHECK(use_index >= 0),
    admission_sequence INTEGER NOT NULL UNIQUE CHECK(admission_sequence >= 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK(admitted_at_unix_ms >= 0),
    UNIQUE(grant_digest, use_index)
) STRICT;
"#;

/// Exact authority-domain configuration expected by one SQLite store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteStoreConfigV1 {
    /// Stable non-zero receipt-store identity.
    pub store_id: [u8; 16],
    /// Explicit store generation.
    pub generation: u64,
}

impl SqliteStoreConfigV1 {
    fn validate(self) -> Result<(), SqliteStoreError> {
        if self.store_id == [0u8; 16] {
            return Err(SqliteStoreError::ZeroStoreId);
        }
        sqlite_i64(self.generation, "generation")?;
        Ok(())
    }
}

/// In-memory health gate for privileged mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteStoreHealthV1 {
    /// Exact profile and clean-writer preconditions were established.
    Healthy,
    /// A stale writer marker proves the previous lifecycle did not complete a verified clean close.
    RecoveryRequired,
    /// An unexpected SQLite error occurred during a mutating transaction or commit.
    DurabilityUncertain,
}

/// Immutable admission row persisted by the first SQLite tranche.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteAdmissionV1 {
    /// Minimal immutable receipt binding.
    pub binding: ReceiptAdmissionBindingV1,
    /// Exact session-bound grant commitment being consumed.
    pub grant_digest: [u8; 32],
    /// Exact use slot within that grant.
    pub use_index: u32,
    /// Exact monotonic durable admission sequence.
    pub admission_sequence: u64,
}

impl SqliteAdmissionV1 {
    /// Validate non-sentinel fields and SQLite integer bounds.
    pub fn validate(self) -> Result<(), SqliteStoreError> {
        self.binding.validate()?;
        if self.grant_digest == [0u8; 32] {
            return Err(SqliteStoreError::ZeroGrantDigest);
        }
        sqlite_i64(u64::from(self.use_index), "use_index")?;
        sqlite_i64(self.admission_sequence, "admission_sequence")?;
        sqlite_i64(self.binding.admitted_at_unix_ms, "admitted_at_unix_ms")?;
        Ok(())
    }
}

/// Result of one admission transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteAdmissionDecisionV1 {
    /// New immutable admission and use-slot reservation committed.
    Admitted,
    /// Exact same immutable admission was already committed; safe lost-ack replay.
    DuplicateSame,
}

/// First experimental SQLite admission store.
pub struct SqliteOperationStoreV1 {
    connection: Connection,
    database_path: PathBuf,
    marker_path: PathBuf,
    health: SqliteStoreHealthV1,
    config: SqliteStoreConfigV1,
    store_schema_digest: [u8; 32],
}

impl SqliteOperationStoreV1 {
    /// Open or create a store under the exact `sqlite-delete-extra-v1` profile.
    ///
    /// On Unix, a stale sidecar marker after exclusive database ownership is acquired
    /// causes the store to open `RecoveryRequired`; privileged mutations remain disabled.
    pub fn open(
        database_path: impl AsRef<Path>,
        config: SqliteStoreConfigV1,
    ) -> Result<Self, SqliteStoreError> {
        #[cfg(not(unix))]
        {
            let _ = database_path;
            let _ = config;
            return Err(SqliteStoreError::UnsupportedPlatformProfile);
        }

        #[cfg(unix)]
        {
            config.validate()?;
            let database_path = database_path.as_ref().to_path_buf();
            let parent = database_path
                .parent()
                .ok_or(SqliteStoreError::DatabasePathHasNoParent)?;
            fs::create_dir_all(parent)?;

            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            let connection = Connection::open_with_flags(&database_path, flags)?;
            configure_connection(&connection)?;
            acquire_exclusive_process_lock(&connection)?;

            let marker_path = marker_path(&database_path);
            let marker_existed = marker_path.exists();
            if !marker_existed {
                create_unclean_marker(&marker_path)?;
            }

            let store_schema_digest = store_schema_digest_v1();
            let mut store = Self {
                connection,
                database_path,
                marker_path,
                health: if marker_existed {
                    SqliteStoreHealthV1::RecoveryRequired
                } else {
                    SqliteStoreHealthV1::Healthy
                },
                config,
                store_schema_digest,
            };

            if marker_existed {
                // No database mutation is permitted on an unclean lifecycle. Basic profile
                // establishment has already occurred; recovery tooling may inspect state.
                return Ok(store);
            }

            if let Err(error) = store.initialize_or_verify_metadata() {
                // The marker deliberately remains. A failed authority-domain open is not
                // silently converted back into a clean lifecycle.
                store.health = SqliteStoreHealthV1::RecoveryRequired;
                return Err(error);
            }
            Ok(store)
        }
    }

    /// Current fail-stop health.
    pub fn health(&self) -> SqliteStoreHealthV1 {
        self.health
    }

    /// Exact configured authority-domain identity.
    pub fn config(&self) -> SqliteStoreConfigV1 {
        self.config
    }

    /// Exact deterministic store-schema commitment.
    pub fn store_schema_digest(&self) -> [u8; 32] {
        self.store_schema_digest
    }

    /// Path of the fail-stop unclean-writer marker.
    pub fn marker_path(&self) -> &Path {
        &self.marker_path
    }

    /// Count immutable admissions. Inspection remains available while recovery is required.
    pub fn admission_count(&self) -> Result<u64, SqliteStoreError> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM admissions", [], |row| row.get(0))?;
        u64::try_from(count).map_err(|_| SqliteStoreError::CorruptInteger("admission count"))
    }

    /// Read one immutable admission by operation id.
    pub fn admission(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<SqliteAdmissionV1>, SqliteStoreError> {
        read_admission(&self.connection, operation_id)
    }

    /// Run SQLite's full integrity check. This does not by itself clear recovery state.
    pub fn integrity_check(&self) -> Result<(), SqliteStoreError> {
        let result: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(SqliteStoreError::IntegrityCheckFailed(result))
        }
    }

    /// Atomically reserve one operation id, one grant-use slot, and the exact next sequence.
    pub fn admit(
        &mut self,
        admission: SqliteAdmissionV1,
    ) -> Result<SqliteAdmissionDecisionV1, SqliteStoreError> {
        self.require_healthy()?;
        admission.validate()?;

        let result = self.admit_inner(admission);
        if matches!(result, Err(SqliteStoreError::Sqlite(_))) {
            self.health = SqliteStoreHealthV1::DurabilityUncertain;
        }
        result
    }

    /// Explicit verified clean close.
    ///
    /// Ordinary `Drop` intentionally leaves the marker in place. This method removes and
    /// synchronizes the marker while the exclusive SQLite ownership is still held, then
    /// closes the connection. Recovery-required or durability-uncertain stores cannot
    /// erase the marker through this API.
    pub fn close_clean(self) -> Result<(), SqliteStoreError> {
        if self.health != SqliteStoreHealthV1::Healthy {
            return Err(SqliteStoreError::CleanCloseDenied(self.health));
        }

        let marker_path = self.marker_path.clone();
        remove_unclean_marker(&marker_path)?;
        match self.connection.close() {
            Ok(()) => Ok(()),
            Err((_connection, error)) => {
                // Best effort to restore the fail-stop marker if connection finalization
                // unexpectedly fails after marker removal.
                let _ = create_unclean_marker(&marker_path);
                Err(SqliteStoreError::Sqlite(error))
            }
        }
    }

    fn initialize_or_verify_metadata(&mut self) -> Result<(), SqliteStoreError> {
        let has_meta: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='store_meta')",
            [],
            |row| row.get(0),
        )?;

        if has_meta == 0 {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(STORE_SCHEMA_SQL_V1)?;
            transaction.execute(
                "INSERT INTO store_meta(singleton, schema_version, store_id, generation, store_schema_digest, next_admission_sequence) VALUES(1, ?1, ?2, ?3, ?4, 0)",
                params![
                    SQLITE_STORE_SCHEMA_VERSION_V1,
                    &self.config.store_id[..],
                    sqlite_i64(self.config.generation, "generation")?,
                    &self.store_schema_digest[..],
                ],
            )?;
            transaction.commit()?;
            return Ok(());
        }

        let (schema_version, store_id, generation, schema_digest): (i64, Vec<u8>, i64, Vec<u8>) =
            self.connection.query_row(
                "SELECT schema_version, store_id, generation, store_schema_digest FROM store_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        if schema_version != SQLITE_STORE_SCHEMA_VERSION_V1 {
            return Err(SqliteStoreError::SchemaVersionMismatch {
                expected: SQLITE_STORE_SCHEMA_VERSION_V1,
                found: schema_version,
            });
        }
        if fixed_16(&store_id, "store_id")? != self.config.store_id {
            return Err(SqliteStoreError::StoreIdMismatch);
        }
        if u64::try_from(generation).map_err(|_| SqliteStoreError::CorruptInteger("generation"))?
            != self.config.generation
        {
            return Err(SqliteStoreError::GenerationMismatch);
        }
        if fixed_32(&schema_digest, "store_schema_digest")? != self.store_schema_digest {
            return Err(SqliteStoreError::StoreSchemaDigestMismatch);
        }
        Ok(())
    }

    fn admit_inner(
        &mut self,
        admission: SqliteAdmissionV1,
    ) -> Result<SqliteAdmissionDecisionV1, SqliteStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = read_admission(&transaction, admission.binding.operation_id)? {
            if existing == admission {
                transaction.rollback()?;
                return Ok(SqliteAdmissionDecisionV1::DuplicateSame);
            }
            transaction.rollback()?;
            return Err(SqliteStoreError::OperationIdConflict);
        }

        let slot_owner: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT operation_id FROM admissions WHERE grant_digest=?1 AND use_index=?2",
                params![&admission.grant_digest[..], i64::from(admission.use_index)],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(owner) = slot_owner {
            if fixed_16(&owner, "operation_id")? != admission.binding.operation_id {
                transaction.rollback()?;
                return Err(SqliteStoreError::GrantUseSlotConflict);
            }
        }

        let next_sequence: i64 = transaction.query_row(
            "SELECT next_admission_sequence FROM store_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let next_sequence = u64::try_from(next_sequence)
            .map_err(|_| SqliteStoreError::CorruptInteger("next_admission_sequence"))?;
        if admission.admission_sequence != next_sequence {
            transaction.rollback()?;
            return Err(SqliteStoreError::AdmissionSequenceMismatch {
                expected: next_sequence,
                found: admission.admission_sequence,
            });
        }
        let following = next_sequence
            .checked_add(1)
            .ok_or(SqliteStoreError::AdmissionSequenceOverflow)?;

        transaction.execute(
            "INSERT INTO admissions(operation_id, admission_digest, grant_digest, use_index, admission_sequence, admitted_at_unix_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &admission.binding.operation_id[..],
                &admission.binding.admission_digest[..],
                &admission.grant_digest[..],
                i64::from(admission.use_index),
                sqlite_i64(admission.admission_sequence, "admission_sequence")?,
                sqlite_i64(admission.binding.admitted_at_unix_ms, "admitted_at_unix_ms")?,
            ],
        )?;
        transaction.execute(
            "UPDATE store_meta SET next_admission_sequence=?1 WHERE singleton=1",
            params![sqlite_i64(following, "next_admission_sequence")?],
        )?;
        transaction.commit()?;
        Ok(SqliteAdmissionDecisionV1::Admitted)
    }

    fn require_healthy(&self) -> Result<(), SqliteStoreError> {
        if self.health != SqliteStoreHealthV1::Healthy {
            return Err(SqliteStoreError::StoreNotHealthy(self.health));
        }
        Ok(())
    }
}

fn configure_connection(connection: &Connection) -> Result<(), SqliteStoreError> {
    connection.busy_timeout(Duration::from_millis(0))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    let journal_mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(SqliteStoreError::JournalModeMismatch(journal_mode));
    }
    connection.pragma_update(None, "synchronous", "EXTRA")?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    if synchronous != 3 {
        return Err(SqliteStoreError::SynchronousModeMismatch(synchronous));
    }
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(SqliteStoreError::ForeignKeysDisabled);
    }
    Ok(())
}

fn acquire_exclusive_process_lock(connection: &Connection) -> Result<(), SqliteStoreError> {
    let locking_mode: String =
        connection.query_row("PRAGMA locking_mode=EXCLUSIVE", [], |row| row.get(0))?;
    if !locking_mode.eq_ignore_ascii_case("exclusive") {
        return Err(SqliteStoreError::LockingModeMismatch(locking_mode));
    }
    connection.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
    Ok(())
}

fn read_admission(
    connection: &Connection,
    operation_id: [u8; 16],
) -> Result<Option<SqliteAdmissionV1>, SqliteStoreError> {
    let row: Option<(Vec<u8>, Vec<u8>, i64, i64, i64)> = connection
        .query_row(
            "SELECT admission_digest, grant_digest, use_index, admission_sequence, admitted_at_unix_ms FROM admissions WHERE operation_id=?1",
            params![&operation_id[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((admission_digest, grant_digest, use_index, admission_sequence, admitted_at)) = row else {
        return Ok(None);
    };
    Ok(Some(SqliteAdmissionV1 {
        binding: ReceiptAdmissionBindingV1 {
            admission_digest: fixed_32(&admission_digest, "admission_digest")?,
            operation_id,
            admitted_at_unix_ms: u64::try_from(admitted_at)
                .map_err(|_| SqliteStoreError::CorruptInteger("admitted_at_unix_ms"))?,
        },
        grant_digest: fixed_32(&grant_digest, "grant_digest")?,
        use_index: u32::try_from(use_index)
            .map_err(|_| SqliteStoreError::CorruptInteger("use_index"))?,
        admission_sequence: u64::try_from(admission_sequence)
            .map_err(|_| SqliteStoreError::CorruptInteger("admission_sequence"))?,
    }))
}

fn store_schema_digest_v1() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia-operation-store-schema-v1");
    hasher.update(SQLITE_STORE_PROFILE_V1.as_bytes());
    hasher.update(STORE_SCHEMA_SQL_V1.as_bytes());
    *hasher.finalize().as_bytes()
}

fn marker_path(database_path: &Path) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(UNCLEAN_WRITER_MARKER_SUFFIX_V1);
    PathBuf::from(value)
}

#[cfg(unix)]
fn create_unclean_marker(path: &Path) -> Result<(), SqliteStoreError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(b"xenia-operation-store-open-v1\n")?;
    file.sync_all()?;
    sync_parent(path)?;
    Ok(())
}

#[cfg(unix)]
fn remove_unclean_marker(path: &Path) -> Result<(), SqliteStoreError> {
    fs::remove_file(path)?;
    sync_parent(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), SqliteStoreError> {
    let parent = path
        .parent()
        .ok_or(SqliteStoreError::DatabasePathHasNoParent)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, SqliteStoreError> {
    i64::try_from(value).map_err(|_| SqliteStoreError::IntegerOutOfRange(field))
}

fn fixed_16(bytes: &[u8], field: &'static str) -> Result<[u8; 16], SqliteStoreError> {
    bytes
        .try_into()
        .map_err(|_| SqliteStoreError::BlobLength(field))
}

fn fixed_32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], SqliteStoreError> {
    bytes
        .try_into()
        .map_err(|_| SqliteStoreError::BlobLength(field))
}

/// SQLite admission-store failure.
#[derive(Debug, Error)]
pub enum SqliteStoreError {
    /// The conservative V1 profile is currently implemented only for Unix directory-sync semantics.
    #[error("sqlite-delete-extra-v1 is currently qualified only for Unix-like platforms")]
    UnsupportedPlatformProfile,
    /// Store id used the zero sentinel.
    #[error("store id must not be zero")]
    ZeroStoreId,
    /// Grant digest used the zero sentinel.
    #[error("grant digest must not be zero")]
    ZeroGrantDigest,
    /// Database path had no parent directory.
    #[error("database path has no parent directory")]
    DatabasePathHasNoParent,
    /// SQLite did not enter the requested rollback journal mode.
    #[error("SQLite journal mode mismatch: {0}")]
    JournalModeMismatch(String),
    /// SQLite did not retain `synchronous=EXTRA`.
    #[error("SQLite synchronous mode mismatch: {0}")]
    SynchronousModeMismatch(i64),
    /// SQLite foreign-key enforcement could not be enabled.
    #[error("SQLite foreign keys are disabled")]
    ForeignKeysDisabled,
    /// SQLite did not enter exclusive locking mode.
    #[error("SQLite locking mode mismatch: {0}")]
    LockingModeMismatch(String),
    /// Existing database schema version differs from V1.
    #[error("store schema version mismatch: expected {expected}, found {found}")]
    SchemaVersionMismatch {
        /// Exact expected schema version.
        expected: i64,
        /// Version read from the database.
        found: i64,
    },
    /// Existing store id differs from the configured authority domain.
    #[error("store id mismatch")]
    StoreIdMismatch,
    /// Existing store generation differs from the configured authority domain.
    #[error("store generation mismatch")]
    GenerationMismatch,
    /// Stored schema commitment differs from this implementation profile.
    #[error("store schema digest mismatch")]
    StoreSchemaDigestMismatch,
    /// Same operation id was reused with different immutable admission state.
    #[error("operation id conflict")]
    OperationIdConflict,
    /// Same grant-use slot is already consumed by another operation.
    #[error("grant-use slot conflict")]
    GrantUseSlotConflict,
    /// Admission sequence was not exactly the next durable sequence.
    #[error("admission sequence mismatch: expected {expected}, found {found}")]
    AdmissionSequenceMismatch {
        /// Exact next durable sequence.
        expected: u64,
        /// Sequence supplied by the caller.
        found: u64,
    },
    /// Admission sequence overflowed.
    #[error("admission sequence overflow")]
    AdmissionSequenceOverflow,
    /// Mutation attempted while store health was fail-stopped.
    #[error("store is not healthy: {0:?}")]
    StoreNotHealthy(SqliteStoreHealthV1),
    /// Clean close attempted from a fail-stopped lifecycle.
    #[error("clean close denied for store health {0:?}")]
    CleanCloseDenied(SqliteStoreHealthV1),
    /// SQLite integrity check did not return `ok`.
    #[error("SQLite integrity check failed: {0}")]
    IntegrityCheckFailed(String),
    /// Unsigned model value cannot fit SQLite's signed INTEGER domain.
    #[error("value out of SQLite INTEGER range: {0}")]
    IntegerOutOfRange(&'static str),
    /// Stored signed integer cannot be interpreted as the expected non-negative value.
    #[error("corrupt SQLite integer field: {0}")]
    CorruptInteger(&'static str),
    /// Stored blob had the wrong exact length.
    #[error("corrupt SQLite blob length: {0}")]
    BlobLength(&'static str),
    /// Receipt/admission binding validation failed.
    #[error("admission binding rejected: {0}")]
    ReceiptBinding(#[from] ReceiptFinalizationError),
    /// SQLite operation failed.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Filesystem marker/directory synchronization failed.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn config() -> SqliteStoreConfigV1 {
        SqliteStoreConfigV1 {
            store_id: [1u8; 16],
            generation: 0,
        }
    }

    fn admission(operation: u8, grant: u8, use_index: u32, sequence: u64) -> SqliteAdmissionV1 {
        SqliteAdmissionV1 {
            binding: ReceiptAdmissionBindingV1 {
                admission_digest: [operation; 32],
                operation_id: [operation; 16],
                admitted_at_unix_ms: 1_000 + sequence,
            },
            grant_digest: [grant; 32],
            use_index,
            admission_sequence: sequence,
        }
    }

    fn path(temp: &TempDir) -> PathBuf {
        temp.path().join("operations.sqlite3")
    }

    #[test]
    fn new_store_opens_healthy_and_integrity_checks() {
        let temp = TempDir::new().unwrap();
        let store = SqliteOperationStoreV1::open(path(&temp), config()).unwrap();
        assert_eq!(store.health(), SqliteStoreHealthV1::Healthy);
        assert_eq!(store.admission_count().unwrap(), 0);
        store.integrity_check().unwrap();
        store.close_clean().unwrap();
    }

    #[test]
    fn exact_admission_retry_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let mut store = SqliteOperationStoreV1::open(path(&temp), config()).unwrap();
        let row = admission(3, 4, 0, 0);
        assert_eq!(
            store.admit(row).unwrap(),
            SqliteAdmissionDecisionV1::Admitted
        );
        assert_eq!(
            store.admit(row).unwrap(),
            SqliteAdmissionDecisionV1::DuplicateSame
        );
        assert_eq!(store.admission_count().unwrap(), 1);
        store.close_clean().unwrap();
    }

    #[test]
    fn operation_id_conflict_does_not_mutate_store() {
        let temp = TempDir::new().unwrap();
        let mut store = SqliteOperationStoreV1::open(path(&temp), config()).unwrap();
        store.admit(admission(3, 4, 0, 0)).unwrap();
        let mut conflict = admission(3, 4, 0, 0);
        conflict.binding.admission_digest = [9u8; 32];
        assert!(matches!(
            store.admit(conflict),
            Err(SqliteStoreError::OperationIdConflict)
        ));
        assert_eq!(store.admission_count().unwrap(), 1);
        assert_eq!(store.health(), SqliteStoreHealthV1::Healthy);
        store.close_clean().unwrap();
    }

    #[test]
    fn grant_use_slot_cannot_be_reused_by_another_operation() {
        let temp = TempDir::new().unwrap();
        let mut store = SqliteOperationStoreV1::open(path(&temp), config()).unwrap();
        store.admit(admission(3, 4, 0, 0)).unwrap();
        assert!(matches!(
            store.admit(admission(5, 4, 0, 1)),
            Err(SqliteStoreError::GrantUseSlotConflict)
        ));
        assert_eq!(store.admission_count().unwrap(), 1);
        store.close_clean().unwrap();
    }

    #[test]
    fn admission_sequence_must_be_gap_free() {
        let temp = TempDir::new().unwrap();
        let mut store = SqliteOperationStoreV1::open(path(&temp), config()).unwrap();
        assert!(matches!(
            store.admit(admission(3, 4, 0, 1)),
            Err(SqliteStoreError::AdmissionSequenceMismatch {
                expected: 0,
                found: 1
            })
        ));
        assert_eq!(store.admission_count().unwrap(), 0);
        store.close_clean().unwrap();
    }

    #[test]
    fn explicit_clean_close_allows_healthy_reopen() {
        let temp = TempDir::new().unwrap();
        let db = path(&temp);
        let store = SqliteOperationStoreV1::open(&db, config()).unwrap();
        let marker = store.marker_path().to_path_buf();
        assert!(marker.exists());
        store.close_clean().unwrap();
        assert!(!marker.exists());
        let store = SqliteOperationStoreV1::open(&db, config()).unwrap();
        assert_eq!(store.health(), SqliteStoreHealthV1::Healthy);
        store.close_clean().unwrap();
    }

    #[test]
    fn ordinary_drop_leaves_fail_stop_marker() {
        let temp = TempDir::new().unwrap();
        let db = path(&temp);
        {
            let store = SqliteOperationStoreV1::open(&db, config()).unwrap();
            assert!(store.marker_path().exists());
        }
        let mut reopened = SqliteOperationStoreV1::open(&db, config()).unwrap();
        assert_eq!(reopened.health(), SqliteStoreHealthV1::RecoveryRequired);
        assert!(matches!(
            reopened.admit(admission(3, 4, 0, 0)),
            Err(SqliteStoreError::StoreNotHealthy(
                SqliteStoreHealthV1::RecoveryRequired
            ))
        ));
        assert!(matches!(
            reopened.close_clean(),
            Err(SqliteStoreError::CleanCloseDenied(
                SqliteStoreHealthV1::RecoveryRequired
            ))
        ));
    }

    #[test]
    fn committed_admission_survives_clean_reopen() {
        let temp = TempDir::new().unwrap();
        let db = path(&temp);
        let row = admission(3, 4, 0, 0);
        let mut store = SqliteOperationStoreV1::open(&db, config()).unwrap();
        store.admit(row).unwrap();
        store.close_clean().unwrap();
        let store = SqliteOperationStoreV1::open(&db, config()).unwrap();
        assert_eq!(store.admission([3u8; 16]).unwrap(), Some(row));
        store.close_clean().unwrap();
    }
}
