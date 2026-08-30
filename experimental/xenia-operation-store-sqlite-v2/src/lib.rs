// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Experimental SQLite V2 store for recovery-safe privileged-operation authority.
//!
//! This crate deliberately stops before any privileged external effect. It persists exact
//! V2 admission authority, atomically reserves one grant/use slot, appends receipt events with
//! compare-and-append semantics, and advances a local hash-chained store frontier after every
//! mutation. Successful admission and `EffectArmed` commits return the authenticated persistence
//! context required by the V2 persistence-proof contract.
//!
//! The initial Linux profile assumes the parent authority directory is provisioned by a trusted
//! service manager. The final directory and persistent leaves are checked here; every ancestor
//! component must still satisfy ADR-012's deployment-controlled-root requirement. SQLite opens
//! the database with `SQLITE_OPEN_NOFOLLOW` as an additional leaf defense.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_admission_proof_v2::{
    AdmissionPersistenceProofV2, AuthenticatedPersistenceContextV2,
    EffectArmedPersistenceProofV2, PersistenceProofV2Error,
};
use xenia_operation_authority_epoch::{AuthorityEpochError, OperationAuthorityEpochV1};
use xenia_operation_authority_v2::{
    AdmissionAuthorityV2, AuthorityV2Error, EffectArmAuthorityV2, StoreAuthorityV2,
    UseAuthorityV2,
};
use xenia_operation_receipt_finalization::{
    ReceiptAdmissionBindingV1, ReceiptEventV1, ReceiptFinalizationError, ReceiptStateV1,
};

/// Exact SQLite durability/security profile implemented by this experiment.
pub const SQLITE_STORE_PROFILE_V2: &str = "sqlite-delete-extra-nofollow-v2";
/// Reference Linux authority-root profile expected by this experiment.
pub const LINUX_AUTHORITY_ROOT_PROFILE_V1: &str = "linux-systemd-state-root-v1";
/// Exact database filename for the reference V2 profile.
pub const SQLITE_DATABASE_FILENAME_V2: &str = "operations-v2.sqlite3";
/// Exact schema version persisted in `store_meta`.
pub const SQLITE_STORE_SCHEMA_VERSION_V2: i64 = 2;
/// Fail-stop marker suffix.
pub const UNCLEAN_WRITER_MARKER_SUFFIX_V2: &str = ".xenia-operation-store-open-v2";

const MARKER_BYTES_V2: &[u8] = b"xenia-operation-store-open-v2\n";
const ADMISSION_ROOT_DOMAIN_V2: &[u8] = b"xenia-operation-store-admissions-root-v2";
const RECEIPT_HEADS_ROOT_DOMAIN_V2: &[u8] = b"xenia-operation-store-receipt-heads-root-v2";
const FRONTIER_DOMAIN_V2: &[u8] = b"xenia-operation-store-frontier-v2";
const USE_SLOT_DOMAIN_V2: &[u8] = b"xenia-operation-store-use-slot-v2";
const BACKEND_AUTHORITY_DOMAIN_V2: &[u8] = b"xenia-operation-store-sqlite-backend-authority-v2";
const PERSISTENCE_PROFILE_DOMAIN_V2: &[u8] = b"xenia-operation-store-persistence-profile-v2";
const COMMIT_EVIDENCE_DOMAIN_V2: &[u8] = b"xenia-operation-store-commit-evidence-v2";

const STORE_SCHEMA_SQL_V2: &str = r#"
CREATE TABLE store_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
    store_schema_digest BLOB NOT NULL CHECK(length(store_schema_digest) = 32),
    store_id BLOB NOT NULL CHECK(length(store_id) = 16),
    generation INTEGER NOT NULL CHECK(generation >= 0),
    authority_domain_id BLOB NOT NULL CHECK(length(authority_domain_id) = 16),
    authority_epoch_digest BLOB NOT NULL CHECK(length(authority_epoch_digest) = 32),
    store_authority_digest BLOB NOT NULL CHECK(length(store_authority_digest) = 32),
    backend_authority_digest BLOB NOT NULL CHECK(length(backend_authority_digest) = 32),
    persistence_profile_digest BLOB NOT NULL CHECK(length(persistence_profile_digest) = 32),
    next_admission_sequence INTEGER NOT NULL CHECK(next_admission_sequence >= 0),
    next_frontier_sequence INTEGER NOT NULL CHECK(next_frontier_sequence >= 1),
    current_frontier_digest BLOB NOT NULL CHECK(length(current_frontier_digest) = 32)
) STRICT;

CREATE TABLE admissions (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
    raw_admission_digest BLOB NOT NULL CHECK(length(raw_admission_digest) = 32),
    admission_authority_digest BLOB NOT NULL UNIQUE CHECK(length(admission_authority_digest) = 32),
    use_authority_digest BLOB NOT NULL CHECK(length(use_authority_digest) = 32),
    grant_authority_digest BLOB NOT NULL CHECK(length(grant_authority_digest) = 32),
    raw_use_digest BLOB NOT NULL CHECK(length(raw_use_digest) = 32),
    use_index INTEGER NOT NULL CHECK(use_index >= 0),
    admission_sequence INTEGER NOT NULL UNIQUE CHECK(admission_sequence >= 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK(admitted_at_unix_ms >= 0),
    authority_epoch_digest BLOB NOT NULL CHECK(length(authority_epoch_digest) = 32),
    UNIQUE(grant_authority_digest, use_index)
) STRICT;

CREATE TABLE admission_proofs (
    operation_id BLOB PRIMARY KEY REFERENCES admissions(operation_id) ON DELETE RESTRICT,
    proof_digest BLOB NOT NULL UNIQUE CHECK(length(proof_digest) = 32),
    proof_bytes BLOB NOT NULL
) STRICT;

CREATE TABLE receipt_events (
    operation_id BLOB NOT NULL REFERENCES admissions(operation_id) ON DELETE RESTRICT,
    event_index INTEGER NOT NULL CHECK(event_index >= 0),
    previous_event_digest BLOB NOT NULL CHECK(length(previous_event_digest) = 32),
    event_digest BLOB NOT NULL UNIQUE CHECK(length(event_digest) = 32),
    event_bytes BLOB NOT NULL,
    state_code INTEGER NOT NULL CHECK(state_code BETWEEN 0 AND 5),
    recorded_at_unix_ms INTEGER NOT NULL CHECK(recorded_at_unix_ms >= 0),
    PRIMARY KEY(operation_id, event_index)
) STRICT;

CREATE TABLE effect_armed_proofs (
    operation_id BLOB PRIMARY KEY REFERENCES admissions(operation_id) ON DELETE RESTRICT,
    receipt_event_digest BLOB NOT NULL UNIQUE CHECK(length(receipt_event_digest) = 32),
    proof_digest BLOB NOT NULL UNIQUE CHECK(length(proof_digest) = 32),
    proof_bytes BLOB NOT NULL
) STRICT;

CREATE TABLE frontiers (
    frontier_sequence INTEGER PRIMARY KEY CHECK(frontier_sequence >= 0),
    previous_frontier_digest BLOB NOT NULL CHECK(length(previous_frontier_digest) = 32),
    admissions_root_digest BLOB NOT NULL CHECK(length(admissions_root_digest) = 32),
    receipt_heads_root_digest BLOB NOT NULL CHECK(length(receipt_heads_root_digest) = 32),
    frontier_digest BLOB NOT NULL UNIQUE CHECK(length(frontier_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0)
) STRICT;
"#;

/// Trusted semantic facts mapping a validated raw use to its grant use-slot.
///
/// This is deliberately not serializable. A runtime must construct it from the semantic grant/use
/// validator, not from caller-controlled persistence input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedUseSlotV2 {
    /// Exact V2 grant-authority commitment whose finite slot is being consumed.
    pub grant_authority_digest: [u8; 32],
    /// Exact raw semantic use commitment already carried by `UseAuthorityV2`.
    pub raw_use_digest: [u8; 32],
    /// Zero-based grant use index authenticated from the raw semantic use.
    pub use_index: u32,
}

impl AuthenticatedUseSlotV2 {
    fn validate_against(self, use_authority: &UseAuthorityV2) -> Result<(), SqliteStoreV2Error> {
        use_authority.validate()?;
        if self.grant_authority_digest != use_authority.grant_authority_digest {
            return Err(SqliteStoreV2Error::GrantAuthorityMismatch);
        }
        if self.raw_use_digest != use_authority.raw_use_digest {
            return Err(SqliteStoreV2Error::RawUseDigestMismatch);
        }
        Ok(())
    }

    fn reservation_digest(self, use_authority: &UseAuthorityV2) -> Result<[u8; 32], SqliteStoreV2Error> {
        self.validate_against(use_authority)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(USE_SLOT_DOMAIN_V2);
        hasher.update(&use_authority.operation_id);
        hasher.update(&use_authority.authority_digest()?);
        hasher.update(&self.grant_authority_digest);
        hasher.update(&self.raw_use_digest);
        hasher.update(&self.use_index.to_le_bytes());
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Trusted semantic admission facts not directly exposed by `AdmissionAuthorityV2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedAdmissionContextV2 {
    /// Exact raw admission commitment already carried by `AdmissionAuthorityV2`.
    pub raw_admission_digest: [u8; 32],
    /// Durable semantic admission time used by receipt-chain validation.
    pub admitted_at_unix_ms: u64,
}

impl AuthenticatedAdmissionContextV2 {
    fn validate_against(self, admission: &AdmissionAuthorityV2) -> Result<(), SqliteStoreV2Error> {
        admission.validate()?;
        if self.raw_admission_digest != admission.raw_admission_digest {
            return Err(SqliteStoreV2Error::RawAdmissionDigestMismatch);
        }
        Ok(())
    }
}

/// Initial fail-stop health of the experimental V2 store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteStoreHealthV2 {
    /// Profile, filesystem leaf/root, metadata, and clean-writer checks succeeded.
    Healthy,
    /// The previous process lifecycle did not complete a verified clean close.
    RecoveryRequired,
    /// A mutating SQLite operation returned an error whose commit outcome may be ambiguous.
    DurabilityUncertain,
}

/// Result class for an idempotent durable admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecisionV2 {
    /// This call committed the immutable admission.
    Admitted,
    /// The exact same immutable admission/proof was already present after a lost acknowledgement.
    DuplicateSame,
}

/// Result class for append-only receipt persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptDecisionV2 {
    /// This call appended the event.
    Appended,
    /// The exact event was already the durable event at this index.
    DuplicateSame,
}

/// Successful durable admission plus the non-serialized authenticated persistence context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCommitV2 {
    /// Whether this was a new commit or exact lost-ack replay.
    pub decision: AdmissionDecisionV2,
    /// Store-issued V2 durable-admission proof.
    pub proof: AdmissionPersistenceProofV2,
    /// Authenticated in-process persistence facts needed to validate `proof`.
    pub authenticated_persistence: AuthenticatedPersistenceContextV2,
}

/// Successful durable write-ahead `EffectArmed` commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectArmedCommitV2 {
    /// Whether this was a new append or exact lost-ack replay.
    pub decision: ReceiptDecisionV2,
    /// Store-issued V2 write-ahead persistence proof.
    pub proof: EffectArmedPersistenceProofV2,
    /// Authenticated in-process persistence facts needed to validate `proof`.
    pub authenticated_persistence: AuthenticatedPersistenceContextV2,
}

/// Successful ordinary receipt append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptCommitV2 {
    /// Whether this was a new append or exact lost-ack replay.
    pub decision: ReceiptDecisionV2,
    /// Exact receipt event commitment.
    pub event_digest: [u8; 32],
    /// Exact local store frontier containing this event.
    pub committed_frontier_digest: [u8; 32],
    /// Authenticated backend facts for this commit.
    pub authenticated_persistence: AuthenticatedPersistenceContextV2,
}

/// Experimental SQLite V2 authority/receipt store.
pub struct SqliteOperationStoreV2 {
    connection: Connection,
    database_path: PathBuf,
    marker_path: PathBuf,
    expected_uid: u32,
    health: SqliteStoreHealthV2,
    current_epoch: OperationAuthorityEpochV1,
    store_authority: StoreAuthorityV2,
    store_schema_digest: [u8; 32],
    backend_authority_digest: [u8; 32],
    persistence_profile_digest: [u8; 32],
}

impl SqliteOperationStoreV2 {
    /// Open or create the V2 authority store under a pre-provisioned private authority root.
    ///
    /// The parent directory must already exist, be a real directory (not a symlink), be exactly
    /// `expected_uid` owned, and have mode `0700`. The database filename is fixed by this profile.
    pub fn open(
        database_path: impl AsRef<Path>,
        current_epoch: OperationAuthorityEpochV1,
        expected_uid: u32,
    ) -> Result<Self, SqliteStoreV2Error> {
        current_epoch.validate()?;
        let store_authority = StoreAuthorityV2::from_epoch(&current_epoch)?;
        let database_path = database_path.as_ref().to_path_buf();
        require_database_filename(&database_path)?;
        let parent = database_path
            .parent()
            .ok_or(SqliteStoreV2Error::DatabasePathHasNoParent)?;
        verify_authority_root(parent, expected_uid)?;
+
+        let database_existed = database_path.exists();
+        if database_existed {
+            verify_private_regular_leaf(&database_path, expected_uid)?;
+        }
+
+        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
+            | OpenFlags::SQLITE_OPEN_CREATE
+            | OpenFlags::SQLITE_OPEN_NO_MUTEX
+            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
+        let connection = Connection::open_with_flags(&database_path, flags)?;
+        set_private_file_mode(&database_path)?;
+        verify_private_regular_leaf(&database_path, expected_uid)?;
+        configure_connection(&connection)?;
+        acquire_exclusive_process_lock(&connection)?;
+
+        let marker_path = marker_path(&database_path);
+        let marker_existed = marker_path.exists();
+        if marker_existed {
+            verify_unclean_marker(&marker_path, expected_uid)?;
+        } else {
+            create_unclean_marker(&marker_path, expected_uid)?;
+        }
+
+        let store_schema_digest = store_schema_digest_v2();
+        let backend_authority_digest = backend_authority_digest_v2();
+        let persistence_profile_digest = persistence_profile_digest_v2();
+        let mut store = Self {
+            connection,
+            database_path,
+            marker_path,
+            expected_uid,
+            health: if marker_existed {
+                SqliteStoreHealthV2::RecoveryRequired
+            } else {
+                SqliteStoreHealthV2::Healthy
+            },
+            current_epoch,
+            store_authority,
+            store_schema_digest,
+            backend_authority_digest,
+            persistence_profile_digest,
+        };
+
+        if marker_existed {
+            store.verify_metadata()?;
+            return Ok(store);
+        }
+
+        if let Err(error) = store.initialize_or_verify_metadata() {
+            store.health = SqliteStoreHealthV2::RecoveryRequired;
+            return Err(error);
+        }
+        Ok(store)
+    }
+
+    /// Current fail-stop health.
+    pub fn health(&self) -> SqliteStoreHealthV2 {
+        self.health
+    }
+
+    /// Exact current authority epoch bound into this store instance.
+    pub fn current_epoch(&self) -> &OperationAuthorityEpochV1 {
+        &self.current_epoch
+    }
+
+    /// Exact persistent V2 store authority.
+    pub fn store_authority(&self) -> &StoreAuthorityV2 {
+        &self.store_authority
+    }
+
+    /// Backend identity/configuration commitment authenticated by this store instance.
+    pub fn backend_authority_digest(&self) -> [u8; 32] {
+        self.backend_authority_digest
+    }
+
+    /// Named persistence profile commitment authenticated by this store instance.
+    pub fn persistence_profile_digest(&self) -> [u8; 32] {
+        self.persistence_profile_digest
+    }
+
+    /// Exact current locally committed frontier digest.
+    pub fn current_frontier_digest(&self) -> Result<[u8; 32], SqliteStoreV2Error> {
+        let bytes: Vec<u8> = self.connection.query_row(
+            "SELECT current_frontier_digest FROM store_meta WHERE singleton=1",
+            [],
+            |row| row.get(0),
+        )?;
+        fixed_32(&bytes, "current_frontier_digest")
+    }
+
+    /// Run SQLite structural integrity plus the V2 local frontier/root verifier.
+    pub fn verify_local_integrity(&self) -> Result<(), SqliteStoreV2Error> {
+        let result: String = self
+            .connection
+            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
+        if result != "ok" {
+            return Err(SqliteStoreV2Error::IntegrityCheckFailed(result));
+        }
+        self.verify_frontier_chain()
+    }
+
+    /// Atomically commit one exact V2 admission/use-slot and return a store-authenticated proof.
+    #[allow(clippy::too_many_arguments)]
+    pub fn admit(
+        &mut self,
+        admission: &AdmissionAuthorityV2,
+        use_authority: &UseAuthorityV2,
+        semantic_admission: AuthenticatedAdmissionContextV2,
+        use_slot: AuthenticatedUseSlotV2,
+        persisted_at_unix_ms: u64,
+    ) -> Result<AdmissionCommitV2, SqliteStoreV2Error> {
+        self.require_healthy()?;
+        admission.validate()?;
+        use_authority.validate()?;
+        admission.authority_epoch.validate_against(&self.current_epoch)?;
+        semantic_admission.validate_against(admission)?;
+        use_slot.validate_against(use_authority)?;
+        if admission.operation_id != use_authority.operation_id {
+            return Err(SqliteStoreV2Error::OperationIdMismatch);
+        }
+        if admission.use_authority_digest != use_authority.authority_digest()? {
+            return Err(SqliteStoreV2Error::UseAuthorityMismatch);
+        }
+        if persisted_at_unix_ms < semantic_admission.admitted_at_unix_ms
+            || persisted_at_unix_ms < self.current_epoch.established_at_unix_ms
+        {
+            return Err(SqliteStoreV2Error::PersistenceTimestampRegression);
+        }
+
+        let result = self.admit_inner(
+            admission,
+            use_authority,
+            semantic_admission,
+            use_slot,
+            persisted_at_unix_ms,
+        );
+        if matches!(result, Err(SqliteStoreV2Error::Sqlite(_))) {
+            self.health = SqliteStoreHealthV2::DurabilityUncertain;
+        }
+        result
+    }
+
+    /// Durably append the first write-ahead `EffectArmed` event and return its V2 proof.
+    #[allow(clippy::too_many_arguments)]
+    pub fn append_effect_armed(
+        &mut self,
+        admission: &AdmissionAuthorityV2,
+        semantic_admission: AuthenticatedAdmissionContextV2,
+        admission_proof: &AdmissionPersistenceProofV2,
+        arm: &EffectArmAuthorityV2,
+        event: &ReceiptEventV1,
+        persisted_at_unix_ms: u64,
+    ) -> Result<EffectArmedCommitV2, SqliteStoreV2Error> {
+        self.require_healthy()?;
+        semantic_admission.validate_against(admission)?;
+        arm.validate_final_gate(admission, &self.store_authority, &self.current_epoch)?;
+        if event.state != ReceiptStateV1::EffectArmed {
+            return Err(SqliteStoreV2Error::EffectArmedMethodRequiresEffectArmed);
+        }
+        if event.arm_authorization_digest != Some(arm.raw_arm_authorization_digest) {
+            return Err(SqliteStoreV2Error::ArmAuthorizationDigestMismatch);
+        }
+        if persisted_at_unix_ms < admission_proof.persisted_at_unix_ms {
+            return Err(SqliteStoreV2Error::PersistenceTimestampRegression);
+        }
+        self.validate_stored_admission_proof(admission, admission_proof)?;
+
+        let binding = ReceiptAdmissionBindingV1 {
+            admission_digest: admission.raw_admission_digest,
+            operation_id: admission.operation_id,
+            admitted_at_unix_ms: semantic_admission.admitted_at_unix_ms,
+        };
+        event.validate_first(binding)?;
+
+        let result = self.append_effect_armed_inner(
+            admission,
+            admission_proof,
+            arm,
+            event,
+            persisted_at_unix_ms,
+        );
+        if matches!(result, Err(SqliteStoreV2Error::Sqlite(_))) {
+            self.health = SqliteStoreHealthV2::DurabilityUncertain;
+        }
+        result
+    }
+
+    /// Append a non-`EffectArmed` receipt event with exact compare-and-append semantics.
+    pub fn append_receipt(
+        &mut self,
+        admission: &AdmissionAuthorityV2,
+        semantic_admission: AuthenticatedAdmissionContextV2,
+        event: &ReceiptEventV1,
+        persisted_at_unix_ms: u64,
+    ) -> Result<ReceiptCommitV2, SqliteStoreV2Error> {
+        self.require_healthy()?;
+        admission.validate()?;
+        admission.authority_epoch.validate_against(&self.current_epoch)?;
+        semantic_admission.validate_against(admission)?;
+        if event.state == ReceiptStateV1::EffectArmed {
+            return Err(SqliteStoreV2Error::EffectArmedRequiresDedicatedMethod);
+        }
+        if persisted_at_unix_ms < event.recorded_at_unix_ms {
+            return Err(SqliteStoreV2Error::PersistenceTimestampRegression);
+        }
+        let binding = ReceiptAdmissionBindingV1 {
+            admission_digest: admission.raw_admission_digest,
+            operation_id: admission.operation_id,
+            admitted_at_unix_ms: semantic_admission.admitted_at_unix_ms,
+        };
+
+        let result = self.append_receipt_inner(binding, event, persisted_at_unix_ms);
+        if matches!(result, Err(SqliteStoreV2Error::Sqlite(_))) {
+            self.health = SqliteStoreHealthV2::DurabilityUncertain;
+        }
+        result
+    }
+
+    /// Explicit verified clean close. Ordinary `Drop` intentionally leaves the marker.
+    pub fn close_clean(self) -> Result<(), SqliteStoreV2Error> {
+        if self.health != SqliteStoreHealthV2::Healthy {
+            return Err(SqliteStoreV2Error::CleanCloseDenied(self.health));
+        }
+        let marker_path = self.marker_path.clone();
+        let expected_uid = self.expected_uid;
+        remove_unclean_marker(&marker_path, expected_uid)?;
+        match self.connection.close() {
+            Ok(()) => Ok(()),
+            Err((_connection, error)) => {
+                let _ = create_unclean_marker(&marker_path, expected_uid);
+                Err(SqliteStoreV2Error::Sqlite(error))
+            }
+        }
+    }
+
+    fn initialize_or_verify_metadata(&mut self) -> Result<(), SqliteStoreV2Error> {
+        let has_meta: i64 = self.connection.query_row(
+            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='store_meta')",
+            [],
+            |row| row.get(0),
+        )?;
+        if has_meta != 0 {
+            return self.verify_metadata();
+        }
+
+        let transaction = self
+            .connection
+            .transaction_with_behavior(TransactionBehavior::Immediate)?;
+        transaction.execute_batch(STORE_SCHEMA_SQL_V2)?;
+
+        let admissions_root = empty_root(ADMISSION_ROOT_DOMAIN_V2);
+        let receipt_heads_root = empty_root(RECEIPT_HEADS_ROOT_DOMAIN_V2);
+        let store_authority_digest = self.store_authority.authority_digest()?;
+        let genesis_frontier = frontier_digest(
+            store_authority_digest,
+            0,
+            [0u8; 32],
+            admissions_root,
+            receipt_heads_root,
+            self.current_epoch.established_at_unix_ms,
+        );
+        transaction.execute(
+            "INSERT INTO frontiers(frontier_sequence, previous_frontier_digest, admissions_root_digest, receipt_heads_root_digest, frontier_digest, created_at_unix_ms) VALUES(0, ?1, ?2, ?3, ?4, ?5)",
+            params![
+                &[0u8; 32][..],
+                &admissions_root[..],
+                &receipt_heads_root[..],
+                &genesis_frontier[..],
+                sqlite_i64(self.current_epoch.established_at_unix_ms, "frontier time")?,
+            ],
+        )?;
+
+        transaction.execute(
+            "INSERT INTO store_meta(singleton, schema_version, store_schema_digest, store_id, generation, authority_domain_id, authority_epoch_digest, store_authority_digest, backend_authority_digest, persistence_profile_digest, next_admission_sequence, next_frontier_sequence, current_frontier_digest) VALUES(1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, 1, ?10)",
+            params![
+                SQLITE_STORE_SCHEMA_VERSION_V2,
+                &self.store_schema_digest[..],
+                &self.current_epoch.store_id[..],
+                sqlite_i64(self.current_epoch.store_generation, "generation")?,
+                &self.current_epoch.authority_domain_id[..],
+                &self.current_epoch.epoch_digest()?[..],
+                &store_authority_digest[..],
+                &self.backend_authority_digest[..],
+                &self.persistence_profile_digest[..],
+                &genesis_frontier[..],
+            ],
+        )?;
+        transaction.commit()?;
+        Ok(())
+    }
+
+    fn verify_metadata(&self) -> Result<(), SqliteStoreV2Error> {
+        let row: (i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
+            self.connection.query_row(
+                "SELECT schema_version, store_schema_digest, store_id, generation, authority_domain_id, authority_epoch_digest, store_authority_digest, backend_authority_digest, persistence_profile_digest FROM store_meta WHERE singleton=1",
+                [],
+                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
+            )?;
+        if row.0 != SQLITE_STORE_SCHEMA_VERSION_V2 {
+            return Err(SqliteStoreV2Error::SchemaVersionMismatch {
+                expected: SQLITE_STORE_SCHEMA_VERSION_V2,
+                found: row.0,
+            });
+        }
+        if fixed_32(&row.1, "store_schema_digest")? != self.store_schema_digest {
+            return Err(SqliteStoreV2Error::StoreSchemaDigestMismatch);
+        }
+        if fixed_16(&row.2, "store_id")? != self.current_epoch.store_id {
+            return Err(SqliteStoreV2Error::StoreIdMismatch);
+        }
+        let generation = u64::try_from(row.3)
+            .map_err(|_| SqliteStoreV2Error::CorruptInteger("generation"))?;
+        if generation != self.current_epoch.store_generation {
+            return Err(SqliteStoreV2Error::GenerationMismatch);
+        }
+        if fixed_16(&row.4, "authority_domain_id")? != self.current_epoch.authority_domain_id {
+            return Err(SqliteStoreV2Error::AuthorityDomainMismatch);
+        }
+        if fixed_32(&row.5, "authority_epoch_digest")? != self.current_epoch.epoch_digest()? {
+            return Err(SqliteStoreV2Error::AuthorityEpochMismatch);
+        }
+        if fixed_32(&row.6, "store_authority_digest")? != self.store_authority.authority_digest()? {
+            return Err(SqliteStoreV2Error::StoreAuthorityMismatch);
+        }
+        if fixed_32(&row.7, "backend_authority_digest")? != self.backend_authority_digest {
+            return Err(SqliteStoreV2Error::BackendAuthorityMismatch);
+        }
+        if fixed_32(&row.8, "persistence_profile_digest")? != self.persistence_profile_digest {
+            return Err(SqliteStoreV2Error::PersistenceProfileMismatch);
+        }
+        Ok(())
+    }
+
+    #[allow(clippy::too_many_arguments)]
+    fn admit_inner(
+        &mut self,
+        admission: &AdmissionAuthorityV2,
+        use_authority: &UseAuthorityV2,
+        semantic_admission: AuthenticatedAdmissionContextV2,
+        use_slot: AuthenticatedUseSlotV2,
+        persisted_at_unix_ms: u64,
+    ) -> Result<AdmissionCommitV2, SqliteStoreV2Error> {
+        let admission_digest = admission.authority_digest()?;
+        let use_digest = use_authority.authority_digest()?;
+        let use_slot_digest = use_slot.reservation_digest(use_authority)?;
+        let transaction = self
+            .connection
+            .transaction_with_behavior(TransactionBehavior::Immediate)?;
+
+        if let Some(existing) = read_admission_row(&transaction, admission.operation_id)? {
+            if existing.admission_authority_digest != admission_digest
+                || existing.raw_admission_digest != admission.raw_admission_digest
+                || existing.use_authority_digest != use_digest
+                || existing.grant_authority_digest != use_slot.grant_authority_digest
+                || existing.raw_use_digest != use_slot.raw_use_digest
+                || existing.use_index != use_slot.use_index
+                || existing.admitted_at_unix_ms != semantic_admission.admitted_at_unix_ms
+            {
+                transaction.rollback()?;
+                return Err(SqliteStoreV2Error::OperationIdConflict);
+            }
+            let proof = read_admission_proof(&transaction, admission.operation_id)?
+                .ok_or(SqliteStoreV2Error::MissingAdmissionProof)?;
+            transaction.rollback()?;
+            let authenticated = AuthenticatedPersistenceContextV2 {
+                backend_authority_digest: proof.backend_authority_digest,
+                persistence_profile_digest: proof.persistence_profile_digest,
+                commit_evidence_digest: proof.commit_evidence_digest,
+            };
+            proof.validate_against(
+                admission,
+                &self.store_authority,
+                &self.current_epoch,
+                authenticated,
+            )?;
+            return Ok(AdmissionCommitV2 {
+                decision: AdmissionDecisionV2::DuplicateSame,
+                proof,
+                authenticated_persistence: authenticated,
+            });
+        }
+
+        let slot_owner: Option<Vec<u8>> = transaction
+            .query_row(
+                "SELECT operation_id FROM admissions WHERE grant_authority_digest=?1 AND use_index=?2",
+                params![&use_slot.grant_authority_digest[..], i64::from(use_slot.use_index)],
+                |row| row.get(0),
+            )
+            .optional()?;
+        if slot_owner.is_some() {
+            transaction.rollback()?;
+            return Err(SqliteStoreV2Error::GrantUseSlotConflict);
+        }
+
+        let next_sequence = next_admission_sequence(&transaction)?;
+        transaction.execute(
+            "INSERT INTO admissions(operation_id, raw_admission_digest, admission_authority_digest, use_authority_digest, grant_authority_digest, raw_use_digest, use_index, admission_sequence, admitted_at_unix_ms, authority_epoch_digest) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
+            params![
+                &admission.operation_id[..],
+                &admission.raw_admission_digest[..],
+                &admission_digest[..],
+                &use_digest[..],
+                &use_slot.grant_authority_digest[..],
+                &use_slot.raw_use_digest[..],
+                i64::from(use_slot.use_index),
+                sqlite_i64(next_sequence, "admission_sequence")?,
+                sqlite_i64(semantic_admission.admitted_at_unix_ms, "admitted_at_unix_ms")?,
+                &self.current_epoch.epoch_digest()?[..],
+            ],
+        )?;
+        transaction.execute(
+            "UPDATE store_meta SET next_admission_sequence=?1 WHERE singleton=1",
+            params![sqlite_i64(
+                next_sequence
+                    .checked_add(1)
+                    .ok_or(SqliteStoreV2Error::AdmissionSequenceOverflow)?,
+                "next_admission_sequence"
+            )?],
+        )?;
+
+        let frontier = append_frontier(
+            &transaction,
+            self.store_authority.authority_digest()?,
+            persisted_at_unix_ms,
+        )?;
+        let commit_evidence = commit_evidence_digest(
+            b"admission",
+            admission_digest,
+            use_slot_digest,
+            frontier,
+            next_sequence,
+        );
+        let authenticated = self.persistence_context(commit_evidence);
+        let proof = AdmissionPersistenceProofV2::new(
+            admission,
+            &self.store_authority,
+            &self.current_epoch,
+            next_sequence,
+            use_slot_digest,
+            frontier,
+            authenticated,
+            persisted_at_unix_ms,
+        )?;
+        transaction.execute(
+            "INSERT INTO admission_proofs(operation_id, proof_digest, proof_bytes) VALUES(?1, ?2, ?3)",
+            params![
+                &admission.operation_id[..],
+                &proof.proof_digest()?[..],
+                bincode::serialize(&proof)?,
+            ],
+        )?;
+        transaction.commit()?;
+        Ok(AdmissionCommitV2 {
+            decision: AdmissionDecisionV2::Admitted,
+            proof,
+            authenticated_persistence: authenticated,
+        })
+    }
+
+    fn append_effect_armed_inner(
+        &mut self,
+        admission: &AdmissionAuthorityV2,
+        admission_proof: &AdmissionPersistenceProofV2,
+        arm: &EffectArmAuthorityV2,
+        event: &ReceiptEventV1,
+        persisted_at_unix_ms: u64,
+    ) -> Result<EffectArmedCommitV2, SqliteStoreV2Error> {
+        let event_digest = event.event_digest()?;
+        let transaction = self
+            .connection
+            .transaction_with_behavior(TransactionBehavior::Immediate)?;
+
+        if let Some(existing) = read_receipt_event(&transaction, event.operation_id, event.event_index)? {
+            if existing.event_digest()? != event_digest {
+                transaction.rollback()?;
+                return Err(SqliteStoreV2Error::ReceiptCasConflict);
+            }
+            let proof = read_effect_armed_proof(&transaction, event.operation_id)?
+                .ok_or(SqliteStoreV2Error::MissingEffectArmedProof)?;
+            transaction.rollback()?;
+            let authenticated = AuthenticatedPersistenceContextV2 {
+                backend_authority_digest: proof.backend_authority_digest,
+                persistence_profile_digest: proof.persistence_profile_digest,
+                commit_evidence_digest: proof.commit_evidence_digest,
+            };
+            proof.validate_final_gate(
+                arm,
+                admission_proof,
+                &self.store_authority,
+                &self.current_epoch,
+                authenticated,
+            )?;
+            return Ok(EffectArmedCommitV2 {
+                decision: ReceiptDecisionV2::DuplicateSame,
+                proof,
+                authenticated_persistence: authenticated,
+            });
+        }
+
+        if receipt_head(&transaction, event.operation_id)?.is_some() {
+            transaction.rollback()?;
+            return Err(SqliteStoreV2Error::ReceiptCasConflict);
+        }
+        insert_receipt_event(&transaction, event)?;
+        let frontier = append_frontier(
+            &transaction,
+            self.store_authority.authority_digest()?,
+            persisted_at_unix_ms,
+        )?;
+        let commit_evidence = commit_evidence_digest(
+            b"effect-armed",
+            arm.authority_digest()?,
+            admission_proof.proof_digest()?,
+            frontier,
+            u64::from(event.event_index),
+        );
+        let authenticated = self.persistence_context(commit_evidence);
+        let proof = EffectArmedPersistenceProofV2::new(
+            arm,
+            admission_proof,
+            &self.store_authority,
+            &self.current_epoch,
+            event_digest,
+            frontier,
+            authenticated,
+            persisted_at_unix_ms,
+        )?;
+        transaction.execute(
+            "INSERT INTO effect_armed_proofs(operation_id, receipt_event_digest, proof_digest, proof_bytes) VALUES(?1, ?2, ?3, ?4)",
+            params![
+                &event.operation_id[..],
+                &event_digest[..],
+                &proof.proof_digest()?[..],
+                bincode::serialize(&proof)?,
+            ],
+        )?;
+        transaction.commit()?;
+        Ok(EffectArmedCommitV2 {
+            decision: ReceiptDecisionV2::Appended,
+            proof,
+            authenticated_persistence: authenticated,
+        })
+    }
+
+    fn append_receipt_inner(
+        &mut self,
+        binding: ReceiptAdmissionBindingV1,
+        event: &ReceiptEventV1,
+        persisted_at_unix_ms: u64,
+    ) -> Result<ReceiptCommitV2, SqliteStoreV2Error> {
+        let event_digest = event.event_digest()?;
+        let transaction = self
+            .connection
+            .transaction_with_behavior(TransactionBehavior::Immediate)?;
+
+        if let Some(existing) = read_receipt_event(&transaction, event.operation_id, event.event_index)? {
+            if existing.event_digest()? != event_digest {
+                transaction.rollback()?;
+                return Err(SqliteStoreV2Error::ReceiptCasConflict);
+            }
+            let frontier = current_frontier_digest_tx(&transaction)?;
+            transaction.rollback()?;
+            return Ok(ReceiptCommitV2 {
+                decision: ReceiptDecisionV2::DuplicateSame,
+                event_digest,
+                committed_frontier_digest: frontier,
+                authenticated_persistence: self.persistence_context(commit_evidence_digest(
+                    b"receipt-duplicate",
+                    event_digest,
+                    [0xDD; 32],
+                    frontier,
+                    u64::from(event.event_index),
+                )),
+            });
+        }
+
+        match receipt_head(&transaction, event.operation_id)? {
+            None => event.validate_first(binding)?,
+            Some(previous) => event.validate_successor(binding, &previous)?,
+        }
+        insert_receipt_event(&transaction, event)?;
+        let frontier = append_frontier(
+            &transaction,
+            self.store_authority.authority_digest()?,
+            persisted_at_unix_ms,
+        )?;
+        let commit_evidence = commit_evidence_digest(
+            b"receipt",
+            event_digest,
+            event.previous_event_digest,
+            frontier,
+            u64::from(event.event_index),
+        );
+        let authenticated = self.persistence_context(commit_evidence);
+        transaction.commit()?;
+        Ok(ReceiptCommitV2 {
+            decision: ReceiptDecisionV2::Appended,
+            event_digest,
+            committed_frontier_digest: frontier,
+            authenticated_persistence: authenticated,
+        })
+    }
+
+    fn validate_stored_admission_proof(
+        &self,
+        admission: &AdmissionAuthorityV2,
+        supplied: &AdmissionPersistenceProofV2,
+    ) -> Result<(), SqliteStoreV2Error> {
+        let stored = read_admission_proof(&self.connection, admission.operation_id)?
+            .ok_or(SqliteStoreV2Error::MissingAdmissionProof)?;
+        if stored.proof_digest()? != supplied.proof_digest()? {
+            return Err(SqliteStoreV2Error::AdmissionProofMismatch);
+        }
+        let authenticated = AuthenticatedPersistenceContextV2 {
+            backend_authority_digest: stored.backend_authority_digest,
+            persistence_profile_digest: stored.persistence_profile_digest,
+            commit_evidence_digest: stored.commit_evidence_digest,
+        };
+        stored.validate_against(
+            admission,
+            &self.store_authority,
+            &self.current_epoch,
+            authenticated,
+        )?;
+        Ok(())
+    }
+
+    fn persistence_context(&self, commit_evidence_digest: [u8; 32]) -> AuthenticatedPersistenceContextV2 {
+        AuthenticatedPersistenceContextV2 {
+            backend_authority_digest: self.backend_authority_digest,
+            persistence_profile_digest: self.persistence_profile_digest,
+            commit_evidence_digest,
+        }
+    }
+
+    fn verify_frontier_chain(&self) -> Result<(), SqliteStoreV2Error> {
+        let store_authority_digest = self.store_authority.authority_digest()?;
+        let mut statement = self.connection.prepare(
+            "SELECT frontier_sequence, previous_frontier_digest, admissions_root_digest, receipt_heads_root_digest, frontier_digest, created_at_unix_ms FROM frontiers ORDER BY frontier_sequence",
+        )?;
+        let mut rows = statement.query([])?;
+        let mut expected_sequence = 0u64;
+        let mut previous = [0u8; 32];
+        let mut last_admissions_root = None;
+        let mut last_receipt_heads_root = None;
+        let mut last_frontier = None;
+        while let Some(row) = rows.next()? {
+            let sequence_i: i64 = row.get(0)?;
+            let sequence = u64::try_from(sequence_i)
+                .map_err(|_| SqliteStoreV2Error::CorruptInteger("frontier_sequence"))?;
+            if sequence != expected_sequence {
+                return Err(SqliteStoreV2Error::FrontierSequenceMismatch);
+            }
+            let stored_previous = fixed_32(&row.get::<_, Vec<u8>>(1)?, "previous_frontier_digest")?;
+            let admissions_root = fixed_32(&row.get::<_, Vec<u8>>(2)?, "admissions_root_digest")?;
+            let receipt_heads_root = fixed_32(&row.get::<_, Vec<u8>>(3)?, "receipt_heads_root_digest")?;
+            let stored_frontier = fixed_32(&row.get::<_, Vec<u8>>(4)?, "frontier_digest")?;
+            let created_i: i64 = row.get(5)?;
+            let created_at = u64::try_from(created_i)
+                .map_err(|_| SqliteStoreV2Error::CorruptInteger("frontier time"))?;
+            if stored_previous != previous {
+                return Err(SqliteStoreV2Error::FrontierPreviousMismatch);
+            }
+            let expected = frontier_digest(
+                store_authority_digest,
+                sequence,
+                stored_previous,
+                admissions_root,
+                receipt_heads_root,
+                created_at,
+            );
+            if expected != stored_frontier {
+                return Err(SqliteStoreV2Error::FrontierDigestMismatch);
+            }
+            previous = stored_frontier;
+            last_admissions_root = Some(admissions_root);
+            last_receipt_heads_root = Some(receipt_heads_root);
+            last_frontier = Some(stored_frontier);
+            expected_sequence = expected_sequence
+                .checked_add(1)
+                .ok_or(SqliteStoreV2Error::FrontierSequenceOverflow)?;
+        }
+
+        let last_frontier = last_frontier.ok_or(SqliteStoreV2Error::MissingGenesisFrontier)?;
+        if current_frontier_digest_conn(&self.connection)? != last_frontier {
+            return Err(SqliteStoreV2Error::CurrentFrontierMismatch);
+        }
+        let next_sequence: i64 = self.connection.query_row(
+            "SELECT next_frontier_sequence FROM store_meta WHERE singleton=1",
+            [],
+            |row| row.get(0),
+        )?;
+        let next_sequence = u64::try_from(next_sequence)
+            .map_err(|_| SqliteStoreV2Error::CorruptInteger("next_frontier_sequence"))?;
+        if next_sequence != expected_sequence {
+            return Err(SqliteStoreV2Error::FrontierSequenceMismatch);
+        }
+
+        let current_admissions_root = compute_admissions_root(&self.connection)?;
+        let current_receipt_heads_root = compute_receipt_heads_root(&self.connection)?;
+        if last_admissions_root != Some(current_admissions_root)
+            || last_receipt_heads_root != Some(current_receipt_heads_root)
+        {
+            return Err(SqliteStoreV2Error::FrontierRootMismatch);
+        }
+        Ok(())
+    }
+
+    fn require_healthy(&self) -> Result<(), SqliteStoreV2Error> {
+        if self.health != SqliteStoreHealthV2::Healthy {
+            return Err(SqliteStoreV2Error::StoreNotHealthy(self.health));
+        }
+        Ok(())
+    }
+}
+
+#[derive(Debug, Clone, PartialEq, Eq)]
+struct StoredAdmissionRowV2 {
+    raw_admission_digest: [u8; 32],
+    admission_authority_digest: [u8; 32],
+    use_authority_digest: [u8; 32],
+    grant_authority_digest: [u8; 32],
+    raw_use_digest: [u8; 32],
+    use_index: u32,
+    admitted_at_unix_ms: u64,
+}
+
+fn require_database_filename(path: &Path) -> Result<(), SqliteStoreV2Error> {
+    if path.file_name().and_then(|name| name.to_str()) != Some(SQLITE_DATABASE_FILENAME_V2) {
+        return Err(SqliteStoreV2Error::UnexpectedDatabaseFilename);
+    }
+    Ok(())
+}
+
+fn verify_authority_root(path: &Path, expected_uid: u32) -> Result<(), SqliteStoreV2Error> {
+    let metadata = fs::symlink_metadata(path)?;
+    if metadata.file_type().is_symlink() || !metadata.is_dir() {
+        return Err(SqliteStoreV2Error::AuthorityRootNotRealDirectory);
+    }
+    if metadata.uid() != expected_uid {
+        return Err(SqliteStoreV2Error::FilesystemOwnerMismatch);
+    }
+    if metadata.mode() & 0o777 != 0o700 {
+        return Err(SqliteStoreV2Error::AuthorityRootModeMismatch);
+    }
+    Ok(())
+}
+
+fn set_private_file_mode(path: &Path) -> Result<(), SqliteStoreV2Error> {
+    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
+    sync_parent(path)?;
+    Ok(())
+}
+
+fn verify_private_regular_leaf(path: &Path, expected_uid: u32) -> Result<(), SqliteStoreV2Error> {
+    let metadata = fs::symlink_metadata(path)?;
+    if metadata.file_type().is_symlink() || !metadata.is_file() {
+        return Err(SqliteStoreV2Error::PersistentLeafNotRegularFile);
+    }
+    if metadata.uid() != expected_uid {
+        return Err(SqliteStoreV2Error::FilesystemOwnerMismatch);
+    }
+    if metadata.mode() & 0o777 != 0o600 {
+        return Err(SqliteStoreV2Error::PersistentLeafModeMismatch);
+    }
+    if metadata.nlink() != 1 {
+        return Err(SqliteStoreV2Error::UnexpectedHardLinkCount);
+    }
+    Ok(())
+}
+
+fn configure_connection(connection: &Connection) -> Result<(), SqliteStoreV2Error> {
+    connection.busy_timeout(Duration::from_millis(0))?;
+    connection.pragma_update(None, "foreign_keys", "ON")?;
+    let journal_mode: String =
+        connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
+    if !journal_mode.eq_ignore_ascii_case("delete") {
+        return Err(SqliteStoreV2Error::JournalModeMismatch(journal_mode));
+    }
+    connection.pragma_update(None, "synchronous", "EXTRA")?;
+    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
+    if synchronous != 3 {
+        return Err(SqliteStoreV2Error::SynchronousModeMismatch(synchronous));
+    }
+    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
+    if foreign_keys != 1 {
+        return Err(SqliteStoreV2Error::ForeignKeysDisabled);
+    }
+    Ok(())
+}
+
+fn acquire_exclusive_process_lock(connection: &Connection) -> Result<(), SqliteStoreV2Error> {
+    let locking_mode: String =
+        connection.query_row("PRAGMA locking_mode=EXCLUSIVE", [], |row| row.get(0))?;
+    if !locking_mode.eq_ignore_ascii_case("exclusive") {
+        return Err(SqliteStoreV2Error::LockingModeMismatch(locking_mode));
+    }
+    connection.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
+    Ok(())
+}
+
+fn marker_path(database_path: &Path) -> PathBuf {
+    let mut value = database_path.as_os_str().to_os_string();
+    value.push(UNCLEAN_WRITER_MARKER_SUFFIX_V2);
+    PathBuf::from(value)
+}
+
+fn create_unclean_marker(path: &Path, expected_uid: u32) -> Result<(), SqliteStoreV2Error> {
+    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
+    file.set_permissions(fs::Permissions::from_mode(0o600))?;
+    file.write_all(MARKER_BYTES_V2)?;
+    file.sync_all()?;
+    sync_parent(path)?;
+    verify_private_regular_leaf(path, expected_uid)
+}
+
+fn verify_unclean_marker(path: &Path, expected_uid: u32) -> Result<(), SqliteStoreV2Error> {
+    verify_private_regular_leaf(path, expected_uid)?;
+    let mut file = File::open(path)?;
+    let mut bytes = Vec::new();
+    file.read_to_end(&mut bytes)?;
+    if bytes != MARKER_BYTES_V2 {
+        return Err(SqliteStoreV2Error::UnexpectedMarkerContent);
+    }
+    Ok(())
+}
+
+fn remove_unclean_marker(path: &Path, expected_uid: u32) -> Result<(), SqliteStoreV2Error> {
+    verify_unclean_marker(path, expected_uid)?;
+    fs::remove_file(path)?;
+    sync_parent(path)
+}
+
+fn sync_parent(path: &Path) -> Result<(), SqliteStoreV2Error> {
+    let parent = path
+        .parent()
+        .ok_or(SqliteStoreV2Error::DatabasePathHasNoParent)?;
+    File::open(parent)?.sync_all()?;
+    Ok(())
+}
+
+fn read_admission_row(
+    connection: &Connection,
+    operation_id: [u8; 16],
+) -> Result<Option<StoredAdmissionRowV2>, SqliteStoreV2Error> {
+    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64)> = connection
+        .query_row(
+            "SELECT raw_admission_digest, admission_authority_digest, use_authority_digest, grant_authority_digest, raw_use_digest, use_index, admitted_at_unix_ms FROM admissions WHERE operation_id=?1",
+            params![&operation_id[..]],
+            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
+        )
+        .optional()?;
+    let Some(row) = row else {
+        return Ok(None);
+    };
+    Ok(Some(StoredAdmissionRowV2 {
+        raw_admission_digest: fixed_32(&row.0, "raw_admission_digest")?,
+        admission_authority_digest: fixed_32(&row.1, "admission_authority_digest")?,
+        use_authority_digest: fixed_32(&row.2, "use_authority_digest")?,
+        grant_authority_digest: fixed_32(&row.3, "grant_authority_digest")?,
+        raw_use_digest: fixed_32(&row.4, "raw_use_digest")?,
+        use_index: u32::try_from(row.5)
+            .map_err(|_| SqliteStoreV2Error::CorruptInteger("use_index"))?,
+        admitted_at_unix_ms: u64::try_from(row.6)
+            .map_err(|_| SqliteStoreV2Error::CorruptInteger("admitted_at_unix_ms"))?,
+    }))
+}
+
+fn read_admission_proof(
+    connection: &Connection,
+    operation_id: [u8; 16],
+) -> Result<Option<AdmissionPersistenceProofV2>, SqliteStoreV2Error> {
+    let bytes: Option<Vec<u8>> = connection
+        .query_row(
+            "SELECT proof_bytes FROM admission_proofs WHERE operation_id=?1",
+            params![&operation_id[..]],
+            |row| row.get(0),
+        )
+        .optional()?;
+    bytes
+        .map(|bytes| bincode::deserialize(&bytes).map_err(SqliteStoreV2Error::Encoding))
+        .transpose()
+}
+
+fn read_effect_armed_proof(
+    connection: &Connection,
+    operation_id: [u8; 16],
+) -> Result<Option<EffectArmedPersistenceProofV2>, SqliteStoreV2Error> {
+    let bytes: Option<Vec<u8>> = connection
+        .query_row(
+            "SELECT proof_bytes FROM effect_armed_proofs WHERE operation_id=?1",
+            params![&operation_id[..]],
+            |row| row.get(0),
+        )
+        .optional()?;
+    bytes
+        .map(|bytes| bincode::deserialize(&bytes).map_err(SqliteStoreV2Error::Encoding))
+        .transpose()
+}
+
+fn insert_receipt_event(
+    transaction: &Transaction<'_>,
+    event: &ReceiptEventV1,
+) -> Result<(), SqliteStoreV2Error> {
+    transaction.execute(
+        "INSERT INTO receipt_events(operation_id, event_index, previous_event_digest, event_digest, event_bytes, state_code, recorded_at_unix_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
+        params![
+            &event.operation_id[..],
+            i64::from(event.event_index),
+            &event.previous_event_digest[..],
+            &event.event_digest()?[..],
+            bincode::serialize(event)?,
+            receipt_state_code(event.state),
+            sqlite_i64(event.recorded_at_unix_ms, "receipt time")?,
+        ],
+    )?;
+    Ok(())
+}
+
+fn read_receipt_event(
+    connection: &Connection,
+    operation_id: [u8; 16],
+    event_index: u32,
+) -> Result<Option<ReceiptEventV1>, SqliteStoreV2Error> {
+    let bytes: Option<Vec<u8>> = connection
+        .query_row(
+            "SELECT event_bytes FROM receipt_events WHERE operation_id=?1 AND event_index=?2",
+            params![&operation_id[..], i64::from(event_index)],
+            |row| row.get(0),
+        )
+        .optional()?;
+    bytes
+        .map(|bytes| bincode::deserialize(&bytes).map_err(SqliteStoreV2Error::Encoding))
+        .transpose()
+}
+
+fn receipt_head(
+    connection: &Connection,
+    operation_id: [u8; 16],
+) -> Result<Option<ReceiptEventV1>, SqliteStoreV2Error> {
+    let bytes: Option<Vec<u8>> = connection
+        .query_row(
+            "SELECT event_bytes FROM receipt_events WHERE operation_id=?1 ORDER BY event_index DESC LIMIT 1",
+            params![&operation_id[..]],
+            |row| row.get(0),
+        )
+        .optional()?;
+    bytes
+        .map(|bytes| bincode::deserialize(&bytes).map_err(SqliteStoreV2Error::Encoding))
+        .transpose()
+}
+
+fn receipt_state_code(state: ReceiptStateV1) -> i64 {
+    match state {
+        ReceiptStateV1::EffectArmed => 0,
+        ReceiptStateV1::CancelledBeforeEffect => 1,
+        ReceiptStateV1::CancelledAfterArmBeforeEffect => 2,
+        ReceiptStateV1::Completed => 3,
+        ReceiptStateV1::FailedKnown => 4,
+        ReceiptStateV1::OutcomeUnknown => 5,
+    }
+}
+
+fn next_admission_sequence(connection: &Connection) -> Result<u64, SqliteStoreV2Error> {
+    let value: i64 = connection.query_row(
+        "SELECT next_admission_sequence FROM store_meta WHERE singleton=1",
+        [],
+        |row| row.get(0),
+    )?;
+    u64::try_from(value).map_err(|_| SqliteStoreV2Error::CorruptInteger("next_admission_sequence"))
+}
+
+fn append_frontier(
+    transaction: &Transaction<'_>,
+    store_authority_digest: [u8; 32],
+    created_at_unix_ms: u64,
+) -> Result<[u8; 32], SqliteStoreV2Error> {
+    let sequence_i: i64 = transaction.query_row(
+        "SELECT next_frontier_sequence FROM store_meta WHERE singleton=1",
+        [],
+        |row| row.get(0),
+    )?;
+    let sequence = u64::try_from(sequence_i)
+        .map_err(|_| SqliteStoreV2Error::CorruptInteger("next_frontier_sequence"))?;
+    let previous = current_frontier_digest_tx(transaction)?;
+    let admissions_root = compute_admissions_root(transaction)?;
+    let receipt_heads_root = compute_receipt_heads_root(transaction)?;
+    let digest = frontier_digest(
+        store_authority_digest,
+        sequence,
+        previous,
+        admissions_root,
+        receipt_heads_root,
+        created_at_unix_ms,
+    );
+    transaction.execute(
+        "INSERT INTO frontiers(frontier_sequence, previous_frontier_digest, admissions_root_digest, receipt_heads_root_digest, frontier_digest, created_at_unix_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
+        params![
+            sqlite_i64(sequence, "frontier_sequence")?,
+            &previous[..],
+            &admissions_root[..],
+            &receipt_heads_root[..],
+            &digest[..],
+            sqlite_i64(created_at_unix_ms, "frontier time")?,
+        ],
+    )?;
+    let following = sequence
+        .checked_add(1)
+        .ok_or(SqliteStoreV2Error::FrontierSequenceOverflow)?;
+    transaction.execute(
+        "UPDATE store_meta SET next_frontier_sequence=?1, current_frontier_digest=?2 WHERE singleton=1",
+        params![sqlite_i64(following, "next_frontier_sequence")?, &digest[..]],
+    )?;
+    Ok(digest)
+}
+
+fn compute_admissions_root(connection: &Connection) -> Result<[u8; 32], SqliteStoreV2Error> {
+    let count: i64 = connection.query_row("SELECT COUNT(*) FROM admissions", [], |row| row.get(0))?;
+    let count = u64::try_from(count)
+        .map_err(|_| SqliteStoreV2Error::CorruptInteger("admission count"))?;
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(ADMISSION_ROOT_DOMAIN_V2);
+    hasher.update(&count.to_le_bytes());
+    let mut statement = connection.prepare(
+        "SELECT admission_authority_digest FROM admissions ORDER BY admission_sequence",
+    )?;
+    let mut rows = statement.query([])?;
+    while let Some(row) = rows.next()? {
+        let digest = fixed_32(&row.get::<_, Vec<u8>>(0)?, "admission_authority_digest")?;
+        hasher.update(&digest);
+    }
+    Ok(*hasher.finalize().as_bytes())
+}
+
+fn compute_receipt_heads_root(connection: &Connection) -> Result<[u8; 32], SqliteStoreV2Error> {
+    let count: i64 = connection.query_row("SELECT COUNT(*) FROM admissions", [], |row| row.get(0))?;
+    let count = u64::try_from(count)
+        .map_err(|_| SqliteStoreV2Error::CorruptInteger("admission count"))?;
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(RECEIPT_HEADS_ROOT_DOMAIN_V2);
+    hasher.update(&count.to_le_bytes());
+    let mut statement = connection.prepare("SELECT operation_id FROM admissions ORDER BY operation_id")?;
+    let mut rows = statement.query([])?;
+    while let Some(row) = rows.next()? {
+        let operation_id = fixed_16(&row.get::<_, Vec<u8>>(0)?, "operation_id")?;
+        let head: Option<Vec<u8>> = connection
+            .query_row(
+                "SELECT event_digest FROM receipt_events WHERE operation_id=?1 ORDER BY event_index DESC LIMIT 1",
+                params![&operation_id[..]],
+                |row| row.get(0),
+            )
+            .optional()?;
+        let head = match head {
+            Some(bytes) => fixed_32(&bytes, "event_digest")?,
+            None => [0u8; 32],
+        };
+        hasher.update(&operation_id);
+        hasher.update(&head);
+    }
+    Ok(*hasher.finalize().as_bytes())
+}
+
+fn current_frontier_digest_tx(transaction: &Transaction<'_>) -> Result<[u8; 32], SqliteStoreV2Error> {
+    current_frontier_digest_conn(transaction)
+}
+
+fn current_frontier_digest_conn(connection: &Connection) -> Result<[u8; 32], SqliteStoreV2Error> {
+    let bytes: Vec<u8> = connection.query_row(
+        "SELECT current_frontier_digest FROM store_meta WHERE singleton=1",
+        [],
+        |row| row.get(0),
+    )?;
+    fixed_32(&bytes, "current_frontier_digest")
+}
+
+fn empty_root(domain: &[u8]) -> [u8; 32] {
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(domain);
+    hasher.update(&0u64.to_le_bytes());
+    *hasher.finalize().as_bytes()
+}
+
+fn frontier_digest(
+    store_authority_digest: [u8; 32],
+    sequence: u64,
+    previous: [u8; 32],
+    admissions_root: [u8; 32],
+    receipt_heads_root: [u8; 32],
+    created_at_unix_ms: u64,
+) -> [u8; 32] {
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(FRONTIER_DOMAIN_V2);
+    hasher.update(&store_authority_digest);
+    hasher.update(&sequence.to_le_bytes());
+    hasher.update(&previous);
+    hasher.update(&admissions_root);
+    hasher.update(&receipt_heads_root);
+    hasher.update(&created_at_unix_ms.to_le_bytes());
+    *hasher.finalize().as_bytes()
+}
+
+fn store_schema_digest_v2() -> [u8; 32] {
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(b"xenia-operation-store-sqlite-schema-v2");
+    hasher.update(SQLITE_STORE_PROFILE_V2.as_bytes());
+    hasher.update(STORE_SCHEMA_SQL_V2.as_bytes());
+    *hasher.finalize().as_bytes()
+}
+
+fn backend_authority_digest_v2() -> [u8; 32] {
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(BACKEND_AUTHORITY_DOMAIN_V2);
+    hasher.update(SQLITE_STORE_PROFILE_V2.as_bytes());
+    hasher.update(&store_schema_digest_v2());
+    *hasher.finalize().as_bytes()
+}
+
+fn persistence_profile_digest_v2() -> [u8; 32] {
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(PERSISTENCE_PROFILE_DOMAIN_V2);
+    hasher.update(SQLITE_STORE_PROFILE_V2.as_bytes());
+    hasher.update(LINUX_AUTHORITY_ROOT_PROFILE_V1.as_bytes());
+    *hasher.finalize().as_bytes()
+}
+
+fn commit_evidence_digest(
+    mutation_kind: &[u8],
+    primary: [u8; 32],
+    secondary: [u8; 32],
+    frontier: [u8; 32],
+    sequence: u64,
+) -> [u8; 32] {
+    let mut hasher = blake3::Hasher::new();
+    hasher.update(COMMIT_EVIDENCE_DOMAIN_V2);
+    hasher.update(mutation_kind);
+    hasher.update(&primary);
+    hasher.update(&secondary);
+    hasher.update(&frontier);
+    hasher.update(&sequence.to_le_bytes());
+    *hasher.finalize().as_bytes()
+}
+
+fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, SqliteStoreV2Error> {
+    i64::try_from(value).map_err(|_| SqliteStoreV2Error::IntegerOutOfRange(field))
+}
+
+fn fixed_16(bytes: &[u8], field: &'static str) -> Result<[u8; 16], SqliteStoreV2Error> {
+    bytes
+        .try_into()
+        .map_err(|_| SqliteStoreV2Error::BlobLength(field))
+}
+
+fn fixed_32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], SqliteStoreV2Error> {
+    bytes
+        .try_into()
+        .map_err(|_| SqliteStoreV2Error::BlobLength(field))
+}
+
+/// SQLite V2 operation-store failure.
+#[derive(Debug, Error)]
+pub enum SqliteStoreV2Error {
+    /// Database filename differs from the fixed V2 deployment profile.
+    #[error("unexpected SQLite V2 database filename")]
+    UnexpectedDatabaseFilename,
+    /// Database path has no parent authority directory.
+    #[error("database path has no parent directory")]
+    DatabasePathHasNoParent,
+    /// Final authority root is a symlink or not a directory.
+    #[error("authority root must be a real directory")]
+    AuthorityRootNotRealDirectory,
+    /// Filesystem owner differs from the trusted service identity.
+    #[error("filesystem owner mismatch")]
+    FilesystemOwnerMismatch,
+    /// Final authority root is not exactly mode 0700.
+    #[error("authority root mode must be 0700")]
+    AuthorityRootModeMismatch,
+    /// Persistent database/marker leaf is not a regular non-symlink file.
+    #[error("persistent store leaf must be a regular non-symlink file")]
+    PersistentLeafNotRegularFile,
+    /// Persistent database/marker leaf is not exactly mode 0600.
+    #[error("persistent store leaf mode must be 0600")]
+    PersistentLeafModeMismatch,
+    /// Persistent leaf has an unexpected hard-link count.
+    #[error("persistent store leaf has unexpected hard links")]
+    UnexpectedHardLinkCount,
+    /// Existing fail-stop marker contents are not the exact V2 marker.
+    #[error("unexpected unclean-writer marker contents")]
+    UnexpectedMarkerContent,
+    /// SQLite did not enter DELETE rollback-journal mode.
+    #[error("SQLite journal mode mismatch: {0}")]
+    JournalModeMismatch(String),
+    /// SQLite did not retain synchronous=EXTRA.
+    #[error("SQLite synchronous mode mismatch: {0}")]
+    SynchronousModeMismatch(i64),
+    /// SQLite foreign keys could not be enabled.
+    #[error("SQLite foreign keys are disabled")]
+    ForeignKeysDisabled,
+    /// SQLite did not retain exclusive locking mode.
+    #[error("SQLite locking mode mismatch: {0}")]
+    LockingModeMismatch(String),
+    /// Schema version mismatch.
+    #[error("store schema version mismatch: expected {expected}, found {found}")]
+    SchemaVersionMismatch {
+        /// Expected exact schema version.
+        expected: i64,
+        /// Version read from disk.
+        found: i64,
+    },
+    /// Store schema commitment mismatch.
+    #[error("store schema digest mismatch")]
+    StoreSchemaDigestMismatch,
+    /// Store id mismatch.
+    #[error("store id mismatch")]
+    StoreIdMismatch,
+    /// Store generation mismatch.
+    #[error("store generation mismatch")]
+    GenerationMismatch,
+    /// Authority domain mismatch.
+    #[error("authority domain mismatch")]
+    AuthorityDomainMismatch,
+    /// Authority epoch mismatch.
+    #[error("authority epoch mismatch")]
+    AuthorityEpochMismatch,
+    /// Store authority commitment mismatch.
+    #[error("store authority mismatch")]
+    StoreAuthorityMismatch,
+    /// Backend authority commitment mismatch.
+    #[error("backend authority mismatch")]
+    BackendAuthorityMismatch,
+    /// Persistence profile commitment mismatch.
+    #[error("persistence profile mismatch")]
+    PersistenceProfileMismatch,
+    /// Same operation id was reused for different immutable authority.
+    #[error("operation id conflict")]
+    OperationIdConflict,
+    /// Another operation already owns this exact finite grant use slot.
+    #[error("grant use slot conflict")]
+    GrantUseSlotConflict,
+    /// Operation id differs across use/admission authority.
+    #[error("operation id mismatch")]
+    OperationIdMismatch,
+    /// Admission points at a different use authority.
+    #[error("use authority mismatch")]
+    UseAuthorityMismatch,
+    /// Authenticated slot names another grant authority.
+    #[error("authenticated grant authority mismatch")]
+    GrantAuthorityMismatch,
+    /// Authenticated slot names another raw use commitment.
+    #[error("authenticated raw use digest mismatch")]
+    RawUseDigestMismatch,
+    /// Authenticated admission context names another raw admission commitment.
+    #[error("authenticated raw admission digest mismatch")]
+    RawAdmissionDigestMismatch,
+    /// Admission sequence overflow.
+    #[error("admission sequence overflow")]
+    AdmissionSequenceOverflow,
+    /// Receipt/frontier sequence overflow.
+    #[error("frontier sequence overflow")]
+    FrontierSequenceOverflow,
+    /// Missing admission persistence proof for a durable admission.
+    #[error("durable admission is missing its persistence proof")]
+    MissingAdmissionProof,
+    /// Supplied admission proof differs from the proof persisted by this store.
+    #[error("admission persistence proof mismatch")]
+    AdmissionProofMismatch,
+    /// Missing durable EffectArmed persistence proof.
+    #[error("effect armed event is missing its persistence proof")]
+    MissingEffectArmedProof,
+    /// Receipt compare-and-append head/index conflict.
+    #[error("receipt compare-and-append conflict")]
+    ReceiptCasConflict,
+    /// The dedicated arm method received another receipt state.
+    #[error("append_effect_armed requires EffectArmed state")]
+    EffectArmedMethodRequiresEffectArmed,
+    /// Generic receipt path attempted to append EffectArmed.
+    #[error("EffectArmed requires the dedicated persistence-proof path")]
+    EffectArmedRequiresDedicatedMethod,
+    /// Receipt arm authorization does not bind the V2 arm's raw semantic authorization.
+    #[error("receipt arm authorization digest mismatch")]
+    ArmAuthorizationDigestMismatch,
+    /// Persistence timestamp precedes semantic or predecessor evidence.
+    #[error("persistence timestamp regressed")]
+    PersistenceTimestampRegression,
+    /// Store is fail-stopped.
+    #[error("store is not healthy: {0:?}")]
+    StoreNotHealthy(SqliteStoreHealthV2),
+    /// Clean close is forbidden outside Healthy state.
+    #[error("clean close denied for store health {0:?}")]
+    CleanCloseDenied(SqliteStoreHealthV2),
+    /// SQLite integrity check failed.
+    #[error("SQLite integrity check failed: {0}")]
+    IntegrityCheckFailed(String),
+    /// Local frontier sequence is not contiguous.
+    #[error("local frontier sequence mismatch")]
+    FrontierSequenceMismatch,
+    /// Local frontier predecessor commitment is wrong.
+    #[error("local frontier previous digest mismatch")]
+    FrontierPreviousMismatch,
+    /// Local frontier digest does not recompute.
+    #[error("local frontier digest mismatch")]
+    FrontierDigestMismatch,
+    /// No genesis frontier exists.
+    #[error("missing genesis frontier")]
+    MissingGenesisFrontier,
+    /// `store_meta` current frontier differs from the frontier chain head.
+    #[error("current frontier metadata mismatch")]
+    CurrentFrontierMismatch,
+    /// Current admission/receipt roots differ from the frontier head.
+    #[error("current frontier semantic roots mismatch")]
+    FrontierRootMismatch,
+    /// Unsigned value cannot fit SQLite INTEGER.
+    #[error("value out of SQLite INTEGER range: {0}")]
+    IntegerOutOfRange(&'static str),
+    /// Stored SQLite integer is invalid for the expected unsigned field.
+    #[error("corrupt SQLite integer field: {0}")]
+    CorruptInteger(&'static str),
+    /// Stored fixed-size blob has the wrong length.
+    #[error("corrupt SQLite blob length: {0}")]
+    BlobLength(&'static str),
+    /// Authority V2 validation failed.
+    #[error(transparent)]
+    Authority(#[from] AuthorityV2Error),
+    /// Authority epoch validation failed.
+    #[error(transparent)]
+    Epoch(#[from] AuthorityEpochError),
+    /// Persistence-proof validation failed.
+    #[error(transparent)]
+    PersistenceProof(#[from] PersistenceProofV2Error),
+    /// Receipt finalization validation failed.
+    #[error(transparent)]
+    Receipt(#[from] ReceiptFinalizationError),
+    /// Bincode serialization/deserialization failed.
+    #[error("bincode encoding failed: {0}")]
+    Encoding(#[from] bincode::Error),
+    /// SQLite operation failed.
+    #[error("SQLite error: {0}")]
+    Sqlite(#[from] rusqlite::Error),
+    /// Filesystem operation failed.
+    #[error("filesystem error: {0}")]
+    Io(#[from] std::io::Error),
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
+    use tempfile::TempDir;
+    use xenia_operation_authority_epoch::{
+        AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1,
+    };
+    use xenia_operation_authority_v2::{
+        AuthenticatedIssuanceContextV2, GrantAuthorityV2,
+    };
+
+    struct Fixture {
+        epoch: OperationAuthorityEpochV1,
+        grant: GrantAuthorityV2,
+        use_authority: UseAuthorityV2,
+        admission: AdmissionAuthorityV2,
+        semantic_admission: AuthenticatedAdmissionContextV2,
+        use_slot: AuthenticatedUseSlotV2,
+    }
+
+    fn epoch() -> OperationAuthorityEpochV1 {
+        OperationAuthorityEpochV1 {
+            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
+            authority_domain_id: [1; 16],
+            epoch_id: [2; 16],
+            epoch_sequence: 0,
+            previous_epoch_digest: [0; 32],
+            store_id: [3; 16],
+            store_generation: 0,
+            reason: AuthorityEpochReasonV1::Genesis,
+            established_at_unix_ms: 1_000,
+        }
+    }
+
+    fn fixture() -> Fixture {
+        let epoch = epoch();
+        let issuance = AuthenticatedIssuanceContextV2 {
+            issuer_authority_digest: [0x11; 32],
+            issuance_evidence_digest: [0x12; 32],
+        };
+        let grant = GrantAuthorityV2::new([0x21; 32], &epoch, issuance, 1_020).unwrap();
+        let use_authority =
+            UseAuthorityV2::new([0x31; 16], [0x32; 32], &grant, &epoch, issuance).unwrap();
+        let admission = AdmissionAuthorityV2::new(
+            [0x41; 32],
+            &use_authority,
+            &grant,
+            &epoch,
+            issuance,
+        )
+        .unwrap();
+        Fixture {
+            epoch,
+            grant,
+            use_authority: use_authority.clone(),
+            admission,
+            semantic_admission: AuthenticatedAdmissionContextV2 {
+                raw_admission_digest: [0x41; 32],
+                admitted_at_unix_ms: 1_050,
+            },
+            use_slot: AuthenticatedUseSlotV2 {
+                grant_authority_digest: use_authority.grant_authority_digest,
+                raw_use_digest: use_authority.raw_use_digest,
+                use_index: 0,
+            },
+        }
+    }
+
+    fn private_root() -> (TempDir, PathBuf, u32) {
+        let temp = TempDir::new().unwrap();
+        let root = temp.path().join("authority");
+        fs::create_dir(&root).unwrap();
+        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
+        let uid = fs::symlink_metadata(&root).unwrap().uid();
+        (temp, root, uid)
+    }
+
+    fn database_path(root: &Path) -> PathBuf {
+        root.join(SQLITE_DATABASE_FILENAME_V2)
+    }
+
+    #[test]
+    fn new_store_commits_admission_proof_and_frontier() {
+        let fixture = fixture();
+        let (_temp, root, uid) = private_root();
+        let mut store =
+            SqliteOperationStoreV2::open(database_path(&root), fixture.epoch.clone(), uid).unwrap();
+        let genesis = store.current_frontier_digest().unwrap();
+        let commit = store
+            .admit(
+                &fixture.admission,
+                &fixture.use_authority,
+                fixture.semantic_admission,
+                fixture.use_slot,
+                1_100,
+            )
+            .unwrap();
+        assert_eq!(commit.decision, AdmissionDecisionV2::Admitted);
+        assert_ne!(commit.proof.committed_frontier_digest, genesis);
+        commit
+            .proof
+            .validate_against(
+                &fixture.admission,
+                store.store_authority(),
+                store.current_epoch(),
+                commit.authenticated_persistence,
+            )
+            .unwrap();
+        store.verify_local_integrity().unwrap();
+        store.close_clean().unwrap();
+    }
+
+    #[test]
+    fn exact_admission_retry_returns_same_durable_proof() {
+        let fixture = fixture();
+        let (_temp, root, uid) = private_root();
+        let mut store =
+            SqliteOperationStoreV2::open(database_path(&root), fixture.epoch.clone(), uid).unwrap();
+        let first = store
+            .admit(
+                &fixture.admission,
+                &fixture.use_authority,
+                fixture.semantic_admission,
+                fixture.use_slot,
+                1_100,
+            )
+            .unwrap();
+        let second = store
+            .admit(
+                &fixture.admission,
+                &fixture.use_authority,
+                fixture.semantic_admission,
+                fixture.use_slot,
+                1_100,
+            )
+            .unwrap();
+        assert_eq!(second.decision, AdmissionDecisionV2::DuplicateSame);
+        assert_eq!(first.proof.proof_digest().unwrap(), second.proof.proof_digest().unwrap());
+        store.close_clean().unwrap();
+    }
+
+    #[test]
+    fn another_operation_cannot_reuse_grant_slot() {
+        let fixture = fixture();
+        let (_temp, root, uid) = private_root();
+        let mut store =
+            SqliteOperationStoreV2::open(database_path(&root), fixture.epoch.clone(), uid).unwrap();
+        store
+            .admit(
+                &fixture.admission,
+                &fixture.use_authority,
+                fixture.semantic_admission,
+                fixture.use_slot,
+                1_100,
+            )
+            .unwrap();
+
+        let issuance = AuthenticatedIssuanceContextV2 {
+            issuer_authority_digest: fixture.grant.issuer_authority_digest,
+            issuance_evidence_digest: fixture.grant.issuance_evidence_digest,
+        };
+        let other_use = UseAuthorityV2::new(
+            [0x51; 16],
+            [0x52; 32],
+            &fixture.grant,
+            &fixture.epoch,
+            issuance,
+        )
+        .unwrap();
+        let other_admission = AdmissionAuthorityV2::new(
+            [0x53; 32],
+            &other_use,
+            &fixture.grant,
+            &fixture.epoch,
+            issuance,
+        )
+        .unwrap();
+        let slot = AuthenticatedUseSlotV2 {
+            grant_authority_digest: fixture.use_slot.grant_authority_digest,
+            raw_use_digest: other_use.raw_use_digest,
+            use_index: 0,
+        };
+        assert!(matches!(
+            store.admit(
+                &other_admission,
+                &other_use,
+                AuthenticatedAdmissionContextV2 {
+                    raw_admission_digest: [0x53; 32],
+                    admitted_at_unix_ms: 1_060,
+                },
+                slot,
+                1_120,
+            ),
+            Err(SqliteStoreV2Error::GrantUseSlotConflict)
+        ));
+        store.close_clean().unwrap();
+    }
+
+    #[test]
+    fn effect_armed_and_terminal_receipts_advance_frontier() {
+        let fixture = fixture();
+        let (_temp, root, uid) = private_root();
+        let mut store =
+            SqliteOperationStoreV2::open(database_path(&root), fixture.epoch.clone(), uid).unwrap();
+        let admission_commit = store
+            .admit(
+                &fixture.admission,
+                &fixture.use_authority,
+                fixture.semantic_admission,
+                fixture.use_slot,
+                1_100,
+            )
+            .unwrap();
+        let arm = EffectArmAuthorityV2::new(
+            [0x61; 32],
+            &fixture.admission,
+            store.store_authority(),
+            store.current_epoch(),
+        )
+        .unwrap();
+        let armed = ReceiptEventV1 {
+            schema: xenia_operation_receipt_finalization::RECEIPT_FINALIZATION_SCHEMA_V1.into(),
+            admission_digest: fixture.admission.raw_admission_digest,
+            operation_id: fixture.admission.operation_id,
+            event_index: 0,
+            previous_event_digest: [0; 32],
+            state: ReceiptStateV1::EffectArmed,
+            recorded_at_unix_ms: 1_150,
+            arm_authorization_digest: Some(arm.raw_arm_authorization_digest),
+            evidence_digest: None,
+        };
+        let arm_commit = store
+            .append_effect_armed(
+                &fixture.admission,
+                fixture.semantic_admission,
+                &admission_commit.proof,
+                &arm,
+                &armed,
+                1_160,
+            )
+            .unwrap();
+        arm_commit
+            .proof
+            .validate_final_gate(
+                &arm,
+                &admission_commit.proof,
+                store.store_authority(),
+                store.current_epoch(),
+                arm_commit.authenticated_persistence,
+            )
+            .unwrap();
+
+        let terminal = ReceiptEventV1 {
+            schema: xenia_operation_receipt_finalization::RECEIPT_FINALIZATION_SCHEMA_V1.into(),
+            admission_digest: fixture.admission.raw_admission_digest,
+            operation_id: fixture.admission.operation_id,
+            event_index: 1,
+            previous_event_digest: armed.event_digest().unwrap(),
+            state: ReceiptStateV1::CancelledAfterArmBeforeEffect,
+            recorded_at_unix_ms: 1_170,
+            arm_authorization_digest: None,
+            evidence_digest: Some([0x71; 32]),
+        };
+        store
+            .append_receipt(
+                &fixture.admission,
+                fixture.semantic_admission,
+                &terminal,
+                1_180,
+            )
+            .unwrap();
+        store.verify_local_integrity().unwrap();
+        store.close_clean().unwrap();
+    }
+
+    #[test]
+    fn database_symlink_is_rejected_before_sqlite_open() {
+        let fixture = fixture();
+        let (_temp, root, uid) = private_root();
+        let target = root.join("real.sqlite3");
+        File::create(&target).unwrap();
+        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
+        symlink(&target, database_path(&root)).unwrap();
+        assert!(matches!(
+            SqliteOperationStoreV2::open(database_path(&root), fixture.epoch, uid),
+            Err(SqliteStoreV2Error::PersistentLeafNotRegularFile)
+        ));
+    }
+
+    #[test]
+    fn authority_root_must_be_private() {
+        let fixture = fixture();
+        let (_temp, root, uid) = private_root();
+        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
+        assert!(matches!(
+            SqliteOperationStoreV2::open(database_path(&root), fixture.epoch, uid),
+            Err(SqliteStoreV2Error::AuthorityRootModeMismatch)
+        ));
+    }
+
+    #[test]
+    fn ordinary_drop_requires_recovery_on_reopen() {
+        let fixture = fixture();
+        let (_temp, root, uid) = private_root();
+        let path = database_path(&root);
+        {
+            let store = SqliteOperationStoreV2::open(&path, fixture.epoch.clone(), uid).unwrap();
+            assert_eq!(store.health(), SqliteStoreHealthV2::Healthy);
+        }
+        let store = SqliteOperationStoreV2::open(&path, fixture.epoch, uid).unwrap();
+        assert_eq!(store.health(), SqliteStoreHealthV2::RecoveryRequired);
+    }
+}
