// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic retained evidence bundles for operation-frontier anti-rollback witnesses.
//!
//! This crate packages the exact signed frontier witness together with the exact signed Xenia
//! ledger checkpoint it references. The bundle can prove local self-consistency before retention,
//! but it is still not an authorization token: recovery trust requires the independently retained
//! ledger key plus recovered signed ledger/frontier history through the authority adapter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_ledger::{
    CheckpointError, CheckpointFreshnessPolicy, LedgerCheckpoint, LedgerEntry, Verifier,
    checkpoint_fingerprint,
};
use xenia_operation_frontier_ledger_adapter::{
    OperationFrontierWitnessAdapterError, VerifiedOperationFrontierWitnessV1,
    verify_operation_frontier_witness_successor_v1, verify_operation_frontier_witness_v1,
};
use xenia_operation_frontier_ledger_witness::{
    FrontierLedgerWitnessError, LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessV1,
};
use xenia_operation_store_frontier::OperationStoreFrontierV1;

/// Stable schema for retained witness/checkpoint bundles.
pub const RETAINED_OPERATION_FRONTIER_WITNESS_BUNDLE_SCHEMA_V1: &str =
    "xenia-retained-operation-frontier-witness-bundle-v1";
/// Domain separator for the exact retained bundle commitment.
pub const RETAINED_OPERATION_FRONTIER_WITNESS_BUNDLE_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-retained-operation-frontier-witness-bundle-digest-v1";

/// One atomically retainable signed witness plus the exact signed checkpoint it references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedOperationFrontierWitnessBundleV1 {
    /// Exact bundle schema.
    pub schema: String,
    /// Externally retained signed frontier witness.
    pub witness: OperationFrontierLedgerWitnessV1,
    /// Exact signed Xenia ledger checkpoint bound by the witness.
    pub ledger_checkpoint: LedgerCheckpoint,
    /// Time this bundle was handed to the external retention domain, in Unix milliseconds.
    pub retained_at_unix_ms: u64,
}

impl RetainedOperationFrontierWitnessBundleV1 {
    /// Construct a locally self-consistent bundle before external retention.
    ///
    /// This validates the checkpoint's own signature and exact witness binding, but does not know
    /// whether the checkpoint key is the independently retained trusted key for this deployment.
    pub fn new(
        witness: OperationFrontierLedgerWitnessV1,
        ledger_checkpoint: LedgerCheckpoint,
        retained_at_unix_ms: u64,
    ) -> Result<Self, RetainedWitnessBundleError> {
        let value = Self {
            schema: RETAINED_OPERATION_FRONTIER_WITNESS_BUNDLE_SCHEMA_V1.to_string(),
            witness,
            ledger_checkpoint,
            retained_at_unix_ms,
        };
        value.validate_local()?;
        Ok(value)
    }

    /// Validate bundle-local signature/binding/time invariants without making a recovery decision.
    pub fn validate_local(&self) -> Result<(), RetainedWitnessBundleError> {
        if self.schema != RETAINED_OPERATION_FRONTIER_WITNESS_BUNDLE_SCHEMA_V1 {
            return Err(RetainedWitnessBundleError::UnsupportedSchema);
        }
        self.witness.validate()?;
        Verifier::verify_checkpoint(&self.ledger_checkpoint)?;

        let expected_binding = LedgerCheckpointBindingV1::new(
            checkpoint_fingerprint(&self.ledger_checkpoint)?,
            self.ledger_checkpoint.entry_count,
            self.ledger_checkpoint.head_hash,
            self.ledger_checkpoint.ledger_public_key,
            self.ledger_checkpoint.timestamp_unix_secs,
        )?;
        if self.witness.payload.ledger_checkpoint != expected_binding {
            return Err(RetainedWitnessBundleError::CheckpointBindingMismatch);
        }

        let checkpoint_ms = self
            .ledger_checkpoint
            .timestamp_unix_secs
            .checked_mul(1_000)
            .ok_or(RetainedWitnessBundleError::CheckpointTimestampOverflow)?;
        if self.retained_at_unix_ms < self.witness.payload.witnessed_at_unix_ms {
            return Err(RetainedWitnessBundleError::RetentionPredatesWitness);
        }
        if self.retained_at_unix_ms < checkpoint_ms {
            return Err(RetainedWitnessBundleError::RetentionPredatesCheckpoint);
        }
        Ok(())
    }

    /// Canonical bincode-v1 bytes for external immutable retention.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RetainedWitnessBundleError> {
        self.validate_local()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable BLAKE3-256 commitment to the exact retained bundle.
    pub fn bundle_digest(&self) -> Result<[u8; 32], RetainedWitnessBundleError> {
        Ok(domain_digest(
            RETAINED_OPERATION_FRONTIER_WITNESS_BUNDLE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    /// Validate append-only successor semantics for an external retention log.
    ///
    /// The contained witnesses must be exact V1 successors and retention time may not regress.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), RetainedWitnessBundleError> {
        previous.validate_local()?;
        self.validate_local()?;
        self.witness.validate_successor(&previous.witness)?;
        if self.retained_at_unix_ms < previous.retained_at_unix_ms {
            return Err(RetainedWitnessBundleError::RetentionTimestampRegressed);
        }
        Ok(())
    }
}

/// Verify one retained bundle against independently trusted/recovered local state.
pub fn verify_retained_operation_frontier_bundle_v1(
    bundle: &RetainedOperationFrontierWitnessBundleV1,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
) -> Result<VerifiedOperationFrontierWitnessV1, RetainedWitnessBundleError> {
    bundle.validate_local()?;
    Ok(verify_operation_frontier_witness_v1(
        &bundle.witness,
        &bundle.ledger_checkpoint,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        freshness_policy,
    )?)
}

/// Verify retained predecessor/candidate bundles as one append-only recovery-evidence lineage.
pub fn verify_retained_operation_frontier_bundle_successor_v1(
    previous: &RetainedOperationFrontierWitnessBundleV1,
    candidate: &RetainedOperationFrontierWitnessBundleV1,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
) -> Result<VerifiedOperationFrontierWitnessV1, RetainedWitnessBundleError> {
    previous.validate_local()?;
    candidate.validate_successor(previous)?;
    Ok(verify_operation_frontier_witness_successor_v1(
        &previous.witness,
        &previous.ledger_checkpoint,
        &candidate.witness,
        &candidate.ledger_checkpoint,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        freshness_policy,
    )?)
}

/// Errors surfaced by retained witness bundle creation/verification.
#[derive(Debug, Error)]
pub enum RetainedWitnessBundleError {
    /// Unknown retained-bundle schema.
    #[error("unsupported retained frontier witness bundle schema")]
    UnsupportedSchema,
    /// Witness contract rejected the retained witness.
    #[error("retained witness failed validation: {0}")]
    Witness(#[from] FrontierLedgerWitnessError),
    /// Real checkpoint signature/schema validation failed.
    #[error("retained ledger checkpoint failed validation: {0}")]
    Checkpoint(#[from] CheckpointError),
    /// Witness binding did not equal the exact retained checkpoint.
    #[error("retained witness does not bind the exact retained ledger checkpoint")]
    CheckpointBindingMismatch,
    /// Checkpoint seconds could not be represented in milliseconds.
    #[error("retained ledger checkpoint timestamp overflow")]
    CheckpointTimestampOverflow,
    /// Bundle retention time predates the signed witness.
    #[error("retention time predates witness creation")]
    RetentionPredatesWitness,
    /// Bundle retention time predates the signed checkpoint.
    #[error("retention time predates ledger checkpoint")]
    RetentionPredatesCheckpoint,
    /// Retention timestamp moved backward across bundle succession.
    #[error("retention timestamp regressed")]
    RetentionTimestampRegressed,
    /// Canonical bundle serialization failed.
    #[error("retained witness bundle serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
    /// Authority-owning ledger/frontier composition rejected the bundle.
    #[error("retained witness bundle failed authority verification: {0}")]
    Adapter(#[from] OperationFrontierWitnessAdapterError),
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, checkpoint_fingerprint};
    use xenia_operation_frontier_ledger_witness::{
        OperationFrontierLedgerWitnessPayloadV1, OperationFrontierLedgerWitnessV1,
    };

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn ledger(key: SigningKey) -> Chain {
        let mut chain = Chain::new(key);
        chain
            .append(ConsentEventRecord {
                source_id: [1u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(2),
                kind: ConsentKind::Approval,
                scope: "retention-bundle-test".to_string(),
            })
            .unwrap();
        chain
    }

    fn frontier(sequence: u64, previous: [u8; 32], time_ms: u64) -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            [7u8; 16],
            0,
            sequence,
            [8u8; 32],
            previous,
            time_ms,
            &[],
            &[],
        )
        .unwrap()
    }

    fn witness(
        key: &SigningKey,
        checkpoint: &LedgerCheckpoint,
        frontier: &OperationStoreFrontierV1,
        witness_sequence: u64,
        previous_witness_digest: [u8; 32],
        time_ms: u64,
    ) -> OperationFrontierLedgerWitnessV1 {
        let binding = LedgerCheckpointBindingV1::new(
            checkpoint_fingerprint(checkpoint).unwrap(),
            checkpoint.entry_count,
            checkpoint.head_hash,
            checkpoint.ledger_public_key,
            checkpoint.timestamp_unix_secs,
        )
        .unwrap();
        OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                frontier.anchor(time_ms).unwrap(),
                binding,
                witness_sequence,
                previous_witness_digest,
                time_ms,
            )
            .unwrap(),
            key,
        )
        .unwrap()
    }

    #[test]
    fn bundle_keeps_exact_checkpoint_with_witness() {
        let key = key(3);
        let chain = ledger(key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let witness = witness(&key, &checkpoint, &f0, 0, [0u8; 32], 100_000);
        let bundle = RetainedOperationFrontierWitnessBundleV1::new(
            witness,
            checkpoint,
            101_000,
        )
        .unwrap();
        bundle.validate_local().unwrap();
        assert_ne!(bundle.bundle_digest().unwrap(), [0u8; 32]);
    }

    #[test]
    fn mismatched_checkpoint_cannot_be_packaged() {
        let key = key(3);
        let chain = ledger(key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let different_checkpoint = chain.sign_checkpoint(101);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let witness = witness(&key, &checkpoint, &f0, 0, [0u8; 32], 100_000);
        assert!(matches!(
            RetainedOperationFrontierWitnessBundleV1::new(
                witness,
                different_checkpoint,
                101_000,
            ),
            Err(RetainedWitnessBundleError::CheckpointBindingMismatch)
        ));
    }

    #[test]
    fn retained_bundle_composes_with_real_recovery_history() {
        let key = key(3);
        let chain = ledger(key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let bundle = RetainedOperationFrontierWitnessBundleV1::new(
            witness(&key, &checkpoint, &f0, 0, [0u8; 32], 100_000),
            checkpoint,
            101_000,
        )
        .unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let verified = verify_retained_operation_frontier_bundle_v1(
            &bundle,
            &entries,
            key.verifying_key().to_bytes(),
            std::slice::from_ref(&f0),
            101,
            CheckpointFreshnessPolicy {
                max_age_secs: Some(10),
                max_future_skew_secs: 5,
            },
        )
        .unwrap();
        assert_eq!(verified.witness_sequence(), 0);
    }
}
