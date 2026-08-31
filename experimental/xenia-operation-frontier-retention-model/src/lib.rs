// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reference model for append-only external retention of operation-frontier witness bundles.
//!
//! This is an executable behavioral oracle, not a network/object-store implementation. Future
//! retention backends should match these sequence/fork/durability semantics before they are used
//! to satisfy ADR-023 rollback-resistance claims.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;
use xenia_operation_frontier_retention_bundle::{
    RetainedOperationFrontierWitnessBundleV1, RetainedWitnessBundleError,
};

/// Health of the local retention client/model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionHealthV1 {
    /// All acknowledged mutations have known durable outcomes.
    Healthy,
    /// A persistence call had an unknown outcome; no further writes are allowed until readback.
    DurabilityUncertain,
}

/// Result of an external persistence attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPersistenceOutcomeV1 {
    /// Backend confirms the exact candidate is durable.
    Durable,
    /// Backend confirms it did not durably append the candidate.
    Rejected,
    /// Backend cannot prove whether the candidate committed.
    Unknown,
}

/// Successful append classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionDecisionV1 {
    /// New exact next bundle was durably appended.
    Appended,
    /// Exact already-durable bundle was replayed.
    DuplicateSame,
}

/// In-memory reference model for one retained witness lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRetentionModelV1 {
    bundles: Vec<RetainedOperationFrontierWitnessBundleV1>,
    health: RetentionHealthV1,
}

impl Default for ExternalRetentionModelV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalRetentionModelV1 {
    /// Construct an empty healthy retention lineage.
    pub const fn new() -> Self {
        Self {
            bundles: Vec::new(),
            health: RetentionHealthV1::Healthy,
        }
    }

    /// Rehydrate from externally read-back durable bundles.
    ///
    /// Readback is the only V1 path from `DurabilityUncertain` to a fresh healthy model. Every
    /// bundle and successor relationship is revalidated rather than trusting a mutable latest
    /// pointer.
    pub fn from_retained_lineage(
        bundles: Vec<RetainedOperationFrontierWitnessBundleV1>,
    ) -> Result<Self, RetentionModelError> {
        if let Some(first) = bundles.first() {
            first.validate_local()?;
            if first.witness.payload.witness_sequence != 0 {
                return Err(RetentionModelError::SequenceGap);
            }
            for pair in bundles.windows(2) {
                pair[1].validate_successor(&pair[0])?;
            }
        }
        Ok(Self {
            bundles,
            health: RetentionHealthV1::Healthy,
        })
    }

    /// Current fail-stop health.
    pub const fn health(&self) -> RetentionHealthV1 {
        self.health
    }

    /// Number of known durable bundles in this lineage.
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Whether no durable witness bundle is known yet.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Latest known durable retained bundle.
    pub fn latest(&self) -> Option<&RetainedOperationFrontierWitnessBundleV1> {
        self.bundles.last()
    }

    /// Append one candidate only after the caller-supplied persistence boundary reports Durable.
    ///
    /// `persist` represents the external immutable/CAS backend. V1 makes a deliberately strict
    /// distinction between a definite rejection and an unknown outcome. Unknown outcome freezes
    /// all future writes; callers must read the external lineage back and rehydrate a new model.
    pub fn append_with_persistence(
        &mut self,
        candidate: RetainedOperationFrontierWitnessBundleV1,
        persist: impl FnOnce(&RetainedOperationFrontierWitnessBundleV1) -> RetentionPersistenceOutcomeV1,
    ) -> Result<RetentionDecisionV1, RetentionModelError> {
        if self.health != RetentionHealthV1::Healthy {
            return Err(RetentionModelError::DurabilityUncertain);
        }
        candidate.validate_local()?;
        let sequence = candidate.witness.payload.witness_sequence;

        if let Some(existing) = self
            .bundles
            .iter()
            .find(|bundle| bundle.witness.payload.witness_sequence == sequence)
        {
            if existing == &candidate {
                return Ok(RetentionDecisionV1::DuplicateSame);
            }
            return Err(RetentionModelError::SequenceConflict);
        }

        match self.bundles.last() {
            None => {
                if sequence != 0 {
                    return Err(RetentionModelError::SequenceGap);
                }
            }
            Some(previous) => {
                let expected = previous
                    .witness
                    .payload
                    .witness_sequence
                    .checked_add(1)
                    .ok_or(RetentionModelError::SequenceOverflow)?;
                if sequence != expected {
                    return Err(RetentionModelError::SequenceGap);
                }
                candidate.validate_successor(previous)?;
            }
        }

        match persist(&candidate) {
            RetentionPersistenceOutcomeV1::Durable => {
                self.bundles.push(candidate);
                Ok(RetentionDecisionV1::Appended)
            }
            RetentionPersistenceOutcomeV1::Rejected => Err(RetentionModelError::PersistenceRejected),
            RetentionPersistenceOutcomeV1::Unknown => {
                self.health = RetentionHealthV1::DurabilityUncertain;
                Err(RetentionModelError::DurabilityUncertain)
            }
        }
    }
}

/// Fail-closed reference-model errors.
#[derive(Debug, Error)]
pub enum RetentionModelError {
    /// Retained bundle was malformed or its signed witness/checkpoint pairing was invalid.
    #[error("retained witness bundle rejected: {0}")]
    Bundle(#[from] RetainedWitnessBundleError),
    /// Same witness sequence was already durably bound to different immutable bytes.
    #[error("retention witness sequence conflict")]
    SequenceConflict,
    /// Candidate did not use the exact next witness sequence.
    #[error("retention witness sequence gap or regression")]
    SequenceGap,
    /// Witness sequence overflowed.
    #[error("retention witness sequence overflow")]
    SequenceOverflow,
    /// Backend definitively rejected persistence; no acknowledgement is issued.
    #[error("external retention backend rejected durable append")]
    PersistenceRejected,
    /// Persistence outcome is unknown; further mutation is fail-stopped until external readback.
    #[error("external retention durability outcome is uncertain")]
    DurabilityUncertain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, checkpoint_fingerprint};
    use xenia_operation_frontier_ledger_witness::{
        LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
        OperationFrontierLedgerWitnessV1,
    };
    use xenia_operation_store_frontier::OperationStoreFrontierV1;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn chain(signing_key: SigningKey) -> Chain {
        let mut chain = Chain::new(signing_key);
        chain
            .append(ConsentEventRecord {
                source_id: [1u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(2),
                kind: ConsentKind::Approval,
                scope: "retention-model-test".to_string(),
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

    fn bundle(
        signing_key: &SigningKey,
        checkpoint: &xenia_ledger::LedgerCheckpoint,
        frontier: &OperationStoreFrontierV1,
        sequence: u64,
        previous_witness_digest: [u8; 32],
        time_ms: u64,
    ) -> RetainedOperationFrontierWitnessBundleV1 {
        let binding = LedgerCheckpointBindingV1::new(
            checkpoint_fingerprint(checkpoint).unwrap(),
            checkpoint.entry_count,
            checkpoint.head_hash,
            checkpoint.ledger_public_key,
            checkpoint.timestamp_unix_secs,
        )
        .unwrap();
        let witness = OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                frontier.anchor(time_ms).unwrap(),
                binding,
                sequence,
                previous_witness_digest,
                time_ms,
            )
            .unwrap(),
            signing_key,
        )
        .unwrap();
        RetainedOperationFrontierWitnessBundleV1::new(witness, checkpoint.clone(), time_ms).unwrap()
    }

    #[test]
    fn durable_append_precedes_success_ack() {
        let signing_key = key();
        let chain = chain(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let b0 = bundle(&signing_key, &checkpoint, &f0, 0, [0u8; 32], 100_000);
        let mut model = ExternalRetentionModelV1::new();
        let decision = model
            .append_with_persistence(b0, |_| RetentionPersistenceOutcomeV1::Durable)
            .unwrap();
        assert_eq!(decision, RetentionDecisionV1::Appended);
        assert_eq!(model.len(), 1);
    }

    #[test]
    fn exact_replay_is_duplicate_without_second_persist() {
        let signing_key = key();
        let chain = chain(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let b0 = bundle(&signing_key, &checkpoint, &f0, 0, [0u8; 32], 100_000);
        let mut model = ExternalRetentionModelV1::new();
        model
            .append_with_persistence(b0.clone(), |_| RetentionPersistenceOutcomeV1::Durable)
            .unwrap();
        let decision = model
            .append_with_persistence(b0, |_| panic!("duplicate must not repersist"))
            .unwrap();
        assert_eq!(decision, RetentionDecisionV1::DuplicateSame);
    }

    #[test]
    fn same_sequence_different_bundle_is_fork_conflict() {
        let signing_key = key();
        let chain = chain(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let b0 = bundle(&signing_key, &checkpoint, &f0, 0, [0u8; 32], 100_000);
        let mut altered = b0.clone();
        altered.retained_at_unix_ms += 1;
        let mut model = ExternalRetentionModelV1::new();
        model
            .append_with_persistence(b0, |_| RetentionPersistenceOutcomeV1::Durable)
            .unwrap();
        assert!(matches!(
            model.append_with_persistence(altered, |_| RetentionPersistenceOutcomeV1::Durable),
            Err(RetentionModelError::SequenceConflict)
        ));
    }

    #[test]
    fn sequence_gap_is_rejected_before_persistence() {
        let signing_key = key();
        let chain = chain(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let b0 = bundle(&signing_key, &checkpoint, &f0, 1, [9u8; 32], 100_000);
        let mut model = ExternalRetentionModelV1::new();
        assert!(matches!(
            model.append_with_persistence(b0, |_| panic!("gap must not persist")),
            Err(RetentionModelError::SequenceGap)
        ));
    }

    #[test]
    fn definite_rejection_keeps_model_healthy_and_unchanged() {
        let signing_key = key();
        let chain = chain(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let b0 = bundle(&signing_key, &checkpoint, &f0, 0, [0u8; 32], 100_000);
        let mut model = ExternalRetentionModelV1::new();
        assert!(matches!(
            model.append_with_persistence(b0, |_| RetentionPersistenceOutcomeV1::Rejected),
            Err(RetentionModelError::PersistenceRejected)
        ));
        assert_eq!(model.health(), RetentionHealthV1::Healthy);
        assert!(model.is_empty());
    }

    #[test]
    fn unknown_persistence_outcome_fail_stops_until_readback() {
        let signing_key = key();
        let chain = chain(signing_key.clone());
        let checkpoint = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let b0 = bundle(&signing_key, &checkpoint, &f0, 0, [0u8; 32], 100_000);
        let mut model = ExternalRetentionModelV1::new();
        assert!(matches!(
            model.append_with_persistence(b0.clone(), |_| RetentionPersistenceOutcomeV1::Unknown),
            Err(RetentionModelError::DurabilityUncertain)
        ));
        assert_eq!(model.health(), RetentionHealthV1::DurabilityUncertain);
        assert!(matches!(
            model.append_with_persistence(b0.clone(), |_| RetentionPersistenceOutcomeV1::Durable),
            Err(RetentionModelError::DurabilityUncertain)
        ));

        // External readback, not an in-memory clear flag, re-establishes known state.
        let recovered = ExternalRetentionModelV1::from_retained_lineage(vec![b0]).unwrap();
        assert_eq!(recovered.health(), RetentionHealthV1::Healthy);
        assert_eq!(recovered.len(), 1);
    }
}
