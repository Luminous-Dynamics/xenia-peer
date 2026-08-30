// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Executable reference model for Xenia privileged-operation receipt stores.
//!
//! This crate models the security semantics required by ADR-007 without choosing
//! a concrete database. It is intentionally deterministic and in-memory: the
//! purpose is to give future SQLite/other backends an oracle for admission
//! uniqueness, receipt compare-and-append, fail-stop durability health, startup
//! recovery classification, and operation-store frontier generation.
//!
//! It performs no process execution, network I/O, credential access, external
//! anchoring, or persistence.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use xenia_operation_receipt_finalization::{
    ReceiptAdmissionBindingV1, ReceiptEventV1, ReceiptFinalizationError, ReceiptStateV1,
};
use xenia_operation_store_frontier::{
    AdmissionFrontierEntryV1, OperationStoreFrontierError, OperationStoreFrontierV1,
    ReceiptHeadFrontierEntryV1,
};

/// Store health gate controlling whether privileged-operation state may advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreHealthV1 {
    /// Durability and recovery invariants are currently trusted.
    Healthy,
    /// A write acknowledgement or durability guarantee became uncertain.
    DurabilityUncertain,
    /// Startup or integrity verification found state that requires explicit recovery.
    RecoveryRequired,
}

/// Immutable model admission row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreAdmissionV1 {
    /// Minimal receipt validation binding.
    pub binding: ReceiptAdmissionBindingV1,
    /// Exact session-bound grant digest being consumed.
    pub grant_digest: [u8; 32],
    /// Exact use slot within that grant.
    pub use_index: u32,
    /// Exact monotonic durable admission sequence.
    pub admission_sequence: u64,
}

impl StoreAdmissionV1 {
    /// Validate admission-local invariants.
    pub fn validate(self) -> Result<(), StoreModelError> {
        self.binding.validate()?;
        if self.grant_digest == [0u8; 32] {
            return Err(StoreModelError::ZeroGrantDigest);
        }
        Ok(())
    }

    fn reservation_key(self) -> ([u8; 32], u32) {
        (self.grant_digest, self.use_index)
    }
}

/// Result of an atomic admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecisionV1 {
    /// New operation and grant-use slot were atomically reserved.
    Admitted,
    /// Exact same immutable admission already exists; safe lost-ack duplicate.
    DuplicateSame,
}

/// Result of an append-only receipt compare-and-append attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptAppendDecisionV1 {
    /// Receipt event became the new operation head.
    Appended,
    /// Exact same receipt event is already the head; safe lost-ack duplicate.
    DuplicateSame,
}

/// Expected predecessor supplied with one receipt append request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptHeadExpectationV1 {
    /// Expected predecessor event index, or `None` before the first event.
    pub event_index: Option<u32>,
    /// Expected predecessor digest, all zero when `event_index` is `None`.
    pub event_digest: [u8; 32],
}

impl ReceiptHeadExpectationV1 {
    /// Canonical expectation for the first post-admission receipt event.
    pub const fn empty() -> Self {
        Self {
            event_index: None,
            event_digest: [0u8; 32],
        }
    }
}

/// Conservative startup recovery classification for one admitted operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDispositionV1 {
    /// Admission exists but no effect was armed; recovery should terminate it without effect.
    CancelBeforeEffect,
    /// Effect was armed and adapter-specific recovery must prove the result or emit unknown.
    RecoverArmedOutcome,
}

/// Deterministic in-memory reference model for the durable receipt store.
#[derive(Debug, Clone)]
pub struct OperationStoreModelV1 {
    store_id: [u8; 16],
    generation: u64,
    store_schema_digest: [u8; 32],
    health: StoreHealthV1,
    next_admission_sequence: u64,
    admissions: BTreeMap<[u8; 16], StoreAdmissionV1>,
    reservations: BTreeMap<([u8; 32], u32), [u8; 16]>,
    receipt_heads: BTreeMap<[u8; 16], ReceiptEventV1>,
    frontiers: Vec<OperationStoreFrontierV1>,
}

impl OperationStoreModelV1 {
    /// Create an empty healthy store authority domain.
    pub fn new(
        store_id: [u8; 16],
        generation: u64,
        store_schema_digest: [u8; 32],
    ) -> Result<Self, StoreModelError> {
        if store_id == [0u8; 16] {
            return Err(StoreModelError::ZeroStoreId);
        }
        if store_schema_digest == [0u8; 32] {
            return Err(StoreModelError::ZeroStoreSchemaDigest);
        }
        Ok(Self {
            store_id,
            generation,
            store_schema_digest,
            health: StoreHealthV1::Healthy,
            next_admission_sequence: 0,
            admissions: BTreeMap::new(),
            reservations: BTreeMap::new(),
            receipt_heads: BTreeMap::new(),
            frontiers: Vec::new(),
        })
    }

    /// Current fail-stop store health.
    pub fn health(&self) -> StoreHealthV1 {
        self.health
    }

    /// Number of durable admissions represented by the model.
    pub fn admission_count(&self) -> usize {
        self.admissions.len()
    }

    /// Current immutable admission for `operation_id`, if present.
    pub fn admission(&self, operation_id: [u8; 16]) -> Option<StoreAdmissionV1> {
        self.admissions.get(&operation_id).copied()
    }

    /// Current receipt head for `operation_id`, if present.
    pub fn receipt_head(&self, operation_id: [u8; 16]) -> Option<&ReceiptEventV1> {
        self.receipt_heads.get(&operation_id)
    }

    /// Atomically reserve one operation id, one grant-use slot, and one admission sequence.
    ///
    /// No model state changes unless every uniqueness and sequence check succeeds.
    pub fn admit(
        &mut self,
        admission: StoreAdmissionV1,
    ) -> Result<AdmissionDecisionV1, StoreModelError> {
        self.require_healthy()?;
        admission.validate()?;

        if let Some(existing) = self.admissions.get(&admission.binding.operation_id) {
            if *existing == admission {
                return Ok(AdmissionDecisionV1::DuplicateSame);
            }
            return Err(StoreModelError::OperationIdConflict);
        }

        if let Some(existing_operation) = self.reservations.get(&admission.reservation_key()) {
            if *existing_operation != admission.binding.operation_id {
                return Err(StoreModelError::GrantUseSlotConflict);
            }
        }

        if admission.admission_sequence != self.next_admission_sequence {
            return Err(StoreModelError::AdmissionSequenceMismatch {
                expected: self.next_admission_sequence,
                found: admission.admission_sequence,
            });
        }

        let next = self
            .next_admission_sequence
            .checked_add(1)
            .ok_or(StoreModelError::AdmissionSequenceOverflow)?;

        // Mutation begins only after all checks above have succeeded.
        self.admissions
            .insert(admission.binding.operation_id, admission);
        self.reservations
            .insert(admission.reservation_key(), admission.binding.operation_id);
        self.next_admission_sequence = next;
        Ok(AdmissionDecisionV1::Admitted)
    }

    /// Compare-and-append one receipt event against the exact durable head.
    ///
    /// A caller that lost the acknowledgement may resend the exact same event;
    /// if it is already the head the result is `DuplicateSame` rather than a
    /// second transition.
    pub fn append_receipt(
        &mut self,
        expectation: ReceiptHeadExpectationV1,
        event: ReceiptEventV1,
    ) -> Result<ReceiptAppendDecisionV1, StoreModelError> {
        self.require_healthy()?;
        let admission = self
            .admissions
            .get(&event.operation_id)
            .copied()
            .ok_or(StoreModelError::UnknownOperation)?;

        if let Some(current) = self.receipt_heads.get(&event.operation_id) {
            if current.event_digest()? == event.event_digest()? {
                return Ok(ReceiptAppendDecisionV1::DuplicateSame);
            }
            let current_digest = current.event_digest()?;
            if expectation.event_index != Some(current.event_index)
                || expectation.event_digest != current_digest
            {
                return Err(StoreModelError::ReceiptHeadConflict);
            }
            event.validate_successor(admission.binding, current)?;
        } else {
            if expectation != ReceiptHeadExpectationV1::empty() {
                return Err(StoreModelError::ReceiptHeadConflict);
            }
            event.validate_first(admission.binding)?;
        }

        self.receipt_heads.insert(event.operation_id, event);
        Ok(ReceiptAppendDecisionV1::Appended)
    }

    /// Mark durability as uncertain and immediately fail-stop future writes.
    pub fn mark_durability_uncertain(&mut self) {
        self.health = StoreHealthV1::DurabilityUncertain;
    }

    /// Mark startup/integrity verification as requiring explicit recovery.
    pub fn mark_recovery_required(&mut self) {
        self.health = StoreHealthV1::RecoveryRequired;
    }

    /// Restore healthy state only after an external caller has completed the
    /// deployment's required integrity/anti-rollback recovery procedure.
    pub fn restore_verified_health(&mut self) {
        self.health = StoreHealthV1::Healthy;
    }

    /// Classify all nonterminal operations conservatively for startup recovery.
    pub fn recovery_scan(&self) -> Vec<([u8; 16], RecoveryDispositionV1)> {
        let mut work = Vec::new();
        for operation_id in self.admissions.keys().copied() {
            match self.receipt_heads.get(&operation_id) {
                None => work.push((operation_id, RecoveryDispositionV1::CancelBeforeEffect)),
                Some(head) if head.state == ReceiptStateV1::EffectArmed => {
                    work.push((operation_id, RecoveryDispositionV1::RecoverArmedOutcome));
                }
                Some(_) => {}
            }
        }
        work
    }

    /// Produce and retain the next deterministic full-store anti-rollback frontier.
    pub fn checkpoint(
        &mut self,
        recorded_at_unix_ms: u64,
    ) -> Result<OperationStoreFrontierV1, StoreModelError> {
        self.require_healthy()?;

        let mut admissions: Vec<_> = self
            .admissions
            .values()
            .map(|row| AdmissionFrontierEntryV1 {
                admission_sequence: row.admission_sequence,
                operation_id: row.binding.operation_id,
                admission_digest: row.binding.admission_digest,
            })
            .collect();
        admissions.sort_by_key(|entry| entry.admission_sequence);

        let mut receipt_heads = Vec::with_capacity(admissions.len());
        for admission in &admissions {
            let head = self.receipt_heads.get(&admission.operation_id);
            receipt_heads.push(ReceiptHeadFrontierEntryV1 {
                operation_id: admission.operation_id,
                event_index: head.map(|event| event.event_index),
                event_digest: match head {
                    Some(event) => event.event_digest()?,
                    None => [0u8; 32],
                },
            });
        }
        receipt_heads.sort_by_key(|entry| entry.operation_id);

        let checkpoint_sequence = u64::try_from(self.frontiers.len())
            .map_err(|_| StoreModelError::CheckpointSequenceOverflow)?;
        let previous_frontier_digest = match self.frontiers.last() {
            Some(frontier) => frontier.frontier_digest()?,
            None => [0u8; 32],
        };
        let frontier = OperationStoreFrontierV1::from_state(
            self.store_id,
            self.generation,
            checkpoint_sequence,
            self.store_schema_digest,
            previous_frontier_digest,
            recorded_at_unix_ms,
            &admissions,
            &receipt_heads,
        )?;
        if let Some(previous) = self.frontiers.last() {
            frontier.validate_successor(previous)?;
        }
        self.frontiers.push(frontier.clone());
        Ok(frontier)
    }

    /// Retained frontier history. V1 intentionally does not support destructive pruning.
    pub fn frontiers(&self) -> &[OperationStoreFrontierV1] {
        &self.frontiers
    }

    /// Verify internal operation/reservation one-to-one consistency.
    pub fn verify_internal_indexes(&self) -> Result<(), StoreModelError> {
        if self.admissions.len() != self.reservations.len() {
            return Err(StoreModelError::InternalIndexMismatch);
        }
        let mut seen_sequences = BTreeSet::new();
        for admission in self.admissions.values() {
            if self.reservations.get(&admission.reservation_key())
                != Some(&admission.binding.operation_id)
            {
                return Err(StoreModelError::InternalIndexMismatch);
            }
            if !seen_sequences.insert(admission.admission_sequence) {
                return Err(StoreModelError::InternalIndexMismatch);
            }
        }
        Ok(())
    }

    fn require_healthy(&self) -> Result<(), StoreModelError> {
        if self.health != StoreHealthV1::Healthy {
            return Err(StoreModelError::StoreNotHealthy(self.health));
        }
        Ok(())
    }
}

/// Reference-model failure.
#[derive(Debug, Error)]
pub enum StoreModelError {
    /// Store id may not use the zero sentinel.
    #[error("store id must not be zero")]
    ZeroStoreId,
    /// Store schema commitment may not use the zero sentinel.
    #[error("store schema digest must not be zero")]
    ZeroStoreSchemaDigest,
    /// Grant commitment may not use the zero sentinel.
    #[error("grant digest must not be zero")]
    ZeroGrantDigest,
    /// Same operation id was presented with different immutable admission bytes.
    #[error("operation id already belongs to a different admission")]
    OperationIdConflict,
    /// Same grant-use slot is already reserved by another operation.
    #[error("grant-use slot already reserved by another operation")]
    GrantUseSlotConflict,
    /// Admission sequence was not the exact next durable sequence.
    #[error("admission sequence mismatch: expected {expected}, found {found}")]
    AdmissionSequenceMismatch {
        /// Exact expected next sequence.
        expected: u64,
        /// Sequence supplied by the caller.
        found: u64,
    },
    /// Admission sequence overflowed.
    #[error("admission sequence overflow")]
    AdmissionSequenceOverflow,
    /// Receipt append referenced no immutable admission.
    #[error("receipt append references unknown operation")]
    UnknownOperation,
    /// Receipt compare-and-append expectation did not match the durable head.
    #[error("receipt head compare-and-append conflict")]
    ReceiptHeadConflict,
    /// Store is fail-stopped until explicit recovery succeeds.
    #[error("operation store is not healthy: {0:?}")]
    StoreNotHealthy(StoreHealthV1),
    /// Internal operation/reservation indexes disagree.
    #[error("operation store internal indexes disagree")]
    InternalIndexMismatch,
    /// Frontier checkpoint sequence overflowed.
    #[error("frontier checkpoint sequence overflow")]
    CheckpointSequenceOverflow,
    /// Receipt semantic validation failed.
    #[error("receipt validation failed: {0}")]
    Receipt(#[from] ReceiptFinalizationError),
    /// Frontier construction or lineage validation failed.
    #[error("frontier validation failed: {0}")]
    Frontier(#[from] OperationStoreFrontierError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operation_receipt_finalization::RECEIPT_FINALIZATION_SCHEMA_V1;

    fn store() -> OperationStoreModelV1 {
        OperationStoreModelV1::new([1u8; 16], 0, [2u8; 32]).unwrap()
    }

    fn admission(operation: u8, grant: u8, use_index: u32, sequence: u64) -> StoreAdmissionV1 {
        StoreAdmissionV1 {
            binding: ReceiptAdmissionBindingV1 {
                admission_digest: [operation; 32],
                operation_id: [operation; 16],
                admitted_at_unix_ms: 100 + sequence,
            },
            grant_digest: [grant; 32],
            use_index,
            admission_sequence: sequence,
        }
    }

    fn armed(operation: u8, admitted_at: u64) -> ReceiptEventV1 {
        ReceiptEventV1 {
            schema: RECEIPT_FINALIZATION_SCHEMA_V1.to_string(),
            admission_digest: [operation; 32],
            operation_id: [operation; 16],
            event_index: 0,
            previous_event_digest: [0u8; 32],
            state: ReceiptStateV1::EffectArmed,
            recorded_at_unix_ms: admitted_at + 1,
            arm_authorization_digest: Some([9u8; 32]),
            evidence_digest: None,
        }
    }

    fn terminal(
        previous: &ReceiptEventV1,
        state: ReceiptStateV1,
        evidence: u8,
    ) -> ReceiptEventV1 {
        ReceiptEventV1 {
            schema: RECEIPT_FINALIZATION_SCHEMA_V1.to_string(),
            admission_digest: previous.admission_digest,
            operation_id: previous.operation_id,
            event_index: previous.event_index + 1,
            previous_event_digest: previous.event_digest().unwrap(),
            state,
            recorded_at_unix_ms: previous.recorded_at_unix_ms + 1,
            arm_authorization_digest: None,
            evidence_digest: Some([evidence; 32]),
        }
    }

    #[test]
    fn exact_duplicate_admission_is_idempotent() {
        let mut store = store();
        let row = admission(3, 4, 0, 0);
        assert_eq!(store.admit(row).unwrap(), AdmissionDecisionV1::Admitted);
        assert_eq!(
            store.admit(row).unwrap(),
            AdmissionDecisionV1::DuplicateSame
        );
        assert_eq!(store.admission_count(), 1);
    }

    #[test]
    fn operation_id_cannot_change_immutable_admission() {
        let mut store = store();
        store.admit(admission(3, 4, 0, 0)).unwrap();
        let mut conflicting = admission(3, 4, 0, 0);
        conflicting.binding.admission_digest = [8u8; 32];
        assert!(matches!(
            store.admit(conflicting),
            Err(StoreModelError::OperationIdConflict)
        ));
        assert_eq!(store.admission_count(), 1);
    }

    #[test]
    fn grant_use_slot_is_unique_across_operations() {
        let mut store = store();
        store.admit(admission(3, 4, 0, 0)).unwrap();
        assert!(matches!(
            store.admit(admission(5, 4, 0, 1)),
            Err(StoreModelError::GrantUseSlotConflict)
        ));
    }

    #[test]
    fn admission_sequence_has_no_gaps() {
        let mut store = store();
        assert!(matches!(
            store.admit(admission(3, 4, 0, 1)),
            Err(StoreModelError::AdmissionSequenceMismatch {
                expected: 0,
                found: 1
            })
        ));
    }

    #[test]
    fn receipt_compare_and_append_rejects_stale_head() {
        let mut store = store();
        let row = admission(3, 4, 0, 0);
        store.admit(row).unwrap();
        let armed = armed(3, row.binding.admitted_at_unix_ms);
        store
            .append_receipt(ReceiptHeadExpectationV1::empty(), armed.clone())
            .unwrap();
        let complete = terminal(&armed, ReceiptStateV1::Completed, 7);
        assert!(matches!(
            store.append_receipt(ReceiptHeadExpectationV1::empty(), complete),
            Err(StoreModelError::ReceiptHeadConflict)
        ));
    }

    #[test]
    fn exact_receipt_retry_is_idempotent_after_lost_ack() {
        let mut store = store();
        let row = admission(3, 4, 0, 0);
        store.admit(row).unwrap();
        let armed = armed(3, row.binding.admitted_at_unix_ms);
        assert_eq!(
            store
                .append_receipt(ReceiptHeadExpectationV1::empty(), armed.clone())
                .unwrap(),
            ReceiptAppendDecisionV1::Appended
        );
        assert_eq!(
            store
                .append_receipt(ReceiptHeadExpectationV1::empty(), armed)
                .unwrap(),
            ReceiptAppendDecisionV1::DuplicateSame
        );
    }

    #[test]
    fn terminal_receipt_cannot_be_extended() {
        let mut store = store();
        let row = admission(3, 4, 0, 0);
        store.admit(row).unwrap();
        let armed = armed(3, row.binding.admitted_at_unix_ms);
        store
            .append_receipt(ReceiptHeadExpectationV1::empty(), armed.clone())
            .unwrap();
        let complete = terminal(&armed, ReceiptStateV1::Completed, 7);
        let armed_digest = armed.event_digest().unwrap();
        store
            .append_receipt(
                ReceiptHeadExpectationV1 {
                    event_index: Some(0),
                    event_digest: armed_digest,
                },
                complete.clone(),
            )
            .unwrap();
        let attempted = terminal(&complete, ReceiptStateV1::FailedKnown, 8);
        let complete_digest = complete.event_digest().unwrap();
        assert!(matches!(
            store.append_receipt(
                ReceiptHeadExpectationV1 {
                    event_index: Some(1),
                    event_digest: complete_digest,
                },
                attempted
            ),
            Err(StoreModelError::Receipt(
                ReceiptFinalizationError::TerminalExtended
            ))
        ));
    }

    #[test]
    fn startup_recovery_is_conservative() {
        let mut store = store();
        let a = admission(3, 4, 0, 0);
        let b = admission(5, 4, 1, 1);
        store.admit(a).unwrap();
        store.admit(b).unwrap();
        let armed_b = armed(5, b.binding.admitted_at_unix_ms);
        store
            .append_receipt(ReceiptHeadExpectationV1::empty(), armed_b)
            .unwrap();
        assert_eq!(
            store.recovery_scan(),
            vec![
                ([3u8; 16], RecoveryDispositionV1::CancelBeforeEffect),
                ([5u8; 16], RecoveryDispositionV1::RecoverArmedOutcome),
            ]
        );
    }

    #[test]
    fn durability_uncertainty_fail_stops_mutation() {
        let mut store = store();
        store.mark_durability_uncertain();
        assert!(matches!(
            store.admit(admission(3, 4, 0, 0)),
            Err(StoreModelError::StoreNotHealthy(
                StoreHealthV1::DurabilityUncertain
            ))
        ));
    }

    #[test]
    fn frontier_advances_over_admission_and_receipt_state() {
        let mut store = store();
        let genesis = store.checkpoint(1).unwrap();
        let row = admission(3, 4, 0, 0);
        store.admit(row).unwrap();
        let after_admission = store.checkpoint(2).unwrap();
        assert_ne!(
            genesis.frontier_digest().unwrap(),
            after_admission.frontier_digest().unwrap()
        );
        let armed = armed(3, row.binding.admitted_at_unix_ms);
        store
            .append_receipt(ReceiptHeadExpectationV1::empty(), armed)
            .unwrap();
        let after_arm = store.checkpoint(3).unwrap();
        assert_ne!(
            after_admission.frontier_digest().unwrap(),
            after_arm.frontier_digest().unwrap()
        );
        after_admission.validate_successor(&genesis).unwrap();
        after_arm.validate_successor(&after_admission).unwrap();
    }

    #[test]
    fn internal_indexes_remain_one_to_one() {
        let mut store = store();
        store.admit(admission(3, 4, 0, 0)).unwrap();
        store.admit(admission(5, 4, 1, 1)).unwrap();
        store.verify_internal_indexes().unwrap();
    }
}
