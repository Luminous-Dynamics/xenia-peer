// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime-free anti-rollback frontier contracts for Xenia privileged-operation stores.
//!
//! ADR-007 identifies an important claim boundary: a transactional receipt database can
//! still reopen spent authority if an older backup, VM snapshot, or disk image is restored.
//! This crate defines deterministic full-store frontier commitments and external anchor
//! records so a newer trusted checkpoint can detect that rollback.
//!
//! V1 deliberately prefers simple, auditable full-state commitments over an incremental
//! Merkle accumulator. A future scalable accumulator may replace the internal set-digest
//! calculation only under a new schema/version; it must preserve the same anti-rollback
//! and lineage invariants.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact schema label for [`OperationStoreFrontierV1`].
pub const OPERATION_STORE_FRONTIER_SCHEMA_V1: &str = "xenia-operation-store-frontier-v1";
/// Exact schema label for [`OperationStoreFrontierAnchorV1`].
pub const OPERATION_STORE_FRONTIER_ANCHOR_SCHEMA_V1: &str =
    "xenia-operation-store-frontier-anchor-v1";
/// Domain separator for canonical admission-set commitments.
pub const OPERATION_ADMISSION_SET_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-admission-set-digest-v1";
/// Domain separator for canonical receipt-head-set commitments.
pub const OPERATION_RECEIPT_HEAD_SET_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-receipt-head-set-digest-v1";
/// Domain separator for complete store-frontier commitments.
pub const OPERATION_STORE_FRONTIER_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-store-frontier-digest-v1";

/// Canonical admission summary included in the V1 full-store frontier calculation.
///
/// The exact `admission_digest` is expected to commit the complete immutable operation
/// admission. The frontier therefore does not duplicate every admission field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AdmissionFrontierEntryV1 {
    /// Monotonic durable admission sequence allocated by the receipt store.
    pub admission_sequence: u64,
    /// Stable operation identifier.
    pub operation_id: [u8; 16],
    /// Exact immutable admission commitment.
    pub admission_digest: [u8; 32],
}

impl AdmissionFrontierEntryV1 {
    /// Validate unset-sentinel rejection for one canonical entry.
    pub fn validate(&self) -> Result<(), OperationStoreFrontierError> {
        if self.operation_id == [0u8; 16] {
            return Err(OperationStoreFrontierError::ZeroOperationId);
        }
        if self.admission_digest == [0u8; 32] {
            return Err(OperationStoreFrontierError::ZeroAdmissionDigest);
        }
        Ok(())
    }
}

/// Canonical current receipt-head summary for one admitted operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReceiptHeadFrontierEntryV1 {
    /// Stable operation identifier.
    pub operation_id: [u8; 16],
    /// Current post-admission receipt event index, or `None` when no event exists yet.
    pub event_index: Option<u32>,
    /// Exact current event digest, or all zeros when `event_index` is `None`.
    pub event_digest: [u8; 32],
}

impl ReceiptHeadFrontierEntryV1 {
    /// Validate the canonical empty/non-empty receipt-head representation.
    pub fn validate(&self) -> Result<(), OperationStoreFrontierError> {
        if self.operation_id == [0u8; 16] {
            return Err(OperationStoreFrontierError::ZeroOperationId);
        }
        match self.event_index {
            None if self.event_digest == [0u8; 32] => Ok(()),
            Some(_) if self.event_digest != [0u8; 32] => Ok(()),
            None => Err(OperationStoreFrontierError::UnexpectedReceiptHeadDigest),
            Some(_) => Err(OperationStoreFrontierError::MissingReceiptHeadDigest),
        }
    }
}

/// Deterministic checkpoint of the complete durable operation-store security state.
///
/// A frontier is useful for anti-rollback only when at least one newer reference to its
/// digest survives outside the rollback scope. See [`OperationStoreFrontierAnchorV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationStoreFrontierV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Stable random identity of one receipt-store authority domain.
    pub store_id: [u8; 16],
    /// Store generation. V1 successor validation does not permit implicit generation changes.
    pub generation: u64,
    /// Monotonic checkpoint sequence within this store generation.
    pub checkpoint_sequence: u64,
    /// Commitment to the exact durable store schema/representation profile.
    pub store_schema_digest: [u8; 32],
    /// Number of durable immutable admissions represented by this frontier.
    pub admission_count: u64,
    /// Highest committed admission sequence, or `None` for an empty store.
    pub highest_admission_sequence: Option<u64>,
    /// Commitment to all canonical immutable admission summaries.
    pub admission_set_digest: [u8; 32],
    /// Commitment to exactly one current receipt head for every admission.
    pub receipt_head_set_digest: [u8; 32],
    /// Digest of the immediately previous frontier, or all zeros for checkpoint zero.
    pub previous_frontier_digest: [u8; 32],
    /// Trusted-enough wall-clock evidence metadata; not the ordering authority.
    pub recorded_at_unix_ms: u64,
}

impl OperationStoreFrontierV1 {
    /// Construct a frontier from complete canonically ordered durable state.
    ///
    /// `admissions` must be strictly increasing by `admission_sequence` and contain unique
    /// operation ids. `receipt_heads` must be strictly increasing by `operation_id` and
    /// contain exactly the same operation-id set as `admissions`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_state(
        store_id: [u8; 16],
        generation: u64,
        checkpoint_sequence: u64,
        store_schema_digest: [u8; 32],
        previous_frontier_digest: [u8; 32],
        recorded_at_unix_ms: u64,
        admissions: &[AdmissionFrontierEntryV1],
        receipt_heads: &[ReceiptHeadFrontierEntryV1],
    ) -> Result<Self, OperationStoreFrontierError> {
        validate_admission_entries(admissions)?;
        validate_receipt_heads(receipt_heads)?;
        validate_matching_operation_sets(admissions, receipt_heads)?;

        let admission_count = u64::try_from(admissions.len())
            .map_err(|_| OperationStoreFrontierError::EntryCountOverflow)?;
        let highest_admission_sequence = admissions.last().map(|entry| entry.admission_sequence);

        let value = Self {
            schema: OPERATION_STORE_FRONTIER_SCHEMA_V1.to_string(),
            store_id,
            generation,
            checkpoint_sequence,
            store_schema_digest,
            admission_count,
            highest_admission_sequence,
            admission_set_digest: admission_set_digest(admissions)?,
            receipt_head_set_digest: receipt_head_set_digest(receipt_heads)?,
            previous_frontier_digest,
            recorded_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate frontier-local invariants independent of the underlying rows.
    pub fn validate(&self) -> Result<(), OperationStoreFrontierError> {
        if self.schema != OPERATION_STORE_FRONTIER_SCHEMA_V1 {
            return Err(OperationStoreFrontierError::UnsupportedFrontierSchema);
        }
        if self.store_id == [0u8; 16] {
            return Err(OperationStoreFrontierError::ZeroStoreId);
        }
        if self.store_schema_digest == [0u8; 32] {
            return Err(OperationStoreFrontierError::ZeroStoreSchemaDigest);
        }
        if self.admission_set_digest == [0u8; 32] {
            return Err(OperationStoreFrontierError::ZeroAdmissionSetDigest);
        }
        if self.receipt_head_set_digest == [0u8; 32] {
            return Err(OperationStoreFrontierError::ZeroReceiptHeadSetDigest);
        }
        if self.admission_count == 0 && self.highest_admission_sequence.is_some() {
            return Err(OperationStoreFrontierError::EmptyStoreHasHighestSequence);
        }
        if self.admission_count > 0 && self.highest_admission_sequence.is_none() {
            return Err(OperationStoreFrontierError::NonEmptyStoreMissingHighestSequence);
        }
        if self.checkpoint_sequence == 0 {
            if self.previous_frontier_digest != [0u8; 32] {
                return Err(OperationStoreFrontierError::GenesisHasPreviousFrontier);
            }
        } else if self.previous_frontier_digest == [0u8; 32] {
            return Err(OperationStoreFrontierError::MissingPreviousFrontierDigest);
        }
        Ok(())
    }

    /// Recompute component commitments from complete durable state and compare them to this frontier.
    pub fn verify_state(
        &self,
        admissions: &[AdmissionFrontierEntryV1],
        receipt_heads: &[ReceiptHeadFrontierEntryV1],
    ) -> Result<(), OperationStoreFrontierError> {
        self.validate()?;
        validate_admission_entries(admissions)?;
        validate_receipt_heads(receipt_heads)?;
        validate_matching_operation_sets(admissions, receipt_heads)?;

        let admission_count = u64::try_from(admissions.len())
            .map_err(|_| OperationStoreFrontierError::EntryCountOverflow)?;
        if self.admission_count != admission_count {
            return Err(OperationStoreFrontierError::AdmissionCountMismatch);
        }
        if self.highest_admission_sequence
            != admissions.last().map(|entry| entry.admission_sequence)
        {
            return Err(OperationStoreFrontierError::HighestAdmissionSequenceMismatch);
        }
        if self.admission_set_digest != admission_set_digest(admissions)? {
            return Err(OperationStoreFrontierError::AdmissionSetDigestMismatch);
        }
        if self.receipt_head_set_digest != receipt_head_set_digest(receipt_heads)? {
            return Err(OperationStoreFrontierError::ReceiptHeadSetDigestMismatch);
        }
        Ok(())
    }

    /// Deterministic canonical bincode-v1 bytes for checkpoint/evidence binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperationStoreFrontierError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3-256 commitment to this complete frontier.
    pub fn frontier_digest(&self) -> Result<[u8; 32], OperationStoreFrontierError> {
        Ok(domain_digest(
            OPERATION_STORE_FRONTIER_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    /// Validate this frontier as the exact next checkpoint after `previous`.
    pub fn validate_successor(
        &self,
        previous: &Self,
    ) -> Result<(), OperationStoreFrontierError> {
        previous.validate()?;
        self.validate()?;

        if self.store_id != previous.store_id {
            return Err(OperationStoreFrontierError::StoreIdMismatch);
        }
        if self.generation != previous.generation {
            return Err(OperationStoreFrontierError::GenerationMismatch);
        }
        if self.store_schema_digest != previous.store_schema_digest {
            return Err(OperationStoreFrontierError::StoreSchemaChangedWithinGeneration);
        }

        let expected_sequence = previous
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(OperationStoreFrontierError::CheckpointSequenceOverflow)?;
        if self.checkpoint_sequence != expected_sequence {
            return Err(OperationStoreFrontierError::CheckpointSequenceMismatch);
        }
        if self.previous_frontier_digest != previous.frontier_digest()? {
            return Err(OperationStoreFrontierError::PreviousFrontierDigestMismatch);
        }
        if self.admission_count < previous.admission_count {
            return Err(OperationStoreFrontierError::AdmissionCountRegression);
        }
        match (
            previous.highest_admission_sequence,
            self.highest_admission_sequence,
        ) {
            (Some(_), None) => {
                return Err(OperationStoreFrontierError::HighestAdmissionSequenceRegression);
            }
            (Some(old), Some(new)) if new < old => {
                return Err(OperationStoreFrontierError::HighestAdmissionSequenceRegression);
            }
            _ => {}
        }
        if self.recorded_at_unix_ms < previous.recorded_at_unix_ms {
            return Err(OperationStoreFrontierError::TimestampRegression);
        }
        Ok(())
    }

    /// Construct an externally storable anchor record for this exact frontier.
    pub fn anchor(
        &self,
        anchored_at_unix_ms: u64,
    ) -> Result<OperationStoreFrontierAnchorV1, OperationStoreFrontierError> {
        self.validate()?;
        if anchored_at_unix_ms < self.recorded_at_unix_ms {
            return Err(OperationStoreFrontierError::AnchorTimestampBeforeFrontier);
        }
        Ok(OperationStoreFrontierAnchorV1 {
            schema: OPERATION_STORE_FRONTIER_ANCHOR_SCHEMA_V1.to_string(),
            store_id: self.store_id,
            generation: self.generation,
            checkpoint_sequence: self.checkpoint_sequence,
            frontier_digest: self.frontier_digest()?,
            anchored_at_unix_ms,
        })
    }
}

/// Compact reference to one trusted frontier retained outside the receipt-store rollback scope.
///
/// This type deliberately contains no signature or transport. A Xenia ledger event, TPM-backed
/// record, immutable object store, or remote witness may authenticate these exact bytes under
/// its own trust model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationStoreFrontierAnchorV1 {
    /// Exact V1 anchor schema label.
    pub schema: String,
    /// Receipt-store identity the anchor applies to.
    pub store_id: [u8; 16],
    /// Receipt-store generation the anchor applies to.
    pub generation: u64,
    /// Exact anchored checkpoint sequence.
    pub checkpoint_sequence: u64,
    /// Exact anchored frontier commitment.
    pub frontier_digest: [u8; 32],
    /// Evidence metadata for when the external anchor was written.
    pub anchored_at_unix_ms: u64,
}

impl OperationStoreFrontierAnchorV1 {
    /// Validate anchor-local syntax.
    pub fn validate(&self) -> Result<(), OperationStoreFrontierError> {
        if self.schema != OPERATION_STORE_FRONTIER_ANCHOR_SCHEMA_V1 {
            return Err(OperationStoreFrontierError::UnsupportedAnchorSchema);
        }
        if self.store_id == [0u8; 16] {
            return Err(OperationStoreFrontierError::ZeroStoreId);
        }
        if self.frontier_digest == [0u8; 32] {
            return Err(OperationStoreFrontierError::ZeroFrontierDigest);
        }
        Ok(())
    }

    /// Deterministic canonical bytes suitable for an external evidence domain.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperationStoreFrontierError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }
}

/// Validate a retained frontier chain in checkpoint order.
///
/// V1 permits a slice starting at any checkpoint, but every adjacent pair must be an exact
/// successor. Deployments claiming anti-rollback against an anchor must retain the anchored
/// frontier itself so [`verify_anchor_lineage`] can prove ancestry.
pub fn validate_frontier_chain(
    frontiers: &[OperationStoreFrontierV1],
) -> Result<(), OperationStoreFrontierError> {
    let Some(first) = frontiers.first() else {
        return Ok(());
    };
    first.validate()?;
    for pair in frontiers.windows(2) {
        pair[1].validate_successor(&pair[0])?;
    }
    Ok(())
}

/// Prove that the local retained frontier chain contains the exact externally anchored
/// checkpoint and has not rolled back or forked behind it.
///
/// A local chain newer than the anchor is accepted only when the exact anchored frontier is
/// still retained and the subsequent chain validates. This intentionally forbids destructive
/// V1 pruning that would make ancestry unverifiable.
pub fn verify_anchor_lineage(
    anchor: &OperationStoreFrontierAnchorV1,
    local_frontiers: &[OperationStoreFrontierV1],
) -> Result<(), OperationStoreFrontierError> {
    anchor.validate()?;
    validate_frontier_chain(local_frontiers)?;

    let Some(current) = local_frontiers.last() else {
        return Err(OperationStoreFrontierError::RollbackDetected);
    };
    if current.store_id != anchor.store_id {
        return Err(OperationStoreFrontierError::StoreIdMismatch);
    }
    if current.generation != anchor.generation {
        return Err(OperationStoreFrontierError::GenerationMismatch);
    }
    if current.checkpoint_sequence < anchor.checkpoint_sequence {
        return Err(OperationStoreFrontierError::RollbackDetected);
    }

    let anchored = local_frontiers
        .iter()
        .find(|frontier| frontier.checkpoint_sequence == anchor.checkpoint_sequence)
        .ok_or(OperationStoreFrontierError::AnchoredFrontierMissing)?;

    if anchored.store_id != anchor.store_id {
        return Err(OperationStoreFrontierError::StoreIdMismatch);
    }
    if anchored.generation != anchor.generation {
        return Err(OperationStoreFrontierError::GenerationMismatch);
    }
    if anchored.frontier_digest()? != anchor.frontier_digest {
        return Err(OperationStoreFrontierError::AnchorDigestMismatch);
    }
    Ok(())
}

/// Compute the deterministic V1 admission-set commitment.
pub fn admission_set_digest(
    admissions: &[AdmissionFrontierEntryV1],
) -> Result<[u8; 32], OperationStoreFrontierError> {
    validate_admission_entries(admissions)?;
    Ok(domain_digest(
        OPERATION_ADMISSION_SET_DIGEST_DOMAIN_V1,
        &bincode::serialize(admissions)?,
    ))
}

/// Compute the deterministic V1 receipt-head-set commitment.
pub fn receipt_head_set_digest(
    receipt_heads: &[ReceiptHeadFrontierEntryV1],
) -> Result<[u8; 32], OperationStoreFrontierError> {
    validate_receipt_heads(receipt_heads)?;
    Ok(domain_digest(
        OPERATION_RECEIPT_HEAD_SET_DIGEST_DOMAIN_V1,
        &bincode::serialize(receipt_heads)?,
    ))
}

fn validate_admission_entries(
    admissions: &[AdmissionFrontierEntryV1],
) -> Result<(), OperationStoreFrontierError> {
    let mut operation_ids = BTreeSet::new();
    let mut previous_sequence = None;
    for entry in admissions {
        entry.validate()?;
        if let Some(previous) = previous_sequence {
            if entry.admission_sequence <= previous {
                return Err(OperationStoreFrontierError::AdmissionsNotCanonical);
            }
        }
        previous_sequence = Some(entry.admission_sequence);
        if !operation_ids.insert(entry.operation_id) {
            return Err(OperationStoreFrontierError::DuplicateOperationId);
        }
    }
    Ok(())
}

fn validate_receipt_heads(
    receipt_heads: &[ReceiptHeadFrontierEntryV1],
) -> Result<(), OperationStoreFrontierError> {
    let mut previous_operation_id = None;
    for head in receipt_heads {
        head.validate()?;
        if let Some(previous) = previous_operation_id {
            if head.operation_id <= previous {
                return Err(OperationStoreFrontierError::ReceiptHeadsNotCanonical);
            }
        }
        previous_operation_id = Some(head.operation_id);
    }
    Ok(())
}

fn validate_matching_operation_sets(
    admissions: &[AdmissionFrontierEntryV1],
    receipt_heads: &[ReceiptHeadFrontierEntryV1],
) -> Result<(), OperationStoreFrontierError> {
    if admissions.len() != receipt_heads.len() {
        return Err(OperationStoreFrontierError::ReceiptHeadOperationSetMismatch);
    }
    let admission_ids: BTreeSet<[u8; 16]> =
        admissions.iter().map(|entry| entry.operation_id).collect();
    let receipt_ids: BTreeSet<[u8; 16]> =
        receipt_heads.iter().map(|entry| entry.operation_id).collect();
    if admission_ids != receipt_ids {
        return Err(OperationStoreFrontierError::ReceiptHeadOperationSetMismatch);
    }
    Ok(())
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Validation failure for operation-store frontier and anti-rollback evidence.
#[derive(Debug, Error)]
pub enum OperationStoreFrontierError {
    /// Frontier schema is not the exact V1 label.
    #[error("unsupported operation store frontier schema")]
    UnsupportedFrontierSchema,
    /// External anchor schema is not the exact V1 label.
    #[error("unsupported operation store frontier anchor schema")]
    UnsupportedAnchorSchema,
    /// Store identity is the all-zero unset sentinel.
    #[error("store id must not be all zero")]
    ZeroStoreId,
    /// Store schema commitment is unset.
    #[error("store schema digest must not be all zero")]
    ZeroStoreSchemaDigest,
    /// Operation id is the all-zero unset sentinel.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Admission commitment is unset.
    #[error("admission digest must not be all zero")]
    ZeroAdmissionDigest,
    /// Admission-set commitment is unset.
    #[error("admission set digest must not be all zero")]
    ZeroAdmissionSetDigest,
    /// Receipt-head-set commitment is unset.
    #[error("receipt head set digest must not be all zero")]
    ZeroReceiptHeadSetDigest,
    /// Frontier commitment in an external anchor is unset.
    #[error("frontier digest must not be all zero")]
    ZeroFrontierDigest,
    /// A no-event receipt head unexpectedly carried a digest.
    #[error("receipt head without an event must use the zero digest sentinel")]
    UnexpectedReceiptHeadDigest,
    /// An event-bearing receipt head omitted its digest.
    #[error("receipt head with an event must carry a non-zero digest")]
    MissingReceiptHeadDigest,
    /// Admission entries are not in strict canonical sequence order.
    #[error("admission frontier entries are not in strictly increasing sequence order")]
    AdmissionsNotCanonical,
    /// Receipt-head entries are not in strict canonical operation-id order.
    #[error("receipt head entries are not in strictly increasing operation-id order")]
    ReceiptHeadsNotCanonical,
    /// Canonical admission state contained the same operation id more than once.
    #[error("duplicate operation id in admission frontier state")]
    DuplicateOperationId,
    /// Receipt heads did not contain exactly one entry for every admitted operation.
    #[error("receipt-head operation-id set does not match admission operation-id set")]
    ReceiptHeadOperationSetMismatch,
    /// Empty frontier incorrectly declared a highest admission sequence.
    #[error("empty store frontier must not declare a highest admission sequence")]
    EmptyStoreHasHighestSequence,
    /// Non-empty frontier omitted its highest admission sequence.
    #[error("non-empty store frontier must declare a highest admission sequence")]
    NonEmptyStoreMissingHighestSequence,
    /// Checkpoint zero incorrectly linked a predecessor.
    #[error("checkpoint zero must use the zero previous-frontier sentinel")]
    GenesisHasPreviousFrontier,
    /// Non-genesis checkpoint omitted its predecessor commitment.
    #[error("non-genesis checkpoint must commit to the previous frontier")]
    MissingPreviousFrontierDigest,
    /// Admission count could not be represented as u64.
    #[error("admission count overflow")]
    EntryCountOverflow,
    /// Recomputed admission count differs from the frontier.
    #[error("frontier admission count does not match durable state")]
    AdmissionCountMismatch,
    /// Recomputed highest admission sequence differs from the frontier.
    #[error("frontier highest admission sequence does not match durable state")]
    HighestAdmissionSequenceMismatch,
    /// Recomputed admission-set commitment differs from the frontier.
    #[error("frontier admission-set digest does not match durable state")]
    AdmissionSetDigestMismatch,
    /// Recomputed receipt-head commitment differs from the frontier.
    #[error("frontier receipt-head-set digest does not match durable state")]
    ReceiptHeadSetDigestMismatch,
    /// Successor belongs to a different store identity.
    #[error("operation store id mismatch")]
    StoreIdMismatch,
    /// Successor/anchor belongs to a different store generation.
    #[error("operation store generation mismatch")]
    GenerationMismatch,
    /// Store representation changed without an explicit generation transition.
    #[error("store schema changed within one generation")]
    StoreSchemaChangedWithinGeneration,
    /// Checkpoint sequence overflowed.
    #[error("checkpoint sequence overflow")]
    CheckpointSequenceOverflow,
    /// Successor checkpoint sequence is not exactly previous + 1.
    #[error("checkpoint sequence is not the exact successor")]
    CheckpointSequenceMismatch,
    /// Successor does not commit to the actual previous frontier.
    #[error("previous frontier digest mismatch")]
    PreviousFrontierDigestMismatch,
    /// Durable admission count moved backward.
    #[error("admission count regressed")]
    AdmissionCountRegression,
    /// Highest durable admission sequence moved backward.
    #[error("highest admission sequence regressed")]
    HighestAdmissionSequenceRegression,
    /// Frontier evidence timestamp moved backward.
    #[error("frontier timestamp regressed")]
    TimestampRegression,
    /// External anchor predates the frontier it claims to record.
    #[error("anchor timestamp must not precede frontier timestamp")]
    AnchorTimestampBeforeFrontier,
    /// Local durable state is older than the trusted external anchor.
    #[error("operation store rollback detected")]
    RollbackDetected,
    /// V1 local history no longer retains the checkpoint named by the anchor.
    #[error("anchored frontier is missing from retained V1 history")]
    AnchoredFrontierMissing,
    /// Retained checkpoint at the anchor sequence has a different digest.
    #[error("anchored frontier digest mismatch; fork or corruption detected")]
    AnchorDigestMismatch,
    /// Canonical bincode serialization failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admissions_one() -> Vec<AdmissionFrontierEntryV1> {
        vec![AdmissionFrontierEntryV1 {
            admission_sequence: 7,
            operation_id: [1u8; 16],
            admission_digest: [11u8; 32],
        }]
    }

    fn heads_one() -> Vec<ReceiptHeadFrontierEntryV1> {
        vec![ReceiptHeadFrontierEntryV1 {
            operation_id: [1u8; 16],
            event_index: None,
            event_digest: [0u8; 32],
        }]
    }

    fn frontier_zero() -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            [9u8; 16],
            0,
            0,
            [8u8; 32],
            [0u8; 32],
            1_000,
            &admissions_one(),
            &heads_one(),
        )
        .unwrap()
    }

    fn frontier_one(previous: &OperationStoreFrontierV1) -> OperationStoreFrontierV1 {
        let admissions = vec![
            AdmissionFrontierEntryV1 {
                admission_sequence: 7,
                operation_id: [1u8; 16],
                admission_digest: [11u8; 32],
            },
            AdmissionFrontierEntryV1 {
                admission_sequence: 8,
                operation_id: [2u8; 16],
                admission_digest: [12u8; 32],
            },
        ];
        let heads = vec![
            ReceiptHeadFrontierEntryV1 {
                operation_id: [1u8; 16],
                event_index: Some(0),
                event_digest: [21u8; 32],
            },
            ReceiptHeadFrontierEntryV1 {
                operation_id: [2u8; 16],
                event_index: None,
                event_digest: [0u8; 32],
            },
        ];
        OperationStoreFrontierV1::from_state(
            previous.store_id,
            previous.generation,
            1,
            previous.store_schema_digest,
            previous.frontier_digest().unwrap(),
            1_001,
            &admissions,
            &heads,
        )
        .unwrap()
    }

    #[test]
    fn frontier_is_deterministic_for_identical_state() {
        let a = frontier_zero();
        let b = frontier_zero();
        assert_eq!(a.frontier_digest().unwrap(), b.frontier_digest().unwrap());
    }

    #[test]
    fn admission_state_changes_frontier() {
        let first = frontier_zero();
        let second = frontier_one(&first);
        assert_ne!(first.frontier_digest().unwrap(), second.frontier_digest().unwrap());
    }

    #[test]
    fn receipt_head_requires_zero_digest_when_no_event_exists() {
        let bad = ReceiptHeadFrontierEntryV1 {
            operation_id: [1u8; 16],
            event_index: None,
            event_digest: [1u8; 32],
        };
        assert!(matches!(
            bad.validate(),
            Err(OperationStoreFrontierError::UnexpectedReceiptHeadDigest)
        ));
    }

    #[test]
    fn admissions_must_be_strictly_increasing_by_sequence() {
        let bad = vec![
            AdmissionFrontierEntryV1 {
                admission_sequence: 8,
                operation_id: [1u8; 16],
                admission_digest: [1u8; 32],
            },
            AdmissionFrontierEntryV1 {
                admission_sequence: 7,
                operation_id: [2u8; 16],
                admission_digest: [2u8; 32],
            },
        ];
        assert!(matches!(
            admission_set_digest(&bad),
            Err(OperationStoreFrontierError::AdmissionsNotCanonical)
        ));
    }

    #[test]
    fn receipt_heads_must_match_admitted_operation_set() {
        let admissions = admissions_one();
        let heads = vec![ReceiptHeadFrontierEntryV1 {
            operation_id: [2u8; 16],
            event_index: None,
            event_digest: [0u8; 32],
        }];
        assert!(matches!(
            OperationStoreFrontierV1::from_state(
                [9u8; 16],
                0,
                0,
                [8u8; 32],
                [0u8; 32],
                1_000,
                &admissions,
                &heads,
            ),
            Err(OperationStoreFrontierError::ReceiptHeadOperationSetMismatch)
        ));
    }

    #[test]
    fn successor_binds_exact_previous_frontier() {
        let first = frontier_zero();
        let second = frontier_one(&first);
        assert!(second.validate_successor(&first).is_ok());

        let mut wrong = second;
        wrong.previous_frontier_digest = [77u8; 32];
        assert!(matches!(
            wrong.validate_successor(&first),
            Err(OperationStoreFrontierError::PreviousFrontierDigestMismatch)
        ));
    }

    #[test]
    fn anchor_accepts_exact_newer_descendant_chain() {
        let first = frontier_zero();
        let anchor = first.anchor(1_000).unwrap();
        let second = frontier_one(&first);
        assert!(verify_anchor_lineage(&anchor, &[first, second]).is_ok());
    }

    #[test]
    fn anchor_detects_rollback_to_older_local_state() {
        let first = frontier_zero();
        let second = frontier_one(&first);
        let anchor = second.anchor(1_001).unwrap();
        assert!(matches!(
            verify_anchor_lineage(&anchor, &[first]),
            Err(OperationStoreFrontierError::RollbackDetected)
        ));
    }

    #[test]
    fn anchor_detects_fork_at_same_checkpoint_sequence() {
        let first = frontier_zero();
        let anchor = first.anchor(1_000).unwrap();
        let mut fork = first.clone();
        fork.admission_set_digest = [42u8; 32];
        assert!(matches!(
            verify_anchor_lineage(&anchor, &[fork]),
            Err(OperationStoreFrontierError::AnchorDigestMismatch)
        ));
    }

    #[test]
    fn v1_requires_anchored_checkpoint_to_remain_retained() {
        let first = frontier_zero();
        let anchor = first.anchor(1_000).unwrap();
        let second = frontier_one(&first);
        assert!(matches!(
            verify_anchor_lineage(&anchor, &[second]),
            Err(OperationStoreFrontierError::AnchoredFrontierMissing)
        ));
    }

    #[test]
    fn different_store_cannot_satisfy_anchor() {
        let first = frontier_zero();
        let anchor = first.anchor(1_000).unwrap();
        let mut other = first;
        other.store_id = [3u8; 16];
        assert!(matches!(
            verify_anchor_lineage(&anchor, &[other]),
            Err(OperationStoreFrontierError::StoreIdMismatch)
        ));
    }

    #[test]
    fn verify_state_detects_receipt_head_tampering() {
        let frontier = frontier_zero();
        let admissions = admissions_one();
        let mut heads = heads_one();
        heads[0].event_index = Some(0);
        heads[0].event_digest = [99u8; 32];
        assert!(matches!(
            frontier.verify_state(&admissions, &heads),
            Err(OperationStoreFrontierError::ReceiptHeadSetDigestMismatch)
        ));
    }
}
