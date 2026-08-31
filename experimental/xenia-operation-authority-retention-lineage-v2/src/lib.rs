// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified append-only external retention for operation-authority states and transition evidence.
//!
//! ADR-023/024 retained one witness bundle per witness sequence. Once the authority model also
//! carries governed key/store transitions and global-revocation receipts, a witness sequence is no
//! longer a sufficient external-storage record identity. V2 therefore introduces its own exact
//! `retention_sequence` and previous-record digest while preserving the semantic authority-state
//! chain inside each typed payload.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_epoch::{AuthorityEpochError, AuthorityEpochReasonV1};
use xenia_operation_frontier_governed_transition::{
    GovernedOperationAuthorityTransitionV1, GovernedTransitionError,
    RetainedOperationAuthorityStateV1,
};
use xenia_operation_frontier_retention_bundle::RetainedWitnessBundleError;
use xenia_operation_global_revocation_transition::{
    GlobalRevocationTransitionError, GlobalRevocationTransitionReceiptV1,
};

/// Exact retained-record schema.
pub const OPERATION_AUTHORITY_RETENTION_RECORD_SCHEMA_V2: &str =
    "xenia-operation-authority-retention-record-v2";
/// Domain separator for exact retained-record commitments.
pub const OPERATION_AUTHORITY_RETENTION_RECORD_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-operation-authority-retention-record-digest-v2";

/// Explicit claim about what record zero means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionLineageOriginV2 {
    /// External retention contains the real witness-lineage genesis.
    FullWitnessLineageGenesis,
    /// External protection begins at this already-existing state; earlier history is not claimed.
    AdoptedAnchor,
}

/// One typed semantic payload retained in the external authority-evidence sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationAuthorityRetentionPayloadV2 {
    /// Ordinary same-epoch/same-store/same-ledger authority-state checkpoint.
    AuthorityState(RetainedOperationAuthorityStateV1),
    /// ADR-025 governed key/store discontinuity evidence containing exact previous/candidate state.
    GovernedTransition(GovernedOperationAuthorityTransitionV1),
    /// ADR-026 same-store global revocation, including the exact previous/candidate states and
    /// signed historical transition receipt.
    GlobalRevocationTransition {
        /// Exact retained predecessor state.
        previous: RetainedOperationAuthorityStateV1,
        /// Exact retained global-revocation successor state.
        candidate: RetainedOperationAuthorityStateV1,
        /// Ledger-signed historical receipt produced after the live revocation gate passed.
        receipt: GlobalRevocationTransitionReceiptV1,
    },
}

impl OperationAuthorityRetentionPayloadV2 {
    /// Validate payload-local signatures, typed predecessor bindings, and epoch/store semantics.
    ///
    /// This deliberately does not re-authenticate recovery/global-revocation approval. Those are
    /// authority-verifier responsibilities. External retention stores immutable evidence; it must
    /// not invent authority merely by persisting bytes.
    pub fn validate_local(&self) -> Result<(), AuthorityRetentionErrorV2> {
        match self {
            Self::AuthorityState(state) => state.validate_local()?,
            Self::GovernedTransition(transition) => transition.validate_local()?,
            Self::GlobalRevocationTransition {
                previous,
                candidate,
                receipt,
            } => {
                previous.validate_local()?;
                candidate.validate_local()?;
                receipt.validate_local()?;
                if receipt.previous_state_digest != previous.state_digest()?
                    || receipt.candidate_state_digest != candidate.state_digest()?
                    || receipt.candidate_epoch_digest != candidate.authority_epoch.epoch_digest()?
                    || receipt.witness_digest
                        != candidate.retained_bundle.witness.witness_digest()?
                {
                    return Err(AuthorityRetentionErrorV2::GlobalRevocationReceiptStateMismatch);
                }
                candidate
                    .retained_bundle
                    .validate_successor(&previous.retained_bundle)?;
                candidate
                    .authority_epoch
                    .validate_successor(&previous.authority_epoch)?;
                match &candidate.authority_epoch.reason {
                    AuthorityEpochReasonV1::GlobalRevocation {
                        revocation_decision_digest,
                    } if *revocation_decision_digest == receipt.decision.decision_digest()? => {}
                    _ => {
                        return Err(
                            AuthorityRetentionErrorV2::GlobalRevocationEpochDecisionMismatch,
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// The authority state immediately before this payload's semantic event, when explicitly
    /// carried by the payload.
    pub fn initial_state(&self) -> Option<&RetainedOperationAuthorityStateV1> {
        match self {
            Self::AuthorityState(_) => None,
            Self::GovernedTransition(transition) => Some(&transition.previous),
            Self::GlobalRevocationTransition { previous, .. } => Some(previous),
        }
    }

    /// The authority state established by / represented at the end of this payload.
    pub fn terminal_state(&self) -> &RetainedOperationAuthorityStateV1 {
        match self {
            Self::AuthorityState(state) => state,
            Self::GovernedTransition(transition) => &transition.candidate,
            Self::GlobalRevocationTransition { candidate, .. } => candidate,
        }
    }

    fn minimum_record_time_ms(&self) -> u64 {
        match self {
            Self::AuthorityState(state) => state.retained_bundle.retained_at_unix_ms,
            Self::GovernedTransition(transition) => transition
                .transitioned_at_unix_ms
                .max(transition.candidate.retained_bundle.retained_at_unix_ms),
            Self::GlobalRevocationTransition {
                candidate, receipt, ..
            } => receipt
                .verified_at_unix_ms
                .max(candidate.retained_bundle.retained_at_unix_ms),
        }
    }
}

/// One immutable member of the external authority-evidence retention sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationAuthorityRetentionRecordV2 {
    /// Exact record schema.
    pub schema: String,
    /// Contiguous zero-based retention sequence, independent of witness sequence.
    pub retention_sequence: u64,
    /// Exact digest of the previous retained record, or all-zero for record zero.
    pub previous_record_digest: [u8; 32],
    /// Explicit origin claim on record zero; `None` on every successor.
    pub lineage_origin: Option<RetentionLineageOriginV2>,
    /// Typed authority evidence retained by this record.
    pub payload: OperationAuthorityRetentionPayloadV2,
    /// Local/external-handoff retention time used for monotonic audit ordering.
    pub retained_at_unix_ms: u64,
}

impl OperationAuthorityRetentionRecordV2 {
    /// Construct and locally validate a retained record.
    pub fn new(
        retention_sequence: u64,
        previous_record_digest: [u8; 32],
        lineage_origin: Option<RetentionLineageOriginV2>,
        payload: OperationAuthorityRetentionPayloadV2,
        retained_at_unix_ms: u64,
    ) -> Result<Self, AuthorityRetentionErrorV2> {
        let value = Self {
            schema: OPERATION_AUTHORITY_RETENTION_RECORD_SCHEMA_V2.to_string(),
            retention_sequence,
            previous_record_digest,
            lineage_origin,
            payload,
            retained_at_unix_ms,
        };
        value.validate_local()?;
        Ok(value)
    }

    /// Validate record-local shape independent of its retained predecessor.
    pub fn validate_local(&self) -> Result<(), AuthorityRetentionErrorV2> {
        if self.schema != OPERATION_AUTHORITY_RETENTION_RECORD_SCHEMA_V2 {
            return Err(AuthorityRetentionErrorV2::UnsupportedRecordSchema);
        }
        self.payload.validate_local()?;
        if self.retained_at_unix_ms < self.payload.minimum_record_time_ms() {
            return Err(AuthorityRetentionErrorV2::RecordPredatesPayloadEvidence);
        }
        match self.retention_sequence {
            0 => {
                if self.previous_record_digest != [0u8; 32] {
                    return Err(AuthorityRetentionErrorV2::GenesisHasPreviousRecord);
                }
                let origin = self
                    .lineage_origin
                    .ok_or(AuthorityRetentionErrorV2::GenesisMissingOrigin)?;
                let OperationAuthorityRetentionPayloadV2::AuthorityState(state) = &self.payload
                else {
                    return Err(AuthorityRetentionErrorV2::GenesisMustBeAuthorityState);
                };
                if origin == RetentionLineageOriginV2::FullWitnessLineageGenesis {
                    let witness = &state.retained_bundle.witness;
                    if witness.payload.witness_sequence != 0
                        || witness.payload.previous_witness_digest != [0u8; 32]
                    {
                        return Err(AuthorityRetentionErrorV2::FalseFullGenesisClaim);
                    }
                }
            }
            _ => {
                if self.previous_record_digest == [0u8; 32] {
                    return Err(AuthorityRetentionErrorV2::SuccessorMissingPreviousRecord);
                }
                if self.lineage_origin.is_some() {
                    return Err(AuthorityRetentionErrorV2::SuccessorHasOrigin);
                }
            }
        }
        Ok(())
    }

    /// Canonical retained-record bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityRetentionErrorV2> {
        self.validate_local()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable exact retained-record commitment.
    pub fn record_digest(&self) -> Result<[u8; 32], AuthorityRetentionErrorV2> {
        Ok(domain_digest(
            OPERATION_AUTHORITY_RETENTION_RECORD_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }

    /// Validate this record as the exact semantic successor of `previous`.
    pub fn validate_successor(
        &self,
        previous: &Self,
    ) -> Result<(), AuthorityRetentionErrorV2> {
        previous.validate_local()?;
        self.validate_local()?;
        let expected_sequence = previous
            .retention_sequence
            .checked_add(1)
            .ok_or(AuthorityRetentionErrorV2::RetentionSequenceOverflow)?;
        if self.retention_sequence != expected_sequence {
            return Err(AuthorityRetentionErrorV2::RetentionSequenceMismatch);
        }
        if self.previous_record_digest != previous.record_digest()? {
            return Err(AuthorityRetentionErrorV2::PreviousRecordDigestMismatch);
        }
        if self.retained_at_unix_ms < previous.retained_at_unix_ms {
            return Err(AuthorityRetentionErrorV2::RetentionTimestampRegressed);
        }

        let previous_terminal = previous.payload.terminal_state();
        match &self.payload {
            OperationAuthorityRetentionPayloadV2::AuthorityState(candidate) => {
                if candidate.authority_epoch != previous_terminal.authority_epoch {
                    return Err(AuthorityRetentionErrorV2::OrdinaryStateChangedAuthorityEpoch);
                }
                candidate
                    .retained_bundle
                    .validate_successor(&previous_terminal.retained_bundle)?;
            }
            OperationAuthorityRetentionPayloadV2::GovernedTransition(transition) => {
                if transition.previous.state_digest()? != previous_terminal.state_digest()? {
                    return Err(AuthorityRetentionErrorV2::TransitionPredecessorMismatch);
                }
            }
            OperationAuthorityRetentionPayloadV2::GlobalRevocationTransition {
                previous: transition_previous,
                ..
            } => {
                if transition_previous.state_digest()? != previous_terminal.state_digest()? {
                    return Err(AuthorityRetentionErrorV2::TransitionPredecessorMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Health of the reference external persistence state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRetentionHealthV2 {
    /// New append attempts may be evaluated.
    Healthy,
    /// A backend could not prove whether a candidate committed. No further writes are allowed.
    DurabilityUncertain,
}

/// Result reported by a concrete persistence boundary for one exact new record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceOutcomeV2 {
    /// Backend positively confirms the exact record is durably retained.
    Durable,
    /// Backend positively confirms the record was not durably retained.
    Rejected,
    /// Backend cannot prove whether the record committed.
    Unknown,
}

/// Successful append classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRetentionAppendResultV2 {
    /// A new exact next record was durably appended.
    Appended,
    /// The exact immutable record was already present; persistence was not called again.
    DuplicateSame,
}

/// Executable V2 reference model for an append-only independent authority-evidence backend.
#[derive(Debug, Clone)]
pub struct OperationAuthorityRetentionModelV2 {
    health: AuthorityRetentionHealthV2,
    records: Vec<OperationAuthorityRetentionRecordV2>,
}

impl Default for OperationAuthorityRetentionModelV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationAuthorityRetentionModelV2 {
    /// New empty healthy reference model.
    pub const fn new() -> Self {
        Self {
            health: AuthorityRetentionHealthV2::Healthy,
            records: Vec::new(),
        }
    }

    /// Rehydrate only by reading back the complete immutable external lineage and validating it.
    pub fn from_retained_lineage(
        records: Vec<OperationAuthorityRetentionRecordV2>,
    ) -> Result<Self, AuthorityRetentionErrorV2> {
        validate_retained_lineage_v2(&records)?;
        Ok(Self {
            health: AuthorityRetentionHealthV2::Healthy,
            records,
        })
    }

    /// Current fail-stop health.
    pub const fn health(&self) -> AuthorityRetentionHealthV2 {
        self.health
    }

    /// Complete retained records known to this model.
    pub fn records(&self) -> &[OperationAuthorityRetentionRecordV2] {
        &self.records
    }

    /// Append one record using persistence-before-ack semantics.
    pub fn append(
        &mut self,
        candidate: OperationAuthorityRetentionRecordV2,
        persist: impl FnOnce(&OperationAuthorityRetentionRecordV2) -> PersistenceOutcomeV2,
    ) -> Result<AuthorityRetentionAppendResultV2, AuthorityRetentionErrorV2> {
        if self.health != AuthorityRetentionHealthV2::Healthy {
            return Err(AuthorityRetentionErrorV2::DurabilityUncertain);
        }
        candidate.validate_local()?;

        let sequence = usize::try_from(candidate.retention_sequence)
            .map_err(|_| AuthorityRetentionErrorV2::RetentionSequenceOutOfRange)?;
        if sequence < self.records.len() {
            let existing = &self.records[sequence];
            if existing.canonical_bytes()? == candidate.canonical_bytes()? {
                return Ok(AuthorityRetentionAppendResultV2::DuplicateSame);
            }
            return Err(AuthorityRetentionErrorV2::RetentionSequenceConflict);
        }
        if sequence > self.records.len() {
            return Err(AuthorityRetentionErrorV2::RetentionSequenceGap);
        }

        if let Some(previous) = self.records.last() {
            candidate.validate_successor(previous)?;
        } else if candidate.retention_sequence != 0 {
            return Err(AuthorityRetentionErrorV2::RetentionSequenceGap);
        }

        match persist(&candidate) {
            PersistenceOutcomeV2::Durable => {
                self.records.push(candidate);
                Ok(AuthorityRetentionAppendResultV2::Appended)
            }
            PersistenceOutcomeV2::Rejected => Err(AuthorityRetentionErrorV2::PersistenceRejected),
            PersistenceOutcomeV2::Unknown => {
                self.health = AuthorityRetentionHealthV2::DurabilityUncertain;
                Err(AuthorityRetentionErrorV2::PersistenceOutcomeUnknown)
            }
        }
    }
}

/// Validate a complete retained V2 lineage from its explicit origin through the latest record.
pub fn validate_retained_lineage_v2(
    records: &[OperationAuthorityRetentionRecordV2],
) -> Result<(), AuthorityRetentionErrorV2> {
    let Some(first) = records.first() else {
        return Ok(());
    };
    first.validate_local()?;
    if first.retention_sequence != 0 {
        return Err(AuthorityRetentionErrorV2::RetentionSequenceGap);
    }
    for pair in records.windows(2) {
        pair[1].validate_successor(&pair[0])?;
    }
    Ok(())
}

/// Fail-closed V2 external authority-retention errors.
#[derive(Debug, Error)]
pub enum AuthorityRetentionErrorV2 {
    /// Unknown record schema.
    #[error("unsupported operation authority retention record schema")]
    UnsupportedRecordSchema,
    /// Record payload local state/signature failed.
    #[error("retained authority state/transition failed validation: {0}")]
    GovernedTransition(#[from] GovernedTransitionError),
    /// Retained witness bundle succession failed.
    #[error("retained witness bundle rejected authority retention lineage: {0}")]
    RetainedBundle(#[from] RetainedWitnessBundleError),
    /// Authority epoch succession failed.
    #[error("authority epoch rejected authority retention lineage: {0}")]
    AuthorityEpoch(#[from] AuthorityEpochError),
    /// Global revocation receipt/decision failed validation.
    #[error("global revocation evidence rejected authority retention lineage: {0}")]
    GlobalRevocation(#[from] GlobalRevocationTransitionError),
    /// Global revocation receipt does not bind the exact carried previous/candidate state.
    #[error("global revocation receipt does not match retained previous/candidate state")]
    GlobalRevocationReceiptStateMismatch,
    /// Global revocation candidate epoch does not commit the exact retained approved decision.
    #[error("global revocation epoch does not commit retained decision digest")]
    GlobalRevocationEpochDecisionMismatch,
    /// Retention record timestamp predates evidence carried by its payload.
    #[error("retention record predates payload evidence")]
    RecordPredatesPayloadEvidence,
    /// Record zero unexpectedly names a predecessor record.
    #[error("retention genesis must not name a previous record")]
    GenesisHasPreviousRecord,
    /// Record zero did not explicitly state the lineage-origin claim.
    #[error("retention genesis requires explicit lineage origin")]
    GenesisMissingOrigin,
    /// Record zero must establish an authority-state anchor, not begin with a transition.
    #[error("retention genesis must be an authority-state record")]
    GenesisMustBeAuthorityState,
    /// Claimed full witness genesis was not actually witness sequence zero/no predecessor.
    #[error("full witness-lineage genesis claim does not match embedded witness")]
    FalseFullGenesisClaim,
    /// Non-genesis record omitted predecessor commitment.
    #[error("retention successor requires previous-record digest")]
    SuccessorMissingPreviousRecord,
    /// Non-genesis record attempted to redefine lineage origin.
    #[error("only retention record zero may define lineage origin")]
    SuccessorHasOrigin,
    /// Retention sequence overflowed.
    #[error("retention sequence overflow")]
    RetentionSequenceOverflow,
    /// Retention sequence is not exact previous + 1.
    #[error("retention sequence mismatch")]
    RetentionSequenceMismatch,
    /// Record predecessor digest is not the exact prior record.
    #[error("previous retention-record digest mismatch")]
    PreviousRecordDigestMismatch,
    /// Retention timestamp moved backward.
    #[error("retention timestamp regressed")]
    RetentionTimestampRegressed,
    /// Ordinary state record tried to change operation authority epoch without a transition record.
    #[error("ordinary retained authority state changed authority epoch")]
    OrdinaryStateChangedAuthorityEpoch,
    /// Transition payload does not begin at the immediately previous terminal state.
    #[error("authority transition predecessor does not match retained terminal state")]
    TransitionPredecessorMismatch,
    /// Retention sequence cannot fit local address space.
    #[error("retention sequence out of local address range")]
    RetentionSequenceOutOfRange,
    /// Existing sequence contains different immutable bytes.
    #[error("retention sequence conflict / fork evidence")]
    RetentionSequenceConflict,
    /// Candidate skipped one or more external retention records.
    #[error("retention sequence gap")]
    RetentionSequenceGap,
    /// Backend positively rejected persistence.
    #[error("external retention backend rejected append")]
    PersistenceRejected,
    /// Backend could not prove whether append committed; model is now fail-stopped.
    #[error("external retention append outcome is unknown")]
    PersistenceOutcomeUnknown,
    /// Model is fail-stopped after an earlier ambiguous persistence result.
    #[error("external retention durability is uncertain; immutable readback required")]
    DurabilityUncertain,
    /// Canonical record serialization failed.
    #[error("authority retention serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
