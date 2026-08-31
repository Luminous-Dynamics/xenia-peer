// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Governed transition verification across operation-store recovery and ledger-key rotation.
//!
//! Ordinary ADR-022 witness succession deliberately rejects ledger-key and operation-store
//! generation changes. This adapter proves the exceptional case without weakening that default:
//! every retained state binds the exact operation authority epoch, and a discontinuity is accepted
//! only when the existing Xenia ledger-key transition and/or governed recovery contracts justify it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use xenia_ledger::{
    CheckpointContinuityError, CheckpointFreshnessPolicy, LedgerEntry, LedgerKeyTransition,
    LedgerKeyTransitionError, Verifier as LedgerVerifier,
};
use xenia_operation_authority_epoch::{
    AuthorityEpochError, OperationAuthorityEpochV1,
};
use xenia_operation_frontier_retention_bundle::{
    RetainedOperationFrontierWitnessBundleV1, RetainedWitnessBundleError,
    verify_retained_operation_frontier_bundle_v1,
};
use xenia_operation_store_frontier::OperationStoreFrontierV1;
use xenia_operation_store_recovery::{
    OperationStoreRecoveryAssessmentV1, OperationStoreRecoveryPlanV1, RecoveryProtocolError,
};

/// Stable schema for one retained operation-authority state.
pub const RETAINED_OPERATION_AUTHORITY_STATE_SCHEMA_V1: &str =
    "xenia-retained-operation-authority-state-v1";
/// Stable schema for governed state-transition evidence.
pub const GOVERNED_OPERATION_AUTHORITY_TRANSITION_SCHEMA_V1: &str =
    "xenia-governed-operation-authority-transition-v1";
/// Domain separator for the state-attestation signature.
pub const OPERATION_AUTHORITY_STATE_MESSAGE_DOMAIN_V1: &[u8] =
    b"xenia-operation-authority-state-message-v1";
/// Domain separator for exact signed state commitments.
pub const OPERATION_AUTHORITY_STATE_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-authority-state-digest-v1";
/// Domain separator for exact transition-evidence commitments.
pub const GOVERNED_OPERATION_AUTHORITY_TRANSITION_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-governed-operation-authority-transition-digest-v1";

/// Atomically retainable operation authority state: frontier/ledger witness plus exact epoch.
///
/// The additional signature is by the same ledger key referenced by the retained checkpoint and
/// commits the exact retained bundle together with the exact `OperationAuthorityEpochV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedOperationAuthorityStateV1 {
    /// Exact state schema.
    pub schema: String,
    /// Exact witness/checkpoint evidence bundle.
    pub retained_bundle: RetainedOperationFrontierWitnessBundleV1,
    /// Exact operation-authority epoch serving the witnessed store identity/generation.
    pub authority_epoch: OperationAuthorityEpochV1,
    /// Ed25519 signature under the retained ledger checkpoint key over bundle + epoch.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl RetainedOperationAuthorityStateV1 {
    /// Sign one retained authority state with the ledger authority named by its checkpoint.
    pub fn sign_ed25519(
        retained_bundle: RetainedOperationFrontierWitnessBundleV1,
        authority_epoch: OperationAuthorityEpochV1,
        signing_key: &SigningKey,
    ) -> Result<Self, GovernedTransitionError> {
        retained_bundle.validate_local()?;
        authority_epoch.validate()?;
        validate_epoch_store_binding(&retained_bundle, &authority_epoch)?;
        if signing_key.verifying_key().to_bytes()
            != retained_bundle.ledger_checkpoint.ledger_public_key
        {
            return Err(GovernedTransitionError::StateSigningKeyMismatch);
        }
        let message = authority_state_message(&retained_bundle, &authority_epoch)?;
        let value = Self {
            schema: RETAINED_OPERATION_AUTHORITY_STATE_SCHEMA_V1.to_string(),
            retained_bundle,
            authority_epoch,
            signature: signing_key.sign(&message).to_bytes(),
        };
        value.validate_local()?;
        Ok(value)
    }

    /// Validate signed state syntax/store binding without deciding recovery legitimacy.
    pub fn validate_local(&self) -> Result<(), GovernedTransitionError> {
        if self.schema != RETAINED_OPERATION_AUTHORITY_STATE_SCHEMA_V1 {
            return Err(GovernedTransitionError::UnsupportedAuthorityStateSchema);
        }
        self.retained_bundle.validate_local()?;
        self.authority_epoch.validate()?;
        validate_epoch_store_binding(&self.retained_bundle, &self.authority_epoch)?;
        if self.retained_bundle.witness.payload.witnessed_at_unix_ms
            < self.authority_epoch.established_at_unix_ms
        {
            return Err(GovernedTransitionError::WitnessPredatesAuthorityEpoch);
        }
        let key = VerifyingKey::from_bytes(&self.retained_bundle.ledger_checkpoint.ledger_public_key)
            .map_err(|_| GovernedTransitionError::MalformedLedgerKey)?;
        key.verify(
            &authority_state_message(&self.retained_bundle, &self.authority_epoch)?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| GovernedTransitionError::BadAuthorityStateSignature)
    }

    /// Exact signed-state canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GovernedTransitionError> {
        self.validate_local()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable commitment to the exact signed retained authority state.
    pub fn state_digest(&self) -> Result<[u8; 32], GovernedTransitionError> {
        Ok(domain_digest(
            OPERATION_AUTHORITY_STATE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Governed store-transition evidence from ADR-014/#191.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedStoreTransitionEvidenceV1 {
    /// Immutable recovery assessment.
    pub assessment: OperationStoreRecoveryAssessmentV1,
    /// Short-lived approved recovery plan derived from that assessment.
    pub plan: OperationStoreRecoveryPlanV1,
}

impl GovernedStoreTransitionEvidenceV1 {
    /// Validate local syntax only. Approval authenticity remains an external policy decision.
    pub fn validate(&self) -> Result<(), GovernedTransitionError> {
        self.assessment.validate()?;
        self.plan.validate()?;
        if self.plan.assessment_digest != self.assessment.assessment_digest()? {
            return Err(GovernedTransitionError::RecoveryAssessmentMismatch);
        }
        Ok(())
    }
}

/// Evidence joining an exact previous retained authority state to one exceptional successor.
///
/// `ledger_key_transition` is required exactly when the checkpoint key changes. `recovery` is
/// required exactly when the operation-store id/generation changes. This record is evidence only;
/// production verification still invokes the underlying cryptographic/recovery authority gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedOperationAuthorityTransitionV1 {
    /// Exact transition schema.
    pub schema: String,
    /// Exact signed retained state before the discontinuity.
    pub previous: RetainedOperationAuthorityStateV1,
    /// Exact signed retained state after the discontinuity.
    pub candidate: RetainedOperationAuthorityStateV1,
    /// Dual-signed ledger-key handover when the ledger key changes.
    pub ledger_key_transition: Option<LedgerKeyTransition>,
    /// Governed ADR-014 store recovery evidence when store identity/generation changes.
    pub recovery: Option<GovernedStoreTransitionEvidenceV1>,
    /// Evidence timestamp in Unix milliseconds.
    pub transitioned_at_unix_ms: u64,
}

impl GovernedOperationAuthorityTransitionV1 {
    /// Construct locally coherent transition evidence.
    pub fn new(
        previous: RetainedOperationAuthorityStateV1,
        candidate: RetainedOperationAuthorityStateV1,
        ledger_key_transition: Option<LedgerKeyTransition>,
        recovery: Option<GovernedStoreTransitionEvidenceV1>,
        transitioned_at_unix_ms: u64,
    ) -> Result<Self, GovernedTransitionError> {
        let value = Self {
            schema: GOVERNED_OPERATION_AUTHORITY_TRANSITION_SCHEMA_V1.to_string(),
            previous,
            candidate,
            ledger_key_transition,
            recovery,
            transitioned_at_unix_ms,
        };
        value.validate_local()?;
        Ok(value)
    }

    /// Validate syntax, signed state bindings, and the global witness sequence link.
    ///
    /// This intentionally does not authenticate recovery approval or prove ledger/store history.
    pub fn validate_local(&self) -> Result<(), GovernedTransitionError> {
        if self.schema != GOVERNED_OPERATION_AUTHORITY_TRANSITION_SCHEMA_V1 {
            return Err(GovernedTransitionError::UnsupportedTransitionSchema);
        }
        self.previous.validate_local()?;
        self.candidate.validate_local()?;
        if let Some(recovery) = &self.recovery {
            recovery.validate()?;
        }
        if let Some(key_transition) = &self.ledger_key_transition {
            LedgerVerifier::verify_ledger_key_transition(key_transition)?;
        }

        let previous_witness = &self.previous.retained_bundle.witness;
        let candidate_witness = &self.candidate.retained_bundle.witness;
        let expected_sequence = previous_witness
            .payload
            .witness_sequence
            .checked_add(1)
            .ok_or(GovernedTransitionError::WitnessSequenceOverflow)?;
        if candidate_witness.payload.witness_sequence != expected_sequence {
            return Err(GovernedTransitionError::WitnessSequenceMismatch);
        }
        if candidate_witness.payload.previous_witness_digest != previous_witness.witness_digest()? {
            return Err(GovernedTransitionError::PreviousWitnessDigestMismatch);
        }
        if candidate_witness.payload.witnessed_at_unix_ms
            < previous_witness.payload.witnessed_at_unix_ms
        {
            return Err(GovernedTransitionError::WitnessTimestampRegressed);
        }
        if self.candidate.retained_bundle.retained_at_unix_ms
            < self.previous.retained_bundle.retained_at_unix_ms
        {
            return Err(GovernedTransitionError::RetentionTimestampRegressed);
        }
        if self.transitioned_at_unix_ms < self.candidate.retained_bundle.retained_at_unix_ms {
            return Err(GovernedTransitionError::TransitionPredatesCandidateRetention);
        }
        Ok(())
    }

    /// Canonical transition-evidence bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GovernedTransitionError> {
        self.validate_local()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable commitment to the exact transition evidence.
    pub fn transition_digest(&self) -> Result<[u8; 32], GovernedTransitionError> {
        Ok(domain_digest(
            GOVERNED_OPERATION_AUTHORITY_TRANSITION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Successful authority-owned verification of an exceptional retained-state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedGovernedOperationAuthorityTransitionV1 {
    transition_digest: [u8; 32],
    previous_state_digest: [u8; 32],
    candidate_state_digest: [u8; 32],
    candidate_epoch_digest: [u8; 32],
    ledger_key_rotated: bool,
    store_transitioned: bool,
}

impl VerifiedGovernedOperationAuthorityTransitionV1 {
    /// Digest of the complete verified transition evidence.
    pub const fn transition_digest(self) -> [u8; 32] {
        self.transition_digest
    }

    /// Digest of the exact previous signed authority state.
    pub const fn previous_state_digest(self) -> [u8; 32] {
        self.previous_state_digest
    }

    /// Digest of the exact candidate signed authority state.
    pub const fn candidate_state_digest(self) -> [u8; 32] {
        self.candidate_state_digest
    }

    /// Exact candidate authority-epoch commitment.
    pub const fn candidate_epoch_digest(self) -> [u8; 32] {
        self.candidate_epoch_digest
    }

    /// Whether a dual-signed ledger-key handover was verified.
    pub const fn ledger_key_rotated(self) -> bool {
        self.ledger_key_rotated
    }

    /// Whether ADR-014 authorized store identity/generation transition was verified.
    pub const fn store_transitioned(self) -> bool {
        self.store_transitioned
    }
}

/// Verify one exceptional retained authority-state transition.
///
/// `verify_recovery_approval` is the deployment's authenticated recovery-approval trust path.
/// Merely possessing a serialized `OperationStoreRecoveryPlanV1` is intentionally insufficient.
#[allow(clippy::too_many_arguments)]
pub fn verify_governed_operation_authority_transition_v1(
    transition: &GovernedOperationAuthorityTransitionV1,
    previous_ledger_entries: &[LedgerEntry],
    candidate_ledger_entries: &[LedgerEntry],
    trusted_previous_ledger_public_key: [u8; 32],
    previous_frontiers: &[OperationStoreFrontierV1],
    candidate_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
    verify_recovery_approval: impl FnOnce(
        &OperationStoreRecoveryAssessmentV1,
        &OperationStoreRecoveryPlanV1,
    ) -> bool,
) -> Result<VerifiedGovernedOperationAuthorityTransitionV1, GovernedTransitionError> {
    transition.validate_local()?;

    // Previous state must be fully trusted under the independently retained old ledger key.
    verify_retained_operation_frontier_bundle_v1(
        &transition.previous.retained_bundle,
        previous_ledger_entries,
        trusted_previous_ledger_public_key,
        previous_frontiers,
        now_unix_secs,
        historical_freshness(freshness_policy),
    )?;

    let previous_key = transition.previous.retained_bundle.ledger_checkpoint.ledger_public_key;
    let candidate_key = transition.candidate.retained_bundle.ledger_checkpoint.ledger_public_key;
    let ledger_key_rotated = previous_key != candidate_key;

    if ledger_key_rotated {
        let key_transition = transition
            .ledger_key_transition
            .as_ref()
            .ok_or(GovernedTransitionError::MissingLedgerKeyTransition)?;
        if key_transition.previous_checkpoint != transition.previous.retained_bundle.ledger_checkpoint {
            return Err(GovernedTransitionError::LedgerTransitionPreviousCheckpointMismatch);
        }
        LedgerVerifier::verify_ledger_key_successor(
            &transition.previous.retained_bundle.ledger_checkpoint,
            key_transition,
            &transition.candidate.retained_bundle.ledger_checkpoint,
            candidate_ledger_entries,
        )?;
        verify_retained_operation_frontier_bundle_v1(
            &transition.candidate.retained_bundle,
            candidate_ledger_entries,
            key_transition.new_ledger_public_key,
            candidate_frontiers,
            now_unix_secs,
            freshness_policy,
        )?;
    } else {
        if transition.ledger_key_transition.is_some() {
            return Err(GovernedTransitionError::UnexpectedLedgerKeyTransition);
        }
        let trusted_key = VerifyingKey::from_bytes(&trusted_previous_ledger_public_key)
            .map_err(|_| GovernedTransitionError::MalformedLedgerKey)?;
        // Both checkpoints must be prefixes of one currently recovered same-key ledger.
        LedgerVerifier::verify_checkpoint_prefix(
            &transition.previous.retained_bundle.ledger_checkpoint,
            candidate_ledger_entries,
            &trusted_key,
        )?;
        verify_retained_operation_frontier_bundle_v1(
            &transition.candidate.retained_bundle,
            candidate_ledger_entries,
            trusted_previous_ledger_public_key,
            candidate_frontiers,
            now_unix_secs,
            freshness_policy,
        )?;
    }

    let previous_anchor = &transition.previous.retained_bundle.witness.payload.frontier_anchor;
    let candidate_anchor = &transition.candidate.retained_bundle.witness.payload.frontier_anchor;
    let store_transitioned = previous_anchor.store_id != candidate_anchor.store_id
        || previous_anchor.generation != candidate_anchor.generation;

    let now_unix_ms = now_unix_secs
        .checked_mul(1_000)
        .ok_or(GovernedTransitionError::CurrentTimeOverflow)?;

    if store_transitioned {
        let recovery = transition
            .recovery
            .as_ref()
            .ok_or(GovernedTransitionError::MissingGovernedRecoveryEvidence)?;
        if !verify_recovery_approval(&recovery.assessment, &recovery.plan) {
            return Err(GovernedTransitionError::RecoveryApprovalNotAuthenticated);
        }
        recovery.plan.validate_next_epoch(
            &recovery.assessment,
            &transition.previous.authority_epoch,
            &transition.candidate.authority_epoch,
            now_unix_ms,
        )?;
    } else {
        if transition.recovery.is_some() {
            return Err(GovernedTransitionError::UnexpectedGovernedRecoveryEvidence);
        }
        if transition.previous.authority_epoch != transition.candidate.authority_epoch {
            return Err(GovernedTransitionError::UnprovenAuthorityEpochChange);
        }
        // Preserve local frontier monotonicity when the store generation did not change.
        if candidate_anchor.checkpoint_sequence < previous_anchor.checkpoint_sequence {
            return Err(GovernedTransitionError::FrontierCheckpointRegressed);
        }
        if candidate_anchor.checkpoint_sequence == previous_anchor.checkpoint_sequence
            && candidate_anchor.frontier_digest != previous_anchor.frontier_digest
        {
            return Err(GovernedTransitionError::FrontierForkAtSameCheckpoint);
        }
    }

    if !ledger_key_rotated && !store_transitioned {
        return Err(GovernedTransitionError::NoGovernedDiscontinuity);
    }

    Ok(VerifiedGovernedOperationAuthorityTransitionV1 {
        transition_digest: transition.transition_digest()?,
        previous_state_digest: transition.previous.state_digest()?,
        candidate_state_digest: transition.candidate.state_digest()?,
        candidate_epoch_digest: transition.candidate.authority_epoch.epoch_digest()?,
        ledger_key_rotated,
        store_transitioned,
    })
}

/// Fail-closed governed-transition errors.
#[derive(Debug, Error)]
pub enum GovernedTransitionError {
    /// Unknown signed retained-authority-state schema.
    #[error("unsupported retained operation authority state schema")]
    UnsupportedAuthorityStateSchema,
    /// Unknown governed transition schema.
    #[error("unsupported governed authority transition schema")]
    UnsupportedTransitionSchema,
    /// Retained witness/checkpoint bundle failed validation or authority composition.
    #[error("retained frontier bundle rejected transition: {0}")]
    RetainedBundle(#[from] RetainedWitnessBundleError),
    /// Authority epoch failed structural/successor validation.
    #[error("operation authority epoch rejected transition: {0}")]
    AuthorityEpoch(#[from] AuthorityEpochError),
    /// Governed recovery assessment/plan/next-epoch validation failed.
    #[error("governed recovery rejected transition: {0}")]
    Recovery(#[from] RecoveryProtocolError),
    /// Ledger-key transition/successor epoch validation failed.
    #[error("ledger key transition rejected authority transition: {0}")]
    LedgerKeyTransition(#[from] LedgerKeyTransitionError),
    /// Same-key checkpoint prefix/ledger continuity validation failed.
    #[error("ledger checkpoint continuity rejected authority transition: {0}")]
    CheckpointContinuity(#[from] CheckpointContinuityError),
    /// Canonical serialization failed.
    #[error("governed authority transition serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
    /// Authority state store id/generation does not equal the retained frontier anchor binding.
    #[error("authority epoch store binding does not match retained frontier anchor")]
    AuthorityEpochStoreBindingMismatch,
    /// State signature key differs from retained ledger checkpoint key.
    #[error("authority state signing key does not match retained ledger checkpoint key")]
    StateSigningKeyMismatch,
    /// Ledger key bytes are malformed.
    #[error("ledger public key is malformed")]
    MalformedLedgerKey,
    /// State witness was created before the epoch it claims to represent.
    #[error("retained witness predates operation authority epoch establishment")]
    WitnessPredatesAuthorityEpoch,
    /// Signed authority-state attestation failed.
    #[error("retained operation authority state signature is invalid")]
    BadAuthorityStateSignature,
    /// Recovery plan named an assessment other than the supplied assessment.
    #[error("governed recovery plan does not bind the supplied assessment")]
    RecoveryAssessmentMismatch,
    /// Witness sequence overflowed.
    #[error("witness sequence overflow")]
    WitnessSequenceOverflow,
    /// Candidate witness sequence was not exact previous + 1.
    #[error("candidate witness sequence mismatch")]
    WitnessSequenceMismatch,
    /// Candidate did not commit the exact previous signed witness.
    #[error("candidate previous-witness digest mismatch")]
    PreviousWitnessDigestMismatch,
    /// Witness timestamp moved backward across the transition.
    #[error("witness timestamp regressed")]
    WitnessTimestampRegressed,
    /// External retention timestamp moved backward.
    #[error("retention timestamp regressed")]
    RetentionTimestampRegressed,
    /// Transition record predates candidate external retention.
    #[error("governed transition record predates candidate retention")]
    TransitionPredatesCandidateRetention,
    /// Ledger key changed but no dual-signed `LedgerKeyTransition` was supplied.
    #[error("ledger key rotation requires dual-signed ledger key transition evidence")]
    MissingLedgerKeyTransition,
    /// Ledger key stayed the same but a key-transition artifact was supplied.
    #[error("ledger key transition evidence supplied without a key change")]
    UnexpectedLedgerKeyTransition,
    /// Key-transition artifact does not finalize the exact retained previous checkpoint.
    #[error("ledger key transition previous checkpoint does not match retained previous state")]
    LedgerTransitionPreviousCheckpointMismatch,
    /// Store identity/generation changed without governed recovery evidence.
    #[error("store transition requires governed recovery evidence")]
    MissingGovernedRecoveryEvidence,
    /// Store did not change but recovery transition evidence was supplied.
    #[error("governed store recovery evidence supplied without a store transition")]
    UnexpectedGovernedRecoveryEvidence,
    /// Deployment recovery authority did not authenticate the plan approval.
    #[error("recovery plan approval was not authenticated by the configured trust path")]
    RecoveryApprovalNotAuthenticated,
    /// Same store/generation attempted to change operation authority epoch without supported proof.
    #[error("authority epoch changed without a supported governed store transition")]
    UnprovenAuthorityEpochChange,
    /// Same-generation frontier checkpoint moved backward.
    #[error("operation frontier checkpoint regressed without a generation transition")]
    FrontierCheckpointRegressed,
    /// Same-generation frontier reused a checkpoint sequence with a different digest.
    #[error("operation frontier fork at same checkpoint")]
    FrontierForkAtSameCheckpoint,
    /// No ledger-key or store discontinuity exists; ordinary witness succession should be used.
    #[error("no governed discontinuity exists; use ordinary witness succession")]
    NoGovernedDiscontinuity,
    /// Current seconds could not be represented in milliseconds.
    #[error("current time overflow")]
    CurrentTimeOverflow,
}

fn validate_epoch_store_binding(
    bundle: &RetainedOperationFrontierWitnessBundleV1,
    epoch: &OperationAuthorityEpochV1,
) -> Result<(), GovernedTransitionError> {
    let anchor = &bundle.witness.payload.frontier_anchor;
    if epoch.store_id != anchor.store_id || epoch.store_generation != anchor.generation {
        return Err(GovernedTransitionError::AuthorityEpochStoreBindingMismatch);
    }
    Ok(())
}

fn authority_state_message(
    bundle: &RetainedOperationFrontierWitnessBundleV1,
    epoch: &OperationAuthorityEpochV1,
) -> Result<Vec<u8>, GovernedTransitionError> {
    let bundle_bytes = bundle.canonical_bytes()?;
    let epoch_bytes = epoch.canonical_bytes()?;
    let mut message = Vec::with_capacity(
        OPERATION_AUTHORITY_STATE_MESSAGE_DOMAIN_V1.len()
            + 16
            + bundle_bytes.len()
            + epoch_bytes.len(),
    );
    message.extend_from_slice(OPERATION_AUTHORITY_STATE_MESSAGE_DOMAIN_V1);
    message.extend_from_slice(&(bundle_bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(&bundle_bytes);
    message.extend_from_slice(&(epoch_bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(&epoch_bytes);
    Ok(message)
}

fn historical_freshness(policy: CheckpointFreshnessPolicy) -> CheckpointFreshnessPolicy {
    CheckpointFreshnessPolicy {
        max_age_secs: None,
        max_future_skew_secs: policy.max_future_skew_secs,
    }
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
    use uuid::Uuid;
    use xenia_ledger::{
        Chain, ConsentEventRecord, ConsentKind, LedgerCheckpoint, checkpoint_fingerprint,
    };
    use xenia_operation_authority_epoch::{
        AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1,
    };
    use xenia_operation_frontier_ledger_witness::{
        LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
        OperationFrontierLedgerWitnessV1,
    };
    use xenia_operation_store_frontier::OperationStoreFrontierV1;
    use xenia_operation_store_recovery::{
        RECOVERY_ASSESSMENT_SCHEMA_V1, RECOVERY_PLAN_SCHEMA_V1, RecoveryCheckKindV1,
        RecoveryCheckStatusV1, RecoveryCheckV1, RecoveryDispositionV1,
    };

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn append_event(chain: &mut Chain, request: u128, kind: ConsentKind) {
        chain
            .append(ConsentEventRecord {
                source_id: [1u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(request),
                kind,
                scope: "governed-transition-test".to_string(),
            })
            .unwrap();
    }

    fn frontier(
        generation: u64,
        sequence: u64,
        previous: [u8; 32],
        time_ms: u64,
    ) -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            [7u8; 16],
            generation,
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
        signing_key: &SigningKey,
        checkpoint: &LedgerCheckpoint,
        frontier: &OperationStoreFrontierV1,
        sequence: u64,
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
                sequence,
                previous_witness_digest,
                time_ms,
            )
            .unwrap(),
            signing_key,
        )
        .unwrap()
    }

    fn state(
        signing_key: &SigningKey,
        checkpoint: LedgerCheckpoint,
        frontier: &OperationStoreFrontierV1,
        witness_sequence: u64,
        previous_witness_digest: [u8; 32],
        time_ms: u64,
        epoch: OperationAuthorityEpochV1,
    ) -> RetainedOperationAuthorityStateV1 {
        let retained = RetainedOperationFrontierWitnessBundleV1::new(
            witness(
                signing_key,
                &checkpoint,
                frontier,
                witness_sequence,
                previous_witness_digest,
                time_ms,
            ),
            checkpoint,
            time_ms,
        )
        .unwrap();
        RetainedOperationAuthorityStateV1::sign_ed25519(retained, epoch, signing_key).unwrap()
    }

    fn genesis_epoch() -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: [1u8; 16],
            epoch_id: [2u8; 16],
            epoch_sequence: 0,
            previous_epoch_digest: [0u8; 32],
            store_id: [7u8; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::Genesis,
            established_at_unix_ms: 1_000,
        }
    }

    fn recovery_for_rollover(
        current: &OperationAuthorityEpochV1,
        authorized_at_ms: u64,
    ) -> (GovernedStoreTransitionEvidenceV1, OperationAuthorityEpochV1) {
        let assessment = OperationStoreRecoveryAssessmentV1 {
            schema: RECOVERY_ASSESSMENT_SCHEMA_V1.to_string(),
            assessment_id: [11u8; 16],
            authority_domain_id: current.authority_domain_id,
            current_authority_epoch_digest: current.epoch_digest().unwrap(),
            store_id: current.store_id,
            store_generation: current.store_generation,
            checks: vec![RecoveryCheckV1 {
                kind: RecoveryCheckKindV1::FrontierAnchorContinuity,
                status: RecoveryCheckStatusV1::Passed,
                evidence_digest: [12u8; 32],
            }],
            assessed_at_unix_ms: authorized_at_ms - 1,
        };
        let next_epoch_id = [13u8; 16];
        let plan = OperationStoreRecoveryPlanV1 {
            schema: RECOVERY_PLAN_SCHEMA_V1.to_string(),
            plan_id: [14u8; 16],
            assessment_digest: assessment.assessment_digest().unwrap(),
            current_authority_epoch_digest: current.epoch_digest().unwrap(),
            recovery_policy_digest: [15u8; 32],
            approval_digest: [16u8; 32],
            required_checks: vec![RecoveryCheckKindV1::FrontierAnchorContinuity],
            disposition: RecoveryDispositionV1::AdvanceStoreGenerationAndEpoch {
                next_epoch_id,
                next_store_generation: current.store_generation + 1,
            },
            authorized_at_unix_ms: authorized_at_ms,
            expires_at_unix_ms: authorized_at_ms + 60_000,
        };
        let next = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: current.authority_domain_id,
            epoch_id: next_epoch_id,
            epoch_sequence: current.epoch_sequence + 1,
            previous_epoch_digest: current.epoch_digest().unwrap(),
            store_id: current.store_id,
            store_generation: current.store_generation + 1,
            reason: AuthorityEpochReasonV1::RecoveryGenerationRollover {
                recovery_decision_digest: plan.plan_digest().unwrap(),
            },
            established_at_unix_ms: authorized_at_ms + 1,
        };
        (
            GovernedStoreTransitionEvidenceV1 { assessment, plan },
            next,
        )
    }

    fn policy() -> CheckpointFreshnessPolicy {
        CheckpointFreshnessPolicy {
            max_age_secs: Some(1_000),
            max_future_skew_secs: 10,
        }
    }

    #[test]
    fn dual_signed_ledger_key_rotation_preserves_same_operation_epoch() {
        let old_key = key(3);
        let new_key = key(4);
        let mut old_chain = Chain::new(old_key.clone());
        append_event(&mut old_chain, 2, ConsentKind::Approval);
        let old_checkpoint = old_chain.sign_checkpoint(100);
        let f0 = frontier(0, 0, [0u8; 32], 100_000);
        let epoch = genesis_epoch();
        let previous = state(&old_key, old_checkpoint.clone(), &f0, 0, [0u8; 32], 100_000, epoch.clone());

        let key_transition = LedgerKeyTransition::sign(
            old_checkpoint,
            &old_key,
            &new_key,
            101,
        )
        .unwrap();
        let mut new_chain = Chain::new(new_key.clone());
        append_event(&mut new_chain, 3, ConsentKind::Approval);
        let new_checkpoint = new_chain.sign_checkpoint(102);
        let f1 = frontier(0, 1, f0.frontier_digest().unwrap(), 102_000);
        let candidate = state(
            &new_key,
            new_checkpoint,
            &f1,
            1,
            previous.retained_bundle.witness.witness_digest().unwrap(),
            102_000,
            epoch,
        );
        let transition = GovernedOperationAuthorityTransitionV1::new(
            previous,
            candidate,
            Some(key_transition),
            None,
            103_000,
        )
        .unwrap();

        let verified = verify_governed_operation_authority_transition_v1(
            &transition,
            &old_chain.iter().cloned().collect::<Vec<_>>(),
            &new_chain.iter().cloned().collect::<Vec<_>>(),
            old_key.verifying_key().to_bytes(),
            std::slice::from_ref(&f0),
            &[f0, f1],
            103,
            policy(),
            |_, _| false,
        )
        .unwrap();
        assert!(verified.ledger_key_rotated());
        assert!(!verified.store_transitioned());
    }

    #[test]
    fn store_generation_rollover_requires_live_approved_recovery_plan() {
        let signing_key = key(3);
        let mut chain = Chain::new(signing_key.clone());
        append_event(&mut chain, 2, ConsentKind::Approval);
        let checkpoint0 = chain.sign_checkpoint(100);
        let f0 = frontier(0, 0, [0u8; 32], 100_000);
        let epoch0 = genesis_epoch();
        let previous = state(&signing_key, checkpoint0, &f0, 0, [0u8; 32], 100_000, epoch0.clone());

        append_event(&mut chain, 3, ConsentKind::Revocation);
        let checkpoint1 = chain.sign_checkpoint(201);
        let (recovery, epoch1) = recovery_for_rollover(&epoch0, 200_000);
        let f1 = frontier(1, 0, [0u8; 32], 201_000);
        let candidate = state(
            &signing_key,
            checkpoint1,
            &f1,
            1,
            previous.retained_bundle.witness.witness_digest().unwrap(),
            201_000,
            epoch1,
        );
        let transition = GovernedOperationAuthorityTransitionV1::new(
            previous,
            candidate,
            None,
            Some(recovery),
            202_000,
        )
        .unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();

        let verified = verify_governed_operation_authority_transition_v1(
            &transition,
            &entries,
            &entries,
            signing_key.verifying_key().to_bytes(),
            std::slice::from_ref(&f0),
            std::slice::from_ref(&f1),
            202,
            policy(),
            |assessment, plan| {
                plan.approval_digest == [16u8; 32]
                    && plan.assessment_digest == assessment.assessment_digest().unwrap()
            },
        )
        .unwrap();
        assert!(!verified.ledger_key_rotated());
        assert!(verified.store_transitioned());
    }

    #[test]
    fn unauthenticated_recovery_approval_cannot_bless_generation_change() {
        let signing_key = key(3);
        let mut chain = Chain::new(signing_key.clone());
        append_event(&mut chain, 2, ConsentKind::Approval);
        let checkpoint0 = chain.sign_checkpoint(100);
        let f0 = frontier(0, 0, [0u8; 32], 100_000);
        let epoch0 = genesis_epoch();
        let previous = state(&signing_key, checkpoint0, &f0, 0, [0u8; 32], 100_000, epoch0.clone());
        append_event(&mut chain, 3, ConsentKind::Revocation);
        let checkpoint1 = chain.sign_checkpoint(201);
        let (recovery, epoch1) = recovery_for_rollover(&epoch0, 200_000);
        let f1 = frontier(1, 0, [0u8; 32], 201_000);
        let candidate = state(
            &signing_key,
            checkpoint1,
            &f1,
            1,
            previous.retained_bundle.witness.witness_digest().unwrap(),
            201_000,
            epoch1,
        );
        let transition = GovernedOperationAuthorityTransitionV1::new(
            previous,
            candidate,
            None,
            Some(recovery),
            202_000,
        )
        .unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        assert!(matches!(
            verify_governed_operation_authority_transition_v1(
                &transition,
                &entries,
                &entries,
                signing_key.verifying_key().to_bytes(),
                std::slice::from_ref(&f0),
                std::slice::from_ref(&f1),
                202,
                policy(),
                |_, _| false,
            ),
            Err(GovernedTransitionError::RecoveryApprovalNotAuthenticated)
        ));
    }

    #[test]
    fn ledger_key_change_without_dual_signed_handover_fails() {
        let old_key = key(3);
        let new_key = key(4);
        let mut old_chain = Chain::new(old_key.clone());
        append_event(&mut old_chain, 2, ConsentKind::Approval);
        let old_checkpoint = old_chain.sign_checkpoint(100);
        let f0 = frontier(0, 0, [0u8; 32], 100_000);
        let epoch = genesis_epoch();
        let previous = state(&old_key, old_checkpoint, &f0, 0, [0u8; 32], 100_000, epoch.clone());
        let mut new_chain = Chain::new(new_key.clone());
        append_event(&mut new_chain, 3, ConsentKind::Approval);
        let checkpoint1 = new_chain.sign_checkpoint(102);
        let f1 = frontier(0, 1, f0.frontier_digest().unwrap(), 102_000);
        let candidate = state(
            &new_key,
            checkpoint1,
            &f1,
            1,
            previous.retained_bundle.witness.witness_digest().unwrap(),
            102_000,
            epoch,
        );
        let transition = GovernedOperationAuthorityTransitionV1::new(
            previous,
            candidate,
            None,
            None,
            103_000,
        )
        .unwrap();
        assert!(matches!(
            verify_governed_operation_authority_transition_v1(
                &transition,
                &old_chain.iter().cloned().collect::<Vec<_>>(),
                &new_chain.iter().cloned().collect::<Vec<_>>(),
                old_key.verifying_key().to_bytes(),
                std::slice::from_ref(&f0),
                &[f0, f1],
                103,
                policy(),
                |_, _| false,
            ),
            Err(GovernedTransitionError::MissingLedgerKeyTransition)
        ));
    }

    #[test]
    fn same_store_epoch_change_without_supported_transition_is_rejected() {
        let signing_key = key(3);
        let mut chain = Chain::new(signing_key.clone());
        append_event(&mut chain, 2, ConsentKind::Approval);
        let checkpoint0 = chain.sign_checkpoint(100);
        let f0 = frontier(0, 0, [0u8; 32], 100_000);
        let epoch0 = genesis_epoch();
        let previous = state(&signing_key, checkpoint0, &f0, 0, [0u8; 32], 100_000, epoch0.clone());
        append_event(&mut chain, 3, ConsentKind::Revocation);
        let checkpoint1 = chain.sign_checkpoint(101);
        let f1 = frontier(0, 1, f0.frontier_digest().unwrap(), 101_000);
        let epoch1 = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: epoch0.authority_domain_id,
            epoch_id: [20u8; 16],
            epoch_sequence: 1,
            previous_epoch_digest: epoch0.epoch_digest().unwrap(),
            store_id: epoch0.store_id,
            store_generation: epoch0.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: [21u8; 32],
            },
            established_at_unix_ms: 100_500,
        };
        let candidate = state(
            &signing_key,
            checkpoint1,
            &f1,
            1,
            previous.retained_bundle.witness.witness_digest().unwrap(),
            101_000,
            epoch1,
        );
        let transition = GovernedOperationAuthorityTransitionV1::new(
            previous,
            candidate,
            None,
            None,
            102_000,
        )
        .unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        assert!(matches!(
            verify_governed_operation_authority_transition_v1(
                &transition,
                &entries,
                &entries,
                signing_key.verifying_key().to_bytes(),
                std::slice::from_ref(&f0),
                &[f0, f1],
                102,
                policy(),
                |_, _| false,
            ),
            Err(GovernedTransitionError::UnprovenAuthorityEpochChange)
        ));
    }
}
