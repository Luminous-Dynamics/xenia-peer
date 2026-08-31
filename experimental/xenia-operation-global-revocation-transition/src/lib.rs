// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authenticated same-store global-revocation transitions for Xenia operation authority.
//!
//! A global revocation changes the operation-authority epoch while preserving the ledger key and
//! operation-store identity/generation. V1 separates the short-lived **application** decision from
//! durable **historical** verification: a live, externally approved revocation intent is verified
//! against the exact retained predecessor/candidate state; the ledger authority can then sign a
//! transition receipt. Years later recovery verifies the receipt was created inside the original
//! decision window rather than incorrectly requiring that short-lived decision to still be live.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use xenia_ledger::{CheckpointFreshnessPolicy, LedgerEntry};
use xenia_operation_authority_epoch::{
    AuthorityEpochError, AuthorityEpochReasonV1, OperationAuthorityEpochV1,
};
use xenia_operation_frontier_governed_transition::{
    GovernedTransitionError, RetainedOperationAuthorityStateV1,
};
use xenia_operation_frontier_retention_bundle::{
    RetainedWitnessBundleError, verify_retained_operation_frontier_bundle_successor_v1,
};
use xenia_operation_store_frontier::OperationStoreFrontierV1;

/// Exact schema for the approval-independent revocation intent.
pub const GLOBAL_REVOCATION_INTENT_SCHEMA_V1: &str =
    "xenia-operation-global-revocation-intent-v1";
/// Exact schema for an externally approved decision.
pub const GLOBAL_REVOCATION_DECISION_SCHEMA_V1: &str =
    "xenia-operation-global-revocation-decision-v1";
/// Exact schema for the signed historical transition receipt.
pub const GLOBAL_REVOCATION_TRANSITION_RECEIPT_SCHEMA_V1: &str =
    "xenia-operation-global-revocation-transition-receipt-v1";
/// Domain separator for intent commitments authenticated by the external approval path.
pub const GLOBAL_REVOCATION_INTENT_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-global-revocation-intent-digest-v1";
/// Domain separator for complete approved-decision commitments embedded by the successor epoch.
pub const GLOBAL_REVOCATION_DECISION_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-global-revocation-decision-digest-v1";
/// Domain separator for the ledger-signed historical receipt message.
pub const GLOBAL_REVOCATION_TRANSITION_RECEIPT_MESSAGE_DOMAIN_V1: &[u8] =
    b"xenia-operation-global-revocation-transition-receipt-message-v1";
/// Domain separator for exact signed receipt commitments.
pub const GLOBAL_REVOCATION_TRANSITION_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-global-revocation-transition-receipt-digest-v1";
/// Maximum time a prepared revocation decision remains applicable: 15 minutes.
pub const MAX_GLOBAL_REVOCATION_DECISION_LIFETIME_MS_V1: u64 = 15 * 60 * 1_000;

/// The only V1 revocation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlobalRevocationScopeV1 {
    /// Invalidate every outstanding privileged-operation authority object bound to the old epoch.
    AllOutstandingPrivilegedOperationAuthority,
}

/// Approval-independent intent that an external emergency/policy authority must authenticate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRevocationIntentV1 {
    /// Exact schema label.
    pub schema: String,
    /// Unique intent/decision identity.
    pub decision_id: [u8; 16],
    /// Exact operation-authority domain being invalidated.
    pub authority_domain_id: [u8; 16],
    /// Exact predecessor authority epoch commitment the decision may revoke.
    pub previous_authority_epoch_digest: [u8; 32],
    /// Fixed V1 global scope.
    pub scope: GlobalRevocationScopeV1,
    /// Exact policy revision governing the emergency revocation.
    pub revocation_policy_digest: [u8; 32],
    /// Privacy-preserving commitment to operator rationale / incident evidence.
    pub rationale_digest: [u8; 32],
    /// Trusted-enough authorization-window start in Unix milliseconds.
    pub authorized_at_unix_ms: u64,
    /// Exclusive hard expiry for applying this intent.
    pub expires_at_unix_ms: u64,
}

impl GlobalRevocationIntentV1 {
    /// Validate canonical intent syntax.
    pub fn validate(&self) -> Result<(), GlobalRevocationTransitionError> {
        if self.schema != GLOBAL_REVOCATION_INTENT_SCHEMA_V1 {
            return Err(GlobalRevocationTransitionError::UnsupportedIntentSchema);
        }
        if self.decision_id == [0u8; 16] {
            return Err(GlobalRevocationTransitionError::ZeroDecisionId);
        }
        if self.authority_domain_id == [0u8; 16] {
            return Err(GlobalRevocationTransitionError::ZeroAuthorityDomainId);
        }
        require_nonzero32(
            self.previous_authority_epoch_digest,
            GlobalRevocationTransitionError::ZeroPreviousEpochDigest,
        )?;
        require_nonzero32(
            self.revocation_policy_digest,
            GlobalRevocationTransitionError::ZeroPolicyDigest,
        )?;
        require_nonzero32(
            self.rationale_digest,
            GlobalRevocationTransitionError::ZeroRationaleDigest,
        )?;
        if self.expires_at_unix_ms <= self.authorized_at_unix_ms {
            return Err(GlobalRevocationTransitionError::InvalidDecisionWindow);
        }
        if self.expires_at_unix_ms - self.authorized_at_unix_ms
            > MAX_GLOBAL_REVOCATION_DECISION_LIFETIME_MS_V1
        {
            return Err(GlobalRevocationTransitionError::DecisionLifetimeTooLong);
        }
        Ok(())
    }

    /// Require the intent to be live at an application time.
    pub fn require_live_at(&self, now_unix_ms: u64) -> Result<(), GlobalRevocationTransitionError> {
        self.validate()?;
        if now_unix_ms < self.authorized_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(GlobalRevocationTransitionError::DecisionNotLive);
        }
        Ok(())
    }

    /// Canonical intent bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GlobalRevocationTransitionError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable intent commitment the external approval path must authenticate.
    pub fn intent_digest(&self) -> Result<[u8; 32], GlobalRevocationTransitionError> {
        Ok(domain_digest(
            GLOBAL_REVOCATION_INTENT_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Externally approved global-revocation decision.
///
/// `approval_digest` must authenticate the exact [`GlobalRevocationIntentV1::intent_digest`]
/// through a deployment-owned policy/emergency authority. It does not authenticate itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRevocationDecisionV1 {
    /// Exact decision schema.
    pub schema: String,
    /// Exact approval-independent intent.
    pub intent: GlobalRevocationIntentV1,
    /// Commitment to the external approval artifact for that exact intent digest.
    pub approval_digest: [u8; 32],
}

impl GlobalRevocationDecisionV1 {
    /// Validate local syntax without authenticating the approval.
    pub fn validate(&self) -> Result<(), GlobalRevocationTransitionError> {
        if self.schema != GLOBAL_REVOCATION_DECISION_SCHEMA_V1 {
            return Err(GlobalRevocationTransitionError::UnsupportedDecisionSchema);
        }
        self.intent.validate()?;
        require_nonzero32(
            self.approval_digest,
            GlobalRevocationTransitionError::ZeroApprovalDigest,
        )
    }

    /// Require the decision intent to be live at an application time.
    pub fn require_live_at(&self, now_unix_ms: u64) -> Result<(), GlobalRevocationTransitionError> {
        self.validate()?;
        self.intent.require_live_at(now_unix_ms)
    }

    /// Canonical complete approved-decision bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GlobalRevocationTransitionError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable complete decision commitment embedded by the successor epoch.
    pub fn decision_digest(&self) -> Result<[u8; 32], GlobalRevocationTransitionError> {
        Ok(domain_digest(
            GLOBAL_REVOCATION_DECISION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Successful application-time verification of one global revocation transition.
///
/// Private, non-serializable fields prevent serialized evidence from manufacturing an approval
/// result. A receipt can be signed only from this verified token inside this crate's API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedGlobalRevocationTransitionV1 {
    decision_digest: [u8; 32],
    previous_epoch_digest: [u8; 32],
    candidate_epoch_digest: [u8; 32],
    previous_state_digest: [u8; 32],
    candidate_state_digest: [u8; 32],
    witness_digest: [u8; 32],
    ledger_public_key: [u8; 32],
    verified_at_unix_ms: u64,
}

impl VerifiedGlobalRevocationTransitionV1 {
    /// Exact authenticated decision commitment.
    pub const fn decision_digest(self) -> [u8; 32] {
        self.decision_digest
    }
    /// Exact revoked predecessor epoch commitment.
    pub const fn previous_epoch_digest(self) -> [u8; 32] {
        self.previous_epoch_digest
    }
    /// Exact candidate global-revocation epoch commitment.
    pub const fn candidate_epoch_digest(self) -> [u8; 32] {
        self.candidate_epoch_digest
    }
    /// Exact candidate retained-authority-state commitment.
    pub const fn candidate_state_digest(self) -> [u8; 32] {
        self.candidate_state_digest
    }
    /// Exact candidate witness commitment.
    pub const fn witness_digest(self) -> [u8; 32] {
        self.witness_digest
    }
    /// Application-time verification time retained by the signed receipt.
    pub const fn verified_at_unix_ms(self) -> u64 {
        self.verified_at_unix_ms
    }
}

/// Signed durable evidence that one exact revocation transition passed the live application gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRevocationTransitionReceiptV1 {
    /// Exact receipt schema.
    pub schema: String,
    /// Exact approved decision whose digest is embedded by the candidate epoch.
    pub decision: GlobalRevocationDecisionV1,
    /// Exact previous retained-authority-state commitment.
    pub previous_state_digest: [u8; 32],
    /// Exact candidate retained-authority-state commitment.
    pub candidate_state_digest: [u8; 32],
    /// Exact candidate authority-epoch commitment.
    pub candidate_epoch_digest: [u8; 32],
    /// Exact candidate frontier-witness commitment.
    pub witness_digest: [u8; 32],
    /// Time the live application verifier succeeded.
    pub verified_at_unix_ms: u64,
    /// Ledger public key that signed this receipt.
    pub ledger_public_key: [u8; 32],
    /// Signature under the same ledger authority that signs the retained candidate state.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl GlobalRevocationTransitionReceiptV1 {
    /// Create a durable receipt only after successful live verification.
    pub fn sign_after_verification(
        decision: GlobalRevocationDecisionV1,
        verified: VerifiedGlobalRevocationTransitionV1,
        signing_key: &SigningKey,
    ) -> Result<Self, GlobalRevocationTransitionError> {
        decision.validate()?;
        if decision.decision_digest()? != verified.decision_digest {
            return Err(GlobalRevocationTransitionError::ReceiptDecisionMismatch);
        }
        let ledger_public_key = signing_key.verifying_key().to_bytes();
        if ledger_public_key != verified.ledger_public_key {
            return Err(GlobalRevocationTransitionError::ReceiptSigningKeyMismatch);
        }
        let mut value = Self {
            schema: GLOBAL_REVOCATION_TRANSITION_RECEIPT_SCHEMA_V1.to_string(),
            decision,
            previous_state_digest: verified.previous_state_digest,
            candidate_state_digest: verified.candidate_state_digest,
            candidate_epoch_digest: verified.candidate_epoch_digest,
            witness_digest: verified.witness_digest,
            verified_at_unix_ms: verified.verified_at_unix_ms,
            ledger_public_key,
            signature: [0u8; 64],
        };
        value.signature = signing_key.sign(&receipt_message(&value)?).to_bytes();
        value.validate_local()?;
        Ok(value)
    }

    /// Validate receipt syntax, decision window, and ledger signature without authenticating the
    /// external approval or recovered ledger/frontier history.
    pub fn validate_local(&self) -> Result<(), GlobalRevocationTransitionError> {
        if self.schema != GLOBAL_REVOCATION_TRANSITION_RECEIPT_SCHEMA_V1 {
            return Err(GlobalRevocationTransitionError::UnsupportedReceiptSchema);
        }
        self.decision.validate()?;
        if self.verified_at_unix_ms < self.decision.intent.authorized_at_unix_ms
            || self.verified_at_unix_ms >= self.decision.intent.expires_at_unix_ms
        {
            return Err(GlobalRevocationTransitionError::ReceiptOutsideDecisionWindow);
        }
        let key = VerifyingKey::from_bytes(&self.ledger_public_key)
            .map_err(|_| GlobalRevocationTransitionError::MalformedLedgerKey)?;
        key.verify(
            &receipt_message(self)?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| GlobalRevocationTransitionError::BadReceiptSignature)
    }

    /// Canonical signed receipt bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GlobalRevocationTransitionError> {
        self.validate_local()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable exact receipt commitment for append-only external retention.
    pub fn receipt_digest(&self) -> Result<[u8; 32], GlobalRevocationTransitionError> {
        Ok(domain_digest(
            GLOBAL_REVOCATION_TRANSITION_RECEIPT_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Verify a global revocation while its short-lived decision is still live.
///
/// `verify_revocation_approval` must authenticate `approval_digest` as approval of the exact
/// `intent_digest`. This function does not mutate the epoch/store and does not itself revoke
/// anything; it proves the supplied candidate state is the exact permitted successor.
#[allow(clippy::too_many_arguments)]
pub fn verify_global_revocation_transition_v1(
    previous: &RetainedOperationAuthorityStateV1,
    candidate: &RetainedOperationAuthorityStateV1,
    decision: &GlobalRevocationDecisionV1,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
    verify_revocation_approval: impl FnOnce([u8; 32], [u8; 32]) -> bool,
) -> Result<VerifiedGlobalRevocationTransitionV1, GlobalRevocationTransitionError> {
    let now_unix_ms = now_unix_secs
        .checked_mul(1_000)
        .ok_or(GlobalRevocationTransitionError::CurrentTimeOverflow)?;
    decision.require_live_at(now_unix_ms)?;
    verify_transition_common(
        previous,
        candidate,
        decision,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        freshness_policy,
        true,
        verify_revocation_approval,
    )
    .map(|common| VerifiedGlobalRevocationTransitionV1 {
        decision_digest: common.decision_digest,
        previous_epoch_digest: common.previous_epoch_digest,
        candidate_epoch_digest: common.candidate_epoch_digest,
        previous_state_digest: common.previous_state_digest,
        candidate_state_digest: common.candidate_state_digest,
        witness_digest: common.witness_digest,
        ledger_public_key: common.ledger_public_key,
        verified_at_unix_ms: now_unix_ms,
    })
}

/// Verify a retained signed receipt long after the original application window expired.
///
/// Historical verification re-authenticates the external approval and complete signed
/// ledger/frontier/epoch lineage, but does **not** require the short-lived decision to be live at
/// `now`. Instead the signed receipt must prove the live verifier succeeded inside that window.
#[allow(clippy::too_many_arguments)]
pub fn verify_retained_global_revocation_transition_v1(
    receipt: &GlobalRevocationTransitionReceiptV1,
    previous: &RetainedOperationAuthorityStateV1,
    candidate: &RetainedOperationAuthorityStateV1,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    future_skew_secs: u64,
    verify_revocation_approval: impl FnOnce([u8; 32], [u8; 32]) -> bool,
) -> Result<VerifiedGlobalRevocationTransitionV1, GlobalRevocationTransitionError> {
    receipt.validate_local()?;
    let historical_policy = CheckpointFreshnessPolicy {
        max_age_secs: None,
        max_future_skew_secs: future_skew_secs,
    };
    let common = verify_transition_common(
        previous,
        candidate,
        &receipt.decision,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        historical_policy,
        false,
        verify_revocation_approval,
    )?;

    if receipt.previous_state_digest != common.previous_state_digest
        || receipt.candidate_state_digest != common.candidate_state_digest
        || receipt.candidate_epoch_digest != common.candidate_epoch_digest
        || receipt.witness_digest != common.witness_digest
        || receipt.ledger_public_key != common.ledger_public_key
    {
        return Err(GlobalRevocationTransitionError::ReceiptEvidenceMismatch);
    }
    if receipt.decision.decision_digest()? != common.decision_digest {
        return Err(GlobalRevocationTransitionError::ReceiptDecisionMismatch);
    }
    if candidate.authority_epoch.established_at_unix_ms > receipt.verified_at_unix_ms {
        return Err(GlobalRevocationTransitionError::ReceiptPredatesCandidateEpoch);
    }

    Ok(VerifiedGlobalRevocationTransitionV1 {
        decision_digest: common.decision_digest,
        previous_epoch_digest: common.previous_epoch_digest,
        candidate_epoch_digest: common.candidate_epoch_digest,
        previous_state_digest: common.previous_state_digest,
        candidate_state_digest: common.candidate_state_digest,
        witness_digest: common.witness_digest,
        ledger_public_key: common.ledger_public_key,
        verified_at_unix_ms: receipt.verified_at_unix_ms,
    })
}

struct CommonVerifiedTransition {
    decision_digest: [u8; 32],
    previous_epoch_digest: [u8; 32],
    candidate_epoch_digest: [u8; 32],
    previous_state_digest: [u8; 32],
    candidate_state_digest: [u8; 32],
    witness_digest: [u8; 32],
    ledger_public_key: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn verify_transition_common(
    previous: &RetainedOperationAuthorityStateV1,
    candidate: &RetainedOperationAuthorityStateV1,
    decision: &GlobalRevocationDecisionV1,
    ledger_entries: &[LedgerEntry],
    trusted_ledger_public_key: [u8; 32],
    local_frontiers: &[OperationStoreFrontierV1],
    now_unix_secs: u64,
    freshness_policy: CheckpointFreshnessPolicy,
    require_live_now: bool,
    verify_revocation_approval: impl FnOnce([u8; 32], [u8; 32]) -> bool,
) -> Result<CommonVerifiedTransition, GlobalRevocationTransitionError> {
    previous.validate_local()?;
    candidate.validate_local()?;
    decision.validate()?;

    let now_unix_ms = now_unix_secs
        .checked_mul(1_000)
        .ok_or(GlobalRevocationTransitionError::CurrentTimeOverflow)?;
    if require_live_now {
        decision.require_live_at(now_unix_ms)?;
    }

    let previous_epoch_digest = previous.authority_epoch.epoch_digest()?;
    if decision.intent.authority_domain_id != previous.authority_epoch.authority_domain_id {
        return Err(GlobalRevocationTransitionError::AuthorityDomainMismatch);
    }
    if decision.intent.previous_authority_epoch_digest != previous_epoch_digest {
        return Err(GlobalRevocationTransitionError::PreviousEpochMismatch);
    }

    let intent_digest = decision.intent.intent_digest()?;
    if !verify_revocation_approval(intent_digest, decision.approval_digest) {
        return Err(GlobalRevocationTransitionError::RevocationApprovalNotAuthenticated);
    }

    let verified_witness = verify_retained_operation_frontier_bundle_successor_v1(
        &previous.retained_bundle,
        &candidate.retained_bundle,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        freshness_policy,
    )?;

    candidate.authority_epoch.validate_successor(&previous.authority_epoch)?;
    let decision_digest = decision.decision_digest()?;
    match &candidate.authority_epoch.reason {
        AuthorityEpochReasonV1::GlobalRevocation {
            revocation_decision_digest,
        } if *revocation_decision_digest == decision_digest => {}
        AuthorityEpochReasonV1::GlobalRevocation { .. } => {
            return Err(GlobalRevocationTransitionError::DecisionDigestMismatch);
        }
        _ => return Err(GlobalRevocationTransitionError::CandidateIsNotGlobalRevocation),
    }

    if candidate.authority_epoch.established_at_unix_ms < decision.intent.authorized_at_unix_ms
        || candidate.authority_epoch.established_at_unix_ms >= decision.intent.expires_at_unix_ms
    {
        return Err(GlobalRevocationTransitionError::EpochEstablishedOutsideDecisionWindow);
    }

    let maximum_future_ms = freshness_policy
        .max_future_skew_secs
        .checked_mul(1_000)
        .and_then(|skew| now_unix_ms.checked_add(skew))
        .ok_or(GlobalRevocationTransitionError::CurrentTimeOverflow)?;
    if candidate.authority_epoch.established_at_unix_ms > maximum_future_ms {
        return Err(GlobalRevocationTransitionError::CandidateEpochTooFarInFuture);
    }

    let ledger_public_key = candidate.retained_bundle.ledger_checkpoint.ledger_public_key;
    if ledger_public_key != previous.retained_bundle.ledger_checkpoint.ledger_public_key {
        return Err(GlobalRevocationTransitionError::LedgerKeyChanged);
    }

    Ok(CommonVerifiedTransition {
        decision_digest,
        previous_epoch_digest,
        candidate_epoch_digest: candidate.authority_epoch.epoch_digest()?,
        previous_state_digest: previous.state_digest()?,
        candidate_state_digest: candidate.state_digest()?,
        witness_digest: verified_witness.witness_digest(),
        ledger_public_key,
    })
}

/// Fail-closed global-revocation transition errors.
#[derive(Debug, Error)]
pub enum GlobalRevocationTransitionError {
    /// Intent schema mismatch.
    #[error("unsupported global revocation intent schema")]
    UnsupportedIntentSchema,
    /// Decision schema mismatch.
    #[error("unsupported global revocation decision schema")]
    UnsupportedDecisionSchema,
    /// Receipt schema mismatch.
    #[error("unsupported global revocation transition receipt schema")]
    UnsupportedReceiptSchema,
    /// Decision identity is unset.
    #[error("global revocation decision id must not be all zero")]
    ZeroDecisionId,
    /// Authority domain identity is unset.
    #[error("global revocation authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Previous epoch commitment is unset.
    #[error("global revocation intent requires previous authority epoch digest")]
    ZeroPreviousEpochDigest,
    /// Policy commitment is unset.
    #[error("global revocation intent requires policy digest")]
    ZeroPolicyDigest,
    /// Rationale/evidence commitment is unset.
    #[error("global revocation intent requires rationale digest")]
    ZeroRationaleDigest,
    /// Approval commitment is unset.
    #[error("global revocation decision requires approval digest")]
    ZeroApprovalDigest,
    /// Decision window is empty/reversed.
    #[error("global revocation decision window is invalid")]
    InvalidDecisionWindow,
    /// Decision is reusable for longer than the V1 hard bound.
    #[error("global revocation decision lifetime exceeds V1 maximum")]
    DecisionLifetimeTooLong,
    /// Live application occurred outside the decision window.
    #[error("global revocation decision is not live at application time")]
    DecisionNotLive,
    /// Decision authority domain differs from the retained predecessor epoch.
    #[error("global revocation authority domain mismatch")]
    AuthorityDomainMismatch,
    /// Decision commits an epoch other than the exact retained predecessor.
    #[error("global revocation previous authority epoch digest mismatch")]
    PreviousEpochMismatch,
    /// External policy/emergency trust path did not authenticate the exact intent/approval pair.
    #[error("global revocation approval was not authenticated for the exact intent")]
    RevocationApprovalNotAuthenticated,
    /// Successor authority epoch is not a global-revocation reason.
    #[error("candidate authority epoch is not a global revocation")]
    CandidateIsNotGlobalRevocation,
    /// Successor global-revocation reason commits a different approved decision.
    #[error("candidate global-revocation epoch does not commit the exact decision digest")]
    DecisionDigestMismatch,
    /// Candidate authority epoch establishment did not fall inside the decision window.
    #[error("candidate authority epoch was established outside the revocation decision window")]
    EpochEstablishedOutsideDecisionWindow,
    /// Candidate authority epoch timestamp is implausibly far in the future.
    #[error("candidate authority epoch exceeds permitted future clock skew")]
    CandidateEpochTooFarInFuture,
    /// Global revocation attempted to rotate the ledger key.
    #[error("global revocation V1 must preserve the ledger key")]
    LedgerKeyChanged,
    /// Receipt was signed by a key different from the verified candidate ledger key.
    #[error("global revocation receipt signing key mismatch")]
    ReceiptSigningKeyMismatch,
    /// Receipt carries a different decision than the live verified transition.
    #[error("global revocation receipt decision mismatch")]
    ReceiptDecisionMismatch,
    /// Receipt verification timestamp was not inside the original short-lived decision window.
    #[error("global revocation transition receipt is outside the original decision window")]
    ReceiptOutsideDecisionWindow,
    /// Receipt ledger key bytes are malformed.
    #[error("global revocation receipt ledger key is malformed")]
    MalformedLedgerKey,
    /// Receipt signature is invalid.
    #[error("global revocation transition receipt signature is invalid")]
    BadReceiptSignature,
    /// Receipt commitments differ from the independently reverified retained state/lineage.
    #[error("global revocation transition receipt evidence does not match recovered state")]
    ReceiptEvidenceMismatch,
    /// Receipt claims live verification before the candidate epoch existed.
    #[error("global revocation transition receipt predates candidate epoch establishment")]
    ReceiptPredatesCandidateEpoch,
    /// Current time conversion/clock-skew calculation overflowed.
    #[error("current time overflow")]
    CurrentTimeOverflow,
    /// Retained signed authority-state validation failed.
    #[error("retained authority state rejected global revocation: {0}")]
    GovernedState(#[from] GovernedTransitionError),
    /// Ordinary retained witness/checkpoint succession failed.
    #[error("retained frontier lineage rejected global revocation: {0}")]
    RetainedLineage(#[from] RetainedWitnessBundleError),
    /// Authority-epoch successor rules rejected the candidate.
    #[error("authority epoch rejected global revocation: {0}")]
    AuthorityEpoch(#[from] AuthorityEpochError),
    /// Canonical serialization failed.
    #[error("global revocation serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

fn receipt_message(
    receipt: &GlobalRevocationTransitionReceiptV1,
) -> Result<Vec<u8>, GlobalRevocationTransitionError> {
    receipt.decision.validate()?;
    let decision_bytes = receipt.decision.canonical_bytes()?;
    let mut message = Vec::with_capacity(
        GLOBAL_REVOCATION_TRANSITION_RECEIPT_MESSAGE_DOMAIN_V1.len()
            + 8
            + decision_bytes.len()
            + 32 * 5
            + 8,
    );
    message.extend_from_slice(GLOBAL_REVOCATION_TRANSITION_RECEIPT_MESSAGE_DOMAIN_V1);
    message.extend_from_slice(&(decision_bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(&decision_bytes);
    message.extend_from_slice(&receipt.previous_state_digest);
    message.extend_from_slice(&receipt.candidate_state_digest);
    message.extend_from_slice(&receipt.candidate_epoch_digest);
    message.extend_from_slice(&receipt.witness_digest);
    message.extend_from_slice(&receipt.ledger_public_key);
    message.extend_from_slice(&receipt.verified_at_unix_ms.to_be_bytes());
    Ok(message)
}

fn require_nonzero32(
    value: [u8; 32],
    error: GlobalRevocationTransitionError,
) -> Result<(), GlobalRevocationTransitionError> {
    if value == [0u8; 32] { Err(error) } else { Ok(()) }
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
    use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, LedgerCheckpoint, checkpoint_fingerprint};
    use xenia_operation_authority_epoch::OPERATION_AUTHORITY_EPOCH_SCHEMA_V1;
    use xenia_operation_frontier_ledger_witness::{
        LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
        OperationFrontierLedgerWitnessV1,
    };
    use xenia_operation_frontier_retention_bundle::RetainedOperationFrontierWitnessBundleV1;

    fn key(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32]) }

    fn append_event(chain: &mut Chain, request: u128, kind: ConsentKind) {
        chain.append(ConsentEventRecord {
            source_id: [1u8; 32],
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(request),
            kind,
            scope: "global-revocation-test".to_string(),
        }).unwrap();
    }

    fn frontier(sequence: u64, previous: [u8; 32], time_ms: u64) -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            [7u8; 16], 0, sequence, [8u8; 32], previous, time_ms, &[], &[],
        ).unwrap()
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
        ).unwrap();
        OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                frontier.anchor(time_ms).unwrap(), binding, sequence, previous_witness_digest, time_ms,
            ).unwrap(),
            signing_key,
        ).unwrap()
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
        let bundle = RetainedOperationFrontierWitnessBundleV1::new(
            witness(signing_key, &checkpoint, frontier, witness_sequence, previous_witness_digest, time_ms),
            checkpoint,
            time_ms,
        ).unwrap();
        RetainedOperationAuthorityStateV1::sign_ed25519(bundle, epoch, signing_key).unwrap()
    }

    fn epoch0() -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: [1u8; 16],
            epoch_id: [2u8; 16],
            epoch_sequence: 0,
            previous_epoch_digest: [0u8; 32],
            store_id: [7u8; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::Genesis,
            established_at_unix_ms: 100_000,
        }
    }

    fn decision(previous: &OperationAuthorityEpochV1) -> GlobalRevocationDecisionV1 {
        GlobalRevocationDecisionV1 {
            schema: GLOBAL_REVOCATION_DECISION_SCHEMA_V1.to_string(),
            intent: GlobalRevocationIntentV1 {
                schema: GLOBAL_REVOCATION_INTENT_SCHEMA_V1.to_string(),
                decision_id: [20u8; 16],
                authority_domain_id: previous.authority_domain_id,
                previous_authority_epoch_digest: previous.epoch_digest().unwrap(),
                scope: GlobalRevocationScopeV1::AllOutstandingPrivilegedOperationAuthority,
                revocation_policy_digest: [21u8; 32],
                rationale_digest: [23u8; 32],
                authorized_at_unix_ms: 101_000,
                expires_at_unix_ms: 161_000,
            },
            approval_digest: [22u8; 32],
        }
    }

    fn epoch1(previous: &OperationAuthorityEpochV1, decision: &GlobalRevocationDecisionV1) -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: previous.authority_domain_id,
            epoch_id: [3u8; 16],
            epoch_sequence: previous.epoch_sequence + 1,
            previous_epoch_digest: previous.epoch_digest().unwrap(),
            store_id: previous.store_id,
            store_generation: previous.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: decision.decision_digest().unwrap(),
            },
            established_at_unix_ms: 102_000,
        }
    }

    fn policy() -> CheckpointFreshnessPolicy {
        CheckpointFreshnessPolicy { max_age_secs: Some(1_000), max_future_skew_secs: 10 }
    }

    struct Fixture {
        signing_key: SigningKey,
        chain: Chain,
        f0: OperationStoreFrontierV1,
        f1: OperationStoreFrontierV1,
        previous: RetainedOperationAuthorityStateV1,
        candidate: RetainedOperationAuthorityStateV1,
        decision: GlobalRevocationDecisionV1,
    }

    fn fixture() -> Fixture {
        let signing_key = key(3);
        let mut chain = Chain::new(signing_key.clone());
        append_event(&mut chain, 2, ConsentKind::Approval);
        let checkpoint0 = chain.sign_checkpoint(100);
        let f0 = frontier(0, [0u8; 32], 100_000);
        let e0 = epoch0();
        let previous = state(&signing_key, checkpoint0, &f0, 0, [0u8; 32], 100_000, e0.clone());

        let decision = decision(&e0);
        append_event(&mut chain, 3, ConsentKind::Revocation);
        let checkpoint1 = chain.sign_checkpoint(102);
        let f1 = frontier(1, f0.frontier_digest().unwrap(), 102_000);
        let candidate = state(
            &signing_key,
            checkpoint1,
            &f1,
            1,
            previous.retained_bundle.witness.witness_digest().unwrap(),
            102_000,
            epoch1(&e0, &decision),
        );

        Fixture { signing_key, chain, f0, f1, previous, candidate, decision }
    }

    fn approval(intent_digest: [u8; 32], approval_digest: [u8; 32], expected_intent: [u8; 32]) -> bool {
        intent_digest == expected_intent && approval_digest == [22u8; 32]
    }

    #[test]
    fn live_revocation_can_issue_receipt_and_historical_recovery_survives_expiry() {
        let fixture = fixture();
        let expected_intent = fixture.decision.intent.intent_digest().unwrap();
        let entries = fixture.chain.iter().cloned().collect::<Vec<_>>();
        let frontiers = [fixture.f0.clone(), fixture.f1.clone()];
        let verified = verify_global_revocation_transition_v1(
            &fixture.previous,
            &fixture.candidate,
            &fixture.decision,
            &entries,
            fixture.signing_key.verifying_key().to_bytes(),
            &frontiers,
            102,
            policy(),
            |intent, approval_digest| approval(intent, approval_digest, expected_intent),
        ).unwrap();
        let receipt = GlobalRevocationTransitionReceiptV1::sign_after_verification(
            fixture.decision.clone(), verified, &fixture.signing_key,
        ).unwrap();

        // Long after the 161-second decision expiry, historical verification still succeeds.
        let historical = verify_retained_global_revocation_transition_v1(
            &receipt,
            &fixture.previous,
            &fixture.candidate,
            &entries,
            fixture.signing_key.verifying_key().to_bytes(),
            &frontiers,
            10_000,
            10,
            |intent, approval_digest| approval(intent, approval_digest, expected_intent),
        ).unwrap();
        assert_eq!(historical.decision_digest(), fixture.decision.decision_digest().unwrap());
        assert_eq!(historical.verified_at_unix_ms(), 102_000);
    }

    #[test]
    fn stale_prepared_decision_cannot_pass_live_application_gate() {
        let fixture = fixture();
        let expected_intent = fixture.decision.intent.intent_digest().unwrap();
        let entries = fixture.chain.iter().cloned().collect::<Vec<_>>();
        assert!(matches!(
            verify_global_revocation_transition_v1(
                &fixture.previous,
                &fixture.candidate,
                &fixture.decision,
                &entries,
                fixture.signing_key.verifying_key().to_bytes(),
                &[fixture.f0.clone(), fixture.f1.clone()],
                161,
                policy(),
                |intent, approval_digest| approval(intent, approval_digest, expected_intent),
            ),
            Err(GlobalRevocationTransitionError::DecisionNotLive)
        ));
    }

    #[test]
    fn approval_is_bound_to_exact_intent_digest() {
        let fixture = fixture();
        let wrong_intent = [99u8; 32];
        let entries = fixture.chain.iter().cloned().collect::<Vec<_>>();
        assert!(matches!(
            verify_global_revocation_transition_v1(
                &fixture.previous,
                &fixture.candidate,
                &fixture.decision,
                &entries,
                fixture.signing_key.verifying_key().to_bytes(),
                &[fixture.f0.clone(), fixture.f1.clone()],
                102,
                policy(),
                |intent, approval_digest| approval(intent, approval_digest, wrong_intent),
            ),
            Err(GlobalRevocationTransitionError::RevocationApprovalNotAuthenticated)
        ));
    }

    #[test]
    fn candidate_epoch_must_commit_complete_approved_decision() {
        let fixture = fixture();
        let mut changed = fixture.decision.clone();
        changed.approval_digest = [55u8; 32];
        let expected_intent = changed.intent.intent_digest().unwrap();
        let entries = fixture.chain.iter().cloned().collect::<Vec<_>>();
        assert!(matches!(
            verify_global_revocation_transition_v1(
                &fixture.previous,
                &fixture.candidate,
                &changed,
                &entries,
                fixture.signing_key.verifying_key().to_bytes(),
                &[fixture.f0.clone(), fixture.f1.clone()],
                102,
                policy(),
                |intent, _| intent == expected_intent,
            ),
            Err(GlobalRevocationTransitionError::DecisionDigestMismatch)
        ));
    }

    #[test]
    fn tampered_historical_receipt_fails_signature() {
        let fixture = fixture();
        let expected_intent = fixture.decision.intent.intent_digest().unwrap();
        let entries = fixture.chain.iter().cloned().collect::<Vec<_>>();
        let frontiers = [fixture.f0.clone(), fixture.f1.clone()];
        let verified = verify_global_revocation_transition_v1(
            &fixture.previous,
            &fixture.candidate,
            &fixture.decision,
            &entries,
            fixture.signing_key.verifying_key().to_bytes(),
            &frontiers,
            102,
            policy(),
            |intent, approval_digest| approval(intent, approval_digest, expected_intent),
        ).unwrap();
        let mut receipt = GlobalRevocationTransitionReceiptV1::sign_after_verification(
            fixture.decision.clone(), verified, &fixture.signing_key,
        ).unwrap();
        receipt.witness_digest[0] ^= 1;
        assert!(matches!(
            receipt.validate_local(),
            Err(GlobalRevocationTransitionError::BadReceiptSignature)
        ));
    }
}
