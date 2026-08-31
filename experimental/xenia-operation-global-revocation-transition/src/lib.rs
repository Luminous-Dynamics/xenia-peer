// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authenticated same-store global-revocation transitions for Xenia operation authority.
//!
//! ADR-025 deliberately rejects an authority-epoch change when the protected store and ledger
//! identity remain unchanged. This crate defines the one V1 exception: a short-lived, externally
//! authenticated decision may advance the exact operation authority epoch for
//! `AuthorityEpochReasonV1::GlobalRevocation`, invalidating every older epoch-bound grant/use/arm
//! object without changing the store generation or ledger key.
//!
//! Serialized decision/state bytes are evidence, not bearer authority. Production verification
//! requires an independently authenticated revocation-approval path plus complete retained
//! ledger/frontier succession verification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
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

/// Exact schema for one global operation-authority revocation decision.
pub const GLOBAL_REVOCATION_DECISION_SCHEMA_V1: &str =
    "xenia-operation-global-revocation-decision-v1";
/// Domain separator for deterministic decision commitments.
pub const GLOBAL_REVOCATION_DECISION_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-global-revocation-decision-digest-v1";
/// Maximum time a prepared revocation decision remains applicable: 15 minutes.
pub const MAX_GLOBAL_REVOCATION_DECISION_LIFETIME_MS_V1: u64 = 15 * 60 * 1_000;

/// The only V1 revocation scope.
///
/// V1 intentionally has no partial grant/session subset. A global revocation changes the whole
/// operation-authority epoch, so every older epoch-bound privileged-operation authority becomes
/// stale at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlobalRevocationScopeV1 {
    /// Invalidate every outstanding privileged-operation authority object bound to the old epoch.
    AllOutstandingPrivilegedOperationAuthority,
}

/// Short-lived decision authorizing one exact global authority-epoch invalidation.
///
/// `approval_digest` is a commitment to external human/organizational/emergency authorization;
/// it is not self-authenticating. The verifier requires a deployment-owned approval callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRevocationDecisionV1 {
    /// Exact schema label.
    pub schema: String,
    /// Unique decision identity.
    pub decision_id: [u8; 16],
    /// Exact operation-authority domain being invalidated.
    pub authority_domain_id: [u8; 16],
    /// Exact predecessor authority epoch commitment the decision is allowed to revoke.
    pub previous_authority_epoch_digest: [u8; 32],
    /// Fixed V1 revocation scope.
    pub scope: GlobalRevocationScopeV1,
    /// Exact policy revision governing this revocation decision.
    pub revocation_policy_digest: [u8; 32],
    /// Exact externally authenticated approval commitment.
    pub approval_digest: [u8; 32],
    /// Privacy-preserving commitment to the operator/emergency rationale or incident evidence.
    pub rationale_digest: [u8; 32],
    /// Trusted-enough authorization time in Unix milliseconds.
    pub authorized_at_unix_ms: u64,
    /// Exclusive hard expiry for applying this decision.
    pub expires_at_unix_ms: u64,
}

impl GlobalRevocationDecisionV1 {
    /// Validate canonical decision syntax independent of live authority state.
    pub fn validate(&self) -> Result<(), GlobalRevocationTransitionError> {
        if self.schema != GLOBAL_REVOCATION_DECISION_SCHEMA_V1 {
            return Err(GlobalRevocationTransitionError::UnsupportedDecisionSchema);
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
            self.approval_digest,
            GlobalRevocationTransitionError::ZeroApprovalDigest,
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

    /// Require this decision to be live at the exact application time.
    pub fn require_live_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<(), GlobalRevocationTransitionError> {
        self.validate()?;
        if now_unix_ms < self.authorized_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(GlobalRevocationTransitionError::DecisionNotLive);
        }
        Ok(())
    }

    /// Canonical bincode-v1 decision bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GlobalRevocationTransitionError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable commitment embedded by the successor authority epoch.
    pub fn decision_digest(&self) -> Result<[u8; 32], GlobalRevocationTransitionError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(GLOBAL_REVOCATION_DECISION_DIGEST_DOMAIN_V1);
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Successful authority-owned verification of one global revocation epoch transition.
///
/// The type is deliberately non-serializable and has private fields so persisted evidence cannot
/// manufacture the result of an authenticated approval/lineage verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedGlobalRevocationTransitionV1 {
    decision_digest: [u8; 32],
    previous_epoch_digest: [u8; 32],
    candidate_epoch_digest: [u8; 32],
    candidate_state_digest: [u8; 32],
    witness_digest: [u8; 32],
}

impl VerifiedGlobalRevocationTransitionV1 {
    /// Exact authenticated decision commitment.
    pub const fn decision_digest(self) -> [u8; 32] {
        self.decision_digest
    }

    /// Exact revoked predecessor authority-epoch commitment.
    pub const fn previous_epoch_digest(self) -> [u8; 32] {
        self.previous_epoch_digest
    }

    /// Exact successor global-revocation epoch commitment.
    pub const fn candidate_epoch_digest(self) -> [u8; 32] {
        self.candidate_epoch_digest
    }

    /// Exact signed candidate retained-authority-state commitment.
    pub const fn candidate_state_digest(self) -> [u8; 32] {
        self.candidate_state_digest
    }

    /// Exact candidate frontier witness commitment that passed anti-rollback succession.
    pub const fn witness_digest(self) -> [u8; 32] {
        self.witness_digest
    }
}

/// Verify one same-store/same-ledger global-revocation transition.
///
/// `verify_revocation_approval` is the deployment's independent emergency/policy authorization
/// path. It must authenticate the exact decision/approval commitment; returning `true` merely
/// because the structure is well formed would violate this contract's trust boundary.
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
    verify_revocation_approval: impl FnOnce(&GlobalRevocationDecisionV1) -> bool,
) -> Result<VerifiedGlobalRevocationTransitionV1, GlobalRevocationTransitionError> {
    previous.validate_local()?;
    candidate.validate_local()?;

    let now_unix_ms = now_unix_secs
        .checked_mul(1_000)
        .ok_or(GlobalRevocationTransitionError::CurrentTimeOverflow)?;
    decision.require_live_at(now_unix_ms)?;

    let previous_epoch_digest = previous.authority_epoch.epoch_digest()?;
    if decision.authority_domain_id != previous.authority_epoch.authority_domain_id {
        return Err(GlobalRevocationTransitionError::AuthorityDomainMismatch);
    }
    if decision.previous_authority_epoch_digest != previous_epoch_digest {
        return Err(GlobalRevocationTransitionError::PreviousEpochMismatch);
    }
    if !verify_revocation_approval(decision) {
        return Err(GlobalRevocationTransitionError::RevocationApprovalNotAuthenticated);
    }

    // Reuse ordinary same-key/same-generation anti-rollback succession. Global revocation changes
    // operation authority, not the external witness/storage/ledger lineage.
    let verified_witness = verify_retained_operation_frontier_bundle_successor_v1(
        &previous.retained_bundle,
        &candidate.retained_bundle,
        ledger_entries,
        trusted_ledger_public_key,
        local_frontiers,
        now_unix_secs,
        freshness_policy,
    )?;

    candidate
        .authority_epoch
        .validate_successor(&previous.authority_epoch)?;

    let expected_decision_digest = decision.decision_digest()?;
    match &candidate.authority_epoch.reason {
        AuthorityEpochReasonV1::GlobalRevocation {
            revocation_decision_digest,
        } if *revocation_decision_digest == expected_decision_digest => {}
        AuthorityEpochReasonV1::GlobalRevocation { .. } => {
            return Err(GlobalRevocationTransitionError::DecisionDigestMismatch);
        }
        _ => return Err(GlobalRevocationTransitionError::CandidateIsNotGlobalRevocation),
    }

    if candidate.authority_epoch.established_at_unix_ms < decision.authorized_at_unix_ms
        || candidate.authority_epoch.established_at_unix_ms >= decision.expires_at_unix_ms
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

    Ok(VerifiedGlobalRevocationTransitionV1 {
        decision_digest: expected_decision_digest,
        previous_epoch_digest,
        candidate_epoch_digest: candidate.authority_epoch.epoch_digest()?,
        candidate_state_digest: candidate.state_digest()?,
        witness_digest: verified_witness.witness_digest(),
    })
}

/// Fail-closed global-revocation transition errors.
#[derive(Debug, Error)]
pub enum GlobalRevocationTransitionError {
    /// Decision schema mismatch.
    #[error("unsupported global revocation decision schema")]
    UnsupportedDecisionSchema,
    /// Decision identity is unset.
    #[error("global revocation decision id must not be all zero")]
    ZeroDecisionId,
    /// Authority domain identity is unset.
    #[error("global revocation authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Previous epoch commitment is unset.
    #[error("global revocation decision requires previous authority epoch digest")]
    ZeroPreviousEpochDigest,
    /// Policy commitment is unset.
    #[error("global revocation decision requires policy digest")]
    ZeroPolicyDigest,
    /// Approval commitment is unset.
    #[error("global revocation decision requires approval digest")]
    ZeroApprovalDigest,
    /// Rationale/evidence commitment is unset.
    #[error("global revocation decision requires rationale digest")]
    ZeroRationaleDigest,
    /// Decision window is empty/reversed.
    #[error("global revocation decision window is invalid")]
    InvalidDecisionWindow,
    /// Decision is reusable for longer than the V1 hard bound.
    #[error("global revocation decision lifetime exceeds V1 maximum")]
    DecisionLifetimeTooLong,
    /// Decision was applied before authorization or after expiry.
    #[error("global revocation decision is not live at application time")]
    DecisionNotLive,
    /// Decision authority domain differs from the retained predecessor epoch.
    #[error("global revocation authority domain mismatch")]
    AuthorityDomainMismatch,
    /// Decision commits an epoch other than the exact retained predecessor.
    #[error("global revocation previous authority epoch digest mismatch")]
    PreviousEpochMismatch,
    /// External policy/emergency trust path did not authenticate the decision approval.
    #[error("global revocation approval was not authenticated")]
    RevocationApprovalNotAuthenticated,
    /// Successor authority epoch is not a global-revocation reason.
    #[error("candidate authority epoch is not a global revocation")]
    CandidateIsNotGlobalRevocation,
    /// Successor global-revocation reason commits a different decision.
    #[error("candidate global-revocation epoch does not commit the exact decision digest")]
    DecisionDigestMismatch,
    /// Candidate authority epoch establishment did not fall within the live decision window.
    #[error("candidate authority epoch was established outside the revocation decision window")]
    EpochEstablishedOutsideDecisionWindow,
    /// Candidate authority epoch timestamp is implausibly far in the future.
    #[error("candidate authority epoch exceeds permitted future clock skew")]
    CandidateEpochTooFarInFuture,
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
    /// Canonical decision serialization failed.
    #[error("global revocation decision serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

fn require_nonzero32(
    value: [u8; 32],
    error: GlobalRevocationTransitionError,
) -> Result<(), GlobalRevocationTransitionError> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, LedgerCheckpoint, checkpoint_fingerprint};
    use xenia_operation_authority_epoch::OPERATION_AUTHORITY_EPOCH_SCHEMA_V1;
    use xenia_operation_frontier_ledger_witness::{
        LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
        OperationFrontierLedgerWitnessV1,
    };
    use xenia_operation_frontier_retention_bundle::RetainedOperationFrontierWitnessBundleV1;

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
                scope: "global-revocation-test".to_string(),
            })
            .unwrap();
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
        let bundle = RetainedOperationFrontierWitnessBundleV1::new(
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
        RetainedOperationAuthorityStateV1::sign_ed25519(bundle, epoch, signing_key).unwrap()
    }

    fn decision(previous: &OperationAuthorityEpochV1) -> GlobalRevocationDecisionV1 {
        GlobalRevocationDecisionV1 {
            schema: GLOBAL_REVOCATION_DECISION_SCHEMA_V1.to_string(),
            decision_id: [20u8; 16],
            authority_domain_id: previous.authority_domain_id,
            previous_authority_epoch_digest: previous.epoch_digest().unwrap(),
            scope: GlobalRevocationScopeV1::AllOutstandingPrivilegedOperationAuthority,
            revocation_policy_digest: [21u8; 32],
            approval_digest: [22u8; 32],
            rationale_digest: [23u8; 32],
            authorized_at_unix_ms: 101_000,
            expires_at_unix_ms: 161_000,
        }
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
        CheckpointFreshnessPolicy {
            max_age_secs: Some(1_000),
            max_future_skew_secs: 10,
        }
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
        let previous = state(
            &signing_key,
            checkpoint0,
            &f0,
            0,
            [0u8; 32],
            100_000,
            e0.clone(),
        );

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

        Fixture {
            signing_key,
            chain,
            f0,
            f1,
            previous,
            candidate,
            decision,
        }
    }

    fn verify(fixture: &Fixture, decision: &GlobalRevocationDecisionV1, approval_ok: bool, now: u64) -> Result<VerifiedGlobalRevocationTransitionV1, GlobalRevocationTransitionError> {
        verify_global_revocation_transition_v1(
            &fixture.previous,
            &fixture.candidate,
            decision,
            &fixture.chain.iter().cloned().collect::<Vec<_>>(),
            fixture.signing_key.verifying_key().to_bytes(),
            &[fixture.f0.clone(), fixture.f1.clone()],
            now,
            policy(),
            |decision| approval_ok && decision.approval_digest == [22u8; 32],
        )
    }

    #[test]
    fn authenticated_global_revocation_advances_epoch_without_changing_store() {
        let fixture = fixture();
        let verified = verify(&fixture, &fixture.decision, true, 102).unwrap();
        assert_eq!(verified.decision_digest(), fixture.decision.decision_digest().unwrap());
        assert_ne!(verified.previous_epoch_digest(), verified.candidate_epoch_digest());
        assert_eq!(fixture.previous.authority_epoch.store_id, fixture.candidate.authority_epoch.store_id);
        assert_eq!(
            fixture.previous.authority_epoch.store_generation,
            fixture.candidate.authority_epoch.store_generation
        );
    }

    #[test]
    fn structurally_valid_but_unauthenticated_revocation_fails() {
        let fixture = fixture();
        assert!(matches!(
            verify(&fixture, &fixture.decision, false, 102),
            Err(GlobalRevocationTransitionError::RevocationApprovalNotAuthenticated)
        ));
    }

    #[test]
    fn stale_prepared_revocation_cannot_be_applied_later() {
        let fixture = fixture();
        assert!(matches!(
            verify(&fixture, &fixture.decision, true, 161),
            Err(GlobalRevocationTransitionError::DecisionNotLive)
        ));
    }

    #[test]
    fn decision_for_another_previous_epoch_fails() {
        let fixture = fixture();
        let mut wrong = fixture.decision.clone();
        wrong.previous_authority_epoch_digest = [99u8; 32];
        assert!(matches!(
            verify(&fixture, &wrong, true, 102),
            Err(GlobalRevocationTransitionError::PreviousEpochMismatch)
        ));
    }

    #[test]
    fn candidate_must_commit_exact_authenticated_decision_digest() {
        let fixture = fixture();
        let mut different = fixture.decision.clone();
        different.rationale_digest = [77u8; 32];
        assert!(matches!(
            verify(&fixture, &different, true, 102),
            Err(GlobalRevocationTransitionError::DecisionDigestMismatch)
        ));
    }

    #[test]
    fn global_revocation_cannot_change_store_generation() {
        let fixture = fixture();
        let mut candidate = fixture.candidate.clone();
        candidate.authority_epoch.store_generation = 1;
        // The signed retained state must bind the altered epoch/store, which also forces a matching
        // frontier generation. Reusing the old bundle therefore fails locally before approval can
        // bless an inconsistent store transition.
        assert!(RetainedOperationAuthorityStateV1::sign_ed25519(
            candidate.retained_bundle,
            candidate.authority_epoch,
            &fixture.signing_key,
        )
        .is_err());
    }
}
