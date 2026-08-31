// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::SigningKey;
use uuid::Uuid;
use xenia_ledger::{
    Chain, CheckpointFreshnessPolicy, ConsentEventRecord, ConsentKind, LedgerCheckpoint,
    LedgerKeyTransition, checkpoint_fingerprint,
};
use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1, OperationAuthorityEpochV1,
};
use xenia_operation_frontier_governed_transition::{
    GovernedOperationAuthorityTransitionV1, GovernedStoreTransitionEvidenceV1,
    GovernedTransitionError, RetainedOperationAuthorityStateV1,
    verify_governed_operation_authority_transition_v1,
};
use xenia_operation_frontier_ledger_witness::{
    LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
    OperationFrontierLedgerWitnessV1,
};
use xenia_operation_frontier_retention_bundle::RetainedOperationFrontierWitnessBundleV1;
use xenia_operation_store_frontier::OperationStoreFrontierV1;
use xenia_operation_store_recovery::{
    OperationStoreRecoveryAssessmentV1, OperationStoreRecoveryPlanV1,
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
            scope: "combined-governed-transition-test".to_string(),
        })
        .unwrap();
}

fn frontier(generation: u64, sequence: u64, previous: [u8; 32], time_ms: u64) -> OperationStoreFrontierV1 {
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
    let payload = OperationFrontierLedgerWitnessPayloadV1::new(
        frontier.anchor(time_ms).unwrap(),
        binding,
        sequence,
        previous_witness_digest,
        time_ms,
    )
    .unwrap();
    OperationFrontierLedgerWitnessV1::sign_ed25519(payload, signing_key).unwrap()
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
        established_at_unix_ms: 100_000,
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

struct CombinedFixture {
    old_key: SigningKey,
    old_chain: Chain,
    new_chain: Chain,
    previous_frontier: OperationStoreFrontierV1,
    candidate_frontier: OperationStoreFrontierV1,
    previous: RetainedOperationAuthorityStateV1,
    candidate: RetainedOperationAuthorityStateV1,
    key_transition: LedgerKeyTransition,
    recovery: GovernedStoreTransitionEvidenceV1,
}

fn combined_fixture() -> CombinedFixture {
    let old_key = key(3);
    let new_key = key(4);
    let mut old_chain = Chain::new(old_key.clone());
    append_event(&mut old_chain, 2, ConsentKind::Approval);
    let old_checkpoint = old_chain.sign_checkpoint(100);
    let f0 = frontier(0, 0, [0u8; 32], 100_000);
    let epoch0 = genesis_epoch();
    let previous = state(
        &old_key,
        old_checkpoint.clone(),
        &f0,
        0,
        [0u8; 32],
        100_000,
        epoch0.clone(),
    );

    let key_transition = LedgerKeyTransition::sign(
        old_checkpoint,
        &old_key,
        &new_key,
        200,
    )
    .unwrap();
    let (recovery, epoch1) = recovery_for_rollover(&epoch0, 200_000);

    let mut new_chain = Chain::new(new_key.clone());
    append_event(&mut new_chain, 3, ConsentKind::Approval);
    let new_checkpoint = new_chain.sign_checkpoint(201);
    let f1 = frontier(1, 0, [0u8; 32], 201_000);
    let candidate = state(
        &new_key,
        new_checkpoint,
        &f1,
        1,
        previous.retained_bundle.witness.witness_digest().unwrap(),
        201_000,
        epoch1,
    );

    CombinedFixture {
        old_key,
        old_chain,
        new_chain,
        previous_frontier: f0,
        candidate_frontier: f1,
        previous,
        candidate,
        key_transition,
        recovery,
    }
}

fn verify(
    fixture: &CombinedFixture,
    key_transition: Option<LedgerKeyTransition>,
    recovery: Option<GovernedStoreTransitionEvidenceV1>,
    approval_ok: bool,
) -> Result<(), GovernedTransitionError> {
    let transition = GovernedOperationAuthorityTransitionV1::new(
        fixture.previous.clone(),
        fixture.candidate.clone(),
        key_transition,
        recovery,
        202_000,
    )?;
    verify_governed_operation_authority_transition_v1(
        &transition,
        &fixture.old_chain.iter().cloned().collect::<Vec<_>>(),
        &fixture.new_chain.iter().cloned().collect::<Vec<_>>(),
        fixture.old_key.verifying_key().to_bytes(),
        std::slice::from_ref(&fixture.previous_frontier),
        std::slice::from_ref(&fixture.candidate_frontier),
        202,
        policy(),
        |assessment, plan| {
            approval_ok
                && plan.approval_digest == [16u8; 32]
                && plan.assessment_digest == assessment.assessment_digest().unwrap()
        },
    )
    .map(|verified| {
        assert!(verified.ledger_key_rotated());
        assert!(verified.store_transitioned());
    })
}

#[test]
fn key_rotation_and_generation_rollover_require_both_authority_proofs() {
    let fixture = combined_fixture();
    verify(
        &fixture,
        Some(fixture.key_transition.clone()),
        Some(fixture.recovery.clone()),
        true,
    )
    .unwrap();
}

#[test]
fn combined_transition_without_key_handover_fails() {
    let fixture = combined_fixture();
    assert!(matches!(
        verify(&fixture, None, Some(fixture.recovery.clone()), true),
        Err(GovernedTransitionError::MissingLedgerKeyTransition)
    ));
}

#[test]
fn combined_transition_without_recovery_evidence_fails() {
    let fixture = combined_fixture();
    assert!(matches!(
        verify(&fixture, Some(fixture.key_transition.clone()), None, true),
        Err(GovernedTransitionError::MissingGovernedRecoveryEvidence)
    ));
}

#[test]
fn combined_transition_with_unauthenticated_recovery_approval_fails() {
    let fixture = combined_fixture();
    assert!(matches!(
        verify(
            &fixture,
            Some(fixture.key_transition.clone()),
            Some(fixture.recovery.clone()),
            false,
        ),
        Err(GovernedTransitionError::RecoveryApprovalNotAuthenticated)
    ));
}

#[test]
fn recovery_plan_cannot_authorize_a_different_candidate_epoch() {
    let fixture = combined_fixture();
    let mut wrong_candidate = fixture.candidate.clone();
    wrong_candidate.authority_epoch.epoch_id = [99u8; 16];
    // Re-sign so the failure is the governed recovery/epoch binding, not a stale state signature.
    wrong_candidate = RetainedOperationAuthorityStateV1::sign_ed25519(
        wrong_candidate.retained_bundle,
        wrong_candidate.authority_epoch,
        &key(4),
    )
    .unwrap();
    let transition = GovernedOperationAuthorityTransitionV1::new(
        fixture.previous.clone(),
        wrong_candidate,
        Some(fixture.key_transition.clone()),
        Some(fixture.recovery.clone()),
        202_000,
    )
    .unwrap();
    assert!(verify_governed_operation_authority_transition_v1(
        &transition,
        &fixture.old_chain.iter().cloned().collect::<Vec<_>>(),
        &fixture.new_chain.iter().cloned().collect::<Vec<_>>(),
        fixture.old_key.verifying_key().to_bytes(),
        std::slice::from_ref(&fixture.previous_frontier),
        std::slice::from_ref(&fixture.candidate_frontier),
        202,
        policy(),
        |_, _| true,
    )
    .is_err());
}

#[test]
fn key_transition_must_finalize_exact_retained_previous_checkpoint() {
    let fixture = combined_fixture();
    let other_old_key = key(5);
    let mut other_old_chain = Chain::new(other_old_key.clone());
    append_event(&mut other_old_chain, 77, ConsentKind::Approval);
    let other_checkpoint = other_old_chain.sign_checkpoint(100);
    let bad_transition = LedgerKeyTransition::sign(
        other_checkpoint,
        &other_old_key,
        &key(4),
        200,
    )
    .unwrap();
    assert!(matches!(
        verify(
            &fixture,
            Some(bad_transition),
            Some(fixture.recovery.clone()),
            true,
        ),
        Err(GovernedTransitionError::LedgerTransitionPreviousCheckpointMismatch)
    ));
}
