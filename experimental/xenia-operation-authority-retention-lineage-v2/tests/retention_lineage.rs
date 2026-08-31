// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::Cell;

use ed25519_dalek::SigningKey;
use uuid::Uuid;
use xenia_ledger::{
    Chain, CheckpointFreshnessPolicy, ConsentEventRecord, ConsentKind, LedgerCheckpoint,
    checkpoint_fingerprint,
};
use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1, OperationAuthorityEpochV1,
};
use xenia_operation_authority_retention_lineage_v2::{
    AuthorityRetentionAppendResultV2, AuthorityRetentionErrorV2, AuthorityRetentionHealthV2,
    OperationAuthorityRetentionModelV2, OperationAuthorityRetentionPayloadV2,
    OperationAuthorityRetentionRecordV2, PersistenceOutcomeV2, RetentionLineageOriginV2,
    validate_retained_lineage_v2,
};
use xenia_operation_frontier_governed_transition::RetainedOperationAuthorityStateV1;
use xenia_operation_frontier_ledger_witness::{
    LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
    OperationFrontierLedgerWitnessV1,
};
use xenia_operation_frontier_retention_bundle::RetainedOperationFrontierWitnessBundleV1;
use xenia_operation_global_revocation_transition::{
    GLOBAL_REVOCATION_DECISION_SCHEMA_V1, GLOBAL_REVOCATION_INTENT_SCHEMA_V1,
    GlobalRevocationDecisionV1, GlobalRevocationIntentV1, GlobalRevocationScopeV1,
    GlobalRevocationTransitionReceiptV1, verify_global_revocation_transition_v1,
};
use xenia_operation_store_frontier::OperationStoreFrontierV1;

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
            scope: "authority-retention-v2-test".to_string(),
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
    let payload = OperationFrontierLedgerWitnessPayloadV1::new(
        frontier.anchor(time_ms).unwrap(),
        binding,
        witness_sequence,
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

fn policy() -> CheckpointFreshnessPolicy {
    CheckpointFreshnessPolicy {
        max_age_secs: Some(1_000),
        max_future_skew_secs: 10,
    }
}

fn ordinary_states() -> (
    SigningKey,
    Chain,
    OperationStoreFrontierV1,
    OperationStoreFrontierV1,
    RetainedOperationAuthorityStateV1,
    RetainedOperationAuthorityStateV1,
) {
    let signing_key = key(3);
    let mut chain = Chain::new(signing_key.clone());
    append_event(&mut chain, 2, ConsentKind::Approval);
    let checkpoint0 = chain.sign_checkpoint(100);
    let f0 = frontier(0, 0, [0u8; 32], 100_000);
    let epoch = genesis_epoch();
    let s0 = state(
        &signing_key,
        checkpoint0,
        &f0,
        0,
        [0u8; 32],
        100_000,
        epoch.clone(),
    );

    append_event(&mut chain, 3, ConsentKind::Approval);
    let checkpoint1 = chain.sign_checkpoint(101);
    let f1 = frontier(0, 1, f0.frontier_digest().unwrap(), 101_000);
    let s1 = state(
        &signing_key,
        checkpoint1,
        &f1,
        1,
        s0.retained_bundle.witness.witness_digest().unwrap(),
        101_000,
        epoch,
    );
    (signing_key, chain, f0, f1, s0, s1)
}

fn record0(
    state: RetainedOperationAuthorityStateV1,
    origin: RetentionLineageOriginV2,
) -> OperationAuthorityRetentionRecordV2 {
    let time_ms = state.retained_bundle.retained_at_unix_ms;
    OperationAuthorityRetentionRecordV2::new(
        0,
        [0u8; 32],
        Some(origin),
        OperationAuthorityRetentionPayloadV2::AuthorityState(state),
        time_ms,
    )
    .unwrap()
}

fn ordinary_record(
    previous: &OperationAuthorityRetentionRecordV2,
    state: RetainedOperationAuthorityStateV1,
) -> OperationAuthorityRetentionRecordV2 {
    let time_ms = state.retained_bundle.retained_at_unix_ms;
    OperationAuthorityRetentionRecordV2::new(
        previous.retention_sequence + 1,
        previous.record_digest().unwrap(),
        None,
        OperationAuthorityRetentionPayloadV2::AuthorityState(state),
        time_ms,
    )
    .unwrap()
}

#[test]
fn full_genesis_and_ordinary_state_progression_validate() {
    let (_, _, _, _, s0, s1) = ordinary_states();
    let r0 = record0(s0, RetentionLineageOriginV2::FullWitnessLineageGenesis);
    let r1 = ordinary_record(&r0, s1);
    r1.validate_successor(&r0).unwrap();
    validate_retained_lineage_v2(&[r0, r1]).unwrap();
}

#[test]
fn adopted_anchor_is_explicit_and_does_not_fake_full_witness_genesis() {
    let signing_key = key(3);
    let mut chain = Chain::new(signing_key.clone());
    append_event(&mut chain, 2, ConsentKind::Approval);
    let checkpoint = chain.sign_checkpoint(100);
    let f0 = frontier(0, 0, [0u8; 32], 100_000);
    let adopted_state = state(
        &signing_key,
        checkpoint,
        &f0,
        5,
        [9u8; 32],
        100_000,
        genesis_epoch(),
    );

    assert!(matches!(
        OperationAuthorityRetentionRecordV2::new(
            0,
            [0u8; 32],
            Some(RetentionLineageOriginV2::FullWitnessLineageGenesis),
            OperationAuthorityRetentionPayloadV2::AuthorityState(adopted_state.clone()),
            100_000,
        ),
        Err(AuthorityRetentionErrorV2::FalseFullGenesisClaim)
    ));

    OperationAuthorityRetentionRecordV2::new(
        0,
        [0u8; 32],
        Some(RetentionLineageOriginV2::AdoptedAnchor),
        OperationAuthorityRetentionPayloadV2::AuthorityState(adopted_state),
        100_000,
    )
    .unwrap();
}

#[test]
fn ordinary_state_record_cannot_silently_advance_authority_epoch() {
    let (signing_key, mut chain, f0, _, s0, _) = ordinary_states();
    append_event(&mut chain, 4, ConsentKind::Revocation);
    let checkpoint = chain.sign_checkpoint(102);
    let f1 = frontier(0, 1, f0.frontier_digest().unwrap(), 102_000);
    let previous_epoch = s0.authority_epoch.clone();
    let changed_epoch = OperationAuthorityEpochV1 {
        schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
        authority_domain_id: previous_epoch.authority_domain_id,
        epoch_id: [30u8; 16],
        epoch_sequence: 1,
        previous_epoch_digest: previous_epoch.epoch_digest().unwrap(),
        store_id: previous_epoch.store_id,
        store_generation: previous_epoch.store_generation,
        reason: AuthorityEpochReasonV1::GlobalRevocation {
            revocation_decision_digest: [31u8; 32],
        },
        established_at_unix_ms: 101_500,
    };
    let changed_state = state(
        &signing_key,
        checkpoint,
        &f1,
        1,
        s0.retained_bundle.witness.witness_digest().unwrap(),
        102_000,
        changed_epoch,
    );
    let r0 = record0(s0, RetentionLineageOriginV2::FullWitnessLineageGenesis);
    let r1 = OperationAuthorityRetentionRecordV2::new(
        1,
        r0.record_digest().unwrap(),
        None,
        OperationAuthorityRetentionPayloadV2::AuthorityState(changed_state),
        102_000,
    )
    .unwrap();
    assert!(matches!(
        r1.validate_successor(&r0),
        Err(AuthorityRetentionErrorV2::OrdinaryStateChangedAuthorityEpoch)
    ));
}

#[test]
fn duplicate_same_is_idempotent_and_conflict_is_not() {
    let (_, _, _, _, s0, _) = ordinary_states();
    let r0 = record0(s0, RetentionLineageOriginV2::FullWitnessLineageGenesis);
    let calls = Cell::new(0u32);
    let mut model = OperationAuthorityRetentionModelV2::new();
    assert_eq!(
        model
            .append(r0.clone(), |_| {
                calls.set(calls.get() + 1);
                PersistenceOutcomeV2::Durable
            })
            .unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(
        model
            .append(r0.clone(), |_| {
                calls.set(calls.get() + 1);
                PersistenceOutcomeV2::Durable
            })
            .unwrap(),
        AuthorityRetentionAppendResultV2::DuplicateSame
    );
    assert_eq!(calls.get(), 1);

    let mut fork = r0;
    fork.retained_at_unix_ms += 1;
    assert!(matches!(
        model.append(fork, |_| {
            calls.set(calls.get() + 1);
            PersistenceOutcomeV2::Durable
        }),
        Err(AuthorityRetentionErrorV2::RetentionSequenceConflict)
    ));
    assert_eq!(calls.get(), 1);
}

#[test]
fn sequence_gap_fails_before_persistence() {
    let (_, _, _, _, s0, _) = ordinary_states();
    let calls = Cell::new(0u32);
    let gap = OperationAuthorityRetentionRecordV2::new(
        2,
        [9u8; 32],
        None,
        OperationAuthorityRetentionPayloadV2::AuthorityState(s0),
        100_000,
    )
    .unwrap();
    let mut model = OperationAuthorityRetentionModelV2::new();
    assert!(matches!(
        model.append(gap, |_| {
            calls.set(calls.get() + 1);
            PersistenceOutcomeV2::Durable
        }),
        Err(AuthorityRetentionErrorV2::RetentionSequenceGap)
    ));
    assert_eq!(calls.get(), 0);
}

#[test]
fn rejected_write_stays_healthy_but_unknown_write_fail_stops_until_readback() {
    let (_, _, _, _, s0, s1) = ordinary_states();
    let r0 = record0(s0, RetentionLineageOriginV2::FullWitnessLineageGenesis);
    let r1 = ordinary_record(&r0, s1);
    let mut model = OperationAuthorityRetentionModelV2::new();
    model
        .append(r0.clone(), |_| PersistenceOutcomeV2::Durable)
        .unwrap();

    assert!(matches!(
        model.append(r1.clone(), |_| PersistenceOutcomeV2::Rejected),
        Err(AuthorityRetentionErrorV2::PersistenceRejected)
    ));
    assert_eq!(model.health(), AuthorityRetentionHealthV2::Healthy);
    assert_eq!(model.records().len(), 1);

    assert!(matches!(
        model.append(r1.clone(), |_| PersistenceOutcomeV2::Unknown),
        Err(AuthorityRetentionErrorV2::PersistenceOutcomeUnknown)
    ));
    assert_eq!(
        model.health(),
        AuthorityRetentionHealthV2::DurabilityUncertain
    );
    assert!(matches!(
        model.append(r1, |_| PersistenceOutcomeV2::Durable),
        Err(AuthorityRetentionErrorV2::DurabilityUncertain)
    ));

    // Immutable readback proves the ambiguous candidate was absent; a fresh validated model may
    // resume from the externally observed one-record lineage.
    let restored = OperationAuthorityRetentionModelV2::from_retained_lineage(
        model.records().to_vec(),
    )
    .unwrap();
    assert_eq!(restored.health(), AuthorityRetentionHealthV2::Healthy);
    assert_eq!(restored.records().len(), 1);
}

struct RevocationFixture {
    signing_key: SigningKey,
    chain: Chain,
    f0: OperationStoreFrontierV1,
    f1: OperationStoreFrontierV1,
    previous: RetainedOperationAuthorityStateV1,
    candidate: RetainedOperationAuthorityStateV1,
    receipt: GlobalRevocationTransitionReceiptV1,
}

fn revocation_fixture() -> RevocationFixture {
    let signing_key = key(7);
    let mut chain = Chain::new(signing_key.clone());
    append_event(&mut chain, 10, ConsentKind::Approval);
    let checkpoint0 = chain.sign_checkpoint(100);
    let f0 = frontier(0, 0, [0u8; 32], 100_000);
    let e0 = genesis_epoch();
    let previous = state(
        &signing_key,
        checkpoint0,
        &f0,
        0,
        [0u8; 32],
        100_000,
        e0.clone(),
    );

    let decision = GlobalRevocationDecisionV1 {
        schema: GLOBAL_REVOCATION_DECISION_SCHEMA_V1.to_string(),
        intent: GlobalRevocationIntentV1 {
            schema: GLOBAL_REVOCATION_INTENT_SCHEMA_V1.to_string(),
            decision_id: [40u8; 16],
            authority_domain_id: e0.authority_domain_id,
            previous_authority_epoch_digest: e0.epoch_digest().unwrap(),
            scope: GlobalRevocationScopeV1::AllOutstandingPrivilegedOperationAuthority,
            revocation_policy_digest: [41u8; 32],
            rationale_digest: [42u8; 32],
            authorized_at_unix_ms: 101_000,
            expires_at_unix_ms: 161_000,
        },
        approval_digest: [43u8; 32],
    };
    let e1 = OperationAuthorityEpochV1 {
        schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
        authority_domain_id: e0.authority_domain_id,
        epoch_id: [44u8; 16],
        epoch_sequence: 1,
        previous_epoch_digest: e0.epoch_digest().unwrap(),
        store_id: e0.store_id,
        store_generation: e0.store_generation,
        reason: AuthorityEpochReasonV1::GlobalRevocation {
            revocation_decision_digest: decision.decision_digest().unwrap(),
        },
        established_at_unix_ms: 102_000,
    };

    append_event(&mut chain, 11, ConsentKind::Revocation);
    let checkpoint1 = chain.sign_checkpoint(102);
    let f1 = frontier(0, 1, f0.frontier_digest().unwrap(), 102_000);
    let candidate = state(
        &signing_key,
        checkpoint1,
        &f1,
        1,
        previous.retained_bundle.witness.witness_digest().unwrap(),
        102_000,
        e1,
    );
    let entries = chain.iter().cloned().collect::<Vec<_>>();
    let frontiers = [f0.clone(), f1.clone()];
    let expected_intent = decision.intent.intent_digest().unwrap();
    let verified = verify_global_revocation_transition_v1(
        &previous,
        &candidate,
        &decision,
        &entries,
        signing_key.verifying_key().to_bytes(),
        &frontiers,
        102,
        policy(),
        |intent, approval| intent == expected_intent && approval == [43u8; 32],
    )
    .unwrap();
    let receipt = GlobalRevocationTransitionReceiptV1::sign_after_verification(
        decision,
        verified,
        &signing_key,
    )
    .unwrap();

    RevocationFixture {
        signing_key,
        chain,
        f0,
        f1,
        previous,
        candidate,
        receipt,
    }
}

#[test]
fn global_revocation_receipt_is_one_atomic_retention_record() {
    let fixture = revocation_fixture();
    let r0 = record0(
        fixture.previous.clone(),
        RetentionLineageOriginV2::FullWitnessLineageGenesis,
    );
    let r1 = OperationAuthorityRetentionRecordV2::new(
        1,
        r0.record_digest().unwrap(),
        None,
        OperationAuthorityRetentionPayloadV2::GlobalRevocationTransition {
            previous: fixture.previous,
            candidate: fixture.candidate,
            receipt: fixture.receipt,
        },
        102_000,
    )
    .unwrap();
    r1.validate_successor(&r0).unwrap();
    validate_retained_lineage_v2(&[r0, r1]).unwrap();

    // Keep these real signed fixtures live in the test so the retained transition is demonstrably
    // derived from the same ledger/frontier history used by ADR-026.
    assert_eq!(fixture.chain.len(), 2);
    assert_eq!(fixture.f0.checkpoint_sequence, 0);
    assert_eq!(fixture.f1.checkpoint_sequence, 1);
    assert_ne!(fixture.signing_key.verifying_key().to_bytes(), [0u8; 32]);
}

#[test]
fn transition_record_cannot_be_inserted_beside_the_wrong_predecessor_state() {
    let fixture = revocation_fixture();

    let other_key = key(9);
    let mut other_chain = Chain::new(other_key.clone());
    append_event(&mut other_chain, 90, ConsentKind::Approval);
    let other_checkpoint = other_chain.sign_checkpoint(100);
    let other_frontier = frontier(0, 0, [0u8; 32], 100_000);
    let other_state = state(
        &other_key,
        other_checkpoint,
        &other_frontier,
        7,
        [77u8; 32],
        100_000,
        genesis_epoch(),
    );
    let wrong_r0 = record0(other_state, RetentionLineageOriginV2::AdoptedAnchor);

    let r1 = OperationAuthorityRetentionRecordV2::new(
        1,
        wrong_r0.record_digest().unwrap(),
        None,
        OperationAuthorityRetentionPayloadV2::GlobalRevocationTransition {
            previous: fixture.previous,
            candidate: fixture.candidate,
            receipt: fixture.receipt,
        },
        102_000,
    )
    .unwrap();
    assert!(matches!(
        r1.validate_successor(&wrong_r0),
        Err(AuthorityRetentionErrorV2::TransitionPredecessorMismatch)
    ));
}
