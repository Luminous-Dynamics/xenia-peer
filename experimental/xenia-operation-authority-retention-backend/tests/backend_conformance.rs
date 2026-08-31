// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use uuid::Uuid;
use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, LedgerCheckpoint, checkpoint_fingerprint};
use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1, OperationAuthorityEpochV1,
};
use xenia_operation_authority_retention_backend::{
    AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1, AuthorityRetentionBackendErrorV1,
    AuthorityRetentionNamespaceV1, AuthorityRetentionObjectLocatorV1, AuthorityRetentionObjectV1,
    BackendCreateOutcomeV1, BackendEnumerateOutcomeV1, BackendReadOutcomeV1,
    ImmutableAuthorityRetentionBackendV1, append_via_backend_v1, readback_complete_lineage_v1,
};
use xenia_operation_authority_retention_lineage_v2::{
    AuthorityRetentionAppendResultV2, AuthorityRetentionHealthV2,
    OperationAuthorityRetentionModelV2, OperationAuthorityRetentionPayloadV2,
    OperationAuthorityRetentionRecordV2, RetentionLineageOriginV2,
};
use xenia_operation_frontier_governed_transition::RetainedOperationAuthorityStateV1;
use xenia_operation_frontier_ledger_witness::{
    LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
    OperationFrontierLedgerWitnessV1,
};
use xenia_operation_frontier_retention_bundle::RetainedOperationFrontierWitnessBundleV1;
use xenia_operation_store_frontier::OperationStoreFrontierV1;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn append_event(chain: &mut Chain, request: u128) {
    chain
        .append(ConsentEventRecord {
            source_id: [1u8; 32],
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(request),
            kind: ConsentKind::Approval,
            scope: "authority-retention-backend-test".to_string(),
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

fn epoch() -> OperationAuthorityEpochV1 {
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

fn state(
    signing_key: &SigningKey,
    checkpoint: LedgerCheckpoint,
    frontier: &OperationStoreFrontierV1,
    witness_sequence: u64,
    previous_witness_digest: [u8; 32],
    time_ms: u64,
    epoch: OperationAuthorityEpochV1,
) -> RetainedOperationAuthorityStateV1 {
    let binding = LedgerCheckpointBindingV1::new(
        checkpoint_fingerprint(&checkpoint).unwrap(),
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
            witness_sequence,
            previous_witness_digest,
            time_ms,
        )
        .unwrap(),
        signing_key,
    )
    .unwrap();
    let bundle = RetainedOperationFrontierWitnessBundleV1::new(witness, checkpoint, time_ms).unwrap();
    RetainedOperationAuthorityStateV1::sign_ed25519(bundle, epoch, signing_key).unwrap()
}

fn records() -> (OperationAuthorityRetentionRecordV2, OperationAuthorityRetentionRecordV2) {
    let signing_key = key(3);
    let mut chain = Chain::new(signing_key.clone());
    append_event(&mut chain, 2);
    let f0 = frontier(0, [0u8; 32], 100_000);
    let s0 = state(
        &signing_key,
        chain.sign_checkpoint(100),
        &f0,
        0,
        [0u8; 32],
        100_000,
        epoch(),
    );
    let r0 = OperationAuthorityRetentionRecordV2::new(
        0,
        [0u8; 32],
        Some(RetentionLineageOriginV2::FullWitnessLineageGenesis),
        OperationAuthorityRetentionPayloadV2::AuthorityState(s0.clone()),
        100_000,
    )
    .unwrap();

    append_event(&mut chain, 3);
    let f1 = frontier(1, f0.frontier_digest().unwrap(), 101_000);
    let s1 = state(
        &signing_key,
        chain.sign_checkpoint(101),
        &f1,
        1,
        s0.retained_bundle.witness.witness_digest().unwrap(),
        101_000,
        epoch(),
    );
    let r1 = OperationAuthorityRetentionRecordV2::new(
        1,
        r0.record_digest().unwrap(),
        None,
        OperationAuthorityRetentionPayloadV2::AuthorityState(s1),
        101_000,
    )
    .unwrap();
    (r0, r1)
}

fn namespace() -> AuthorityRetentionNamespaceV1 {
    AuthorityRetentionNamespaceV1 {
        schema: AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1.to_string(),
        authority_domain_id: [1u8; 16],
        retention_lineage_id: [50u8; 16],
        retention_policy_digest: [51u8; 32],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateMode {
    Normal,
    CommitThenUnknown,
    Reject,
    UnknownWithoutCommit,
}

struct FakeBackend {
    objects: BTreeMap<AuthorityRetentionObjectLocatorV1, Vec<u8>>,
    create_mode: CreateMode,
    create_calls: u32,
    read_calls: u32,
    enumerate_unknown: bool,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            create_mode: CreateMode::Normal,
            create_calls: 0,
            read_calls: 0,
            enumerate_unknown: false,
        }
    }
}

impl ImmutableAuthorityRetentionBackendV1 for FakeBackend {
    fn create_if_absent(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
        bytes: &[u8],
    ) -> BackendCreateOutcomeV1 {
        self.create_calls += 1;
        match self.create_mode {
            CreateMode::Normal => {
                if self.objects.contains_key(locator) {
                    BackendCreateOutcomeV1::AlreadyExists
                } else {
                    self.objects.insert(locator.clone(), bytes.to_vec());
                    BackendCreateOutcomeV1::DurableCreated
                }
            }
            CreateMode::CommitThenUnknown => {
                self.objects
                    .entry(locator.clone())
                    .or_insert_with(|| bytes.to_vec());
                BackendCreateOutcomeV1::Unknown
            }
            CreateMode::Reject => BackendCreateOutcomeV1::Rejected,
            CreateMode::UnknownWithoutCommit => BackendCreateOutcomeV1::Unknown,
        }
    }

    fn read_exact(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
    ) -> BackendReadOutcomeV1 {
        self.read_calls += 1;
        self.objects
            .get(locator)
            .cloned()
            .map(BackendReadOutcomeV1::Found)
            .unwrap_or(BackendReadOutcomeV1::NotFound)
    }

    fn enumerate_complete(
        &mut self,
        namespace_digest: [u8; 32],
    ) -> BackendEnumerateOutcomeV1 {
        if self.enumerate_unknown {
            return BackendEnumerateOutcomeV1::Unknown;
        }
        let sequences = self
            .objects
            .keys()
            .filter(|locator| locator.namespace_digest == namespace_digest)
            .map(|locator| locator.retention_sequence)
            .collect::<Vec<_>>();
        BackendEnumerateOutcomeV1::Complete(sequences)
    }
}

#[test]
fn durable_create_and_complete_readback_round_trip() {
    let (r0, r1) = records();
    let ns = namespace();
    let mut backend = FakeBackend::default();
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert_eq!(
        append_via_backend_v1(&mut model, &ns, &mut backend, r0.clone()).unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(
        append_via_backend_v1(&mut model, &ns, &mut backend, r1.clone()).unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(backend.create_calls, 2);

    let recovered = readback_complete_lineage_v1(&ns, &mut backend).unwrap();
    assert_eq!(recovered.records(), &[r0, r1]);
}

#[test]
fn commit_then_lost_ack_is_resolved_only_by_exact_authoritative_read() {
    let (r0, _) = records();
    let ns = namespace();
    let mut backend = FakeBackend {
        create_mode: CreateMode::CommitThenUnknown,
        ..FakeBackend::default()
    };
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert_eq!(
        append_via_backend_v1(&mut model, &ns, &mut backend, r0).unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(backend.create_calls, 1);
    assert_eq!(backend.read_calls, 1);
    assert_eq!(model.health(), AuthorityRetentionHealthV2::Healthy);
}

#[test]
fn already_existing_exact_object_can_recover_a_previous_lost_ack() {
    let (r0, _) = records();
    let ns = namespace();
    let object = AuthorityRetentionObjectV1::new(ns.clone(), r0.clone()).unwrap();
    let locator = object.locator().unwrap();
    let mut backend = FakeBackend::default();
    backend
        .objects
        .insert(locator, object.canonical_bytes().unwrap());

    let mut fresh_model = OperationAuthorityRetentionModelV2::new();
    assert_eq!(
        append_via_backend_v1(&mut fresh_model, &ns, &mut backend, r0).unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(backend.create_calls, 1);
    assert_eq!(backend.read_calls, 1);
}

#[test]
fn conflicting_immutable_object_fail_stops_local_writes() {
    let (r0, _) = records();
    let ns = namespace();
    let locator = AuthorityRetentionObjectV1::new(ns.clone(), r0.clone())
        .unwrap()
        .locator()
        .unwrap();
    let mut backend = FakeBackend::default();
    backend.objects.insert(locator, b"different immutable bytes".to_vec());
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        append_via_backend_v1(&mut model, &ns, &mut backend, r0),
        Err(AuthorityRetentionBackendErrorV1::ExternalObjectConflict)
    ));
    assert_eq!(
        model.health(),
        AuthorityRetentionHealthV2::DurabilityUncertain
    );
}

#[test]
fn unresolved_create_timeout_fail_stops_local_writes() {
    let (r0, _) = records();
    let ns = namespace();
    let mut backend = FakeBackend {
        create_mode: CreateMode::UnknownWithoutCommit,
        ..FakeBackend::default()
    };
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        append_via_backend_v1(&mut model, &ns, &mut backend, r0),
        Err(AuthorityRetentionBackendErrorV1::BackendStateUnknown)
    ));
    assert_eq!(backend.read_calls, 1);
    assert_eq!(
        model.health(),
        AuthorityRetentionHealthV2::DurabilityUncertain
    );
}

#[test]
fn definite_backend_rejection_does_not_poison_model_health() {
    let (r0, _) = records();
    let ns = namespace();
    let mut backend = FakeBackend {
        create_mode: CreateMode::Reject,
        ..FakeBackend::default()
    };
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        append_via_backend_v1(&mut model, &ns, &mut backend, r0),
        Err(AuthorityRetentionBackendErrorV1::BackendRejected)
    ));
    assert_eq!(model.health(), AuthorityRetentionHealthV2::Healthy);
    assert!(model.records().is_empty());
}

#[test]
fn namespace_authority_mismatch_fails_before_provider_call() {
    let (r0, _) = records();
    let mut wrong = namespace();
    wrong.authority_domain_id = [99u8; 16];
    let mut backend = FakeBackend::default();
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        append_via_backend_v1(&mut model, &wrong, &mut backend, r0),
        Err(AuthorityRetentionBackendErrorV1::AuthorityDomainMismatch)
    ));
    assert_eq!(backend.create_calls, 0);
    assert_eq!(model.health(), AuthorityRetentionHealthV2::Healthy);
}

#[test]
fn readback_rejects_gap_even_when_each_object_is_locally_valid() {
    let (r0, _) = records();
    let ns = namespace();
    let mut backend = FakeBackend::default();
    let object0 = AuthorityRetentionObjectV1::new(ns.clone(), r0.clone()).unwrap();
    backend.objects.insert(
        object0.locator().unwrap(),
        object0.canonical_bytes().unwrap(),
    );

    let gap_record = OperationAuthorityRetentionRecordV2::new(
        2,
        [88u8; 32],
        None,
        r0.payload,
        102_000,
    )
    .unwrap();
    let object2 = AuthorityRetentionObjectV1::new(ns.clone(), gap_record).unwrap();
    backend.objects.insert(
        object2.locator().unwrap(),
        object2.canonical_bytes().unwrap(),
    );

    assert!(matches!(
        readback_complete_lineage_v1(&ns, &mut backend),
        Err(AuthorityRetentionBackendErrorV1::ExternalSequenceGapOrDuplicate)
    ));
}
