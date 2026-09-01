// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use uuid::Uuid;
use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, checkpoint_fingerprint};
use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1, OperationAuthorityEpochV1,
};
use xenia_operation_authority_retention_backend::{
    AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1, AuthorityRetentionNamespaceV1,
    AuthorityRetentionObjectLocatorV1, BackendCreateOutcomeV1, BackendEnumerateOutcomeV1,
    BackendReadOutcomeV1, ImmutableAuthorityRetentionBackendV1,
};
use xenia_operation_authority_retention_lineage_v2::{
    AuthorityRetentionAppendResultV2, OperationAuthorityRetentionModelV2,
    OperationAuthorityRetentionPayloadV2, OperationAuthorityRetentionRecordV2,
    RetentionLineageOriginV2,
};
use xenia_operation_authority_retention_namespace_gate::{
    AuthorityRetentionNamespaceTrustSourceV1, NamespaceGateErrorV1, NamespaceTrustOutcomeV1,
    VERIFIED_NAMESPACE_TOKEN_MAX_LIFETIME_MS_V1, authenticate_and_append_v1,
    authenticate_and_readback_v1, verify_authority_retention_namespace_v1,
    append_via_verified_namespace_v1,
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

fn namespace() -> AuthorityRetentionNamespaceV1 {
    AuthorityRetentionNamespaceV1 {
        schema: AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1.to_string(),
        authority_domain_id: [1u8; 16],
        retention_lineage_id: [50u8; 16],
        retention_policy_digest: [51u8; 32],
    }
}

fn record() -> OperationAuthorityRetentionRecordV2 {
    let signing_key = key(3);
    let mut chain = Chain::new(signing_key.clone());
    chain
        .append(ConsentEventRecord {
            source_id: [1u8; 32],
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            kind: ConsentKind::Approval,
            scope: "authority-retention-namespace-gate-test".to_string(),
        })
        .unwrap();
    let checkpoint = chain.sign_checkpoint(100);
    let frontier = OperationStoreFrontierV1::from_state(
        [7u8; 16],
        0,
        0,
        [8u8; 32],
        [0u8; 32],
        100_000,
        &[],
        &[],
    )
    .unwrap();
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
            frontier.anchor(100_000).unwrap(),
            binding,
            0,
            [0u8; 32],
            100_000,
        )
        .unwrap(),
        &signing_key,
    )
    .unwrap();
    let bundle =
        RetainedOperationFrontierWitnessBundleV1::new(witness, checkpoint, 100_000).unwrap();
    let epoch = OperationAuthorityEpochV1 {
        schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
        authority_domain_id: [1u8; 16],
        epoch_id: [2u8; 16],
        epoch_sequence: 0,
        previous_epoch_digest: [0u8; 32],
        store_id: [7u8; 16],
        store_generation: 0,
        reason: AuthorityEpochReasonV1::Genesis,
        established_at_unix_ms: 100_000,
    };
    let state = RetainedOperationAuthorityStateV1::sign_ed25519(bundle, epoch, &signing_key).unwrap();
    OperationAuthorityRetentionRecordV2::new(
        0,
        [0u8; 32],
        Some(RetentionLineageOriginV2::FullWitnessLineageGenesis),
        OperationAuthorityRetentionPayloadV2::AuthorityState(state),
        100_000,
    )
    .unwrap()
}

#[derive(Clone)]
struct TrustSource {
    outcome: NamespaceTrustOutcomeV1,
    calls: u32,
}

impl AuthorityRetentionNamespaceTrustSourceV1 for TrustSource {
    fn authenticate_expected_namespace(
        &mut self,
        _authority_domain_id: [u8; 16],
    ) -> NamespaceTrustOutcomeV1 {
        self.calls += 1;
        self.outcome
    }
}

fn matching_trust(ns: &AuthorityRetentionNamespaceV1, valid_until_unix_ms: u64) -> TrustSource {
    TrustSource {
        outcome: NamespaceTrustOutcomeV1::Authenticated {
            authority_domain_id: ns.authority_domain_id,
            expected_namespace_digest: ns.namespace_digest().unwrap(),
            trust_evidence_digest: [77u8; 32],
            valid_until_unix_ms,
        },
        calls: 0,
    }
}

#[derive(Default)]
struct Backend {
    objects: BTreeMap<AuthorityRetentionObjectLocatorV1, Vec<u8>>,
    create_calls: u32,
    read_calls: u32,
    enumerate_calls: u32,
}

impl ImmutableAuthorityRetentionBackendV1 for Backend {
    fn create_if_absent(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
        bytes: &[u8],
    ) -> BackendCreateOutcomeV1 {
        self.create_calls += 1;
        if self.objects.contains_key(locator) {
            BackendCreateOutcomeV1::AlreadyExists
        } else {
            self.objects.insert(locator.clone(), bytes.to_vec());
            BackendCreateOutcomeV1::DurableCreated
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
        self.enumerate_calls += 1;
        BackendEnumerateOutcomeV1::Complete(
            self.objects
                .keys()
                .filter(|locator| locator.namespace_digest == namespace_digest)
                .map(|locator| locator.retention_sequence)
                .collect(),
        )
    }
}

#[test]
fn matching_external_namespace_trust_allows_append_and_fresh_readback() {
    let ns = namespace();
    let mut trust = matching_trust(&ns, 200_000);
    let mut backend = Backend::default();
    let mut model = OperationAuthorityRetentionModelV2::new();
    let retained = record();

    assert_eq!(
        authenticate_and_append_v1(
            &mut model,
            ns.clone(),
            &mut trust,
            &mut backend,
            retained.clone(),
            100_000,
        )
        .unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(trust.calls, 1);
    assert_eq!(backend.create_calls, 1);

    let recovered = authenticate_and_readback_v1(
        ns,
        &mut trust,
        &mut backend,
        100_001,
    )
    .unwrap();
    assert_eq!(trust.calls, 2);
    assert_eq!(backend.enumerate_calls, 1);
    assert_eq!(recovered.records(), &[retained]);
}

#[test]
fn wrong_expected_namespace_fails_before_provider_io() {
    let ns = namespace();
    let mut trust = TrustSource {
        outcome: NamespaceTrustOutcomeV1::Authenticated {
            authority_domain_id: ns.authority_domain_id,
            expected_namespace_digest: [88u8; 32],
            trust_evidence_digest: [77u8; 32],
            valid_until_unix_ms: 200_000,
        },
        calls: 0,
    };
    let mut backend = Backend::default();
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        authenticate_and_append_v1(
            &mut model,
            ns,
            &mut trust,
            &mut backend,
            record(),
            100_000,
        ),
        Err(NamespaceGateErrorV1::ExpectedNamespaceDigestMismatch)
    ));
    assert_eq!(backend.create_calls, 0);
}

#[test]
fn trust_source_unknown_fails_before_provider_io() {
    let mut trust = TrustSource {
        outcome: NamespaceTrustOutcomeV1::Unknown,
        calls: 0,
    };
    let mut backend = Backend::default();
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        authenticate_and_append_v1(
            &mut model,
            namespace(),
            &mut trust,
            &mut backend,
            record(),
            100_000,
        ),
        Err(NamespaceGateErrorV1::TrustSourceUnknown)
    ));
    assert_eq!(backend.create_calls, 0);
}

#[test]
fn expired_trust_attestation_fails_before_provider_io() {
    let ns = namespace();
    let mut trust = matching_trust(&ns, 99_999);
    let mut backend = Backend::default();
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        authenticate_and_append_v1(
            &mut model,
            ns,
            &mut trust,
            &mut backend,
            record(),
            100_000,
        ),
        Err(NamespaceGateErrorV1::TrustAttestationExpired)
    ));
    assert_eq!(backend.create_calls, 0);
}

#[test]
fn wrong_authority_domain_from_trust_source_fails_closed() {
    let ns = namespace();
    let mut trust = TrustSource {
        outcome: NamespaceTrustOutcomeV1::Authenticated {
            authority_domain_id: [9u8; 16],
            expected_namespace_digest: ns.namespace_digest().unwrap(),
            trust_evidence_digest: [77u8; 32],
            valid_until_unix_ms: 200_000,
        },
        calls: 0,
    };
    assert!(matches!(
        verify_authority_retention_namespace_v1(ns, &mut trust, 100_000),
        Err(NamespaceGateErrorV1::TrustSourceAuthorityDomainMismatch)
    ));
}

#[test]
fn verified_token_expires_before_backend_can_observe_record() {
    let ns = namespace();
    let mut trust = matching_trust(&ns, u64::MAX);
    let verified = verify_authority_retention_namespace_v1(ns, &mut trust, 100_000).unwrap();
    assert_eq!(
        verified.expires_at_unix_ms(),
        100_000 + VERIFIED_NAMESPACE_TOKEN_MAX_LIFETIME_MS_V1
    );

    let mut backend = Backend::default();
    let mut model = OperationAuthorityRetentionModelV2::new();
    assert!(matches!(
        append_via_verified_namespace_v1(
            &mut model,
            verified,
            &mut backend,
            record(),
            160_001,
        ),
        Err(NamespaceGateErrorV1::VerifiedNamespaceTokenExpired)
    ));
    assert_eq!(backend.create_calls, 0);
}
