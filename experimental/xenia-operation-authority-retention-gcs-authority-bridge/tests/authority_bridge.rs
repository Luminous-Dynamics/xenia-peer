// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use google_cloud_gax::{
    error::{Error as GaxError, rpc::{Code, Status}},
    response::Response,
};
use google_cloud_storage::{
    client::{Storage, StorageControl},
    model::{ListObjectsRequest, ListObjectsResponse, Object, ReadObjectRequest},
    model_ext::{ObjectHighlights, WriteObjectRequest},
    read_object::ReadObjectResponse,
    request_options::RequestOptions as DataRequestOptions,
    streaming_source::StreamingSource,
    stub::{Storage as StorageStub, StorageControl as StorageControlStub},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}},
};
use uuid::Uuid;
use xenia_ledger::{
    Chain, ConsentEventRecord, ConsentKind, checkpoint_fingerprint,
};
use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1, OperationAuthorityEpochV1,
};
use xenia_operation_authority_retention_backend::{
    AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1, AuthorityRetentionBackendErrorV1,
    AuthorityRetentionNamespaceV1, AuthorityRetentionObjectV1,
};
use xenia_operation_authority_retention_gcs_authority_bridge::{
    GcsAuthorityBridgeErrorV1, GcsAuthorityRetentionBridgeV1,
};
use xenia_operation_authority_retention_gcs_create_transport::GCS_AUTHORITY_CREATE_MAX_BYTES_V1;
use xenia_operation_authority_retention_gcs_profile::{
    GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1, GCS_RUNTIME_OBJECT_PERMISSIONS_V1,
    GCS_RUST_SDK_CRATE_V1, GCS_RUST_SDK_VERSION_V1, GCS_STORAGE_API_PROFILE_V1,
    GcsAuthorityRetentionProfileV1,
};
use xenia_operation_authority_retention_gcs_readback_transport::GcsReadbackTransportErrorV1;
use xenia_operation_authority_retention_lineage_v2::{
    AuthorityRetentionAppendResultV2, AuthorityRetentionErrorV2, AuthorityRetentionHealthV2,
    OperationAuthorityRetentionModelV2, OperationAuthorityRetentionPayloadV2,
    OperationAuthorityRetentionRecordV2, RetentionLineageOriginV2,
};
use xenia_operation_authority_retention_namespace_gate::{
    AuthorityRetentionNamespaceTrustSourceV1, NamespaceTrustOutcomeV1,
    VerifiedAuthorityRetentionNamespaceV1, verify_authority_retention_namespace_v1,
};
use xenia_operation_frontier_governed_transition::RetainedOperationAuthorityStateV1;
use xenia_operation_frontier_ledger_witness::{
    LedgerCheckpointBindingV1, OperationFrontierLedgerWitnessPayloadV1,
    OperationFrontierLedgerWitnessV1,
};
use xenia_operation_frontier_retention_bundle::RetainedOperationFrontierWitnessBundleV1;
use xenia_operation_store_frontier::OperationStoreFrontierV1;

#[derive(Debug, Default)]
struct SharedStore {
    objects: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    write_calls: AtomicUsize,
    read_calls: AtomicUsize,
    list_calls: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
enum WriteMode {
    Durable,
    CommitThenDeadline,
    FailedPrecondition,
}

#[derive(Debug)]
struct WriteStub {
    store: Arc<SharedStore>,
    mode: WriteMode,
}

impl StorageStub for WriteStub {
    fn write_object_buffered<P>(
        &self,
        mut payload: P,
        request: WriteObjectRequest,
        _options: DataRequestOptions,
    ) -> impl std::future::Future<Output = google_cloud_storage::Result<Object>> + Send
    where
        P: StreamingSource + Send + Sync + 'static,
    {
        self.store.write_calls.fetch_add(1, Ordering::SeqCst);
        let store = self.store.clone();
        let mode = self.mode;
        async move {
            let resource = request
                .spec
                .resource
                .expect("qualified write request always carries an object resource");
            let mut bytes = Vec::new();
            while let Some(chunk) = payload.next().await {
                bytes.extend_from_slice(&chunk.expect("Bytes-backed test payload cannot fail"));
            }
            let key = (resource.bucket, resource.name);
            match mode {
                WriteMode::Durable => {
                    store.objects.lock().unwrap().insert(key, bytes);
                    Ok(Object::new())
                }
                WriteMode::CommitThenDeadline => {
                    store.objects.lock().unwrap().insert(key, bytes);
                    Err(GaxError::service(
                        Status::default().set_code(Code::DeadlineExceeded),
                    ))
                }
                WriteMode::FailedPrecondition => Err(GaxError::service(
                    Status::default().set_code(Code::FailedPrecondition),
                )),
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ReadMode {
    Normal,
    OversizeMetadata,
}

#[derive(Debug)]
struct ReadStub {
    store: Arc<SharedStore>,
    mode: ReadMode,
}

impl StorageStub for ReadStub {
    fn read_object(
        &self,
        request: ReadObjectRequest,
        _options: DataRequestOptions,
    ) -> impl std::future::Future<Output = google_cloud_storage::Result<ReadObjectResponse>> + Send {
        self.store.read_calls.fetch_add(1, Ordering::SeqCst);
        let store = self.store.clone();
        let mode = self.mode;
        async move {
            let key = (request.bucket, request.object);
            let Some(bytes) = store.objects.lock().unwrap().get(&key).cloned() else {
                return Err(GaxError::service(Status::default().set_code(Code::NotFound)));
            };
            let mut metadata = ObjectHighlights::default();
            metadata.size = match mode {
                ReadMode::Normal => i64::try_from(bytes.len()).unwrap(),
                ReadMode::OversizeMetadata =>
                    i64::try_from(GCS_AUTHORITY_CREATE_MAX_BYTES_V1 + 1).unwrap(),
            };
            Ok(ReadObjectResponse::from_source(metadata, Bytes::from(bytes)))
        }
    }
}

#[derive(Debug)]
struct ControlStub {
    store: Arc<SharedStore>,
}

impl StorageControlStub for ControlStub {
    fn list_objects(
        &self,
        request: ListObjectsRequest,
        _options: google_cloud_gax::options::RequestOptions,
    ) -> impl std::future::Future<
        Output = google_cloud_storage::Result<Response<ListObjectsResponse>>,
    > + Send {
        self.store.list_calls.fetch_add(1, Ordering::SeqCst);
        let store = self.store.clone();
        async move {
            let objects = store
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|(bucket, name)| {
                    bucket == &request.parent && name.starts_with(&request.prefix)
                })
                .map(|(bucket, name)| {
                    Object::new()
                        .set_bucket(bucket.clone())
                        .set_name(name.clone())
                })
                .collect::<Vec<_>>();
            Ok(Response::from(ListObjectsResponse::new().set_objects(objects)))
        }
    }
}

#[derive(Debug)]
struct TrustSource {
    authority_domain_id: [u8; 16],
    expected_namespace_digest: [u8; 32],
    valid_until_unix_ms: u64,
}

impl AuthorityRetentionNamespaceTrustSourceV1 for TrustSource {
    fn authenticate_expected_namespace(
        &mut self,
        authority_domain_id: [u8; 16],
    ) -> NamespaceTrustOutcomeV1 {
        assert_eq!(authority_domain_id, self.authority_domain_id);
        NamespaceTrustOutcomeV1::Authenticated {
            authority_domain_id,
            expected_namespace_digest: self.expected_namespace_digest,
            trust_evidence_digest: [0x55; 32],
            valid_until_unix_ms: self.valid_until_unix_ms,
        }
    }
}

fn profile(bucket_name: &str, iam_byte: u8) -> GcsAuthorityRetentionProfileV1 {
    GcsAuthorityRetentionProfileV1 {
        schema: GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1.to_string(),
        project_number: 123,
        bucket_name: bucket_name.to_string(),
        bucket_location: "us-central1".to_string(),
        minimum_bucket_retention_seconds: 31_536_000,
        required_recovery_horizon_seconds: 31_536_000,
        runtime_principal_digest: [1u8; 32],
        retention_admin_principal_digest: [2u8; 32],
        encryption_profile_digest: [3u8; 32],
        iam_policy_profile_digest: [iam_byte; 32],
        runtime_object_permissions: GCS_RUNTIME_OBJECT_PERMISSIONS_V1
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        require_locked_bucket_retention: true,
        require_uniform_bucket_level_access: true,
        require_public_access_prevention_enforced: true,
        require_object_versioning_disabled: true,
        require_hierarchical_namespace_disabled: true,
        require_no_lifecycle_rules: true,
        rust_sdk_crate: GCS_RUST_SDK_CRATE_V1.to_string(),
        rust_sdk_version: GCS_RUST_SDK_VERSION_V1.to_string(),
        storage_api_profile: GCS_STORAGE_API_PROFILE_V1.to_string(),
    }
}

fn namespace(profile: &GcsAuthorityRetentionProfileV1) -> AuthorityRetentionNamespaceV1 {
    AuthorityRetentionNamespaceV1 {
        schema: AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1.to_string(),
        authority_domain_id: [1u8; 16],
        retention_lineage_id: [9u8; 16],
        retention_policy_digest: profile.profile_digest().unwrap(),
    }
}

fn verified_namespace(
    namespace: AuthorityRetentionNamespaceV1,
    verified_at_unix_ms: u64,
    valid_until_unix_ms: u64,
) -> VerifiedAuthorityRetentionNamespaceV1 {
    let mut trust = TrustSource {
        authority_domain_id: namespace.authority_domain_id,
        expected_namespace_digest: namespace.namespace_digest().unwrap(),
        valid_until_unix_ms,
    };
    verify_authority_retention_namespace_v1(namespace, &mut trust, verified_at_unix_ms).unwrap()
}

fn bridge(
    store: Arc<SharedStore>,
    profile: GcsAuthorityRetentionProfileV1,
    write_mode: WriteMode,
    read_mode: ReadMode,
) -> GcsAuthorityRetentionBridgeV1<WriteStub, ReadStub> {
    GcsAuthorityRetentionBridgeV1::new(
        Storage::from_stub(WriteStub {
            store: store.clone(),
            mode: write_mode,
        }),
        Storage::from_stub(ReadStub {
            store: store.clone(),
            mode: read_mode,
        }),
        StorageControl::from_stub(ControlStub { store }),
        profile,
    )
    .unwrap()
}

fn genesis_record() -> OperationAuthorityRetentionRecordV2 {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let mut chain = Chain::new(signing_key.clone());
    chain
        .append(ConsentEventRecord {
            source_id: [1u8; 32],
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            kind: ConsentKind::Approval,
            scope: "gcs-authority-bridge-test".to_string(),
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
    let witness_payload = OperationFrontierLedgerWitnessPayloadV1::new(
        frontier.anchor(100_000).unwrap(),
        binding,
        0,
        [0u8; 32],
        100_000,
    )
    .unwrap();
    let witness = OperationFrontierLedgerWitnessV1::sign_ed25519(witness_payload, &signing_key)
        .unwrap();
    let bundle = RetainedOperationFrontierWitnessBundleV1::new(
        witness,
        checkpoint,
        100_000,
    )
    .unwrap();
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
    let state = RetainedOperationAuthorityStateV1::sign_ed25519(bundle, epoch, &signing_key)
        .unwrap();
    OperationAuthorityRetentionRecordV2::new(
        0,
        [0u8; 32],
        Some(RetentionLineageOriginV2::FullWitnessLineageGenesis),
        OperationAuthorityRetentionPayloadV2::AuthorityState(state),
        100_000,
    )
    .unwrap()
}

#[tokio::test]
async fn expired_verified_namespace_reaches_zero_provider_calls() {
    let p = profile("xenia-authority-bridge-expired", 4);
    let ns = namespace(&p);
    let token = verified_namespace(ns, 1_000, 1_000_000);
    let store = Arc::new(SharedStore::default());
    let bridge = bridge(store.clone(), p, WriteMode::Durable, ReadMode::Normal);
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        bridge
            .append_verified(&mut model, token, genesis_record(), 61_001)
            .await,
        Err(GcsAuthorityBridgeErrorV1::NamespaceGate(_))
    ));
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.read_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.list_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_profile_binding_reaches_zero_provider_calls() {
    let namespace_profile = profile("xenia-authority-bridge-a", 4);
    let bridge_profile = profile("xenia-authority-bridge-b", 5);
    let ns = namespace(&namespace_profile);
    let token = verified_namespace(ns, 1_000, 50_000);
    let store = Arc::new(SharedStore::default());
    let bridge = bridge(
        store.clone(),
        bridge_profile,
        WriteMode::Durable,
        ReadMode::Normal,
    );
    let mut model = OperationAuthorityRetentionModelV2::new();

    assert!(matches!(
        bridge
            .append_verified(&mut model, token, genesis_record(), 1_001)
            .await,
        Err(GcsAuthorityBridgeErrorV1::Profile(_))
    ));
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.read_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_semantic_candidate_reaches_zero_provider_calls() {
    let p = profile("xenia-authority-bridge-invalid", 4);
    let ns = namespace(&p);
    let token = verified_namespace(ns, 1_000, 50_000);
    let store = Arc::new(SharedStore::default());
    let bridge = bridge(store.clone(), p, WriteMode::Durable, ReadMode::Normal);
    let mut model = OperationAuthorityRetentionModelV2::new();
    let mut candidate = genesis_record();
    candidate.schema = "not-the-v2-schema".to_string();

    assert!(matches!(
        bridge
            .append_verified(&mut model, token, candidate, 1_001)
            .await,
        Err(GcsAuthorityBridgeErrorV1::Retention(
            AuthorityRetentionErrorV2::UnsupportedRecordSchema
        ))
    ));
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.read_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn durable_append_replay_is_provider_free_and_complete_readback_round_trips() {
    let p = profile("xenia-authority-bridge-roundtrip", 4);
    let ns = namespace(&p);
    let store = Arc::new(SharedStore::default());
    let bridge = bridge(store.clone(), p, WriteMode::Durable, ReadMode::Normal);
    let candidate = genesis_record();
    let mut model = OperationAuthorityRetentionModelV2::new();

    let token = verified_namespace(ns.clone(), 1_000, 50_000);
    assert_eq!(
        bridge
            .append_verified(&mut model, token, candidate.clone(), 1_001)
            .await
            .unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 1);

    let replay = verified_namespace(ns.clone(), 2_000, 50_000);
    assert_eq!(
        bridge
            .append_verified(&mut model, replay, candidate, 2_001)
            .await
            .unwrap(),
        AuthorityRetentionAppendResultV2::DuplicateSame
    );
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 1);

    let recovery = verified_namespace(ns, 3_000, 50_000);
    let recovered = bridge.readback_verified(recovery, 3_001).await.unwrap();
    assert_eq!(recovered.records(), model.records());
    assert_eq!(store.list_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.read_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lost_ack_is_accepted_only_after_exact_authoritative_readback() {
    let p = profile("xenia-authority-bridge-lost-ack", 4);
    let ns = namespace(&p);
    let store = Arc::new(SharedStore::default());
    let bridge = bridge(
        store.clone(),
        p,
        WriteMode::CommitThenDeadline,
        ReadMode::Normal,
    );
    let mut model = OperationAuthorityRetentionModelV2::new();
    let token = verified_namespace(ns, 1_000, 50_000);

    assert_eq!(
        bridge
            .append_verified(&mut model, token, genesis_record(), 1_001)
            .await
            .unwrap(),
        AuthorityRetentionAppendResultV2::Appended
    );
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.read_calls.load(Ordering::SeqCst), 1);
    assert_eq!(model.health(), AuthorityRetentionHealthV2::Healthy);
}

#[tokio::test]
async fn conflicting_existing_bytes_fail_stop_the_live_model() {
    let p = profile("xenia-authority-bridge-conflict", 4);
    let ns = namespace(&p);
    let candidate = genesis_record();
    let external = AuthorityRetentionObjectV1::new(ns.clone(), candidate.clone()).unwrap();
    let locator = external.locator().unwrap();
    let bucket = format!("projects/_/buckets/{}", p.bucket_name);
    let object = p
        .object_name(locator.namespace_digest, locator.retention_sequence)
        .unwrap();
    let store = Arc::new(SharedStore::default());
    store
        .objects
        .lock()
        .unwrap()
        .insert((bucket, object), b"conflicting immutable bytes".to_vec());
    let bridge = bridge(
        store.clone(),
        p,
        WriteMode::FailedPrecondition,
        ReadMode::Normal,
    );
    let mut model = OperationAuthorityRetentionModelV2::new();
    let token = verified_namespace(ns, 1_000, 50_000);

    assert!(matches!(
        bridge
            .append_verified(&mut model, token, candidate, 1_001)
            .await,
        Err(GcsAuthorityBridgeErrorV1::Backend(
            AuthorityRetentionBackendErrorV1::ExternalObjectConflict
        ))
    ));
    assert_eq!(model.health(), AuthorityRetentionHealthV2::DurabilityUncertain);
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.read_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unresolved_create_plus_readback_validation_error_still_fail_stops_model() {
    let p = profile("xenia-authority-bridge-read-error", 4);
    let ns = namespace(&p);
    let store = Arc::new(SharedStore::default());
    let bridge = bridge(
        store.clone(),
        p,
        WriteMode::CommitThenDeadline,
        ReadMode::OversizeMetadata,
    );
    let mut model = OperationAuthorityRetentionModelV2::new();
    let token = verified_namespace(ns, 1_000, 50_000);

    assert!(matches!(
        bridge
            .append_verified(&mut model, token, genesis_record(), 1_001)
            .await,
        Err(GcsAuthorityBridgeErrorV1::ReadbackTransport(
            GcsReadbackTransportErrorV1::ExternalObjectTooLarge { .. }
        ))
    ));
    assert_eq!(model.health(), AuthorityRetentionHealthV2::DurabilityUncertain);
    assert_eq!(store.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.read_calls.load(Ordering::SeqCst), 1);
}
