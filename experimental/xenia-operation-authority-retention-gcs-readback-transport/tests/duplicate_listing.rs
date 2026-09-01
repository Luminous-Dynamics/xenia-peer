// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use google_cloud_gax::response::Response;
use google_cloud_storage::{
    client::{Storage, StorageControl},
    model::{ListObjectsRequest, ListObjectsResponse, Object},
    stub::{Storage as StorageStub, StorageControl as StorageControlStub},
};
use xenia_operation_authority_retention_gcs_profile::{
    GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1, GCS_RUNTIME_OBJECT_PERMISSIONS_V1,
    GCS_RUST_SDK_CRATE_V1, GCS_RUST_SDK_VERSION_V1, GCS_STORAGE_API_PROFILE_V1,
    GcsAuthorityRetentionProfileV1,
};
use xenia_operation_authority_retention_gcs_readback_transport::{
    GcsAuthorityReadbackTransportV1, GcsReadbackTransportErrorV1,
};

#[derive(Debug)]
struct DataStub;
impl StorageStub for DataStub {}

#[derive(Debug)]
struct DuplicateListStub;
impl StorageControlStub for DuplicateListStub {
    fn list_objects(
        &self,
        req: ListObjectsRequest,
        _options: google_cloud_gax::options::RequestOptions,
    ) -> impl std::future::Future<
        Output = google_cloud_storage::Result<Response<ListObjectsResponse>>,
    > + Send {
        async move {
            let name = format!("{}{:020}.bin", req.prefix, 7);
            let first = Object::new()
                .set_bucket(req.parent.clone())
                .set_name(name.clone());
            let duplicate = Object::new().set_bucket(req.parent).set_name(name);
            Ok(Response::from(
                ListObjectsResponse::new().set_objects([first, duplicate]),
            ))
        }
    }
}

fn profile() -> GcsAuthorityRetentionProfileV1 {
    GcsAuthorityRetentionProfileV1 {
        schema: GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1.to_string(),
        project_number: 123,
        bucket_name: "xenia-authority-retention-test".to_string(),
        bucket_location: "us-central1".to_string(),
        minimum_bucket_retention_seconds: 31_536_000,
        required_recovery_horizon_seconds: 31_536_000,
        runtime_principal_digest: [1u8; 32],
        retention_admin_principal_digest: [2u8; 32],
        encryption_profile_digest: [3u8; 32],
        iam_policy_profile_digest: [4u8; 32],
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

#[tokio::test]
async fn duplicate_sequence_is_never_complete() {
    let data = Storage::from_stub(DataStub);
    let control = StorageControl::from_stub(DuplicateListStub);
    let transport = GcsAuthorityReadbackTransportV1::new(data, control, profile()).unwrap();

    assert!(matches!(
        transport.enumerate_complete([0xabu8; 32]).await,
        Err(GcsReadbackTransportErrorV1::DuplicateSequence)
    ));
}
