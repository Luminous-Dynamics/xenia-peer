// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single-shot Google Cloud Storage create transport for Xenia authority retention.
//!
//! This crate owns the first mutating provider call beneath ADR-028/029/030/031. It deliberately
//! keeps creation narrower than the general Google Storage writer: canonical objects are bounded to
//! 1 MiB, `if_generation_match = 0` is mandatory, automatic create retries are disabled, and the
//! resumable-upload threshold is forced to `usize::MAX` so the qualified payload remains on the
//! single-shot path. Any ambiguous SDK failure is delegated to ADR-031's fail-closed classifier.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use bytes::Bytes;
use google_cloud_gax::retry_policy::NeverRetry;
use google_cloud_storage::{client::Storage, stub::Storage as StorageStub};
use thiserror::Error;
use xenia_operation_authority_retention_backend::{
    AuthorityRetentionObjectLocatorV1, BackendCreateOutcomeV1,
};
use xenia_operation_authority_retention_gcs_adapter::classify_generation_zero_create_error_v1;
use xenia_operation_authority_retention_gcs_profile::{
    GcsAuthorityRetentionProfileV1, GcsProfileErrorV1,
};

/// Maximum canonical ADR-028 object size accepted by the V1 create transport.
pub const GCS_AUTHORITY_CREATE_MAX_BYTES_V1: usize = 1024 * 1024;
/// Fixed Google bucket resource prefix used by the V1 Storage API.
pub const GCS_BUCKET_RESOURCE_PREFIX_V1: &str = "projects/_/buckets/";

/// Google Storage create transport with frozen ADR-031 mutation semantics.
#[derive(Debug, Clone)]
pub struct GcsAuthorityCreateTransportV1<S>
where
    S: StorageStub + 'static,
{
    client: Storage<S>,
    profile: GcsAuthorityRetentionProfileV1,
}

impl<S> GcsAuthorityCreateTransportV1<S>
where
    S: StorageStub + 'static,
{
    /// Construct the transport after validating the exact ADR-030 provider profile.
    pub fn new(
        client: Storage<S>,
        profile: GcsAuthorityRetentionProfileV1,
    ) -> Result<Self, GcsCreateTransportErrorV1> {
        profile.validate()?;
        Ok(Self { client, profile })
    }

    /// Return the frozen provider profile used by this transport.
    pub fn profile(&self) -> &GcsAuthorityRetentionProfileV1 {
        &self.profile
    }

    /// Execute one create-if-absent mutation using the exact ADR-031 request profile.
    ///
    /// This function does not perform ADR-028 lost-ack readback itself. `AlreadyExists` and
    /// `Unknown` are intentionally returned to the higher durability state machine, which must
    /// resolve them through an authoritative exact read before accepting durability.
    pub async fn create_if_absent(
        &self,
        locator: &AuthorityRetentionObjectLocatorV1,
        canonical_bytes: &[u8],
    ) -> Result<BackendCreateOutcomeV1, GcsCreateTransportErrorV1> {
        self.profile.validate()?;
        validate_canonical_object_bytes_v1(canonical_bytes)?;

        let bucket = bucket_resource_name_v1(&self.profile)?;
        let object = self
            .profile
            .object_name(locator.namespace_digest, locator.retention_sequence)?;
        let payload = Bytes::copy_from_slice(canonical_bytes);

        let result = self
            .client
            .write_object(bucket, object, payload)
            .set_if_generation_match(0)
            .with_retry_policy(NeverRetry)
            .with_resumable_upload_threshold(usize::MAX)
            .send_buffered()
            .await;

        Ok(match result {
            Ok(_) => BackendCreateOutcomeV1::DurableCreated,
            Err(error) => classify_generation_zero_create_error_v1(&error),
        })
    }
}

/// Validate payload bounds before any provider call can observe authority evidence.
pub fn validate_canonical_object_bytes_v1(
    canonical_bytes: &[u8],
) -> Result<(), GcsCreateTransportErrorV1> {
    if canonical_bytes.is_empty() {
        return Err(GcsCreateTransportErrorV1::EmptyCanonicalObject);
    }
    if canonical_bytes.len() > GCS_AUTHORITY_CREATE_MAX_BYTES_V1 {
        return Err(GcsCreateTransportErrorV1::CanonicalObjectTooLarge {
            observed: canonical_bytes.len(),
            maximum: GCS_AUTHORITY_CREATE_MAX_BYTES_V1,
        });
    }
    Ok(())
}

/// Exact Google Storage bucket resource name for the qualified profile.
pub fn bucket_resource_name_v1(
    profile: &GcsAuthorityRetentionProfileV1,
) -> Result<String, GcsCreateTransportErrorV1> {
    profile.validate()?;
    Ok(format!(
        "{GCS_BUCKET_RESOURCE_PREFIX_V1}{}",
        profile.bucket_name
    ))
}

/// Create-transport preflight/provider-profile errors.
#[derive(Debug, Error)]
pub enum GcsCreateTransportErrorV1 {
    /// ADR-030 profile validation failed.
    #[error("GCS authority retention profile rejected create transport: {0}")]
    Profile(#[from] GcsProfileErrorV1),
    /// Canonical ADR-028 object was unexpectedly empty.
    #[error("GCS authority retention canonical object must not be empty")]
    EmptyCanonicalObject,
    /// Canonical object exceeds the single-shot V1 qualification bound.
    #[error("GCS authority retention object is {observed} bytes; maximum is {maximum}")]
    CanonicalObjectTooLarge {
        /// Observed canonical byte length.
        observed: usize,
        /// Frozen V1 maximum canonical byte length.
        maximum: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_gax::error::{Error as GaxError, rpc::{Code, Status}};
    use google_cloud_storage::{
        model::Object,
        model_ext::WriteObjectRequest,
        request_options::RequestOptions,
        streaming_source::StreamingSource,
    };
    use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
    use xenia_operation_authority_retention_gcs_profile::{
        GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1, GCS_RUNTIME_OBJECT_PERMISSIONS_V1,
        GCS_RUST_SDK_CRATE_V1, GCS_RUST_SDK_VERSION_V1, GCS_STORAGE_API_PROFILE_V1,
    };

    #[derive(Debug)]
    struct CapturedWrite {
        request: WriteObjectRequest,
        bytes: Vec<u8>,
        resumable_threshold: usize,
    }

    #[derive(Debug, Default)]
    struct CaptureStub {
        calls: AtomicUsize,
        captured: Mutex<Option<CapturedWrite>>,
    }

    impl StorageStub for CaptureStub {
        fn write_object_buffered<P>(
            &self,
            mut payload: P,
            request: WriteObjectRequest,
            options: RequestOptions,
        ) -> impl std::future::Future<Output = google_cloud_storage::Result<Object>> + Send
        where
            P: StreamingSource + Send + Sync + 'static,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            async move {
                let mut bytes = Vec::new();
                while let Some(chunk) = payload.next().await {
                    match chunk {
                        Ok(chunk) => bytes.extend_from_slice(&chunk),
                        Err(_) => panic!("test Bytes payload unexpectedly failed"),
                    }
                }
                *self.captured.lock().unwrap() = Some(CapturedWrite {
                    request,
                    bytes,
                    resumable_threshold: options.resumable_upload_threshold(),
                });
                Ok(Object::new())
            }
        }
    }

    #[derive(Debug)]
    struct ErrorStub {
        calls: AtomicUsize,
        code: Code,
    }

    impl StorageStub for ErrorStub {
        fn write_object_buffered<P>(
            &self,
            _payload: P,
            _request: WriteObjectRequest,
            _options: RequestOptions,
        ) -> impl std::future::Future<Output = google_cloud_storage::Result<Object>> + Send
        where
            P: StreamingSource + Send + Sync + 'static,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let code = self.code;
            async move { Err(GaxError::service(Status::default().set_code(code))) }
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

    fn locator() -> AuthorityRetentionObjectLocatorV1 {
        AuthorityRetentionObjectLocatorV1 {
            namespace_digest: [0xabu8; 32],
            retention_sequence: 42,
        }
    }

    #[tokio::test]
    async fn real_google_builder_emits_exact_generation_zero_single_shot_request() {
        let stub = Arc::new(CaptureStub::default());
        let client = Storage::from_stub(stub.clone());
        let p = profile();
        let expected_name = p.object_name(locator().namespace_digest, 42).unwrap();
        let transport = GcsAuthorityCreateTransportV1::new(client, p).unwrap();
        let bytes = b"canonical-xenia-authority-object";

        assert_eq!(
            transport.create_if_absent(&locator(), bytes).await.unwrap(),
            BackendCreateOutcomeV1::DurableCreated
        );
        assert_eq!(stub.calls.load(Ordering::SeqCst), 1);

        let captured = stub.captured.lock().unwrap();
        let captured = captured.as_ref().unwrap();
        assert_eq!(captured.request.spec.if_generation_match, Some(0));
        assert_eq!(captured.request.spec.if_generation_not_match, None);
        assert_eq!(captured.request.spec.if_metageneration_match, None);
        assert_eq!(captured.request.spec.if_metageneration_not_match, None);
        let resource = captured.request.spec.resource.as_ref().unwrap();
        assert_eq!(resource.bucket, "projects/_/buckets/xenia-authority-retention-test");
        assert_eq!(resource.name, expected_name);
        assert_eq!(captured.bytes, bytes);
        assert_eq!(captured.resumable_threshold, usize::MAX);
    }

    #[tokio::test]
    async fn oversize_is_rejected_before_google_stub_call() {
        let stub = Arc::new(CaptureStub::default());
        let client = Storage::from_stub(stub.clone());
        let transport = GcsAuthorityCreateTransportV1::new(client, profile()).unwrap();
        let bytes = vec![0u8; GCS_AUTHORITY_CREATE_MAX_BYTES_V1 + 1];

        assert!(matches!(
            transport.create_if_absent(&locator(), &bytes).await,
            Err(GcsCreateTransportErrorV1::CanonicalObjectTooLarge { .. })
        ));
        assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn generation_precondition_failure_remains_already_exists_for_adr028_readback() {
        let stub = Arc::new(ErrorStub {
            calls: AtomicUsize::new(0),
            code: Code::FailedPrecondition,
        });
        let client = Storage::from_stub(stub.clone());
        let transport = GcsAuthorityCreateTransportV1::new(client, profile()).unwrap();

        assert_eq!(
            transport.create_if_absent(&locator(), b"canonical").await.unwrap(),
            BackendCreateOutcomeV1::AlreadyExists
        );
        assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ambiguous_service_failure_remains_unknown() {
        let stub = Arc::new(ErrorStub {
            calls: AtomicUsize::new(0),
            code: Code::DeadlineExceeded,
        });
        let client = Storage::from_stub(stub.clone());
        let transport = GcsAuthorityCreateTransportV1::new(client, profile()).unwrap();

        assert_eq!(
            transport.create_if_absent(&locator(), b"canonical").await.unwrap(),
            BackendCreateOutcomeV1::Unknown
        );
        assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
    }
}
