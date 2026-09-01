// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Google Cloud Storage readback transport for Xenia authority retention.
//!
//! Reads are non-mutating, but their results still establish recovery evidence. V1 therefore
//! returns exact object bytes only after the complete Google read stream succeeds and returns a
//! complete sequence listing only after the paginator reaches a clean end. Partial bytes/items are
//! never surfaced as authoritative results.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use google_cloud_gax::paginator::ItemPaginator;
use google_cloud_storage::{
    client::{Storage, StorageControl},
    stub::{Storage as StorageStub, StorageControl as StorageControlStub},
};
use thiserror::Error;
use xenia_operation_authority_retention_backend::{
    AuthorityRetentionObjectLocatorV1, BackendEnumerateOutcomeV1, BackendReadOutcomeV1,
};
use xenia_operation_authority_retention_gcs_adapter::{
    GcsListErrorClassV1, GcsReadErrorClassV1, classify_complete_list_error_v1,
    classify_exact_read_error_v1,
};
use xenia_operation_authority_retention_gcs_create_transport::{
    GCS_AUTHORITY_CREATE_MAX_BYTES_V1, bucket_resource_name_v1,
};
use xenia_operation_authority_retention_gcs_profile::{
    GcsAuthorityRetentionProfileV1, GcsProfileErrorV1,
};

/// Exact read/list transport for one frozen ADR-030 GCS profile.
#[derive(Debug, Clone)]
pub struct GcsAuthorityReadbackTransportV1<D, C>
where
    D: StorageStub + 'static,
    C: StorageControlStub + 'static,
{
    data: Storage<D>,
    control: StorageControl<C>,
    profile: GcsAuthorityRetentionProfileV1,
}

impl<D, C> GcsAuthorityReadbackTransportV1<D, C>
where
    D: StorageStub + 'static,
    C: StorageControlStub + 'static,
{
    /// Construct after validating the exact ADR-030 provider profile.
    pub fn new(
        data: Storage<D>,
        control: StorageControl<C>,
        profile: GcsAuthorityRetentionProfileV1,
    ) -> Result<Self, GcsReadbackTransportErrorV1> {
        profile.validate()?;
        Ok(Self {
            data,
            control,
            profile,
        })
    }

    /// Read one immutable object completely before exposing any bytes as authoritative.
    pub async fn read_exact(
        &self,
        locator: &AuthorityRetentionObjectLocatorV1,
    ) -> Result<BackendReadOutcomeV1, GcsReadbackTransportErrorV1> {
        self.profile.validate()?;
        let bucket = bucket_resource_name_v1(&self.profile)?;
        let object = self
            .profile
            .object_name(locator.namespace_digest, locator.retention_sequence)?;

        let mut response = match self.data.read_object(bucket, object).send().await {
            Ok(response) => response,
            Err(error) => return Ok(map_read_error(&error)),
        };

        let metadata = response.object();
        if metadata.size < 0 {
            return Err(GcsReadbackTransportErrorV1::NegativeObjectSize);
        }
        if metadata.size as u64 > GCS_AUTHORITY_CREATE_MAX_BYTES_V1 as u64 {
            return Err(GcsReadbackTransportErrorV1::ExternalObjectTooLarge {
                observed_minimum: metadata.size as u64,
                maximum: GCS_AUTHORITY_CREATE_MAX_BYTES_V1,
            });
        }

        let mut bytes = Vec::with_capacity(
            (metadata.size as usize).min(GCS_AUTHORITY_CREATE_MAX_BYTES_V1),
        );
        while let Some(chunk) = response.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => return Ok(map_read_error(&error)),
            };
            if bytes.len().saturating_add(chunk.len()) > GCS_AUTHORITY_CREATE_MAX_BYTES_V1 {
                return Err(GcsReadbackTransportErrorV1::ExternalObjectTooLarge {
                    observed_minimum: bytes.len() as u64 + chunk.len() as u64,
                    maximum: GCS_AUTHORITY_CREATE_MAX_BYTES_V1,
                });
            }
            bytes.extend_from_slice(&chunk);
        }

        if bytes.is_empty() {
            return Err(GcsReadbackTransportErrorV1::EmptyExternalObject);
        }
        Ok(BackendReadOutcomeV1::Found(bytes))
    }

    /// Enumerate the complete exact ADR-030 namespace sequence.
    ///
    /// The result is `Complete` only after the Google paginator terminates normally. Any page/item
    /// error discards all sequences accumulated so far.
    pub async fn enumerate_complete(
        &self,
        namespace_digest: [u8; 32],
    ) -> Result<BackendEnumerateOutcomeV1, GcsReadbackTransportErrorV1> {
        self.profile.validate()?;
        let bucket = bucket_resource_name_v1(&self.profile)?;
        let prefix = self.profile.namespace_object_prefix(namespace_digest)?;
        let mut items = self
            .control
            .list_objects()
            .set_parent(bucket.clone())
            .set_prefix(prefix.clone())
            .set_versions(false)
            .by_item();

        let mut sequences = Vec::new();
        while let Some(item) = items.next().await {
            let object = match item {
                Ok(object) => object,
                Err(error) => {
                    return Ok(match classify_complete_list_error_v1(&error) {
                        GcsListErrorClassV1::Rejected => BackendEnumerateOutcomeV1::Rejected,
                        GcsListErrorClassV1::Unknown => BackendEnumerateOutcomeV1::Unknown,
                    });
                }
            };
            if object.bucket != bucket {
                return Err(GcsReadbackTransportErrorV1::ForeignBucketObject);
            }
            let sequence = parse_sequence_from_object_name_v1(&prefix, &object.name)?;
            if sequences.last().is_some_and(|previous| *previous >= sequence) {
                return Err(GcsReadbackTransportErrorV1::NonIncreasingEnumeration);
            }
            sequences.push(sequence);
        }

        Ok(BackendEnumerateOutcomeV1::Complete(sequences))
    }
}

fn map_read_error(error: &google_cloud_gax::error::Error) -> BackendReadOutcomeV1 {
    match classify_exact_read_error_v1(error) {
        GcsReadErrorClassV1::NotFound => BackendReadOutcomeV1::NotFound,
        GcsReadErrorClassV1::Rejected => BackendReadOutcomeV1::Rejected,
        GcsReadErrorClassV1::Unknown => BackendReadOutcomeV1::Unknown,
    }
}

/// Parse the exact ADR-030 fixed-width object-name grammar into a retention sequence.
pub fn parse_sequence_from_object_name_v1(
    expected_prefix: &str,
    object_name: &str,
) -> Result<u64, GcsReadbackTransportErrorV1> {
    let suffix = object_name
        .strip_prefix(expected_prefix)
        .ok_or(GcsReadbackTransportErrorV1::ForeignNamespaceObject)?;
    let digits = suffix
        .strip_suffix(".bin")
        .ok_or(GcsReadbackTransportErrorV1::MalformedObjectName)?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(GcsReadbackTransportErrorV1::MalformedObjectName);
    }
    let sequence = digits
        .parse::<u64>()
        .map_err(|_| GcsReadbackTransportErrorV1::MalformedObjectName)?;
    if format!("{sequence:020}.bin") != suffix {
        return Err(GcsReadbackTransportErrorV1::MalformedObjectName);
    }
    Ok(sequence)
}

/// Readback transport/profile/content validation errors.
#[derive(Debug, Error)]
pub enum GcsReadbackTransportErrorV1 {
    /// ADR-030 provider profile validation failed.
    #[error("GCS authority retention profile rejected readback transport: {0}")]
    Profile(#[from] GcsProfileErrorV1),
    /// ADR-032 create-transport shared profile helper failed.
    #[error("GCS authority create-profile helper rejected readback transport: {0}")]
    CreateProfile(
        #[from]
        xenia_operation_authority_retention_gcs_create_transport::GcsCreateTransportErrorV1,
    ),
    /// Google object metadata contained an invalid negative size.
    #[error("GCS retained object reported a negative size")]
    NegativeObjectSize,
    /// Object is larger than the V1 writer could have produced.
    #[error("GCS retained object exceeds qualified V1 bound: at least {observed_minimum} bytes > {maximum}")]
    ExternalObjectTooLarge {
        /// Lower bound already observed from metadata/streaming.
        observed_minimum: u64,
        /// Frozen V1 maximum.
        maximum: usize,
    },
    /// V1 canonical ADR-028 objects are never empty.
    #[error("GCS retained authority object is empty")]
    EmptyExternalObject,
    /// Listing returned an object from another bucket.
    #[error("GCS namespace listing returned an object from another bucket")]
    ForeignBucketObject,
    /// Listing returned an object outside the exact requested namespace prefix.
    #[error("GCS namespace listing returned a foreign-prefix object")]
    ForeignNamespaceObject,
    /// Object name does not match exact fixed-width ADR-030 grammar.
    #[error("GCS retained object name does not match ADR-030 grammar")]
    MalformedObjectName,
    /// Complete listing was not strictly increasing in retention sequence.
    #[error("GCS retained object enumeration is duplicate or out of order")]
    NonIncreasingEnumeration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use google_cloud_gax::{
        error::{
            Error as GaxError,
            rpc::{Code, Status},
        },
        response::Response,
    };
    use google_cloud_storage::{
        model::{ListObjectsRequest, ListObjectsResponse, Object, ReadObjectRequest},
        model_ext::ObjectHighlights,
        read_object::ReadObjectResponse,
        request_options::RequestOptions as DataRequestOptions,
        streaming_source::{SizeHint, StreamingSource},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use xenia_operation_authority_retention_gcs_profile::{
        GCS_AUTHORITY_RETENTION_PROFILE_SCHEMA_V1, GCS_RUNTIME_OBJECT_PERMISSIONS_V1,
        GCS_RUST_SDK_CRATE_V1, GCS_RUST_SDK_VERSION_V1, GCS_STORAGE_API_PROFILE_V1,
    };

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
                .map(|v| (*v).to_string())
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
            retention_sequence: 0,
        }
    }

    #[derive(Debug)]
    struct ReadSuccessStub;
    impl StorageStub for ReadSuccessStub {
        fn read_object(
            &self,
            _req: ReadObjectRequest,
            _options: DataRequestOptions,
        ) -> impl std::future::Future<Output = google_cloud_storage::Result<ReadObjectResponse>> + Send
        {
            async {
                let mut meta = ObjectHighlights::default();
                meta.size = 6;
                Ok(ReadObjectResponse::from_source(meta, "abcdef"))
            }
        }
    }

    #[derive(Debug)]
    struct PartialThenErrorSource {
        step: u8,
    }
    impl StreamingSource for PartialThenErrorSource {
        type Error = std::io::Error;

        fn next(
            &mut self,
        ) -> impl std::future::Future<Output = Option<Result<Bytes, Self::Error>>> + Send {
            let step = self.step;
            self.step = self.step.saturating_add(1);
            async move {
                match step {
                    0 => Some(Ok(Bytes::from_static(b"abc"))),
                    1 => Some(Err(std::io::Error::other("injected read failure"))),
                    _ => None,
                }
            }
        }

        fn size_hint(
            &self,
        ) -> impl std::future::Future<Output = Result<SizeHint, Self::Error>> + Send {
            async { Ok(SizeHint::with_exact(6)) }
        }
    }

    #[derive(Debug)]
    struct PartialReadStub;
    impl StorageStub for PartialReadStub {
        fn read_object(
            &self,
            _req: ReadObjectRequest,
            _options: DataRequestOptions,
        ) -> impl std::future::Future<Output = google_cloud_storage::Result<ReadObjectResponse>> + Send
        {
            async {
                let mut meta = ObjectHighlights::default();
                meta.size = 6;
                Ok(ReadObjectResponse::from_source(
                    meta,
                    PartialThenErrorSource { step: 0 },
                ))
            }
        }
    }

    #[derive(Debug)]
    struct OversizeSource {
        emitted: bool,
    }
    impl StreamingSource for OversizeSource {
        type Error = std::io::Error;

        fn next(
            &mut self,
        ) -> impl std::future::Future<Output = Option<Result<Bytes, Self::Error>>> + Send {
            let emit = !self.emitted;
            self.emitted = true;
            async move {
                emit.then(|| {
                    Ok(Bytes::from(vec![
                        7u8;
                        GCS_AUTHORITY_CREATE_MAX_BYTES_V1 + 1
                    ]))
                })
            }
        }

        fn size_hint(
            &self,
        ) -> impl std::future::Future<Output = Result<SizeHint, Self::Error>> + Send {
            async { Ok(SizeHint::with_exact(1)) }
        }
    }

    #[derive(Debug)]
    struct OversizeReadStub;
    impl StorageStub for OversizeReadStub {
        fn read_object(
            &self,
            _req: ReadObjectRequest,
            _options: DataRequestOptions,
        ) -> impl std::future::Future<Output = google_cloud_storage::Result<ReadObjectResponse>> + Send
        {
            async {
                let mut meta = ObjectHighlights::default();
                meta.size = 1;
                Ok(ReadObjectResponse::from_source(
                    meta,
                    OversizeSource { emitted: false },
                ))
            }
        }
    }

    #[derive(Debug)]
    struct EmptyControlStub;
    impl StorageControlStub for EmptyControlStub {}

    #[derive(Debug)]
    struct ListStub {
        calls: AtomicUsize,
        fail_second_page: bool,
    }
    impl StorageControlStub for ListStub {
        fn list_objects(
            &self,
            req: ListObjectsRequest,
            _options: google_cloud_gax::options::RequestOptions,
        ) -> impl std::future::Future<
            Output = google_cloud_storage::Result<Response<ListObjectsResponse>>,
        > + Send {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let fail_second = self.fail_second_page;
            async move {
                let prefix = req.prefix.clone();
                let parent = req.parent.clone();
                if req.page_token.is_empty() {
                    let first = Object::new()
                        .set_bucket(parent.clone())
                        .set_name(format!("{prefix}{:020}.bin", 0));
                    if fail_second {
                        Ok(Response::from(
                            ListObjectsResponse::new()
                                .set_objects([first])
                                .set_next_page_token("next"),
                        ))
                    } else {
                        let second = Object::new()
                            .set_bucket(parent)
                            .set_name(format!("{prefix}{:020}.bin", 1));
                        Ok(Response::from(
                            ListObjectsResponse::new().set_objects([first, second]),
                        ))
                    }
                } else {
                    Err(GaxError::service(
                        Status::default().set_code(Code::DataLoss),
                    ))
                }
            }
        }
    }

    #[tokio::test]
    async fn exact_read_returns_bytes_only_after_clean_stream_end() {
        let data = Storage::from_stub(ReadSuccessStub);
        let control = StorageControl::from_stub(EmptyControlStub);
        let transport = GcsAuthorityReadbackTransportV1::new(data, control, profile()).unwrap();
        assert_eq!(
            transport.read_exact(&locator()).await.unwrap(),
            BackendReadOutcomeV1::Found(b"abcdef".to_vec())
        );
    }

    #[tokio::test]
    async fn partial_stream_failure_discards_prefix_and_returns_unknown() {
        let data = Storage::from_stub(PartialReadStub);
        let control = StorageControl::from_stub(EmptyControlStub);
        let transport = GcsAuthorityReadbackTransportV1::new(data, control, profile()).unwrap();
        assert_eq!(
            transport.read_exact(&locator()).await.unwrap(),
            BackendReadOutcomeV1::Unknown
        );
    }

    #[tokio::test]
    async fn streaming_cap_rejects_object_even_when_metadata_claims_tiny_size() {
        let data = Storage::from_stub(OversizeReadStub);
        let control = StorageControl::from_stub(EmptyControlStub);
        let transport = GcsAuthorityReadbackTransportV1::new(data, control, profile()).unwrap();
        assert!(matches!(
            transport.read_exact(&locator()).await,
            Err(GcsReadbackTransportErrorV1::ExternalObjectTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn complete_listing_parses_exact_fixed_width_sequences() {
        let list = Arc::new(ListStub {
            calls: AtomicUsize::new(0),
            fail_second_page: false,
        });
        let data = Storage::from_stub(ReadSuccessStub);
        let control = StorageControl::from_stub(list.clone());
        let transport = GcsAuthorityReadbackTransportV1::new(data, control, profile()).unwrap();
        assert_eq!(
            transport
                .enumerate_complete(locator().namespace_digest)
                .await
                .unwrap(),
            BackendEnumerateOutcomeV1::Complete(vec![0, 1])
        );
        assert_eq!(list.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn second_page_failure_never_returns_partial_complete_listing() {
        let list = Arc::new(ListStub {
            calls: AtomicUsize::new(0),
            fail_second_page: true,
        });
        let data = Storage::from_stub(ReadSuccessStub);
        let control = StorageControl::from_stub(list.clone());
        let transport = GcsAuthorityReadbackTransportV1::new(data, control, profile()).unwrap();
        assert_eq!(
            transport
                .enumerate_complete(locator().namespace_digest)
                .await
                .unwrap(),
            BackendEnumerateOutcomeV1::Unknown
        );
        assert_eq!(list.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn object_name_parser_rejects_noncanonical_width_and_foreign_prefix() {
        let prefix = "xenia-authority-retention/v1/abc/";
        assert_eq!(
            parse_sequence_from_object_name_v1(prefix, &format!("{prefix}{:020}.bin", 9))
                .unwrap(),
            9
        );
        assert!(matches!(
            parse_sequence_from_object_name_v1(prefix, &format!("{prefix}9.bin")),
            Err(GcsReadbackTransportErrorV1::MalformedObjectName)
        ));
        assert!(matches!(
            parse_sequence_from_object_name_v1(prefix, "other/00000000000000000009.bin"),
            Err(GcsReadbackTransportErrorV1::ForeignNamespaceObject)
        ));
    }
}
