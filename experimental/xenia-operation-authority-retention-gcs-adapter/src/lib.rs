// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conservative Google Cloud Storage SDK error classification for Xenia authority retention.
//!
//! This crate is intentionally below ADR-028's durability state machine and ADR-029's namespace
//! authority gate. It translates the exact Google Rust SDK/GAX error surface into provider outcomes
//! without allowing automatic retries or optimistic timeout handling to redefine Xenia semantics.
//!
//! The first tranche is pure classification: no credentials, network access, Tokio runtime bridge,
//! or production bucket are required. Network transport is added only after this mapping qualifies.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use google_cloud_gax::error::{Error as GaxError, rpc::Code};
use xenia_operation_authority_retention_backend::BackendCreateOutcomeV1;

/// Frozen Google Storage SDK version for this adapter lineage.
pub const GCS_ADAPTER_STORAGE_SDK_VERSION_V1: &str = "1.18.0";
/// Frozen Google GAX version for this adapter lineage.
pub const GCS_ADAPTER_GAX_VERSION_V1: &str = "1.14.0";

/// Classification of one failed authoritative object read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcsReadErrorClassV1 {
    /// Service positively reports no live object at the exact object name.
    NotFound,
    /// Request is positively rejected in a way that cannot represent a successful read.
    Rejected,
    /// Current object state cannot be established from the failure.
    Unknown,
}

/// Classification of one failed complete-list operation/page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcsListErrorClassV1 {
    /// Request is positively rejected in a way that cannot represent a complete listing.
    Rejected,
    /// Listing completeness/current state cannot be established from the failure.
    Unknown,
}

/// Classify one failed generation-zero create attempt into ADR-028 provider semantics.
///
/// This function is valid only for the ADR-030 request profile: the write carries exactly
/// `ifGenerationMatch = 0` and no other mutable provider precondition. Under that frozen request,
/// `FailedPrecondition` / HTTP 412 means the live object name was already occupied and maps to
/// `AlreadyExists`. Any future additional precondition requires a new classifier/schema.
///
/// Serialization failure is rejectable because GAX documents it as a client-side failure before a
/// request is made. Timeout, deserialization, retry exhaustion, transient/service failures, and all
/// unrecognized cases remain `Unknown` because the object may have committed before the error was
/// observed.
pub fn classify_generation_zero_create_error_v1(error: &GaxError) -> BackendCreateOutcomeV1 {
    if error.is_serialization() {
        return BackendCreateOutcomeV1::Rejected;
    }
    if error.is_timeout() || error.is_deserialization() || error.is_exhausted() {
        return BackendCreateOutcomeV1::Unknown;
    }

    if let Some(status) = error.status() {
        return match status.code {
            Code::FailedPrecondition => BackendCreateOutcomeV1::AlreadyExists,
            Code::InvalidArgument
            | Code::Unauthenticated
            | Code::PermissionDenied
            | Code::NotFound
            | Code::AlreadyExists
            | Code::Unimplemented
            | Code::OutOfRange => BackendCreateOutcomeV1::Rejected,
            Code::Cancelled
            | Code::Unknown
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Internal
            | Code::Unavailable
            | Code::DataLoss => BackendCreateOutcomeV1::Unknown,
            Code::Ok => BackendCreateOutcomeV1::Unknown,
        };
    }

    match error.http_status_code() {
        Some(412) => BackendCreateOutcomeV1::AlreadyExists,
        Some(400 | 401 | 403 | 404 | 405 | 411 | 413 | 414 | 415 | 422 | 501) => {
            BackendCreateOutcomeV1::Rejected
        }
        // Conflict is *not* treated as generation-precondition evidence. Only HTTP 412 gets that
        // meaning in the frozen V1 request profile.
        Some(408 | 409 | 425 | 429) => BackendCreateOutcomeV1::Unknown,
        Some(code) if code >= 500 => BackendCreateOutcomeV1::Unknown,
        _ => BackendCreateOutcomeV1::Unknown,
    }
}

/// Classify one failed exact object read.
///
/// Reads are non-mutating, so SDK retry/resume is allowed in a later transport layer. This function
/// classifies only the final unresolved error. A service `NotFound`/HTTP 404 is authoritative
/// absence. Client serialization or definite auth/request rejection is `Rejected`; timeout,
/// deserialization, retry exhaustion, transient/server status, and unrecognized cases are `Unknown`.
pub fn classify_exact_read_error_v1(error: &GaxError) -> GcsReadErrorClassV1 {
    if error.is_serialization() {
        return GcsReadErrorClassV1::Rejected;
    }
    if error.is_timeout() || error.is_deserialization() || error.is_exhausted() {
        return GcsReadErrorClassV1::Unknown;
    }

    if let Some(status) = error.status() {
        return match status.code {
            Code::NotFound => GcsReadErrorClassV1::NotFound,
            Code::InvalidArgument
            | Code::Unauthenticated
            | Code::PermissionDenied
            | Code::FailedPrecondition
            | Code::AlreadyExists
            | Code::Unimplemented
            | Code::OutOfRange => GcsReadErrorClassV1::Rejected,
            Code::Cancelled
            | Code::Unknown
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Internal
            | Code::Unavailable
            | Code::DataLoss
            | Code::Ok => GcsReadErrorClassV1::Unknown,
        };
    }

    match error.http_status_code() {
        Some(404) => GcsReadErrorClassV1::NotFound,
        Some(400 | 401 | 403 | 405 | 411 | 413 | 414 | 415 | 422 | 501) => {
            GcsReadErrorClassV1::Rejected
        }
        Some(408 | 409 | 412 | 425 | 429) => GcsReadErrorClassV1::Unknown,
        Some(code) if code >= 500 => GcsReadErrorClassV1::Unknown,
        _ => GcsReadErrorClassV1::Unknown,
    }
}

/// Classify one failed object-list request/page.
///
/// ADR-028 requires a complete authoritative enumeration. Any transient, timeout, deserialization,
/// retry-exhaustion, server, or unrecognized failure therefore maps to `Unknown`; a later list
/// transport must never return `Complete` after one page in a multi-page listing failed.
pub fn classify_complete_list_error_v1(error: &GaxError) -> GcsListErrorClassV1 {
    if error.is_serialization() {
        return GcsListErrorClassV1::Rejected;
    }
    if error.is_timeout() || error.is_deserialization() || error.is_exhausted() {
        return GcsListErrorClassV1::Unknown;
    }

    if let Some(status) = error.status() {
        return match status.code {
            Code::InvalidArgument
            | Code::Unauthenticated
            | Code::PermissionDenied
            | Code::NotFound
            | Code::FailedPrecondition
            | Code::AlreadyExists
            | Code::Unimplemented
            | Code::OutOfRange => GcsListErrorClassV1::Rejected,
            Code::Cancelled
            | Code::Unknown
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Internal
            | Code::Unavailable
            | Code::DataLoss
            | Code::Ok => GcsListErrorClassV1::Unknown,
        };
    }

    match error.http_status_code() {
        Some(400 | 401 | 403 | 404 | 405 | 411 | 413 | 414 | 415 | 422 | 501) => {
            GcsListErrorClassV1::Rejected
        }
        Some(408 | 409 | 412 | 425 | 429) => GcsListErrorClassV1::Unknown,
        Some(code) if code >= 500 => GcsListErrorClassV1::Unknown,
        _ => GcsListErrorClassV1::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_gax::error::rpc::Status;

    fn service(code: Code) -> GaxError {
        GaxError::service(Status::default().set_code(code))
    }

    #[test]
    fn generation_precondition_failure_is_the_only_service_conflict_class() {
        assert_eq!(
            classify_generation_zero_create_error_v1(&service(Code::FailedPrecondition)),
            BackendCreateOutcomeV1::AlreadyExists
        );
        assert_eq!(
            classify_generation_zero_create_error_v1(&service(Code::AlreadyExists)),
            BackendCreateOutcomeV1::Rejected
        );
        assert_eq!(
            classify_generation_zero_create_error_v1(&service(Code::Aborted)),
            BackendCreateOutcomeV1::Unknown
        );
    }

    #[test]
    fn create_transient_and_server_codes_are_unknown() {
        for code in [
            Code::Cancelled,
            Code::Unknown,
            Code::DeadlineExceeded,
            Code::ResourceExhausted,
            Code::Aborted,
            Code::Internal,
            Code::Unavailable,
            Code::DataLoss,
        ] {
            assert_eq!(
                classify_generation_zero_create_error_v1(&service(code)),
                BackendCreateOutcomeV1::Unknown,
                "code {code:?} must remain ambiguous"
            );
        }
    }

    #[test]
    fn create_definite_request_or_authorization_rejections_are_rejected() {
        for code in [
            Code::InvalidArgument,
            Code::Unauthenticated,
            Code::PermissionDenied,
            Code::NotFound,
            Code::AlreadyExists,
            Code::Unimplemented,
            Code::OutOfRange,
        ] {
            assert_eq!(
                classify_generation_zero_create_error_v1(&service(code)),
                BackendCreateOutcomeV1::Rejected,
                "code {code:?} should be a definite rejection"
            );
        }
    }

    #[test]
    fn read_not_found_is_distinct_from_unknown() {
        assert_eq!(
            classify_exact_read_error_v1(&service(Code::NotFound)),
            GcsReadErrorClassV1::NotFound
        );
        assert_eq!(
            classify_exact_read_error_v1(&service(Code::Unavailable)),
            GcsReadErrorClassV1::Unknown
        );
    }

    #[test]
    fn incomplete_list_transients_are_unknown() {
        for code in [
            Code::Cancelled,
            Code::DeadlineExceeded,
            Code::ResourceExhausted,
            Code::Aborted,
            Code::Internal,
            Code::Unavailable,
            Code::DataLoss,
        ] {
            assert_eq!(
                classify_complete_list_error_v1(&service(code)),
                GcsListErrorClassV1::Unknown
            );
        }
    }
}
