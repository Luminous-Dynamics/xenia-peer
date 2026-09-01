// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use google_cloud_gax::error::{Error as GaxError, rpc::{Code, Status}};
use xenia_operation_authority_retention_backend::BackendCreateOutcomeV1;
use xenia_operation_authority_retention_gcs_adapter::{
    GcsListErrorClassV1, GcsReadErrorClassV1, classify_complete_list_error_v1,
    classify_exact_read_error_v1, classify_generation_zero_create_error_v1,
};

#[test]
fn timeout_is_unknown_for_create_read_and_list() {
    let create = GaxError::timeout("simulated create timeout");
    assert_eq!(
        classify_generation_zero_create_error_v1(&create),
        BackendCreateOutcomeV1::Unknown
    );

    let read = GaxError::timeout("simulated read timeout");
    assert_eq!(classify_exact_read_error_v1(&read), GcsReadErrorClassV1::Unknown);

    let list = GaxError::timeout("simulated list timeout");
    assert_eq!(
        classify_complete_list_error_v1(&list),
        GcsListErrorClassV1::Unknown
    );
}

#[test]
fn exhausted_retry_policy_never_becomes_definite_create_rejection() {
    let error = GaxError::exhausted("simulated retry exhaustion");
    assert_eq!(
        classify_generation_zero_create_error_v1(&error),
        BackendCreateOutcomeV1::Unknown
    );
}

#[test]
fn deadline_exceeded_stays_unknown_for_mutating_create() {
    let error = GaxError::service(Status::default().set_code(Code::DeadlineExceeded));
    assert_eq!(
        classify_generation_zero_create_error_v1(&error),
        BackendCreateOutcomeV1::Unknown
    );
}

#[test]
fn generation_precondition_service_failure_requires_exact_read_resolution_upstream() {
    let error = GaxError::service(Status::default().set_code(Code::FailedPrecondition));
    assert_eq!(
        classify_generation_zero_create_error_v1(&error),
        BackendCreateOutcomeV1::AlreadyExists
    );
}
