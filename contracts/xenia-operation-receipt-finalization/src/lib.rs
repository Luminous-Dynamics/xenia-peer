// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Standalone finalization contract for Xenia privileged-operation receipts.
//!
//! This crate exists to qualify the pre-freeze receipt semantics independently
//! from the production workspace while the stacked execution branch is still
//! undergoing lockfile/format qualification. It performs no storage and causes
//! no privileged side effects.
//!
//! The contract freezes two ADR-008 amendments that must be folded back into
//! `xenia-operation-receipt-proto` before its V1 serialized layout is declared
//! stable:
//!
//! 1. `EffectArmed` binds the exact fresh effect-arm authorization digest.
//! 2. `CancelledAfterArmBeforeEffect` is a distinct terminal state and requires
//!    positive evidence that adapter invocation never began.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standalone candidate schema used only during V1 finalization.
pub const RECEIPT_FINALIZATION_SCHEMA_V1: &str =
    "xenia-operation-receipt-event-v1-finalization";
/// Domain separator for finalization-candidate receipt commitments.
pub const RECEIPT_FINALIZATION_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-receipt-event-v1-finalization-digest";

/// Minimal immutable admission binding needed to validate a receipt chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptAdmissionBindingV1 {
    /// Exact immutable admission digest.
    pub admission_digest: [u8; 32],
    /// Exact operation identifier carried by the admission.
    pub operation_id: [u8; 16],
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
}

impl ReceiptAdmissionBindingV1 {
    /// Validate non-sentinel admission bindings.
    pub fn validate(self) -> Result<(), ReceiptFinalizationError> {
        if self.admission_digest == [0u8; 32] {
            return Err(ReceiptFinalizationError::ZeroAdmissionDigest);
        }
        if self.operation_id == [0u8; 16] {
            return Err(ReceiptFinalizationError::ZeroOperationId);
        }
        Ok(())
    }
}

/// Durable operation lifecycle state after immutable admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptStateV1 {
    /// Write-ahead marker permitting an adapter to approach its effect boundary.
    EffectArmed,
    /// Admission was consumed, but the operation was cancelled before arming.
    CancelledBeforeEffect,
    /// Effect was armed, but Xenia positively proved adapter invocation never began.
    CancelledAfterArmBeforeEffect,
    /// Adapter positively established its defined success condition.
    Completed,
    /// Adapter positively established a defined failure after invocation could begin.
    FailedKnown,
    /// Effect was armed and the target outcome cannot be proven.
    OutcomeUnknown,
}

impl ReceiptStateV1 {
    /// Whether this state permanently terminates the operation lifecycle.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CancelledBeforeEffect
                | Self::CancelledAfterArmBeforeEffect
                | Self::Completed
                | Self::FailedKnown
                | Self::OutcomeUnknown
        )
    }

    fn requires_arm_authorization(self) -> bool {
        matches!(self, Self::EffectArmed)
    }

    fn requires_terminal_evidence(self) -> bool {
        matches!(
            self,
            Self::CancelledAfterArmBeforeEffect
                | Self::Completed
                | Self::FailedKnown
                | Self::OutcomeUnknown
        )
    }
}

/// One append-only post-admission receipt transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptEventV1 {
    /// Exact candidate schema label.
    pub schema: String,
    /// Exact immutable admission digest extended by this event.
    pub admission_digest: [u8; 32],
    /// Exact operation id copied from the admission.
    pub operation_id: [u8; 16],
    /// Zero-based event position after admission.
    pub event_index: u32,
    /// Previous event digest, or all zero for event zero.
    pub previous_event_digest: [u8; 32],
    /// New durable lifecycle state.
    pub state: ReceiptStateV1,
    /// Durable event time in Unix milliseconds.
    pub recorded_at_unix_ms: u64,
    /// Exact fresh arm-authorization commitment.
    ///
    /// Required only for `EffectArmed`; later events bind it through the
    /// previous-event digest chain.
    pub arm_authorization_digest: Option<[u8; 32]>,
    /// Commitment to outcome, recovery, or positive no-invocation evidence.
    ///
    /// Required for every terminal state after `EffectArmed`. It is forbidden
    /// for `EffectArmed` and `CancelledBeforeEffect`.
    pub evidence_digest: Option<[u8; 32]>,
}

impl ReceiptEventV1 {
    /// Validate event-local field semantics.
    pub fn validate_shape(&self) -> Result<(), ReceiptFinalizationError> {
        if self.schema != RECEIPT_FINALIZATION_SCHEMA_V1 {
            return Err(ReceiptFinalizationError::UnsupportedSchema);
        }
        if self.admission_digest == [0u8; 32] {
            return Err(ReceiptFinalizationError::ZeroAdmissionDigest);
        }
        if self.operation_id == [0u8; 16] {
            return Err(ReceiptFinalizationError::ZeroOperationId);
        }

        if self.state.requires_arm_authorization() {
            match self.arm_authorization_digest {
                Some(digest) if digest != [0u8; 32] => {}
                _ => return Err(ReceiptFinalizationError::MissingArmAuthorization),
            }
        } else if self.arm_authorization_digest.is_some() {
            return Err(ReceiptFinalizationError::UnexpectedArmAuthorization);
        }

        if self.state.requires_terminal_evidence() {
            match self.evidence_digest {
                Some(digest) if digest != [0u8; 32] => {}
                _ => return Err(ReceiptFinalizationError::MissingTerminalEvidence),
            }
        } else if self.evidence_digest.is_some() {
            return Err(ReceiptFinalizationError::UnexpectedTerminalEvidence);
        }
        Ok(())
    }

    /// Validate the first post-admission event.
    pub fn validate_first(
        &self,
        admission: ReceiptAdmissionBindingV1,
    ) -> Result<(), ReceiptFinalizationError> {
        self.validate_shape()?;
        admission.validate()?;
        if self.admission_digest != admission.admission_digest {
            return Err(ReceiptFinalizationError::AdmissionMismatch);
        }
        if self.operation_id != admission.operation_id {
            return Err(ReceiptFinalizationError::OperationMismatch);
        }
        if self.event_index != 0 {
            return Err(ReceiptFinalizationError::BadFirstIndex);
        }
        if self.previous_event_digest != [0u8; 32] {
            return Err(ReceiptFinalizationError::BadFirstPreviousDigest);
        }
        if self.recorded_at_unix_ms < admission.admitted_at_unix_ms {
            return Err(ReceiptFinalizationError::TimestampRegression);
        }
        if !matches!(
            self.state,
            ReceiptStateV1::EffectArmed | ReceiptStateV1::CancelledBeforeEffect
        ) {
            return Err(ReceiptFinalizationError::InvalidFirstState);
        }
        Ok(())
    }

    /// Validate the exact monotonic successor of a prior receipt event.
    pub fn validate_successor(
        &self,
        admission: ReceiptAdmissionBindingV1,
        previous: &Self,
    ) -> Result<(), ReceiptFinalizationError> {
        self.validate_shape()?;
        previous.validate_shape()?;
        admission.validate()?;

        if self.admission_digest != admission.admission_digest
            || previous.admission_digest != admission.admission_digest
        {
            return Err(ReceiptFinalizationError::AdmissionMismatch);
        }
        if self.operation_id != admission.operation_id
            || previous.operation_id != admission.operation_id
        {
            return Err(ReceiptFinalizationError::OperationMismatch);
        }
        let expected_index = previous
            .event_index
            .checked_add(1)
            .ok_or(ReceiptFinalizationError::EventIndexOverflow)?;
        if self.event_index != expected_index {
            return Err(ReceiptFinalizationError::EventIndexMismatch);
        }
        if self.previous_event_digest != previous.event_digest()? {
            return Err(ReceiptFinalizationError::PreviousDigestMismatch);
        }
        if self.recorded_at_unix_ms < previous.recorded_at_unix_ms {
            return Err(ReceiptFinalizationError::TimestampRegression);
        }
        if previous.state.is_terminal() {
            return Err(ReceiptFinalizationError::TerminalExtended);
        }

        match previous.state {
            ReceiptStateV1::EffectArmed => {
                if !matches!(
                    self.state,
                    ReceiptStateV1::CancelledAfterArmBeforeEffect
                        | ReceiptStateV1::Completed
                        | ReceiptStateV1::FailedKnown
                        | ReceiptStateV1::OutcomeUnknown
                ) {
                    return Err(ReceiptFinalizationError::InvalidTransition);
                }
            }
            ReceiptStateV1::CancelledBeforeEffect
            | ReceiptStateV1::CancelledAfterArmBeforeEffect
            | ReceiptStateV1::Completed
            | ReceiptStateV1::FailedKnown
            | ReceiptStateV1::OutcomeUnknown => {
                return Err(ReceiptFinalizationError::TerminalExtended);
            }
        }
        Ok(())
    }

    /// Canonical bincode-v1 bytes for deterministic evidence binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptFinalizationError> {
        self.validate_shape()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3 commitment to this exact event.
    pub fn event_digest(&self) -> Result<[u8; 32], ReceiptFinalizationError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECEIPT_FINALIZATION_DIGEST_DOMAIN_V1);
        hasher.update(&self.canonical_bytes()?);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Validate an entire append-only receipt chain against one admission.
pub fn validate_chain(
    admission: ReceiptAdmissionBindingV1,
    events: &[ReceiptEventV1],
) -> Result<(), ReceiptFinalizationError> {
    admission.validate()?;
    let Some(first) = events.first() else {
        return Ok(());
    };
    first.validate_first(admission)?;
    for pair in events.windows(2) {
        pair[1].validate_successor(admission, &pair[0])?;
    }
    Ok(())
}

/// Receipt finalization validation failure.
#[derive(Debug, Error)]
pub enum ReceiptFinalizationError {
    /// Schema label differs from the exact finalization candidate.
    #[error("unsupported receipt finalization schema")]
    UnsupportedSchema,
    /// Admission digest is unset.
    #[error("admission digest must not be zero")]
    ZeroAdmissionDigest,
    /// Operation id is unset.
    #[error("operation id must not be zero")]
    ZeroOperationId,
    /// `EffectArmed` lacks a fresh authorization commitment.
    #[error("effect armed requires a non-zero arm authorization digest")]
    MissingArmAuthorization,
    /// A non-armed state carried an arm authorization commitment.
    #[error("only effect armed may carry arm authorization digest")]
    UnexpectedArmAuthorization,
    /// A post-arm terminal state lacks positive evidence.
    #[error("post-arm terminal state requires non-zero evidence digest")]
    MissingTerminalEvidence,
    /// A state that should not carry terminal evidence did so.
    #[error("effect armed/cancelled-before-effect must not carry terminal evidence")]
    UnexpectedTerminalEvidence,
    /// Event admission digest differs from the immutable admission.
    #[error("receipt admission digest mismatch")]
    AdmissionMismatch,
    /// Event operation id differs from the immutable admission.
    #[error("receipt operation id mismatch")]
    OperationMismatch,
    /// First post-admission event index was not zero.
    #[error("first event index must be zero")]
    BadFirstIndex,
    /// First event previous digest was not the zero sentinel.
    #[error("first previous digest must be zero")]
    BadFirstPreviousDigest,
    /// First state was neither armed nor cancelled-before-effect.
    #[error("invalid first receipt state")]
    InvalidFirstState,
    /// Receipt time regressed.
    #[error("receipt timestamp regressed")]
    TimestampRegression,
    /// Event index overflowed.
    #[error("receipt event index overflow")]
    EventIndexOverflow,
    /// Event index was not the exact successor.
    #[error("receipt event index mismatch")]
    EventIndexMismatch,
    /// Previous event digest did not bind the actual predecessor.
    #[error("receipt previous-event digest mismatch")]
    PreviousDigestMismatch,
    /// State transition is not permitted.
    #[error("invalid receipt state transition")]
    InvalidTransition,
    /// A terminal state was extended.
    #[error("terminal receipt state may not be extended")]
    TerminalExtended,
    /// Canonical serialization failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission() -> ReceiptAdmissionBindingV1 {
        ReceiptAdmissionBindingV1 {
            admission_digest: [1u8; 32],
            operation_id: [2u8; 16],
            admitted_at_unix_ms: 10,
        }
    }

    fn first(state: ReceiptStateV1) -> ReceiptEventV1 {
        ReceiptEventV1 {
            schema: RECEIPT_FINALIZATION_SCHEMA_V1.to_string(),
            admission_digest: [1u8; 32],
            operation_id: [2u8; 16],
            event_index: 0,
            previous_event_digest: [0u8; 32],
            state,
            recorded_at_unix_ms: 11,
            arm_authorization_digest: matches!(state, ReceiptStateV1::EffectArmed)
                .then_some([3u8; 32]),
            evidence_digest: None,
        }
    }

    fn next(previous: &ReceiptEventV1, state: ReceiptStateV1, evidence: Option<[u8; 32]>) -> ReceiptEventV1 {
        ReceiptEventV1 {
            schema: RECEIPT_FINALIZATION_SCHEMA_V1.to_string(),
            admission_digest: [1u8; 32],
            operation_id: [2u8; 16],
            event_index: previous.event_index + 1,
            previous_event_digest: previous.event_digest().unwrap(),
            state,
            recorded_at_unix_ms: previous.recorded_at_unix_ms + 1,
            arm_authorization_digest: None,
            evidence_digest: evidence,
        }
    }

    #[test]
    fn armed_requires_exact_fresh_authorization() {
        let mut armed = first(ReceiptStateV1::EffectArmed);
        assert!(armed.validate_first(admission()).is_ok());
        armed.arm_authorization_digest = None;
        assert!(matches!(
            armed.validate_first(admission()),
            Err(ReceiptFinalizationError::MissingArmAuthorization)
        ));
    }

    #[test]
    fn cancelled_before_effect_cannot_smuggle_arm_authority() {
        let mut cancelled = first(ReceiptStateV1::CancelledBeforeEffect);
        cancelled.arm_authorization_digest = Some([9u8; 32]);
        assert!(matches!(
            cancelled.validate_first(admission()),
            Err(ReceiptFinalizationError::UnexpectedArmAuthorization)
        ));
    }

    #[test]
    fn positive_post_arm_cancel_is_distinct_and_terminal() {
        let armed = first(ReceiptStateV1::EffectArmed);
        let cancelled = next(
            &armed,
            ReceiptStateV1::CancelledAfterArmBeforeEffect,
            Some([4u8; 32]),
        );
        assert!(cancelled.validate_successor(admission(), &armed).is_ok());
        assert!(cancelled.state.is_terminal());
    }

    #[test]
    fn post_arm_cancel_without_no_invocation_proof_is_rejected() {
        let armed = first(ReceiptStateV1::EffectArmed);
        let cancelled = next(
            &armed,
            ReceiptStateV1::CancelledAfterArmBeforeEffect,
            None,
        );
        assert!(matches!(
            cancelled.validate_successor(admission(), &armed),
            Err(ReceiptFinalizationError::MissingTerminalEvidence)
        ));
    }

    #[test]
    fn direct_completion_from_admission_is_rejected() {
        let mut completed = first(ReceiptStateV1::Completed);
        completed.evidence_digest = Some([5u8; 32]);
        assert!(matches!(
            completed.validate_first(admission()),
            Err(ReceiptFinalizationError::InvalidFirstState)
        ));
    }

    #[test]
    fn unknown_outcome_is_terminal_and_cannot_be_rewritten() {
        let armed = first(ReceiptStateV1::EffectArmed);
        let unknown = next(&armed, ReceiptStateV1::OutcomeUnknown, Some([6u8; 32]));
        let completed = next(&unknown, ReceiptStateV1::Completed, Some([7u8; 32]));
        assert!(matches!(
            completed.validate_successor(admission(), &unknown),
            Err(ReceiptFinalizationError::TerminalExtended)
        ));
    }

    #[test]
    fn receipt_digest_binds_arm_authorization() {
        let first = first(ReceiptStateV1::EffectArmed);
        let mut second = first.clone();
        second.arm_authorization_digest = Some([8u8; 32]);
        assert_ne!(first.event_digest().unwrap(), second.event_digest().unwrap());
    }

    #[test]
    fn chain_rejects_forked_previous_digest() {
        let armed = first(ReceiptStateV1::EffectArmed);
        let mut completed = next(&armed, ReceiptStateV1::Completed, Some([5u8; 32]));
        completed.previous_event_digest = [9u8; 32];
        assert!(matches!(
            validate_chain(admission(), &[armed, completed]),
            Err(ReceiptFinalizationError::PreviousDigestMismatch)
        ));
    }
}
