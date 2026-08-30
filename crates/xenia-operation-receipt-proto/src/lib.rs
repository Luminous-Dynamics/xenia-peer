// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime-free contracts for durable privileged-operation admission and receipts.
//!
//! This crate deliberately does not perform storage, process execution, network
//! I/O, secret access, target recovery, or retries. It defines the write-ahead
//! evidence objects and monotonic transition rules that a Xenia operation
//! runtime must durably enforce before crossing an external-effect boundary.
//!
//! The core safety claim is **at-most-once local admission**, not generic
//! exactly-once external effects. Arbitrary target systems cannot be made part
//! of Xenia's local transaction. When a crash makes the target outcome
//! unknowable, the protocol preserves that uncertainty instead of authorizing a
//! blind retry.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable schema label for [`OperationAdmissionV1`].
pub const OPERATION_ADMISSION_SCHEMA_V1: &str = "xenia-operation-admission-v1";
/// Stable schema label for [`OperationReceiptEventV1`].
pub const OPERATION_RECEIPT_EVENT_SCHEMA_V1: &str = "xenia-operation-receipt-event-v1";
/// Domain separator for immutable admission commitments.
pub const OPERATION_ADMISSION_DIGEST_DOMAIN_V1: &[u8] = b"xenia-operation-admission-digest-v1";
/// Domain separator for append-only receipt-event commitments.
pub const OPERATION_RECEIPT_EVENT_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-receipt-event-digest-v1";
/// Maximum adapter-name bytes in V1.
pub const MAX_ADAPTER_NAME_BYTES_V1: usize = 128;
/// Maximum adapter protocol-version label bytes in V1.
pub const MAX_ADAPTER_PROTOCOL_VERSION_BYTES_V1: usize = 64;

/// Identity of the enforcement adapter that will cross the external-effect boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperationAdapterIdentityV1 {
    /// Stable lower-case adapter identifier, for example `native-exec` or `redfish`.
    pub name: String,
    /// Stable adapter protocol/contract version, for example `exec-v1`.
    pub protocol_version: String,
    /// Optional commitment to the exact adapter implementation/build identity.
    pub implementation_digest: Option<[u8; 32]>,
}

impl OperationAdapterIdentityV1 {
    /// Validate bounded, canonical adapter identity fields.
    pub fn validate(&self) -> Result<(), OperationReceiptProtocolError> {
        validate_token(
            "adapter name",
            &self.name,
            MAX_ADAPTER_NAME_BYTES_V1,
            TokenAlphabet::LowerName,
        )?;
        validate_token(
            "adapter protocol version",
            &self.protocol_version,
            MAX_ADAPTER_PROTOCOL_VERSION_BYTES_V1,
            TokenAlphabet::Version,
        )?;
        if self.implementation_digest == Some([0u8; 32]) {
            return Err(OperationReceiptProtocolError::ZeroImplementationDigest);
        }
        Ok(())
    }
}

/// Adapter-declared recovery semantics for one admitted operation.
///
/// This declaration is committed before effect. It may not be widened after
/// admission merely because a retry would be convenient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplaySemanticsV1 {
    /// Safe default: Xenia never automatically starts another effect attempt.
    NonReplayable,
    /// The target supports a stable idempotency key bound to this logical operation.
    TargetIdempotencyKey {
        /// Commitment to the exact target idempotency key.
        key_digest: [u8; 32],
    },
    /// The target exposes recoverable transaction semantics strong enough for the adapter.
    Transactional {
        /// Commitment to the exact target transaction/recovery scope.
        transaction_scope_digest: [u8; 32],
    },
}

impl ReplaySemanticsV1 {
    /// Validate that replay-capable classes carry an explicit non-zero binding.
    pub fn validate(&self) -> Result<(), OperationReceiptProtocolError> {
        match self {
            Self::NonReplayable => Ok(()),
            Self::TargetIdempotencyKey { key_digest } if *key_digest == [0u8; 32] => {
                Err(OperationReceiptProtocolError::ZeroReplayBindingDigest)
            }
            Self::Transactional {
                transaction_scope_digest,
            } if *transaction_scope_digest == [0u8; 32] => {
                Err(OperationReceiptProtocolError::ZeroReplayBindingDigest)
            }
            Self::TargetIdempotencyKey { .. } | Self::Transactional { .. } => Ok(()),
        }
    }
}

/// Immutable write-ahead admission record for one privileged operation.
///
/// Storage must atomically enforce uniqueness of both `operation_id` and
/// (`grant_digest`, `use_index`) before this record is considered committed.
/// The external effect must not begin before this admission is durable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationAdmissionV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Unique operation identifier in the local evidence domain.
    pub operation_id: [u8; 16],
    /// Exact digest of the session-bound capability grant being consumed.
    pub grant_digest: [u8; 32],
    /// Exact digest of the validated `CapabilityUseV1`.
    pub use_digest: [u8; 32],
    /// Exact adapter request commitment.
    ///
    /// The all-zero digest is permitted because ADR-005 uses it as the
    /// canonical representation for a parameterless operation.
    pub request_digest: [u8; 32],
    /// Authenticated session-context commitment current at admission.
    pub session_context_hash: [u8; 32],
    /// Authenticated subject commitment current at admission.
    pub subject_fingerprint: [u8; 32],
    /// Exact consumed-use slot from the grant.
    pub use_index: u32,
    /// Monotonic durable admission sequence allocated by the runtime/storage domain.
    pub admission_sequence: u64,
    /// Exact adapter identity committed before effect.
    pub adapter: OperationAdapterIdentityV1,
    /// Exact replay/recovery semantics committed before effect.
    pub replay: ReplaySemanticsV1,
    /// Trusted-enough Unix-millisecond time at durable admission.
    pub admitted_at_unix_ms: u64,
}

impl OperationAdmissionV1 {
    /// Validate bounded immutable admission syntax.
    pub fn validate(&self) -> Result<(), OperationReceiptProtocolError> {
        if self.schema != OPERATION_ADMISSION_SCHEMA_V1 {
            return Err(OperationReceiptProtocolError::UnsupportedAdmissionSchema);
        }
        if self.operation_id == [0u8; 16] {
            return Err(OperationReceiptProtocolError::ZeroOperationId);
        }
        if self.grant_digest == [0u8; 32] {
            return Err(OperationReceiptProtocolError::ZeroGrantDigest);
        }
        if self.use_digest == [0u8; 32] {
            return Err(OperationReceiptProtocolError::ZeroUseDigest);
        }
        if self.session_context_hash == [0u8; 32] {
            return Err(OperationReceiptProtocolError::ZeroSessionContextHash);
        }
        if self.subject_fingerprint == [0u8; 32] {
            return Err(OperationReceiptProtocolError::ZeroSubjectFingerprint);
        }
        self.adapter.validate()?;
        self.replay.validate()?;
        Ok(())
    }

    /// Deterministic canonical bincode-v1 bytes for evidence/signature binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperationReceiptProtocolError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3-256 commitment to the complete immutable admission.
    pub fn admission_digest(&self) -> Result<[u8; 32], OperationReceiptProtocolError> {
        Ok(domain_digest(
            OPERATION_ADMISSION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    /// Storage uniqueness key for the consumed grant-use slot.
    pub fn reservation_key(&self) -> GrantUseReservationKeyV1 {
        GrantUseReservationKeyV1 {
            grant_digest: self.grant_digest,
            use_index: self.use_index,
        }
    }
}

/// Key whose uniqueness prevents two operations from consuming one grant use slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GrantUseReservationKeyV1 {
    /// Exact grant commitment.
    pub grant_digest: [u8; 32],
    /// Exact use slot within that grant.
    pub use_index: u32,
}

/// Durable state appended after admission.
///
/// `EffectArmed` is intentionally a write-ahead state. Once it is durably
/// recorded, the adapter is permitted to cross its external-effect boundary.
/// A crash after `EffectArmed` is therefore treated as potentially having
/// caused the effect even if the actual target call had not yet begun.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationReceiptStateV1 {
    /// Durable write-ahead marker permitting the adapter to begin the external effect.
    EffectArmed,
    /// Admission was consumed, but Xenia knows the effect boundary was never armed.
    CancelledBeforeEffect,
    /// Adapter positively established its defined success condition.
    Completed,
    /// Adapter positively established a defined failure after the effect was armed.
    FailedKnown,
    /// The effect was armed but its target outcome cannot be proven.
    OutcomeUnknown,
}

impl OperationReceiptStateV1 {
    /// Whether this state is terminal and may never be replaced by another state.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CancelledBeforeEffect | Self::Completed | Self::FailedKnown | Self::OutcomeUnknown
        )
    }

    fn requires_outcome_digest(self) -> bool {
        matches!(Self::Completed | Self::FailedKnown | Self::OutcomeUnknown, self)
    }
}

/// One append-only operation-receipt transition.
///
/// Admission itself is the initial durable state, so the first event has
/// `event_index == 0` and can only be `EffectArmed` or
/// `CancelledBeforeEffect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReceiptEventV1 {
    /// Exact V1 event schema label.
    pub schema: String,
    /// Exact immutable admission commitment this event extends.
    pub admission_digest: [u8; 32],
    /// Operation id copied from the immutable admission for indexed lookup.
    pub operation_id: [u8; 16],
    /// Zero-based event position in this operation's receipt chain.
    pub event_index: u32,
    /// Previous event digest, or all zeros for the first post-admission event.
    pub previous_event_digest: [u8; 32],
    /// New durable state.
    pub state: OperationReceiptStateV1,
    /// Trusted-enough Unix-millisecond time when this state was durably recorded.
    pub recorded_at_unix_ms: u64,
    /// Commitment to separately governed outcome/recovery evidence.
    ///
    /// Required and non-zero for `Completed`, `FailedKnown`, and
    /// `OutcomeUnknown`; forbidden for `EffectArmed` and
    /// `CancelledBeforeEffect`.
    pub outcome_digest: Option<[u8; 32]>,
}

impl OperationReceiptEventV1 {
    /// Validate event-local shape independent of chain position.
    pub fn validate_shape(&self) -> Result<(), OperationReceiptProtocolError> {
        if self.schema != OPERATION_RECEIPT_EVENT_SCHEMA_V1 {
            return Err(OperationReceiptProtocolError::UnsupportedReceiptEventSchema);
        }
        if self.admission_digest == [0u8; 32] {
            return Err(OperationReceiptProtocolError::ZeroAdmissionDigest);
        }
        if self.operation_id == [0u8; 16] {
            return Err(OperationReceiptProtocolError::ZeroOperationId);
        }
        if self.state.requires_outcome_digest() {
            match self.outcome_digest {
                Some(digest) if digest != [0u8; 32] => {}
                _ => return Err(OperationReceiptProtocolError::MissingOutcomeDigest),
            }
        } else if self.outcome_digest.is_some() {
            return Err(OperationReceiptProtocolError::UnexpectedOutcomeDigest);
        }
        Ok(())
    }

    /// Validate the first receipt event against its immutable admission.
    pub fn validate_first(
        &self,
        admission: &OperationAdmissionV1,
    ) -> Result<(), OperationReceiptProtocolError> {
        self.validate_shape()?;
        admission.validate()?;
        if self.admission_digest != admission.admission_digest()? {
            return Err(OperationReceiptProtocolError::AdmissionDigestMismatch);
        }
        if self.operation_id != admission.operation_id {
            return Err(OperationReceiptProtocolError::OperationIdMismatch);
        }
        if self.event_index != 0 {
            return Err(OperationReceiptProtocolError::BadFirstEventIndex);
        }
        if self.previous_event_digest != [0u8; 32] {
            return Err(OperationReceiptProtocolError::BadFirstPreviousDigest);
        }
        if self.recorded_at_unix_ms < admission.admitted_at_unix_ms {
            return Err(OperationReceiptProtocolError::TimestampRegression);
        }
        if !matches!(
            self.state,
            OperationReceiptStateV1::EffectArmed
                | OperationReceiptStateV1::CancelledBeforeEffect
        ) {
            return Err(OperationReceiptProtocolError::InvalidFirstState);
        }
        Ok(())
    }

    /// Validate this event as the exact monotonic successor of `previous`.
    pub fn validate_successor(
        &self,
        admission: &OperationAdmissionV1,
        previous: &Self,
    ) -> Result<(), OperationReceiptProtocolError> {
        self.validate_shape()?;
        previous.validate_shape()?;
        admission.validate()?;

        let admission_digest = admission.admission_digest()?;
        if self.admission_digest != admission_digest || previous.admission_digest != admission_digest {
            return Err(OperationReceiptProtocolError::AdmissionDigestMismatch);
        }
        if self.operation_id != admission.operation_id
            || previous.operation_id != admission.operation_id
        {
            return Err(OperationReceiptProtocolError::OperationIdMismatch);
        }
        let expected_index = previous
            .event_index
            .checked_add(1)
            .ok_or(OperationReceiptProtocolError::EventIndexOverflow)?;
        if self.event_index != expected_index {
            return Err(OperationReceiptProtocolError::EventIndexMismatch);
        }
        if self.previous_event_digest != previous.event_digest()? {
            return Err(OperationReceiptProtocolError::PreviousEventDigestMismatch);
        }
        if self.recorded_at_unix_ms < previous.recorded_at_unix_ms {
            return Err(OperationReceiptProtocolError::TimestampRegression);
        }
        if previous.state.is_terminal() {
            return Err(OperationReceiptProtocolError::TerminalStateExtended);
        }
        match previous.state {
            OperationReceiptStateV1::EffectArmed => {
                if !matches!(
                    self.state,
                    OperationReceiptStateV1::Completed
                        | OperationReceiptStateV1::FailedKnown
                        | OperationReceiptStateV1::OutcomeUnknown
                ) {
                    return Err(OperationReceiptProtocolError::InvalidStateTransition);
                }
            }
            OperationReceiptStateV1::CancelledBeforeEffect
            | OperationReceiptStateV1::Completed
            | OperationReceiptStateV1::FailedKnown
            | OperationReceiptStateV1::OutcomeUnknown => {
                return Err(OperationReceiptProtocolError::TerminalStateExtended);
            }
        }
        Ok(())
    }

    /// Deterministic canonical bincode-v1 bytes for this receipt event.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperationReceiptProtocolError> {
        self.validate_shape()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3-256 commitment to this receipt event.
    pub fn event_digest(&self) -> Result<[u8; 32], OperationReceiptProtocolError> {
        Ok(domain_digest(
            OPERATION_RECEIPT_EVENT_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Validate an entire append-only receipt chain against its admission.
pub fn validate_receipt_chain(
    admission: &OperationAdmissionV1,
    events: &[OperationReceiptEventV1],
) -> Result<(), OperationReceiptProtocolError> {
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

/// Protocol validation failure for durable operation admission/receipt evidence.
#[derive(Debug, Error)]
pub enum OperationReceiptProtocolError {
    /// Admission schema is not the exact V1 schema.
    #[error("unsupported operation admission schema")]
    UnsupportedAdmissionSchema,
    /// Receipt-event schema is not the exact V1 schema.
    #[error("unsupported operation receipt event schema")]
    UnsupportedReceiptEventSchema,
    /// Operation id is the all-zero unset sentinel.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Grant digest is the all-zero unset sentinel.
    #[error("grant digest must not be all zero")]
    ZeroGrantDigest,
    /// Capability-use digest is the all-zero unset sentinel.
    #[error("use digest must not be all zero")]
    ZeroUseDigest,
    /// Session-context commitment is the all-zero unset sentinel.
    #[error("session context hash must not be all zero")]
    ZeroSessionContextHash,
    /// Subject commitment is the all-zero unset sentinel.
    #[error("subject fingerprint must not be all zero")]
    ZeroSubjectFingerprint,
    /// Adapter implementation digest, when present, must not be all zero.
    #[error("adapter implementation digest must not be all zero")]
    ZeroImplementationDigest,
    /// Replay-capable semantics require a non-zero target binding commitment.
    #[error("replay binding digest must not be all zero")]
    ZeroReplayBindingDigest,
    /// Admission commitment is the all-zero unset sentinel.
    #[error("admission digest must not be all zero")]
    ZeroAdmissionDigest,
    /// A required outcome/recovery commitment is absent or all zero.
    #[error("terminal post-effect state requires a non-zero outcome digest")]
    MissingOutcomeDigest,
    /// A non-outcome state unexpectedly carried outcome evidence.
    #[error("effect-armed/cancelled state must not carry an outcome digest")]
    UnexpectedOutcomeDigest,
    /// Adapter/resource token text is empty, oversized, non-ASCII, or non-canonical.
    #[error("invalid token field: {0}")]
    InvalidToken(&'static str),
    /// First event did not commit to the exact admission.
    #[error("receipt event admission digest does not match admission")]
    AdmissionDigestMismatch,
    /// Receipt event operation id differs from the admission.
    #[error("receipt event operation id does not match admission")]
    OperationIdMismatch,
    /// First post-admission event must have index zero.
    #[error("first receipt event index must be zero")]
    BadFirstEventIndex,
    /// First event must use the all-zero previous-event sentinel.
    #[error("first receipt event previous digest must be all zero")]
    BadFirstPreviousDigest,
    /// First event may only arm the effect or cancel before effect.
    #[error("invalid first receipt state")]
    InvalidFirstState,
    /// Receipt event index is not the exact successor index.
    #[error("receipt event index is not the exact successor index")]
    EventIndexMismatch,
    /// Event index overflowed u32.
    #[error("receipt event index overflow")]
    EventIndexOverflow,
    /// Previous-event commitment does not match the actual prior event.
    #[error("receipt previous-event digest mismatch")]
    PreviousEventDigestMismatch,
    /// Durable receipt time moved backward.
    #[error("receipt timestamp regressed")]
    TimestampRegression,
    /// State transition is not permitted by the V1 monotonic lifecycle.
    #[error("invalid operation receipt state transition")]
    InvalidStateTransition,
    /// An immutable terminal receipt was extended.
    #[error("terminal operation receipt state may not be extended")]
    TerminalStateExtended,
    /// Canonical bincode serialization failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

#[derive(Clone, Copy)]
enum TokenAlphabet {
    LowerName,
    Version,
}

fn validate_token(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    alphabet: TokenAlphabet,
) -> Result<(), OperationReceiptProtocolError> {
    if value.is_empty() || value.len() > max_bytes || !value.is_ascii() {
        return Err(OperationReceiptProtocolError::InvalidToken(field));
    }
    let valid = match alphabet {
        TokenAlphabet::LowerName => value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-')
        }),
        TokenAlphabet::Version => value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
        }),
    };
    if !valid {
        return Err(OperationReceiptProtocolError::InvalidToken(field));
    }
    Ok(())
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> OperationAdapterIdentityV1 {
        OperationAdapterIdentityV1 {
            name: "native-exec".to_string(),
            protocol_version: "exec-v1".to_string(),
            implementation_digest: Some([7u8; 32]),
        }
    }

    fn admission() -> OperationAdmissionV1 {
        OperationAdmissionV1 {
            schema: OPERATION_ADMISSION_SCHEMA_V1.to_string(),
            operation_id: [1u8; 16],
            grant_digest: [2u8; 32],
            use_digest: [3u8; 32],
            request_digest: [4u8; 32],
            session_context_hash: [5u8; 32],
            subject_fingerprint: [6u8; 32],
            use_index: 2,
            admission_sequence: 41,
            adapter: adapter(),
            replay: ReplaySemanticsV1::NonReplayable,
            admitted_at_unix_ms: 10_000,
        }
    }

    fn first_event(
        admission: &OperationAdmissionV1,
        state: OperationReceiptStateV1,
    ) -> OperationReceiptEventV1 {
        OperationReceiptEventV1 {
            schema: OPERATION_RECEIPT_EVENT_SCHEMA_V1.to_string(),
            admission_digest: admission.admission_digest().unwrap(),
            operation_id: admission.operation_id,
            event_index: 0,
            previous_event_digest: [0u8; 32],
            state,
            recorded_at_unix_ms: 10_001,
            outcome_digest: None,
        }
    }

    fn successor(
        admission: &OperationAdmissionV1,
        previous: &OperationReceiptEventV1,
        state: OperationReceiptStateV1,
        outcome_digest: Option<[u8; 32]>,
    ) -> OperationReceiptEventV1 {
        OperationReceiptEventV1 {
            schema: OPERATION_RECEIPT_EVENT_SCHEMA_V1.to_string(),
            admission_digest: admission.admission_digest().unwrap(),
            operation_id: admission.operation_id,
            event_index: previous.event_index + 1,
            previous_event_digest: previous.event_digest().unwrap(),
            state,
            recorded_at_unix_ms: previous.recorded_at_unix_ms + 1,
            outcome_digest,
        }
    }

    #[test]
    fn admission_commitment_changes_with_replay_semantics() {
        let base = admission();
        let mut idempotent = base.clone();
        idempotent.replay = ReplaySemanticsV1::TargetIdempotencyKey {
            key_digest: [9u8; 32],
        };
        assert_ne!(
            base.admission_digest().unwrap(),
            idempotent.admission_digest().unwrap()
        );
    }

    #[test]
    fn request_digest_may_be_canonical_zero_for_parameterless_action() {
        let mut value = admission();
        value.request_digest = [0u8; 32];
        assert!(value.validate().is_ok());
    }

    #[test]
    fn replay_capability_requires_explicit_target_binding() {
        let mut value = admission();
        value.replay = ReplaySemanticsV1::TargetIdempotencyKey {
            key_digest: [0u8; 32],
        };
        assert!(matches!(
            value.validate(),
            Err(OperationReceiptProtocolError::ZeroReplayBindingDigest)
        ));
    }

    #[test]
    fn first_event_can_arm_effect() {
        let admission = admission();
        let armed = first_event(&admission, OperationReceiptStateV1::EffectArmed);
        assert!(armed.validate_first(&admission).is_ok());
    }

    #[test]
    fn first_event_can_cancel_without_effect() {
        let admission = admission();
        let cancelled = first_event(
            &admission,
            OperationReceiptStateV1::CancelledBeforeEffect,
        );
        assert!(cancelled.validate_first(&admission).is_ok());
        assert!(cancelled.state.is_terminal());
    }

    #[test]
    fn completion_requires_effect_armed_predecessor() {
        let admission = admission();
        let armed = first_event(&admission, OperationReceiptStateV1::EffectArmed);
        let completed = successor(
            &admission,
            &armed,
            OperationReceiptStateV1::Completed,
            Some([11u8; 32]),
        );
        assert!(completed.validate_successor(&admission, &armed).is_ok());
    }

    #[test]
    fn direct_completion_from_admission_is_rejected() {
        let admission = admission();
        let mut completed = first_event(&admission, OperationReceiptStateV1::Completed);
        completed.outcome_digest = Some([11u8; 32]);
        assert!(matches!(
            completed.validate_first(&admission),
            Err(OperationReceiptProtocolError::InvalidFirstState)
        ));
    }

    #[test]
    fn terminal_state_cannot_be_extended() {
        let admission = admission();
        let armed = first_event(&admission, OperationReceiptStateV1::EffectArmed);
        let unknown = successor(
            &admission,
            &armed,
            OperationReceiptStateV1::OutcomeUnknown,
            Some([12u8; 32]),
        );
        let attempted_extension = successor(
            &admission,
            &unknown,
            OperationReceiptStateV1::Completed,
            Some([13u8; 32]),
        );
        assert!(matches!(
            attempted_extension.validate_successor(&admission, &unknown),
            Err(OperationReceiptProtocolError::TerminalStateExtended)
        ));
    }

    #[test]
    fn chain_rejects_wrong_previous_digest() {
        let admission = admission();
        let armed = first_event(&admission, OperationReceiptStateV1::EffectArmed);
        let mut failed = successor(
            &admission,
            &armed,
            OperationReceiptStateV1::FailedKnown,
            Some([14u8; 32]),
        );
        failed.previous_event_digest = [99u8; 32];
        assert!(matches!(
            validate_receipt_chain(&admission, &[armed, failed]),
            Err(OperationReceiptProtocolError::PreviousEventDigestMismatch)
        ));
    }

    #[test]
    fn post_effect_terminal_states_require_outcome_commitment() {
        let admission = admission();
        let armed = first_event(&admission, OperationReceiptStateV1::EffectArmed);
        let failed = successor(
            &admission,
            &armed,
            OperationReceiptStateV1::FailedKnown,
            None,
        );
        assert!(matches!(
            failed.validate_successor(&admission, &armed),
            Err(OperationReceiptProtocolError::MissingOutcomeDigest)
        ));
    }

    #[test]
    fn use_slot_reservation_key_is_exact() {
        let admission = admission();
        assert_eq!(
            admission.reservation_key(),
            GrantUseReservationKeyV1 {
                grant_digest: [2u8; 32],
                use_index: 2,
            }
        );
    }

    #[test]
    fn receipt_event_digest_binds_state_and_outcome() {
        let admission = admission();
        let armed = first_event(&admission, OperationReceiptStateV1::EffectArmed);
        let completed = successor(
            &admission,
            &armed,
            OperationReceiptStateV1::Completed,
            Some([20u8; 32]),
        );
        let failed = successor(
            &admission,
            &armed,
            OperationReceiptStateV1::FailedKnown,
            Some([20u8; 32]),
        );
        assert_ne!(
            completed.event_digest().unwrap(),
            failed.event_digest().unwrap()
        );
    }
}
