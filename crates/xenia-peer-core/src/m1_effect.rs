// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic reference model for one-shot M1 effect admission.
//!
//! This module models the local ordering contract in Xenia #504. It is not
//! wired into the daemon's OS/network effect paths and does not prove those
//! effects are linearizable. A runtime owner must serialize calls to this
//! state machine and couple `linearize_commit` to the real effect boundary.
//!
//! The modeled ordering is:
//!
//! ```text
//! exact operation intent
//!     -> prepare (replay identity reserved)
//!     -> linearize_commit (single effect admission point)
//!     -> owner effect call
//!     -> Committed | ConfirmedNoEffect | Unknown
//!     -> owner-qualified reconciliation of Unknown
//! ```
//!
//! A Revoke ordered before `linearize_commit` rejects the operation. A
//! commit-admission ordered first is retained as in-flight across revocation;
//! its effect result must still be recorded, or becomes Unknown on recovery.
//! Unknown is never silently retried or converted into no-effect.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use blake3::Hasher;

use crate::{M1DataDirection, M1Permission, M1PermissionSet};

/// Immutable, payload-redacted identity of one proposed M1 effect.
///
/// The operation and resource commitments are supplied by the effect owner.
/// This model binds them into a deterministic fingerprint but does not verify
/// their external provenance or the contents they commit to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M1EffectIntentV1 {
    /// Stable idempotency identity for this logical operation.
    pub operation_id: [u8; 16],
    /// M1 session identity.
    pub session_id: [u8; 16],
    /// Monotonic session/rekey epoch expected by this operation.
    pub session_epoch: u64,
    /// Exact M1 lane being exercised.
    pub permission: M1Permission,
    /// Direction of the protected information/control flow.
    pub direction: M1DataDirection,
    /// Commitment to the exact host/resource identity.
    pub resource_commitment: [u8; 32],
    /// Commitment to the exact operation/payload semantics.
    pub operation_commitment: [u8; 32],
    /// Commitment to the recipient consent record/scope.
    pub consent_commitment: [u8; 32],
    /// Commitment to the purpose under which the operation was requested.
    pub purpose_commitment: [u8; 32],
    /// Commitment to the disclosure audience or effect recipient.
    pub audience_commitment: [u8; 32],
    /// Commitment to the policy/profile used to form the decision.
    pub policy_commitment: [u8; 32],
    /// Optional Mycelix delegation content commitment.
    ///
    /// Presence binds the value into the operation fingerprint only. This
    /// reference model does not authenticate or validate ROS-005 authority.
    pub delegation_commitment: Option<[u8; 32]>,
    /// Optional authority epoch paired with `delegation_commitment`.
    ///
    /// Presence binds the value into the operation fingerprint only. This
    /// reference model does not prove that the epoch is current.
    pub authority_epoch: Option<u64>,
}

impl M1EffectIntentV1 {
    /// Compute the versioned, domain-separated operation fingerprint.
    ///
    /// The operation ID is the map key/idempotency identity and is not part of
    /// this content fingerprint. Every permission/resource/purpose/audience/
    /// consent/policy/session/delegation dimension is included.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"xenia.m1.effect-intent.v1\0");
        hasher.update(&self.session_id);
        hasher.update(&self.session_epoch.to_be_bytes());
        hasher.update(self.permission.action_id().as_bytes());
        hasher.update(&[direction_tag(self.direction)]);
        hasher.update(&self.resource_commitment);
        hasher.update(&self.operation_commitment);
        hasher.update(&self.consent_commitment);
        hasher.update(&self.purpose_commitment);
        hasher.update(&self.audience_commitment);
        hasher.update(&self.policy_commitment);
        match self.delegation_commitment {
            Some(commitment) => {
                hasher.update(&[1]);
                hasher.update(&commitment);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        match self.authority_epoch {
            Some(epoch) => {
                hasher.update(&[1]);
                hasher.update(&epoch.to_be_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

/// Current state of one operation in the effect-admission model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1EffectDisposition {
    /// Intent reserved; no final effect admission has occurred.
    Prepared,
    /// The exact operation crossed the single local effect-admission point.
    CommitLinearized,
    /// The owner reported that its declared local commit point was crossed.
    Committed,
    /// The owner positively established that the protected effect did not occur.
    ConfirmedNoEffect,
    /// Dispatch may have happened, but the outcome is not yet established.
    Unknown,
    /// Revocation won before the final effect-admission point.
    Rejected,
}

/// Result of attempting to prepare an operation ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1EffectPrepareResult {
    /// A new operation identity was reserved.
    New(M1PreparedOperation),
    /// This operation ID already exists with the same content fingerprint.
    ///
    /// The existing state is returned; a second commit permit is not issued.
    Existing(M1EffectSnapshot),
}

/// Opaque handle for a newly prepared operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct M1PreparedOperation {
    operation_id: [u8; 16],
    fingerprint: [u8; 32],
    admission_sequence: u64,
}

impl M1PreparedOperation {
    /// Stable operation identity.
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }

    /// Content fingerprint fixed when the operation was prepared.
    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }

    /// Per-gate sequence assigned at admission preparation.
    pub const fn admission_sequence(self) -> u64 {
        self.admission_sequence
    }
}

/// Receipt for a single linearized effect admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct M1EffectCommitReceipt {
    operation_id: [u8; 16],
    fingerprint: [u8; 32],
    session_epoch: u64,
    admission_sequence: u64,
    linearization_sequence: u64,
}

impl M1EffectCommitReceipt {
    /// Stable operation identity.
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }

    /// Exact immutable operation fingerprint.
    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }

    /// Session epoch at the effect-admission point.
    pub const fn session_epoch(self) -> u64 {
        self.session_epoch
    }

    /// Sequence of the earlier prepare/admission reservation.
    pub const fn admission_sequence(self) -> u64 {
        self.admission_sequence
    }

    /// Sequence that linearizes this operation against revocation.
    pub const fn linearization_sequence(self) -> u64 {
        self.linearization_sequence
    }
}

/// Owner-side outcome recorded after a linearized admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1EffectCompletion {
    /// The effect owner confirms its declared local commit point was crossed.
    Committed,
    /// The effect owner positively confirms that no protected effect occurred.
    ConfirmedNoEffect,
    /// Dispatch may have occurred; reconciliation is required before retry.
    Unknown,
}

/// Owner-qualified outcome supplied when reconciling an Unknown operation.
///
/// Constructing this value does not verify an external source. The adapter
/// calling `record_reconciliation` must authenticate the owner evidence and
/// prove that it names this exact operation/fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1ReconciledOutcome {
    /// Qualified evidence establishes the effect committed.
    Committed,
    /// Qualified evidence establishes no protected effect occurred.
    ConfirmedNoEffect,
}

/// Read-only view of one operation's current model state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct M1EffectSnapshot {
    /// Stable operation identity.
    pub operation_id: [u8; 16],
    /// Exact intent fingerprint.
    pub fingerprint: [u8; 32],
    /// Sequence assigned when the intent was reserved.
    pub admission_sequence: u64,
    /// Sequence of the effect-admission linearization point, if reached.
    pub linearization_sequence: Option<u64>,
    /// Sequence of terminal completion/reconciliation, if established.
    pub resolution_sequence: Option<u64>,
    /// Current disposition.
    pub disposition: M1EffectDisposition,
}

/// Fail-closed error from the deterministic M1 effect model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum M1EffectError {
    /// A new effect cannot be admitted after local revocation.
    Revoked,
    /// The M1 lane was not included in the session's granted permission set.
    PermissionDenied(M1Permission),
    /// The intent names a different session.
    SessionMismatch,
    /// The intent names a stale or future session epoch.
    SessionEpochMismatch {
        /// Current gate epoch.
        current: u64,
        /// Epoch requested by the operation.
        requested: u64,
    },
    /// Direction disagrees with the stable direction of the M1 permission.
    DirectionMismatch(M1Permission),
    /// A required commitment is all-zero/absent.
    MissingCommitment(&'static str),
    /// Delegation commitment and authority epoch must be present together.
    IncompleteAuthorityBinding,
    /// The same operation ID was reused with different immutable content.
    IdempotencyConflict,
    /// The prepared handle does not match the stored operation.
    StalePreparedHandle,
    /// The operation has already crossed or terminated its one-shot admission.
    AlreadyConsumed,
    /// The operation is not in the required lifecycle state.
    InvalidTransition {
        /// Actual stored state.
        actual: M1EffectDisposition,
        /// Required state name.
        required: &'static str,
    },
    /// The monotonic event sequence was exhausted.
    SequenceExhausted,
}

impl fmt::Display for M1EffectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked => write!(f, "M1 effect gate is revoked"),
            Self::PermissionDenied(permission) => {
                write!(f, "M1 permission {permission:?} is not granted")
            }
            Self::SessionMismatch => write!(f, "M1 effect intent session mismatch"),
            Self::SessionEpochMismatch { current, requested } => write!(
                f,
                "M1 effect intent epoch {requested} does not match current epoch {current}"
            ),
            Self::DirectionMismatch(permission) => {
                write!(f, "M1 direction mismatch for {permission:?}")
            }
            Self::MissingCommitment(field) => {
                write!(f, "M1 effect intent is missing commitment {field}")
            }
            Self::IncompleteAuthorityBinding => write!(
                f,
                "delegation commitment and authority epoch must be supplied together"
            ),
            Self::IdempotencyConflict => write!(
                f,
                "M1 operation ID was reused with a different intent fingerprint"
            ),
            Self::StalePreparedHandle => write!(f, "M1 prepared-operation handle is stale"),
            Self::AlreadyConsumed => write!(f, "M1 operation admission is already consumed"),
            Self::InvalidTransition { actual, required } => {
                write!(f, "M1 effect transition from {actual:?} requires {required}")
            }
            Self::SequenceExhausted => write!(f, "M1 effect sequence exhausted"),
        }
    }
}

impl Error for M1EffectError {}

#[derive(Debug, Clone, Copy)]
struct OperationRecord {
    fingerprint: [u8; 32],
    admission_sequence: u64,
    linearization_sequence: Option<u64>,
    resolution_sequence: Option<u64>,
    disposition: M1EffectDisposition,
}

/// Deterministic, single-session effect-admission state machine.
///
/// All mutations require `&mut self`. A runtime must protect the same
/// instance with one owner-local serialization primitive and use that same
/// primitive for both `linearize_commit` and `revoke`. If different locks,
/// replicas or bypass routes mutate the effect independently, this model does
/// not provide linearizability.
#[derive(Debug)]
pub struct M1EffectGate {
    session_id: [u8; 16],
    session_epoch: u64,
    granted: M1PermissionSet,
    revoked: bool,
    revocation_sequence: Option<u64>,
    next_sequence: u64,
    operations: BTreeMap<[u8; 16], OperationRecord>,
}

impl M1EffectGate {
    /// Construct a fresh gate for one exact Xenia session and epoch.
    pub fn new(
        session_id: [u8; 16],
        session_epoch: u64,
        granted: M1PermissionSet,
    ) -> Self {
        Self {
            session_id,
            session_epoch,
            granted,
            revoked: false,
            revocation_sequence: None,
            next_sequence: 1,
            operations: BTreeMap::new(),
        }
    }

    /// Reserve an exact operation ID and immutable intent fingerprint.
    ///
    /// Repeating an identical ID/fingerprint returns the existing snapshot.
    /// Reusing the ID with changed intent is a conflict. The call is only a
    /// preparation step; the final effect owner must still call
    /// `linearize_commit` immediately at its protected effect boundary.
    pub fn prepare(
        &mut self,
        intent: &M1EffectIntentV1,
    ) -> Result<M1EffectPrepareResult, M1EffectError> {
        let fingerprint = intent.fingerprint();
        if let Some(existing) = self.operations.get(&intent.operation_id) {
            if existing.fingerprint != fingerprint {
                return Err(M1EffectError::IdempotencyConflict);
            }
            return Ok(M1EffectPrepareResult::Existing(snapshot_record(
                intent.operation_id,
                existing,
            )));
        }

        if self.revoked {
            return Err(M1EffectError::Revoked);
        }
        self.validate_intent(intent)?;
        if !self.granted.contains(intent.permission) {
            return Err(M1EffectError::PermissionDenied(intent.permission));
        }

        let admission_sequence = self.take_sequence()?;
        self.operations.insert(
            intent.operation_id,
            OperationRecord {
                fingerprint,
                admission_sequence,
                linearization_sequence: None,
                resolution_sequence: None,
                disposition: M1EffectDisposition::Prepared,
            },
        );
        Ok(M1EffectPrepareResult::New(M1PreparedOperation {
            operation_id: intent.operation_id,
            fingerprint,
            admission_sequence,
        }))
    }

    /// Linearize the operation against local revocation at the effect owner.
    ///
    /// This is the one-shot, final authorization/dispatch-admission point. A
    /// successful receipt means this operation won the ordering race against
    /// `revoke`; it does not itself prove that an OS/network effect succeeded.
    /// The owner must immediately invoke the exact effect named by the
    /// fingerprint, then record its result.
    pub fn linearize_commit(
        &mut self,
        prepared: M1PreparedOperation,
    ) -> Result<M1EffectCommitReceipt, M1EffectError> {
        if self.revoked {
            return Err(M1EffectError::Revoked);
        }
        let record = self
            .operations
            .get(&prepared.operation_id)
            .ok_or(M1EffectError::StalePreparedHandle)?;
        if record.fingerprint != prepared.fingerprint
            || record.admission_sequence != prepared.admission_sequence
        {
            return Err(M1EffectError::StalePreparedHandle);
        }
        if record.disposition != M1EffectDisposition::Prepared {
            return Err(M1EffectError::AlreadyConsumed);
        }

        let linearization_sequence = self.take_sequence()?;
        let record = self
            .operations
            .get_mut(&prepared.operation_id)
            .expect("record was checked above");
        record.linearization_sequence = Some(linearization_sequence);
        record.disposition = M1EffectDisposition::CommitLinearized;

        Ok(M1EffectCommitReceipt {
            operation_id: prepared.operation_id,
            fingerprint: prepared.fingerprint,
            session_epoch: self.session_epoch,
            admission_sequence: prepared.admission_sequence,
            linearization_sequence,
        })
    }

    /// Record the effect owner's immediate result for a linearized commit.
    ///
    /// A timeout, cancellation or crash after possible dispatch must use
    /// `Unknown`, never `ConfirmedNoEffect`. A receipt can be completed only
    /// once; duplicate completion attempts cannot create another effect.
    pub fn complete(
        &mut self,
        receipt: M1EffectCommitReceipt,
        completion: M1EffectCompletion,
    ) -> Result<M1EffectSnapshot, M1EffectError> {
        self.validate_receipt(&receipt)?;
        {
            let record = self
                .operations
                .get(&receipt.operation_id)
                .ok_or(M1EffectError::StalePreparedHandle)?;
            if record.disposition != M1EffectDisposition::CommitLinearized
                || record.fingerprint != receipt.fingerprint
                || record.admission_sequence != receipt.admission_sequence
                || record.linearization_sequence != Some(receipt.linearization_sequence)
            {
                return Err(M1EffectError::AlreadyConsumed);
            }
        }
        let resolution_sequence = self.take_sequence()?;
        let record = self
            .operations
            .get_mut(&receipt.operation_id)
            .expect("record was checked above");
        record.disposition = match completion {
            M1EffectCompletion::Committed => M1EffectDisposition::Committed,
            M1EffectCompletion::ConfirmedNoEffect => M1EffectDisposition::ConfirmedNoEffect,
            M1EffectCompletion::Unknown => M1EffectDisposition::Unknown,
        };
        record.resolution_sequence = Some(resolution_sequence);
        Ok(snapshot_record(receipt.operation_id, record))
    }

    /// Revoke this session's gate and invalidate every operation not yet
    /// linearized. Already-linearized operations retain their ordering and
    /// must finish as Committed, ConfirmedNoEffect or Unknown.
    ///
    /// Repeated revocation is idempotent and returns the original sequence.
    pub fn revoke(&mut self) -> Result<u64, M1EffectError> {
        if let Some(sequence) = self.revocation_sequence {
            return Ok(sequence);
        }
        // Fence first, even if the bookkeeping sequence is exhausted.
        self.revoked = true;
        let sequence = match self.take_sequence() {
            Ok(sequence) => sequence,
            Err(error) => {
                for record in self.operations.values_mut() {
                    if record.disposition == M1EffectDisposition::Prepared {
                        record.disposition = M1EffectDisposition::Rejected;
                        record.resolution_sequence = None;
                    }
                }
                return Err(error);
            }
        };
        self.revocation_sequence = Some(sequence);
        for record in self.operations.values_mut() {
            if record.disposition == M1EffectDisposition::Prepared {
                record.disposition = M1EffectDisposition::Rejected;
                record.resolution_sequence = Some(sequence);
            }
        }
        Ok(sequence)
    }

    /// Convert crash-interrupted, already-linearized operations to Unknown.
    ///
    /// This models restart recovery after a durable commit-admission record
    /// but before a trustworthy terminal outcome. It deliberately does not
    /// reissue a permit or guess that the operation had no effect.
    pub fn recover_after_crash(&mut self) {
        for record in self.operations.values_mut() {
            if record.disposition == M1EffectDisposition::CommitLinearized {
                record.disposition = M1EffectDisposition::Unknown;
                record.resolution_sequence = None;
            }
        }
    }

    /// Record an owner-qualified reconciliation of an Unknown operation.
    ///
    /// The calling adapter is responsible for authenticating the evidence,
    /// checking its source independence/contract, and matching the exact
    /// operation identity/fingerprint. This model only enforces the state
    /// transition once that qualification has happened.
    pub fn record_reconciliation(
        &mut self,
        operation_id: [u8; 16],
        fingerprint: [u8; 32],
        outcome: M1ReconciledOutcome,
    ) -> Result<M1EffectSnapshot, M1EffectError> {
        {
            let record = self
                .operations
                .get(&operation_id)
                .ok_or(M1EffectError::StalePreparedHandle)?;
            if record.fingerprint != fingerprint {
                return Err(M1EffectError::IdempotencyConflict);
            }
            if record.disposition != M1EffectDisposition::Unknown {
                return Err(M1EffectError::InvalidTransition {
                    actual: record.disposition,
                    required: "Unknown",
                });
            }
        }

        let resolution_sequence = self.take_sequence()?;
        let record = self
            .operations
            .get_mut(&operation_id)
            .expect("record was checked above");
        record.disposition = match outcome {
            M1ReconciledOutcome::Committed => M1EffectDisposition::Committed,
            M1ReconciledOutcome::ConfirmedNoEffect => M1EffectDisposition::ConfirmedNoEffect,
        };
        record.resolution_sequence = Some(resolution_sequence);
        Ok(snapshot_record(operation_id, record))
    }

    /// Return the immutable current view for one operation.
    pub fn operation(&self, operation_id: [u8; 16]) -> Option<M1EffectSnapshot> {
        self.operations
            .get(&operation_id)
            .map(|record| snapshot_record(operation_id, record))
    }

    /// Local session revocation sequence, if the gate has been revoked.
    pub const fn revocation_sequence(&self) -> Option<u64> {
        self.revocation_sequence
    }

    /// Whether this session's local effect gate is revoked.
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    fn validate_intent(&self, intent: &M1EffectIntentV1) -> Result<(), M1EffectError> {
        if intent.operation_id.iter().all(|byte| *byte == 0) {
            return Err(M1EffectError::MissingCommitment("operation_id"));
        }
        if intent.session_id.iter().all(|byte| *byte == 0) {
            return Err(M1EffectError::MissingCommitment("session_id"));
        }
        if intent.session_id != self.session_id {
            return Err(M1EffectError::SessionMismatch);
        }
        if intent.session_epoch != self.session_epoch {
            return Err(M1EffectError::SessionEpochMismatch {
                current: self.session_epoch,
                requested: intent.session_epoch,
            });
        }
        if intent.permission.direction() != intent.direction {
            return Err(M1EffectError::DirectionMismatch(intent.permission));
        }
        for (name, value) in [
            ("resource", &intent.resource_commitment),
            ("operation", &intent.operation_commitment),
            ("consent", &intent.consent_commitment),
            ("purpose", &intent.purpose_commitment),
            ("audience", &intent.audience_commitment),
            ("policy", &intent.policy_commitment),
        ] {
            if value.iter().all(|byte| *byte == 0) {
                return Err(M1EffectError::MissingCommitment(name));
            }
        }
        if intent.delegation_commitment.is_some() != intent.authority_epoch.is_some() {
            return Err(M1EffectError::IncompleteAuthorityBinding);
        }
        if intent
            .delegation_commitment
            .is_some_and(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(M1EffectError::MissingCommitment("delegation"));
        }
        Ok(())
    }

    fn validate_receipt(&self, receipt: &M1EffectCommitReceipt) -> Result<(), M1EffectError> {
        if receipt.session_epoch != self.session_epoch {
            return Err(M1EffectError::SessionEpochMismatch {
                current: self.session_epoch,
                requested: receipt.session_epoch,
            });
        }
        Ok(())
    }

    fn take_sequence(&mut self) -> Result<u64, M1EffectError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(M1EffectError::SequenceExhausted)?;
        Ok(sequence)
    }

}

fn snapshot_record(
    operation_id: [u8; 16],
    record: &OperationRecord,
) -> M1EffectSnapshot {
    M1EffectSnapshot {
        operation_id,
        fingerprint: record.fingerprint,
        admission_sequence: record.admission_sequence,
        linearization_sequence: record.linearization_sequence,
        resolution_sequence: record.resolution_sequence,
        disposition: record.disposition,
    }
}

fn direction_tag(direction: M1DataDirection) -> u8 {
    match direction {
        M1DataDirection::HostToViewer => 1,
        M1DataDirection::ViewerToHost => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn intent(operation_id: u8, permission: M1Permission) -> M1EffectIntentV1 {
        M1EffectIntentV1 {
            operation_id: [operation_id; 16],
            session_id: [0xA1; 16],
            session_epoch: 7,
            permission,
            direction: permission.direction(),
            resource_commitment: digest(1),
            operation_commitment: digest(2),
            consent_commitment: digest(3),
            purpose_commitment: digest(4),
            audience_commitment: digest(5),
            policy_commitment: digest(6),
            delegation_commitment: None,
            authority_epoch: None,
        }
    }

    fn gate() -> M1EffectGate {
        M1EffectGate::new([0xA1; 16], 7, M1PermissionSet::all())
    }

    fn prepare_new(
        gate: &mut M1EffectGate,
        intent: &M1EffectIntentV1,
    ) -> M1PreparedOperation {
        match gate.prepare(intent).unwrap() {
            M1EffectPrepareResult::New(prepared) => prepared,
            M1EffectPrepareResult::Existing(_) => panic!("expected a new operation"),
        }
    }

    #[test]
    fn revoke_before_final_effect_admission_rejects_the_operation() {
        let mut gate = gate();
        let operation = intent(1, M1Permission::InjectInput);
        let prepared = prepare_new(&mut gate, &operation);
        let revoke_sequence = gate.revoke().unwrap();

        assert_eq!(
            gate.linearize_commit(prepared),
            Err(M1EffectError::Revoked)
        );
        let snapshot = gate.operation(operation.operation_id).unwrap();
        assert_eq!(snapshot.disposition, M1EffectDisposition::Rejected);
        assert!(snapshot.linearization_sequence.is_none());
        assert!(snapshot.admission_sequence < revoke_sequence);
    }

    #[test]
    fn final_effect_admission_before_revoke_is_preserved_and_ordered() {
        let mut gate = gate();
        let operation = intent(2, M1Permission::WriteHostClipboard);
        let prepared = prepare_new(&mut gate, &operation);
        let receipt = gate.linearize_commit(prepared).unwrap();
        let revoke_sequence = gate.revoke().unwrap();

        assert!(receipt.linearization_sequence() < revoke_sequence);
        assert_eq!(
            gate.operation(operation.operation_id).unwrap().disposition,
            M1EffectDisposition::CommitLinearized
        );
        let snapshot = gate
            .complete(receipt, M1EffectCompletion::Committed)
            .unwrap();
        assert_eq!(snapshot.disposition, M1EffectDisposition::Committed);
        assert!(snapshot.resolution_sequence.unwrap() > revoke_sequence);
    }

    #[test]
    fn identical_operation_retry_is_idempotent_and_changed_fingerprint_conflicts() {
        let mut gate = gate();
        let operation = intent(3, M1Permission::SendFileToViewer);
        let prepared = prepare_new(&mut gate, &operation);
        let first = gate.linearize_commit(prepared).unwrap();

        let duplicate = gate.prepare(&operation).unwrap();
        let M1EffectPrepareResult::Existing(snapshot) = duplicate else {
            panic!("identical operation must resolve to the original identity");
        };
        assert_eq!(snapshot.disposition, M1EffectDisposition::CommitLinearized);
        assert_eq!(snapshot.linearization_sequence, Some(first.linearization_sequence()));

        let mut changed = operation.clone();
        changed.resource_commitment = digest(7);
        assert_eq!(
            gate.prepare(&changed),
            Err(M1EffectError::IdempotencyConflict)
        );
        assert_eq!(
            gate.linearize_commit(prepared),
            Err(M1EffectError::AlreadyConsumed)
        );
    }

    #[test]
    fn unknown_outcome_blocks_retry_until_exact_operation_is_reconciled() {
        let mut gate = gate();
        let operation = intent(4, M1Permission::ReceiveFileFromViewer);
        let prepared = prepare_new(&mut gate, &operation);
        let receipt = gate.linearize_commit(prepared).unwrap();
        let snapshot = gate
            .complete(receipt, M1EffectCompletion::Unknown)
            .unwrap();
        assert_eq!(snapshot.disposition, M1EffectDisposition::Unknown);

        let M1EffectPrepareResult::Existing(existing) = gate.prepare(&operation).unwrap() else {
            panic!("retry must return existing operation, not a fresh permit");
        };
        assert_eq!(existing.disposition, M1EffectDisposition::Unknown);
        assert_eq!(
            gate.linearize_commit(prepared),
            Err(M1EffectError::AlreadyConsumed)
        );
        assert_eq!(
            gate.record_reconciliation(
                operation.operation_id,
                digest(99),
                M1ReconciledOutcome::ConfirmedNoEffect,
            ),
            Err(M1EffectError::IdempotencyConflict)
        );

        let resolved = gate
            .record_reconciliation(
                operation.operation_id,
                operation.fingerprint(),
                M1ReconciledOutcome::Committed,
            )
            .unwrap();
        assert_eq!(resolved.disposition, M1EffectDisposition::Committed);
        assert!(resolved.resolution_sequence.unwrap() > snapshot.resolution_sequence.unwrap());
    }

    #[test]
    fn crash_recovery_converts_linearized_incomplete_work_to_unknown() {
        let mut gate = gate();
        let operation = intent(5, M1Permission::StreamAudio);
        let prepared = prepare_new(&mut gate, &operation);
        let _receipt = gate.linearize_commit(prepared).unwrap();

        gate.recover_after_crash();
        let snapshot = gate.operation(operation.operation_id).unwrap();
        assert_eq!(snapshot.disposition, M1EffectDisposition::Unknown);
        assert_eq!(snapshot.resolution_sequence, None);
        assert_eq!(
            gate.linearize_commit(prepared),
            Err(M1EffectError::AlreadyConsumed)
        );
    }

    #[test]
    fn every_fingerprint_dimension_is_bound() {
        let base = intent(6, M1Permission::StreamFrame);
        let fingerprint = base.fingerprint();

        let mut changed = base.clone();
        changed.session_epoch += 1;
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.permission = M1Permission::ReadHostClipboard;
        changed.direction = changed.permission.direction();
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.resource_commitment = digest(7);
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.operation_commitment = digest(7);
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.consent_commitment = digest(7);
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.purpose_commitment = digest(7);
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.audience_commitment = digest(7);
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.policy_commitment = digest(7);
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.delegation_commitment = Some(digest(8));
        changed.authority_epoch = Some(3);
        assert_ne!(changed.fingerprint(), fingerprint);
        let mut changed = base.clone();
        changed.authority_epoch = Some(4);
        changed.delegation_commitment = Some(digest(8));
        assert_ne!(changed.fingerprint(), fingerprint);
    }

    #[test]
    fn rejects_wrong_session_epoch_direction_and_missing_commitments() {
        let mut gate = gate();
        let mut wrong_session = intent(7, M1Permission::InjectInput);
        wrong_session.session_id = [0xB2; 16];
        assert_eq!(
            gate.prepare(&wrong_session),
            Err(M1EffectError::SessionMismatch)
        );

        let mut wrong_epoch = intent(8, M1Permission::InjectInput);
        wrong_epoch.session_epoch = 8;
        assert!(matches!(
            gate.prepare(&wrong_epoch),
            Err(M1EffectError::SessionEpochMismatch { current: 7, requested: 8 })
        ));

        let mut wrong_direction = intent(9, M1Permission::InjectInput);
        wrong_direction.direction = M1DataDirection::HostToViewer;
        assert_eq!(
            gate.prepare(&wrong_direction),
            Err(M1EffectError::DirectionMismatch(M1Permission::InjectInput))
        );

        let mut missing = intent(10, M1Permission::InjectInput);
        missing.consent_commitment = [0; 32];
        assert_eq!(
            gate.prepare(&missing),
            Err(M1EffectError::MissingCommitment("consent"))
        );

        let mut incomplete_authority = intent(11, M1Permission::InjectInput);
        incomplete_authority.delegation_commitment = Some(digest(8));
        assert_eq!(
            gate.prepare(&incomplete_authority),
            Err(M1EffectError::IncompleteAuthorityBinding)
        );
    }

    #[test]
    fn wrong_lane_is_not_permitted_even_when_session_is_active() {
        let granted = M1PermissionSet {
            stream_frame: true,
            ..M1PermissionSet::default()
        };
        let mut gate = M1EffectGate::new([0xA1; 16], 7, granted);
        let wrong_lane = intent(12, M1Permission::InjectInput);
        assert_eq!(
            gate.prepare(&wrong_lane),
            Err(M1EffectError::PermissionDenied(M1Permission::InjectInput))
        );
    }

    #[test]
    fn commit_and_revoke_race_has_one_serializable_winner() {
        let mut initial = gate();
        let operation = intent(13, M1Permission::InjectInput);
        let prepared = prepare_new(&mut initial, &operation);
        let gate = Arc::new(Mutex::new(initial));
        let barrier = Arc::new(Barrier::new(3));

        let commit_gate = Arc::clone(&gate);
        let commit_barrier = Arc::clone(&barrier);
        let commit_thread = thread::spawn(move || {
            commit_barrier.wait();
            commit_gate
                .lock()
                .expect("effect gate mutex poisoned")
                .linearize_commit(prepared)
        });

        let revoke_gate = Arc::clone(&gate);
        let revoke_barrier = Arc::clone(&barrier);
        let revoke_thread = thread::spawn(move || {
            revoke_barrier.wait();
            revoke_gate
                .lock()
                .expect("effect gate mutex poisoned")
                .revoke()
        });

        barrier.wait();
        let commit_result = commit_thread.join().unwrap();
        let revoke_sequence = revoke_thread.join().unwrap().unwrap();
        let snapshot = gate
            .lock()
            .expect("effect gate mutex poisoned")
            .operation(operation.operation_id)
            .unwrap();

        match commit_result {
            Ok(receipt) => {
                assert!(receipt.linearization_sequence() < revoke_sequence);
                assert_eq!(snapshot.disposition, M1EffectDisposition::CommitLinearized);
            }
            Err(M1EffectError::Revoked) => {
                assert!(snapshot.linearization_sequence.is_none());
                assert_eq!(snapshot.disposition, M1EffectDisposition::Rejected);
            }
            other => panic!("unexpected concurrent result: {other:?}"),
        }
    }

    #[test]
    fn revoke_fences_even_when_sequence_bookkeeping_is_exhausted() {
        let mut gate = gate();
        let operation = intent(15, M1Permission::InjectInput);
        let prepared = prepare_new(&mut gate, &operation);
        gate.next_sequence = u64::MAX;

        assert_eq!(gate.revoke(), Err(M1EffectError::SequenceExhausted));
        assert!(gate.is_revoked());
        assert_eq!(
            gate.linearize_commit(prepared),
            Err(M1EffectError::Revoked)
        );
        let snapshot = gate.operation(operation.operation_id).unwrap();
        assert_eq!(snapshot.disposition, M1EffectDisposition::Rejected);
        assert_eq!(snapshot.resolution_sequence, None);
    }

    #[test]
    fn zero_operation_and_session_ids_are_rejected() {
        let mut gate = gate();
        let mut empty_operation = intent(16, M1Permission::InjectInput);
        empty_operation.operation_id = [0; 16];
        assert_eq!(
            gate.prepare(&empty_operation),
            Err(M1EffectError::MissingCommitment("operation_id"))
        );

        let mut empty_session = intent(17, M1Permission::InjectInput);
        empty_session.session_id = [0; 16];
        assert_eq!(
            gate.prepare(&empty_session),
            Err(M1EffectError::MissingCommitment("session_id"))
        );
    }

    #[test]
    fn revoke_is_idempotent_and_does_not_rewrite_committed_history() {
        let mut gate = gate();
        let operation = intent(14, M1Permission::StreamTelemetry);
        let prepared = prepare_new(&mut gate, &operation);
        let receipt = gate.linearize_commit(prepared).unwrap();
        let completion = gate
            .complete(receipt, M1EffectCompletion::Committed)
            .unwrap();
        let first_revoke = gate.revoke().unwrap();
        let second_revoke = gate.revoke().unwrap();

        assert_eq!(first_revoke, second_revoke);
        assert_eq!(
            gate.operation(operation.operation_id).unwrap().disposition,
            M1EffectDisposition::Committed
        );
        assert!(completion.resolution_sequence.unwrap() < first_revoke);
    }
}
