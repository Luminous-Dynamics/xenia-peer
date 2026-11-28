// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Stage-accurate, payload-free evidence for privileged remote operations.
//!
//! This module is intentionally separate from the human consent ledger and
//! the legacy M1 session audit events. It records the strongest lifecycle
//! stage actually established by the effect-owning subsystem:
//!
//! `AuthorizationAdmitted -> EffectAttempted -> EffectCommitted -> OutcomeObserved`
//!
//! A timeout or ambiguous result after an attempt becomes `Unknown`. It must
//! be reconciled by stable operation ID before the caller retries. The ledger
//! does not perform effects, authorize operations, serialize revocation with
//! an operating-system call, sign evidence, or prove remote presentation.
//!
//! Event hashes provide tamper-evident ordering inside this in-memory model;
//! they are not signatures or an external trust anchor.

use std::collections::HashMap;

use crate::m1_session::M1Permission;

/// Maximum operation records retained by one in-memory session ledger.
pub const MAX_OPERATION_RECORDS: usize = 4_096;
/// Maximum stage events retained by one in-memory session ledger.
pub const MAX_OPERATION_EVENTS: usize = 32_768;

/// Stable, caller-generated idempotency identity for one protected operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId(pub [u8; 16]);

/// Direction of the protected operation across the host/viewer boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OperationDirection {
    /// Information disclosed from host to viewer.
    HostToViewer = 1,
    /// Viewer-originated data or control applied to the host.
    ViewerToHost = 2,
}

/// Payload-free operation context bound into the evidence chain.
///
/// Resource, consent and policy values are digests/commitments. Do not put
/// paths, file bytes, clipboard contents, raw input, media or bearer secrets
/// into this structure. The caller is responsible for choosing a
/// privacy-preserving resource identity digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationContext {
    /// Fingerprint of the authenticated Xenia session.
    pub session_fingerprint: [u8; 32],
    /// Exact M1 permission lane for this operation.
    pub lane: M1Permission,
    /// Direction of the protected information/control flow.
    pub direction: OperationDirection,
    /// Digest of a narrowly scoped resource identity or resource class.
    pub resource_digest: [u8; 32],
    /// Commitment/digest identifying the recipient's consent boundary.
    pub consent_reference_digest: [u8; 32],
    /// Digest of the policy used for this admission.
    pub policy_digest: [u8; 32],
    /// Optional semantic-delegation commitment digest.
    pub authority_commitment_digest: Option<[u8; 32]>,
    /// Optional authority epoch bound to the decision.
    pub authority_epoch: Option<u64>,
}

impl OperationContext {
    /// Canonical context digest; excludes payloads and secret material.
    pub fn digest(self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"XENIA-OPERATION-CONTEXT-V1\0");
        hasher.update(&self.session_fingerprint);
        hasher.update(&[permission_tag(self.lane)]);
        hasher.update(&[self.direction as u8]);
        hasher.update(&self.resource_digest);
        hasher.update(&self.consent_reference_digest);
        hasher.update(&self.policy_digest);
        match self.authority_commitment_digest {
            Some(digest) => {
                hasher.update(&[1]);
                hasher.update(&digest);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        match self.authority_epoch {
            Some(epoch) => {
                hasher.update(&[1]);
                hasher.update(&epoch.to_le_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

fn permission_tag(permission: M1Permission) -> u8 {
    match permission {
        M1Permission::StreamFrame => 1,
        M1Permission::StreamTelemetry => 2,
        M1Permission::StreamAudio => 3,
        M1Permission::InjectInput => 4,
        M1Permission::ReadHostClipboard => 5,
        M1Permission::WriteHostClipboard => 6,
        M1Permission::SendFileToViewer => 7,
        M1Permission::ReceiveFileFromViewer => 8,
    }
}

/// Operation lifecycle state.
///
/// `Committed` is not proof of remote observation. `Unknown` is not a
/// terminal failure and cannot be retried until reconciliation establishes
/// whether the effect committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationState {
    /// Recipient consent and applicable authority gates admitted the operation.
    Admitted,
    /// The effect-owning subsystem actually invoked the protected operation.
    Attempted,
    /// The local effect owner confirms that its defined commit point was crossed.
    Committed,
    /// A stronger, layer-specific observer acknowledged the outcome.
    Observed,
    /// Operation was rejected before dispatch; no effect was attempted.
    Rejected,
    /// Effect was attempted and the effect owner confirms no local commit occurred.
    NotCommitted,
    /// Dispatch/commit outcome is ambiguous and requires reconciliation.
    Unknown,
    /// Unknown outcome was reconciled as not committed.
    ReconciledNotCommitted,
    /// Unknown outcome was reconciled as locally committed.
    ReconciledCommitted,
    /// Unknown outcome was reconciled with an independent observation receipt.
    ReconciledObserved,
}

/// Stage event appended to the operation evidence chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OperationEventKind {
    /// Authorization/consent admission succeeded.
    AuthorizationAdmitted = 1,
    /// The effect or transport call was actually invoked.
    EffectAttempted = 2,
    /// The effect owner confirms its local commit point.
    EffectCommitted = 3,
    /// A layer-specific observer confirms a stronger outcome.
    OutcomeObserved = 4,
    /// The operation was rejected before effect attempt.
    Rejected = 5,
    /// The effect was attempted but the local owner confirms no commit occurred.
    EffectNotCommitted = 8,
    /// The operation outcome became ambiguous after attempt.
    Unknown = 6,
    /// An unknown outcome was reconciled by a scoped receipt.
    Reconciled = 7,
}

/// Result established by independent reconciliation of an unknown operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// Reconciliation proves the operation did not commit.
    NotCommitted,
    /// Reconciliation proves the local effect committed.
    Committed,
    /// Reconciliation proves the stronger layer-specific outcome was observed.
    Observed,
}

/// Immutable stage event in the append-only operation transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationEvidenceEvent {
    /// Global monotonically increasing event sequence within the ledger.
    pub event_sequence: u64,
    /// Stable identity of the protected operation.
    pub operation_id: OperationId,
    /// Caller-assigned monotonically increasing operation sequence.
    pub operation_sequence: u64,
    /// Digest of the exact operation context.
    pub context_digest: [u8; 32],
    /// Stage established by the producer.
    pub kind: OperationEventKind,
    /// Clock-domain identifier for the local monotonic tick.
    pub clock_domain: u64,
    /// Local monotonic tick in the ledger's one clock domain.
    pub at_ticks: u64,
    /// Digest/commitment for the evidence supporting this stage.
    pub evidence_digest: [u8; 32],
    /// Hash of the preceding event, or zero for the first event.
    pub previous_hash: [u8; 32],
    /// Domain-separated hash of this event and the previous hash.
    pub event_hash: [u8; 32],
}

/// Current view of one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationSnapshot {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Caller-assigned operation sequence.
    pub operation_sequence: u64,
    /// Payload-free operation context.
    pub context: OperationContext,
    /// Current lifecycle state.
    pub state: OperationState,
    /// Digest of the latest reconciliation receipt, if reconciled.
    pub reconciliation_digest: Option<[u8; 32]>,
}

/// Aggregate lifecycle counts for a bounded operation-evidence ledger.
///
/// These counts expose state without exporting operation IDs, resource labels,
/// raw clipboard data, input payloads, or other sensitive operation context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationEvidenceStateCounts {
    /// Operations admitted but not yet attempted.
    pub admitted: u64,
    /// Operations whose effect owner was invoked but has no terminal result.
    pub attempted: u64,
    /// Operations committed by the local effect owner.
    pub committed: u64,
    /// Operations observed at a stronger layer.
    pub observed: u64,
    /// Operations rejected before effect attempt.
    pub rejected: u64,
    /// Operations the effect owner confirms did not commit.
    pub not_committed: u64,
    /// Operations whose effect outcome remains ambiguous.
    pub unknown: u64,
    /// Unknown operations reconciled as not committed.
    pub reconciled_not_committed: u64,
    /// Unknown operations reconciled as locally committed.
    pub reconciled_committed: u64,
    /// Unknown operations reconciled with an independent observation.
    pub reconciled_observed: u64,
}

impl OperationEvidenceStateCounts {
    /// Operations that still block a claim of a fully resolved lifecycle.
    ///
    /// Committed is not counted as pending local mutation; it can still await
    /// a stronger observer, which is represented separately by committed.
    pub fn pending_effects(self) -> u64 {
        self.admitted.saturating_add(self.attempted).saturating_add(self.unknown)
    }

    /// Total distinct operation records represented by this snapshot.
    pub fn total(self) -> u64 {
        self.admitted
            .saturating_add(self.attempted)
            .saturating_add(self.committed)
            .saturating_add(self.observed)
            .saturating_add(self.rejected)
            .saturating_add(self.not_committed)
            .saturating_add(self.unknown)
            .saturating_add(self.reconciled_not_committed)
            .saturating_add(self.reconciled_committed)
            .saturating_add(self.reconciled_observed)
    }
}

/// Result of admitting an operation ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionResult {
    /// A new operation record and admission event were created.
    Created(OperationSnapshot),
    /// An identical operation ID/context/sequence already exists; no new event
    /// was appended, making repeated admission idempotent.
    AlreadyPresent(OperationSnapshot),
}

/// Operation evidence ledger error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationEvidenceError {
    /// Operation table or event table reached its configured hard capacity.
    CapacityFull,
    /// The same operation ID was reused with a different sequence/context.
    OperationIdConflict,
    /// Caller-supplied operation sequence did not strictly increase.
    NonMonotonicOperationSequence {
        /// Previously admitted sequence.
        previous: u64,
        /// Newly requested sequence.
        observed: u64,
    },
    /// The operation context belongs to another authenticated session.
    SessionFingerprintMismatch,
    /// The operation ID is not present in this ledger.
    UnknownOperation,
    /// The requested transition is not legal from the current state.
    InvalidTransition {
        /// Current state.
        from: OperationState,
        /// Requested event.
        event: OperationEventKind,
    },
    /// Event clock moved backwards within this ledger's clock domain.
    ClockRegression {
        /// Previously appended tick.
        previous: u64,
        /// Requested tick.
        observed: u64,
    },
    /// Global event sequence exhausted its integer range.
    EventSequenceExhausted,
    /// Reconciliation disagrees with an already recorded reconciliation receipt.
    ReconciliationConflict,
}

/// Bounded, in-memory, append-only operation evidence ledger.
///
/// It deliberately does not replace the consent ledger. Frame/input/chunk
/// stage events belong here rather than in human consent-boundary history.
#[derive(Debug)]
pub struct OperationEvidenceLedger {
    session_fingerprint: [u8; 32],
    clock_domain: u64,
    records: HashMap<OperationId, OperationSnapshot>,
    events: Vec<OperationEvidenceEvent>,
    last_operation_sequence: Option<u64>,
    next_event_sequence: u64,
    last_event_tick: Option<u64>,
    last_event_hash: [u8; 32],
}

impl OperationEvidenceLedger {
    /// Construct an empty ledger for one authenticated session and one local
    /// monotonic clock domain.
    pub fn new(session_fingerprint: [u8; 32], clock_domain: u64) -> Self {
        Self {
            session_fingerprint,
            clock_domain,
            records: HashMap::new(),
            events: Vec::new(),
            last_operation_sequence: None,
            next_event_sequence: 1,
            last_event_tick: None,
            last_event_hash: [0; 32],
        }
    }

    /// Admit a new operation. Repeating the same ID, sequence and context is
    /// idempotent; reusing an ID with different semantics is rejected.
    pub fn admit(
        &mut self,
        operation_id: OperationId,
        operation_sequence: u64,
        context: OperationContext,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<AdmissionResult, OperationEvidenceError> {
        if context.session_fingerprint != self.session_fingerprint {
            return Err(OperationEvidenceError::SessionFingerprintMismatch);
        }
        let context_digest = context.digest();

        if let Some(existing) = self.records.get(&operation_id).copied() {
            if existing.operation_sequence == operation_sequence && existing.context == context {
                return Ok(AdmissionResult::AlreadyPresent(existing));
            }
            return Err(OperationEvidenceError::OperationIdConflict);
        }

        if let Some(previous) = self.last_operation_sequence
            && operation_sequence <= previous
        {
            return Err(OperationEvidenceError::NonMonotonicOperationSequence {
                previous,
                observed: operation_sequence,
            });
        }
        if self.records.len() >= MAX_OPERATION_RECORDS {
            return Err(OperationEvidenceError::CapacityFull);
        }

        self.append_event(
            operation_id,
            operation_sequence,
            context_digest,
            OperationEventKind::AuthorizationAdmitted,
            at_ticks,
            evidence_digest,
        )?;

        let snapshot = OperationSnapshot {
            operation_id,
            operation_sequence,
            context,
            state: OperationState::Admitted,
            reconciliation_digest: None,
        };
        self.records.insert(operation_id, snapshot);
        self.last_operation_sequence = Some(operation_sequence);
        Ok(AdmissionResult::Created(snapshot))
    }

    /// Record that the effect-owning subsystem actually invoked the operation.
    pub fn mark_attempted(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        self.transition(
            operation_id,
            &[OperationState::Admitted],
            OperationState::Attempted,
            OperationEventKind::EffectAttempted,
            at_ticks,
            evidence_digest,
        )
    }

    /// Record the local effect owner's defined commit point.
    ///
    /// This call must be made by the effect owner only after it knows the
    /// effect committed. It does not imply receiver observation or display.
    pub fn mark_committed(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        effect_owner_receipt_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        self.transition(
            operation_id,
            &[OperationState::Attempted],
            OperationState::Committed,
            OperationEventKind::EffectCommitted,
            at_ticks,
            effect_owner_receipt_digest,
        )
    }

    /// Record a layer-specific observation stronger than local commit.
    ///
    /// Examples include receiver-side file hash verification. Do not use this
    /// for a local send success or a compositor submission callback.
    pub fn mark_observed(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        observation_receipt_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        let current = self.snapshot(operation_id)?;
        let (next, allowed) = match current.state {
            OperationState::Committed => {
                (OperationState::Observed, &[OperationState::Committed][..])
            }
            OperationState::ReconciledCommitted => (
                OperationState::ReconciledObserved,
                &[OperationState::ReconciledCommitted][..],
            ),
            other => {
                return Err(OperationEvidenceError::InvalidTransition {
                    from: other,
                    event: OperationEventKind::OutcomeObserved,
                });
            }
        };
        self.transition(
            operation_id,
            allowed,
            next,
            OperationEventKind::OutcomeObserved,
            at_ticks,
            observation_receipt_digest,
        )
    }

    /// Reject an admitted operation before the protected effect is attempted.
    ///
    /// Once an attempt occurred, a failed/ambiguous return is not enough to
    /// claim rejection; use `mark_unknown` unless non-commit is independently
    /// established by the effect owner.
    pub fn mark_rejected(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        rejection_evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        self.transition(
            operation_id,
            &[OperationState::Admitted],
            OperationState::Rejected,
            OperationEventKind::Rejected,
            at_ticks,
            rejection_evidence_digest,
        )
    }

    /// Record a definitive non-commit after the effect owner was invoked.
    ///
    /// This differs from `mark_rejected`: the protected operation was
    /// actually attempted, but the effect owner proves its local commit point
    /// was not crossed. Use UNKNOWN when the result is ambiguous.
    pub fn mark_not_committed(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        non_commit_evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        self.transition(
            operation_id,
            &[OperationState::Attempted],
            OperationState::NotCommitted,
            OperationEventKind::EffectNotCommitted,
            at_ticks,
            non_commit_evidence_digest,
        )
    }

    /// Mark the operation outcome ambiguous after dispatch/attempt.
    ///
    /// This state blocks automatic retry. It remains UNKNOWN until
    /// `reconcile_unknown` supplies a stable receipt.
    pub fn mark_unknown(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        ambiguity_evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        self.transition(
            operation_id,
            &[OperationState::Attempted],
            OperationState::Unknown,
            OperationEventKind::Unknown,
            at_ticks,
            ambiguity_evidence_digest,
        )
    }

    /// Reconcile an unknown outcome using an independently established receipt.
    ///
    /// Replaying the exact same receipt is idempotent. A different receipt for
    /// an already reconciled operation is a conflict, not an overwrite.
    pub fn reconcile_unknown(
        &mut self,
        operation_id: OperationId,
        outcome: ReconciliationOutcome,
        at_ticks: u64,
        receipt_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        let current = self.snapshot(operation_id)?;
        if current.state != OperationState::Unknown {
            let expected = match outcome {
                ReconciliationOutcome::NotCommitted => OperationState::ReconciledNotCommitted,
                ReconciliationOutcome::Committed => OperationState::ReconciledCommitted,
                ReconciliationOutcome::Observed => OperationState::ReconciledObserved,
            };
            if current.state == expected && current.reconciliation_digest == Some(receipt_digest) {
                return Ok(current);
            }
            if matches!(
                current.state,
                OperationState::ReconciledNotCommitted
                    | OperationState::ReconciledCommitted
                    | OperationState::ReconciledObserved
            ) {
                return Err(OperationEvidenceError::ReconciliationConflict);
            }
            return Err(OperationEvidenceError::InvalidTransition {
                from: current.state,
                event: OperationEventKind::Reconciled,
            });
        }

        let next = match outcome {
            ReconciliationOutcome::NotCommitted => OperationState::ReconciledNotCommitted,
            ReconciliationOutcome::Committed => OperationState::ReconciledCommitted,
            ReconciliationOutcome::Observed => OperationState::ReconciledObserved,
        };
        let mut snapshot = self.transition(
            operation_id,
            &[OperationState::Unknown],
            next,
            OperationEventKind::Reconciled,
            at_ticks,
            receipt_digest,
        )?;
        snapshot.reconciliation_digest = Some(receipt_digest);
        self.records.insert(operation_id, snapshot);
        Ok(snapshot)
    }

    /// Return the current state of one known operation.
    pub fn snapshot(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        self.records
            .get(&operation_id)
            .copied()
            .ok_or(OperationEvidenceError::UnknownOperation)
    }

    /// Read the append-only event sequence.
    pub fn events(&self) -> &[OperationEvidenceEvent] {
        &self.events
    }

    /// Return payload-free counts derived from the current operation records.
    pub fn state_counts(&self) -> OperationEvidenceStateCounts {
        let mut counts = OperationEvidenceStateCounts::default();
        for record in self.records.values() {
            match record.state {
                OperationState::Admitted => counts.admitted = counts.admitted.saturating_add(1),
                OperationState::Attempted => counts.attempted = counts.attempted.saturating_add(1),
                OperationState::Committed => counts.committed = counts.committed.saturating_add(1),
                OperationState::Observed => counts.observed = counts.observed.saturating_add(1),
                OperationState::Rejected => counts.rejected = counts.rejected.saturating_add(1),
                OperationState::NotCommitted => counts.not_committed = counts.not_committed.saturating_add(1),
                OperationState::Unknown => counts.unknown = counts.unknown.saturating_add(1),
                OperationState::ReconciledNotCommitted => counts.reconciled_not_committed = counts.reconciled_not_committed.saturating_add(1),
                OperationState::ReconciledCommitted => counts.reconciled_committed = counts.reconciled_committed.saturating_add(1),
                OperationState::ReconciledObserved => counts.reconciled_observed = counts.reconciled_observed.saturating_add(1),
            }
        }
        counts
    }

    /// Current chain digest for external binding/export.
    ///
    /// This is a hash-chain commitment only. It does not authenticate the
    /// author or establish the truth of the supplied effect-owner receipts.
    pub fn chain_digest(&self) -> [u8; 32] {
        self.last_event_hash
    }

    /// Verify event sequence, clock monotonicity and all hash links.
    pub fn verify_chain(&self) -> bool {
        let mut previous_hash = [0_u8; 32];
        let mut expected_sequence = 1_u64;
        let mut previous_tick = None;

        for event in &self.events {
            if event.event_sequence != expected_sequence
                || event.previous_hash != previous_hash
                || event.clock_domain != self.clock_domain
                || previous_tick.is_some_and(|tick| event.at_ticks < tick)
            {
                return false;
            }

            let expected_hash = event_hash(event);
            if expected_hash != event.event_hash {
                return false;
            }

            previous_hash = event.event_hash;
            previous_tick = Some(event.at_ticks);
            expected_sequence = match expected_sequence.checked_add(1) {
                Some(value) => value,
                None => return false,
            };
        }

        previous_hash == self.last_event_hash
            && expected_sequence == self.next_event_sequence
            && self.events.len() <= MAX_OPERATION_EVENTS
            && self.records.len() <= MAX_OPERATION_RECORDS
    }

    fn transition(
        &mut self,
        operation_id: OperationId,
        allowed_states: &[OperationState],
        next_state: OperationState,
        event_kind: OperationEventKind,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, OperationEvidenceError> {
        let current = self.snapshot(operation_id)?;
        if !allowed_states.contains(&current.state) {
            return Err(OperationEvidenceError::InvalidTransition {
                from: current.state,
                event: event_kind,
            });
        }

        self.append_event(
            operation_id,
            current.operation_sequence,
            current.context.digest(),
            event_kind,
            at_ticks,
            evidence_digest,
        )?;

        let mut updated = current;
        updated.state = next_state;
        self.records.insert(operation_id, updated);
        Ok(updated)
    }

    fn append_event(
        &mut self,
        operation_id: OperationId,
        operation_sequence: u64,
        context_digest: [u8; 32],
        kind: OperationEventKind,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<(), OperationEvidenceError> {
        if self.events.len() >= MAX_OPERATION_EVENTS {
            return Err(OperationEvidenceError::CapacityFull);
        }
        if let Some(previous) = self.last_event_tick
            && at_ticks < previous
        {
            return Err(OperationEvidenceError::ClockRegression {
                previous,
                observed: at_ticks,
            });
        }

        let event_sequence = self.next_event_sequence;
        let next_event_sequence = event_sequence
            .checked_add(1)
            .ok_or(OperationEvidenceError::EventSequenceExhausted)?;
        let previous_hash = self.last_event_hash;
        let mut event = OperationEvidenceEvent {
            event_sequence,
            operation_id,
            operation_sequence,
            context_digest,
            kind,
            clock_domain: self.clock_domain,
            at_ticks,
            evidence_digest,
            previous_hash,
            event_hash: [0; 32],
        };
        let event_hash = event_hash(&event);
        event.event_hash = event_hash;
        self.events.push(event);
        self.next_event_sequence = next_event_sequence;
        self.last_event_tick = Some(at_ticks);
        self.last_event_hash = event_hash;
        Ok(())
    }
}

fn event_hash(event: &OperationEvidenceEvent) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-OPERATION-EVENT-V1\0");
    hasher.update(&event.previous_hash);
    hasher.update(&event.event_sequence.to_le_bytes());
    hasher.update(&event.operation_id.0);
    hasher.update(&event.operation_sequence.to_le_bytes());
    hasher.update(&event.context_digest);
    hasher.update(&[event.kind as u8]);
    hasher.update(&event.clock_domain.to_le_bytes());
    hasher.update(&event.at_ticks.to_le_bytes());
    hasher.update(&event.evidence_digest);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> OperationContext {
        OperationContext {
            session_fingerprint: [1; 32],
            lane: M1Permission::InjectInput,
            direction: OperationDirection::ViewerToHost,
            resource_digest: [2; 32],
            consent_reference_digest: [3; 32],
            policy_digest: [4; 32],
            authority_commitment_digest: Some([5; 32]),
            authority_epoch: Some(8),
        }
    }

    fn ledger() -> OperationEvidenceLedger {
        OperationEvidenceLedger::new([1; 32], 77)
    }

    fn operation(id: u8) -> OperationId {
        OperationId([id; 16])
    }

    fn admit_one(
        ledger: &mut OperationEvidenceLedger,
        id: OperationId,
        sequence: u64,
    ) -> OperationSnapshot {
        match ledger.admit(id, sequence, context(), 10, [9; 32]) {
            Ok(AdmissionResult::Created(snapshot)) => snapshot,
            Ok(AdmissionResult::AlreadyPresent(snapshot)) => snapshot,
            Err(error) => panic!("operation admission failed: {error:?}"),
        }
    }

    #[test]
    fn operation_progression_distinguishes_admission_attempt_commit_and_observation() {
        let mut ledger = ledger();
        let admitted = admit_one(&mut ledger, operation(1), 1);
        assert_eq!(admitted.state, OperationState::Admitted);

        let attempted = ledger
            .mark_attempted(operation(1), 11, [10; 32])
            .unwrap_or_else(|error| panic!("attempt failed: {error:?}"));
        assert_eq!(attempted.state, OperationState::Attempted);

        let committed = ledger
            .mark_committed(operation(1), 12, [11; 32])
            .unwrap_or_else(|error| panic!("commit failed: {error:?}"));
        assert_eq!(committed.state, OperationState::Committed);

        let observed = ledger
            .mark_observed(operation(1), 13, [12; 32])
            .unwrap_or_else(|error| panic!("observation failed: {error:?}"));
        assert_eq!(observed.state, OperationState::Observed);
        assert_eq!(ledger.events().len(), 4);
        assert!(ledger.verify_chain());
    }

    #[test]
    fn unknown_outcome_is_not_retried_and_requires_reconciliation() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(2), 1);
        ledger
            .mark_attempted(operation(2), 11, [10; 32])
            .unwrap_or_else(|error| panic!("attempt failed: {error:?}"));
        let unknown = ledger
            .mark_unknown(operation(2), 12, [11; 32])
            .unwrap_or_else(|error| panic!("unknown transition failed: {error:?}"));
        assert_eq!(unknown.state, OperationState::Unknown);
        assert_eq!(
            ledger.mark_attempted(operation(2), 13, [12; 32]),
            Err(OperationEvidenceError::InvalidTransition {
                from: OperationState::Unknown,
                event: OperationEventKind::EffectAttempted,
            })
        );

        let reconciled = ledger
            .reconcile_unknown(
                operation(2),
                ReconciliationOutcome::NotCommitted,
                14,
                [13; 32],
            )
            .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(reconciled.state, OperationState::ReconciledNotCommitted);
        assert_eq!(reconciled.reconciliation_digest, Some([13; 32]));
        assert_eq!(
            ledger
                .reconcile_unknown(
                    operation(2),
                    ReconciliationOutcome::NotCommitted,
                    14,
                    [13; 32],
                )
                .unwrap_or_else(|error| panic!("idempotent receipt failed: {error:?}")),
            reconciled
        );
        assert!(ledger.verify_chain());
    }

    #[test]
    fn duplicate_admission_is_idempotent_but_changed_context_conflicts() {
        let mut ledger = ledger();
        let created = admit_one(&mut ledger, operation(3), 1);
        let event_count = ledger.events().len();

        let duplicate = ledger
            .admit(operation(3), 1, context(), 20, [99; 32])
            .unwrap_or_else(|error| panic!("duplicate admission failed: {error:?}"));
        assert_eq!(duplicate, AdmissionResult::AlreadyPresent(created));
        assert_eq!(ledger.events().len(), event_count);

        let mut changed = context();
        changed.resource_digest = [0xFF; 32];
        assert_eq!(
            ledger.admit(operation(3), 1, changed, 21, [0; 32]),
            Err(OperationEvidenceError::OperationIdConflict)
        );
    }

    #[test]
    fn stage_order_cannot_claim_commit_without_attempt() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(4), 1);
        assert_eq!(
            ledger.mark_committed(operation(4), 11, [10; 32]),
            Err(OperationEvidenceError::InvalidTransition {
                from: OperationState::Admitted,
                event: OperationEventKind::EffectCommitted,
            })
        );
        assert_eq!(
            ledger.mark_observed(operation(4), 11, [10; 32]),
            Err(OperationEvidenceError::InvalidTransition {
                from: OperationState::Admitted,
                event: OperationEventKind::OutcomeObserved,
            })
        );
        assert_eq!(
            ledger.mark_not_committed(operation(4), 11, [10; 32]),
            Err(OperationEvidenceError::InvalidTransition {
                from: OperationState::Admitted,
                event: OperationEventKind::EffectNotCommitted,
            })
        );
        assert_eq!(ledger.events().len(), 1);
        assert!(ledger.verify_chain());
    }

    #[test]
    fn rejection_is_only_valid_before_effect_attempt() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(5), 1);
        let rejected = ledger
            .mark_rejected(operation(5), 11, [10; 32])
            .unwrap_or_else(|error| panic!("rejection failed: {error:?}"));
        assert_eq!(rejected.state, OperationState::Rejected);
        assert_eq!(
            ledger.mark_unknown(operation(5), 12, [11; 32]),
            Err(OperationEvidenceError::InvalidTransition {
                from: OperationState::Rejected,
                event: OperationEventKind::Unknown,
            })
        );
    }

    #[test]
    fn attempted_effect_can_be_definitively_not_committed() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(12), 1);
        ledger
            .mark_attempted(operation(12), 11, [10; 32])
            .unwrap_or_else(|error| panic!("attempt failed: {error:?}"));
        let not_committed = ledger
            .mark_not_committed(operation(12), 12, [11; 32])
            .unwrap_or_else(|error| panic!("non-commit receipt failed: {error:?}"));
        assert_eq!(not_committed.state, OperationState::NotCommitted);
        assert_eq!(
            ledger.mark_rejected(operation(12), 13, [12; 32]),
            Err(OperationEvidenceError::InvalidTransition {
                from: OperationState::NotCommitted,
                event: OperationEventKind::Rejected,
            })
        );
        assert_eq!(
            ledger.mark_unknown(operation(12), 13, [12; 32]),
            Err(OperationEvidenceError::InvalidTransition {
                from: OperationState::NotCommitted,
                event: OperationEventKind::Unknown,
            })
        );
        assert!(ledger.verify_chain());
    }

    #[test]
    fn operation_sequences_and_clock_ticks_must_be_monotonic() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(6), 2);
        assert_eq!(
            ledger.admit(operation(7), 1, context(), 11, [10; 32]),
            Err(OperationEvidenceError::NonMonotonicOperationSequence {
                previous: 2,
                observed: 1,
            })
        );
        assert_eq!(
            ledger.mark_attempted(operation(6), 9, [11; 32]),
            Err(OperationEvidenceError::ClockRegression {
                previous: 10,
                observed: 9,
            })
        );
    }

    #[test]
    fn context_from_another_session_is_rejected() {
        let mut ledger = ledger();
        let mut foreign = context();
        foreign.session_fingerprint = [0xAA; 32];
        assert_eq!(
            ledger.admit(operation(8), 1, foreign, 10, [9; 32]),
            Err(OperationEvidenceError::SessionFingerprintMismatch)
        );
        assert!(ledger.events().is_empty());
    }

    #[test]
    fn hash_chain_detects_event_tampering() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(9), 1);
        ledger
            .mark_attempted(operation(9), 11, [10; 32])
            .unwrap_or_else(|error| panic!("attempt failed: {error:?}"));
        assert!(ledger.verify_chain());

        ledger.events[0].evidence_digest[0] ^= 1;
        assert!(!ledger.verify_chain());
    }

    #[test]
    fn hash_chain_binds_each_event_to_the_ledger_clock_domain() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(11), 1);
        assert!(ledger.verify_chain());
        ledger.events[0].clock_domain += 1;
        assert!(!ledger.verify_chain());
    }

    #[test]
    fn reconciliation_receipt_cannot_be_silently_overwritten() {
        let mut ledger = ledger();
        admit_one(&mut ledger, operation(10), 1);
        ledger
            .mark_attempted(operation(10), 11, [10; 32])
            .unwrap_or_else(|error| panic!("attempt failed: {error:?}"));
        ledger
            .mark_unknown(operation(10), 12, [11; 32])
            .unwrap_or_else(|error| panic!("unknown transition failed: {error:?}"));
        ledger
            .reconcile_unknown(
                operation(10),
                ReconciliationOutcome::Committed,
                13,
                [12; 32],
            )
            .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(
            ledger.reconcile_unknown(
                operation(10),
                ReconciliationOutcome::NotCommitted,
                14,
                [13; 32],
            ),
            Err(OperationEvidenceError::ReconciliationConflict)
        );
    }
}
