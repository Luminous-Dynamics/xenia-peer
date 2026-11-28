// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Non-blocking admission and outcome tracking for asynchronous transport effects.
//!
//! The gate protects the ordering boundary around an async send without
//! holding a mutex across the network future:
//!
//! 1. Prepare a one-shot operation permit after external authorization.
//! 2. Call begin_dispatch immediately before invoking the transport future.
//! 3. Await the send without holding the gate mutex.
//! 4. Record local transport acceptance, or conservatively record UNKNOWN.
//!
//! begin_dispatch is the logical dispatch-admission linearization point. If it
//! wins before revocation, that already-admitted send may finish after
//! revocation. If revocation wins first, dispatch is rejected. This contract
//! does not promise that no socket byte is physically written after the wall
//! clock instant at which revocation returns.
//!
//! A transport Ok(()) means only that the local transport accepted the
//! complete envelope according to its API. It does not prove peer receipt,
//! decode, application, display, or user observation. A send error or dropped
//! future is UNKNOWN unless a lower layer independently proves no dispatch
//! occurred. UNKNOWN blocks new mutations until externally verified
//! reconciliation. The caller must authenticate that reconciliation receipt.
//!
//! All gate locks are held only for bounded in-memory state transitions. Never
//! hold this mutex over await, socket I/O, encoding, file transfer, or a remote
//! acknowledgement. This is a local ordering primitive, not an authorization
//! engine or a durable journal.

use std::collections::{HashMap, VecDeque, hash_map::Entry};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::m1_session::M1Permission;

/// Maximum number of prepared/in-flight/unknown dispatches retained at once.
pub const MAX_OUTSTANDING_ASYNC_DISPATCHES: usize = 4_096;
/// Maximum recent reconciliation receipts cached for in-memory idempotency.
pub const MAX_RECENT_DISPATCH_RECONCILIATIONS: usize = 1_024;

static NEXT_DISPATCH_GATE_ID: AtomicU64 = AtomicU64::new(1);

/// Direction of the protected data flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DispatchDirection {
    /// Host-originated data sent to the viewer.
    HostToViewer = 1,
    /// Viewer-originated data sent to the host.
    ViewerToHost = 2,
}

/// Payload-redacted identity of one logical transport dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchRequest {
    /// Stable operation identity derived from the authenticated session and operation sequence.
    pub operation_id: [u8; 16],
    /// Strictly increasing per-session sequence; never reset across rekey/regrant.
    pub operation_sequence: u64,
    /// Authenticated session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Exact permission lane independently authorized by the caller.
    pub lane: M1Permission,
    /// Direction across the host/viewer boundary.
    pub direction: DispatchDirection,
    /// Digest of the privacy-preserving operation/resource context.
    pub context_digest: [u8; 32],
    /// Current authority/rekey epoch independently checked by the caller.
    pub authority_epoch: u64,
}

/// Opaque, non-cloneable permit for one transport-dispatch admission.
#[must_use = "a dispatch permit must begin dispatch or be dropped before dispatch"]
#[derive(Debug)]
pub struct DispatchPermit {
    gate_id: u64,
    inner: Arc<Mutex<DispatchInner>>,
    request: DispatchRequest,
    consumed: bool,
}

impl Drop for DispatchPermit {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        if let Ok(mut inner) = self.inner.lock() {
            let is_prepared = inner
                .operations
                .get(&self.request.operation_id)
                .is_some_and(|record| {
                    record.request == self.request
                        && matches!(record.state, OperationState::Prepared)
                });
            if is_prepared {
                inner.operations.remove(&self.request.operation_id);
                inner.prepared_count = inner.prepared_count.saturating_sub(1);
                inner.cancelled_before_dispatch_total =
                    inner.cancelled_before_dispatch_total.saturating_add(1);
            }
        }
    }
}

/// Result category at the local transport boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportDispatchOutcome {
    /// The transport API returned success for the complete envelope.
    ///
    /// This is not evidence of peer receipt or application.
    AcceptedByTransport,
    /// The transport was invoked but its local dispatch result is ambiguous.
    Unknown,
}

/// A local receipt for one dispatch boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchReceipt {
    /// Original operation identity.
    pub operation_id: [u8; 16],
    /// Authenticated session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Permission lane bound to the operation.
    pub lane: M1Permission,
    /// Direction bound to the operation.
    pub direction: DispatchDirection,
    /// Payload-redacted operation/resource context digest.
    pub context_digest: [u8; 32],
    /// Authority epoch at admission.
    pub authority_epoch: u64,
    /// Monotonic per-session operation sequence.
    pub operation_sequence: u64,
    /// Local transport outcome; never implies remote application.
    pub outcome: TransportDispatchOutcome,
    /// Digest of transport evidence supplied by the caller.
    pub evidence_digest: [u8; 32],
}

/// One-shot guard representing a transport dispatch admitted before await.
#[must_use = "a dispatch guard must record a result; dropping it records UNKNOWN"]
#[derive(Debug)]
pub struct DispatchGuard {
    inner: Arc<Mutex<DispatchInner>>,
    request: DispatchRequest,
    fallback_unknown_digest: [u8; 32],
    resolved: bool,
}

impl DispatchGuard {
    /// Record that the transport API accepted the complete envelope.
    pub fn accepted_by_transport(
        mut self,
        evidence_digest: [u8; 32],
    ) -> Result<DispatchReceipt, DispatchGateError> {
        self.finish(
            TransportDispatchOutcome::AcceptedByTransport,
            evidence_digest,
        )
    }

    /// Record an ambiguous transport result.
    ///
    /// Use this for write errors/cancellation unless the transport has
    /// independently proved that no bytes or message were dispatched.
    pub fn mark_unknown(
        mut self,
        evidence_digest: [u8; 32],
    ) -> Result<DispatchReceipt, DispatchGateError> {
        self.finish(TransportDispatchOutcome::Unknown, evidence_digest)
    }

    fn finish(
        &mut self,
        outcome: TransportDispatchOutcome,
        evidence_digest: [u8; 32],
    ) -> Result<DispatchReceipt, DispatchGateError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DispatchGateError::LockPoisoned)?;
        let record = inner
            .operations
            .get(&self.request.operation_id)
            .copied()
            .ok_or(DispatchGateError::OperationNotFound)?;
        if record.request != self.request || !matches!(record.state, OperationState::InFlight) {
            return Err(DispatchGateError::OperationNotInFlight);
        }
        match outcome {
            TransportDispatchOutcome::AcceptedByTransport => {
                inner.operations.remove(&self.request.operation_id);
                inner.in_flight_count = inner.in_flight_count.saturating_sub(1);
                inner.accepted_total = inner.accepted_total.saturating_add(1);
            }
            TransportDispatchOutcome::Unknown => {
                if let Some(record) = inner.operations.get_mut(&self.request.operation_id) {
                    record.state = OperationState::Unknown { evidence_digest };
                    inner.in_flight_count = inner.in_flight_count.saturating_sub(1);
                    inner.unknown_count = inner.unknown_count.saturating_add(1);
                }
            }
        }
        self.resolved = true;
        Ok(DispatchReceipt {
            operation_id: self.request.operation_id,
            session_fingerprint: self.request.session_fingerprint,
            lane: self.request.lane,
            direction: self.request.direction,
            context_digest: self.request.context_digest,
            authority_epoch: self.request.authority_epoch,
            operation_sequence: self.request.operation_sequence,
            outcome,
            evidence_digest,
        })
    }
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        if let Ok(mut inner) = self.inner.lock()
            && let Some(record) = inner.operations.get_mut(&self.request.operation_id)
            && record.request == self.request
            && matches!(record.state, OperationState::InFlight)
        {
            // Future cancellation, task abortion, or panic is ambiguous.
            // The fallback digest is a marker, not an attestation.
            record.state = OperationState::Unknown {
                evidence_digest: self.fallback_unknown_digest,
            };
            inner.in_flight_count = inner.in_flight_count.saturating_sub(1);
            inner.unknown_count = inner.unknown_count.saturating_add(1);
        }
    }
}

/// Outcome proven by an independently authenticated reconciliation receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchReconciliationOutcome {
    /// A trusted transport/effect owner proves no dispatch occurred.
    NotDispatched,
    /// A trusted transport/effect owner proves local transport acceptance.
    TransportAccepted,
    /// A trusted remote observer proves receipt at the named remote boundary.
    PeerObserved,
}

/// Idempotent record of an independently verified reconciliation decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchReconciliationReceipt {
    /// Reconciled operation identity.
    pub operation_id: [u8; 16],
    /// Original UNKNOWN evidence digest.
    pub original_unknown_digest: [u8; 32],
    /// Independently established outcome.
    pub outcome: DispatchReconciliationOutcome,
    /// Digest of the externally verified receipt.
    pub receipt_digest: [u8; 32],
}

/// Receipt for the local revocation linearization point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchRevocationReceipt {
    /// Session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Authority epoch before revocation.
    pub previous_epoch: u64,
    /// Revoked authority epoch.
    pub revoked_epoch: u64,
    /// Digest of caller-supplied authenticated revocation evidence.
    pub evidence_digest: [u8; 32],
    /// Sends admitted before revocation that are still in flight.
    ///
    /// These operations may finish after this receipt. They are not silently
    /// cancelled or reclassified as not dispatched.
    pub in_flight_operations: Vec<[u8; 16]>,
}

/// Receipt for reactivation after externally verified new consent/authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchReactivationReceipt {
    /// Session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Revoked epoch.
    pub previous_epoch: u64,
    /// New active authority epoch.
    pub active_epoch: u64,
    /// Digest of caller-supplied regrant evidence.
    pub evidence_digest: [u8; 32],
}

/// An operation whose WAL-recovered latest state is UNKNOWN.
///
/// The request must be reconstructed from authenticated WAL identity fields,
/// not from caller-supplied live network data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveredUnknownDispatch {
    /// Original operation identity and authorization context.
    pub request: DispatchRequest,
    /// Digest of the durable UNKNOWN event created during WAL recovery.
    pub evidence_digest: [u8; 32],
}

/// Complete recovery projection supplied after the durable WAL is verified.
///
/// Every attempted operation lacking a durable owner outcome must appear in
/// unresolved_unknowns. Omitting one would incorrectly release the replay
/// barrier, so callers must construct this only from a complete replay of the
/// verified operation journal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DispatchRecoveryState {
    /// Highest durably admitted operation sequence, including terminal ops.
    pub last_admitted_sequence: Option<u64>,
    /// All unresolved UNKNOWN operations recovered from the durable WAL.
    pub unresolved_unknowns: Vec<RecoveredUnknownDispatch>,
}

/// Bounded observation of the local asynchronous dispatch gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchGateSnapshot {
    /// Session fingerprint bound to this gate.
    pub session_fingerprint: [u8; 32],
    /// Current authority epoch.
    pub authority_epoch: u64,
    /// Whether new dispatch admissions are permitted.
    pub active: bool,
    /// Currently outstanding operation IDs (prepared, in-flight, unknown).
    pub operation_count: usize,
    /// Permits prepared but not yet admitted to dispatch.
    pub prepared_operations: usize,
    /// Dispatches admitted and not yet resolved.
    pub in_flight_operations: usize,
    /// Ambiguous dispatches awaiting reconciliation.
    pub unknown_operations: usize,
    /// Locally accepted transport sends.
    pub accepted_operations: usize,
    /// Cumulative permits invalidated/dropped before dispatch.
    pub cancelled_before_dispatch: usize,
    /// Cumulative reconciled unknown dispatches.
    pub reconciled_operations: usize,
}

/// Fail-closed errors from the asynchronous dispatch gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchGateError {
    /// Process-wide gate identity was exhausted.
    GateIdExhausted,
    /// Internal mutex was poisoned.
    LockPoisoned,
    /// Request belongs to another authenticated session.
    SessionMismatch,
    /// Permit belongs to another gate instance.
    ForeignPermit,
    /// Gate has been revoked.
    Revoked,
    /// Request epoch does not equal the current authority epoch.
    AuthorityEpochMismatch {
        /// Current epoch.
        current: u64,
        /// Requested epoch.
        requested: u64,
    },
    /// Operation ID has already been consumed.
    DuplicateOperation,
    /// An UNKNOWN send must be reconciled before a new mutation.
    UnknownOutcomeOutstanding,
    /// Maximum outstanding prepared/in-flight/unknown dispatch capacity is exhausted.
    OperationCapacityFull,
    /// The operation is not present in this gate.
    OperationNotFound,
    /// The operation is not currently in flight.
    OperationNotInFlight,
    /// The operation does not have an UNKNOWN result to reconcile.
    UnknownOperationNotFound,
    /// A conflicting reconciliation receipt was supplied.
    ReconciliationConflict,
    /// Reactivation was attempted on an active gate.
    NotRevoked,
    /// The caller supplied an operation sequence which is not strictly increasing.
    NonMonotonicOperationSequence {
        /// Last admitted operation sequence.
        previous: u64,
        /// Requested operation sequence.
        observed: u64,
    },
    /// The operation ID does not match the canonical session/epoch/lane/sequence/context digest.
    OperationIdentityMismatch,
    /// The new authority epoch must strictly increase.
    NonMonotonicEpoch {
        /// Current epoch.
        current: u64,
        /// Requested epoch.
        requested: u64,
    },
    /// In-flight dispatches must resolve before reactivation.
    InFlightOutstanding,
    /// The recovered WAL projection is incomplete or internally inconsistent.
    InvalidRecoveryState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatePhase {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationState {
    Prepared,
    InFlight,
    Unknown { evidence_digest: [u8; 32] },
}

#[derive(Clone, Copy, Debug)]
struct OperationRecord {
    request: DispatchRequest,
    state: OperationState,
}

#[derive(Debug)]
struct DispatchInner {
    session_fingerprint: [u8; 32],
    authority_epoch: u64,
    last_admitted_sequence: Option<u64>,
    phase: GatePhase,
    operations: HashMap<[u8; 16], OperationRecord>,
    prepared_count: usize,
    in_flight_count: usize,
    unknown_count: usize,
    recent_reconciliations: HashMap<[u8; 16], DispatchReconciliationReceipt>,
    reconciliation_order: VecDeque<[u8; 16]>,
    accepted_total: usize,
    cancelled_before_dispatch_total: usize,
    reconciled_total: usize,
}

/// Non-blocking local state machine for async transport dispatch admission.
///
/// All external authorization, consent, scope, freshness and resource checks
/// must happen before prepare_after_admission. The gate serializes only local
/// in-memory state transitions. It does not perform persistence or signatures.
#[derive(Debug)]
pub struct TransportDispatchGate {
    gate_id: u64,
    inner: Arc<Mutex<DispatchInner>>,
}

impl TransportDispatchGate {
    /// Create a gate for a genuinely new authenticated session.
    ///
    /// Do not use this constructor to resume a prior session. Resumed sessions
    /// must use restore with a complete projection from the verified WAL.
    pub fn new(
        session_fingerprint: [u8; 32],
        authority_epoch: u64,
    ) -> Result<Self, DispatchGateError> {
        Self::restore(
            session_fingerprint,
            authority_epoch,
            DispatchRecoveryState::default(),
        )
    }

    /// Restore a gate after process restart using a complete projection of the
    /// verified operation WAL.
    ///
    /// Every Attempted operation without a durable terminal owner result must
    /// be supplied as unresolved UNKNOWN. The durable journal, not this
    /// in-memory gate, remains the source of truth for the projection.
    pub fn restore(
        session_fingerprint: [u8; 32],
        authority_epoch: u64,
        recovery: DispatchRecoveryState,
    ) -> Result<Self, DispatchGateError> {
        let last_admitted_sequence = recovery.last_admitted_sequence;
        let mut operations = HashMap::new();
        for unknown in recovery.unresolved_unknowns {
            let request = unknown.request;
            let Some(high_water) = last_admitted_sequence else {
                return Err(DispatchGateError::InvalidRecoveryState);
            };
            if request.session_fingerprint != session_fingerprint
                || request.authority_epoch > authority_epoch
                || request.operation_sequence == 0
                || request.operation_sequence > high_water
                || request.operation_id != derive_dispatch_operation_id(
                    request.session_fingerprint,
                    request.authority_epoch,
                    request.lane,
                    request.direction,
                    request.operation_sequence,
                    request.context_digest,
                )
                || operations.len() >= MAX_OUTSTANDING_ASYNC_DISPATCHES
            {
                return Err(DispatchGateError::InvalidRecoveryState);
            }
            let previous = operations.insert(
                request.operation_id,
                OperationRecord {
                    request,
                    state: OperationState::Unknown {
                        evidence_digest: unknown.evidence_digest,
                    },
                },
            );
            if previous.is_some() {
                return Err(DispatchGateError::InvalidRecoveryState);
            }
        }
        let unknown_count = operations.len();
        let gate_id = NEXT_DISPATCH_GATE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| DispatchGateError::GateIdExhausted)?;
        Ok(Self {
            gate_id,
            inner: Arc::new(Mutex::new(DispatchInner {
                session_fingerprint,
                authority_epoch,
                last_admitted_sequence,
                phase: GatePhase::Active,
                operations,
                prepared_count: 0,
                in_flight_count: 0,
                unknown_count,
                recent_reconciliations: HashMap::new(),
                reconciliation_order: VecDeque::new(),
                accepted_total: 0,
                cancelled_before_dispatch_total: 0,
                reconciled_total: 0,
            })),
        })
    }

    /// Reserve one stable operation ID after the caller has independently
    /// verified authority, consent, lane, direction and operation context.
    pub fn prepare_after_admission(
        &self,
        request: DispatchRequest,
    ) -> Result<DispatchPermit, DispatchGateError> {
        let mut inner = self.lock()?;
        if request.session_fingerprint != inner.session_fingerprint {
            return Err(DispatchGateError::SessionMismatch);
        }
        if inner.phase != GatePhase::Active {
            return Err(DispatchGateError::Revoked);
        }
        if request.authority_epoch != inner.authority_epoch {
            return Err(DispatchGateError::AuthorityEpochMismatch {
                current: inner.authority_epoch,
                requested: request.authority_epoch,
            });
        }
        if inner.unknown_count > 0 {
            return Err(DispatchGateError::UnknownOutcomeOutstanding);
        }
        if inner.operations.contains_key(&request.operation_id) {
            return Err(DispatchGateError::DuplicateOperation);
        }
        if let Some(previous) = inner.last_admitted_sequence
            && request.operation_sequence <= previous
        {
            return Err(DispatchGateError::NonMonotonicOperationSequence {
                previous,
                observed: request.operation_sequence,
            });
        }
        let expected_operation_id = derive_dispatch_operation_id(
            request.session_fingerprint,
            request.authority_epoch,
            request.lane,
            request.direction,
            request.operation_sequence,
            request.context_digest,
        );
        if request.operation_id != expected_operation_id {
            return Err(DispatchGateError::OperationIdentityMismatch);
        }
        if inner.operations.len() >= MAX_OUTSTANDING_ASYNC_DISPATCHES {
            return Err(DispatchGateError::OperationCapacityFull);
        }
        inner.last_admitted_sequence = Some(request.operation_sequence);
        match inner.operations.entry(request.operation_id) {
            Entry::Vacant(entry) => {
                entry.insert(OperationRecord {
                    request,
                    state: OperationState::Prepared,
                });
                inner.prepared_count = inner.prepared_count.saturating_add(1);
            }
            Entry::Occupied(_) => return Err(DispatchGateError::DuplicateOperation),
        }
        Ok(DispatchPermit {
            gate_id: self.gate_id,
            inner: Arc::clone(&self.inner),
            request,
            consumed: false,
        })
    }

    /// Linearize one async send immediately before invoking the transport
    /// future. The returned guard owns the in-flight operation.
    ///
    /// The caller must not insert an unbounded delay between this call and
    /// invoking the transport API. The send future is awaited without holding
    /// this gate's mutex. Dropping the returned guard records UNKNOWN.
    pub fn begin_dispatch(
        &self,
        mut permit: DispatchPermit,
    ) -> Result<DispatchGuard, DispatchGateError> {
        if permit.gate_id != self.gate_id || !Arc::ptr_eq(&permit.inner, &self.inner) {
            return Err(DispatchGateError::ForeignPermit);
        }
        let mut inner = self.lock()?;
        if permit.request.session_fingerprint != inner.session_fingerprint {
            return Err(DispatchGateError::SessionMismatch);
        }
        if inner.phase != GatePhase::Active {
            return Err(DispatchGateError::Revoked);
        }
        if permit.request.authority_epoch != inner.authority_epoch {
            return Err(DispatchGateError::AuthorityEpochMismatch {
                current: inner.authority_epoch,
                requested: permit.request.authority_epoch,
            });
        }
        let record = inner
            .operations
            .get_mut(&permit.request.operation_id)
            .ok_or(DispatchGateError::OperationNotFound)?;
        if record.request != permit.request || !matches!(record.state, OperationState::Prepared) {
            return Err(DispatchGateError::OperationNotInFlight);
        }
        record.state = OperationState::InFlight;
        inner.prepared_count = inner.prepared_count.saturating_sub(1);
        inner.in_flight_count = inner.in_flight_count.saturating_add(1);
        permit.consumed = true;
        let request = permit.request;
        drop(inner);
        drop(permit);
        Ok(DispatchGuard {
            inner: Arc::clone(&self.inner),
            request,
            fallback_unknown_digest: abandoned_guard_digest(&request),
            resolved: false,
        })
    }

    /// Revoke future dispatch admissions at a strictly newer authority epoch.
    ///
    /// Prepared permits are invalidated. In-flight sends admitted earlier are
    /// returned in the receipt and may finish after this call. This operation
    /// never waits for network I/O.
    pub fn revoke(
        &self,
        revoked_epoch: u64,
        evidence_digest: [u8; 32],
    ) -> Result<DispatchRevocationReceipt, DispatchGateError> {
        let mut inner = self.lock()?;
        if inner.phase != GatePhase::Active {
            return Err(DispatchGateError::Revoked);
        }
        if revoked_epoch <= inner.authority_epoch {
            return Err(DispatchGateError::NonMonotonicEpoch {
                current: inner.authority_epoch,
                requested: revoked_epoch,
            });
        }
        let previous_epoch = inner.authority_epoch;
        let prepared_operations: Vec<_> = inner
            .operations
            .iter()
            .filter_map(|(operation_id, record)| {
                matches!(record.state, OperationState::Prepared).then_some(*operation_id)
            })
            .collect();
        for operation_id in prepared_operations {
            inner.operations.remove(&operation_id);
            inner.prepared_count = inner.prepared_count.saturating_sub(1);
            inner.cancelled_before_dispatch_total =
                inner.cancelled_before_dispatch_total.saturating_add(1);
        }
        let mut in_flight_operations: Vec<_> = inner
            .operations
            .iter()
            .filter_map(|(operation_id, record)| {
                matches!(record.state, OperationState::InFlight).then_some(*operation_id)
            })
            .collect();
        in_flight_operations.sort_unstable();
        inner.authority_epoch = revoked_epoch;
        inner.phase = GatePhase::Revoked;
        Ok(DispatchRevocationReceipt {
            session_fingerprint: inner.session_fingerprint,
            previous_epoch,
            revoked_epoch,
            evidence_digest,
            in_flight_operations,
        })
    }

    /// Reconcile one UNKNOWN result after the caller authenticates an
    /// independent receipt tied to the exact operation ID.
    ///
    /// Repeating the same decision and receipt digest is idempotent. Conflicts
    /// fail closed. This method does not verify the external receipt.
    pub fn reconcile_unknown(
        &self,
        operation_id: [u8; 16],
        outcome: DispatchReconciliationOutcome,
        receipt_digest: [u8; 32],
    ) -> Result<DispatchReconciliationReceipt, DispatchGateError> {
        let mut inner = self.lock()?;
        if let Some(existing) = inner.recent_reconciliations.get(&operation_id) {
            return if existing.outcome == outcome && existing.receipt_digest == receipt_digest {
                Ok(*existing)
            } else {
                Err(DispatchGateError::ReconciliationConflict)
            };
        }
        let record = inner
            .operations
            .get(&operation_id)
            .copied()
            .ok_or(DispatchGateError::UnknownOperationNotFound)?;
        let OperationState::Unknown { evidence_digest } = record.state else {
            return Err(DispatchGateError::UnknownOperationNotFound);
        };
        let receipt = DispatchReconciliationReceipt {
            operation_id,
            original_unknown_digest: evidence_digest,
            outcome,
            receipt_digest,
        };
        inner.operations.remove(&operation_id);
        inner.unknown_count = inner.unknown_count.saturating_sub(1);
        inner.recent_reconciliations.insert(operation_id, receipt);
        inner.reconciliation_order.push_back(operation_id);
        while inner.reconciliation_order.len() > MAX_RECENT_DISPATCH_RECONCILIATIONS {
            if let Some(expired) = inner.reconciliation_order.pop_front() {
                inner.recent_reconciliations.remove(&expired);
            }
        }
        inner.reconciled_total = inner.reconciled_total.saturating_add(1);
        Ok(receipt)
    }

    /// Reactivate after new external authority/consent is independently
    /// verified. No in-flight or UNKNOWN operation may remain.
    pub fn reactivate_after_regrant(
        &self,
        active_epoch: u64,
        evidence_digest: [u8; 32],
    ) -> Result<DispatchReactivationReceipt, DispatchGateError> {
        let mut inner = self.lock()?;
        if inner.phase != GatePhase::Revoked {
            return Err(DispatchGateError::NotRevoked);
        }
        if active_epoch <= inner.authority_epoch {
            return Err(DispatchGateError::NonMonotonicEpoch {
                current: inner.authority_epoch,
                requested: active_epoch,
            });
        }
        if inner
            .operations
            .values()
            .any(|record| matches!(record.state, OperationState::InFlight))
        {
            return Err(DispatchGateError::InFlightOutstanding);
        }
        if inner.unknown_count > 0 {
            return Err(DispatchGateError::UnknownOutcomeOutstanding);
        }
        let previous_epoch = inner.authority_epoch;
        inner.authority_epoch = active_epoch;
        inner.phase = GatePhase::Active;
        Ok(DispatchReactivationReceipt {
            session_fingerprint: inner.session_fingerprint,
            previous_epoch,
            active_epoch,
            evidence_digest,
        })
    }

    /// Return a bounded snapshot of local dispatch state.
    pub fn snapshot(&self) -> Result<DispatchGateSnapshot, DispatchGateError> {
        let inner = self.lock()?;
        let snapshot = DispatchGateSnapshot {
            session_fingerprint: inner.session_fingerprint,
            authority_epoch: inner.authority_epoch,
            active: inner.phase == GatePhase::Active,
            operation_count: inner.operations.len(),
            prepared_operations: inner.prepared_count,
            in_flight_operations: inner.in_flight_count,
            unknown_operations: inner.unknown_count,
            accepted_operations: inner.accepted_total,
            cancelled_before_dispatch: inner.cancelled_before_dispatch_total,
            reconciled_operations: inner.reconciled_total,
        };
        Ok(snapshot)
    }

    fn lock(&self) -> Result<MutexGuard<'_, DispatchInner>, DispatchGateError> {
        self.inner
            .lock()
            .map_err(|_| DispatchGateError::LockPoisoned)
    }
}

/// Derive the stable operation ID from a monotonic session sequence and
/// the exact authenticated operation context. The sequence must not reset
/// across rekey or regrant. Long-term duplicate history remains the WAL's job.
pub fn derive_dispatch_operation_id(
    session_fingerprint: [u8; 32],
    authority_epoch: u64,
    lane: M1Permission,
    direction: DispatchDirection,
    operation_sequence: u64,
    context_digest: [u8; 32],
) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-ASYNC-DISPATCH-OPERATION-V1\0");
    hasher.update(&session_fingerprint);
    hasher.update(&authority_epoch.to_le_bytes());
    hasher.update(&[dispatch_permission_tag(lane), direction as u8]);
    hasher.update(&operation_sequence.to_le_bytes());
    hasher.update(&context_digest);
    let digest = hasher.finalize();
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&digest.as_bytes()[..16]);
    operation_id
}

fn dispatch_permission_tag(permission: M1Permission) -> u8 {
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

fn abandoned_guard_digest(request: &DispatchRequest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-ASYNC-DISPATCH-GUARD-DROPPED-V1\0");
    hasher.update(&request.operation_id);
    hasher.update(&request.session_fingerprint);
    hasher.update(&request.context_digest);
    hasher.update(&request.authority_epoch.to_le_bytes());
    hasher.update(&request.operation_sequence.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> TransportDispatchGate {
        TransportDispatchGate::new([1; 32], 7)
            .unwrap_or_else(|error| panic!("gate construction failed: {error:?}"))
    }

    fn request(id: u8) -> DispatchRequest {
        let session_fingerprint = [1; 32];
        let lane = M1Permission::StreamFrame;
        let direction = DispatchDirection::HostToViewer;
        let context_digest = [id.wrapping_add(20); 32];
        let authority_epoch = 7;
        let operation_sequence = u64::from(id);
        DispatchRequest {
            operation_id: derive_dispatch_operation_id(
                session_fingerprint,
                authority_epoch,
                lane,
                direction,
                operation_sequence,
                context_digest,
            ),
            operation_sequence,
            session_fingerprint,
            lane,
            direction,
            context_digest,
            authority_epoch,
        }
    }

    #[test]
    fn dropped_prepared_permit_is_cancelled_without_unknown() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(1))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        drop(permit);
        let snapshot = gate
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"));
        assert_eq!(snapshot.prepared_operations, 0);
        assert_eq!(snapshot.cancelled_before_dispatch, 1);
        assert_eq!(snapshot.unknown_operations, 0);
    }

    #[test]
    fn revoke_before_dispatch_rejects_prepared_permit() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(2))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        let receipt = gate
            .revoke(8, [8; 32])
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));
        assert!(receipt.in_flight_operations.is_empty());
        assert_eq!(
            gate.begin_dispatch(permit).err(),
            Some(DispatchGateError::Revoked)
        );
        let snapshot = gate
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"));
        assert_eq!(snapshot.in_flight_operations, 0);
        assert_eq!(snapshot.cancelled_before_dispatch, 1);
    }

    #[test]
    fn dispatch_admitted_before_revoke_may_finish_after_revoke() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(3))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        let guard = gate
            .begin_dispatch(permit)
            .unwrap_or_else(|error| panic!("dispatch admission failed: {error:?}"));
        let revoked = gate
            .revoke(8, [9; 32])
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));
        assert_eq!(revoked.in_flight_operations, vec![request(3).operation_id]);

        let send_receipt = guard
            .accepted_by_transport([10; 32])
            .unwrap_or_else(|error| panic!("transport receipt failed: {error:?}"));
        assert_eq!(
            send_receipt.outcome,
            TransportDispatchOutcome::AcceptedByTransport
        );
        let snapshot = gate
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"));
        assert_eq!(snapshot.in_flight_operations, 0);
        assert_eq!(snapshot.accepted_operations, 1);
        assert!(!snapshot.active);
    }

    #[test]
    fn dropped_in_flight_guard_becomes_unknown_and_blocks_new_dispatch() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(4))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        let guard = gate
            .begin_dispatch(permit)
            .unwrap_or_else(|error| panic!("dispatch admission failed: {error:?}"));
        drop(guard);
        assert_eq!(
            gate.prepare_after_admission(request(5)).err(),
            Some(DispatchGateError::UnknownOutcomeOutstanding)
        );
        assert_eq!(
            gate.snapshot()
                .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"))
                .unknown_operations,
            1
        );
        let reconciled = gate
            .reconcile_unknown(
                request(4).operation_id,
                DispatchReconciliationOutcome::NotDispatched,
                [11; 32],
            )
            .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(
            reconciled.outcome,
            DispatchReconciliationOutcome::NotDispatched
        );
        assert!(
            gate.prepare_after_admission(request(5)).is_ok(),
            "verified reconciliation should release the admission fence"
        );
    }

    #[test]
    fn repeated_same_reconciliation_is_idempotent_and_conflict_fails() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(6))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        drop(
            gate.begin_dispatch(permit)
                .unwrap_or_else(|error| panic!("dispatch admission failed: {error:?}")),
        );
        let first = gate
            .reconcile_unknown(
                request(6).operation_id,
                DispatchReconciliationOutcome::TransportAccepted,
                [12; 32],
            )
            .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(
            gate.reconcile_unknown(
                request(6).operation_id,
                DispatchReconciliationOutcome::TransportAccepted,
                [12; 32],
            )
            .unwrap_or_else(|error| panic!("idempotent reconciliation failed: {error:?}")),
            first
        );
        assert_eq!(
            gate.reconcile_unknown(
                request(6).operation_id,
                DispatchReconciliationOutcome::NotDispatched,
                [13; 32],
            ),
            Err(DispatchGateError::ReconciliationConflict)
        );
    }

    #[test]
    fn revocation_does_not_reactivate_while_send_is_unknown() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(7))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        let guard = gate
            .begin_dispatch(permit)
            .unwrap_or_else(|error| panic!("dispatch admission failed: {error:?}"));
        let revoked = gate
            .revoke(8, [14; 32])
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));
        assert_eq!(revoked.in_flight_operations, vec![request(7).operation_id]);
        drop(guard);
        assert_eq!(
            gate.reactivate_after_regrant(9, [15; 32]),
            Err(DispatchGateError::UnknownOutcomeOutstanding)
        );
        gate.reconcile_unknown(
            request(7).operation_id,
            DispatchReconciliationOutcome::NotDispatched,
            [16; 32],
        )
        .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        let reactivated = gate
            .reactivate_after_regrant(9, [17; 32])
            .unwrap_or_else(|error| panic!("reactivation failed: {error:?}"));
        assert_eq!(reactivated.active_epoch, 9);
    }

    #[test]
    fn in_flight_send_must_resolve_before_reactivation() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(8))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        let guard = gate
            .begin_dispatch(permit)
            .unwrap_or_else(|error| panic!("dispatch admission failed: {error:?}"));
        gate.revoke(8, [18; 32])
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));
        assert_eq!(
            gate.reactivate_after_regrant(9, [19; 32]),
            Err(DispatchGateError::InFlightOutstanding)
        );
        guard
            .accepted_by_transport([20; 32])
            .unwrap_or_else(|error| panic!("send completion failed: {error:?}"));
        assert!(gate.reactivate_after_regrant(9, [21; 32]).is_ok());
    }

    #[test]
    fn duplicate_operation_identity_cannot_receive_another_permit() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(9))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        assert_eq!(
            gate.prepare_after_admission(request(9)).err(),
            Some(DispatchGateError::DuplicateOperation)
        );
        drop(permit);
    }

    #[test]
    fn foreign_gate_permit_is_rejected() {
        let first = gate();
        let second = gate();
        let permit = first
            .prepare_after_admission(request(10))
            .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
        assert_eq!(
            second.begin_dispatch(permit).err(),
            Some(DispatchGateError::ForeignPermit)
        );
    }

    #[test]
    fn request_session_and_epoch_are_checked() {
        let gate = gate();
        let mut wrong_session = request(11);
        wrong_session.session_fingerprint = [99; 32];
        assert_eq!(
            gate.prepare_after_admission(wrong_session).err(),
            Some(DispatchGateError::SessionMismatch)
        );
        let mut wrong_epoch = request(12);
        wrong_epoch.authority_epoch = 8;
        assert_eq!(
            gate.prepare_after_admission(wrong_epoch).err(),
            Some(DispatchGateError::AuthorityEpochMismatch {
                current: 7,
                requested: 8,
            })
        );
    }

    #[test]
    fn completed_dispatches_do_not_consume_outstanding_capacity() {
        let gate = gate();
        for id in 1_u64..=10_000 {
            let context_digest = [id.to_le_bytes()[0]; 32];
            let operation_id = derive_dispatch_operation_id(
                [1; 32],
                7,
                M1Permission::StreamFrame,
                DispatchDirection::HostToViewer,
                id,
                context_digest,
            );
            let request = DispatchRequest {
                operation_id,
                operation_sequence: id,
                session_fingerprint: [1; 32],
                lane: M1Permission::StreamFrame,
                direction: DispatchDirection::HostToViewer,
                context_digest,
                authority_epoch: 7,
            };
            let permit = gate
                .prepare_after_admission(request)
                .unwrap_or_else(|error| panic!("prepare {id} failed: {error:?}"));
            gate.begin_dispatch(permit)
                .unwrap_or_else(|error| panic!("dispatch {id} failed: {error:?}"))
                .accepted_by_transport([id.to_le_bytes()[0]; 32])
                .unwrap_or_else(|error| panic!("completion {id} failed: {error:?}"));
        }
        let snapshot = gate
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"));
        assert_eq!(snapshot.operation_count, 0);
        assert_eq!(snapshot.accepted_operations, 10_000);
        assert_eq!(snapshot.unknown_operations, 0);
    }

    #[test]
    fn completed_operation_sequence_cannot_be_replayed() {
        let gate = gate();
        let request = request(12);
        gate.begin_dispatch(
            gate.prepare_after_admission(request)
                .unwrap_or_else(|error| panic!("prepare failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("dispatch admission failed: {error:?}"))
        .accepted_by_transport([12; 32])
        .unwrap_or_else(|error| panic!("completion failed: {error:?}"));

        assert_eq!(
            gate.prepare_after_admission(request).err(),
            Some(DispatchGateError::NonMonotonicOperationSequence {
                previous: 12,
                observed: 12,
            })
        );
    }

    #[test]
    fn operation_identity_binds_sequence_epoch_lane_and_context() {
        let gate = gate();
        let mut forged = request(13);
        forged.context_digest = [250; 32];
        assert_eq!(
            gate.prepare_after_admission(forged).err(),
            Some(DispatchGateError::OperationIdentityMismatch)
        );
    }

    #[test]
    fn outstanding_dispatch_capacity_is_strictly_bounded() {
        let gate = gate();
        let mut permits = Vec::with_capacity(MAX_OUTSTANDING_ASYNC_DISPATCHES);
        for sequence in 1..=MAX_OUTSTANDING_ASYNC_DISPATCHES as u64 {
            let context_digest = [sequence.to_le_bytes()[0]; 32];
            let operation_id = derive_dispatch_operation_id(
                [1; 32],
                7,
                M1Permission::StreamFrame,
                DispatchDirection::HostToViewer,
                sequence,
                context_digest,
            );
            permits.push(
                gate.prepare_after_admission(DispatchRequest {
                    operation_id,
                    operation_sequence: sequence,
                    session_fingerprint: [1; 32],
                    lane: M1Permission::StreamFrame,
                    direction: DispatchDirection::HostToViewer,
                    context_digest,
                    authority_epoch: 7,
                })
                .unwrap_or_else(|error| panic!("prepare {sequence} failed: {error:?}")),
            );
        }
        let next_sequence = MAX_OUTSTANDING_ASYNC_DISPATCHES as u64 + 1;
        let context_digest = [next_sequence.to_le_bytes()[0]; 32];
        assert_eq!(
            gate.prepare_after_admission(DispatchRequest {
                operation_id: derive_dispatch_operation_id(
                    [1; 32],
                    7,
                    M1Permission::StreamFrame,
                    DispatchDirection::HostToViewer,
                    next_sequence,
                    context_digest,
                ),
                operation_sequence: next_sequence,
                session_fingerprint: [1; 32],
                lane: M1Permission::StreamFrame,
                direction: DispatchDirection::HostToViewer,
                context_digest,
                authority_epoch: 7,
            })
            .err(),
            Some(DispatchGateError::OperationCapacityFull)
        );
        drop(permits);
        let snapshot = gate
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"));
        assert_eq!(snapshot.operation_count, 0);
        assert_eq!(
            snapshot.cancelled_before_dispatch,
            MAX_OUTSTANDING_ASYNC_DISPATCHES
        );
    }

    #[test]
    fn restore_uses_durable_operation_sequence_high_water() {
        let gate = TransportDispatchGate::restore([1; 32], 7, 42)
            .unwrap_or_else(|error| panic!("restore failed: {error:?}"));
        assert_eq!(
            gate.prepare_after_admission(request(42)).err(),
            Some(DispatchGateError::NonMonotonicOperationSequence {
                previous: 42,
                observed: 42,
            })
        );
        assert!(gate.prepare_after_admission(request(43)).is_ok());
    }

    #[test]
    fn revoke_and_begin_dispatch_have_one_linearization_winner() {
        use std::sync::Barrier;
        use std::thread;

        for id in 20_u8..52 {
            let gate = Arc::new(gate());
            let operation_id = request(id).operation_id;
            let permit = gate
                .prepare_after_admission(request(id))
                .unwrap_or_else(|error| panic!("prepare failed: {error:?}"));
            let barrier = Arc::new(Barrier::new(3));

            let dispatch_gate = Arc::clone(&gate);
            let dispatch_barrier = Arc::clone(&barrier);
            let dispatch = thread::spawn(move || {
                dispatch_barrier.wait();
                match dispatch_gate.begin_dispatch(permit) {
                    Ok(guard) => {
                        guard
                            .accepted_by_transport([id.wrapping_add(40); 32])
                            .unwrap_or_else(|error| panic!("completion failed: {error:?}"));
                        true
                    }
                    Err(DispatchGateError::Revoked) => false,
                    Err(error) => panic!("unexpected dispatch result: {error:?}"),
                }
            });

            let revoke_gate = Arc::clone(&gate);
            let revoke_barrier = Arc::clone(&barrier);
            let revoke = thread::spawn(move || {
                revoke_barrier.wait();
                revoke_gate
                    .revoke(8, [id.wrapping_add(60); 32])
                    .unwrap_or_else(|error| panic!("revoke failed: {error:?}"))
            });

            barrier.wait();
            let dispatch_won = dispatch
                .join()
                .unwrap_or_else(|_| panic!("dispatch thread panicked"));
            let revoke_receipt = revoke
                .join()
                .unwrap_or_else(|_| panic!("revoke thread panicked"));
            let was_in_flight_at_revoke =
                revoke_receipt.in_flight_operations.contains(&operation_id);
            let snapshot = gate
                .snapshot()
                .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"));

            if dispatch_won {
                assert!(
                    was_in_flight_at_revoke || snapshot.accepted_operations == 1,
                    "a pre-revoke dispatch must be either in-flight at revoke or already accepted"
                );
            } else {
                assert!(!was_in_flight_at_revoke);
                assert_eq!(snapshot.cancelled_before_dispatch, 1);
                assert_eq!(snapshot.accepted_operations, 0);
            }
        }
    }
    #[test]
    fn loom_exhaustively_checks_dispatch_revoke_and_completion_order() {
        loom::model(|| {
            use loom::sync::mpsc;
            use loom::sync::{Arc, Mutex};
            use loom::thread;

            #[derive(Default)]
            struct ModelState {
                active: bool,
                prepared: bool,
                in_flight: bool,
                accepted: bool,
                cancelled: bool,
                revoke_saw_in_flight: bool,
            }

            let state = Arc::new(Mutex::new(ModelState {
                active: true,
                prepared: true,
                ..ModelState::default()
            }));
            let (completion_tx, completion_rx) = mpsc::channel();

            let dispatch_state = Arc::clone(&state);
            let dispatch = thread::spawn(move || {
                let admitted = {
                    let mut state = dispatch_state
                        .lock()
                        .unwrap_or_else(|_| panic!("model lock poisoned"));
                    if state.active && state.prepared {
                        state.prepared = false;
                        state.in_flight = true;
                        true
                    } else {
                        false
                    }
                };
                completion_tx
                    .send(admitted)
                    .unwrap_or_else(|_| panic!("completion signal failed"));
                admitted
            });

            let finish_state = Arc::clone(&state);
            let finish = thread::spawn(move || {
                let admitted = completion_rx
                    .recv()
                    .unwrap_or_else(|_| panic!("dispatch completion signal missing"));
                if admitted {
                    let mut state = finish_state
                        .lock()
                        .unwrap_or_else(|_| panic!("model lock poisoned"));
                    if state.in_flight {
                        state.in_flight = false;
                        state.accepted = true;
                    }
                }
            });

            let revoke_state = Arc::clone(&state);
            let revoke = thread::spawn(move || {
                let mut state = revoke_state
                    .lock()
                    .unwrap_or_else(|_| panic!("model lock poisoned"));
                state.active = false;
                if state.prepared {
                    state.prepared = false;
                    state.cancelled = true;
                }
                if state.in_flight {
                    state.revoke_saw_in_flight = true;
                }
            });

            let dispatch_admitted = dispatch
                .join()
                .unwrap_or_else(|_| panic!("model dispatch thread panicked"));
            finish
                .join()
                .unwrap_or_else(|_| panic!("model finish thread panicked"));
            revoke
                .join()
                .unwrap_or_else(|_| panic!("model revoke thread panicked"));

            let state = state
                .lock()
                .unwrap_or_else(|_| panic!("model lock poisoned"));
            assert!(!state.in_flight);
            if dispatch_admitted {
                assert!(
                    state.revoke_saw_in_flight || state.accepted,
                    "an admitted send must be either in flight at revoke or already accepted"
                );
                assert!(!state.cancelled);
            } else {
                assert!(state.cancelled);
                assert!(!state.accepted);
                assert!(!state.revoke_saw_in_flight);
            }
        });
    }
}
