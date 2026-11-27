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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::m1_session::M1Permission;

/// Maximum number of logical operations retained by one dispatch gate.
pub const MAX_ASYNC_DISPATCH_OPERATIONS: usize = 4_096;

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
    /// Stable operation identity retained across reconnect/retry.
    pub operation_id: [u8; 16],
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
        if let Ok(mut inner) = self.inner.lock()
            && let Some(record) = inner.operations.get_mut(&self.request.operation_id)
            && record.request == self.request
            && matches!(record.state, OperationState::Prepared)
        {
            // A permit dropped before begin_dispatch is definitively not
            // dispatched. Keep its operation ID consumed.
            record.state = OperationState::CancelledBeforeDispatch;
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
        self.finish(TransportDispatchOutcome::AcceptedByTransport, evidence_digest)
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
        let mut inner = self.inner.lock().map_err(|_| DispatchGateError::LockPoisoned)?;
        let record = inner
            .operations
            .get_mut(&self.request.operation_id)
            .ok_or(DispatchGateError::OperationNotFound)?;
        if record.request != self.request || !matches!(record.state, OperationState::InFlight) {
            return Err(DispatchGateError::OperationNotInFlight);
        }
        record.state = match outcome {
            TransportDispatchOutcome::AcceptedByTransport => {
                OperationState::AcceptedByTransport { evidence_digest }
            }
            TransportDispatchOutcome::Unknown => OperationState::Unknown { evidence_digest },
        };
        self.resolved = true;
        Ok(DispatchReceipt {
            operation_id: self.request.operation_id,
            session_fingerprint: self.request.session_fingerprint,
            lane: self.request.lane,
            direction: self.request.direction,
            context_digest: self.request.context_digest,
            authority_epoch: self.request.authority_epoch,
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

/// Bounded observation of the local asynchronous dispatch gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchGateSnapshot {
    /// Session fingerprint bound to this gate.
    pub session_fingerprint: [u8; 32],
    /// Current authority epoch.
    pub authority_epoch: u64,
    /// Whether new dispatch admissions are permitted.
    pub active: bool,
    /// Unique operation IDs retained.
    pub operation_count: usize,
    /// Permits prepared but not yet admitted to dispatch.
    pub prepared_operations: usize,
    /// Dispatches admitted and not yet resolved.
    pub in_flight_operations: usize,
    /// Ambiguous dispatches awaiting reconciliation.
    pub unknown_operations: usize,
    /// Locally accepted transport sends.
    pub accepted_operations: usize,
    /// Permits invalidated/dropped before dispatch.
    pub cancelled_before_dispatch: usize,
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
    /// Per-session operation capacity is exhausted.
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
    /// The new authority epoch must strictly increase.
    NonMonotonicEpoch {
        /// Current epoch.
        current: u64,
        /// Requested epoch.
        requested: u64,
    },
    /// In-flight dispatches must resolve before reactivation.
    InFlightOutstanding,
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
    AcceptedByTransport {
        evidence_digest: [u8; 32],
    },
    Unknown {
        evidence_digest: [u8; 32],
    },
    CancelledBeforeDispatch,
    Reconciled {
        original_unknown_digest: [u8; 32],
        outcome: DispatchReconciliationOutcome,
        receipt_digest: [u8; 32],
    },
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
    phase: GatePhase,
    operations: HashMap<[u8; 16], OperationRecord>,
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
    /// Create an active gate for one authenticated session and authority epoch.
    pub fn new(
        session_fingerprint: [u8; 32],
        authority_epoch: u64,
    ) -> Result<Self, DispatchGateError> {
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
                phase: GatePhase::Active,
                operations: HashMap::new(),
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
        if inner
            .operations
            .values()
            .any(|record| matches!(record.state, OperationState::Unknown { .. }))
        {
            return Err(DispatchGateError::UnknownOutcomeOutstanding);
        }
        if inner.operations.len() >= MAX_ASYNC_DISPATCH_OPERATIONS {
            return Err(DispatchGateError::OperationCapacityFull);
        }
        if inner.operations.contains_key(&request.operation_id) {
            return Err(DispatchGateError::DuplicateOperation);
        }
        inner.operations.insert(
            request.operation_id,
            OperationRecord {
                request,
                state: OperationState::Prepared,
            },
        );
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
        if record.request != permit.request || !matches!(record.state, OperationState::Prepared)
        {
            return Err(DispatchGateError::OperationNotInFlight);
        }
        record.state = OperationState::InFlight;
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
        let mut in_flight_operations = Vec::new();
        for (operation_id, record) in &mut inner.operations {
            match record.state {
                OperationState::Prepared => {
                    record.state = OperationState::CancelledBeforeDispatch;
                }
                OperationState::InFlight => in_flight_operations.push(*operation_id),
                _ => {}
            }
        }
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
        let record = inner
            .operations
            .get_mut(&operation_id)
            .ok_or(DispatchGateError::OperationNotFound)?;
        match record.state {
            OperationState::Unknown { evidence_digest } => {
                record.state = OperationState::Reconciled {
                    original_unknown_digest: evidence_digest,
                    outcome,
                    receipt_digest,
                };
                Ok(DispatchReconciliationReceipt {
                    operation_id,
                    original_unknown_digest: evidence_digest,
                    outcome,
                    receipt_digest,
                })
            }
            OperationState::Reconciled {
                original_unknown_digest,
                outcome: existing_outcome,
                receipt_digest: existing_digest,
            } if existing_outcome == outcome && existing_digest == receipt_digest => {
                Ok(DispatchReconciliationReceipt {
                    operation_id,
                    original_unknown_digest,
                    outcome,
                    receipt_digest,
                })
            }
            OperationState::Reconciled { .. } => {
                Err(DispatchGateError::ReconciliationConflict)
            }
            _ => Err(DispatchGateError::UnknownOperationNotFound),
        }
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
        if inner
            .operations
            .values()
            .any(|record| matches!(record.state, OperationState::Unknown { .. }))
        {
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
        let mut snapshot = DispatchGateSnapshot {
            session_fingerprint: inner.session_fingerprint,
            authority_epoch: inner.authority_epoch,
            active: inner.phase == GatePhase::Active,
            operation_count: inner.operations.len(),
            prepared_operations: 0,
            in_flight_operations: 0,
            unknown_operations: 0,
            accepted_operations: 0,
            cancelled_before_dispatch: 0,
        };
        for record in inner.operations.values() {
            match record.state {
                OperationState::Prepared => snapshot.prepared_operations += 1,
                OperationState::InFlight => snapshot.in_flight_operations += 1,
                OperationState::Unknown { .. } => snapshot.unknown_operations += 1,
                OperationState::AcceptedByTransport { evidence_digest } => {
                    let _ = evidence_digest;
                    snapshot.accepted_operations += 1;
                }
                OperationState::CancelledBeforeDispatch => {
                    snapshot.cancelled_before_dispatch += 1;
                }
                OperationState::Reconciled {
                    original_unknown_digest,
                    outcome,
                    receipt_digest,
                } => {
                    let _ = (original_unknown_digest, outcome, receipt_digest);
                }
            }
        }
        Ok(snapshot)
    }

    fn lock(&self) -> Result<MutexGuard<'_, DispatchInner>, DispatchGateError> {
        self.inner
            .lock()
            .map_err(|_| DispatchGateError::LockPoisoned)
    }
}

fn abandoned_guard_digest(request: &DispatchRequest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-ASYNC-DISPATCH-GUARD-DROPPED-V1\0");
    hasher.update(&request.operation_id);
    hasher.update(&request.session_fingerprint);
    hasher.update(&request.context_digest);
    hasher.update(&request.authority_epoch.to_le_bytes());
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
        DispatchRequest {
            operation_id: [id; 16],
            session_fingerprint: [1; 32],
            lane: M1Permission::StreamFrame,
            direction: DispatchDirection::HostToViewer,
            context_digest: [id.wrapping_add(20); 32],
            authority_epoch: 7,
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
        assert_eq!(revoked.in_flight_operations, vec![[3; 16]]);

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
                [4; 16],
                DispatchReconciliationOutcome::NotDispatched,
                [11; 32],
            )
            .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(reconciled.outcome, DispatchReconciliationOutcome::NotDispatched);
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
                [6; 16],
                DispatchReconciliationOutcome::TransportAccepted,
                [12; 32],
            )
            .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(
            gate.reconcile_unknown(
                [6; 16],
                DispatchReconciliationOutcome::TransportAccepted,
                [12; 32],
            )
            .unwrap_or_else(|error| panic!("idempotent reconciliation failed: {error:?}")),
            first
        );
        assert_eq!(
            gate.reconcile_unknown(
                [6; 16],
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
        assert_eq!(revoked.in_flight_operations, vec![[7; 16]]);
        drop(guard);
        assert_eq!(
            gate.reactivate_after_regrant(9, [15; 32]),
            Err(DispatchGateError::UnknownOutcomeOutstanding)
        );
        gate.reconcile_unknown(
            [7; 16],
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
}
