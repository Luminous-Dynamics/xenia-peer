// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Local serialization primitive for revocation versus synchronous effect commit.
//!
//! This module is deliberately not an authorization engine. The caller must
//! establish consent, semantic authority, scope and freshness before calling
//! `prepare_after_admission`. This gate serializes that already-admitted
//! operation's short, synchronous effect-owner commit against local revocation.
//!
//! The effect closure executes while the gate mutex is held:
//! - if commit acquires the lock first, its closure returns before revocation
//!   can linearize;
//! - if revoke acquires the lock first, a later commit is denied before its
//!   closure is invoked.
//!
//! Do not hold this gate across an async operation, network round trip, file
//! transfer, or unbounded computation. Those require a narrower effect-owner
//! commit point and operation-level reconciliation. A panic while the closure
//! holds the mutex poisons the gate; subsequent calls fail closed.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::m1_session::M1Permission;

/// Maximum number of distinct operation IDs admitted by one gate/session.
pub const MAX_GATE_OPERATIONS: usize = 4_096;

static NEXT_GATE_ID: AtomicU64 = AtomicU64::new(1);

/// Direction of the protected effect across the host/viewer boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EffectDirection {
    /// Host-originated information disclosed to the viewer.
    HostToViewer = 1,
    /// Viewer-originated data or commands applied to the host.
    ViewerToHost = 2,
}

/// Request to create a one-shot effect permit after external authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectPermitRequest {
    /// Stable, caller-generated idempotency ID for this operation.
    pub operation_id: [u8; 16],
    /// Authenticated session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Exact M1 lane checked by the caller.
    pub lane: M1Permission,
    /// Direction of the protected effect.
    pub direction: EffectDirection,
    /// Digest of the full privacy-preserving operation context.
    pub context_digest: [u8; 32],
    /// Authority epoch checked by the caller.
    pub authority_epoch: u64,
}

/// Opaque, non-cloneable, one-shot permit for one local effect commit.
///
/// Fields are private so safe external code cannot construct or mutate a
/// permit. A permit is bound to the gate instance that created it.
#[must_use = "an effect permit must be committed or explicitly abandoned"]
#[derive(Debug)]
pub struct EffectCommitPermit {
    gate_id: u64,
    operation_id: [u8; 16],
    session_fingerprint: [u8; 32],
    lane: M1Permission,
    direction: EffectDirection,
    context_digest: [u8; 32],
    authority_epoch: u64,
}

/// Outcome returned by the effect-owning closure.
///
/// `Committed` must only be returned after the effect owner's defined local
/// commit point. `Unknown` is not a failure and must be reconciled before a
/// new operation is issued. The digest is supporting evidence, not a
/// signature or independent attestation.
#[derive(Debug, PartialEq, Eq)]
pub enum EffectExecution<T> {
    /// The local effect owner confirms its commit point.
    Committed {
        /// Result returned by the local effect owner.
        value: T,
        /// Digest of the local commit receipt/evidence.
        evidence_digest: [u8; 32],
    },
    /// The effect owner was invoked but confirms its local commit point
    /// was not crossed.
    NotCommitted {
        /// Digest of the definitive non-commit evidence.
        evidence_digest: [u8; 32],
    },
    /// The effect was invoked but its commit status is ambiguous.
    Unknown {
        /// Digest of the ambiguity/dispatch evidence.
        evidence_digest: [u8; 32],
    },
}

/// Result of running one synchronous effect-owner closure under the gate.
#[derive(Debug, PartialEq, Eq)]
pub struct EffectCommitReceipt<T> {
    /// Stable operation identity.
    pub operation_id: [u8; 16],
    /// Authenticated session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Exact permission lane.
    pub lane: M1Permission,
    /// Effect direction.
    pub direction: EffectDirection,
    /// Context digest checked when the permit was prepared.
    pub context_digest: [u8; 32],
    /// Authority epoch required at the commit boundary.
    pub authority_epoch: u64,
    /// Actual outcome returned by the effect owner.
    pub execution: EffectExecution<T>,
}

/// Snapshot of the gate's local state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectGateSnapshot {
    /// Session fingerprint bound to this gate.
    pub session_fingerprint: [u8; 32],
    /// Current observed authority epoch.
    pub authority_epoch: u64,
    /// Whether new commits are locally permitted.
    pub active: bool,
    /// Number of unique operation IDs already issued by this gate.
    pub issued_operations: usize,
    /// Number of permits still eligible for local commit.
    pub pending_operations: usize,
    /// Number of dispatched operations whose outcome is still unresolved.
    pub unresolved_unknown_operations: usize,
}

/// Receipt proving a prepared permit was abandoned before invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectPermitAbandonReceipt {
    /// Stable operation identity; it remains consumed and cannot be reused.
    pub operation_id: [u8; 16],
    /// Session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Exact M1 permission lane.
    pub lane: M1Permission,
    /// Effect direction.
    pub direction: EffectDirection,
    /// Context digest bound to the permit.
    pub context_digest: [u8; 32],
    /// Authority epoch at permit issuance.
    pub authority_epoch: u64,
    /// Digest of caller-supplied abandonment rationale/evidence.
    pub evidence_digest: [u8; 32],
}

/// Receipt for a local revocation linearization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectRevocationReceipt {
    /// Session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Epoch before the revocation was observed.
    pub previous_epoch: u64,
    /// New epoch bound to the revoked state.
    pub revoked_epoch: u64,
    /// Digest of the authenticated revocation evidence supplied by the caller.
    pub evidence_digest: [u8; 32],
}

/// Result established by an externally verified reconciliation receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectReconciliationOutcome {
    /// The operation did not commit.
    NotCommitted,
    /// The local effect owner confirms the operation committed.
    Committed,
    /// A stronger observer confirms the outcome was observed.
    Observed,
}

/// Local record of a verified reconciliation decision.
///
/// The receipt digest is supplied only after the caller independently verifies
/// its source. This gate does not authenticate the receipt itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectReconciliationReceipt {
    /// Stable operation identity.
    pub operation_id: [u8; 16],
    /// Digest recorded when the effect owner returned UNKNOWN.
    pub original_unknown_digest: [u8; 32],
    /// Reconciled outcome.
    pub outcome: EffectReconciliationOutcome,
    /// Digest of the independently verified reconciliation receipt.
    pub receipt_digest: [u8; 32],
}

/// Receipt for reactivation after an externally verified new grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectReactivationReceipt {
    /// Session fingerprint.
    pub session_fingerprint: [u8; 32],
    /// Epoch before the new grant.
    pub previous_epoch: u64,
    /// New authority epoch activated.
    pub active_epoch: u64,
    /// Digest of the regrant evidence supplied by the caller.
    pub evidence_digest: [u8; 32],
}

/// Fail-closed errors returned by the local effect-commit gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectGateError {
    /// The process-wide gate identity counter was exhausted.
    GateIdExhausted,
    /// The gate's mutex was poisoned by a panic while the lock was held.
    LockPoisoned,
    /// The request/permit refers to a different authenticated session.
    SessionMismatch,
    /// A commit permit belongs to another gate instance.
    ForeignGatePermit,
    /// The gate has observed revocation and is inactive.
    Revoked,
    /// The permit was invalidated by revocation, epoch advance or UNKNOWN.
    PermitInvalidated,
    /// The permit/request epoch is not the gate's current epoch.
    AuthorityEpochMismatch {
        /// Current gate epoch.
        current: u64,
        /// Request/permit epoch.
        requested: u64,
    },
    /// An operation ID has already been issued in this gate/session.
    DuplicateOperation,
    /// A dispatched operation is unresolved; no new mutation may be admitted.
    UnknownOutcomeOutstanding,
    /// No unresolved UNKNOWN record exists for the supplied operation ID.
    UnknownOperationNotFound,
    /// A different reconciliation receipt was presented for an already resolved operation.
    ReconciliationConflict,
    /// The per-session operation-ID bound has been reached.
    OperationCapacityFull,
    /// New authority epochs must be strictly greater than the current epoch.
    NonMonotonicEpoch {
        /// Current gate epoch.
        current: u64,
        /// Requested new epoch.
        requested: u64,
    },
    /// Re-activation is only valid from a revoked gate.
    NotRevoked,
    /// The gate is already revoked with a different receipt/epoch.
    AlreadyRevoked,
}

/// Internal local gate phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatePhase {
    Active,
    Revoked {
        previous_epoch: u64,
        evidence_digest: [u8; 32],
    },
}

#[derive(Debug)]
struct GateInner {
    session_fingerprint: [u8; 32],
    authority_epoch: u64,
    phase: GatePhase,
    issued_operations: HashSet<[u8; 16]>,
    pending_operations: HashSet<[u8; 16]>,
    unknown_operations: HashMap<[u8; 16], [u8; 32]>,
    reconciled_operations: HashMap<[u8; 16], EffectReconciliationReceipt>,
}

/// Serializes a synchronous local effect commit against local revocation.
///
/// The gate does not establish who may authorize an action. Callers must
/// perform recipient-consent, delegated-authority, purpose/resource scope,
/// expiry and freshness checks before requesting a permit.
#[derive(Debug)]
pub struct EffectCommitGate {
    gate_id: u64,
    inner: Mutex<GateInner>,
}

impl EffectCommitGate {
    /// Create a locally active gate for one authenticated session and
    /// authority epoch.
    pub fn new(
        session_fingerprint: [u8; 32],
        authority_epoch: u64,
    ) -> Result<Self, EffectGateError> {
        let gate_id = NEXT_GATE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| EffectGateError::GateIdExhausted)?;

        Ok(Self {
            gate_id,
            inner: Mutex::new(GateInner {
                session_fingerprint,
                authority_epoch,
                phase: GatePhase::Active,
                issued_operations: HashSet::new(),
                pending_operations: HashSet::new(),
                unknown_operations: HashMap::new(),
                reconciled_operations: HashMap::new(),
            }),
        })
    }

    /// Create a one-shot permit after all external authorization checks pass.
    ///
    /// This method checks that the caller's session and authority epoch match
    /// the gate's current local view. It does not validate the truth or
    /// signature of the consent/delegation evidence represented by the
    /// supplied digests.
    pub fn prepare_after_admission(
        &self,
        request: EffectPermitRequest,
    ) -> Result<EffectCommitPermit, EffectGateError> {
        let mut inner = self.lock()?;
        if request.session_fingerprint != inner.session_fingerprint {
            return Err(EffectGateError::SessionMismatch);
        }
        if !matches!(inner.phase, GatePhase::Active) {
            return Err(EffectGateError::Revoked);
        }
        if !inner.unknown_operations.is_empty() {
            return Err(EffectGateError::UnknownOutcomeOutstanding);
        }
        if request.authority_epoch != inner.authority_epoch {
            return Err(EffectGateError::AuthorityEpochMismatch {
                current: inner.authority_epoch,
                requested: request.authority_epoch,
            });
        }
        if inner.issued_operations.len() >= MAX_GATE_OPERATIONS {
            return Err(EffectGateError::OperationCapacityFull);
        }
        if !inner.issued_operations.insert(request.operation_id) {
            return Err(EffectGateError::DuplicateOperation);
        }
        inner.pending_operations.insert(request.operation_id);

        Ok(EffectCommitPermit {
            gate_id: self.gate_id,
            operation_id: request.operation_id,
            session_fingerprint: request.session_fingerprint,
            lane: request.lane,
            direction: request.direction,
            context_digest: request.context_digest,
            authority_epoch: request.authority_epoch,
        })
    }

    /// Explicitly abandon a prepared permit before invoking its effect.
    ///
    /// The operation ID remains consumed for this gate/session. Abandoning a
    /// permit is not a rejection receipt from the effect owner and does not
    /// prove that no other process independently performed the operation.
    pub fn abandon(
        &self,
        permit: EffectCommitPermit,
        evidence_digest: [u8; 32],
    ) -> Result<EffectPermitAbandonReceipt, EffectGateError> {
        let mut inner = self.lock()?;
        if permit.gate_id != self.gate_id {
            return Err(EffectGateError::ForeignGatePermit);
        }
        if permit.session_fingerprint != inner.session_fingerprint {
            return Err(EffectGateError::SessionMismatch);
        }
        if !matches!(inner.phase, GatePhase::Active) {
            return Err(EffectGateError::Revoked);
        }
        if permit.authority_epoch != inner.authority_epoch {
            return Err(EffectGateError::AuthorityEpochMismatch {
                current: inner.authority_epoch,
                requested: permit.authority_epoch,
            });
        }
        if !inner.pending_operations.remove(&permit.operation_id) {
            return Err(EffectGateError::PermitInvalidated);
        }
        Ok(EffectPermitAbandonReceipt {
            operation_id: permit.operation_id,
            session_fingerprint: permit.session_fingerprint,
            lane: permit.lane,
            direction: permit.direction,
            context_digest: permit.context_digest,
            authority_epoch: permit.authority_epoch,
            evidence_digest,
        })
    }

    /// Execute a short synchronous effect-owner commit while holding the same
    /// lock used by `revoke`.
    ///
    /// The closure must contain only the local operation's actual commit
    /// boundary. Do not put async work, network I/O, a whole file transfer or
    /// lengthy processing here. For a multi-step/async operation, use a
    /// separate permit/receipt at the actual effect-owner commit point.
    ///
    /// If the closure returns `Unknown`, the caller must reconcile by
    /// operation ID before authorizing a new operation. This gate does not
    /// decide whether the closure's evidence digest is truthful.
    pub fn commit<T, F>(
        &self,
        permit: EffectCommitPermit,
        effect_owner_commit: F,
    ) -> Result<EffectCommitReceipt<T>, EffectGateError>
    where
        F: FnOnce() -> EffectExecution<T>,
    {
        let mut inner = self.lock()?;
        if permit.gate_id != self.gate_id {
            return Err(EffectGateError::ForeignGatePermit);
        }
        if permit.session_fingerprint != inner.session_fingerprint {
            return Err(EffectGateError::SessionMismatch);
        }
        if !matches!(inner.phase, GatePhase::Active) {
            return Err(EffectGateError::Revoked);
        }
        if permit.authority_epoch != inner.authority_epoch {
            return Err(EffectGateError::AuthorityEpochMismatch {
                current: inner.authority_epoch,
                requested: permit.authority_epoch,
            });
        }
        if !inner.unknown_operations.is_empty() {
            return Err(EffectGateError::UnknownOutcomeOutstanding);
        }
        if !inner.pending_operations.remove(&permit.operation_id) {
            return Err(EffectGateError::PermitInvalidated);
        }

        // Linearization boundary: revoke takes this same mutex. The
        // synchronous effect-owner call therefore completes before a later
        // revoke can acquire/linearize, or it is not invoked at all.
        let execution = effect_owner_commit();
        if let EffectExecution::Unknown { evidence_digest } = &execution {
            inner
                .unknown_operations
                .insert(permit.operation_id, *evidence_digest);
            // Any other permit prepared before the ambiguous dispatch is now
            // stale. Reconciliation must be followed by fresh admission.
            inner.pending_operations.clear();
        }
        let receipt = EffectCommitReceipt {
            operation_id: permit.operation_id,
            session_fingerprint: permit.session_fingerprint,
            lane: permit.lane,
            direction: permit.direction,
            context_digest: permit.context_digest,
            authority_epoch: permit.authority_epoch,
            execution,
        };
        drop(inner);
        Ok(receipt)
    }

    /// Observe authenticated local revocation and invalidate every outstanding
    /// permit by advancing to a strictly newer authority epoch.
    ///
    /// A repeated identical revocation receipt is idempotent. A conflicting
    /// receipt cannot overwrite an already revoked state.
    pub fn revoke(
        &self,
        revoked_epoch: u64,
        evidence_digest: [u8; 32],
    ) -> Result<EffectRevocationReceipt, EffectGateError> {
        let mut inner = self.lock()?;
        if let GatePhase::Revoked {
            previous_epoch,
            evidence_digest: prior_digest,
        } = inner.phase
        {
            if revoked_epoch == inner.authority_epoch && evidence_digest == prior_digest {
                return Ok(EffectRevocationReceipt {
                    session_fingerprint: inner.session_fingerprint,
                    previous_epoch,
                    revoked_epoch,
                    evidence_digest,
                });
            }
            return Err(EffectGateError::AlreadyRevoked);
        }
        if revoked_epoch <= inner.authority_epoch {
            return Err(EffectGateError::NonMonotonicEpoch {
                current: inner.authority_epoch,
                requested: revoked_epoch,
            });
        }

        let previous_epoch = inner.authority_epoch;
        inner.pending_operations.clear();
        inner.authority_epoch = revoked_epoch;
        inner.phase = GatePhase::Revoked {
            previous_epoch,
            evidence_digest,
        };

        Ok(EffectRevocationReceipt {
            session_fingerprint: inner.session_fingerprint,
            previous_epoch,
            revoked_epoch,
            evidence_digest,
        })
    }

    /// Reactivate after an externally verified new consent/delegation grant.
    ///
    /// The new epoch must be strictly newer than the revocation epoch.
    /// Previously issued operation IDs remain consumed for this gate/session.
    pub fn reactivate_after_regrant(
        &self,
        active_epoch: u64,
        evidence_digest: [u8; 32],
    ) -> Result<EffectReactivationReceipt, EffectGateError> {
        let mut inner = self.lock()?;
        if !matches!(inner.phase, GatePhase::Revoked { .. }) {
            return Err(EffectGateError::NotRevoked);
        }
        if active_epoch <= inner.authority_epoch {
            return Err(EffectGateError::NonMonotonicEpoch {
                current: inner.authority_epoch,
                requested: active_epoch,
            });
        }

        let previous_epoch = inner.authority_epoch;
        inner.pending_operations.clear();
        inner.authority_epoch = active_epoch;
        inner.phase = GatePhase::Active;

        Ok(EffectReactivationReceipt {
            session_fingerprint: inner.session_fingerprint,
            previous_epoch,
            active_epoch,
            evidence_digest,
        })
    }

    /// Advance the locally observed authority epoch without changing active
    /// status. This invalidates outstanding permits from the prior epoch.
    pub fn advance_authority_epoch(
        &self,
        new_epoch: u64,
    ) -> Result<u64, EffectGateError> {
        let mut inner = self.lock()?;
        if !matches!(inner.phase, GatePhase::Active) {
            return Err(EffectGateError::Revoked);
        }
        if new_epoch <= inner.authority_epoch {
            return Err(EffectGateError::NonMonotonicEpoch {
                current: inner.authority_epoch,
                requested: new_epoch,
            });
        }
        inner.authority_epoch = new_epoch;
        Ok(new_epoch)
    }

    /// Reconcile an outstanding UNKNOWN operation using an externally
    /// verified receipt. While any UNKNOWN remains, prepare and commit are
    /// blocked for the entire session.
    ///
    /// The caller must authenticate the receipt before calling this method.
    /// Repeating the same receipt is idempotent; a conflicting receipt cannot
    /// overwrite the prior resolution.
    pub fn reconcile_unknown(
        &self,
        operation_id: [u8; 16],
        outcome: EffectReconciliationOutcome,
        receipt_digest: [u8; 32],
    ) -> Result<EffectReconciliationReceipt, EffectGateError> {
        let mut inner = self.lock()?;
        if let Some(existing) = inner.reconciled_operations.get(&operation_id).copied() {
            if existing.outcome == outcome && existing.receipt_digest == receipt_digest {
                return Ok(existing);
            }
            return Err(EffectGateError::ReconciliationConflict);
        }
        let original_unknown_digest = inner
            .unknown_operations
            .remove(&operation_id)
            .ok_or(EffectGateError::UnknownOperationNotFound)?;
        let receipt = EffectReconciliationReceipt {
            operation_id,
            original_unknown_digest,
            outcome,
            receipt_digest,
        };
        inner.reconciled_operations.insert(operation_id, receipt);
        Ok(receipt)
    }

    /// Read a fail-closed snapshot of the gate.
    pub fn snapshot(&self) -> Result<EffectGateSnapshot, EffectGateError> {
        let inner = self.lock()?;
        Ok(EffectGateSnapshot {
            session_fingerprint: inner.session_fingerprint,
            authority_epoch: inner.authority_epoch,
            active: matches!(inner.phase, GatePhase::Active),
            issued_operations: inner.issued_operations.len(),
            pending_operations: inner.pending_operations.len(),
            unresolved_unknown_operations: inner.unknown_operations.len(),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, GateInner>, EffectGateError> {
        self.inner.lock().map_err(|_| EffectGateError::LockPoisoned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    fn gate() -> EffectCommitGate {
        EffectCommitGate::new([1; 32], 7)
            .unwrap_or_else(|error| panic!("gate creation failed: {error:?}"))
    }

    fn request(id: u8) -> EffectPermitRequest {
        EffectPermitRequest {
            operation_id: [id; 16],
            session_fingerprint: [1; 32],
            lane: M1Permission::InjectInput,
            direction: EffectDirection::ViewerToHost,
            context_digest: [2; 32],
            authority_epoch: 7,
        }
    }

    #[test]
    fn commit_runs_after_admission_and_returns_stage_receipt() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(1))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        let receipt = gate
            .commit(permit, || EffectExecution::Committed {
                value: 42_u64,
                evidence_digest: [3; 32],
            })
            .unwrap_or_else(|error| panic!("commit failed: {error:?}"));
        assert_eq!(receipt.operation_id, [1; 16]);
        assert_eq!(receipt.authority_epoch, 7);
        assert_eq!(
            receipt.execution,
            EffectExecution::Committed {
                value: 42,
                evidence_digest: [3; 32],
            }
        );
    }

    #[test]
    fn revocation_before_commit_denies_without_invoking_effect() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(2))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        gate.revoke(8, [4; 32])
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));

        let invoked = AtomicBool::new(false);
        let result = gate.commit(permit, || {
            invoked.store(true, Ordering::SeqCst);
            EffectExecution::Committed {
                value: (),
                evidence_digest: [5; 32],
            }
        });
        assert_eq!(result, Err(EffectGateError::Revoked));
        assert!(!invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn commit_closure_finishes_before_a_waiting_revoke_linearizes() {
        let gate = Arc::new(gate());
        let permit = gate
            .prepare_after_admission(request(3))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        let entered_commit = Arc::new(Barrier::new(2));
        let release_commit = Arc::new(Barrier::new(2));

        let commit_gate = Arc::clone(&gate);
        let commit_entered = Arc::clone(&entered_commit);
        let commit_release = Arc::clone(&release_commit);
        let commit_thread = thread::spawn(move || {
            commit_gate.commit(permit, || {
                commit_entered.wait();
                commit_release.wait();
                EffectExecution::Committed {
                    value: (),
                    evidence_digest: [6; 32],
                }
            })
        });

        // The effect closure has entered while holding the gate mutex.
        entered_commit.wait();
        let revoke_gate = Arc::clone(&gate);
        let (started_tx, started_rx) = mpsc::channel();
        let revoke_thread = thread::spawn(move || {
            let _ = started_tx.send(());
            revoke_gate.revoke(8, [7; 32])
        });
        started_rx
            .recv()
            .unwrap_or_else(|error| panic!("revoke thread did not start: {error}"));

        // Release the local commit. Revoke can only acquire the mutex after
        // this closure and its receipt have completed.
        release_commit.wait();
        let committed = commit_thread
            .join()
            .unwrap_or_else(|_| panic!("commit thread panicked"))
            .unwrap_or_else(|error| panic!("commit failed: {error:?}"));
        let revoked = revoke_thread
            .join()
            .unwrap_or_else(|_| panic!("revoke thread panicked"))
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));

        assert!(matches!(
            committed.execution,
            EffectExecution::Committed { .. }
        ));
        assert_eq!(revoked.previous_epoch, 7);
        assert_eq!(revoked.revoked_epoch, 8);
        assert!(!gate.snapshot().unwrap_or_else(|e| panic!("{e:?}")).active);
    }

    #[test]
    fn unknown_invalidates_all_previously_prepared_permits() {
        let gate = gate();
        let first = gate
            .prepare_after_admission(request(16))
            .unwrap_or_else(|error| panic!("first permit failed: {error:?}"));
        let second = gate
            .prepare_after_admission(request(17))
            .unwrap_or_else(|error| panic!("second permit failed: {error:?}"));

        let unknown = gate
            .commit(first, || EffectExecution::<()>::Unknown {
                evidence_digest: [21; 32],
            })
            .unwrap_or_else(|error| panic!("first commit failed: {error:?}"));
        assert!(matches!(unknown.execution, EffectExecution::Unknown { .. }));

        assert_eq!(
            gate.commit(second, || EffectExecution::Committed {
                value: (),
                evidence_digest: [22; 32],
            }),
            Err(EffectGateError::UnknownOutcomeOutstanding)
        );
        gate.reconcile_unknown(
            [16; 16],
            EffectReconciliationOutcome::NotCommitted,
            [23; 32],
        )
        .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(
            gate.snapshot()
                .unwrap_or_else(|error| panic!("snapshot failed: {error:?}"))
                .pending_operations,
            0
        );
        assert_eq!(
            gate.prepare_after_admission(request(18))
                .unwrap_or_else(|error| panic!("fresh permit failed: {error:?}"))
                .operation_id,
            [18; 16]
        );
    }

    #[test]
    fn abandoned_permit_releases_pending_slot_but_consumes_operation_id() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(19))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        let receipt = gate
            .abandon(permit, [25; 32])
            .unwrap_or_else(|error| panic!("abandon failed: {error:?}"));
        assert_eq!(receipt.operation_id, [19; 16]);
        assert_eq!(
            gate.snapshot()
                .unwrap_or_else(|error| panic!("{error:?}"))
                .pending_operations,
            0
        );
        assert_eq!(
            gate.prepare_after_admission(request(19)).err(),
            Some(EffectGateError::DuplicateOperation)
        );
        assert!(gate.prepare_after_admission(request(20)).is_ok());
    }

    #[test]
    fn one_operation_id_cannot_receive_two_permits() {
        let gate = gate();
        let _permit = gate
            .prepare_after_admission(request(4))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        assert_eq!(
            gate.prepare_after_admission(request(4)).err(),
            Some(EffectGateError::DuplicateOperation)
        );
    }

    #[test]
    fn foreign_gate_permit_is_rejected() {
        let first = gate();
        let second = gate();
        let permit = first
            .prepare_after_admission(request(5))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        assert_eq!(
            second.commit(permit, || EffectExecution::Committed {
                value: (),
                evidence_digest: [8; 32],
            }),
            Err(EffectGateError::ForeignGatePermit)
        );
    }

    #[test]
    fn epoch_advance_invalidates_previously_issued_permits() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(6))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        gate.advance_authority_epoch(8)
            .unwrap_or_else(|error| panic!("epoch advance failed: {error:?}"));
        assert_eq!(
            gate.commit(permit, || EffectExecution::Committed {
                value: (),
                evidence_digest: [9; 32],
            }),
            Err(EffectGateError::AuthorityEpochMismatch {
                current: 8,
                requested: 7,
            })
        );
    }

    #[test]
    fn reactivation_requires_a_strictly_new_epoch() {
        let gate = gate();
        gate.revoke(8, [10; 32])
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));
        assert_eq!(
            gate.reactivate_after_regrant(8, [11; 32]),
            Err(EffectGateError::NonMonotonicEpoch {
                current: 8,
                requested: 8,
            })
        );
        assert_eq!(
            gate.reactivate_after_regrant(9, [12; 32])
                .unwrap_or_else(|error| panic!("reactivation failed: {error:?}"))
                .active_epoch,
            9
        );
    }

    #[test]
    fn definitive_non_commit_does_not_hold_the_session_unknown() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(22))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        let receipt = gate
            .commit(permit, || EffectExecution::<()>::NotCommitted {
                evidence_digest: [26; 32],
            })
            .unwrap_or_else(|error| panic!("commit failed: {error:?}"));
        assert_eq!(
            receipt.execution,
            EffectExecution::NotCommitted {
                evidence_digest: [26; 32],
            }
        );
        assert_eq!(
            gate.snapshot()
                .unwrap_or_else(|error| panic!("{error:?}"))
                .unresolved_unknown_operations,
            0
        );
        assert_eq!(
            gate.prepare_after_admission(request(23))
                .unwrap_or_else(|error| panic!("new operation blocked: {error:?}"))
                .operation_id,
            [23; 16]
        );
        assert_eq!(
            gate.prepare_after_admission(request(22)).err(),
            Some(EffectGateError::DuplicateOperation)
        );
    }

    #[test]
    fn unknown_outcome_blocks_new_mutations_until_reconciled() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(7))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        let receipt = gate
            .commit(permit, || EffectExecution::<()>::Unknown {
                evidence_digest: [13; 32],
            })
            .unwrap_or_else(|error| panic!("commit failed: {error:?}"));
        assert_eq!(
            receipt.execution,
            EffectExecution::Unknown {
                evidence_digest: [13; 32],
            }
        );
        assert_eq!(
            gate.prepare_after_admission(request(8)).err(),
            Some(EffectGateError::UnknownOutcomeOutstanding)
        );
        assert_eq!(
            gate.snapshot()
                .unwrap_or_else(|error| panic!("{error:?}"))
                .unresolved_unknown_operations,
            1
        );

        // A permit prepared before the UNKNOWN result is invalidated even
        // after reconciliation; callers must obtain a new one under current
        // authority and intent.
        let old_permit = gate
            .prepare_after_admission(request(8))
            .unwrap_err();
        assert_eq!(old_permit, EffectGateError::UnknownOutcomeOutstanding);
        let reconciled = gate
            .reconcile_unknown(
                [7; 16],
                EffectReconciliationOutcome::NotCommitted,
                [14; 32],
            )
            .unwrap_or_else(|error| panic!("reconciliation failed: {error:?}"));
        assert_eq!(reconciled.original_unknown_digest, [13; 32]);
        assert_eq!(
            gate.reconcile_unknown(
                [7; 16],
                EffectReconciliationOutcome::NotCommitted,
                [14; 32],
            )
            .unwrap_or_else(|error| panic!("idempotent receipt failed: {error:?}")),
            reconciled
        );
        let next = gate
            .prepare_after_admission(request(8))
            .unwrap_or_else(|error| panic!("fresh operation still blocked: {error:?}"));
        assert_eq!(next.operation_id, [8; 16]);
    }

    #[test]
    fn session_mismatch_is_rejected_before_permit_creation() {
        let gate = gate();
        let mut foreign = request(8);
        foreign.session_fingerprint = [0xAA; 32];
        assert_eq!(
            gate.prepare_after_admission(foreign).err(),
            Some(EffectGateError::SessionMismatch)
        );
        assert_eq!(
            gate.snapshot()
                .unwrap_or_else(|error| panic!("{error:?}"))
                .issued_operations,
            0
        );
    }

    #[test]
    fn panic_inside_effect_owner_poisoning_fails_closed() {
        let gate = gate();
        let permit = gate
            .prepare_after_admission(request(15))
            .unwrap_or_else(|error| panic!("permit failed: {error:?}"));
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = gate.commit(permit, || -> EffectExecution<()> {
                panic!("simulated effect-owner panic after invocation");
            });
        }));
        assert!(panic_result.is_err());
        assert_eq!(gate.snapshot(), Err(EffectGateError::LockPoisoned));
    }

    #[test]
    fn revoked_gate_is_idempotent_only_for_identical_receipt() {
        let gate = gate();
        let first = gate
            .revoke(8, [14; 32])
            .unwrap_or_else(|error| panic!("revoke failed: {error:?}"));
        assert_eq!(
            gate.revoke(8, [14; 32])
                .unwrap_or_else(|error| panic!("idempotent revoke failed: {error:?}")),
            first
        );
        assert_eq!(
            gate.revoke(9, [15; 32]).err(),
            Some(EffectGateError::AlreadyRevoked)
        );
    }
}
