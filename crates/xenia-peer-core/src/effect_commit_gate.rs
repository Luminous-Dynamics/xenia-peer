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

use std::collections::HashSet;
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
    /// The local effect owner confirms rejection before commit.
    Rejected {
        /// Digest of the rejection evidence.
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
    /// The permit/request epoch is not the gate's current epoch.
    AuthorityEpochMismatch {
        /// Current gate epoch.
        current: u64,
        /// Request/permit epoch.
        requested: u64,
    },
    /// An operation ID has already been issued in this gate/session.
    DuplicateOperation,
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
        let inner = self.lock()?;
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

        // Linearization boundary: revoke takes this same mutex. The
        // synchronous effect-owner call therefore completes before a later
        // revoke can acquire/linearize, or it is not invoked at all.
        let execution = effect_owner_commit();
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

    /// Read a fail-closed snapshot of the gate.
    pub fn snapshot(&self) -> Result<EffectGateSnapshot, EffectGateError> {
        let inner = self.lock()?;
        Ok(EffectGateSnapshot {
            session_fingerprint: inner.session_fingerprint,
            authority_epoch: inner.authority_epoch,
            active: matches!(inner.phase, GatePhase::Active),
            issued_operations: inner.issued_operations.len(),
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
            started_tx.send(()).ok();
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
    fn unknown_effect_outcome_consumes_operation_id_without_claiming_commit() {
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
            gate.prepare_after_admission(request(7)).err(),
            Some(EffectGateError::DuplicateOperation)
        );
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
