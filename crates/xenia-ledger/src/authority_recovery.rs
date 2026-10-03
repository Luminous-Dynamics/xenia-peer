// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit crash/recovery state machine for durable authority transitions.
//!
//! This module is deliberately smaller than the cryptographic proof layers. It
//! makes the lifecycle invariant executable: authenticated state is not itself
//! durable authority, an ambiguous persistence outcome cannot activate authority,
//! and a stale predecessor cannot resurrect after a successor transition commits.
//!
//! This is a pure lifecycle reducer, not a persistence verifier. Callers must
//! emit `DurableCommit` or a `Recover*` event only after the authoritative
//! persistence adapter has verified the exact transition claim. The event value
//! itself is not cryptographic evidence of persistence.

use thiserror::Error;

/// Lifecycle state of an authority transition across crashes and recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRecoveryStateV1 {
    // All non-OldActive variants carry this private seal so callers cannot
    // fabricate a lifecycle state that claims an already-verified transition.

    /// The predecessor authority is the active authority.
    OldActive,
    /// A successor transition has been prepared but is not durable.
    TransitionPending {
        /// Fingerprint of the exact signed ledger-key transition being prepared.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        /// Exact durable-ledger frontier expected for this transition.
        durable_frontier_digest: [u8; 32],
        _seal: RecoveryStateSeal,
    },
    /// The successor transition is durably committed, but activation/recovery has not yet completed.
    TransitionCommitted {
        /// Fingerprint of the exact signed ledger-key transition committed durably.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        _seal: RecoveryStateSeal,
    },
    /// The persistence result is ambiguous; no authority may be activated.
    OutcomeUnknown {
        /// Fingerprint of the exact transition whose persistence outcome is unknown.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        _seal: RecoveryStateSeal,
    },
    /// Recovery from a predecessor state while reconciling one exact transition.
    RecoveryFromOld {
        /// Fingerprint of the exact signed transition being reconciled.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        _seal: RecoveryStateSeal,
    },
    /// Recovery after a successor transition was already durably committed.
    RecoveryAfterCommit {
        /// Fingerprint of the exact committed transition being recovered.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        _seal: RecoveryStateSeal,
    },
    /// Recovery while reconciling an ambiguous persistence result.
    RecoveryAfterUnknown {
        /// Fingerprint of the exact transition being reconciled.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        _seal: RecoveryStateSeal,
    },
    /// The successor authority has been recovered and activated.
    SuccessorActive {
        /// Fingerprint of the exact transition that established successor authority.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        _seal: RecoveryStateSeal,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Private construction seal for transition-bearing recovery states.
struct RecoveryStateSeal;

 
/// Events that move the authority recovery state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRecoveryEventV1 {
    /// A transition has been prepared locally.
    PrepareTransition {
        /// Fingerprint of the exact signed ledger-key transition being prepared.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
        /// Exact durable-ledger frontier expected for this transition.
        durable_frontier_digest: [u8; 32],
    },
    /// Persistence definitively committed the exact transition.
    DurableCommit {
        /// Fingerprint of the exact signed ledger-key transition durably committed.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
    },
    /// Persistence definitively did not commit the transition.
    ProvenNotPersisted {
        /// Fingerprint of the exact signed ledger-key transition proven absent.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
    },
    /// Persistence returned an ambiguous result.
    CommitOutcomeUnknown {
        /// Fingerprint of the exact transition whose persistence outcome is unknown.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
    },
    /// A crash/restart enters recovery for one exact transition.
    BeginRecovery {
        /// Fingerprint of the exact signed transition being recovered.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
    },
    /// Recovery proves the successor transition is durably committed.
    RecoverSuccessor {
        /// Fingerprint of the exact transition proven durably committed.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
    },
    /// Recovery proves the exact transition is absent.
    RecoverOld {
        /// Fingerprint of the exact signed transition proven absent.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
    },
    /// Recovery cannot determine the durable outcome.
    RecoverOutcomeUnknown {
        /// Fingerprint of the exact transition whose outcome remains unknown.
        transition_fingerprint: [u8; 32],
        /// Successor authority epoch bound to this exact transition.
        authority_epoch: u64,
    },
    /// The already-recovered successor is activated.
    ActivateSuccessor,
}
 
/// State-machine violations are fail-closed: an invalid event never produces
/// an authority-bearing successor state.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRecoveryError {
    /// The event is not valid from the current lifecycle state.
    #[error("invalid authority recovery transition from {state:?} via {event:?}")]
    InvalidTransition {
        /// State from which the rejected event was attempted.
        state: AuthorityRecoveryStateV1,
        /// Event that was rejected.
        event: AuthorityRecoveryEventV1,
    },
    /// A transition-bearing state or event supplied an empty fingerprint.
    #[error("authority recovery transition fingerprint must be nonzero")]
    InvalidTransitionFingerprint,
    /// A recovery event named a different exact transition than the current state.
    #[error("authority recovery transition fingerprint does not match current state")]
    TransitionFingerprintMismatch,
    /// A recovery event named a different successor authority epoch than the current state.
    #[error("authority recovery authority epoch does not match current state")]
    AuthorityEpochMismatch,
    /// A recovery state or event used an empty durable-ledger frontier digest.
    #[error("authority recovery durable frontier digest must be nonzero")]
    InvalidDurableFrontierDigest,
    /// A recovery event named a different durable-ledger frontier than the current state.
    #[error("authority recovery durable frontier does not match current state")]
    DurableFrontierMismatch,
}
impl AuthorityRecoveryStateV1 {
    /// Prepare one exact authority transition.
    ///
    /// Preparation carries no successor authority and may safely be requested by
    /// untrusted orchestration code.
    pub fn prepare_transition(
        self,
        transition_fingerprint: [u8; 32],
        authority_epoch: u64,
        durable_frontier_digest: [u8; 32],
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::PrepareTransition {
            transition_fingerprint,
            authority_epoch,
            durable_frontier_digest,
        })
    }

    /// Record that one exact transition was proven absent from durable storage.
    pub fn proven_not_persisted(
        self,
        transition_fingerprint: [u8; 32],
        authority_epoch: u64,
        durable_frontier_digest: [u8; 32],
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::ProvenNotPersisted {
            transition_fingerprint,
            authority_epoch,
            durable_frontier_digest,
        })
    }

    /// Record that persistence of one exact transition remains ambiguous.
    pub fn commit_outcome_unknown(
        self,
        transition_fingerprint: [u8; 32],
        authority_epoch: u64,
        durable_frontier_digest: [u8; 32],
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::CommitOutcomeUnknown {
            transition_fingerprint,
            authority_epoch,
            durable_frontier_digest,
        })
    }

    /// Enter recovery for one exact transition.
    pub fn begin_recovery(
        self,
        transition_fingerprint: [u8; 32],
        authority_epoch: u64,
        durable_frontier_digest: [u8; 32],
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::BeginRecovery {
            transition_fingerprint,
            authority_epoch,
            durable_frontier_digest,
        })
    }

    /// Record that recovery proved one exact transition absent.
    pub fn recover_old(
        self,
        transition_fingerprint: [u8; 32],
        authority_epoch: u64,
        durable_frontier_digest: [u8; 32],
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::RecoverOld {
            transition_fingerprint,
            authority_epoch,
            durable_frontier_digest,
        })
    }

    /// Record that recovery still cannot determine the durable outcome.
    pub fn recover_outcome_unknown(
        self,
        transition_fingerprint: [u8; 32],
        authority_epoch: u64,
        durable_frontier_digest: [u8; 32],
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::RecoverOutcomeUnknown {
            transition_fingerprint,
            authority_epoch,
            durable_frontier_digest,
        })
    }

    /// Commit one exact transition only with an opaque durable-authority proof.
    ///
    /// The proof is minted only after the authoritative persistence boundary accepts
    /// the corresponding transition. External callers therefore cannot advance a
    /// pending state by constructing a look-alike durable-commit event.
    pub fn commit_durable(
        self,
        durable_authority: &crate::DurableAuthorityEpochV1,
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::DurableCommit {
            transition_fingerprint: durable_authority.key_transition_fingerprint(),
            authority_epoch: durable_authority.authority_epoch(),
            durable_frontier_digest: durable_authority.durable_frontier_digest(),
        })
    }

    /// Recover one exact successor only with an opaque durable-authority proof.
    pub fn recover_successor(
        self,
        durable_authority: &crate::DurableAuthorityEpochV1,
    ) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::RecoverSuccessor {
            transition_fingerprint: durable_authority.key_transition_fingerprint(),
            authority_epoch: durable_authority.authority_epoch(),
            durable_frontier_digest: durable_authority.durable_frontier_digest(),
        })
    }

    /// Activate a successor whose exact transition has already been durably committed.
    pub fn activate_successor(self) -> Result<Self, AuthorityRecoveryError> {
        self.apply(AuthorityRecoveryEventV1::ActivateSuccessor)
    }

    /// Apply one lifecycle event and return the next state.
    ///
    /// This reducer is crate-private so authority-bearing transitions cannot be
    /// advanced externally with an event that only claims durable persistence.
    fn apply(self, event: AuthorityRecoveryEventV1) -> Result<Self, AuthorityRecoveryError> {
        use AuthorityRecoveryEventV1::*;
        use AuthorityRecoveryStateV1::*;

        let next = match (self, event) {
            (
                OldActive,
                PrepareTransition {
                    transition_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => TransitionPending {
                transition_fingerprint: require_fingerprint(transition_fingerprint)?,
                authority_epoch: event_authority_epoch,
                durable_frontier_digest: require_digest(event_frontier_digest)?,
                _seal: RecoveryStateSeal,
            },
            (
                TransitionPending {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                DurableCommit {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                TransitionCommitted {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                TransitionPending {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                ProvenNotPersisted {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                OldActive
            }
            (
                TransitionPending {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                CommitOutcomeUnknown {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                OutcomeUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                TransitionCommitted {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                BeginRecovery {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                RecoveryAfterCommit {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                SuccessorActive {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                BeginRecovery {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                RecoveryAfterCommit {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                OldActive,
                BeginRecovery {
                    transition_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => RecoveryFromOld {
                transition_fingerprint: require_fingerprint(transition_fingerprint)?,
                authority_epoch: event_authority_epoch,
                durable_frontier_digest: require_digest(event_frontier_digest)?,
                _seal: RecoveryStateSeal,
            },
            (
                OutcomeUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                BeginRecovery {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryFromOld {
                    transition_fingerprint: state_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                RecoverSuccessor {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    state_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                TransitionCommitted {
                    transition_fingerprint: state_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryFromOld {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                RecoverOld {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                OldActive
            }
            (
                RecoveryAfterCommit {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                RecoverSuccessor {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                TransitionCommitted {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                RecoverSuccessor {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                TransitionCommitted {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                RecoverOld {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                OldActive
            }
            (
                RecoveryFromOld {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                RecoverOutcomeUnknown {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                OutcomeUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                RecoverOutcomeUnknown {
                    transition_fingerprint: event_fingerprint,
                    authority_epoch: event_authority_epoch,
                    durable_frontier_digest: event_frontier_digest,
                },
            ) => {
                require_matching_identity(
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    event_fingerprint,
                    event_authority_epoch,
                    event_frontier_digest,
                )?;
                OutcomeUnknown {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                TransitionCommitted {
                    transition_fingerprint,
                    authority_epoch,
                    durable_frontier_digest,
                    ..
                },
                ActivateSuccessor,
            ) => SuccessorActive {
                transition_fingerprint,
                authority_epoch,
                durable_frontier_digest,
                _seal: RecoveryStateSeal,
            },
            _ => {
                return Err(AuthorityRecoveryError::InvalidTransition { state: self, event });
            }
        };
        Ok(next)
    }

    /// True only for states where successor authority is active.
    pub const fn successor_authoritative(self) -> bool {
        matches!(self, Self::SuccessorActive { .. })
    }

    /// Return the exact successor authority epoch attached to this state.
    pub const fn authority_epoch(self) -> Option<u64> {
        match self {
            Self::OldActive => None,
            Self::TransitionPending { authority_epoch, .. }
            | Self::TransitionCommitted { authority_epoch, .. }
            | Self::OutcomeUnknown { authority_epoch, .. }
            | Self::RecoveryFromOld { authority_epoch, .. }
            | Self::RecoveryAfterCommit { authority_epoch, .. }
            | Self::RecoveryAfterUnknown { authority_epoch, .. }
            | Self::SuccessorActive { authority_epoch, .. } => Some(authority_epoch),
        }
    }

    /// Return the exact durable-ledger frontier digest attached to this state.
    pub const fn durable_frontier_digest(self) -> Option<[u8; 32]> {
        match self {
            Self::OldActive => None,
            Self::TransitionPending { durable_frontier_digest, .. }
            | Self::TransitionCommitted { durable_frontier_digest, .. }
            | Self::OutcomeUnknown { durable_frontier_digest, .. }
            | Self::RecoveryFromOld { durable_frontier_digest, .. }
            | Self::RecoveryAfterCommit { durable_frontier_digest, .. }
            | Self::RecoveryAfterUnknown { durable_frontier_digest, .. }
            | Self::SuccessorActive { durable_frontier_digest, .. } => Some(durable_frontier_digest),
        }
    }

    /// Return the exact key-transition fingerprint attached to this state.
    pub const fn transition_fingerprint(self) -> Option<[u8; 32]> {
        match self {
            Self::OldActive => None,
            Self::TransitionPending {
                transition_fingerprint,
                ..
            }
            | Self::TransitionCommitted {
                transition_fingerprint,
                ..
            }
            | Self::OutcomeUnknown {
                transition_fingerprint,
                ..
            }
            | Self::RecoveryFromOld {
                transition_fingerprint,
                ..
            }
            | Self::RecoveryAfterCommit {
                transition_fingerprint,
                ..
            }
            | Self::RecoveryAfterUnknown {
                transition_fingerprint,
                ..
            }
            | Self::SuccessorActive {
                transition_fingerprint,
                ..
            } => Some(transition_fingerprint),
        }
    }
}

fn require_fingerprint(fingerprint: [u8; 32]) -> Result<[u8; 32], AuthorityRecoveryError> {
    if fingerprint == [0u8; 32] {
        return Err(AuthorityRecoveryError::InvalidTransitionFingerprint);
    }
    Ok(fingerprint)
}

fn require_digest(digest: [u8; 32]) -> Result<[u8; 32], AuthorityRecoveryError> {
    if digest == [0u8; 32] {
        return Err(AuthorityRecoveryError::InvalidDurableFrontierDigest);
    }
    Ok(digest)
}

fn require_matching_identity(
    state_fingerprint: [u8; 32],
    state_authority_epoch: u64,
    state_frontier_digest: [u8; 32],
    event_fingerprint: [u8; 32],
    event_authority_epoch: u64,
    event_frontier_digest: [u8; 32],
) -> Result<(), AuthorityRecoveryError> {
    require_fingerprint(state_fingerprint)?;
    require_fingerprint(event_fingerprint)?;
    require_digest(state_frontier_digest)?;
    require_digest(event_frontier_digest)?;
    if state_fingerprint != event_fingerprint {
        return Err(AuthorityRecoveryError::TransitionFingerprintMismatch);
    }
    if state_authority_epoch != event_authority_epoch {
        return Err(AuthorityRecoveryError::AuthorityEpochMismatch);
    }
    if state_frontier_digest != event_frontier_digest {
        return Err(AuthorityRecoveryError::DurableFrontierMismatch);
    }
    Ok(())
}
 
#[cfg(test)]
mod tests {
    use super::*;

    const TRANSITION_A: [u8; 32] = [0xA1; 32];
    const TRANSITION_B: [u8; 32] = [0xB2; 32];

    fn pending(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::TransitionPending {
            transition_fingerprint: fingerprint,
            authority_epoch: 8,
            durable_frontier_digest: [0xF1; 32],
            _seal: RecoveryStateSeal,
        }
    }

    fn committed(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::TransitionCommitted {
            transition_fingerprint: fingerprint,
            authority_epoch: 8,
            durable_frontier_digest: [0xF1; 32],
            _seal: RecoveryStateSeal,
        }
    }

    fn unknown(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::OutcomeUnknown {
            transition_fingerprint: fingerprint,
            authority_epoch: 8,
            durable_frontier_digest: [0xF1; 32],
            _seal: RecoveryStateSeal,
        }
    }

    fn recovery_from_old(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::RecoveryFromOld {
            transition_fingerprint: fingerprint,
            authority_epoch: 8,
            durable_frontier_digest: [0xF1; 32],
            _seal: RecoveryStateSeal,
        }
    }

    fn recovery_after_commit(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::RecoveryAfterCommit {
            transition_fingerprint: fingerprint,
            authority_epoch: 8,
            durable_frontier_digest: [0xF1; 32],
            _seal: RecoveryStateSeal,
        }
    }

    fn recovery_after_unknown(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::RecoveryAfterUnknown {
            transition_fingerprint: fingerprint,
            authority_epoch: 8,
            durable_frontier_digest: [0xF1; 32],
            _seal: RecoveryStateSeal,
        }
    }

    fn successor_active(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::SuccessorActive {
            transition_fingerprint: fingerprint,
            authority_epoch: 8,
            durable_frontier_digest: [0xF1; 32],
            _seal: RecoveryStateSeal,
        }
    }

    #[test]
    fn happy_path_requires_durable_commit_before_activation() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::DurableCommit {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap();

        assert_eq!(state, successor_active(TRANSITION_A));
        assert!(state.successor_authoritative());
        assert_eq!(state.transition_fingerprint(), Some(TRANSITION_A));
        assert_eq!(state.authority_epoch(), Some(8));
    }

    #[test]
    fn ambiguous_commit_cannot_activate_successor() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::CommitOutcomeUnknown {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap();

        assert_eq!(state, unknown(TRANSITION_A));
        assert!(!state.successor_authoritative());
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::ActivateSuccessor),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn same_key_transition_fingerprint_with_different_epoch_is_rejected() {
        let state = pending(TRANSITION_A);
        let result = state.apply(AuthorityRecoveryEventV1::DurableCommit {
            transition_fingerprint: TRANSITION_A,
            authority_epoch: 9,
        });

        assert_eq!(result, Err(AuthorityRecoveryError::AuthorityEpochMismatch));
        assert_eq!(state, pending(TRANSITION_A));
    }

    #[test]
    fn zero_frontier_digest_cannot_create_recovery_authority() {
        let result = AuthorityRecoveryStateV1::OldActive.apply(
            AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0; 32],
            },
        );

        assert_eq!(
            result,
            Err(AuthorityRecoveryError::InvalidDurableFrontierDigest)
        );
    }

    #[test]
    fn same_transition_and_epoch_with_different_frontier_is_rejected() {
        let state = pending(TRANSITION_A);
        let result = state.apply(AuthorityRecoveryEventV1::DurableCommit {
            transition_fingerprint: TRANSITION_A,
            authority_epoch: 8,
            durable_frontier_digest: [0xF2; 32],
        });

        assert_eq!(
            result,
            Err(AuthorityRecoveryError::DurableFrontierMismatch)
        );
        assert_eq!(state, pending(TRANSITION_A));
    }

    #[test]
    fn mismatched_commit_proof_cannot_advance_transition() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap();

        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::DurableCommit {
                transition_fingerprint: TRANSITION_B,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            }),
            Err(AuthorityRecoveryError::TransitionFingerprintMismatch)
        ));
        assert_eq!(state, pending(TRANSITION_A));
    }

    #[test]
    fn zero_fingerprint_can_never_create_transition_authority() {
        assert!(matches!(
            AuthorityRecoveryStateV1::OldActive.apply(
                AuthorityRecoveryEventV1::PrepareTransition {
                    transition_fingerprint: [0; 32],
                    authority_epoch: 8,
                    durable_frontier_digest: [0xF1; 32],
                    }
            ),
            Err(AuthorityRecoveryError::InvalidTransitionFingerprint)
        ));
        assert!(matches!(
            AuthorityRecoveryStateV1::OldActive.apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: [0; 32],
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            }),
            Err(AuthorityRecoveryError::InvalidTransitionFingerprint)
        ));
        assert!(matches!(
            recovery_from_old(TRANSITION_A).apply(
                AuthorityRecoveryEventV1::RecoverSuccessor {
                    transition_fingerprint: [0; 32],
                    authority_epoch: 8,
                    durable_frontier_digest: [0xF1; 32],
                    }
            ),
            Err(AuthorityRecoveryError::InvalidTransitionFingerprint)
        ));
    }

    #[test]
    fn crash_recovery_accepts_only_matching_durable_outcome() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::DurableCommit {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverSuccessor {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap();

        assert_eq!(state, successor_active(TRANSITION_A));

        let stale = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverOld {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap();

        assert_eq!(stale, AuthorityRecoveryStateV1::OldActive);
        assert!(!stale.successor_authoritative());
        assert_eq!(stale.transition_fingerprint(), None);
    }

    #[test]
    fn mismatched_recovery_entry_cannot_cross_transition_boundary() {
        let state = committed(TRANSITION_A);
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_B,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            }),
            Err(AuthorityRecoveryError::TransitionFingerprintMismatch)
        ));
    }

    #[test]
    fn stale_snapshot_cannot_skip_recovery_boundary() {
        let state = committed(TRANSITION_A);
        assert_eq!(
            state
                .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
                .unwrap(),
            successor_active(TRANSITION_A)
        );
        assert!(matches!(
            AuthorityRecoveryStateV1::OldActive
                .apply(AuthorityRecoveryEventV1::ActivateSuccessor),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn recover_old_cannot_substitute_a_different_transition() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap();

        assert_eq!(state, recovery_from_old(TRANSITION_A));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverOld {
                transition_fingerprint: TRANSITION_B,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            }),
            Err(AuthorityRecoveryError::TransitionFingerprintMismatch)
        ));
    }

    #[test]
    fn committed_successor_cannot_recover_to_predecessor() {
        let state = successor_active(TRANSITION_A)
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap();

        assert_eq!(state, recovery_after_commit(TRANSITION_A));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverOld {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            }),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverOutcomeUnknown {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            }),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
        assert_eq!(
            state
                .apply(AuthorityRecoveryEventV1::RecoverSuccessor {
                    transition_fingerprint: TRANSITION_A,
                    authority_epoch: 8,
                    durable_frontier_digest: [0xF1; 32],
                    })
                .unwrap(),
            committed(TRANSITION_A)
        );
    }

    #[test]
    fn outcome_unknown_remains_non_authoritative_until_reconciled() {
        let state = unknown(TRANSITION_A)
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverOutcomeUnknown {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap();

        assert_eq!(state, unknown(TRANSITION_A));
        assert!(!state.successor_authoritative());
        assert_eq!(state.transition_fingerprint(), Some(TRANSITION_A));
    }

    #[test]
    fn unknown_recovery_cannot_substitute_a_different_transition() {
        let state = unknown(TRANSITION_A)
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            })
            .unwrap();

        assert_eq!(state, recovery_after_unknown(TRANSITION_A));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverSuccessor {
                transition_fingerprint: TRANSITION_B,
                authority_epoch: 8,
                durable_frontier_digest: [0xF1; 32],
            }),
            Err(AuthorityRecoveryError::TransitionFingerprintMismatch)
        ));
    }
}
