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
        _seal: RecoveryStateSeal,
    },
    /// The successor transition is durably committed, but activation/recovery has not yet completed.
    TransitionCommitted {
        /// Fingerprint of the exact signed ledger-key transition committed durably.
        transition_fingerprint: [u8; 32],
        _seal: RecoveryStateSeal,
    },
    /// The persistence result is ambiguous; no authority may be activated.
    OutcomeUnknown {
        /// Fingerprint of the exact transition whose persistence outcome is unknown.
        transition_fingerprint: [u8; 32],
        _seal: RecoveryStateSeal,
    },
    /// Recovery from a predecessor state while reconciling one exact transition.
    RecoveryFromOld {
        /// Fingerprint of the exact signed transition being reconciled.
        transition_fingerprint: [u8; 32],
        _seal: RecoveryStateSeal,
    },
    /// Recovery after a successor transition was already durably committed.
    RecoveryAfterCommit {
        /// Fingerprint of the exact committed transition being recovered.
        transition_fingerprint: [u8; 32],
        _seal: RecoveryStateSeal,
    },
    /// Recovery while reconciling an ambiguous persistence result.
    RecoveryAfterUnknown {
        /// Fingerprint of the exact transition being reconciled.
        transition_fingerprint: [u8; 32],
        _seal: RecoveryStateSeal,
    },
    /// The successor authority has been recovered and activated.
    SuccessorActive {
        /// Fingerprint of the exact transition that established successor authority.
        transition_fingerprint: [u8; 32],
        _seal: RecoveryStateSeal,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryStateSeal;

 
/// Events that move the authority recovery state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRecoveryEventV1 {
    /// A transition has been prepared locally.
    PrepareTransition {
        /// Fingerprint of the exact signed ledger-key transition being prepared.
        transition_fingerprint: [u8; 32],
    },
    /// Persistence definitively committed the exact transition.
    DurableCommit {
        /// Fingerprint of the exact signed ledger-key transition durably committed.
        transition_fingerprint: [u8; 32],
    },
    /// Persistence definitively did not commit the transition.
    ProvenNotPersisted {
        /// Fingerprint of the exact signed ledger-key transition proven absent.
        transition_fingerprint: [u8; 32],
    },
    /// Persistence returned an ambiguous result.
    CommitOutcomeUnknown {
        /// Fingerprint of the exact transition whose persistence outcome is unknown.
        transition_fingerprint: [u8; 32],
    },
    /// A crash/restart enters recovery for one exact transition.
    BeginRecovery {
        /// Fingerprint of the exact signed transition being recovered.
        transition_fingerprint: [u8; 32],
    },
    /// Recovery proves the successor transition is durably committed.
    RecoverSuccessor {
        /// Fingerprint of the exact transition proven durably committed.
        transition_fingerprint: [u8; 32],
    },
    /// Recovery proves the exact transition is absent.
    RecoverOld {
        /// Fingerprint of the exact signed transition proven absent.
        transition_fingerprint: [u8; 32],
    },
    /// Recovery cannot determine the durable outcome.
    RecoverOutcomeUnknown {
        /// Fingerprint of the exact transition whose outcome remains unknown.
        transition_fingerprint: [u8; 32],
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
}
impl AuthorityRecoveryStateV1 {
    /// Apply one lifecycle event and return the next state.
    pub fn apply(self, event: AuthorityRecoveryEventV1) -> Result<Self, AuthorityRecoveryError> {
        use AuthorityRecoveryEventV1::*;
        use AuthorityRecoveryStateV1::*;

        let next = match (self, event) {
            (
                OldActive,
                PrepareTransition {
                    transition_fingerprint,
                },
            ) => TransitionPending {
                transition_fingerprint: require_fingerprint(transition_fingerprint)?,
                _seal: RecoveryStateSeal,
            },
            (
                TransitionPending {
                    transition_fingerprint,
                    ..
                },
                DurableCommit {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                TransitionCommitted {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                TransitionPending {
                    transition_fingerprint,
                    ..
                },
                ProvenNotPersisted {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                OldActive
            }
            (
                TransitionPending {
                    transition_fingerprint,
                    ..
                },
                CommitOutcomeUnknown {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                OutcomeUnknown {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                TransitionCommitted {
                    transition_fingerprint,
                    ..
                },
                BeginRecovery {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                RecoveryAfterCommit {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                SuccessorActive {
                    transition_fingerprint,
                    ..
                },
                BeginRecovery {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                RecoveryAfterCommit {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                OldActive,
                BeginRecovery {
                    transition_fingerprint,
                },
            ) => RecoveryFromOld {
                transition_fingerprint: require_fingerprint(transition_fingerprint)?,
                _seal: RecoveryStateSeal,
            },
            (
                OutcomeUnknown {
                    transition_fingerprint,
                    ..
                },
                BeginRecovery {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryFromOld {
                    transition_fingerprint: state_fingerprint,
                    ..
                },
                RecoverSuccessor {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(state_fingerprint, event_fingerprint)?;
                TransitionCommitted {
                    transition_fingerprint: state_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryFromOld {
                    transition_fingerprint,
                    ..
                },
                RecoverOld {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                OldActive
            }
            (
                RecoveryAfterCommit {
                    transition_fingerprint,
                    ..
                },
                RecoverSuccessor {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                TransitionCommitted {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    ..
                },
                RecoverSuccessor {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                TransitionCommitted {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    ..
                },
                RecoverOld {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                OldActive
            }
            (
                RecoveryFromOld {
                    transition_fingerprint,
                    ..
                },
                RecoverOutcomeUnknown {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                OutcomeUnknown {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                RecoveryAfterUnknown {
                    transition_fingerprint,
                    ..
                },
                RecoverOutcomeUnknown {
                    transition_fingerprint: event_fingerprint,
                },
            ) => {
                require_matching_fingerprint(transition_fingerprint, event_fingerprint)?;
                OutcomeUnknown {
                    transition_fingerprint,
                    _seal: RecoveryStateSeal,
                }
            }
            (
                TransitionCommitted {
                    transition_fingerprint,
                    ..
                },
                ActivateSuccessor,
            ) => SuccessorActive {
                transition_fingerprint,
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

fn require_matching_fingerprint(
    state_fingerprint: [u8; 32],
    event_fingerprint: [u8; 32],
) -> Result<(), AuthorityRecoveryError> {
    require_fingerprint(state_fingerprint)?;
    require_fingerprint(event_fingerprint)?;
    if state_fingerprint != event_fingerprint {
        return Err(AuthorityRecoveryError::TransitionFingerprintMismatch);
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
            _seal: RecoveryStateSeal,
        }
    }

    fn committed(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::TransitionCommitted {
            transition_fingerprint: fingerprint,
            _seal: RecoveryStateSeal,
        }
    }

    fn unknown(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::OutcomeUnknown {
            transition_fingerprint: fingerprint,
            _seal: RecoveryStateSeal,
        }
    }

    fn recovery_from_old(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::RecoveryFromOld {
            transition_fingerprint: fingerprint,
            _seal: RecoveryStateSeal,
        }
    }

    fn recovery_after_commit(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::RecoveryAfterCommit {
            transition_fingerprint: fingerprint,
            _seal: RecoveryStateSeal,
        }
    }

    fn recovery_after_unknown(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::RecoveryAfterUnknown {
            transition_fingerprint: fingerprint,
            _seal: RecoveryStateSeal,
        }
    }

    fn successor_active(fingerprint: [u8; 32]) -> AuthorityRecoveryStateV1 {
        AuthorityRecoveryStateV1::SuccessorActive {
            transition_fingerprint: fingerprint,
            _seal: RecoveryStateSeal,
        }
    }

    #[test]
    fn happy_path_requires_durable_commit_before_activation() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::DurableCommit {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap();

        assert_eq!(state, successor_active(TRANSITION_A));
        assert!(state.successor_authoritative());
        assert_eq!(state.transition_fingerprint(), Some(TRANSITION_A));
    }

    #[test]
    fn ambiguous_commit_cannot_activate_successor() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::CommitOutcomeUnknown {
                transition_fingerprint: TRANSITION_A,
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
    fn mismatched_commit_proof_cannot_advance_transition() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap();

        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::DurableCommit {
                transition_fingerprint: TRANSITION_B,
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
                }
            ),
            Err(AuthorityRecoveryError::InvalidTransitionFingerprint)
        ));
        assert!(matches!(
            AuthorityRecoveryStateV1::OldActive.apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: [0; 32],
            }),
            Err(AuthorityRecoveryError::InvalidTransitionFingerprint)
        ));
        assert!(matches!(
            recovery_from_old(TRANSITION_A).apply(
                AuthorityRecoveryEventV1::RecoverSuccessor {
                    transition_fingerprint: [0; 32],
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
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::DurableCommit {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverSuccessor {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap();

        assert_eq!(state, successor_active(TRANSITION_A));

        let stale = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverOld {
                transition_fingerprint: TRANSITION_A,
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
            })
            .unwrap();

        assert_eq!(state, recovery_from_old(TRANSITION_A));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverOld {
                transition_fingerprint: TRANSITION_B,
            }),
            Err(AuthorityRecoveryError::TransitionFingerprintMismatch)
        ));
    }

    #[test]
    fn committed_successor_cannot_recover_to_predecessor() {
        let state = successor_active(TRANSITION_A)
            .apply(AuthorityRecoveryEventV1::BeginRecovery {
                transition_fingerprint: TRANSITION_A,
            })
            .unwrap();

        assert_eq!(state, recovery_after_commit(TRANSITION_A));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverOld {
                transition_fingerprint: TRANSITION_A,
            }),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverOutcomeUnknown {
                transition_fingerprint: TRANSITION_A,
            }),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
        assert_eq!(
            state
                .apply(AuthorityRecoveryEventV1::RecoverSuccessor {
                    transition_fingerprint: TRANSITION_A,
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
            })
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverOutcomeUnknown {
                transition_fingerprint: TRANSITION_A,
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
            })
            .unwrap();

        assert_eq!(state, recovery_after_unknown(TRANSITION_A));
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverSuccessor {
                transition_fingerprint: TRANSITION_B,
            }),
            Err(AuthorityRecoveryError::TransitionFingerprintMismatch)
        ));
    }
}
