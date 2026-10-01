// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit crash/recovery state machine for durable authority transitions.
//!
//! This module is deliberately smaller than the cryptographic proof layers. It
//! makes the lifecycle invariant executable: authenticated state is not itself
//! durable authority, an ambiguous persistence outcome cannot activate authority,
//! and a stale predecessor cannot resurrect after a successor transition commits.

use thiserror::Error;

/// Lifecycle state of an authority transition across crashes and recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRecoveryStateV1 {
    /// The predecessor authority is the active authority.
    OldActive,
    /// A successor transition has been prepared but is not durable.
    TransitionPending,
    /// The successor transition is durably committed, but activation/recovery
    /// has not yet completed.
    TransitionCommitted,
    /// The successor authority has been recovered and activated.
    SuccessorActive,
    /// The persistence result is ambiguous; no authority may be activated.
    OutcomeUnknown,
    /// Recovery from a predecessor state with no known committed transition.
    RecoveryFromOld,
    /// Recovery after a successor transition was already durably committed.
    RecoveryAfterCommit,
    /// Recovery while reconciling an ambiguous persistence result.
    RecoveryAfterUnknown,
}

/// Events that move the authority recovery state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRecoveryEventV1 {
    /// A transition has been prepared locally.
    PrepareTransition,
    /// Persistence definitively committed the exact transition.
    DurableCommit,
    /// Persistence definitively did not commit the transition.
    ProvenNotPersisted,
    /// Persistence returned an ambiguous result.
    CommitOutcomeUnknown,
    /// A crash/restart enters recovery.
    BeginRecovery,
    /// Recovery proves the successor transition is durably committed.
    RecoverSuccessor,
    /// Recovery proves the successor transition is absent.
    RecoverOld,
    /// Recovery cannot determine the durable outcome.
    RecoverOutcomeUnknown,
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
        /// Event that is invalid for the current state.
        event: AuthorityRecoveryEventV1,
    },
}

impl AuthorityRecoveryStateV1 {
    /// Apply one lifecycle event and return the next state.
    pub fn apply(
        self,
        event: AuthorityRecoveryEventV1,
    ) -> Result<Self, AuthorityRecoveryError> {
        use AuthorityRecoveryEventV1::*;
        use AuthorityRecoveryStateV1::*;

        let next = match (self, event) {
            (OldActive, PrepareTransition) => TransitionPending,
            (TransitionPending, DurableCommit) => TransitionCommitted,
            (TransitionPending, ProvenNotPersisted) => OldActive,
            (TransitionPending, CommitOutcomeUnknown) => OutcomeUnknown,
            (TransitionCommitted, BeginRecovery) => RecoveryAfterCommit,
            (SuccessorActive, BeginRecovery) => RecoveryAfterCommit,
            (OldActive, BeginRecovery) => RecoveryFromOld,
            (OutcomeUnknown, BeginRecovery) => RecoveryAfterUnknown,
            (RecoveryFromOld, RecoverSuccessor) => TransitionCommitted,
            (RecoveryFromOld, RecoverOld) => OldActive,
            (RecoveryAfterCommit, RecoverSuccessor) => TransitionCommitted,
            (RecoveryAfterUnknown, RecoverSuccessor) => TransitionCommitted,
            (RecoveryAfterUnknown, RecoverOld) => OldActive,
            (RecoveryFromOld, RecoverOutcomeUnknown) => OutcomeUnknown,
            (RecoveryAfterCommit, RecoverOutcomeUnknown) => OutcomeUnknown,
            (RecoveryAfterUnknown, RecoverOutcomeUnknown) => OutcomeUnknown,
            (TransitionCommitted, ActivateSuccessor) => SuccessorActive,
            _ => {
                return Err(AuthorityRecoveryError::InvalidTransition { state: self, event });
            }
        };
        Ok(next)
    }

    /// True only for states where successor authority is active.
    pub const fn successor_authoritative(self) -> bool {
        matches!(self, Self::SuccessorActive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_requires_durable_commit_before_activation() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::DurableCommit)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap();

        assert_eq!(state, AuthorityRecoveryStateV1::SuccessorActive);
        assert!(state.successor_authoritative());
    }

    #[test]
    fn ambiguous_commit_cannot_activate_successor() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::CommitOutcomeUnknown)
            .unwrap();

        assert_eq!(state, AuthorityRecoveryStateV1::OutcomeUnknown);
        assert!(!state.successor_authoritative());
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::ActivateSuccessor),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn crash_recovery_accepts_only_authoritative_durable_outcome() {
        let committed = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::DurableCommit)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::BeginRecovery)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverSuccessor)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap();

        assert!(committed.successor_authoritative());

        let stale = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::BeginRecovery)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverOld)
            .unwrap();

        assert_eq!(stale, AuthorityRecoveryStateV1::OldActive);
        assert!(!stale.successor_authoritative());
    }

    #[test]
    fn stale_snapshot_cannot_skip_recovery_boundary() {
        let state = AuthorityRecoveryStateV1::TransitionCommitted;
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::ActivateSuccessor),
            Ok(AuthorityRecoveryStateV1::SuccessorActive)
        ));
        assert!(matches!(
            AuthorityRecoveryStateV1::OldActive.apply(
                AuthorityRecoveryEventV1::ActivateSuccessor
            ),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn committed_successor_cannot_recover_to_predecessor() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::DurableCommit)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::ActivateSuccessor)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::BeginRecovery)
            .unwrap();

        assert_eq!(state, AuthorityRecoveryStateV1::RecoveryAfterCommit);
        assert!(matches!(
            state.apply(AuthorityRecoveryEventV1::RecoverOld),
            Err(AuthorityRecoveryError::InvalidTransition { .. })
        ));
        assert_eq!(
            state.apply(AuthorityRecoveryEventV1::RecoverSuccessor).unwrap(),
            AuthorityRecoveryStateV1::TransitionCommitted
        );
    }

    #[test]
    fn outcome_unknown_remains_non_authoritative_until_reconciled() {
        let state = AuthorityRecoveryStateV1::OldActive
            .apply(AuthorityRecoveryEventV1::PrepareTransition)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::CommitOutcomeUnknown)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::BeginRecovery)
            .unwrap()
            .apply(AuthorityRecoveryEventV1::RecoverOutcomeUnknown)
            .unwrap();

        assert_eq!(state, AuthorityRecoveryStateV1::OutcomeUnknown);
        assert!(!state.successor_authoritative());
    }
}
