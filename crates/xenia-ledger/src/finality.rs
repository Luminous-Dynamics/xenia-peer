// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash-aware finality attempt lifecycle.
//!
//! This module does not make a host input backend transactional. Instead it
//! makes the unavoidable boundary explicit: once an exact handle is consumed
//! and an external effect may have started, a crash leaves an outcome that must
//! be reconciled rather than guessed. In particular, an indeterminate attempt
//! cannot be silently retried as though no effect occurred.
//!
//! The state and receipt records are serializable audit material, not authority.
//! A production finality sink must durably journal the state transitions before
//! relying on them across process restart.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable schema for a finality-attempt record.
pub const FINALITY_ATTEMPT_SCHEMA: &str = "xenia-finality-attempt-v2";

/// Stable schema for a finality receipt.
pub const FINALITY_RECEIPT_SCHEMA: &str = "xenia-finality-receipt-v2";

/// Outcome of an exact external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityOutcomeV1 {
    /// The protected effect was confirmed to have occurred.
    Committed,
    /// The protected effect was confirmed not to have occurred.
    Denied,
    /// The external outcome cannot be established safely.
    Indeterminate,
}

/// Lifecycle state of one exact effectuation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityAttemptStateV1 {
    /// The exact act/sink pair is prepared but has not crossed the external boundary.
    Prepared,
    /// The one-use execution handle was consumed and effectuation may have started.
    EffectuationStarted,
    /// The external consequence was confirmed.
    Committed,
    /// The external consequence was confirmed absent or rejected before effectuation.
    Denied,
    /// The external outcome cannot be safely classified.
    Indeterminate,
}

/// Durable audit record for one finality attempt.
///
/// This is intentionally not an authority object. Deserializing a record never
/// creates an execution capability; it only reconstructs an audit state that a
/// finality sink must reconcile against its authoritative external state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityAttemptV1 {
    /// Stable record schema.
    pub schema: String,
    /// Application-chosen unique attempt identifier.
    pub attempt_id: [u8; 16],
    /// Exact execution-handle/native replay identity consumed for this attempt.
    pub handle_digest: [u8; 32],
    /// Durable same-action fence identity. This intentionally does not include
    /// the native authorization identifier or operation identifier.
    pub action_key_digest: [u8; 32],
    /// Exact Candidate Act digest.
    pub act_digest: [u8; 32],
    /// Exact finality-sink digest.
    pub sink_digest: [u8; 32],
    /// Current lifecycle state.
    pub state: FinalityAttemptStateV1,
}

impl FinalityAttemptV1 {
    /// Create a prepared attempt for one exact handle/act/sink identity.
    pub fn prepare(
        attempt_id: [u8; 16],
        handle_digest: [u8; 32],
        action_key_digest: [u8; 32],
        act_digest: [u8; 32],
        sink_digest: [u8; 32],
    ) -> Result<Self, FinalityAttemptError> {
        require_nonzero_16(attempt_id, FinalityAttemptError::ZeroAttemptId)?;
        require_nonzero(handle_digest, FinalityAttemptError::ZeroHandleDigest)?;
        require_nonzero(action_key_digest, FinalityAttemptError::ZeroActionKeyDigest)?;
        require_nonzero(act_digest, FinalityAttemptError::ZeroActDigest)?;
        require_nonzero(sink_digest, FinalityAttemptError::ZeroSinkDigest)?;

        Ok(Self {
            schema: FINALITY_ATTEMPT_SCHEMA.to_string(),
            attempt_id,
            handle_digest,
            action_key_digest,
            act_digest,
            sink_digest,
            state: FinalityAttemptStateV1::Prepared,
        })
    }

    /// Mark the exact attempt as crossing the last preventable boundary.
    pub fn mark_effectuation_started(&mut self) -> Result<(), FinalityAttemptError> {
        self.transition(FinalityAttemptStateV1::EffectuationStarted)
    }

    /// Record a confirmed external success.
    pub fn commit(&mut self) -> Result<FinalityReceiptV1, FinalityAttemptError> {
        self.transition(FinalityAttemptStateV1::Committed)?;
        Ok(self.receipt(FinalityOutcomeV1::Committed))
    }

    /// Record a confirmed refusal / non-effect.
    pub fn deny(&mut self) -> Result<FinalityReceiptV1, FinalityAttemptError> {
        self.transition(FinalityAttemptStateV1::Denied)?;
        Ok(self.receipt(FinalityOutcomeV1::Denied))
    }

    /// Enter the fail-closed indeterminate state after an uncertain external outcome.
    pub fn mark_indeterminate(&mut self) -> Result<FinalityReceiptV1, FinalityAttemptError> {
        self.transition(FinalityAttemptStateV1::Indeterminate)?;
        Ok(self.receipt(FinalityOutcomeV1::Indeterminate))
    }

    /// Resolve an indeterminate attempt using an authoritative external observation.
    ///
    /// A reconciliation result can close the attempt, but the attempt never
    /// returns to Prepared or EffectuationStarted; that prevents a crash
    /// recovery path from accidentally treating an unknown outcome as unused.
    pub fn reconcile(
        &mut self,
        outcome: FinalityOutcomeV1,
    ) -> Result<FinalityReceiptV1, FinalityAttemptError> {
        match (self.state, outcome) {
            (FinalityAttemptStateV1::Indeterminate, FinalityOutcomeV1::Committed) => {
                self.state = FinalityAttemptStateV1::Committed;
                Ok(self.receipt(FinalityOutcomeV1::Committed))
            }
            (FinalityAttemptStateV1::Indeterminate, FinalityOutcomeV1::Denied) => {
                self.state = FinalityAttemptStateV1::Denied;
                Ok(self.receipt(FinalityOutcomeV1::Denied))
            }
            (FinalityAttemptStateV1::Indeterminate, FinalityOutcomeV1::Indeterminate) => {
                Ok(self.receipt(FinalityOutcomeV1::Indeterminate))
            }
            _ => Err(FinalityAttemptError::InvalidTransition {
                from: self.state,
                to: outcome,
            }),
        }
    }

    /// Validate the structural identity of this audit record.
    ///
    /// Validation never grants authority; it only prevents malformed records
    /// from being mistaken for a well-formed finality attempt.
    pub fn validate(&self) -> Result<(), FinalityAttemptError> {
        if self.schema != FINALITY_ATTEMPT_SCHEMA {
            return Err(FinalityAttemptError::UnsupportedSchema);
        }
        require_nonzero_16(self.attempt_id, FinalityAttemptError::ZeroAttemptId)?;
        require_nonzero(self.handle_digest, FinalityAttemptError::ZeroHandleDigest)?;
        require_nonzero(self.action_key_digest, FinalityAttemptError::ZeroActionKeyDigest)?;
        require_nonzero(self.act_digest, FinalityAttemptError::ZeroActDigest)?;
        require_nonzero(self.sink_digest, FinalityAttemptError::ZeroSinkDigest)?;
        Ok(())
    }

    /// Return the current state.
    pub fn state(&self) -> FinalityAttemptStateV1 {
        self.state
    }

    /// Stable digest of the complete attempt identity and lifecycle state.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"xenia:finality-attempt-digest:v1\0");
        hasher.update(self.schema.as_bytes());
        hasher.update(&self.attempt_id);
        hasher.update(&self.handle_digest);
        hasher.update(&self.action_key_digest);
        hasher.update(&self.act_digest);
        hasher.update(&self.sink_digest);
        hasher.update(&[state_tag(self.state)]);
        *hasher.finalize().as_bytes()
    }

    fn transition(
        &mut self,
        next: FinalityAttemptStateV1,
    ) -> Result<(), FinalityAttemptError> {
        let valid = matches!(
            (self.state, next),
            (
                FinalityAttemptStateV1::Prepared,
                FinalityAttemptStateV1::EffectuationStarted
            ) | (
                FinalityAttemptStateV1::EffectuationStarted,
                FinalityAttemptStateV1::Committed
            ) | (
                FinalityAttemptStateV1::EffectuationStarted,
                FinalityAttemptStateV1::Denied
            ) | (
                FinalityAttemptStateV1::EffectuationStarted,
                FinalityAttemptStateV1::Indeterminate
            )
        );
        if !valid {
            return Err(FinalityAttemptError::InvalidTransition {
                from: self.state,
                to: outcome_for_state(next),
            });
        }
        self.state = next;
        Ok(())
    }

    fn receipt(&self, outcome: FinalityOutcomeV1) -> FinalityReceiptV1 {
        FinalityReceiptV1 {
            schema: FINALITY_RECEIPT_SCHEMA.to_string(),
            attempt_digest: self.digest(),
            attempt_id: self.attempt_id,
            handle_digest: self.handle_digest,
            action_key_digest: self.action_key_digest,
            act_digest: self.act_digest,
            sink_digest: self.sink_digest,
            outcome,
        }
    }
}

/// Durable description of what the finality sink actually established.
///
/// The receipt is evidence produced by the sink; it is not itself a signature
/// or proof of the external system's state unless an integrator adds one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityReceiptV1 {
    /// Stable receipt schema.
    pub schema: String,
    /// Digest of the exact attempt lifecycle record.
    pub attempt_digest: [u8; 32],
    /// Exact attempt identifier.
    pub attempt_id: [u8; 16],
    /// Exact execution-handle/native replay identity.
    pub handle_digest: [u8; 32],
    /// Durable same-action fence identity.
    pub action_key_digest: [u8; 32],
    /// Exact Candidate Act digest.
    pub act_digest: [u8; 32],
    /// Exact finality-sink digest.
    pub sink_digest: [u8; 32],
    /// Established external outcome.
    pub outcome: FinalityOutcomeV1,
}

impl FinalityReceiptV1 {
    /// Validate the structural identity of this audit receipt.
    pub fn validate(&self) -> Result<(), FinalityAttemptError> {
        if self.schema != FINALITY_RECEIPT_SCHEMA {
            return Err(FinalityAttemptError::UnsupportedReceiptSchema);
        }
        require_nonzero_16(self.attempt_id, FinalityAttemptError::ZeroAttemptId)?;
        require_nonzero(self.attempt_digest, FinalityAttemptError::ZeroAttemptDigest)?;
        require_nonzero(self.handle_digest, FinalityAttemptError::ZeroHandleDigest)?;
        require_nonzero(self.action_key_digest, FinalityAttemptError::ZeroActionKeyDigest)?;
        require_nonzero(self.act_digest, FinalityAttemptError::ZeroActDigest)?;
        require_nonzero(self.sink_digest, FinalityAttemptError::ZeroSinkDigest)?;
        Ok(())
    }

    /// Stable digest for external archival and higher-level evidence binding.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"xenia:finality-receipt-digest:v1\0");
        hasher.update(self.schema.as_bytes());
        hasher.update(&self.attempt_digest);
        hasher.update(&self.attempt_id);
        hasher.update(&self.handle_digest);
        hasher.update(&self.action_key_digest);
        hasher.update(&self.act_digest);
        hasher.update(&self.sink_digest);
        hasher.update(&[self.outcome as u8]);
        *hasher.finalize().as_bytes()
    }

    /// True when the receipt is safe to archive as a terminal known outcome.
    pub fn is_terminal_known(&self) -> bool {
        matches!(
            self.outcome,
            FinalityOutcomeV1::Committed | FinalityOutcomeV1::Denied
        )
    }
}

/// Construction and transition failures for finality attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FinalityAttemptError {
    /// Attempt id was all zeroes.
    #[error("finality attempt id must be nonzero")]
    ZeroAttemptId,
    /// Execution-handle digest was all zeroes.
    #[error("finality handle digest must be nonzero")]
    ZeroHandleDigest,
    /// Durable same-action fence identity was all zeroes.
    #[error("finality action-key digest must be nonzero")]
    ZeroActionKeyDigest,
    /// Attempt digest in a receipt was all zeroes.
    #[error("finality attempt digest must be nonzero")]
    ZeroAttemptDigest,
    /// Act digest was all zeroes.
    #[error("finality act digest must be nonzero")]
    ZeroActDigest,
    /// Sink digest was all zeroes.
    #[error("finality sink digest must be nonzero")]
    ZeroSinkDigest,
    /// The attempt schema is not recognized.
    #[error("unsupported finality attempt schema")]
    UnsupportedSchema,
    /// The receipt schema is not recognized.
    #[error("unsupported finality receipt schema")]
    UnsupportedReceiptSchema,
    /// The requested lifecycle transition is impossible.
    #[error("invalid finality transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Prior lifecycle state.
        from: FinalityAttemptStateV1,
        /// Requested outcome represented by the destination.
        to: FinalityOutcomeV1,
    },
}

fn state_tag(state: FinalityAttemptStateV1) -> u8 {
    match state {
        FinalityAttemptStateV1::Prepared => 0,
        FinalityAttemptStateV1::EffectuationStarted => 1,
        FinalityAttemptStateV1::Committed => 2,
        FinalityAttemptStateV1::Denied => 3,
        FinalityAttemptStateV1::Indeterminate => 4,
    }
}

fn require_nonzero(
    value: [u8; 32],
    error: FinalityAttemptError,
) -> Result<(), FinalityAttemptError> {
    if value == [0; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn require_nonzero_16(
    value: [u8; 16],
    error: FinalityAttemptError,
) -> Result<(), FinalityAttemptError> {
    if value == [0; 16] {
        Err(error)
    } else {
        Ok(())
    }
}

fn outcome_for_state(state: FinalityAttemptStateV1) -> FinalityOutcomeV1 {
    match state {
        FinalityAttemptStateV1::Committed => FinalityOutcomeV1::Committed,
        FinalityAttemptStateV1::Denied => FinalityOutcomeV1::Denied,
        FinalityAttemptStateV1::Indeterminate => FinalityOutcomeV1::Indeterminate,
        FinalityAttemptStateV1::Prepared | FinalityAttemptStateV1::EffectuationStarted => {
            FinalityOutcomeV1::Indeterminate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> FinalityAttemptV1 {
        FinalityAttemptV1::prepare([1; 16], [2; 32], [9; 32], [3; 32], [4; 32]).unwrap()
    }

    #[test]
    fn prepared_attempt_requires_exact_nonzero_identity() {
        assert!(FinalityAttemptV1::prepare([0; 16], [2; 32], [9; 32], [3; 32], [4; 32]).is_err());
        assert!(FinalityAttemptV1::prepare([1; 16], [0; 32], [9; 32], [3; 32], [4; 32]).is_err());
        assert!(FinalityAttemptV1::prepare([1; 16], [2; 32], [0; 32], [3; 32], [4; 32]).is_err());
        assert!(FinalityAttemptV1::prepare([1; 16], [2; 32], [9; 32], [3; 32], [0; 32]).is_err());
    }

    #[test]
    fn generated_attempts_and_receipts_validate() {
        let mut attempt = attempt();
        attempt.validate().unwrap();
        let mut malformed_action = attempt.clone();
        malformed_action.action_key_digest = [0; 32];
        assert!(matches!(
            malformed_action.validate(),
            Err(FinalityAttemptError::ZeroActionKeyDigest)
        ));


        attempt.mark_effectuation_started().unwrap();
        let receipt = attempt.commit().unwrap();
        receipt.validate().unwrap();

        let mut malformed = attempt.clone();
        malformed.schema = "wrong".into();
        assert!(matches!(
            malformed.validate(),
            Err(FinalityAttemptError::UnsupportedSchema)
        ));

        let mut malformed_receipt = receipt;
        malformed_receipt.schema = "wrong".into();
        assert!(matches!(
            malformed_receipt.validate(),
            Err(FinalityAttemptError::UnsupportedReceiptSchema)
        ));
    }

    #[test]
    fn normal_success_requires_crossing_effectuation_boundary() {
        let mut attempt = attempt();
        assert!(attempt.commit().is_err());
        attempt.mark_effectuation_started().unwrap();
        let receipt = attempt.commit().unwrap();
        assert_eq!(attempt.state(), FinalityAttemptStateV1::Committed);
        assert_eq!(receipt.outcome, FinalityOutcomeV1::Committed);
        assert!(receipt.is_terminal_known());
    }

    #[test]
    fn uncertain_effect_cannot_be_silently_retried() {
        let mut attempt = attempt();
        attempt.mark_effectuation_started().unwrap();
        let receipt = attempt.mark_indeterminate().unwrap();
        assert_eq!(receipt.outcome, FinalityOutcomeV1::Indeterminate);
        assert!(!receipt.is_terminal_known());

        assert!(attempt.mark_effectuation_started().is_err());
        assert!(attempt.commit().is_err());
        assert!(attempt.deny().is_err());

        let reconciled = attempt.reconcile(FinalityOutcomeV1::Committed).unwrap();
        assert_eq!(reconciled.outcome, FinalityOutcomeV1::Committed);
        assert_eq!(attempt.state(), FinalityAttemptStateV1::Committed);
        assert!(attempt.reconcile(FinalityOutcomeV1::Committed).is_err());
    }

    #[test]
    fn indeterminate_reconciliation_can_resolve_absence_without_reexecution() {
        let mut attempt = attempt();
        attempt.mark_effectuation_started().unwrap();
        attempt.mark_indeterminate().unwrap();
        let receipt = attempt.reconcile(FinalityOutcomeV1::Denied).unwrap();
        assert_eq!(receipt.outcome, FinalityOutcomeV1::Denied);
        assert_eq!(attempt.state(), FinalityAttemptStateV1::Denied);
    }

    #[test]
    fn indeterminate_attempt_round_trips_as_non_replayable_audit_state() {
        let mut attempt = attempt();
        attempt.mark_effectuation_started().unwrap();
        attempt.mark_indeterminate().unwrap();

        let encoded = serde_json::to_vec(&attempt).unwrap();
        let restored: FinalityAttemptV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.state(), FinalityAttemptStateV1::Indeterminate);
        assert!(restored.mark_effectuation_started().is_err());
        assert!(restored.commit().is_err());
    }

    #[test]
    fn terminal_attempts_cannot_reopen() {
        let mut attempt = attempt();
        attempt.mark_effectuation_started().unwrap();
        attempt.deny().unwrap();
        assert!(attempt.mark_effectuation_started().is_err());
        assert!(attempt.commit().is_err());
        assert!(attempt.mark_indeterminate().is_err());
    }

    #[test]
    fn digest_changes_with_lifecycle_state() {
        let mut attempt = attempt();
        let prepared = attempt.digest();
        attempt.mark_effectuation_started().unwrap();
        assert_ne!(prepared, attempt.digest());
        attempt.mark_indeterminate().unwrap();
        assert_ne!(prepared, attempt.digest());
    }
}
