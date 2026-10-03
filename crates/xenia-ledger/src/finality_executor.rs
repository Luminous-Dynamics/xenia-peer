// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable finality executor for one exact execution handle.
//!
//! The executor serializes the critical lifecycle in one owner:
//! verify exact act/sink/current state, durably reserve the handle, cross the
//! external effect boundary, and durably record the closed or indeterminate
//! outcome. A crash after reservation but before a terminal outcome leaves
//! EffectuationStarted in the journal, which is explicitly a reconciliation
//! state rather than permission to retry.

use crate::{
    ExactExecutionConsumptionError, ExactExecutionHandleV1, FinalityAttemptError,
    FinalityAttemptV1, FinalityAttemptError, FinalityJournalError, FinalityJournalV1,
    FinalityOutcomeV1, FinalityReceiptV1,
};

/// Coordinates one exact execution handle with the durable finality journal.
///
/// The journal must have one logical writer. This type provides the sequencing
/// invariant but cannot provide cross-process file locking by itself.
pub struct FinalityExecutorV1<'a> {
    journal: &'a mut FinalityJournalV1,
}

impl<'a> FinalityExecutorV1<'a> {
    /// Create a durable finality executor over an already-open journal.
    pub fn new(journal: &'a mut FinalityJournalV1) -> Self {
        Self { journal }
    }

    /// Verify, durably reserve, effectuate, and record one exact operation.
    ///
    /// The effect closure is called only after the exact execution handle has
    /// been durably reserved. Its returned outcome must be an evidence-backed
    /// classification:
    /// - Committed: the external effect is confirmed.
    /// - Denied: the external system is known not to have effected the act.
    /// - Indeterminate: the external outcome cannot safely be established.
    ///
    /// In particular, an ordinary backend error should only map to Denied when
    /// the backend contract proves that the protected effect did not start.
    /// Otherwise the caller should return Indeterminate.
    pub fn execute(
        &mut self,
        handle: &ExactExecutionHandleV1,
        now_unix_s: u64,
        actual_act_digest: [u8; 32],
        actual_sink_digest: [u8; 32],
        current_protected_state_digest: [u8; 32],
        attempt_id: [u8; 16],
        effect: impl FnOnce() -> FinalityOutcomeV1,
    ) -> Result<FinalityReceiptV1, FinalityExecutorError> {
        handle.validate_current(
            now_unix_s,
            actual_act_digest,
            actual_sink_digest,
            current_protected_state_digest,
        )?;

        if attempt_id == [0; 16] {
            return Err(FinalityExecutorError::ZeroAttemptId);
        }

        let mut attempt = crate::FinalityAttemptV1::prepare(
            attempt_id,
            handle.digest(),
            actual_act_digest,
            actual_sink_digest,
        )?;

        self.journal.append_attempt(&attempt)?;
        attempt.mark_effectuation_started()?;
        self.journal.append_attempt(&attempt)?;

        let outcome = effect();

        let receipt = match outcome {
            FinalityOutcomeV1::Committed => {
                attempt.commit()?
            }
            FinalityOutcomeV1::Denied => {
                attempt.deny()?
            }
            FinalityOutcomeV1::Indeterminate => {
                attempt.mark_indeterminate()?
            }
        };

        self.journal.append_attempt(&attempt)?;
        self.journal.append_receipt(&receipt)?;
        Ok(receipt)
    }

    /// True when the journal contains an attempt that requires authoritative reconciliation.
    pub fn requires_reconciliation(
        &self,
        attempt_id: [u8; 16],
    ) -> bool {
        matches!(
            self.journal.latest_attempt(attempt_id).map(FinalityAttemptV1::state),
            Some(FinalityAttemptStateV1::EffectuationStarted)
                | Some(FinalityAttemptStateV1::Indeterminate)
        )
    }

    /// Get the latest durable attempt for one attempt identifier.
    pub fn latest_attempt(&self, attempt_id: [u8; 16]) -> Option<&crate::FinalityAttemptV1> {
        self.journal.latest_attempt(attempt_id)
    }
}

/// Errors raised while executing one exact finality attempt.\n#[derive(Debug, thiserror::Error)]
pub enum FinalityExecutorError {
    /// The exact handle did not match the actual consequence request.
    #[error("execution handle validation failed: {0}")]
    Handle(#[from] ExactExecutionConsumptionError),
    /// The attempt identifier was empty.
    #[error("finality executor attempt id must be nonzero")]
    ZeroAttemptId,
    /// Finality attempt lifecycle construction failed.
    #[error("finality attempt lifecycle failed: {0}")]
    Attempt(#[from] FinalityAttemptError),
    /// Durable finality journaling failed.
    #[error("durable finality journal failed: {0}")]
    Journal(#[from] FinalityJournalError),
    /// The durable attempt schema must remain the current execution schema.
    #[error("unsupported finality attempt schema: {0}")]
    UnsupportedSchema(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FinalityAttemptV1, FinalityAttemptStateV1};
    use std::fs;
    use std::path::PathBuf;

    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "xenia-finality-executor-{}",
            std::process::id()
        ))
    }

    #[test]
    fn started_attempt_is_the_recovery_boundary() {
        let path = path();
        let _ = fs::remove_file(&path);

        let mut journal = FinalityJournalV1::open(&path).unwrap();
        let mut attempt =
            FinalityAttemptV1::prepare([1; 16], [2; 32], [3; 32], [4; 32]).unwrap();
        journal.append_attempt(&attempt).unwrap();
        attempt.mark_effectuation_started().unwrap();
        journal.append_attempt(&attempt).unwrap();

        assert!(matches!(
            journal.latest_attempt([1; 16]).unwrap().state(),
            FinalityAttemptStateV1::EffectuationStarted
        ));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn committed_path_requires_started_state() {
        let path = path();
        let _ = fs::remove_file(&path);

        let mut journal = FinalityJournalV1::open(&path).unwrap();
        let mut attempt =
            FinalityAttemptV1::prepare([5; 16], [6; 32], [7; 32], [8; 32]).unwrap();
        assert!(attempt.commit().is_err());
        journal.append_attempt(&attempt).unwrap();
        attempt.mark_effectuation_started().unwrap();
        journal.append_attempt(&attempt).unwrap();
        let receipt = attempt.commit().unwrap();
        journal.append_attempt(&attempt).unwrap();
        journal.append_receipt(&receipt).unwrap();
        assert_eq!(receipt.outcome, FinalityOutcomeV1::Committed);

        let _ = fs::remove_file(&path);
    }
}
