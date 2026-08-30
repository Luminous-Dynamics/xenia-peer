// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime-free governed recovery contracts for Xenia privileged-operation stores.
//!
//! Recovery is deliberately not a boolean `clear_recovery` operation. V1 separates a
//! read-only assessment from a short-lived approved recovery plan, and binds any epoch/store
//! transition to that exact plan. These records are evidence/decision commitments, not
//! bearer credentials and not authorization to perform arbitrary privileged effects.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OperationAuthorityEpochV1,
};

/// Exact schema label for [`OperationStoreRecoveryAssessmentV1`].
pub const RECOVERY_ASSESSMENT_SCHEMA_V1: &str = "xenia-operation-store-recovery-assessment-v1";
/// Exact schema label for [`OperationStoreRecoveryPlanV1`].
pub const RECOVERY_PLAN_SCHEMA_V1: &str = "xenia-operation-store-recovery-plan-v1";
/// Domain separator for recovery-assessment commitments.
pub const RECOVERY_ASSESSMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-store-recovery-assessment-digest-v1";
/// Domain separator for recovery-plan commitments.
pub const RECOVERY_PLAN_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-store-recovery-plan-digest-v1";
/// Maximum number of evidence checks in one V1 recovery assessment.
pub const MAX_RECOVERY_CHECKS_V1: usize = 32;
/// Maximum lifetime of one approved recovery plan: 15 minutes.
pub const MAX_RECOVERY_PLAN_LIFETIME_MS_V1: u64 = 15 * 60 * 1000;

/// Canonical category of evidence considered during governed recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryCheckKindV1 {
    /// SQLite/database structural integrity.
    StoreStructuralIntegrity,
    /// Filesystem path/owner/type/mode authority-root integrity.
    FilesystemAuthorityIntegrity,
    /// Immutable admission and grant-use reservation integrity.
    AdmissionReservationIntegrity,
    /// Append-only receipt-chain integrity, when receipt persistence exists.
    ReceiptChainIntegrity,
    /// Local frontier and external anti-rollback continuity.
    FrontierAnchorContinuity,
    /// Adapter-specific reconciliation of any armed but nonterminal operations.
    ArmedOperationReconciliation,
}

/// Result for one assessed recovery check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryCheckStatusV1 {
    /// Evidence establishes the check's success under the named profile.
    Passed,
    /// Evidence establishes a failure/inconsistency.
    Failed,
    /// This check is outside the current deployment's implemented feature set or claim.
    NotApplicable,
}

/// One canonical evidence-check result.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecoveryCheckV1 {
    /// Exact check category.
    pub kind: RecoveryCheckKindV1,
    /// Assessment result.
    pub status: RecoveryCheckStatusV1,
    /// Non-zero commitment to the evidence supporting this status.
    pub evidence_digest: [u8; 32],
}

impl RecoveryCheckV1 {
    /// Validate that the evidence commitment is explicit.
    pub fn validate(&self) -> Result<(), RecoveryProtocolError> {
        if self.evidence_digest == [0u8; 32] {
            return Err(RecoveryProtocolError::ZeroEvidenceDigest);
        }
        Ok(())
    }
}

/// Immutable read-only assessment of one fail-stopped operation store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationStoreRecoveryAssessmentV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Unique assessment identity.
    pub assessment_id: [u8; 16],
    /// Exact authority domain being assessed.
    pub authority_domain_id: [u8; 16],
    /// Current authority epoch commitment observed before any recovery mutation.
    pub current_authority_epoch_digest: [u8; 32],
    /// Receipt store identity observed during assessment.
    pub store_id: [u8; 16],
    /// Receipt store generation observed during assessment.
    pub store_generation: u64,
    /// Sorted, unique evidence-check results.
    pub checks: Vec<RecoveryCheckV1>,
    /// Trusted-enough assessment time.
    pub assessed_at_unix_ms: u64,
}

impl OperationStoreRecoveryAssessmentV1 {
    /// Validate bounded canonical assessment syntax.
    pub fn validate(&self) -> Result<(), RecoveryProtocolError> {
        if self.schema != RECOVERY_ASSESSMENT_SCHEMA_V1 {
            return Err(RecoveryProtocolError::UnsupportedAssessmentSchema);
        }
        if self.assessment_id == [0u8; 16] {
            return Err(RecoveryProtocolError::ZeroAssessmentId);
        }
        if self.authority_domain_id == [0u8; 16] {
            return Err(RecoveryProtocolError::ZeroAuthorityDomainId);
        }
        if self.current_authority_epoch_digest == [0u8; 32] {
            return Err(RecoveryProtocolError::ZeroAuthorityEpochDigest);
        }
        if self.store_id == [0u8; 16] {
            return Err(RecoveryProtocolError::ZeroStoreId);
        }
        if self.checks.is_empty() || self.checks.len() > MAX_RECOVERY_CHECKS_V1 {
            return Err(RecoveryProtocolError::InvalidCheckCount);
        }
        for check in &self.checks {
            check.validate()?;
        }
        if self.checks.windows(2).any(|pair| pair[0].kind >= pair[1].kind) {
            return Err(RecoveryProtocolError::NonCanonicalChecks);
        }
        Ok(())
    }

    /// Find the status of one exact check category.
    pub fn status(&self, kind: RecoveryCheckKindV1) -> Option<RecoveryCheckStatusV1> {
        self.checks
            .binary_search_by_key(&kind, |check| check.kind)
            .ok()
            .map(|index| self.checks[index].status)
    }

    /// Require every policy-required check to be present and passed.
    pub fn require_passed(
        &self,
        required: &[RecoveryCheckKindV1],
    ) -> Result<(), RecoveryProtocolError> {
        self.validate()?;
        if required.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RecoveryProtocolError::NonCanonicalRequiredChecks);
        }
        for kind in required {
            match self.status(*kind) {
                Some(RecoveryCheckStatusV1::Passed) => {}
                Some(RecoveryCheckStatusV1::Failed | RecoveryCheckStatusV1::NotApplicable)
                | None => return Err(RecoveryProtocolError::RequiredCheckNotPassed(*kind)),
            }
        }
        Ok(())
    }

    /// Deterministic assessment commitment.
    pub fn assessment_digest(&self) -> Result<[u8; 32], RecoveryProtocolError> {
        self.validate()?;
        Ok(domain_digest(
            RECOVERY_ASSESSMENT_DIGEST_DOMAIN_V1,
            &bincode::serialize(self)?,
        ))
    }
}

/// Explicit governed recovery disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryDispositionV1 {
    /// Keep the store quarantined; no mutation authority is restored.
    Quarantine,
    /// Resume the same exact store generation and authority epoch after continuity proof.
    ResumeSameEpoch,
    /// Advance the same store to the exact next generation and a new authority epoch.
    AdvanceStoreGenerationAndEpoch {
        /// Preselected unique identity for the next authority epoch.
        next_epoch_id: [u8; 16],
        /// Exact next store generation expected by the plan.
        next_store_generation: u64,
    },
    /// Replace the receipt store and start generation zero under a new authority epoch.
    ReplaceStoreAndAdvanceEpoch {
        /// Preselected new receipt-store identity.
        new_store_id: [u8; 16],
        /// Preselected unique identity for the next authority epoch.
        next_epoch_id: [u8; 16],
    },
}

/// Short-lived approved plan derived from an immutable assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationStoreRecoveryPlanV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Unique recovery-plan identity.
    pub plan_id: [u8; 16],
    /// Exact assessment commitment this plan responds to.
    pub assessment_digest: [u8; 32],
    /// Exact authority epoch that must still be current when the plan executes.
    pub current_authority_epoch_digest: [u8; 32],
    /// Exact policy revision governing this recovery decision.
    pub recovery_policy_digest: [u8; 32],
    /// Exact human/organizational approval commitment.
    pub approval_digest: [u8; 32],
    /// Sorted, unique checks that the recovery policy requires to pass.
    pub required_checks: Vec<RecoveryCheckKindV1>,
    /// Explicit recovery disposition.
    pub disposition: RecoveryDispositionV1,
    /// Trusted-enough authorization time.
    pub authorized_at_unix_ms: u64,
    /// Exclusive hard expiry for this plan.
    pub expires_at_unix_ms: u64,
}

impl OperationStoreRecoveryPlanV1 {
    /// Validate canonical plan syntax independent of the current store/epoch.
    pub fn validate(&self) -> Result<(), RecoveryProtocolError> {
        if self.schema != RECOVERY_PLAN_SCHEMA_V1 {
            return Err(RecoveryProtocolError::UnsupportedPlanSchema);
        }
        if self.plan_id == [0u8; 16] {
            return Err(RecoveryProtocolError::ZeroPlanId);
        }
        require_nonzero(self.assessment_digest, RecoveryProtocolError::ZeroAssessmentDigest)?;
        require_nonzero(
            self.current_authority_epoch_digest,
            RecoveryProtocolError::ZeroAuthorityEpochDigest,
        )?;
        require_nonzero(
            self.recovery_policy_digest,
            RecoveryProtocolError::ZeroRecoveryPolicyDigest,
        )?;
        require_nonzero(self.approval_digest, RecoveryProtocolError::ZeroApprovalDigest)?;

        if self.required_checks.is_empty()
            || self.required_checks.len() > MAX_RECOVERY_CHECKS_V1
            || self.required_checks.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RecoveryProtocolError::NonCanonicalRequiredChecks);
        }
        if self.expires_at_unix_ms <= self.authorized_at_unix_ms {
            return Err(RecoveryProtocolError::InvalidPlanWindow);
        }
        let lifetime = self.expires_at_unix_ms - self.authorized_at_unix_ms;
        if lifetime > MAX_RECOVERY_PLAN_LIFETIME_MS_V1 {
            return Err(RecoveryProtocolError::PlanLifetimeTooLong);
        }
        match &self.disposition {
            RecoveryDispositionV1::Quarantine | RecoveryDispositionV1::ResumeSameEpoch => {}
            RecoveryDispositionV1::AdvanceStoreGenerationAndEpoch {
                next_epoch_id, ..
            } => {
                if *next_epoch_id == [0u8; 16] {
                    return Err(RecoveryProtocolError::ZeroNextEpochId);
                }
            }
            RecoveryDispositionV1::ReplaceStoreAndAdvanceEpoch {
                new_store_id,
                next_epoch_id,
            } => {
                if *new_store_id == [0u8; 16] {
                    return Err(RecoveryProtocolError::ZeroReplacementStoreId);
                }
                if *next_epoch_id == [0u8; 16] {
                    return Err(RecoveryProtocolError::ZeroNextEpochId);
                }
            }
        }
        Ok(())
    }

    /// Require this plan to be live at `now_unix_ms`.
    pub fn require_live_at(&self, now_unix_ms: u64) -> Result<(), RecoveryProtocolError> {
        self.validate()?;
        if now_unix_ms < self.authorized_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(RecoveryProtocolError::PlanNotLive);
        }
        Ok(())
    }

    /// Validate this plan against the exact assessment and current authority epoch.
    pub fn validate_against(
        &self,
        assessment: &OperationStoreRecoveryAssessmentV1,
        current_epoch: &OperationAuthorityEpochV1,
    ) -> Result<(), RecoveryProtocolError> {
        self.validate()?;
        assessment.validate()?;
        current_epoch.validate()?;

        if self.assessment_digest != assessment.assessment_digest()? {
            return Err(RecoveryProtocolError::AssessmentDigestMismatch);
        }
        let current_epoch_digest = current_epoch.epoch_digest()?;
        if self.current_authority_epoch_digest != current_epoch_digest
            || assessment.current_authority_epoch_digest != current_epoch_digest
        {
            return Err(RecoveryProtocolError::AuthorityEpochMismatch);
        }
        if assessment.authority_domain_id != current_epoch.authority_domain_id {
            return Err(RecoveryProtocolError::AuthorityDomainMismatch);
        }
        if assessment.store_id != current_epoch.store_id
            || assessment.store_generation != current_epoch.store_generation
        {
            return Err(RecoveryProtocolError::StoreBindingMismatch);
        }

        match self.disposition {
            RecoveryDispositionV1::Quarantine => Ok(()),
            RecoveryDispositionV1::ResumeSameEpoch
            | RecoveryDispositionV1::AdvanceStoreGenerationAndEpoch { .. }
            | RecoveryDispositionV1::ReplaceStoreAndAdvanceEpoch { .. } => {
                assessment.require_passed(&self.required_checks)
            }
        }
    }

    /// Deterministic recovery-plan commitment used by a governed epoch transition.
    pub fn plan_digest(&self) -> Result<[u8; 32], RecoveryProtocolError> {
        self.validate()?;
        Ok(domain_digest(
            RECOVERY_PLAN_DIGEST_DOMAIN_V1,
            &bincode::serialize(self)?,
        ))
    }

    /// Validate a proposed next authority epoch as the exact transition authorized by this plan.
    ///
    /// `ResumeSameEpoch` and `Quarantine` do not create a successor epoch and are therefore
    /// rejected by this function.
    pub fn validate_next_epoch(
        &self,
        current: &OperationAuthorityEpochV1,
        next: &OperationAuthorityEpochV1,
    ) -> Result<(), RecoveryProtocolError> {
        self.validate()?;
        next.validate_successor(current)?;
        let plan_digest = self.plan_digest()?;

        match (&self.disposition, &next.reason) {
            (
                RecoveryDispositionV1::AdvanceStoreGenerationAndEpoch {
                    next_epoch_id,
                    next_store_generation,
                },
                AuthorityEpochReasonV1::RecoveryGenerationRollover {
                    recovery_decision_digest,
                },
            ) => {
                if next.epoch_id != *next_epoch_id
                    || next.store_generation != *next_store_generation
                    || *recovery_decision_digest != plan_digest
                {
                    return Err(RecoveryProtocolError::NextEpochDoesNotMatchPlan);
                }
            }
            (
                RecoveryDispositionV1::ReplaceStoreAndAdvanceEpoch {
                    new_store_id,
                    next_epoch_id,
                },
                AuthorityEpochReasonV1::StoreReplacement {
                    recovery_decision_digest,
                },
            ) => {
                if next.store_id != *new_store_id
                    || next.epoch_id != *next_epoch_id
                    || *recovery_decision_digest != plan_digest
                {
                    return Err(RecoveryProtocolError::NextEpochDoesNotMatchPlan);
                }
            }
            (RecoveryDispositionV1::Quarantine | RecoveryDispositionV1::ResumeSameEpoch, _) => {
                return Err(RecoveryProtocolError::DispositionCreatesNoNextEpoch);
            }
            _ => return Err(RecoveryProtocolError::NextEpochDoesNotMatchPlan),
        }
        Ok(())
    }
}

/// Recovery contract failure.
#[derive(Debug, Error)]
pub enum RecoveryProtocolError {
    /// Assessment schema mismatch.
    #[error("unsupported recovery assessment schema")]
    UnsupportedAssessmentSchema,
    /// Recovery-plan schema mismatch.
    #[error("unsupported recovery plan schema")]
    UnsupportedPlanSchema,
    /// Assessment id is unset.
    #[error("assessment id must not be all zero")]
    ZeroAssessmentId,
    /// Recovery plan id is unset.
    #[error("recovery plan id must not be all zero")]
    ZeroPlanId,
    /// Authority domain is unset.
    #[error("authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Current epoch commitment is unset.
    #[error("authority epoch digest must not be all zero")]
    ZeroAuthorityEpochDigest,
    /// Store id is unset.
    #[error("store id must not be all zero")]
    ZeroStoreId,
    /// Evidence commitment is unset.
    #[error("recovery check requires a non-zero evidence digest")]
    ZeroEvidenceDigest,
    /// Assessment commitment is unset.
    #[error("assessment digest must not be all zero")]
    ZeroAssessmentDigest,
    /// Recovery-policy commitment is unset.
    #[error("recovery policy digest must not be all zero")]
    ZeroRecoveryPolicyDigest,
    /// Approval commitment is unset.
    #[error("recovery approval digest must not be all zero")]
    ZeroApprovalDigest,
    /// Replacement store identity is unset.
    #[error("replacement store id must not be all zero")]
    ZeroReplacementStoreId,
    /// Next epoch identity is unset.
    #[error("next epoch id must not be all zero")]
    ZeroNextEpochId,
    /// Check list size is invalid.
    #[error("recovery assessment must contain 1..=32 checks")]
    InvalidCheckCount,
    /// Assessment checks are not strictly sorted and unique.
    #[error("recovery checks must be strictly sorted and unique")]
    NonCanonicalChecks,
    /// Required check policy is not strictly sorted/unique.
    #[error("required recovery checks must be non-empty, strictly sorted and unique")]
    NonCanonicalRequiredChecks,
    /// One policy-required check did not pass.
    #[error("required recovery check did not pass: {0:?}")]
    RequiredCheckNotPassed(RecoveryCheckKindV1),
    /// Recovery-plan time window is invalid.
    #[error("recovery plan time window is invalid")]
    InvalidPlanWindow,
    /// Recovery plan exceeds V1 lifetime limit.
    #[error("recovery plan lifetime exceeds 15 minutes")]
    PlanLifetimeTooLong,
    /// Recovery plan is not live now.
    #[error("recovery plan is not currently live")]
    PlanNotLive,
    /// Plan assessment commitment differs from supplied assessment.
    #[error("recovery assessment digest mismatch")]
    AssessmentDigestMismatch,
    /// Current authority epoch changed since assessment/plan.
    #[error("operation authority epoch mismatch")]
    AuthorityEpochMismatch,
    /// Authority domain differs.
    #[error("operation authority domain mismatch")]
    AuthorityDomainMismatch,
    /// Assessed store id/generation differs from current epoch.
    #[error("receipt store binding mismatch")]
    StoreBindingMismatch,
    /// Proposed successor epoch is not the exact transition authorized by this plan.
    #[error("next authority epoch does not match recovery plan")]
    NextEpochDoesNotMatchPlan,
    /// This disposition does not create a successor epoch.
    #[error("recovery disposition does not create a next authority epoch")]
    DispositionCreatesNoNextEpoch,
    /// Authority-epoch contract rejected the transition.
    #[error("authority epoch validation failed: {0}")]
    AuthorityEpoch(#[from] xenia_operation_authority_epoch::AuthorityEpochError),
    /// Serialization failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

fn require_nonzero(value: [u8; 32], error: RecoveryProtocolError) -> Result<(), RecoveryProtocolError> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operation_authority_epoch::{
        AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1,
    };

    fn epoch() -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: [1u8; 16],
            epoch_id: [2u8; 16],
            epoch_sequence: 0,
            previous_epoch_digest: [0u8; 32],
            store_id: [3u8; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::Genesis,
            established_at_unix_ms: 100,
        }
    }

    fn checks() -> Vec<RecoveryCheckV1> {
        vec![
            RecoveryCheckV1 {
                kind: RecoveryCheckKindV1::StoreStructuralIntegrity,
                status: RecoveryCheckStatusV1::Passed,
                evidence_digest: [10u8; 32],
            },
            RecoveryCheckV1 {
                kind: RecoveryCheckKindV1::FilesystemAuthorityIntegrity,
                status: RecoveryCheckStatusV1::Passed,
                evidence_digest: [11u8; 32],
            },
            RecoveryCheckV1 {
                kind: RecoveryCheckKindV1::AdmissionReservationIntegrity,
                status: RecoveryCheckStatusV1::Passed,
                evidence_digest: [12u8; 32],
            },
        ]
    }

    fn assessment(current: &OperationAuthorityEpochV1) -> OperationStoreRecoveryAssessmentV1 {
        OperationStoreRecoveryAssessmentV1 {
            schema: RECOVERY_ASSESSMENT_SCHEMA_V1.to_string(),
            assessment_id: [4u8; 16],
            authority_domain_id: current.authority_domain_id,
            current_authority_epoch_digest: current.epoch_digest().unwrap(),
            store_id: current.store_id,
            store_generation: current.store_generation,
            checks: checks(),
            assessed_at_unix_ms: 110,
        }
    }

    fn required() -> Vec<RecoveryCheckKindV1> {
        vec![
            RecoveryCheckKindV1::StoreStructuralIntegrity,
            RecoveryCheckKindV1::FilesystemAuthorityIntegrity,
            RecoveryCheckKindV1::AdmissionReservationIntegrity,
        ]
    }

    fn plan(
        assessment: &OperationStoreRecoveryAssessmentV1,
        current: &OperationAuthorityEpochV1,
        disposition: RecoveryDispositionV1,
    ) -> OperationStoreRecoveryPlanV1 {
        OperationStoreRecoveryPlanV1 {
            schema: RECOVERY_PLAN_SCHEMA_V1.to_string(),
            plan_id: [5u8; 16],
            assessment_digest: assessment.assessment_digest().unwrap(),
            current_authority_epoch_digest: current.epoch_digest().unwrap(),
            recovery_policy_digest: [6u8; 32],
            approval_digest: [7u8; 32],
            required_checks: required(),
            disposition,
            authorized_at_unix_ms: 120,
            expires_at_unix_ms: 120 + 60_000,
        }
    }

    #[test]
    fn same_epoch_resume_requires_all_policy_checks_to_pass() {
        let current = epoch();
        let assessment = assessment(&current);
        let plan = plan(&assessment, &current, RecoveryDispositionV1::ResumeSameEpoch);
        assert!(plan.validate_against(&assessment, &current).is_ok());
    }

    #[test]
    fn failed_required_check_blocks_resume() {
        let current = epoch();
        let mut assessment = assessment(&current);
        assessment.checks[1].status = RecoveryCheckStatusV1::Failed;
        let plan = plan(&assessment, &current, RecoveryDispositionV1::ResumeSameEpoch);
        assert!(matches!(
            plan.validate_against(&assessment, &current),
            Err(RecoveryProtocolError::RequiredCheckNotPassed(
                RecoveryCheckKindV1::FilesystemAuthorityIntegrity
            ))
        ));
    }

    #[test]
    fn stale_assessment_cannot_drive_recovery_after_epoch_change() {
        let current = epoch();
        let assessment = assessment(&current);
        let plan = plan(&assessment, &current, RecoveryDispositionV1::ResumeSameEpoch);
        let revoked = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: current.authority_domain_id,
            epoch_id: [8u8; 16],
            epoch_sequence: 1,
            previous_epoch_digest: current.epoch_digest().unwrap(),
            store_id: current.store_id,
            store_generation: current.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: [9u8; 32],
            },
            established_at_unix_ms: 121,
        };
        assert!(matches!(
            plan.validate_against(&assessment, &revoked),
            Err(RecoveryProtocolError::AuthorityEpochMismatch)
                | Err(RecoveryProtocolError::StoreBindingMismatch)
        ));
    }

    #[test]
    fn generation_rollover_epoch_must_commit_exact_plan_digest() {
        let current = epoch();
        let assessment = assessment(&current);
        let plan = plan(
            &assessment,
            &current,
            RecoveryDispositionV1::AdvanceStoreGenerationAndEpoch {
                next_epoch_id: [13u8; 16],
                next_store_generation: 1,
            },
        );
        let next = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: current.authority_domain_id,
            epoch_id: [13u8; 16],
            epoch_sequence: 1,
            previous_epoch_digest: current.epoch_digest().unwrap(),
            store_id: current.store_id,
            store_generation: 1,
            reason: AuthorityEpochReasonV1::RecoveryGenerationRollover {
                recovery_decision_digest: plan.plan_digest().unwrap(),
            },
            established_at_unix_ms: 130,
        };
        assert!(plan.validate_next_epoch(&current, &next).is_ok());
    }

    #[test]
    fn replacement_epoch_must_use_planned_new_store_id() {
        let current = epoch();
        let assessment = assessment(&current);
        let plan = plan(
            &assessment,
            &current,
            RecoveryDispositionV1::ReplaceStoreAndAdvanceEpoch {
                new_store_id: [14u8; 16],
                next_epoch_id: [15u8; 16],
            },
        );
        let mut next = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: current.authority_domain_id,
            epoch_id: [15u8; 16],
            epoch_sequence: 1,
            previous_epoch_digest: current.epoch_digest().unwrap(),
            store_id: [16u8; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::StoreReplacement {
                recovery_decision_digest: plan.plan_digest().unwrap(),
            },
            established_at_unix_ms: 130,
        };
        assert!(matches!(
            plan.validate_next_epoch(&current, &next),
            Err(RecoveryProtocolError::NextEpochDoesNotMatchPlan)
        ));
        next.store_id = [14u8; 16];
        assert!(plan.validate_next_epoch(&current, &next).is_ok());
    }

    #[test]
    fn quarantine_never_requires_a_successor_epoch() {
        let current = epoch();
        let assessment = assessment(&current);
        let plan = plan(&assessment, &current, RecoveryDispositionV1::Quarantine);
        assert!(plan.validate_against(&assessment, &current).is_ok());
    }
}
