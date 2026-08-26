// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Read-only evidence semantics for ransomware/operator-compromise exercises.
//!
//! This crate does **not** authenticate operators, mint tokens, revoke keys, or
//! authorize actions. Xenia's existing operator surfaces remain the sole owners
//! of those security decisions. Exercise code records what those boundaries
//! actually returned and this crate evaluates whether post-revocation
//! containment was demonstrated across distinct authority paths.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const OPERATOR_CONTAINMENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExerciseId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OperatorId(pub String);

/// Distinct operator-authority boundaries exercised after revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundarySurface {
    /// A fresh `/auth/verify` attempt to mint a new role-scoped token.
    FreshTokenIssuance,
    /// An already-issued token attempting an authenticated consent mutation.
    ExistingTokenConsentMutation,
    /// An already-issued Admin token attempting to revoke another operator.
    ExistingTokenOperatorRevocation,
    /// An already-issued Admin token attempting the high-blast-radius key replacement path.
    ExistingTokenKeyReplacement,
    /// An already-issued token attempting to read the private full audit ledger.
    ExistingTokenAuditLedgerRead,
    /// A cryptographically authenticated peer attempting to establish the sealed operator channel.
    SealedOperatorChannel,
}

impl BoundarySurface {
    /// Minimum baseline for a compromised-operator containment exercise.
    ///
    /// The four paths deliberately cover fresh authentication, retained bearer
    /// authority, private read authority, and the independent sealed-channel
    /// handshake path.
    pub const REQUIRED_BASELINE: [Self; 4] = [
        Self::FreshTokenIssuance,
        Self::ExistingTokenKeyReplacement,
        Self::ExistingTokenAuditLedgerRead,
        Self::SealedOperatorChannel,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryDecision {
    Allowed,
    Refused,
}

/// Locator for the underlying test/log/receipt that demonstrates an observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLocator {
    pub locator: String,
    pub digest: String,
    /// Immutable source/build revision that emitted the evidence.
    pub source_revision: String,
}

impl EvidenceLocator {
    pub fn is_complete(&self) -> bool {
        !self.locator.trim().is_empty()
            && !self.digest.trim().is_empty()
            && !self.source_revision.trim().is_empty()
    }
}

/// Evidence that the target operator entered the live revocation set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationObservation {
    pub exercise_id: ExerciseId,
    pub operator_id: OperatorId,
    pub effective_at_unix_ms: u64,
    pub evidence: EvidenceLocator,
}

/// One observed decision from an existing Xenia security boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryObservation {
    pub exercise_id: ExerciseId,
    pub operator_id: OperatorId,
    pub surface: BoundarySurface,
    pub decision: BoundaryDecision,
    pub observed_at_unix_ms: u64,
    pub evidence: EvidenceLocator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperatorContainmentOutcome {
    Verified,
    Failed,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationError {
    UnsupportedSchemaVersion { found: u16 },
    EmptyExerciseId,
    EmptyOperatorId,
    IncompleteRevocationEvidence,
    ForeignRevocationExercise,
    ForeignRevocationOperator,
    ForeignBoundaryExercise { surface: BoundarySurface },
    ForeignBoundaryOperator { surface: BoundarySurface },
    BoundaryBeforeRevocation { surface: BoundarySurface },
    IncompleteBoundaryEvidence { surface: BoundarySurface },
    DuplicateRequiredBoundary { surface: BoundarySurface },
    MissingRequiredBoundary { surface: BoundarySurface },
}

/// Complete evidence set for one intentionally-compromised operator exercise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCompromiseEvidence {
    pub schema_version: u16,
    pub exercise_id: ExerciseId,
    pub operator_id: OperatorId,
    pub revocation: RevocationObservation,
    #[serde(default)]
    pub boundaries: Vec<BoundaryObservation>,
}

impl OperatorCompromiseEvidence {
    pub fn validation_errors(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if self.schema_version != OPERATOR_CONTAINMENT_SCHEMA_VERSION {
            errors.push(ValidationError::UnsupportedSchemaVersion {
                found: self.schema_version,
            });
        }
        if self.exercise_id.0.trim().is_empty() {
            errors.push(ValidationError::EmptyExerciseId);
        }
        if self.operator_id.0.trim().is_empty() {
            errors.push(ValidationError::EmptyOperatorId);
        }
        if !self.revocation.evidence.is_complete() {
            errors.push(ValidationError::IncompleteRevocationEvidence);
        }
        if self.revocation.exercise_id != self.exercise_id {
            errors.push(ValidationError::ForeignRevocationExercise);
        }
        if self.revocation.operator_id != self.operator_id {
            errors.push(ValidationError::ForeignRevocationOperator);
        }

        for boundary in &self.boundaries {
            if boundary.exercise_id != self.exercise_id {
                errors.push(ValidationError::ForeignBoundaryExercise {
                    surface: boundary.surface,
                });
            }
            if boundary.operator_id != self.operator_id {
                errors.push(ValidationError::ForeignBoundaryOperator {
                    surface: boundary.surface,
                });
            }
            if boundary.observed_at_unix_ms < self.revocation.effective_at_unix_ms {
                errors.push(ValidationError::BoundaryBeforeRevocation {
                    surface: boundary.surface,
                });
            }
            if !boundary.evidence.is_complete() {
                errors.push(ValidationError::IncompleteBoundaryEvidence {
                    surface: boundary.surface,
                });
            }
        }

        for required in BoundarySurface::REQUIRED_BASELINE {
            let count = self
                .boundaries
                .iter()
                .filter(|observation| observation.surface == required)
                .count();
            match count {
                0 => errors.push(ValidationError::MissingRequiredBoundary { surface: required }),
                1 => {}
                _ => errors.push(ValidationError::DuplicateRequiredBoundary { surface: required }),
            }
        }

        errors
    }

    /// Evaluate operator containment asymmetrically.
    ///
    /// - a complete, same-run, post-revocation `ALLOWED` result on any required
    ///   boundary is a material `FAILED` result;
    /// - malformed, stale/foreign, missing, duplicate, or incomplete evidence is
    ///   `UNPROVEN` rather than silently accepted;
    /// - only one evidenced `REFUSED` observation on each required baseline
    ///   surface yields `VERIFIED`.
    pub fn outcome(&self) -> OperatorContainmentOutcome {
        let base_identity_valid = self.schema_version == OPERATOR_CONTAINMENT_SCHEMA_VERSION
            && !self.exercise_id.0.trim().is_empty()
            && !self.operator_id.0.trim().is_empty()
            && self.revocation.exercise_id == self.exercise_id
            && self.revocation.operator_id == self.operator_id
            && self.revocation.evidence.is_complete();

        if base_identity_valid {
            let required: BTreeSet<BoundarySurface> =
                BoundarySurface::REQUIRED_BASELINE.into_iter().collect();

            let demonstrated_post_revocation_allow = self.boundaries.iter().any(|observation| {
                required.contains(&observation.surface)
                    && observation.exercise_id == self.exercise_id
                    && observation.operator_id == self.operator_id
                    && observation.observed_at_unix_ms >= self.revocation.effective_at_unix_ms
                    && observation.evidence.is_complete()
                    && observation.decision == BoundaryDecision::Allowed
            });

            if demonstrated_post_revocation_allow {
                return OperatorContainmentOutcome::Failed;
            }
        }

        if !self.validation_errors().is_empty() {
            return OperatorContainmentOutcome::Unproven;
        }

        if BoundarySurface::REQUIRED_BASELINE.into_iter().all(|required| {
            self.boundaries.iter().any(|observation| {
                observation.surface == required && observation.decision == BoundaryDecision::Refused
            })
        }) {
            OperatorContainmentOutcome::Verified
        } else {
            OperatorContainmentOutcome::Unproven
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator(label: &str) -> EvidenceLocator {
        EvidenceLocator {
            locator: format!("receipt:{label}"),
            digest: format!("sha256:{label}"),
            source_revision: "git:abc123".to_string(),
        }
    }

    fn boundary(surface: BoundarySurface, decision: BoundaryDecision) -> BoundaryObservation {
        BoundaryObservation {
            exercise_id: ExerciseId("exercise-001".to_string()),
            operator_id: OperatorId("alice".to_string()),
            surface,
            decision,
            observed_at_unix_ms: 2_000,
            evidence: locator(&format!("{surface:?}")),
        }
    }

    fn verified_fixture() -> OperatorCompromiseEvidence {
        OperatorCompromiseEvidence {
            schema_version: OPERATOR_CONTAINMENT_SCHEMA_VERSION,
            exercise_id: ExerciseId("exercise-001".to_string()),
            operator_id: OperatorId("alice".to_string()),
            revocation: RevocationObservation {
                exercise_id: ExerciseId("exercise-001".to_string()),
                operator_id: OperatorId("alice".to_string()),
                effective_at_unix_ms: 1_500,
                evidence: locator("revocation"),
            },
            boundaries: BoundarySurface::REQUIRED_BASELINE
                .into_iter()
                .map(|surface| boundary(surface, BoundaryDecision::Refused))
                .collect(),
        }
    }

    #[test]
    fn four_distinct_post_revocation_refusals_verify_containment() {
        let evidence = verified_fixture();
        assert!(evidence.validation_errors().is_empty());
        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Verified);
    }

    #[test]
    fn fresh_token_success_after_revocation_is_failure() {
        let mut evidence = verified_fixture();
        evidence
            .boundaries
            .iter_mut()
            .find(|b| b.surface == BoundarySurface::FreshTokenIssuance)
            .unwrap()
            .decision = BoundaryDecision::Allowed;

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Failed);
    }

    #[test]
    fn retained_admin_token_key_replacement_success_is_failure() {
        let mut evidence = verified_fixture();
        evidence
            .boundaries
            .iter_mut()
            .find(|b| b.surface == BoundarySurface::ExistingTokenKeyReplacement)
            .unwrap()
            .decision = BoundaryDecision::Allowed;

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Failed);
    }

    #[test]
    fn missing_private_audit_read_check_is_unproven() {
        let mut evidence = verified_fixture();
        evidence
            .boundaries
            .retain(|b| b.surface != BoundarySurface::ExistingTokenAuditLedgerRead);

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Unproven);
    }

    #[test]
    fn pre_revocation_refusal_does_not_prove_containment() {
        let mut evidence = verified_fixture();
        evidence.boundaries[0].observed_at_unix_ms = 1_499;

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Unproven);
    }

    #[test]
    fn foreign_operator_observation_is_unproven() {
        let mut evidence = verified_fixture();
        evidence.boundaries[0].operator_id = OperatorId("mallory".to_string());

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Unproven);
    }

    #[test]
    fn incomplete_allow_evidence_is_not_promoted_to_failure() {
        let mut evidence = verified_fixture();
        let observation = evidence
            .boundaries
            .iter_mut()
            .find(|b| b.surface == BoundarySurface::FreshTokenIssuance)
            .unwrap();
        observation.decision = BoundaryDecision::Allowed;
        observation.evidence.digest.clear();

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Unproven);
    }

    #[test]
    fn duplicate_required_boundary_is_unproven() {
        let mut evidence = verified_fixture();
        evidence.boundaries.push(boundary(
            BoundarySurface::FreshTokenIssuance,
            BoundaryDecision::Refused,
        ));

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Unproven);
    }

    #[test]
    fn extra_nonbaseline_refusal_does_not_invalidate_baseline() {
        let mut evidence = verified_fixture();
        evidence.boundaries.push(boundary(
            BoundarySurface::ExistingTokenConsentMutation,
            BoundaryDecision::Refused,
        ));

        assert_eq!(evidence.outcome(), OperatorContainmentOutcome::Verified);
    }

    #[test]
    fn evidence_roundtrips_through_json() {
        let evidence = verified_fixture();
        let json = serde_json::to_string(&evidence).expect("serialize evidence");
        let decoded: OperatorCompromiseEvidence =
            serde_json::from_str(&json).expect("deserialize evidence");

        assert_eq!(decoded, evidence);
        assert_eq!(decoded.outcome(), OperatorContainmentOutcome::Verified);
    }
}
