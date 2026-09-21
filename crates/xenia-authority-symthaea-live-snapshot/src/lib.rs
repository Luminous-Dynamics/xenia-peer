// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coherent live Xenia authority snapshots for Symthaea authorization receipts.
//!
//! This layer composes three already-separated theorems:
//!
//! - D3A1b holds a stable read barrier around live authority state;
//! - D3B canonicalizes the effective enrollment/revocation/RBAC state;
//! - D0 derives the narrow Symthaea attestation permission from canonical Xenia RBAC.
//!
//! A positive snapshot is therefore bound to one exact durable authority
//! generation, one exact effective-policy commitment, one exact non-revoked
//! operator enrollment, and one explicit typed attestation scope. It still does
//! **not** authenticate an operator request, verify a Symthaea attestation, sign
//! a D1 receipt, or admit evidence in Symthaea.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use xenia_symthaea_attestation_authority::SymthaeaAuthorityScopeV1;
use xenia_symthaea_authority_generation::{AuthorityVersionV1, SHA256_LEN, StableAuthoritySnapshot};
use xenia_symthaea_authority_state_commitment::{
    EffectiveSymthaeaPolicyCommitmentInputV1, SymthaeaEnrollmentCommitmentInputV1,
};
use xenia_symthaea_live_authority_guard::{LiveAuthorityGuard, LiveAuthorityGuardError};
use xenia_symthaea_rbac::{
    SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1, permit_symthaea_attestation_scope_v1,
};

/// Owned authoritative material read from the live daemon while the guard's
/// stable snapshot barrier is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySnapshotMaterialV1 {
    /// Active enrollment records relevant to Symthaea attestation authority.
    pub enrollments: Vec<SymthaeaEnrollmentCommitmentInputV1>,
    /// Effective revoked operator ids.
    pub revoked_operator_ids: Vec<String>,
}

impl AuthoritySnapshotMaterialV1 {
    /// Build the exact D3B effective-policy input represented by this material.
    pub fn effective_policy_input(&self) -> EffectiveSymthaeaPolicyCommitmentInputV1 {
        EffectiveSymthaeaPolicyCommitmentInputV1 {
            rbac_policy_version: SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1,
            enrollments: self.enrollments.clone(),
            revoked_operator_ids: self.revoked_operator_ids.clone(),
        }
    }

    /// Compute the canonical D3B effective-policy commitment.
    pub fn effective_policy_commitment_sha256(
        &self,
    ) -> Result<[u8; SHA256_LEN], AuthoritySnapshotValidationError> {
        self.effective_policy_input()
            .sha256()
            .ok_or(AuthoritySnapshotValidationError::InvalidEffectivePolicy)
    }
}

/// Positive coherent authority snapshot for one exact operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoherentSymthaeaAuthoritySnapshotV1 {
    operator: SymthaeaEnrollmentCommitmentInputV1,
    enrollment_commitment_sha256: [u8; SHA256_LEN],
    effective_policy_commitment_sha256: [u8; SHA256_LEN],
    authority_scope: SymthaeaAuthorityScopeV1,
}

impl CoherentSymthaeaAuthoritySnapshotV1 {
    /// Exact authoritative operator enrollment read under the stable barrier.
    pub fn operator(&self) -> &SymthaeaEnrollmentCommitmentInputV1 {
        &self.operator
    }

    /// Canonical D3B commitment to this exact operator enrollment.
    pub const fn enrollment_commitment_sha256(&self) -> [u8; SHA256_LEN] {
        self.enrollment_commitment_sha256
    }

    /// Canonical D3B commitment to the complete effective authority policy.
    pub const fn effective_policy_commitment_sha256(&self) -> [u8; SHA256_LEN] {
        self.effective_policy_commitment_sha256
    }

    /// Typed Symthaea attestation scope permitted by D0 RBAC for this operator.
    pub const fn authority_scope(&self) -> SymthaeaAuthorityScopeV1 {
        self.authority_scope
    }
}

/// Validation failures while turning one stable live read into a positive
/// Symthaea authority snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthoritySnapshotValidationError {
    /// Enrollment/revocation/RBAC material cannot produce a canonical D3B commitment.
    InvalidEffectivePolicy,
    /// Requested operator id was not present in the active enrollment set.
    OperatorNotEnrolled(String),
    /// Requested operator id is present in the effective revocation set.
    OperatorRevoked(String),
    /// Canonical Xenia role does not permit the requested Symthaea attestation scope.
    RoleNotPermitted(String),
    /// Individual enrollment record could not produce its canonical commitment.
    InvalidEnrollment(String),
    /// Material read under the stable barrier does not match the commitment
    /// recorded for that authority generation.
    GenerationCommitmentMismatch {
        /// Commitment carried by the durable authority generation.
        recorded: [u8; SHA256_LEN],
        /// Commitment recomputed from the live material.
        computed: [u8; SHA256_LEN],
    },
}

/// Snapshot callback error that preserves whether failure came from the daemon
/// read adapter or from canonical validation of the material it supplied.
#[derive(Debug)]
pub enum AuthoritySnapshotReadError<E> {
    /// Authoritative source could not be read.
    Source(E),
    /// Source was readable but did not establish a coherent positive snapshot.
    Validation(AuthoritySnapshotValidationError),
}

/// Read one coherent, committed, non-revoked and RBAC-permitted authority
/// snapshot for `operator_id`.
///
/// `read_material` is invoked while D3A1b's stable read barrier is held. The
/// resulting owned material is canonicalized before the barrier is released,
/// and its effective-policy digest must exactly equal the commitment recorded
/// in the durable authority generation passed to the same callback.
pub fn read_coherent_symthaea_authority_snapshot_v1<E, F>(
    guard: &LiveAuthorityGuard,
    operator_id: &str,
    read_material: F,
) -> Result<
    StableAuthoritySnapshot<CoherentSymthaeaAuthoritySnapshotV1>,
    LiveAuthorityGuardError<AuthoritySnapshotReadError<E>>,
>
where
    F: FnOnce() -> Result<AuthoritySnapshotMaterialV1, E>,
{
    guard.with_stable_snapshot(|version| {
        let material = read_material().map_err(AuthoritySnapshotReadError::Source)?;
        coherent_from_material(version, operator_id, material)
            .map_err(AuthoritySnapshotReadError::Validation)
    })
}

fn coherent_from_material(
    version: AuthorityVersionV1,
    operator_id: &str,
    material: AuthoritySnapshotMaterialV1,
) -> Result<CoherentSymthaeaAuthoritySnapshotV1, AuthoritySnapshotValidationError> {
    let policy_commitment = material.effective_policy_commitment_sha256()?;
    if policy_commitment != version.state_commitment_sha256 {
        return Err(
            AuthoritySnapshotValidationError::GenerationCommitmentMismatch {
                recorded: version.state_commitment_sha256,
                computed: policy_commitment,
            },
        );
    }

    let operator = material
        .enrollments
        .iter()
        .find(|enrollment| enrollment.operator_id == operator_id)
        .cloned()
        .ok_or_else(|| {
            AuthoritySnapshotValidationError::OperatorNotEnrolled(operator_id.to_string())
        })?;

    if material
        .revoked_operator_ids
        .iter()
        .any(|revoked| revoked == operator_id)
    {
        return Err(AuthoritySnapshotValidationError::OperatorRevoked(
            operator_id.to_string(),
        ));
    }

    let required_scope = SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1;
    let permit = permit_symthaea_attestation_scope_v1(operator.role, required_scope).ok_or_else(|| {
        AuthoritySnapshotValidationError::RoleNotPermitted(operator_id.to_string())
    })?;

    let enrollment_commitment_sha256 = operator.sha256().ok_or_else(|| {
        AuthoritySnapshotValidationError::InvalidEnrollment(operator_id.to_string())
    })?;

    Ok(CoherentSymthaeaAuthoritySnapshotV1 {
        operator,
        enrollment_commitment_sha256,
        effective_policy_commitment_sha256: policy_commitment,
        authority_scope: permit.scope(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use xenia_handshake::ML_DSA_65_PK_LEN;
    use xenia_operator_proto::OperatorRole;

    const HOST: [u8; SHA256_LEN] = [0x11; SHA256_LEN];

    fn alice(role: OperatorRole) -> SymthaeaEnrollmentCommitmentInputV1 {
        SymthaeaEnrollmentCommitmentInputV1 {
            operator_id: "alice".into(),
            ed25519_pubkey: [0x21; 32],
            ml_dsa_65_pubkey: vec![0x31; ML_DSA_65_PK_LEN],
            role,
        }
    }

    fn bob() -> SymthaeaEnrollmentCommitmentInputV1 {
        SymthaeaEnrollmentCommitmentInputV1 {
            operator_id: "bob".into(),
            ed25519_pubkey: [0x41; 32],
            ml_dsa_65_pubkey: vec![0x51; ML_DSA_65_PK_LEN],
            role: OperatorRole::Viewer,
        }
    }

    fn material(role: OperatorRole, revoked: Vec<&str>) -> AuthoritySnapshotMaterialV1 {
        AuthoritySnapshotMaterialV1 {
            enrollments: vec![alice(role), bob()],
            revoked_operator_ids: revoked.into_iter().map(str::to_string).collect(),
        }
    }

    fn ledger_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("authority-generation.bin")
    }

    fn guard_for(material: &AuthoritySnapshotMaterialV1, dir: &tempfile::TempDir) -> LiveAuthorityGuard {
        let commitment = material.effective_policy_commitment_sha256().unwrap();
        LiveAuthorityGuard::bootstrap_new(ledger_path(dir), HOST, commitment).unwrap()
    }

    #[test]
    fn coherent_admin_snapshot_binds_generation_enrollment_policy_and_scope() {
        let dir = tempfile::tempdir().unwrap();
        let source = material(OperatorRole::Admin, vec![]);
        let guard = guard_for(&source, &dir);

        let snapshot = read_coherent_symthaea_authority_snapshot_v1(
            &guard,
            "alice",
            || Ok::<_, &'static str>(source.clone()),
        )
        .unwrap();

        assert_eq!(snapshot.version().generation, 1);
        assert_eq!(
            snapshot.value().effective_policy_commitment_sha256(),
            snapshot.version().state_commitment_sha256
        );
        assert_eq!(snapshot.value().operator().operator_id, "alice");
        assert_eq!(
            snapshot.value().enrollment_commitment_sha256(),
            alice(OperatorRole::Admin).sha256().unwrap()
        );
        assert_eq!(
            snapshot.value().authority_scope(),
            SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1
        );
    }

    #[test]
    fn mismatched_live_material_cannot_hide_behind_recorded_generation() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = material(OperatorRole::Admin, vec![]);
        let guard = guard_for(&recorded, &dir);
        let changed = material(OperatorRole::Admin, vec!["bob"]);

        let result = read_coherent_symthaea_authority_snapshot_v1(
            &guard,
            "alice",
            || Ok::<_, &'static str>(changed),
        );
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::Snapshot(
                AuthoritySnapshotReadError::Validation(
                    AuthoritySnapshotValidationError::GenerationCommitmentMismatch { .. }
                )
            ))
        ));
        assert!(!guard.is_poisoned());
    }

    #[test]
    fn revoked_operator_cannot_produce_positive_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let source = material(OperatorRole::Admin, vec!["alice"]);
        let guard = guard_for(&source, &dir);
        let result = read_coherent_symthaea_authority_snapshot_v1(
            &guard,
            "alice",
            || Ok::<_, &'static str>(source),
        );
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::Snapshot(
                AuthoritySnapshotReadError::Validation(
                    AuthoritySnapshotValidationError::OperatorRevoked(operator)
                )
            )) if operator == "alice"
        ));
    }

    #[test]
    fn lower_role_cannot_produce_attestation_authority_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let source = material(OperatorRole::Operator, vec![]);
        let guard = guard_for(&source, &dir);
        let result = read_coherent_symthaea_authority_snapshot_v1(
            &guard,
            "alice",
            || Ok::<_, &'static str>(source),
        );
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::Snapshot(
                AuthoritySnapshotReadError::Validation(
                    AuthoritySnapshotValidationError::RoleNotPermitted(operator)
                )
            )) if operator == "alice"
        ));
    }

    #[test]
    fn duplicate_operator_identity_fails_before_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let good = material(OperatorRole::Admin, vec![]);
        let guard = guard_for(&good, &dir);
        let mut malformed = good.clone();
        let mut duplicate = bob();
        duplicate.operator_id = "alice".into();
        malformed.enrollments.push(duplicate);

        let result = read_coherent_symthaea_authority_snapshot_v1(
            &guard,
            "alice",
            || Ok::<_, &'static str>(malformed),
        );
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::Snapshot(
                AuthoritySnapshotReadError::Validation(
                    AuthoritySnapshotValidationError::InvalidEffectivePolicy
                )
            ))
        ));
    }

    #[test]
    fn source_read_failure_is_not_reinterpreted_as_policy_denial() {
        let dir = tempfile::tempdir().unwrap();
        let source = material(OperatorRole::Admin, vec![]);
        let guard = guard_for(&source, &dir);
        let result = read_coherent_symthaea_authority_snapshot_v1(
            &guard,
            "alice",
            || Err::<AuthoritySnapshotMaterialV1, _>("policy lock poisoned"),
        );
        assert!(matches!(
            result,
            Err(LiveAuthorityGuardError::Snapshot(
                AuthoritySnapshotReadError::Source("policy lock poisoned")
            ))
        ));
        assert!(!guard.is_poisoned());
    }
}
