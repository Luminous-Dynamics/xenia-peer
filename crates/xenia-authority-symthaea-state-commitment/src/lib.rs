// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical commitments for the effective Xenia authority state relevant to
//! Symthaea verification-receipt attestation.
//!
//! These types deliberately describe only the v1 authority domain: operator
//! id, Ed25519 + ML-DSA-65 enrollment pair, canonical role, the D0 RBAC policy
//! version, and effective revoked operator ids. ML-DSA-87 is intentionally not
//! represented because it does not participate in v1 Symthaea attestation
//! authority.
//!
//! This crate freezes bytes only. A live daemon adapter must build these values
//! from one coherent authoritative state snapshot; caller-created values are
//! not authority merely because their commitments are well formed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest as _, Sha256};
use xenia_handshake::ML_DSA_65_PK_LEN;
use xenia_operator_proto::OperatorRole;
use xenia_symthaea_rbac::SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1;

/// Domain separator for one exact operator enrollment commitment.
pub const ENROLLMENT_COMMITMENT_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-enrollment-commitment-v1\0";
/// Domain separator for the effective authority-policy commitment.
pub const EFFECTIVE_POLICY_COMMITMENT_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-effective-policy-commitment-v1\0";
/// SHA-256 output size.
pub const SHA256_LEN: usize = 32;
/// Maximum operator-id size accepted by the portable contract.
pub const MAX_OPERATOR_ID_BYTES: usize = 4 * 1024;

/// Canonical v1 enrollment identity relevant to Symthaea attestation authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymthaeaEnrollmentCommitmentInputV1 {
    /// Stable Xenia operator id.
    pub operator_id: String,
    /// Exact enrolled Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Exact enrolled ML-DSA-65 public key.
    pub ml_dsa_65_pubkey: Vec<u8>,
    /// Authoritative Xenia role.
    pub role: OperatorRole,
}

impl SymthaeaEnrollmentCommitmentInputV1 {
    /// Structural validity for the canonical commitment input.
    pub fn validate_structure(&self) -> bool {
        bounded_nonempty(&self.operator_id) && self.ml_dsa_65_pubkey.len() == ML_DSA_65_PK_LEN
    }

    /// Exact canonical bytes for this enrollment identity.
    pub fn canonical_bytes(&self) -> Option<Vec<u8>> {
        if !self.validate_structure() {
            return None;
        }
        let mut out = Vec::new();
        out.extend_from_slice(ENROLLMENT_COMMITMENT_DOMAIN_V1);
        push_field(&mut out, "operator_id", self.operator_id.as_bytes());
        push_field(&mut out, "ed25519_pubkey", &self.ed25519_pubkey);
        push_field(&mut out, "ml_dsa_65_pubkey", &self.ml_dsa_65_pubkey);
        push_field(&mut out, "operator_role", self.role.as_str().as_bytes());
        Some(out)
    }

    /// SHA-256 of the exact canonical enrollment bytes.
    pub fn sha256(&self) -> Option<[u8; SHA256_LEN]> {
        self.canonical_bytes()
            .map(|bytes| Sha256::digest(bytes).into())
    }
}

/// Canonical effective-policy input for the v1 Symthaea authority domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveSymthaeaPolicyCommitmentInputV1 {
    /// D0 RBAC policy version represented by this snapshot.
    pub rbac_policy_version: u16,
    /// Relevant active enrollment identities. Input order is non-semantic.
    pub enrollments: Vec<SymthaeaEnrollmentCommitmentInputV1>,
    /// Effective revoked operator ids. Input order is non-semantic.
    pub revoked_operator_ids: Vec<String>,
}

impl EffectiveSymthaeaPolicyCommitmentInputV1 {
    /// Structural validity, including fail-closed uniqueness rules.
    pub fn validate_structure(&self) -> bool {
        if self.rbac_policy_version != SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1 {
            return false;
        }
        if self
            .enrollments
            .iter()
            .any(|enrollment| !enrollment.validate_structure())
        {
            return false;
        }
        if self
            .revoked_operator_ids
            .iter()
            .any(|operator_id| !bounded_nonempty(operator_id))
        {
            return false;
        }

        // Current Xenia semantics require one stable operator id and one
        // Ed25519 enrollment root per active enrollment. Ambiguous duplicates
        // fail closed instead of being silently de-duplicated by canonicalization.
        for (index, enrollment) in self.enrollments.iter().enumerate() {
            for other in &self.enrollments[..index] {
                if enrollment.operator_id == other.operator_id
                    || enrollment.ed25519_pubkey == other.ed25519_pubkey
                {
                    return false;
                }
            }
        }
        for (index, operator_id) in self.revoked_operator_ids.iter().enumerate() {
            if self.revoked_operator_ids[..index].contains(operator_id) {
                return false;
            }
        }
        true
    }

    /// Exact deterministic bytes for the effective v1 policy state.
    ///
    /// Enrollment and revocation sets are sorted by their canonical bytes, so
    /// `HashMap`/`HashSet` iteration order and config-file ordering cannot
    /// alter the commitment.
    pub fn canonical_bytes(&self) -> Option<Vec<u8>> {
        if !self.validate_structure() {
            return None;
        }

        let mut enrollment_bytes = self
            .enrollments
            .iter()
            .map(SymthaeaEnrollmentCommitmentInputV1::canonical_bytes)
            .collect::<Option<Vec<_>>>()?;
        enrollment_bytes.sort();

        let mut revoked = self
            .revoked_operator_ids
            .iter()
            .map(|id| id.as_bytes().to_vec())
            .collect::<Vec<_>>();
        revoked.sort();

        let mut out = Vec::new();
        out.extend_from_slice(EFFECTIVE_POLICY_COMMITMENT_DOMAIN_V1);
        push_field(
            &mut out,
            "rbac_policy_version",
            &self.rbac_policy_version.to_be_bytes(),
        );
        push_field(
            &mut out,
            "enrollment_count",
            &u32::try_from(enrollment_bytes.len()).ok()?.to_be_bytes(),
        );
        for enrollment in enrollment_bytes {
            push_field(&mut out, "enrollment", &enrollment);
        }
        push_field(
            &mut out,
            "revoked_count",
            &u32::try_from(revoked.len()).ok()?.to_be_bytes(),
        );
        for operator_id in revoked {
            push_field(&mut out, "revoked_operator_id", &operator_id);
        }
        Some(out)
    }

    /// SHA-256 of the exact canonical effective-policy bytes.
    pub fn sha256(&self) -> Option<[u8; SHA256_LEN]> {
        self.canonical_bytes()
            .map(|bytes| Sha256::digest(bytes).into())
    }
}

fn bounded_nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_OPERATOR_ID_BYTES
}

fn push_field(out: &mut Vec<u8>, label: &str, value: &[u8]) {
    let label_len = u16::try_from(label.len()).expect("static label length fits u16");
    let value_len = u32::try_from(value.len()).expect("validated field length fits u32");
    out.extend_from_slice(&label_len.to_be_bytes());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> SymthaeaEnrollmentCommitmentInputV1 {
        SymthaeaEnrollmentCommitmentInputV1 {
            operator_id: "alice".into(),
            ed25519_pubkey: [0x11; 32],
            ml_dsa_65_pubkey: vec![0x22; ML_DSA_65_PK_LEN],
            role: OperatorRole::Admin,
        }
    }

    fn bob() -> SymthaeaEnrollmentCommitmentInputV1 {
        SymthaeaEnrollmentCommitmentInputV1 {
            operator_id: "bob".into(),
            ed25519_pubkey: [0x33; 32],
            ml_dsa_65_pubkey: vec![0x44; ML_DSA_65_PK_LEN],
            role: OperatorRole::Viewer,
        }
    }

    fn policy() -> EffectiveSymthaeaPolicyCommitmentInputV1 {
        EffectiveSymthaeaPolicyCommitmentInputV1 {
            rbac_policy_version: SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1,
            enrollments: vec![bob(), alice()],
            revoked_operator_ids: vec!["carol".into()],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn frozen_enrollment_vector_is_stable() {
        assert_eq!(
            hex(&alice().sha256().unwrap()),
            "3ed22b6d76b0bf45bfeec77d7c9bcef2a2941c00671e46cc86fe7c82f77920ab"
        );
    }

    #[test]
    fn frozen_effective_policy_vector_is_stable() {
        assert_eq!(
            hex(&policy().sha256().unwrap()),
            "5dd38332b3997db286076a5e2e153961448873fb7af47bb811c0a6e0ce486452"
        );
    }

    #[test]
    fn set_order_is_not_semantic() {
        let a = policy();
        let mut b = policy();
        b.enrollments.reverse();
        b.revoked_operator_ids = vec!["zeta".into(), "carol".into()];

        let mut c = policy();
        c.revoked_operator_ids = vec!["carol".into(), "zeta".into()];

        assert_eq!(b.sha256(), c.sha256());
        assert_ne!(a.sha256(), b.sha256());
    }

    #[test]
    fn role_key_and_revocation_changes_are_commitment_visible() {
        let baseline_enrollment = alice().sha256();
        let baseline_policy = policy().sha256();

        let mut changed_role = alice();
        changed_role.role = OperatorRole::Operator;
        assert_ne!(baseline_enrollment, changed_role.sha256());

        let mut changed_key = alice();
        changed_key.ml_dsa_65_pubkey[0] ^= 1;
        assert_ne!(baseline_enrollment, changed_key.sha256());

        let mut changed_policy = policy();
        changed_policy.revoked_operator_ids.push("alice".into());
        assert_ne!(baseline_policy, changed_policy.sha256());
    }

    #[test]
    fn duplicate_ids_keys_and_revocations_fail_closed() {
        let mut duplicate_id = policy();
        let mut second_alice = bob();
        second_alice.operator_id = "alice".into();
        duplicate_id.enrollments.push(second_alice);
        assert!(!duplicate_id.validate_structure());
        assert!(duplicate_id.sha256().is_none());

        let mut duplicate_key = policy();
        let mut other = bob();
        other.operator_id = "dave".into();
        other.ed25519_pubkey = alice().ed25519_pubkey;
        duplicate_key.enrollments.push(other);
        assert!(!duplicate_key.validate_structure());

        let mut duplicate_revocation = policy();
        duplicate_revocation.revoked_operator_ids.push("carol".into());
        assert!(!duplicate_revocation.validate_structure());
    }

    #[test]
    fn malformed_key_and_wrong_policy_version_fail_closed() {
        let mut malformed = alice();
        malformed.ml_dsa_65_pubkey.pop();
        assert!(!malformed.validate_structure());
        assert!(malformed.sha256().is_none());

        let mut wrong_version = policy();
        wrong_version.rbac_policy_version += 1;
        assert!(!wrong_version.validate_structure());
    }
}
