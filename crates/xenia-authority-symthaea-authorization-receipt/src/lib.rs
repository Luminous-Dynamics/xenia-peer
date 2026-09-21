// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable, crypto-verifier-free authorization receipt for Xenia decisions
//! concerning Symthaea verification-receipt attestations.
//!
//! This crate freezes the bytes a live Xenia daemon may later sign after
//! independently establishing operator signature validity, exact joint
//! enrollment, current policy state, and the v1 Symthaea attestation RBAC rule.
//! It deliberately does not perform those checks itself.
//!
//! A structurally valid or even correctly signed receipt is still not a
//! Symthaea evidence-admission or assurance-qualification decision.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use xenia_operator_proto::OperatorRole;
use xenia_symthaea_attestation_contract::{
    HybridSignatureBundleV1, XeniaHybridSuiteV1,
};
use xenia_symthaea_attestation_authority::SYMTHAEA_RECEIPT_ATTESTATION_SCOPE_V1;
use xenia_symthaea_rbac::SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1;

/// Portable authorization-receipt protocol version.
pub const CURRENT_AUTHORIZATION_RECEIPT_VERSION: u16 = 1;
/// Domain separator for the exact receipt bytes authenticated by the daemon.
pub const AUTHORIZATION_RECEIPT_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-authorization-receipt-v1\0";
/// Fixed audience: these bytes are intended only for Symthaea assurance intake.
pub const AUTHORIZATION_AUDIENCE_V1: &str = "symthaea-assurance";
/// A positive receipt type has exactly one fixed decision label.
pub const AUTHORIZATION_DECISION_V1: &str = "authorized";
/// Maximum offline lifetime of a v1 positive authorization receipt.
pub const MAX_AUTHORIZATION_TTL_SECS_V1: u64 = 5 * 60;
/// Defensive bound for identifier-like strings in the portable receipt.
pub const MAX_IDENTIFIER_BYTES: usize = 4 * 1024;
/// SHA-256 digest size.
pub const SHA256_LEN: usize = 32;

/// A portable Xenia daemon decision about one exact Symthaea receipt
/// attestation.
///
/// Public fields make serialization/interoperability straightforward. Callers
/// must still run [`Self::validate_structure`] and then authenticate the
/// daemon signatures against an independently trusted Xenia daemon identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XeniaSymthaeaAuthorizationReceiptV1 {
    /// Protocol version; exactly 1 for this type.
    pub protocol_version: u16,
    /// RBAC policy version that authorized this decision.
    pub rbac_policy_version: u16,
    /// Fixed intended audience.
    pub audience: String,
    /// Exact Symthaea verification-receipt UUID bytes.
    pub symthaea_receipt_id: [u8; 16],
    /// SHA-256 of exact canonical Symthaea verification-receipt bytes.
    pub symthaea_receipt_digest_sha256: [u8; SHA256_LEN],
    /// Caller-generated nonce binding the response to one authorization request.
    pub request_nonce: [u8; 32],
    /// Stable Xenia operator identity obtained from authoritative enrollment.
    pub operator_id: String,
    /// Canonical role obtained from authoritative Xenia policy state.
    pub operator_role: OperatorRole,
    /// Xenia-derived commitment to the exact jointly enrolled hybrid key pair.
    pub operator_key_lineage_commitment: String,
    /// Exact authority scope authorized by RBAC policy v1.
    pub authority_scope: String,
    /// Commitment to the exact enrollment snapshot used for the decision.
    pub enrollment_commitment_sha256: [u8; SHA256_LEN],
    /// Commitment to the exact authorization policy snapshot used.
    pub policy_commitment_sha256: [u8; SHA256_LEN],
    /// Monotonic daemon authority-state epoch at evaluation time.
    pub authority_state_epoch: u64,
    /// Inclusive start/evaluation time of this decision.
    pub authorized_at_unix_s: u64,
    /// Inclusive expiry; v1 permits at most five minutes of offline reuse.
    pub expires_at_unix_s: u64,
    /// Fingerprint of the Xenia daemon host identity expected to vouch for the
    /// delegated HTTP-auth signing identity.
    pub daemon_host_fingerprint: [u8; SHA256_LEN],
    /// SHA-256 of the exact daemon delegation certificate used by a future
    /// verifier to bind HTTP-auth keys to the host identity.
    pub daemon_delegation_certificate_digest_sha256: [u8; SHA256_LEN],
    /// Commitment to the verifier/runtime artifact that evaluated the decision.
    pub verifier_artifact_commitment_sha256: [u8; SHA256_LEN],
}

impl XeniaSymthaeaAuthorizationReceiptV1 {
    /// Construct a v1 positive receipt. This is structural construction only;
    /// the caller is responsible for having actually established the decision.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symthaea_receipt_id: [u8; 16],
        symthaea_receipt_digest_sha256: [u8; SHA256_LEN],
        request_nonce: [u8; 32],
        operator_id: impl Into<String>,
        operator_role: OperatorRole,
        operator_key_lineage_commitment: impl Into<String>,
        enrollment_commitment_sha256: [u8; SHA256_LEN],
        policy_commitment_sha256: [u8; SHA256_LEN],
        authority_state_epoch: u64,
        authorized_at_unix_s: u64,
        expires_at_unix_s: u64,
        daemon_host_fingerprint: [u8; SHA256_LEN],
        daemon_delegation_certificate_digest_sha256: [u8; SHA256_LEN],
        verifier_artifact_commitment_sha256: [u8; SHA256_LEN],
    ) -> Option<Self> {
        let value = Self {
            protocol_version: CURRENT_AUTHORIZATION_RECEIPT_VERSION,
            rbac_policy_version: SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1,
            audience: AUTHORIZATION_AUDIENCE_V1.to_string(),
            symthaea_receipt_id,
            symthaea_receipt_digest_sha256,
            request_nonce,
            operator_id: operator_id.into(),
            operator_role,
            operator_key_lineage_commitment: operator_key_lineage_commitment.into(),
            authority_scope: SYMTHAEA_RECEIPT_ATTESTATION_SCOPE_V1.to_string(),
            enrollment_commitment_sha256,
            policy_commitment_sha256,
            authority_state_epoch,
            authorized_at_unix_s,
            expires_at_unix_s,
            daemon_host_fingerprint,
            daemon_delegation_certificate_digest_sha256,
            verifier_artifact_commitment_sha256,
        };
        value.validate_structure().then_some(value)
    }

    /// Structural validation only. This does not authenticate the daemon or
    /// establish that the underlying policy/enrollment checks actually ran.
    pub fn validate_structure(&self) -> bool {
        self.protocol_version == CURRENT_AUTHORIZATION_RECEIPT_VERSION
            && self.rbac_policy_version == SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1
            && self.audience == AUTHORIZATION_AUDIENCE_V1
            && self.authority_scope == SYMTHAEA_RECEIPT_ATTESTATION_SCOPE_V1
            && self.operator_role == OperatorRole::Admin
            && bounded_nonempty(&self.operator_id)
            && bounded_nonempty(&self.operator_key_lineage_commitment)
            && self.symthaea_receipt_id != [0; 16]
            && nonzero32(&self.symthaea_receipt_digest_sha256)
            && nonzero32(&self.request_nonce)
            && nonzero32(&self.enrollment_commitment_sha256)
            && nonzero32(&self.policy_commitment_sha256)
            && self.authority_state_epoch > 0
            && self.expires_at_unix_s >= self.authorized_at_unix_s
            && self
                .expires_at_unix_s
                .saturating_sub(self.authorized_at_unix_s)
                <= MAX_AUTHORIZATION_TTL_SECS_V1
            && nonzero32(&self.daemon_host_fingerprint)
            && nonzero32(&self.daemon_delegation_certificate_digest_sha256)
            && nonzero32(&self.verifier_artifact_commitment_sha256)
    }

    /// Whether `now` lies inside this receipt's inclusive validity interval.
    pub fn is_current_at(&self, now_unix_s: u64) -> bool {
        self.validate_structure()
            && self.authorized_at_unix_s <= now_unix_s
            && now_unix_s <= self.expires_at_unix_s
    }

    /// Exact domain-separated bytes the daemon's two signatures must cover.
    pub fn canonical_signing_transcript(&self) -> Option<Vec<u8>> {
        if !self.validate_structure() {
            return None;
        }

        let mut out = Vec::new();
        out.extend_from_slice(AUTHORIZATION_RECEIPT_DOMAIN_V1);
        push_field(
            &mut out,
            "protocol_version",
            &self.protocol_version.to_be_bytes(),
        );
        push_field(
            &mut out,
            "rbac_policy_version",
            &self.rbac_policy_version.to_be_bytes(),
        );
        push_field(&mut out, "decision", AUTHORIZATION_DECISION_V1.as_bytes());
        push_field(&mut out, "audience", self.audience.as_bytes());
        push_field(&mut out, "symthaea_receipt_id", &self.symthaea_receipt_id);
        push_field(
            &mut out,
            "symthaea_receipt_digest_sha256",
            &self.symthaea_receipt_digest_sha256,
        );
        push_field(&mut out, "request_nonce", &self.request_nonce);
        push_field(&mut out, "operator_id", self.operator_id.as_bytes());
        push_field(
            &mut out,
            "operator_role",
            self.operator_role.as_str().as_bytes(),
        );
        push_field(
            &mut out,
            "operator_key_lineage_commitment",
            self.operator_key_lineage_commitment.as_bytes(),
        );
        push_field(
            &mut out,
            "authority_scope",
            self.authority_scope.as_bytes(),
        );
        push_field(
            &mut out,
            "enrollment_commitment_sha256",
            &self.enrollment_commitment_sha256,
        );
        push_field(
            &mut out,
            "policy_commitment_sha256",
            &self.policy_commitment_sha256,
        );
        push_field(
            &mut out,
            "authority_state_epoch",
            &self.authority_state_epoch.to_be_bytes(),
        );
        push_field(
            &mut out,
            "authorized_at_unix_s",
            &self.authorized_at_unix_s.to_be_bytes(),
        );
        push_field(
            &mut out,
            "expires_at_unix_s",
            &self.expires_at_unix_s.to_be_bytes(),
        );
        push_field(
            &mut out,
            "daemon_host_fingerprint",
            &self.daemon_host_fingerprint,
        );
        push_field(
            &mut out,
            "daemon_delegation_certificate_digest_sha256",
            &self.daemon_delegation_certificate_digest_sha256,
        );
        push_field(
            &mut out,
            "verifier_artifact_commitment_sha256",
            &self.verifier_artifact_commitment_sha256,
        );
        Some(out)
    }

    /// SHA-256 commitment to the exact canonical signing transcript.
    pub fn transcript_sha256(&self) -> Option<[u8; SHA256_LEN]> {
        self.canonical_signing_transcript()
            .map(|bytes| Sha256::digest(bytes).into())
    }
}

/// Portable hybrid-signed positive authorization receipt. Signature
/// verification belongs to a later Xenia verifier tranche.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedXeniaSymthaeaAuthorizationReceiptV1 {
    /// Positive authorization receipt body.
    pub receipt: XeniaSymthaeaAuthorizationReceiptV1,
    /// Exact v1 hybrid suite; both signatures are mandatory.
    pub suite: XeniaHybridSuiteV1,
    /// Ed25519 + ML-DSA-65 signatures over `receipt.canonical_signing_transcript()`.
    pub signatures: HybridSignatureBundleV1,
}

impl SignedXeniaSymthaeaAuthorizationReceiptV1 {
    /// Structural validation only; no signature verification occurs here.
    pub fn validate_structure(&self) -> bool {
        self.receipt.validate_structure()
            && self.suite == XeniaHybridSuiteV1::Ed25519MlDsa65V1
            && self.signatures.validate_structure()
    }
}

fn bounded_nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_IDENTIFIER_BYTES
}

fn nonzero32(value: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn push_field(out: &mut Vec<u8>, label: &str, value: &[u8]) {
    let label_len = u16::try_from(label.len()).expect("static label length fits u16");
    let value_len = u32::try_from(value.len()).expect("validated value length fits u32");
    out.extend_from_slice(&label_len.to_be_bytes());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_symthaea_attestation_contract::{
        ED25519_SIGNATURE_LEN, ML_DSA_65_SIGNATURE_LEN,
    };

    fn receipt() -> XeniaSymthaeaAuthorizationReceiptV1 {
        XeniaSymthaeaAuthorizationReceiptV1::new(
            [0x11; 16],
            hex32("ce4c2c8873da8c165ad2e60941836c1f92c5cab3d930c83f3761a85de120f6dc"),
            [0x22; 32],
            "operator:alice",
            OperatorRole::Admin,
            "sha256:lineage",
            [0x33; 32],
            [0x44; 32],
            7,
            1000,
            1200,
            [0x55; 32],
            [0x66; 32],
            [0x77; 32],
        )
        .unwrap()
    }

    fn signatures() -> HybridSignatureBundleV1 {
        HybridSignatureBundleV1 {
            ed25519: [0x88; ED25519_SIGNATURE_LEN],
            ml_dsa_65: vec![0x99; ML_DSA_65_SIGNATURE_LEN],
        }
    }

    fn hex32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut out = [0u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let hi = from_hex(chunk[0]);
            let lo = from_hex(chunk[1]);
            out[index] = (hi << 4) | lo;
        }
        out
    }

    fn from_hex(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex fixture"),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn frozen_authorization_receipt_vector_is_stable() {
        assert_eq!(
            hex(&receipt().transcript_sha256().unwrap()),
            "0278942172d6d7cd8f95bd7f2e8e314645d9dc9bf8dc2d8c4ed4b843613e4a71"
        );
    }

    #[test]
    fn v1_is_admin_only_and_scope_audience_are_fixed() {
        let value = receipt();
        assert_eq!(value.operator_role, OperatorRole::Admin);
        assert_eq!(value.rbac_policy_version, 1);
        assert_eq!(value.authority_scope, SYMTHAEA_RECEIPT_ATTESTATION_SCOPE_V1);
        assert_eq!(value.audience, AUTHORIZATION_AUDIENCE_V1);

        let mut lower_role = value.clone();
        lower_role.operator_role = OperatorRole::Operator;
        assert!(!lower_role.validate_structure());
    }

    #[test]
    fn ttl_is_bounded_and_time_interval_is_inclusive() {
        let mut value = receipt();
        value.authorized_at_unix_s = 1000;
        value.expires_at_unix_s = 1300;
        assert!(value.validate_structure());
        assert!(value.is_current_at(1000));
        assert!(value.is_current_at(1300));
        assert!(!value.is_current_at(999));
        assert!(!value.is_current_at(1301));

        value.expires_at_unix_s = 1301;
        assert!(!value.validate_structure());
    }

    #[test]
    fn all_security_relevant_substitutions_change_signed_bytes() {
        let baseline = receipt().canonical_signing_transcript().unwrap();

        let mut cases = Vec::new();
        let mut v = receipt();
        v.symthaea_receipt_digest_sha256[0] ^= 1;
        cases.push(v);
        let mut v = receipt();
        v.request_nonce[0] ^= 1;
        cases.push(v);
        let mut v = receipt();
        v.operator_id = "operator:bob".into();
        cases.push(v);
        let mut v = receipt();
        v.operator_key_lineage_commitment = "sha256:rotated".into();
        cases.push(v);
        let mut v = receipt();
        v.enrollment_commitment_sha256[0] ^= 1;
        cases.push(v);
        let mut v = receipt();
        v.policy_commitment_sha256[0] ^= 1;
        cases.push(v);
        let mut v = receipt();
        v.authority_state_epoch += 1;
        cases.push(v);
        let mut v = receipt();
        v.daemon_host_fingerprint[0] ^= 1;
        cases.push(v);
        let mut v = receipt();
        v.daemon_delegation_certificate_digest_sha256[0] ^= 1;
        cases.push(v);
        let mut v = receipt();
        v.verifier_artifact_commitment_sha256[0] ^= 1;
        cases.push(v);

        for changed in cases {
            assert_ne!(baseline, changed.canonical_signing_transcript().unwrap());
        }
    }

    #[test]
    fn signature_outputs_do_not_change_signed_message() {
        let a = SignedXeniaSymthaeaAuthorizationReceiptV1 {
            receipt: receipt(),
            suite: XeniaHybridSuiteV1::Ed25519MlDsa65V1,
            signatures: signatures(),
        };
        let mut b = a.clone();
        b.signatures.ed25519[0] ^= 1;
        b.signatures.ml_dsa_65[0] ^= 1;
        assert_ne!(a.signatures, b.signatures);
        assert_eq!(
            a.receipt.canonical_signing_transcript().unwrap(),
            b.receipt.canonical_signing_transcript().unwrap()
        );
    }

    #[test]
    fn zero_or_unbounded_authority_inputs_fail_closed() {
        let mut value = receipt();
        value.request_nonce = [0; 32];
        assert!(!value.validate_structure());

        let mut value = receipt();
        value.policy_commitment_sha256 = [0; 32];
        assert!(!value.validate_structure());

        let mut value = receipt();
        value.authority_state_epoch = 0;
        assert!(!value.validate_structure());

        let mut value = receipt();
        value.operator_id = "x".repeat(MAX_IDENTIFIER_BYTES + 1);
        assert!(!value.validate_structure());
    }
}
