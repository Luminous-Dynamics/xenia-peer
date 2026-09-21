// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable Xenia-daemon authorization receipt for Symthaea attestations.
//!
//! This crate freezes the exact bytes a future Xenia daemon signer/verifier
//! must authenticate after upstream layers have established the exact Symthaea
//! receipt, hybrid operator identity, current joint enrollment, and RBAC scope.
//!
//! Structural validity is deliberately weaker than authenticated authority:
//! parsing this type or observing signature-shaped bytes does not prove that a
//! trusted Xenia daemon issued the decision.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use xenia_symthaea_attestation_contract::{
    HybridSignatureBundleV1, ReceiptDigestV1, XeniaHybridSuiteV1,
};

/// Portable daemon-authorization receipt schema version.
pub const XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1: u16 = 1;
/// Domain separator for the exact bytes authenticated by both daemon signatures.
pub const XENIA_SYMTHAEA_DAEMON_RECEIPT_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-authorization-receipt-v1\0";
/// RBAC policy version bound into v1 receipts.
pub const XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1: u16 = 1;
/// Maximum lifetime of a portable v1 daemon authority decision.
pub const MAX_DAEMON_AUTHORIZATION_RECEIPT_TTL_SECS_V1: u64 = 300;
/// Defensive bound for portable logical identifiers.
pub const MAX_DAEMON_AUTHORIZATION_STRING_BYTES_V1: usize = 4 * 1024;

/// Portable authority scope spelling frozen by the v1 daemon receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortableSymthaeaAuthorityScopeV1 {
    /// Authority to attest one Symthaea verification receipt.
    VerificationReceiptAttestationV1,
}

impl PortableSymthaeaAuthorityScopeV1 {
    /// Stable scope identifier shared with XENIA-SYM-001C/D0.
    pub const fn id(self) -> &'static str {
        match self {
            Self::VerificationReceiptAttestationV1 => {
                "attest:symthaea-verification-receipt:v1"
            }
        }
    }
}

/// Exact portable authorization decision a Xenia daemon may sign.
///
/// This value is data only. It becomes authenticated authority only after a
/// later verifier establishes both daemon signatures and authenticates the
/// daemon signing identity back to the expected host identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XeniaSymthaeaDaemonAuthorizationDecisionV1 {
    /// Receipt schema version.
    pub schema_version: u16,
    /// Fresh daemon-generated nonce for replay/idempotency tracking.
    pub decision_nonce: [u8; 32],
    /// Exact Symthaea verification-receipt UUID bytes.
    pub receipt_id: [u8; 16],
    /// Exact SHA-256 digest of canonical Symthaea receipt bytes.
    pub receipt_digest: ReceiptDigestV1,
    /// Authoritative Xenia enrollment-record identifier used for the decision.
    pub enrollment_id: String,
    /// Stable logical operator/signer identity.
    pub signer_id: String,
    /// Xenia-derived commitment to the exact jointly enrolled hybrid key pair.
    pub key_lineage_commitment: String,
    /// Exact authority scope established by policy.
    pub authority_scope: PortableSymthaeaAuthorityScopeV1,
    /// Version of the Xenia→Symthaea RBAC mapping used for this decision.
    pub rbac_policy_version: u16,
    /// Fingerprint of the daemon host identity to which the issuer is bound.
    pub daemon_host_fingerprint: [u8; 32],
    /// Time at which Xenia evaluated authorization.
    pub issued_unix_s: u64,
    /// Mandatory inclusive expiry for this portable authorization receipt.
    pub valid_until_unix_s: u64,
    /// Exact hybrid signature suite required over the canonical decision bytes.
    pub suite: XeniaHybridSuiteV1,
}

impl XeniaSymthaeaDaemonAuthorizationDecisionV1 {
    /// Structural validation only; no signature or daemon trust verification.
    pub fn validate_structure(&self) -> bool {
        self.schema_version == XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1
            && self.decision_nonce != [0; 32]
            && self.receipt_id != [0; 16]
            && self.daemon_host_fingerprint != [0; 32]
            && bounded_nonempty(&self.enrollment_id)
            && bounded_nonempty(&self.signer_id)
            && bounded_nonempty(&self.key_lineage_commitment)
            && self.rbac_policy_version == XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1
            && self.valid_until_unix_s >= self.issued_unix_s
            && self
                .valid_until_unix_s
                .checked_sub(self.issued_unix_s)
                .is_some_and(|ttl| ttl <= MAX_DAEMON_AUTHORIZATION_RECEIPT_TTL_SECS_V1)
            && self.suite == XeniaHybridSuiteV1::Ed25519MlDsa65V1
    }

    /// Whether the decision has not started yet at `now_unix_s`.
    pub fn is_not_yet_valid_at(&self, now_unix_s: u64) -> bool {
        now_unix_s < self.issued_unix_s
    }

    /// Whether the decision has expired at `now_unix_s`.
    pub fn is_expired_at(&self, now_unix_s: u64) -> bool {
        now_unix_s > self.valid_until_unix_s
    }

    /// Check exact binding to one Symthaea receipt id + canonical digest.
    pub fn matches_symthaea_receipt(
        &self,
        receipt_id: &[u8; 16],
        receipt_digest: &ReceiptDigestV1,
    ) -> bool {
        self.validate_structure()
            && &self.receipt_id == receipt_id
            && &self.receipt_digest == receipt_digest
    }

    /// Deterministic, domain-separated bytes both daemon signatures authenticate.
    ///
    /// Signature bytes are intentionally excluded because they are outputs over
    /// this transcript rather than inputs to it.
    pub fn canonical_signing_transcript(&self) -> Option<Vec<u8>> {
        if !self.validate_structure() {
            return None;
        }

        let mut out = Vec::new();
        out.extend_from_slice(XENIA_SYMTHAEA_DAEMON_RECEIPT_DOMAIN_V1);
        push_field(&mut out, "schema_version", &self.schema_version.to_be_bytes());
        push_field(&mut out, "decision_nonce", &self.decision_nonce);
        push_field(&mut out, "receipt_id", &self.receipt_id);
        push_field(
            &mut out,
            "receipt_digest.algorithm",
            self.receipt_digest.algorithm.id().as_bytes(),
        );
        push_field(
            &mut out,
            "receipt_digest.bytes",
            &self.receipt_digest.bytes,
        );
        push_field(&mut out, "enrollment_id", self.enrollment_id.as_bytes());
        push_field(&mut out, "signer_id", self.signer_id.as_bytes());
        push_field(
            &mut out,
            "key_lineage_commitment",
            self.key_lineage_commitment.as_bytes(),
        );
        push_field(
            &mut out,
            "authority_scope",
            self.authority_scope.id().as_bytes(),
        );
        push_field(
            &mut out,
            "rbac_policy_version",
            &self.rbac_policy_version.to_be_bytes(),
        );
        push_field(
            &mut out,
            "daemon_host_fingerprint",
            &self.daemon_host_fingerprint,
        );
        push_field(
            &mut out,
            "issued_unix_s",
            &self.issued_unix_s.to_be_bytes(),
        );
        push_field(
            &mut out,
            "valid_until_unix_s",
            &self.valid_until_unix_s.to_be_bytes(),
        );
        push_field(&mut out, "suite", self.suite.id().as_bytes());
        Some(out)
    }

    /// SHA-256 of the exact canonical signing transcript, useful for evidence
    /// manifests and frozen cross-component vectors.
    pub fn canonical_transcript_sha256(&self) -> Option<[u8; 32]> {
        self.canonical_signing_transcript()
            .map(|bytes| Sha256::digest(bytes).into())
    }
}

/// Portable decision plus exact two-signature daemon output.
///
/// Presence of this envelope is not itself proof that either signature is
/// cryptographically valid or that the signing keys belong to the expected
/// Xenia daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
    /// Exact daemon decision whose canonical bytes were signed.
    pub decision: XeniaSymthaeaDaemonAuthorizationDecisionV1,
    /// Ed25519 + ML-DSA-65 signatures over the same canonical decision bytes.
    pub signatures: HybridSignatureBundleV1,
}

impl SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
    /// Structural validation only; no cryptographic or trust-root claim.
    pub fn validate_structure(&self) -> bool {
        self.decision.validate_structure() && self.signatures.validate_structure()
    }

    /// Canonical message authenticated by the two signatures.
    pub fn canonical_signing_transcript(&self) -> Option<Vec<u8>> {
        if !self.validate_structure() {
            return None;
        }
        self.decision.canonical_signing_transcript()
    }
}

fn bounded_nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_DAEMON_AUTHORIZATION_STRING_BYTES_V1
}

fn push_field(out: &mut Vec<u8>, label: &str, value: &[u8]) {
    let label_len = u16::try_from(label.len()).expect("static transcript label fits u16");
    let value_len = u32::try_from(value.len()).expect("validated transcript field fits u32");
    out.extend_from_slice(&label_len.to_be_bytes());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_symthaea_attestation_contract::{
        DigestAlgorithmV1, ED25519_SIGNATURE_LEN, ML_DSA_65_SIGNATURE_LEN,
    };

    const FROZEN_TRANSCRIPT_SHA256: &str =
        "99bc3a54e0d1a1feb16fbe4cd279ef0207acea591751a9d0eafc1bf39ff29a5e";

    fn decision() -> XeniaSymthaeaDaemonAuthorizationDecisionV1 {
        XeniaSymthaeaDaemonAuthorizationDecisionV1 {
            schema_version: XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1,
            decision_nonce: [0xA1; 32],
            receipt_id: [0x11; 16],
            receipt_digest: ReceiptDigestV1 {
                algorithm: DigestAlgorithmV1::Sha256,
                bytes: [0x22; 32],
            },
            enrollment_id: "enrollment:alice:v1".into(),
            signer_id: "operator:alice".into(),
            key_lineage_commitment: "sha256:lineage".into(),
            authority_scope: PortableSymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
            rbac_policy_version: XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1,
            daemon_host_fingerprint: [0x33; 32],
            issued_unix_s: 100,
            valid_until_unix_s: 200,
            suite: XeniaHybridSuiteV1::Ed25519MlDsa65V1,
        }
    }

    fn signed() -> SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
        SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
            decision: decision(),
            signatures: HybridSignatureBundleV1 {
                ed25519: [0x44; ED25519_SIGNATURE_LEN],
                ml_dsa_65: vec![0x55; ML_DSA_65_SIGNATURE_LEN],
            },
        }
    }

    #[test]
    fn frozen_canonical_vector_is_stable() {
        let value = decision();
        assert!(value.validate_structure());
        let digest = value.canonical_transcript_sha256().unwrap();
        let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual, FROZEN_TRANSCRIPT_SHA256);
    }

    #[test]
    fn portable_receipt_always_has_a_short_lived_expiry() {
        let mut value = decision();
        value.valid_until_unix_s =
            value.issued_unix_s + MAX_DAEMON_AUTHORIZATION_RECEIPT_TTL_SECS_V1;
        assert!(value.validate_structure());

        value.valid_until_unix_s += 1;
        assert!(!value.validate_structure());

        value.valid_until_unix_s = value.issued_unix_s - 1;
        assert!(!value.validate_structure());
    }

    #[test]
    fn validity_boundaries_are_inclusive() {
        let value = decision();
        assert!(!value.is_not_yet_valid_at(100));
        assert!(!value.is_expired_at(200));
        assert!(value.is_not_yet_valid_at(99));
        assert!(value.is_expired_at(201));
    }

    #[test]
    fn zero_identity_or_replay_fields_fail_closed() {
        let mut value = decision();
        value.decision_nonce = [0; 32];
        assert!(!value.validate_structure());

        let mut value = decision();
        value.receipt_id = [0; 16];
        assert!(!value.validate_structure());

        let mut value = decision();
        value.daemon_host_fingerprint = [0; 32];
        assert!(!value.validate_structure());
    }

    #[test]
    fn receipt_substitution_breaks_exact_binding() {
        let value = decision();
        assert!(value.matches_symthaea_receipt(&[0x11; 16], &value.receipt_digest));
        assert!(!value.matches_symthaea_receipt(&[0x12; 16], &value.receipt_digest));

        let mut other_digest = value.receipt_digest.clone();
        other_digest.bytes[0] ^= 1;
        assert!(!value.matches_symthaea_receipt(&[0x11; 16], &other_digest));
    }

    #[test]
    fn authority_metadata_substitution_changes_signed_bytes() {
        let base = decision().canonical_signing_transcript().unwrap();

        let mut changed = decision();
        changed.signer_id = "operator:bob".into();
        assert_ne!(base, changed.canonical_signing_transcript().unwrap());

        let mut changed = decision();
        changed.key_lineage_commitment = "sha256:rotated".into();
        assert_ne!(base, changed.canonical_signing_transcript().unwrap());

        let mut changed = decision();
        changed.daemon_host_fingerprint = [0x34; 32];
        assert_ne!(base, changed.canonical_signing_transcript().unwrap());

        let mut changed = decision();
        changed.decision_nonce = [0xA2; 32];
        assert_ne!(base, changed.canonical_signing_transcript().unwrap());
    }

    #[test]
    fn signature_replacement_does_not_change_message_being_signed() {
        let mut value = signed();
        let before = value.canonical_signing_transcript().unwrap();
        value.signatures.ed25519[0] ^= 1;
        value.signatures.ml_dsa_65[0] ^= 1;
        assert_eq!(before, value.canonical_signing_transcript().unwrap());
    }

    #[test]
    fn malformed_signature_bundle_fails_structurally() {
        let mut value = signed();
        value.signatures.ml_dsa_65.pop();
        assert!(!value.validate_structure());
        assert!(value.canonical_signing_transcript().is_none());
    }

    #[test]
    fn unsupported_scope_fails_closed_during_deserialization() {
        let json = serde_json::json!({
            "schema_version": 1,
            "decision_nonce": vec![1; 32],
            "receipt_id": vec![1; 16],
            "receipt_digest": {"algorithm": "sha256", "bytes": vec![2; 32]},
            "enrollment_id": "enrollment:alice:v1",
            "signer_id": "operator:alice",
            "key_lineage_commitment": "sha256:lineage",
            "authority_scope": "UnknownScopeV9",
            "rbac_policy_version": 1,
            "daemon_host_fingerprint": vec![3; 32],
            "issued_unix_s": 100,
            "valid_until_unix_s": 200,
            "suite": "Ed25519MlDsa65V1"
        });
        assert!(
            serde_json::from_value::<XeniaSymthaeaDaemonAuthorizationDecisionV1>(json).is_err()
        );
    }
}
