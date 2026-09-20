// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable byte contract for Symthaea verification-receipt attestations.
//!
//! This crate intentionally duplicates the SEC-002F canonical transcript rules
//! without depending on the Symthaea repository. Byte equality is established
//! by frozen cross-repository vectors. Real signature verification, current
//! enrollment binding, and authorization are later Xenia tranches.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Current portable attestation protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;
/// Symthaea verification-receipt schema version consumed by this contract.
pub const SYMTHAEA_RECEIPT_SCHEMA_VERSION: u16 = 1;
/// Domain separator for the exact bytes both hybrid signatures authenticate.
pub const ATTESTATION_TRANSCRIPT_DOMAIN_V1: &[u8] =
    b"symthaea-verification-receipt-attestation-v1\0";
/// SHA-256 digest size.
pub const SHA256_LEN: usize = 32;
/// Ed25519 signature size (RFC 8032).
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-65 signature size (FIPS 204 / Xenia implementation).
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// Maximum canonical identifier/namespace length accepted by v1.
pub const MAX_IDENTIFIER_BYTES: usize = 4 * 1024;

/// Digest algorithm fixed by v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestAlgorithmV1 {
    /// SHA-256.
    #[serde(rename = "sha256")]
    Sha256,
}

impl DigestAlgorithmV1 {
    /// Stable wire identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }
}

/// Algorithm-qualified digest of exact canonical Symthaea receipt bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptDigestV1 {
    /// Digest algorithm.
    pub algorithm: DigestAlgorithmV1,
    /// Raw SHA-256 bytes.
    pub bytes: [u8; SHA256_LEN],
}

impl ReceiptDigestV1 {
    /// Hash exact canonical receipt bytes.
    pub fn of_canonical_receipt(bytes: &[u8]) -> Self {
        Self {
            algorithm: DigestAlgorithmV1::Sha256,
            bytes: Sha256::digest(bytes).into(),
        }
    }
}

/// Hybrid signature suite fixed by v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XeniaHybridSuiteV1 {
    /// Ed25519 and ML-DSA-65 must both verify over the same transcript.
    Ed25519MlDsa65V1,
}

impl XeniaHybridSuiteV1 {
    /// Stable wire spelling, intentionally byte-identical to Symthaea SEC-002F.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Ed25519MlDsa65V1 => "Ed25519MlDsa65V1",
        }
    }
}

/// Exact two-signature bundle for the v1 hybrid suite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignatureBundleV1 {
    /// Ed25519 signature bytes.
    pub ed25519: [u8; ED25519_SIGNATURE_LEN],
    /// ML-DSA-65 signature bytes.
    pub ml_dsa_65: Vec<u8>,
}

impl HybridSignatureBundleV1 {
    /// Structural validation only; no signature verification occurs here.
    pub fn validate_structure(&self) -> bool {
        self.ml_dsa_65.len() == ML_DSA_65_SIGNATURE_LEN
    }
}

/// Portable mirror of Symthaea's SEC-002F attestation contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymthaeaReceiptAttestationV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Symthaea receipt schema version.
    pub receipt_schema_version: u16,
    /// Exact Symthaea receipt UUID bytes.
    pub receipt_id: [u8; 16],
    /// SHA-256 of exact canonical Symthaea receipt bytes.
    pub payload_digest: ReceiptDigestV1,
    /// Authority-provider namespace.
    pub provider_namespace: String,
    /// Stable logical signer identity.
    pub signer_id: String,
    /// Current key-lineage identifier/commitment.
    pub key_lineage_commitment: String,
    /// Exact hybrid signature suite.
    pub suite: XeniaHybridSuiteV1,
    /// Signature outputs over `canonical_signing_transcript()`.
    pub signatures: HybridSignatureBundleV1,
}

impl SymthaeaReceiptAttestationV1 {
    /// Construct a portable attestation bound to exact canonical receipt bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        canonical_receipt_bytes: &[u8],
        receipt_schema_version: u16,
        receipt_id: [u8; 16],
        provider_namespace: impl Into<String>,
        signer_id: impl Into<String>,
        key_lineage_commitment: impl Into<String>,
        suite: XeniaHybridSuiteV1,
        signatures: HybridSignatureBundleV1,
    ) -> Option<Self> {
        let value = Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            receipt_schema_version,
            receipt_id,
            payload_digest: ReceiptDigestV1::of_canonical_receipt(canonical_receipt_bytes),
            provider_namespace: provider_namespace.into(),
            signer_id: signer_id.into(),
            key_lineage_commitment: key_lineage_commitment.into(),
            suite,
            signatures,
        };
        value.validate_structure().then_some(value)
    }

    /// Structural validation only; no cryptographic or authorization claim.
    pub fn validate_structure(&self) -> bool {
        self.protocol_version == CURRENT_PROTOCOL_VERSION
            && self.receipt_schema_version == SYMTHAEA_RECEIPT_SCHEMA_VERSION
            && self.receipt_id != [0; 16]
            && bounded_nonempty(&self.provider_namespace)
            && bounded_nonempty(&self.signer_id)
            && bounded_nonempty(&self.key_lineage_commitment)
            && self.signatures.validate_structure()
    }

    /// Check only that the stored payload digest matches exact canonical receipt bytes.
    pub fn matches_canonical_receipt(&self, canonical_receipt_bytes: &[u8]) -> bool {
        self.validate_structure()
            && ReceiptDigestV1::of_canonical_receipt(canonical_receipt_bytes)
                == self.payload_digest
    }

    /// Exact domain-separated transcript both signatures must authenticate.
    pub fn canonical_signing_transcript(&self) -> Option<Vec<u8>> {
        if !self.validate_structure() {
            return None;
        }

        let mut out = Vec::new();
        out.extend_from_slice(ATTESTATION_TRANSCRIPT_DOMAIN_V1);
        push_field(
            &mut out,
            "protocol_version",
            &self.protocol_version.to_be_bytes(),
        );
        push_field(
            &mut out,
            "receipt_schema_version",
            &self.receipt_schema_version.to_be_bytes(),
        );
        push_field(&mut out, "receipt_id", &self.receipt_id);
        push_field(
            &mut out,
            "payload_digest.algorithm",
            self.payload_digest.algorithm.id().as_bytes(),
        );
        push_field(
            &mut out,
            "payload_digest.bytes",
            &self.payload_digest.bytes,
        );
        push_field(
            &mut out,
            "provider_namespace",
            self.provider_namespace.as_bytes(),
        );
        push_field(&mut out, "signer_id", self.signer_id.as_bytes());
        push_field(
            &mut out,
            "key_lineage_commitment",
            self.key_lineage_commitment.as_bytes(),
        );
        push_field(&mut out, "suite", self.suite.id().as_bytes());
        Some(out)
    }

    /// Exact signing transcript only when the payload digest matches the supplied receipt bytes.
    pub fn canonical_signing_transcript_for(
        &self,
        canonical_receipt_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        if self.matches_canonical_receipt(canonical_receipt_bytes) {
            self.canonical_signing_transcript()
        } else {
            None
        }
    }
}

fn bounded_nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_IDENTIFIER_BYTES
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

    fn symthaea_fixture_receipt_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        push_field(&mut out, "domain", b"symthaea-verification-receipt-v1");
        push_field(&mut out, "schema_version", &1u16.to_be_bytes());
        push_field(&mut out, "receipt_id", &[0x11; 16]);
        push_field(&mut out, "subject.namespace", b"symthaea.source");
        push_field(&mut out, "subject.id", b"crate-a");
        push_field(&mut out, "subject.digest", b"sha256:subject");
        push_field(&mut out, "method", b"formal_proof");
        push_field(&mut out, "conclusion", b"supports");
        push_field(&mut out, "property", b"property.memory_safe");
        push_field(
            &mut out,
            "does_not_establish",
            b"property.side_channel_free",
        );
        push_field(&mut out, "verifier.id", b"verifier.example");
        push_field(&mut out, "verifier.version", b"1.2.3");
        push_field(
            &mut out,
            "verifier.artifact_digest",
            b"sha256:verifier",
        );
        push_field(&mut out, "environment_digest", b"sha256:environment");
        push_field(&mut out, "input_digest", b"sha256:input");
        push_field(&mut out, "output_digest", b"sha256:output");
        push_field(&mut out, "assumptions.present", &[1]);
        push_field(&mut out, "assumptions.digest", b"sha256:assumptions");
        push_field(&mut out, "issued_unix_s", &100u64.to_be_bytes());
        push_field(&mut out, "valid_until.present", &[1]);
        push_field(&mut out, "valid_until_unix_s", &200u64.to_be_bytes());
        out
    }

    fn signatures() -> HybridSignatureBundleV1 {
        HybridSignatureBundleV1 {
            ed25519: [0xAA; ED25519_SIGNATURE_LEN],
            ml_dsa_65: vec![0xBB; ML_DSA_65_SIGNATURE_LEN],
        }
    }

    fn contract() -> SymthaeaReceiptAttestationV1 {
        SymthaeaReceiptAttestationV1::new(
            &symthaea_fixture_receipt_bytes(),
            1,
            [0x11; 16],
            "luminous-dynamics/xenia",
            "operator:alice",
            "sha256:lineage",
            XeniaHybridSuiteV1::Ed25519MlDsa65V1,
            signatures(),
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn frozen_cross_repository_vectors_match_symthaea_sec_002f() {
        let receipt_bytes = symthaea_fixture_receipt_bytes();
        let payload = ReceiptDigestV1::of_canonical_receipt(&receipt_bytes);
        assert_eq!(
            hex(&payload.bytes),
            "ce4c2c8873da8c165ad2e60941836c1f92c5cab3d930c83f3761a85de120f6dc"
        );

        let transcript = contract()
            .canonical_signing_transcript_for(&receipt_bytes)
            .unwrap();
        let digest: [u8; SHA256_LEN] = Sha256::digest(transcript).into();
        assert_eq!(
            hex(&digest),
            "b77c2d5e2f6c36a7f93fb3883af6d5d0d405e1c9f02e80b97a0eb55d657aeeac"
        );
    }

    #[test]
    fn authority_metadata_substitution_changes_signed_bytes() {
        let baseline = contract().canonical_signing_transcript().unwrap();

        let mut provider = contract();
        provider.provider_namespace = "other-provider".into();
        assert_ne!(baseline, provider.canonical_signing_transcript().unwrap());

        let mut signer = contract();
        signer.signer_id = "operator:bob".into();
        assert_ne!(baseline, signer.canonical_signing_transcript().unwrap());

        let mut lineage = contract();
        lineage.key_lineage_commitment = "sha256:rotated-lineage".into();
        assert_ne!(baseline, lineage.canonical_signing_transcript().unwrap());
    }

    #[test]
    fn receipt_substitution_breaks_payload_binding() {
        let value = contract();
        let mut different = symthaea_fixture_receipt_bytes();
        different.push(0);
        assert!(!value.matches_canonical_receipt(&different));
        assert!(value.canonical_signing_transcript_for(&different).is_none());
    }

    #[test]
    fn signatures_are_outputs_not_transcript_inputs() {
        let a = contract();
        let mut b = a.clone();
        b.signatures.ed25519 = [0xCC; ED25519_SIGNATURE_LEN];
        b.signatures.ml_dsa_65 = vec![0xDD; ML_DSA_65_SIGNATURE_LEN];
        assert_ne!(a.signatures, b.signatures);
        assert_eq!(
            a.canonical_signing_transcript().unwrap(),
            b.canonical_signing_transcript().unwrap()
        );
    }

    #[test]
    fn malformed_signature_bundle_fails_closed() {
        let mut value = contract();
        value.signatures.ml_dsa_65.pop();
        assert!(!value.validate_structure());
    }

    #[test]
    fn unsupported_suite_fails_closed_at_deserialization() {
        assert!(serde_json::from_str::<XeniaHybridSuiteV1>(r#""UnknownSuite""#).is_err());
    }
}
