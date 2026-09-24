// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical, crypto-verifier-free Xenia artifact-attestation contract.
//!
//! This crate answers only one question: **what exact bytes would an enrolled
//! Xenia hybrid identity sign to attest to one exact artifact digest?**
//!
//! It deliberately does not verify signatures, resolve enrollment, prove
//! freshness, interpret artifact contents, or confer authority. A later verifier
//! may establish that a current enrolled identity signed [`ArtifactAttestationV1`]
//! bytes, but even that result means only provenance over those exact bytes.
//!
//! ```text
//! valid attestation
//! != artifact is true
//! != artifact passed qualification
//! != executor environment is genuine
//! != product is ready
//! != action is authorized
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest as _, Sha256};
use thiserror::Error;

const SIGNING_DOMAIN_V1: &[u8] = b"xenia-artifact-attestation-v1\0";
const OPERATOR_ID_DOMAIN_V1: &[u8] = b"xenia/artifact-attestation/operator-id/v1\0";
const KEY_LINEAGE_DOMAIN_V1: &[u8] = b"xenia/artifact-attestation/key-lineage/v1\0";
const STATEMENT_DOMAIN_V1: &[u8] = b"xenia/artifact-attestation/statement/v1\0";

const MAX_CONTEXT_LEN: usize = 512;
const MAX_PURPOSE_LEN: usize = 256;
const MAX_OPERATOR_ID_LEN: usize = 512;

/// Current artifact-attestation protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;
/// SHA-256 digest size used by v1.
pub const SHA256_LEN: usize = 32;
/// Ed25519 public-key size used by v1.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// ML-DSA-65 public-key size used by v1.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// Algorithm-qualified SHA-256 digest used by the v1 contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; SHA256_LEN]);

impl Sha256Digest {
    /// Construct from an already-computed SHA-256 digest.
    pub const fn from_bytes(bytes: [u8; SHA256_LEN]) -> Self {
        Self(bytes)
    }

    /// Hash arbitrary bytes with SHA-256.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Borrow the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }

    /// Copy the exact digest bytes.
    pub const fn into_bytes(self) -> [u8; SHA256_LEN] {
        self.0
    }
}

/// Hybrid signature suite named by artifact-attestation v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactAttestationSuite {
    /// Ed25519 and ML-DSA-65 signatures over the same canonical transcript.
    Ed25519MlDsa65V1,
}

impl ArtifactAttestationSuite {
    const fn code(self) -> u16 {
        match self {
            Self::Ed25519MlDsa65V1 => 1,
        }
    }
}

/// Exact signable artifact-attestation statement.
///
/// The statement contains no qualification verdict, trust score, approval bit,
/// freshness proof, or action authority. Context and purpose are exact UTF-8
/// strings: Unicode normalization is intentionally not performed behind the
/// caller's back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactAttestationV1 {
    context: String,
    purpose: String,
    artifact_digest: Sha256Digest,
    suite: ArtifactAttestationSuite,
    operator_id: String,
    ed25519_pubkey: [u8; ED25519_PUBLIC_KEY_LEN],
    ml_dsa_65_pubkey: Vec<u8>,
}

impl ArtifactAttestationV1 {
    /// Construct one validated v1 statement.
    ///
    /// `context` should identify the semantic artifact protocol, while `purpose`
    /// should identify why the signer is making the attestation. Neither field
    /// grants authority merely by naming it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: String,
        purpose: String,
        artifact_digest: Sha256Digest,
        suite: ArtifactAttestationSuite,
        operator_id: String,
        ed25519_pubkey: [u8; ED25519_PUBLIC_KEY_LEN],
        ml_dsa_65_pubkey: Vec<u8>,
    ) -> Result<Self, AttestationContractError> {
        validate_text("context", &context, MAX_CONTEXT_LEN)?;
        validate_text("purpose", &purpose, MAX_PURPOSE_LEN)?;
        validate_text("operator_id", &operator_id, MAX_OPERATOR_ID_LEN)?;
        if ml_dsa_65_pubkey.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(AttestationContractError::InvalidMlDsa65PublicKeyLength {
                len: ml_dsa_65_pubkey.len(),
                expected: ML_DSA_65_PUBLIC_KEY_LEN,
            });
        }

        Ok(Self {
            context,
            purpose,
            artifact_digest,
            suite,
            operator_id,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
        })
    }

    /// Exact semantic context bound into the signature transcript.
    pub fn context(&self) -> &str {
        &self.context
    }

    /// Exact attestation purpose bound into the signature transcript.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Exact artifact digest bound into the signature transcript.
    pub const fn artifact_digest(&self) -> Sha256Digest {
        self.artifact_digest
    }

    /// Hybrid signature suite named by the statement.
    pub const fn suite(&self) -> ArtifactAttestationSuite {
        self.suite
    }

    /// Stable logical Xenia operator identifier asserted by the statement.
    ///
    /// A verifier must still bind this identifier and key pair to current
    /// authoritative enrollment. Merely reading it is not an enrollment proof.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Exact Ed25519 public key named by the statement.
    pub const fn ed25519_pubkey(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.ed25519_pubkey
    }

    /// Exact ML-DSA-65 public key named by the statement.
    pub fn ml_dsa_65_pubkey(&self) -> &[u8] {
        &self.ml_dsa_65_pubkey
    }

    /// Canonical bytes both hybrid signatures must cover.
    ///
    /// Layout:
    ///
    /// ```text
    /// "xenia-artifact-attestation-v1\\0"
    /// || protocol_version(u16,be)
    /// || suite(u16,be)
    /// || digest_algorithm_sha256(u16,be = 1)
    /// || artifact_sha256(32)
    /// || len(context)(u32,be) || context(UTF-8)
    /// || len(purpose)(u32,be) || purpose(UTF-8)
    /// || len(operator_id)(u32,be) || operator_id(UTF-8)
    /// || ed25519_pubkey(32)
    /// || len(ml_dsa_65_pubkey)(u32,be) || ml_dsa_65_pubkey
    /// ```
    pub fn signing_transcript(&self) -> Result<Vec<u8>, AttestationContractError> {
        let mut out = Vec::new();
        out.extend_from_slice(SIGNING_DOMAIN_V1);
        out.extend_from_slice(&CURRENT_PROTOCOL_VERSION.to_be_bytes());
        out.extend_from_slice(&self.suite.code().to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // SHA-256 algorithm code.
        out.extend_from_slice(self.artifact_digest.as_bytes());
        push_bytes(&mut out, "context", self.context.as_bytes())?;
        push_bytes(&mut out, "purpose", self.purpose.as_bytes())?;
        push_bytes(&mut out, "operator_id", self.operator_id.as_bytes())?;
        out.extend_from_slice(&self.ed25519_pubkey);
        push_bytes(&mut out, "ml_dsa_65_pubkey", &self.ml_dsa_65_pubkey)?;
        Ok(out)
    }

    /// Domain-separated commitment to the stable logical operator identifier.
    pub fn operator_id_commitment(&self) -> Result<Sha256Digest, AttestationContractError> {
        operator_id_commitment(&self.operator_id)
    }

    /// Domain-separated commitment to the exact hybrid key lineage.
    pub fn key_lineage_commitment(&self) -> Result<Sha256Digest, AttestationContractError> {
        key_lineage_commitment(self.suite, &self.ed25519_pubkey, &self.ml_dsa_65_pubkey)
    }

    /// Domain-separated identity of this exact canonical attestation statement.
    pub fn statement_commitment(&self) -> Result<Sha256Digest, AttestationContractError> {
        let transcript = self.signing_transcript()?;
        let mut out = Vec::new();
        out.extend_from_slice(STATEMENT_DOMAIN_V1);
        push_bytes(&mut out, "signing_transcript", &transcript)?;
        Ok(Sha256Digest::of_bytes(&out))
    }
}

/// Domain-separated commitment to one exact logical operator identifier.
pub fn operator_id_commitment(
    operator_id: &str,
) -> Result<Sha256Digest, AttestationContractError> {
    validate_text("operator_id", operator_id, MAX_OPERATOR_ID_LEN)?;
    let mut out = Vec::new();
    out.extend_from_slice(OPERATOR_ID_DOMAIN_V1);
    push_bytes(&mut out, "operator_id", operator_id.as_bytes())?;
    Ok(Sha256Digest::of_bytes(&out))
}

/// Domain-separated commitment to one exact hybrid key lineage.
pub fn key_lineage_commitment(
    suite: ArtifactAttestationSuite,
    ed25519_pubkey: &[u8; ED25519_PUBLIC_KEY_LEN],
    ml_dsa_65_pubkey: &[u8],
) -> Result<Sha256Digest, AttestationContractError> {
    if ml_dsa_65_pubkey.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        return Err(AttestationContractError::InvalidMlDsa65PublicKeyLength {
            len: ml_dsa_65_pubkey.len(),
            expected: ML_DSA_65_PUBLIC_KEY_LEN,
        });
    }
    let mut out = Vec::new();
    out.extend_from_slice(KEY_LINEAGE_DOMAIN_V1);
    out.extend_from_slice(&suite.code().to_be_bytes());
    out.extend_from_slice(ed25519_pubkey);
    push_bytes(&mut out, "ml_dsa_65_pubkey", ml_dsa_65_pubkey)?;
    Ok(Sha256Digest::of_bytes(&out))
}

fn validate_text(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), AttestationContractError> {
    if value.is_empty() {
        return Err(AttestationContractError::EmptyField { field });
    }
    if value.len() > max {
        return Err(AttestationContractError::FieldTooLarge {
            field,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

fn push_bytes(
    out: &mut Vec<u8>,
    field: &'static str,
    bytes: &[u8],
) -> Result<(), AttestationContractError> {
    let len = u32::try_from(bytes.len()).map_err(|_| AttestationContractError::FieldTooLarge {
        field,
        len: bytes.len(),
        max: u32::MAX as usize,
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Canonical artifact-attestation contract failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttestationContractError {
    /// A required canonical text field was empty.
    #[error("artifact attestation field {field} must not be empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// A canonical field exceeded its v1 bound.
    #[error("artifact attestation field {field} is too large: {len} > {max}")]
    FieldTooLarge {
        /// Field name.
        field: &'static str,
        /// Observed byte length.
        len: usize,
        /// Maximum byte length.
        max: usize,
    },
    /// ML-DSA-65 key material had the wrong exact public-key length.
    #[error("invalid ML-DSA-65 public key length: {len}; expected {expected}")]
    InvalidMlDsa65PublicKeyLength {
        /// Observed byte length.
        len: usize,
        /// Required v1 byte length.
        expected: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &str = "luminous-dynamics/sol-atlas/qualification-receipt/v2";
    const PURPOSE: &str = "observed-qualification-execution";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn statement(
        artifact_byte: u8,
        context: &str,
        purpose: &str,
        operator_id: &str,
        ed_byte: u8,
        ml_byte: u8,
    ) -> ArtifactAttestationV1 {
        ArtifactAttestationV1::new(
            context.to_owned(),
            purpose.to_owned(),
            Sha256Digest::from_bytes([artifact_byte; SHA256_LEN]),
            ArtifactAttestationSuite::Ed25519MlDsa65V1,
            operator_id.to_owned(),
            [ed_byte; ED25519_PUBLIC_KEY_LEN],
            vec![ml_byte; ML_DSA_65_PUBLIC_KEY_LEN],
        )
        .unwrap()
    }

    #[test]
    fn frozen_sol_atlas_consumer_vectors() {
        let statement = statement(0xa5, CONTEXT, PURPOSE, "operator:alice", 0x21, 0x22);
        let transcript = statement.signing_transcript().unwrap();

        assert_eq!(transcript.len(), 2166);
        assert_eq!(
            hex(Sha256Digest::of_bytes(&transcript).as_bytes()),
            "3ff16739e7a54fe9405a556944ed1407485a40561d024aea6ce81ecdd81aaf55"
        );
        assert_eq!(
            hex(statement.operator_id_commitment().unwrap().as_bytes()),
            "5eb982dcfb2afbd346c543c7879458e71d03b317b5e44ca1355d91d239f27c68"
        );
        assert_eq!(
            hex(statement.key_lineage_commitment().unwrap().as_bytes()),
            "aaf1dfd395584931af2e98e7a8ae861675c7315b1967d4543267d0dd433d8d06"
        );
        assert_eq!(
            hex(statement.statement_commitment().unwrap().as_bytes()),
            "2997d30333944003d287593bb696a897d3965a4d06e2420424fe8ee4f4fda573"
        );
    }

    #[test]
    fn artifact_context_and_purpose_substitution_change_statement_identity() {
        let baseline = statement(0xa5, CONTEXT, PURPOSE, "operator:alice", 0x21, 0x22)
            .statement_commitment()
            .unwrap();
        let changed_artifact = statement(0xa6, CONTEXT, PURPOSE, "operator:alice", 0x21, 0x22)
            .statement_commitment()
            .unwrap();
        let changed_context = statement(
            0xa5,
            "luminous-dynamics/sol-atlas/qualification-receipt/v3",
            PURPOSE,
            "operator:alice",
            0x21,
            0x22,
        )
        .statement_commitment()
        .unwrap();
        let changed_purpose = statement(
            0xa5,
            CONTEXT,
            "approved-for-production",
            "operator:alice",
            0x21,
            0x22,
        )
        .statement_commitment()
        .unwrap();

        assert_ne!(baseline, changed_artifact);
        assert_ne!(baseline, changed_context);
        assert_ne!(baseline, changed_purpose);
    }

    #[test]
    fn stable_operator_identity_is_separate_from_key_lineage() {
        let old = statement(0xa5, CONTEXT, PURPOSE, "operator:alice", 0x21, 0x22);
        let rotated = statement(0xa5, CONTEXT, PURPOSE, "operator:alice", 0x23, 0x24);

        assert_eq!(
            old.operator_id_commitment().unwrap(),
            rotated.operator_id_commitment().unwrap()
        );
        assert_ne!(
            old.key_lineage_commitment().unwrap(),
            rotated.key_lineage_commitment().unwrap()
        );
        assert_ne!(
            old.statement_commitment().unwrap(),
            rotated.statement_commitment().unwrap()
        );
    }

    #[test]
    fn operator_substitution_changes_both_logical_and_statement_identity() {
        let alice = statement(0xa5, CONTEXT, PURPOSE, "operator:alice", 0x21, 0x22);
        let bob = statement(0xa5, CONTEXT, PURPOSE, "operator:bob", 0x21, 0x22);

        assert_ne!(
            alice.operator_id_commitment().unwrap(),
            bob.operator_id_commitment().unwrap()
        );
        assert_eq!(
            alice.key_lineage_commitment().unwrap(),
            bob.key_lineage_commitment().unwrap()
        );
        assert_ne!(
            alice.statement_commitment().unwrap(),
            bob.statement_commitment().unwrap()
        );
    }

    #[test]
    fn malformed_or_ambiguous_required_fields_fail_closed() {
        assert_eq!(
            ArtifactAttestationV1::new(
                String::new(),
                PURPOSE.to_owned(),
                Sha256Digest::from_bytes([0xa5; SHA256_LEN]),
                ArtifactAttestationSuite::Ed25519MlDsa65V1,
                "operator:alice".to_owned(),
                [0x21; ED25519_PUBLIC_KEY_LEN],
                vec![0x22; ML_DSA_65_PUBLIC_KEY_LEN],
            )
            .unwrap_err(),
            AttestationContractError::EmptyField { field: "context" }
        );

        let oversized = "x".repeat(MAX_PURPOSE_LEN + 1);
        assert_eq!(
            ArtifactAttestationV1::new(
                CONTEXT.to_owned(),
                oversized,
                Sha256Digest::from_bytes([0xa5; SHA256_LEN]),
                ArtifactAttestationSuite::Ed25519MlDsa65V1,
                "operator:alice".to_owned(),
                [0x21; ED25519_PUBLIC_KEY_LEN],
                vec![0x22; ML_DSA_65_PUBLIC_KEY_LEN],
            )
            .unwrap_err(),
            AttestationContractError::FieldTooLarge {
                field: "purpose",
                len: MAX_PURPOSE_LEN + 1,
                max: MAX_PURPOSE_LEN,
            }
        );

        assert_eq!(
            ArtifactAttestationV1::new(
                CONTEXT.to_owned(),
                PURPOSE.to_owned(),
                Sha256Digest::from_bytes([0xa5; SHA256_LEN]),
                ArtifactAttestationSuite::Ed25519MlDsa65V1,
                "operator:alice".to_owned(),
                [0x21; ED25519_PUBLIC_KEY_LEN],
                vec![0x22; ML_DSA_65_PUBLIC_KEY_LEN - 1],
            )
            .unwrap_err(),
            AttestationContractError::InvalidMlDsa65PublicKeyLength {
                len: ML_DSA_65_PUBLIC_KEY_LEN - 1,
                expected: ML_DSA_65_PUBLIC_KEY_LEN,
            }
        );
    }

    #[test]
    fn contract_contains_no_qualification_verdict_surface() {
        let statement = statement(0xa5, CONTEXT, PURPOSE, "operator:alice", 0x21, 0x22);
        let transcript = statement.signing_transcript().unwrap();
        let text = String::from_utf8_lossy(&transcript);

        // Purpose is caller-declared exact context, not an interpreted verdict.
        // The canonical contract itself adds no pass/trust/approval authority bit.
        assert!(!text.contains("qualification_status"));
        assert!(!text.contains("trusted=true"));
        assert!(!text.contains("authorized=true"));
    }
}
