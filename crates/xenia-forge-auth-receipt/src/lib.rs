// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable Xenia authentication receipts for Mycelix Forge.
//!
//! This crate is deliberately I/O-free and contains no enrollment/session
//! authority. It defines the exact Forge-bound bytes an operator signs and the
//! exact receipt/wire commitments a verifier may emit after successful hybrid
//! verification. The daemon-side producer is a separate integration layer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Receipt protocol version shared with Mycelix Forge FORGE-005B1.
pub const RECEIPT_VERSION: u16 = 1;

const PROVIDER_NAMESPACE_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/provider-namespace/v1\0";
const OPERATOR_ID_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/operator-id/v1\0";
const KEY_LINEAGE_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/key-lineage/v1\0";
const CHALLENGE_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/challenge/v1\0";
const RECEIPT_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/verification-receipt/v1\0";
const FORGE_AUTH_TRANSCRIPT_DOMAIN_V1: &[u8] = b"xenia-forge-authentication-v1\0";
const CRYPTO_EVIDENCE_DOMAIN_V1: &[u8] = b"xenia-forge-authentication-crypto-evidence-v1\0";
const CHALLENGE_CONSUMPTION_DOMAIN_V1: &[u8] = b"xenia-forge-authentication-challenge-consumption-v1\0";
const VERIFIER_STATE_DOMAIN_V1: &[u8] = b"xenia-forge-authentication-verifier-state-v1\0";

/// Fixed SHA-256 digest size used by the v1 bridge.
pub const SHA256_LEN: usize = 32;

/// Wire digest matching Mycelix Forge's JSON `Digest` representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeDigest {
    algorithm: ForgeDigestAlgorithm,
    bytes: Vec<u8>,
}

impl ForgeDigest {
    /// Construct a SHA-256 wire digest.
    pub fn sha256(bytes: [u8; SHA256_LEN]) -> Self {
        Self {
            algorithm: ForgeDigestAlgorithm::Sha256,
            bytes: bytes.to_vec(),
        }
    }

    /// Raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Validate and copy the digest into a fixed array.
    pub fn as_sha256(&self) -> Result<[u8; SHA256_LEN], ForgeReceiptError> {
        if self.algorithm != ForgeDigestAlgorithm::Sha256 || self.bytes.len() != SHA256_LEN {
            return Err(ForgeReceiptError::MalformedDigest);
        }
        self.bytes
            .as_slice()
            .try_into()
            .map_err(|_| ForgeReceiptError::MalformedDigest)
    }
}

/// Digest algorithm identifier compatible with Mycelix Forge JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForgeDigestAlgorithm {
    /// SHA-256.
    #[serde(rename = "sha256")]
    Sha256,
}

/// Hybrid authentication suite asserted by a v1 receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XeniaHybridSuite {
    /// Ed25519 and ML-DSA-65 both verified over the same transcript.
    Ed25519MlDsa65V1,
}

impl XeniaHybridSuite {
    const fn code(self) -> u16 {
        match self {
            Self::Ed25519MlDsa65V1 => 1,
        }
    }
}

/// Portable receipt wire shape consumed by Mycelix Forge FORGE-005B1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeAuthenticationReceiptV1 {
    /// Protocol version.
    pub version: u16,
    /// Exact Forge authentication request SHA-256.
    pub request_commitment: ForgeDigest,
    /// Stable Xenia logical operator-id commitment.
    pub operator_id_commitment: ForgeDigest,
    /// Current enrolled hybrid key-lineage commitment.
    pub key_lineage_commitment: ForgeDigest,
    /// Exact one-time challenge commitment.
    pub challenge_commitment: ForgeDigest,
    /// Required hybrid suite.
    pub suite: XeniaHybridSuite,
    /// Evidence commitment over the transcript/signature material actually verified.
    pub cryptographic_evidence: ForgeDigest,
    /// Evidence commitment that the one-time challenge was consumed.
    pub challenge_consumption_evidence: ForgeDigest,
    /// Commitment to the exact enrollment state used by the verifier.
    pub verifier_state_commitment: ForgeDigest,
    /// Verification time in Unix seconds.
    pub verified_at_unix_secs: u64,
}

impl ForgeAuthenticationReceiptV1 {
    /// Canonical bytes matching the Mycelix FORGE-005B1 adapter.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ForgeReceiptError> {
        if self.version != RECEIPT_VERSION {
            return Err(ForgeReceiptError::UnsupportedVersion(self.version));
        }
        let mut out = Vec::new();
        out.extend_from_slice(RECEIPT_DOMAIN_V1);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_digest(&mut out, &self.request_commitment)?;
        push_digest(&mut out, &self.operator_id_commitment)?;
        push_digest(&mut out, &self.key_lineage_commitment)?;
        push_digest(&mut out, &self.challenge_commitment)?;
        out.extend_from_slice(&self.suite.code().to_be_bytes());
        push_digest(&mut out, &self.cryptographic_evidence)?;
        push_digest(&mut out, &self.challenge_consumption_evidence)?;
        push_digest(&mut out, &self.verifier_state_commitment)?;
        out.extend_from_slice(&self.verified_at_unix_secs.to_be_bytes());
        Ok(out)
    }

    /// SHA-256 of the exact canonical receipt.
    pub fn digest(&self) -> Result<[u8; SHA256_LEN], ForgeReceiptError> {
        Ok(sha256(&self.canonical_bytes()?))
    }
}

/// Exact bytes the Xenia operator signs for a Forge authentication request.
///
/// The Forge request commitment already binds project, authority epoch,
/// principal, key-lineage binding, capability, action subject and challenge.
/// The challenge and presented keys are repeated here deliberately so the
/// Xenia verifier can fail closed if any relay layer mixes subjects.
pub fn forge_authentication_transcript(
    forge_request_commitment: &[u8; SHA256_LEN],
    challenge: &[u8; SHA256_LEN],
    ed25519_pubkey: &[u8; 32],
    ml_dsa_65_pubkey: &[u8],
) -> Result<Vec<u8>, ForgeReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(FORGE_AUTH_TRANSCRIPT_DOMAIN_V1);
    out.extend_from_slice(forge_request_commitment);
    out.extend_from_slice(challenge);
    out.extend_from_slice(ed25519_pubkey);
    push_bytes(&mut out, "ml_dsa_65_pubkey", ml_dsa_65_pubkey)?;
    Ok(out)
}

/// Stable provider namespace digest used by the Forge/Xenia adapter.
pub fn provider_namespace_commitment() -> [u8; SHA256_LEN] {
    sha256(PROVIDER_NAMESPACE_DOMAIN_V1)
}

/// Stable commitment to Xenia's logical operator id.
pub fn operator_id_commitment(operator_id: &str) -> Result<[u8; SHA256_LEN], ForgeReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(OPERATOR_ID_DOMAIN_V1);
    push_bytes(&mut out, "operator_id", operator_id.as_bytes())?;
    Ok(sha256(&out))
}

/// Commitment to the exact current Xenia hybrid key lineage.
pub fn key_lineage_commitment(
    ed25519_pubkey: &[u8],
    ml_dsa_65_pubkey: &[u8],
    ml_dsa_87_pubkey: Option<&[u8]>,
) -> Result<[u8; SHA256_LEN], ForgeReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(KEY_LINEAGE_DOMAIN_V1);
    push_bytes(&mut out, "ed25519_pubkey", ed25519_pubkey)?;
    push_bytes(&mut out, "ml_dsa_65_pubkey", ml_dsa_65_pubkey)?;
    match ml_dsa_87_pubkey {
        Some(key) => {
            out.push(1);
            push_bytes(&mut out, "ml_dsa_87_pubkey", key)?;
        }
        None => out.push(0),
    }
    Ok(sha256(&out))
}

/// Commitment to the exact verifier-issued challenge.
pub fn challenge_commitment(challenge: &[u8; SHA256_LEN]) -> [u8; SHA256_LEN] {
    let mut out = Vec::with_capacity(CHALLENGE_DOMAIN_V1.len() + challenge.len());
    out.extend_from_slice(CHALLENGE_DOMAIN_V1);
    out.extend_from_slice(challenge);
    sha256(&out)
}

/// Commitment to the exact transcript and both signatures that the verifier checked.
pub fn cryptographic_evidence_commitment(
    transcript: &[u8],
    ed25519_signature: &[u8],
    ml_dsa_65_signature: &[u8],
) -> Result<[u8; SHA256_LEN], ForgeReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(CRYPTO_EVIDENCE_DOMAIN_V1);
    push_bytes(&mut out, "transcript", transcript)?;
    push_bytes(&mut out, "ed25519_signature", ed25519_signature)?;
    push_bytes(&mut out, "ml_dsa_65_signature", ml_dsa_65_signature)?;
    Ok(sha256(&out))
}

/// Commitment proving which challenge was consumed by the verifier and when.
pub fn challenge_consumption_evidence(
    challenge: &[u8; SHA256_LEN],
    operator_id: &str,
    verified_at_unix_secs: u64,
) -> Result<[u8; SHA256_LEN], ForgeReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(CHALLENGE_CONSUMPTION_DOMAIN_V1);
    out.extend_from_slice(challenge);
    push_bytes(&mut out, "operator_id", operator_id.as_bytes())?;
    out.extend_from_slice(&verified_at_unix_secs.to_be_bytes());
    Ok(sha256(&out))
}

/// Commitment to the exact stable operator identity, role and current key lineage
/// resolved from Xenia's authoritative enrollment state.
pub fn verifier_state_commitment(
    operator_id: &str,
    role: &str,
    key_lineage: &[u8; SHA256_LEN],
) -> Result<[u8; SHA256_LEN], ForgeReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(VERIFIER_STATE_DOMAIN_V1);
    push_bytes(&mut out, "operator_id", operator_id.as_bytes())?;
    push_bytes(&mut out, "role", role.as_bytes())?;
    out.extend_from_slice(key_lineage);
    Ok(sha256(&out))
}

fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
    Sha256::digest(bytes).into()
}

fn push_digest(out: &mut Vec<u8>, digest: &ForgeDigest) -> Result<(), ForgeReceiptError> {
    let bytes = digest.as_sha256()?;
    push_bytes(out, "digest_algorithm", b"sha256")?;
    push_bytes(out, "digest", &bytes)
}

fn push_bytes(
    out: &mut Vec<u8>,
    field: &'static str,
    bytes: &[u8],
) -> Result<(), ForgeReceiptError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ForgeReceiptError::FieldTooLarge {
        field,
        len: bytes.len(),
        max: u32::MAX as usize,
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Receipt-contract failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ForgeReceiptError {
    /// Unsupported receipt version.
    #[error("unsupported Forge/Xenia receipt version: {0}")]
    UnsupportedVersion(u16),
    /// A wire digest was not exactly one SHA-256 value.
    #[error("malformed Forge receipt digest")]
    MalformedDigest,
    /// Canonical field exceeded the v1 encoding bound.
    #[error("canonical field {field} is too large: {len} > {max}")]
    FieldTooLarge {
        /// Field name.
        field: &'static str,
        /// Observed length.
        len: usize,
        /// Maximum length.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ForgeDigest {
        ForgeDigest::sha256([byte; 32])
    }

    #[test]
    fn forge_auth_transcript_binds_request_challenge_and_keys() {
        let a = forge_authentication_transcript(&[1; 32], &[2; 32], &[3; 32], &[4; 64]).unwrap();
        let b = forge_authentication_transcript(&[9; 32], &[2; 32], &[3; 32], &[4; 64]).unwrap();
        let c = forge_authentication_transcript(&[1; 32], &[8; 32], &[3; 32], &[4; 64]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn key_replacement_changes_lineage_not_operator_identity() {
        let operator = operator_id_commitment("operator:alice").unwrap();
        let before = key_lineage_commitment(&[1; 32], &[2; 64], None).unwrap();
        let after = key_lineage_commitment(&[3; 32], &[4; 64], None).unwrap();
        assert_ne!(before, after);
        assert_eq!(operator, operator_id_commitment("operator:alice").unwrap());
    }

    #[test]
    fn receipt_json_shape_is_stable_and_round_trips() {
        let receipt = ForgeAuthenticationReceiptV1 {
            version: RECEIPT_VERSION,
            request_commitment: digest(1),
            operator_id_commitment: digest(2),
            key_lineage_commitment: digest(3),
            challenge_commitment: digest(4),
            suite: XeniaHybridSuite::Ed25519MlDsa65V1,
            cryptographic_evidence: digest(5),
            challenge_consumption_evidence: digest(6),
            verifier_state_commitment: digest(7),
            verified_at_unix_secs: 1_797_000_000,
        };
        let json = serde_json::to_vec(&receipt).unwrap();
        let decoded: ForgeAuthenticationReceiptV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.digest().unwrap(), receipt.digest().unwrap());
    }

    #[test]
    fn receipt_digest_changes_with_verifier_state() {
        let mut a = ForgeAuthenticationReceiptV1 {
            version: RECEIPT_VERSION,
            request_commitment: digest(1),
            operator_id_commitment: digest(2),
            key_lineage_commitment: digest(3),
            challenge_commitment: digest(4),
            suite: XeniaHybridSuite::Ed25519MlDsa65V1,
            cryptographic_evidence: digest(5),
            challenge_consumption_evidence: digest(6),
            verifier_state_commitment: digest(7),
            verified_at_unix_secs: 1_797_000_000,
        };
        let before = a.digest().unwrap();
        a.verifier_state_commitment = digest(8);
        assert_ne!(before, a.digest().unwrap());
    }
}
