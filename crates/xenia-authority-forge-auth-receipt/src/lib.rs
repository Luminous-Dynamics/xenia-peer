// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable Forge-bound Xenia hybrid-authentication transcript and receipt contract.
//!
//! This crate is deliberately crypto-verifier-free and I/O-free. It freezes the
//! exact cross-repository bytes shared by Xenia and Mycelix Forge. The daemon-side
//! producer must verify the signatures and consume the challenge before minting a
//! receipt; merely deserializing [`XeniaVerificationReceiptV1`] proves nothing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const PROVIDER_NAMESPACE_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/provider-namespace/v1\0";
const OPERATOR_ID_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/operator-id/v1\0";
const KEY_LINEAGE_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/key-lineage/v1\0";
const CHALLENGE_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/challenge/v1\0";
const RECEIPT_DOMAIN_V1: &[u8] = b"mycelix-forge/xenia/verification-receipt/v1\0";
const FORGE_AUTH_SIGNING_DOMAIN_V1: &[u8] = b"xenia-forge-auth-v1\0";

/// Current portable receipt protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;
/// Exact Forge/Xenia v1 request/challenge digest size.
pub const SHA256_LEN: usize = 32;

/// Protocol version validated as supported by this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Current v1 protocol value.
    pub const CURRENT: Self = Self(CURRENT_PROTOCOL_VERSION);
    /// Numeric wire value.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        if value == CURRENT_PROTOCOL_VERSION {
            Ok(Self(value))
        } else {
            Err(D::Error::custom(format!("unsupported Xenia Forge receipt version {value}")))
        }
    }
}

/// Digest suite fixed by Forge/Xenia receipt v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    /// SHA-256.
    #[serde(rename = "sha256")]
    Sha256,
}

impl DigestAlgorithm {
    /// Stable wire identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }
}

/// Validated algorithm-qualified digest compatible with Mycelix Forge's wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Digest {
    algorithm: DigestAlgorithm,
    bytes: Vec<u8>,
}

impl Digest {
    /// Construct a SHA-256 digest from exact bytes.
    pub fn sha256(bytes: [u8; SHA256_LEN]) -> Self {
        Self {
            algorithm: DigestAlgorithm::Sha256,
            bytes: bytes.to_vec(),
        }
    }

    /// Hash arbitrary bytes with SHA-256.
    pub fn of_bytes(input: &[u8]) -> Self {
        let digest: [u8; SHA256_LEN] = Sha256::digest(input).into();
        Self::sha256(digest)
    }

    /// Digest algorithm.
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copy raw bytes into a fixed SHA-256 array.
    pub fn as_sha256(&self) -> [u8; SHA256_LEN] {
        let mut out = [0u8; SHA256_LEN];
        out.copy_from_slice(&self.bytes);
        out
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireDigest {
            algorithm: DigestAlgorithm,
            bytes: Vec<u8>,
        }

        let wire = WireDigest::deserialize(deserializer)?;
        if wire.bytes.len() != SHA256_LEN {
            return Err(D::Error::custom(format!(
                "invalid SHA-256 digest length: {}",
                wire.bytes.len()
            )));
        }
        Ok(Self {
            algorithm: wire.algorithm,
            bytes: wire.bytes,
        })
    }
}

/// Hybrid signature suite asserted by a v1 receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XeniaHybridSuite {
    /// Both Ed25519 and ML-DSA-65 verified over the same Forge-bound transcript.
    Ed25519MlDsa65V1,
}

impl XeniaHybridSuite {
    const fn code(self) -> u16 {
        match self {
            Self::Ed25519MlDsa65V1 => 1,
        }
    }
}

/// Portable receipt emitted only after successful Xenia-side verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XeniaVerificationReceiptV1 {
    version: ProtocolVersion,
    request_commitment: Digest,
    operator_id_commitment: Digest,
    key_lineage_commitment: Digest,
    challenge_commitment: Digest,
    suite: XeniaHybridSuite,
    cryptographic_evidence: Digest,
    challenge_consumption_evidence: Digest,
    verifier_state_commitment: Digest,
    verified_at_unix_secs: u64,
}

impl XeniaVerificationReceiptV1 {
    /// Construct a receipt from already-established producer evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_commitment: Digest,
        operator_id_commitment: Digest,
        key_lineage_commitment: Digest,
        challenge_commitment: Digest,
        suite: XeniaHybridSuite,
        cryptographic_evidence: Digest,
        challenge_consumption_evidence: Digest,
        verifier_state_commitment: Digest,
        verified_at_unix_secs: u64,
    ) -> Self {
        Self {
            version: ProtocolVersion::CURRENT,
            request_commitment,
            operator_id_commitment,
            key_lineage_commitment,
            challenge_commitment,
            suite,
            cryptographic_evidence,
            challenge_consumption_evidence,
            verifier_state_commitment,
            verified_at_unix_secs,
        }
    }

    /// Exact Forge authentication-request commitment.
    pub fn request_commitment(&self) -> &Digest { &self.request_commitment }
    /// Stable logical Xenia operator-id commitment.
    pub fn operator_id_commitment(&self) -> &Digest { &self.operator_id_commitment }
    /// Current hybrid key-lineage commitment.
    pub fn key_lineage_commitment(&self) -> &Digest { &self.key_lineage_commitment }
    /// Exact one-time challenge commitment.
    pub fn challenge_commitment(&self) -> &Digest { &self.challenge_commitment }
    /// Verified hybrid suite.
    pub const fn suite(&self) -> XeniaHybridSuite { self.suite }
    /// Cryptographic-verification evidence commitment.
    pub fn cryptographic_evidence(&self) -> &Digest { &self.cryptographic_evidence }
    /// Challenge-consumption evidence commitment.
    pub fn challenge_consumption_evidence(&self) -> &Digest { &self.challenge_consumption_evidence }
    /// Verifier/enrollment-state commitment.
    pub fn verifier_state_commitment(&self) -> &Digest { &self.verifier_state_commitment }
    /// Verification Unix timestamp.
    pub const fn verified_at_unix_secs(&self) -> u64 { self.verified_at_unix_secs }

    /// Canonical receipt bytes byte-identical to Mycelix `forge-xenia` v1.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        let mut out = Vec::new();
        out.extend_from_slice(RECEIPT_DOMAIN_V1);
        out.extend_from_slice(&self.version.get().to_be_bytes());
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

    /// SHA-256 identity of the exact canonical receipt.
    pub fn digest(&self) -> Result<Digest, ReceiptError> {
        Ok(Digest::of_bytes(&self.canonical_bytes()?))
    }
}

/// Stable Xenia provider namespace expected by Mycelix Forge.
pub fn xenia_provider_namespace() -> Digest {
    Digest::of_bytes(PROVIDER_NAMESPACE_DOMAIN_V1)
}

/// Stable logical operator-id commitment.
pub fn operator_id_commitment(operator_id: &str) -> Result<Digest, ReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(OPERATOR_ID_DOMAIN_V1);
    push_bytes(&mut out, "operator_id", operator_id.as_bytes())?;
    Ok(Digest::of_bytes(&out))
}

/// Commitment to the exact enrolled hybrid key lineage.
pub fn key_lineage_commitment(
    ed25519_pubkey: &[u8],
    ml_dsa_65_pubkey: &[u8],
    ml_dsa_87_pubkey: Option<&[u8]>,
) -> Result<Digest, ReceiptError> {
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
    Ok(Digest::of_bytes(&out))
}

/// Commitment to the exact verifier-issued challenge.
pub fn challenge_commitment(challenge: &[u8; SHA256_LEN]) -> Digest {
    let mut out = Vec::with_capacity(CHALLENGE_DOMAIN_V1.len() + challenge.len());
    out.extend_from_slice(CHALLENGE_DOMAIN_V1);
    out.extend_from_slice(challenge);
    Digest::of_bytes(&out)
}

/// Exact transcript both Xenia signatures must cover for a Forge authentication.
///
/// Layout: `xenia-forge-auth-v1\0 || forge_request_sha256(32) || challenge(32)
/// || ed25519_pubkey(32) || len(ml_dsa_65_pubkey)(4,be) || ml_dsa_65_pubkey`.
pub fn forge_auth_signing_transcript(
    forge_request_sha256: &[u8; SHA256_LEN],
    challenge: &[u8; SHA256_LEN],
    ed25519_pubkey: &[u8; 32],
    ml_dsa_65_pubkey: &[u8],
) -> Result<Vec<u8>, ReceiptError> {
    let mut out = Vec::new();
    out.extend_from_slice(FORGE_AUTH_SIGNING_DOMAIN_V1);
    out.extend_from_slice(forge_request_sha256);
    out.extend_from_slice(challenge);
    out.extend_from_slice(ed25519_pubkey);
    push_bytes(&mut out, "ml_dsa_65_pubkey", ml_dsa_65_pubkey)?;
    Ok(out)
}

fn push_digest(out: &mut Vec<u8>, digest: &Digest) -> Result<(), ReceiptError> {
    push_bytes(out, "digest_algorithm", digest.algorithm().id().as_bytes())?;
    push_bytes(out, "digest", digest.as_bytes())
}

fn push_bytes(out: &mut Vec<u8>, field: &'static str, bytes: &[u8]) -> Result<(), ReceiptError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ReceiptError::CanonicalFieldTooLarge {
        field,
        len: bytes.len(),
        max: u32::MAX as usize,
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Portable receipt/transcript contract failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReceiptError {
    /// Canonical field exceeded the v1 encoding limit.
    #[error("canonical field {field} is too large: {len} > {max}")]
    CanonicalFieldTooLarge {
        /// Field name.
        field: &'static str,
        /// Observed length.
        len: usize,
        /// Maximum encodable length.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn frozen_cross_repository_vectors() {
        let provider = xenia_provider_namespace();
        assert_eq!(hex(provider.as_bytes()), "70d580fbc1dd8a0eda43876be6190747c0d7dab9ea539884010deb7b660ab799");

        let operator = operator_id_commitment("operator:alice").unwrap();
        assert_eq!(hex(operator.as_bytes()), "60ab5a633d7994f3c36bc0aaddca98be2d34cdea854bee0564741784953b460c");

        let ed = [0x21; 32];
        let ml = [0x22; 64];
        let lineage = key_lineage_commitment(&ed, &ml, None).unwrap();
        assert_eq!(hex(lineage.as_bytes()), "4b3d09f732d0e97d766ba200115db99fdb63d227d139aa18776c6f0bb86fa507");

        let challenge = [0x44; 32];
        let challenge_digest = challenge_commitment(&challenge);
        assert_eq!(hex(challenge_digest.as_bytes()), "1a1b90df161f09c04fa22c1e5cc8eac6e86117c5caa163848aab8159aac879a0");

        let request = [0x55; 32];
        let transcript = forge_auth_signing_transcript(&request, &challenge, &ed, &ml).unwrap();
        assert_eq!(
            hex(Digest::of_bytes(&transcript).as_bytes()),
            "e4c26bd6ccfea84d2c8d3a75d662239b9659473e9b5eaeeb1bfeb3741a0a9936"
        );

        let receipt = XeniaVerificationReceiptV1::new(
            Digest::sha256(request),
            operator,
            lineage,
            challenge_digest,
            XeniaHybridSuite::Ed25519MlDsa65V1,
            Digest::sha256([0x66; 32]),
            Digest::sha256([0x77; 32]),
            Digest::sha256([0x88; 32]),
            1_234_567_890,
        );
        assert_eq!(
            hex(receipt.digest().unwrap().as_bytes()),
            "1d964f49115fafcc1350f69a48ed0792e89e8fab303e880dad96375498cb0a83"
        );
    }

    #[test]
    fn transcript_binds_exact_forge_request() {
        let challenge = [0x44; 32];
        let ed = [0x21; 32];
        let ml = [0x22; 64];
        let a = forge_auth_signing_transcript(&[0x55; 32], &challenge, &ed, &ml).unwrap();
        let b = forge_auth_signing_transcript(&[0x56; 32], &challenge, &ed, &ml).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn any_key_rotation_changes_lineage() {
        let ed = [0x21; 32];
        let ml = [0x22; 64];
        let baseline = key_lineage_commitment(&ed, &ml, None).unwrap();
        let mut changed_ed = ed;
        changed_ed[0] ^= 1;
        assert_ne!(baseline, key_lineage_commitment(&changed_ed, &ml, None).unwrap());
        let mut changed_ml = ml;
        changed_ml[0] ^= 1;
        assert_ne!(baseline, key_lineage_commitment(&ed, &changed_ml, None).unwrap());
        assert_ne!(baseline, key_lineage_commitment(&ed, &ml, Some(&[0x33; 32])).unwrap());
    }

    #[test]
    fn receipt_serde_preserves_validated_wire_shape() {
        let receipt = XeniaVerificationReceiptV1::new(
            Digest::sha256([1; 32]),
            Digest::sha256([2; 32]),
            Digest::sha256([3; 32]),
            Digest::sha256([4; 32]),
            XeniaHybridSuite::Ed25519MlDsa65V1,
            Digest::sha256([5; 32]),
            Digest::sha256([6; 32]),
            Digest::sha256([7; 32]),
            42,
        );
        let json = serde_json::to_vec(&receipt).unwrap();
        let decoded: XeniaVerificationReceiptV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn serde_rejects_wrong_digest_length_and_protocol_version() {
        let bad_digest = r#"{"algorithm":"sha256","bytes":[1,2,3]}"#;
        assert!(serde_json::from_str::<Digest>(bad_digest).is_err());
        assert!(serde_json::from_str::<ProtocolVersion>("2").is_err());
    }
}
