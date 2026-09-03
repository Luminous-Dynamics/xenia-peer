// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authenticated local trust policy for SIF release credentials.
//!
//! The portable Mycelix credential cannot decide which release-authority keys or
//! administrative trust domains this Xenia deployment trusts. Those roots are
//! fixed by this independently signed local policy. Runtime code consumes only a
//! [`VerifiedSifReleaseAuthorityPolicy`], never raw JSON authority lists.
//!
//! V1 deliberately keeps root enrollment outside the policy being signed: the
//! caller supplies one already-trusted Ed25519 policy-root public key (for example
//! from Nix/system configuration or another independently retained enrollment
//! artifact). A signed policy therefore cannot self-authorize its own root.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_ledger::{ReleaseCredentialTrustPolicy, TrustedReleaseAuthority};

pub(crate) const SIF_RELEASE_AUTHORITY_POLICY_SCHEMA: &str =
    "xenia-sif-release-authority-policy-v1";
pub(crate) const SIF_RELEASE_AUTHORITY_POLICY_SIGNATURE_SCHEMA: &str =
    "xenia-sif-release-authority-policy-signature-v1";
pub(crate) const SIF_RELEASE_AUTHORITY_POLICY_SIGNATURE_ALGORITHM: &str = "ed25519-rfc8032";

const POLICY_MESSAGE_DOMAIN: &[u8] = b"xenia:sif-release-authority-policy:message:v1";
const POLICY_DIGEST_DOMAIN: &[u8] = b"xenia:sif-release-authority-policy:digest:v1";
const POLICY_SIGNATURE_DOMAIN: &[u8] = b"xenia:sif-release-authority-policy:signature:v1";
const POLICY_ROOT_KEY_ID_DOMAIN: &[u8] = b"xenia:sif-release-authority-policy:root-key:v1";
const MAX_POLICY_FILE_BYTES: u64 = 256 * 1024;
const MAX_RELEASE_AUTHORITIES: usize = 32;
const MAX_POLICY_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SifReleaseAuthorityPolicyEntryV1 {
    /// Ed25519 release-authority public key, 32 bytes as hexadecimal.
    pub public_key_hex: String,
    /// Locally assigned administrative trust-domain identifier, 32 bytes as hexadecimal.
    pub trust_domain_id_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SifReleaseAuthorityPolicyV1 {
    pub schema: String,
    /// Human-stable policy identifier. Epoch supplies anti-rollback ordering.
    pub policy_id: String,
    /// Strictly positive monotonic policy generation.
    pub policy_epoch: u64,
    /// Inclusive policy validity start in Unix seconds.
    pub valid_from_unix_secs: u64,
    /// Exclusive policy validity end in Unix seconds.
    pub valid_until_unix_secs: u64,
    /// Local administration domain expected in the bound Xenia execution credential.
    pub local_execution_trust_domain_id_hex: String,
    /// Minimum distinct trusted authority keys whose signatures must verify.
    pub min_valid_signatures: u8,
    /// Minimum distinct locally assigned administrative domains represented.
    pub min_distinct_trust_domains: u8,
    /// Complete trusted release-authority set for this policy generation.
    pub authorities: Vec<SifReleaseAuthorityPolicyEntryV1>,
    /// Optional predecessor identity for operator/audit continuity. Epoch, not this
    /// field, is the anti-rollback primitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_policy_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SifReleaseAuthorityPolicySignatureV1 {
    pub schema: String,
    pub algorithm: String,
    /// BLAKE3-256 digest of the canonical policy semantics.
    pub policy_digest_hex: String,
    /// Domain-separated identifier of the independently enrolled root key.
    pub root_key_id_hex: String,
    /// Raw Ed25519 signature over the domain-separated policy-signature message.
    pub signature_hex: String,
}

/// Runtime-ready policy produced only after structure, epoch, validity, root,
/// digest and signature checks all succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedSifReleaseAuthorityPolicy {
    pub policy_id: String,
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub root_key_id: [u8; 32],
    pub local_execution_trust_domain_id: [u8; 32],
    pub authorities: Vec<TrustedReleaseAuthority>,
    pub credential_policy: ReleaseCredentialTrustPolicy,
}

/// Load and authenticate one bounded policy/signature pair.
pub(crate) fn load_verified_sif_release_authority_policy(
    policy_path: &Path,
    signature_path: &Path,
    trusted_root_public_key: [u8; 32],
    minimum_policy_epoch: u64,
    now_unix_secs: u64,
) -> Result<VerifiedSifReleaseAuthorityPolicy, SifReleaseAuthorityPolicyError> {
    let policy: SifReleaseAuthorityPolicyV1 = read_bounded_json(policy_path, "policy")?;
    let signature: SifReleaseAuthorityPolicySignatureV1 =
        read_bounded_json(signature_path, "policy signature")?;
    verify_sif_release_authority_policy(
        &policy,
        &signature,
        trusted_root_public_key,
        minimum_policy_epoch,
        now_unix_secs,
    )
}

/// Verify an already-decoded policy against one independently trusted root.
pub(crate) fn verify_sif_release_authority_policy(
    policy: &SifReleaseAuthorityPolicyV1,
    signature: &SifReleaseAuthorityPolicySignatureV1,
    trusted_root_public_key: [u8; 32],
    minimum_policy_epoch: u64,
    now_unix_secs: u64,
) -> Result<VerifiedSifReleaseAuthorityPolicy, SifReleaseAuthorityPolicyError> {
    if minimum_policy_epoch == 0 {
        return Err(SifReleaseAuthorityPolicyError::InvalidMinimumEpoch);
    }
    let normalized = normalize_policy(policy)?;
    if normalized.policy_epoch < minimum_policy_epoch {
        return Err(SifReleaseAuthorityPolicyError::PolicyEpochRollback {
            observed: normalized.policy_epoch,
            minimum: minimum_policy_epoch,
        });
    }
    if now_unix_secs < normalized.valid_from_unix_secs
        || now_unix_secs >= normalized.valid_until_unix_secs
    {
        return Err(SifReleaseAuthorityPolicyError::PolicyOutsideValidityWindow);
    }

    let root = VerifyingKey::from_bytes(&trusted_root_public_key)
        .map_err(|_| SifReleaseAuthorityPolicyError::InvalidRootPublicKey)?;
    if normalized
        .authorities
        .iter()
        .any(|authority| authority.public_key == trusted_root_public_key)
    {
        return Err(SifReleaseAuthorityPolicyError::PolicyRootAlsoReleaseAuthority);
    }

    if signature.schema != SIF_RELEASE_AUTHORITY_POLICY_SIGNATURE_SCHEMA {
        return Err(SifReleaseAuthorityPolicyError::UnsupportedSignatureSchema(
            signature.schema.clone(),
        ));
    }
    if signature.algorithm != SIF_RELEASE_AUTHORITY_POLICY_SIGNATURE_ALGORITHM {
        return Err(SifReleaseAuthorityPolicyError::UnsupportedSignatureAlgorithm(
            signature.algorithm.clone(),
        ));
    }

    let digest = policy_digest_from_normalized(&normalized);
    let declared_digest = parse_hex_32("policy_digest_hex", &signature.policy_digest_hex)?;
    if declared_digest != digest {
        return Err(SifReleaseAuthorityPolicyError::PolicyDigestMismatch);
    }
    let root_key_id = release_policy_root_key_id(&trusted_root_public_key);
    let declared_root_key_id = parse_hex_32("root_key_id_hex", &signature.root_key_id_hex)?;
    if declared_root_key_id != root_key_id {
        return Err(SifReleaseAuthorityPolicyError::RootKeyIdMismatch);
    }
    let signature_bytes = parse_hex_64("signature_hex", &signature.signature_hex)?;
    root.verify(
        &policy_signature_message(digest),
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| SifReleaseAuthorityPolicyError::InvalidPolicySignature)?;

    Ok(VerifiedSifReleaseAuthorityPolicy {
        policy_id: normalized.policy_id,
        policy_epoch: normalized.policy_epoch,
        policy_digest: digest,
        root_key_id,
        local_execution_trust_domain_id: normalized.local_execution_trust_domain_id,
        authorities: normalized.authorities,
        credential_policy: ReleaseCredentialTrustPolicy {
            min_valid_signatures: normalized.min_valid_signatures,
            min_distinct_trust_domains: normalized.min_distinct_trust_domains,
        },
    })
}

/// Sign a policy with an already-enrolled root key. Runtime verification never
/// calls this; it exists for deterministic tooling/tests and a future explicit
/// one-shot policy ceremony.
pub(crate) fn sign_sif_release_authority_policy(
    policy: &SifReleaseAuthorityPolicyV1,
    root_key: &SigningKey,
) -> Result<SifReleaseAuthorityPolicySignatureV1, SifReleaseAuthorityPolicyError> {
    let normalized = normalize_policy(policy)?;
    let digest = policy_digest_from_normalized(&normalized);
    let signature = root_key.sign(&policy_signature_message(digest)).to_bytes();
    Ok(SifReleaseAuthorityPolicySignatureV1 {
        schema: SIF_RELEASE_AUTHORITY_POLICY_SIGNATURE_SCHEMA.to_string(),
        algorithm: SIF_RELEASE_AUTHORITY_POLICY_SIGNATURE_ALGORITHM.to_string(),
        policy_digest_hex: hex::encode(digest),
        root_key_id_hex: hex::encode(release_policy_root_key_id(
            &root_key.verifying_key().to_bytes(),
        )),
        signature_hex: hex::encode(signature),
    })
}

pub(crate) fn release_policy_root_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_ROOT_KEY_ID_DOMAIN);
    hasher.update(&[0]);
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

#[derive(Debug)]
struct NormalizedPolicy {
    policy_id: String,
    policy_epoch: u64,
    valid_from_unix_secs: u64,
    valid_until_unix_secs: u64,
    local_execution_trust_domain_id: [u8; 32],
    min_valid_signatures: u8,
    min_distinct_trust_domains: u8,
    authorities: Vec<TrustedReleaseAuthority>,
    supersedes_policy_id: Option<String>,
}

fn normalize_policy(
    policy: &SifReleaseAuthorityPolicyV1,
) -> Result<NormalizedPolicy, SifReleaseAuthorityPolicyError> {
    if policy.schema != SIF_RELEASE_AUTHORITY_POLICY_SCHEMA {
        return Err(SifReleaseAuthorityPolicyError::UnsupportedPolicySchema(
            policy.schema.clone(),
        ));
    }
    validate_policy_id("policy_id", &policy.policy_id)?;
    if let Some(previous) = policy.supersedes_policy_id.as_deref() {
        validate_policy_id("supersedes_policy_id", previous)?;
        if previous == policy.policy_id {
            return Err(SifReleaseAuthorityPolicyError::SelfSupersession);
        }
    }
    if policy.policy_epoch == 0 {
        return Err(SifReleaseAuthorityPolicyError::ZeroPolicyEpoch);
    }
    if policy.valid_until_unix_secs <= policy.valid_from_unix_secs {
        return Err(SifReleaseAuthorityPolicyError::InvalidValidityWindow);
    }
    if policy.authorities.is_empty() || policy.authorities.len() > MAX_RELEASE_AUTHORITIES {
        return Err(SifReleaseAuthorityPolicyError::InvalidAuthorityCount {
            observed: policy.authorities.len(),
            maximum: MAX_RELEASE_AUTHORITIES,
        });
    }
    if policy.min_valid_signatures == 0
        || policy.min_distinct_trust_domains == 0
        || policy.min_distinct_trust_domains > policy.min_valid_signatures
        || usize::from(policy.min_valid_signatures) > policy.authorities.len()
    {
        return Err(SifReleaseAuthorityPolicyError::InvalidThreshold);
    }

    let local_execution_trust_domain_id = parse_hex_32(
        "local_execution_trust_domain_id_hex",
        &policy.local_execution_trust_domain_id_hex,
    )?;
    if local_execution_trust_domain_id == [0u8; 32] {
        return Err(SifReleaseAuthorityPolicyError::ZeroExecutionTrustDomain);
    }

    let mut authorities = Vec::with_capacity(policy.authorities.len());
    let mut key_ids = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for entry in &policy.authorities {
        let public_key = parse_hex_32("authority.public_key_hex", &entry.public_key_hex)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| SifReleaseAuthorityPolicyError::InvalidAuthorityPublicKey)?;
        let trust_domain_id =
            parse_hex_32("authority.trust_domain_id_hex", &entry.trust_domain_id_hex)?;
        if trust_domain_id == [0u8; 32] {
            return Err(SifReleaseAuthorityPolicyError::ZeroAuthorityTrustDomain);
        }
        let authority = TrustedReleaseAuthority {
            public_key,
            trust_domain_id,
        };
        if !key_ids.insert(authority.key_id()) {
            return Err(SifReleaseAuthorityPolicyError::DuplicateAuthorityKey);
        }
        domains.insert(trust_domain_id);
        authorities.push(authority);
    }
    if domains.len() < usize::from(policy.min_distinct_trust_domains) {
        return Err(SifReleaseAuthorityPolicyError::ImpossibleDomainThreshold {
            available: domains.len(),
            required: policy.min_distinct_trust_domains,
        });
    }

    // Canonical semantics are independent of JSON list order. The key id is a
    // stable domain-separated identifier already defined by the credential verifier.
    authorities.sort_by_key(TrustedReleaseAuthority::key_id);

    Ok(NormalizedPolicy {
        policy_id: policy.policy_id.clone(),
        policy_epoch: policy.policy_epoch,
        valid_from_unix_secs: policy.valid_from_unix_secs,
        valid_until_unix_secs: policy.valid_until_unix_secs,
        local_execution_trust_domain_id,
        min_valid_signatures: policy.min_valid_signatures,
        min_distinct_trust_domains: policy.min_distinct_trust_domains,
        authorities,
        supersedes_policy_id: policy.supersedes_policy_id.clone(),
    })
}

fn policy_digest_from_normalized(policy: &NormalizedPolicy) -> [u8; 32] {
    let message = canonical_policy_message(policy);
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&message);
    *hasher.finalize().as_bytes()
}

fn canonical_policy_message(policy: &NormalizedPolicy) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + policy.authorities.len() * 64);
    out.extend_from_slice(POLICY_MESSAGE_DOMAIN);
    out.push(0);
    out.extend_from_slice(SIF_RELEASE_AUTHORITY_POLICY_SCHEMA.as_bytes());
    out.push(0);
    push_bounded_string(&mut out, &policy.policy_id);
    out.extend_from_slice(&policy.policy_epoch.to_be_bytes());
    out.extend_from_slice(&policy.valid_from_unix_secs.to_be_bytes());
    out.extend_from_slice(&policy.valid_until_unix_secs.to_be_bytes());
    out.extend_from_slice(&policy.local_execution_trust_domain_id);
    out.push(policy.min_valid_signatures);
    out.push(policy.min_distinct_trust_domains);
    out.extend_from_slice(&(policy.authorities.len() as u16).to_be_bytes());
    for authority in &policy.authorities {
        out.extend_from_slice(&authority.public_key);
        out.extend_from_slice(&authority.trust_domain_id);
    }
    match policy.supersedes_policy_id.as_deref() {
        Some(previous) => {
            out.push(1);
            push_bounded_string(&mut out, previous);
        }
        None => out.push(0),
    }
    out
}

fn policy_signature_message(policy_digest: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(POLICY_SIGNATURE_DOMAIN);
    out.push(0);
    out.extend_from_slice(SIF_RELEASE_AUTHORITY_POLICY_SIGNATURE_SCHEMA.as_bytes());
    out.push(0);
    out.extend_from_slice(&policy_digest);
    out
}

fn push_bounded_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn validate_policy_id(
    field: &'static str,
    value: &str,
) -> Result<(), SifReleaseAuthorityPolicyError> {
    if value.is_empty() || value.len() > MAX_POLICY_ID_BYTES || value.len() > u16::MAX as usize {
        return Err(SifReleaseAuthorityPolicyError::InvalidPolicyId { field });
    }
    Ok(())
}

fn parse_hex_32(
    field: &'static str,
    value: &str,
) -> Result<[u8; 32], SifReleaseAuthorityPolicyError> {
    let bytes = hex::decode(value)
        .map_err(|_| SifReleaseAuthorityPolicyError::InvalidHex { field })?;
    bytes
        .try_into()
        .map_err(|_| SifReleaseAuthorityPolicyError::InvalidHexLength {
            field,
            expected: 32,
        })
}

fn parse_hex_64(
    field: &'static str,
    value: &str,
) -> Result<[u8; 64], SifReleaseAuthorityPolicyError> {
    let bytes = hex::decode(value)
        .map_err(|_| SifReleaseAuthorityPolicyError::InvalidHex { field })?;
    bytes
        .try_into()
        .map_err(|_| SifReleaseAuthorityPolicyError::InvalidHexLength {
            field,
            expected: 64,
        })
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    label: &'static str,
) -> Result<T, SifReleaseAuthorityPolicyError> {
    let metadata = std::fs::metadata(path).map_err(|source| {
        SifReleaseAuthorityPolicyError::Read {
            label,
            source,
        }
    })?;
    if metadata.len() > MAX_POLICY_FILE_BYTES {
        return Err(SifReleaseAuthorityPolicyError::FileTooLarge {
            label,
            observed: metadata.len(),
            maximum: MAX_POLICY_FILE_BYTES,
        });
    }
    let bytes = std::fs::read(path).map_err(|source| SifReleaseAuthorityPolicyError::Read {
        label,
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| SifReleaseAuthorityPolicyError::Json {
        label,
        source,
    })
}

#[derive(Debug, Error)]
pub(crate) enum SifReleaseAuthorityPolicyError {
    #[error("unsupported SIF release-authority policy schema: {0}")]
    UnsupportedPolicySchema(String),
    #[error("unsupported SIF release-authority policy signature schema: {0}")]
    UnsupportedSignatureSchema(String),
    #[error("unsupported SIF release-authority policy signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("SIF release-authority {field} is empty or too long")]
    InvalidPolicyId { field: &'static str },
    #[error("SIF release-authority policy cannot supersede itself")]
    SelfSupersession,
    #[error("SIF release-authority policy epoch must be greater than zero")]
    ZeroPolicyEpoch,
    #[error("minimum SIF release-authority policy epoch must be greater than zero")]
    InvalidMinimumEpoch,
    #[error("SIF release-authority policy epoch rollback: observed {observed}, minimum {minimum}")]
    PolicyEpochRollback { observed: u64, minimum: u64 },
    #[error("SIF release-authority policy validity window is invalid")]
    InvalidValidityWindow,
    #[error("SIF release-authority policy is not currently valid")]
    PolicyOutsideValidityWindow,
    #[error("SIF release-authority policy has {observed} authorities; allowed range is 1..={maximum}")]
    InvalidAuthorityCount { observed: usize, maximum: usize },
    #[error("SIF release-authority policy threshold is invalid")]
    InvalidThreshold,
    #[error("SIF release-authority policy requires {required} trust domains but only {available} exist")]
    ImpossibleDomainThreshold { available: usize, required: u8 },
    #[error("SIF release-authority execution trust-domain id must not be all zero")]
    ZeroExecutionTrustDomain,
    #[error("SIF release-authority trust-domain id must not be all zero")]
    ZeroAuthorityTrustDomain,
    #[error("SIF release-authority policy repeats a trusted key")]
    DuplicateAuthorityKey,
    #[error("SIF release-authority policy contains an invalid Ed25519 authority public key")]
    InvalidAuthorityPublicKey,
    #[error("trusted SIF release-authority policy root is not a valid Ed25519 public key")]
    InvalidRootPublicKey,
    #[error("SIF release-authority policy root must be distinct from release-authority keys")]
    PolicyRootAlsoReleaseAuthority,
    #[error("SIF release-authority policy digest does not match its signature artifact")]
    PolicyDigestMismatch,
    #[error("SIF release-authority policy signature names a different trusted root")]
    RootKeyIdMismatch,
    #[error("SIF release-authority policy signature is invalid")]
    InvalidPolicySignature,
    #[error("SIF release-authority field {field} is not valid hexadecimal")]
    InvalidHex { field: &'static str },
    #[error("SIF release-authority field {field} must decode to exactly {expected} bytes")]
    InvalidHexLength {
        field: &'static str,
        expected: usize,
    },
    #[error("failed to read SIF release-authority {label}: {source}")]
    Read {
        label: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("SIF release-authority {label} file is {observed} bytes; maximum is {maximum}")]
    FileTooLarge {
        label: &'static str,
        observed: u64,
        maximum: u64,
    },
    #[error("failed to decode SIF release-authority {label} JSON: {source}")]
    Json {
        label: &'static str,
        #[source]
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(entries: &[(SigningKey, [u8; 32])]) -> SifReleaseAuthorityPolicyV1 {
        SifReleaseAuthorityPolicyV1 {
            schema: SIF_RELEASE_AUTHORITY_POLICY_SCHEMA.to_string(),
            policy_id: "release-prod-a".to_string(),
            policy_epoch: 7,
            valid_from_unix_secs: 1_000,
            valid_until_unix_secs: 2_000,
            local_execution_trust_domain_id_hex: hex::encode([0x44u8; 32]),
            min_valid_signatures: 2,
            min_distinct_trust_domains: 2,
            authorities: entries
                .iter()
                .map(|(key, domain)| SifReleaseAuthorityPolicyEntryV1 {
                    public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                    trust_domain_id_hex: hex::encode(domain),
                })
                .collect(),
            supersedes_policy_id: Some("release-prod-previous".to_string()),
        }
    }

    #[test]
    fn signed_policy_resolves_exact_runtime_trust_inputs() {
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let a = SigningKey::from_bytes(&[2u8; 32]);
        let b = SigningKey::from_bytes(&[3u8; 32]);
        let input = policy(&[(a, [0xA1; 32]), (b, [0xB2; 32])]);
        let signature = sign_sif_release_authority_policy(&input, &root).unwrap();

        let verified = verify_sif_release_authority_policy(
            &input,
            &signature,
            root.verifying_key().to_bytes(),
            7,
            1_500,
        )
        .unwrap();

        assert_eq!(verified.policy_id, "release-prod-a");
        assert_eq!(verified.policy_epoch, 7);
        assert_eq!(verified.authorities.len(), 2);
        assert_eq!(verified.credential_policy.min_valid_signatures, 2);
        assert_eq!(verified.credential_policy.min_distinct_trust_domains, 2);
        assert_eq!(verified.local_execution_trust_domain_id, [0x44; 32]);
        assert_eq!(
            verified.root_key_id,
            release_policy_root_key_id(&root.verifying_key().to_bytes())
        );
    }

    #[test]
    fn authority_order_does_not_change_policy_digest() {
        let root = SigningKey::from_bytes(&[4u8; 32]);
        let a = SigningKey::from_bytes(&[5u8; 32]);
        let b = SigningKey::from_bytes(&[6u8; 32]);
        let first = policy(&[(a.clone(), [0xA1; 32]), (b.clone(), [0xB2; 32])]);
        let second = policy(&[(b, [0xB2; 32]), (a, [0xA1; 32])]);
        let first_sig = sign_sif_release_authority_policy(&first, &root).unwrap();
        let second_sig = sign_sif_release_authority_policy(&second, &root).unwrap();
        assert_eq!(first_sig.policy_digest_hex, second_sig.policy_digest_hex);
    }

    #[test]
    fn stale_epoch_and_expired_policy_fail_closed() {
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let a = SigningKey::from_bytes(&[8u8; 32]);
        let b = SigningKey::from_bytes(&[9u8; 32]);
        let input = policy(&[(a, [0xA1; 32]), (b, [0xB2; 32])]);
        let signature = sign_sif_release_authority_policy(&input, &root).unwrap();

        assert!(matches!(
            verify_sif_release_authority_policy(
                &input,
                &signature,
                root.verifying_key().to_bytes(),
                8,
                1_500,
            ),
            Err(SifReleaseAuthorityPolicyError::PolicyEpochRollback { .. })
        ));
        assert!(matches!(
            verify_sif_release_authority_policy(
                &input,
                &signature,
                root.verifying_key().to_bytes(),
                7,
                2_000,
            ),
            Err(SifReleaseAuthorityPolicyError::PolicyOutsideValidityWindow)
        ));
    }

    #[test]
    fn wrong_root_and_policy_tamper_fail_closed() {
        let root = SigningKey::from_bytes(&[10u8; 32]);
        let wrong_root = SigningKey::from_bytes(&[11u8; 32]);
        let a = SigningKey::from_bytes(&[12u8; 32]);
        let b = SigningKey::from_bytes(&[13u8; 32]);
        let mut input = policy(&[(a, [0xA1; 32]), (b, [0xB2; 32])]);
        let signature = sign_sif_release_authority_policy(&input, &root).unwrap();

        assert!(matches!(
            verify_sif_release_authority_policy(
                &input,
                &signature,
                wrong_root.verifying_key().to_bytes(),
                7,
                1_500,
            ),
            Err(SifReleaseAuthorityPolicyError::RootKeyIdMismatch)
        ));

        input.min_valid_signatures = 1;
        assert!(matches!(
            verify_sif_release_authority_policy(
                &input,
                &signature,
                root.verifying_key().to_bytes(),
                7,
                1_500,
            ),
            Err(SifReleaseAuthorityPolicyError::PolicyDigestMismatch)
        ));
    }

    #[test]
    fn impossible_domain_threshold_and_root_overlap_are_refused() {
        let root = SigningKey::from_bytes(&[14u8; 32]);
        let a = SigningKey::from_bytes(&[15u8; 32]);
        let b = SigningKey::from_bytes(&[16u8; 32]);
        let same_domain = [0xAA; 32];
        let impossible = policy(&[(a, same_domain), (b, same_domain)]);
        assert!(matches!(
            sign_sif_release_authority_policy(&impossible, &root),
            Err(SifReleaseAuthorityPolicyError::ImpossibleDomainThreshold { .. })
        ));

        let other = SigningKey::from_bytes(&[17u8; 32]);
        let overlapping = policy(&[(root.clone(), [0xA1; 32]), (other, [0xB2; 32])]);
        let signature = sign_sif_release_authority_policy(&overlapping, &root).unwrap();
        assert!(matches!(
            verify_sif_release_authority_policy(
                &overlapping,
                &signature,
                root.verifying_key().to_bytes(),
                7,
                1_500,
            ),
            Err(SifReleaseAuthorityPolicyError::PolicyRootAlsoReleaseAuthority)
        ));
    }
}
