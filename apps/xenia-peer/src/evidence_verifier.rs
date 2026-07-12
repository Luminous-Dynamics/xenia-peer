// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Evidence bundle signature verification: the `--verify-evidence-bundle` /
//! `--verify-sealed-evidence-bundle` / `--verify-sealed-evidence-trust-policy-signature`
//! CLI commands, and the suite-selection machinery (classical Ed25519 vs.
//! ML-DSA-65 vs. ML-DSA-87) they share with the daemon's own evidence-export
//! path. Extracted out of `main.rs` (2026-07-12) — self-contained, no
//! dependency on `Args` or any other daemon-runtime state, just CLI-supplied
//! paths/keys/suite selections in, a verification report or error out.

use clap::ValueEnum;
use xenia_ledger::Ed25519EvidenceSignatureBackend;
#[cfg(feature = "pqc-signatures")]
use xenia_ledger::{MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum EvidenceVerifierSuite {
    Ed25519Rfc8032,
    MlDsa65Fips204,
    MlDsa87Fips204,
}

impl EvidenceVerifierSuite {
    const fn stable_label(self) -> &'static str {
        match self {
            Self::Ed25519Rfc8032 => "ed25519-rfc8032",
            Self::MlDsa65Fips204 => "ml-dsa-65-fips204",
            Self::MlDsa87Fips204 => "ml-dsa-87-fips204",
        }
    }

    const fn is_post_quantum(self) -> bool {
        !matches!(self, Self::Ed25519Rfc8032)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum EvidenceProfileRequirement {
    HybridPrePqcV1,
    FullPqcV1,
}

impl EvidenceProfileRequirement {
    const fn stable_label(self) -> &'static str {
        match self {
            Self::HybridPrePqcV1 => "hybrid-pre-pqc-v1",
            Self::FullPqcV1 => "full-pqc-v1",
        }
    }

    const fn expected_downgrade_policy_label(self) -> &'static str {
        match self {
            Self::HybridPrePqcV1 => "explicit-classical-signature-allowance",
            Self::FullPqcV1 => "reject-classical-signatures",
        }
    }
}
pub fn parse_evidence_public_key_hex(
    hex_text: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_text)?;
    if bytes.is_empty() {
        return Err("evidence public key must not be empty".into());
    }
    Ok(bytes)
}

fn parse_evidence_key_fingerprint_hex(
    hex_text: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_text)?;
    let found = bytes.len();
    let fingerprint: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("evidence key fingerprint must be exactly 32 bytes, found {found}"))?;
    Ok(fingerprint)
}

pub struct ResolvedSealedEvidenceTrust {
    pub trusted_transcript_key_fingerprint: [u8; 32],
    pub trusted_ledger_key_fingerprint: [u8; 32],
    pub trust_policy: Option<crate::m1_runtime::SealedEvidenceTrustPolicyReceipt>,
}

/// The sealed-evidence trust-anchor inputs, all derived from CLI flags.
/// Bundled into one struct so [`resolve_sealed_evidence_trust_anchors`] takes
/// a single argument rather than ten positional ones.
#[derive(Clone, Copy)]
pub struct SealedEvidenceTrustInputs<'a> {
    pub trust_policy_path: Option<&'a std::path::Path>,
    pub trust_policy_signature_path: Option<&'a std::path::Path>,
    pub trusted_policy_root_fingerprint_hex: Option<&'a str>,
    pub policy_roots_path: Option<&'a std::path::Path>,
    pub required_policy_root_id: Option<&'a str>,
    pub trusted_transcript_key_fingerprint_hex: Option<&'a str>,
    pub trusted_ledger_key_fingerprint_hex: Option<&'a str>,
    pub suite: EvidenceVerifierSuite,
    pub minimum_policy_epoch: Option<u64>,
    pub require_signed_policy: bool,
}

pub fn resolve_sealed_evidence_trust_anchors(
    inputs: SealedEvidenceTrustInputs,
) -> Result<ResolvedSealedEvidenceTrust, Box<dyn std::error::Error>> {
    let SealedEvidenceTrustInputs {
        trust_policy_path,
        trust_policy_signature_path,
        trusted_policy_root_fingerprint_hex,
        policy_roots_path,
        required_policy_root_id,
        trusted_transcript_key_fingerprint_hex,
        trusted_ledger_key_fingerprint_hex,
        suite,
        minimum_policy_epoch,
        require_signed_policy,
    } = inputs;
    if let Some(path) = trust_policy_path {
        let policy = crate::m1_runtime::read_sealed_evidence_trust_policy_file(path)?;
        if let Some(minimum_policy_epoch) = minimum_policy_epoch {
            crate::m1_runtime::require_sealed_evidence_trust_policy_minimum_epoch(
                &policy,
                minimum_policy_epoch,
            )?;
        }
        let trust_anchors =
            crate::m1_runtime::sealed_evidence_trust_policy_anchors(&policy, suite.stable_label())?;
        let mut trust_policy = crate::m1_runtime::sealed_evidence_trust_policy_receipt_file(
            path,
            &policy,
            suite.stable_label(),
        )?;
        if let Some(signature_path) = trust_policy_signature_path {
            let (trusted_policy_root_fingerprint, root_receipt) = if let Some(roots_path) =
                policy_roots_path
            {
                if trusted_policy_root_fingerprint_hex.is_some() {
                    return Err("use either --sealed-evidence-policy-roots or --trusted-sealed-evidence-policy-root-fingerprint-hex, not both".into());
                }
                let root_receipt =
                    crate::m1_runtime::sealed_evidence_policy_root_receipt_file_for_signature(
                        roots_path,
                        signature_path,
                        suite.stable_label(),
                        required_policy_root_id,
                    )?;
                let trusted_policy_root_fingerprint = parse_evidence_key_fingerprint_hex(
                    &root_receipt.policy_root_key_fingerprint_hex,
                )?;
                (trusted_policy_root_fingerprint, Some(root_receipt))
            } else {
                if required_policy_root_id.is_some() {
                    return Err("--required-sealed-evidence-policy-root-id requires --sealed-evidence-policy-roots".into());
                }
                let root_fingerprint_hex = trusted_policy_root_fingerprint_hex.ok_or(
                        "--sealed-evidence-trust-policy-signature requires either --sealed-evidence-policy-roots or --trusted-sealed-evidence-policy-root-fingerprint-hex",
                    )?;
                (
                    parse_evidence_key_fingerprint_hex(root_fingerprint_hex)?,
                    None,
                )
            };

            let signature_receipt =
                verify_sealed_evidence_trust_policy_signature_with_selected_suite(
                    path,
                    signature_path,
                    suite,
                    trusted_policy_root_fingerprint,
                )?;
            crate::m1_runtime::attach_sealed_evidence_trust_policy_signature_receipt(
                &mut trust_policy,
                signature_receipt,
            );
            if let Some(root_receipt) = root_receipt {
                crate::m1_runtime::attach_sealed_evidence_policy_root_receipt(
                    &mut trust_policy,
                    root_receipt,
                );
            }
        } else if require_signed_policy {
            return Err("--require-signed-sealed-evidence-trust-policy requires --sealed-evidence-trust-policy-signature".into());
        } else if trusted_policy_root_fingerprint_hex.is_some() {
            return Err("--trusted-sealed-evidence-policy-root-fingerprint-hex requires --sealed-evidence-trust-policy-signature".into());
        } else if policy_roots_path.is_some() {
            return Err(
                "--sealed-evidence-policy-roots requires --sealed-evidence-trust-policy-signature"
                    .into(),
            );
        } else if required_policy_root_id.is_some() {
            return Err(
                "--required-sealed-evidence-policy-root-id requires --sealed-evidence-policy-roots"
                    .into(),
            );
        }
        return Ok(ResolvedSealedEvidenceTrust {
            trusted_transcript_key_fingerprint: trust_anchors.trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint: trust_anchors.trusted_ledger_key_fingerprint,
            trust_policy: Some(trust_policy),
        });
    }

    if trust_policy_signature_path.is_some()
        || trusted_policy_root_fingerprint_hex.is_some()
        || policy_roots_path.is_some()
        || required_policy_root_id.is_some()
        || require_signed_policy
    {
        return Err(
            "signed sealed evidence trust policy flags require --sealed-evidence-trust-policy"
                .into(),
        );
    }

    let transcript_fingerprint_hex = trusted_transcript_key_fingerprint_hex
        .ok_or("--verify-sealed-evidence-bundle requires either --sealed-evidence-trust-policy or --trusted-transcript-key-fingerprint-hex")?;
    let ledger_fingerprint_hex = trusted_ledger_key_fingerprint_hex
        .ok_or("--verify-sealed-evidence-bundle requires either --sealed-evidence-trust-policy or --trusted-ledger-key-fingerprint-hex")?;

    Ok(ResolvedSealedEvidenceTrust {
        trusted_transcript_key_fingerprint: parse_evidence_key_fingerprint_hex(
            transcript_fingerprint_hex,
        )?,
        trusted_ledger_key_fingerprint: parse_evidence_key_fingerprint_hex(ledger_fingerprint_hex)?,
        trust_policy: None,
    })
}

fn parse_ed25519_public_key_bytes(
    bytes: &[u8],
) -> Result<ed25519_dalek::VerifyingKey, Box<dyn std::error::Error>> {
    let public_key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be exactly 32 bytes")?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)?)
}

pub fn verify_evidence_bundle_with_selected_suite(
    bundle_dir: &std::path::Path,
    public_key: &[u8],
    suite: EvidenceVerifierSuite,
    required_profile: Option<EvidenceProfileRequirement>,
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    preflight_evidence_verifier_selection(bundle_dir, suite, required_profile)?;

    match suite {
        EvidenceVerifierSuite::Ed25519Rfc8032 => {
            let public_key = parse_ed25519_public_key_bytes(public_key)?;
            let backend = Ed25519EvidenceSignatureBackend;
            Ok(
                crate::m1_runtime::verify_transcript_bound_evidence_bundle_dir_with_backend(
                    bundle_dir,
                    &public_key.to_bytes(),
                    &backend,
                )?,
            )
        }
        EvidenceVerifierSuite::MlDsa65Fips204 => {
            verify_ml_dsa_65_evidence_bundle(bundle_dir, public_key)
        }
        EvidenceVerifierSuite::MlDsa87Fips204 => {
            verify_ml_dsa_87_evidence_bundle(bundle_dir, public_key)
        }
    }
}

pub fn verify_sealed_evidence_bundle_with_selected_suite(
    bundle_dir: &std::path::Path,
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
    suite: EvidenceVerifierSuite,
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    validate_sealed_evidence_verifier_suite(suite)?;

    match suite {
        EvidenceVerifierSuite::Ed25519Rfc8032 => unreachable!(
            "validate_sealed_evidence_verifier_suite rejects classical sealed full-PQC verification"
        ),
        EvidenceVerifierSuite::MlDsa65Fips204 => verify_sealed_ml_dsa_65_evidence_bundle(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
        ),
        EvidenceVerifierSuite::MlDsa87Fips204 => verify_sealed_ml_dsa_87_evidence_bundle(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
        ),
    }
}

fn verify_sealed_evidence_trust_policy_signature_with_selected_suite(
    policy_path: &std::path::Path,
    signature_path: &std::path::Path,
    suite: EvidenceVerifierSuite,
    trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    validate_sealed_evidence_verifier_suite(suite)?;

    match suite {
        EvidenceVerifierSuite::Ed25519Rfc8032 => unreachable!(
            "validate_sealed_evidence_verifier_suite rejects classical sealed full-PQC verification"
        ),
        EvidenceVerifierSuite::MlDsa65Fips204 => {
            verify_ml_dsa_65_sealed_evidence_trust_policy_signature(
                policy_path,
                signature_path,
                trusted_policy_root_fingerprint,
            )
        }
        EvidenceVerifierSuite::MlDsa87Fips204 => {
            verify_ml_dsa_87_sealed_evidence_trust_policy_signature(
                policy_path,
                signature_path,
                trusted_policy_root_fingerprint,
            )
        }
    }
}

fn validate_sealed_evidence_verifier_suite(
    suite: EvidenceVerifierSuite,
) -> Result<(), Box<dyn std::error::Error>> {
    if suite.is_post_quantum() {
        Ok(())
    } else {
        Err("sealed full-PQC evidence verification requires an ML-DSA verifier suite".into())
    }
}

fn preflight_evidence_verifier_selection(
    bundle_dir: &std::path::Path,
    suite: EvidenceVerifierSuite,
    required_profile: Option<EvidenceProfileRequirement>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = crate::m1_runtime::read_evidence_crypto_manifest_export_dir(bundle_dir)?;
    let selected_label = suite.stable_label();

    if let Some(required_profile) = required_profile {
        validate_required_profile_suite(required_profile, suite)?;

        let required_label = required_profile.stable_label();
        if manifest.profile != required_label {
            return Err(format!(
                "evidence profile {:?} does not satisfy required evidence profile {required_label:?}",
                manifest.profile
            )
            .into());
        }

        let expected_downgrade_policy = required_profile.expected_downgrade_policy_label();
        if manifest.downgrade_policy != expected_downgrade_policy {
            return Err(format!(
                "evidence downgrade policy {:?} does not satisfy required evidence profile {required_label:?}; expected {expected_downgrade_policy:?}",
                manifest.downgrade_policy
            )
            .into());
        }
    }

    if manifest.transcript_signature != selected_label {
        return Err(format!(
            "evidence transcript signature {:?} does not match requested verifier suite {selected_label:?}",
            manifest.transcript_signature
        )
        .into());
    }

    if manifest.ledger_signature != selected_label {
        return Err(format!(
            "evidence ledger signature {:?} does not match requested verifier suite {selected_label:?}",
            manifest.ledger_signature
        )
        .into());
    }

    Ok(())
}

fn validate_required_profile_suite(
    required_profile: EvidenceProfileRequirement,
    suite: EvidenceVerifierSuite,
) -> Result<(), Box<dyn std::error::Error>> {
    match required_profile {
        EvidenceProfileRequirement::HybridPrePqcV1
            if suite == EvidenceVerifierSuite::Ed25519Rfc8032 =>
        {
            Ok(())
        }
        EvidenceProfileRequirement::HybridPrePqcV1 => Err(format!(
            "evidence profile {:?} requires verifier suite {:?}, got {:?}",
            required_profile.stable_label(),
            EvidenceVerifierSuite::Ed25519Rfc8032.stable_label(),
            suite.stable_label()
        )
        .into()),
        EvidenceProfileRequirement::FullPqcV1 if suite.is_post_quantum() => Ok(()),
        EvidenceProfileRequirement::FullPqcV1 => Err(format!(
            "evidence profile {:?} requires a post-quantum verifier suite, got {:?}",
            required_profile.stable_label(),
            suite.stable_label()
        )
        .into()),
    }
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_65_evidence_bundle(
    bundle_dir: &std::path::Path,
    public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa65EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir, public_key, &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_65_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--evidence-signature-suite ml-dsa-65-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_87_evidence_bundle(
    bundle_dir: &std::path::Path,
    public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa87EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir, public_key, &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_87_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _public_key: &[u8],
) -> Result<crate::m1_runtime::EvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--evidence-signature-suite ml-dsa-87-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_sealed_ml_dsa_65_evidence_bundle(
    bundle_dir: &std::path::Path,
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa65EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_sealed_ml_dsa_65_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _trusted_transcript_key_fingerprint: [u8; 32],
    _trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--sealed-evidence-signature-suite ml-dsa-65-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_65_sealed_evidence_trust_policy_signature(
    policy_path: &std::path::Path,
    signature_path: &std::path::Path,
    trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    let backend = MlDsa65EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_evidence_trust_policy_signature_file_with_backend(
            policy_path,
            signature_path,
            EvidenceVerifierSuite::MlDsa65Fips204.stable_label(),
            trusted_policy_root_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_65_sealed_evidence_trust_policy_signature(
    _policy_path: &std::path::Path,
    _signature_path: &std::path::Path,
    _trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    Err("--sealed-evidence-trust-policy-signature with ml-dsa-65-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_sealed_ml_dsa_87_evidence_bundle(
    bundle_dir: &std::path::Path,
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    let backend = MlDsa87EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_transcript_bound_evidence_bundle_dir_with_backend(
            bundle_dir,
            trusted_transcript_key_fingerprint,
            trusted_ledger_key_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_sealed_ml_dsa_87_evidence_bundle(
    _bundle_dir: &std::path::Path,
    _trusted_transcript_key_fingerprint: [u8; 32],
    _trusted_ledger_key_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceVerificationReport, Box<dyn std::error::Error>> {
    Err("--sealed-evidence-signature-suite ml-dsa-87-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa_87_sealed_evidence_trust_policy_signature(
    policy_path: &std::path::Path,
    signature_path: &std::path::Path,
    trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    let backend = MlDsa87EvidenceSignatureBackend;
    Ok(
        crate::m1_runtime::verify_sealed_evidence_trust_policy_signature_file_with_backend(
            policy_path,
            signature_path,
            EvidenceVerifierSuite::MlDsa87Fips204.stable_label(),
            trusted_policy_root_fingerprint,
            &backend,
        )?,
    )
}

#[cfg(not(feature = "pqc-signatures"))]
fn verify_ml_dsa_87_sealed_evidence_trust_policy_signature(
    _policy_path: &std::path::Path,
    _signature_path: &std::path::Path,
    _trusted_policy_root_fingerprint: [u8; 32],
) -> Result<crate::m1_runtime::SealedEvidenceTrustPolicySignatureReceipt, Box<dyn std::error::Error>>
{
    Err("--sealed-evidence-trust-policy-signature with ml-dsa-87-fips204 requires building xenia-peer with feature `pqc-signatures`".into())
}

#[cfg(test)]
mod evidence_verifier_preflight_tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use uuid::Uuid;

    fn manifest_dir(test_name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xenia-peer-pqc-preflight-{test_name}-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_manifest(
        dir: &Path,
        profile: &str,
        transcript_signature: &str,
        ledger_signature: &str,
        downgrade_policy: &str,
    ) {
        let manifest = serde_json::json!({
            "schema": "xenia-evidence-crypto-manifest-v1",
            "profile": profile,
            "kem": "ml-kem-768-fips203",
            "transcript_signature": transcript_signature,
            "ledger_signature": ledger_signature,
            "hash_chain": "blake3-256",
            "kdf": "hkdf-sha256",
            "aead": "chacha20-poly1305",
            "downgrade_policy": downgrade_policy,
        });
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(dir.join("evidence_manifest.json"), bytes).unwrap();
    }

    #[test]
    fn preflight_accepts_matching_hybrid_profile_and_ed25519_suite() {
        let dir = manifest_dir("hybrid-ok");
        write_manifest(
            &dir,
            "hybrid-pre-pqc-v1",
            "ed25519-rfc8032",
            "ed25519-rfc8032",
            "explicit-classical-signature-allowance",
        );

        preflight_evidence_verifier_selection(
            &dir,
            EvidenceVerifierSuite::Ed25519Rfc8032,
            Some(EvidenceProfileRequirement::HybridPrePqcV1),
        )
        .unwrap();

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preflight_rejects_transcript_suite_mismatch() {
        let dir = manifest_dir("transcript-mismatch");
        write_manifest(
            &dir,
            "full-pqc-v1",
            "ml-dsa-87-fips204",
            "ml-dsa-65-fips204",
            "reject-classical-signatures",
        );

        let err = preflight_evidence_verifier_selection(
            &dir,
            EvidenceVerifierSuite::MlDsa65Fips204,
            Some(EvidenceProfileRequirement::FullPqcV1),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("evidence transcript signature"));
        assert!(err.contains("requested verifier suite"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preflight_rejects_full_pqc_requirement_with_classical_suite() {
        let err = validate_required_profile_suite(
            EvidenceProfileRequirement::FullPqcV1,
            EvidenceVerifierSuite::Ed25519Rfc8032,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("requires a post-quantum verifier suite"));
    }

    #[test]
    fn preflight_rejects_required_profile_downgrade_policy_mismatch() {
        let dir = manifest_dir("downgrade-policy-mismatch");
        write_manifest(
            &dir,
            "full-pqc-v1",
            "ml-dsa-65-fips204",
            "ml-dsa-65-fips204",
            "explicit-classical-signature-allowance",
        );

        let err = preflight_evidence_verifier_selection(
            &dir,
            EvidenceVerifierSuite::MlDsa65Fips204,
            Some(EvidenceProfileRequirement::FullPqcV1),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("evidence downgrade policy"));
        assert!(err.contains("reject-classical-signatures"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sealed_verifier_rejects_classical_suite() {
        let err = validate_sealed_evidence_verifier_suite(EvidenceVerifierSuite::Ed25519Rfc8032)
            .unwrap_err()
            .to_string();

        assert!(err.contains("sealed full-PQC"));
        assert!(err.contains("ML-DSA"));
    }

    #[test]
    fn evidence_key_fingerprint_parser_requires_32_bytes() {
        let ok = parse_evidence_key_fingerprint_hex(&"ab".repeat(32)).unwrap();
        assert_eq!(ok, [0xAB; 32]);

        let err = parse_evidence_key_fingerprint_hex(&"ab".repeat(31))
            .unwrap_err()
            .to_string();
        assert!(err.contains("exactly 32 bytes"));
    }
}
