// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-local M1 runtime skeleton.
//!
//! This module wires the deterministic M1 session state machine to the
//! consent ledger without adding networking, capture, GUI, or real input
//! injection. It is the first app-layer runtime bridge:
//!
//! session transition -> audit event -> consent-boundary ledger record.
//!
//! Frame and input operation events remain state-machine audit events, but
//! they are deliberately not represented as consent ledger entries yet.

#![allow(dead_code)] // Skeleton lands before daemon CLI/runtime integration.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xenia_ledger::{
    CURRENT_EVIDENCE_CRYPTO_MANIFEST, Chain, ConsentKind, CryptoPolicyProfile, DowngradePolicy,
    Ed25519EvidenceSignatureBackend, EvidenceBundleSeal, EvidenceBundleVerifyError,
    EvidenceCryptoManifest, EvidencePublicKeyBinding, EvidenceSignatureBackend, LedgerEntry,
    LedgerEntryExport, LedgerError, SessionTranscriptBinding, SessionTranscriptSignature,
    SignatureEnvelope, SignatureSuite, Verifier, VerifyError,
};
use xenia_peer_core::{
    M1Permission, M1PermissionSet, M1SessionError, M1SessionMachine, M1SessionState,
};

use crate::m1_ledger::consent_record_for_m1_event;

#[derive(Debug)]
pub(crate) enum M1RuntimeError {
    Session(M1SessionError),
    Ledger(LedgerError),
    Verify(VerifyError),
    EvidenceBundle(EvidenceBundleVerifyError),
    MissingTranscriptBinding,
    FullPqcRuntimeUnavailable {
        transcript_signature: String,
        ledger_signature: String,
    },
    UnsupportedEvidenceExportProfile(String),
    EvidenceManifest(String),
    TrustedKeyFingerprintMismatch {
        surface: &'static str,
        trusted: [u8; 32],
        bundle: [u8; 32],
    },
    PersistIo(std::io::Error),
    PersistCodec(bincode::Error),
    PersistJson(serde_json::Error),
}

impl fmt::Display for M1RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(err) => write!(f, "M1 session error: {err}"),
            Self::Ledger(err) => write!(f, "M1 ledger error: {err}"),
            Self::Verify(err) => write!(f, "M1 ledger verification error: {err}"),
            Self::EvidenceBundle(err) => write!(f, "M1 transcript-bound evidence error: {err}"),
            Self::MissingTranscriptBinding => write!(
                f,
                "M1 session has no canonical handshake transcript hash bound"
            ),
            Self::FullPqcRuntimeUnavailable {
                transcript_signature,
                ledger_signature,
            } => write!(
                f,
                "full-pqc-v1 evidence export is unavailable: transcript_signature={transcript_signature}, ledger_signature={ledger_signature}"
            ),
            Self::UnsupportedEvidenceExportProfile(profile) => {
                write!(f, "unsupported evidence export profile: {profile}")
            }
            Self::EvidenceManifest(err) => write!(f, "M1 evidence manifest error: {err}"),
            Self::TrustedKeyFingerprintMismatch {
                surface,
                trusted,
                bundle,
            } => write!(
                f,
                "M1 sealed evidence {surface} key fingerprint did not match trust anchor: trusted={}, bundle={}",
                hex::encode(trusted),
                hex::encode(bundle)
            ),
            Self::PersistIo(err) => write!(f, "M1 ledger persistence I/O error: {err}"),
            Self::PersistCodec(err) => write!(f, "M1 ledger persistence codec error: {err}"),
            Self::PersistJson(err) => write!(f, "M1 evidence JSON persistence error: {err}"),
        }
    }
}

impl Error for M1RuntimeError {}

impl From<M1SessionError> for M1RuntimeError {
    fn from(err: M1SessionError) -> Self {
        Self::Session(err)
    }
}

impl From<LedgerError> for M1RuntimeError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err)
    }
}

impl From<VerifyError> for M1RuntimeError {
    fn from(err: VerifyError) -> Self {
        Self::Verify(err)
    }
}

impl From<EvidenceBundleVerifyError> for M1RuntimeError {
    fn from(err: EvidenceBundleVerifyError) -> Self {
        Self::EvidenceBundle(err)
    }
}

impl From<std::io::Error> for M1RuntimeError {
    fn from(err: std::io::Error) -> Self {
        Self::PersistIo(err)
    }
}

impl From<bincode::Error> for M1RuntimeError {
    fn from(err: bincode::Error) -> Self {
        Self::PersistCodec(err)
    }
}

impl From<serde_json::Error> for M1RuntimeError {
    fn from(err: serde_json::Error) -> Self {
        Self::PersistJson(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EvidenceCryptoManifestExport {
    pub schema: String,
    pub profile: String,
    pub kem: String,
    pub transcript_signature: String,
    pub ledger_signature: String,
    pub hash_chain: String,
    pub kdf: String,
    pub aead: String,
    pub downgrade_policy: String,
}

impl EvidenceCryptoManifestExport {
    pub(crate) fn current() -> Self {
        let manifest = CURRENT_EVIDENCE_CRYPTO_MANIFEST;
        Self {
            schema: manifest.schema.to_string(),
            profile: manifest.profile.stable_label().to_string(),
            kem: manifest.kem.to_string(),
            transcript_signature: manifest.transcript_signature.stable_label().to_string(),
            ledger_signature: manifest.ledger_signature.stable_label().to_string(),
            hash_chain: manifest.hash_chain.to_string(),
            kdf: manifest.kdf.to_string(),
            aead: manifest.aead.to_string(),
            downgrade_policy: manifest.downgrade_policy.stable_label().to_string(),
        }
    }

    fn to_manifest(&self) -> Result<EvidenceCryptoManifest, M1RuntimeError> {
        let current = CURRENT_EVIDENCE_CRYPTO_MANIFEST;
        require_label("schema", &self.schema, current.schema)?;
        require_label("kem", &self.kem, current.kem)?;
        require_label("hash_chain", &self.hash_chain, current.hash_chain)?;
        require_label("kdf", &self.kdf, current.kdf)?;
        require_label("aead", &self.aead, current.aead)?;

        let profile = match self.profile.as_str() {
            "hybrid-pre-pqc-v1" => CryptoPolicyProfile::HybridPrePqcV1,
            "full-pqc-v1" => CryptoPolicyProfile::FullPqcV1,
            other => {
                return Err(M1RuntimeError::EvidenceManifest(format!(
                    "unsupported profile label {other:?}"
                )));
            }
        };
        let transcript_signature = SignatureSuite::from_stable_label(&self.transcript_signature)
            .ok_or_else(|| {
                M1RuntimeError::EvidenceManifest(format!(
                    "unsupported transcript_signature label {:?}",
                    self.transcript_signature
                ))
            })?;
        let ledger_signature = SignatureSuite::from_stable_label(&self.ledger_signature)
            .ok_or_else(|| {
                M1RuntimeError::EvidenceManifest(format!(
                    "unsupported ledger_signature label {:?}",
                    self.ledger_signature
                ))
            })?;
        let downgrade_policy = match self.downgrade_policy.as_str() {
            "explicit-classical-signature-allowance" => {
                DowngradePolicy::ExplicitClassicalSignatureAllowance
            }
            "reject-classical-signatures" => DowngradePolicy::RejectClassicalSignatures,
            other => {
                return Err(M1RuntimeError::EvidenceManifest(format!(
                    "unsupported downgrade_policy label {other:?}"
                )));
            }
        };

        Ok(EvidenceCryptoManifest {
            schema: current.schema,
            profile,
            kem: current.kem,
            transcript_signature,
            ledger_signature,
            hash_chain: current.hash_chain,
            kdf: current.kdf,
            aead: current.aead,
            downgrade_policy,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EvidenceArtifactDigests {
    pub schema: String,
    pub hash_algorithm: String,
    pub evidence_manifest_blake3: String,
    pub ledger_entries_blake3: String,
    pub session_transcript_binding_blake3: String,
    pub artifact_set_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEvidenceArtifactDigests {
    pub schema: String,
    pub hash_algorithm: String,
    pub evidence_manifest_blake3: String,
    pub session_transcript_binding_blake3: String,
    pub session_transcript_signature_blake3: String,
    pub transcript_public_key_binding_blake3: String,
    pub ledger_public_key_binding_blake3: String,
    pub ledger_entries_blake3: String,
    pub evidence_bundle_seal_blake3: String,
    pub artifact_set_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EvidenceVerificationReport {
    pub schema: String,
    pub verifier: String,
    pub verified: bool,
    pub profile: String,
    pub ledger_entries: usize,
    pub session_id: Uuid,
    pub transcript_hash_algorithm: String,
    pub transcript_signature: String,
    pub ledger_signature: String,
    pub operator_public_key_hex: String,
    pub artifacts: EvidenceArtifactDigests,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEvidenceTrustPolicyReceipt {
    pub schema: String,
    pub source: String,
    pub profile: String,
    pub signature_suite: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_blake3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_signature_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_signature_blake3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_root_key_fingerprint_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_roots_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_roots_blake3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_root_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_root_valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_root_valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_root_supersedes_root_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEvidenceVerificationReport {
    pub schema: String,
    pub verifier: String,
    pub verified: bool,
    pub profile: String,
    pub ledger_entries: usize,
    pub session_id: Uuid,
    pub transcript_hash_algorithm: String,
    pub transcript_signature: String,
    pub ledger_signature: String,
    pub transcript_public_key_fingerprint_hex: String,
    pub ledger_public_key_fingerprint_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_policy: Option<SealedEvidenceTrustPolicyReceipt>,
    pub artifacts: SealedEvidenceArtifactDigests,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEvidenceTrustPolicy {
    pub schema: String,
    pub profile: String,
    pub signature_suite: String,
    pub trusted_transcript_key_fingerprint_hex: String,
    pub trusted_ledger_key_fingerprint_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub revoked_policy_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEvidenceTrustPolicySignature {
    pub schema: String,
    pub policy_schema: String,
    pub profile: String,
    pub signature_suite: String,
    pub policy_blake3: String,
    pub root_public_key_binding: EvidencePublicKeyBinding,
    pub signature: SignatureEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEvidencePolicyRoots {
    pub schema: String,
    pub profile: String,
    pub signature_suite: String,
    pub roots: Vec<SealedEvidencePolicyRoot>,
    #[serde(default)]
    pub revoked_root_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEvidencePolicyRoot {
    pub root_id: String,
    pub root_key_fingerprint_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_root_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedEvidencePolicyRootReceipt {
    pub policy_roots_path: String,
    pub policy_roots_blake3: String,
    pub policy_root_id: String,
    pub policy_root_key_fingerprint_hex: String,
    pub policy_root_valid_from: Option<String>,
    pub policy_root_valid_until: Option<String>,
    pub policy_root_supersedes_root_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedEvidenceTrustPolicySignatureReceipt {
    pub policy_signature_path: String,
    pub policy_signature_blake3: String,
    pub policy_root_key_fingerprint_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedEvidenceTrustAnchors {
    pub trusted_transcript_key_fingerprint: [u8; 32],
    pub trusted_ledger_key_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct M1EvidenceBundlePaths {
    pub dir: PathBuf,
    pub manifest: PathBuf,
    pub ledger_entries: PathBuf,
    pub session_transcript_binding: PathBuf,
    pub verification_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct M1SealedEvidenceBundlePaths {
    pub dir: PathBuf,
    pub manifest: PathBuf,
    pub session_transcript_binding: PathBuf,
    pub session_transcript_signature: PathBuf,
    pub transcript_public_key_binding: PathBuf,
    pub ledger_public_key_binding: PathBuf,
    pub ledger_entries: PathBuf,
    pub evidence_bundle_seal: PathBuf,
    pub verification_report: PathBuf,
}

pub(crate) fn verify_transcript_bound_evidence_bundle_dir(
    dir: impl AsRef<Path>,
    public_key: &VerifyingKey,
) -> Result<EvidenceVerificationReport, M1RuntimeError> {
    verify_transcript_bound_evidence_bundle_dir_with_backend(
        dir,
        &public_key.to_bytes(),
        &Ed25519EvidenceSignatureBackend,
    )
}

pub(crate) fn read_evidence_crypto_manifest_export_dir(
    dir: impl AsRef<Path>,
) -> Result<EvidenceCryptoManifestExport, M1RuntimeError> {
    read_json(&dir.as_ref().join("evidence_manifest.json"))
}

pub(crate) fn read_evidence_verification_report_dir(
    dir: impl AsRef<Path>,
) -> Result<EvidenceVerificationReport, M1RuntimeError> {
    read_json(&evidence_bundle_paths(dir.as_ref()).verification_report)
}

pub(crate) fn read_sealed_evidence_verification_report_dir(
    dir: impl AsRef<Path>,
) -> Result<SealedEvidenceVerificationReport, M1RuntimeError> {
    read_json(&sealed_evidence_bundle_paths(dir.as_ref()).verification_report)
}

pub(crate) fn read_sealed_evidence_trust_policy_file(
    path: impl AsRef<Path>,
) -> Result<SealedEvidenceTrustPolicy, M1RuntimeError> {
    read_json(path.as_ref())
}

pub(crate) fn read_sealed_evidence_trust_policy_signature_file(
    path: impl AsRef<Path>,
) -> Result<SealedEvidenceTrustPolicySignature, M1RuntimeError> {
    read_json(path.as_ref())
}

pub(crate) fn read_sealed_evidence_policy_roots_file(
    path: impl AsRef<Path>,
) -> Result<SealedEvidencePolicyRoots, M1RuntimeError> {
    read_json(path.as_ref())
}

pub(crate) fn sealed_evidence_policy_root_receipt_file_for_signature(
    roots_path: impl AsRef<Path>,
    signature_path: impl AsRef<Path>,
    expected_signature_suite: &str,
    required_root_id: Option<&str>,
) -> Result<SealedEvidencePolicyRootReceipt, M1RuntimeError> {
    let roots_path = roots_path.as_ref();
    let signature = read_sealed_evidence_trust_policy_signature_file(signature_path.as_ref())?;
    let roots = read_sealed_evidence_policy_roots_file(roots_path)?;
    let root_fingerprint_hex =
        hex::encode(signature.root_public_key_binding.public_key_fingerprint);
    let root = require_sealed_evidence_policy_root_at(
        &roots,
        expected_signature_suite,
        &root_fingerprint_hex,
        required_root_id,
        Utc::now(),
    )?;

    Ok(SealedEvidencePolicyRootReceipt {
        policy_roots_path: roots_path.display().to_string(),
        policy_roots_blake3: blake3_file_hex(roots_path)?,
        policy_root_id: root.root_id.clone(),
        policy_root_key_fingerprint_hex: root.root_key_fingerprint_hex.clone(),
        policy_root_valid_from: root.valid_from.clone(),
        policy_root_valid_until: root.valid_until.clone(),
        policy_root_supersedes_root_id: root.supersedes_root_id.clone(),
    })
}

pub(crate) fn sealed_evidence_trust_policy_anchors(
    policy: &SealedEvidenceTrustPolicy,
    expected_signature_suite: &str,
) -> Result<SealedEvidenceTrustAnchors, M1RuntimeError> {
    require_sealed_evidence_trust_policy(policy, expected_signature_suite)?;

    Ok(SealedEvidenceTrustAnchors {
        trusted_transcript_key_fingerprint: parse_trust_policy_fingerprint_hex(
            "transcript",
            &policy.trusted_transcript_key_fingerprint_hex,
        )?,
        trusted_ledger_key_fingerprint: parse_trust_policy_fingerprint_hex(
            "ledger",
            &policy.trusted_ledger_key_fingerprint_hex,
        )?,
    })
}

pub(crate) fn sealed_evidence_trust_policy_receipt_file(
    path: impl AsRef<Path>,
    policy: &SealedEvidenceTrustPolicy,
    expected_signature_suite: &str,
) -> Result<SealedEvidenceTrustPolicyReceipt, M1RuntimeError> {
    let path = path.as_ref();
    require_sealed_evidence_trust_policy(policy, expected_signature_suite)?;

    Ok(SealedEvidenceTrustPolicyReceipt {
        schema: "xenia-sealed-evidence-trust-policy-receipt-v1".to_string(),
        source: "enrolled-policy".to_string(),
        profile: policy.profile.clone(),
        signature_suite: policy.signature_suite.clone(),
        policy_path: Some(path.display().to_string()),
        policy_blake3: Some(blake3_file_hex(path)?),
        policy_id: policy.policy_id.clone(),
        operator_id: policy.operator_id.clone(),
        policy_epoch: policy.policy_epoch,
        valid_from: policy.valid_from.clone(),
        valid_until: policy.valid_until.clone(),
        policy_signature_path: None,
        policy_signature_blake3: None,
        policy_root_key_fingerprint_hex: None,
        policy_roots_path: None,
        policy_roots_blake3: None,
        policy_root_id: None,
        policy_root_valid_from: None,
        policy_root_valid_until: None,
        policy_root_supersedes_root_id: None,
    })
}

pub(crate) fn attach_sealed_evidence_trust_policy_signature_receipt(
    receipt: &mut SealedEvidenceTrustPolicyReceipt,
    signature_receipt: SealedEvidenceTrustPolicySignatureReceipt,
) {
    receipt.source = "signed-enrolled-policy".to_string();
    receipt.policy_signature_path = Some(signature_receipt.policy_signature_path);
    receipt.policy_signature_blake3 = Some(signature_receipt.policy_signature_blake3);
    receipt.policy_root_key_fingerprint_hex =
        Some(signature_receipt.policy_root_key_fingerprint_hex);
}

pub(crate) fn attach_sealed_evidence_policy_root_receipt(
    receipt: &mut SealedEvidenceTrustPolicyReceipt,
    root_receipt: SealedEvidencePolicyRootReceipt,
) {
    receipt.policy_roots_path = Some(root_receipt.policy_roots_path);
    receipt.policy_roots_blake3 = Some(root_receipt.policy_roots_blake3);
    receipt.policy_root_id = Some(root_receipt.policy_root_id);
    receipt.policy_root_valid_from = root_receipt.policy_root_valid_from;
    receipt.policy_root_valid_until = root_receipt.policy_root_valid_until;
    receipt.policy_root_supersedes_root_id = root_receipt.policy_root_supersedes_root_id;
}

pub(crate) fn verify_sealed_evidence_trust_policy_signature_file_with_backend(
    policy_path: impl AsRef<Path>,
    signature_path: impl AsRef<Path>,
    expected_signature_suite: &str,
    trusted_policy_root_fingerprint: [u8; 32],
    backend: &impl EvidenceSignatureBackend,
) -> Result<SealedEvidenceTrustPolicySignatureReceipt, M1RuntimeError> {
    let policy_path = policy_path.as_ref();
    let signature_path = signature_path.as_ref();
    let signature = read_sealed_evidence_trust_policy_signature_file(signature_path)?;
    require_sealed_evidence_trust_policy_signature(
        &signature,
        expected_signature_suite,
        policy_path,
        trusted_policy_root_fingerprint,
        backend,
    )?;

    Ok(SealedEvidenceTrustPolicySignatureReceipt {
        policy_signature_path: signature_path.display().to_string(),
        policy_signature_blake3: blake3_file_hex(signature_path)?,
        policy_root_key_fingerprint_hex: hex::encode(
            signature.root_public_key_binding.public_key_fingerprint,
        ),
    })
}

pub(crate) fn write_sealed_evidence_verification_report_dir(
    dir: impl AsRef<Path>,
    report: &SealedEvidenceVerificationReport,
) -> Result<PathBuf, M1RuntimeError> {
    let path = sealed_evidence_bundle_paths(dir.as_ref()).verification_report;
    write_json(&path, report)?;
    Ok(path)
}

pub(crate) fn audit_evidence_verification_report_artifacts_dir(
    dir: impl AsRef<Path>,
) -> Result<EvidenceVerificationReport, M1RuntimeError> {
    let dir = dir.as_ref();
    let paths = evidence_bundle_paths(dir);
    let report = read_evidence_verification_report_dir(dir)?;
    require_evidence_verification_report_schema(&report)?;

    let actual_artifacts = evidence_artifact_digests(
        &paths.manifest,
        &paths.ledger_entries,
        &paths.session_transcript_binding,
    )?;
    require_evidence_report_artifacts_match_current_bundle(&report.artifacts, &actual_artifacts)?;

    Ok(report)
}

pub(crate) fn audit_sealed_evidence_verification_report_artifacts_dir(
    dir: impl AsRef<Path>,
) -> Result<SealedEvidenceVerificationReport, M1RuntimeError> {
    let dir = dir.as_ref();
    let paths = sealed_evidence_bundle_paths(dir);
    let report = read_sealed_evidence_verification_report_dir(dir)?;
    require_sealed_evidence_verification_report_schema(&report)?;

    let actual_artifacts = sealed_evidence_artifact_digests(&paths)?;
    require_sealed_evidence_report_artifacts_match_current_bundle(
        &report.artifacts,
        &actual_artifacts,
    )?;

    Ok(report)
}

pub(crate) fn verify_transcript_bound_evidence_bundle_dir_with_backend(
    dir: impl AsRef<Path>,
    public_key: &[u8],
    backend: &impl EvidenceSignatureBackend,
) -> Result<EvidenceVerificationReport, M1RuntimeError> {
    let dir = dir.as_ref();
    let paths = evidence_bundle_paths(dir);
    let manifest_export = read_evidence_crypto_manifest_export_dir(dir)?;
    let manifest = manifest_export.to_manifest()?;
    let binding: SessionTranscriptBinding = read_json(&paths.session_transcript_binding)?;
    let entries: Vec<LedgerEntryExport> = read_json(&paths.ledger_entries)?;

    Verifier::verify_transcript_bound_evidence_bundle_with_backend(
        manifest, &binding, &entries, public_key, backend,
    )?;

    let artifacts = evidence_artifact_digests(
        &paths.manifest,
        &paths.ledger_entries,
        &paths.session_transcript_binding,
    )?;

    Ok(evidence_verification_report(
        &manifest_export,
        &binding,
        entries.len(),
        "xenia-ledger::Verifier::verify_transcript_bound_evidence_bundle_with_backend",
        hex::encode(public_key),
        artifacts,
    ))
}

pub(crate) fn verify_sealed_transcript_bound_evidence_bundle_dir_with_backend(
    dir: impl AsRef<Path>,
    trusted_transcript_key_fingerprint: [u8; 32],
    trusted_ledger_key_fingerprint: [u8; 32],
    backend: &impl EvidenceSignatureBackend,
) -> Result<SealedEvidenceVerificationReport, M1RuntimeError> {
    let dir = dir.as_ref();
    let paths = sealed_evidence_bundle_paths(dir);
    let manifest_export = read_evidence_crypto_manifest_export_dir(dir)?;
    let manifest = manifest_export.to_manifest()?;

    if manifest.profile != CryptoPolicyProfile::FullPqcV1 {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence verifier requires full-pqc-v1, found {:?}",
            manifest_export.profile
        )));
    }

    let binding: SessionTranscriptBinding = read_json(&paths.session_transcript_binding)?;
    let transcript_signature: SessionTranscriptSignature =
        read_json(&paths.session_transcript_signature)?;
    let transcript_key_binding: EvidencePublicKeyBinding =
        read_json(&paths.transcript_public_key_binding)?;
    let ledger_key_binding: EvidencePublicKeyBinding = read_json(&paths.ledger_public_key_binding)?;
    let entries: Vec<LedgerEntryExport> = read_json(&paths.ledger_entries)?;
    let bundle_seal: EvidenceBundleSeal = read_json(&paths.evidence_bundle_seal)?;

    require_trusted_key_fingerprint(
        "transcript",
        trusted_transcript_key_fingerprint,
        transcript_key_binding.public_key_fingerprint,
    )?;
    require_trusted_key_fingerprint(
        "ledger",
        trusted_ledger_key_fingerprint,
        ledger_key_binding.public_key_fingerprint,
    )?;

    Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
        manifest,
        &binding,
        &transcript_signature,
        &bundle_seal,
        &transcript_key_binding,
        &entries,
        &ledger_key_binding,
        backend,
        backend,
    )?;

    let artifacts = sealed_evidence_artifact_digests(&paths)?;

    Ok(sealed_evidence_verification_report(
        &manifest_export,
        &binding,
        entries.len(),
        "xenia-ledger::Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings",
        transcript_key_binding.public_key_fingerprint,
        ledger_key_binding.public_key_fingerprint,
        artifacts,
    ))
}

pub(crate) struct M1RuntimeSession {
    session: M1SessionMachine,
    chain: Chain,
    source_id: [u8; 32],
    session_id: Uuid,
    request_id: Uuid,
    scope: String,
    session_transcript_hash: Option<[u8; 32]>,
    next_audit_index: usize,
}

impl M1RuntimeSession {
    pub(crate) fn new(
        signing_key: SigningKey,
        source_id: [u8; 32],
        session_id: Uuid,
        request_id: Uuid,
        scope: impl Into<String>,
    ) -> Self {
        Self::from_chain(
            Chain::new(signing_key),
            source_id,
            session_id,
            request_id,
            scope,
        )
    }

    pub(crate) fn from_chain(
        chain: Chain,
        source_id: [u8; 32],
        session_id: Uuid,
        request_id: Uuid,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            session: M1SessionMachine::new(),
            chain,
            source_id,
            session_id,
            request_id,
            scope: scope.into(),
            session_transcript_hash: None,
            next_audit_index: 0,
        }
    }

    pub(crate) fn from_persisted_entries(
        signing_key: SigningKey,
        entries: Vec<LedgerEntry>,
        source_id: [u8; 32],
        session_id: Uuid,
        request_id: Uuid,
        scope: impl Into<String>,
    ) -> Result<Self, M1RuntimeError> {
        let mut runtime = Self::from_chain(
            Chain::from_entries(entries, signing_key),
            source_id,
            session_id,
            request_id,
            scope,
        );
        runtime.replay_persisted_consent_state()?;
        Ok(runtime)
    }

    pub(crate) fn state(&self) -> M1SessionState {
        self.session.state()
    }

    pub(crate) fn entries(&self) -> Vec<LedgerEntry> {
        self.chain.iter().cloned().collect()
    }

    pub(crate) fn export_entries(&self) -> Vec<LedgerEntryExport> {
        self.chain.export_entries()
    }

    pub(crate) fn bind_session_transcript_hash(&mut self, transcript_hash: [u8; 32]) {
        self.session_transcript_hash = Some(transcript_hash);
    }

    pub(crate) fn session_transcript_binding(&self) -> Option<SessionTranscriptBinding> {
        self.session_transcript_hash.map(|hash| {
            SessionTranscriptBinding::from_hash(
                self.session_id,
                hash,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
            )
        })
    }

    pub(crate) fn verify_transcript_bound_export(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), M1RuntimeError> {
        let Some(binding) = self.session_transcript_binding() else {
            return Err(M1RuntimeError::MissingTranscriptBinding);
        };
        let entries = self.export_entries();
        Verifier::verify_transcript_bound_evidence_bundle(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &entries,
            public_key,
        )?;
        Ok(())
    }

    pub(crate) fn write_transcript_bound_evidence_bundle(
        &self,
        public_key: &VerifyingKey,
        dir: impl AsRef<Path>,
    ) -> Result<M1EvidenceBundlePaths, M1RuntimeError> {
        self.write_transcript_bound_evidence_bundle_for_profile(
            public_key,
            dir,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.profile.stable_label(),
        )
    }

    pub(crate) fn write_transcript_bound_evidence_bundle_for_profile(
        &self,
        public_key: &VerifyingKey,
        dir: impl AsRef<Path>,
        requested_profile: &str,
    ) -> Result<M1EvidenceBundlePaths, M1RuntimeError> {
        let manifest = EvidenceCryptoManifestExport::current();
        ensure_runtime_can_emit_profile(requested_profile, &manifest)?;

        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;

        let Some(binding) = self.session_transcript_binding() else {
            return Err(M1RuntimeError::MissingTranscriptBinding);
        };
        let entries = self.export_entries();
        Verifier::verify_transcript_bound_evidence_bundle(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &entries,
            public_key,
        )?;

        let paths = evidence_bundle_paths(dir);

        write_json(&paths.manifest, &manifest)?;
        write_json(&paths.ledger_entries, &entries)?;
        write_json(&paths.session_transcript_binding, &binding)?;

        let artifacts = evidence_artifact_digests(
            &paths.manifest,
            &paths.ledger_entries,
            &paths.session_transcript_binding,
        )?;
        let report = evidence_verification_report(
            &manifest,
            &binding,
            entries.len(),
            "xenia-ledger::Verifier::verify_transcript_bound_evidence_bundle",
            hex::encode(public_key.to_bytes()),
            artifacts,
        );
        write_json(&paths.verification_report, &report)?;

        Ok(paths)
    }

    pub(crate) fn ledger_len(&self) -> usize {
        self.chain.len()
    }

    pub(crate) fn stable_names(&self) -> Vec<&'static str> {
        self.chain
            .iter()
            .map(|entry| entry.event.stable_name())
            .collect()
    }

    pub(crate) fn persist_entries_bincode(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), M1RuntimeError> {
        let bytes = bincode::serialize(&self.entries())?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub(crate) fn load_entries_bincode(
        path: impl AsRef<Path>,
    ) -> Result<Vec<LedgerEntry>, M1RuntimeError> {
        let bytes = std::fs::read(path)?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub(crate) fn verify_entries(
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), M1RuntimeError> {
        Verifier::verify_chain(entries, public_key)?;
        Ok(())
    }

    fn replay_persisted_consent_state(&mut self) -> Result<(), M1RuntimeError> {
        let entries = self.entries();

        for entry in entries {
            match entry.event.kind {
                ConsentKind::Request => self.session.offer()?,
                ConsentKind::Approval => self.session.grant_consent()?,
                ConsentKind::Denial => self.session.deny_consent()?,
                ConsentKind::Revocation => self.session.revoke()?,
                ConsentKind::Violation => self.session.fail()?,
                ConsentKind::AthenaTriage => {}
            }
        }

        self.next_audit_index = self.session.audit().len();
        Ok(())
    }

    pub(crate) fn offer(&mut self) -> Result<(), M1RuntimeError> {
        self.session.offer()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn grant_consent(&mut self) -> Result<(), M1RuntimeError> {
        self.session.grant_consent()?;
        self.flush_new_audit_events()
    }

    /// Grant consent for exactly the tiers in `granted`. Ungranted tiers
    /// remain denied even while the session is active, so a screen-view
    /// approval does not silently authorize input, clipboard, or files.
    pub(crate) fn grant_consent_scoped(
        &mut self,
        granted: M1PermissionSet,
    ) -> Result<(), M1RuntimeError> {
        self.session.grant_consent_scoped(granted)?;
        self.flush_new_audit_events()
    }

    pub(crate) fn deny_consent(&mut self) -> Result<(), M1RuntimeError> {
        self.session.deny_consent()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn stream_frame(&mut self) -> Result<(), M1RuntimeError> {
        self.session.stream_frame()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn inject_input(&mut self) -> Result<(), M1RuntimeError> {
        self.session.inject_input()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn read_host_clipboard(&mut self) -> Result<(), M1RuntimeError> {
        self.session.read_host_clipboard()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn write_host_clipboard(&mut self) -> Result<(), M1RuntimeError> {
        self.session.write_host_clipboard()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn send_file_to_viewer(&mut self) -> Result<(), M1RuntimeError> {
        self.session.send_file_to_viewer()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn receive_file_from_viewer(&mut self) -> Result<(), M1RuntimeError> {
        self.session.receive_file_from_viewer()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn allow_frame_flow(&mut self) -> Result<(), M1RuntimeError> {
        self.stream_frame()
    }

    pub(crate) fn preflight_frame_flow(&self) -> Result<(), M1RuntimeError> {
        if self.session.state() == M1SessionState::Active {
            Ok(())
        } else {
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: self.session.state(),
                permission: M1Permission::StreamFrame,
            }))
        }
    }

    pub(crate) fn allow_input_flow(&mut self) -> Result<(), M1RuntimeError> {
        self.inject_input()
    }

    pub(crate) fn allow_host_clipboard_read(&mut self) -> Result<(), M1RuntimeError> {
        self.read_host_clipboard()
    }

    pub(crate) fn allow_host_clipboard_write(&mut self) -> Result<(), M1RuntimeError> {
        self.write_host_clipboard()
    }

    pub(crate) fn allow_file_send_to_viewer(&mut self) -> Result<(), M1RuntimeError> {
        self.send_file_to_viewer()
    }

    pub(crate) fn allow_file_receive_from_viewer(&mut self) -> Result<(), M1RuntimeError> {
        self.receive_file_from_viewer()
    }

    pub(crate) fn revoke(&mut self) -> Result<(), M1RuntimeError> {
        self.session.revoke()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn end(&mut self) -> Result<(), M1RuntimeError> {
        self.session.end()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn fail(&mut self) -> Result<(), M1RuntimeError> {
        self.session.fail()?;
        self.flush_new_audit_events()
    }

    pub(crate) fn verify(&self, public_key: &VerifyingKey) -> Result<(), M1RuntimeError> {
        let entries = self.entries();
        Verifier::verify_chain(&entries, public_key)?;
        Ok(())
    }

    fn flush_new_audit_events(&mut self) -> Result<(), M1RuntimeError> {
        let events = self.session.audit()[self.next_audit_index..].to_vec();

        for event in events {
            if let Some(record) = consent_record_for_m1_event(
                self.source_id,
                self.session_id,
                self.request_id,
                self.scope.clone(),
                event,
            ) {
                self.chain.append(record)?;
            }
        }

        self.next_audit_index = self.session.audit().len();
        Ok(())
    }
}

fn evidence_bundle_paths(dir: &Path) -> M1EvidenceBundlePaths {
    M1EvidenceBundlePaths {
        dir: dir.to_path_buf(),
        manifest: dir.join("evidence_manifest.json"),
        ledger_entries: dir.join("ledger_entries.json"),
        session_transcript_binding: dir.join("session_transcript_binding.json"),
        verification_report: dir.join("verification_report.json"),
    }
}

fn sealed_evidence_bundle_paths(dir: &Path) -> M1SealedEvidenceBundlePaths {
    M1SealedEvidenceBundlePaths {
        dir: dir.to_path_buf(),
        manifest: dir.join("evidence_manifest.json"),
        session_transcript_binding: dir.join("session_transcript_binding.json"),
        session_transcript_signature: dir.join("session_transcript_signature.json"),
        transcript_public_key_binding: dir.join("transcript_public_key_binding.json"),
        ledger_public_key_binding: dir.join("ledger_public_key_binding.json"),
        ledger_entries: dir.join("ledger_entries.json"),
        evidence_bundle_seal: dir.join("evidence_bundle_seal.json"),
        verification_report: dir.join("verification_report.json"),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), M1RuntimeError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, M1RuntimeError> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn evidence_artifact_digests(
    manifest_path: &Path,
    ledger_entries_path: &Path,
    session_transcript_binding_path: &Path,
) -> Result<EvidenceArtifactDigests, M1RuntimeError> {
    let evidence_manifest_blake3 = blake3_file_hex(manifest_path)?;
    let ledger_entries_blake3 = blake3_file_hex(ledger_entries_path)?;
    let session_transcript_binding_blake3 = blake3_file_hex(session_transcript_binding_path)?;
    let artifact_set_blake3 = evidence_artifact_set_digest(
        &evidence_manifest_blake3,
        &ledger_entries_blake3,
        &session_transcript_binding_blake3,
    );

    Ok(EvidenceArtifactDigests {
        schema: "xenia-evidence-artifact-digests-v1".to_string(),
        hash_algorithm: "blake3-256".to_string(),
        evidence_manifest_blake3,
        ledger_entries_blake3,
        session_transcript_binding_blake3,
        artifact_set_blake3,
    })
}

fn blake3_file_hex(path: &Path) -> Result<String, M1RuntimeError> {
    let bytes = std::fs::read(path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn evidence_artifact_set_digest(
    evidence_manifest_blake3: &str,
    ledger_entries_blake3: &str,
    session_transcript_binding_blake3: &str,
) -> String {
    artifact_set_digest(&[
        ("evidence_manifest.json", evidence_manifest_blake3),
        ("ledger_entries.json", ledger_entries_blake3),
        (
            "session_transcript_binding.json",
            session_transcript_binding_blake3,
        ),
    ])
}

fn sealed_evidence_artifact_digests(
    paths: &M1SealedEvidenceBundlePaths,
) -> Result<SealedEvidenceArtifactDigests, M1RuntimeError> {
    let evidence_manifest_blake3 = blake3_file_hex(&paths.manifest)?;
    let session_transcript_binding_blake3 = blake3_file_hex(&paths.session_transcript_binding)?;
    let session_transcript_signature_blake3 = blake3_file_hex(&paths.session_transcript_signature)?;
    let transcript_public_key_binding_blake3 =
        blake3_file_hex(&paths.transcript_public_key_binding)?;
    let ledger_public_key_binding_blake3 = blake3_file_hex(&paths.ledger_public_key_binding)?;
    let ledger_entries_blake3 = blake3_file_hex(&paths.ledger_entries)?;
    let evidence_bundle_seal_blake3 = blake3_file_hex(&paths.evidence_bundle_seal)?;
    let artifact_set_blake3 = artifact_set_digest(&[
        ("evidence_manifest.json", &evidence_manifest_blake3),
        (
            "session_transcript_binding.json",
            &session_transcript_binding_blake3,
        ),
        (
            "session_transcript_signature.json",
            &session_transcript_signature_blake3,
        ),
        (
            "transcript_public_key_binding.json",
            &transcript_public_key_binding_blake3,
        ),
        (
            "ledger_public_key_binding.json",
            &ledger_public_key_binding_blake3,
        ),
        ("ledger_entries.json", &ledger_entries_blake3),
        ("evidence_bundle_seal.json", &evidence_bundle_seal_blake3),
    ]);

    Ok(SealedEvidenceArtifactDigests {
        schema: "xenia-sealed-evidence-artifact-digests-v1".to_string(),
        hash_algorithm: "blake3-256".to_string(),
        evidence_manifest_blake3,
        session_transcript_binding_blake3,
        session_transcript_signature_blake3,
        transcript_public_key_binding_blake3,
        ledger_public_key_binding_blake3,
        ledger_entries_blake3,
        evidence_bundle_seal_blake3,
        artifact_set_blake3,
    })
}

fn artifact_set_digest(named_digests: &[(&str, &str)]) -> String {
    let mut hasher = blake3::Hasher::new();
    for (name, digest) in named_digests {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

fn require_trusted_key_fingerprint(
    surface: &'static str,
    trusted: [u8; 32],
    bundle: [u8; 32],
) -> Result<(), M1RuntimeError> {
    if trusted == bundle {
        Ok(())
    } else {
        Err(M1RuntimeError::TrustedKeyFingerprintMismatch {
            surface,
            trusted,
            bundle,
        })
    }
}

pub(crate) fn require_sealed_evidence_trust_policy_minimum_epoch(
    policy: &SealedEvidenceTrustPolicy,
    minimum_policy_epoch: u64,
) -> Result<(), M1RuntimeError> {
    if minimum_policy_epoch == 0 {
        return Err(M1RuntimeError::EvidenceManifest(
            "minimum sealed evidence policy epoch must be greater than zero".to_string(),
        ));
    }

    let policy_epoch = policy.policy_epoch.ok_or_else(|| {
        M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy does not declare policy_epoch; required minimum is {minimum_policy_epoch}"
        ))
    })?;

    if policy_epoch < minimum_policy_epoch {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy policy_epoch {policy_epoch} is below required minimum {minimum_policy_epoch}"
        )));
    }

    Ok(())
}

fn require_sealed_evidence_trust_policy(
    policy: &SealedEvidenceTrustPolicy,
    expected_signature_suite: &str,
) -> Result<(), M1RuntimeError> {
    require_sealed_evidence_trust_policy_at(policy, expected_signature_suite, Utc::now())
}

fn require_sealed_evidence_trust_policy_at(
    policy: &SealedEvidenceTrustPolicy,
    expected_signature_suite: &str,
    now: DateTime<Utc>,
) -> Result<(), M1RuntimeError> {
    if policy.schema != "xenia-sealed-evidence-trust-policy-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed evidence trust policy schema {:?}",
            policy.schema
        )));
    }

    if policy.profile != "full-pqc-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy must require profile full-pqc-v1, found {:?}",
            policy.profile
        )));
    }

    if policy.signature_suite != expected_signature_suite {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy signature suite {:?} did not match selected verifier suite {:?}",
            policy.signature_suite, expected_signature_suite
        )));
    }

    if policy.policy_epoch == Some(0) {
        return Err(M1RuntimeError::EvidenceManifest(
            "sealed evidence trust policy policy_epoch must be greater than zero".to_string(),
        ));
    }

    if let Some(policy_id) = policy.policy_id.as_deref()
        && policy
            .revoked_policy_ids
            .iter()
            .any(|revoked| revoked == policy_id)
    {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy id {policy_id:?} is revoked by policy"
        )));
    }

    let valid_from = policy
        .valid_from
        .as_deref()
        .map(|value| parse_policy_rfc3339("valid_from", value))
        .transpose()?;
    let valid_until = policy
        .valid_until
        .as_deref()
        .map(|value| parse_policy_rfc3339("valid_until", value))
        .transpose()?;

    if let (Some(valid_from), Some(valid_until)) = (&valid_from, &valid_until)
        && valid_from >= valid_until
    {
        return Err(M1RuntimeError::EvidenceManifest(
            "sealed evidence trust policy valid_from must be before valid_until".to_string(),
        ));
    }

    if let Some(valid_from) = valid_from
        && now < valid_from
    {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy is not valid until {valid_from}"
        )));
    }

    if let Some(valid_until) = valid_until
        && now >= valid_until
    {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy expired at {valid_until}"
        )));
    }

    Ok(())
}

fn require_sealed_evidence_trust_policy_signature(
    signature: &SealedEvidenceTrustPolicySignature,
    expected_signature_suite: &str,
    policy_path: &Path,
    trusted_policy_root_fingerprint: [u8; 32],
    backend: &impl EvidenceSignatureBackend,
) -> Result<(), M1RuntimeError> {
    if signature.schema != "xenia-sealed-evidence-trust-policy-signature-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed evidence trust policy signature schema {:?}",
            signature.schema
        )));
    }

    if signature.policy_schema != "xenia-sealed-evidence-trust-policy-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy signature covers unsupported policy schema {:?}",
            signature.policy_schema
        )));
    }

    if signature.profile != "full-pqc-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy signature must require profile full-pqc-v1, found {:?}",
            signature.profile
        )));
    }

    if signature.signature_suite != expected_signature_suite {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy signature suite {:?} did not match selected verifier suite {:?}",
            signature.signature_suite, expected_signature_suite
        )));
    }

    let signature_suite = SignatureSuite::from_stable_label(&signature.signature_suite)
        .ok_or_else(|| {
            M1RuntimeError::EvidenceManifest(format!(
                "unsupported sealed evidence trust policy signature suite {:?}",
                signature.signature_suite
            ))
        })?;

    signature
        .root_public_key_binding
        .validate_against_signature_suite_and_backend(signature_suite, backend)
        .map_err(|err| {
            M1RuntimeError::EvidenceManifest(format!(
                "sealed evidence trust policy root public key binding rejected: {err}"
            ))
        })?;

    require_trusted_key_fingerprint(
        "trust-policy-root",
        trusted_policy_root_fingerprint,
        signature.root_public_key_binding.public_key_fingerprint,
    )?;

    let envelope_suite = signature.signature.validate_shape().map_err(|err| {
        M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy signature envelope rejected: {err}"
        ))
    })?;
    if envelope_suite != signature_suite {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy signature envelope suite {:?} did not match signature suite {:?}",
            envelope_suite, signature_suite
        )));
    }

    let policy_blake3 = blake3_file_hex(policy_path)?;
    if policy_blake3 != signature.policy_blake3 {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy signature policy_blake3 {:?} did not match current policy file {:?}",
            signature.policy_blake3, policy_blake3
        )));
    }

    let message = sealed_evidence_trust_policy_signature_message(signature);
    backend
        .verify_signature(
            &signature.root_public_key_binding.public_key,
            &message,
            &signature.signature.signature,
        )
        .map_err(|err| {
            M1RuntimeError::EvidenceManifest(format!(
                "sealed evidence trust policy signature verification failed: {err}"
            ))
        })?;

    Ok(())
}

fn sealed_evidence_trust_policy_signature_message(
    signature: &SealedEvidenceTrustPolicySignature,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:sealed-evidence-trust-policy-signature:v1");
    message.push(0);
    message.extend_from_slice(signature.policy_schema.as_bytes());
    message.push(0);
    message.extend_from_slice(signature.profile.as_bytes());
    message.push(0);
    message.extend_from_slice(signature.signature_suite.as_bytes());
    message.push(0);
    message.extend_from_slice(signature.policy_blake3.as_bytes());
    message
}

fn require_sealed_evidence_policy_root_at<'a>(
    roots: &'a SealedEvidencePolicyRoots,
    expected_signature_suite: &str,
    root_fingerprint_hex: &str,
    required_root_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<&'a SealedEvidencePolicyRoot, M1RuntimeError> {
    if roots.schema != "xenia-sealed-evidence-policy-roots-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed evidence policy-roots schema {:?}",
            roots.schema
        )));
    }

    if roots.profile != "full-pqc-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence policy-roots must require profile full-pqc-v1, found {:?}",
            roots.profile
        )));
    }

    if roots.signature_suite != expected_signature_suite {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence policy-roots signature suite {:?} did not match selected verifier suite {:?}",
            roots.signature_suite, expected_signature_suite
        )));
    }

    if roots.roots.is_empty() {
        return Err(M1RuntimeError::EvidenceManifest(
            "sealed evidence policy-roots registry must contain at least one root".to_string(),
        ));
    }

    let mut seen_root_ids = Vec::new();
    let mut matched = None;
    for root in &roots.roots {
        if root.root_id.trim().is_empty() {
            return Err(M1RuntimeError::EvidenceManifest(
                "sealed evidence policy-root id must not be empty".to_string(),
            ));
        }
        if seen_root_ids.iter().any(|seen| seen == &root.root_id) {
            return Err(M1RuntimeError::EvidenceManifest(format!(
                "duplicate sealed evidence policy-root id {:?}",
                root.root_id
            )));
        }
        seen_root_ids.push(root.root_id.clone());

        parse_trust_policy_fingerprint_hex("policy-root", &root.root_key_fingerprint_hex)?;

        if root.supersedes_root_id.as_deref() == Some(root.root_id.as_str()) {
            return Err(M1RuntimeError::EvidenceManifest(format!(
                "sealed evidence policy-root {:?} cannot supersede itself",
                root.root_id
            )));
        }

        if root
            .root_key_fingerprint_hex
            .eq_ignore_ascii_case(root_fingerprint_hex)
        {
            matched = Some(root);
        }
    }

    let root = matched.ok_or_else(|| {
        M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence policy-root fingerprint {root_fingerprint_hex:?} is not enrolled"
        ))
    })?;

    if let Some(required_root_id) = required_root_id
        && root.root_id != required_root_id
    {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence policy-root id {:?} did not match required root id {:?}",
            root.root_id, required_root_id
        )));
    }

    if roots
        .revoked_root_ids
        .iter()
        .any(|revoked| revoked == &root.root_id)
    {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence policy-root id {:?} is revoked",
            root.root_id
        )));
    }

    let valid_from = root
        .valid_from
        .as_deref()
        .map(|value| parse_policy_root_rfc3339("valid_from", value))
        .transpose()?;
    let valid_until = root
        .valid_until
        .as_deref()
        .map(|value| parse_policy_root_rfc3339("valid_until", value))
        .transpose()?;

    if let (Some(valid_from), Some(valid_until)) = (&valid_from, &valid_until)
        && valid_from >= valid_until
    {
        return Err(M1RuntimeError::EvidenceManifest(
            "sealed evidence policy-root valid_from must be before valid_until".to_string(),
        ));
    }

    if let Some(valid_from) = valid_from
        && now < valid_from
    {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence policy-root {:?} is not valid until {valid_from}",
            root.root_id
        )));
    }

    if let Some(valid_until) = valid_until
        && now >= valid_until
    {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence policy-root {:?} expired at {valid_until}",
            root.root_id
        )));
    }

    Ok(root)
}

fn parse_policy_root_rfc3339(
    field: &'static str,
    value: &str,
) -> Result<DateTime<Utc>, M1RuntimeError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|err| {
            M1RuntimeError::EvidenceManifest(format!(
                "sealed evidence policy-root {field} is not RFC3339: {err}"
            ))
        })
}

fn parse_policy_rfc3339(field: &'static str, value: &str) -> Result<DateTime<Utc>, M1RuntimeError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|err| {
            M1RuntimeError::EvidenceManifest(format!(
                "sealed evidence trust policy {field} is not RFC3339: {err}"
            ))
        })
}

fn parse_trust_policy_fingerprint_hex(
    surface: &'static str,
    value: &str,
) -> Result<[u8; 32], M1RuntimeError> {
    let bytes = hex::decode(value).map_err(|err| {
        M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy {surface} fingerprint is not valid hex: {err}"
        ))
    })?;
    let found = bytes.len();
    bytes.try_into().map_err(|_| {
        M1RuntimeError::EvidenceManifest(format!(
            "sealed evidence trust policy {surface} fingerprint must be exactly 32 bytes, found {found}"
        ))
    })
}

fn require_sealed_evidence_verification_report_schema(
    report: &SealedEvidenceVerificationReport,
) -> Result<(), M1RuntimeError> {
    if report.schema != "xenia-sealed-evidence-verification-report-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed verification report schema {:?}",
            report.schema
        )));
    }

    if !report.verified {
        return Err(M1RuntimeError::EvidenceManifest(
            "sealed verification_report.json does not record a successful verification".to_string(),
        ));
    }

    if report.artifacts.schema != "xenia-sealed-evidence-artifact-digests-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed verification report artifact digest schema {:?}",
            report.artifacts.schema
        )));
    }

    if report.artifacts.hash_algorithm != "blake3-256" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed verification report artifact digest algorithm {:?}",
            report.artifacts.hash_algorithm
        )));
    }

    if let Some(trust_policy) = &report.trust_policy {
        require_sealed_evidence_trust_policy_receipt_schema(trust_policy)?;
    }

    Ok(())
}

fn require_sealed_evidence_trust_policy_receipt_schema(
    receipt: &SealedEvidenceTrustPolicyReceipt,
) -> Result<(), M1RuntimeError> {
    if receipt.schema != "xenia-sealed-evidence-trust-policy-receipt-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed evidence trust policy receipt schema {:?}",
            receipt.schema
        )));
    }

    match receipt.source.as_str() {
        "enrolled-policy" => Ok(()),
        "signed-enrolled-policy" => {
            if receipt.policy_signature_path.is_none()
                || receipt.policy_signature_blake3.is_none()
                || receipt.policy_root_key_fingerprint_hex.is_none()
            {
                return Err(M1RuntimeError::EvidenceManifest(
                    "signed sealed evidence trust policy receipt is missing policy signature fields"
                        .to_string(),
                ));
            }
            Ok(())
        }
        other => Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported sealed evidence trust policy receipt source {other:?}"
        ))),
    }
}

fn require_evidence_verification_report_schema(
    report: &EvidenceVerificationReport,
) -> Result<(), M1RuntimeError> {
    if report.schema != "xenia-evidence-verification-report-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported verification report schema {:?}",
            report.schema
        )));
    }

    if !report.verified {
        return Err(M1RuntimeError::EvidenceManifest(
            "verification_report.json does not record a successful verification".to_string(),
        ));
    }

    if report.artifacts.schema != "xenia-evidence-artifact-digests-v1" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported verification report artifact digest schema {:?}",
            report.artifacts.schema
        )));
    }

    if report.artifacts.hash_algorithm != "blake3-256" {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "unsupported verification report artifact digest algorithm {:?}",
            report.artifacts.hash_algorithm
        )));
    }

    Ok(())
}

fn require_evidence_report_artifacts_match_current_bundle(
    expected: &EvidenceArtifactDigests,
    actual: &EvidenceArtifactDigests,
) -> Result<(), M1RuntimeError> {
    if expected != actual {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "verification_report artifact digests do not match current bundle artifacts: report artifact_set_blake3={}, current artifact_set_blake3={}",
            expected.artifact_set_blake3, actual.artifact_set_blake3
        )));
    }

    Ok(())
}

fn require_sealed_evidence_report_artifacts_match_current_bundle(
    expected: &SealedEvidenceArtifactDigests,
    actual: &SealedEvidenceArtifactDigests,
) -> Result<(), M1RuntimeError> {
    if expected != actual {
        return Err(M1RuntimeError::EvidenceManifest(format!(
            "sealed verification_report artifact digests do not match current sealed bundle artifacts: report artifact_set_blake3={}, current artifact_set_blake3={}",
            expected.artifact_set_blake3, actual.artifact_set_blake3
        )));
    }

    Ok(())
}

fn evidence_verification_report(
    manifest: &EvidenceCryptoManifestExport,
    binding: &SessionTranscriptBinding,
    ledger_entries: usize,
    verifier: impl Into<String>,
    operator_public_key_hex: String,
    artifacts: EvidenceArtifactDigests,
) -> EvidenceVerificationReport {
    EvidenceVerificationReport {
        schema: "xenia-evidence-verification-report-v1".to_string(),
        verifier: verifier.into(),
        verified: true,
        profile: manifest.profile.clone(),
        ledger_entries,
        session_id: binding.session_id,
        transcript_hash_algorithm: binding.transcript_hash_algorithm.clone(),
        transcript_signature: manifest.transcript_signature.clone(),
        ledger_signature: manifest.ledger_signature.clone(),
        operator_public_key_hex,
        artifacts,
    }
}

fn sealed_evidence_verification_report(
    manifest: &EvidenceCryptoManifestExport,
    binding: &SessionTranscriptBinding,
    ledger_entries: usize,
    verifier: impl Into<String>,
    transcript_key_fingerprint: [u8; 32],
    ledger_key_fingerprint: [u8; 32],
    artifacts: SealedEvidenceArtifactDigests,
) -> SealedEvidenceVerificationReport {
    SealedEvidenceVerificationReport {
        schema: "xenia-sealed-evidence-verification-report-v1".to_string(),
        verifier: verifier.into(),
        verified: true,
        profile: manifest.profile.clone(),
        ledger_entries,
        session_id: binding.session_id,
        transcript_hash_algorithm: binding.transcript_hash_algorithm.clone(),
        transcript_signature: manifest.transcript_signature.clone(),
        ledger_signature: manifest.ledger_signature.clone(),
        transcript_public_key_fingerprint_hex: hex::encode(transcript_key_fingerprint),
        ledger_public_key_fingerprint_hex: hex::encode(ledger_key_fingerprint),
        trust_policy: None,
        artifacts,
    }
}

fn require_label(field: &str, found: &str, expected: &str) -> Result<(), M1RuntimeError> {
    if found == expected {
        Ok(())
    } else {
        Err(M1RuntimeError::EvidenceManifest(format!(
            "{field} label {found:?} did not match supported label {expected:?}"
        )))
    }
}

fn ensure_runtime_can_emit_profile(
    requested_profile: &str,
    current_manifest: &EvidenceCryptoManifestExport,
) -> Result<(), M1RuntimeError> {
    if requested_profile == current_manifest.profile {
        return Ok(());
    }

    if requested_profile == "full-pqc-v1" {
        return Err(M1RuntimeError::FullPqcRuntimeUnavailable {
            transcript_signature: current_manifest.transcript_signature.clone(),
            ledger_signature: current_manifest.ledger_signature.clone(),
        });
    }

    Err(M1RuntimeError::UnsupportedEvidenceExportProfile(
        requested_profile.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_ledger::ConsentKind;
    use xenia_peer_core::M1Permission;

    fn runtime(seed: u8) -> (M1RuntimeSession, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();

        let runtime = M1RuntimeSession::new(
            signing_key,
            [0xAB; 32],
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            "view screen",
        );

        (runtime, verifying_key)
    }

    #[test]
    fn runtime_lifecycle_appends_only_consent_boundaries() {
        let (mut runtime, verifying_key) = runtime(11);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.stream_frame().unwrap();
        runtime.inject_input().unwrap();
        runtime.revoke().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Revoked);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Approval);
        assert_eq!(entries[2].event.kind, ConsentKind::Revocation);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn runtime_exports_transcript_bound_evidence() {
        let (mut runtime, verifying_key) = runtime(21);
        runtime.bind_session_transcript_hash([0x5A; 32]);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        let binding = runtime.session_transcript_binding().unwrap();
        assert_eq!(binding.session_id, Uuid::from_bytes([1; 16]));
        assert_eq!(binding.transcript_hash, [0x5A; 32]);
        assert_eq!(runtime.export_entries().len(), 3);
        runtime
            .verify_transcript_bound_export(&verifying_key)
            .expect("transcript-bound export should verify");
    }

    #[test]
    fn runtime_writes_verifier_consumable_evidence_bundle() {
        let (mut runtime, verifying_key) = runtime(23);
        runtime.bind_session_transcript_hash([0x6B; 32]);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "xenia-m1-evidence-bundle-{}-{}",
            std::process::id(),
            23
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let paths = runtime
            .write_transcript_bound_evidence_bundle(&verifying_key, &dir)
            .expect("evidence bundle should write after verification");

        assert_eq!(paths.dir, dir);
        assert!(paths.manifest.exists());
        assert!(paths.ledger_entries.exists());
        assert!(paths.session_transcript_binding.exists());
        assert!(paths.verification_report.exists());

        let manifest = std::fs::read_to_string(&paths.manifest).unwrap();
        assert!(manifest.contains("hybrid-pre-pqc-v1"));
        assert!(manifest.contains("ed25519-rfc8032"));

        let report = std::fs::read_to_string(&paths.verification_report).unwrap();
        assert!(report.contains("\"verified\": true"));
        assert!(report.contains("xenia-ledger::Verifier::verify_transcript_bound_evidence_bundle"));

        let _ = std::fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn verifier_reads_bundle_without_trusting_export_report() {
        let (mut runtime, verifying_key) = runtime(24);
        runtime.bind_session_transcript_hash([0x7C; 32]);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "xenia-m1-evidence-verify-{}-{}",
            std::process::id(),
            24
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let paths = runtime
            .write_transcript_bound_evidence_bundle(&verifying_key, &dir)
            .unwrap();
        std::fs::write(
            &paths.verification_report,
            b"not trusted by verifier
",
        )
        .unwrap();

        let report = verify_transcript_bound_evidence_bundle_dir(&dir, &verifying_key)
            .expect("bundle verifier should recompute trust from manifest, binding, entries");

        assert!(report.verified);
        assert_eq!(report.ledger_entries, 3);
        assert_eq!(report.session_id, Uuid::from_bytes([1; 16]));
        assert_eq!(
            report.artifacts.evidence_manifest_blake3,
            blake3_file_hex(&paths.manifest).unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verification_report_carries_verified_artifact_digests() {
        let (mut runtime, verifying_key) = runtime(26);
        runtime.bind_session_transcript_hash([0x9E; 32]);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "xenia-m1-evidence-artifact-digests-{}-{}",
            std::process::id(),
            26
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let paths = runtime
            .write_transcript_bound_evidence_bundle(&verifying_key, &dir)
            .expect("evidence bundle should write artifact digests");
        let report: EvidenceVerificationReport = read_json(&paths.verification_report).unwrap();

        let manifest_digest = blake3_file_hex(&paths.manifest).unwrap();
        let ledger_digest = blake3_file_hex(&paths.ledger_entries).unwrap();
        let binding_digest = blake3_file_hex(&paths.session_transcript_binding).unwrap();

        assert_eq!(
            report.artifacts.schema,
            "xenia-evidence-artifact-digests-v1"
        );
        assert_eq!(report.artifacts.hash_algorithm, "blake3-256");
        assert_eq!(report.artifacts.evidence_manifest_blake3, manifest_digest);
        assert_eq!(report.artifacts.ledger_entries_blake3, ledger_digest);
        assert_eq!(
            report.artifacts.session_transcript_binding_blake3,
            binding_digest
        );
        assert_eq!(
            report.artifacts.artifact_set_blake3,
            evidence_artifact_set_digest(
                &report.artifacts.evidence_manifest_blake3,
                &report.artifacts.ledger_entries_blake3,
                &report.artifacts.session_transcript_binding_blake3,
            )
        );

        let verifier_report = verify_transcript_bound_evidence_bundle_dir(&dir, &verifying_key)
            .expect("verifier should recompute matching artifact digests");
        assert_eq!(verifier_report.artifacts, report.artifacts);

        let audited_report = audit_evidence_verification_report_artifacts_dir(&dir)
            .expect("report audit should accept unchanged artifact digests");
        assert_eq!(audited_report.artifacts, report.artifacts);

        std::fs::write(&paths.ledger_entries, b"[]").unwrap();
        let err = audit_evidence_verification_report_artifacts_dir(&dir)
            .expect_err("report audit should reject a swapped artifact");
        assert!(
            err.to_string()
                .contains("verification_report artifact digests do not match")
        );

        let _ = std::fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn sealed_verification_report_audit_rejects_swapped_artifacts() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-m1-sealed-report-audit-{}-{}",
            std::process::id(),
            27
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let paths = sealed_evidence_bundle_paths(&dir);
        for (path, content) in [
            (&paths.manifest, b"{\"artifact\":\"manifest\"}\n".as_slice()),
            (
                &paths.session_transcript_binding,
                b"{\"artifact\":\"session_transcript_binding\"}\n".as_slice(),
            ),
            (
                &paths.session_transcript_signature,
                b"{\"artifact\":\"session_transcript_signature\"}\n".as_slice(),
            ),
            (
                &paths.transcript_public_key_binding,
                b"{\"artifact\":\"transcript_public_key_binding\"}\n".as_slice(),
            ),
            (
                &paths.ledger_public_key_binding,
                b"{\"artifact\":\"ledger_public_key_binding\"}\n".as_slice(),
            ),
            (&paths.ledger_entries, b"[]\n".as_slice()),
            (
                &paths.evidence_bundle_seal,
                b"{\"artifact\":\"evidence_bundle_seal\"}\n".as_slice(),
            ),
        ] {
            std::fs::write(path, content).unwrap();
        }

        let artifacts = sealed_evidence_artifact_digests(&paths).unwrap();
        let report = SealedEvidenceVerificationReport {
            schema: "xenia-sealed-evidence-verification-report-v1".to_string(),
            verifier: "test sealed verifier".to_string(),
            verified: true,
            profile: "full-pqc-v1".to_string(),
            ledger_entries: 3,
            session_id: Uuid::from_bytes([3; 16]),
            transcript_hash_algorithm: "blake3-256".to_string(),
            transcript_signature: "ml-dsa-65-fips204".to_string(),
            ledger_signature: "ml-dsa-65-fips204".to_string(),
            transcript_public_key_fingerprint_hex: hex::encode([0xA5; 32]),
            ledger_public_key_fingerprint_hex: hex::encode([0x5A; 32]),
            trust_policy: None,
            artifacts: artifacts.clone(),
        };
        write_json(&paths.verification_report, &report).unwrap();

        let audited_report = audit_sealed_evidence_verification_report_artifacts_dir(&dir)
            .expect("sealed report audit should accept unchanged artifact digests");
        assert_eq!(audited_report.artifacts, artifacts);

        std::fs::write(
            &paths.evidence_bundle_seal,
            b"{\"artifact\":\"tampered\"}\n",
        )
        .unwrap();
        let err = audit_sealed_evidence_verification_report_artifacts_dir(&dir)
            .expect_err("sealed report audit should reject a swapped sealed artifact");
        assert!(
            err.to_string()
                .contains("sealed verification_report artifact digests do not match")
        );

        let _ = std::fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn sealed_trust_policy_accepts_matching_full_pqc_suite() {
        let policy = SealedEvidenceTrustPolicy {
            schema: "xenia-sealed-evidence-trust-policy-v1".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            trusted_transcript_key_fingerprint_hex: hex::encode([0xA5; 32]),
            trusted_ledger_key_fingerprint_hex: hex::encode([0x5A; 32]),
            policy_id: Some("test-policy".to_string()),
            operator_id: Some("test-operator".to_string()),
            policy_epoch: Some(1),
            valid_from: None,
            valid_until: None,
            revoked_policy_ids: Vec::new(),
        };

        let anchors = sealed_evidence_trust_policy_anchors(&policy, "ml-dsa-65-fips204")
            .expect("matching full-PQC trust policy should parse");

        assert_eq!(anchors.trusted_transcript_key_fingerprint, [0xA5; 32]);
        assert_eq!(anchors.trusted_ledger_key_fingerprint, [0x5A; 32]);
    }

    #[test]
    fn sealed_trust_policy_receipt_records_policy_source() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-sealed-trust-policy-receipt-{}-{}",
            std::process::id(),
            12
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trusted_keys.json");
        let policy = SealedEvidenceTrustPolicy {
            schema: "xenia-sealed-evidence-trust-policy-v1".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            trusted_transcript_key_fingerprint_hex: hex::encode([0xA5; 32]),
            trusted_ledger_key_fingerprint_hex: hex::encode([0x5A; 32]),
            policy_id: Some("test-policy".to_string()),
            operator_id: Some("test-operator".to_string()),
            policy_epoch: Some(1),
            valid_from: Some("2026-01-01T00:00:00Z".to_string()),
            valid_until: Some("2099-01-01T00:00:00Z".to_string()),
            revoked_policy_ids: Vec::new(),
        };
        write_json(&path, &policy).unwrap();

        let receipt =
            sealed_evidence_trust_policy_receipt_file(&path, &policy, "ml-dsa-65-fips204")
                .expect("matching policy should produce a report receipt");

        assert_eq!(
            receipt.schema,
            "xenia-sealed-evidence-trust-policy-receipt-v1"
        );
        assert_eq!(receipt.source, "enrolled-policy");
        assert_eq!(receipt.signature_suite, "ml-dsa-65-fips204");
        assert_eq!(receipt.policy_id.as_deref(), Some("test-policy"));
        assert_eq!(receipt.operator_id.as_deref(), Some("test-operator"));
        assert_eq!(receipt.policy_epoch, Some(1));
        assert_eq!(receipt.valid_from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(receipt.valid_until.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert_eq!(receipt.policy_blake3, Some(blake3_file_hex(&path).unwrap()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_trust_policy_signature_receipt_records_policy_root() {
        let mut receipt = SealedEvidenceTrustPolicyReceipt {
            schema: "xenia-sealed-evidence-trust-policy-receipt-v1".to_string(),
            source: "enrolled-policy".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            policy_path: Some("trusted_keys.json".to_string()),
            policy_blake3: Some(hex::encode([0x11; 32])),
            policy_id: Some("test-policy".to_string()),
            operator_id: Some("test-operator".to_string()),
            policy_epoch: Some(7),
            valid_from: None,
            valid_until: None,
            policy_signature_path: None,
            policy_signature_blake3: None,
            policy_root_key_fingerprint_hex: None,
            policy_roots_path: None,
            policy_roots_blake3: None,
            policy_root_id: None,
            policy_root_valid_from: None,
            policy_root_valid_until: None,
            policy_root_supersedes_root_id: None,
        };

        attach_sealed_evidence_trust_policy_signature_receipt(
            &mut receipt,
            SealedEvidenceTrustPolicySignatureReceipt {
                policy_signature_path: "trusted_keys.signature.json".to_string(),
                policy_signature_blake3: hex::encode([0x22; 32]),
                policy_root_key_fingerprint_hex: hex::encode([0x33; 32]),
            },
        );

        assert_eq!(receipt.source, "signed-enrolled-policy");
        assert_eq!(
            receipt.policy_signature_path.as_deref(),
            Some("trusted_keys.signature.json")
        );
        let expected_root = hex::encode([0x33; 32]);
        assert_eq!(
            receipt.policy_root_key_fingerprint_hex.as_deref(),
            Some(expected_root.as_str())
        );
    }

    #[test]
    fn sealed_policy_roots_authorize_matching_current_root() {
        let now = DateTime::parse_from_rfc3339("2026-07-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let roots = SealedEvidencePolicyRoots {
            schema: "xenia-sealed-evidence-policy-roots-v1".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            roots: vec![SealedEvidencePolicyRoot {
                root_id: "root-2026-q3".to_string(),
                root_key_fingerprint_hex: hex::encode([0x44; 32]),
                operator_id: Some("ops".to_string()),
                valid_from: Some("2026-01-01T00:00:00Z".to_string()),
                valid_until: Some("2027-01-01T00:00:00Z".to_string()),
                supersedes_root_id: Some("root-2026-q2".to_string()),
            }],
            revoked_root_ids: Vec::new(),
        };

        let root = require_sealed_evidence_policy_root_at(
            &roots,
            "ml-dsa-65-fips204",
            &hex::encode([0x44; 32]),
            Some("root-2026-q3"),
            now,
        )
        .expect("matching enrolled root should authorize signed policy verification");

        assert_eq!(root.root_id, "root-2026-q3");
        assert_eq!(root.supersedes_root_id.as_deref(), Some("root-2026-q2"));
    }

    #[test]
    fn sealed_policy_roots_reject_revoked_required_and_stale_roots() {
        let now = DateTime::parse_from_rfc3339("2026-07-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut roots = SealedEvidencePolicyRoots {
            schema: "xenia-sealed-evidence-policy-roots-v1".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            roots: vec![SealedEvidencePolicyRoot {
                root_id: "root-2026-q3".to_string(),
                root_key_fingerprint_hex: hex::encode([0x44; 32]),
                operator_id: Some("ops".to_string()),
                valid_from: Some("2026-01-01T00:00:00Z".to_string()),
                valid_until: Some("2027-01-01T00:00:00Z".to_string()),
                supersedes_root_id: None,
            }],
            revoked_root_ids: Vec::new(),
        };

        let err = require_sealed_evidence_policy_root_at(
            &roots,
            "ml-dsa-65-fips204",
            &hex::encode([0x44; 32]),
            Some("root-2026-q4"),
            now,
        )
        .expect_err("required root id mismatch must fail closed");
        assert!(err.to_string().contains("did not match required root id"));

        roots.revoked_root_ids = vec!["root-2026-q3".to_string()];
        let err = require_sealed_evidence_policy_root_at(
            &roots,
            "ml-dsa-65-fips204",
            &hex::encode([0x44; 32]),
            None,
            now,
        )
        .expect_err("revoked policy root must fail closed");
        assert!(err.to_string().contains("is revoked"));

        roots.revoked_root_ids.clear();
        roots.roots[0].valid_until = Some("2026-07-02T12:00:00Z".to_string());
        let err = require_sealed_evidence_policy_root_at(
            &roots,
            "ml-dsa-65-fips204",
            &hex::encode([0x44; 32]),
            None,
            now,
        )
        .expect_err("expired policy root must fail closed");
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn sealed_trust_policy_rejects_wrong_suite() {
        let policy = SealedEvidenceTrustPolicy {
            schema: "xenia-sealed-evidence-trust-policy-v1".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            trusted_transcript_key_fingerprint_hex: hex::encode([0xA5; 32]),
            trusted_ledger_key_fingerprint_hex: hex::encode([0x5A; 32]),
            policy_id: None,
            operator_id: None,
            policy_epoch: Some(1),
            valid_from: None,
            valid_until: None,
            revoked_policy_ids: Vec::new(),
        };

        let err = sealed_evidence_trust_policy_anchors(&policy, "ml-dsa-87-fips204")
            .expect_err("mismatched trust policy suite must fail closed");
        assert!(
            err.to_string()
                .contains("did not match selected verifier suite")
        );
    }

    #[test]
    fn sealed_trust_policy_rejects_expired_future_and_revoked_policy() {
        let now = DateTime::parse_from_rfc3339("2026-07-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut policy = SealedEvidenceTrustPolicy {
            schema: "xenia-sealed-evidence-trust-policy-v1".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            trusted_transcript_key_fingerprint_hex: hex::encode([0xA5; 32]),
            trusted_ledger_key_fingerprint_hex: hex::encode([0x5A; 32]),
            policy_id: Some("test-policy".to_string()),
            operator_id: Some("test-operator".to_string()),
            policy_epoch: Some(7),
            valid_from: Some("2026-01-01T00:00:00Z".to_string()),
            valid_until: Some("2027-01-01T00:00:00Z".to_string()),
            revoked_policy_ids: Vec::new(),
        };

        require_sealed_evidence_trust_policy_at(&policy, "ml-dsa-65-fips204", now)
            .expect("policy should be valid inside its window");

        policy.valid_until = Some("2026-07-02T12:00:00Z".to_string());
        let err = require_sealed_evidence_trust_policy_at(&policy, "ml-dsa-65-fips204", now)
            .expect_err("expired policy must fail closed");
        assert!(err.to_string().contains("expired"));

        policy.valid_until = Some("2027-01-01T00:00:00Z".to_string());
        policy.valid_from = Some("2026-08-01T00:00:00Z".to_string());
        let err = require_sealed_evidence_trust_policy_at(&policy, "ml-dsa-65-fips204", now)
            .expect_err("future policy must fail closed");
        assert!(err.to_string().contains("not valid until"));

        policy.valid_from = Some("2026-01-01T00:00:00Z".to_string());
        policy.revoked_policy_ids = vec!["test-policy".to_string()];
        let err = require_sealed_evidence_trust_policy_at(&policy, "ml-dsa-65-fips204", now)
            .expect_err("revoked policy id must fail closed");
        assert!(err.to_string().contains("is revoked by policy"));
    }

    #[test]
    fn sealed_trust_policy_minimum_epoch_fails_closed() {
        let mut policy = SealedEvidenceTrustPolicy {
            schema: "xenia-sealed-evidence-trust-policy-v1".to_string(),
            profile: "full-pqc-v1".to_string(),
            signature_suite: "ml-dsa-65-fips204".to_string(),
            trusted_transcript_key_fingerprint_hex: hex::encode([0xA5; 32]),
            trusted_ledger_key_fingerprint_hex: hex::encode([0x5A; 32]),
            policy_id: Some("test-policy".to_string()),
            operator_id: Some("test-operator".to_string()),
            policy_epoch: Some(7),
            valid_from: None,
            valid_until: None,
            revoked_policy_ids: Vec::new(),
        };

        require_sealed_evidence_trust_policy_minimum_epoch(&policy, 7)
            .expect("matching minimum policy epoch should pass");

        let err = require_sealed_evidence_trust_policy_minimum_epoch(&policy, 8)
            .expect_err("stale policy epoch must fail closed");
        assert!(err.to_string().contains("below required minimum"));

        policy.policy_epoch = None;
        let err = require_sealed_evidence_trust_policy_minimum_epoch(&policy, 1)
            .expect_err("missing policy epoch must fail closed when a minimum is required");
        assert!(err.to_string().contains("does not declare policy_epoch"));
    }

    #[test]
    fn runtime_refuses_full_pqc_export_until_pq_signatures_land() {
        let (mut runtime, verifying_key) = runtime(25);
        runtime.bind_session_transcript_hash([0x8D; 32]);
        runtime.offer().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "xenia-m1-full-pqc-refusal-{}-{}",
            std::process::id(),
            25
        ));
        let _ = std::fs::remove_dir_all(&dir);

        assert!(matches!(
            runtime.write_transcript_bound_evidence_bundle_for_profile(
                &verifying_key,
                &dir,
                "full-pqc-v1"
            ),
            Err(M1RuntimeError::FullPqcRuntimeUnavailable {
                transcript_signature,
                ledger_signature
            }) if transcript_signature == "ed25519-rfc8032" && ledger_signature == "ed25519-rfc8032"
        ));
        assert!(!dir.exists());
    }

    #[test]
    fn runtime_without_transcript_hash_cannot_verify_transcript_bound_export() {
        let (mut runtime, verifying_key) = runtime(22);
        runtime.offer().unwrap();

        assert!(matches!(
            runtime.verify_transcript_bound_export(&verifying_key),
            Err(M1RuntimeError::MissingTranscriptBinding)
        ));
    }

    #[test]
    fn stream_and_input_do_not_append_consent_entries() {
        let (mut runtime, verifying_key) = runtime(12);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();

        let before_ops = runtime.entries().len();
        runtime.stream_frame().unwrap();
        runtime.inject_input().unwrap();
        let after_ops = runtime.entries().len();

        assert_eq!(before_ops, 2);
        assert_eq!(after_ops, 2);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn denied_session_records_denial_and_blocks_privileged_flow() {
        let (mut runtime, verifying_key) = runtime(13);

        runtime.offer().unwrap();
        runtime.deny_consent().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Denied);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Denial);

        assert!(matches!(
            runtime.stream_frame(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Denied,
                permission: M1Permission::StreamFrame,
            }))
        ));

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn preflight_frame_flow_is_non_auditing_and_fails_closed() {
        let (mut runtime, _) = runtime(18);

        runtime.offer().unwrap();
        let before = runtime.ledger_len();
        assert!(matches!(
            runtime.preflight_frame_flow(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::StreamFrame,
            }))
        ));
        assert_eq!(runtime.ledger_len(), before);

        runtime.grant_consent().unwrap();
        let before = runtime.ledger_len();
        runtime.preflight_frame_flow().unwrap();
        assert_eq!(runtime.ledger_len(), before);
    }

    #[test]
    fn normal_end_is_not_written_as_consent_revocation() {
        let (mut runtime, verifying_key) = runtime(14);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.end().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Ended);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Approval);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn failed_session_records_protocol_violation() {
        let (mut runtime, verifying_key) = runtime(15);

        runtime.offer().unwrap();
        runtime.fail().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Failed);

        let entries = runtime.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event.kind, ConsentKind::Request);
        assert_eq!(entries[1].event.kind, ConsentKind::Violation);

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn revoked_session_blocks_privileged_flow() {
        let (mut runtime, verifying_key) = runtime(16);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        assert_eq!(runtime.state(), M1SessionState::Revoked);
        assert_eq!(
            runtime.stable_names(),
            vec!["consent.requested", "consent.granted", "consent.revoked"]
        );
        assert!(matches!(
            runtime.allow_frame_flow(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1Permission::StreamFrame,
            }))
        ));
        assert!(matches!(
            runtime.allow_input_flow(),
            Err(M1RuntimeError::Session(M1SessionError::PermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1Permission::InjectInput,
            }))
        ));

        runtime.verify(&verifying_key).unwrap();
    }

    #[test]
    fn runtime_transcript_persists_and_reloads() {
        let (mut runtime, verifying_key) = runtime(17);

        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        runtime.revoke().unwrap();

        let path = std::env::temp_dir().join(format!(
            "xenia-m1-runtime-transcript-{}-{}.bin",
            std::process::id(),
            17
        ));

        runtime.persist_entries_bincode(&path).unwrap();
        let reloaded = M1RuntimeSession::load_entries_bincode(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(reloaded, runtime.entries());
        M1RuntimeSession::verify_entries(&reloaded, &verifying_key).unwrap();
    }

    #[test]
    fn rehydrated_runtime_continues_hash_chain() {
        let signing_key = SigningKey::from_bytes(&[18; 32]);
        let verifying_key = signing_key.verifying_key();
        let source_id = [0xAB; 32];
        let session_id = Uuid::from_bytes([1; 16]);
        let request_id = Uuid::from_bytes([2; 16]);

        let mut runtime = M1RuntimeSession::new(
            signing_key.clone(),
            source_id,
            session_id,
            request_id,
            "view screen",
        );
        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        let persisted = runtime.entries();

        let mut rehydrated = M1RuntimeSession::from_persisted_entries(
            signing_key,
            persisted,
            source_id,
            session_id,
            request_id,
            "view screen",
        )
        .unwrap();
        rehydrated.revoke().unwrap();

        let entries = rehydrated.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].event.kind, ConsentKind::Revocation);
        M1RuntimeSession::verify_entries(&entries, &verifying_key).unwrap();
    }
}
