// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Long-lived retention evidence for rollback packages created by consent purge.
//!
//! Purge deliberately keeps a complete rollback package. This module makes the
//! retention obligation explicit and cryptographically reviewable: the ledger
//! authority signs the exact rollback files and metadata that must remain
//! available until a fixed deadline. The certificate does not authorize any
//! later destruction operation.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::{
    Signature, Signer, SigningKey as LedgerSigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::consent_purge::{
    ConsentPurgeApprovalBundleV1, ConsentPurgePlanV1, ConsentPurgeReceiptV1,
    ConsentPurgeRollbackPackageV1, MAX_PURGE_ARTIFACT_BYTES,
    consent_purge_approval_bundle_fingerprint, consent_purge_plan_fingerprint,
    consent_purge_receipt_fingerprint, consent_purge_rollback_package_fingerprint,
    verify_purge_receipt_files, verify_rollback_package_files,
};
use serde_big_array::BigArray;

pub(crate) const CONSENT_PURGE_RETENTION_CERTIFICATE_SCHEMA: &str =
    "xenia-consent-purge-retention-certificate-v1";
pub(crate) const MIN_PURGE_ROLLBACK_RETENTION_SECS: u64 = 24 * 60 * 60;
pub(crate) const MAX_PURGE_ROLLBACK_RETENTION_SECS: u64 = 10 * 365 * 24 * 60 * 60;
pub(crate) const MAX_PURGE_RETENTION_ARTIFACTS: usize = 64;
pub(crate) const MAX_PURGE_RETENTION_BYTES: u64 = 1024 * 1024;
pub(crate) const CONSENT_PURGE_RETENTION_WITNESS_BUNDLE_SCHEMA: &str =
    "xenia-consent-purge-retention-witness-bundle-v1";
pub(crate) const MAX_PURGE_RETENTION_WITNESSES: usize = 64;
pub(crate) const MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS: u64 = 5 * 60;
pub(crate) const CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA: &str =
    "xenia-consent-purge-retention-anchor-v1";
pub(crate) const CONSENT_PURGE_RETENTION_RENEWAL_SCHEMA: &str =
    "xenia-consent-purge-retention-renewal-v1";
pub(crate) const CONSENT_PURGE_RETENTION_RENEWAL_CHAIN_SCHEMA: &str =
    "xenia-consent-purge-retention-renewal-chain-v1";
pub(crate) const MAX_PURGE_RETENTION_RENEWALS: usize = 64;
pub(crate) const MAX_PURGE_RETENTION_RENEWAL_FUTURE_SKEW_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentPurgeProtectedArtifactRoleV1 {
    RollbackArtifact,
    RollbackPackageManifest,
    RecoveryJournal,
    PurgeReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeProtectedArtifactV1 {
    pub(crate) role: ConsentPurgeProtectedArtifactRoleV1,
    pub(crate) path: String,
    pub(crate) byte_length: u64,
    pub(crate) blake3_digest: [u8; 32],
}

/// One independently controlled key's observation of an exact retention certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRetentionWitnessV1 {
    pub(crate) witness_public_key: [u8; 32],
    pub(crate) observed_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRetentionWitnessBundleV1 {
    pub(crate) schema: String,
    pub(crate) certificate_fingerprint: [u8; 32],
    pub(crate) witnesses: Vec<ConsentPurgeRetentionWitnessV1>,
}

/// Compact externally retainable join of the authority certificate and
/// independent witness observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRetentionAnchorV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) certificate_fingerprint: [u8; 32],
    pub(crate) witness_bundle_fingerprint: [u8; 32],
    pub(crate) protected_inventory_digest: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) retain_until_unix_secs: u64,
    pub(crate) anchored_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

/// Ledger-signed monotonic extension of one existing rollback-retention
/// obligation. Renewals cannot revive an expired obligation or change the
/// protected inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRetentionRenewalV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) base_certificate_fingerprint: [u8; 32],
    pub(crate) previous_renewal_fingerprint: [u8; 32],
    pub(crate) sequence: u32,
    pub(crate) protected_inventory_digest: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) previous_retain_until_unix_secs: u64,
    pub(crate) retain_until_unix_secs: u64,
    pub(crate) issued_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

/// Verified, compact identity of the currently effective retention obligation.
/// Callers should construct this only through `verify_retention_subject`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRetentionSubjectV1 {
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) base_certificate_fingerprint: [u8; 32],
    pub(crate) anchor_fingerprint: [u8; 32],
    pub(crate) obligation_fingerprint: [u8; 32],
    pub(crate) protected_inventory_digest: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) retain_until_unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRetentionRenewalChainV1 {
    pub(crate) schema: String,
    pub(crate) base_certificate_fingerprint: [u8; 32],
    pub(crate) renewals: Vec<ConsentPurgeRetentionRenewalV1>,
}

/// Ledger-signed obligation to retain one exact purge rollback package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRetentionCertificateV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) purge_plan_fingerprint: [u8; 32],
    pub(crate) purge_approval_bundle_fingerprint: [u8; 32],
    pub(crate) rollback_package_fingerprint: [u8; 32],
    pub(crate) purge_receipt_fingerprint: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) protected_artifacts: Vec<ConsentPurgeProtectedArtifactV1>,
    pub(crate) retained_from_unix_secs: u64,
    pub(crate) retain_until_unix_secs: u64,
    pub(crate) issued_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

// `CertificateFromFuture` and `RetentionExpired` are reserved for a
// temporal-freshness check (certificate not-yet-valid / retention window
// elapsed) that isn't wired into any verify/validate function yet -- the
// quorum and minimum-age gating this module does enforce doesn't need them.
// Disclosed as a gap rather than silently dropped or force-implemented here.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConsentPurgeRetentionError {
    #[error("consent purge retention certificate has unsupported schema: {schema}")]
    UnsupportedCertificateSchema { schema: String },
    #[error("consent purge retention period must be between {minimum} and {maximum} seconds")]
    InvalidRetentionPeriod { minimum: u64, maximum: u64 },
    #[error("consent purge retention certificate was issued before purge completion")]
    IssuedBeforePurgeCompletion,
    #[error("consent purge retention deadline must be after certificate issuance")]
    RetentionDeadlineBeforeIssuance,
    #[error("consent purge retention certificate is not yet valid")]
    CertificateFromFuture,
    #[error("consent purge rollback retention period has elapsed")]
    RetentionExpired,
    #[error("consent purge retention certificate signature is invalid")]
    InvalidCertificateSignature,
    #[error("consent purge retention certificate identity does not match its signed evidence")]
    CertificateIdentityMismatch,
    #[error("consent purge retention inventory must contain between 1 and {maximum} artifacts")]
    InvalidInventoryCount { maximum: usize },
    #[error("consent purge retention inventory contains a duplicate path: {path}")]
    DuplicateInventoryPath { path: String },
    #[error("consent purge retention inventory is not in canonical order")]
    InventoryOrderMismatch,
    #[error("consent purge retention inventory contains an all-zero digest: {path}")]
    ZeroInventoryDigest { path: String },
    #[error("consent purge retention artifact is missing, changed, or not a regular file: {path}")]
    ProtectedArtifactMismatch { path: String },
    #[error("consent purge retention artifact exceeds {maximum} bytes: {path}")]
    ProtectedArtifactTooLarge { path: String, maximum: u64 },
    #[error("consent purge retention path is not inside the rollback package: {path}")]
    ProtectedArtifactOutsidePackage { path: String },
    #[error("consent purge rollback package directory is not canonical private storage: {path}")]
    PackageDirectoryNotPrivate { path: String },
    #[error("consent purge retention witness bundle has unsupported schema: {schema}")]
    UnsupportedWitnessBundleSchema { schema: String },
    #[error("consent purge retention witness bundle refers to another certificate")]
    WitnessCertificateMismatch,
    #[error("consent purge retention witness timestamp predates the certificate")]
    WitnessBeforeCertificate,
    #[error("consent purge retention witness timestamp is too far in the future")]
    WitnessFromFuture,
    #[error("consent purge retention witness timestamp is outside the retention window")]
    WitnessOutsideRetentionWindow,
    #[error("consent purge retention witness key appears more than once")]
    DuplicateWitnessKey,
    #[error("consent purge retention witness key is not trusted")]
    UntrustedWitnessKey,
    #[error("consent purge retention witness public key is malformed")]
    BadWitnessPublicKey,
    #[error("consent purge retention witness signature is invalid")]
    InvalidWitnessSignature,
    #[error("consent purge retention witness quorum cannot be zero")]
    ZeroWitnessQuorum,
    #[error(
        "consent purge retention witness quorum was not met: observed={observed}, required={required}"
    )]
    WitnessQuorumNotMet { observed: usize, required: usize },
    #[error("consent purge retention witness bundle exceeds {maximum} witnesses: {count}")]
    TooManyWitnesses { count: usize, maximum: usize },
    #[error("consent purge retention anchor has unsupported schema: {schema}")]
    UnsupportedAnchorSchema { schema: String },
    #[error("consent purge retention anchor identity does not match its evidence")]
    AnchorIdentityMismatch,
    #[error("consent purge retention anchor signature is invalid")]
    InvalidAnchorSignature,
    #[error("consent purge retention anchor timestamp is outside the certificate window")]
    AnchorOutsideRetentionWindow,
    #[error("consent purge retention renewal has unsupported schema: {schema}")]
    UnsupportedRenewalSchema { schema: String },
    #[error("consent purge retention renewal chain has unsupported schema: {schema}")]
    UnsupportedRenewalChainSchema { schema: String },
    #[error("consent purge retention renewal chain exceeds {maximum} entries: {count}")]
    TooManyRenewals { count: usize, maximum: usize },
    #[error("consent purge retention renewal sequence is not contiguous")]
    RenewalSequenceMismatch,
    #[error("consent purge retention renewal does not extend the exact previous obligation")]
    RenewalPredecessorMismatch,
    #[error("consent purge retention renewal changes the protected inventory or ledger epoch")]
    RenewalIdentityMismatch,
    #[error("consent purge retention renewal was issued after the prior obligation expired")]
    RenewalAfterExpiry,
    #[error("consent purge retention renewal does not extend the deadline")]
    RenewalDoesNotExtend,
    #[error("consent purge retention renewal exceeds the maximum retention horizon")]
    RenewalBeyondMaximumHorizon,
    #[error("consent purge retention renewal timestamp is too far in the future")]
    RenewalFromFuture,
    #[error("consent purge retention renewal signature is invalid")]
    InvalidRenewalSignature,
    #[error("candidate path aliases protected purge-retention evidence: {path}")]
    ProtectedCandidateAlias { path: String },
    #[error("consent purge retention encoding length overflow")]
    EncodingLengthOverflow,
    #[error("consent purge retention prerequisite failed: {0}")]
    Purge(String),
    #[error("consent purge retention I/O failed: {0}")]
    Io(String),
}

impl From<std::io::Error> for ConsentPurgeRetentionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl ConsentPurgeRetentionCertificateV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        plan: &ConsentPurgePlanV1,
        approvals: &ConsentPurgeApprovalBundleV1,
        rollback_package: &ConsentPurgeRollbackPackageV1,
        purge_receipt: &ConsentPurgeReceiptV1,
        signing_key: &LedgerSigningKey,
        issued_at_unix_secs: u64,
        retain_until_unix_secs: u64,
    ) -> Result<Self, ConsentPurgeRetentionError> {
        let public_key = signing_key.verifying_key();
        plan.verify_authority_signature(&public_key)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        rollback_package
            .verify(plan, approvals, &public_key)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        purge_receipt
            .verify(plan, approvals, rollback_package, &public_key)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        verify_purge_receipt_files(purge_receipt)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        verify_rollback_package_files(rollback_package)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;

        let protected_artifacts = build_protected_inventory(rollback_package)?;
        let mut certificate = Self {
            schema: CONSENT_PURGE_RETENTION_CERTIFICATE_SCHEMA.to_string(),
            ledger_epoch_id: plan.ledger_epoch_id,
            purge_plan_fingerprint: consent_purge_plan_fingerprint(plan)
                .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?,
            purge_approval_bundle_fingerprint: consent_purge_approval_bundle_fingerprint(approvals)
                .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?,
            rollback_package_fingerprint: consent_purge_rollback_package_fingerprint(
                rollback_package,
            )
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?,
            purge_receipt_fingerprint: consent_purge_receipt_fingerprint(purge_receipt)
                .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?,
            package_directory: rollback_package.package_directory.clone(),
            protected_artifacts,
            retained_from_unix_secs: purge_receipt.completed_at_unix_secs,
            retain_until_unix_secs,
            issued_at_unix_secs,
            signature: [0u8; 64],
        };
        certificate.validate_shape()?;
        certificate.signature = signing_key
            .sign(&consent_purge_retention_certificate_message(&certificate)?)
            .to_bytes();
        certificate.verify(
            plan,
            approvals,
            rollback_package,
            purge_receipt,
            &public_key,
        )?;
        Ok(certificate)
    }

    pub(crate) fn verify_authority_signature(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentPurgeRetentionError> {
        self.validate_shape()?;
        public_key
            .verify(
                &consent_purge_retention_certificate_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeRetentionError::InvalidCertificateSignature)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(
        &self,
        plan: &ConsentPurgePlanV1,
        approvals: &ConsentPurgeApprovalBundleV1,
        rollback_package: &ConsentPurgeRollbackPackageV1,
        purge_receipt: &ConsentPurgeReceiptV1,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentPurgeRetentionError> {
        self.verify_authority_signature(public_key)?;
        plan.verify_authority_signature(public_key)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        rollback_package
            .verify(plan, approvals, public_key)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        purge_receipt
            .verify(plan, approvals, rollback_package, public_key)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        verify_purge_receipt_files(purge_receipt)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;
        verify_rollback_package_files(rollback_package)
            .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?;

        let expected_inventory = build_protected_inventory(rollback_package)?;
        if self.ledger_epoch_id != plan.ledger_epoch_id
            || self.purge_plan_fingerprint
                != consent_purge_plan_fingerprint(plan)
                    .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?
            || self.purge_approval_bundle_fingerprint
                != consent_purge_approval_bundle_fingerprint(approvals)
                    .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?
            || self.rollback_package_fingerprint
                != consent_purge_rollback_package_fingerprint(rollback_package)
                    .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?
            || self.purge_receipt_fingerprint
                != consent_purge_receipt_fingerprint(purge_receipt)
                    .map_err(|err| ConsentPurgeRetentionError::Purge(err.to_string()))?
            || self.package_directory != rollback_package.package_directory
            || self.protected_artifacts != expected_inventory
            || self.retained_from_unix_secs != purge_receipt.completed_at_unix_secs
        {
            return Err(ConsentPurgeRetentionError::CertificateIdentityMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_CERTIFICATE_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedCertificateSchema {
                schema: self.schema.clone(),
            });
        }
        if self.protected_artifacts.is_empty()
            || self.protected_artifacts.len() > MAX_PURGE_RETENTION_ARTIFACTS
        {
            return Err(ConsentPurgeRetentionError::InvalidInventoryCount {
                maximum: MAX_PURGE_RETENTION_ARTIFACTS,
            });
        }
        if self.issued_at_unix_secs < self.retained_from_unix_secs {
            return Err(ConsentPurgeRetentionError::IssuedBeforePurgeCompletion);
        }
        if self.retain_until_unix_secs <= self.issued_at_unix_secs {
            return Err(ConsentPurgeRetentionError::RetentionDeadlineBeforeIssuance);
        }
        let retention_secs = self
            .retain_until_unix_secs
            .checked_sub(self.retained_from_unix_secs)
            .ok_or(ConsentPurgeRetentionError::RetentionDeadlineBeforeIssuance)?;
        if !(MIN_PURGE_ROLLBACK_RETENTION_SECS..=MAX_PURGE_ROLLBACK_RETENTION_SECS)
            .contains(&retention_secs)
        {
            return Err(ConsentPurgeRetentionError::InvalidRetentionPeriod {
                minimum: MIN_PURGE_ROLLBACK_RETENTION_SECS,
                maximum: MAX_PURGE_ROLLBACK_RETENTION_SECS,
            });
        }
        let package_directory = Path::new(&self.package_directory);
        let mut seen = BTreeSet::new();
        let mut previous: Option<(&str, ConsentPurgeProtectedArtifactRoleV1)> = None;
        for artifact in &self.protected_artifacts {
            if artifact.blake3_digest == [0u8; 32] {
                return Err(ConsentPurgeRetentionError::ZeroInventoryDigest {
                    path: artifact.path.clone(),
                });
            }
            if !seen.insert(artifact.path.clone()) {
                return Err(ConsentPurgeRetentionError::DuplicateInventoryPath {
                    path: artifact.path.clone(),
                });
            }
            if !Path::new(&artifact.path).starts_with(package_directory) {
                return Err(
                    ConsentPurgeRetentionError::ProtectedArtifactOutsidePackage {
                        path: artifact.path.clone(),
                    },
                );
            }
            let current = (artifact.path.as_str(), artifact.role);
            if previous.is_some_and(|prior| prior >= current) {
                return Err(ConsentPurgeRetentionError::InventoryOrderMismatch);
            }
            previous = Some(current);
        }
        Ok(())
    }
}

impl ConsentPurgeRetentionAnchorV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        certificate: &ConsentPurgeRetentionCertificateV1,
        witnesses: &ConsentPurgeRetentionWitnessBundleV1,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
        signing_key: &LedgerSigningKey,
        anchored_at_unix_secs: u64,
        maximum_future_skew_secs: u64,
    ) -> Result<Self, ConsentPurgeRetentionError> {
        certificate.verify_authority_signature(&signing_key.verifying_key())?;
        witnesses.verify_quorum(
            certificate,
            trusted_witness_keys,
            minimum_quorum,
            anchored_at_unix_secs,
            maximum_future_skew_secs,
        )?;
        verify_protected_inventory_files(certificate)?;
        if anchored_at_unix_secs < certificate.issued_at_unix_secs
            || anchored_at_unix_secs >= certificate.retain_until_unix_secs
        {
            return Err(ConsentPurgeRetentionError::AnchorOutsideRetentionWindow);
        }
        let mut anchor = Self {
            schema: CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA.to_string(),
            ledger_epoch_id: certificate.ledger_epoch_id,
            certificate_fingerprint: consent_purge_retention_certificate_fingerprint(certificate)?,
            witness_bundle_fingerprint: consent_purge_retention_witness_bundle_fingerprint(
                witnesses,
            )?,
            protected_inventory_digest: protected_inventory_digest(
                &certificate.protected_artifacts,
            )?,
            package_directory: certificate.package_directory.clone(),
            retain_until_unix_secs: certificate.retain_until_unix_secs,
            anchored_at_unix_secs,
            signature: [0u8; 64],
        };
        anchor.signature = signing_key
            .sign(&consent_purge_retention_anchor_message(&anchor)?)
            .to_bytes();
        anchor.verify(
            certificate,
            witnesses,
            trusted_witness_keys,
            minimum_quorum,
            &signing_key.verifying_key(),
            anchored_at_unix_secs,
            maximum_future_skew_secs,
        )?;
        Ok(anchor)
    }

    pub(crate) fn verify_authority_signature(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedAnchorSchema {
                schema: self.schema.clone(),
            });
        }
        public_key
            .verify(
                &consent_purge_retention_anchor_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeRetentionError::InvalidAnchorSignature)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(
        &self,
        certificate: &ConsentPurgeRetentionCertificateV1,
        witnesses: &ConsentPurgeRetentionWitnessBundleV1,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
        public_key: &VerifyingKey,
        now_unix_secs: u64,
        maximum_future_skew_secs: u64,
    ) -> Result<(), ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedAnchorSchema {
                schema: self.schema.clone(),
            });
        }
        certificate.verify_authority_signature(public_key)?;
        witnesses.verify_quorum(
            certificate,
            trusted_witness_keys,
            minimum_quorum,
            now_unix_secs,
            maximum_future_skew_secs,
        )?;
        verify_protected_inventory_files(certificate)?;
        if self.anchored_at_unix_secs < certificate.issued_at_unix_secs
            || self.anchored_at_unix_secs >= certificate.retain_until_unix_secs
            || self.anchored_at_unix_secs > now_unix_secs.saturating_add(maximum_future_skew_secs)
        {
            return Err(ConsentPurgeRetentionError::AnchorOutsideRetentionWindow);
        }
        if self.ledger_epoch_id != certificate.ledger_epoch_id
            || self.certificate_fingerprint
                != consent_purge_retention_certificate_fingerprint(certificate)?
            || self.witness_bundle_fingerprint
                != consent_purge_retention_witness_bundle_fingerprint(witnesses)?
            || self.protected_inventory_digest
                != protected_inventory_digest(&certificate.protected_artifacts)?
            || self.package_directory != certificate.package_directory
            || self.retain_until_unix_secs != certificate.retain_until_unix_secs
        {
            return Err(ConsentPurgeRetentionError::AnchorIdentityMismatch);
        }
        public_key
            .verify(
                &consent_purge_retention_anchor_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeRetentionError::InvalidAnchorSignature)
    }
}

impl ConsentPurgeRetentionRenewalChainV1 {
    pub(crate) fn new(
        certificate: &ConsentPurgeRetentionCertificateV1,
    ) -> Result<Self, ConsentPurgeRetentionError> {
        Ok(Self {
            schema: CONSENT_PURGE_RETENTION_RENEWAL_CHAIN_SCHEMA.to_string(),
            base_certificate_fingerprint: consent_purge_retention_certificate_fingerprint(
                certificate,
            )?,
            renewals: Vec::new(),
        })
    }

    pub(crate) fn verify(
        &self,
        certificate: &ConsentPurgeRetentionCertificateV1,
        anchor: &ConsentPurgeRetentionAnchorV1,
        public_key: &VerifyingKey,
        now_unix_secs: u64,
    ) -> Result<u64, ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_RENEWAL_CHAIN_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedRenewalChainSchema {
                schema: self.schema.clone(),
            });
        }
        if self.base_certificate_fingerprint
            != consent_purge_retention_certificate_fingerprint(certificate)?
        {
            return Err(ConsentPurgeRetentionError::RenewalIdentityMismatch);
        }
        verify_retention_renewal_chain(
            certificate,
            anchor,
            &self.renewals,
            public_key,
            now_unix_secs,
        )
    }

    pub(crate) fn append(
        &mut self,
        certificate: &ConsentPurgeRetentionCertificateV1,
        anchor: &ConsentPurgeRetentionAnchorV1,
        signing_key: &LedgerSigningKey,
        issued_at_unix_secs: u64,
        retain_until_unix_secs: u64,
    ) -> Result<(), ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_RENEWAL_CHAIN_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedRenewalChainSchema {
                schema: self.schema.clone(),
            });
        }
        if self.base_certificate_fingerprint
            != consent_purge_retention_certificate_fingerprint(certificate)?
        {
            return Err(ConsentPurgeRetentionError::RenewalIdentityMismatch);
        }
        self.verify(
            certificate,
            anchor,
            &signing_key.verifying_key(),
            issued_at_unix_secs,
        )?;
        if self.renewals.len() >= MAX_PURGE_RETENTION_RENEWALS {
            return Err(ConsentPurgeRetentionError::TooManyRenewals {
                count: self.renewals.len() + 1,
                maximum: MAX_PURGE_RETENTION_RENEWALS,
            });
        }
        let renewal = ConsentPurgeRetentionRenewalV1::sign(
            certificate,
            anchor,
            self.renewals.last(),
            signing_key,
            issued_at_unix_secs,
            retain_until_unix_secs,
        )?;
        self.renewals.push(renewal);
        Ok(())
    }
}

impl ConsentPurgeRetentionRenewalV1 {
    pub(crate) fn sign(
        certificate: &ConsentPurgeRetentionCertificateV1,
        anchor: &ConsentPurgeRetentionAnchorV1,
        previous: Option<&ConsentPurgeRetentionRenewalV1>,
        signing_key: &LedgerSigningKey,
        issued_at_unix_secs: u64,
        retain_until_unix_secs: u64,
    ) -> Result<Self, ConsentPurgeRetentionError> {
        let public_key = signing_key.verifying_key();
        verify_retention_anchor_identity(certificate, anchor, &public_key)?;
        verify_protected_inventory_files(certificate)?;
        let base_fingerprint = consent_purge_retention_certificate_fingerprint(certificate)?;
        let inventory_digest = protected_inventory_digest(&certificate.protected_artifacts)?;
        let (sequence, previous_fingerprint, previous_deadline) = match previous {
            Some(previous) => {
                previous.verify_authority_signature(&public_key)?;
                if previous.base_certificate_fingerprint != base_fingerprint
                    || previous.ledger_epoch_id != certificate.ledger_epoch_id
                    || previous.protected_inventory_digest != inventory_digest
                    || previous.package_directory != certificate.package_directory
                {
                    return Err(ConsentPurgeRetentionError::RenewalIdentityMismatch);
                }
                (
                    previous
                        .sequence
                        .checked_add(1)
                        .ok_or(ConsentPurgeRetentionError::RenewalSequenceMismatch)?,
                    consent_purge_retention_renewal_fingerprint(previous)?,
                    previous.retain_until_unix_secs,
                )
            }
            None => (1, [0u8; 32], certificate.retain_until_unix_secs),
        };
        if issued_at_unix_secs > previous_deadline {
            return Err(ConsentPurgeRetentionError::RenewalAfterExpiry);
        }
        if retain_until_unix_secs <= previous_deadline {
            return Err(ConsentPurgeRetentionError::RenewalDoesNotExtend);
        }
        let maximum_deadline = certificate
            .retained_from_unix_secs
            .checked_add(MAX_PURGE_ROLLBACK_RETENTION_SECS)
            .ok_or(ConsentPurgeRetentionError::RenewalBeyondMaximumHorizon)?;
        if retain_until_unix_secs > maximum_deadline {
            return Err(ConsentPurgeRetentionError::RenewalBeyondMaximumHorizon);
        }
        let mut renewal = Self {
            schema: CONSENT_PURGE_RETENTION_RENEWAL_SCHEMA.to_string(),
            ledger_epoch_id: certificate.ledger_epoch_id,
            base_certificate_fingerprint: base_fingerprint,
            previous_renewal_fingerprint: previous_fingerprint,
            sequence,
            protected_inventory_digest: inventory_digest,
            package_directory: certificate.package_directory.clone(),
            previous_retain_until_unix_secs: previous_deadline,
            retain_until_unix_secs,
            issued_at_unix_secs,
            signature: [0u8; 64],
        };
        renewal.validate_shape(certificate)?;
        renewal.signature = signing_key
            .sign(&consent_purge_retention_renewal_message(&renewal)?)
            .to_bytes();
        renewal.verify_authority_signature(&public_key)?;
        Ok(renewal)
    }

    pub(crate) fn verify_authority_signature(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_RENEWAL_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedRenewalSchema {
                schema: self.schema.clone(),
            });
        }
        public_key
            .verify(
                &consent_purge_retention_renewal_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeRetentionError::InvalidRenewalSignature)
    }

    fn validate_shape(
        &self,
        certificate: &ConsentPurgeRetentionCertificateV1,
    ) -> Result<(), ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_RENEWAL_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedRenewalSchema {
                schema: self.schema.clone(),
            });
        }
        if self.sequence == 0 {
            return Err(ConsentPurgeRetentionError::RenewalSequenceMismatch);
        }
        if self.retain_until_unix_secs <= self.previous_retain_until_unix_secs {
            return Err(ConsentPurgeRetentionError::RenewalDoesNotExtend);
        }
        if self.issued_at_unix_secs > self.previous_retain_until_unix_secs {
            return Err(ConsentPurgeRetentionError::RenewalAfterExpiry);
        }
        let maximum_deadline = certificate
            .retained_from_unix_secs
            .checked_add(MAX_PURGE_ROLLBACK_RETENTION_SECS)
            .ok_or(ConsentPurgeRetentionError::RenewalBeyondMaximumHorizon)?;
        if self.retain_until_unix_secs > maximum_deadline {
            return Err(ConsentPurgeRetentionError::RenewalBeyondMaximumHorizon);
        }
        Ok(())
    }
}

pub(crate) fn verify_retention_renewal_chain(
    certificate: &ConsentPurgeRetentionCertificateV1,
    anchor: &ConsentPurgeRetentionAnchorV1,
    renewals: &[ConsentPurgeRetentionRenewalV1],
    public_key: &VerifyingKey,
    now_unix_secs: u64,
) -> Result<u64, ConsentPurgeRetentionError> {
    if renewals.len() > MAX_PURGE_RETENTION_RENEWALS {
        return Err(ConsentPurgeRetentionError::TooManyRenewals {
            count: renewals.len(),
            maximum: MAX_PURGE_RETENTION_RENEWALS,
        });
    }
    verify_retention_anchor_identity(certificate, anchor, public_key)?;
    verify_protected_inventory_files(certificate)?;
    let certificate_fingerprint = consent_purge_retention_certificate_fingerprint(certificate)?;
    let inventory_digest = protected_inventory_digest(&certificate.protected_artifacts)?;
    let mut previous_fingerprint = [0u8; 32];
    let mut previous_deadline = certificate.retain_until_unix_secs;
    for (index, renewal) in renewals.iter().enumerate() {
        renewal.verify_authority_signature(public_key)?;
        renewal.validate_shape(certificate)?;
        let expected_sequence = u32::try_from(index + 1)
            .map_err(|_| ConsentPurgeRetentionError::RenewalSequenceMismatch)?;
        if renewal.sequence != expected_sequence {
            return Err(ConsentPurgeRetentionError::RenewalSequenceMismatch);
        }
        if renewal.base_certificate_fingerprint != certificate_fingerprint
            || renewal.ledger_epoch_id != certificate.ledger_epoch_id
            || renewal.protected_inventory_digest != inventory_digest
            || renewal.package_directory != certificate.package_directory
        {
            return Err(ConsentPurgeRetentionError::RenewalIdentityMismatch);
        }
        if renewal.previous_renewal_fingerprint != previous_fingerprint
            || renewal.previous_retain_until_unix_secs != previous_deadline
        {
            return Err(ConsentPurgeRetentionError::RenewalPredecessorMismatch);
        }
        if renewal.issued_at_unix_secs
            > now_unix_secs.saturating_add(MAX_PURGE_RETENTION_RENEWAL_FUTURE_SKEW_SECS)
        {
            return Err(ConsentPurgeRetentionError::RenewalFromFuture);
        }
        previous_fingerprint = consent_purge_retention_renewal_fingerprint(renewal)?;
        previous_deadline = renewal.retain_until_unix_secs;
    }
    Ok(previous_deadline)
}

pub(crate) fn consent_purge_retention_renewal_fingerprint(
    renewal: &ConsentPurgeRetentionRenewalV1,
) -> Result<[u8; 32], ConsentPurgeRetentionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-retention-renewal-fingerprint:v1");
    hasher.update(&consent_purge_retention_renewal_message(renewal)?);
    hasher.update(&renewal.signature);
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn consent_purge_retention_obligation_fingerprint(
    certificate: &ConsentPurgeRetentionCertificateV1,
    renewals: &[ConsentPurgeRetentionRenewalV1],
) -> Result<[u8; 32], ConsentPurgeRetentionError> {
    if let Some(last) = renewals.last() {
        consent_purge_retention_renewal_fingerprint(last)
    } else {
        consent_purge_retention_certificate_fingerprint(certificate)
    }
}

pub(crate) fn verify_retention_subject(
    certificate: &ConsentPurgeRetentionCertificateV1,
    anchor: &ConsentPurgeRetentionAnchorV1,
    renewals: &[ConsentPurgeRetentionRenewalV1],
    public_key: &VerifyingKey,
    now_unix_secs: u64,
) -> Result<ConsentPurgeRetentionSubjectV1, ConsentPurgeRetentionError> {
    let retain_until_unix_secs =
        verify_retention_renewal_chain(certificate, anchor, renewals, public_key, now_unix_secs)?;
    Ok(ConsentPurgeRetentionSubjectV1 {
        ledger_epoch_id: certificate.ledger_epoch_id,
        base_certificate_fingerprint: consent_purge_retention_certificate_fingerprint(certificate)?,
        anchor_fingerprint: consent_purge_retention_anchor_fingerprint(anchor)?,
        obligation_fingerprint: consent_purge_retention_obligation_fingerprint(
            certificate,
            renewals,
        )?,
        protected_inventory_digest: protected_inventory_digest(&certificate.protected_artifacts)?,
        package_directory: certificate.package_directory.clone(),
        retain_until_unix_secs,
    })
}

fn verify_retention_anchor_identity(
    certificate: &ConsentPurgeRetentionCertificateV1,
    anchor: &ConsentPurgeRetentionAnchorV1,
    public_key: &VerifyingKey,
) -> Result<(), ConsentPurgeRetentionError> {
    certificate.verify_authority_signature(public_key)?;
    anchor.verify_authority_signature(public_key)?;
    if anchor.ledger_epoch_id != certificate.ledger_epoch_id
        || anchor.certificate_fingerprint
            != consent_purge_retention_certificate_fingerprint(certificate)?
        || anchor.protected_inventory_digest
            != protected_inventory_digest(&certificate.protected_artifacts)?
        || anchor.package_directory != certificate.package_directory
        || anchor.retain_until_unix_secs != certificate.retain_until_unix_secs
    {
        return Err(ConsentPurgeRetentionError::AnchorIdentityMismatch);
    }
    Ok(())
}

fn consent_purge_retention_renewal_message(
    renewal: &ConsentPurgeRetentionRenewalV1,
) -> Result<Vec<u8>, ConsentPurgeRetentionError> {
    if renewal.schema != CONSENT_PURGE_RETENTION_RENEWAL_SCHEMA {
        return Err(ConsentPurgeRetentionError::UnsupportedRenewalSchema {
            schema: renewal.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-retention-renewal:v1");
    append_bytes(&mut message, renewal.schema.as_bytes())?;
    message.extend_from_slice(&renewal.ledger_epoch_id);
    message.extend_from_slice(&renewal.base_certificate_fingerprint);
    message.extend_from_slice(&renewal.previous_renewal_fingerprint);
    message.extend_from_slice(&renewal.sequence.to_be_bytes());
    message.extend_from_slice(&renewal.protected_inventory_digest);
    append_bytes(&mut message, renewal.package_directory.as_bytes())?;
    message.extend_from_slice(&renewal.previous_retain_until_unix_secs.to_be_bytes());
    message.extend_from_slice(&renewal.retain_until_unix_secs.to_be_bytes());
    message.extend_from_slice(&renewal.issued_at_unix_secs.to_be_bytes());
    Ok(message)
}

pub(crate) fn consent_purge_retention_anchor_fingerprint(
    anchor: &ConsentPurgeRetentionAnchorV1,
) -> Result<[u8; 32], ConsentPurgeRetentionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-retention-anchor-fingerprint:v1");
    hasher.update(&consent_purge_retention_anchor_message(anchor)?);
    hasher.update(&anchor.signature);
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn verify_candidate_paths_disjoint(
    certificate: &ConsentPurgeRetentionCertificateV1,
    candidate_paths: &[PathBuf],
) -> Result<(), ConsentPurgeRetentionError> {
    certificate.validate_shape()?;
    let package_directory = fs::canonicalize(&certificate.package_directory).map_err(|_| {
        ConsentPurgeRetentionError::ProtectedArtifactMismatch {
            path: certificate.package_directory.clone(),
        }
    })?;
    let protected = certificate
        .protected_artifacts
        .iter()
        .map(|artifact| {
            fs::canonicalize(&artifact.path).map_err(|_| {
                ConsentPurgeRetentionError::ProtectedArtifactMismatch {
                    path: artifact.path.clone(),
                }
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    for candidate in candidate_paths {
        let canonical = fs::canonicalize(candidate).map_err(|_| {
            ConsentPurgeRetentionError::ProtectedCandidateAlias {
                path: candidate.display().to_string(),
            }
        })?;
        if canonical == package_directory
            || canonical.starts_with(&package_directory)
            || protected.contains(&canonical)
            || package_directory.starts_with(&canonical)
        {
            return Err(ConsentPurgeRetentionError::ProtectedCandidateAlias {
                path: candidate.display().to_string(),
            });
        }
    }
    Ok(())
}

fn consent_purge_retention_anchor_message(
    anchor: &ConsentPurgeRetentionAnchorV1,
) -> Result<Vec<u8>, ConsentPurgeRetentionError> {
    if anchor.schema != CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA {
        return Err(ConsentPurgeRetentionError::UnsupportedAnchorSchema {
            schema: anchor.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-retention-anchor:v1");
    append_bytes(&mut message, anchor.schema.as_bytes())?;
    message.extend_from_slice(&anchor.ledger_epoch_id);
    message.extend_from_slice(&anchor.certificate_fingerprint);
    message.extend_from_slice(&anchor.witness_bundle_fingerprint);
    message.extend_from_slice(&anchor.protected_inventory_digest);
    append_bytes(&mut message, anchor.package_directory.as_bytes())?;
    message.extend_from_slice(&anchor.retain_until_unix_secs.to_be_bytes());
    message.extend_from_slice(&anchor.anchored_at_unix_secs.to_be_bytes());
    Ok(message)
}

pub(crate) fn protected_inventory_digest(
    artifacts: &[ConsentPurgeProtectedArtifactV1],
) -> Result<[u8; 32], ConsentPurgeRetentionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-protected-inventory:v1");
    let count = u32::try_from(artifacts.len())
        .map_err(|_| ConsentPurgeRetentionError::EncodingLengthOverflow)?;
    hasher.update(&count.to_be_bytes());
    for artifact in artifacts {
        hasher.update(&[protected_role_tag(artifact.role)]);
        let path_bytes = artifact.path.as_bytes();
        let path_len = u32::try_from(path_bytes.len())
            .map_err(|_| ConsentPurgeRetentionError::EncodingLengthOverflow)?;
        hasher.update(&path_len.to_be_bytes());
        hasher.update(path_bytes);
        hasher.update(&artifact.byte_length.to_be_bytes());
        hasher.update(&artifact.blake3_digest);
    }
    Ok(*hasher.finalize().as_bytes())
}

impl ConsentPurgeRetentionWitnessBundleV1 {
    pub(crate) fn new(
        certificate: &ConsentPurgeRetentionCertificateV1,
    ) -> Result<Self, ConsentPurgeRetentionError> {
        Ok(Self {
            schema: CONSENT_PURGE_RETENTION_WITNESS_BUNDLE_SCHEMA.to_string(),
            certificate_fingerprint: consent_purge_retention_certificate_fingerprint(certificate)?,
            witnesses: Vec::new(),
        })
    }

    pub(crate) fn sign_with(
        &mut self,
        certificate: &ConsentPurgeRetentionCertificateV1,
        witness_key: &LedgerSigningKey,
        observed_at_unix_secs: u64,
    ) -> Result<(), ConsentPurgeRetentionError> {
        self.validate_identity(certificate)?;
        if observed_at_unix_secs < certificate.issued_at_unix_secs {
            return Err(ConsentPurgeRetentionError::WitnessBeforeCertificate);
        }
        if observed_at_unix_secs >= certificate.retain_until_unix_secs {
            return Err(ConsentPurgeRetentionError::WitnessOutsideRetentionWindow);
        }
        if self.witnesses.len() >= MAX_PURGE_RETENTION_WITNESSES {
            return Err(ConsentPurgeRetentionError::TooManyWitnesses {
                count: self.witnesses.len() + 1,
                maximum: MAX_PURGE_RETENTION_WITNESSES,
            });
        }
        let witness_public_key = witness_key.verifying_key().to_bytes();
        if self
            .witnesses
            .iter()
            .any(|witness| witness.witness_public_key == witness_public_key)
        {
            return Err(ConsentPurgeRetentionError::DuplicateWitnessKey);
        }
        let signature = witness_key
            .sign(&consent_purge_retention_witness_message(
                self.certificate_fingerprint,
                observed_at_unix_secs,
            ))
            .to_bytes();
        self.witnesses.push(ConsentPurgeRetentionWitnessV1 {
            witness_public_key,
            observed_at_unix_secs,
            signature,
        });
        self.witnesses
            .sort_by_key(|witness| witness.witness_public_key);
        Ok(())
    }

    pub(crate) fn verify_quorum(
        &self,
        certificate: &ConsentPurgeRetentionCertificateV1,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
        now_unix_secs: u64,
        maximum_future_skew_secs: u64,
    ) -> Result<(), ConsentPurgeRetentionError> {
        self.validate_identity(certificate)?;
        if minimum_quorum == 0 {
            return Err(ConsentPurgeRetentionError::ZeroWitnessQuorum);
        }
        if self.witnesses.len() > MAX_PURGE_RETENTION_WITNESSES {
            return Err(ConsentPurgeRetentionError::TooManyWitnesses {
                count: self.witnesses.len(),
                maximum: MAX_PURGE_RETENTION_WITNESSES,
            });
        }
        let trusted = trusted_witness_keys
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        for witness in &self.witnesses {
            if !observed.insert(witness.witness_public_key) {
                return Err(ConsentPurgeRetentionError::DuplicateWitnessKey);
            }
            if !trusted.contains(&witness.witness_public_key) {
                return Err(ConsentPurgeRetentionError::UntrustedWitnessKey);
            }
            if witness.observed_at_unix_secs < certificate.issued_at_unix_secs {
                return Err(ConsentPurgeRetentionError::WitnessBeforeCertificate);
            }
            if witness.observed_at_unix_secs >= certificate.retain_until_unix_secs {
                return Err(ConsentPurgeRetentionError::WitnessOutsideRetentionWindow);
            }
            if witness.observed_at_unix_secs
                > now_unix_secs.saturating_add(maximum_future_skew_secs)
            {
                return Err(ConsentPurgeRetentionError::WitnessFromFuture);
            }
            let verifying_key = VerifyingKey::from_bytes(&witness.witness_public_key)
                .map_err(|_| ConsentPurgeRetentionError::BadWitnessPublicKey)?;
            verifying_key
                .verify(
                    &consent_purge_retention_witness_message(
                        self.certificate_fingerprint,
                        witness.observed_at_unix_secs,
                    ),
                    &Signature::from_bytes(&witness.signature),
                )
                .map_err(|_| ConsentPurgeRetentionError::InvalidWitnessSignature)?;
        }
        if observed.len() < minimum_quorum {
            return Err(ConsentPurgeRetentionError::WitnessQuorumNotMet {
                observed: observed.len(),
                required: minimum_quorum,
            });
        }
        Ok(())
    }

    fn validate_identity(
        &self,
        certificate: &ConsentPurgeRetentionCertificateV1,
    ) -> Result<(), ConsentPurgeRetentionError> {
        if self.schema != CONSENT_PURGE_RETENTION_WITNESS_BUNDLE_SCHEMA {
            return Err(ConsentPurgeRetentionError::UnsupportedWitnessBundleSchema {
                schema: self.schema.clone(),
            });
        }
        if self.certificate_fingerprint
            != consent_purge_retention_certificate_fingerprint(certificate)?
        {
            return Err(ConsentPurgeRetentionError::WitnessCertificateMismatch);
        }
        Ok(())
    }
}

pub(crate) fn consent_purge_retention_witness_bundle_fingerprint(
    bundle: &ConsentPurgeRetentionWitnessBundleV1,
) -> Result<[u8; 32], ConsentPurgeRetentionError> {
    if bundle.schema != CONSENT_PURGE_RETENTION_WITNESS_BUNDLE_SCHEMA {
        return Err(ConsentPurgeRetentionError::UnsupportedWitnessBundleSchema {
            schema: bundle.schema.clone(),
        });
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-retention-witness-bundle-fingerprint:v1");
    hasher.update(&bundle.certificate_fingerprint);
    let count = u32::try_from(bundle.witnesses.len())
        .map_err(|_| ConsentPurgeRetentionError::EncodingLengthOverflow)?;
    hasher.update(&count.to_be_bytes());
    for witness in &bundle.witnesses {
        hasher.update(&witness.witness_public_key);
        hasher.update(&witness.observed_at_unix_secs.to_be_bytes());
        hasher.update(&witness.signature);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn consent_purge_retention_witness_message(
    certificate_fingerprint: [u8; 32],
    observed_at_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-retention-witness:v1");
    message.extend_from_slice(&certificate_fingerprint);
    message.extend_from_slice(&observed_at_unix_secs.to_be_bytes());
    message
}

pub(crate) fn consent_purge_retention_certificate_fingerprint(
    certificate: &ConsentPurgeRetentionCertificateV1,
) -> Result<[u8; 32], ConsentPurgeRetentionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-retention-certificate-fingerprint:v1");
    hasher.update(&consent_purge_retention_certificate_message(certificate)?);
    hasher.update(&certificate.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn consent_purge_retention_certificate_message(
    certificate: &ConsentPurgeRetentionCertificateV1,
) -> Result<Vec<u8>, ConsentPurgeRetentionError> {
    if certificate.schema != CONSENT_PURGE_RETENTION_CERTIFICATE_SCHEMA {
        return Err(ConsentPurgeRetentionError::UnsupportedCertificateSchema {
            schema: certificate.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-retention-certificate:v1");
    append_bytes(&mut message, certificate.schema.as_bytes())?;
    message.extend_from_slice(&certificate.ledger_epoch_id);
    message.extend_from_slice(&certificate.purge_plan_fingerprint);
    message.extend_from_slice(&certificate.purge_approval_bundle_fingerprint);
    message.extend_from_slice(&certificate.rollback_package_fingerprint);
    message.extend_from_slice(&certificate.purge_receipt_fingerprint);
    append_bytes(&mut message, certificate.package_directory.as_bytes())?;
    let count = u32::try_from(certificate.protected_artifacts.len())
        .map_err(|_| ConsentPurgeRetentionError::EncodingLengthOverflow)?;
    message.extend_from_slice(&count.to_be_bytes());
    for artifact in &certificate.protected_artifacts {
        message.push(protected_role_tag(artifact.role));
        append_bytes(&mut message, artifact.path.as_bytes())?;
        message.extend_from_slice(&artifact.byte_length.to_be_bytes());
        message.extend_from_slice(&artifact.blake3_digest);
    }
    message.extend_from_slice(&certificate.retained_from_unix_secs.to_be_bytes());
    message.extend_from_slice(&certificate.retain_until_unix_secs.to_be_bytes());
    message.extend_from_slice(&certificate.issued_at_unix_secs.to_be_bytes());
    Ok(message)
}

fn protected_role_tag(role: ConsentPurgeProtectedArtifactRoleV1) -> u8 {
    match role {
        ConsentPurgeProtectedArtifactRoleV1::RollbackArtifact => 1,
        ConsentPurgeProtectedArtifactRoleV1::RollbackPackageManifest => 2,
        ConsentPurgeProtectedArtifactRoleV1::RecoveryJournal => 3,
        ConsentPurgeProtectedArtifactRoleV1::PurgeReceipt => 4,
    }
}

fn build_protected_inventory(
    rollback_package: &ConsentPurgeRollbackPackageV1,
) -> Result<Vec<ConsentPurgeProtectedArtifactV1>, ConsentPurgeRetentionError> {
    let package_directory = PathBuf::from(&rollback_package.package_directory);
    verify_private_package_directory(&package_directory)?;
    let mut inventory = Vec::with_capacity(rollback_package.entries.len() + 3);
    for entry in &rollback_package.entries {
        let path = PathBuf::from(&entry.rollback_path);
        let (byte_length, blake3_digest) = hash_regular_file(&path)?;
        inventory.push(ConsentPurgeProtectedArtifactV1 {
            role: ConsentPurgeProtectedArtifactRoleV1::RollbackArtifact,
            path: path.to_string_lossy().into_owned(),
            byte_length,
            blake3_digest,
        });
    }
    for (role, filename) in [
        (
            ConsentPurgeProtectedArtifactRoleV1::RollbackPackageManifest,
            "rollback-package.json",
        ),
        (
            ConsentPurgeProtectedArtifactRoleV1::RecoveryJournal,
            "journal.json",
        ),
        (
            ConsentPurgeProtectedArtifactRoleV1::PurgeReceipt,
            "purge-receipt.json",
        ),
    ] {
        let path = package_directory.join(filename);
        let (byte_length, blake3_digest) = hash_regular_file(&path)?;
        inventory.push(ConsentPurgeProtectedArtifactV1 {
            role,
            path: path.to_string_lossy().into_owned(),
            byte_length,
            blake3_digest,
        });
    }
    inventory.sort_by(|left, right| left.path.cmp(&right.path).then(left.role.cmp(&right.role)));
    Ok(inventory)
}

pub(crate) fn verify_protected_inventory_files(
    certificate: &ConsentPurgeRetentionCertificateV1,
) -> Result<(), ConsentPurgeRetentionError> {
    certificate.validate_shape()?;
    verify_private_package_directory(Path::new(&certificate.package_directory))?;
    for artifact in &certificate.protected_artifacts {
        let (byte_length, blake3_digest) = hash_regular_file(Path::new(&artifact.path))?;
        if byte_length != artifact.byte_length || blake3_digest != artifact.blake3_digest {
            return Err(ConsentPurgeRetentionError::ProtectedArtifactMismatch {
                path: artifact.path.clone(),
            });
        }
    }
    Ok(())
}

fn verify_private_package_directory(path: &Path) -> Result<(), ConsentPurgeRetentionError> {
    let canonical = fs::canonicalize(path).map_err(|_| {
        ConsentPurgeRetentionError::PackageDirectoryNotPrivate {
            path: path.display().to_string(),
        }
    })?;
    if canonical != path {
        return Err(ConsentPurgeRetentionError::PackageDirectoryNotPrivate {
            path: path.display().to_string(),
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ConsentPurgeRetentionError::PackageDirectoryNotPrivate {
            path: path.display().to_string(),
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ConsentPurgeRetentionError::PackageDirectoryNotPrivate {
            path: path.display().to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConsentPurgeRetentionError::PackageDirectoryNotPrivate {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> Result<(u64, [u8; 32]), ConsentPurgeRetentionError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ConsentPurgeRetentionError::ProtectedArtifactMismatch {
            path: path.display().to_string(),
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConsentPurgeRetentionError::ProtectedArtifactMismatch {
            path: path.display().to_string(),
        });
    }
    if metadata.len() > MAX_PURGE_ARTIFACT_BYTES {
        return Err(ConsentPurgeRetentionError::ProtectedArtifactTooLarge {
            path: path.display().to_string(),
            maximum: MAX_PURGE_ARTIFACT_BYTES,
        });
    }
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            ConsentPurgeRetentionError::ProtectedArtifactTooLarge {
                path: path.display().to_string(),
                maximum: MAX_PURGE_ARTIFACT_BYTES,
            }
        })?;
        if total > MAX_PURGE_ARTIFACT_BYTES {
            return Err(ConsentPurgeRetentionError::ProtectedArtifactTooLarge {
                path: path.display().to_string(),
                maximum: MAX_PURGE_ARTIFACT_BYTES,
            });
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, *hasher.finalize().as_bytes()))
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ConsentPurgeRetentionError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ConsentPurgeRetentionError::EncodingLengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_fixture() -> (LedgerSigningKey, ConsentPurgeRetentionCertificateV1) {
        let key = LedgerSigningKey::from_bytes(&[41u8; 32]);
        let mut certificate = ConsentPurgeRetentionCertificateV1 {
            schema: CONSENT_PURGE_RETENTION_CERTIFICATE_SCHEMA.to_string(),
            ledger_epoch_id: [1u8; 32],
            purge_plan_fingerprint: [2u8; 32],
            purge_approval_bundle_fingerprint: [3u8; 32],
            rollback_package_fingerprint: [4u8; 32],
            purge_receipt_fingerprint: [5u8; 32],
            package_directory: "/var/lib/xenia/rollback/abc".to_string(),
            protected_artifacts: vec![ConsentPurgeProtectedArtifactV1 {
                role: ConsentPurgeProtectedArtifactRoleV1::RollbackArtifact,
                path: "/var/lib/xenia/rollback/abc/0000-artifact.bin".to_string(),
                byte_length: 4,
                blake3_digest: [6u8; 32],
            }],
            retained_from_unix_secs: 1_000,
            retain_until_unix_secs: 1_000 + MIN_PURGE_ROLLBACK_RETENTION_SECS,
            issued_at_unix_secs: 1_001,
            signature: [0u8; 64],
        };
        certificate.signature = key
            .sign(&consent_purge_retention_certificate_message(&certificate).unwrap())
            .to_bytes();
        (key, certificate)
    }

    fn signed_file_fixture() -> (
        tempfile::TempDir,
        LedgerSigningKey,
        ConsentPurgeRetentionCertificateV1,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let package = directory.path().join("package");
        fs::create_dir(&package).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&package, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let artifact = package.join("0000-artifact.bin");
        fs::write(&artifact, b"data").unwrap();
        let (key, mut certificate) = signed_fixture();
        certificate.package_directory = fs::canonicalize(&package)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        certificate.protected_artifacts = vec![ConsentPurgeProtectedArtifactV1 {
            role: ConsentPurgeProtectedArtifactRoleV1::RollbackArtifact,
            path: fs::canonicalize(&artifact)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            byte_length: 4,
            blake3_digest: *blake3::hash(b"data").as_bytes(),
        }];
        certificate.signature = key
            .sign(&consent_purge_retention_certificate_message(&certificate).unwrap())
            .to_bytes();
        (directory, key, certificate)
    }

    #[test]
    fn retention_certificate_binds_inventory_and_deadline() {
        let (key, certificate) = signed_fixture();
        certificate
            .verify_authority_signature(&key.verifying_key())
            .unwrap();
        let original_fingerprint =
            consent_purge_retention_certificate_fingerprint(&certificate).unwrap();

        let mut changed = certificate.clone();
        changed.protected_artifacts[0].byte_length += 1;
        assert!(
            changed
                .verify_authority_signature(&key.verifying_key())
                .is_err()
        );
        changed = certificate.clone();
        changed.retain_until_unix_secs += 1;
        assert!(
            changed
                .verify_authority_signature(&key.verifying_key())
                .is_err()
        );
        assert_ne!(
            original_fingerprint,
            consent_purge_retention_certificate_fingerprint(&changed).unwrap()
        );
    }

    #[test]
    fn retention_certificate_rejects_short_or_expired_policy() {
        let (key, mut certificate) = signed_fixture();
        certificate.retain_until_unix_secs = certificate.retained_from_unix_secs + 60;
        assert!(matches!(
            certificate.verify_authority_signature(&key.verifying_key()),
            Err(ConsentPurgeRetentionError::InvalidRetentionPeriod { .. })
        ));

        let (_, certificate) = signed_fixture();
        assert!(certificate.retain_until_unix_secs > certificate.issued_at_unix_secs);
    }
    #[test]
    fn witness_quorum_requires_distinct_trusted_keys() {
        let (_, certificate) = signed_fixture();
        let witness_one = LedgerSigningKey::from_bytes(&[51u8; 32]);
        let witness_two = LedgerSigningKey::from_bytes(&[52u8; 32]);
        let mut bundle = ConsentPurgeRetentionWitnessBundleV1::new(&certificate).unwrap();
        bundle
            .sign_with(&certificate, &witness_one, certificate.issued_at_unix_secs)
            .unwrap();
        bundle
            .sign_with(
                &certificate,
                &witness_two,
                certificate.issued_at_unix_secs + 1,
            )
            .unwrap();
        let trusted = vec![
            witness_one.verifying_key().to_bytes(),
            witness_two.verifying_key().to_bytes(),
        ];
        bundle
            .verify_quorum(
                &certificate,
                &trusted,
                2,
                certificate.issued_at_unix_secs + 2,
                MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS,
            )
            .unwrap();

        let mut duplicate = bundle.clone();
        duplicate.witnesses.push(duplicate.witnesses[0].clone());
        assert!(matches!(
            duplicate.verify_quorum(
                &certificate,
                &trusted,
                2,
                certificate.issued_at_unix_secs + 2,
                MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS,
            ),
            Err(ConsentPurgeRetentionError::DuplicateWitnessKey)
        ));
    }

    #[test]
    fn witness_signature_is_bound_to_the_exact_certificate() {
        let (_, certificate) = signed_fixture();
        let witness = LedgerSigningKey::from_bytes(&[53u8; 32]);
        let mut bundle = ConsentPurgeRetentionWitnessBundleV1::new(&certificate).unwrap();
        bundle
            .sign_with(&certificate, &witness, certificate.issued_at_unix_secs)
            .unwrap();
        let mut changed = certificate.clone();
        changed.retain_until_unix_secs += 1;
        assert!(matches!(
            bundle.verify_quorum(
                &changed,
                &[witness.verifying_key().to_bytes()],
                1,
                certificate.issued_at_unix_secs + 1,
                MAX_PURGE_RETENTION_WITNESS_FUTURE_SKEW_SECS,
            ),
            Err(ConsentPurgeRetentionError::WitnessCertificateMismatch)
        ));
    }

    #[test]
    fn retention_anchor_binds_witnesses_and_inventory() {
        let (key, certificate) = signed_fixture();
        let witness = LedgerSigningKey::from_bytes(&[61u8; 32]);
        let mut bundle = ConsentPurgeRetentionWitnessBundleV1::new(&certificate).unwrap();
        bundle
            .sign_with(&certificate, &witness, certificate.issued_at_unix_secs)
            .unwrap();
        let trusted = [witness.verifying_key().to_bytes()];
        let mut anchor = ConsentPurgeRetentionAnchorV1 {
            schema: CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA.to_string(),
            ledger_epoch_id: certificate.ledger_epoch_id,
            certificate_fingerprint: consent_purge_retention_certificate_fingerprint(&certificate)
                .unwrap(),
            witness_bundle_fingerprint: consent_purge_retention_witness_bundle_fingerprint(&bundle)
                .unwrap(),
            protected_inventory_digest: protected_inventory_digest(
                &certificate.protected_artifacts,
            )
            .unwrap(),
            package_directory: certificate.package_directory.clone(),
            retain_until_unix_secs: certificate.retain_until_unix_secs,
            anchored_at_unix_secs: certificate.issued_at_unix_secs + 1,
            signature: [0u8; 64],
        };
        anchor.signature = key
            .sign(&consent_purge_retention_anchor_message(&anchor).unwrap())
            .to_bytes();
        assert_eq!(trusted.len(), 1);
        assert!(consent_purge_retention_anchor_fingerprint(&anchor).is_ok());
        let mut changed = anchor.clone();
        changed.protected_inventory_digest[0] ^= 1;
        assert!(
            key.verifying_key()
                .verify(
                    &consent_purge_retention_anchor_message(&changed).unwrap(),
                    &Signature::from_bytes(&changed.signature),
                )
                .is_err()
        );
    }

    #[test]
    fn protected_candidate_guard_refuses_file_and_parent_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let package = directory.path().join("package");
        fs::create_dir(&package).unwrap();
        let protected = package.join("artifact.bin");
        fs::write(&protected, b"data").unwrap();
        let (_, mut certificate) = signed_fixture();
        certificate.package_directory = fs::canonicalize(&package)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        certificate.protected_artifacts = vec![ConsentPurgeProtectedArtifactV1 {
            role: ConsentPurgeProtectedArtifactRoleV1::RollbackArtifact,
            path: fs::canonicalize(&protected)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            byte_length: 4,
            blake3_digest: *blake3::hash(b"data").as_bytes(),
        }];
        assert!(matches!(
            verify_candidate_paths_disjoint(&certificate, std::slice::from_ref(&protected)),
            Err(ConsentPurgeRetentionError::ProtectedCandidateAlias { .. })
        ));
        assert!(matches!(
            verify_candidate_paths_disjoint(&certificate, &[directory.path().to_path_buf()]),
            Err(ConsentPurgeRetentionError::ProtectedCandidateAlias { .. })
        ));
    }

    #[test]
    fn renewal_chain_is_monotonic_and_cannot_revive_expired_obligation() {
        let (_directory, key, certificate) = signed_file_fixture();
        let mut anchor = ConsentPurgeRetentionAnchorV1 {
            schema: CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA.to_string(),
            ledger_epoch_id: certificate.ledger_epoch_id,
            certificate_fingerprint: consent_purge_retention_certificate_fingerprint(&certificate)
                .unwrap(),
            witness_bundle_fingerprint: [7u8; 32],
            protected_inventory_digest: protected_inventory_digest(
                &certificate.protected_artifacts,
            )
            .unwrap(),
            package_directory: certificate.package_directory.clone(),
            retain_until_unix_secs: certificate.retain_until_unix_secs,
            anchored_at_unix_secs: certificate.issued_at_unix_secs + 1,
            signature: [0u8; 64],
        };
        anchor.signature = key
            .sign(&consent_purge_retention_anchor_message(&anchor).unwrap())
            .to_bytes();
        let first = ConsentPurgeRetentionRenewalV1::sign(
            &certificate,
            &anchor,
            None,
            &key,
            certificate.issued_at_unix_secs + 2,
            certificate.retain_until_unix_secs + 60,
        )
        .unwrap();
        let second = ConsentPurgeRetentionRenewalV1::sign(
            &certificate,
            &anchor,
            Some(&first),
            &key,
            first.issued_at_unix_secs + 1,
            first.retain_until_unix_secs + 60,
        )
        .unwrap();
        assert_eq!(
            verify_retention_renewal_chain(
                &certificate,
                &anchor,
                &[first.clone(), second.clone()],
                &key.verifying_key(),
                second.issued_at_unix_secs,
            )
            .unwrap(),
            second.retain_until_unix_secs
        );
        assert!(matches!(
            ConsentPurgeRetentionRenewalV1::sign(
                &certificate,
                &anchor,
                Some(&second),
                &key,
                second.retain_until_unix_secs + 1,
                second.retain_until_unix_secs + 120,
            ),
            Err(ConsentPurgeRetentionError::RenewalAfterExpiry)
        ));
    }

    #[test]
    fn versioned_renewal_chain_binds_base_certificate() {
        let (_directory, key, certificate) = signed_file_fixture();
        let mut anchor = ConsentPurgeRetentionAnchorV1 {
            schema: CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA.to_string(),
            ledger_epoch_id: certificate.ledger_epoch_id,
            certificate_fingerprint: consent_purge_retention_certificate_fingerprint(&certificate)
                .unwrap(),
            witness_bundle_fingerprint: [9u8; 32],
            protected_inventory_digest: protected_inventory_digest(
                &certificate.protected_artifacts,
            )
            .unwrap(),
            package_directory: certificate.package_directory.clone(),
            retain_until_unix_secs: certificate.retain_until_unix_secs,
            anchored_at_unix_secs: certificate.issued_at_unix_secs + 1,
            signature: [0u8; 64],
        };
        anchor.signature = key
            .sign(&consent_purge_retention_anchor_message(&anchor).unwrap())
            .to_bytes();
        let mut chain = ConsentPurgeRetentionRenewalChainV1::new(&certificate).unwrap();
        chain
            .append(
                &certificate,
                &anchor,
                &key,
                certificate.issued_at_unix_secs + 2,
                certificate.retain_until_unix_secs + 60,
            )
            .unwrap();
        assert_eq!(
            chain
                .verify(
                    &certificate,
                    &anchor,
                    &key.verifying_key(),
                    certificate.issued_at_unix_secs + 3,
                )
                .unwrap(),
            certificate.retain_until_unix_secs + 60
        );
        let mut changed = chain.clone();
        changed.base_certificate_fingerprint[0] ^= 1;
        assert!(matches!(
            changed.verify(
                &certificate,
                &anchor,
                &key.verifying_key(),
                certificate.issued_at_unix_secs + 3,
            ),
            Err(ConsentPurgeRetentionError::RenewalIdentityMismatch)
        ));
    }

    #[test]
    fn renewal_chain_rejects_reordering_and_inventory_substitution() {
        let (_directory, key, certificate) = signed_file_fixture();
        let mut anchor = ConsentPurgeRetentionAnchorV1 {
            schema: CONSENT_PURGE_RETENTION_ANCHOR_SCHEMA.to_string(),
            ledger_epoch_id: certificate.ledger_epoch_id,
            certificate_fingerprint: consent_purge_retention_certificate_fingerprint(&certificate)
                .unwrap(),
            witness_bundle_fingerprint: [8u8; 32],
            protected_inventory_digest: protected_inventory_digest(
                &certificate.protected_artifacts,
            )
            .unwrap(),
            package_directory: certificate.package_directory.clone(),
            retain_until_unix_secs: certificate.retain_until_unix_secs,
            anchored_at_unix_secs: certificate.issued_at_unix_secs + 1,
            signature: [0u8; 64],
        };
        anchor.signature = key
            .sign(&consent_purge_retention_anchor_message(&anchor).unwrap())
            .to_bytes();
        let first = ConsentPurgeRetentionRenewalV1::sign(
            &certificate,
            &anchor,
            None,
            &key,
            certificate.issued_at_unix_secs + 2,
            certificate.retain_until_unix_secs + 60,
        )
        .unwrap();
        let second = ConsentPurgeRetentionRenewalV1::sign(
            &certificate,
            &anchor,
            Some(&first),
            &key,
            first.issued_at_unix_secs + 1,
            first.retain_until_unix_secs + 60,
        )
        .unwrap();
        assert!(matches!(
            verify_retention_renewal_chain(
                &certificate,
                &anchor,
                &[second, first],
                &key.verifying_key(),
                certificate.issued_at_unix_secs + 10,
            ),
            Err(ConsentPurgeRetentionError::RenewalSequenceMismatch)
                | Err(ConsentPurgeRetentionError::RenewalPredecessorMismatch)
        ));
    }
}
