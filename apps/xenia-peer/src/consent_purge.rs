// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit authorization for removing already-quarantined consent artifacts.
//!
//! Retirement quarantine is reversible and intentionally does not unlink data.
//! Purge is a separate ceremony. A purge plan is short lived, ledger-signed,
//! bound to an exact signed quarantine receipt, and valid only after a minimum
//! quarantine age has elapsed. The rollback root and every future backup path
//! are part of the signed authorization.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{
    Signature, Signer, SigningKey as LedgerSigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use uuid::Uuid;

use crate::audit_ledger_store::{persist_owner_only_atomic, read_bounded_json};
use crate::consent_retirement::{
    ConsentRetirementApprovalBundleV1, ConsentRetirementArtifactRoleV1, ConsentRetirementPlanV1,
    ConsentRetirementQuarantineReceiptV1, consent_retirement_approval_bundle_fingerprint,
    consent_retirement_plan_fingerprint, consent_retirement_receipt_fingerprint,
    verify_quarantined_receipt_files,
};

pub(crate) const CONSENT_PURGE_PLAN_SCHEMA: &str = "xenia-consent-purge-plan-v1";
pub(crate) const MAX_PURGE_CANDIDATES: usize = 32;
pub(crate) const MIN_PURGE_QUARANTINE_AGE_SECS: u64 = 24 * 60 * 60;
pub(crate) const MAX_PURGE_QUARANTINE_AGE_SECS: u64 = 365 * 24 * 60 * 60;
pub(crate) const MAX_PURGE_PLAN_LIFETIME_SECS: u64 = 60 * 60;
pub(crate) const MAX_PURGE_PATH_BYTES: usize = 4096;
pub(crate) const MAX_PURGE_TRANSACTION_BYTES: u64 = 1024 * 1024;
pub(crate) const CONSENT_PURGE_APPROVAL_BUNDLE_SCHEMA: &str =
    "xenia-consent-purge-approval-bundle-v1";
pub(crate) const MAX_PURGE_APPROVALS: usize = 64;
pub(crate) const CONSENT_PURGE_ROLLBACK_PACKAGE_SCHEMA: &str =
    "xenia-consent-purge-rollback-package-v1";
pub(crate) const CONSENT_PURGE_JOURNAL_SCHEMA: &str = "xenia-consent-purge-journal-v1";
pub(crate) const CONSENT_PURGE_RECEIPT_SCHEMA: &str = "xenia-consent-purge-receipt-v1";
pub(crate) const MAX_PURGE_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeArtifactV1 {
    pub(crate) role: ConsentRetirementArtifactRoleV1,
    pub(crate) quarantine_path: String,
    pub(crate) rollback_path: String,
    pub(crate) byte_length: u64,
    pub(crate) blake3_digest: [u8; 32],
}

/// One independently controlled purge key's approval of an exact signed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeApprovalV1 {
    pub(crate) witness_public_key: [u8; 32],
    pub(crate) approved_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeApprovalBundleV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approvals: Vec<ConsentPurgeApprovalV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeRollbackPackageV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approval_bundle_fingerprint: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) created_at_unix_secs: u64,
    pub(crate) entries: Vec<ConsentPurgeArtifactV1>,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentPurgeJournalStateV1 {
    Prepared,
    Deleting,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentPurgeJournalEntryStateV1 {
    Pending,
    Deleted,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeJournalEntryV1 {
    pub(crate) artifact: ConsentPurgeArtifactV1,
    pub(crate) state: ConsentPurgeJournalEntryStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeJournalV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approval_bundle_fingerprint: [u8; 32],
    pub(crate) rollback_package_fingerprint: [u8; 32],
    pub(crate) transaction_directory: String,
    pub(crate) state: ConsentPurgeJournalStateV1,
    pub(crate) started_at_unix_secs: u64,
    pub(crate) updated_at_unix_secs: u64,
    pub(crate) entries: Vec<ConsentPurgeJournalEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeReceiptV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approval_bundle_fingerprint: [u8; 32],
    pub(crate) rollback_package_fingerprint: [u8; 32],
    pub(crate) transaction_directory: String,
    pub(crate) started_at_unix_secs: u64,
    pub(crate) completed_at_unix_secs: u64,
    pub(crate) entries: Vec<ConsentPurgeJournalEntryV1>,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentPurgeRecoveryOutcomeV1 {
    FinalizedCommitted,
    RolledBack,
    AlreadyCommitted,
    AlreadyRolledBack,
}

/// Ledger-authority authorization for one exact purge attempt. The plan cannot
/// be issued until the signed quarantine receipt has aged by at least the
/// configured minimum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgePlanV1 {
    pub(crate) schema: String,
    pub(crate) purge_id: [u8; 16],
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) retirement_plan_fingerprint: [u8; 32],
    pub(crate) retirement_approval_bundle_fingerprint: [u8; 32],
    pub(crate) quarantine_receipt_fingerprint: [u8; 32],
    pub(crate) quarantine_transaction_directory: String,
    pub(crate) rollback_root: String,
    pub(crate) candidates: Vec<ConsentPurgeArtifactV1>,
    pub(crate) quarantine_completed_at_unix_secs: u64,
    pub(crate) minimum_quarantine_age_secs: u64,
    pub(crate) issued_at_unix_secs: u64,
    pub(crate) expires_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConsentPurgeError {
    #[error("consent purge plan has unsupported schema: {schema}")]
    UnsupportedPlanSchema { schema: String },
    #[error("consent purge plan must contain between 1 and {maximum} candidates")]
    InvalidCandidateCount { maximum: usize },
    #[error("consent purge path is not canonical absolute UTF-8: {path}")]
    NonCanonicalPath { path: String },
    #[error("consent purge path exceeds {maximum} UTF-8 bytes: {path}")]
    PathTooLong { path: String, maximum: usize },
    #[error("consent purge candidate path appears more than once: {path}")]
    DuplicateCandidatePath { path: String },
    #[error("consent purge candidate digest cannot be all zeroes: {path}")]
    ZeroCandidateDigest { path: String },
    #[error("consent purge candidates are not in canonical order")]
    CandidateOrderMismatch,
    #[error("consent purge rollback root overlaps quarantine storage")]
    RollbackRootOverlapsQuarantine,
    #[error("consent purge minimum quarantine age must be between {minimum} and {maximum} seconds")]
    InvalidMinimumAge { minimum: u64, maximum: u64 },
    #[error("consent purge plan was issued before the quarantine minimum age elapsed")]
    QuarantineAgeNotMet,
    #[error("consent purge plan expiry must be after issuance")]
    InvalidPlanWindow,
    #[error("consent purge plan lifetime exceeds {maximum} seconds")]
    PlanWindowTooLong { maximum: u64 },
    #[error("consent purge plan signature is invalid")]
    InvalidPlanSignature,
    #[error("consent purge plan is not yet valid")]
    PlanFromFuture,
    #[error("consent purge plan expired")]
    PlanExpired,
    #[error("consent purge plan does not match the retirement plan")]
    RetirementPlanMismatch,
    #[error("consent purge plan does not match the retirement approval bundle")]
    RetirementApprovalsMismatch,
    #[error("consent purge plan does not match the quarantine receipt")]
    QuarantineReceiptMismatch,
    #[error("consent purge plan encoding length overflow")]
    EncodingLengthOverflow,
    #[error("consent purge approval bundle has unsupported schema: {schema}")]
    UnsupportedApprovalBundleSchema { schema: String },
    #[error("consent purge approval bundle refers to another plan")]
    ApprovalPlanMismatch,
    #[error("consent purge approval timestamp is outside the plan window")]
    ApprovalOutsidePlanWindow,
    #[error("consent purge approval key appears more than once")]
    DuplicateApprovalKey,
    #[error("consent purge approval key is not trusted")]
    UntrustedApprovalKey,
    #[error("consent purge approval public key is malformed")]
    BadApprovalPublicKey,
    #[error("consent purge approval signature is invalid")]
    InvalidApprovalSignature,
    #[error("consent purge approval quorum cannot be zero")]
    ZeroApprovalQuorum,
    #[error("consent purge approval quorum was not met: observed={observed}, required={required}")]
    ApprovalQuorumNotMet { observed: usize, required: usize },
    #[error("consent purge approval bundle exceeds {maximum} approvals: {count}")]
    TooManyApprovals { count: usize, maximum: usize },
    #[error("consent purge rollback package has unsupported schema: {schema}")]
    UnsupportedRollbackPackageSchema { schema: String },
    #[error("consent purge journal has unsupported schema: {schema}")]
    UnsupportedJournalSchema { schema: String },
    #[error("consent purge receipt has unsupported schema: {schema}")]
    UnsupportedReceiptSchema { schema: String },
    #[error("consent purge rollback package signature is invalid")]
    InvalidRollbackPackageSignature,
    #[error("consent purge receipt signature is invalid")]
    InvalidReceiptSignature,
    #[error("consent purge rollback package identity does not match the plan")]
    RollbackPackageIdentityMismatch,
    #[error("consent purge journal identity does not match the signed inputs")]
    JournalIdentityMismatch,
    #[error("consent purge receipt identity does not match the signed inputs")]
    ReceiptIdentityMismatch,
    #[error("consent purge transaction already exists: {path}")]
    TransactionAlreadyExists { path: String },
    #[error("consent purge artifact is not a regular non-symlink file: {path}")]
    ArtifactNotRegular { path: String },
    #[error("consent purge artifact exceeds {maximum} bytes: {path}")]
    ArtifactTooLarge { path: String, maximum: u64 },
    #[error("consent purge artifact is missing or changed: {path}")]
    ArtifactChanged { path: String },
    #[error("consent purge rollback package copy is missing or changed: {path}")]
    RollbackCopyMismatch { path: String },
    #[error("consent purge committed transaction is missing its signed receipt")]
    MissingCommittedReceipt,
    #[error("consent purge journal state is invalid for this operation")]
    InvalidJournalState,
    #[error(
        "consent purge filesystem state is ambiguous: quarantine={quarantine}, rollback={rollback}"
    )]
    AmbiguousFilesystemState {
        quarantine: String,
        rollback: String,
    },
    #[error("consent purge I/O failed: {0}")]
    Io(String),
    #[error("consent purge JSON failed: {0}")]
    Json(String),
    #[error("consent purge prerequisite failed: {0}")]
    Retirement(String),
}

impl From<std::io::Error> for ConsentPurgeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for ConsentPurgeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl ConsentPurgePlanV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        retirement_plan: &ConsentRetirementPlanV1,
        retirement_approvals: &ConsentRetirementApprovalBundleV1,
        quarantine_receipt: &ConsentRetirementQuarantineReceiptV1,
        rollback_root: String,
        minimum_quarantine_age_secs: u64,
        signing_key: &LedgerSigningKey,
        issued_at_unix_secs: u64,
        expires_at_unix_secs: u64,
    ) -> Result<Self, ConsentPurgeError> {
        let public_key = signing_key.verifying_key();
        retirement_plan
            .verify_authority_signature(&public_key)
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
        let observed_keys = retirement_approvals
            .approvals
            .iter()
            .map(|approval| approval.witness_public_key)
            .collect::<Vec<_>>();
        retirement_approvals
            .verify_quorum(retirement_plan, &observed_keys, observed_keys.len().max(1))
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
        quarantine_receipt
            .verify(retirement_plan, retirement_approvals, &public_key)
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
        verify_quarantined_receipt_files(quarantine_receipt)
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;

        let purge_id = *Uuid::new_v4().as_bytes();
        let rollback_directory = Path::new(&rollback_root).join(hex::encode(purge_id));
        let mut candidates = quarantine_receipt
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| ConsentPurgeArtifactV1 {
                role: entry.artifact.role,
                quarantine_path: entry.quarantine_path.clone(),
                rollback_path: rollback_directory
                    .join(format!("{index:04}-artifact.bin"))
                    .to_string_lossy()
                    .into_owned(),
                byte_length: entry.artifact.byte_length,
                blake3_digest: entry.artifact.blake3_digest,
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.quarantine_path
                .cmp(&right.quarantine_path)
                .then(left.role.cmp(&right.role))
        });
        for (index, candidate) in candidates.iter_mut().enumerate() {
            candidate.rollback_path = rollback_directory
                .join(format!("{index:04}-artifact.bin"))
                .to_string_lossy()
                .into_owned();
        }

        let mut plan = Self {
            schema: CONSENT_PURGE_PLAN_SCHEMA.to_string(),
            purge_id,
            ledger_epoch_id: retirement_plan.ledger_epoch_id,
            retirement_plan_fingerprint: consent_retirement_plan_fingerprint(retirement_plan)
                .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?,
            retirement_approval_bundle_fingerprint: consent_retirement_approval_bundle_fingerprint(
                retirement_approvals,
            )
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?,
            quarantine_receipt_fingerprint: consent_retirement_receipt_fingerprint(
                quarantine_receipt,
            )
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?,
            quarantine_transaction_directory: quarantine_receipt.transaction_directory.clone(),
            rollback_root,
            candidates,
            quarantine_completed_at_unix_secs: quarantine_receipt.completed_at_unix_secs,
            minimum_quarantine_age_secs,
            issued_at_unix_secs,
            expires_at_unix_secs,
            signature: [0u8; 64],
        };
        plan.validate_shape()?;
        plan.signature = signing_key
            .sign(&consent_purge_plan_message(&plan)?)
            .to_bytes();
        plan.verify(
            retirement_plan,
            retirement_approvals,
            quarantine_receipt,
            &public_key,
            issued_at_unix_secs,
        )?;
        Ok(plan)
    }

    pub(crate) fn verify_authority_signature(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentPurgeError> {
        if self.schema != CONSENT_PURGE_PLAN_SCHEMA {
            return Err(ConsentPurgeError::UnsupportedPlanSchema {
                schema: self.schema.clone(),
            });
        }
        self.validate_shape()?;
        public_key
            .verify(
                &consent_purge_plan_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeError::InvalidPlanSignature)
    }

    pub(crate) fn verify_authority_signature_and_window(
        &self,
        public_key: &VerifyingKey,
        now_unix_secs: u64,
    ) -> Result<(), ConsentPurgeError> {
        self.verify_authority_signature(public_key)?;
        if now_unix_secs < self.issued_at_unix_secs {
            return Err(ConsentPurgeError::PlanFromFuture);
        }
        if now_unix_secs >= self.expires_at_unix_secs {
            return Err(ConsentPurgeError::PlanExpired);
        }
        Ok(())
    }

    pub(crate) fn verify(
        &self,
        retirement_plan: &ConsentRetirementPlanV1,
        retirement_approvals: &ConsentRetirementApprovalBundleV1,
        quarantine_receipt: &ConsentRetirementQuarantineReceiptV1,
        public_key: &VerifyingKey,
        now_unix_secs: u64,
    ) -> Result<(), ConsentPurgeError> {
        self.verify_authority_signature_and_window(public_key, now_unix_secs)?;
        retirement_plan
            .verify_authority_signature(public_key)
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
        quarantine_receipt
            .verify(retirement_plan, retirement_approvals, public_key)
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
        verify_quarantined_receipt_files(quarantine_receipt)
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
        if self.ledger_epoch_id != retirement_plan.ledger_epoch_id
            || self.retirement_plan_fingerprint
                != consent_retirement_plan_fingerprint(retirement_plan)
                    .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?
        {
            return Err(ConsentPurgeError::RetirementPlanMismatch);
        }
        if self.retirement_approval_bundle_fingerprint
            != consent_retirement_approval_bundle_fingerprint(retirement_approvals)
                .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?
        {
            return Err(ConsentPurgeError::RetirementApprovalsMismatch);
        }
        if self.quarantine_receipt_fingerprint
            != consent_retirement_receipt_fingerprint(quarantine_receipt)
                .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?
            || self.quarantine_transaction_directory != quarantine_receipt.transaction_directory
            || self.quarantine_completed_at_unix_secs != quarantine_receipt.completed_at_unix_secs
        {
            return Err(ConsentPurgeError::QuarantineReceiptMismatch);
        }
        let expected_directory = Path::new(&self.rollback_root).join(hex::encode(self.purge_id));
        let mut expected_candidates = quarantine_receipt
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| ConsentPurgeArtifactV1 {
                role: entry.artifact.role,
                quarantine_path: entry.quarantine_path.clone(),
                rollback_path: expected_directory
                    .join(format!("{index:04}-artifact.bin"))
                    .to_string_lossy()
                    .into_owned(),
                byte_length: entry.artifact.byte_length,
                blake3_digest: entry.artifact.blake3_digest,
            })
            .collect::<Vec<_>>();
        expected_candidates.sort_by(|left, right| {
            left.quarantine_path
                .cmp(&right.quarantine_path)
                .then(left.role.cmp(&right.role))
        });
        // Re-number rollback paths after canonical sorting. The signed path is
        // deterministic from the final order, not from receipt insertion order.
        for (index, candidate) in expected_candidates.iter_mut().enumerate() {
            candidate.rollback_path = expected_directory
                .join(format!("{index:04}-artifact.bin"))
                .to_string_lossy()
                .into_owned();
        }
        if self.candidates != expected_candidates {
            return Err(ConsentPurgeError::QuarantineReceiptMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ConsentPurgeError> {
        if self.candidates.is_empty() || self.candidates.len() > MAX_PURGE_CANDIDATES {
            return Err(ConsentPurgeError::InvalidCandidateCount {
                maximum: MAX_PURGE_CANDIDATES,
            });
        }
        validate_absolute_normal_path(&self.quarantine_transaction_directory)?;
        validate_absolute_normal_path(&self.rollback_root)?;
        let quarantine = Path::new(&self.quarantine_transaction_directory);
        let rollback = Path::new(&self.rollback_root);
        if quarantine.starts_with(rollback) || rollback.starts_with(quarantine) {
            return Err(ConsentPurgeError::RollbackRootOverlapsQuarantine);
        }
        if !(MIN_PURGE_QUARANTINE_AGE_SECS..=MAX_PURGE_QUARANTINE_AGE_SECS)
            .contains(&self.minimum_quarantine_age_secs)
        {
            return Err(ConsentPurgeError::InvalidMinimumAge {
                minimum: MIN_PURGE_QUARANTINE_AGE_SECS,
                maximum: MAX_PURGE_QUARANTINE_AGE_SECS,
            });
        }
        let not_before = self
            .quarantine_completed_at_unix_secs
            .checked_add(self.minimum_quarantine_age_secs)
            .ok_or(ConsentPurgeError::QuarantineAgeNotMet)?;
        if self.issued_at_unix_secs < not_before {
            return Err(ConsentPurgeError::QuarantineAgeNotMet);
        }
        if self.expires_at_unix_secs <= self.issued_at_unix_secs {
            return Err(ConsentPurgeError::InvalidPlanWindow);
        }
        if self
            .expires_at_unix_secs
            .saturating_sub(self.issued_at_unix_secs)
            > MAX_PURGE_PLAN_LIFETIME_SECS
        {
            return Err(ConsentPurgeError::PlanWindowTooLong {
                maximum: MAX_PURGE_PLAN_LIFETIME_SECS,
            });
        }
        let expected_rollback_directory =
            Path::new(&self.rollback_root).join(hex::encode(self.purge_id));
        let mut paths = BTreeSet::new();
        let mut previous: Option<(&str, ConsentRetirementArtifactRoleV1)> = None;
        for (index, candidate) in self.candidates.iter().enumerate() {
            validate_absolute_normal_path(&candidate.quarantine_path)?;
            validate_absolute_normal_path(&candidate.rollback_path)?;
            if candidate.blake3_digest == [0u8; 32] {
                return Err(ConsentPurgeError::ZeroCandidateDigest {
                    path: candidate.quarantine_path.clone(),
                });
            }
            if !paths.insert(candidate.quarantine_path.as_str()) {
                return Err(ConsentPurgeError::DuplicateCandidatePath {
                    path: candidate.quarantine_path.clone(),
                });
            }
            let expected = expected_rollback_directory.join(format!("{index:04}-artifact.bin"));
            if Path::new(&candidate.rollback_path) != expected.as_path() {
                return Err(ConsentPurgeError::CandidateOrderMismatch);
            }
            if let Some((previous_path, previous_role)) = previous
                && (previous_path, previous_role)
                    > (candidate.quarantine_path.as_str(), candidate.role)
            {
                return Err(ConsentPurgeError::CandidateOrderMismatch);
            }
            previous = Some((candidate.quarantine_path.as_str(), candidate.role));
        }
        Ok(())
    }
}

impl ConsentPurgeApprovalBundleV1 {
    pub(crate) fn new(plan: &ConsentPurgePlanV1) -> Result<Self, ConsentPurgeError> {
        Ok(Self {
            schema: CONSENT_PURGE_APPROVAL_BUNDLE_SCHEMA.to_string(),
            plan_fingerprint: consent_purge_plan_fingerprint(plan)?,
            approvals: Vec::new(),
        })
    }

    pub(crate) fn sign_with(
        &mut self,
        plan: &ConsentPurgePlanV1,
        witness_signing_key: &LedgerSigningKey,
        approved_at_unix_secs: u64,
    ) -> Result<(), ConsentPurgeError> {
        if self.schema != CONSENT_PURGE_APPROVAL_BUNDLE_SCHEMA {
            return Err(ConsentPurgeError::UnsupportedApprovalBundleSchema {
                schema: self.schema.clone(),
            });
        }
        if self.plan_fingerprint != consent_purge_plan_fingerprint(plan)? {
            return Err(ConsentPurgeError::ApprovalPlanMismatch);
        }
        if approved_at_unix_secs < plan.issued_at_unix_secs
            || approved_at_unix_secs >= plan.expires_at_unix_secs
        {
            return Err(ConsentPurgeError::ApprovalOutsidePlanWindow);
        }
        if self.approvals.len() >= MAX_PURGE_APPROVALS {
            return Err(ConsentPurgeError::TooManyApprovals {
                count: self.approvals.len() + 1,
                maximum: MAX_PURGE_APPROVALS,
            });
        }
        let witness_public_key = witness_signing_key.verifying_key().to_bytes();
        if self
            .approvals
            .iter()
            .any(|approval| approval.witness_public_key == witness_public_key)
        {
            return Err(ConsentPurgeError::DuplicateApprovalKey);
        }
        let message = consent_purge_approval_message(
            &self.plan_fingerprint,
            &witness_public_key,
            approved_at_unix_secs,
        );
        self.approvals.push(ConsentPurgeApprovalV1 {
            witness_public_key,
            approved_at_unix_secs,
            signature: witness_signing_key.sign(&message).to_bytes(),
        });
        Ok(())
    }

    pub(crate) fn verify_quorum(
        &self,
        plan: &ConsentPurgePlanV1,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<(), ConsentPurgeError> {
        if self.schema != CONSENT_PURGE_APPROVAL_BUNDLE_SCHEMA {
            return Err(ConsentPurgeError::UnsupportedApprovalBundleSchema {
                schema: self.schema.clone(),
            });
        }
        if minimum_quorum == 0 {
            return Err(ConsentPurgeError::ZeroApprovalQuorum);
        }
        if self.approvals.len() > MAX_PURGE_APPROVALS {
            return Err(ConsentPurgeError::TooManyApprovals {
                count: self.approvals.len(),
                maximum: MAX_PURGE_APPROVALS,
            });
        }
        if self.plan_fingerprint != consent_purge_plan_fingerprint(plan)? {
            return Err(ConsentPurgeError::ApprovalPlanMismatch);
        }
        let trusted = trusted_witness_keys
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        for approval in &self.approvals {
            if approval.approved_at_unix_secs < plan.issued_at_unix_secs
                || approval.approved_at_unix_secs >= plan.expires_at_unix_secs
            {
                return Err(ConsentPurgeError::ApprovalOutsidePlanWindow);
            }
            if !observed.insert(approval.witness_public_key) {
                return Err(ConsentPurgeError::DuplicateApprovalKey);
            }
            if !trusted.contains(&approval.witness_public_key) {
                return Err(ConsentPurgeError::UntrustedApprovalKey);
            }
            let public_key = VerifyingKey::from_bytes(&approval.witness_public_key)
                .map_err(|_| ConsentPurgeError::BadApprovalPublicKey)?;
            public_key
                .verify(
                    &consent_purge_approval_message(
                        &self.plan_fingerprint,
                        &approval.witness_public_key,
                        approval.approved_at_unix_secs,
                    ),
                    &Signature::from_bytes(&approval.signature),
                )
                .map_err(|_| ConsentPurgeError::InvalidApprovalSignature)?;
        }
        if observed.len() < minimum_quorum {
            return Err(ConsentPurgeError::ApprovalQuorumNotMet {
                observed: observed.len(),
                required: minimum_quorum,
            });
        }
        Ok(())
    }
}

pub(crate) fn consent_purge_approval_bundle_fingerprint(
    approvals: &ConsentPurgeApprovalBundleV1,
) -> Result<[u8; 32], ConsentPurgeError> {
    if approvals.schema != CONSENT_PURGE_APPROVAL_BUNDLE_SCHEMA {
        return Err(ConsentPurgeError::UnsupportedApprovalBundleSchema {
            schema: approvals.schema.clone(),
        });
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-approval-bundle-fingerprint:v1");
    hasher.update(approvals.schema.as_bytes());
    hasher.update(&approvals.plan_fingerprint);
    hasher.update(&(approvals.approvals.len() as u64).to_be_bytes());
    for approval in &approvals.approvals {
        hasher.update(&approval.witness_public_key);
        hasher.update(&approval.approved_at_unix_secs.to_be_bytes());
        hasher.update(&approval.signature);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn consent_purge_approval_message(
    plan_fingerprint: &[u8; 32],
    witness_public_key: &[u8; 32],
    approved_at_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-approval:v1");
    message.extend_from_slice(plan_fingerprint);
    message.extend_from_slice(witness_public_key);
    message.extend_from_slice(&approved_at_unix_secs.to_be_bytes());
    message
}

pub(crate) fn consent_purge_plan_fingerprint(
    plan: &ConsentPurgePlanV1,
) -> Result<[u8; 32], ConsentPurgeError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-plan-fingerprint:v1");
    hasher.update(&consent_purge_plan_message(plan)?);
    hasher.update(&plan.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn consent_purge_plan_message(plan: &ConsentPurgePlanV1) -> Result<Vec<u8>, ConsentPurgeError> {
    if plan.schema != CONSENT_PURGE_PLAN_SCHEMA {
        return Err(ConsentPurgeError::UnsupportedPlanSchema {
            schema: plan.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-plan:v1");
    append_bytes(&mut message, plan.schema.as_bytes())?;
    message.extend_from_slice(&plan.purge_id);
    message.extend_from_slice(&plan.ledger_epoch_id);
    message.extend_from_slice(&plan.retirement_plan_fingerprint);
    message.extend_from_slice(&plan.retirement_approval_bundle_fingerprint);
    message.extend_from_slice(&plan.quarantine_receipt_fingerprint);
    append_bytes(
        &mut message,
        plan.quarantine_transaction_directory.as_bytes(),
    )?;
    append_bytes(&mut message, plan.rollback_root.as_bytes())?;
    let count = u32::try_from(plan.candidates.len())
        .map_err(|_| ConsentPurgeError::EncodingLengthOverflow)?;
    message.extend_from_slice(&count.to_be_bytes());
    for candidate in &plan.candidates {
        message.push(retirement_role_tag(candidate.role));
        append_bytes(&mut message, candidate.quarantine_path.as_bytes())?;
        append_bytes(&mut message, candidate.rollback_path.as_bytes())?;
        message.extend_from_slice(&candidate.byte_length.to_be_bytes());
        message.extend_from_slice(&candidate.blake3_digest);
    }
    message.extend_from_slice(&plan.quarantine_completed_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&plan.minimum_quarantine_age_secs.to_be_bytes());
    message.extend_from_slice(&plan.issued_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&plan.expires_at_unix_secs.to_be_bytes());
    Ok(message)
}

fn retirement_role_tag(role: ConsentRetirementArtifactRoleV1) -> u8 {
    match role {
        ConsentRetirementArtifactRoleV1::SupersededCompleteLedger => 1,
        ConsentRetirementArtifactRoleV1::SupersededCompactionBundle => 2,
        ConsentRetirementArtifactRoleV1::SupersededCompactedSnapshot => 3,
    }
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ConsentPurgeError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| ConsentPurgeError::EncodingLengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn canonical_private_root(path: &Path) -> Result<String, ConsentPurgeError> {
    let canonical =
        std::fs::canonicalize(path).map_err(|_| ConsentPurgeError::NonCanonicalPath {
            path: path.display().to_string(),
        })?;
    let metadata =
        std::fs::symlink_metadata(&canonical).map_err(|_| ConsentPurgeError::NonCanonicalPath {
            path: canonical.display().to_string(),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ConsentPurgeError::NonCanonicalPath {
            path: canonical.display().to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConsentPurgeError::NonCanonicalPath {
                path: canonical.display().to_string(),
            });
        }
    }
    let value = canonical
        .to_str()
        .ok_or_else(|| ConsentPurgeError::NonCanonicalPath {
            path: canonical.display().to_string(),
        })?
        .to_owned();
    validate_absolute_normal_path(&value)?;
    Ok(value)
}

fn validate_absolute_normal_path(path: &str) -> Result<(), ConsentPurgeError> {
    if path.len() > MAX_PURGE_PATH_BYTES {
        return Err(ConsentPurgeError::PathTooLong {
            path: path.to_string(),
            maximum: MAX_PURGE_PATH_BYTES,
        });
    }
    let value = Path::new(path);
    if !value.is_absolute()
        || value.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(ConsentPurgeError::NonCanonicalPath {
            path: path.to_string(),
        });
    }
    Ok(())
}

impl ConsentPurgeRollbackPackageV1 {
    fn sign(
        plan: &ConsentPurgePlanV1,
        approvals: &ConsentPurgeApprovalBundleV1,
        signing_key: &LedgerSigningKey,
        created_at_unix_secs: u64,
    ) -> Result<Self, ConsentPurgeError> {
        let mut package = Self {
            schema: CONSENT_PURGE_ROLLBACK_PACKAGE_SCHEMA.to_string(),
            plan_fingerprint: consent_purge_plan_fingerprint(plan)?,
            approval_bundle_fingerprint: consent_purge_approval_bundle_fingerprint(approvals)?,
            package_directory: purge_transaction_directory(plan)
                .to_string_lossy()
                .into_owned(),
            created_at_unix_secs,
            entries: plan.candidates.clone(),
            signature: [0u8; 64],
        };
        package.signature = signing_key
            .sign(&consent_purge_rollback_package_message(&package)?)
            .to_bytes();
        package.verify(plan, approvals, &signing_key.verifying_key())?;
        Ok(package)
    }

    pub(crate) fn verify(
        &self,
        plan: &ConsentPurgePlanV1,
        approvals: &ConsentPurgeApprovalBundleV1,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentPurgeError> {
        if self.schema != CONSENT_PURGE_ROLLBACK_PACKAGE_SCHEMA {
            return Err(ConsentPurgeError::UnsupportedRollbackPackageSchema {
                schema: self.schema.clone(),
            });
        }
        if self.plan_fingerprint != consent_purge_plan_fingerprint(plan)?
            || self.approval_bundle_fingerprint
                != consent_purge_approval_bundle_fingerprint(approvals)?
            || self.package_directory
                != purge_transaction_directory(plan).to_string_lossy().as_ref()
            || self.entries != plan.candidates
            || self.created_at_unix_secs < plan.issued_at_unix_secs
        {
            return Err(ConsentPurgeError::RollbackPackageIdentityMismatch);
        }
        public_key
            .verify(
                &consent_purge_rollback_package_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeError::InvalidRollbackPackageSignature)
    }
}

impl ConsentPurgeReceiptV1 {
    pub(crate) fn verify(
        &self,
        plan: &ConsentPurgePlanV1,
        approvals: &ConsentPurgeApprovalBundleV1,
        rollback_package: &ConsentPurgeRollbackPackageV1,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentPurgeError> {
        if self.schema != CONSENT_PURGE_RECEIPT_SCHEMA {
            return Err(ConsentPurgeError::UnsupportedReceiptSchema {
                schema: self.schema.clone(),
            });
        }
        let expected_entries = plan
            .candidates
            .iter()
            .cloned()
            .map(|artifact| ConsentPurgeJournalEntryV1 {
                artifact,
                state: ConsentPurgeJournalEntryStateV1::Deleted,
            })
            .collect::<Vec<_>>();
        if self.plan_fingerprint != consent_purge_plan_fingerprint(plan)?
            || self.approval_bundle_fingerprint
                != consent_purge_approval_bundle_fingerprint(approvals)?
            || self.rollback_package_fingerprint
                != consent_purge_rollback_package_fingerprint(rollback_package)?
            || self.transaction_directory
                != purge_transaction_directory(plan).to_string_lossy().as_ref()
            || self.entries != expected_entries
            || self.completed_at_unix_secs < self.started_at_unix_secs
        {
            return Err(ConsentPurgeError::ReceiptIdentityMismatch);
        }
        public_key
            .verify(
                &consent_purge_receipt_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentPurgeError::InvalidReceiptSignature)
    }
}

pub(crate) fn purge_transaction_directory(plan: &ConsentPurgePlanV1) -> PathBuf {
    Path::new(&plan.rollback_root).join(hex::encode(plan.purge_id))
}

pub(crate) fn purge_journal_path(plan: &ConsentPurgePlanV1) -> PathBuf {
    purge_transaction_directory(plan).join("journal.json")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_consent_purge(
    plan: &ConsentPurgePlanV1,
    approvals: &ConsentPurgeApprovalBundleV1,
    retirement_plan: &ConsentRetirementPlanV1,
    retirement_approvals: &ConsentRetirementApprovalBundleV1,
    quarantine_receipt: &ConsentRetirementQuarantineReceiptV1,
    trusted_witness_keys: &[[u8; 32]],
    minimum_quorum: usize,
    signing_key: &LedgerSigningKey,
    now_unix_secs: u64,
) -> Result<ConsentPurgeReceiptV1, ConsentPurgeError> {
    plan.verify(
        retirement_plan,
        retirement_approvals,
        quarantine_receipt,
        &signing_key.verifying_key(),
        now_unix_secs,
    )?;
    approvals.verify_quorum(plan, trusted_witness_keys, minimum_quorum)?;
    if canonical_private_root(Path::new(&plan.rollback_root))? != plan.rollback_root {
        return Err(ConsentPurgeError::NonCanonicalPath {
            path: plan.rollback_root.clone(),
        });
    }

    let transaction_directory = purge_transaction_directory(plan);
    if transaction_directory.exists() {
        return Err(ConsentPurgeError::TransactionAlreadyExists {
            path: transaction_directory.display().to_string(),
        });
    }
    let temporary_directory = Path::new(&plan.rollback_root).join(format!(
        ".purge-{}-{}.tmp",
        hex::encode(plan.purge_id),
        Uuid::new_v4()
    ));
    create_owner_only_directory(&temporary_directory)?;
    sync_directory(Path::new(&plan.rollback_root))?;

    let preparation = (|| -> Result<
        (ConsentPurgeRollbackPackageV1, ConsentPurgeJournalV1),
        ConsentPurgeError,
    > {
        for (index, artifact) in plan.candidates.iter().enumerate() {
            let source = Path::new(&artifact.quarantine_path);
            verify_exact_file(source, artifact, false)?;
            let temporary_target = temporary_directory.join(format!("{index:04}-artifact.bin"));
            copy_owner_only_exact(source, &temporary_target, artifact)?;
        }
        let rollback_package = ConsentPurgeRollbackPackageV1::sign(
            plan,
            approvals,
            signing_key,
            now_unix_secs,
        )?;
        persist_purge_json(
            &temporary_directory.join("rollback-package.json"),
            &rollback_package,
        )?;
        let journal = ConsentPurgeJournalV1 {
            schema: CONSENT_PURGE_JOURNAL_SCHEMA.to_string(),
            plan_fingerprint: consent_purge_plan_fingerprint(plan)?,
            approval_bundle_fingerprint: consent_purge_approval_bundle_fingerprint(approvals)?,
            rollback_package_fingerprint: consent_purge_rollback_package_fingerprint(&rollback_package)?,
            transaction_directory: transaction_directory.to_string_lossy().into_owned(),
            state: ConsentPurgeJournalStateV1::Prepared,
            started_at_unix_secs: now_unix_secs,
            updated_at_unix_secs: now_unix_secs,
            entries: plan
                .candidates
                .iter()
                .cloned()
                .map(|artifact| ConsentPurgeJournalEntryV1 {
                    artifact,
                    state: ConsentPurgeJournalEntryStateV1::Pending,
                })
                .collect(),
        };
        // Persist the recovery journal inside the temporary package before the
        // directory becomes visible at its final name. A crash after rename can
        // therefore always be recovered, even before the first unlink.
        persist_purge_json(&temporary_directory.join("journal.json"), &journal)?;
        sync_directory(&temporary_directory)?;
        fs::rename(&temporary_directory, &transaction_directory)?;
        sync_directory(Path::new(&plan.rollback_root))?;
        Ok((rollback_package, journal))
    })();
    let (rollback_package, mut journal) = match preparation {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary_directory);
            return Err(error);
        }
    };
    verify_rollback_package_files(&rollback_package)?;

    let journal_path = transaction_directory.join("journal.json");
    journal.state = ConsentPurgeJournalStateV1::Deleting;
    persist_purge_json(&journal_path, &journal)?;

    for index in 0..journal.entries.len() {
        let artifact = journal.entries[index].artifact.clone();
        verify_exact_file(Path::new(&artifact.quarantine_path), &artifact, false)?;
        verify_exact_file(Path::new(&artifact.rollback_path), &artifact, true)?;
        fs::remove_file(&artifact.quarantine_path)?;
        sync_directory(
            Path::new(&artifact.quarantine_path)
                .parent()
                .ok_or_else(|| ConsentPurgeError::NonCanonicalPath {
                    path: artifact.quarantine_path.clone(),
                })?,
        )?;
        journal.entries[index].state = ConsentPurgeJournalEntryStateV1::Deleted;
        journal.updated_at_unix_secs = now_unix_secs;
        persist_purge_json(&journal_path, &journal)?;
    }

    let mut receipt = ConsentPurgeReceiptV1 {
        schema: CONSENT_PURGE_RECEIPT_SCHEMA.to_string(),
        plan_fingerprint: journal.plan_fingerprint,
        approval_bundle_fingerprint: journal.approval_bundle_fingerprint,
        rollback_package_fingerprint: journal.rollback_package_fingerprint,
        transaction_directory: journal.transaction_directory.clone(),
        started_at_unix_secs: journal.started_at_unix_secs,
        completed_at_unix_secs: now_unix_secs,
        entries: journal.entries.clone(),
        signature: [0u8; 64],
    };
    receipt.signature = signing_key
        .sign(&consent_purge_receipt_message(&receipt)?)
        .to_bytes();
    receipt.verify(
        plan,
        approvals,
        &rollback_package,
        &signing_key.verifying_key(),
    )?;
    persist_purge_json(&transaction_directory.join("purge-receipt.json"), &receipt)?;
    journal.state = ConsentPurgeJournalStateV1::Committed;
    journal.updated_at_unix_secs = now_unix_secs;
    persist_purge_json(&journal_path, &journal)?;
    verify_purge_receipt_files(&receipt)?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_consent_purge(
    journal_path: &Path,
    plan: &ConsentPurgePlanV1,
    approvals: &ConsentPurgeApprovalBundleV1,
    retirement_plan: &ConsentRetirementPlanV1,
    retirement_approvals: &ConsentRetirementApprovalBundleV1,
    quarantine_receipt: &ConsentRetirementQuarantineReceiptV1,
    trusted_witness_keys: &[[u8; 32]],
    minimum_quorum: usize,
    public_key: &VerifyingKey,
    now_unix_secs: u64,
) -> Result<ConsentPurgeRecoveryOutcomeV1, ConsentPurgeError> {
    plan.verify_authority_signature(public_key)?;
    verify_purge_prerequisite_identity(
        plan,
        retirement_plan,
        retirement_approvals,
        quarantine_receipt,
        public_key,
    )?;
    approvals.verify_quorum(plan, trusted_witness_keys, minimum_quorum)?;
    let rollback_package_path = purge_transaction_directory(plan).join("rollback-package.json");
    let rollback_package: ConsentPurgeRollbackPackageV1 = read_bounded_json(
        &rollback_package_path,
        MAX_PURGE_TRANSACTION_BYTES,
        "consent purge rollback package",
    )
    .map_err(|err| ConsentPurgeError::Io(err.to_string()))?;
    rollback_package.verify(plan, approvals, public_key)?;
    verify_rollback_package_files(&rollback_package)?;
    let mut journal: ConsentPurgeJournalV1 = read_bounded_json(
        journal_path,
        MAX_PURGE_TRANSACTION_BYTES,
        "consent purge journal",
    )
    .map_err(|err| ConsentPurgeError::Io(err.to_string()))?;
    verify_purge_journal_identity(&journal, plan, approvals, &rollback_package, journal_path)?;
    let receipt_path = purge_transaction_directory(plan).join("purge-receipt.json");
    if receipt_path.exists() {
        let receipt: ConsentPurgeReceiptV1 = read_bounded_json(
            &receipt_path,
            MAX_PURGE_TRANSACTION_BYTES,
            "consent purge receipt",
        )
        .map_err(|err| ConsentPurgeError::Io(err.to_string()))?;
        receipt.verify(plan, approvals, &rollback_package, public_key)?;
        verify_purge_receipt_files(&receipt)?;
        if journal.state == ConsentPurgeJournalStateV1::RolledBack {
            return Err(ConsentPurgeError::InvalidJournalState);
        }
        if journal.state == ConsentPurgeJournalStateV1::Committed {
            return Ok(ConsentPurgeRecoveryOutcomeV1::AlreadyCommitted);
        }
        journal.state = ConsentPurgeJournalStateV1::Committed;
        journal.updated_at_unix_secs = now_unix_secs;
        persist_purge_json(journal_path, &journal)?;
        return Ok(ConsentPurgeRecoveryOutcomeV1::FinalizedCommitted);
    }
    match journal.state {
        ConsentPurgeJournalStateV1::Committed => Err(ConsentPurgeError::MissingCommittedReceipt),
        ConsentPurgeJournalStateV1::RolledBack => {
            verify_rolled_back_purge_files(&journal)?;
            Ok(ConsentPurgeRecoveryOutcomeV1::AlreadyRolledBack)
        }
        ConsentPurgeJournalStateV1::Prepared | ConsentPurgeJournalStateV1::Deleting => {
            rollback_incomplete_purge(&mut journal, journal_path, now_unix_secs)?;
            Ok(ConsentPurgeRecoveryOutcomeV1::RolledBack)
        }
    }
}

pub(crate) fn verify_purge_receipt_files(
    receipt: &ConsentPurgeReceiptV1,
) -> Result<(), ConsentPurgeError> {
    for entry in &receipt.entries {
        if Path::new(&entry.artifact.quarantine_path).exists() {
            return Err(ConsentPurgeError::AmbiguousFilesystemState {
                quarantine: entry.artifact.quarantine_path.clone(),
                rollback: entry.artifact.rollback_path.clone(),
            });
        }
        verify_exact_file(
            Path::new(&entry.artifact.rollback_path),
            &entry.artifact,
            true,
        )?;
        if entry.state != ConsentPurgeJournalEntryStateV1::Deleted {
            return Err(ConsentPurgeError::ReceiptIdentityMismatch);
        }
    }
    Ok(())
}

pub(crate) fn verify_purge_prerequisite_identity(
    plan: &ConsentPurgePlanV1,
    retirement_plan: &ConsentRetirementPlanV1,
    retirement_approvals: &ConsentRetirementApprovalBundleV1,
    quarantine_receipt: &ConsentRetirementQuarantineReceiptV1,
    public_key: &VerifyingKey,
) -> Result<(), ConsentPurgeError> {
    retirement_plan
        .verify_authority_signature(public_key)
        .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
    quarantine_receipt
        .verify(retirement_plan, retirement_approvals, public_key)
        .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?;
    if plan.retirement_plan_fingerprint
        != consent_retirement_plan_fingerprint(retirement_plan)
            .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?
        || plan.retirement_approval_bundle_fingerprint
            != consent_retirement_approval_bundle_fingerprint(retirement_approvals)
                .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?
        || plan.quarantine_receipt_fingerprint
            != consent_retirement_receipt_fingerprint(quarantine_receipt)
                .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?
    {
        return Err(ConsentPurgeError::QuarantineReceiptMismatch);
    }
    Ok(())
}

fn rollback_incomplete_purge(
    journal: &mut ConsentPurgeJournalV1,
    journal_path: &Path,
    now_unix_secs: u64,
) -> Result<(), ConsentPurgeError> {
    for index in (0..journal.entries.len()).rev() {
        let artifact = journal.entries[index].artifact.clone();
        let quarantine = Path::new(&artifact.quarantine_path);
        let rollback = Path::new(&artifact.rollback_path);
        verify_exact_file(rollback, &artifact, true)?;
        if quarantine.exists() {
            verify_exact_file(quarantine, &artifact, false)?;
        } else {
            copy_owner_only_exact(rollback, quarantine, &artifact)?;
            sync_directory(quarantine.parent().ok_or_else(|| {
                ConsentPurgeError::NonCanonicalPath {
                    path: artifact.quarantine_path.clone(),
                }
            })?)?;
        }
        journal.entries[index].state = ConsentPurgeJournalEntryStateV1::Restored;
        journal.updated_at_unix_secs = now_unix_secs;
        persist_purge_json(journal_path, journal)?;
    }
    journal.state = ConsentPurgeJournalStateV1::RolledBack;
    journal.updated_at_unix_secs = now_unix_secs;
    persist_purge_json(journal_path, journal)
}

fn verify_rolled_back_purge_files(
    journal: &ConsentPurgeJournalV1,
) -> Result<(), ConsentPurgeError> {
    for entry in &journal.entries {
        verify_exact_file(
            Path::new(&entry.artifact.quarantine_path),
            &entry.artifact,
            false,
        )?;
        verify_exact_file(
            Path::new(&entry.artifact.rollback_path),
            &entry.artifact,
            true,
        )?;
        if entry.state != ConsentPurgeJournalEntryStateV1::Restored {
            return Err(ConsentPurgeError::InvalidJournalState);
        }
    }
    Ok(())
}

fn verify_purge_journal_identity(
    journal: &ConsentPurgeJournalV1,
    plan: &ConsentPurgePlanV1,
    approvals: &ConsentPurgeApprovalBundleV1,
    rollback_package: &ConsentPurgeRollbackPackageV1,
    journal_path: &Path,
) -> Result<(), ConsentPurgeError> {
    if journal.schema != CONSENT_PURGE_JOURNAL_SCHEMA {
        return Err(ConsentPurgeError::UnsupportedJournalSchema {
            schema: journal.schema.clone(),
        });
    }
    let expected_entries = plan
        .candidates
        .iter()
        .cloned()
        .map(|artifact| ConsentPurgeJournalEntryV1 {
            artifact,
            state: ConsentPurgeJournalEntryStateV1::Pending,
        })
        .collect::<Vec<_>>();
    let same_artifacts = journal.entries.len() == expected_entries.len()
        && journal
            .entries
            .iter()
            .zip(expected_entries)
            .all(|(observed, expected)| observed.artifact == expected.artifact);
    if journal.plan_fingerprint != consent_purge_plan_fingerprint(plan)?
        || journal.approval_bundle_fingerprint
            != consent_purge_approval_bundle_fingerprint(approvals)?
        || journal.rollback_package_fingerprint
            != consent_purge_rollback_package_fingerprint(rollback_package)?
        || journal.transaction_directory
            != purge_transaction_directory(plan).to_string_lossy().as_ref()
        || std::fs::canonicalize(journal_path).ok()
            != std::fs::canonicalize(purge_journal_path(plan)).ok()
        || !same_artifacts
    {
        return Err(ConsentPurgeError::JournalIdentityMismatch);
    }
    Ok(())
}

pub(crate) fn verify_rollback_package_files(
    package: &ConsentPurgeRollbackPackageV1,
) -> Result<(), ConsentPurgeError> {
    for artifact in &package.entries {
        verify_exact_file(Path::new(&artifact.rollback_path), artifact, true)?;
    }
    Ok(())
}

fn copy_owner_only_exact(
    source: &Path,
    target: &Path,
    artifact: &ConsentPurgeArtifactV1,
) -> Result<(), ConsentPurgeError> {
    if target.exists() {
        return Err(ConsentPurgeError::TransactionAlreadyExists {
            path: target.display().to_string(),
        });
    }
    let mut input = File::open(source)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(target)?;
    let copied = std::io::copy(&mut input, &mut output)?;
    if copied != artifact.byte_length {
        return Err(ConsentPurgeError::ArtifactChanged {
            path: source.display().to_string(),
        });
    }
    output.flush()?;
    output.sync_all()?;
    verify_exact_file(target, artifact, true)
}

fn verify_exact_file(
    path: &Path,
    artifact: &ConsentPurgeArtifactV1,
    rollback_copy: bool,
) -> Result<(), ConsentPurgeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        if rollback_copy {
            ConsentPurgeError::RollbackCopyMismatch {
                path: path.display().to_string(),
            }
        } else {
            ConsentPurgeError::ArtifactChanged {
                path: path.display().to_string(),
            }
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConsentPurgeError::ArtifactNotRegular {
            path: path.display().to_string(),
        });
    }
    if metadata.len() > MAX_PURGE_ARTIFACT_BYTES {
        return Err(ConsentPurgeError::ArtifactTooLarge {
            path: path.display().to_string(),
            maximum: MAX_PURGE_ARTIFACT_BYTES,
        });
    }
    let (length, digest) = hash_file(path)?;
    if length != artifact.byte_length || digest != artifact.blake3_digest {
        return Err(if rollback_copy {
            ConsentPurgeError::RollbackCopyMismatch {
                path: path.display().to_string(),
            }
        } else {
            ConsentPurgeError::ArtifactChanged {
                path: path.display().to_string(),
            }
        });
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(u64, [u8; 32]), ConsentPurgeError> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total =
            total
                .checked_add(read as u64)
                .ok_or_else(|| ConsentPurgeError::ArtifactTooLarge {
                    path: path.display().to_string(),
                    maximum: MAX_PURGE_ARTIFACT_BYTES,
                })?;
        if total > MAX_PURGE_ARTIFACT_BYTES {
            return Err(ConsentPurgeError::ArtifactTooLarge {
                path: path.display().to_string(),
                maximum: MAX_PURGE_ARTIFACT_BYTES,
            });
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, *hasher.finalize().as_bytes()))
}

pub(crate) fn consent_purge_rollback_package_fingerprint(
    package: &ConsentPurgeRollbackPackageV1,
) -> Result<[u8; 32], ConsentPurgeError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-rollback-package-fingerprint:v1");
    hasher.update(&consent_purge_rollback_package_message(package)?);
    hasher.update(&package.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn consent_purge_rollback_package_message(
    package: &ConsentPurgeRollbackPackageV1,
) -> Result<Vec<u8>, ConsentPurgeError> {
    if package.schema != CONSENT_PURGE_ROLLBACK_PACKAGE_SCHEMA {
        return Err(ConsentPurgeError::UnsupportedRollbackPackageSchema {
            schema: package.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-rollback-package:v1");
    append_bytes(&mut message, package.schema.as_bytes())?;
    message.extend_from_slice(&package.plan_fingerprint);
    message.extend_from_slice(&package.approval_bundle_fingerprint);
    append_bytes(&mut message, package.package_directory.as_bytes())?;
    message.extend_from_slice(&package.created_at_unix_secs.to_be_bytes());
    append_purge_artifacts(&mut message, &package.entries)?;
    Ok(message)
}

pub(crate) fn consent_purge_receipt_fingerprint(
    receipt: &ConsentPurgeReceiptV1,
) -> Result<[u8; 32], ConsentPurgeError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-purge-receipt-fingerprint:v1");
    hasher.update(&consent_purge_receipt_message(receipt)?);
    hasher.update(&receipt.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn consent_purge_receipt_message(
    receipt: &ConsentPurgeReceiptV1,
) -> Result<Vec<u8>, ConsentPurgeError> {
    if receipt.schema != CONSENT_PURGE_RECEIPT_SCHEMA {
        return Err(ConsentPurgeError::UnsupportedReceiptSchema {
            schema: receipt.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-purge-receipt:v1");
    append_bytes(&mut message, receipt.schema.as_bytes())?;
    message.extend_from_slice(&receipt.plan_fingerprint);
    message.extend_from_slice(&receipt.approval_bundle_fingerprint);
    message.extend_from_slice(&receipt.rollback_package_fingerprint);
    append_bytes(&mut message, receipt.transaction_directory.as_bytes())?;
    message.extend_from_slice(&receipt.started_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&receipt.completed_at_unix_secs.to_be_bytes());
    let count = u32::try_from(receipt.entries.len())
        .map_err(|_| ConsentPurgeError::EncodingLengthOverflow)?;
    message.extend_from_slice(&count.to_be_bytes());
    for entry in &receipt.entries {
        append_purge_artifact(&mut message, &entry.artifact)?;
        message.push(match entry.state {
            ConsentPurgeJournalEntryStateV1::Pending => 1,
            ConsentPurgeJournalEntryStateV1::Deleted => 2,
            ConsentPurgeJournalEntryStateV1::Restored => 3,
        });
    }
    Ok(message)
}

fn append_purge_artifacts(
    output: &mut Vec<u8>,
    artifacts: &[ConsentPurgeArtifactV1],
) -> Result<(), ConsentPurgeError> {
    let count =
        u32::try_from(artifacts.len()).map_err(|_| ConsentPurgeError::EncodingLengthOverflow)?;
    output.extend_from_slice(&count.to_be_bytes());
    for artifact in artifacts {
        append_purge_artifact(output, artifact)?;
    }
    Ok(())
}

fn append_purge_artifact(
    output: &mut Vec<u8>,
    artifact: &ConsentPurgeArtifactV1,
) -> Result<(), ConsentPurgeError> {
    output.push(retirement_role_tag(artifact.role));
    append_bytes(output, artifact.quarantine_path.as_bytes())?;
    append_bytes(output, artifact.rollback_path.as_bytes())?;
    output.extend_from_slice(&artifact.byte_length.to_be_bytes());
    output.extend_from_slice(&artifact.blake3_digest);
    Ok(())
}

fn persist_purge_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ConsentPurgeError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_PURGE_TRANSACTION_BYTES {
        return Err(ConsentPurgeError::ArtifactTooLarge {
            path: path.display().to_string(),
            maximum: MAX_PURGE_TRANSACTION_BYTES,
        });
    }
    persist_owner_only_atomic(path, &bytes).map_err(|err| ConsentPurgeError::Io(err.to_string()))
}

#[cfg(unix)]
fn create_owner_only_directory(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_owner_only_directory(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir(path)
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent_retirement::{
        ConsentRetirementJournalEntryStateV1, ConsentRetirementJournalEntryV1,
    };

    fn fixture() -> (
        LedgerSigningKey,
        ConsentRetirementPlanV1,
        ConsentRetirementApprovalBundleV1,
        ConsentRetirementQuarantineReceiptV1,
    ) {
        let key = LedgerSigningKey::from_bytes(&[0x71; 32]);
        let plan = ConsentRetirementPlanV1 {
            schema: crate::consent_retirement::CONSENT_RETIREMENT_PLAN_SCHEMA.into(),
            plan_id: [7; 16],
            ledger_epoch_id: [9; 32],
            active_state_digest: [8; 32],
            state_pin_fingerprint: [6; 32],
            gc_certificate_fingerprint: [5; 32],
            quarantine_root: "/var/lib/xenia/quarantine".into(),
            candidates: vec![crate::consent_retirement::ConsentRetirementArtifactV1 {
                role: ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
                canonical_path: "/var/lib/xenia/old-ledger".into(),
                byte_length: 4,
                blake3_digest: *blake3::hash(b"data").as_bytes(),
            }],
            issued_at_unix_secs: 1,
            expires_at_unix_secs: 100,
            signature: [0; 64],
        };
        // End-to-end signed prerequisite fixtures are exercised by the
        // retirement module. These tests isolate purge-plan shape invariants;
        // filesystem execution tests are added with the purge transaction.
        let approvals = ConsentRetirementApprovalBundleV1 {
            schema: crate::consent_retirement::CONSENT_RETIREMENT_APPROVAL_BUNDLE_SCHEMA.into(),
            plan_fingerprint: [0; 32],
            approvals: vec![],
        };
        let receipt = ConsentRetirementQuarantineReceiptV1 {
            schema: crate::consent_retirement::CONSENT_RETIREMENT_RECEIPT_SCHEMA.into(),
            plan_fingerprint: [0; 32],
            approval_bundle_fingerprint: [0; 32],
            transaction_directory: "/var/lib/xenia/quarantine/tx".into(),
            started_at_unix_secs: 10,
            completed_at_unix_secs: 20,
            entries: vec![ConsentRetirementJournalEntryV1 {
                artifact: plan.candidates[0].clone(),
                quarantine_path: "/var/lib/xenia/quarantine/tx/0000-artifact.bin".into(),
                state: ConsentRetirementJournalEntryStateV1::Moved,
            }],
            signature: [0; 64],
        };
        (key, plan, approvals, receipt)
    }

    #[test]
    fn plan_shape_requires_aged_quarantine_and_disjoint_rollback_root() {
        let (_key, retirement_plan, approvals, receipt) = fixture();
        let purge_id = [3; 16];
        let mut purge = ConsentPurgePlanV1 {
            schema: CONSENT_PURGE_PLAN_SCHEMA.into(),
            purge_id,
            ledger_epoch_id: retirement_plan.ledger_epoch_id,
            retirement_plan_fingerprint: [1; 32],
            retirement_approval_bundle_fingerprint: [2; 32],
            quarantine_receipt_fingerprint: [3; 32],
            quarantine_transaction_directory: receipt.transaction_directory,
            rollback_root: "/mnt/xenia-rollback".into(),
            candidates: vec![ConsentPurgeArtifactV1 {
                role: ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
                quarantine_path: "/var/lib/xenia/quarantine/tx/0000-artifact.bin".into(),
                rollback_path: format!(
                    "/mnt/xenia-rollback/{}/0000-artifact.bin",
                    hex::encode(purge_id)
                ),
                byte_length: 4,
                blake3_digest: *blake3::hash(b"data").as_bytes(),
            }],
            quarantine_completed_at_unix_secs: 20,
            minimum_quarantine_age_secs: MIN_PURGE_QUARANTINE_AGE_SECS,
            issued_at_unix_secs: 20 + MIN_PURGE_QUARANTINE_AGE_SECS,
            expires_at_unix_secs: 20 + MIN_PURGE_QUARANTINE_AGE_SECS + 60,
            signature: [0; 64],
        };
        purge.validate_shape().unwrap();
        purge.rollback_root = "/var/lib/xenia/quarantine".into();
        assert_eq!(
            purge.validate_shape(),
            Err(ConsentPurgeError::RollbackRootOverlapsQuarantine)
        );
        let _ = approvals;
    }

    #[test]
    fn plan_shape_refuses_early_or_long_lived_authorization() {
        let (_key, retirement_plan, _approvals, receipt) = fixture();
        let purge_id = [4; 16];
        let mut purge = ConsentPurgePlanV1 {
            schema: CONSENT_PURGE_PLAN_SCHEMA.into(),
            purge_id,
            ledger_epoch_id: retirement_plan.ledger_epoch_id,
            retirement_plan_fingerprint: [1; 32],
            retirement_approval_bundle_fingerprint: [2; 32],
            quarantine_receipt_fingerprint: [3; 32],
            quarantine_transaction_directory: receipt.transaction_directory,
            rollback_root: "/mnt/xenia-rollback".into(),
            candidates: vec![ConsentPurgeArtifactV1 {
                role: ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
                quarantine_path: "/var/lib/xenia/quarantine/tx/0000-artifact.bin".into(),
                rollback_path: format!(
                    "/mnt/xenia-rollback/{}/0000-artifact.bin",
                    hex::encode(purge_id)
                ),
                byte_length: 4,
                blake3_digest: *blake3::hash(b"data").as_bytes(),
            }],
            quarantine_completed_at_unix_secs: 20,
            minimum_quarantine_age_secs: MIN_PURGE_QUARANTINE_AGE_SECS,
            issued_at_unix_secs: 20,
            expires_at_unix_secs: 80,
            signature: [0; 64],
        };
        assert_eq!(
            purge.validate_shape(),
            Err(ConsentPurgeError::QuarantineAgeNotMet)
        );
        purge.issued_at_unix_secs = 20 + MIN_PURGE_QUARANTINE_AGE_SECS;
        purge.expires_at_unix_secs = purge.issued_at_unix_secs + MAX_PURGE_PLAN_LIFETIME_SECS + 1;
        assert_eq!(
            purge.validate_shape(),
            Err(ConsentPurgeError::PlanWindowTooLong {
                maximum: MAX_PURGE_PLAN_LIFETIME_SECS
            })
        );
    }
    #[test]
    fn purge_approval_quorum_requires_distinct_trusted_keys() {
        let (_key, retirement_plan, _approvals, receipt) = fixture();
        let purge_id = [5; 16];
        let plan = ConsentPurgePlanV1 {
            schema: CONSENT_PURGE_PLAN_SCHEMA.into(),
            purge_id,
            ledger_epoch_id: retirement_plan.ledger_epoch_id,
            retirement_plan_fingerprint: [1; 32],
            retirement_approval_bundle_fingerprint: [2; 32],
            quarantine_receipt_fingerprint: [3; 32],
            quarantine_transaction_directory: receipt.transaction_directory,
            rollback_root: "/mnt/xenia-rollback".into(),
            candidates: vec![ConsentPurgeArtifactV1 {
                role: ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
                quarantine_path: "/var/lib/xenia/quarantine/tx/0000-artifact.bin".into(),
                rollback_path: format!(
                    "/mnt/xenia-rollback/{}/0000-artifact.bin",
                    hex::encode(purge_id)
                ),
                byte_length: 4,
                blake3_digest: *blake3::hash(b"data").as_bytes(),
            }],
            quarantine_completed_at_unix_secs: 20,
            minimum_quarantine_age_secs: MIN_PURGE_QUARANTINE_AGE_SECS,
            issued_at_unix_secs: 20 + MIN_PURGE_QUARANTINE_AGE_SECS,
            expires_at_unix_secs: 20 + MIN_PURGE_QUARANTINE_AGE_SECS + 60,
            signature: [7; 64],
        };
        let first = LedgerSigningKey::from_bytes(&[0x72; 32]);
        let second = LedgerSigningKey::from_bytes(&[0x73; 32]);
        let mut bundle = ConsentPurgeApprovalBundleV1::new(&plan).unwrap();
        bundle
            .sign_with(&plan, &first, plan.issued_at_unix_secs)
            .unwrap();
        assert_eq!(
            bundle.verify_quorum(
                &plan,
                &[
                    first.verifying_key().to_bytes(),
                    second.verifying_key().to_bytes()
                ],
                2,
            ),
            Err(ConsentPurgeError::ApprovalQuorumNotMet {
                observed: 1,
                required: 2,
            })
        );
        bundle
            .sign_with(&plan, &second, plan.issued_at_unix_secs + 1)
            .unwrap();
        bundle
            .verify_quorum(
                &plan,
                &[
                    first.verifying_key().to_bytes(),
                    second.verifying_key().to_bytes(),
                ],
                2,
            )
            .unwrap();
        assert_eq!(
            bundle.sign_with(&plan, &first, plan.issued_at_unix_secs + 2),
            Err(ConsentPurgeError::DuplicateApprovalKey)
        );
    }

    #[test]
    fn rollback_copy_hashing_detects_substitution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"expected").unwrap();
        let artifact = ConsentPurgeArtifactV1 {
            role: ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            quarantine_path: path.to_string_lossy().into_owned(),
            rollback_path: dir.path().join("copy").to_string_lossy().into_owned(),
            byte_length: 8,
            blake3_digest: *blake3::hash(b"expected").as_bytes(),
        };
        verify_exact_file(&path, &artifact, false).unwrap();
        std::fs::write(&path, b"changed!").unwrap();
        assert!(matches!(
            verify_exact_file(&path, &artifact, false),
            Err(ConsentPurgeError::ArtifactChanged { .. })
        ));
    }

    #[test]
    fn incomplete_purge_restores_missing_quarantine_bytes_from_backup() {
        let dir = tempfile::tempdir().unwrap();
        let quarantine = dir.path().join("quarantine-artifact");
        let rollback = dir.path().join("rollback-artifact");
        std::fs::write(&rollback, b"payload").unwrap();
        let artifact = ConsentPurgeArtifactV1 {
            role: ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            quarantine_path: quarantine.to_string_lossy().into_owned(),
            rollback_path: rollback.to_string_lossy().into_owned(),
            byte_length: 7,
            blake3_digest: *blake3::hash(b"payload").as_bytes(),
        };
        let journal_path = dir.path().join("journal.json");
        let mut journal = ConsentPurgeJournalV1 {
            schema: CONSENT_PURGE_JOURNAL_SCHEMA.into(),
            plan_fingerprint: [1; 32],
            approval_bundle_fingerprint: [2; 32],
            rollback_package_fingerprint: [3; 32],
            transaction_directory: dir.path().to_string_lossy().into_owned(),
            state: ConsentPurgeJournalStateV1::Deleting,
            started_at_unix_secs: 1,
            updated_at_unix_secs: 1,
            entries: vec![ConsentPurgeJournalEntryV1 {
                artifact,
                state: ConsentPurgeJournalEntryStateV1::Pending,
            }],
        };
        rollback_incomplete_purge(&mut journal, &journal_path, 2).unwrap();
        assert_eq!(std::fs::read(&quarantine).unwrap(), b"payload");
        assert_eq!(journal.state, ConsentPurgeJournalStateV1::RolledBack);
        assert!(rollback.exists());
    }
}
