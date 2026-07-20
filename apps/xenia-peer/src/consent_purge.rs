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
use std::path::{Component, Path};

use ed25519_dalek::{
    Signature, Signer, SigningKey as LedgerSigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::consent_retirement::{
    consent_retirement_approval_bundle_fingerprint, consent_retirement_plan_fingerprint,
    consent_retirement_receipt_fingerprint, verify_quarantined_receipt_files,
    ConsentRetirementApprovalBundleV1, ConsentRetirementArtifactRoleV1,
    ConsentRetirementPlanV1, ConsentRetirementQuarantineReceiptV1,
};

pub(crate) const CONSENT_PURGE_PLAN_SCHEMA: &str = "xenia-consent-purge-plan-v1";
pub(crate) const MAX_PURGE_CANDIDATES: usize = 32;
pub(crate) const MIN_PURGE_QUARANTINE_AGE_SECS: u64 = 24 * 60 * 60;
pub(crate) const MAX_PURGE_QUARANTINE_AGE_SECS: u64 = 365 * 24 * 60 * 60;
pub(crate) const MAX_PURGE_PLAN_LIFETIME_SECS: u64 = 60 * 60;
pub(crate) const MAX_PURGE_PATH_BYTES: usize = 4096;
pub(crate) const MAX_PURGE_TRANSACTION_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentPurgeArtifactV1 {
    pub(crate) role: ConsentRetirementArtifactRoleV1,
    pub(crate) quarantine_path: String,
    pub(crate) rollback_path: String,
    pub(crate) byte_length: u64,
    pub(crate) blake3_digest: [u8; 32],
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
    #[error("consent purge prerequisite failed: {0}")]
    Retirement(String),
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
            retirement_approval_bundle_fingerprint:
                consent_retirement_approval_bundle_fingerprint(retirement_approvals)
                    .map_err(|err| ConsentPurgeError::Retirement(err.to_string()))?,
            quarantine_receipt_fingerprint:
                consent_retirement_receipt_fingerprint(quarantine_receipt)
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
        plan.signature = signing_key.sign(&consent_purge_plan_message(&plan)?).to_bytes();
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
            || self.quarantine_completed_at_unix_secs
                != quarantine_receipt.completed_at_unix_secs
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
        let expected_rollback_directory = Path::new(&self.rollback_root).join(hex::encode(self.purge_id));
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
            if Path::new(&candidate.rollback_path) != expected {
                return Err(ConsentPurgeError::CandidateOrderMismatch);
            }
            if let Some((previous_path, previous_role)) = previous {
                if (previous_path, previous_role)
                    > (candidate.quarantine_path.as_str(), candidate.role)
                {
                    return Err(ConsentPurgeError::CandidateOrderMismatch);
                }
            }
            previous = Some((candidate.quarantine_path.as_str(), candidate.role));
        }
        Ok(())
    }
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
    let length = u32::try_from(bytes.len()).map_err(|_| ConsentPurgeError::EncodingLengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn canonical_private_root(path: &Path) -> Result<String, ConsentPurgeError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| ConsentPurgeError::NonCanonicalPath {
        path: path.display().to_string(),
    })?;
    let metadata = std::fs::symlink_metadata(&canonical)
        .map_err(|_| ConsentPurgeError::NonCanonicalPath {
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
    if path.as_bytes().len() > MAX_PURGE_PATH_BYTES {
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
                rollback_path: format!("/mnt/xenia-rollback/{}/0000-artifact.bin", hex::encode(purge_id)),
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
                rollback_path: format!("/mnt/xenia-rollback/{}/0000-artifact.bin", hex::encode(purge_id)),
                byte_length: 4,
                blake3_digest: *blake3::hash(b"data").as_bytes(),
            }],
            quarantine_completed_at_unix_secs: 20,
            minimum_quarantine_age_secs: MIN_PURGE_QUARANTINE_AGE_SECS,
            issued_at_unix_secs: 20,
            expires_at_unix_secs: 80,
            signature: [0; 64],
        };
        assert_eq!(purge.validate_shape(), Err(ConsentPurgeError::QuarantineAgeNotMet));
        purge.issued_at_unix_secs = 20 + MIN_PURGE_QUARANTINE_AGE_SECS;
        purge.expires_at_unix_secs = purge.issued_at_unix_secs + MAX_PURGE_PLAN_LIFETIME_SECS + 1;
        assert_eq!(
            purge.validate_shape(),
            Err(ConsentPurgeError::PlanWindowTooLong {
                maximum: MAX_PURGE_PLAN_LIFETIME_SECS
            })
        );
    }
}
