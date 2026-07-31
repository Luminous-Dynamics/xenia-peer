// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authorization-only readiness protocol for eventual rollback-package destruction.
//!
//! This module contains no filesystem deletion operation. It proves that one
//! exact inventory has completed its retention period, remains covered by an
//! independently attested custody quorum, and has received a distinct final-
//! destruction approval quorum.

use std::collections::BTreeSet;
use std::path::Path;

use ed25519_dalek::{
    Signature, Signer, SigningKey as LedgerSigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::consent_purge_custody::{
    ConsentPurgeCustodyBundleV1, ConsentPurgeCustodyError, MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
    consent_purge_custody_bundle_fingerprint,
};
use crate::consent_purge_retention::{
    ConsentPurgeProtectedArtifactV1, ConsentPurgeRetentionCertificateV1,
    ConsentPurgeRetentionError, ConsentPurgeRetentionSubjectV1,
    consent_purge_retention_certificate_fingerprint, protected_inventory_digest,
    verify_protected_inventory_files,
};
use serde_big_array::BigArray;

pub(crate) const CONSENT_FINAL_DESTRUCTION_PLAN_SCHEMA: &str =
    "xenia-consent-final-destruction-plan-v1";
pub(crate) const CONSENT_FINAL_DESTRUCTION_APPROVAL_BUNDLE_SCHEMA: &str =
    "xenia-consent-final-destruction-approval-bundle-v1";
pub(crate) const CONSENT_FINAL_DESTRUCTION_READINESS_SCHEMA: &str =
    "xenia-consent-final-destruction-readiness-v1";
pub(crate) const MAX_FINAL_DESTRUCTION_CANDIDATES: usize = 64;
pub(crate) const MAX_FINAL_DESTRUCTION_APPROVALS: usize = 64;
pub(crate) const MAX_FINAL_DESTRUCTION_PLAN_LIFETIME_SECS: u64 = 60 * 60;
pub(crate) const MAX_FINAL_DESTRUCTION_FUTURE_SKEW_SECS: u64 = 5 * 60;
pub(crate) const MAX_FINAL_DESTRUCTION_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentFinalDestructionPlanV1 {
    pub(crate) schema: String,
    pub(crate) destruction_id: [u8; 16],
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) retention_base_certificate_fingerprint: [u8; 32],
    pub(crate) retention_obligation_fingerprint: [u8; 32],
    pub(crate) retention_anchor_fingerprint: [u8; 32],
    pub(crate) custody_bundle_fingerprint: [u8; 32],
    pub(crate) protected_inventory_digest: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) candidates: Vec<ConsentPurgeProtectedArtifactV1>,
    pub(crate) retention_satisfied_at_unix_secs: u64,
    pub(crate) issued_at_unix_secs: u64,
    pub(crate) expires_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentFinalDestructionApprovalV1 {
    pub(crate) witness_public_key: [u8; 32],
    pub(crate) approved_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentFinalDestructionApprovalBundleV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approvals: Vec<ConsentFinalDestructionApprovalV1>,
}

/// Ledger-signed proof that all readiness checks passed. It is not permission
/// for an implicit cleanup implementation and does not delete any path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentFinalDestructionReadinessV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) destruction_id: [u8; 16],
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approval_bundle_fingerprint: [u8; 32],
    pub(crate) custody_bundle_fingerprint: [u8; 32],
    pub(crate) protected_inventory_digest: [u8; 32],
    pub(crate) package_directory: String,
    pub(crate) candidate_count: u32,
    pub(crate) ready_at_unix_secs: u64,
    pub(crate) expires_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConsentFinalDestructionError {
    #[error("final-destruction plan has unsupported schema: {schema}")]
    UnsupportedPlanSchema { schema: String },
    #[error("final-destruction approval bundle has unsupported schema: {schema}")]
    UnsupportedApprovalBundleSchema { schema: String },
    #[error("final-destruction readiness artifact has unsupported schema: {schema}")]
    UnsupportedReadinessSchema { schema: String },
    #[error("final-destruction id cannot be all zeroes")]
    ZeroDestructionId,
    #[error("final-destruction plan must contain the complete protected inventory")]
    IncompleteCandidateInventory,
    #[error("final-destruction plan contains too many candidates: {count}; maximum={maximum}")]
    TooManyCandidates { count: usize, maximum: usize },
    #[error("final-destruction candidate inventory is not canonical")]
    CandidateOrderMismatch,
    #[error("final-destruction candidate lies outside the protected package: {path}")]
    CandidateOutsidePackage { path: String },
    #[error("final-destruction candidate has an all-zero digest: {path}")]
    ZeroCandidateDigest { path: String },
    #[error("final-destruction candidate inventory digest does not match the plan")]
    CandidateInventoryDigestMismatch,
    #[error("final-destruction candidate path appears more than once: {path}")]
    DuplicateCandidatePath { path: String },
    #[error("final-destruction plan identity does not match verified retention evidence")]
    RetentionSubjectMismatch,
    #[error("final-destruction plan cannot be issued before retention expires")]
    RetentionStillActive,
    #[error("final-destruction plan expiry must be after issuance")]
    InvalidPlanWindow,
    #[error("final-destruction plan lifetime exceeds {maximum} seconds")]
    PlanWindowTooLong { maximum: u64 },
    #[error("final-destruction plan is not yet valid")]
    PlanFromFuture,
    #[error("final-destruction plan expired")]
    PlanExpired,
    #[error("final-destruction plan signature is invalid")]
    InvalidPlanSignature,
    #[error("final-destruction approval bundle refers to another plan")]
    ApprovalPlanMismatch,
    #[error("final-destruction approval key appears more than once")]
    DuplicateApprovalKey,
    #[error("final-destruction approvals are not in canonical key order")]
    ApprovalOrderMismatch,
    #[error("final-destruction approval key is not trusted")]
    UntrustedApprovalKey,
    #[error("final-destruction approval public key is malformed")]
    BadApprovalPublicKey,
    #[error("final-destruction approval signature is invalid")]
    InvalidApprovalSignature,
    #[error("final-destruction approval timestamp is outside the plan window")]
    ApprovalOutsidePlanWindow,
    #[error("final-destruction approval was recorded after the readiness timestamp")]
    ApprovalAfterReadiness,
    #[error("final-destruction approval quorum cannot be zero")]
    ZeroApprovalQuorum,
    #[error(
        "final-destruction approval quorum was not met: observed={observed}, required={required}"
    )]
    ApprovalQuorumNotMet { observed: usize, required: usize },
    #[error("final-destruction approval bundle exceeds {maximum} approvals: {count}")]
    TooManyApprovals { count: usize, maximum: usize },
    #[error("final-destruction readiness identity does not match its prerequisite evidence")]
    ReadinessIdentityMismatch,
    #[error("final-destruction readiness signature is invalid")]
    InvalidReadinessSignature,
    #[error("final-destruction encoding length overflow")]
    EncodingLengthOverflow,
    #[error("final-destruction retention prerequisite failed: {0}")]
    Retention(String),
    #[error("final-destruction custody prerequisite failed: {0}")]
    Custody(String),
}

impl From<ConsentPurgeRetentionError> for ConsentFinalDestructionError {
    fn from(error: ConsentPurgeRetentionError) -> Self {
        Self::Retention(error.to_string())
    }
}

impl From<ConsentPurgeCustodyError> for ConsentFinalDestructionError {
    fn from(error: ConsentPurgeCustodyError) -> Self {
        Self::Custody(error.to_string())
    }
}

impl ConsentFinalDestructionPlanV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        certificate: &ConsentPurgeRetentionCertificateV1,
        subject: &ConsentPurgeRetentionSubjectV1,
        custody_bundle: &ConsentPurgeCustodyBundleV1,
        trusted_custodian_keys: &[[u8; 32]],
        custody_quorum: usize,
        signing_key: &LedgerSigningKey,
        issued_at_unix_secs: u64,
        expires_at_unix_secs: u64,
    ) -> Result<Self, ConsentFinalDestructionError> {
        certificate.verify_authority_signature(&signing_key.verifying_key())?;
        verify_protected_inventory_files(certificate)?;
        verify_certificate_matches_subject(certificate, subject)?;
        if issued_at_unix_secs < subject.retain_until_unix_secs {
            return Err(ConsentFinalDestructionError::RetentionStillActive);
        }
        custody_bundle.verify_quorum(
            subject,
            trusted_custodian_keys,
            custody_quorum,
            issued_at_unix_secs,
            MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
            expires_at_unix_secs,
        )?;
        let mut plan = Self {
            schema: CONSENT_FINAL_DESTRUCTION_PLAN_SCHEMA.to_string(),
            destruction_id: *Uuid::new_v4().as_bytes(),
            ledger_epoch_id: subject.ledger_epoch_id,
            retention_base_certificate_fingerprint: subject.base_certificate_fingerprint,
            retention_obligation_fingerprint: subject.obligation_fingerprint,
            retention_anchor_fingerprint: subject.anchor_fingerprint,
            custody_bundle_fingerprint: consent_purge_custody_bundle_fingerprint(custody_bundle)?,
            protected_inventory_digest: subject.protected_inventory_digest,
            package_directory: subject.package_directory.clone(),
            candidates: certificate.protected_artifacts.clone(),
            retention_satisfied_at_unix_secs: subject.retain_until_unix_secs,
            issued_at_unix_secs,
            expires_at_unix_secs,
            signature: [0u8; 64],
        };
        plan.validate_shape()?;
        plan.signature = signing_key
            .sign(&consent_final_destruction_plan_message(&plan)?)
            .to_bytes();
        plan.verify_authority_signature(&signing_key.verifying_key())?;
        Ok(plan)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(
        &self,
        certificate: &ConsentPurgeRetentionCertificateV1,
        subject: &ConsentPurgeRetentionSubjectV1,
        custody_bundle: &ConsentPurgeCustodyBundleV1,
        trusted_custodian_keys: &[[u8; 32]],
        custody_quorum: usize,
        public_key: &VerifyingKey,
        now_unix_secs: u64,
    ) -> Result<(), ConsentFinalDestructionError> {
        self.verify_authority_signature(public_key)?;
        certificate.verify_authority_signature(public_key)?;
        verify_protected_inventory_files(certificate)?;
        verify_certificate_matches_subject(certificate, subject)?;
        custody_bundle.verify_quorum(
            subject,
            trusted_custodian_keys,
            custody_quorum,
            now_unix_secs,
            MAX_PURGE_CUSTODY_FUTURE_SKEW_SECS,
            self.expires_at_unix_secs,
        )?;
        if now_unix_secs < self.issued_at_unix_secs {
            return Err(ConsentFinalDestructionError::PlanFromFuture);
        }
        if now_unix_secs > self.expires_at_unix_secs {
            return Err(ConsentFinalDestructionError::PlanExpired);
        }
        if self.ledger_epoch_id != subject.ledger_epoch_id
            || self.retention_base_certificate_fingerprint != subject.base_certificate_fingerprint
            || self.retention_obligation_fingerprint != subject.obligation_fingerprint
            || self.retention_anchor_fingerprint != subject.anchor_fingerprint
            || self.custody_bundle_fingerprint
                != consent_purge_custody_bundle_fingerprint(custody_bundle)?
            || self.protected_inventory_digest != subject.protected_inventory_digest
            || self.package_directory != subject.package_directory
            || self.candidates != certificate.protected_artifacts
            || self.retention_satisfied_at_unix_secs != subject.retain_until_unix_secs
        {
            return Err(ConsentFinalDestructionError::RetentionSubjectMismatch);
        }
        Ok(())
    }

    pub(crate) fn verify_authority_signature(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentFinalDestructionError> {
        self.validate_shape()?;
        public_key
            .verify(
                &consent_final_destruction_plan_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentFinalDestructionError::InvalidPlanSignature)
    }

    fn validate_shape(&self) -> Result<(), ConsentFinalDestructionError> {
        if self.schema != CONSENT_FINAL_DESTRUCTION_PLAN_SCHEMA {
            return Err(ConsentFinalDestructionError::UnsupportedPlanSchema {
                schema: self.schema.clone(),
            });
        }
        if self.destruction_id == [0u8; 16] {
            return Err(ConsentFinalDestructionError::ZeroDestructionId);
        }
        if self.candidates.is_empty() {
            return Err(ConsentFinalDestructionError::IncompleteCandidateInventory);
        }
        if self.candidates.len() > MAX_FINAL_DESTRUCTION_CANDIDATES {
            return Err(ConsentFinalDestructionError::TooManyCandidates {
                count: self.candidates.len(),
                maximum: MAX_FINAL_DESTRUCTION_CANDIDATES,
            });
        }
        if self.expires_at_unix_secs <= self.issued_at_unix_secs {
            return Err(ConsentFinalDestructionError::InvalidPlanWindow);
        }
        if self
            .expires_at_unix_secs
            .saturating_sub(self.issued_at_unix_secs)
            > MAX_FINAL_DESTRUCTION_PLAN_LIFETIME_SECS
        {
            return Err(ConsentFinalDestructionError::PlanWindowTooLong {
                maximum: MAX_FINAL_DESTRUCTION_PLAN_LIFETIME_SECS,
            });
        }
        if self.issued_at_unix_secs < self.retention_satisfied_at_unix_secs {
            return Err(ConsentFinalDestructionError::RetentionStillActive);
        }
        let package_directory = Path::new(&self.package_directory);
        let mut seen = BTreeSet::new();
        let mut previous: Option<(
            &str,
            crate::consent_purge_retention::ConsentPurgeProtectedArtifactRoleV1,
        )> = None;
        for candidate in &self.candidates {
            if candidate.blake3_digest == [0u8; 32] {
                return Err(ConsentFinalDestructionError::ZeroCandidateDigest {
                    path: candidate.path.clone(),
                });
            }
            if !Path::new(&candidate.path).starts_with(package_directory) {
                return Err(ConsentFinalDestructionError::CandidateOutsidePackage {
                    path: candidate.path.clone(),
                });
            }
            if !seen.insert(candidate.path.clone()) {
                return Err(ConsentFinalDestructionError::DuplicateCandidatePath {
                    path: candidate.path.clone(),
                });
            }
            let current = (candidate.path.as_str(), candidate.role);
            if previous.is_some_and(|prior| prior >= current) {
                return Err(ConsentFinalDestructionError::CandidateOrderMismatch);
            }
            previous = Some(current);
        }
        if protected_inventory_digest(&self.candidates)? != self.protected_inventory_digest {
            return Err(ConsentFinalDestructionError::CandidateInventoryDigestMismatch);
        }
        Ok(())
    }
}

impl ConsentFinalDestructionApprovalBundleV1 {
    pub(crate) fn new(
        plan: &ConsentFinalDestructionPlanV1,
    ) -> Result<Self, ConsentFinalDestructionError> {
        Ok(Self {
            schema: CONSENT_FINAL_DESTRUCTION_APPROVAL_BUNDLE_SCHEMA.to_string(),
            plan_fingerprint: consent_final_destruction_plan_fingerprint(plan)?,
            approvals: Vec::new(),
        })
    }

    pub(crate) fn sign_with(
        &mut self,
        plan: &ConsentFinalDestructionPlanV1,
        signing_key: &LedgerSigningKey,
        approved_at_unix_secs: u64,
    ) -> Result<(), ConsentFinalDestructionError> {
        self.validate_plan(plan)?;
        if approved_at_unix_secs < plan.issued_at_unix_secs
            || approved_at_unix_secs > plan.expires_at_unix_secs
        {
            return Err(ConsentFinalDestructionError::ApprovalOutsidePlanWindow);
        }
        if self.approvals.len() >= MAX_FINAL_DESTRUCTION_APPROVALS {
            return Err(ConsentFinalDestructionError::TooManyApprovals {
                count: self.approvals.len() + 1,
                maximum: MAX_FINAL_DESTRUCTION_APPROVALS,
            });
        }
        let public_key = signing_key.verifying_key().to_bytes();
        if self
            .approvals
            .iter()
            .any(|approval| approval.witness_public_key == public_key)
        {
            return Err(ConsentFinalDestructionError::DuplicateApprovalKey);
        }
        let signature = signing_key
            .sign(&consent_final_destruction_approval_message(
                self.plan_fingerprint,
                approved_at_unix_secs,
            ))
            .to_bytes();
        self.approvals.push(ConsentFinalDestructionApprovalV1 {
            witness_public_key: public_key,
            approved_at_unix_secs,
            signature,
        });
        self.approvals
            .sort_by_key(|approval| approval.witness_public_key);
        Ok(())
    }

    pub(crate) fn verify_quorum(
        &self,
        plan: &ConsentFinalDestructionPlanV1,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<(), ConsentFinalDestructionError> {
        self.validate_plan(plan)?;
        if minimum_quorum == 0 {
            return Err(ConsentFinalDestructionError::ZeroApprovalQuorum);
        }
        if self.approvals.len() > MAX_FINAL_DESTRUCTION_APPROVALS {
            return Err(ConsentFinalDestructionError::TooManyApprovals {
                count: self.approvals.len(),
                maximum: MAX_FINAL_DESTRUCTION_APPROVALS,
            });
        }
        let trusted = trusted_witness_keys
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut seen = BTreeSet::new();
        let mut previous_key: Option<[u8; 32]> = None;
        let mut observed = 0usize;
        for approval in &self.approvals {
            if previous_key.is_some_and(|previous| previous >= approval.witness_public_key) {
                return Err(ConsentFinalDestructionError::ApprovalOrderMismatch);
            }
            previous_key = Some(approval.witness_public_key);
            if !seen.insert(approval.witness_public_key) {
                return Err(ConsentFinalDestructionError::DuplicateApprovalKey);
            }
            if !trusted.contains(&approval.witness_public_key) {
                return Err(ConsentFinalDestructionError::UntrustedApprovalKey);
            }
            if approval.approved_at_unix_secs < plan.issued_at_unix_secs
                || approval.approved_at_unix_secs > plan.expires_at_unix_secs
            {
                return Err(ConsentFinalDestructionError::ApprovalOutsidePlanWindow);
            }
            let public_key = VerifyingKey::from_bytes(&approval.witness_public_key)
                .map_err(|_| ConsentFinalDestructionError::BadApprovalPublicKey)?;
            public_key
                .verify(
                    &consent_final_destruction_approval_message(
                        self.plan_fingerprint,
                        approval.approved_at_unix_secs,
                    ),
                    &Signature::from_bytes(&approval.signature),
                )
                .map_err(|_| ConsentFinalDestructionError::InvalidApprovalSignature)?;
            observed += 1;
        }
        if observed < minimum_quorum {
            return Err(ConsentFinalDestructionError::ApprovalQuorumNotMet {
                observed,
                required: minimum_quorum,
            });
        }
        Ok(())
    }

    fn validate_plan(
        &self,
        plan: &ConsentFinalDestructionPlanV1,
    ) -> Result<(), ConsentFinalDestructionError> {
        if self.schema != CONSENT_FINAL_DESTRUCTION_APPROVAL_BUNDLE_SCHEMA {
            return Err(
                ConsentFinalDestructionError::UnsupportedApprovalBundleSchema {
                    schema: self.schema.clone(),
                },
            );
        }
        if self.plan_fingerprint != consent_final_destruction_plan_fingerprint(plan)? {
            return Err(ConsentFinalDestructionError::ApprovalPlanMismatch);
        }
        Ok(())
    }
}

impl ConsentFinalDestructionReadinessV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        plan: &ConsentFinalDestructionPlanV1,
        approvals: &ConsentFinalDestructionApprovalBundleV1,
        custody_bundle: &ConsentPurgeCustodyBundleV1,
        trusted_destruction_witness_keys: &[[u8; 32]],
        destruction_quorum: usize,
        signing_key: &LedgerSigningKey,
        ready_at_unix_secs: u64,
    ) -> Result<Self, ConsentFinalDestructionError> {
        plan.verify_authority_signature(&signing_key.verifying_key())?;
        approvals.verify_quorum(plan, trusted_destruction_witness_keys, destruction_quorum)?;
        if approvals
            .approvals
            .iter()
            .any(|approval| approval.approved_at_unix_secs > ready_at_unix_secs)
        {
            return Err(ConsentFinalDestructionError::ApprovalAfterReadiness);
        }
        if ready_at_unix_secs < plan.issued_at_unix_secs {
            return Err(ConsentFinalDestructionError::PlanFromFuture);
        }
        if ready_at_unix_secs > plan.expires_at_unix_secs {
            return Err(ConsentFinalDestructionError::PlanExpired);
        }
        if consent_purge_custody_bundle_fingerprint(custody_bundle)?
            != plan.custody_bundle_fingerprint
        {
            return Err(ConsentFinalDestructionError::ReadinessIdentityMismatch);
        }
        let candidate_count = u32::try_from(plan.candidates.len())
            .map_err(|_| ConsentFinalDestructionError::EncodingLengthOverflow)?;
        let mut readiness = Self {
            schema: CONSENT_FINAL_DESTRUCTION_READINESS_SCHEMA.to_string(),
            ledger_epoch_id: plan.ledger_epoch_id,
            destruction_id: plan.destruction_id,
            plan_fingerprint: consent_final_destruction_plan_fingerprint(plan)?,
            approval_bundle_fingerprint: consent_final_destruction_approval_bundle_fingerprint(
                approvals,
            )?,
            custody_bundle_fingerprint: plan.custody_bundle_fingerprint,
            protected_inventory_digest: plan.protected_inventory_digest,
            package_directory: plan.package_directory.clone(),
            candidate_count,
            ready_at_unix_secs,
            expires_at_unix_secs: plan.expires_at_unix_secs,
            signature: [0u8; 64],
        };
        readiness.signature = signing_key
            .sign(&consent_final_destruction_readiness_message(&readiness)?)
            .to_bytes();
        readiness.verify(
            plan,
            approvals,
            custody_bundle,
            trusted_destruction_witness_keys,
            destruction_quorum,
            &signing_key.verifying_key(),
        )?;
        Ok(readiness)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(
        &self,
        plan: &ConsentFinalDestructionPlanV1,
        approvals: &ConsentFinalDestructionApprovalBundleV1,
        custody_bundle: &ConsentPurgeCustodyBundleV1,
        trusted_destruction_witness_keys: &[[u8; 32]],
        destruction_quorum: usize,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentFinalDestructionError> {
        if self.schema != CONSENT_FINAL_DESTRUCTION_READINESS_SCHEMA {
            return Err(ConsentFinalDestructionError::UnsupportedReadinessSchema {
                schema: self.schema.clone(),
            });
        }
        plan.verify_authority_signature(public_key)?;
        approvals.verify_quorum(plan, trusted_destruction_witness_keys, destruction_quorum)?;
        if approvals
            .approvals
            .iter()
            .any(|approval| approval.approved_at_unix_secs > self.ready_at_unix_secs)
        {
            return Err(ConsentFinalDestructionError::ApprovalAfterReadiness);
        }
        let candidate_count = u32::try_from(plan.candidates.len())
            .map_err(|_| ConsentFinalDestructionError::EncodingLengthOverflow)?;
        if self.ledger_epoch_id != plan.ledger_epoch_id
            || self.destruction_id != plan.destruction_id
            || self.plan_fingerprint != consent_final_destruction_plan_fingerprint(plan)?
            || self.approval_bundle_fingerprint
                != consent_final_destruction_approval_bundle_fingerprint(approvals)?
            || self.custody_bundle_fingerprint
                != consent_purge_custody_bundle_fingerprint(custody_bundle)?
            || self.protected_inventory_digest != plan.protected_inventory_digest
            || self.package_directory != plan.package_directory
            || self.candidate_count != candidate_count
            || self.ready_at_unix_secs < plan.issued_at_unix_secs
            || self.ready_at_unix_secs > plan.expires_at_unix_secs
            || self.expires_at_unix_secs != plan.expires_at_unix_secs
        {
            return Err(ConsentFinalDestructionError::ReadinessIdentityMismatch);
        }
        public_key
            .verify(
                &consent_final_destruction_readiness_message(self)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ConsentFinalDestructionError::InvalidReadinessSignature)
    }
}

pub(crate) fn consent_final_destruction_plan_fingerprint(
    plan: &ConsentFinalDestructionPlanV1,
) -> Result<[u8; 32], ConsentFinalDestructionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-final-destruction-plan-fingerprint:v1");
    hasher.update(&consent_final_destruction_plan_message(plan)?);
    hasher.update(&plan.signature);
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn consent_final_destruction_approval_bundle_fingerprint(
    approvals: &ConsentFinalDestructionApprovalBundleV1,
) -> Result<[u8; 32], ConsentFinalDestructionError> {
    if approvals.schema != CONSENT_FINAL_DESTRUCTION_APPROVAL_BUNDLE_SCHEMA {
        return Err(
            ConsentFinalDestructionError::UnsupportedApprovalBundleSchema {
                schema: approvals.schema.clone(),
            },
        );
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-final-destruction-approval-bundle-fingerprint:v1");
    hasher.update(&approvals.plan_fingerprint);
    let count = u32::try_from(approvals.approvals.len())
        .map_err(|_| ConsentFinalDestructionError::EncodingLengthOverflow)?;
    hasher.update(&count.to_be_bytes());
    for approval in &approvals.approvals {
        hasher.update(&approval.witness_public_key);
        hasher.update(&approval.approved_at_unix_secs.to_be_bytes());
        hasher.update(&approval.signature);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn consent_final_destruction_readiness_fingerprint(
    readiness: &ConsentFinalDestructionReadinessV1,
) -> Result<[u8; 32], ConsentFinalDestructionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-final-destruction-readiness-fingerprint:v1");
    hasher.update(&consent_final_destruction_readiness_message(readiness)?);
    hasher.update(&readiness.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn verify_certificate_matches_subject(
    certificate: &ConsentPurgeRetentionCertificateV1,
    subject: &ConsentPurgeRetentionSubjectV1,
) -> Result<(), ConsentFinalDestructionError> {
    if certificate.ledger_epoch_id != subject.ledger_epoch_id
        || consent_purge_retention_certificate_fingerprint(certificate)?
            != subject.base_certificate_fingerprint
        || certificate.package_directory != subject.package_directory
        || protected_inventory_digest(&certificate.protected_artifacts)?
            != subject.protected_inventory_digest
    {
        return Err(ConsentFinalDestructionError::RetentionSubjectMismatch);
    }
    Ok(())
}

fn consent_final_destruction_plan_message(
    plan: &ConsentFinalDestructionPlanV1,
) -> Result<Vec<u8>, ConsentFinalDestructionError> {
    if plan.schema != CONSENT_FINAL_DESTRUCTION_PLAN_SCHEMA {
        return Err(ConsentFinalDestructionError::UnsupportedPlanSchema {
            schema: plan.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-final-destruction-plan:v1");
    append_bytes(&mut message, plan.schema.as_bytes())?;
    message.extend_from_slice(&plan.destruction_id);
    message.extend_from_slice(&plan.ledger_epoch_id);
    message.extend_from_slice(&plan.retention_base_certificate_fingerprint);
    message.extend_from_slice(&plan.retention_obligation_fingerprint);
    message.extend_from_slice(&plan.retention_anchor_fingerprint);
    message.extend_from_slice(&plan.custody_bundle_fingerprint);
    message.extend_from_slice(&plan.protected_inventory_digest);
    append_bytes(&mut message, plan.package_directory.as_bytes())?;
    let count = u32::try_from(plan.candidates.len())
        .map_err(|_| ConsentFinalDestructionError::EncodingLengthOverflow)?;
    message.extend_from_slice(&count.to_be_bytes());
    for candidate in &plan.candidates {
        message.push(protected_role_tag(candidate.role));
        append_bytes(&mut message, candidate.path.as_bytes())?;
        message.extend_from_slice(&candidate.byte_length.to_be_bytes());
        message.extend_from_slice(&candidate.blake3_digest);
    }
    message.extend_from_slice(&plan.retention_satisfied_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&plan.issued_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&plan.expires_at_unix_secs.to_be_bytes());
    Ok(message)
}

fn consent_final_destruction_approval_message(
    plan_fingerprint: [u8; 32],
    approved_at_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-final-destruction-approval:v1");
    message.extend_from_slice(&plan_fingerprint);
    message.extend_from_slice(&approved_at_unix_secs.to_be_bytes());
    message
}

fn consent_final_destruction_readiness_message(
    readiness: &ConsentFinalDestructionReadinessV1,
) -> Result<Vec<u8>, ConsentFinalDestructionError> {
    if readiness.schema != CONSENT_FINAL_DESTRUCTION_READINESS_SCHEMA {
        return Err(ConsentFinalDestructionError::UnsupportedReadinessSchema {
            schema: readiness.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-final-destruction-readiness:v1");
    append_bytes(&mut message, readiness.schema.as_bytes())?;
    message.extend_from_slice(&readiness.ledger_epoch_id);
    message.extend_from_slice(&readiness.destruction_id);
    message.extend_from_slice(&readiness.plan_fingerprint);
    message.extend_from_slice(&readiness.approval_bundle_fingerprint);
    message.extend_from_slice(&readiness.custody_bundle_fingerprint);
    message.extend_from_slice(&readiness.protected_inventory_digest);
    append_bytes(&mut message, readiness.package_directory.as_bytes())?;
    message.extend_from_slice(&readiness.candidate_count.to_be_bytes());
    message.extend_from_slice(&readiness.ready_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&readiness.expires_at_unix_secs.to_be_bytes());
    Ok(message)
}

fn protected_role_tag(
    role: crate::consent_purge_retention::ConsentPurgeProtectedArtifactRoleV1,
) -> u8 {
    use crate::consent_purge_retention::ConsentPurgeProtectedArtifactRoleV1;
    match role {
        ConsentPurgeProtectedArtifactRoleV1::RollbackArtifact => 1,
        ConsentPurgeProtectedArtifactRoleV1::RollbackPackageManifest => 2,
        ConsentPurgeProtectedArtifactRoleV1::RecoveryJournal => 3,
        ConsentPurgeProtectedArtifactRoleV1::PurgeReceipt => 4,
    }
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ConsentFinalDestructionError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ConsentFinalDestructionError::EncodingLengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent_purge_custody::{
        ConsentPurgeCustodyAttestationV1, ConsentPurgeCustodyClassV1,
    };
    use crate::consent_purge_retention::{
        CONSENT_PURGE_RETENTION_CERTIFICATE_SCHEMA, ConsentPurgeProtectedArtifactRoleV1,
    };

    fn subject() -> ConsentPurgeRetentionSubjectV1 {
        ConsentPurgeRetentionSubjectV1 {
            ledger_epoch_id: [1u8; 32],
            base_certificate_fingerprint: [2u8; 32],
            anchor_fingerprint: [3u8; 32],
            obligation_fingerprint: [4u8; 32],
            protected_inventory_digest: protected_inventory_digest(&[artifact()]).unwrap(),
            package_directory: "/rollback/xenia/package".to_string(),
            retain_until_unix_secs: 20_000,
        }
    }

    fn artifact() -> ConsentPurgeProtectedArtifactV1 {
        ConsentPurgeProtectedArtifactV1 {
            role: ConsentPurgeProtectedArtifactRoleV1::RollbackArtifact,
            path: "/rollback/xenia/package/artifact.bin".to_string(),
            byte_length: 4,
            blake3_digest: [6u8; 32],
        }
    }

    fn certificate() -> ConsentPurgeRetentionCertificateV1 {
        ConsentPurgeRetentionCertificateV1 {
            schema: CONSENT_PURGE_RETENTION_CERTIFICATE_SCHEMA.to_string(),
            ledger_epoch_id: [1u8; 32],
            purge_plan_fingerprint: [7u8; 32],
            purge_approval_bundle_fingerprint: [8u8; 32],
            rollback_package_fingerprint: [9u8; 32],
            purge_receipt_fingerprint: [10u8; 32],
            package_directory: "/rollback/xenia/package".to_string(),
            protected_artifacts: vec![artifact()],
            retained_from_unix_secs: 1_000,
            retain_until_unix_secs: 20_000,
            issued_at_unix_secs: 1_001,
            signature: [0u8; 64],
        }
    }

    fn custody(
        subject: &ConsentPurgeRetentionSubjectV1,
    ) -> (LedgerSigningKey, ConsentPurgeCustodyBundleV1) {
        let key = LedgerSigningKey::from_bytes(&[21u8; 32]);
        let attestation = ConsentPurgeCustodyAttestationV1::sign(
            subject,
            ConsentPurgeCustodyClassV1::RemoteVault,
            "vault://independent/object",
            [5u8; 16],
            &key,
            19_000,
            30_000,
        )
        .unwrap();
        let mut bundle = ConsentPurgeCustodyBundleV1::new(subject);
        bundle.add(subject, attestation).unwrap();
        (key, bundle)
    }

    fn signed_plan(
        ledger_key: &LedgerSigningKey,
        subject: &ConsentPurgeRetentionSubjectV1,
        custody_bundle: &ConsentPurgeCustodyBundleV1,
    ) -> ConsentFinalDestructionPlanV1 {
        let mut plan = ConsentFinalDestructionPlanV1 {
            schema: CONSENT_FINAL_DESTRUCTION_PLAN_SCHEMA.to_string(),
            destruction_id: [12u8; 16],
            ledger_epoch_id: subject.ledger_epoch_id,
            retention_base_certificate_fingerprint: subject.base_certificate_fingerprint,
            retention_obligation_fingerprint: subject.obligation_fingerprint,
            retention_anchor_fingerprint: subject.anchor_fingerprint,
            custody_bundle_fingerprint: consent_purge_custody_bundle_fingerprint(custody_bundle)
                .unwrap(),
            protected_inventory_digest: subject.protected_inventory_digest,
            package_directory: subject.package_directory.clone(),
            candidates: vec![artifact()],
            retention_satisfied_at_unix_secs: subject.retain_until_unix_secs,
            issued_at_unix_secs: 20_001,
            expires_at_unix_secs: 20_601,
            signature: [0u8; 64],
        };
        plan.signature = ledger_key
            .sign(&consent_final_destruction_plan_message(&plan).unwrap())
            .to_bytes();
        plan
    }

    #[test]
    fn plan_binds_complete_inventory_and_elapsed_retention() {
        let subject = subject();
        let (_, custody_bundle) = custody(&subject);
        let ledger_key = LedgerSigningKey::from_bytes(&[31u8; 32]);
        let plan = signed_plan(&ledger_key, &subject, &custody_bundle);
        plan.verify_authority_signature(&ledger_key.verifying_key())
            .unwrap();
        let mut changed = plan.clone();
        changed.candidates.clear();
        assert!(matches!(
            changed.verify_authority_signature(&ledger_key.verifying_key()),
            Err(ConsentFinalDestructionError::IncompleteCandidateInventory)
        ));
    }

    #[test]
    fn destruction_approval_is_bound_to_exact_plan() {
        let subject = subject();
        let (_, custody_bundle) = custody(&subject);
        let ledger_key = LedgerSigningKey::from_bytes(&[32u8; 32]);
        let plan = signed_plan(&ledger_key, &subject, &custody_bundle);
        let witness = LedgerSigningKey::from_bytes(&[33u8; 32]);
        let mut approvals = ConsentFinalDestructionApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 20_100).unwrap();
        approvals
            .verify_quorum(&plan, &[witness.verifying_key().to_bytes()], 1)
            .unwrap();
        let mut changed = plan.clone();
        changed.expires_at_unix_secs += 1;
        assert!(matches!(
            approvals.verify_quorum(&changed, &[witness.verifying_key().to_bytes()], 1),
            Err(ConsentFinalDestructionError::ApprovalPlanMismatch)
        ));
    }

    /// Regression test for the quorum-count comparison in `verify_quorum`
    /// (distinct from `destruction_approval_is_bound_to_exact_plan`, which
    /// only ever exercises quorum == 1). One trusted approval must not
    /// satisfy a quorum of two; a second, distinct trusted approval must.
    #[test]
    fn final_destruction_approval_quorum_requires_the_configured_threshold() {
        let subject = subject();
        let (_, custody_bundle) = custody(&subject);
        let ledger_key = LedgerSigningKey::from_bytes(&[41u8; 32]);
        let plan = signed_plan(&ledger_key, &subject, &custody_bundle);
        let first = LedgerSigningKey::from_bytes(&[42u8; 32]);
        let second = LedgerSigningKey::from_bytes(&[43u8; 32]);
        let trusted = [
            first.verifying_key().to_bytes(),
            second.verifying_key().to_bytes(),
        ];
        let mut approvals = ConsentFinalDestructionApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &first, 20_100).unwrap();
        assert_eq!(
            approvals.verify_quorum(&plan, &trusted, 2),
            Err(ConsentFinalDestructionError::ApprovalQuorumNotMet {
                observed: 1,
                required: 2,
            })
        );
        approvals.sign_with(&plan, &second, 20_101).unwrap();
        approvals.verify_quorum(&plan, &trusted, 2).unwrap();
    }

    #[test]
    fn readiness_is_authorization_only_and_expires_with_plan() {
        let subject = subject();
        let (_, custody_bundle) = custody(&subject);
        let ledger_key = LedgerSigningKey::from_bytes(&[34u8; 32]);
        let plan = signed_plan(&ledger_key, &subject, &custody_bundle);
        let witness = LedgerSigningKey::from_bytes(&[35u8; 32]);
        let mut approvals = ConsentFinalDestructionApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 20_100).unwrap();
        let readiness = ConsentFinalDestructionReadinessV1::sign(
            &plan,
            &approvals,
            &custody_bundle,
            &[witness.verifying_key().to_bytes()],
            1,
            &ledger_key,
            20_200,
        )
        .unwrap();
        readiness
            .verify(
                &plan,
                &approvals,
                &custody_bundle,
                &[witness.verifying_key().to_bytes()],
                1,
                &ledger_key.verifying_key(),
            )
            .unwrap();
        assert!(consent_final_destruction_readiness_fingerprint(&readiness).is_ok());
    }

    #[test]
    fn readiness_rejects_approval_after_readiness_time() {
        let subject = subject();
        let (_, custody_bundle) = custody(&subject);
        let ledger_key = LedgerSigningKey::from_bytes(&[39u8; 32]);
        let plan = signed_plan(&ledger_key, &subject, &custody_bundle);
        let witness = LedgerSigningKey::from_bytes(&[40u8; 32]);
        let mut approvals = ConsentFinalDestructionApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 20_300).unwrap();
        assert!(matches!(
            ConsentFinalDestructionReadinessV1::sign(
                &plan,
                &approvals,
                &custody_bundle,
                &[witness.verifying_key().to_bytes()],
                1,
                &ledger_key,
                20_200,
            ),
            Err(ConsentFinalDestructionError::ApprovalAfterReadiness)
        ));
    }

    #[test]
    fn approval_bundle_rejects_noncanonical_order() {
        let subject = subject();
        let (_, custody_bundle) = custody(&subject);
        let ledger_key = LedgerSigningKey::from_bytes(&[36u8; 32]);
        let plan = signed_plan(&ledger_key, &subject, &custody_bundle);
        let first = LedgerSigningKey::from_bytes(&[37u8; 32]);
        let second = LedgerSigningKey::from_bytes(&[38u8; 32]);
        let mut approvals = ConsentFinalDestructionApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &first, 20_100).unwrap();
        approvals.sign_with(&plan, &second, 20_101).unwrap();
        approvals.approvals.reverse();
        assert!(matches!(
            approvals.verify_quorum(
                &plan,
                &[
                    first.verifying_key().to_bytes(),
                    second.verifying_key().to_bytes(),
                ],
                2,
            ),
            Err(ConsentFinalDestructionError::ApprovalOrderMismatch)
        ));
    }

    #[test]
    fn certificate_subject_helper_rejects_inventory_substitution() {
        let mut certificate = certificate();
        let mut subject = subject();
        subject.base_certificate_fingerprint =
            consent_purge_retention_certificate_fingerprint(&certificate).unwrap();
        verify_certificate_matches_subject(&certificate, &subject).unwrap();
        let mut changed_subject = subject.clone();
        changed_subject.base_certificate_fingerprint = [99u8; 32];
        assert!(matches!(
            verify_certificate_matches_subject(&certificate, &changed_subject),
            Err(ConsentFinalDestructionError::RetentionSubjectMismatch)
        ));
        certificate.protected_artifacts[0].byte_length += 1;
        assert!(matches!(
            verify_certificate_matches_subject(&certificate, &subject),
            Err(ConsentFinalDestructionError::RetentionSubjectMismatch)
        ));
    }
}
