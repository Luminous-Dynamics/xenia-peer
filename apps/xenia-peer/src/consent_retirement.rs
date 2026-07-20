// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit, signed retirement plans for superseded consent-ledger artifacts.
//!
//! A GC-readiness certificate proves that compacted state and cold archives are
//! sufficient for recovery. It does not identify which local files an operator
//! intends to retire. This module adds that missing authorization boundary: an
//! exact, short-lived plan signed by the ledger authority. The plan commits to
//! every candidate's role, canonical absolute path, byte length, and BLAKE3
//! digest, plus the independently retained state pin and GC certificate that
//! justified the operation.
//!
//! Execution never unlinks artifacts. It moves exact verified bytes into a
//! dedicated same-filesystem quarantine transaction, persists a crash journal
//! before and after each rename, and emits a ledger-signed completion receipt.
//! An uncommitted transaction can be rolled back only with the original signed
//! plan and independent approval quorum.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{
    Signature, Signer, SigningKey as LedgerSigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use xenia_ledger::LedgerArchiveSegment;

use crate::audit_ledger_store::{
    AuditLedgerStoreError, persist_owner_only_atomic, read_bounded_json,
};
use crate::consent_compaction::{
    consent_compacted_state_pin_fingerprint, consent_compaction_gc_certificate_fingerprint,
    ConsentCompactedActiveStateV1, ConsentCompactedStatePinV1,
    ConsentCompactionGcCertificateV1, ConsentRecoveryError,
};

pub(crate) const CONSENT_RETIREMENT_PLAN_SCHEMA: &str =
    "xenia-consent-retirement-plan-v1";
pub(crate) const MAX_RETIREMENT_CANDIDATES: usize = 32;
pub(crate) const MAX_RETIREMENT_PLAN_LIFETIME_SECS: u64 = 24 * 60 * 60;
pub(crate) const MAX_RETIREMENT_PATH_BYTES: usize = 4096;
pub(crate) const CONSENT_RETIREMENT_APPROVAL_BUNDLE_SCHEMA: &str =
    "xenia-consent-retirement-approval-bundle-v1";
pub(crate) const MAX_RETIREMENT_APPROVALS: usize = 64;
pub(crate) const CONSENT_RETIREMENT_JOURNAL_SCHEMA: &str =
    "xenia-consent-retirement-journal-v1";
pub(crate) const CONSENT_RETIREMENT_RECEIPT_SCHEMA: &str =
    "xenia-consent-retirement-quarantine-receipt-v1";
pub(crate) const MAX_RETIREMENT_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_RETIREMENT_TRANSACTION_BYTES: u64 = 1024 * 1024;

/// Artifact classes that may be moved out of active use after compacted-state
/// activation. Cold archives, active state, retained pins, signing keys, and
/// certificates are intentionally absent and therefore cannot appear in a
/// valid plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentRetirementArtifactRoleV1 {
    SupersededCompleteLedger,
    SupersededCompactionBundle,
    SupersededCompactedSnapshot,
}

impl ConsentRetirementArtifactRoleV1 {
    fn tag(self) -> u8 {
        match self {
            Self::SupersededCompleteLedger => 1,
            Self::SupersededCompactionBundle => 2,
            Self::SupersededCompactedSnapshot => 3,
        }
    }
}

/// Exact immutable observation of one retirement candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRetirementArtifactV1 {
    pub(crate) role: ConsentRetirementArtifactRoleV1,
    pub(crate) canonical_path: String,
    pub(crate) byte_length: u64,
    pub(crate) blake3_digest: [u8; 32],
}

/// One independently controlled retention key's approval of an exact plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRetirementApprovalV1 {
    pub(crate) witness_public_key: [u8; 32],
    pub(crate) approved_at_unix_secs: u64,
    pub(crate) signature: [u8; 64],
}

/// Independent approvals over one ledger-authority retirement plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRetirementApprovalBundleV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approvals: Vec<ConsentRetirementApprovalV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentRetirementJournalStateV1 {
    Prepared,
    Moving,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentRetirementJournalEntryStateV1 {
    Pending,
    Moved,
    Restored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentRetirementRecoveryOutcomeV1 {
    FinalizedCommitted,
    RolledBack,
    AlreadyCommitted,
    AlreadyRolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRetirementJournalEntryV1 {
    pub(crate) artifact: ConsentRetirementArtifactV1,
    pub(crate) quarantine_path: String,
    pub(crate) state: ConsentRetirementJournalEntryStateV1,
}

/// Crash-recovery journal persisted before the first filesystem mutation and
/// after every successful rename. The journal is local operational state; the
/// final receipt below is the signed audit artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRetirementJournalV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approval_bundle_fingerprint: [u8; 32],
    pub(crate) transaction_directory: String,
    pub(crate) state: ConsentRetirementJournalStateV1,
    pub(crate) started_at_unix_secs: u64,
    pub(crate) updated_at_unix_secs: u64,
    pub(crate) entries: Vec<ConsentRetirementJournalEntryV1>,
}

/// Ledger-signed proof that exact candidate bytes were moved into a dedicated
/// quarantine transaction directory. Quarantine is reversible and does not
/// unlink any artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRetirementQuarantineReceiptV1 {
    pub(crate) schema: String,
    pub(crate) plan_fingerprint: [u8; 32],
    pub(crate) approval_bundle_fingerprint: [u8; 32],
    pub(crate) transaction_directory: String,
    pub(crate) started_at_unix_secs: u64,
    pub(crate) completed_at_unix_secs: u64,
    pub(crate) entries: Vec<ConsentRetirementJournalEntryV1>,
    pub(crate) signature: [u8; 64],
}

/// Ledger-authority authorization for one exact, bounded retirement attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRetirementPlanV1 {
    pub(crate) schema: String,
    pub(crate) plan_id: [u8; 16],
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) active_state_digest: [u8; 32],
    pub(crate) state_pin_fingerprint: [u8; 32],
    pub(crate) gc_certificate_fingerprint: [u8; 32],
    pub(crate) quarantine_root: String,
    pub(crate) candidates: Vec<ConsentRetirementArtifactV1>,
    pub(crate) issued_at_unix_secs: u64,
    pub(crate) expires_at_unix_secs: u64,
    pub(crate) signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConsentRetirementError {
    #[error("consent retirement plan has unsupported schema: {schema}")]
    UnsupportedPlanSchema { schema: String },
    #[error("consent retirement plan must contain between 1 and {maximum} candidates")]
    InvalidCandidateCount { maximum: usize },
    #[error("consent retirement path is not canonical absolute UTF-8: {path}")]
    NonCanonicalPath { path: String },
    #[error("consent retirement path exceeds {maximum} UTF-8 bytes: {path}")]
    PathTooLong { path: String, maximum: usize },
    #[error("consent retirement candidate path appears more than once: {path}")]
    DuplicateCandidatePath { path: String },
    #[error("consent retirement candidate digest cannot be all zeroes: {path}")]
    ZeroCandidateDigest { path: String },
    #[error("consent retirement candidates are not in canonical order")]
    CandidateOrderMismatch,
    #[error("consent retirement plan expiry must be after issuance")]
    InvalidPlanWindow,
    #[error("consent retirement plan lifetime exceeds {maximum} seconds")]
    PlanWindowTooLong { maximum: u64 },
    #[error("consent retirement plan was issued before the GC certificate")]
    PlanPredatesCertificate,
    #[error("consent retirement plan does not match the verified compacted state")]
    ActiveStateMismatch,
    #[error("consent retirement plan does not match the retained state pin")]
    StatePinMismatch,
    #[error("consent retirement plan does not match the GC-readiness certificate")]
    GcCertificateMismatch,
    #[error("consent retirement plan signature is invalid")]
    InvalidPlanSignature,
    #[error("consent retirement plan is not yet valid")]
    PlanFromFuture,
    #[error("consent retirement plan expired")]
    PlanExpired,
    #[error("consent retirement plan encoding length overflow")]
    EncodingLengthOverflow,
    #[error("consent retirement artifact exceeds {maximum} bytes: {path}")]
    ArtifactTooLarge { path: String, maximum: u64 },
    #[error("consent retirement artifact is not a regular non-symlink file: {path}")]
    ArtifactNotRegular { path: String },
    #[error("consent retirement artifact no longer matches its signed observation: {path}")]
    ArtifactChanged { path: String },
    #[error("consent retirement quarantine root is invalid: {path}")]
    InvalidQuarantineRoot { path: String },
    #[error("consent retirement quarantine root permissions are too broad: path={path}, mode={mode:o}")]
    InsecureQuarantineRootPermissions { path: String, mode: u32 },
    #[error("consent retirement transaction already exists: {path}")]
    TransactionAlreadyExists { path: String },
    #[error("consent retirement transaction target already exists: {path}")]
    QuarantineTargetExists { path: String },
    #[error("consent retirement journal has unsupported schema: {schema}")]
    UnsupportedJournalSchema { schema: String },
    #[error("consent retirement journal does not match the authorized plan or approvals")]
    JournalIdentityMismatch,
    #[error("consent retirement journal state does not permit this operation")]
    InvalidJournalState,
    #[error("consent retirement transaction already has a signed completion receipt")]
    ReceiptAlreadyExists,
    #[error("consent retirement rollback found both original and quarantined copies: original={original}, quarantine={quarantine}")]
    RollbackArtifactPresentInBoth { original: String, quarantine: String },
    #[error("consent retirement rollback found neither original nor quarantined copy: original={original}, quarantine={quarantine}")]
    RollbackArtifactMissing { original: String, quarantine: String },
    #[error("consent retirement rollback failed after an execution error: {0}")]
    RollbackFailed(String),
    #[error("consent retirement receipt has unsupported schema: {schema}")]
    UnsupportedReceiptSchema { schema: String },
    #[error("consent retirement receipt does not match the authorized plan or approvals")]
    ReceiptIdentityMismatch,
    #[error("consent retirement receipt signature is invalid")]
    InvalidReceiptSignature,
    #[error("consent retirement committed artifact is missing or changed in quarantine: {path}")]
    QuarantinedArtifactMismatch { path: String },
    #[error("consent retirement original path reappeared after quarantine: {path}")]
    QuarantinedOriginalReappeared { path: String },
    #[error("consent retirement journal is committed but its signed receipt is missing")]
    MissingCommittedReceipt,
    #[error("consent retirement filesystem error: {0}")]
    Io(String),
    #[error("consent retirement persistence error: {0}")]
    Store(String),
    #[error("consent retirement JSON error: {0}")]
    Json(String),
    #[error("unsupported consent retirement approval bundle schema: {schema}")]
    UnsupportedApprovalBundleSchema { schema: String },
    #[error("consent retirement approval bundle targets a different plan")]
    ApprovalPlanMismatch,
    #[error("consent retirement approval timestamp falls outside the plan window")]
    ApprovalOutsidePlanWindow,
    #[error("consent retirement approval public key is malformed")]
    BadApprovalPublicKey,
    #[error("consent retirement approval signature is invalid")]
    BadApprovalSignature,
    #[error("consent retirement approval key appears more than once")]
    DuplicateApprovalKey,
    #[error("consent retirement approval key is not trusted")]
    UntrustedApprovalKey,
    #[error("consent retirement approval bundle has {count} signatures; maximum is {maximum}")]
    TooManyApprovals { count: usize, maximum: usize },
    #[error("consent retirement approval quorum must be greater than zero")]
    ZeroApprovalQuorum,
    #[error("consent retirement approval quorum not met: verified={verified}, required={required}")]
    ApprovalQuorumNotMet { verified: usize, required: usize },
    #[error("consent retirement prerequisite verification failed: {0}")]
    Recovery(#[from] ConsentRecoveryError),
}

impl From<std::io::Error> for ConsentRetirementError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<AuditLedgerStoreError> for ConsentRetirementError {
    fn from(error: AuditLedgerStoreError) -> Self {
        Self::Store(error.to_string())
    }
}

impl From<serde_json::Error> for ConsentRetirementError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl ConsentRetirementPlanV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        active_state: &ConsentCompactedActiveStateV1,
        state_pin: &ConsentCompactedStatePinV1,
        gc_certificate: &ConsentCompactionGcCertificateV1,
        archive_segments: &[LedgerArchiveSegment],
        quarantine_root: String,
        mut candidates: Vec<ConsentRetirementArtifactV1>,
        signing_key: &LedgerSigningKey,
        issued_at_unix_secs: u64,
        expires_at_unix_secs: u64,
    ) -> Result<Self, ConsentRetirementError> {
        let public_key = signing_key.verifying_key();
        gc_certificate.verify(
            active_state,
            state_pin,
            archive_segments,
            &public_key,
        )?;
        candidates.sort_by(|left, right| {
            left.canonical_path
                .cmp(&right.canonical_path)
                .then(left.role.cmp(&right.role))
        });
        let mut plan = Self {
            schema: CONSENT_RETIREMENT_PLAN_SCHEMA.to_string(),
            plan_id: *Uuid::new_v4().as_bytes(),
            ledger_epoch_id: active_state.cutover_receipt.ledger_epoch_id,
            active_state_digest: active_state.state_digest,
            state_pin_fingerprint: consent_compacted_state_pin_fingerprint(state_pin)?,
            gc_certificate_fingerprint: consent_compaction_gc_certificate_fingerprint(
                gc_certificate,
            )?,
            quarantine_root,
            candidates,
            issued_at_unix_secs,
            expires_at_unix_secs,
            signature: [0u8; 64],
        };
        plan.validate_shape()?;
        if plan.issued_at_unix_secs < gc_certificate.issued_at_unix_secs {
            return Err(ConsentRetirementError::PlanPredatesCertificate);
        }
        let message = consent_retirement_plan_message(&plan)?;
        plan.signature = signing_key.sign(&message).to_bytes();
        plan.verify(
            active_state,
            state_pin,
            gc_certificate,
            archive_segments,
            &public_key,
            issued_at_unix_secs,
        )?;
        Ok(plan)
    }

    pub(crate) fn verify_authority_signature(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRetirementError> {
        if self.schema != CONSENT_RETIREMENT_PLAN_SCHEMA {
            return Err(ConsentRetirementError::UnsupportedPlanSchema {
                schema: self.schema.clone(),
            });
        }
        self.validate_shape()?;
        let message = consent_retirement_plan_message(self)?;
        public_key
            .verify(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| ConsentRetirementError::InvalidPlanSignature)
    }

    pub(crate) fn verify_authority_signature_and_window(
        &self,
        public_key: &VerifyingKey,
        now_unix_secs: u64,
    ) -> Result<(), ConsentRetirementError> {
        self.verify_authority_signature(public_key)?;
        if now_unix_secs < self.issued_at_unix_secs {
            return Err(ConsentRetirementError::PlanFromFuture);
        }
        if now_unix_secs >= self.expires_at_unix_secs {
            return Err(ConsentRetirementError::PlanExpired);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(
        &self,
        active_state: &ConsentCompactedActiveStateV1,
        state_pin: &ConsentCompactedStatePinV1,
        gc_certificate: &ConsentCompactionGcCertificateV1,
        archive_segments: &[LedgerArchiveSegment],
        public_key: &VerifyingKey,
        now_unix_secs: u64,
    ) -> Result<(), ConsentRetirementError> {
        self.verify_authority_signature_and_window(public_key, now_unix_secs)?;
        gc_certificate.verify(active_state, state_pin, archive_segments, public_key)?;
        if self.ledger_epoch_id != active_state.cutover_receipt.ledger_epoch_id
            || self.active_state_digest != active_state.state_digest
        {
            return Err(ConsentRetirementError::ActiveStateMismatch);
        }
        if self.state_pin_fingerprint != consent_compacted_state_pin_fingerprint(state_pin)? {
            return Err(ConsentRetirementError::StatePinMismatch);
        }
        if self.gc_certificate_fingerprint
            != consent_compaction_gc_certificate_fingerprint(gc_certificate)?
        {
            return Err(ConsentRetirementError::GcCertificateMismatch);
        }
        if self.issued_at_unix_secs < gc_certificate.issued_at_unix_secs {
            return Err(ConsentRetirementError::PlanPredatesCertificate);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ConsentRetirementError> {
        if self.candidates.is_empty() || self.candidates.len() > MAX_RETIREMENT_CANDIDATES {
            return Err(ConsentRetirementError::InvalidCandidateCount {
                maximum: MAX_RETIREMENT_CANDIDATES,
            });
        }
        if self.expires_at_unix_secs <= self.issued_at_unix_secs {
            return Err(ConsentRetirementError::InvalidPlanWindow);
        }
        if self
            .expires_at_unix_secs
            .saturating_sub(self.issued_at_unix_secs)
            > MAX_RETIREMENT_PLAN_LIFETIME_SECS
        {
            return Err(ConsentRetirementError::PlanWindowTooLong {
                maximum: MAX_RETIREMENT_PLAN_LIFETIME_SECS,
            });
        }
        validate_absolute_normal_path(&self.quarantine_root)?;
        let mut paths = BTreeSet::new();
        let mut previous: Option<(&str, ConsentRetirementArtifactRoleV1)> = None;
        for candidate in &self.candidates {
            validate_absolute_normal_path(&candidate.canonical_path)?;
            if candidate.blake3_digest == [0u8; 32] {
                return Err(ConsentRetirementError::ZeroCandidateDigest {
                    path: candidate.canonical_path.clone(),
                });
            }
            if !paths.insert(candidate.canonical_path.as_str()) {
                return Err(ConsentRetirementError::DuplicateCandidatePath {
                    path: candidate.canonical_path.clone(),
                });
            }
            if let Some((previous_path, previous_role)) = previous {
                if (previous_path, previous_role)
                    > (candidate.canonical_path.as_str(), candidate.role)
                {
                    return Err(ConsentRetirementError::CandidateOrderMismatch);
                }
            }
            previous = Some((candidate.canonical_path.as_str(), candidate.role));
        }
        Ok(())
    }
}

pub(crate) fn observe_retirement_artifact(
    role: ConsentRetirementArtifactRoleV1,
    path: &Path,
) -> Result<ConsentRetirementArtifactV1, ConsentRetirementError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConsentRetirementError::ArtifactNotRegular {
            path: path.display().to_string(),
        });
    }
    if metadata.len() > MAX_RETIREMENT_ARTIFACT_BYTES {
        return Err(ConsentRetirementError::ArtifactTooLarge {
            path: path.display().to_string(),
            maximum: MAX_RETIREMENT_ARTIFACT_BYTES,
        });
    }
    let canonical = fs::canonicalize(path)?;
    let canonical_path = canonical
        .to_str()
        .ok_or_else(|| ConsentRetirementError::NonCanonicalPath {
            path: canonical.display().to_string(),
        })?
        .to_string();
    validate_absolute_normal_path(&canonical_path)?;
    let mut file = File::open(&canonical)?;
    let mut hasher = blake3::Hasher::new();
    let mut observed = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or_else(|| ConsentRetirementError::ArtifactTooLarge {
                path: canonical_path.clone(),
                maximum: MAX_RETIREMENT_ARTIFACT_BYTES,
            })?;
        if observed > MAX_RETIREMENT_ARTIFACT_BYTES {
            return Err(ConsentRetirementError::ArtifactTooLarge {
                path: canonical_path,
                maximum: MAX_RETIREMENT_ARTIFACT_BYTES,
            });
        }
        hasher.update(&buffer[..read]);
    }
    if observed != metadata.len() {
        return Err(ConsentRetirementError::ArtifactChanged {
            path: canonical_path,
        });
    }
    Ok(ConsentRetirementArtifactV1 {
        role,
        canonical_path,
        byte_length: observed,
        blake3_digest: *hasher.finalize().as_bytes(),
    })
}

pub(crate) fn canonical_quarantine_root(
    path: &Path,
) -> Result<String, ConsentRetirementError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ConsentRetirementError::InvalidQuarantineRoot {
            path: path.display().to_string(),
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ConsentRetirementError::InvalidQuarantineRoot {
            path: path.display().to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConsentRetirementError::InsecureQuarantineRootPermissions {
                path: path.display().to_string(),
                mode,
            });
        }
    }
    let canonical = fs::canonicalize(path)?;
    let canonical_string = canonical
        .to_str()
        .ok_or_else(|| ConsentRetirementError::NonCanonicalPath {
            path: canonical.display().to_string(),
        })?
        .to_string();
    validate_absolute_normal_path(&canonical_string)?;
    Ok(canonical_string)
}

pub(crate) fn quarantine_transaction_directory(plan: &ConsentRetirementPlanV1) -> PathBuf {
    Path::new(&plan.quarantine_root).join(hex::encode(plan.plan_id))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_retirement_quarantine(
    plan: &ConsentRetirementPlanV1,
    approvals: &ConsentRetirementApprovalBundleV1,
    active_state: &ConsentCompactedActiveStateV1,
    state_pin: &ConsentCompactedStatePinV1,
    gc_certificate: &ConsentCompactionGcCertificateV1,
    archive_segments: &[LedgerArchiveSegment],
    trusted_witness_keys: &[[u8; 32]],
    minimum_quorum: usize,
    signing_key: &LedgerSigningKey,
    now_unix_secs: u64,
) -> Result<ConsentRetirementQuarantineReceiptV1, ConsentRetirementError> {
    plan.verify(
        active_state,
        state_pin,
        gc_certificate,
        archive_segments,
        &signing_key.verifying_key(),
        now_unix_secs,
    )?;
    approvals.verify_quorum(plan, trusted_witness_keys, minimum_quorum)?;
    let quarantine_root = Path::new(&plan.quarantine_root);
    if canonical_quarantine_root(quarantine_root)? != plan.quarantine_root {
        return Err(ConsentRetirementError::InvalidQuarantineRoot {
            path: plan.quarantine_root.clone(),
        });
    }

    let transaction_directory = quarantine_transaction_directory(plan);
    match create_owner_only_directory(&transaction_directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ConsentRetirementError::TransactionAlreadyExists {
                path: transaction_directory.display().to_string(),
            });
        }
        Err(error) => return Err(error.into()),
    }
    sync_directory(quarantine_root)?;

    let transaction_directory_string = transaction_directory
        .to_str()
        .ok_or_else(|| ConsentRetirementError::NonCanonicalPath {
            path: transaction_directory.display().to_string(),
        })?
        .to_string();
    let entries = retirement_journal_entries_for_plan(plan)?;
    let mut journal = ConsentRetirementJournalV1 {
        schema: CONSENT_RETIREMENT_JOURNAL_SCHEMA.to_string(),
        plan_fingerprint: consent_retirement_plan_fingerprint(plan)?,
        approval_bundle_fingerprint: consent_retirement_approval_bundle_fingerprint(approvals)?,
        transaction_directory: transaction_directory_string,
        state: ConsentRetirementJournalStateV1::Prepared,
        started_at_unix_secs: now_unix_secs,
        updated_at_unix_secs: now_unix_secs,
        entries,
    };
    let journal_path = transaction_directory.join("journal.json");
    persist_retirement_json(&journal_path, &journal)?;
    journal.state = ConsentRetirementJournalStateV1::Moving;
    persist_retirement_json(&journal_path, &journal)?;

    let mut renamed_any_candidate = false;
    let execution = (|| -> Result<(), ConsentRetirementError> {
        for index in 0..journal.entries.len() {
            let artifact = journal.entries[index].artifact.clone();
            let quarantine_path = journal.entries[index].quarantine_path.clone();
            let observed = observe_retirement_artifact(
                artifact.role,
                Path::new(&artifact.canonical_path),
            )?;
            if observed != artifact {
                return Err(ConsentRetirementError::ArtifactChanged {
                    path: artifact.canonical_path,
                });
            }
            let target = Path::new(&quarantine_path);
            if target.exists() {
                return Err(ConsentRetirementError::QuarantineTargetExists {
                    path: quarantine_path,
                });
            }
            fs::rename(&artifact.canonical_path, target)?;
            renamed_any_candidate = true;
            sync_directory(
                Path::new(&artifact.canonical_path)
                    .parent()
                    .ok_or_else(|| ConsentRetirementError::NonCanonicalPath {
                        path: artifact.canonical_path.clone(),
                    })?,
            )?;
            sync_directory(&transaction_directory)?;
            journal.entries[index].state = ConsentRetirementJournalEntryStateV1::Moved;
            journal.updated_at_unix_secs = now_unix_secs;
            persist_retirement_json(&journal_path, &journal)?;
        }
        Ok(())
    })();

    if let Err(error) = execution {
        if !renamed_any_candidate {
            journal.state = ConsentRetirementJournalStateV1::RolledBack;
            journal.updated_at_unix_secs = now_unix_secs;
            if let Err(persistence_error) = persist_retirement_json(&journal_path, &journal) {
                return Err(ConsentRetirementError::RollbackFailed(format!(
                    "execution error: {error}; rollback journal error: {persistence_error}"
                )));
            }
            return Err(error);
        }
        if let Err(rollback_error) = rollback_retirement_journal(
            &journal_path,
            plan,
            approvals,
            trusted_witness_keys,
            minimum_quorum,
            &signing_key.verifying_key(),
            now_unix_secs,
        ) {
            return Err(ConsentRetirementError::RollbackFailed(format!(
                "execution error: {error}; rollback error: {rollback_error}"
            )));
        }
        return Err(error);
    }

    let mut receipt = ConsentRetirementQuarantineReceiptV1 {
        schema: CONSENT_RETIREMENT_RECEIPT_SCHEMA.to_string(),
        plan_fingerprint: journal.plan_fingerprint,
        approval_bundle_fingerprint: journal.approval_bundle_fingerprint,
        transaction_directory: journal.transaction_directory.clone(),
        started_at_unix_secs: journal.started_at_unix_secs,
        completed_at_unix_secs: now_unix_secs,
        entries: journal.entries.clone(),
        signature: [0u8; 64],
    };
    let message = consent_retirement_receipt_message(&receipt)?;
    receipt.signature = signing_key.sign(&message).to_bytes();
    receipt.verify(plan, approvals, &signing_key.verifying_key())?;
    persist_retirement_json(&transaction_directory.join("receipt.json"), &receipt)?;
    verify_quarantined_receipt_files(&receipt)?;
    journal.state = ConsentRetirementJournalStateV1::Committed;
    journal.updated_at_unix_secs = now_unix_secs;
    persist_retirement_json(&journal_path, &journal)?;
    sync_directory(&transaction_directory)?;
    Ok(receipt)
}

fn retirement_journal_entries_for_plan(
    plan: &ConsentRetirementPlanV1,
) -> Result<Vec<ConsentRetirementJournalEntryV1>, ConsentRetirementError> {
    let transaction_directory = quarantine_transaction_directory(plan);
    let mut entries = Vec::with_capacity(plan.candidates.len());
    for (index, artifact) in plan.candidates.iter().enumerate() {
        let file_name = Path::new(&artifact.canonical_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact");
        let quarantine_path = transaction_directory.join(format!(
            "{index:02}-{}-{file_name}",
            hex::encode(&artifact.blake3_digest[..8])
        ));
        entries.push(ConsentRetirementJournalEntryV1 {
            artifact: artifact.clone(),
            quarantine_path: quarantine_path
                .to_str()
                .ok_or_else(|| ConsentRetirementError::NonCanonicalPath {
                    path: quarantine_path.display().to_string(),
                })?
                .to_string(),
            state: ConsentRetirementJournalEntryStateV1::Pending,
        });
    }
    Ok(entries)
}

fn verify_retirement_journal_identity(
    journal: &ConsentRetirementJournalV1,
    plan: &ConsentRetirementPlanV1,
    approvals: &ConsentRetirementApprovalBundleV1,
    journal_path: &Path,
) -> Result<(), ConsentRetirementError> {
    if journal.schema != CONSENT_RETIREMENT_JOURNAL_SCHEMA {
        return Err(ConsentRetirementError::UnsupportedJournalSchema {
            schema: journal.schema.clone(),
        });
    }
    let transaction_directory = quarantine_transaction_directory(plan);
    if journal_path != transaction_directory.join("journal.json")
        || journal.plan_fingerprint != consent_retirement_plan_fingerprint(plan)?
        || journal.approval_bundle_fingerprint
            != consent_retirement_approval_bundle_fingerprint(approvals)?
        || journal.transaction_directory != transaction_directory.to_string_lossy().as_ref()
        || journal.entries.len() != plan.candidates.len()
    {
        return Err(ConsentRetirementError::JournalIdentityMismatch);
    }
    let expected = retirement_journal_entries_for_plan(plan)?;
    for (observed, expected) in journal.entries.iter().zip(expected) {
        if observed.artifact != expected.artifact
            || observed.quarantine_path != expected.quarantine_path
        {
            return Err(ConsentRetirementError::JournalIdentityMismatch);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rollback_retirement_journal(
    journal_path: &Path,
    plan: &ConsentRetirementPlanV1,
    approvals: &ConsentRetirementApprovalBundleV1,
    trusted_witness_keys: &[[u8; 32]],
    minimum_quorum: usize,
    public_key: &VerifyingKey,
    now_unix_secs: u64,
) -> Result<(), ConsentRetirementError> {
    plan.verify_authority_signature(public_key)?;
    approvals.verify_quorum(plan, trusted_witness_keys, minimum_quorum)?;
    let mut journal: ConsentRetirementJournalV1 = read_bounded_json(
        journal_path,
        MAX_RETIREMENT_TRANSACTION_BYTES,
        "consent retirement journal",
    )?;
    verify_retirement_journal_identity(&journal, plan, approvals, journal_path)?;
    if journal.state == ConsentRetirementJournalStateV1::Committed
        || journal.state == ConsentRetirementJournalStateV1::RolledBack
    {
        return Err(ConsentRetirementError::InvalidJournalState);
    }
    if quarantine_transaction_directory(plan).join("receipt.json").exists() {
        return Err(ConsentRetirementError::ReceiptAlreadyExists);
    }
    for index in (0..journal.entries.len()).rev() {
        let artifact = journal.entries[index].artifact.clone();
        let quarantine_path = journal.entries[index].quarantine_path.clone();
        let original = Path::new(&artifact.canonical_path);
        let quarantined = Path::new(&quarantine_path);
        match (original.exists(), quarantined.exists()) {
            (true, false) => {
                let observed = observe_retirement_artifact(artifact.role, original)?;
                if observed != artifact {
                    return Err(ConsentRetirementError::ArtifactChanged {
                        path: artifact.canonical_path,
                    });
                }
            }
            (false, true) => {
                let observed = observe_retirement_artifact(artifact.role, quarantined)?;
                if observed != artifact {
                    return Err(ConsentRetirementError::ArtifactChanged {
                        path: quarantine_path,
                    });
                }
                fs::rename(quarantined, original)?;
                sync_directory(
                    original
                        .parent()
                        .ok_or_else(|| ConsentRetirementError::NonCanonicalPath {
                            path: artifact.canonical_path.clone(),
                        })?,
                )?;
                sync_directory(
                    quarantined
                        .parent()
                        .ok_or_else(|| ConsentRetirementError::NonCanonicalPath {
                            path: quarantine_path.clone(),
                        })?,
                )?;
            }
            (true, true) => {
                return Err(ConsentRetirementError::RollbackArtifactPresentInBoth {
                    original: artifact.canonical_path,
                    quarantine: quarantine_path,
                });
            }
            (false, false) => {
                return Err(ConsentRetirementError::RollbackArtifactMissing {
                    original: artifact.canonical_path,
                    quarantine: quarantine_path,
                });
            }
        }
        journal.entries[index].state = ConsentRetirementJournalEntryStateV1::Restored;
        journal.updated_at_unix_secs = now_unix_secs;
        persist_retirement_json(journal_path, &journal)?;
    }
    journal.state = ConsentRetirementJournalStateV1::RolledBack;
    journal.updated_at_unix_secs = now_unix_secs;
    persist_retirement_json(journal_path, &journal)
}

fn verify_rolled_back_journal_files(
    journal: &ConsentRetirementJournalV1,
) -> Result<(), ConsentRetirementError> {
    for entry in &journal.entries {
        let original = Path::new(&entry.artifact.canonical_path);
        let quarantined = Path::new(&entry.quarantine_path);
        if quarantined.exists() {
            return Err(ConsentRetirementError::RollbackArtifactPresentInBoth {
                original: entry.artifact.canonical_path.clone(),
                quarantine: entry.quarantine_path.clone(),
            });
        }
        if !original.exists() {
            return Err(ConsentRetirementError::RollbackArtifactMissing {
                original: entry.artifact.canonical_path.clone(),
                quarantine: entry.quarantine_path.clone(),
            });
        }
        match entry.state {
            ConsentRetirementJournalEntryStateV1::Restored => {
                let observed = observe_retirement_artifact(entry.artifact.role, original)?;
                if observed != entry.artifact {
                    return Err(ConsentRetirementError::ArtifactChanged {
                        path: entry.artifact.canonical_path.clone(),
                    });
                }
            }
            ConsentRetirementJournalEntryStateV1::Pending => {
                let metadata = fs::symlink_metadata(original)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(ConsentRetirementError::ArtifactNotRegular {
                        path: entry.artifact.canonical_path.clone(),
                    });
                }
            }
            ConsentRetirementJournalEntryStateV1::Moved => {
                return Err(ConsentRetirementError::InvalidJournalState);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_retirement_transaction(
    journal_path: &Path,
    plan: &ConsentRetirementPlanV1,
    approvals: &ConsentRetirementApprovalBundleV1,
    trusted_witness_keys: &[[u8; 32]],
    minimum_quorum: usize,
    public_key: &VerifyingKey,
    now_unix_secs: u64,
) -> Result<ConsentRetirementRecoveryOutcomeV1, ConsentRetirementError> {
    plan.verify_authority_signature(public_key)?;
    approvals.verify_quorum(plan, trusted_witness_keys, minimum_quorum)?;
    let mut journal: ConsentRetirementJournalV1 = read_bounded_json(
        journal_path,
        MAX_RETIREMENT_TRANSACTION_BYTES,
        "consent retirement journal",
    )?;
    verify_retirement_journal_identity(&journal, plan, approvals, journal_path)?;
    let receipt_path = quarantine_transaction_directory(plan).join("receipt.json");
    if receipt_path.exists() {
        let receipt: ConsentRetirementQuarantineReceiptV1 = read_bounded_json(
            &receipt_path,
            MAX_RETIREMENT_TRANSACTION_BYTES,
            "consent retirement quarantine receipt",
        )?;
        receipt.verify(plan, approvals, public_key)?;
        verify_quarantined_receipt_files(&receipt)?;
        if journal.state == ConsentRetirementJournalStateV1::RolledBack {
            return Err(ConsentRetirementError::InvalidJournalState);
        }
        if journal.state == ConsentRetirementJournalStateV1::Committed {
            return Ok(ConsentRetirementRecoveryOutcomeV1::AlreadyCommitted);
        }
        journal.state = ConsentRetirementJournalStateV1::Committed;
        journal.updated_at_unix_secs = now_unix_secs;
        persist_retirement_json(journal_path, &journal)?;
        return Ok(ConsentRetirementRecoveryOutcomeV1::FinalizedCommitted);
    }
    match journal.state {
        ConsentRetirementJournalStateV1::Committed => {
            Err(ConsentRetirementError::MissingCommittedReceipt)
        }
        ConsentRetirementJournalStateV1::RolledBack => {
            verify_rolled_back_journal_files(&journal)?;
            Ok(ConsentRetirementRecoveryOutcomeV1::AlreadyRolledBack)
        }
        ConsentRetirementJournalStateV1::Prepared
        | ConsentRetirementJournalStateV1::Moving => {
            rollback_retirement_journal(
                journal_path,
                plan,
                approvals,
                trusted_witness_keys,
                minimum_quorum,
                public_key,
                now_unix_secs,
            )?;
            Ok(ConsentRetirementRecoveryOutcomeV1::RolledBack)
        }
    }
}

pub(crate) fn verify_quarantined_receipt_files(
    receipt: &ConsentRetirementQuarantineReceiptV1,
) -> Result<(), ConsentRetirementError> {
    for entry in &receipt.entries {
        if Path::new(&entry.artifact.canonical_path).exists() {
            return Err(ConsentRetirementError::QuarantinedOriginalReappeared {
                path: entry.artifact.canonical_path.clone(),
            });
        }
        let observed = observe_retirement_artifact(
            entry.artifact.role,
            Path::new(&entry.quarantine_path),
        )
        .map_err(|_| ConsentRetirementError::QuarantinedArtifactMismatch {
            path: entry.quarantine_path.clone(),
        })?;
        if observed.byte_length != entry.artifact.byte_length
            || observed.blake3_digest != entry.artifact.blake3_digest
        {
            return Err(ConsentRetirementError::QuarantinedArtifactMismatch {
                path: entry.quarantine_path.clone(),
            });
        }
    }
    Ok(())
}

impl ConsentRetirementQuarantineReceiptV1 {
    pub(crate) fn verify(
        &self,
        plan: &ConsentRetirementPlanV1,
        approvals: &ConsentRetirementApprovalBundleV1,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRetirementError> {
        if self.schema != CONSENT_RETIREMENT_RECEIPT_SCHEMA {
            return Err(ConsentRetirementError::UnsupportedReceiptSchema {
                schema: self.schema.clone(),
            });
        }
        if self.plan_fingerprint != consent_retirement_plan_fingerprint(plan)?
            || self.approval_bundle_fingerprint
                != consent_retirement_approval_bundle_fingerprint(approvals)?
            || self.transaction_directory
                != quarantine_transaction_directory(plan).to_string_lossy().as_ref()
            || self.entries.len() != plan.candidates.len()
            || self.completed_at_unix_secs < self.started_at_unix_secs
        {
            return Err(ConsentRetirementError::ReceiptIdentityMismatch);
        }
        let expected_entries = retirement_journal_entries_for_plan(plan)?;
        for (entry, expected) in self.entries.iter().zip(expected_entries) {
            if entry.artifact != expected.artifact
                || entry.quarantine_path != expected.quarantine_path
                || entry.state != ConsentRetirementJournalEntryStateV1::Moved
            {
                return Err(ConsentRetirementError::ReceiptIdentityMismatch);
            }
        }
        let message = consent_retirement_receipt_message(self)?;
        public_key
            .verify(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| ConsentRetirementError::InvalidReceiptSignature)
    }
}

pub(crate) fn consent_retirement_receipt_fingerprint(
    receipt: &ConsentRetirementQuarantineReceiptV1,
) -> Result<[u8; 32], ConsentRetirementError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-retirement-quarantine-receipt-fingerprint:v1");
    hasher.update(&consent_retirement_receipt_message(receipt)?);
    hasher.update(&receipt.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn consent_retirement_receipt_message(
    receipt: &ConsentRetirementQuarantineReceiptV1,
) -> Result<Vec<u8>, ConsentRetirementError> {
    if receipt.schema != CONSENT_RETIREMENT_RECEIPT_SCHEMA {
        return Err(ConsentRetirementError::UnsupportedReceiptSchema {
            schema: receipt.schema.clone(),
        });
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-retirement-quarantine-receipt:v1");
    append_bytes(&mut message, receipt.schema.as_bytes())?;
    message.extend_from_slice(&receipt.plan_fingerprint);
    message.extend_from_slice(&receipt.approval_bundle_fingerprint);
    append_bytes(&mut message, receipt.transaction_directory.as_bytes())?;
    message.extend_from_slice(&receipt.started_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&receipt.completed_at_unix_secs.to_be_bytes());
    let count = u32::try_from(receipt.entries.len())
        .map_err(|_| ConsentRetirementError::EncodingLengthOverflow)?;
    message.extend_from_slice(&count.to_be_bytes());
    for entry in &receipt.entries {
        message.push(entry.artifact.role.tag());
        append_bytes(&mut message, entry.artifact.canonical_path.as_bytes())?;
        append_bytes(&mut message, entry.quarantine_path.as_bytes())?;
        message.extend_from_slice(&entry.artifact.byte_length.to_be_bytes());
        message.extend_from_slice(&entry.artifact.blake3_digest);
        message.push(match entry.state {
            ConsentRetirementJournalEntryStateV1::Pending => 1,
            ConsentRetirementJournalEntryStateV1::Moved => 2,
            ConsentRetirementJournalEntryStateV1::Restored => 3,
        });
    }
    Ok(message)
}

fn persist_retirement_json<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), ConsentRetirementError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RETIREMENT_TRANSACTION_BYTES {
        return Err(ConsentRetirementError::ArtifactTooLarge {
            path: path.display().to_string(),
            maximum: MAX_RETIREMENT_TRANSACTION_BYTES,
        });
    }
    persist_owner_only_atomic(path, &bytes)?;
    Ok(())
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

impl ConsentRetirementApprovalBundleV1 {
    pub(crate) fn new(
        plan: &ConsentRetirementPlanV1,
    ) -> Result<Self, ConsentRetirementError> {
        Ok(Self {
            schema: CONSENT_RETIREMENT_APPROVAL_BUNDLE_SCHEMA.to_string(),
            plan_fingerprint: consent_retirement_plan_fingerprint(plan)?,
            approvals: Vec::new(),
        })
    }

    pub(crate) fn sign_with(
        &mut self,
        plan: &ConsentRetirementPlanV1,
        witness_signing_key: &LedgerSigningKey,
        approved_at_unix_secs: u64,
    ) -> Result<(), ConsentRetirementError> {
        if self.schema != CONSENT_RETIREMENT_APPROVAL_BUNDLE_SCHEMA {
            return Err(ConsentRetirementError::UnsupportedApprovalBundleSchema {
                schema: self.schema.clone(),
            });
        }
        let expected_plan = consent_retirement_plan_fingerprint(plan)?;
        if self.plan_fingerprint != expected_plan {
            return Err(ConsentRetirementError::ApprovalPlanMismatch);
        }
        if approved_at_unix_secs < plan.issued_at_unix_secs
            || approved_at_unix_secs >= plan.expires_at_unix_secs
        {
            return Err(ConsentRetirementError::ApprovalOutsidePlanWindow);
        }
        if self.approvals.len() >= MAX_RETIREMENT_APPROVALS {
            return Err(ConsentRetirementError::TooManyApprovals {
                count: self.approvals.len() + 1,
                maximum: MAX_RETIREMENT_APPROVALS,
            });
        }
        let witness_public_key = witness_signing_key.verifying_key().to_bytes();
        if self
            .approvals
            .iter()
            .any(|approval| approval.witness_public_key == witness_public_key)
        {
            return Err(ConsentRetirementError::DuplicateApprovalKey);
        }
        let message = consent_retirement_approval_message(
            &self.plan_fingerprint,
            &witness_public_key,
            approved_at_unix_secs,
        );
        self.approvals.push(ConsentRetirementApprovalV1 {
            witness_public_key,
            approved_at_unix_secs,
            signature: witness_signing_key.sign(&message).to_bytes(),
        });
        Ok(())
    }

    pub(crate) fn verify_quorum(
        &self,
        plan: &ConsentRetirementPlanV1,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<(), ConsentRetirementError> {
        if self.schema != CONSENT_RETIREMENT_APPROVAL_BUNDLE_SCHEMA {
            return Err(ConsentRetirementError::UnsupportedApprovalBundleSchema {
                schema: self.schema.clone(),
            });
        }
        if minimum_quorum == 0 {
            return Err(ConsentRetirementError::ZeroApprovalQuorum);
        }
        if self.approvals.len() > MAX_RETIREMENT_APPROVALS {
            return Err(ConsentRetirementError::TooManyApprovals {
                count: self.approvals.len(),
                maximum: MAX_RETIREMENT_APPROVALS,
            });
        }
        let expected_plan = consent_retirement_plan_fingerprint(plan)?;
        if self.plan_fingerprint != expected_plan {
            return Err(ConsentRetirementError::ApprovalPlanMismatch);
        }
        let trusted = trusted_witness_keys.iter().copied().collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        for approval in &self.approvals {
            if approval.approved_at_unix_secs < plan.issued_at_unix_secs
                || approval.approved_at_unix_secs >= plan.expires_at_unix_secs
            {
                return Err(ConsentRetirementError::ApprovalOutsidePlanWindow);
            }
            if !observed.insert(approval.witness_public_key) {
                return Err(ConsentRetirementError::DuplicateApprovalKey);
            }
            if !trusted.contains(&approval.witness_public_key) {
                return Err(ConsentRetirementError::UntrustedApprovalKey);
            }
            let public_key = VerifyingKey::from_bytes(&approval.witness_public_key)
                .map_err(|_| ConsentRetirementError::BadApprovalPublicKey)?;
            let message = consent_retirement_approval_message(
                &self.plan_fingerprint,
                &approval.witness_public_key,
                approval.approved_at_unix_secs,
            );
            public_key
                .verify(&message, &Signature::from_bytes(&approval.signature))
                .map_err(|_| ConsentRetirementError::BadApprovalSignature)?;
        }
        if observed.len() < minimum_quorum {
            return Err(ConsentRetirementError::ApprovalQuorumNotMet {
                verified: observed.len(),
                required: minimum_quorum,
            });
        }
        Ok(())
    }
}

pub(crate) fn consent_retirement_approval_bundle_fingerprint(
    bundle: &ConsentRetirementApprovalBundleV1,
) -> Result<[u8; 32], ConsentRetirementError> {
    if bundle.schema != CONSENT_RETIREMENT_APPROVAL_BUNDLE_SCHEMA {
        return Err(ConsentRetirementError::UnsupportedApprovalBundleSchema {
            schema: bundle.schema.clone(),
        });
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-retirement-approval-bundle-fingerprint:v1");
    hasher.update(&bundle.plan_fingerprint);
    let count = u32::try_from(bundle.approvals.len())
        .map_err(|_| ConsentRetirementError::EncodingLengthOverflow)?;
    hasher.update(&count.to_be_bytes());
    for approval in &bundle.approvals {
        hasher.update(&approval.witness_public_key);
        hasher.update(&approval.approved_at_unix_secs.to_be_bytes());
        hasher.update(&approval.signature);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn consent_retirement_approval_message(
    plan_fingerprint: &[u8; 32],
    witness_public_key: &[u8; 32],
    approved_at_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(128);
    message.extend_from_slice(b"xenia:consent-retirement-approval:v1");
    message.extend_from_slice(CONSENT_RETIREMENT_APPROVAL_BUNDLE_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(plan_fingerprint);
    message.extend_from_slice(witness_public_key);
    message.extend_from_slice(&approved_at_unix_secs.to_be_bytes());
    message
}

pub(crate) fn consent_retirement_plan_fingerprint(
    plan: &ConsentRetirementPlanV1,
) -> Result<[u8; 32], ConsentRetirementError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-retirement-plan-fingerprint:v1");
    hasher.update(&consent_retirement_plan_message(plan)?);
    hasher.update(&plan.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn consent_retirement_plan_message(
    plan: &ConsentRetirementPlanV1,
) -> Result<Vec<u8>, ConsentRetirementError> {
    let mut message = Vec::new();
    message.extend_from_slice(b"xenia:consent-retirement-plan:v1");
    append_bytes(&mut message, plan.schema.as_bytes())?;
    message.extend_from_slice(&plan.plan_id);
    message.extend_from_slice(&plan.ledger_epoch_id);
    message.extend_from_slice(&plan.active_state_digest);
    message.extend_from_slice(&plan.state_pin_fingerprint);
    message.extend_from_slice(&plan.gc_certificate_fingerprint);
    append_bytes(&mut message, plan.quarantine_root.as_bytes())?;
    let candidate_count = u32::try_from(plan.candidates.len())
        .map_err(|_| ConsentRetirementError::EncodingLengthOverflow)?;
    message.extend_from_slice(&candidate_count.to_be_bytes());
    for candidate in &plan.candidates {
        message.push(candidate.role.tag());
        append_bytes(&mut message, candidate.canonical_path.as_bytes())?;
        message.extend_from_slice(&candidate.byte_length.to_be_bytes());
        message.extend_from_slice(&candidate.blake3_digest);
    }
    message.extend_from_slice(&plan.issued_at_unix_secs.to_be_bytes());
    message.extend_from_slice(&plan.expires_at_unix_secs.to_be_bytes());
    Ok(message)
}

fn append_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), ConsentRetirementError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ConsentRetirementError::EncodingLengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn validate_absolute_normal_path(path: &str) -> Result<(), ConsentRetirementError> {
    if path.as_bytes().len() > MAX_RETIREMENT_PATH_BYTES {
        return Err(ConsentRetirementError::PathTooLong {
            path: path.to_string(),
            maximum: MAX_RETIREMENT_PATH_BYTES,
        });
    }
    let candidate = Path::new(path);
    if !candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir
            )
        })
    {
        return Err(ConsentRetirementError::NonCanonicalPath {
            path: path.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, LedgerArchiveSegment};

    use crate::audit_ledger_store::read_bounded_json;
    use crate::consent_compaction::{
        ConsentCompactedSnapshotV1, ConsentCompactedStatePinV1,
        ConsentCompactionBundleV1, ConsentCompactionGcCertificateV1,
    };

    fn event(kind: ConsentKind, session: u128, request: u128) -> ConsentEventRecord {
        ConsentEventRecord {
            source_id: [0x22; 32],
            session_id: Uuid::from_u128(session),
            request_id: Uuid::from_u128(request),
            kind,
            scope: "display".into(),
        }
    }

    fn prerequisites() -> (
        LedgerSigningKey,
        ConsentCompactedActiveStateV1,
        ConsentCompactedStatePinV1,
        ConsentCompactionGcCertificateV1,
        Vec<LedgerArchiveSegment>,
    ) {
        let key = LedgerSigningKey::from_bytes(&[0x51; 32]);
        let mut complete = Chain::new(key.clone());
        let genesis = complete.sign_checkpoint(100);
        complete.append(event(ConsentKind::Denial, 1, 2)).unwrap();
        let archive = vec![LedgerArchiveSegment::from_chain(&complete, genesis, 101).unwrap()];
        let bundle = ConsentCompactionBundleV1::build(&complete, archive.clone(), 102).unwrap();
        let entries = complete.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &key.verifying_key(),
        )
        .unwrap();
        let active = ConsentCompactedActiveStateV1::activate(snapshot, &archive, &key, 103)
            .unwrap();
        let pin = ConsentCompactedStatePinV1::sign_for_state(&active, &key, 104).unwrap();
        let certificate = ConsentCompactionGcCertificateV1::sign_for_state(
            &active,
            &pin,
            &archive,
            &key,
            105,
        )
        .unwrap();
        (key, active, pin, certificate, archive)
    }

    fn candidates() -> Vec<ConsentRetirementArtifactV1> {
        vec![ConsentRetirementArtifactV1 {
            role: ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            canonical_path: "/var/lib/xenia/consent.ledger".into(),
            byte_length: 123,
            blake3_digest: [0x33; 32],
        }]
    }

    #[test]
    fn plan_binds_exact_candidates_and_prerequisites() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            "/var/lib/xenia/retired".into(),
            candidates(),
            &key,
            106,
            200,
        )
        .unwrap();
        plan.verify(
            &active,
            &pin,
            &certificate,
            &archive,
            &key.verifying_key(),
            150,
        )
        .unwrap();
        assert_ne!(consent_retirement_plan_fingerprint(&plan).unwrap(), [0u8; 32]);
    }

    #[test]
    fn plan_refuses_candidate_or_window_substitution() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let mut plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            "/var/lib/xenia/retired".into(),
            candidates(),
            &key,
            106,
            200,
        )
        .unwrap();
        plan.candidates[0].byte_length += 1;
        assert_eq!(
            plan.verify(
                &active,
                &pin,
                &certificate,
                &archive,
                &key.verifying_key(),
                150,
            ),
            Err(ConsentRetirementError::InvalidPlanSignature)
        );

        plan.candidates[0].byte_length -= 1;
        assert_eq!(
            plan.verify(
                &active,
                &pin,
                &certificate,
                &archive,
                &key.verifying_key(),
                201,
            ),
            Err(ConsentRetirementError::PlanExpired)
        );
    }

    #[test]
    fn quarantine_moves_exact_bytes_and_emits_a_signed_receipt() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let dir = tempfile::tempdir().unwrap();
        let candidate_path = dir.path().join("consent.ledger");
        std::fs::write(&candidate_path, b"signed-ledger-bytes").unwrap();
        let quarantine_root = dir.path().join("quarantine");
        create_owner_only_directory(&quarantine_root).unwrap();
        let artifact = observe_retirement_artifact(
            ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            &candidate_path,
        )
        .unwrap();
        let plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            std::fs::canonicalize(&quarantine_root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vec![artifact],
            &key,
            106,
            200,
        )
        .unwrap();
        let witness = LedgerSigningKey::from_bytes(&[0x64; 32]);
        let mut approvals = ConsentRetirementApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 107).unwrap();
        let receipt = execute_retirement_quarantine(
            &plan,
            &approvals,
            &active,
            &pin,
            &certificate,
            &archive,
            &[witness.verifying_key().to_bytes()],
            1,
            &key,
            108,
        )
        .unwrap();
        receipt.verify(&plan, &approvals, &key.verifying_key()).unwrap();
        assert!(!candidate_path.exists());
        assert!(Path::new(&receipt.entries[0].quarantine_path).exists());
        assert_ne!(consent_retirement_receipt_fingerprint(&receipt).unwrap(), [0u8; 32]);
    }

    #[test]
    fn quarantine_refuses_changed_candidate_bytes_before_rename() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let dir = tempfile::tempdir().unwrap();
        let candidate_path = dir.path().join("consent.ledger");
        std::fs::write(&candidate_path, b"first").unwrap();
        let quarantine_root = dir.path().join("quarantine");
        create_owner_only_directory(&quarantine_root).unwrap();
        let artifact = observe_retirement_artifact(
            ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            &candidate_path,
        )
        .unwrap();
        let plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            std::fs::canonicalize(&quarantine_root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vec![artifact],
            &key,
            106,
            200,
        )
        .unwrap();
        let witness = LedgerSigningKey::from_bytes(&[0x65; 32]);
        let mut approvals = ConsentRetirementApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 107).unwrap();
        std::fs::write(&candidate_path, b"second").unwrap();
        assert!(matches!(
            execute_retirement_quarantine(
                &plan,
                &approvals,
                &active,
                &pin,
                &certificate,
                &archive,
                &[witness.verifying_key().to_bytes()],
                1,
                &key,
                108,
            ),
            Err(ConsentRetirementError::ArtifactChanged { .. })
        ));
        assert_eq!(std::fs::read(&candidate_path).unwrap(), b"second");
    }

    #[test]
    fn recovery_reconciles_a_rename_before_the_pending_journal_entry_was_updated() {
        let (authority_key, active, pin, certificate, archive) = prerequisites();
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("consent.ledger");
        std::fs::write(&original, b"ledger").unwrap();
        let quarantine_root = dir.path().join("quarantine");
        create_owner_only_directory(&quarantine_root).unwrap();
        let artifact = observe_retirement_artifact(
            ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            &original,
        )
        .unwrap();
        let plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            std::fs::canonicalize(&quarantine_root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vec![artifact],
            &authority_key,
            106,
            200,
        )
        .unwrap();
        let witness = LedgerSigningKey::from_bytes(&[0x66; 32]);
        let mut approvals = ConsentRetirementApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 107).unwrap();
        let transaction = quarantine_transaction_directory(&plan);
        std::fs::create_dir(&transaction).unwrap();
        let entries = retirement_journal_entries_for_plan(&plan).unwrap();
        let quarantined = PathBuf::from(&entries[0].quarantine_path);
        std::fs::rename(&original, &quarantined).unwrap();
        // Simulate a crash after rename and directory sync but before the
        // journal entry could be advanced from Pending to Moved.
        assert_eq!(entries[0].state, ConsentRetirementJournalEntryStateV1::Pending);
        let journal_path = transaction.join("journal.json");
        let journal = ConsentRetirementJournalV1 {
            schema: CONSENT_RETIREMENT_JOURNAL_SCHEMA.into(),
            plan_fingerprint: consent_retirement_plan_fingerprint(&plan).unwrap(),
            approval_bundle_fingerprint: consent_retirement_approval_bundle_fingerprint(&approvals)
                .unwrap(),
            transaction_directory: transaction.to_string_lossy().into_owned(),
            state: ConsentRetirementJournalStateV1::Moving,
            started_at_unix_secs: 108,
            updated_at_unix_secs: 108,
            entries,
        };
        persist_retirement_json(&journal_path, &journal).unwrap();
        rollback_retirement_journal(
            &journal_path,
            &plan,
            &approvals,
            &[witness.verifying_key().to_bytes()],
            1,
            &authority_key.verifying_key(),
            109,
        )
        .unwrap();
        assert_eq!(std::fs::read(&original).unwrap(), b"ledger");
        assert!(!quarantined.exists());
    }

    #[test]
    fn recovery_finalizes_a_receipted_transaction_with_a_stale_journal_state() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let dir = tempfile::tempdir().unwrap();
        let candidate_path = dir.path().join("consent.ledger");
        std::fs::write(&candidate_path, b"ledger").unwrap();
        let quarantine_root = dir.path().join("quarantine");
        create_owner_only_directory(&quarantine_root).unwrap();
        let artifact = observe_retirement_artifact(
            ConsentRetirementArtifactRoleV1::SupersededCompleteLedger,
            &candidate_path,
        )
        .unwrap();
        let plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            std::fs::canonicalize(&quarantine_root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vec![artifact],
            &key,
            106,
            200,
        )
        .unwrap();
        let witness = LedgerSigningKey::from_bytes(&[0x67; 32]);
        let mut approvals = ConsentRetirementApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 107).unwrap();
        let receipt = execute_retirement_quarantine(
            &plan,
            &approvals,
            &active,
            &pin,
            &certificate,
            &archive,
            &[witness.verifying_key().to_bytes()],
            1,
            &key,
            108,
        )
        .unwrap();
        let journal_path = Path::new(&receipt.transaction_directory).join("journal.json");
        let mut journal: ConsentRetirementJournalV1 = read_bounded_json(
            &journal_path,
            MAX_RETIREMENT_TRANSACTION_BYTES,
            "journal",
        )
        .unwrap();
        journal.state = ConsentRetirementJournalStateV1::Moving;
        persist_retirement_json(&journal_path, &journal).unwrap();
        assert_eq!(
            recover_retirement_transaction(
                &journal_path,
                &plan,
                &approvals,
                &[witness.verifying_key().to_bytes()],
                1,
                &key.verifying_key(),
                109,
            )
            .unwrap(),
            ConsentRetirementRecoveryOutcomeV1::FinalizedCommitted
        );
    }

    #[test]
    fn independent_approval_quorum_binds_the_exact_plan() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            "/var/lib/xenia/retired".into(),
            candidates(),
            &key,
            106,
            200,
        )
        .unwrap();
        let witness_one = LedgerSigningKey::from_bytes(&[0x61; 32]);
        let witness_two = LedgerSigningKey::from_bytes(&[0x62; 32]);
        let mut approvals = ConsentRetirementApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness_one, 107).unwrap();
        approvals.sign_with(&plan, &witness_two, 108).unwrap();
        approvals
            .verify_quorum(
                &plan,
                &[
                    witness_one.verifying_key().to_bytes(),
                    witness_two.verifying_key().to_bytes(),
                ],
                2,
            )
            .unwrap();
        assert_ne!(
            consent_retirement_approval_bundle_fingerprint(&approvals).unwrap(),
            [0u8; 32]
        );
    }

    #[test]
    fn approval_quorum_refuses_untrusted_duplicate_or_substituted_signers() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let plan = ConsentRetirementPlanV1::sign(
            &active,
            &pin,
            &certificate,
            &archive,
            "/var/lib/xenia/retired".into(),
            candidates(),
            &key,
            106,
            200,
        )
        .unwrap();
        let witness = LedgerSigningKey::from_bytes(&[0x63; 32]);
        let mut approvals = ConsentRetirementApprovalBundleV1::new(&plan).unwrap();
        approvals.sign_with(&plan, &witness, 107).unwrap();
        assert_eq!(
            approvals.verify_quorum(&plan, &[[0x99; 32]], 1),
            Err(ConsentRetirementError::UntrustedApprovalKey)
        );
        approvals.approvals.push(approvals.approvals[0].clone());
        assert_eq!(
            approvals.verify_quorum(
                &plan,
                &[witness.verifying_key().to_bytes()],
                1,
            ),
            Err(ConsentRetirementError::DuplicateApprovalKey)
        );
    }

    #[test]
    fn plan_refuses_protected_or_ambiguous_path_shapes() {
        let (key, active, pin, certificate, archive) = prerequisites();
        let mut invalid = candidates();
        invalid[0].canonical_path = "../consent.ledger".into();
        assert!(matches!(
            ConsentRetirementPlanV1::sign(
                &active,
                &pin,
                &certificate,
                &archive,
                "/var/lib/xenia/retired".into(),
                invalid,
                &key,
                106,
                200,
            ),
            Err(ConsentRetirementError::NonCanonicalPath { .. })
        ));
    }
}
