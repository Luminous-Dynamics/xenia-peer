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
//! This module deliberately does not delete or move files. Execution is a
//! separate phase so review, independent countersignature, and crash recovery
//! can be enforced before any filesystem mutation occurs.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use ed25519_dalek::{
    Signature, Signer, SigningKey as LedgerSigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use xenia_ledger::LedgerArchiveSegment;

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
    #[error("consent retirement prerequisite verification failed: {0}")]
    Recovery(#[from] ConsentRecoveryError),
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
        if self.schema != CONSENT_RETIREMENT_PLAN_SCHEMA {
            return Err(ConsentRetirementError::UnsupportedPlanSchema {
                schema: self.schema.clone(),
            });
        }
        self.validate_shape()?;
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
        if now_unix_secs < self.issued_at_unix_secs {
            return Err(ConsentRetirementError::PlanFromFuture);
        }
        if now_unix_secs >= self.expires_at_unix_secs {
            return Err(ConsentRetirementError::PlanExpired);
        }
        let message = consent_retirement_plan_message(self)?;
        public_key
            .verify(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| ConsentRetirementError::InvalidPlanSignature)
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
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
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
