// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Durable write-ahead journal for the stage-accurate operation evidence model.
//!
//! The journal is separate from the human consent ledger. Every admission and
//! effect-attempt record is length-framed, hash-linked and synchronously
//! persisted before the caller is allowed to dispatch the protected effect.
//! After restart, an operation left at Attempted is conservatively advanced to
//! Unknown; it is never automatically retried.
//!
//! This module does not authorize operations, verify external receipt truth,
//! sign exports, or prove remote presentation. The caller must still establish
//! consent/authority and supply trustworthy effect-owner receipts.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::m1_session::M1Permission;
use crate::operation_evidence::{
    AdmissionResult, OperationContext, OperationDirection, OperationEvidenceError,
    OperationEvidenceEvent, OperationEvidenceLedger, OperationId, OperationSnapshot,
    OperationState, ReconciliationOutcome,
};

/// Durable WAL schema version. A future incompatible record layout must bump it.
pub const OPERATION_WAL_SCHEMA_VERSION: u16 = 1;
/// Maximum serialized WAL body size, excluding the four-byte frame prefix.
pub const MAX_OPERATION_WAL_RECORD_BYTES: usize = 1024;
/// Maximum bytes in one session WAL. Capacity exhaustion fails closed.
pub const MAX_OPERATION_WAL_BYTES: u64 = 32 * 1024 * 1024;

/// Errors returned by the durable operation journal.
#[derive(Debug)]
pub enum DurableOperationJournalError {
    /// An underlying filesystem operation failed.
    Io(io::Error),
    /// A WAL record could not be encoded or decoded.
    Codec(String),
    /// The existing in-memory operation state machine rejected a transition.
    Operation(OperationEvidenceError),
    /// A complete framed record was corrupt, out of sequence, or hash-invalid.
    CorruptRecord {
        /// Sequence number expected at the point of corruption.
        sequence: u64,
    },
    /// The WAL uses a schema version this implementation does not understand.
    UnsupportedSchema(u16),
    /// The file is bound to a different authenticated session.
    SessionFingerprintMismatch,
    /// The file is bound to a different monotonic clock domain.
    ClockDomainMismatch,
    /// Another writer already owns this journal path.
    WriterAlreadyActive,
    /// One record exceeds the strict record-size limit.
    RecordTooLarge,
    /// The session journal reached its hard byte/event/operation capacity.
    CapacityFull,
    /// The requested event tick regressed relative to the last durable event.
    ClockRegression {
        /// Last durable event tick.
        previous: u64,
        /// Regressing tick supplied by the caller.
        observed: u64,
    },
    /// The journal sequence counter is exhausted.
    SequenceExhausted,
    /// The trusted anchor points beyond the recovered journal head.
    JournalBehindAnchor {
        /// Sequence durably recorded by the external witness.
        anchored_sequence: u64,
        /// Highest locally recovered sequence.
        recovered_sequence: u64,
    },
    /// The retained WAL prefix does not match the external checkpoint.
    JournalAnchorPrefixMismatch {
        /// Sequence where the anchored prefix differs.
        sequence: u64,
    },
    /// A previously durable WAL command disagreed with the in-memory state model.
    ReplayDivergence,
    /// A write/sync failed; the journal is poisoned and must be reopened.
    Poisoned,
}

impl fmt::Display for DurableOperationJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "operation WAL I/O failure: {error}"),
            Self::Codec(error) => write!(f, "operation WAL codec failure: {error}"),
            Self::Operation(error) => write!(f, "operation evidence transition failed: {error:?}"),
            Self::CorruptRecord { sequence } => {
                write!(f, "operation WAL record {sequence} is corrupt")
            }
            Self::UnsupportedSchema(version) => {
                write!(f, "unsupported operation WAL schema version {version}")
            }
            Self::SessionFingerprintMismatch => {
                write!(f, "operation WAL belongs to another session")
            }
            Self::ClockDomainMismatch => {
                write!(f, "operation WAL belongs to another clock domain")
            }
            Self::WriterAlreadyActive => write!(f, "another process owns this operation WAL"),
            Self::RecordTooLarge => write!(f, "operation WAL record exceeds its size bound"),
            Self::CapacityFull => write!(f, "operation WAL reached its hard capacity"),
            Self::ClockRegression { previous, observed } => write!(
                f,
                "operation WAL clock regressed from {previous} to {observed}"
            ),
            Self::SequenceExhausted => write!(f, "operation WAL sequence is exhausted"),
            Self::JournalBehindAnchor { anchored_sequence, recovered_sequence } => write!(
                f,
                "operation WAL is behind anchor sequence {anchored_sequence} (recovered {recovered_sequence})"
            ),
            Self::JournalAnchorPrefixMismatch { sequence } => {
                write!(f, "operation WAL does not match the trusted anchor at sequence {sequence}")
            }
            Self::ReplayDivergence => {
                write!(
                    f,
                    "durable WAL command diverged from operation evidence state"
                )
            }
            Self::Poisoned => write!(f, "operation WAL is poisoned; reopen and reconcile"),
        }
    }
}

impl std::error::Error for DurableOperationJournalError {}

impl From<io::Error> for DurableOperationJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<OperationEvidenceError> for DurableOperationJournalError {
    fn from(error: OperationEvidenceError) -> Self {
        Self::Operation(error)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PersistedOperationContext {
    session_fingerprint: [u8; 32],
    lane_tag: u8,
    direction_tag: u8,
    resource_digest: [u8; 32],
    consent_reference_digest: [u8; 32],
    policy_digest: [u8; 32],
    authority_commitment_digest: Option<[u8; 32]>,
    authority_epoch: Option<u64>,
}

impl TryFrom<OperationContext> for PersistedOperationContext {
    type Error = DurableOperationJournalError;

    fn try_from(context: OperationContext) -> Result<Self, Self::Error> {
        let lane_tag = permission_tag(context.lane);
        let direction_tag = match context.direction {
            OperationDirection::HostToViewer => 1,
            OperationDirection::ViewerToHost => 2,
        };
        Ok(Self {
            session_fingerprint: context.session_fingerprint,
            lane_tag,
            direction_tag,
            resource_digest: context.resource_digest,
            consent_reference_digest: context.consent_reference_digest,
            policy_digest: context.policy_digest,
            authority_commitment_digest: context.authority_commitment_digest,
            authority_epoch: context.authority_epoch,
        })
    }
}

impl TryFrom<PersistedOperationContext> for OperationContext {
    type Error = DurableOperationJournalError;

    fn try_from(context: PersistedOperationContext) -> Result<Self, Self::Error> {
        let lane = permission_from_tag(context.lane_tag)
            .ok_or(DurableOperationJournalError::CorruptRecord { sequence: 0 })?;
        let direction = match context.direction_tag {
            1 => OperationDirection::HostToViewer,
            2 => OperationDirection::ViewerToHost,
            _ => return Err(DurableOperationJournalError::CorruptRecord { sequence: 0 }),
        };
        Ok(Self {
            session_fingerprint: context.session_fingerprint,
            lane,
            direction,
            resource_digest: context.resource_digest,
            consent_reference_digest: context.consent_reference_digest,
            policy_digest: context.policy_digest,
            authority_commitment_digest: context.authority_commitment_digest,
            authority_epoch: context.authority_epoch,
        })
    }
}

fn permission_tag(permission: M1Permission) -> u8 {
    match permission {
        M1Permission::StreamFrame => 1,
        M1Permission::StreamTelemetry => 2,
        M1Permission::StreamAudio => 3,
        M1Permission::InjectInput => 4,
        M1Permission::ReadHostClipboard => 5,
        M1Permission::WriteHostClipboard => 6,
        M1Permission::SendFileToViewer => 7,
        M1Permission::ReceiveFileFromViewer => 8,
    }
}

fn permission_from_tag(tag: u8) -> Option<M1Permission> {
    match tag {
        1 => Some(M1Permission::StreamFrame),
        2 => Some(M1Permission::StreamTelemetry),
        3 => Some(M1Permission::StreamAudio),
        4 => Some(M1Permission::InjectInput),
        5 => Some(M1Permission::ReadHostClipboard),
        6 => Some(M1Permission::WriteHostClipboard),
        7 => Some(M1Permission::SendFileToViewer),
        8 => Some(M1Permission::ReceiveFileFromViewer),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum WalReconciliationOutcome {
    NotCommitted,
    Committed,
    Observed,
}

impl From<ReconciliationOutcome> for WalReconciliationOutcome {
    fn from(outcome: ReconciliationOutcome) -> Self {
        match outcome {
            ReconciliationOutcome::NotCommitted => Self::NotCommitted,
            ReconciliationOutcome::Committed => Self::Committed,
            ReconciliationOutcome::Observed => Self::Observed,
        }
    }
}

impl From<WalReconciliationOutcome> for ReconciliationOutcome {
    fn from(outcome: WalReconciliationOutcome) -> Self {
        match outcome {
            WalReconciliationOutcome::NotCommitted => Self::NotCommitted,
            WalReconciliationOutcome::Committed => Self::Committed,
            WalReconciliationOutcome::Observed => Self::Observed,
        }
    }
}

/// A single durable state transition. Raw operation payloads are never stored.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum WalCommand {
    Admit {
        operation_id: [u8; 16],
        operation_sequence: u64,
        context: PersistedOperationContext,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    },
    Attempted {
        operation_id: [u8; 16],
        at_ticks: u64,
        evidence_digest: [u8; 32],
    },
    Committed {
        operation_id: [u8; 16],
        at_ticks: u64,
        evidence_digest: [u8; 32],
    },
    Observed {
        operation_id: [u8; 16],
        at_ticks: u64,
        evidence_digest: [u8; 32],
    },
    Rejected {
        operation_id: [u8; 16],
        at_ticks: u64,
        evidence_digest: [u8; 32],
    },
    NotCommitted {
        operation_id: [u8; 16],
        at_ticks: u64,
        evidence_digest: [u8; 32],
    },
    Unknown {
        operation_id: [u8; 16],
        at_ticks: u64,
        evidence_digest: [u8; 32],
    },
    Reconcile {
        operation_id: [u8; 16],
        outcome: WalReconciliationOutcome,
        at_ticks: u64,
        receipt_digest: [u8; 32],
    },
}

impl WalCommand {
    fn operation_id(self) -> [u8; 16] {
        match self {
            Self::Admit { operation_id, .. }
            | Self::Attempted { operation_id, .. }
            | Self::Committed { operation_id, .. }
            | Self::Observed { operation_id, .. }
            | Self::Rejected { operation_id, .. }
            | Self::NotCommitted { operation_id, .. }
            | Self::Unknown { operation_id, .. }
            | Self::Reconcile { operation_id, .. } => operation_id,
        }
    }

    fn at_ticks(self) -> u64 {
        match self {
            Self::Admit { at_ticks, .. }
            | Self::Attempted { at_ticks, .. }
            | Self::Committed { at_ticks, .. }
            | Self::Observed { at_ticks, .. }
            | Self::Rejected { at_ticks, .. }
            | Self::NotCommitted { at_ticks, .. }
            | Self::Unknown { at_ticks, .. }
            | Self::Reconcile { at_ticks, .. } => at_ticks,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct WalRecordBody {
    schema_version: u16,
    journal_sequence: u64,
    session_fingerprint: [u8; 32],
    clock_domain: u64,
    previous_hash: [u8; 32],
    command: WalCommand,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct WalRecord {
    body: WalRecordBody,
    record_hash: [u8; 32],
}

fn wal_record_hash(body: &WalRecordBody) -> Result<[u8; 32], DurableOperationJournalError> {
    let encoded = bincode::serialize(body)
        .map_err(|error| DurableOperationJournalError::Codec(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-DURABLE-OPERATION-WAL-V1\0");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn recovery_unknown_digest(
    operation_id: OperationId,
    operation_sequence: u64,
    last_record_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"XENIA-OPERATION-WAL-RECOVERY-UNKNOWN-V1\0");
    hasher.update(&operation_id.0);
    hasher.update(&operation_sequence.to_le_bytes());
    hasher.update(&last_record_hash);
    *hasher.finalize().as_bytes()
}

fn reserved_wal_bytes_for_slots(slots: usize) -> Result<u64, DurableOperationJournalError> {
    let frame_and_record_bytes = 4_u64
        .checked_add(
            u64::try_from(MAX_OPERATION_WAL_RECORD_BYTES)
                .map_err(|_| DurableOperationJournalError::CapacityFull)?,
        )
        .ok_or(DurableOperationJournalError::CapacityFull)?;
    u64::try_from(slots)
        .ok()
        .and_then(|count| count.checked_mul(frame_and_record_bytes))
        .ok_or(DurableOperationJournalError::CapacityFull)
}

fn reserved_event_slots_for_state(state: OperationState) -> usize {
    match state {
        OperationState::Admitted => 3,
        OperationState::Attempted => 2,
        OperationState::Committed
        | OperationState::Unknown
        | OperationState::ReconciledCommitted => 1,
        OperationState::Observed
        | OperationState::Rejected
        | OperationState::NotCommitted
        | OperationState::ReconciledNotCommitted
        | OperationState::ReconciledObserved => 0,
    }
}

/// Payload-free candidate head for an independently protected journal checkpoint.
///
/// The digest is an unkeyed local WAL-chain head. This value is not itself an
/// authenticated anchor; callers must persist/authenticate it in a separate
/// trust domain before relying on it for rollback detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableOperationJournalHead {
    /// Authenticated session identity bound to the journal.
    pub session_fingerprint: [u8; 32],
    /// Monotonic clock domain used by the operation ledger.
    pub clock_domain: u64,
    /// Current WAL record sequence.
    pub journal_sequence: u64,
    /// BLAKE3 hash-chain digest of the current WAL head.
    pub wal_chain_digest: [u8; 32],
    /// Highest admitted operation sequence recovered from the ledger.
    pub last_operation_sequence: Option<u64>,
}

/// A durable, single-writer operation journal backed by a framed binary WAL.
///
/// A successful `admit` or `mark_attempted` call returns only after
/// `sync_data` has completed. Callers must not dispatch an effect until the
/// corresponding `mark_attempted` call succeeds. If a process restarts with
/// an Attempted operation lacking a durable owner result, `open` writes an
/// UNKNOWN recovery record before returning.
///
/// The journal is deliberately single-writer. A create-new lock file prevents
/// two processes from appending to the same WAL concurrently. A stale lock
/// after an unclean process termination is not removed automatically; the
/// operator must inspect the owning process and recover it explicitly.
pub struct DurableOperationEvidenceJournal {
    path: PathBuf,
    lock_path: PathBuf,
    lock_file: Option<File>,
    file: File,
    session_fingerprint: [u8; 32],
    clock_domain: u64,
    ledger: OperationEvidenceLedger,
    operation_ids: HashSet<OperationId>,
    last_operation_sequence: Option<u64>,
    journal_sequence: u64,
    last_record_hash: [u8; 32],
    /// Bounded verified prefix heads, including the sequence-zero genesis.
    prefix_heads: Vec<DurableOperationJournalHead>,
    last_event_tick: Option<u64>,
    poisoned: bool,
}

impl fmt::Debug for DurableOperationEvidenceJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableOperationEvidenceJournal")
            .field("path", &self.path)
            .field("session_fingerprint", &self.session_fingerprint)
            .field("clock_domain", &self.clock_domain)
            .field("journal_sequence", &self.journal_sequence)
            .field("operation_count", &self.operation_ids.len())
            .field("event_count", &self.ledger.events().len())
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl DurableOperationEvidenceJournal {
    /// Open or create one journal, verify its full hash chain, replay it, and
    /// durably convert every interrupted Attempted operation to UNKNOWN.
    pub fn open(
        path: impl AsRef<Path>,
        session_fingerprint: [u8; 32],
        clock_domain: u64,
    ) -> Result<Self, DurableOperationJournalError> {
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path_for(&path);
        let lock_file = create_writer_lock(&lock_path)?;

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let path_existed = path.exists();
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) => {
                drop(lock_file);
                let _ = fs::remove_file(&lock_path);
                return Err(DurableOperationJournalError::Io(error));
            }
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                drop(file);
                drop(lock_file);
                let _ = fs::remove_file(&lock_path);
                return Err(DurableOperationJournalError::Io(error));
            }
        }

        let mut journal = Self {
            path: path.clone(),
            lock_path,
            lock_file: Some(lock_file),
            file,
            session_fingerprint,
            clock_domain,
            ledger: OperationEvidenceLedger::new(session_fingerprint, clock_domain),
            operation_ids: HashSet::new(),
            last_operation_sequence: None,
            journal_sequence: 0,
            last_record_hash: [0; 32],
            prefix_heads: vec![DurableOperationJournalHead {
                session_fingerprint,
                clock_domain,
                journal_sequence: 0,
                wal_chain_digest: [0; 32],
                last_operation_sequence: None,
            }],
            last_event_tick: None,
            poisoned: false,
        };
        if !path_existed {
            sync_parent_directory(&journal.path)?;
        }
        journal.replay_existing()?;
        // Stabilize the fully verified recovered prefix before any caller
        // can observe a committed state or dispatch a new protected effect.
        // This also re-establishes durability after a prior sync error.
        journal.file.sync_all()?;
        journal.recover_interrupted_attempts()?;
        Ok(journal)
    }

    /// Admit an operation and durably write the admission receipt before any
    /// effect owner can be invoked.
    pub fn admit(
        &mut self,
        operation_id: OperationId,
        operation_sequence: u64,
        context: OperationContext,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<AdmissionResult, DurableOperationJournalError> {
        self.ensure_healthy()?;
        if context.session_fingerprint != self.session_fingerprint {
            return Err(DurableOperationJournalError::SessionFingerprintMismatch);
        }

        if let Ok(existing) = self.ledger.snapshot(operation_id) {
            if existing.operation_sequence == operation_sequence && existing.context == context {
                return Ok(AdmissionResult::AlreadyPresent(existing));
            }
            return Err(DurableOperationJournalError::Operation(
                OperationEvidenceError::OperationIdConflict,
            ));
        }

        if let Some(previous) = self.last_operation_sequence
            && operation_sequence <= previous
        {
            return Err(DurableOperationJournalError::Operation(
                OperationEvidenceError::NonMonotonicOperationSequence {
                    previous,
                    observed: operation_sequence,
                },
            ));
        }
        if self.operation_ids.len() >= super::operation_evidence::MAX_OPERATION_RECORDS {
            return Err(DurableOperationJournalError::CapacityFull);
        }
        self.ensure_capacity_for_admission()?;
        let persisted_context = PersistedOperationContext::try_from(context)?;
        self.append_command(WalCommand::Admit {
            operation_id: operation_id.0,
            operation_sequence,
            context: persisted_context,
            at_ticks,
            evidence_digest,
        })?;
        match self.ledger.admit(
            operation_id,
            operation_sequence,
            context,
            at_ticks,
            evidence_digest,
        ) {
            Ok(result) => {
                self.operation_ids.insert(operation_id);
                self.last_operation_sequence = Some(operation_sequence);
                self.record_head_candidate();
                Ok(result)
            }
            Err(_) => {
                self.poisoned = true;
                Err(DurableOperationJournalError::ReplayDivergence)
            }
        }
    }

    /// Durably record that the effect-owning subsystem is about to be invoked.
    /// The caller must invoke no external effect unless this method succeeds.
    pub fn mark_attempted(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.require_state(
            operation_id,
            &[OperationState::Admitted],
            crate::operation_evidence::OperationEventKind::EffectAttempted,
        )?;
        self.ensure_capacity_for_transition(operation_id, OperationState::Attempted)?;
        self.append_command(WalCommand::Attempted {
            operation_id: operation_id.0,
            at_ticks,
            evidence_digest,
        })?;
        let result = self
            .ledger
            .mark_attempted(operation_id, at_ticks, evidence_digest);
        self.apply_or_poison(result)
    }

    /// Persist a local effect-owner commit receipt. If the append/sync fails,
    /// the caller must treat the outcome as UNKNOWN and stop new effects.
    pub fn mark_committed(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        owner_receipt_digest: [u8; 32],
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.require_state(
            operation_id,
            &[OperationState::Attempted],
            crate::operation_evidence::OperationEventKind::EffectCommitted,
        )?;
        self.ensure_capacity_for_transition(operation_id, OperationState::Committed)?;
        self.append_command(WalCommand::Committed {
            operation_id: operation_id.0,
            at_ticks,
            evidence_digest: owner_receipt_digest,
        })?;
        let result = self
            .ledger
            .mark_committed(operation_id, at_ticks, owner_receipt_digest);
        self.apply_or_poison(result)
    }

    /// Persist an independently established observation receipt.
    pub fn mark_observed(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        observation_receipt_digest: [u8; 32],
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.ensure_healthy()?;
        let current = self.ledger.snapshot(operation_id)?;
        if !matches!(
            current.state,
            OperationState::Committed | OperationState::ReconciledCommitted
        ) {
            return Err(DurableOperationJournalError::Operation(
                OperationEvidenceError::InvalidTransition {
                    from: current.state,
                    event: crate::operation_evidence::OperationEventKind::OutcomeObserved,
                },
            ));
        }
        self.ensure_capacity_for_transition(operation_id, OperationState::Observed)?;
        self.append_command(WalCommand::Observed {
            operation_id: operation_id.0,
            at_ticks,
            evidence_digest: observation_receipt_digest,
        })?;
        let result = self
            .ledger
            .mark_observed(operation_id, at_ticks, observation_receipt_digest);
        self.apply_or_poison(result)
    }

    /// Persist rejection before the effect owner is invoked.
    pub fn mark_rejected(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        rejection_evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.require_state(
            operation_id,
            &[OperationState::Admitted],
            crate::operation_evidence::OperationEventKind::Rejected,
        )?;
        self.ensure_capacity_for_transition(operation_id, OperationState::Rejected)?;
        self.append_command(WalCommand::Rejected {
            operation_id: operation_id.0,
            at_ticks,
            evidence_digest: rejection_evidence_digest,
        })?;
        let result = self
            .ledger
            .mark_rejected(operation_id, at_ticks, rejection_evidence_digest);
        self.apply_or_poison(result)
    }

    /// Persist a definitive post-attempt non-commit receipt.
    pub fn mark_not_committed(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.require_state(
            operation_id,
            &[OperationState::Attempted],
            crate::operation_evidence::OperationEventKind::EffectNotCommitted,
        )?;
        self.ensure_capacity_for_transition(operation_id, OperationState::NotCommitted)?;
        self.append_command(WalCommand::NotCommitted {
            operation_id: operation_id.0,
            at_ticks,
            evidence_digest,
        })?;
        let result = self
            .ledger
            .mark_not_committed(operation_id, at_ticks, evidence_digest);
        self.apply_or_poison(result)
    }

    /// Persist an ambiguous result. UNKNOWN blocks unsafe retry until an
    /// independently verified receipt reconciles this operation ID.
    pub fn mark_unknown(
        &mut self,
        operation_id: OperationId,
        at_ticks: u64,
        evidence_digest: [u8; 32],
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.require_state(
            operation_id,
            &[OperationState::Attempted],
            crate::operation_evidence::OperationEventKind::Unknown,
        )?;
        self.ensure_capacity_for_transition(operation_id, OperationState::Unknown)?;
        self.append_command(WalCommand::Unknown {
            operation_id: operation_id.0,
            at_ticks,
            evidence_digest,
        })?;
        let result = self
            .ledger
            .mark_unknown(operation_id, at_ticks, evidence_digest);
        self.apply_or_poison(result)
    }

    /// Persist reconciliation of an UNKNOWN outcome. Replaying the same
    /// outcome/receipt is idempotent; conflicting receipts are rejected.
    pub fn reconcile_unknown(
        &mut self,
        operation_id: OperationId,
        outcome: ReconciliationOutcome,
        at_ticks: u64,
        receipt_digest: [u8; 32],
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.ensure_healthy()?;
        let current = self.ledger.snapshot(operation_id)?;
        let expected = match outcome {
            ReconciliationOutcome::NotCommitted => OperationState::ReconciledNotCommitted,
            ReconciliationOutcome::Committed => OperationState::ReconciledCommitted,
            ReconciliationOutcome::Observed => OperationState::ReconciledObserved,
        };
        if current.state == expected && current.reconciliation_digest == Some(receipt_digest) {
            return Ok(current);
        }
        if current.state != OperationState::Unknown {
            return Err(DurableOperationJournalError::Operation(
                OperationEvidenceError::ReconciliationConflict,
            ));
        }
        let next_state = match outcome {
            ReconciliationOutcome::NotCommitted => OperationState::ReconciledNotCommitted,
            ReconciliationOutcome::Committed => OperationState::ReconciledCommitted,
            ReconciliationOutcome::Observed => OperationState::ReconciledObserved,
        };
        self.ensure_capacity_for_transition(operation_id, next_state)?;
        self.append_command(WalCommand::Reconcile {
            operation_id: operation_id.0,
            outcome: outcome.into(),
            at_ticks,
            receipt_digest,
        })?;
        let result = self
            .ledger
            .reconcile_unknown(operation_id, outcome, at_ticks, receipt_digest);
        self.apply_or_poison(result)
    }

    /// Read the latest state of one operation.
    pub fn snapshot(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.ledger.snapshot(operation_id).map_err(Into::into)
    }

    /// Read the in-memory view of the fully replayed operation event chain.
    pub fn events(&self) -> &[OperationEvidenceEvent] {
        self.ledger.events()
    }

    /// Hash-chain root for the operation stage ledger.
    pub fn operation_chain_digest(&self) -> [u8; 32] {
        self.ledger.chain_digest()
    }

    /// Hash-chain root for the durable WAL framing layer.
    pub fn wal_chain_digest(&self) -> [u8; 32] {
        self.last_record_hash
    }

    /// Current durable WAL sequence.
    pub fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Export a payload-free candidate head for an independent anchor service.
    ///
    /// A caller must not treat this local unkeyed digest as a trust anchor until
    /// a separate, rollback-resistant witness has durably accepted it.
    pub fn head_candidate(&self) -> DurableOperationJournalHead {
        DurableOperationJournalHead {
            session_fingerprint: self.session_fingerprint,
            clock_domain: self.clock_domain,
            journal_sequence: self.journal_sequence,
            wal_chain_digest: self.last_record_hash,
            last_operation_sequence: self.last_operation_sequence,
        }
    }

    /// Verify that an external checkpoint is an exact prefix of this fully
    /// replayed WAL. A later recovered head is acceptable only when it extends
    /// the exact anchored hash/sequence/operation-sequence tuple.
    pub fn verify_anchor_prefix(
        &self,
        anchor: &DurableOperationJournalHead,
    ) -> Result<(), DurableOperationJournalError> {
        if anchor.session_fingerprint != self.session_fingerprint {
            return Err(DurableOperationJournalError::SessionFingerprintMismatch);
        }
        if anchor.clock_domain != self.clock_domain {
            return Err(DurableOperationJournalError::ClockDomainMismatch);
        }
        if anchor.journal_sequence > self.journal_sequence {
            return Err(DurableOperationJournalError::JournalBehindAnchor {
                anchored_sequence: anchor.journal_sequence,
                recovered_sequence: self.journal_sequence,
            });
        }
        let index = usize::try_from(anchor.journal_sequence)
            .map_err(|_| DurableOperationJournalError::JournalBehindAnchor {
                anchored_sequence: anchor.journal_sequence,
                recovered_sequence: self.journal_sequence,
            })?;
        let Some(prefix) = self.prefix_heads.get(index) else {
            return Err(DurableOperationJournalError::JournalBehindAnchor {
                anchored_sequence: anchor.journal_sequence,
                recovered_sequence: self.journal_sequence,
            });
        };
        if prefix.journal_sequence != anchor.journal_sequence
            || prefix.wal_chain_digest != anchor.wal_chain_digest
            || prefix.last_operation_sequence != anchor.last_operation_sequence
        {
            return Err(DurableOperationJournalError::JournalAnchorPrefixMismatch {
                sequence: anchor.journal_sequence,
            });
        }
        Ok(())
    }

    /// Whether a failed append has poisoned this in-process writer.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Verify the replayed in-memory operation chain.
    pub fn verify_operation_chain(&self) -> bool {
        !self.poisoned && self.ledger.verify_chain()
    }

    fn reserved_event_slots(&self) -> Result<usize, DurableOperationJournalError> {
        self.operation_ids
            .iter()
            .try_fold(0_usize, |total, operation_id| {
                let snapshot = self.ledger.snapshot(*operation_id)?;
                total
                    .checked_add(reserved_event_slots_for_state(snapshot.state))
                    .ok_or(DurableOperationJournalError::CapacityFull)
            })
    }

    fn ensure_wal_capacity_with_reserved_slots(
        &self,
        reserved_slots_after: usize,
    ) -> Result<(), DurableOperationJournalError> {
        let frame_and_record_bytes = reserved_wal_bytes_for_slots(1)?;
        let reserved_bytes = reserved_wal_bytes_for_slots(reserved_slots_after)?;
        let required = self
            .file
            .metadata()?
            .len()
            .checked_add(frame_and_record_bytes)
            .and_then(|value| value.checked_add(reserved_bytes))
            .ok_or(DurableOperationJournalError::CapacityFull)?;
        if required > MAX_OPERATION_WAL_BYTES {
            return Err(DurableOperationJournalError::CapacityFull);
        }
        Ok(())
    }

    fn ensure_capacity_for_admission(&self) -> Result<(), DurableOperationJournalError> {
        let reserved = self.reserved_event_slots()?;
        let required = self
            .ledger
            .events()
            .len()
            .checked_add(1)
            .and_then(|value| value.checked_add(reserved))
            .and_then(|value| {
                value.checked_add(reserved_event_slots_for_state(OperationState::Admitted))
            })
            .ok_or(DurableOperationJournalError::CapacityFull)?;
        if required > super::operation_evidence::MAX_OPERATION_EVENTS {
            return Err(DurableOperationJournalError::CapacityFull);
        }
        let reserved_after = reserved
            .checked_add(reserved_event_slots_for_state(OperationState::Admitted))
            .ok_or(DurableOperationJournalError::CapacityFull)?;
        self.ensure_wal_capacity_with_reserved_slots(reserved_after)
    }

    fn ensure_capacity_for_transition(
        &self,
        operation_id: OperationId,
        next_state: OperationState,
    ) -> Result<(), DurableOperationJournalError> {
        let current = self.ledger.snapshot(operation_id)?;
        let reserved = self.reserved_event_slots()?;
        // Add the complete outstanding reservation before subtracting
        // this operation's current reservation. Subtracting first can
        // underflow for a small event count even when the final budget fits.
        let required = self
            .ledger
            .events()
            .len()
            .checked_add(1)
            .and_then(|value| value.checked_add(reserved))
            .and_then(|value| value.checked_sub(reserved_event_slots_for_state(current.state)))
            .and_then(|value| value.checked_add(reserved_event_slots_for_state(next_state)))
            .ok_or(DurableOperationJournalError::CapacityFull)?;
        if required > super::operation_evidence::MAX_OPERATION_EVENTS {
            return Err(DurableOperationJournalError::CapacityFull);
        }
        let reserved_after = reserved
            .checked_sub(reserved_event_slots_for_state(current.state))
            .and_then(|value| value.checked_add(reserved_event_slots_for_state(next_state)))
            .ok_or(DurableOperationJournalError::CapacityFull)?;
        self.ensure_wal_capacity_with_reserved_slots(reserved_after)
    }

    fn require_state(
        &self,
        operation_id: OperationId,
        allowed: &[OperationState],
        event: crate::operation_evidence::OperationEventKind,
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        self.ensure_healthy()?;
        let snapshot = self.ledger.snapshot(operation_id)?;
        if allowed.contains(&snapshot.state) {
            Ok(snapshot)
        } else {
            Err(DurableOperationJournalError::Operation(
                OperationEvidenceError::InvalidTransition {
                    from: snapshot.state,
                    event,
                },
            ))
        }
    }

    fn ensure_healthy(&self) -> Result<(), DurableOperationJournalError> {
        if self.poisoned {
            Err(DurableOperationJournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn append_command(&mut self, command: WalCommand) -> Result<(), DurableOperationJournalError> {
        self.ensure_healthy()?;
        if self.ledger.events().len() >= super::operation_evidence::MAX_OPERATION_EVENTS {
            return Err(DurableOperationJournalError::CapacityFull);
        }
        let at_ticks = command.at_ticks();
        if let Some(previous) = self.last_event_tick
            && at_ticks < previous
        {
            return Err(DurableOperationJournalError::ClockRegression {
                previous,
                observed: at_ticks,
            });
        }
        let next_sequence = self
            .journal_sequence
            .checked_add(1)
            .ok_or(DurableOperationJournalError::SequenceExhausted)?;
        let body = WalRecordBody {
            schema_version: OPERATION_WAL_SCHEMA_VERSION,
            journal_sequence: next_sequence,
            session_fingerprint: self.session_fingerprint,
            clock_domain: self.clock_domain,
            previous_hash: self.last_record_hash,
            command,
        };
        let record_hash = wal_record_hash(&body)?;
        let record = WalRecord { body, record_hash };
        let encoded = bincode::serialize(&record)
            .map_err(|error| DurableOperationJournalError::Codec(error.to_string()))?;
        if encoded.len() > MAX_OPERATION_WAL_RECORD_BYTES {
            return Err(DurableOperationJournalError::RecordTooLarge);
        }
        let encoded_len = u32::try_from(encoded.len())
            .map_err(|_| DurableOperationJournalError::RecordTooLarge)?;
        let current_len = self.file.metadata()?.len();
        let next_file_len = current_len
            .checked_add(4 + u64::from(encoded_len))
            .ok_or(DurableOperationJournalError::CapacityFull)?;
        if next_file_len > MAX_OPERATION_WAL_BYTES {
            return Err(DurableOperationJournalError::CapacityFull);
        }

        let append_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::End(0))?;
            self.file.write_all(&encoded_len.to_le_bytes())?;
            self.file.write_all(&encoded)?;
            self.file.sync_data()
        })();
        if let Err(error) = append_result {
            self.poisoned = true;
            return Err(DurableOperationJournalError::Io(error));
        }

        self.journal_sequence = next_sequence;
        self.last_record_hash = record_hash;
        self.last_event_tick = Some(at_ticks);
        self.record_head_candidate();
        Ok(())
    }

    fn record_head_candidate(&mut self) {
        let head = self.head_candidate();
        if let Some(last) = self.prefix_heads.last_mut()
            && last.journal_sequence == head.journal_sequence
        {
            *last = head;
        } else {
            self.prefix_heads.push(head);
        }
    }

    fn apply_or_poison(
        &mut self,
        result: Result<OperationSnapshot, OperationEvidenceError>,
    ) -> Result<OperationSnapshot, DurableOperationJournalError> {
        match result {
            Ok(snapshot) => Ok(snapshot),
            Err(_) => {
                self.poisoned = true;
                Err(DurableOperationJournalError::ReplayDivergence)
            }
        }
    }

    fn replay_existing(&mut self) -> Result<(), DurableOperationJournalError> {
        if self.file.metadata()?.len() > MAX_OPERATION_WAL_BYTES {
            return Err(DurableOperationJournalError::CapacityFull);
        }
        let read_file = File::open(&self.path)?;
        let mut reader = BufReader::new(read_file);
        let mut valid_bytes = 0_u64;

        loop {
            let mut length_bytes = [0_u8; 4];
            match reader.read(&mut length_bytes[..1])? {
                0 => break,
                1 => {}
                _ => {
                    return Err(DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    });
                }
            }
            if let Err(error) = reader.read_exact(&mut length_bytes[1..]) {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(DurableOperationJournalError::Io(error));
            }
            let record_len = u32::from_le_bytes(length_bytes) as usize;
            if record_len == 0 || record_len > MAX_OPERATION_WAL_RECORD_BYTES {
                return Err(DurableOperationJournalError::CorruptRecord {
                    sequence: self.journal_sequence.saturating_add(1),
                });
            }
            let mut encoded = vec![0_u8; record_len];
            if let Err(error) = reader.read_exact(&mut encoded) {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(DurableOperationJournalError::Io(error));
            }
            let record: WalRecord = bincode::deserialize(&encoded).map_err(|_| {
                DurableOperationJournalError::CorruptRecord {
                    sequence: self.journal_sequence.saturating_add(1),
                }
            })?;
            let canonical = bincode::serialize(&record)
                .map_err(|error| DurableOperationJournalError::Codec(error.to_string()))?;
            if canonical != encoded {
                return Err(DurableOperationJournalError::CorruptRecord {
                    sequence: self.journal_sequence.saturating_add(1),
                });
            }
            self.verify_record(&record)?;
            self.replay_command(record.body.command)?;
            self.last_record_hash = record.record_hash;
            self.record_head_candidate();
            valid_bytes = valid_bytes.saturating_add(4 + record_len as u64);
        }

        let actual_len = self.file.metadata()?.len();
        if valid_bytes < actual_len {
            self.file.set_len(valid_bytes)?;
            self.file.sync_all()?;
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }

    fn verify_record(&self, record: &WalRecord) -> Result<(), DurableOperationJournalError> {
        if record.body.schema_version != OPERATION_WAL_SCHEMA_VERSION {
            return Err(DurableOperationJournalError::UnsupportedSchema(
                record.body.schema_version,
            ));
        }
        let expected_sequence = self
            .journal_sequence
            .checked_add(1)
            .ok_or(DurableOperationJournalError::SequenceExhausted)?;
        if record.body.session_fingerprint != self.session_fingerprint {
            return Err(DurableOperationJournalError::SessionFingerprintMismatch);
        }
        if record.body.clock_domain != self.clock_domain {
            return Err(DurableOperationJournalError::ClockDomainMismatch);
        }
        if record.body.journal_sequence != expected_sequence
            || record.body.previous_hash != self.last_record_hash
            || record.record_hash != wal_record_hash(&record.body)?
        {
            return Err(DurableOperationJournalError::CorruptRecord {
                sequence: expected_sequence,
            });
        }
        let tick = record.body.command.at_ticks();
        if let Some(previous) = self.last_event_tick
            && tick < previous
        {
            return Err(DurableOperationJournalError::CorruptRecord {
                sequence: expected_sequence,
            });
        }
        Ok(())
    }

    fn replay_command(&mut self, command: WalCommand) -> Result<(), DurableOperationJournalError> {
        let operation_id = OperationId(command.operation_id());
        match command {
            WalCommand::Admit {
                operation_sequence,
                context,
                at_ticks,
                evidence_digest,
                ..
            } => {
                let context = OperationContext::try_from(context)?;
                self.ledger
                    .admit(
                        operation_id,
                        operation_sequence,
                        context,
                        at_ticks,
                        evidence_digest,
                    )
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
                self.operation_ids.insert(operation_id);
                self.last_operation_sequence = Some(operation_sequence);
            }
            WalCommand::Attempted {
                at_ticks,
                evidence_digest,
                ..
            } => {
                self.ledger
                    .mark_attempted(operation_id, at_ticks, evidence_digest)
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
            }
            WalCommand::Committed {
                at_ticks,
                evidence_digest,
                ..
            } => {
                self.ledger
                    .mark_committed(operation_id, at_ticks, evidence_digest)
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
            }
            WalCommand::Observed {
                at_ticks,
                evidence_digest,
                ..
            } => {
                self.ledger
                    .mark_observed(operation_id, at_ticks, evidence_digest)
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
            }
            WalCommand::Rejected {
                at_ticks,
                evidence_digest,
                ..
            } => {
                self.ledger
                    .mark_rejected(operation_id, at_ticks, evidence_digest)
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
            }
            WalCommand::NotCommitted {
                at_ticks,
                evidence_digest,
                ..
            } => {
                self.ledger
                    .mark_not_committed(operation_id, at_ticks, evidence_digest)
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
            }
            WalCommand::Unknown {
                at_ticks,
                evidence_digest,
                ..
            } => {
                self.ledger
                    .mark_unknown(operation_id, at_ticks, evidence_digest)
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
            }
            WalCommand::Reconcile {
                outcome,
                at_ticks,
                receipt_digest,
                ..
            } => {
                self.ledger
                    .reconcile_unknown(operation_id, outcome.into(), at_ticks, receipt_digest)
                    .map_err(|_| DurableOperationJournalError::CorruptRecord {
                        sequence: self.journal_sequence.saturating_add(1),
                    })?;
            }
        }
        let record = self.journal_sequence.saturating_add(1);
        let tick = command.at_ticks();
        // Replay state is applied before the enclosing sequence/hash advances.
        self.last_event_tick = Some(tick);
        self.journal_sequence = record;
        Ok(())
    }

    fn recover_interrupted_attempts(&mut self) -> Result<(), DurableOperationJournalError> {
        let mut interrupted = Vec::new();
        for operation_id in &self.operation_ids {
            let snapshot = self.ledger.snapshot(*operation_id)?;
            if snapshot.state == OperationState::Attempted {
                interrupted.push((*operation_id, snapshot.operation_sequence));
            }
        }
        interrupted.sort_by_key(|(operation_id, _)| operation_id.0);
        for (operation_id, operation_sequence) in interrupted {
            let at_ticks = self
                .last_event_tick
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(DurableOperationJournalError::SequenceExhausted)?;
            let evidence_digest =
                recovery_unknown_digest(operation_id, operation_sequence, self.last_record_hash);
            self.mark_unknown(operation_id, at_ticks, evidence_digest)?;
        }
        Ok(())
    }
}

impl Drop for DurableOperationEvidenceJournal {
    fn drop(&mut self) {
        self.lock_file.take();
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    // Directory fsync is not consistently exposed by std on every platform.
    // The platform qualification document must record this durability limit.
    Ok(())
}

fn lock_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operation");
    path.with_file_name(format!("{file_name}.lock"))
}

fn create_writer_lock(path: &Path) -> Result<File, DurableOperationJournalError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            DurableOperationJournalError::WriterAlreadyActive
        } else {
            DurableOperationJournalError::Io(error)
        }
    })?;
    let process_id = std::process::id().to_le_bytes();
    if let Err(error) = file
        .write_all(&process_id)
        .and_then(|()| file.sync_all())
        .and_then(|()| sync_parent_directory(path))
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(DurableOperationJournalError::Io(error));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xenia-operation-wal-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("create operation WAL test directory: {error}"));
        path
    }

    fn context(session: [u8; 32]) -> OperationContext {
        OperationContext {
            session_fingerprint: session,
            lane: M1Permission::InjectInput,
            direction: OperationDirection::ViewerToHost,
            resource_digest: [3; 32],
            consent_reference_digest: [4; 32],
            policy_digest: [5; 32],
            authority_commitment_digest: Some([6; 32]),
            authority_epoch: Some(7),
        }
    }

    fn operation_id(byte: u8) -> OperationId {
        OperationId([byte; 16])
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn write_ahead_transitions_survive_restart() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [1; 32];
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 100).unwrap();
            journal
                .admit(operation_id(1), 1, context(session), 1, [10; 32])
                .unwrap();
            journal
                .mark_attempted(operation_id(1), 2, [11; 32])
                .unwrap();
            journal
                .mark_committed(operation_id(1), 3, [12; 32])
                .unwrap();
            assert_eq!(
                journal.snapshot(operation_id(1)).unwrap().state,
                OperationState::Committed
            );
            assert!(journal.verify_operation_chain());
        }
        {
            let journal = DurableOperationEvidenceJournal::open(&path, session, 100).unwrap();
            assert_eq!(
                journal.snapshot(operation_id(1)).unwrap().state,
                OperationState::Committed
            );
            assert_eq!(journal.journal_sequence(), 3);
            assert!(journal.verify_operation_chain());
        }
        cleanup(&path);
    }

    #[test]
    fn interrupted_attempt_recovers_as_unknown_and_cannot_be_retried() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [2; 32];
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 101).unwrap();
            journal
                .admit(operation_id(2), 1, context(session), 1, [20; 32])
                .unwrap();
            journal
                .mark_attempted(operation_id(2), 2, [21; 32])
                .unwrap();
        }
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 101).unwrap();
            assert_eq!(
                journal.snapshot(operation_id(2)).unwrap().state,
                OperationState::Unknown
            );
            assert!(matches!(
                journal.mark_attempted(operation_id(2), 4, [22; 32]),
                Err(DurableOperationJournalError::Operation(
                    OperationEvidenceError::InvalidTransition { .. }
                ))
            ));
            assert_eq!(journal.journal_sequence(), 3);
        }
        cleanup(&path);
    }

    #[test]
    fn torn_final_record_is_truncated_to_last_valid_boundary() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [3; 32];
        let valid_len;
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 102).unwrap();
            journal
                .admit(operation_id(3), 1, context(session), 1, [30; 32])
                .unwrap();
            valid_len = journal.file.metadata().unwrap().len();
        }
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0x20, 0x00]).unwrap();
            file.sync_all().unwrap();
        }
        {
            let journal = DurableOperationEvidenceJournal::open(&path, session, 102).unwrap();
            assert_eq!(journal.file.metadata().unwrap().len(), valid_len);
            assert_eq!(
                journal.snapshot(operation_id(3)).unwrap().state,
                OperationState::Admitted
            );
        }
        cleanup(&path);
    }

    #[test]
    fn head_candidate_restores_sequence_and_digest_after_reopen() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [15; 32];
        let first_head = {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 115).unwrap();
            journal
                .admit(operation_id(15), 15, context(session), 1, [150; 32])
                .unwrap();
            let head = journal.head_candidate();
            assert_eq!(head.session_fingerprint, session);
            assert_eq!(head.clock_domain, 115);
            assert_eq!(head.journal_sequence, journal.journal_sequence());
            assert_eq!(head.last_operation_sequence, Some(15));
            assert_ne!(head.wal_chain_digest, [0; 32]);
            head
        };
        let reopened = DurableOperationEvidenceJournal::open(&path, session, 115).unwrap();
        assert_eq!(reopened.head_candidate(), first_head);
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn complete_record_tampering_fails_closed() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [4; 32];
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 103).unwrap();
            journal
                .admit(operation_id(4), 1, context(session), 1, [40; 32])
                .unwrap();
        }
        {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            file.seek(SeekFrom::Start(8)).unwrap();
            file.write_all(&[0xFF]).unwrap();
            file.sync_all().unwrap();
        }
        assert!(matches!(
            DurableOperationEvidenceJournal::open(&path, session, 103),
            Err(DurableOperationJournalError::CorruptRecord { .. })
        ));
        cleanup(&path);
    }

    #[test]
    fn identical_admission_is_idempotent_without_a_second_wal_record() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [12; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 111).unwrap();
        let first = journal
            .admit(operation_id(12), 1, context(session), 1, [120; 32])
            .unwrap();
        let before = journal.journal_sequence();
        let repeated = journal
            .admit(operation_id(12), 1, context(session), 2, [121; 32])
            .unwrap();
        assert!(matches!(first, AdmissionResult::Created(_)));
        assert!(matches!(repeated, AdmissionResult::AlreadyPresent(_)));
        assert_eq!(journal.journal_sequence(), before);
        drop(journal);
        cleanup(&path);
    }

    #[test]
    fn conflicting_operation_id_reuse_is_rejected() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [5; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 104).unwrap();
        journal
            .admit(operation_id(5), 1, context(session), 1, [50; 32])
            .unwrap();
        let mut altered_context = context(session);
        altered_context.resource_digest = [99; 32];
        assert!(matches!(
            journal.admit(operation_id(5), 2, altered_context, 2, [51; 32]),
            Err(DurableOperationJournalError::Operation(
                OperationEvidenceError::OperationIdConflict
            ))
        ));
        drop(journal);
        cleanup(&path);
    }

    #[test]
    fn reserved_wal_space_covers_each_terminal_and_reconciliation_slot() {
        let frame_and_record = reserved_wal_bytes_for_slots(1).unwrap();
        assert_eq!(
            reserved_wal_bytes_for_slots(3).unwrap(),
            frame_and_record.saturating_mul(3)
        );
    }

    #[test]
    fn lifecycle_states_reserve_terminal_and_reconciliation_event_slots() {
        assert_eq!(reserved_event_slots_for_state(OperationState::Admitted), 3);
        assert_eq!(reserved_event_slots_for_state(OperationState::Attempted), 2);
        assert_eq!(reserved_event_slots_for_state(OperationState::Unknown), 1);
        assert_eq!(reserved_event_slots_for_state(OperationState::Committed), 1);
        assert_eq!(
            reserved_event_slots_for_state(OperationState::ReconciledCommitted),
            1
        );
        assert_eq!(reserved_event_slots_for_state(OperationState::Observed), 0);
        assert_eq!(reserved_event_slots_for_state(OperationState::Rejected), 0);
    }

    #[test]
    fn invalid_transition_is_rejected_before_wal_append() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [10; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 109).unwrap();
        journal
            .admit(operation_id(10), 1, context(session), 1, [100; 32])
            .unwrap();
        let before = journal.journal_sequence();
        assert!(matches!(
            journal.mark_committed(operation_id(10), 2, [101; 32]),
            Err(DurableOperationJournalError::Operation(
                OperationEvidenceError::InvalidTransition { .. }
            ))
        ));
        assert_eq!(journal.journal_sequence(), before);
        assert!(!journal.is_poisoned());
        drop(journal);
        cleanup(&path);
    }

    #[test]
    fn regressing_tick_is_rejected_before_wal_append() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [11; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 110).unwrap();
        journal
            .admit(operation_id(11), 1, context(session), 10, [110; 32])
            .unwrap();
        let before = journal.journal_sequence();
        assert!(matches!(
            journal.mark_attempted(operation_id(11), 9, [111; 32]),
            Err(DurableOperationJournalError::ClockRegression {
                previous: 10,
                observed: 9
            })
        ));
        assert_eq!(journal.journal_sequence(), before);
        assert!(!journal.is_poisoned());
        drop(journal);
        cleanup(&path);
    }

    #[test]
    fn second_writer_is_rejected_while_first_writer_is_open() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [6; 32];
        let _first = DurableOperationEvidenceJournal::open(&path, session, 105).unwrap();
        assert!(matches!(
            DurableOperationEvidenceJournal::open(&path, session, 105),
            Err(DurableOperationJournalError::WriterAlreadyActive)
        ));
        drop(_first);
        cleanup(&path);
    }

    #[test]
    fn reconciliation_receipt_survives_restart_and_is_idempotent() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [7; 32];
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 106).unwrap();
            journal
                .admit(operation_id(7), 1, context(session), 1, [70; 32])
                .unwrap();
            journal
                .mark_attempted(operation_id(7), 2, [71; 32])
                .unwrap();
            journal.mark_unknown(operation_id(7), 3, [72; 32]).unwrap();
            journal
                .reconcile_unknown(
                    operation_id(7),
                    ReconciliationOutcome::Committed,
                    4,
                    [73; 32],
                )
                .unwrap();
        }
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 106).unwrap();
            let snapshot = journal.snapshot(operation_id(7)).unwrap();
            assert_eq!(snapshot.state, OperationState::ReconciledCommitted);
            assert_eq!(snapshot.reconciliation_digest, Some([73; 32]));
            let repeated = journal
                .reconcile_unknown(
                    operation_id(7),
                    ReconciliationOutcome::Committed,
                    5,
                    [73; 32],
                )
                .unwrap();
            assert_eq!(repeated, snapshot);
        }
        cleanup(&path);
    }

    #[test]
    fn open_rejects_session_or_clock_domain_mismatch() {
        let dir = temp_dir();
        let path = dir.join("session.wal");
        let session = [8; 32];
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 107).unwrap();
            journal
                .admit(operation_id(8), 1, context(session), 1, [80; 32])
                .unwrap();
        }
        assert!(matches!(
            DurableOperationEvidenceJournal::open(&path, [9; 32], 107),
            Err(DurableOperationJournalError::CorruptRecord { .. })
                | Err(DurableOperationJournalError::SessionFingerprintMismatch)
        ));
        assert!(matches!(
            DurableOperationEvidenceJournal::open(&path, session, 108),
            Err(DurableOperationJournalError::CorruptRecord { .. })
                | Err(DurableOperationJournalError::ClockDomainMismatch)
        ));
        cleanup(&path);
    }
}
