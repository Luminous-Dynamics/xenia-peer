// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Consent-specific recovery summaries for archived ledger prefixes.
//!
//! The generic ledger crate proves archive integrity but intentionally does not
//! understand Xenia's authorization semantics. This module derives the minimum
//! state a future pruning implementation must retain: every signed decision
//! action id for replay refusal, every completed session, approval provenance,
//! and the exact archive boundary. A summary is accepted only when the archive
//! begins at genesis and every consent ceremony in the archived prefix is
//! terminal; active or ambiguous authorization state remains in the live log.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{SigningKey as LedgerSigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_ledger::{
    checkpoint_fingerprint, ledger_archive_sequence_digest, Chain, CheckpointContinuityError,
    ConsentKind, LedgerArchiveError, LedgerArchiveSegment, LedgerCheckpoint,
    LedgerCompactionError, LedgerCompactionManifest, LedgerEntry, Verifier,
};

const CONSENT_RECOVERY_SUMMARY_SCHEMA: &str = "xenia-consent-recovery-summary-v1";
const MAX_RECOVERY_ACTION_IDS: usize = 100_000;
const MAX_RECOVERY_SESSIONS: usize = 100_000;

pub(crate) const CONSENT_COMPACTION_BUNDLE_SCHEMA: &str =
    "xenia-consent-compaction-bundle-v1";
pub(crate) const CONSENT_COMPACTED_SNAPSHOT_SCHEMA: &str =
    "xenia-consent-compacted-snapshot-v1";
pub(crate) const MAX_CONSENT_COMPACTION_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES: usize = 100_000;
pub(crate) const CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA: &str =
    "xenia-consent-compacted-active-state-v1";

/// One completed consent ceremony retained after its detailed entries move to
/// verified cold storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRecoverySessionV1 {
    pub(crate) session_id: [u8; 16],
    pub(crate) terminal_event: String,
    pub(crate) terminal_sequence: u64,
    pub(crate) approving_operator_key: Option<[u8; 32]>,
    pub(crate) approval_action_id: Option<[u8; 16]>,
}

/// Deterministic replay and recovery state derived from a complete archived
/// ledger prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRecoverySummaryV1 {
    pub(crate) schema: String,
    pub(crate) archive_sequence_digest: [u8; 32],
    pub(crate) through_checkpoint: LedgerCheckpoint,
    pub(crate) archived_entry_count: u64,
    pub(crate) replay_action_ids: Vec<[u8; 16]>,
    pub(crate) sessions: Vec<ConsentRecoverySessionV1>,
    pub(crate) summary_digest: [u8; 32],
}

/// Non-destructive compaction preflight artifact. Every detailed archived entry
/// remains embedded and independently verifiable; the recovery summary and
/// signed manifest prove what state a future pruning implementation would need
/// to retain before it is permitted to remove that prefix from live storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentCompactionBundleV1 {
    pub(crate) schema: String,
    pub(crate) archive_segments: Vec<LedgerArchiveSegment>,
    pub(crate) recovery_summary: ConsentRecoverySummaryV1,
    pub(crate) manifest: LedgerCompactionManifest,
}

/// Minimal restore artifact for a future compacted live ledger.
///
/// Detailed prefix entries remain in independently verified archive segments.
/// This snapshot retains only the deterministic recovery summary, the
/// ledger-signed compaction manifest, and the authenticated live suffix after
/// the archived boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentCompactedSnapshotV1 {
    pub(crate) schema: String,
    pub(crate) recovery_summary: ConsentRecoverySummaryV1,
    pub(crate) manifest: LedgerCompactionManifest,
    pub(crate) suffix_entries: Vec<LedgerEntry>,
    pub(crate) snapshot_digest: [u8; 32],
}

/// Durable, appendable consent-ledger state after a verified compaction
/// activation. The original snapshot remains immutable as the signed cutover
/// statement, while `resident_entries` and `current_checkpoint` advance
/// together on each later transactional append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentCompactedActiveStateV1 {
    pub(crate) schema: String,
    pub(crate) activation_snapshot: ConsentCompactedSnapshotV1,
    pub(crate) current_checkpoint: LedgerCheckpoint,
    pub(crate) resident_entries: Vec<LedgerEntry>,
    pub(crate) archived_replay_action_ids: Vec<[u8; 16]>,
    pub(crate) archived_terminal_sessions: Vec<[u8; 16]>,
    pub(crate) state_digest: [u8; 32],
}

/// Fully verified in-memory restore frontier for a compacted consent ledger.
///
/// The chain contains only the resident suffix but retains the signed archive
/// boundary as its append anchor. Replay and terminal-session indexes are
/// derived from the authenticated recovery summary and must be consulted before
/// accepting any new operator action in a future activation path.
pub(crate) struct RestoredConsentStateV1 {
    pub(crate) chain: Chain,
    archived_replay_action_ids: BTreeSet<[u8; 16]>,
    archived_terminal_sessions: BTreeSet<[u8; 16]>,
}

impl RestoredConsentStateV1 {
    pub(crate) fn archived_replay_action_count(&self) -> usize {
        self.archived_replay_action_ids.len()
    }

    pub(crate) fn archived_terminal_session_count(&self) -> usize {
        self.archived_terminal_sessions.len()
    }

    /// Consume the verified restore frontier so startup can materialize the
    /// historical replay and session indexes before opening any listener.
    pub(crate) fn into_parts(
        self,
    ) -> (Chain, BTreeSet<[u8; 16]>, BTreeSet<[u8; 16]>) {
        (
            self.chain,
            self.archived_replay_action_ids,
            self.archived_terminal_sessions,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionPhase {
    Pending,
    Approved,
    Terminal,
}

#[derive(Debug, Clone)]
struct SessionAccumulator {
    phase: SessionPhase,
    approving_operator_key: Option<[u8; 32]>,
    approval_action_id: Option<[u8; 16]>,
    terminal_event: Option<String>,
    terminal_sequence: Option<u64>,
}

impl SessionAccumulator {
    fn pending() -> Self {
        Self {
            phase: SessionPhase::Pending,
            approving_operator_key: None,
            approval_action_id: None,
            terminal_event: None,
            terminal_sequence: None,
        }
    }
}

/// Why an archived prefix could not produce trustworthy recovery state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConsentRecoveryError {
    #[error("consent recovery archive verification failed: {0}")]
    Archive(#[from] LedgerArchiveError),
    #[error("consent recovery archive sequence must begin at ledger genesis")]
    NonGenesisBase,
    #[error("consent recovery action id appears more than once: {action_id}")]
    DuplicateActionId { action_id: String },
    #[error(
        "consent recovery contains an invalid transition for session {session_id} at seq {seq}"
    )]
    InvalidTransition { session_id: String, seq: u64 },
    #[error("consent recovery session {session_id} is not terminal at archive boundary")]
    IncompleteSession { session_id: String },
    #[error("consent recovery has {count} action ids; maximum is {maximum}")]
    TooManyActionIds { count: usize, maximum: usize },
    #[error("consent recovery has {count} sessions; maximum is {maximum}")]
    TooManySessions { count: usize, maximum: usize },
    #[error("consent recovery summary digest mismatch")]
    DigestMismatch,
    #[error("consent recovery summary does not match the verified archive sequence")]
    SummaryMismatch,
    #[error("unsupported consent compaction bundle schema: {schema}")]
    UnsupportedBundleSchema { schema: String },
    #[error("consent compaction manifest does not bind the archive sequence")]
    ManifestArchiveMismatch,
    #[error("consent compaction manifest does not bind the recovery summary")]
    ManifestRecoveryMismatch,
    #[error("consent compaction manifest archive boundary does not match the summary")]
    ManifestBoundaryMismatch,
    #[error("consent compaction archived entry count does not fit this platform")]
    ArchivedEntryCountOverflow,
    #[error("consent compacted suffix has {count} entries; maximum is {maximum}")]
    TooManySuffixEntries { count: usize, maximum: usize },
    #[error("unsupported consent compacted snapshot schema: {schema}")]
    UnsupportedSnapshotSchema { schema: String },
    #[error("consent compacted snapshot digest mismatch")]
    SnapshotDigestMismatch,
    #[error("consent compacted restore signing key does not match the authenticated ledger key")]
    RestoreSigningKeyMismatch,
    #[error("signed decision action id {action_id} reappears at sequence {seq}")]
    SignedDecisionReplay { action_id: String, seq: u64 },
    #[error("terminal archived session {session_id} reappears at sequence {seq}")]
    ArchivedSessionReused { session_id: String, seq: u64 },
    #[error("unsupported consent compacted active-state schema: {schema}")]
    UnsupportedActiveStateSchema { schema: String },
    #[error("consent compacted active-state digest mismatch")]
    ActiveStateDigestMismatch,
    #[error("consent compacted active-state archived replay index mismatch")]
    ActiveReplayIndexMismatch,
    #[error("consent compacted active-state archived terminal-session index mismatch")]
    ActiveTerminalIndexMismatch,
    #[error("consent compacted active-state does not preserve the activation suffix")]
    ActivationSuffixMismatch,
    #[error("consent compacted active-state chain anchor does not match the recovery summary")]
    ActiveAnchorMismatch,
    #[error("consent compaction manifest verification failed: {0}")]
    Manifest(#[from] LedgerCompactionError),
    #[error("consent recovery checkpoint fingerprint failed: {0}")]
    Checkpoint(#[from] xenia_ledger::CheckpointError),
    #[error("consent compacted suffix continuity failed: {0}")]
    Continuity(#[from] CheckpointContinuityError),
}

impl ConsentRecoverySummaryV1 {
    /// Derive deterministic replay and session state from a verified complete
    /// prefix beginning at genesis.
    pub(crate) fn from_archive_sequence(
        segments: &[LedgerArchiveSegment],
    ) -> Result<Self, ConsentRecoveryError> {
        let archive_sequence_digest = ledger_archive_sequence_digest(segments)?;
        let first = segments.first().ok_or(LedgerArchiveError::EmptySequence)?;
        if first.base_checkpoint.entry_count != 0 || first.base_checkpoint.head_hash != [0u8; 32] {
            return Err(ConsentRecoveryError::NonGenesisBase);
        }
        let through_checkpoint = segments
            .last()
            .expect("verified non-empty archive sequence")
            .terminal_checkpoint
            .clone();

        let mut replay_action_ids = BTreeSet::new();
        let mut sessions: BTreeMap<[u8; 16], SessionAccumulator> = BTreeMap::new();

        for entry in segments.iter().flat_map(|segment| segment.entries.iter()) {
            let session_id = *entry.event.session_id.as_bytes();
            let request_id = *entry.event.request_id.as_bytes();
            let is_signed_decision = matches!(
                entry.event.kind,
                ConsentKind::Approval | ConsentKind::Denial | ConsentKind::Revocation
            );
            if is_signed_decision && !replay_action_ids.insert(request_id) {
                return Err(ConsentRecoveryError::DuplicateActionId {
                    action_id: hex::encode(request_id),
                });
            }
            if replay_action_ids.len() > MAX_RECOVERY_ACTION_IDS {
                return Err(ConsentRecoveryError::TooManyActionIds {
                    count: replay_action_ids.len(),
                    maximum: MAX_RECOVERY_ACTION_IDS,
                });
            }

            match entry.event.kind {
                ConsentKind::Request => {
                    let state = sessions
                        .entry(session_id)
                        .or_insert_with(SessionAccumulator::pending);
                    if state.phase != SessionPhase::Pending {
                        return Err(invalid_transition(session_id, entry.seq));
                    }
                }
                ConsentKind::Approval => {
                    let state = sessions
                        .entry(session_id)
                        .or_insert_with(SessionAccumulator::pending);
                    if state.phase != SessionPhase::Pending {
                        return Err(invalid_transition(session_id, entry.seq));
                    }
                    state.phase = SessionPhase::Approved;
                    state.approving_operator_key = Some(entry.event.source_id);
                    state.approval_action_id = Some(request_id);
                }
                ConsentKind::Denial => {
                    let state = sessions
                        .entry(session_id)
                        .or_insert_with(SessionAccumulator::pending);
                    if state.phase != SessionPhase::Pending {
                        return Err(invalid_transition(session_id, entry.seq));
                    }
                    state.phase = SessionPhase::Terminal;
                    state.terminal_event = Some(entry.event.stable_name().to_string());
                    state.terminal_sequence = Some(entry.seq);
                }
                ConsentKind::Revocation => {
                    let state = sessions
                        .entry(session_id)
                        .or_insert_with(SessionAccumulator::pending);
                    if state.phase == SessionPhase::Terminal {
                        return Err(invalid_transition(session_id, entry.seq));
                    }
                    state.phase = SessionPhase::Terminal;
                    state.terminal_event = Some(entry.event.stable_name().to_string());
                    state.terminal_sequence = Some(entry.seq);
                }
                ConsentKind::Violation | ConsentKind::LifecycleTermination => {
                    let state = sessions
                        .entry(session_id)
                        .or_insert_with(SessionAccumulator::pending);
                    if state.phase == SessionPhase::Terminal {
                        return Err(invalid_transition(session_id, entry.seq));
                    }
                    state.phase = SessionPhase::Terminal;
                    state.terminal_event = Some(entry.event.stable_name().to_string());
                    state.terminal_sequence = Some(entry.seq);
                }
                ConsentKind::AthenaTriage | ConsentKind::AuthorizationBinding => {
                    // These are signed audit facts but do not themselves open or
                    // close a consent ceremony in the operator ledger.
                }
            }
            if sessions.len() > MAX_RECOVERY_SESSIONS {
                return Err(ConsentRecoveryError::TooManySessions {
                    count: sessions.len(),
                    maximum: MAX_RECOVERY_SESSIONS,
                });
            }
        }

        let mut completed = Vec::with_capacity(sessions.len());
        for (session_id, state) in sessions {
            if state.phase != SessionPhase::Terminal {
                return Err(ConsentRecoveryError::IncompleteSession {
                    session_id: hex::encode(session_id),
                });
            }
            completed.push(ConsentRecoverySessionV1 {
                session_id,
                terminal_event: state
                    .terminal_event
                    .expect("terminal session has terminal event"),
                terminal_sequence: state
                    .terminal_sequence
                    .expect("terminal session has terminal sequence"),
                approving_operator_key: state.approving_operator_key,
                approval_action_id: state.approval_action_id,
            });
        }

        let mut summary = Self {
            schema: CONSENT_RECOVERY_SUMMARY_SCHEMA.to_string(),
            archive_sequence_digest,
            archived_entry_count: through_checkpoint.entry_count,
            through_checkpoint,
            replay_action_ids: replay_action_ids.into_iter().collect(),
            sessions: completed,
            summary_digest: [0u8; 32],
        };
        summary.summary_digest = consent_recovery_summary_digest(&summary)?;
        Ok(summary)
    }

    /// Recompute the summary from the archive and require byte-for-byte semantic equality.
    pub(crate) fn verify_against_archive(
        &self,
        segments: &[LedgerArchiveSegment],
    ) -> Result<(), ConsentRecoveryError> {
        let observed_digest = consent_recovery_summary_digest(self)?;
        if observed_digest != self.summary_digest {
            return Err(ConsentRecoveryError::DigestMismatch);
        }
        let expected = Self::from_archive_sequence(segments)?;
        if &expected != self {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        Ok(())
    }

    /// Verify the self-contained, signed-summary representation without
    /// reopening cold archive files. The compaction manifest authenticates the
    /// resulting digest; activation must still have performed the stronger
    /// archive-backed verification first.
    pub(crate) fn verify_self(&self) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_RECOVERY_SUMMARY_SCHEMA {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        if self.replay_action_ids.len() > MAX_RECOVERY_ACTION_IDS {
            return Err(ConsentRecoveryError::TooManyActionIds {
                count: self.replay_action_ids.len(),
                maximum: MAX_RECOVERY_ACTION_IDS,
            });
        }
        if self.sessions.len() > MAX_RECOVERY_SESSIONS {
            return Err(ConsentRecoveryError::TooManySessions {
                count: self.sessions.len(),
                maximum: MAX_RECOVERY_SESSIONS,
            });
        }
        if !self.replay_action_ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        if !self.sessions.windows(2).all(|pair| pair[0].session_id < pair[1].session_id) {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        if self.archived_entry_count != self.through_checkpoint.entry_count {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        let observed_digest = consent_recovery_summary_digest(self)?;
        if observed_digest != self.summary_digest {
            return Err(ConsentRecoveryError::DigestMismatch);
        }
        Ok(())
    }
}

impl ConsentCompactionBundleV1 {
    /// Build and sign a preflight bundle from verified archive segments and the
    /// current complete live ledger. This operation never mutates the ledger.
    pub(crate) fn build(
        chain: &Chain,
        archive_segments: Vec<LedgerArchiveSegment>,
        timestamp_unix_secs: u64,
    ) -> Result<Self, ConsentRecoveryError> {
        let recovery_summary =
            ConsentRecoverySummaryV1::from_archive_sequence(&archive_segments)?;
        let manifest = chain.sign_compaction_manifest(
            recovery_summary.through_checkpoint.clone(),
            recovery_summary.archive_sequence_digest,
            recovery_summary.summary_digest,
            timestamp_unix_secs,
        )?;
        let bundle = Self {
            schema: CONSENT_COMPACTION_BUNDLE_SCHEMA.to_string(),
            archive_segments,
            recovery_summary,
            manifest,
        };
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        bundle.verify_suffix_compatibility(&entries)?;
        Ok(bundle)
    }

    /// Verify the archive, recovery summary, signed manifest, and current live
    /// ledger as one indivisible preflight statement.
    pub(crate) fn verify_against_live_ledger(
        &self,
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTION_BUNDLE_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedBundleSchema {
                schema: self.schema.clone(),
            });
        }
        self.recovery_summary
            .verify_against_archive(&self.archive_segments)?;
        if self.manifest.archive_sequence_digest
            != self.recovery_summary.archive_sequence_digest
        {
            return Err(ConsentRecoveryError::ManifestArchiveMismatch);
        }
        if self.manifest.recovery_summary_digest != self.recovery_summary.summary_digest {
            return Err(ConsentRecoveryError::ManifestRecoveryMismatch);
        }
        if self.manifest.archived_through_checkpoint
            != self.recovery_summary.through_checkpoint
        {
            return Err(ConsentRecoveryError::ManifestBoundaryMismatch);
        }
        Verifier::verify_ledger_compaction_manifest_against_entries(
            &self.manifest,
            entries,
            public_key,
        )?;
        self.verify_suffix_compatibility(entries)
    }

    fn verify_suffix_compatibility(
        &self,
        entries: &[LedgerEntry],
    ) -> Result<(), ConsentRecoveryError> {
        let archived_entry_count = usize::try_from(self.recovery_summary.archived_entry_count)
            .map_err(|_| ConsentRecoveryError::ArchivedEntryCountOverflow)?;
        let suffix = entries
            .get(archived_entry_count..)
            .ok_or(ConsentRecoveryError::SummaryMismatch)?;
        verify_recovery_suffix_compatibility(&self.recovery_summary, suffix)
    }
}

impl ConsentCompactedSnapshotV1 {
    /// Build a minimal suffix snapshot from a fully verified preflight bundle
    /// and the complete live ledger. This operation does not mutate storage.
    pub(crate) fn build(
        bundle: &ConsentCompactionBundleV1,
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<Self, ConsentRecoveryError> {
        bundle.verify_against_live_ledger(entries, public_key)?;
        let archived_entry_count = usize::try_from(bundle.recovery_summary.archived_entry_count)
            .map_err(|_| ConsentRecoveryError::ArchivedEntryCountOverflow)?;
        let suffix_entries = entries
            .get(archived_entry_count..)
            .ok_or(ConsentRecoveryError::SummaryMismatch)?
            .to_vec();
        if suffix_entries.len() > MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES {
            return Err(ConsentRecoveryError::TooManySuffixEntries {
                count: suffix_entries.len(),
                maximum: MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES,
            });
        }
        let mut snapshot = Self {
            schema: CONSENT_COMPACTED_SNAPSHOT_SCHEMA.to_string(),
            recovery_summary: bundle.recovery_summary.clone(),
            manifest: bundle.manifest.clone(),
            suffix_entries,
            snapshot_digest: [0u8; 32],
        };
        snapshot.snapshot_digest = consent_compacted_snapshot_digest(&snapshot)?;
        Ok(snapshot)
    }

    /// Verify the archived recovery state, signed boundary manifest, exact
    /// resident suffix, and snapshot commitment without requiring the complete
    /// pre-compaction live ledger.
    pub(crate) fn verify(
        &self,
        archive_segments: &[LedgerArchiveSegment],
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTED_SNAPSHOT_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedSnapshotSchema {
                schema: self.schema.clone(),
            });
        }
        if self.suffix_entries.len() > MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES {
            return Err(ConsentRecoveryError::TooManySuffixEntries {
                count: self.suffix_entries.len(),
                maximum: MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES,
            });
        }
        if consent_compacted_snapshot_digest(self)? != self.snapshot_digest {
            return Err(ConsentRecoveryError::SnapshotDigestMismatch);
        }
        self.recovery_summary
            .verify_against_archive(archive_segments)?;
        if self.manifest.archive_sequence_digest
            != self.recovery_summary.archive_sequence_digest
        {
            return Err(ConsentRecoveryError::ManifestArchiveMismatch);
        }
        if self.manifest.recovery_summary_digest != self.recovery_summary.summary_digest {
            return Err(ConsentRecoveryError::ManifestRecoveryMismatch);
        }
        if self.manifest.archived_through_checkpoint
            != self.recovery_summary.through_checkpoint
        {
            return Err(ConsentRecoveryError::ManifestBoundaryMismatch);
        }
        Verifier::verify_ledger_compaction_manifest(&self.manifest)?;
        if self.manifest.current_checkpoint.ledger_public_key != public_key.to_bytes() {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        Verifier::verify_checkpoint_extension(
            &self.recovery_summary.through_checkpoint,
            &self.manifest.current_checkpoint,
            &self.suffix_entries,
        )?;
        verify_recovery_suffix_compatibility(&self.recovery_summary, &self.suffix_entries)
    }

    /// Verify the immutable signed activation frontier without reopening the
    /// detailed cold archive. This is safe only after an archive-backed
    /// activation step has produced the durable state: the recovery-summary
    /// digest is signed by the compaction manifest, the activation suffix is
    /// fully signature-checked, and the manifest checkpoint must terminate at
    /// that suffix.
    pub(crate) fn verify_signed_frontier(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTED_SNAPSHOT_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedSnapshotSchema {
                schema: self.schema.clone(),
            });
        }
        if self.suffix_entries.len() > MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES {
            return Err(ConsentRecoveryError::TooManySuffixEntries {
                count: self.suffix_entries.len(),
                maximum: MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES,
            });
        }
        if consent_compacted_snapshot_digest(self)? != self.snapshot_digest {
            return Err(ConsentRecoveryError::SnapshotDigestMismatch);
        }
        self.recovery_summary.verify_self()?;
        if self.manifest.archive_sequence_digest
            != self.recovery_summary.archive_sequence_digest
        {
            return Err(ConsentRecoveryError::ManifestArchiveMismatch);
        }
        if self.manifest.recovery_summary_digest != self.recovery_summary.summary_digest {
            return Err(ConsentRecoveryError::ManifestRecoveryMismatch);
        }
        if self.manifest.archived_through_checkpoint
            != self.recovery_summary.through_checkpoint
        {
            return Err(ConsentRecoveryError::ManifestBoundaryMismatch);
        }
        Verifier::verify_ledger_compaction_manifest(&self.manifest)?;
        if self.manifest.current_checkpoint.ledger_public_key != public_key.to_bytes() {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        Verifier::verify_checkpoint_extension(
            &self.recovery_summary.through_checkpoint,
            &self.manifest.current_checkpoint,
            &self.suffix_entries,
        )?;
        verify_recovery_suffix_compatibility(&self.recovery_summary, &self.suffix_entries)
    }

    /// Verify and materialize the exact append frontier and archived recovery
    /// indexes needed by a future compacted-ledger activation path.
    pub(crate) fn restore_state(
        &self,
        archive_segments: &[LedgerArchiveSegment],
        signing_key: &LedgerSigningKey,
    ) -> Result<RestoredConsentStateV1, ConsentRecoveryError> {
        let public_key = signing_key.verifying_key();
        if self.manifest.current_checkpoint.ledger_public_key != public_key.to_bytes() {
            return Err(ConsentRecoveryError::RestoreSigningKeyMismatch);
        }
        self.verify(archive_segments, &public_key)?;
        let archived_replay_action_ids = self
            .recovery_summary
            .replay_action_ids
            .iter()
            .copied()
            .collect();
        let archived_terminal_sessions = self
            .recovery_summary
            .sessions
            .iter()
            .map(|session| session.session_id)
            .collect();
        let chain = Chain::from_checkpoint_suffix(
            self.recovery_summary.through_checkpoint.clone(),
            self.suffix_entries.clone(),
            signing_key.clone(),
        );
        Ok(RestoredConsentStateV1 {
            chain,
            archived_replay_action_ids,
            archived_terminal_sessions,
        })
    }
}

impl ConsentCompactedActiveStateV1 {
    /// Activate a verified compacted snapshot. Cold archive segments are
    /// required here; later startup can verify the signed active state without
    /// repeatedly opening those archive files.
    pub(crate) fn activate(
        snapshot: ConsentCompactedSnapshotV1,
        archive_segments: &[LedgerArchiveSegment],
        signing_key: &LedgerSigningKey,
        timestamp_unix_secs: u64,
    ) -> Result<Self, ConsentRecoveryError> {
        let restored = snapshot.restore_state(archive_segments, signing_key)?;
        let archived_replay_action_ids = restored
            .archived_replay_action_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let archived_terminal_sessions = restored
            .archived_terminal_sessions
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let current_checkpoint = restored.chain.sign_checkpoint(timestamp_unix_secs);
        let resident_entries = restored.chain.iter().cloned().collect();
        let mut state = Self {
            schema: CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA.to_string(),
            activation_snapshot: snapshot,
            current_checkpoint,
            resident_entries,
            archived_replay_action_ids,
            archived_terminal_sessions,
            state_digest: [0u8; 32],
        };
        state.state_digest = consent_compacted_active_state_digest(&state)?;
        state.verify(&signing_key.verifying_key())?;
        Ok(state)
    }

    /// Verify a durable active state using only its signed activation frontier
    /// and current resident suffix. Rollback protection still requires an
    /// independently retained checkpoint or witness, as with an ordinary live
    /// ledger file.
    pub(crate) fn verify(
        &self,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedActiveStateSchema {
                schema: self.schema.clone(),
            });
        }
        if self.resident_entries.len() > MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES {
            return Err(ConsentRecoveryError::TooManySuffixEntries {
                count: self.resident_entries.len(),
                maximum: MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES,
            });
        }
        if consent_compacted_active_state_digest(self)? != self.state_digest {
            return Err(ConsentRecoveryError::ActiveStateDigestMismatch);
        }
        self.activation_snapshot.verify_signed_frontier(public_key)?;
        if self.current_checkpoint.ledger_public_key != public_key.to_bytes() {
            return Err(ConsentRecoveryError::RestoreSigningKeyMismatch);
        }
        let expected_replay = self
            .activation_snapshot
            .recovery_summary
            .replay_action_ids
            .clone();
        if self.archived_replay_action_ids != expected_replay {
            return Err(ConsentRecoveryError::ActiveReplayIndexMismatch);
        }
        let expected_terminal = self
            .activation_snapshot
            .recovery_summary
            .sessions
            .iter()
            .map(|session| session.session_id)
            .collect::<Vec<_>>();
        if self.archived_terminal_sessions != expected_terminal {
            return Err(ConsentRecoveryError::ActiveTerminalIndexMismatch);
        }
        let base = &self.activation_snapshot.recovery_summary.through_checkpoint;
        if self.current_checkpoint.entry_count < base.entry_count {
            return Err(ConsentRecoveryError::ActiveAnchorMismatch);
        }
        Verifier::verify_checkpoint_extension(
            base,
            &self.current_checkpoint,
            &self.resident_entries,
        )?;
        let activation_len = self.activation_snapshot.suffix_entries.len();
        let activation_prefix = self
            .resident_entries
            .get(..activation_len)
            .ok_or(ConsentRecoveryError::ActivationSuffixMismatch)?;
        if activation_prefix != self.activation_snapshot.suffix_entries.as_slice() {
            return Err(ConsentRecoveryError::ActivationSuffixMismatch);
        }
        verify_recovery_suffix_compatibility(
            &self.activation_snapshot.recovery_summary,
            &self.resident_entries,
        )
    }

    /// Rebuild the durable envelope after a successful append to the anchored
    /// chain. The immutable activation snapshot and archived indexes must never
    /// change after cutover.
    pub(crate) fn advance_from_chain(
        &self,
        chain: &Chain,
        timestamp_unix_secs: u64,
    ) -> Result<Self, ConsentRecoveryError> {
        let expected_anchor = &self.activation_snapshot.recovery_summary.through_checkpoint;
        if chain.base_checkpoint() != Some(expected_anchor) {
            return Err(ConsentRecoveryError::ActiveAnchorMismatch);
        }
        let mut next = Self {
            schema: CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA.to_string(),
            activation_snapshot: self.activation_snapshot.clone(),
            current_checkpoint: chain.sign_checkpoint(timestamp_unix_secs),
            resident_entries: chain.iter().cloned().collect(),
            archived_replay_action_ids: self.archived_replay_action_ids.clone(),
            archived_terminal_sessions: self.archived_terminal_sessions.clone(),
            state_digest: [0u8; 32],
        };
        next.state_digest = consent_compacted_active_state_digest(&next)?;
        let public_key = VerifyingKey::from_bytes(&next.current_checkpoint.ledger_public_key)
            .map_err(|_| ConsentRecoveryError::SummaryMismatch)?;
        next.verify(&public_key)?;
        Ok(next)
    }

    /// Materialize the verified append frontier and historical indexes before
    /// any consent transport is allowed to accept an action.
    pub(crate) fn restore_state(
        &self,
        signing_key: &LedgerSigningKey,
    ) -> Result<RestoredConsentStateV1, ConsentRecoveryError> {
        let public_key = signing_key.verifying_key();
        self.verify(&public_key)?;
        let chain = Chain::from_checkpoint_suffix(
            self.activation_snapshot
                .recovery_summary
                .through_checkpoint
                .clone(),
            self.resident_entries.clone(),
            signing_key.clone(),
        );
        Ok(RestoredConsentStateV1 {
            chain,
            archived_replay_action_ids: self
                .archived_replay_action_ids
                .iter()
                .copied()
                .collect(),
            archived_terminal_sessions: self
                .archived_terminal_sessions
                .iter()
                .copied()
                .collect(),
        })
    }
}

fn verify_recovery_suffix_compatibility(
    recovery_summary: &ConsentRecoverySummaryV1,
    suffix: &[LedgerEntry],
) -> Result<(), ConsentRecoveryError> {
    let mut seen_action_ids = recovery_summary
        .replay_action_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let archived_sessions = recovery_summary
        .sessions
        .iter()
        .map(|session| session.session_id)
        .collect::<BTreeSet<_>>();

    for entry in suffix {
        let session_id = *entry.event.session_id.as_bytes();
        if archived_sessions.contains(&session_id) {
            return Err(ConsentRecoveryError::ArchivedSessionReused {
                session_id: hex::encode(session_id),
                seq: entry.seq,
            });
        }
        if matches!(
            entry.event.kind,
            ConsentKind::Approval | ConsentKind::Denial | ConsentKind::Revocation
        ) {
            let action_id = *entry.event.request_id.as_bytes();
            if !seen_action_ids.insert(action_id) {
                return Err(ConsentRecoveryError::SignedDecisionReplay {
                    action_id: hex::encode(action_id),
                    seq: entry.seq,
                });
            }
        }
    }
    Ok(())
}

fn invalid_transition(session_id: [u8; 16], seq: u64) -> ConsentRecoveryError {
    ConsentRecoveryError::InvalidTransition {
        session_id: hex::encode(session_id),
        seq,
    }
}

fn consent_recovery_summary_digest(
    summary: &ConsentRecoverySummaryV1,
) -> Result<[u8; 32], ConsentRecoveryError> {
    if summary.schema != CONSENT_RECOVERY_SUMMARY_SCHEMA {
        return Err(ConsentRecoveryError::SummaryMismatch);
    }
    let checkpoint = checkpoint_fingerprint(&summary.through_checkpoint)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-recovery-summary:v1");
    hasher.update(&[0]);
    hasher.update(summary.schema.as_bytes());
    hasher.update(&[0]);
    hasher.update(&summary.archive_sequence_digest);
    hasher.update(&checkpoint);
    hasher.update(&summary.archived_entry_count.to_be_bytes());
    hasher.update(&(summary.replay_action_ids.len() as u64).to_be_bytes());
    for action_id in &summary.replay_action_ids {
        hasher.update(action_id);
    }
    hasher.update(&(summary.sessions.len() as u64).to_be_bytes());
    for session in &summary.sessions {
        hasher.update(&session.session_id);
        hasher.update(&(session.terminal_event.len() as u64).to_be_bytes());
        hasher.update(session.terminal_event.as_bytes());
        hasher.update(&session.terminal_sequence.to_be_bytes());
        match session.approving_operator_key {
            Some(key) => {
                hasher.update(&[1]);
                hasher.update(&key);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        match session.approval_action_id {
            Some(action_id) => {
                hasher.update(&[1]);
                hasher.update(&action_id);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn consent_compacted_snapshot_digest(
    snapshot: &ConsentCompactedSnapshotV1,
) -> Result<[u8; 32], ConsentRecoveryError> {
    if snapshot.schema != CONSENT_COMPACTED_SNAPSHOT_SCHEMA {
        return Err(ConsentRecoveryError::UnsupportedSnapshotSchema {
            schema: snapshot.schema.clone(),
        });
    }
    let archived = checkpoint_fingerprint(&snapshot.manifest.archived_through_checkpoint)?;
    let current = checkpoint_fingerprint(&snapshot.manifest.current_checkpoint)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-compacted-snapshot:v1");
    hasher.update(&[0]);
    hasher.update(snapshot.schema.as_bytes());
    hasher.update(&[0]);
    hasher.update(&snapshot.recovery_summary.summary_digest);
    hasher.update(&snapshot.recovery_summary.archive_sequence_digest);
    hasher.update(&archived);
    hasher.update(&current);
    hasher.update(&snapshot.manifest.signature);
    hasher.update(&(snapshot.suffix_entries.len() as u64).to_be_bytes());
    for entry in &snapshot.suffix_entries {
        hasher.update(&entry.seq.to_be_bytes());
        hasher.update(&entry.entry_hash);
        hasher.update(&entry.signature);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn consent_compacted_active_state_digest(
    state: &ConsentCompactedActiveStateV1,
) -> Result<[u8; 32], ConsentRecoveryError> {
    if state.schema != CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA {
        return Err(ConsentRecoveryError::UnsupportedActiveStateSchema {
            schema: state.schema.clone(),
        });
    }
    let activation = checkpoint_fingerprint(&state.activation_snapshot.manifest.current_checkpoint)?;
    let current = checkpoint_fingerprint(&state.current_checkpoint)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-compacted-active-state:v1");
    hasher.update(&[0]);
    hasher.update(state.schema.as_bytes());
    hasher.update(&[0]);
    hasher.update(&state.activation_snapshot.snapshot_digest);
    hasher.update(&activation);
    hasher.update(&current);
    hasher.update(&(state.resident_entries.len() as u64).to_be_bytes());
    for entry in &state.resident_entries {
        hasher.update(&entry.seq.to_be_bytes());
        hasher.update(&entry.entry_hash);
        hasher.update(&entry.signature);
    }
    hasher.update(&(state.archived_replay_action_ids.len() as u64).to_be_bytes());
    for action_id in &state.archived_replay_action_ids {
        hasher.update(action_id);
    }
    hasher.update(&(state.archived_terminal_sessions.len() as u64).to_be_bytes());
    for session_id in &state.archived_terminal_sessions {
        hasher.update(session_id);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{Chain, ConsentEventRecord, LedgerArchiveSegment};

    fn event(
        session: u8,
        action: u8,
        kind: ConsentKind,
        source_id: [u8; 32],
    ) -> ConsentEventRecord {
        ConsentEventRecord {
            source_id,
            session_id: Uuid::from_bytes([session; 16]),
            request_id: Uuid::from_bytes([action; 16]),
            kind,
            scope: kind.stable_name().to_string(),
        }
    }

    fn complete_archive() -> Vec<LedgerArchiveSegment> {
        let mut chain = Chain::new(SigningKey::from_bytes(&[0x44; 32]));
        let genesis = chain.sign_checkpoint(100);
        chain
            .append(event(1, 1, ConsentKind::Request, [0x10; 32]))
            .unwrap();
        chain
            .append(event(1, 2, ConsentKind::Approval, [0x20; 32]))
            .unwrap();
        chain
            .append(event(1, 3, ConsentKind::Revocation, [0x20; 32]))
            .unwrap();
        vec![LedgerArchiveSegment::from_chain(&chain, genesis, 101).unwrap()]
    }

    #[test]
    fn summary_retains_replay_ids_and_terminal_approval_provenance() {
        let segments = complete_archive();
        let summary = ConsentRecoverySummaryV1::from_archive_sequence(&segments).unwrap();
        summary.verify_against_archive(&segments).unwrap();

        assert_eq!(summary.archived_entry_count, 3);
        assert_eq!(summary.replay_action_ids, vec![[2u8; 16], [3u8; 16]]);
        assert!(summary.replay_action_ids.binary_search(&[2u8; 16]).is_ok());
        assert_eq!(summary.sessions.len(), 1);
        assert_eq!(summary.sessions[0].terminal_event, "consent.revoked");
        assert_eq!(summary.sessions[0].approving_operator_key, Some([0x20; 32]));
        assert_eq!(summary.sessions[0].approval_action_id, Some([2u8; 16]));
    }

    #[test]
    fn summary_refuses_an_archived_active_grant() {
        let mut chain = Chain::new(SigningKey::from_bytes(&[0x45; 32]));
        let genesis = chain.sign_checkpoint(100);
        chain
            .append(event(1, 1, ConsentKind::Approval, [0x20; 32]))
            .unwrap();
        let segments = vec![LedgerArchiveSegment::from_chain(&chain, genesis, 101).unwrap()];
        assert!(matches!(
            ConsentRecoverySummaryV1::from_archive_sequence(&segments),
            Err(ConsentRecoveryError::IncompleteSession { .. })
        ));
    }

    #[test]
    fn summary_refuses_non_genesis_prefixes_and_duplicate_action_ids() {
        let mut chain = Chain::new(SigningKey::from_bytes(&[0x46; 32]));
        chain
            .append(event(1, 1, ConsentKind::Denial, [0x20; 32]))
            .unwrap();
        let non_genesis = chain.sign_checkpoint(101);
        chain
            .append(event(2, 2, ConsentKind::Denial, [0x21; 32]))
            .unwrap();
        let segments = vec![LedgerArchiveSegment::from_chain(&chain, non_genesis, 102).unwrap()];
        assert_eq!(
            ConsentRecoverySummaryV1::from_archive_sequence(&segments),
            Err(ConsentRecoveryError::NonGenesisBase)
        );

        let mut chain = Chain::new(SigningKey::from_bytes(&[0x47; 32]));
        let genesis = chain.sign_checkpoint(100);
        chain
            .append(event(1, 9, ConsentKind::Denial, [0x20; 32]))
            .unwrap();
        chain
            .append(event(2, 9, ConsentKind::Denial, [0x21; 32]))
            .unwrap();
        let segments = vec![LedgerArchiveSegment::from_chain(&chain, genesis, 101).unwrap()];
        assert!(matches!(
            ConsentRecoverySummaryV1::from_archive_sequence(&segments),
            Err(ConsentRecoveryError::DuplicateActionId { .. })
        ));
    }

    #[test]
    fn bundle_binds_archive_summary_and_current_live_head() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key);
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments, 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        bundle
            .verify_against_live_ledger(
                &entries,
                &SigningKey::from_bytes(&[0x44; 32]).verifying_key(),
            )
            .unwrap();
    }

    #[test]
    fn bundle_refuses_manifest_or_summary_substitution() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let chain = Chain::from_entries(segments[0].entries.clone(), key);
        let mut bundle = ConsentCompactionBundleV1::build(&chain, segments, 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        bundle.manifest.archive_sequence_digest[0] ^= 1;
        assert_eq!(
            bundle.verify_against_live_ledger(
                &entries,
                &SigningKey::from_bytes(&[0x44; 32]).verifying_key(),
            ),
            Err(ConsentRecoveryError::ManifestArchiveMismatch)
        );
    }

    #[test]
    fn bundle_refuses_archived_action_or_session_reuse_in_the_live_suffix() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut replayed_action = Chain::from_entries(segments[0].entries.clone(), key.clone());
        replayed_action
            .append(event(2, 2, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        assert!(matches!(
            ConsentCompactionBundleV1::build(&replayed_action, segments.clone(), 102),
            Err(ConsentRecoveryError::SignedDecisionReplay { .. })
        ));

        let mut reused_session = Chain::from_entries(segments[0].entries.clone(), key);
        reused_session
            .append(event(1, 4, ConsentKind::Request, [0x30; 32]))
            .unwrap();
        assert!(matches!(
            ConsentCompactionBundleV1::build(&reused_session, segments, 102),
            Err(ConsentRecoveryError::ArchivedSessionReused { .. })
        ));
    }

    #[test]
    fn tampered_summary_is_rejected_even_when_json_shape_is_valid() {
        let segments = complete_archive();
        let mut summary = ConsentRecoverySummaryV1::from_archive_sequence(&segments).unwrap();
        summary.sessions[0].terminal_sequence = 99;
        assert!(matches!(
            summary.verify_against_archive(&segments),
            Err(ConsentRecoveryError::DigestMismatch)
        ));
    }

    #[test]
    fn compacted_snapshot_verifies_without_the_complete_live_prefix() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let public_key = key.verifying_key();
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(&bundle, &entries, &public_key).unwrap();

        snapshot.verify(&segments, &public_key).unwrap();
        assert_eq!(snapshot.suffix_entries.len(), 1);
        assert_eq!(snapshot.suffix_entries[0].seq, 3);

        let mut restored = Chain::from_checkpoint_suffix(
            snapshot.recovery_summary.through_checkpoint.clone(),
            snapshot.suffix_entries.clone(),
            key,
        );
        let appended = restored
            .append(event(3, 5, ConsentKind::Denial, [0x31; 32]))
            .unwrap();
        assert_eq!(appended.seq, 4);
    }

    #[test]
    fn compacted_snapshot_refuses_tampered_suffix_even_with_recomputed_envelope_digest() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let public_key = key.verifying_key();
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key);
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let mut snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &public_key).unwrap();
        snapshot.suffix_entries[0].entry_hash[0] ^= 1;
        snapshot.snapshot_digest = consent_compacted_snapshot_digest(&snapshot).unwrap();

        assert!(matches!(
            snapshot.verify(&segments, &public_key),
            Err(ConsentRecoveryError::Continuity(_))
        ));
    }

    #[test]
    fn compacted_restore_materializes_replay_and_terminal_indexes_before_append() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &key.verifying_key(),
        )
        .unwrap();

        let mut restored = snapshot.restore_state(&segments, &key).unwrap();
        assert!(restored.archived_replay_action_ids.contains(&[2u8; 16]));
        assert!(restored.archived_replay_action_ids.contains(&[3u8; 16]));
        assert!(restored.archived_terminal_sessions.contains(&[1u8; 16]));
        assert_eq!(restored.chain.entry_count(), 4);
        assert_eq!(restored.chain.resident_len(), 1);
        let appended = restored
            .chain
            .append(event(3, 5, ConsentKind::Denial, [0x31; 32]))
            .unwrap();
        assert_eq!(appended.seq, 4);
    }

    #[test]
    fn compacted_restore_refuses_a_different_local_signing_key() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &key.verifying_key(),
        )
        .unwrap();
        let wrong_key = SigningKey::from_bytes(&[0x99; 32]);

        assert_eq!(
            snapshot.restore_state(&segments, &wrong_key).err(),
            Some(ConsentRecoveryError::RestoreSigningKeyMismatch)
        );
    }

    #[test]
    fn compacted_snapshot_refuses_summary_or_manifest_substitution() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let public_key = key.verifying_key();
        let chain = Chain::from_entries(segments[0].entries.clone(), key);
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let mut snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &public_key).unwrap();
        snapshot.recovery_summary.summary_digest[0] ^= 1;
        snapshot.snapshot_digest = consent_compacted_snapshot_digest(&snapshot).unwrap();

        assert!(matches!(
            snapshot.verify(&segments, &public_key),
            Err(ConsentRecoveryError::DigestMismatch)
                | Err(ConsentRecoveryError::SummaryMismatch)
                | Err(ConsentRecoveryError::ManifestRecoveryMismatch)
        ));
    }

    #[test]
    fn compacted_active_state_advances_and_restores_without_cold_archive_reads() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &key.verifying_key(),
        )
        .unwrap();
        let active = ConsentCompactedActiveStateV1::activate(
            snapshot,
            &segments,
            &key,
            103,
        )
        .unwrap();
        active.verify(&key.verifying_key()).unwrap();

        let mut restored = active.restore_state(&key).unwrap();
        restored
            .chain
            .append(event(3, 5, ConsentKind::Denial, [0x31; 32]))
            .unwrap();
        let advanced = active.advance_from_chain(&restored.chain, 104).unwrap();
        let reloaded = advanced.restore_state(&key).unwrap();
        assert_eq!(reloaded.chain.entry_count(), 5);
        assert_eq!(reloaded.chain.resident_len(), 2);
        assert_eq!(reloaded.archived_replay_action_count(), 2);
        assert_eq!(reloaded.archived_terminal_session_count(), 1);
    }

    #[test]
    fn compacted_active_state_refuses_index_substitution() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &key.verifying_key(),
        )
        .unwrap();
        let mut active = ConsentCompactedActiveStateV1::activate(
            snapshot,
            &segments,
            &key,
            103,
        )
        .unwrap();
        active.archived_replay_action_ids.push([0xEE; 16]);
        active.state_digest = consent_compacted_active_state_digest(&active).unwrap();
        assert_eq!(
            active.verify(&key.verifying_key()),
            Err(ConsentRecoveryError::ActiveReplayIndexMismatch)
        );
    }

    #[test]
    fn compacted_active_state_refuses_replaced_activation_suffix() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &key.verifying_key(),
        )
        .unwrap();
        let mut active = ConsentCompactedActiveStateV1::activate(
            snapshot,
            &segments,
            &key,
            103,
        )
        .unwrap();
        active.resident_entries[0].entry_hash[0] ^= 1;
        active.state_digest = consent_compacted_active_state_digest(&active).unwrap();
        assert!(matches!(
            active.verify(&key.verifying_key()),
            Err(ConsentRecoveryError::Continuity(_))
                | Err(ConsentRecoveryError::ActivationSuffixMismatch)
        ));
    }

}
