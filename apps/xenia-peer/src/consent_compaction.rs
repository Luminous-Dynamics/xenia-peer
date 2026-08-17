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

use ed25519_dalek::{
    Signature, Signer, SigningKey as LedgerSigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use xenia_ledger::{
    Chain, CheckpointContinuityError, ConsentKind, LedgerArchiveError, LedgerArchiveSegment,
    LedgerCheckpoint, LedgerCompactionError, LedgerCompactionManifest, LedgerEntry, Verifier,
    checkpoint_fingerprint, ledger_archive_sequence_digest,
};

const CONSENT_RECOVERY_SUMMARY_SCHEMA: &str = "xenia-consent-recovery-summary-v1";
const MAX_RECOVERY_ACTION_IDS: usize = 100_000;
const MAX_RECOVERY_SESSIONS: usize = 100_000;

pub(crate) const CONSENT_COMPACTION_BUNDLE_SCHEMA: &str = "xenia-consent-compaction-bundle-v1";
pub(crate) const CONSENT_COMPACTED_SNAPSHOT_SCHEMA: &str = "xenia-consent-compacted-snapshot-v1";
pub(crate) const MAX_CONSENT_COMPACTION_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_CONSENT_COMPACTED_SUFFIX_ENTRIES: usize = 100_000;
pub(crate) const CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA: &str =
    "xenia-consent-compacted-active-state-v2";
const CONSENT_COMPACTED_CUTOVER_RECEIPT_SCHEMA: &str = "xenia-consent-compacted-cutover-receipt-v1";
pub(crate) const CONSENT_COMPACTED_STATE_PIN_SCHEMA: &str = "xenia-consent-compacted-state-pin-v1";
pub(crate) const CONSENT_COMPACTION_GC_CERTIFICATE_SCHEMA: &str =
    "xenia-consent-compaction-gc-certificate-v1";

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

/// Ledger-signed statement that one compacted activation preserved the exact
/// complete-ledger head used to build its snapshot. This makes the cutover
/// identity explicit and refuses cross-key epoch substitution before the
/// active-state envelope can be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentCompactedCutoverReceiptV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) activation_snapshot_digest: [u8; 32],
    pub(crate) archive_sequence_digest: [u8; 32],
    pub(crate) recovery_summary_digest: [u8; 32],
    pub(crate) source_complete_checkpoint: LedgerCheckpoint,
    pub(crate) activated_checkpoint: LedgerCheckpoint,
    pub(crate) activated_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

/// Independently retainable signed observation of one compacted active-state
/// generation. A later state can prove append-only extension from this pin by
/// presenting the resident signed suffix after the pinned checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentCompactedStatePinV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) cutover_receipt_fingerprint: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) active_state_digest: [u8; 32],
    pub(crate) checkpoint: LedgerCheckpoint,
    pub(crate) created_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

/// Signed proof that the cold archive, recovery summary, cutover receipt,
/// current active state, and independently retained state pin all agree. This
/// is a non-destructive prerequisite artifact; it does not authorize deletion
/// by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentCompactionGcCertificateV1 {
    pub(crate) schema: String,
    pub(crate) ledger_epoch_id: [u8; 32],
    pub(crate) cutover_receipt_fingerprint: [u8; 32],
    pub(crate) archive_sequence_digest: [u8; 32],
    pub(crate) recovery_summary_digest: [u8; 32],
    pub(crate) active_state_digest: [u8; 32],
    pub(crate) state_pin_fingerprint: [u8; 32],
    pub(crate) archive_through_checkpoint: LedgerCheckpoint,
    pub(crate) current_checkpoint: LedgerCheckpoint,
    pub(crate) issued_at_unix_secs: u64,
    #[serde(with = "BigArray")]
    pub(crate) signature: [u8; 64],
}

/// Durable, appendable consent-ledger state after a verified compaction
/// activation. The original snapshot and signed cutover receipt remain
/// immutable, while `resident_entries` and `current_checkpoint` advance
/// together on each later transactional append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentCompactedActiveStateV1 {
    pub(crate) schema: String,
    pub(crate) activation_snapshot: ConsentCompactedSnapshotV1,
    pub(crate) cutover_receipt: ConsentCompactedCutoverReceiptV1,
    pub(crate) generation: u64,
    pub(crate) previous_state_digest: [u8; 32],
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
    pub(crate) fn into_parts(self) -> (Chain, BTreeSet<[u8; 16]>, BTreeSet<[u8; 16]>) {
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
    #[error("unsupported consent compacted cutover receipt schema: {schema}")]
    UnsupportedCutoverReceiptSchema { schema: String },
    #[error("consent compacted cutover receipt signature is invalid")]
    InvalidCutoverReceiptSignature,
    #[error("consent compacted cutover receipt does not preserve the source complete-ledger head")]
    CutoverHeadMismatch,
    #[error("consent compacted cutover receipt crosses ledger signing-key epochs")]
    CrossEpochCutover,
    #[error("consent compacted cutover receipt predates the source complete-ledger checkpoint")]
    CutoverTimestampRegressed,
    #[error("consent compacted cutover receipt does not bind the activation snapshot")]
    CutoverSnapshotMismatch,
    #[error("unsupported consent compacted state pin schema: {schema}")]
    UnsupportedStatePinSchema { schema: String },
    #[error("consent compacted state pin signature is invalid")]
    InvalidStatePinSignature,
    #[error("consent compacted state pin belongs to a different cutover or ledger epoch")]
    StatePinIdentityMismatch,
    #[error(
        "consent compacted state pin generation {pinned} is ahead of active generation {active}"
    )]
    StatePinGenerationRollback { pinned: u64, active: u64 },
    #[error("consent compacted state pin does not match the active state at the same generation")]
    StatePinSameGenerationMismatch,
    #[error("consent compacted state pin predates the compacted archive anchor")]
    StatePinPredatesAnchor,
    #[error("consent compacted state pin creation timestamp predates its checkpoint")]
    StatePinTimestampRegressed,
    #[error("consent compacted active-state generation metadata is invalid")]
    ActiveGenerationMismatch,
    #[error("consent compacted active-state generation overflow")]
    ActiveGenerationOverflow,
    #[error("unsupported consent compaction GC certificate schema: {schema}")]
    UnsupportedGcCertificateSchema { schema: String },
    #[error("consent compaction GC certificate signature is invalid")]
    InvalidGcCertificateSignature,
    #[error("consent compaction GC certificate does not match the verified active state")]
    GcCertificateStateMismatch,
    #[error("consent compaction GC certificate does not match the verified cold archive")]
    GcCertificateArchiveMismatch,
    #[error("consent compaction GC certificate timestamp predates the active checkpoint")]
    GcCertificateTimestampRegressed,
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
            .ok_or(LedgerArchiveError::EmptySequence)?
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
                ConsentKind::Violation => {
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
                ConsentKind::AthenaTriage => {
                    // A signed audit fact that does not itself open or close a
                    // consent ceremony in the operator ledger.
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
            let session_id_hex = hex::encode(session_id);
            let terminal_event =
                state
                    .terminal_event
                    .ok_or_else(|| ConsentRecoveryError::IncompleteSession {
                        session_id: session_id_hex.clone(),
                    })?;
            let terminal_sequence =
                state
                    .terminal_sequence
                    .ok_or(ConsentRecoveryError::IncompleteSession {
                        session_id: session_id_hex,
                    })?;
            completed.push(ConsentRecoverySessionV1 {
                session_id,
                terminal_event,
                terminal_sequence,
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
        if !self
            .replay_action_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(ConsentRecoveryError::SummaryMismatch);
        }
        if !self
            .sessions
            .windows(2)
            .all(|pair| pair[0].session_id < pair[1].session_id)
        {
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

/// Translate an absolute (from-true-genesis) entry count into a local index
/// into a possibly-resident-only entries slice.
///
/// `archived_entry_count` (a [`ConsentRecoverySummaryV1`]'s own field) always
/// counts from true genesis, because [`LedgerCheckpoint::entry_count`] is
/// itself always absolute (`Chain::entry_count()` returns
/// `base_entry_count + resident.len()`, never just `resident.len()`) --
/// confirmed by reading `Chain::sign_checkpoint`/`entry_count`, not assumed.
/// But the `entries` slice a caller passes to `verify_suffix_compatibility`/
/// `ConsentCompactedSnapshotV1::build` is NOT always absolute: for a
/// complete (genesis-based) chain it holds every entry, so `anchor` is
/// `None` and this is a no-op; for an anchored-suffix chain (a
/// second-or-later compaction round, `Chain::from_checkpoint_suffix`)
/// `chain.iter()` -- and therefore `entries` -- holds only the resident
/// suffix, so every absolute count must first have the already-archived
/// prefix length subtracted before it can index into that slice. Getting
/// this wrong doesn't misbehave quietly: `entries.get(archived_entry_count..)`
/// against a 5-element resident-only slice with an absolute
/// `archived_entry_count` of 1005 returns `None` (or, pre-Phase-0, could be
/// handed to code that indexes rather than slices and panics outright) --
/// this function exists so that class of bug has exactly one place to be
/// correct.
///
/// Takes the anchor as a full `LedgerCheckpoint` (not just its
/// `entry_count`) rather than a bare offset so that the SAME checkpoint
/// object always drives both the slicing arithmetic here and the
/// cryptographic extension proof in `Chain::sign_compaction_manifest` /
/// `Verifier::verify_ledger_compaction_manifest_against_entries` -- a bare
/// `u64` offset could accidentally be computed from a different, wrong
/// checkpoint without either side noticing.
fn local_suffix_start(
    absolute_entry_count: u64,
    anchor: Option<&LedgerCheckpoint>,
) -> Result<usize, ConsentRecoveryError> {
    let absolute = usize::try_from(absolute_entry_count)
        .map_err(|_| ConsentRecoveryError::ArchivedEntryCountOverflow)?;
    let offset = match anchor {
        Some(checkpoint) => usize::try_from(checkpoint.entry_count)
            .map_err(|_| ConsentRecoveryError::ArchivedEntryCountOverflow)?,
        None => 0,
    };
    absolute
        .checked_sub(offset)
        .ok_or(ConsentRecoveryError::SummaryMismatch)
}

impl ConsentCompactionBundleV1 {
    /// Build and sign a preflight bundle from verified archive segments and
    /// `chain`'s current entries -- either every entry since true genesis
    /// (a complete chain) or, for a second-or-later compaction round, every
    /// entry since the last cutover (an anchored-suffix chain,
    /// `chain.base_checkpoint().is_some()`). This operation never mutates
    /// the ledger.
    pub(crate) fn build(
        chain: &Chain,
        archive_segments: Vec<LedgerArchiveSegment>,
        timestamp_unix_secs: u64,
    ) -> Result<Self, ConsentRecoveryError> {
        let recovery_summary = ConsentRecoverySummaryV1::from_archive_sequence(&archive_segments)?;
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
        bundle.verify_suffix_compatibility(&entries, chain.base_checkpoint())?;
        Ok(bundle)
    }

    /// Verify the archive, recovery summary, signed manifest, and a supplied
    /// entries slice as one indivisible preflight statement.
    ///
    /// `anchor` is `None` when `entries` is a complete, genesis-based
    /// ledger, or `Some` of the anchored chain's own `base_checkpoint()`
    /// when `entries` is an anchored chain's resident suffix. See
    /// [`local_suffix_start`].
    pub(crate) fn verify_against_live_ledger(
        &self,
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
        anchor: Option<&LedgerCheckpoint>,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTION_BUNDLE_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedBundleSchema {
                schema: self.schema.clone(),
            });
        }
        self.recovery_summary
            .verify_against_archive(&self.archive_segments)?;
        if self.manifest.archive_sequence_digest != self.recovery_summary.archive_sequence_digest {
            return Err(ConsentRecoveryError::ManifestArchiveMismatch);
        }
        if self.manifest.recovery_summary_digest != self.recovery_summary.summary_digest {
            return Err(ConsentRecoveryError::ManifestRecoveryMismatch);
        }
        if self.manifest.archived_through_checkpoint != self.recovery_summary.through_checkpoint {
            return Err(ConsentRecoveryError::ManifestBoundaryMismatch);
        }
        Verifier::verify_ledger_compaction_manifest_against_entries(
            &self.manifest,
            entries,
            public_key,
            anchor,
        )?;
        self.verify_suffix_compatibility(entries, anchor)
    }

    fn verify_suffix_compatibility(
        &self,
        entries: &[LedgerEntry],
        anchor: Option<&LedgerCheckpoint>,
    ) -> Result<(), ConsentRecoveryError> {
        let local_start = local_suffix_start(self.recovery_summary.archived_entry_count, anchor)?;
        let suffix = entries
            .get(local_start..)
            .ok_or(ConsentRecoveryError::SummaryMismatch)?;
        verify_recovery_suffix_compatibility(&self.recovery_summary, suffix)
    }
}

impl ConsentCompactedSnapshotV1 {
    /// Build a minimal suffix snapshot from a fully verified preflight bundle
    /// and a supplied entries slice. This operation does not mutate storage.
    /// See [`ConsentCompactionBundleV1::verify_against_live_ledger`] for what
    /// `anchor` means and when it must be `Some`.
    pub(crate) fn build(
        bundle: &ConsentCompactionBundleV1,
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
        anchor: Option<&LedgerCheckpoint>,
    ) -> Result<Self, ConsentRecoveryError> {
        bundle.verify_against_live_ledger(entries, public_key, anchor)?;
        let local_start = local_suffix_start(bundle.recovery_summary.archived_entry_count, anchor)?;
        let suffix_entries = entries
            .get(local_start..)
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
        if self.manifest.archive_sequence_digest != self.recovery_summary.archive_sequence_digest {
            return Err(ConsentRecoveryError::ManifestArchiveMismatch);
        }
        if self.manifest.recovery_summary_digest != self.recovery_summary.summary_digest {
            return Err(ConsentRecoveryError::ManifestRecoveryMismatch);
        }
        if self.manifest.archived_through_checkpoint != self.recovery_summary.through_checkpoint {
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
        if self.manifest.archive_sequence_digest != self.recovery_summary.archive_sequence_digest {
            return Err(ConsentRecoveryError::ManifestArchiveMismatch);
        }
        if self.manifest.recovery_summary_digest != self.recovery_summary.summary_digest {
            return Err(ConsentRecoveryError::ManifestRecoveryMismatch);
        }
        if self.manifest.archived_through_checkpoint != self.recovery_summary.through_checkpoint {
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

impl ConsentCompactedCutoverReceiptV1 {
    fn sign(
        snapshot: &ConsentCompactedSnapshotV1,
        activated_checkpoint: LedgerCheckpoint,
        signing_key: &LedgerSigningKey,
        activated_at_unix_secs: u64,
    ) -> Result<Self, ConsentRecoveryError> {
        let source_complete_checkpoint = snapshot.manifest.current_checkpoint.clone();
        let ledger_epoch_id =
            consent_ledger_epoch_id(&source_complete_checkpoint.ledger_public_key);
        let mut receipt = Self {
            schema: CONSENT_COMPACTED_CUTOVER_RECEIPT_SCHEMA.to_string(),
            ledger_epoch_id,
            activation_snapshot_digest: snapshot.snapshot_digest,
            archive_sequence_digest: snapshot.recovery_summary.archive_sequence_digest,
            recovery_summary_digest: snapshot.recovery_summary.summary_digest,
            source_complete_checkpoint,
            activated_checkpoint,
            activated_at_unix_secs,
            signature: [0u8; 64],
        };
        let message = consent_compacted_cutover_receipt_message(&receipt)?;
        receipt.signature = signing_key.sign(&message).to_bytes();
        receipt.verify(&signing_key.verifying_key(), snapshot)?;
        Ok(receipt)
    }

    fn verify(
        &self,
        public_key: &VerifyingKey,
        snapshot: &ConsentCompactedSnapshotV1,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTED_CUTOVER_RECEIPT_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedCutoverReceiptSchema {
                schema: self.schema.clone(),
            });
        }
        Verifier::verify_checkpoint(&self.source_complete_checkpoint)?;
        Verifier::verify_checkpoint(&self.activated_checkpoint)?;
        if self.source_complete_checkpoint.ledger_public_key != public_key.to_bytes()
            || self.activated_checkpoint.ledger_public_key != public_key.to_bytes()
            || self.source_complete_checkpoint.ledger_public_key
                != self.activated_checkpoint.ledger_public_key
        {
            return Err(ConsentRecoveryError::CrossEpochCutover);
        }
        if self.ledger_epoch_id != consent_ledger_epoch_id(&public_key.to_bytes()) {
            return Err(ConsentRecoveryError::CrossEpochCutover);
        }
        if self.source_complete_checkpoint.entry_count != self.activated_checkpoint.entry_count
            || self.source_complete_checkpoint.head_hash != self.activated_checkpoint.head_hash
        {
            return Err(ConsentRecoveryError::CutoverHeadMismatch);
        }
        if self.activated_at_unix_secs < self.source_complete_checkpoint.timestamp_unix_secs
            || self.activated_checkpoint.timestamp_unix_secs
                < self.source_complete_checkpoint.timestamp_unix_secs
        {
            return Err(ConsentRecoveryError::CutoverTimestampRegressed);
        }
        if self.activation_snapshot_digest != snapshot.snapshot_digest
            || self.archive_sequence_digest != snapshot.recovery_summary.archive_sequence_digest
            || self.recovery_summary_digest != snapshot.recovery_summary.summary_digest
            || self.source_complete_checkpoint != snapshot.manifest.current_checkpoint
        {
            return Err(ConsentRecoveryError::CutoverSnapshotMismatch);
        }
        let message = consent_compacted_cutover_receipt_message(self)?;
        public_key
            .verify(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| ConsentRecoveryError::InvalidCutoverReceiptSignature)
    }
}

impl ConsentCompactedStatePinV1 {
    pub(crate) fn sign_for_state(
        state: &ConsentCompactedActiveStateV1,
        signing_key: &LedgerSigningKey,
        created_at_unix_secs: u64,
    ) -> Result<Self, ConsentRecoveryError> {
        state.verify(&signing_key.verifying_key())?;
        if created_at_unix_secs < state.current_checkpoint.timestamp_unix_secs {
            return Err(ConsentRecoveryError::StatePinTimestampRegressed);
        }
        let mut pin = Self {
            schema: CONSENT_COMPACTED_STATE_PIN_SCHEMA.to_string(),
            ledger_epoch_id: state.cutover_receipt.ledger_epoch_id,
            cutover_receipt_fingerprint: consent_compacted_cutover_receipt_fingerprint(
                &state.cutover_receipt,
            )?,
            generation: state.generation,
            active_state_digest: state.state_digest,
            checkpoint: state.current_checkpoint.clone(),
            created_at_unix_secs,
            signature: [0u8; 64],
        };
        let message = consent_compacted_state_pin_message(&pin)?;
        pin.signature = signing_key.sign(&message).to_bytes();
        pin.verify_against_state(state, &signing_key.verifying_key())?;
        Ok(pin)
    }

    pub(crate) fn verify_against_state(
        &self,
        state: &ConsentCompactedActiveStateV1,
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTED_STATE_PIN_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedStatePinSchema {
                schema: self.schema.clone(),
            });
        }
        state.verify(public_key)?;
        Verifier::verify_checkpoint(&self.checkpoint)?;
        if self.checkpoint.ledger_public_key != public_key.to_bytes()
            || self.ledger_epoch_id != state.cutover_receipt.ledger_epoch_id
            || self.cutover_receipt_fingerprint
                != consent_compacted_cutover_receipt_fingerprint(&state.cutover_receipt)?
        {
            return Err(ConsentRecoveryError::StatePinIdentityMismatch);
        }
        if self.created_at_unix_secs < self.checkpoint.timestamp_unix_secs {
            return Err(ConsentRecoveryError::StatePinTimestampRegressed);
        }
        let message = consent_compacted_state_pin_message(self)?;
        public_key
            .verify(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| ConsentRecoveryError::InvalidStatePinSignature)?;
        if self.generation > state.generation {
            return Err(ConsentRecoveryError::StatePinGenerationRollback {
                pinned: self.generation,
                active: state.generation,
            });
        }
        if self.generation == state.generation {
            if self.active_state_digest != state.state_digest
                || self.checkpoint != state.current_checkpoint
            {
                return Err(ConsentRecoveryError::StatePinSameGenerationMismatch);
            }
            return Ok(());
        }
        let base = &state
            .activation_snapshot
            .recovery_summary
            .through_checkpoint;
        if self.checkpoint.entry_count < base.entry_count {
            return Err(ConsentRecoveryError::StatePinPredatesAnchor);
        }
        let offset = self
            .checkpoint
            .entry_count
            .checked_sub(base.entry_count)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(ConsentRecoveryError::StatePinPredatesAnchor)?;
        let suffix = state
            .resident_entries
            .get(offset..)
            .ok_or(ConsentRecoveryError::StatePinPredatesAnchor)?;
        Verifier::verify_checkpoint_extension(&self.checkpoint, &state.current_checkpoint, suffix)?;
        Ok(())
    }
}

impl ConsentCompactionGcCertificateV1 {
    pub(crate) fn sign_for_state(
        state: &ConsentCompactedActiveStateV1,
        state_pin: &ConsentCompactedStatePinV1,
        archive_segments: &[LedgerArchiveSegment],
        signing_key: &LedgerSigningKey,
        issued_at_unix_secs: u64,
    ) -> Result<Self, ConsentRecoveryError> {
        let public_key = signing_key.verifying_key();
        state.verify(&public_key)?;
        state
            .activation_snapshot
            .verify(archive_segments, &public_key)?;
        state_pin.verify_against_state(state, &public_key)?;
        if issued_at_unix_secs < state.current_checkpoint.timestamp_unix_secs {
            return Err(ConsentRecoveryError::GcCertificateTimestampRegressed);
        }
        let archive_through_checkpoint = archive_segments
            .last()
            .ok_or(LedgerArchiveError::EmptySequence)?
            .terminal_checkpoint
            .clone();
        let mut certificate = Self {
            schema: CONSENT_COMPACTION_GC_CERTIFICATE_SCHEMA.to_string(),
            ledger_epoch_id: state.cutover_receipt.ledger_epoch_id,
            cutover_receipt_fingerprint: consent_compacted_cutover_receipt_fingerprint(
                &state.cutover_receipt,
            )?,
            archive_sequence_digest: ledger_archive_sequence_digest(archive_segments)?,
            recovery_summary_digest: state.activation_snapshot.recovery_summary.summary_digest,
            active_state_digest: state.state_digest,
            state_pin_fingerprint: consent_compacted_state_pin_fingerprint(state_pin)?,
            archive_through_checkpoint,
            current_checkpoint: state.current_checkpoint.clone(),
            issued_at_unix_secs,
            signature: [0u8; 64],
        };
        let message = consent_compaction_gc_certificate_message(&certificate)?;
        certificate.signature = signing_key.sign(&message).to_bytes();
        certificate.verify(state, state_pin, archive_segments, &public_key)?;
        Ok(certificate)
    }

    pub(crate) fn verify(
        &self,
        state: &ConsentCompactedActiveStateV1,
        state_pin: &ConsentCompactedStatePinV1,
        archive_segments: &[LedgerArchiveSegment],
        public_key: &VerifyingKey,
    ) -> Result<(), ConsentRecoveryError> {
        if self.schema != CONSENT_COMPACTION_GC_CERTIFICATE_SCHEMA {
            return Err(ConsentRecoveryError::UnsupportedGcCertificateSchema {
                schema: self.schema.clone(),
            });
        }
        state.verify(public_key)?;
        state
            .activation_snapshot
            .verify(archive_segments, public_key)?;
        state_pin.verify_against_state(state, public_key)?;
        let archive_through_checkpoint = archive_segments
            .last()
            .ok_or(LedgerArchiveError::EmptySequence)?
            .terminal_checkpoint
            .clone();
        if self.archive_sequence_digest != ledger_archive_sequence_digest(archive_segments)?
            || self.archive_through_checkpoint != archive_through_checkpoint
            || self.archive_through_checkpoint
                != state
                    .activation_snapshot
                    .recovery_summary
                    .through_checkpoint
        {
            return Err(ConsentRecoveryError::GcCertificateArchiveMismatch);
        }
        if self.ledger_epoch_id != state.cutover_receipt.ledger_epoch_id
            || self.cutover_receipt_fingerprint
                != consent_compacted_cutover_receipt_fingerprint(&state.cutover_receipt)?
            || self.recovery_summary_digest
                != state.activation_snapshot.recovery_summary.summary_digest
            || self.active_state_digest != state.state_digest
            || self.state_pin_fingerprint != consent_compacted_state_pin_fingerprint(state_pin)?
            || self.current_checkpoint != state.current_checkpoint
        {
            return Err(ConsentRecoveryError::GcCertificateStateMismatch);
        }
        if self.issued_at_unix_secs < self.current_checkpoint.timestamp_unix_secs {
            return Err(ConsentRecoveryError::GcCertificateTimestampRegressed);
        }
        let message = consent_compaction_gc_certificate_message(self)?;
        public_key
            .verify(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| ConsentRecoveryError::InvalidGcCertificateSignature)
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
        let cutover_receipt = ConsentCompactedCutoverReceiptV1::sign(
            &snapshot,
            current_checkpoint.clone(),
            signing_key,
            timestamp_unix_secs,
        )?;
        let resident_entries = restored.chain.iter().cloned().collect();
        let mut state = Self {
            schema: CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA.to_string(),
            activation_snapshot: snapshot,
            cutover_receipt,
            generation: 0,
            previous_state_digest: [0u8; 32],
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
    pub(crate) fn verify(&self, public_key: &VerifyingKey) -> Result<(), ConsentRecoveryError> {
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
        if (self.generation == 0 && self.previous_state_digest != [0u8; 32])
            || (self.generation > 0 && self.previous_state_digest == [0u8; 32])
        {
            return Err(ConsentRecoveryError::ActiveGenerationMismatch);
        }
        self.activation_snapshot
            .verify_signed_frontier(public_key)?;
        self.cutover_receipt
            .verify(public_key, &self.activation_snapshot)?;
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
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(ConsentRecoveryError::ActiveGenerationOverflow)?;
        let mut next = Self {
            schema: CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA.to_string(),
            activation_snapshot: self.activation_snapshot.clone(),
            cutover_receipt: self.cutover_receipt.clone(),
            generation,
            previous_state_digest: self.state_digest,
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
            archived_replay_action_ids: self.archived_replay_action_ids.iter().copied().collect(),
            archived_terminal_sessions: self.archived_terminal_sessions.iter().copied().collect(),
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

fn consent_ledger_epoch_id(ledger_public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-ledger-epoch:v1");
    hasher.update(&[0]);
    hasher.update(ledger_public_key);
    *hasher.finalize().as_bytes()
}

fn consent_compacted_cutover_receipt_message(
    receipt: &ConsentCompactedCutoverReceiptV1,
) -> Result<Vec<u8>, ConsentRecoveryError> {
    if receipt.schema != CONSENT_COMPACTED_CUTOVER_RECEIPT_SCHEMA {
        return Err(ConsentRecoveryError::UnsupportedCutoverReceiptSchema {
            schema: receipt.schema.clone(),
        });
    }
    let source = checkpoint_fingerprint(&receipt.source_complete_checkpoint)?;
    let activated = checkpoint_fingerprint(&receipt.activated_checkpoint)?;
    let mut message = Vec::with_capacity(256);
    message.extend_from_slice(b"xenia:consent-compacted-cutover-receipt:v1");
    message.push(0);
    message.extend_from_slice(receipt.schema.as_bytes());
    message.push(0);
    message.extend_from_slice(&receipt.ledger_epoch_id);
    message.extend_from_slice(&receipt.activation_snapshot_digest);
    message.extend_from_slice(&receipt.archive_sequence_digest);
    message.extend_from_slice(&receipt.recovery_summary_digest);
    message.extend_from_slice(&source);
    message.extend_from_slice(&activated);
    message.extend_from_slice(&receipt.activated_at_unix_secs.to_be_bytes());
    Ok(message)
}

fn consent_compacted_cutover_receipt_fingerprint(
    receipt: &ConsentCompactedCutoverReceiptV1,
) -> Result<[u8; 32], ConsentRecoveryError> {
    let mut message = consent_compacted_cutover_receipt_message(receipt)?;
    message.extend_from_slice(&receipt.signature);
    Ok(*blake3::hash(&message).as_bytes())
}

fn consent_compacted_state_pin_message(
    pin: &ConsentCompactedStatePinV1,
) -> Result<Vec<u8>, ConsentRecoveryError> {
    if pin.schema != CONSENT_COMPACTED_STATE_PIN_SCHEMA {
        return Err(ConsentRecoveryError::UnsupportedStatePinSchema {
            schema: pin.schema.clone(),
        });
    }
    let checkpoint = checkpoint_fingerprint(&pin.checkpoint)?;
    let mut message = Vec::with_capacity(256);
    message.extend_from_slice(b"xenia:consent-compacted-state-pin:v1");
    message.push(0);
    message.extend_from_slice(pin.schema.as_bytes());
    message.push(0);
    message.extend_from_slice(&pin.ledger_epoch_id);
    message.extend_from_slice(&pin.cutover_receipt_fingerprint);
    message.extend_from_slice(&pin.generation.to_be_bytes());
    message.extend_from_slice(&pin.active_state_digest);
    message.extend_from_slice(&checkpoint);
    message.extend_from_slice(&pin.created_at_unix_secs.to_be_bytes());
    Ok(message)
}

pub(crate) fn consent_compacted_state_pin_fingerprint(
    pin: &ConsentCompactedStatePinV1,
) -> Result<[u8; 32], ConsentRecoveryError> {
    let mut message = consent_compacted_state_pin_message(pin)?;
    message.extend_from_slice(&pin.signature);
    Ok(*blake3::hash(&message).as_bytes())
}

pub(crate) fn consent_compaction_gc_certificate_fingerprint(
    certificate: &ConsentCompactionGcCertificateV1,
) -> Result<[u8; 32], ConsentRecoveryError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-compaction-gc-certificate-fingerprint:v1");
    hasher.update(&consent_compaction_gc_certificate_message(certificate)?);
    hasher.update(&certificate.signature);
    Ok(*hasher.finalize().as_bytes())
}

fn consent_compaction_gc_certificate_message(
    certificate: &ConsentCompactionGcCertificateV1,
) -> Result<Vec<u8>, ConsentRecoveryError> {
    if certificate.schema != CONSENT_COMPACTION_GC_CERTIFICATE_SCHEMA {
        return Err(ConsentRecoveryError::UnsupportedGcCertificateSchema {
            schema: certificate.schema.clone(),
        });
    }
    let archive = checkpoint_fingerprint(&certificate.archive_through_checkpoint)?;
    let current = checkpoint_fingerprint(&certificate.current_checkpoint)?;
    let mut message = Vec::with_capacity(320);
    message.extend_from_slice(b"xenia:consent-compaction-gc-certificate:v1");
    message.push(0);
    message.extend_from_slice(certificate.schema.as_bytes());
    message.push(0);
    message.extend_from_slice(&certificate.ledger_epoch_id);
    message.extend_from_slice(&certificate.cutover_receipt_fingerprint);
    message.extend_from_slice(&certificate.archive_sequence_digest);
    message.extend_from_slice(&certificate.recovery_summary_digest);
    message.extend_from_slice(&certificate.active_state_digest);
    message.extend_from_slice(&certificate.state_pin_fingerprint);
    message.extend_from_slice(&archive);
    message.extend_from_slice(&current);
    message.extend_from_slice(&certificate.issued_at_unix_secs.to_be_bytes());
    Ok(message)
}

fn consent_compacted_active_state_digest(
    state: &ConsentCompactedActiveStateV1,
) -> Result<[u8; 32], ConsentRecoveryError> {
    if state.schema != CONSENT_COMPACTED_ACTIVE_STATE_SCHEMA {
        return Err(ConsentRecoveryError::UnsupportedActiveStateSchema {
            schema: state.schema.clone(),
        });
    }
    let activation =
        checkpoint_fingerprint(&state.activation_snapshot.manifest.current_checkpoint)?;
    let current = checkpoint_fingerprint(&state.current_checkpoint)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia:consent-compacted-active-state:v1");
    hasher.update(&[0]);
    hasher.update(state.schema.as_bytes());
    hasher.update(&[0]);
    hasher.update(&state.activation_snapshot.snapshot_digest);
    hasher.update(&consent_compacted_cutover_receipt_fingerprint(
        &state.cutover_receipt,
    )?);
    hasher.update(&state.generation.to_be_bytes());
    hasher.update(&state.previous_state_digest);
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
                None,
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
                None,
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
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &public_key, None).unwrap();

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
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &public_key, None).unwrap();
        snapshot.suffix_entries[0].entry_hash[0] ^= 1;
        snapshot.snapshot_digest = consent_compacted_snapshot_digest(&snapshot).unwrap();

        assert!(matches!(
            snapshot.verify(&segments, &public_key),
            Err(ConsentRecoveryError::Continuity(_))
        ));
    }

    #[test]
    fn second_compaction_round_builds_and_activates_from_an_anchored_chain() {
        // Round 1: an ordinary complete-chain compaction, exactly like every
        // other test in this module -- genesis through 3 entries.
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let public_key = key.verifying_key();
        let complete = Chain::from_entries(segments[0].entries.clone(), key.clone());
        let bundle_1 = ConsentCompactionBundleV1::build(&complete, segments.clone(), 102).unwrap();
        let entries_1 = complete.iter().cloned().collect::<Vec<_>>();
        let snapshot_1 =
            ConsentCompactedSnapshotV1::build(&bundle_1, &entries_1, &public_key, None).unwrap();
        let active_1 =
            ConsentCompactedActiveStateV1::activate(snapshot_1, &segments, &key, 103).unwrap();

        // Boot as a daemon actually would: an anchored-suffix chain picking
        // up exactly where round 1 left off, then some real activity.
        let mut anchored = active_1
            .activation_snapshot
            .restore_state(&segments, &key)
            .unwrap()
            .chain;
        anchored
            .append(event(4, 6, ConsentKind::Request, [0x40; 32]))
            .unwrap();
        anchored
            .append(event(4, 7, ConsentKind::Approval, [0x40; 32]))
            .unwrap();
        anchored
            .append(event(4, 8, ConsentKind::Revocation, [0x40; 32]))
            .unwrap();

        // Round 2: this is the whole point of this test -- prove the
        // anchor-aware fix actually lets a second round work end to end,
        // not just that `from_anchored_chain` alone verifies in isolation
        // (Phase 0's test) or that `anchor: None` didn't regress anything
        // (every other test in this file).
        let segment_2 = LedgerArchiveSegment::from_anchored_chain(&anchored, 104).unwrap();
        assert_eq!(segment_2.base_checkpoint, segments[0].terminal_checkpoint);
        let full_archive = vec![segments[0].clone(), segment_2];

        let anchor = anchored.base_checkpoint().cloned().unwrap();
        assert_eq!(
            anchor.entry_count, 3,
            "round 1 archived 3 entries; that's how many precede round 2's resident suffix"
        );
        let bundle_2 =
            ConsentCompactionBundleV1::build(&anchored, full_archive.clone(), 105).unwrap();
        let entries_2 = anchored.iter().cloned().collect::<Vec<_>>();
        let snapshot_2 =
            ConsentCompactedSnapshotV1::build(&bundle_2, &entries_2, &public_key, Some(&anchor))
                .unwrap();

        // Everything archived so far (3 + 3 = 6) now equals the total
        // entry count -- nothing should be left resident.
        assert_eq!(snapshot_2.recovery_summary.archived_entry_count, 6);
        assert!(
            snapshot_2.suffix_entries.is_empty(),
            "round 2 archived the entire resident suffix; nothing should remain"
        );
        snapshot_2.verify(&full_archive, &public_key).unwrap();

        // Activating round 2 must work exactly like round 1 did, and the
        // resulting chain must be anchored at round 2's own terminal
        // checkpoint with a genuinely empty resident suffix.
        let active_2 =
            ConsentCompactedActiveStateV1::activate(snapshot_2, &full_archive, &key, 106).unwrap();
        let restored_2 = active_2
            .activation_snapshot
            .restore_state(&full_archive, &key)
            .unwrap();
        assert_eq!(restored_2.chain.entry_count(), 6);
        assert_eq!(restored_2.chain.resident_len(), 0);
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
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
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
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
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
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &public_key, None).unwrap();
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
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let active =
            ConsentCompactedActiveStateV1::activate(snapshot, &segments, &key, 103).unwrap();
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
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let mut active =
            ConsentCompactedActiveStateV1::activate(snapshot, &segments, &key, 103).unwrap();
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
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let mut active =
            ConsentCompactedActiveStateV1::activate(snapshot, &segments, &key, 103).unwrap();
        active.resident_entries[0].entry_hash[0] ^= 1;
        active.state_digest = consent_compacted_active_state_digest(&active).unwrap();
        assert!(matches!(
            active.verify(&key.verifying_key()),
            Err(ConsentRecoveryError::Continuity(_))
                | Err(ConsentRecoveryError::ActivationSuffixMismatch)
        ));
    }

    #[test]
    fn compacted_cutover_receipt_binds_the_source_head_and_epoch() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let mut active =
            ConsentCompactedActiveStateV1::activate(snapshot, &segments, &key, 103).unwrap();

        // Checked on the still-untampered receipt: verifying against a key
        // that never produced this epoch's checkpoints is a distinct
        // failure mode from the tampering checked below, and
        // `cutover_receipt.verify` checks each embedded checkpoint's own
        // signature before it ever reaches the cross-epoch/key comparison --
        // so this must run before the tamper introduced next, or it would
        // fail for the wrong reason.
        let wrong_key = SigningKey::from_bytes(&[0x99; 32]);
        assert_eq!(
            active
                .cutover_receipt
                .verify(&wrong_key.verifying_key(), &active.activation_snapshot,),
            Err(ConsentRecoveryError::CrossEpochCutover)
        );

        active.cutover_receipt.source_complete_checkpoint.head_hash[0] ^= 1;
        // Tampering with a field inside a signed checkpoint invalidates that
        // checkpoint's own embedded Ed25519 signature. Recomputing the active
        // state's digest re-verifies every embedded checkpoint via
        // `checkpoint_fingerprint`, so this tamper is caught immediately at
        // digest-recompute time -- an attacker can't launder it into a
        // self-consistent-but-wrong digest without forging a signature
        // (contrast the sibling test above, which tampers with a plain
        // hash-only field outside any signed checkpoint and can still
        // produce a self-consistent-but-wrong digest, caught only later by
        // `.verify()`).
        assert!(consent_compacted_active_state_digest(&active).is_err());
    }

    #[test]
    fn compacted_state_pin_detects_rollback_and_accepts_signed_extension() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let active =
            ConsentCompactedActiveStateV1::activate(snapshot, &segments, &key, 103).unwrap();
        let pin = ConsentCompactedStatePinV1::sign_for_state(&active, &key, 104).unwrap();

        let mut restored = active.restore_state(&key).unwrap();
        restored
            .chain
            .append(event(3, 5, ConsentKind::Denial, [0x31; 32]))
            .unwrap();
        let advanced = active.advance_from_chain(&restored.chain, 105).unwrap();
        pin.verify_against_state(&advanced, &key.verifying_key())
            .unwrap();
        assert_eq!(advanced.generation, 1);
        assert_eq!(advanced.previous_state_digest, active.state_digest);

        let newer_pin = ConsentCompactedStatePinV1::sign_for_state(&advanced, &key, 106).unwrap();
        assert_eq!(
            newer_pin.verify_against_state(&active, &key.verifying_key()),
            Err(ConsentRecoveryError::StatePinGenerationRollback {
                pinned: 1,
                active: 0,
            })
        );
    }

    #[test]
    fn gc_certificate_requires_archive_state_and_pin_agreement() {
        let segments = complete_archive();
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut chain = Chain::from_entries(segments[0].entries.clone(), key.clone());
        chain
            .append(event(2, 4, ConsentKind::Denial, [0x30; 32]))
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&chain, segments.clone(), 102).unwrap();
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let active =
            ConsentCompactedActiveStateV1::activate(snapshot, &segments, &key, 103).unwrap();
        let pin = ConsentCompactedStatePinV1::sign_for_state(&active, &key, 104).unwrap();
        let certificate =
            ConsentCompactionGcCertificateV1::sign_for_state(&active, &pin, &segments, &key, 105)
                .unwrap();
        certificate
            .verify(&active, &pin, &segments, &key.verifying_key())
            .unwrap();

        let mut tampered = certificate.clone();
        tampered.active_state_digest[0] ^= 1;
        assert_eq!(
            tampered.verify(&active, &pin, &segments, &key.verifying_key()),
            Err(ConsentRecoveryError::GcCertificateStateMismatch)
        );
    }
}
