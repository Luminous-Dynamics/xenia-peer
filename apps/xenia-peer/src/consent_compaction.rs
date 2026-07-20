// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Consent-specific recovery summaries for archived ledger prefixes.
//!
//! The generic ledger crate proves archive integrity but intentionally does not
//! understand Xenia's authorization semantics. This module derives the minimum
//! state a future pruning implementation must retain: every authenticated
//! action id for replay refusal, every completed session, approval provenance,
//! and the exact archive boundary. A summary is accepted only when the archive
//! begins at genesis and every consent ceremony in the archived prefix is
//! terminal; active or ambiguous authorization state remains in the live log.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_ledger::{
    checkpoint_fingerprint, ledger_archive_sequence_digest, ConsentKind, LedgerArchiveError,
    LedgerArchiveSegment, LedgerCheckpoint,
};

const CONSENT_RECOVERY_SUMMARY_SCHEMA: &str = "xenia-consent-recovery-summary-v1";
const MAX_RECOVERY_ACTION_IDS: usize = 100_000;
const MAX_RECOVERY_SESSIONS: usize = 100_000;

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
    #[error("consent recovery contains an invalid transition for session {session_id} at seq {seq}")]
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
    #[error("consent recovery checkpoint fingerprint failed: {0}")]
    Checkpoint(#[from] xenia_ledger::CheckpointError),
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
            let is_authenticated_action = matches!(
                entry.event.kind,
                ConsentKind::Approval | ConsentKind::Denial | ConsentKind::Revocation
            );
            if is_authenticated_action && !replay_action_ids.insert(request_id) {
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

    /// Whether an authenticated action id was committed in archived history.
    pub(crate) fn contains_action_id(&self, action_id: &[u8; 16]) -> bool {
        self.replay_action_ids.binary_search(action_id).is_ok()
    }
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
        assert!(summary.contains_action_id(&[2u8; 16]));
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
    fn tampered_summary_is_rejected_even_when_json_shape_is_valid() {
        let segments = complete_archive();
        let mut summary = ConsentRecoverySummaryV1::from_archive_sequence(&segments).unwrap();
        summary.sessions[0].terminal_sequence = 99;
        assert!(matches!(
            summary.verify_against_archive(&segments),
            Err(ConsentRecoveryError::DigestMismatch)
        ));
    }
}
