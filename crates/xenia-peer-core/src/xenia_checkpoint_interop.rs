// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical, payload-redacted checkpoint bytes for Mycelix transparency.
//!
//! This module defines only the Xenia source-log statement. It does not
//! implement RFC 9162, authenticate a transparency tree head, verify Mycelix
//! witness governance, or establish that external effects are true.
//!
//! A Mycelix adapter can include these exact bytes as a leaf in its governed
//! transparency log. RFC 9162 then proves inclusion relative to a supplied
//! root; the separate Mycelix governance layer must authenticate that root and
//! apply witness identity, organization-diversity, key-epoch, and compromise
//! policy. A separate effect verifier must validate owner receipts when the
//! deployment wants to claim more than a source-journal commitment.
//!
//! The raw Xenia session fingerprint is never exported. A deployment-specific
//! keyed BLAKE3 commitment provides an opaque scope identifier. The scope key
//! is never serialized and must be held outside this crate.

use crate::operation_evidence::OperationEvidenceStateCounts;
use crate::operation_evidence_wal::{DurableOperationEvidenceJournal, DurableOperationJournalHead};

/// Version of the canonical Xenia-to-Mycelix checkpoint payload.
pub const XENIA_MYCELIX_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
/// Domain separator for canonical checkpoint payload bytes.
pub const XENIA_MYCELIX_CHECKPOINT_DOMAIN: &[u8] =
    b"XENIA-MYCELIX-OPERATION-JOURNAL-CHECKPOINT-V1\0";
/// Domain separator for the local BLAKE3 checkpoint digest.
pub const XENIA_MYCELIX_CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"XENIA-MYCELIX-CHECKPOINT-DIGEST-V1\0";
/// Domain separator for deployment-scoped journal identity.
pub const XENIA_MYCELIX_SCOPE_DOMAIN: &[u8] = b"XENIA-MYCELIX-JOURNAL-SCOPE-V1\0";

/// Versioned, payload-redacted Xenia WAL checkpoint statement.
///
/// This is a statement by the Xenia publisher, not independent proof of
/// operation truth. Mycelix witnesses authenticate the checkpoint/tree head
/// under their governance policy; a separate verifier must replay or otherwise
/// validate Xenia evidence when the deployment requires that stronger claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XeniaJournalCheckpointV1 {
    /// Opaque commitment to one Xenia journal/session scope.
    pub journal_scope_commitment: [u8; 32],
    /// Monotonic clock domain used by the local operation journal.
    pub clock_domain: u64,
    /// Current M1 authority/rekey epoch supplied by the authenticated caller.
    pub authority_epoch: u64,
    /// Digest of the exact M1 permission/consent policy in force.
    pub policy_digest: [u8; 32],
    /// Durable WAL record sequence.
    pub journal_sequence: u64,
    /// Unkeyed BLAKE3 hash-chain head of the framed WAL.
    pub wal_chain_digest: [u8; 32],
    /// BLAKE3 hash-chain head of the operation-stage ledger.
    pub operation_chain_digest: [u8; 32],
    /// Highest admitted operation sequence, if any.
    pub last_operation_sequence: Option<u64>,
    /// Number of operation-stage events represented by the ledger.
    pub operation_event_count: u64,
    /// Payload-free lifecycle counts reconstructed from the WAL.
    pub state_counts: OperationEvidenceStateCounts,
}

/// Failure to construct an exportable checkpoint from the current WAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XeniaCheckpointBuildError {
    /// A failed append poisoned the current journal writer.
    JournalPoisoned,
    /// The semantic operation-stage chain failed its integrity check.
    OperationChainInvalid,
}

impl std::fmt::Display for XeniaCheckpointBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JournalPoisoned => write!(f, "operation WAL writer is poisoned"),
            Self::OperationChainInvalid => write!(f, "operation evidence chain is invalid"),
        }
    }
}

impl std::error::Error for XeniaCheckpointBuildError {}

impl XeniaJournalCheckpointV1 {
    /// Build a payload from a fully replayed WAL.
    ///
    /// The scope key must be high-entropy and deployment-specific. It is used
    /// only to derive an opaque scope commitment and is never serialized.
    /// Authority epoch and policy digest must come from current authenticated
    /// M1 authority state, not from an untrusted request.
    pub fn from_journal(
        journal: &DurableOperationEvidenceJournal,
        scope_key: &[u8; 32],
        authority_epoch: u64,
        policy_digest: [u8; 32],
    ) -> Result<Self, XeniaCheckpointBuildError> {
        if journal.is_poisoned() {
            return Err(XeniaCheckpointBuildError::JournalPoisoned);
        }
        if !journal.verify_operation_chain() {
            return Err(XeniaCheckpointBuildError::OperationChainInvalid);
        }
        let head = journal.head_candidate();
        Ok(Self {
            journal_scope_commitment: derive_journal_scope_commitment(
                scope_key,
                &head.session_fingerprint,
                head.clock_domain,
            ),
            clock_domain: head.clock_domain,
            authority_epoch,
            policy_digest,
            journal_sequence: head.journal_sequence,
            wal_chain_digest: head.wal_chain_digest,
            operation_chain_digest: journal.operation_chain_digest(),
            last_operation_sequence: head.last_operation_sequence,
            operation_event_count: journal.events().len() as u64,
            state_counts: journal.state_counts(),
        })
    }

    /// Deterministically encode the public wire payload.
    ///
    /// All integers are unsigned big-endian. The optional operation sequence
    /// uses a one-byte tag (0 = None, 1 = Some), followed by a big-endian u64
    /// only for Some. The ten state counts follow in the declared field order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(320);
        output.extend_from_slice(XENIA_MYCELIX_CHECKPOINT_DOMAIN);
        output.extend_from_slice(&XENIA_MYCELIX_CHECKPOINT_SCHEMA_VERSION.to_be_bytes());
        output.extend_from_slice(&self.journal_scope_commitment);
        output.extend_from_slice(&self.clock_domain.to_be_bytes());
        output.extend_from_slice(&self.authority_epoch.to_be_bytes());
        output.extend_from_slice(&self.policy_digest);
        output.extend_from_slice(&self.journal_sequence.to_be_bytes());
        output.extend_from_slice(&self.wal_chain_digest);
        output.extend_from_slice(&self.operation_chain_digest);
        match self.last_operation_sequence {
            None => output.push(0),
            Some(sequence) => {
                output.push(1);
                output.extend_from_slice(&sequence.to_be_bytes());
            }
        }
        output.extend_from_slice(&self.operation_event_count.to_be_bytes());
        let counts = self.state_counts;
        for count in [
            counts.admitted,
            counts.attempted,
            counts.committed,
            counts.observed,
            counts.rejected,
            counts.not_committed,
            counts.unknown,
            counts.reconciled_not_committed,
            counts.reconciled_committed,
            counts.reconciled_observed,
        ] {
            output.extend_from_slice(&count.to_be_bytes());
        }
        output
    }

    /// Return the local BLAKE3 digest of the canonical payload.
    ///
    /// This digest is useful for content identity and API idempotency. It is
    /// not the RFC 9162 leaf hash and does not authenticate a Mycelix tree root.
    pub fn checkpoint_digest(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(XENIA_MYCELIX_CHECKPOINT_DIGEST_DOMAIN);
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    /// Whether any effect is admitted, attempted, or still ambiguous.
    pub fn has_unresolved_effects(&self) -> bool {
        self.state_counts.pending_effects() > 0
    }

    /// Whether local commits still await a stronger observation.
    pub fn has_pending_observation(&self) -> bool {
        self.state_counts.pending_observation() > 0
    }

    /// Whether the operation lifecycle is fully resolved at its declared layer.
    pub fn has_unresolved_lifecycle(&self) -> bool {
        self.state_counts.has_unresolved_lifecycle()
    }

    /// Verify that this statement still describes the exact current WAL and
    /// the same authenticated authority/policy inputs.
    pub fn matches_journal(
        &self,
        journal: &DurableOperationEvidenceJournal,
        scope_key: &[u8; 32],
        authority_epoch: u64,
        policy_digest: [u8; 32],
    ) -> bool {
        Self::from_journal(journal, scope_key, authority_epoch, policy_digest)
            .is_ok_and(|current| *self == current)
    }
}

/// Derive a deployment-scoped opaque journal identifier.
///
/// The keyed commitment prevents an observer without the deployment scope key
/// from correlating a raw session fingerprint across different deployments.
pub fn derive_journal_scope_commitment(
    scope_key: &[u8; 32],
    session_fingerprint: &[u8; 32],
    clock_domain: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(scope_key);
    hasher.update(XENIA_MYCELIX_SCOPE_DOMAIN);
    hasher.update(session_fingerprint);
    hasher.update(&clock_domain.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Check whether a checkpoint's WAL-head fields still match a recovered head.
///
/// This does not authenticate a witness or a transparency root.
pub fn checkpoint_matches_head(
    checkpoint: &XeniaJournalCheckpointV1,
    head: &DurableOperationJournalHead,
) -> bool {
    checkpoint.clock_domain == head.clock_domain
        && checkpoint.journal_sequence == head.journal_sequence
        && checkpoint.wal_chain_digest == head.wal_chain_digest
        && checkpoint.last_operation_sequence == head.last_operation_sequence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m1_session::M1Permission;
    use crate::operation_evidence::{OperationContext, OperationDirection, OperationId};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn journal_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "xenia-mycelix-checkpoint-{}-{}.wal",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn context(session: [u8; 32], id: u8) -> OperationContext {
        OperationContext {
            session_fingerprint: session,
            lane: M1Permission::StreamFrame,
            direction: OperationDirection::HostToViewer,
            resource_digest: [id.wrapping_add(1); 32],
            consent_reference_digest: [2; 32],
            policy_digest: [3; 32],
            authority_commitment_digest: Some([4; 32]),
            authority_epoch: Some(7),
        }
    }

    fn remove_journal(path: &PathBuf) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn canonical_checkpoint_matches_shared_cross_language_golden_vector() {
        const FIXTURE: &str = include_str!("../../../fixtures/xenia-myclix-checkpoint-v1.kat");
        let expected = FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix("payload_hex="))
            .unwrap_or_else(|| panic!("golden payload hex missing"));
        let checkpoint = XeniaJournalCheckpointV1 {
            journal_scope_commitment: [0x11; 32],
            clock_domain: 0x0102_0304_0506_0708,
            authority_epoch: 0x1112_1314_1516_1718,
            policy_digest: [0x22; 32],
            journal_sequence: 0x2122_2324_2526_2728,
            wal_chain_digest: [0x33; 32],
            operation_chain_digest: [0x44; 32],
            last_operation_sequence: Some(0x3132_3334_3536_3738),
            operation_event_count: 0x4142_4344_4546_4748,
            state_counts: OperationEvidenceStateCounts {
                admitted: 0x51,
                attempted: 0x52,
                committed: 0x53,
                observed: 0x54,
                rejected: 0x55,
                not_committed: 0x56,
                unknown: 0x57,
                reconciled_not_committed: 0x58,
                reconciled_committed: 0x59,
                reconciled_observed: 0x5A,
            },
        };
        let actual = checkpoint
            .canonical_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected);
        assert_eq!(checkpoint.canonical_bytes().len(), 297);
    }

    #[test]
    fn checkpoint_is_deterministic_and_redacts_raw_session_fingerprint() {
        let path = journal_path();
        let session = [0xA1; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 31)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        journal
            .admit(OperationId([1; 16]), 1, context(session, 1), 1, [5; 32])
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        let checkpoint =
            XeniaJournalCheckpointV1::from_journal(&journal, &[0xB2; 32], 7, [0xC3; 32]);
        let bytes = checkpoint.canonical_bytes();
        assert_eq!(
            checkpoint,
            XeniaJournalCheckpointV1::from_journal(&journal, &[0xB2; 32], 7, [0xC3; 32])
        );
        assert!(
            !bytes.windows(32).any(|window| window == session),
            "canonical checkpoint must not expose the raw session fingerprint"
        );
        assert_eq!(checkpoint.state_counts.admitted, 1);
        assert_eq!(checkpoint.state_counts.pending_effects(), 1);
        assert!(checkpoint.has_unresolved_effects());
        assert!(checkpoint.has_unresolved_lifecycle());
        assert!(checkpoint.matches_journal(&journal, &[0xB2; 32], 7, [0xC3; 32]));
        assert!(checkpoint_matches_head(
            &checkpoint,
            &journal.head_candidate()
        ));
        drop(journal);
        remove_journal(&path);
    }

    #[test]
    fn scope_commitment_is_keyed_and_deployment_scoped() {
        let session = [1; 32];
        let first = derive_journal_scope_commitment(&[2; 32], &session, 3);
        assert_eq!(
            first,
            derive_journal_scope_commitment(&[2; 32], &session, 3)
        );
        assert_ne!(
            first,
            derive_journal_scope_commitment(&[4; 32], &session, 3)
        );
        assert_ne!(
            first,
            derive_journal_scope_commitment(&[2; 32], &session, 4)
        );
        assert_ne!(
            first,
            derive_journal_scope_commitment(&[2; 32], &[9; 32], 3)
        );
    }

    #[test]
    fn checkpoint_digest_binds_policy_epoch_and_unknown_state() {
        let mut first = XeniaJournalCheckpointV1 {
            journal_scope_commitment: [1; 32],
            clock_domain: 2,
            authority_epoch: 7,
            policy_digest: [3; 32],
            journal_sequence: 4,
            wal_chain_digest: [5; 32],
            operation_chain_digest: [6; 32],
            last_operation_sequence: Some(8),
            operation_event_count: 9,
            state_counts: OperationEvidenceStateCounts {
                admitted: 1,
                attempted: 1,
                unknown: 1,
                ..OperationEvidenceStateCounts::default()
            },
        };
        let digest = first.checkpoint_digest();
        first.authority_epoch += 1;
        assert_ne!(digest, first.checkpoint_digest());
        first.authority_epoch -= 1;
        first.state_counts.unknown += 1;
        assert_ne!(digest, first.checkpoint_digest());
        first.state_counts.unknown -= 1;
        first.policy_digest[0] ^= 0xFF;
        assert_ne!(digest, first.checkpoint_digest());
    }

    #[test]
    fn local_commit_remains_distinct_from_stronger_observation() {
        let path = journal_path();
        let session = [8; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 33)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        let operation_id = OperationId([2; 16]);
        journal
            .admit(operation_id, 1, context(session, 2), 1, [11; 32])
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        journal
            .mark_attempted(operation_id, 2, [12; 32])
            .unwrap_or_else(|error| panic!("attempt failed: {error:?}"));
        journal
            .mark_committed(operation_id, 3, [13; 32])
            .unwrap_or_else(|error| panic!("commit failed: {error:?}"));

        let committed =
            XeniaJournalCheckpointV1::from_journal(&journal, &[0xCC; 32], 7, [0xDD; 32]);
        assert_eq!(committed.state_counts.committed, 1);
        assert_eq!(committed.state_counts.observed, 0);
        assert_eq!(committed.state_counts.pending_effects(), 0);
        assert_eq!(committed.state_counts.pending_observation(), 1);
        assert!(committed.has_pending_observation());
        assert!(committed.has_unresolved_lifecycle());

        journal
            .mark_observed(operation_id, 4, [14; 32])
            .unwrap_or_else(|error| panic!("observation failed: {error:?}"));
        let observed = XeniaJournalCheckpointV1::from_journal(&journal, &[0xCC; 32], 7, [0xDD; 32]);
        assert_eq!(observed.state_counts.observed, 1);
        assert_eq!(observed.state_counts.pending_observation(), 0);
        assert!(!observed.has_unresolved_effects());
        assert!(!observed.has_unresolved_lifecycle());
        drop(journal);
        remove_journal(&path);
    }

    #[test]
    fn checkpoint_exports_unknown_operations_without_claiming_resolution() {
        let path = journal_path();
        let session = [7; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 32)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        journal
            .admit(OperationId([1; 16]), 1, context(session, 1), 1, [8; 32])
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        journal
            .mark_attempted(OperationId([1; 16]), 2, [9; 32])
            .unwrap_or_else(|error| panic!("attempt failed: {error:?}"));
        journal
            .mark_unknown(OperationId([1; 16]), 3, [10; 32])
            .unwrap_or_else(|error| panic!("unknown failed: {error:?}"));
        let checkpoint =
            XeniaJournalCheckpointV1::from_journal(&journal, &[0xAA; 32], 7, [0xBB; 32]);
        assert_eq!(checkpoint.state_counts.unknown, 1);
        assert_eq!(checkpoint.state_counts.pending_effects(), 1);
        assert!(checkpoint.has_unresolved_effects());
        assert!(checkpoint.has_unresolved_lifecycle());
        drop(journal);
        remove_journal(&path);
    }
}
