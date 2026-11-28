// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Rollback-resistant checkpoint protocol for the durable operation WAL.
//!
//! A local unkeyed hash chain detects corruption of the retained prefix, but
//! cannot detect replacement with an older valid prefix. This module defines
//! an interface to an independent monotonic witness for the WAL head.
//!
//! The witness must live in a separate security/failure domain, such as a
//! remote witness service, HSM-backed monotonic store, or separately
//! administered service. A file beside the WAL is not an independent trust
//! anchor. Implementations must authenticate writers and provide durable,
//! atomic compare-and-swap generation updates.
//!
//! A newer local suffix is never auto-promoted merely because its local hash
//! chain is valid. The caller must independently verify its stage receipts
//! before requesting a checkpoint advance. This is essential: an unanchored
//! suffix can be rewritten by an actor who controls the WAL file.

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crate::operation_evidence_wal::{
    DurableOperationEvidenceJournal, DurableOperationJournalError,
    DurableOperationJournalHead,
};

/// A versioned checkpoint committed by an independent journal-head witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalHeadCheckpoint {
    /// Monotonically increasing witness generation.
    pub generation: u64,
    /// Payload-free WAL head accepted by the witness.
    pub head: DurableOperationJournalHead,
}

/// Errors returned by a journal-head witness implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalHeadWitnessError {
    /// Independent witness is unavailable; callers must fail closed.
    Unavailable,
    /// Another writer changed the checkpoint generation.
    CompareAndSwapConflict,
    /// The requested checkpoint violates the witness monotonicity contract.
    InvalidCheckpoint,
    /// Witness storage lock/state is poisoned.
    LockPoisoned,
}

/// Required interface for rollback-resistant journal-head storage.
///
/// A production implementation must provide durable atomic CAS semantics,
/// authenticate the writer, and store state outside the WAL's failure domain.
/// The memory implementation in tests is not a production trust anchor.
pub trait JournalHeadWitness: Send + Sync {
    /// Load the current checkpoint for one authenticated session.
    fn load(
        &self,
        session_fingerprint: [u8; 32],
    ) -> Result<Option<JournalHeadCheckpoint>, JournalHeadWitnessError>;

    /// Atomically replace the checkpoint if the stored generation matches.
    ///
    /// None means the session has never been initialized. A new session starts
    /// at generation 1; later updates increment the current generation by one.
    fn compare_and_swap(
        &self,
        session_fingerprint: [u8; 32],
        expected_generation: Option<u64>,
        next: JournalHeadCheckpoint,
    ) -> Result<JournalHeadCheckpoint, JournalHeadWitnessError>;
}

/// Result of comparing a recovered WAL head with its external checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalHeadVerification {
    /// The local recovered head exactly matches the trusted checkpoint.
    AlreadyAnchored,
    /// An empty new journal was initialized at the sequence-zero genesis head.
    InitializedEmptyJournal,
}

/// Receipt returned after an externally authorized checkpoint advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalHeadAdvanceReceipt {
    /// Previously trusted checkpoint.
    pub previous: JournalHeadCheckpoint,
    /// Newly trusted checkpoint.
    pub current: JournalHeadCheckpoint,
}

/// Rollback, fork, witness, or journal errors.
#[derive(Debug)]
pub enum JournalHeadAnchorError {
    /// The journal's retained history failed a structural/prefix check.
    Journal(DurableOperationJournalError),
    /// External checkpoint service failed or rejected an atomic update.
    Witness(JournalHeadWitnessError),
    /// A non-empty local WAL has no independently trusted checkpoint.
    MissingCheckpointForNonemptyJournal {
        /// Highest locally recovered WAL sequence.
        recovered_sequence: u64,
    },
    /// The local journal is older than the independent checkpoint.
    RollbackDetected {
        /// Sequence held by the witness.
        anchored_sequence: u64,
        /// Highest locally recovered sequence.
        recovered_sequence: u64,
    },
    /// The local WAL has a valid but unanchored suffix. Do not trust it until
    /// the caller independently verifies its receipts and advances the witness.
    UnanchoredSuffix {
        /// Highest sequence already accepted by the witness.
        anchored_sequence: u64,
        /// Highest locally recovered sequence.
        recovered_sequence: u64,
    },
    /// Operation sequence high-water would regress.
    OperationSequenceRegression,
    /// The witness generation counter is exhausted.
    GenerationExhausted,
}

impl From<DurableOperationJournalError> for JournalHeadAnchorError {
    fn from(error: DurableOperationJournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<JournalHeadWitnessError> for JournalHeadAnchorError {
    fn from(error: JournalHeadWitnessError) -> Self {
        Self::Witness(error)
    }
}

/// Verify a local journal against its independent checkpoint.
///
/// A first-use journal may be initialized automatically only while empty. A
/// non-empty journal without a checkpoint requires explicit administrative
/// bootstrap; this function never trusts an existing local file by itself.
/// A newer local suffix is reported as unanchored rather than silently accepted.
pub fn verify_journal_head<W: JournalHeadWitness>(
    journal: &DurableOperationEvidenceJournal,
    witness: &W,
) -> Result<(JournalHeadVerification, JournalHeadCheckpoint), JournalHeadAnchorError> {
    let candidate = journal.head_candidate();
    let existing = witness.load(candidate.session_fingerprint)?;
    match existing {
        None => {
            if candidate.journal_sequence != 0
                || candidate.wal_chain_digest != [0; 32]
                || candidate.last_operation_sequence.is_some()
            {
                return Err(
                    JournalHeadAnchorError::MissingCheckpointForNonemptyJournal {
                        recovered_sequence: candidate.journal_sequence,
                    },
                );
            }
            let checkpoint = JournalHeadCheckpoint {
                generation: 1,
                head: candidate,
            };
            let stored = witness.compare_and_swap(
                candidate.session_fingerprint,
                None,
                checkpoint,
            )?;
            Ok((JournalHeadVerification::InitializedEmptyJournal, stored))
        }
        Some(checkpoint) => {
            if checkpoint.head.session_fingerprint != candidate.session_fingerprint {
                return Err(JournalHeadAnchorError::Journal(
                    DurableOperationJournalError::SessionFingerprintMismatch,
                ));
            }
            if checkpoint.head.clock_domain != candidate.clock_domain {
                return Err(JournalHeadAnchorError::Journal(
                    DurableOperationJournalError::ClockDomainMismatch,
                ));
            }
            if candidate.journal_sequence < checkpoint.head.journal_sequence {
                return Err(JournalHeadAnchorError::RollbackDetected {
                    anchored_sequence: checkpoint.head.journal_sequence,
                    recovered_sequence: candidate.journal_sequence,
                });
            }
            journal.verify_anchor_prefix(&checkpoint.head)?;
            if candidate == checkpoint.head {
                return Ok((JournalHeadVerification::AlreadyAnchored, checkpoint));
            }
            if candidate.journal_sequence > checkpoint.head.journal_sequence {
                return Err(JournalHeadAnchorError::UnanchoredSuffix {
                    anchored_sequence: checkpoint.head.journal_sequence,
                    recovered_sequence: candidate.journal_sequence,
                });
            }
            Err(JournalHeadAnchorError::Journal(
                DurableOperationJournalError::JournalAnchorPrefixMismatch {
                    sequence: checkpoint.head.journal_sequence,
                },
            ))
        }
    }
}

/// Advance the independent witness after the caller has separately verified
/// every new stage/owner receipt in the local suffix.
///
/// This proves that the local suffix extends the exact previous checkpoint and
/// that sequence values do not regress. It does not claim that a local BLAKE3
/// digest proves the truth of external effects; the caller's evidence verifier
/// and the witness's authentication policy must establish that before invoking
/// this method.
pub fn advance_checkpoint_after_external_verification<W: JournalHeadWitness>(
    journal: &DurableOperationEvidenceJournal,
    witness: &W,
    expected_generation: u64,
) -> Result<JournalHeadAdvanceReceipt, JournalHeadAnchorError> {
    let candidate = journal.head_candidate();
    let previous = witness
        .load(candidate.session_fingerprint)?
        .ok_or(JournalHeadAnchorError::MissingCheckpointForNonemptyJournal {
            recovered_sequence: candidate.journal_sequence,
        })?;
    if previous.generation != expected_generation {
        return Err(JournalHeadAnchorError::Witness(
            JournalHeadWitnessError::CompareAndSwapConflict,
        ));
    }
    journal.verify_anchor_prefix(&previous.head)?;
    if candidate.journal_sequence <= previous.head.journal_sequence {
        return Err(JournalHeadAnchorError::UnanchoredSuffix {
            anchored_sequence: previous.head.journal_sequence,
            recovered_sequence: candidate.journal_sequence,
        });
    }
    match (
        previous.head.last_operation_sequence,
        candidate.last_operation_sequence,
    ) {
        (Some(old), Some(new)) if new < old => {
            return Err(JournalHeadAnchorError::OperationSequenceRegression);
        }
        (Some(_), None) => {
            return Err(JournalHeadAnchorError::OperationSequenceRegression);
        }
        _ => {}
    }
    let generation = previous
        .generation
        .checked_add(1)
        .ok_or(JournalHeadAnchorError::GenerationExhausted)?;
    let next = JournalHeadCheckpoint {
        generation,
        head: candidate,
    };
    let current = witness.compare_and_swap(
        candidate.session_fingerprint,
        Some(previous.generation),
        next,
    )?;
    Ok(JournalHeadAdvanceReceipt { previous, current })
}

#[cfg(test)]
#[derive(Clone, Default)]
pub struct MemoryJournalHeadWitness {
    checkpoints: Arc<Mutex<HashMap<[u8; 32], JournalHeadCheckpoint>>>,
}

#[cfg(test)]
impl JournalHeadWitness for MemoryJournalHeadWitness {
    fn load(
        &self,
        session_fingerprint: [u8; 32],
    ) -> Result<Option<JournalHeadCheckpoint>, JournalHeadWitnessError> {
        self.checkpoints
            .lock()
            .map(|state| state.get(&session_fingerprint).copied())
            .map_err(|_| JournalHeadWitnessError::LockPoisoned)
    }

    fn compare_and_swap(
        &self,
        session_fingerprint: [u8; 32],
        expected_generation: Option<u64>,
        next: JournalHeadCheckpoint,
    ) -> Result<JournalHeadCheckpoint, JournalHeadWitnessError> {
        if next.head.session_fingerprint != session_fingerprint {
            return Err(JournalHeadWitnessError::InvalidCheckpoint);
        }
        let mut state = self
            .checkpoints
            .lock()
            .map_err(|_| JournalHeadWitnessError::LockPoisoned)?;
        let current = state.get(&session_fingerprint).copied();
        match (expected_generation, current) {
            (None, None)
                if next.generation == 1
                    && next.head.journal_sequence == 0
                    && next.head.wal_chain_digest == [0; 32]
                    && next.head.last_operation_sequence.is_none() => {}
            (Some(expected), Some(existing)) if existing.generation == expected => {
                if Some(next.generation) != expected.checked_add(1)
                    || next.head.clock_domain != existing.head.clock_domain
                    || next.head.journal_sequence <= existing.head.journal_sequence
                {
                    return Err(JournalHeadWitnessError::InvalidCheckpoint);
                }
                match (
                    existing.head.last_operation_sequence,
                    next.head.last_operation_sequence,
                ) {
                    (Some(old), Some(new)) if new < old => {
                        return Err(JournalHeadWitnessError::InvalidCheckpoint);
                    }
                    (Some(_), None) => return Err(JournalHeadWitnessError::InvalidCheckpoint),
                    _ => {}
                }
            }
            _ => return Err(JournalHeadWitnessError::CompareAndSwapConflict),
        }
        state.insert(session_fingerprint, next);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m1_session::M1Permission;
    use crate::operation_evidence::{OperationContext, OperationDirection, OperationId};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "xenia-journal-head-anchor-{}-{}.wal",
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
            authority_commitment_digest: None,
            authority_epoch: Some(7),
        }
    }

    fn remove_journal(path: &Path) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn empty_journal_initializes_genesis_checkpoint_only() {
        let path = test_path();
        let session = [1; 32];
        let journal = DurableOperationEvidenceJournal::open(&path, session, 17)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        let witness = MemoryJournalHeadWitness::default();
        let (status, checkpoint) = verify_journal_head(&journal, &witness)
            .unwrap_or_else(|error| panic!("anchor init failed: {error:?}"));
        assert_eq!(status, JournalHeadVerification::InitializedEmptyJournal);
        assert_eq!(checkpoint.generation, 1);
        assert_eq!(checkpoint.head.journal_sequence, 0);
        assert_eq!(checkpoint.head.wal_chain_digest, [0; 32]);
        assert_eq!(checkpoint.head.last_operation_sequence, None);
        drop(journal);
        remove_journal(&path);
    }

    #[test]
    fn nonempty_unanchored_journal_is_not_silently_trusted() {
        let path = test_path();
        let session = [2; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 18)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        journal
            .admit(OperationId([1; 16]), 1, context(session, 1), 1, [4; 32])
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        let witness = MemoryJournalHeadWitness::default();
        assert!(matches!(
            verify_journal_head(&journal, &witness),
            Err(JournalHeadAnchorError::MissingCheckpointForNonemptyJournal {
                recovered_sequence: 1
            })
        ));
        drop(journal);
        remove_journal(&path);
    }

    #[test]
    fn verified_suffix_requires_explicit_checkpoint_advance() {
        let path = test_path();
        let session = [3; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 19)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        let witness = MemoryJournalHeadWitness::default();
        let (_, genesis) = verify_journal_head(&journal, &witness)
            .unwrap_or_else(|error| panic!("genesis anchor failed: {error:?}"));
        journal
            .admit(OperationId([2; 16]), 1, context(session, 2), 1, [5; 32])
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        assert!(matches!(
            verify_journal_head(&journal, &witness),
            Err(JournalHeadAnchorError::UnanchoredSuffix {
                anchored_sequence: 0,
                recovered_sequence: 1
            })
        ));
        let advanced = advance_checkpoint_after_external_verification(
            &journal,
            &witness,
            genesis.generation,
        )
        .unwrap_or_else(|error| panic!("checkpoint advance failed: {error:?}"));
        assert_eq!(advanced.current.generation, 2);
        assert_eq!(advanced.current.head, journal.head_candidate());
        let (status, current) = verify_journal_head(&journal, &witness)
            .unwrap_or_else(|error| panic!("verification failed: {error:?}"));
        assert_eq!(status, JournalHeadVerification::AlreadyAnchored);
        assert_eq!(current, advanced.current);
        drop(journal);
        remove_journal(&path);
    }

    #[test]
    fn checkpoint_rejects_truncated_valid_prefix_as_rollback() {
        let path = test_path();
        let session = [4; 32];
        let witness = MemoryJournalHeadWitness::default();
        let prefix_bytes;
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 20)
                .unwrap_or_else(|error| panic!("open failed: {error:?}"));
            let (_, genesis) = verify_journal_head(&journal, &witness)
                .unwrap_or_else(|error| panic!("genesis anchor failed: {error:?}"));
            journal
                .admit(OperationId([3; 16]), 1, context(session, 3), 1, [6; 32])
                .unwrap_or_else(|error| panic!("first admission failed: {error:?}"));
            let first = advance_checkpoint_after_external_verification(
                &journal,
                &witness,
                genesis.generation,
            )
            .unwrap_or_else(|error| panic!("first advance failed: {error:?}"));
            prefix_bytes = fs::read(&path)
                .unwrap_or_else(|error| panic!("prefix read failed: {error:?}"));
            journal
                .admit(OperationId([4; 16]), 2, context(session, 4), 2, [7; 32])
                .unwrap_or_else(|error| panic!("second admission failed: {error:?}"));
            let _second = advance_checkpoint_after_external_verification(
                &journal,
                &witness,
                first.current.generation,
            )
            .unwrap_or_else(|error| panic!("second advance failed: {error:?}"));
        }
        fs::write(&path, prefix_bytes)
            .unwrap_or_else(|error| panic!("rollback fixture write failed: {error:?}"));
        let recovered = DurableOperationEvidenceJournal::open(&path, session, 20)
            .unwrap_or_else(|error| panic!("reopen failed: {error:?}"));
        assert!(matches!(
            verify_journal_head(&recovered, &witness),
            Err(JournalHeadAnchorError::RollbackDetected {
                anchored_sequence: 2,
                recovered_sequence: 1
            })
        ));
        drop(recovered);
        remove_journal(&path);
    }

    #[test]
    fn journal_prefix_index_is_reconstructed_after_restart() {
        let path = test_path();
        let session = [6; 32];
        let anchor;
        {
            let mut journal = DurableOperationEvidenceJournal::open(&path, session, 22)
                .unwrap_or_else(|error| panic!("open failed: {error:?}"));
            journal
                .admit(OperationId([5; 16]), 5, context(session, 5), 1, [8; 32])
                .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
            anchor = journal.head_candidate();
        }
        let recovered = DurableOperationEvidenceJournal::open(&path, session, 22)
            .unwrap_or_else(|error| panic!("reopen failed: {error:?}"));
        assert!(recovered.verify_anchor_prefix(&anchor).is_ok());
        drop(recovered);
        remove_journal(&path);
    }

    #[test]
    fn journal_prefix_check_rejects_forked_digest_and_sequence() {
        let path = test_path();
        let session = [7; 32];
        let mut journal = DurableOperationEvidenceJournal::open(&path, session, 23)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        journal
            .admit(OperationId([6; 16]), 6, context(session, 6), 1, [9; 32])
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        let anchor = journal.head_candidate();

        let mut wrong_digest = anchor;
        wrong_digest.wal_chain_digest = [0xA5; 32];
        assert!(matches!(
            journal.verify_anchor_prefix(&wrong_digest),
            Err(DurableOperationJournalError::JournalAnchorPrefixMismatch { sequence: 1 })
        ));

        let mut wrong_operation_sequence = anchor;
        wrong_operation_sequence.last_operation_sequence = Some(99);
        assert!(matches!(
            journal.verify_anchor_prefix(&wrong_operation_sequence),
            Err(DurableOperationJournalError::JournalAnchorPrefixMismatch { sequence: 1 })
        ));
        drop(journal);
        remove_journal(&path);
    }

    #[test]
    fn witness_compare_and_swap_rejects_stale_generation() {
        let path = test_path();
        let session = [5; 32];
        let journal = DurableOperationEvidenceJournal::open(&path, session, 21)
            .unwrap_or_else(|error| panic!("open failed: {error:?}"));
        let witness = MemoryJournalHeadWitness::default();
        let (_, checkpoint) = verify_journal_head(&journal, &witness)
            .unwrap_or_else(|error| panic!("anchor init failed: {error:?}"));
        let next = JournalHeadCheckpoint {
            generation: 2,
            head: checkpoint.head,
        };
        assert_eq!(
            witness.compare_and_swap(session, Some(0), next),
            Err(JournalHeadWitnessError::CompareAndSwapConflict)
        );
        drop(journal);
        remove_journal(&path);
    }
}
