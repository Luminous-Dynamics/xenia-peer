// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::SystemTime;

use ed25519_dalek::{Signer, SigningKey};

use crate::checkpoint::{LEDGER_CHECKPOINT_SCHEMA, LedgerCheckpoint, checkpoint_message};
use crate::entry::{ConsentEventRecord, LedgerEntry, LedgerEntryExport};
use crate::errors::{LedgerError, TransactionalAppendError};
use crate::hash::compute_entry_hash;

/// Exact in-memory candidate frontier whose persistence outcome is ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingPersistenceFrontier {
    /// Absolute sequence number of the ambiguous candidate entry.
    pub seq: u64,
    /// Hash of the ambiguous candidate entry.
    pub entry_hash: [u8; 32],
    /// Total chain entry count while the candidate remains resident.
    pub entry_count: u64,
    /// Current chain head while the candidate remains resident.
    pub head_hash: [u8; 32],
}

/// Storage callback classification for the outcome-aware append API.
///
/// A backend MUST return [`PersistenceDisposition::OutcomeUnknown`] whenever it
/// cannot prove whether the durable effect occurred.
#[derive(Debug)]
pub enum PersistenceDisposition<E> {
    /// The exact candidate frontier was durably persisted.
    Persisted,
    /// The backend can prove the candidate was not durably persisted.
    ProvenNotPersisted(E),
    /// The backend cannot determine whether the candidate was persisted.
    OutcomeUnknown(E),
}

/// Result of one outcome-aware append attempt.
#[derive(Debug)]
pub enum TransactionalAppendOutcome<E> {
    /// Persistence was confirmed and the entry remains the committed frontier.
    Persisted(LedgerEntry),
    /// Persistence was proven not to have happened and the candidate was removed.
    ProvenNotPersisted {
        /// Backend diagnostic/error value.
        error: E,
        /// Candidate entry that was safely rolled back from memory.
        reverted_entry: LedgerEntry,
    },
    /// Persistence may have happened. The candidate remains resident and the
    /// chain is latched against further append until reconciliation.
    OutcomeUnknown {
        /// Backend diagnostic/error value.
        error: E,
        /// Exact ambiguous candidate frontier.
        pending: PendingPersistenceFrontier,
    },
}

/// Result of explicitly reconciling one ambiguous persistence outcome.
#[derive(Debug)]
pub enum PersistenceReconciliationOutcome<E> {
    /// The candidate was confirmed durable and remains in the chain.
    Persisted(LedgerEntry),
    /// The candidate was proven absent from durable storage and was removed.
    ProvenNotPersisted {
        /// Backend reconciliation diagnostic/error value.
        error: E,
        /// Candidate entry removed after definitive non-persistence proof.
        reverted_entry: LedgerEntry,
    },
    /// Persistence remains ambiguous and the chain stays latched.
    OutcomeUnknown {
        /// Backend reconciliation diagnostic/error value.
        error: E,
        /// Exact still-ambiguous frontier.
        pending: PendingPersistenceFrontier,
    },
}

/// Append-only, hash-chained ledger owned by an operator with a
/// signing key. See the crate-level docs for the semantics.
pub struct Chain {
    /// Number of authenticated entries retained outside this in-memory suffix.
    /// Zero for ordinary complete chains.
    base_entry_count: u64,
    /// Hash immediately before the first resident entry. All zeros for an
    /// ordinary complete chain.
    base_head_hash: [u8; 32],
    /// Signed checkpoint authenticating the compacted prefix, when this chain
    /// contains only a resident suffix.
    base_checkpoint: Option<LedgerCheckpoint>,
    entries: Vec<LedgerEntry>,
    /// Latched exact candidate frontier after a persistence callback reports an
    /// ambiguous outcome. While set, all new append operations fail closed.
    pending_persistence: Option<PendingPersistenceFrontier>,
    pub(crate) signing_key: SigningKey,
}

impl Chain {
    /// Create a new empty chain held by `signing_key`.
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            base_entry_count: 0,
            base_head_hash: [0u8; 32],
            base_checkpoint: None,
            entries: Vec::new(),
            pending_persistence: None,
            signing_key,
        }
    }

    /// Rehydrate a chain from a previously-persisted sequence of entries.
    ///
    /// Does NOT verify the rehydrated entries — the caller should run
    /// [`crate::Verifier::verify_chain`] with the operator's public key to
    /// confirm integrity. This method only establishes the append
    /// frontier for subsequent [`Chain::append`] calls.
    ///
    /// An in-process ambiguous persistence latch is not serialized by this
    /// constructor. Crash recovery must determine the durable frontier from the
    /// storage system before constructing a new appendable chain.
    pub fn from_entries(entries: Vec<LedgerEntry>, signing_key: SigningKey) -> Self {
        Self {
            base_entry_count: 0,
            base_head_hash: [0u8; 32],
            base_checkpoint: None,
            entries,
            pending_persistence: None,
            signing_key,
        }
    }

    /// Rehydrate an appendable resident suffix after a separately retained,
    /// signed prefix checkpoint.
    ///
    /// This constructor does not verify either the checkpoint or the suffix.
    /// Callers must first run [`crate::Verifier::verify_checkpoint_extension`]
    /// (or an equivalent complete restore verifier) before trusting the state.
    pub fn from_checkpoint_suffix(
        base_checkpoint: LedgerCheckpoint,
        entries: Vec<LedgerEntry>,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            base_entry_count: base_checkpoint.entry_count,
            base_head_hash: base_checkpoint.head_hash,
            base_checkpoint: Some(base_checkpoint),
            entries,
            pending_persistence: None,
            signing_key,
        }
    }

    /// Return the total authenticated entry count, including a compacted prefix.
    pub fn len(&self) -> usize {
        usize::try_from(self.entry_count()).unwrap_or(usize::MAX)
    }

    /// Total authenticated entry count, including a compacted prefix.
    pub fn entry_count(&self) -> u64 {
        self.base_entry_count
            .saturating_add(self.entries.len() as u64)
    }

    /// Number of entries currently resident in memory and local live storage.
    pub fn resident_len(&self) -> usize {
        self.entries.len()
    }

    /// Signed checkpoint authenticating a non-resident prefix, if this is an
    /// anchored suffix chain.
    pub fn base_checkpoint(&self) -> Option<&LedgerCheckpoint> {
        self.base_checkpoint.as_ref()
    }

    /// Whether the chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entry_count() == 0
    }

    /// Return the exact ambiguous persistence frontier, if the chain is latched.
    pub fn pending_persistence_frontier(&self) -> Option<PendingPersistenceFrontier> {
        self.pending_persistence
    }

    /// Whether an ambiguous persistence outcome currently blocks new appends.
    pub fn has_uncertain_persistence(&self) -> bool {
        self.pending_persistence.is_some()
    }

    /// The `entry_hash` of the most recent entry, or `[0; 32]` if the
    /// chain is empty (the implicit "pre-genesis" hash).
    pub fn last_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or(self.base_head_hash)
    }

    /// Iterate over resident entries in sequence order. For an anchored suffix
    /// chain, entries before [`Chain::base_checkpoint`] are intentionally not
    /// resident and are therefore not yielded.
    pub fn iter(&self) -> impl Iterator<Item = &LedgerEntry> {
        self.entries.iter()
    }

    /// Return resident entries converted to the export-safe signature-envelope
    /// shape. A compacted prefix remains represented by [`Chain::base_checkpoint`].
    pub fn export_entries(&self) -> Vec<LedgerEntryExport> {
        self.entries
            .iter()
            .map(LedgerEntry::to_export_entry)
            .collect()
    }

    /// Append a new consent event, producing a signed, chained entry.
    ///
    /// If a prior storage operation has an unresolved persistence outcome, this
    /// fails closed until [`Chain::reconcile_pending_persistence`] resolves it.
    pub fn append(&mut self, event: ConsentEventRecord) -> Result<&LedgerEntry, LedgerError> {
        if let Some(pending) = self.pending_persistence {
            return Err(LedgerError::UncertainPersistencePending { seq: pending.seq });
        }

        let entry_index = self.entries.len();
        let seq = self
            .base_entry_count
            .checked_add(entry_index as u64)
            .ok_or(LedgerError::SequenceOverflow)?;
        let prev_hash = self.last_hash();
        let timestamp = SystemTime::now();

        let entry_hash = compute_entry_hash(seq, &prev_hash, &timestamp, &event)?;
        let signature = self.signing_key.sign(&entry_hash).to_bytes();

        self.entries.push(LedgerEntry {
            seq,
            prev_hash,
            timestamp,
            event,
            entry_hash,
            signature,
        });
        self.entries
            .get(entry_index)
            .ok_or(LedgerError::AppendInvariant)
    }

    /// Append a new consent event, but only keep it if `persist` -- given
    /// the resident, now-including-this-entry list -- succeeds.
    ///
    /// **Important:** this legacy method assumes `Err` proves the candidate was
    /// not durably persisted. It rolls the entry back immediately on `Err`.
    /// Storage paths where commit acknowledgement can be ambiguous must use
    /// [`Chain::append_transactional_outcome`] instead.
    pub fn append_transactional<E>(
        &mut self,
        event: ConsentEventRecord,
        persist: impl FnOnce(&[LedgerEntry]) -> Result<(), E>,
    ) -> Result<&LedgerEntry, TransactionalAppendError<E>> {
        self.append(event)
            .map_err(TransactionalAppendError::Ledger)?;
        if let Err(err) = persist(&self.entries) {
            self.entries.pop();
            return Err(TransactionalAppendError::Persist(err));
        }
        self.entries.last().ok_or(TransactionalAppendError::Ledger(
            LedgerError::AppendInvariant,
        ))
    }

    /// Transactional append variant whose persistence callback receives the
    /// complete chain frontier, including any compacted-prefix anchor.
    ///
    /// **Important:** like [`Chain::append_transactional`], callback `Err` must
    /// prove non-persistence. Ambiguous storage backends must use
    /// [`Chain::append_transactional_outcome`].
    pub fn append_transactional_chain<E>(
        &mut self,
        event: ConsentEventRecord,
        persist: impl FnOnce(&Self) -> Result<(), E>,
    ) -> Result<&LedgerEntry, TransactionalAppendError<E>> {
        self.append(event)
            .map_err(TransactionalAppendError::Ledger)?;
        if let Err(err) = persist(self) {
            self.entries.pop();
            return Err(TransactionalAppendError::Persist(err));
        }
        self.entries.last().ok_or(TransactionalAppendError::Ledger(
            LedgerError::AppendInvariant,
        ))
    }

    /// Outcome-aware transactional append for persistence layers whose commit
    /// acknowledgement can be ambiguous.
    ///
    /// The candidate frontier is latched **before** `persist` is invoked. If the
    /// callback panics and the caller catches the unwind while retaining this
    /// `Chain`, further append is therefore still blocked rather than assuming
    /// non-persistence.
    pub fn append_transactional_outcome<E>(
        &mut self,
        event: ConsentEventRecord,
        persist: impl FnOnce(&Self) -> PersistenceDisposition<E>,
    ) -> Result<TransactionalAppendOutcome<E>, LedgerError> {
        self.append(event)?;
        let candidate = self.entries.last().cloned().ok_or(LedgerError::AppendInvariant)?;
        let pending = self.pending_frontier_for(&candidate)?;
        self.pending_persistence = Some(pending);

        match persist(self) {
            PersistenceDisposition::Persisted => {
                self.ensure_pending_matches(pending)?;
                self.pending_persistence = None;
                Ok(TransactionalAppendOutcome::Persisted(candidate))
            }
            PersistenceDisposition::ProvenNotPersisted(error) => {
                self.ensure_pending_matches(pending)?;
                let reverted_entry = self
                    .entries
                    .pop()
                    .ok_or(LedgerError::PendingPersistenceInvariant)?;
                if reverted_entry.entry_hash != pending.entry_hash || reverted_entry.seq != pending.seq {
                    return Err(LedgerError::PendingPersistenceInvariant);
                }
                self.pending_persistence = None;
                Ok(TransactionalAppendOutcome::ProvenNotPersisted {
                    error,
                    reverted_entry,
                })
            }
            PersistenceDisposition::OutcomeUnknown(error) => {
                self.ensure_pending_matches(pending)?;
                Ok(TransactionalAppendOutcome::OutcomeUnknown { error, pending })
            }
        }
    }

    /// Reconcile the exact candidate latched by an earlier
    /// [`Chain::append_transactional_outcome`] call.
    ///
    /// No new ledger entry is created. `ProvenNotPersisted` removes only the
    /// exact ambiguous last entry; `OutcomeUnknown` preserves both the candidate
    /// and the append latch.
    pub fn reconcile_pending_persistence<E>(
        &mut self,
        reconcile: impl FnOnce(&Self, PendingPersistenceFrontier) -> PersistenceDisposition<E>,
    ) -> Result<PersistenceReconciliationOutcome<E>, LedgerError> {
        let pending = self
            .pending_persistence
            .ok_or(LedgerError::PendingPersistenceInvariant)?;
        self.ensure_pending_matches(pending)?;
        let candidate = self.entries.last().cloned().ok_or(LedgerError::PendingPersistenceInvariant)?;

        match reconcile(self, pending) {
            PersistenceDisposition::Persisted => {
                self.ensure_pending_matches(pending)?;
                self.pending_persistence = None;
                Ok(PersistenceReconciliationOutcome::Persisted(candidate))
            }
            PersistenceDisposition::ProvenNotPersisted(error) => {
                self.ensure_pending_matches(pending)?;
                let reverted_entry = self
                    .entries
                    .pop()
                    .ok_or(LedgerError::PendingPersistenceInvariant)?;
                if reverted_entry.entry_hash != pending.entry_hash || reverted_entry.seq != pending.seq {
                    return Err(LedgerError::PendingPersistenceInvariant);
                }
                self.pending_persistence = None;
                Ok(PersistenceReconciliationOutcome::ProvenNotPersisted {
                    error,
                    reverted_entry,
                })
            }
            PersistenceDisposition::OutcomeUnknown(error) => {
                self.ensure_pending_matches(pending)?;
                Ok(PersistenceReconciliationOutcome::OutcomeUnknown { error, pending })
            }
        }
    }

    fn pending_frontier_for(
        &self,
        entry: &LedgerEntry,
    ) -> Result<PendingPersistenceFrontier, LedgerError> {
        let entry_count = self.entry_count();
        let head_hash = self.last_hash();
        if entry_count == 0 || head_hash != entry.entry_hash {
            return Err(LedgerError::PendingPersistenceInvariant);
        }
        Ok(PendingPersistenceFrontier {
            seq: entry.seq,
            entry_hash: entry.entry_hash,
            entry_count,
            head_hash,
        })
    }

    fn ensure_pending_matches(
        &self,
        pending: PendingPersistenceFrontier,
    ) -> Result<(), LedgerError> {
        if self.pending_persistence != Some(pending)
            || self.entry_count() != pending.entry_count
            || self.last_hash() != pending.head_hash
            || self.entries.last().map(|entry| (entry.seq, entry.entry_hash))
                != Some((pending.seq, pending.entry_hash))
        {
            return Err(LedgerError::PendingPersistenceInvariant);
        }
        Ok(())
    }

    /// Consume the chain and return its resident entries. An anchored prefix,
    /// when present, is not included; persistence layers supporting compaction
    /// must retain [`Chain::base_checkpoint`] separately.
    ///
    /// The returned vector does not encode an in-process pending-persistence
    /// latch. Callers should reconcile any ambiguous outcome before consuming a
    /// live chain for ordinary persistence/export purposes.
    pub fn into_entries(self) -> Vec<LedgerEntry> {
        self.entries
    }

    /// Produce a signed [`LedgerCheckpoint`] committing to this chain's
    /// current length and head hash, without exposing any entry contents.
    /// Safe to publish without authentication -- see the checkpoint's own
    /// doc comment for why.
    ///
    /// If [`Chain::has_uncertain_persistence`] is true, this checkpoint commits
    /// the candidate in-memory frontier but does **not** prove it was durably
    /// persisted. Callers must not use such a checkpoint as persistence proof.
    pub fn sign_checkpoint(&self, timestamp_unix_secs: u64) -> LedgerCheckpoint {
        let entry_count = self.entry_count();
        let head_hash = self.last_hash();
        let ledger_public_key = self.signing_key.verifying_key().to_bytes();
        let message = checkpoint_message(
            entry_count,
            &head_hash,
            &ledger_public_key,
            timestamp_unix_secs,
        );
        let signature = self.signing_key.sign(&message).to_bytes();
        LedgerCheckpoint {
            schema: LEDGER_CHECKPOINT_SCHEMA.to_string(),
            entry_count,
            head_hash,
            ledger_public_key,
            timestamp_unix_secs,
            signature,
        }
    }
}
