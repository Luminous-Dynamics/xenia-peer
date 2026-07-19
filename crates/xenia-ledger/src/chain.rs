// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::SystemTime;

use ed25519_dalek::{Signer, SigningKey};

use crate::checkpoint::{LEDGER_CHECKPOINT_SCHEMA, LedgerCheckpoint, checkpoint_message};
use crate::entry::{ConsentEventRecord, LedgerEntry, LedgerEntryExport};
use crate::errors::{LedgerError, TransactionalAppendError};
use crate::hash::compute_entry_hash;

/// Append-only, hash-chained ledger owned by an operator with a
/// signing key. See the crate-level docs for the semantics.
pub struct Chain {
    entries: Vec<LedgerEntry>,
    signing_key: SigningKey,
}

impl Chain {
    /// Create a new empty chain held by `signing_key`.
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            entries: Vec::new(),
            signing_key,
        }
    }

    /// Rehydrate a chain from a previously-persisted sequence of entries.
    ///
    /// Does NOT verify the rehydrated entries — the caller should run
    /// [`crate::Verifier::verify_chain`] with the operator's public key to
    /// confirm integrity. This method only establishes the append
    /// frontier for subsequent [`Chain::append`] calls.
    pub fn from_entries(entries: Vec<LedgerEntry>, signing_key: SigningKey) -> Self {
        Self {
            entries,
            signing_key,
        }
    }

    /// Return the number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `entry_hash` of the most recent entry, or `[0; 32]` if the
    /// chain is empty (the implicit "pre-genesis" hash).
    pub fn last_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32])
    }

    /// Iterate over all entries in sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &LedgerEntry> {
        self.entries.iter()
    }

    /// Return entries converted to the export-safe signature-envelope shape.
    pub fn export_entries(&self) -> Vec<LedgerEntryExport> {
        self.entries
            .iter()
            .map(LedgerEntry::to_export_entry)
            .collect()
    }

    /// Append a new consent event, producing a signed, chained entry.
    pub fn append(&mut self, event: ConsentEventRecord) -> Result<&LedgerEntry, LedgerError> {
        let entry_index = self.entries.len();
        let seq = entry_index as u64;
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
    /// the full, now-including-this-entry list -- succeeds. On a `persist`
    /// failure the just-added entry is removed before returning, so a
    /// caller never observes a successful append that wasn't durably
    /// committed. This crate doesn't know or care *how* persistence
    /// works -- `persist` is any caller-supplied closure (typically a
    /// verified-atomic-file-write, but tests can use an in-memory stub).
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
        Ok(self
            .entries
            .last()
            .expect("append_transactional: entry was just pushed and persist succeeded"))
    }

    /// Consume the chain and return its entries. Useful for persistence.
    pub fn into_entries(self) -> Vec<LedgerEntry> {
        self.entries
    }

    /// Produce a signed [`LedgerCheckpoint`] committing to this chain's
    /// current length and head hash, without exposing any entry contents.
    /// Safe to publish without authentication -- see the checkpoint's own
    /// doc comment for why.
    pub fn sign_checkpoint(&self, timestamp_unix_secs: u64) -> LedgerCheckpoint {
        let entry_count = self.entries.len() as u64;
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
