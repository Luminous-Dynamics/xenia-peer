// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compare-and-swap persistence wrapper for the signed release journal.
//!
//! The signed hash chain detects divergent histories once their heads are
//! compared. This wrapper additionally prevents ordinary concurrent writers from
//! both extending the same durable head when the backing store implements atomic
//! compare-and-swap semantics.

use serde::{Deserialize, Serialize};

use crate::chain::Chain;
use crate::disclosure_v2::{
    AccountabilityDisclosureError, AccountabilityDisclosurePermit, CommittedDisclosurePermit,
    DisclosureReleaseEntry, DisclosureReleaseOutcome,
    DisclosureReleaseState as RawDisclosureReleaseState, TransactionalDisclosureError,
};
use crate::policy::EvidenceCryptoManifest;

/// Durable signed-journal frontier used as a compare-and-swap token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureReleaseFrontier {
    /// Number of durable signed entries.
    pub entry_count: u64,
    /// Last signed entry hash, or all-zero for an empty journal.
    pub head_hash: [u8; 32],
}

impl DisclosureReleaseFrontier {
    /// Empty-journal frontier.
    pub const GENESIS: Self = Self {
        entry_count: 0,
        head_hash: [0u8; 32],
    };
}

/// Atomic persistence contract for release-journal transitions.
pub trait DisclosureReleaseStore {
    /// Store-specific failure.
    type Error;

    /// Persist `next_entries` only when the currently durable frontier equals
    /// `expected`. A stale writer must fail without modifying durable state.
    fn compare_and_swap(
        &mut self,
        expected: DisclosureReleaseFrontier,
        next_entries: &[DisclosureReleaseEntry],
    ) -> Result<(), Self::Error>;
}

/// Release state whose public mutation methods always require CAS persistence.
#[derive(Debug, Default)]
pub struct CasDisclosureReleaseState {
    inner: RawDisclosureReleaseState,
}

impl CasDisclosureReleaseState {
    /// Verify and rehydrate persisted signed entries before allowing mutation.
    pub fn from_verified_entries(
        entries: Vec<DisclosureReleaseEntry>,
        ledger_public_key: &[u8],
    ) -> Result<Self, AccountabilityDisclosureError> {
        Ok(Self {
            inner: RawDisclosureReleaseState::from_verified_entries(entries, ledger_public_key)?,
        })
    }

    /// Current in-memory frontier.
    pub fn frontier(&self) -> DisclosureReleaseFrontier {
        frontier_from_entries(self.inner.entries())
    }

    /// Signed entries for audit/export.
    pub fn entries(&self) -> &[DisclosureReleaseEntry] {
        self.inner.entries()
    }

    /// Consume the state into its serializable signed entries.
    pub fn into_entries(self) -> Vec<DisclosureReleaseEntry> {
        self.inner.into_entries()
    }

    /// Commit a prepared permit only through an atomic CAS persistence step.
    pub fn commit_permit<S: DisclosureReleaseStore>(
        &mut self,
        chain: &Chain,
        permit: AccountabilityDisclosurePermit,
        manifest: EvidenceCryptoManifest,
        store: &mut S,
    ) -> Result<CommittedDisclosurePermit, TransactionalDisclosureError<S::Error>> {
        let expected = self.frontier();
        self.inner
            .commit_permit_transactional(chain, permit, manifest, |next_entries| {
                store.compare_and_swap(expected, next_entries)
            })
    }

    /// Record one terminal outcome only through an atomic CAS persistence step.
    pub fn record_outcome<S: DisclosureReleaseStore>(
        &mut self,
        chain: &Chain,
        release_id: uuid::Uuid,
        outcome: DisclosureReleaseOutcome,
        store: &mut S,
    ) -> Result<(), TransactionalDisclosureError<S::Error>> {
        let expected = self.frontier();
        self.inner
            .record_outcome_transactional(chain, release_id, outcome, |next_entries| {
                store.compare_and_swap(expected, next_entries)
            })
    }
}

fn frontier_from_entries(entries: &[DisclosureReleaseEntry]) -> DisclosureReleaseFrontier {
    DisclosureReleaseFrontier {
        entry_count: entries.len() as u64,
        head_hash: entries
            .last()
            .map(DisclosureReleaseEntry::entry_hash)
            .unwrap_or([0u8; 32]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_has_genesis_frontier() {
        let state = CasDisclosureReleaseState::default();
        assert_eq!(state.frontier(), DisclosureReleaseFrontier::GENESIS);
    }
}
