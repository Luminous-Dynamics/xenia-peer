// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed process-crash recovery for SIF protected-file sends.
//!
//! The strict Unix staged-source path intentionally unlinks its private snapshot after
//! opening it. A process crash therefore destroys the in-memory source handle. The
//! durable write-ahead send journal can still prove exactly which unique ranges were
//! prepared before carrier I/O and which were later carrier-confirmed, but it cannot by
//! itself prove that the source reached its independently verified EOF/BLAKE3 terminal.
//!
//! Recovery is therefore **terminalization, not resumability**. This module verifies the
//! signed send journal offline and derives a conservative release outcome. It never
//! synthesizes `Completed`, even when every declared content byte was carrier-confirmed.
//! A later disclosure attempt requires a fresh release authorization/source lineage.

use uuid::Uuid;
use xenia_ledger::{
    DisclosureReleaseOutcome, FileDisclosureByteAccounting, SifProtectedFileOffer,
    SifProtectedFileSendEntry, SifProtectedFileSendError, SifProtectedFileSendState,
};

/// Verified terminal interpretation of one send journal recovered after process loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredSifSendTerminal {
    release_id: Uuid,
    outcome: DisclosureReleaseOutcome,
    byte_accounting: FileDisclosureByteAccounting,
    possibly_disclosed_unique_bytes: u64,
    confirmed_unique_bytes: u64,
}

impl RecoveredSifSendTerminal {
    /// Exact durable release identifier recovered from the protected Offer.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Fail-closed release outcome to durably record after recovery.
    ///
    /// Recovery produces only `Aborted` or `Partial`; it never produces `Completed`.
    pub const fn outcome(&self) -> DisclosureReleaseOutcome {
        self.outcome
    }

    /// Whether the recovered Partial byte count is exact or a conservative upper bound.
    pub const fn byte_accounting(&self) -> FileDisclosureByteAccounting {
        self.byte_accounting
    }

    /// Unique content bytes durably prepared before carrier I/O.
    pub const fn possibly_disclosed_unique_bytes(&self) -> u64 {
        self.possibly_disclosed_unique_bytes
    }

    /// Unique content bytes whose carrier success was durably confirmed.
    pub const fn confirmed_unique_bytes(&self) -> u64 {
        self.confirmed_unique_bytes
    }
}

/// Verify one persisted send journal and derive its fail-closed process-crash terminal.
///
/// `ledger_public_key` must be the trusted verifier key for the signed send journal. The
/// journal is fully revalidated before any byte frontier is trusted.
pub fn recover_sif_send_terminal(
    offer: SifProtectedFileOffer,
    entries: Vec<SifProtectedFileSendEntry>,
    ledger_public_key: &[u8],
) -> Result<RecoveredSifSendTerminal, SifProtectedFileSendError> {
    let release_id = offer.release_id();
    let state = SifProtectedFileSendState::from_verified_entries(
        offer,
        entries,
        ledger_public_key,
    )?;
    let possible = state.possibly_disclosed_unique_bytes()?;
    let confirmed = state.confirmed_unique_bytes()?;

    let (outcome, byte_accounting) = if possible == 0 {
        (
            DisclosureReleaseOutcome::Aborted,
            FileDisclosureByteAccounting::Exact,
        )
    } else {
        let accounting = if confirmed == possible {
            FileDisclosureByteAccounting::Exact
        } else {
            FileDisclosureByteAccounting::ConservativeUpperBound
        };
        (
            DisclosureReleaseOutcome::Partial {
                bytes_released: possible,
            },
            accounting,
        )
    };

    Ok(RecoveredSifSendTerminal {
        release_id,
        outcome,
        byte_accounting,
        possibly_disclosed_unique_bytes: possible,
        confirmed_unique_bytes: confirmed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use xenia_ledger::{
        Chain, SifProtectedFileChunk, SifProtectedFileSendFrontier,
        SifProtectedFileSendStore, sif_file_result_digest,
    };

    #[derive(Debug, Default)]
    struct MemoryStore {
        entries: Vec<SifProtectedFileSendEntry>,
    }

    impl SifProtectedFileSendStore for MemoryStore {
        type Error = ();

        fn compare_and_swap(
            &mut self,
            expected: SifProtectedFileSendFrontier,
            next_entries: &[SifProtectedFileSendEntry],
        ) -> Result<(), Self::Error> {
            let actual = SifProtectedFileSendFrontier {
                entry_count: self.entries.len() as u64,
                head_hash: self
                    .entries
                    .last()
                    .map(SifProtectedFileSendEntry::entry_hash)
                    .unwrap_or([0u8; 32]),
            };
            if actual != expected {
                return Err(());
            }
            self.entries = next_entries.to_vec();
            Ok(())
        }
    }

    fn fixture(size: u64) -> (
        Chain,
        [u8; 32],
        SifProtectedFileOffer,
        SifProtectedFileSendState,
        MemoryStore,
    ) {
        let signing_key = SigningKey::from_bytes(&[0x51; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let chain = Chain::new(signing_key);
        let content_hash = [0x61; 32];
        let result = sif_file_result_digest("evidence.bin", size, content_hash).unwrap();
        let offer = SifProtectedFileOffer::new(
            Uuid::from_u128(0x100),
            9,
            [0x22; 32],
            result,
            "evidence.bin",
            size,
            content_hash,
        )
        .unwrap();
        let state = SifProtectedFileSendState::new(offer.clone(), &chain).unwrap();
        (chain, public_key, offer, state, MemoryStore::default())
    }

    #[test]
    fn empty_recovered_journal_terminalizes_as_exact_abort() {
        let (_chain, public_key, offer, _state, store) = fixture(4);
        let terminal = recover_sif_send_terminal(offer, store.entries, &public_key).unwrap();
        assert_eq!(terminal.outcome(), DisclosureReleaseOutcome::Aborted);
        assert_eq!(terminal.byte_accounting(), FileDisclosureByteAccounting::Exact);
        assert_eq!(terminal.possibly_disclosed_unique_bytes(), 0);
        assert_eq!(terminal.confirmed_unique_bytes(), 0);
    }

    #[test]
    fn prepared_but_unconfirmed_recovery_uses_conservative_partial() {
        let (chain, public_key, offer, mut state, mut store) = fixture(4);
        let chunk = SifProtectedFileChunk::new(&offer, 0, b"abcd".to_vec()).unwrap();
        state.prepare_chunk(&chain, chunk, &mut store).unwrap();

        let terminal = recover_sif_send_terminal(offer, store.entries, &public_key).unwrap();
        assert_eq!(
            terminal.outcome(),
            DisclosureReleaseOutcome::Partial { bytes_released: 4 }
        );
        assert_eq!(
            terminal.byte_accounting(),
            FileDisclosureByteAccounting::ConservativeUpperBound
        );
        assert_eq!(terminal.possibly_disclosed_unique_bytes(), 4);
        assert_eq!(terminal.confirmed_unique_bytes(), 0);
    }

    #[test]
    fn carrier_confirmed_full_file_still_does_not_recover_as_completed() {
        let (chain, public_key, offer, mut state, mut store) = fixture(4);
        let chunk = SifProtectedFileChunk::new(&offer, 0, b"abcd".to_vec()).unwrap();
        let prepared = state.prepare_chunk(&chain, chunk, &mut store).unwrap();
        state
            .confirm_carrier_success(&chain, &prepared, &mut store)
            .unwrap();

        let terminal = recover_sif_send_terminal(offer, store.entries, &public_key).unwrap();
        assert_eq!(
            terminal.outcome(),
            DisclosureReleaseOutcome::Partial { bytes_released: 4 }
        );
        assert_eq!(terminal.byte_accounting(), FileDisclosureByteAccounting::Exact);
        assert_eq!(terminal.possibly_disclosed_unique_bytes(), 4);
        assert_eq!(terminal.confirmed_unique_bytes(), 4);
    }
}
