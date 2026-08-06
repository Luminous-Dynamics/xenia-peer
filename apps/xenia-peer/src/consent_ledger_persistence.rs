// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Chain-aware persistence strategies for the consent audit ledger.
//!
//! Persistence receives the complete [`xenia_ledger::Chain`] frontier rather
//! than only a resident entry slice. This prevents a future compacted-ledger
//! backend from accidentally losing its signed prefix checkpoint during an
//! otherwise successful append.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use xenia_ledger::Chain;

use crate::audit_ledger_store::{
    AuditLedgerStoreError, MAX_AUDIT_LEDGER_BYTES, persist_entries_atomic,
    persist_owner_only_atomic, read_bounded_json,
};
use crate::consent_compaction::{ConsentCompactedActiveStateV1, RestoredConsentStateV1};

/// Storage implementation used by transactional consent-ledger appends.
pub(crate) trait ConsentLedgerPersister: Send + Sync {
    /// Persist the complete authenticated chain frontier or return an error.
    fn persist(&self, chain: &Chain) -> Result<(), AuditLedgerStoreError>;
}

/// Shared persistence handle used by the consent authority.
pub(crate) type SharedConsentLedgerPersister = Arc<dyn ConsentLedgerPersister>;

/// Persistence for an ordinary complete genesis-based ledger.
pub(crate) struct CompleteConsentLedgerPersister {
    path: PathBuf,
}

impl CompleteConsentLedgerPersister {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl ConsentLedgerPersister for CompleteConsentLedgerPersister {
    fn persist(&self, chain: &Chain) -> Result<(), AuditLedgerStoreError> {
        if chain.base_checkpoint().is_some() {
            return Err(AuditLedgerStoreError::MetadataMismatch(
                "complete ledger persister received an anchored suffix",
            ));
        }
        let entries = chain.iter().cloned().collect::<Vec<_>>();
        persist_entries_atomic(&self.path, &entries)
    }
}

/// Persistence for an activated compacted ledger. The activation envelope
/// advances (a new signed generation) on each transactional append.
///
/// `persist` takes `&self`, matching [`ConsentLedgerPersister`]'s trait
/// signature, but the envelope itself is genuinely mutable across calls --
/// wrapped in a `Mutex` rather than held by value. Found by hand
/// 2026-08-01: constructing this once and calling `persist` twice (the real
/// shape of daemon-startup compacted-mode boot, where one persister is
/// reused for the whole process lifetime, not a fresh one per append) with
/// the envelope held by value silently re-derives `generation` from the
/// same stale base every time -- the *data* written is still always
/// correct (`advance_from_chain` takes the live `chain: &Chain` fresh each
/// call, not an incremental delta), but `generation` never advances past
/// its first real bump, which would defeat the rollback-detection purpose
/// `generation`/`previous_state_digest` exist for on a real multi-append
/// daemon lifetime. Locking and updating the in-memory envelope after each
/// successful disk write closes that gap.
pub(crate) struct CompactedConsentLedgerPersister {
    path: PathBuf,
    activation: std::sync::Mutex<ConsentCompactedActiveStateV1>,
}

impl CompactedConsentLedgerPersister {
    pub(crate) fn new(path: PathBuf, activation: ConsentCompactedActiveStateV1) -> Self {
        Self {
            path,
            activation: std::sync::Mutex::new(activation),
        }
    }
}

impl ConsentLedgerPersister for CompactedConsentLedgerPersister {
    fn persist(&self, chain: &Chain) -> Result<(), AuditLedgerStoreError> {
        let mut activation = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = activation
            .advance_from_chain(chain, unix_now_secs())
            .map_err(AuditLedgerStoreError::CompactedState)?;
        persist_compacted_active_state_atomic(&self.path, &next)?;
        *activation = next;
        Ok(())
    }
}

/// Read and verify an activated compacted ledger before any listener opens.
pub(crate) fn load_compacted_active_state(
    path: &Path,
    signing_key: &SigningKey,
) -> Result<(ConsentCompactedActiveStateV1, RestoredConsentStateV1), AuditLedgerStoreError> {
    let state: ConsentCompactedActiveStateV1 = read_bounded_json(
        path,
        MAX_AUDIT_LEDGER_BYTES,
        "compacted consent active state",
    )?;
    let restored = state
        .restore_state(signing_key)
        .map_err(AuditLedgerStoreError::CompactedState)?;
    Ok((state, restored))
}

/// Atomically persist one activated compacted-ledger frontier.
pub(crate) fn persist_compacted_active_state_atomic(
    path: &Path,
    state: &ConsentCompactedActiveStateV1,
) -> Result<(), AuditLedgerStoreError> {
    let mut bytes = serde_json::to_vec(state)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_AUDIT_LEDGER_BYTES {
        return Err(AuditLedgerStoreError::LimitExceeded(format!(
            "{} serialized bytes exceeds maximum {}",
            bytes.len(),
            MAX_AUDIT_LEDGER_BYTES
        )));
    }
    persist_owner_only_atomic(path, &bytes)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{ConsentEventRecord, ConsentKind, LedgerArchiveSegment};

    use crate::consent_compaction::{
        ConsentCompactedActiveStateV1, ConsentCompactedSnapshotV1, ConsentCompactionBundleV1,
    };

    fn event() -> ConsentEventRecord {
        ConsentEventRecord {
            source_id: [0x11; 32],
            session_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            kind: ConsentKind::Denial,
            scope: "screen".into(),
        }
    }

    #[test]
    fn complete_persister_rejects_an_anchored_suffix() {
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let base = Chain::new(key.clone()).sign_checkpoint(100);
        let chain = Chain::from_checkpoint_suffix(base, Vec::new(), key);
        let persister = CompleteConsentLedgerPersister::new(
            std::env::temp_dir().join("unused-complete-consent-ledger"),
        );
        assert!(matches!(
            persister.persist(&chain),
            Err(AuditLedgerStoreError::MetadataMismatch(_))
        ));
    }

    #[test]
    fn complete_persister_round_trips_a_complete_chain() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-complete-ledger-persister-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consent.ledger");
        let key = SigningKey::from_bytes(&[0x72; 32]);
        let mut chain = Chain::new(key.clone());
        chain.append(event()).unwrap();
        let persister = CompleteConsentLedgerPersister::new(path.clone());
        persister.persist(&chain).unwrap();
        let loaded = crate::audit_ledger_store::load_verified(&path, &key).unwrap();
        assert_eq!(loaded.entry_count(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn compacted_persister_round_trips_and_advances_the_signed_suffix() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-compacted-ledger-persister-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consent.compacted.json");
        let key = SigningKey::from_bytes(&[0x73; 32]);
        let mut complete = Chain::new(key.clone());
        let genesis = complete.sign_checkpoint(100);
        complete.append(event()).unwrap();
        let archive = vec![LedgerArchiveSegment::from_chain(&complete, genesis, 101).unwrap()];
        complete
            .append(ConsentEventRecord {
                source_id: [0x12; 32],
                session_id: Uuid::from_u128(3),
                request_id: Uuid::from_u128(4),
                kind: ConsentKind::Denial,
                scope: "screen".into(),
            })
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(&complete, archive.clone(), 102).unwrap();
        let entries = complete.iter().cloned().collect::<Vec<_>>();
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let active =
            ConsentCompactedActiveStateV1::activate(snapshot, &archive, &key, 103).unwrap();
        persist_compacted_active_state_atomic(&path, &active).unwrap();

        let (activation, mut restored) = load_compacted_active_state(&path, &key).unwrap();
        restored
            .chain
            .append(ConsentEventRecord {
                source_id: [0x13; 32],
                session_id: Uuid::from_u128(5),
                request_id: Uuid::from_u128(6),
                kind: ConsentKind::Denial,
                scope: "screen".into(),
            })
            .unwrap();
        let persister = CompactedConsentLedgerPersister::new(path.clone(), activation);
        persister.persist(&restored.chain).unwrap();

        let (_, reloaded) = load_compacted_active_state(&path, &key).unwrap();
        assert_eq!(reloaded.chain.entry_count(), 3);
        assert_eq!(reloaded.chain.resident_len(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    /// Regression test for a real bug found by hand 2026-08-01: a
    /// `CompactedConsentLedgerPersister` constructed once and reused across
    /// multiple real appends (the actual shape of a long-running daemon
    /// process, not a fresh persister per append) used to silently
    /// re-derive `generation` from the same construction-time snapshot every
    /// call, so it never advanced past its first real bump even though the
    /// persisted entry data was always correct. Two real `persist()` calls
    /// must produce two genuinely different (monotonically increasing)
    /// generations.
    #[test]
    fn compacted_persister_advances_generation_across_repeated_persist_calls() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-compacted-ledger-persister-generation-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consent.compacted.json");
        let key = SigningKey::from_bytes(&[0x74; 32]);
        let mut complete = Chain::new(key.clone());
        let genesis = complete.sign_checkpoint(200);
        complete.append(event()).unwrap();
        let archive = vec![LedgerArchiveSegment::from_chain(&complete, genesis, 201).unwrap()];
        let bundle = ConsentCompactionBundleV1::build(&complete, archive.clone(), 202).unwrap();
        let entries = complete.iter().cloned().collect::<Vec<_>>();
        let snapshot =
            ConsentCompactedSnapshotV1::build(&bundle, &entries, &key.verifying_key(), None)
                .unwrap();
        let active =
            ConsentCompactedActiveStateV1::activate(snapshot, &archive, &key, 203).unwrap();
        persist_compacted_active_state_atomic(&path, &active).unwrap();

        let (activation, mut restored) = load_compacted_active_state(&path, &key).unwrap();
        let initial_generation = activation.generation;
        let persister = CompactedConsentLedgerPersister::new(path.clone(), activation);

        restored
            .chain
            .append(ConsentEventRecord {
                source_id: [0x14; 32],
                session_id: Uuid::from_u128(7),
                request_id: Uuid::from_u128(8),
                kind: ConsentKind::Denial,
                scope: "screen".into(),
            })
            .unwrap();
        persister.persist(&restored.chain).unwrap();
        let (after_first, _) = load_compacted_active_state(&path, &key).unwrap();

        restored
            .chain
            .append(ConsentEventRecord {
                source_id: [0x15; 32],
                session_id: Uuid::from_u128(9),
                request_id: Uuid::from_u128(10),
                kind: ConsentKind::Denial,
                scope: "screen".into(),
            })
            .unwrap();
        persister.persist(&restored.chain).unwrap();
        let (after_second, reloaded) = load_compacted_active_state(&path, &key).unwrap();

        assert_eq!(after_first.generation, initial_generation + 1);
        assert_eq!(
            after_second.generation,
            initial_generation + 2,
            "generation must advance on every real persist call, not just the first"
        );
        assert_eq!(reloaded.chain.entry_count(), 3);
        std::fs::remove_dir_all(dir).ok();
    }
}
