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
use crate::consent_compaction::{
    ConsentCompactedActiveStateV1, RestoredConsentStateV1,
};

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

/// Persistence for an activated compacted ledger. The immutable activation
/// envelope is retained and combined with the chain's latest resident suffix
/// on each transactional append.
pub(crate) struct CompactedConsentLedgerPersister {
    path: PathBuf,
    activation: ConsentCompactedActiveStateV1,
}

impl CompactedConsentLedgerPersister {
    pub(crate) fn new(path: PathBuf, activation: ConsentCompactedActiveStateV1) -> Self {
        Self { path, activation }
    }
}

impl ConsentLedgerPersister for CompactedConsentLedgerPersister {
    fn persist(&self, chain: &Chain) -> Result<(), AuditLedgerStoreError> {
        let next = self
            .activation
            .advance_from_chain(chain, unix_now_secs())
            .map_err(AuditLedgerStoreError::CompactedState)?;
        persist_compacted_active_state_atomic(&self.path, &next)
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
        ConsentCompactedActiveStateV1, ConsentCompactedSnapshotV1,
        ConsentCompactionBundleV1,
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
        let archive = vec![
            LedgerArchiveSegment::from_chain(&complete, genesis, 101).unwrap(),
        ];
        complete
            .append(ConsentEventRecord {
                source_id: [0x12; 32],
                session_id: Uuid::from_u128(3),
                request_id: Uuid::from_u128(4),
                kind: ConsentKind::Denial,
                scope: "screen".into(),
            })
            .unwrap();
        let bundle = ConsentCompactionBundleV1::build(
            &complete,
            archive.clone(),
            102,
        )
        .unwrap();
        let entries = complete.iter().cloned().collect::<Vec<_>>();
        let snapshot = ConsentCompactedSnapshotV1::build(
            &bundle,
            &entries,
            &key.verifying_key(),
        )
        .unwrap();
        let active = ConsentCompactedActiveStateV1::activate(
            snapshot,
            &archive,
            &key,
            103,
        )
        .unwrap();
        persist_compacted_active_state_atomic(&path, &active).unwrap();

        let (activation, mut restored) =
            load_compacted_active_state(&path, &key).unwrap();
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

}
