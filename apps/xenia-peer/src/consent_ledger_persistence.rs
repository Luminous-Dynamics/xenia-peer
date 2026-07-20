// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Chain-aware persistence strategies for the consent audit ledger.
//!
//! Persistence receives the complete [`xenia_ledger::Chain`] frontier rather
//! than only a resident entry slice. This prevents a future compacted-ledger
//! backend from accidentally losing its signed prefix checkpoint during an
//! otherwise successful append.

use std::path::PathBuf;
use std::sync::Arc;

use xenia_ledger::Chain;

use crate::audit_ledger_store::{AuditLedgerStoreError, persist_entries_atomic};

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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{ConsentEventRecord, ConsentKind};

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
}
