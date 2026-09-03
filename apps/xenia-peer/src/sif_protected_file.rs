// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-file precommit boundary for SIF-protected outbound transfer.
//!
//! A prepared disclosure permit is not durably committed until its signed
//! minimum-necessary `result_digest` is proven to describe the exact outbound
//! filename, byte length and BLAKE3 digest held by one already-opened
//! [`xenia_peer_core::TransferSource`]. The source is consumed into the prepared
//! object, so callers cannot validate file A and substitute file B before Commit.
//!
//! Commit revalidates the **current live M1 runtime** through
//! [`crate::sif_m1_authority::commit_disclosure_from_current_runtime`] and only
//! success yields a move-only [`CommittedProtectedFileDisclosure`]. The existing
//! ledger-side [`xenia_ledger::CommittedFileDisclosure`] binding is repeated after
//! Commit as defense in depth. If that supposedly impossible second check fails,
//! this module immediately attempts to persist `Aborted` so zero-byte failure does
//! not silently leave a reusable-looking unresolved release lineage.

#![allow(dead_code)]

use std::path::Path;

use thiserror::Error;
use xenia_ledger::{
    AccountabilityDisclosureError, AccountabilityDisclosurePermit, CommittedFileDisclosure,
    DisclosureReleaseOutcome, DisclosureReleaseState, FileDisclosureError,
    TransactionalDisclosureError, sif_file_result_digest,
};
use xenia_peer_core::TransferSource;

use crate::m1_runtime::M1RuntimeSession;
use crate::sif_m1_authority::{
    M1SifAuthorityError, M1SifCommitError, M1SifOutcomeAuthority,
    commit_disclosure_from_current_runtime,
};
use crate::sif_release_store::{FileSifReleaseStore, SifReleaseStoreError};

/// Prepared exact outbound file whose result commitment has been checked before
/// any durable release Commit. No network operation is available from this type.
pub(crate) struct PreparedProtectedFileDisclosure {
    permit: AccountabilityDisclosurePermit,
    source: TransferSource,
    display_name: String,
    transfer_id: u64,
}

impl PreparedProtectedFileDisclosure {
    /// Consume the already-opened/hashes-bound source and prove that the signed
    /// prepared permit names exactly this wire-visible file.
    pub(crate) fn new(
        permit: AccountabilityDisclosurePermit,
        source: TransferSource,
        display_name: impl Into<String>,
        transfer_id: u64,
    ) -> Result<Self, ProtectedFilePrepareError> {
        if transfer_id == 0 {
            return Err(ProtectedFilePrepareError::ZeroTransferId);
        }
        let display_name = display_name.into();
        require_exact_precommit_result(
            permit.binding().result_digest(),
            &display_name,
            source.size(),
            source.blake3_hash(),
        )?;
        Ok(Self {
            permit,
            source,
            display_name,
            transfer_id,
        })
    }

    /// Exact authenticated Offer metadata already bound by the permit.
    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    pub(crate) fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    pub(crate) fn size(&self) -> u64 {
        self.source.size()
    }

    pub(crate) fn content_blake3(&self) -> [u8; 32] {
        self.source.blake3_hash()
    }

    /// Revalidate current live M1 consent and durably CAS-commit this exact file.
    ///
    /// The caller must hold the live daemon's `AsyncMutex<M1RuntimeSession>` guard
    /// while passing `runtime`, preventing a consent transition from interleaving
    /// between fresh M1 reconstruction and the synchronous release-store CAS.
    pub(crate) fn commit(
        self,
        runtime: &M1RuntimeSession,
        m1_key_path: &Path,
        release_state: &mut DisclosureReleaseState,
        release_store: &mut FileSifReleaseStore,
    ) -> Result<CommittedProtectedFileDisclosure, ProtectedFileCommitError> {
        let Self {
            permit,
            source,
            display_name,
            transfer_id,
        } = self;

        let committed = commit_disclosure_from_current_runtime(
            runtime,
            m1_key_path,
            release_state,
            permit,
            release_store,
        )
        .map_err(map_commit_error)?;
        let (committed_permit, outcome_authority) = committed.into_parts();
        let release_id = committed_permit.release_id();

        match CommittedFileDisclosure::new(
            committed_permit,
            &display_name,
            source.size(),
            source.blake3_hash(),
        ) {
            Ok(disclosure) => Ok(CommittedProtectedFileDisclosure {
                source,
                display_name,
                transfer_id,
                disclosure,
                outcome_authority,
            }),
            Err(binding) => {
                // Precommit validation used these exact same values and owns the
                // TransferSource, so this should only be reachable after an internal
                // invariant regression. Close the durable lineage as Aborted rather
                // than leave a zero-byte unresolved Commit if possible.
                match outcome_authority.record_outcome(
                    release_state,
                    release_id,
                    DisclosureReleaseOutcome::Aborted,
                    release_store,
                ) {
                    Ok(()) => Err(ProtectedFileCommitError::PostCommitBindingAborted(binding)),
                    Err(TransactionalDisclosureError::Protocol(outcome)) => {
                        Err(ProtectedFileCommitError::PostCommitBindingOutcomeProtocol {
                            binding,
                            outcome,
                        })
                    }
                    Err(TransactionalDisclosureError::Persist(store)) => {
                        Err(ProtectedFileCommitError::PostCommitBindingOutcomeStore {
                            binding,
                            store,
                        })
                    }
                }
            }
        }
    }
}

/// Move-only exact-file output capability produced only after durable SIF Commit.
///
/// This tranche intentionally exposes no transport send method yet. The next stack
/// will make the authenticated Offer/Chunk/Complete state machine live on this type,
/// preserving the invariant that no protected sender exists before Commit.
pub(crate) struct CommittedProtectedFileDisclosure {
    source: TransferSource,
    display_name: String,
    transfer_id: u64,
    disclosure: CommittedFileDisclosure,
    outcome_authority: M1SifOutcomeAuthority,
}

impl CommittedProtectedFileDisclosure {
    pub(crate) fn release_id(&self) -> uuid::Uuid {
        self.disclosure.release_id()
    }

    pub(crate) fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    pub(crate) fn size(&self) -> u64 {
        self.source.size()
    }

    pub(crate) fn content_blake3(&self) -> [u8; 32] {
        self.source.blake3_hash()
    }

    pub(crate) fn emitted_bytes(&self) -> u64 {
        self.disclosure.emitted_bytes()
    }
}

fn require_exact_precommit_result(
    permit_result_digest: Option<[u8; 32]>,
    display_name: &str,
    size: u64,
    content_blake3: [u8; 32],
) -> Result<[u8; 32], ProtectedFilePrepareError> {
    let expected = sif_file_result_digest(display_name, size, content_blake3)?;
    match permit_result_digest {
        None => Err(ProtectedFilePrepareError::MissingResultCommitment),
        Some(actual) if actual != expected => Err(ProtectedFilePrepareError::ResultMismatch),
        Some(_) => Ok(expected),
    }
}

fn map_commit_error(
    error: M1SifCommitError<SifReleaseStoreError>,
) -> ProtectedFileCommitError {
    match error {
        M1SifCommitError::Authority(authority) => ProtectedFileCommitError::Authority(authority),
        M1SifCommitError::Release(TransactionalDisclosureError::Protocol(protocol)) => {
            ProtectedFileCommitError::Protocol(protocol)
        }
        M1SifCommitError::Release(TransactionalDisclosureError::Persist(store)) => {
            ProtectedFileCommitError::Store(store)
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ProtectedFilePrepareError {
    #[error("SIF protected file transfer id must be non-zero")]
    ZeroTransferId,
    #[error("SIF protected file prepared permit has no result commitment")]
    MissingResultCommitment,
    #[error("SIF protected file does not match the prepared permit result commitment")]
    ResultMismatch,
    #[error(transparent)]
    FileBinding(#[from] FileDisclosureError),
}

#[derive(Debug, Error)]
pub(crate) enum ProtectedFileCommitError {
    #[error("current M1 authority rejected SIF protected-file Commit: {0}")]
    Authority(#[source] M1SifAuthorityError),
    #[error("SIF release protocol rejected protected-file Commit: {0}")]
    Protocol(#[source] AccountabilityDisclosureError),
    #[error("SIF durable release store rejected protected-file Commit: {0}")]
    Store(#[source] SifReleaseStoreError),
    #[error("post-Commit exact-file invariant failed; Aborted outcome was durably recorded: {0}")]
    PostCommitBindingAborted(#[source] FileDisclosureError),
    #[error("post-Commit exact-file invariant failed and Aborted protocol transition also failed")]
    PostCommitBindingOutcomeProtocol {
        #[source]
        binding: FileDisclosureError,
        outcome: AccountabilityDisclosureError,
    },
    #[error("post-Commit exact-file invariant failed and Aborted persistence also failed")]
    PostCommitBindingOutcomeStore {
        #[source]
        binding: FileDisclosureError,
        store: SifReleaseStoreError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precommit_result_requires_exact_name_size_and_hash() {
        let exact = sif_file_result_digest("report.bin", 7, [0xA5; 32]).unwrap();
        assert_eq!(
            require_exact_precommit_result(Some(exact), "report.bin", 7, [0xA5; 32]).unwrap(),
            exact
        );
        assert!(matches!(
            require_exact_precommit_result(Some(exact), "other.bin", 7, [0xA5; 32]),
            Err(ProtectedFilePrepareError::ResultMismatch)
        ));
        assert!(matches!(
            require_exact_precommit_result(Some(exact), "report.bin", 8, [0xA5; 32]),
            Err(ProtectedFilePrepareError::ResultMismatch)
        ));
        assert!(matches!(
            require_exact_precommit_result(Some(exact), "report.bin", 7, [0xB6; 32]),
            Err(ProtectedFilePrepareError::ResultMismatch)
        ));
    }

    #[test]
    fn precommit_result_rejects_missing_commitment_and_empty_name() {
        assert!(matches!(
            require_exact_precommit_result(None, "report.bin", 7, [0xA5; 32]),
            Err(ProtectedFilePrepareError::MissingResultCommitment)
        ));
        assert!(matches!(
            require_exact_precommit_result(Some([1u8; 32]), "", 7, [0xA5; 32]),
            Err(ProtectedFilePrepareError::FileBinding(
                FileDisclosureError::EmptyDisplayName
            ))
        ));
    }
}
