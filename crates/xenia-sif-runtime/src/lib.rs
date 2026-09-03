// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application-layer runtime bridge for SIF protected file custody.
//!
//! The ledger deliberately owns protocol semantics and portable evidence while
//! `xenia-peer-core` deliberately owns transport/filesystem mechanics. Making the
//! permissively licensed core depend on the AGPL ledger would invert that layering.
//! This crate is the narrow application-layer join instead.
//!
//! Its central invariant is that one authenticated protected chunk advances the
//! semantic receiver and the disk stager together through a move-only transition.
//! If either side rejects/fails, the bridge is consumed and the private staging file
//! is dropped rather than allowing a caller to continue from split semantic/disk state.
//!
//! Positive custody is likewise a joined state: [`DurableVerifiedSifReceive`] exists
//! only when the semantic receiver verified the exact complete stream *and* the
//! crash-durable filesystem wrapper returned [`CrashDurableReceivePublication`].

#![warn(missing_docs)]
#![deny(unsafe_code)]

use std::path::{Path, PathBuf};

use thiserror::Error;
use xenia_ledger::{
    EvidenceCryptoManifest, IncompleteSifProtectedFileReceive,
    IntegrityMismatchSifProtectedFileReceive, SessionTranscriptBinding, SifDeliveryReceiptBinding,
    SifProtectedFileChunk, SifProtectedFileComplete, SifProtectedFileOffer,
    SifProtectedFileReceiveError, SifProtectedFileReceiveTerminal, SifProtectedFileReceiver,
    SignatureSuite, VerifiedSifPersistenceOutcome, VerifiedSifProtectedFileReceive,
};
use xenia_peer_core::{
    CrashDurableIncomingFileStager, CrashDurableReceiveError, CrashDurableReceivePublication,
    IncomingFileStageError,
};

/// Live receiver bridge for one exact SIF protected Offer.
///
/// The type is intentionally consumed by every chunk transition. An I/O failure after
/// semantic state has advanced therefore destroys the whole bridge and drops private
/// staging rather than returning a still-usable half-advanced receiver.
pub struct SifReceiveRuntime {
    semantic: SifProtectedFileReceiver,
    staging: CrashDurableIncomingFileStager,
}

impl SifReceiveRuntime {
    /// Start semantic verification and private disk staging for one exact Offer.
    ///
    /// Protocol validation runs before any staging inode is created.
    pub fn begin(
        offer: SifProtectedFileOffer,
        final_path: &Path,
    ) -> Result<Self, SifReceiveRuntimeError> {
        let expected_size = offer.size();
        let expected_hash = offer.content_blake3();
        let semantic = SifProtectedFileReceiver::new(offer)?;
        let staging =
            CrashDurableIncomingFileStager::create(final_path, expected_size, expected_hash)?;
        Ok(Self { semantic, staging })
    }

    /// Exact protected Offer currently being received.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.semantic.offer()
    }

    /// Contiguous content bytes jointly accepted by semantic and disk state.
    pub fn received_bytes(&self) -> u64 {
        debug_assert_eq!(
            self.semantic.received_bytes(),
            self.staging.received_bytes(),
            "SIF semantic and disk receive frontiers diverged"
        );
        self.semantic.received_bytes()
    }

    /// Consume this bridge while accepting one exact release-bound Chunk.
    ///
    /// Semantic validation occurs first. The exact same offset/data is then appended
    /// to the private disk stager. Any failure consumes `self`; callers cannot retry on
    /// the same state after only one side of the bridge advanced.
    pub fn accept_chunk(
        mut self,
        chunk: &SifProtectedFileChunk,
    ) -> Result<Self, SifReceiveRuntimeError> {
        self.semantic.accept_chunk(chunk)?;
        self.staging.append(chunk.offset(), chunk.data())?;
        debug_assert_eq!(
            self.semantic.received_bytes(),
            self.staging.received_bytes(),
            "SIF semantic and disk receive frontiers diverged after accepted chunk"
        );
        Ok(self)
    }

    /// Validate the sender's release-bound `Complete` marker and finalize custody.
    pub fn finish_with_complete(
        self,
        complete: &SifProtectedFileComplete,
    ) -> Result<SifReceiveRuntimeTerminal, SifReceiveRuntimeError> {
        let Self { semantic, staging } = self;
        let terminal = semantic.finish_with_complete(complete)?;
        Ok(finalize_runtime_terminal(terminal, staging))
    }

    /// Finalize custody after carrier closure even if the final control marker was lost.
    ///
    /// This preserves the ledger distinction between content custody and protocol
    /// finalization: exact verified content can still be durably published, while an
    /// incomplete or mismatched stream is returned as typed negative evidence.
    pub fn finish_observation(self) -> SifReceiveRuntimeTerminal {
        let Self { semantic, staging } = self;
        finalize_runtime_terminal(semantic.finish_observation(), staging)
    }
}

fn finalize_runtime_terminal(
    terminal: SifProtectedFileReceiveTerminal,
    staging: CrashDurableIncomingFileStager,
) -> SifReceiveRuntimeTerminal {
    match terminal {
        SifProtectedFileReceiveTerminal::Verified(verified) => match staging.finish() {
            Ok(publication) => {
                SifReceiveRuntimeTerminal::DurableVerified(DurableVerifiedSifReceive {
                    verified,
                    publication,
                })
            }
            Err(error) => SifReceiveRuntimeTerminal::PersistenceFailed(
                PersistenceFailedSifReceive { verified, error },
            ),
        },
        SifProtectedFileReceiveTerminal::Incomplete(incomplete) => {
            drop(staging);
            SifReceiveRuntimeTerminal::Incomplete(incomplete)
        }
        SifProtectedFileReceiveTerminal::IntegrityMismatch(mismatch) => {
            drop(staging);
            SifReceiveRuntimeTerminal::IntegrityMismatch(mismatch)
        }
    }
}

/// Joined terminal state for protected SIF receive execution.
#[derive(Debug)]
pub enum SifReceiveRuntimeTerminal {
    /// Exact stream verified and crash-durable final-name publication succeeded.
    DurableVerified(DurableVerifiedSifReceive),
    /// Exact stream verified but crash-durable publication failed or became uncertain.
    PersistenceFailed(PersistenceFailedSifReceive),
    /// Fewer than the declared content bytes were observed.
    Incomplete(IncompleteSifProtectedFileReceive),
    /// Full declared bytes arrived but their whole-file BLAKE3 differed.
    IntegrityMismatch(IntegrityMismatchSifProtectedFileReceive),
}

/// Positive joined custody state.
///
/// Construction is private. Possession proves that this runtime instance reached both
/// semantic whole-file verification and the local crash-durable publication boundary.
#[derive(Debug)]
pub struct DurableVerifiedSifReceive {
    verified: VerifiedSifProtectedFileReceive,
    publication: CrashDurableReceivePublication,
}

impl DurableVerifiedSifReceive {
    /// Exact protected Offer whose content and publication succeeded.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.verified.offer()
    }

    /// Local crash-durable publication token paired with this verified stream.
    pub fn publication(&self) -> &CrashDurableReceivePublication {
        &self.publication
    }

    /// Consume joined verified+durable custody into a positive portable receipt binding.
    ///
    /// This is the application-layer API runtime code should use instead of selecting
    /// `VerifiedSifPersistenceOutcome::Persisted` directly on the lower-level ledger
    /// object.
    #[allow(clippy::too_many_arguments)]
    pub fn into_delivery_receipt_binding(
        self,
        session: SessionTranscriptBinding,
        receiver_signature_suite: SignatureSuite,
        receiver_public_key: &[u8],
        observed_at_unix_ms: u64,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SifDeliveryReceiptBinding, SifReceiveRuntimeError> {
        let Self {
            verified,
            publication: _,
        } = self;
        Ok(verified.into_delivery_receipt_binding(
            session,
            receiver_signature_suite,
            receiver_public_key,
            VerifiedSifPersistenceOutcome::Persisted,
            observed_at_unix_ms,
            manifest,
        )?)
    }
}

/// Verified content whose persistence did not reach the positive durability boundary.
#[derive(Debug)]
pub struct PersistenceFailedSifReceive {
    verified: VerifiedSifProtectedFileReceive,
    error: CrashDurableReceiveError,
}

impl PersistenceFailedSifReceive {
    /// Exact Offer whose content verified before persistence failed.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.verified.offer()
    }

    /// Local persistence failure/uncertainty.
    pub fn error(&self) -> &CrashDurableReceiveError {
        &self.error
    }

    /// Final path when publication happened but directory durability became uncertain.
    pub fn published_but_unsynced_path(&self) -> Option<&Path> {
        self.error.published_but_unsynced_path()
    }

    /// Consume verified content into a portable negative persistence receipt binding.
    ///
    /// The local filesystem error is intentionally not embedded in portable evidence;
    /// the portable claim remains the stable `PersistenceFailed` disposition while the
    /// receiver retains detailed local diagnostics.
    #[allow(clippy::too_many_arguments)]
    pub fn into_delivery_receipt_binding(
        self,
        session: SessionTranscriptBinding,
        receiver_signature_suite: SignatureSuite,
        receiver_public_key: &[u8],
        observed_at_unix_ms: u64,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SifDeliveryReceiptBinding, SifReceiveRuntimeError> {
        Ok(self.verified.into_delivery_receipt_binding(
            session,
            receiver_signature_suite,
            receiver_public_key,
            VerifiedSifPersistenceOutcome::Failed,
            observed_at_unix_ms,
            manifest,
        )?)
    }
}

/// Runtime bridge failures that occur before a typed terminal custody observation.
#[derive(Debug, Error)]
pub enum SifReceiveRuntimeError {
    /// Protected semantic protocol/receiver validation failed.
    #[error(transparent)]
    Semantic(#[from] SifProtectedFileReceiveError),
    /// Private filesystem staging failed while jointly advancing a Chunk.
    #[error(transparent)]
    Stage(#[from] IncomingFileStageError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xenia_ledger::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, SifDeliveryDisposition,
        SifProtectedFileComplete, sif_file_result_digest,
    };

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xenia-sif-runtime-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn offer_for(payload: &[u8]) -> SifProtectedFileOffer {
        let hash = *blake3::hash(payload).as_bytes();
        let result = sif_file_result_digest("evidence.bin", payload.len() as u64, hash).unwrap();
        SifProtectedFileOffer::new(
            Uuid::from_u128(1),
            7,
            [0x22; 32],
            result,
            "evidence.bin",
            payload.len() as u64,
            hash,
        )
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn same_chunks_drive_semantic_and_disk_frontiers_to_durable_custody() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let dir = temp_dir();
        let path = dir.join("evidence.bin");
        let runtime = SifReceiveRuntime::begin(offer.clone(), &path).unwrap();
        let runtime = runtime
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 0, b"abcd".to_vec()).unwrap())
            .unwrap();
        assert_eq!(runtime.received_bytes(), 4);
        let runtime = runtime
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 4, b"efghij".to_vec()).unwrap())
            .unwrap();
        assert_eq!(runtime.received_bytes(), payload.len() as u64);

        let terminal = runtime
            .finish_with_complete(&SifProtectedFileComplete::new(&offer).unwrap())
            .unwrap();
        let durable = match terminal {
            SifReceiveRuntimeTerminal::DurableVerified(durable) => durable,
            other => panic!("expected durable verified custody, got {other:?}"),
        };
        assert_eq!(durable.publication().final_path(), path.as_path());
        assert_eq!(std::fs::read(&path).unwrap(), payload);

        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(9),
            [0x77; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let binding = durable
            .into_delivery_receipt_binding(
                session,
                SignatureSuite::Ed25519Rfc8032,
                &[0x55; 32],
                1_780_000_000_300,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
            .unwrap();
        assert_eq!(binding.disposition(), SifDeliveryDisposition::PersistedVerified);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn semantic_rejection_consumes_bridge_and_cleans_private_staging() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let dir = temp_dir();
        let path = dir.join("evidence.bin");
        let runtime = SifReceiveRuntime::begin(offer.clone(), &path).unwrap();
        let bad = SifProtectedFileChunk::new(&offer, 2, b"cd".to_vec()).unwrap();
        assert!(matches!(
            runtime.accept_chunk(&bad),
            Err(SifReceiveRuntimeError::Semantic(_))
        ));
        assert!(!path.exists());
        let staging_count = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".xenia-receive-"))
            })
            .count();
        assert_eq!(staging_count, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn incomplete_semantic_terminal_never_publishes_final_name() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let dir = temp_dir();
        let path = dir.join("evidence.bin");
        let runtime = SifReceiveRuntime::begin(offer.clone(), &path)
            .unwrap()
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 0, b"abcd".to_vec()).unwrap())
            .unwrap();
        assert!(matches!(
            runtime.finish_observation(),
            SifReceiveRuntimeTerminal::Incomplete(_)
        ));
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
