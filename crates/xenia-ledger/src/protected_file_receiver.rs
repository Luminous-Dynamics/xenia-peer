// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stateful receiver verification for the release-bound SIF file protocol.
//!
//! [`SifProtectedFileChunk`] validates one chunk's own bounds and Offer identity.
//! That is not sufficient for a receiver: it must also reject gaps, overlaps and
//! duplicate/out-of-order chunks, then verify the complete byte count and whole-file
//! BLAKE3 before it can make a positive custody claim.
//!
//! This module is transport- and filesystem-independent. The runtime owns actual
//! staging/persistence; this state machine owns only the semantic content stream and
//! produces typed terminal observations that can be converted into the portable
//! receiver-signed delivery receipts from [`crate::SifDeliveryReceiptBinding`].

use thiserror::Error;

use crate::{
    EvidenceCryptoManifest, SessionTranscriptBinding, SifDeliveryDisposition,
    SifDeliveryReceiptBinding, SifDeliveryReceiptError, SifProtectedFileChunk,
    SifProtectedFileComplete, SifProtectedFileOffer, SifProtectedFileProtocolError, SignatureSuite,
};

/// Stateful verifier for one exact SIF protected Offer.
///
/// Chunks are accepted only at the exact next expected offset. This gives the receiver
/// a single contiguous content prefix and makes overlap/gap/duplicate acceptance
/// impossible without an explicit protocol revision.
#[derive(Debug)]
pub struct SifProtectedFileReceiver {
    offer: SifProtectedFileOffer,
    next_offset: u64,
    hasher: blake3::Hasher,
}

impl SifProtectedFileReceiver {
    /// Start receiving one validated protected Offer.
    pub fn new(offer: SifProtectedFileOffer) -> Result<Self, SifProtectedFileReceiveError> {
        offer.validate()?;
        Ok(Self {
            offer,
            next_offset: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    /// Exact protected Offer this receiver state belongs to.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Length of the single contiguous content prefix accepted so far.
    pub const fn received_bytes(&self) -> u64 {
        self.next_offset
    }

    /// Whether the declared content byte count has been received exactly.
    ///
    /// This is not yet an integrity or persistence claim; whole-file BLAKE3 must still
    /// be verified through [`Self::finish_observation`].
    pub fn has_declared_byte_count(&self) -> bool {
        self.next_offset == self.offer.size()
    }

    /// Accept one release-bound Chunk only at the exact next expected offset.
    pub fn accept_chunk(
        &mut self,
        chunk: &SifProtectedFileChunk,
    ) -> Result<(), SifProtectedFileReceiveError> {
        chunk.validate_against_offer(&self.offer)?;
        if chunk.offset() != self.next_offset {
            return Err(SifProtectedFileReceiveError::NonContiguousChunk {
                expected_offset: self.next_offset,
                found_offset: chunk.offset(),
            });
        }
        let len = u64::try_from(chunk.data().len())
            .map_err(|_| SifProtectedFileReceiveError::ByteCountOverflow)?;
        let next = self
            .next_offset
            .checked_add(len)
            .ok_or(SifProtectedFileReceiveError::ByteCountOverflow)?;
        if next > self.offer.size() {
            // The stateless chunk validator should already make this unreachable, but
            // retain the invariant at the stateful boundary too.
            return Err(SifProtectedFileReceiveError::ReceivedBeyondOffer {
                offered: self.offer.size(),
                attempted: next,
            });
        }
        self.hasher.update(chunk.data());
        self.next_offset = next;
        Ok(())
    }

    /// Validate a sender `Complete` marker against the exact Offer, then finalize the
    /// receiver's content observation.
    ///
    /// A premature `Complete` is not a parser/protocol error: it produces a typed
    /// `Incomplete` terminal observation that can be signed as negative delivery
    /// evidence. Likewise, a full-length stream with the wrong hash produces
    /// `IntegrityMismatch` rather than being collapsed into an undifferentiated error.
    pub fn finish_with_complete(
        self,
        complete: &SifProtectedFileComplete,
    ) -> Result<SifProtectedFileReceiveTerminal, SifProtectedFileReceiveError> {
        complete.validate_against_offer(&self.offer)?;
        Ok(self.finish_observation())
    }

    /// Finalize the observed stream without requiring the sender's final control
    /// marker—for example after carrier closure.
    ///
    /// Content custody and protocol-finalization are deliberately separate claims. If
    /// the exact declared bytes arrived and their whole-file hash verifies, the content
    /// observation is `Verified` even when a later `Complete` control envelope was lost.
    pub fn finish_observation(self) -> SifProtectedFileReceiveTerminal {
        if self.next_offset < self.offer.size() {
            return SifProtectedFileReceiveTerminal::Incomplete(
                IncompleteSifProtectedFileReceive {
                    offer: self.offer,
                    received_bytes: self.next_offset,
                },
            );
        }

        let observed_content_blake3 = *self.hasher.finalize().as_bytes();
        if observed_content_blake3 != self.offer.content_blake3() {
            return SifProtectedFileReceiveTerminal::IntegrityMismatch(
                IntegrityMismatchSifProtectedFileReceive {
                    offer: self.offer,
                    observed_content_blake3,
                },
            );
        }

        SifProtectedFileReceiveTerminal::Verified(VerifiedSifProtectedFileReceive {
            offer: self.offer,
            observed_content_blake3,
        })
    }
}

/// Terminal semantic observation for one protected content stream.
#[derive(Debug)]
pub enum SifProtectedFileReceiveTerminal {
    /// Exact declared bytes and whole-file BLAKE3 verified.
    Verified(VerifiedSifProtectedFileReceive),
    /// Fewer than the declared content bytes were observed.
    Incomplete(IncompleteSifProtectedFileReceive),
    /// Full declared byte count arrived but whole-file BLAKE3 differed.
    IntegrityMismatch(IntegrityMismatchSifProtectedFileReceive),
}

/// Complete content verified before persistence is attempted.
#[derive(Debug)]
pub struct VerifiedSifProtectedFileReceive {
    offer: SifProtectedFileOffer,
    observed_content_blake3: [u8; 32],
}

impl VerifiedSifProtectedFileReceive {
    /// Exact Offer whose content verified.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Whole-file BLAKE3 observed by the receiver.
    pub const fn observed_content_blake3(&self) -> [u8; 32] {
        self.observed_content_blake3
    }

    /// Consume verified content after the runtime has attempted durable persistence and
    /// produce the corresponding positive-or-persistence-failure receipt binding.
    #[allow(clippy::too_many_arguments)]
    pub fn into_delivery_receipt_binding(
        self,
        session: SessionTranscriptBinding,
        receiver_signature_suite: SignatureSuite,
        receiver_public_key: &[u8],
        persistence: VerifiedSifPersistenceOutcome,
        observed_at_unix_ms: u64,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SifDeliveryReceiptBinding, SifProtectedFileReceiveError> {
        let disposition = match persistence {
            VerifiedSifPersistenceOutcome::Persisted => SifDeliveryDisposition::PersistedVerified,
            VerifiedSifPersistenceOutcome::Failed => SifDeliveryDisposition::PersistenceFailed,
        };
        Ok(SifDeliveryReceiptBinding::new(
            self.offer.release_id(),
            self.offer.transfer_id(),
            session,
            self.offer.sender_release_entry_hash(),
            self.offer.display_name(),
            self.offer.size(),
            self.offer.content_blake3(),
            receiver_signature_suite,
            receiver_public_key,
            disposition,
            self.offer.size(),
            Some(self.observed_content_blake3),
            observed_at_unix_ms,
            manifest,
        )?)
    }
}

/// Runtime persistence result after cryptographic content verification succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedSifPersistenceOutcome {
    /// Verified content was durably published by the receiver.
    Persisted,
    /// Verified content could not be durably published.
    Failed,
}

/// Incomplete content observation.
#[derive(Debug)]
pub struct IncompleteSifProtectedFileReceive {
    offer: SifProtectedFileOffer,
    received_bytes: u64,
}

impl IncompleteSifProtectedFileReceive {
    /// Exact Offer whose stream ended early.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Contiguous content bytes received before termination.
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Consume this negative observation into a portable receipt binding.
    pub fn into_delivery_receipt_binding(
        self,
        session: SessionTranscriptBinding,
        receiver_signature_suite: SignatureSuite,
        receiver_public_key: &[u8],
        observed_at_unix_ms: u64,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SifDeliveryReceiptBinding, SifProtectedFileReceiveError> {
        Ok(SifDeliveryReceiptBinding::new(
            self.offer.release_id(),
            self.offer.transfer_id(),
            session,
            self.offer.sender_release_entry_hash(),
            self.offer.display_name(),
            self.offer.size(),
            self.offer.content_blake3(),
            receiver_signature_suite,
            receiver_public_key,
            SifDeliveryDisposition::Incomplete,
            self.received_bytes,
            None,
            observed_at_unix_ms,
            manifest,
        )?)
    }
}

/// Full-length content whose observed whole-file hash differs from the Offer.
#[derive(Debug)]
pub struct IntegrityMismatchSifProtectedFileReceive {
    offer: SifProtectedFileOffer,
    observed_content_blake3: [u8; 32],
}

impl IntegrityMismatchSifProtectedFileReceive {
    /// Exact Offer whose full-length content failed integrity verification.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Whole-file BLAKE3 actually observed from the received bytes.
    pub const fn observed_content_blake3(&self) -> [u8; 32] {
        self.observed_content_blake3
    }

    /// Consume this negative observation into a portable receipt binding.
    pub fn into_delivery_receipt_binding(
        self,
        session: SessionTranscriptBinding,
        receiver_signature_suite: SignatureSuite,
        receiver_public_key: &[u8],
        observed_at_unix_ms: u64,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SifDeliveryReceiptBinding, SifProtectedFileReceiveError> {
        Ok(SifDeliveryReceiptBinding::new(
            self.offer.release_id(),
            self.offer.transfer_id(),
            session,
            self.offer.sender_release_entry_hash(),
            self.offer.display_name(),
            self.offer.size(),
            self.offer.content_blake3(),
            receiver_signature_suite,
            receiver_public_key,
            SifDeliveryDisposition::IntegrityMismatch,
            self.offer.size(),
            Some(self.observed_content_blake3),
            observed_at_unix_ms,
            manifest,
        )?)
    }
}

/// Fail-closed protected receiver state-machine errors.
#[derive(Debug, Error)]
pub enum SifProtectedFileReceiveError {
    /// Stateless protected protocol object failed validation.
    #[error(transparent)]
    Protocol(#[from] SifProtectedFileProtocolError),
    /// Delivery-receipt construction failed after a typed terminal observation.
    #[error(transparent)]
    DeliveryReceipt(#[from] SifDeliveryReceiptError),
    /// Chunk did not start at the exact next contiguous offset.
    #[error(
        "SIF protected file chunk is non-contiguous: expected offset {expected_offset}, found {found_offset}"
    )]
    NonContiguousChunk {
        /// Exact next byte offset required by the receiver.
        expected_offset: u64,
        /// Offset carried by the rejected Chunk.
        found_offset: u64,
    },
    /// Receiver byte count could not be represented safely.
    #[error("SIF protected file receive byte count overflow")]
    ByteCountOverflow,
    /// Stateful byte count exceeded the Offer despite stateless validation.
    #[error("SIF protected file receive attempted {attempted} bytes beyond Offer size {offered}")]
    ReceivedBeyondOffer {
        /// Offered file length.
        offered: u64,
        /// Stateful attempted content length.
        attempted: u64,
    },
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, Ed25519EvidenceSignatureBackend,
        SifDeliveryReceiptExpectation, sif_delivery_receiver_key_id, sif_file_result_digest,
        sign_sif_delivery_receipt_ed25519,
    };
    use uuid::Uuid;

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

    #[test]
    fn contiguous_chunks_verify_exact_content() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let mut receiver = SifProtectedFileReceiver::new(offer.clone()).unwrap();
        receiver
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 0, b"abcd".to_vec()).unwrap())
            .unwrap();
        receiver
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 4, b"efghij".to_vec()).unwrap())
            .unwrap();
        assert!(receiver.has_declared_byte_count());
        let terminal = receiver
            .finish_with_complete(&SifProtectedFileComplete::new(&offer).unwrap())
            .unwrap();
        match terminal {
            SifProtectedFileReceiveTerminal::Verified(verified) => {
                assert_eq!(verified.observed_content_blake3(), *blake3::hash(payload).as_bytes());
            }
            other => panic!("expected verified terminal, got {other:?}"),
        }
    }

    #[test]
    fn gaps_overlaps_and_duplicates_are_rejected() {
        let offer = offer_for(b"abcdefghij");
        let mut receiver = SifProtectedFileReceiver::new(offer.clone()).unwrap();
        receiver
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 0, b"abcd".to_vec()).unwrap())
            .unwrap();

        for offset in [0, 2, 5] {
            let chunk = SifProtectedFileChunk::new(&offer, offset, b"ef".to_vec()).unwrap();
            assert!(matches!(
                receiver.accept_chunk(&chunk),
                Err(SifProtectedFileReceiveError::NonContiguousChunk {
                    expected_offset: 4,
                    found_offset
                }) if found_offset == offset
            ));
        }
    }

    #[test]
    fn premature_complete_becomes_signed_negative_evidence_shape() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let mut receiver = SifProtectedFileReceiver::new(offer.clone()).unwrap();
        receiver
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 0, b"abcd".to_vec()).unwrap())
            .unwrap();
        let terminal = receiver
            .finish_with_complete(&SifProtectedFileComplete::new(&offer).unwrap())
            .unwrap();
        let incomplete = match terminal {
            SifProtectedFileReceiveTerminal::Incomplete(incomplete) => incomplete,
            other => panic!("expected incomplete terminal, got {other:?}"),
        };
        assert_eq!(incomplete.received_bytes(), 4);

        let receiver_key = SigningKey::from_bytes(&[0x44; 32]);
        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(9),
            [0x55; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let binding = incomplete
            .into_delivery_receipt_binding(
                session,
                SignatureSuite::Ed25519Rfc8032,
                &receiver_key.verifying_key().to_bytes(),
                1_780_000_000_100,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
            .unwrap();
        assert_eq!(binding.disposition(), SifDeliveryDisposition::Incomplete);
        assert_eq!(binding.received_bytes(), 4);
    }

    #[test]
    fn full_length_wrong_content_is_integrity_mismatch_not_success() {
        let expected = b"abcdefghij";
        let offer = offer_for(expected);
        let mut receiver = SifProtectedFileReceiver::new(offer.clone()).unwrap();
        receiver
            .accept_chunk(
                &SifProtectedFileChunk::new(&offer, 0, b"0123456789".to_vec()).unwrap(),
            )
            .unwrap();
        match receiver.finish_observation() {
            SifProtectedFileReceiveTerminal::IntegrityMismatch(mismatch) => {
                assert_ne!(mismatch.observed_content_blake3(), offer.content_blake3());
            }
            other => panic!("expected integrity mismatch, got {other:?}"),
        }
    }

    #[test]
    fn complete_verified_content_can_produce_externally_verifiable_receipt() {
        let payload = b"abcdefghij";
        let offer = offer_for(payload);
        let mut receiver = SifProtectedFileReceiver::new(offer.clone()).unwrap();
        receiver
            .accept_chunk(&SifProtectedFileChunk::new(&offer, 0, payload.to_vec()).unwrap())
            .unwrap();
        let verified = match receiver.finish_observation() {
            SifProtectedFileReceiveTerminal::Verified(verified) => verified,
            other => panic!("expected verified terminal, got {other:?}"),
        };

        let receiver_key = SigningKey::from_bytes(&[0x66; 32]);
        let receiver_public_key = receiver_key.verifying_key().to_bytes();
        let receiver_key_id = sif_delivery_receiver_key_id(
            SignatureSuite::Ed25519Rfc8032,
            &receiver_public_key,
        );
        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(9),
            [0x77; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let expectation: SifDeliveryReceiptExpectation = offer
            .delivery_expectation(
                &session,
                SignatureSuite::Ed25519Rfc8032,
                receiver_key_id,
            )
            .unwrap();
        let binding = verified
            .into_delivery_receipt_binding(
                session,
                SignatureSuite::Ed25519Rfc8032,
                &receiver_public_key,
                VerifiedSifPersistenceOutcome::Persisted,
                1_780_000_000_200,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
            .unwrap();
        let receipt = sign_sif_delivery_receipt_ed25519(
            binding,
            &receiver_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        receipt
            .verify_for_expectation(
                &expectation,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &receiver_public_key,
            )
            .unwrap();
    }

    #[test]
    fn empty_file_can_verify_without_content_chunks() {
        let offer = offer_for(b"");
        let receiver = SifProtectedFileReceiver::new(offer).unwrap();
        assert!(receiver.has_declared_byte_count());
        assert!(matches!(
            receiver.finish_observation(),
            SifProtectedFileReceiveTerminal::Verified(_)
        ));
    }
}
