// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Semantic wire contract for SIF-protected file transfer.
//!
//! The legacy Xenia file-transfer protocol identifies an Offer primarily by a
//! session-local transfer ID. That is sufficient for ordinary file movement, but not
//! for accountable SIF evidence release: a receiver must know which durable sender
//! release Commit authorized the bytes, and an ordinary legacy `Accept` must never be
//! able to unlock SIF-protected content.
//!
//! This module defines the release-bound protocol objects that a later transport
//! integration must carry under a **dedicated authenticated payload type/domain**.
//! It deliberately does not modify the current legacy `FileTransferMessage` or claim
//! that the existing daemon/viewer already use these messages.
//!
//! Every response/chunk/completion binds the canonical digest of one exact protected
//! Offer. The Offer itself binds the single-use release ID, sender release-journal
//! Commit hash, canonical SIF file-result commitment, wire-visible display name,
//! length, and whole-file BLAKE3. The constructor independently recomputes the file
//! result commitment and refuses a mismatch with the sender's committed result.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::delivery_receipt::SifDeliveryReceiptExpectation;
use crate::file_disclosure::{FileDisclosureError, sif_file_result_digest};
use crate::signature::SignatureSuite;
use crate::SessionTranscriptBinding;

/// Stable semantic protocol schema for SIF protected file messages.
pub const SIF_PROTECTED_FILE_PROTOCOL_SCHEMA: &str = "xenia-sif-protected-file-v1";
/// Stable protected Offer schema.
pub const SIF_PROTECTED_FILE_OFFER_SCHEMA: &str = "xenia-sif-protected-file-offer-v1";
/// Stable Offer response schema.
pub const SIF_PROTECTED_FILE_RESPONSE_SCHEMA: &str = "xenia-sif-protected-file-response-v1";
/// Stable content Chunk schema.
pub const SIF_PROTECTED_FILE_CHUNK_SCHEMA: &str = "xenia-sif-protected-file-chunk-v1";
/// Stable transfer-completion schema.
pub const SIF_PROTECTED_FILE_COMPLETE_SCHEMA: &str = "xenia-sif-protected-file-complete-v1";
/// Commitment algorithm used for protected Offer identifiers.
pub const SIF_PROTECTED_FILE_OFFER_DIGEST_ALGORITHM: &str = "blake3-256";
/// Maximum UTF-8 byte length for the portable wire-visible basename.
pub const MAX_SIF_PROTECTED_FILE_NAME_BYTES: usize = 255;
/// Maximum human-readable Reject reason retained in the authenticated protocol.
pub const MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES: usize = 512;
/// Protocol ceiling for one protected file-content Chunk.
///
/// Runtime carriers may choose a smaller chunk size, but must not exceed this semantic
/// protocol bound without a new protocol revision.
pub const MAX_SIF_PROTECTED_FILE_CHUNK_BYTES: usize = 64 * 1024;

const OFFER_DIGEST_DOMAIN: &[u8] = b"xenia:sif-protected-file:offer-digest:v1";

/// Exact release-bound protected Offer.
///
/// The plaintext display name is present on the live authenticated protocol because a
/// receiver needs a destination basename and must independently derive the same SIF
/// file-result commitment. Portable delivery receipts may subsequently discard the
/// name and retain only the derived commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProtectedFileOffer {
    schema: String,
    release_id: Uuid,
    transfer_id: u64,
    sender_release_entry_hash: [u8; 32],
    result_digest: [u8; 32],
    display_name: String,
    size: u64,
    content_blake3: [u8; 32],
}

impl SifProtectedFileOffer {
    /// Construct a protected Offer only when exact file metadata reproduces the
    /// result commitment already authorized by the sender's durable release.
    pub fn new(
        release_id: Uuid,
        transfer_id: u64,
        sender_release_entry_hash: [u8; 32],
        committed_result_digest: [u8; 32],
        display_name: impl Into<String>,
        size: u64,
        content_blake3: [u8; 32],
    ) -> Result<Self, SifProtectedFileProtocolError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        let derived = sif_file_result_digest(&display_name, size, content_blake3)?;
        if derived != committed_result_digest {
            return Err(SifProtectedFileProtocolError::ResultCommitmentMismatch);
        }
        let offer = Self {
            schema: SIF_PROTECTED_FILE_OFFER_SCHEMA.to_string(),
            release_id,
            transfer_id,
            sender_release_entry_hash,
            result_digest: committed_result_digest,
            display_name,
            size,
            content_blake3,
        };
        offer.validate()?;
        Ok(offer)
    }

    /// Verify the complete semantic Offer after deserialization.
    pub fn validate(&self) -> Result<(), SifProtectedFileProtocolError> {
        if self.schema != SIF_PROTECTED_FILE_OFFER_SCHEMA {
            return Err(SifProtectedFileProtocolError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.release_id.is_nil() {
            return Err(SifProtectedFileProtocolError::NilReleaseId);
        }
        if self.transfer_id == 0 {
            return Err(SifProtectedFileProtocolError::ZeroTransferId);
        }
        require_nonzero("sender_release_entry_hash", &self.sender_release_entry_hash)?;
        require_nonzero("result_digest", &self.result_digest)?;
        require_nonzero("content_blake3", &self.content_blake3)?;
        validate_display_name(&self.display_name)?;
        let derived = sif_file_result_digest(&self.display_name, self.size, self.content_blake3)?;
        if derived != self.result_digest {
            return Err(SifProtectedFileProtocolError::ResultCommitmentMismatch);
        }
        Ok(())
    }

    /// Single-use durable sender release identifier.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Session-local transfer identifier.
    pub const fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    /// Sender release-journal Commit entry hash authorizing this transfer.
    pub const fn sender_release_entry_hash(&self) -> [u8; 32] {
        self.sender_release_entry_hash
    }

    /// Canonical minimum-necessary SIF result commitment.
    pub const fn result_digest(&self) -> [u8; 32] {
        self.result_digest
    }

    /// Exact authenticated wire-visible basename.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Declared protected file length.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Whole-file BLAKE3 committed by the Offer.
    pub const fn content_blake3(&self) -> [u8; 32] {
        self.content_blake3
    }

    /// Domain-separated identifier echoed by every later protocol object.
    pub fn offer_digest(&self) -> Result<[u8; 32], SifProtectedFileProtocolError> {
        self.validate()?;
        Ok(sif_protected_file_offer_digest(self))
    }

    /// Build the exact sender-side expectation for a later portable delivery receipt.
    ///
    /// `session` and receiver key identity must come from trusted local authenticated
    /// session/configuration state, not from an unverified remote receipt.
    pub fn delivery_expectation(
        &self,
        session: &SessionTranscriptBinding,
        receiver_signature_suite: SignatureSuite,
        receiver_key_id: [u8; 32],
    ) -> Result<SifDeliveryReceiptExpectation, SifProtectedFileProtocolError> {
        self.validate()?;
        session
            .validate_against_manifest(crate::CURRENT_EVIDENCE_CRYPTO_MANIFEST)
            .map_err(SifProtectedFileProtocolError::TranscriptBinding)?;
        require_nonzero("receiver_key_id", &receiver_key_id)?;
        Ok(SifDeliveryReceiptExpectation {
            release_id: self.release_id,
            transfer_id: self.transfer_id,
            session_id: session.session_id,
            transcript_hash: session.transcript_hash,
            sender_release_entry_hash: self.sender_release_entry_hash,
            result_digest: self.result_digest,
            expected_size: self.size,
            expected_content_blake3: self.content_blake3,
            receiver_signature_suite,
            receiver_key_id,
        })
    }
}

/// Stable domain-separated digest of one exact protected Offer.
pub fn sif_protected_file_offer_digest(offer: &SifProtectedFileOffer) -> [u8; 32] {
    let name = offer.display_name.as_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(OFFER_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(SIF_PROTECTED_FILE_PROTOCOL_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(SIF_PROTECTED_FILE_OFFER_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(offer.release_id.as_bytes());
    hasher.update(&offer.transfer_id.to_be_bytes());
    hasher.update(&offer.sender_release_entry_hash);
    hasher.update(&offer.result_digest);
    hasher.update(&(name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update(&offer.size.to_be_bytes());
    hasher.update(&offer.content_blake3);
    *hasher.finalize().as_bytes()
}

/// Receiver decision for one exact protected Offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SifProtectedFileOfferDecision {
    /// Receiver accepted this exact release-bound Offer.
    Accept,
    /// Receiver refused this exact release-bound Offer.
    Reject,
}

/// Authenticated response to one exact protected Offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProtectedFileOfferResponse {
    schema: String,
    release_id: Uuid,
    transfer_id: u64,
    offer_digest: [u8; 32],
    decision: SifProtectedFileOfferDecision,
    reason: Option<String>,
}

impl SifProtectedFileOfferResponse {
    /// Accept one exact protected Offer.
    pub fn accept(offer: &SifProtectedFileOffer) -> Result<Self, SifProtectedFileProtocolError> {
        offer.validate()?;
        Ok(Self {
            schema: SIF_PROTECTED_FILE_RESPONSE_SCHEMA.to_string(),
            release_id: offer.release_id,
            transfer_id: offer.transfer_id,
            offer_digest: offer.offer_digest()?,
            decision: SifProtectedFileOfferDecision::Accept,
            reason: None,
        })
    }

    /// Reject one exact protected Offer with a bounded human-readable reason.
    pub fn reject(
        offer: &SifProtectedFileOffer,
        reason: impl Into<String>,
    ) -> Result<Self, SifProtectedFileProtocolError> {
        offer.validate()?;
        let reason = reason.into();
        validate_reject_reason(&reason)?;
        Ok(Self {
            schema: SIF_PROTECTED_FILE_RESPONSE_SCHEMA.to_string(),
            release_id: offer.release_id,
            transfer_id: offer.transfer_id,
            offer_digest: offer.offer_digest()?,
            decision: SifProtectedFileOfferDecision::Reject,
            reason: Some(reason),
        })
    }

    /// Verify that this response belongs to exactly `offer`.
    pub fn validate_against_offer(
        &self,
        offer: &SifProtectedFileOffer,
    ) -> Result<(), SifProtectedFileProtocolError> {
        offer.validate()?;
        if self.schema != SIF_PROTECTED_FILE_RESPONSE_SCHEMA {
            return Err(SifProtectedFileProtocolError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        require_same_binding(
            self.release_id,
            self.transfer_id,
            self.offer_digest,
            offer,
        )?;
        match (self.decision, self.reason.as_deref()) {
            (SifProtectedFileOfferDecision::Accept, None) => Ok(()),
            (SifProtectedFileOfferDecision::Accept, Some(_)) => {
                Err(SifProtectedFileProtocolError::AcceptCarriesRejectReason)
            }
            (SifProtectedFileOfferDecision::Reject, Some(reason)) => validate_reject_reason(reason),
            (SifProtectedFileOfferDecision::Reject, None) => {
                Err(SifProtectedFileProtocolError::RejectMissingReason)
            }
        }
    }

    /// Receiver decision.
    pub const fn decision(&self) -> SifProtectedFileOfferDecision {
        self.decision
    }

    /// Optional bounded Reject reason.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Exact Offer identifier this response names.
    pub const fn offer_digest(&self) -> [u8; 32] {
        self.offer_digest
    }
}

/// One release-bound protected file-content chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProtectedFileChunk {
    schema: String,
    release_id: Uuid,
    transfer_id: u64,
    offer_digest: [u8; 32],
    offset: u64,
    data: Vec<u8>,
}

impl SifProtectedFileChunk {
    /// Build one bounded content Chunk for an exact protected Offer.
    pub fn new(
        offer: &SifProtectedFileOffer,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Self, SifProtectedFileProtocolError> {
        offer.validate()?;
        let chunk = Self {
            schema: SIF_PROTECTED_FILE_CHUNK_SCHEMA.to_string(),
            release_id: offer.release_id,
            transfer_id: offer.transfer_id,
            offer_digest: offer.offer_digest()?,
            offset,
            data,
        };
        chunk.validate_against_offer(offer)?;
        Ok(chunk)
    }

    /// Verify exact Offer binding and content bounds.
    pub fn validate_against_offer(
        &self,
        offer: &SifProtectedFileOffer,
    ) -> Result<(), SifProtectedFileProtocolError> {
        offer.validate()?;
        if self.schema != SIF_PROTECTED_FILE_CHUNK_SCHEMA {
            return Err(SifProtectedFileProtocolError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        require_same_binding(
            self.release_id,
            self.transfer_id,
            self.offer_digest,
            offer,
        )?;
        if self.data.is_empty() {
            return Err(SifProtectedFileProtocolError::EmptyChunk);
        }
        if self.data.len() > MAX_SIF_PROTECTED_FILE_CHUNK_BYTES {
            return Err(SifProtectedFileProtocolError::ChunkTooLarge {
                found: self.data.len(),
                max: MAX_SIF_PROTECTED_FILE_CHUNK_BYTES,
            });
        }
        let len = u64::try_from(self.data.len())
            .map_err(|_| SifProtectedFileProtocolError::ChunkRangeOverflow)?;
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SifProtectedFileProtocolError::ChunkRangeOverflow)?;
        if self.offset >= offer.size || end > offer.size {
            return Err(SifProtectedFileProtocolError::ChunkOutsideOffer {
                offset: self.offset,
                end,
                size: offer.size,
            });
        }
        Ok(())
    }

    /// Content offset committed by this Chunk.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Content payload.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Exact Offer identifier this Chunk names.
    pub const fn offer_digest(&self) -> [u8; 32] {
        self.offer_digest
    }
}

/// Sender declaration that no more content Chunks belong to one exact Offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProtectedFileComplete {
    schema: String,
    release_id: Uuid,
    transfer_id: u64,
    offer_digest: [u8; 32],
}

impl SifProtectedFileComplete {
    /// Construct a completion marker for one exact protected Offer.
    pub fn new(offer: &SifProtectedFileOffer) -> Result<Self, SifProtectedFileProtocolError> {
        offer.validate()?;
        Ok(Self {
            schema: SIF_PROTECTED_FILE_COMPLETE_SCHEMA.to_string(),
            release_id: offer.release_id,
            transfer_id: offer.transfer_id,
            offer_digest: offer.offer_digest()?,
        })
    }

    /// Verify exact Offer binding.
    pub fn validate_against_offer(
        &self,
        offer: &SifProtectedFileOffer,
    ) -> Result<(), SifProtectedFileProtocolError> {
        offer.validate()?;
        if self.schema != SIF_PROTECTED_FILE_COMPLETE_SCHEMA {
            return Err(SifProtectedFileProtocolError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        require_same_binding(
            self.release_id,
            self.transfer_id,
            self.offer_digest,
            offer,
        )
    }

    /// Exact Offer identifier this completion marker names.
    pub const fn offer_digest(&self) -> [u8; 32] {
        self.offer_digest
    }
}

fn require_same_binding(
    release_id: Uuid,
    transfer_id: u64,
    offer_digest: [u8; 32],
    offer: &SifProtectedFileOffer,
) -> Result<(), SifProtectedFileProtocolError> {
    if release_id != offer.release_id {
        return Err(SifProtectedFileProtocolError::ReleaseIdMismatch);
    }
    if transfer_id != offer.transfer_id {
        return Err(SifProtectedFileProtocolError::TransferIdMismatch);
    }
    if offer_digest != offer.offer_digest()? {
        return Err(SifProtectedFileProtocolError::OfferDigestMismatch);
    }
    Ok(())
}

fn validate_display_name(name: &str) -> Result<(), SifProtectedFileProtocolError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(SifProtectedFileProtocolError::InvalidDisplayName);
    }
    if name.len() > MAX_SIF_PROTECTED_FILE_NAME_BYTES {
        return Err(SifProtectedFileProtocolError::DisplayNameTooLong {
            found: name.len(),
            max: MAX_SIF_PROTECTED_FILE_NAME_BYTES,
        });
    }
    Ok(())
}

fn validate_reject_reason(reason: &str) -> Result<(), SifProtectedFileProtocolError> {
    if reason.trim().is_empty() {
        return Err(SifProtectedFileProtocolError::RejectMissingReason);
    }
    if reason.len() > MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES {
        return Err(SifProtectedFileProtocolError::RejectReasonTooLong {
            found: reason.len(),
            max: MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES,
        });
    }
    Ok(())
}

fn require_nonzero(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), SifProtectedFileProtocolError> {
    if *digest == [0u8; 32] {
        Err(SifProtectedFileProtocolError::ZeroCommitment { field })
    } else {
        Ok(())
    }
}

/// Fail-closed SIF protected-file protocol errors.
#[derive(Debug, Error)]
pub enum SifProtectedFileProtocolError {
    /// Canonical file-result commitment derivation failed.
    #[error(transparent)]
    FileBinding(#[from] FileDisclosureError),
    /// Delivery expectation transcript binding failed validation.
    #[error("SIF protected file session transcript binding is invalid: {0}")]
    TranscriptBinding(crate::TranscriptBindingError),
    /// Message schema is unsupported.
    #[error("unsupported SIF protected-file schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found after deserialization.
        schema: String,
    },
    /// Durable release identifier must be non-nil.
    #[error("SIF protected file release_id must not be nil")]
    NilReleaseId,
    /// Transfer ID zero is reserved.
    #[error("SIF protected file transfer_id must be non-zero")]
    ZeroTransferId,
    /// Required digest/key commitment was an all-zero placeholder.
    #[error("SIF protected file commitment {field} must not be all-zero")]
    ZeroCommitment {
        /// Field containing the zero placeholder.
        field: &'static str,
    },
    /// Offer metadata does not reproduce the durable sender result commitment.
    #[error("SIF protected file Offer metadata does not match committed result digest")]
    ResultCommitmentMismatch,
    /// Display name is not a portable bare filename.
    #[error("SIF protected file display name must be a non-empty portable basename")]
    InvalidDisplayName,
    /// Display name exceeded the protocol ceiling.
    #[error("SIF protected file display name is {found} bytes; maximum is {max}")]
    DisplayNameTooLong {
        /// UTF-8 byte length observed.
        found: usize,
        /// Protocol maximum.
        max: usize,
    },
    /// Response/chunk/completion names a different release.
    #[error("SIF protected file release_id does not match Offer")]
    ReleaseIdMismatch,
    /// Response/chunk/completion names a different transfer.
    #[error("SIF protected file transfer_id does not match Offer")]
    TransferIdMismatch,
    /// Response/chunk/completion names a different Offer digest.
    #[error("SIF protected file Offer digest mismatch")]
    OfferDigestMismatch,
    /// An Accept response carried Reject-only human text.
    #[error("SIF protected file Accept must not carry a Reject reason")]
    AcceptCarriesRejectReason,
    /// A Reject response omitted a meaningful reason.
    #[error("SIF protected file Reject requires a non-empty reason")]
    RejectMissingReason,
    /// Reject reason exceeded the protocol ceiling.
    #[error("SIF protected file Reject reason is {found} bytes; maximum is {max}")]
    RejectReasonTooLong {
        /// UTF-8 byte length observed.
        found: usize,
        /// Protocol maximum.
        max: usize,
    },
    /// Content Chunk carried zero bytes.
    #[error("SIF protected file Chunk must contain at least one byte")]
    EmptyChunk,
    /// Content Chunk exceeded the protocol ceiling.
    #[error("SIF protected file Chunk is {found} bytes; maximum is {max}")]
    ChunkTooLarge {
        /// Chunk byte length observed.
        found: usize,
        /// Protocol maximum.
        max: usize,
    },
    /// Chunk end offset overflowed u64.
    #[error("SIF protected file Chunk range overflow")]
    ChunkRangeOverflow,
    /// Chunk lies outside the file length committed by the Offer.
    #[error("SIF protected file Chunk range {offset}..{end} exceeds Offer size {size}")]
    ChunkOutsideOffer {
        /// Chunk start offset.
        offset: u64,
        /// Exclusive chunk end offset.
        end: u64,
        /// Offered file size.
        size: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, SessionTranscriptBinding,
        sif_delivery_receiver_key_id,
    };

    fn offer() -> SifProtectedFileOffer {
        let name = "evidence.bin";
        let size = 10;
        let content = [0xA5; 32];
        let result = sif_file_result_digest(name, size, content).unwrap();
        SifProtectedFileOffer::new(
            Uuid::from_u128(1),
            7,
            [0x11; 32],
            result,
            name,
            size,
            content,
        )
        .unwrap()
    }

    #[test]
    fn offer_binds_release_commit_and_exact_file_result() {
        let offer = offer();
        assert_eq!(
            offer.result_digest(),
            sif_file_result_digest("evidence.bin", 10, [0xA5; 32]).unwrap()
        );
        assert_ne!(offer.offer_digest().unwrap(), [0u8; 32]);

        let wrong = sif_file_result_digest("other.bin", 10, [0xA5; 32]).unwrap();
        assert!(matches!(
            SifProtectedFileOffer::new(
                Uuid::from_u128(1),
                7,
                [0x11; 32],
                wrong,
                "evidence.bin",
                10,
                [0xA5; 32],
            ),
            Err(SifProtectedFileProtocolError::ResultCommitmentMismatch)
        ));
    }

    #[test]
    fn offer_requires_portable_bare_name() {
        let result = sif_file_result_digest("../secret", 1, [0x22; 32]).unwrap();
        assert!(matches!(
            SifProtectedFileOffer::new(
                Uuid::from_u128(1),
                1,
                [0x11; 32],
                result,
                "../secret",
                1,
                [0x22; 32],
            ),
            Err(SifProtectedFileProtocolError::InvalidDisplayName)
        ));
    }

    #[test]
    fn legacy_style_transfer_id_only_accept_is_not_representable() {
        let offer = offer();
        let accepted = SifProtectedFileOfferResponse::accept(&offer).unwrap();
        accepted.validate_against_offer(&offer).unwrap();
        assert_eq!(accepted.decision(), SifProtectedFileOfferDecision::Accept);
        assert_eq!(accepted.offer_digest(), offer.offer_digest().unwrap());
    }

    #[test]
    fn response_for_other_offer_cannot_unlock_content() {
        let offer = offer();
        let response = SifProtectedFileOfferResponse::accept(&offer).unwrap();
        let other = SifProtectedFileOffer::new(
            Uuid::from_u128(2),
            7,
            [0x33; 32],
            sif_file_result_digest("evidence.bin", 10, [0xA5; 32]).unwrap(),
            "evidence.bin",
            10,
            [0xA5; 32],
        )
        .unwrap();
        assert!(matches!(
            response.validate_against_offer(&other),
            Err(SifProtectedFileProtocolError::ReleaseIdMismatch)
                | Err(SifProtectedFileProtocolError::OfferDigestMismatch)
        ));
    }

    #[test]
    fn chunks_are_release_offer_bound_and_range_checked() {
        let offer = offer();
        let first = SifProtectedFileChunk::new(&offer, 0, vec![1, 2, 3, 4]).unwrap();
        first.validate_against_offer(&offer).unwrap();
        assert_eq!(first.offset(), 0);
        assert_eq!(first.data(), &[1, 2, 3, 4]);

        assert!(matches!(
            SifProtectedFileChunk::new(&offer, 9, vec![1, 2]),
            Err(SifProtectedFileProtocolError::ChunkOutsideOffer { .. })
        ));
        assert!(matches!(
            SifProtectedFileChunk::new(&offer, 0, Vec::new()),
            Err(SifProtectedFileProtocolError::EmptyChunk)
        ));
    }

    #[test]
    fn completion_is_bound_to_exact_offer_digest() {
        let offer = offer();
        let complete = SifProtectedFileComplete::new(&offer).unwrap();
        complete.validate_against_offer(&offer).unwrap();
        assert_eq!(complete.offer_digest(), offer.offer_digest().unwrap());
    }

    #[test]
    fn offer_builds_sender_derived_delivery_expectation() {
        let offer = offer();
        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(9),
            [0x77; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let receiver_public_key = [0x66; 32];
        let receiver_key_id = sif_delivery_receiver_key_id(
            SignatureSuite::Ed25519Rfc8032,
            &receiver_public_key,
        );
        let expectation = offer
            .delivery_expectation(
                &session,
                SignatureSuite::Ed25519Rfc8032,
                receiver_key_id,
            )
            .unwrap();
        assert_eq!(expectation.release_id, offer.release_id());
        assert_eq!(expectation.transfer_id, offer.transfer_id());
        assert_eq!(
            expectation.sender_release_entry_hash,
            offer.sender_release_entry_hash()
        );
        assert_eq!(expectation.result_digest, offer.result_digest());
    }
}
