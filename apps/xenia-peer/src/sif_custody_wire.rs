// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-bounded online custody evidence above the dedicated peer-core carrier.
//!
//! The online message intentionally does not echo release/session/file commitments the
//! sender already knows. It carries only the receiver observation and signature. The
//! sender reconstructs the exact [`SifDeliveryReceiptBinding`] from its trusted Offer,
//! authenticated session and enrolled receiver key, then verifies the signature over
//! that reconstructed statement. This prevents the peer from self-authorizing the
//! identity of the release it claims to close.

use thiserror::Error;
use xenia_ledger::{
    EvidenceCryptoManifest, EvidenceSignatureBackend, SessionTranscriptBinding,
    SifDeliveryDisposition, SifDeliveryReceipt, SifDeliveryReceiptBinding,
    SifDeliveryReceiptError, SifProtectedFileOffer, SignatureEnvelopeError, SignatureSuite,
    sif_delivery_receipt_message,
};
use xenia_peer_core::{
    SifCustodyWireChannel, SifCustodyWireError, SifCustodyWirePayload,
    SifProtectedFileWireRole,
};

/// Stable inner online-custody codec version.
pub const SIF_CUSTODY_CODEC_VERSION: u8 = 1;

const CUSTODY_FIXED_BYTES: usize = 1 + 1 + 8 + 1 + 32 + 8 + 1 + 2;

/// Minimal receiver observation + signature sent back to the disclosure origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SifCustodyObservationMessage {
    disposition: SifDeliveryDisposition,
    received_bytes: u64,
    observed_content_blake3: Option<[u8; 32]>,
    observed_at_unix_ms: u64,
    receiver_signature_suite: SignatureSuite,
    signature: Vec<u8>,
}

impl SifCustodyObservationMessage {
    /// Derive the online observation from one already-signed portable receipt.
    ///
    /// `offer` and `session` are locally authenticated receiver state. A receipt for a
    /// different release/session cannot be repackaged into this transfer's custody lane.
    pub fn from_signed_receipt(
        receipt: &SifDeliveryReceipt,
        offer: &SifProtectedFileOffer,
        session: &SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
    ) -> Result<Self, SifCustodySemanticError> {
        let binding = receipt.binding();
        binding.validate_against_manifest(manifest)?;
        require_receipt_matches_local(binding, offer, session)?;
        let suite = receipt.signature().validate_shape()?;
        if suite != binding.receiver_signature_suite() {
            return Err(SifCustodySemanticError::ReceiptSignatureSuiteMismatch);
        }
        Ok(Self {
            disposition: binding.disposition(),
            received_bytes: binding.received_bytes(),
            observed_content_blake3: binding.observed_content_blake3(),
            observed_at_unix_ms: binding.observed_at_unix_ms(),
            receiver_signature_suite: suite,
            signature: receipt.signature().signature.clone(),
        })
    }

    /// Receiver-observed terminal delivery disposition.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.disposition
    }

    /// Receiver-observed file-content bytes.
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Receiver-observed whole-file BLAKE3 when a complete file existed.
    pub const fn observed_content_blake3(&self) -> Option<[u8; 32]> {
        self.observed_content_blake3
    }

    /// Signed receiver wall-clock observation time.
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// Signature suite declared by the receiver artifact.
    pub const fn receiver_signature_suite(&self) -> SignatureSuite {
        self.receiver_signature_suite
    }

    /// Raw receiver signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Verify online custody against sender-known Offer/session and an enrolled key.
    ///
    /// The peer does not supply release ID, transfer ID, sender Commit hash, result
    /// digest, expected size/hash or receiver key ID here. Those values are reconstructed
    /// from trusted local state before signature verification.
    pub fn verify_for_sender_state(
        &self,
        offer: &SifProtectedFileOffer,
        session: SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
        backend: &impl EvidenceSignatureBackend,
        trusted_receiver_public_key: &[u8],
    ) -> Result<VerifiedSifCustodyObservation, SifCustodySemanticError> {
        if self.receiver_signature_suite != backend.suite() {
            return Err(SifCustodySemanticError::VerifierSuiteMismatch {
                message_suite: self.receiver_signature_suite,
                backend_suite: backend.suite(),
            });
        }
        if let Some(expected) = self.receiver_signature_suite.fixed_signature_len()
            && self.signature.len() != expected
        {
            return Err(SifCustodySemanticError::BadSignatureLength {
                expected,
                found: self.signature.len(),
            });
        }

        let binding = SifDeliveryReceiptBinding::new(
            offer.release_id(),
            offer.transfer_id(),
            session,
            offer.sender_release_entry_hash(),
            offer.display_name(),
            offer.size(),
            offer.content_blake3(),
            self.receiver_signature_suite,
            trusted_receiver_public_key,
            self.disposition,
            self.received_bytes,
            self.observed_content_blake3,
            self.observed_at_unix_ms,
            manifest,
        )?;
        if binding.result_digest() != offer.result_digest() {
            return Err(SifCustodySemanticError::LocalOfferResultMismatch);
        }
        backend.verify_signature(
            trusted_receiver_public_key,
            &sif_delivery_receipt_message(&binding),
            &self.signature,
        )?;
        Ok(VerifiedSifCustodyObservation { binding })
    }
}

/// Custody observation whose receiver signature verified against sender-owned context.
#[derive(Debug)]
pub struct VerifiedSifCustodyObservation {
    binding: SifDeliveryReceiptBinding,
}

impl VerifiedSifCustodyObservation {
    /// Exact verified receiver statement reconstructed from sender-known state.
    pub fn binding(&self) -> &SifDeliveryReceiptBinding {
        &self.binding
    }

    /// Receiver disposition after signature verification.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.binding.disposition()
    }

    /// Consume the verified observation into its canonical delivery binding.
    pub fn into_binding(self) -> SifDeliveryReceiptBinding {
        self.binding
    }
}

/// Typed custody semantic channel over peer-core's dedicated `0x37`/`0x38` domain.
pub struct SifCustodySemanticChannel {
    wire: SifCustodyWireChannel,
}

impl SifCustodySemanticChannel {
    /// Create a custody channel with fresh source metadata.
    pub fn new(role: SifProtectedFileWireRole) -> Self {
        Self {
            wire: SifCustodyWireChannel::new(role),
        }
    }

    /// Create a deterministic channel for qualification tests.
    pub fn with_fixture(role: SifProtectedFileWireRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            wire: SifCustodyWireChannel::with_fixture(role, source_id, epoch),
        }
    }

    /// Install the negotiated control key.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.wire.install_control_key(key);
    }

    /// Seal one signed receiver custody observation.
    pub fn seal_observation(
        &mut self,
        message: &SifCustodyObservationMessage,
    ) -> Result<Vec<u8>, SifCustodySemanticError> {
        let payload = SifCustodyWirePayload::new(encode_observation(message)?)?;
        Ok(self.wire.seal(&payload)?)
    }

    /// Open one receiver custody observation from the exact remote custody domain.
    pub fn open_observation(
        &mut self,
        envelope: &[u8],
    ) -> Result<SifCustodyObservationMessage, SifCustodySemanticError> {
        let payload = self.wire.open(envelope)?;
        decode_observation(payload.semantic_bytes())
    }
}

fn encode_observation(
    message: &SifCustodyObservationMessage,
) -> Result<Vec<u8>, SifCustodySemanticError> {
    if let Some(expected) = message.receiver_signature_suite.fixed_signature_len()
        && message.signature.len() != expected
    {
        return Err(SifCustodySemanticError::BadSignatureLength {
            expected,
            found: message.signature.len(),
        });
    }
    let signature_len = u16::try_from(message.signature.len())
        .map_err(|_| SifCustodySemanticError::SignatureTooLarge)?;
    let mut out = Vec::with_capacity(CUSTODY_FIXED_BYTES + message.signature.len());
    out.push(SIF_CUSTODY_CODEC_VERSION);
    out.push(disposition_tag(message.disposition));
    out.extend_from_slice(&message.received_bytes.to_be_bytes());
    match message.observed_content_blake3 {
        Some(hash) => {
            out.push(1);
            out.extend_from_slice(&hash);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; 32]);
        }
    }
    out.extend_from_slice(&message.observed_at_unix_ms.to_be_bytes());
    out.push(signature_suite_tag(message.receiver_signature_suite));
    out.extend_from_slice(&signature_len.to_be_bytes());
    out.extend_from_slice(&message.signature);
    Ok(out)
}

fn decode_observation(bytes: &[u8]) -> Result<SifCustodyObservationMessage, SifCustodySemanticError> {
    if bytes.len() < CUSTODY_FIXED_BYTES {
        return Err(SifCustodySemanticError::TruncatedObservation);
    }
    if bytes[0] != SIF_CUSTODY_CODEC_VERSION {
        return Err(SifCustodySemanticError::UnsupportedCodec { found: bytes[0] });
    }
    let disposition = disposition_from_tag(bytes[1])?;
    let received_bytes = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
    let observed = match bytes[10] {
        0 => {
            if bytes[11..43] != [0u8; 32] {
                return Err(SifCustodySemanticError::NonCanonicalAbsentHash);
            }
            None
        }
        1 => Some(bytes[11..43].try_into().unwrap()),
        _ => return Err(SifCustodySemanticError::BadObservedHashTag),
    };
    let observed_at_unix_ms = u64::from_be_bytes(bytes[43..51].try_into().unwrap());
    let receiver_signature_suite = signature_suite_from_tag(bytes[51])?;
    let signature_len = usize::from(u16::from_be_bytes([bytes[52], bytes[53]]));
    if let Some(expected) = receiver_signature_suite.fixed_signature_len()
        && signature_len != expected
    {
        return Err(SifCustodySemanticError::BadSignatureLength {
            expected,
            found: signature_len,
        });
    }
    let total = CUSTODY_FIXED_BYTES
        .checked_add(signature_len)
        .ok_or(SifCustodySemanticError::SignatureTooLarge)?;
    if bytes.len() != total {
        return Err(SifCustodySemanticError::ObservationLengthMismatch {
            expected: total,
            found: bytes.len(),
        });
    }
    Ok(SifCustodyObservationMessage {
        disposition,
        received_bytes,
        observed_content_blake3: observed,
        observed_at_unix_ms,
        receiver_signature_suite,
        signature: bytes[CUSTODY_FIXED_BYTES..].to_vec(),
    })
}

fn require_receipt_matches_local(
    binding: &SifDeliveryReceiptBinding,
    offer: &SifProtectedFileOffer,
    session: &SessionTranscriptBinding,
) -> Result<(), SifCustodySemanticError> {
    let mismatch = if binding.release_id() != offer.release_id() {
        Some("release_id")
    } else if binding.transfer_id() != offer.transfer_id() {
        Some("transfer_id")
    } else if binding.session().session_id != session.session_id {
        Some("session_id")
    } else if binding.session().transcript_hash != session.transcript_hash {
        Some("transcript_hash")
    } else if binding.sender_release_entry_hash() != offer.sender_release_entry_hash() {
        Some("sender_release_entry_hash")
    } else if binding.result_digest() != offer.result_digest() {
        Some("result_digest")
    } else if binding.expected_size() != offer.size() {
        Some("expected_size")
    } else if binding.expected_content_blake3() != offer.content_blake3() {
        Some("expected_content_blake3")
    } else {
        None
    };
    if let Some(field) = mismatch {
        return Err(SifCustodySemanticError::ReceiptContextMismatch { field });
    }
    Ok(())
}

const fn disposition_tag(value: SifDeliveryDisposition) -> u8 {
    match value {
        SifDeliveryDisposition::PersistedVerified => 0,
        SifDeliveryDisposition::IntegrityMismatch => 1,
        SifDeliveryDisposition::Incomplete => 2,
        SifDeliveryDisposition::PersistenceFailed => 3,
    }
}

fn disposition_from_tag(tag: u8) -> Result<SifDeliveryDisposition, SifCustodySemanticError> {
    match tag {
        0 => Ok(SifDeliveryDisposition::PersistedVerified),
        1 => Ok(SifDeliveryDisposition::IntegrityMismatch),
        2 => Ok(SifDeliveryDisposition::Incomplete),
        3 => Ok(SifDeliveryDisposition::PersistenceFailed),
        _ => Err(SifCustodySemanticError::UnknownDisposition { tag }),
    }
}

const fn signature_suite_tag(value: SignatureSuite) -> u8 {
    match value {
        SignatureSuite::Ed25519Rfc8032 => 0,
        SignatureSuite::MlDsa65Fips204 => 1,
        SignatureSuite::MlDsa87Fips204 => 2,
        SignatureSuite::SlhDsaFips205 => 3,
    }
}

fn signature_suite_from_tag(tag: u8) -> Result<SignatureSuite, SifCustodySemanticError> {
    match tag {
        0 => Ok(SignatureSuite::Ed25519Rfc8032),
        1 => Ok(SignatureSuite::MlDsa65Fips204),
        2 => Ok(SignatureSuite::MlDsa87Fips204),
        3 => Ok(SignatureSuite::SlhDsaFips205),
        _ => Err(SifCustodySemanticError::UnknownSignatureSuite { tag }),
    }
}

/// Fail-closed online custody errors.
#[derive(Debug, Error)]
pub enum SifCustodySemanticError {
    /// Dedicated custody carrier rejected or failed the envelope.
    #[error(transparent)]
    Wire(#[from] SifCustodyWireError),
    /// Portable delivery statement construction/validation failed.
    #[error(transparent)]
    DeliveryReceipt(#[from] SifDeliveryReceiptError),
    /// Signature envelope shape was invalid.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Signature backend rejected the receiver signature.
    #[error(transparent)]
    SignatureVerification(#[from] xenia_ledger::EvidenceSignatureBackendError),
    /// Signed receipt did not belong to the local Offer/session.
    #[error("SIF custody receipt disagreed with local {field}")]
    ReceiptContextMismatch {
        /// Trusted local field that differed.
        field: &'static str,
    },
    /// Portable receipt envelope and binding named different signature suites.
    #[error("SIF custody receipt signature suite disagreed with its binding")]
    ReceiptSignatureSuiteMismatch,
    /// Online message signature suite disagreed with the selected verification backend.
    #[error("SIF custody verifier suite mismatch: message={message_suite:?}, backend={backend_suite:?}")]
    VerifierSuiteMismatch {
        /// Suite carried by the authenticated custody message.
        message_suite: SignatureSuite,
        /// Suite implemented by the local trusted verifier backend.
        backend_suite: SignatureSuite,
    },
    /// Signature length did not match its fixed-suite profile.
    #[error("bad SIF custody signature length: expected {expected}, found {found}")]
    BadSignatureLength {
        /// Fixed expected signature length.
        expected: usize,
        /// Received signature length.
        found: usize,
    },
    /// Signature could not fit the bounded v1 online representation.
    #[error("SIF custody signature exceeds v1 representation")]
    SignatureTooLarge,
    /// Online custody message ended before its fixed header.
    #[error("truncated SIF custody observation")]
    TruncatedObservation,
    /// Online custody codec version is unsupported.
    #[error("unsupported SIF custody codec version {found}")]
    UnsupportedCodec {
        /// Authenticated codec byte.
        found: u8,
    },
    /// Disposition tag is unknown.
    #[error("unknown SIF custody disposition tag {tag}")]
    UnknownDisposition {
        /// Authenticated disposition tag.
        tag: u8,
    },
    /// Signature-suite tag is unknown.
    #[error("unknown SIF custody signature-suite tag {tag}")]
    UnknownSignatureSuite {
        /// Authenticated signature-suite tag.
        tag: u8,
    },
    /// Observed-hash presence tag is invalid.
    #[error("invalid SIF custody observed-hash tag")]
    BadObservedHashTag,
    /// Absent whole-file hash must use the all-zero canonical placeholder.
    #[error("non-canonical SIF custody absent-hash representation")]
    NonCanonicalAbsentHash,
    /// Exact message length did not match the bounded signature length.
    #[error("SIF custody observation length mismatch: expected {expected}, found {found}")]
    ObservationLengthMismatch {
        /// Exact expected authenticated byte length.
        expected: usize,
        /// Actual authenticated byte length.
        found: usize,
    },
    /// Sender-owned Offer metadata failed to reproduce its committed result digest.
    #[error("local SIF Offer metadata does not reproduce its result commitment")]
    LocalOfferResultMismatch,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;
    use xenia_ledger::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, Ed25519EvidenceSignatureBackend,
        SifDeliveryReceiptBinding, sign_sif_delivery_receipt_ed25519, sif_file_result_digest,
    };

    use super::*;

    const KEY: [u8; 32] = [0xA5; 32];
    const SOURCE_ID: [u8; 8] = [0x17; 8];
    const EPOCH: u8 = 4;

    fn offer() -> SifProtectedFileOffer {
        let hash = [0x55; 32];
        let result = sif_file_result_digest("evidence.bin", 5, hash).unwrap();
        SifProtectedFileOffer::new(
            Uuid::from_u128(20),
            7,
            [0x22; 32],
            result,
            "evidence.bin",
            5,
            hash,
        )
        .unwrap()
    }

    fn session() -> SessionTranscriptBinding {
        SessionTranscriptBinding::from_hash(
            Uuid::from_u128(10),
            [0x11; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        )
    }

    fn signed_receipt(signing_key: &SigningKey) -> SifDeliveryReceipt {
        let offer = offer();
        let binding = SifDeliveryReceiptBinding::new(
            offer.release_id(),
            offer.transfer_id(),
            session(),
            offer.sender_release_entry_hash(),
            offer.display_name(),
            offer.size(),
            offer.content_blake3(),
            SignatureSuite::Ed25519Rfc8032,
            &signing_key.verifying_key().to_bytes(),
            SifDeliveryDisposition::PersistedVerified,
            5,
            Some([0x55; 32]),
            1_780_000_000_700,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        sign_sif_delivery_receipt_ed25519(
            binding,
            signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap()
    }

    #[test]
    fn receiver_message_roundtrip_verifies_against_sender_owned_context() {
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let receipt = signed_receipt(&signing_key);
        let message = SifCustodyObservationMessage::from_signed_receipt(
            &receipt,
            &offer(),
            &session(),
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();

        let mut viewer = SifCustodySemanticChannel::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
        );
        let mut host = SifCustodySemanticChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        viewer.install_control_key(KEY);
        host.install_control_key(KEY);
        let envelope = viewer.seal_observation(&message).unwrap();
        let opened = host.open_observation(&envelope).unwrap();
        let verified = opened
            .verify_for_sender_state(
                &offer(),
                session(),
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &signing_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(verified.disposition(), SifDeliveryDisposition::PersistedVerified);
    }

    #[test]
    fn custody_signature_cannot_migrate_to_another_offer() {
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let receipt = signed_receipt(&signing_key);
        let message = SifCustodyObservationMessage::from_signed_receipt(
            &receipt,
            &offer(),
            &session(),
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let mut other = offer();
        // Create a distinct, still-valid Offer rather than mutating private state.
        let other_hash = [0x66; 32];
        let other_result = sif_file_result_digest("other.bin", 5, other_hash).unwrap();
        other = SifProtectedFileOffer::new(
            Uuid::from_u128(21),
            8,
            [0x33; 32],
            other_result,
            "other.bin",
            5,
            other_hash,
        )
        .unwrap();
        assert!(message
            .verify_for_sender_state(
                &other,
                session(),
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &signing_key.verifying_key().to_bytes(),
            )
            .is_err());
    }

    #[test]
    fn observation_codec_rejects_signature_length_bomb_before_copy() {
        let mut forged = vec![0u8; CUSTODY_FIXED_BYTES];
        forged[0] = SIF_CUSTODY_CODEC_VERSION;
        forged[1] = 0;
        forged[10] = 1;
        forged[43..51].copy_from_slice(&1u64.to_be_bytes());
        forged[51] = 0;
        forged[52..54].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_observation(&forged),
            Err(SifCustodySemanticError::BadSignatureLength { .. })
        ));
    }
}
