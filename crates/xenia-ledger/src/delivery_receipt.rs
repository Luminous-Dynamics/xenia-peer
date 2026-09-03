// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable receiver-signed delivery evidence for SIF protected releases.
//!
//! A sender-side release journal can prove that Xenia was authorized to disclose
//! and how many protected bytes may have left the sender. It cannot, by itself,
//! prove that the authenticated receiver reconstructed the same file and persisted
//! it. This module defines that separate evidence surface.
//!
//! The receipt is intentionally commitment-oriented: it carries the SIF file-result
//! commitment, exact expected size/content hash, sender release-Commit hash, and
//! authenticated session-transcript binding without requiring a plaintext filename
//! or local destination path in portable audit evidence.
//!
//! The receipt does not self-authorize its signer. Verifiers must supply the trusted
//! receiver public key and an explicit [`SifDeliveryReceiptExpectation`]. The signed
//! binding contains a domain-separated receiver key ID so a receipt cannot substitute
//! another key or signature suite while preserving the same semantic claims.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::binding::SessionTranscriptBinding;
use crate::entry::TranscriptBindingError;
use crate::policy::EvidenceCryptoManifest;
use crate::signature::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema for portable SIF receiver delivery receipts.
pub const SIF_DELIVERY_RECEIPT_SCHEMA: &str = "xenia-sif-delivery-receipt-v1";
/// Commitment algorithm used by the delivery receipt profile.
pub const SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM: &str = "blake3-256";

const DELIVERY_RECEIPT_MESSAGE_DOMAIN: &[u8] = b"xenia:sif-delivery-receipt:message:v1";
const DELIVERY_RECEIPT_DIGEST_DOMAIN: &[u8] = b"xenia:sif-delivery-receipt:digest:v1";
const DELIVERY_RECEIVER_KEY_DOMAIN: &[u8] = b"xenia:sif-delivery-receipt:receiver-key:v1";

/// Receiver-observed terminal state for one protected file transfer.
///
/// `PersistedVerified` is the only state that asserts successful durable delivery.
/// The other states are signed negative evidence and must never be interpreted as
/// successful custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SifDeliveryDisposition {
    /// The full expected byte count was received, the whole-file BLAKE3 matched,
    /// and local persistence completed successfully.
    PersistedVerified,
    /// The full expected byte count was received but its whole-file BLAKE3 differed
    /// from the protected offer's expected content hash.
    IntegrityMismatch,
    /// Fewer than the expected number of file-content bytes were received.
    Incomplete,
    /// The full file verified cryptographically, but durable local persistence failed.
    PersistenceFailed,
}

/// Canonical receiver-signed statement for one SIF protected release.
///
/// Fields are private so construction must pass the semantic validation performed by
/// [`Self::new`]. Portable verifiers should still call
/// [`SifDeliveryReceipt::verify_for_expectation`] rather than trusting deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifDeliveryReceiptBinding {
    schema: String,
    commitment_algorithm: String,
    release_id: Uuid,
    transfer_id: u64,
    session: SessionTranscriptBinding,
    sender_release_entry_hash: [u8; 32],
    result_digest: [u8; 32],
    expected_size: u64,
    expected_content_blake3: [u8; 32],
    receiver_signature_suite: SignatureSuite,
    receiver_key_id: [u8; 32],
    disposition: SifDeliveryDisposition,
    received_bytes: u64,
    observed_content_blake3: Option<[u8; 32]>,
    observed_at_unix_ms: u64,
}

impl SifDeliveryReceiptBinding {
    /// Build a receiver delivery statement from exact protected-offer and local
    /// receiver observations.
    ///
    /// `receiver_public_key` is used only to derive the domain-separated receiver key
    /// ID committed by the statement; it is not embedded in the portable receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        release_id: Uuid,
        transfer_id: u64,
        session: SessionTranscriptBinding,
        sender_release_entry_hash: [u8; 32],
        result_digest: [u8; 32],
        expected_size: u64,
        expected_content_blake3: [u8; 32],
        receiver_signature_suite: SignatureSuite,
        receiver_public_key: &[u8],
        disposition: SifDeliveryDisposition,
        received_bytes: u64,
        observed_content_blake3: Option<[u8; 32]>,
        observed_at_unix_ms: u64,
        manifest: EvidenceCryptoManifest,
    ) -> Result<Self, SifDeliveryReceiptError> {
        if let Some(expected) = receiver_signature_suite.fixed_public_key_len()
            && receiver_public_key.len() != expected
        {
            return Err(SifDeliveryReceiptError::BadReceiverPublicKeyLength {
                expected,
                found: receiver_public_key.len(),
            });
        }
        let binding = Self {
            schema: SIF_DELIVERY_RECEIPT_SCHEMA.to_string(),
            commitment_algorithm: SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM.to_string(),
            release_id,
            transfer_id,
            session,
            sender_release_entry_hash,
            result_digest,
            expected_size,
            expected_content_blake3,
            receiver_signature_suite,
            receiver_key_id: sif_delivery_receiver_key_id(
                receiver_signature_suite,
                receiver_public_key,
            ),
            disposition,
            received_bytes,
            observed_content_blake3,
            observed_at_unix_ms,
        };
        binding.validate_against_manifest(manifest)?;
        Ok(binding)
    }

    /// Single-use sender release identifier this delivery observation closes remotely.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Session-local protected transfer identifier.
    pub const fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    /// Authenticated Xenia session transcript under which delivery occurred.
    pub fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    /// Sender's signed release-journal Commit entry hash.
    pub const fn sender_release_entry_hash(&self) -> [u8; 32] {
        self.sender_release_entry_hash
    }

    /// Exact SIF minimum-necessary file result commitment.
    pub const fn result_digest(&self) -> [u8; 32] {
        self.result_digest
    }

    /// File length committed by the protected offer.
    pub const fn expected_size(&self) -> u64 {
        self.expected_size
    }

    /// Whole-file BLAKE3 committed by the protected offer.
    pub const fn expected_content_blake3(&self) -> [u8; 32] {
        self.expected_content_blake3
    }

    /// Signature suite used by the receiver for this receipt.
    pub const fn receiver_signature_suite(&self) -> SignatureSuite {
        self.receiver_signature_suite
    }

    /// Domain-separated identifier for the externally trusted receiver key.
    pub const fn receiver_key_id(&self) -> [u8; 32] {
        self.receiver_key_id
    }

    /// Receiver-observed terminal delivery state.
    pub const fn disposition(&self) -> SifDeliveryDisposition {
        self.disposition
    }

    /// Number of file-content bytes observed by the receiver.
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Whole-file BLAKE3 observed by the receiver when a complete file was available.
    pub const fn observed_content_blake3(&self) -> Option<[u8; 32]> {
        self.observed_content_blake3
    }

    /// Receiver wall-clock observation timestamp in Unix milliseconds.
    ///
    /// This is signed provenance, not proof that the receiver's clock was accurate.
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// Validate schema, transcript binding, commitments, and disposition semantics.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), SifDeliveryReceiptError> {
        if self.schema != SIF_DELIVERY_RECEIPT_SCHEMA {
            return Err(SifDeliveryReceiptError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.commitment_algorithm != SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM {
            return Err(SifDeliveryReceiptError::UnsupportedCommitmentAlgorithm {
                algorithm: self.commitment_algorithm.clone(),
            });
        }
        if self.release_id.is_nil() {
            return Err(SifDeliveryReceiptError::NilReleaseId);
        }
        if self.transfer_id == 0 {
            return Err(SifDeliveryReceiptError::ZeroTransferId);
        }
        require_nonzero("sender_release_entry_hash", &self.sender_release_entry_hash)?;
        require_nonzero("result_digest", &self.result_digest)?;
        require_nonzero("expected_content_blake3", &self.expected_content_blake3)?;
        require_nonzero("receiver_key_id", &self.receiver_key_id)?;
        if self.observed_at_unix_ms == 0 {
            return Err(SifDeliveryReceiptError::ZeroObservationTime);
        }
        self.session.validate_against_manifest(manifest)?;
        if self.received_bytes > self.expected_size {
            return Err(SifDeliveryReceiptError::ReceivedBeyondExpected {
                expected: self.expected_size,
                received: self.received_bytes,
            });
        }

        match self.disposition {
            SifDeliveryDisposition::PersistedVerified => {
                require_complete_verified_observation(self)?;
            }
            SifDeliveryDisposition::IntegrityMismatch => {
                if self.received_bytes != self.expected_size {
                    return Err(SifDeliveryReceiptError::DispositionInvariant(
                        "IntegrityMismatch requires the full declared byte count",
                    ));
                }
                let observed = self.observed_content_blake3.ok_or(
                    SifDeliveryReceiptError::DispositionInvariant(
                        "IntegrityMismatch requires a whole-file observed BLAKE3",
                    ),
                )?;
                if observed == self.expected_content_blake3 {
                    return Err(SifDeliveryReceiptError::DispositionInvariant(
                        "IntegrityMismatch cannot carry the expected content hash",
                    ));
                }
            }
            SifDeliveryDisposition::Incomplete => {
                if self.received_bytes >= self.expected_size {
                    return Err(SifDeliveryReceiptError::DispositionInvariant(
                        "Incomplete requires fewer than the declared byte count",
                    ));
                }
                if self.observed_content_blake3.is_some() {
                    return Err(SifDeliveryReceiptError::DispositionInvariant(
                        "Incomplete must not label a partial-stream hash as whole-file BLAKE3",
                    ));
                }
            }
            SifDeliveryDisposition::PersistenceFailed => {
                require_complete_verified_observation(self)?;
            }
        }
        Ok(())
    }
}

/// Portable signed SIF delivery receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifDeliveryReceipt {
    binding: SifDeliveryReceiptBinding,
    signature: SignatureEnvelope,
}

impl SifDeliveryReceipt {
    /// Canonical receiver-signed delivery statement.
    pub fn binding(&self) -> &SifDeliveryReceiptBinding {
        &self.binding
    }

    /// Algorithm-tagged receiver signature.
    pub fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }

    /// Verify this receipt against an explicit sender-side expectation and externally
    /// trusted receiver public key.
    pub fn verify_for_expectation(
        &self,
        expectation: &SifDeliveryReceiptExpectation,
        manifest: EvidenceCryptoManifest,
        backend: &impl EvidenceSignatureBackend,
        trusted_receiver_public_key: &[u8],
    ) -> Result<(), SifDeliveryReceiptError> {
        self.binding.validate_against_manifest(manifest)?;
        expectation.validate()?;
        require_expectation_match(&self.binding, expectation)?;

        let suite = self.signature.validate_shape()?;
        if suite != self.binding.receiver_signature_suite {
            return Err(SifDeliveryReceiptError::SignatureSuiteBindingMismatch {
                binding_suite: self.binding.receiver_signature_suite,
                signature_suite: suite,
            });
        }
        if suite != backend.suite() {
            return Err(SifDeliveryReceiptError::SignatureSuiteBackendMismatch {
                backend_suite: backend.suite(),
                signature_suite: suite,
            });
        }
        if let Some(expected) = suite.fixed_public_key_len()
            && trusted_receiver_public_key.len() != expected
        {
            return Err(SifDeliveryReceiptError::BadReceiverPublicKeyLength {
                expected,
                found: trusted_receiver_public_key.len(),
            });
        }
        let receiver_key_id =
            sif_delivery_receiver_key_id(suite, trusted_receiver_public_key);
        if receiver_key_id != self.binding.receiver_key_id
            || receiver_key_id != expectation.receiver_key_id
        {
            return Err(SifDeliveryReceiptError::ReceiverKeyIdMismatch);
        }

        backend.verify_signature(
            trusted_receiver_public_key,
            &sif_delivery_receipt_message(&self.binding),
            &self.signature.signature,
        )?;
        Ok(())
    }
}

/// Sender-side values a portable receipt must match exactly.
///
/// Construct this from trusted local release/session state, not from the unverified
/// receipt being checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SifDeliveryReceiptExpectation {
    /// Expected single-use release ID.
    pub release_id: Uuid,
    /// Expected session-local transfer ID.
    pub transfer_id: u64,
    /// Expected authenticated session ID.
    pub session_id: Uuid,
    /// Expected authenticated session transcript hash.
    pub transcript_hash: [u8; 32],
    /// Expected sender release-journal Commit entry hash.
    pub sender_release_entry_hash: [u8; 32],
    /// Expected SIF file-result commitment.
    pub result_digest: [u8; 32],
    /// Expected file length.
    pub expected_size: u64,
    /// Expected whole-file BLAKE3.
    pub expected_content_blake3: [u8; 32],
    /// Expected receiver signature suite.
    pub receiver_signature_suite: SignatureSuite,
    /// Expected externally enrolled receiver key ID.
    pub receiver_key_id: [u8; 32],
}

impl SifDeliveryReceiptExpectation {
    /// Validate non-zero identifiers and commitments before receipt comparison.
    pub fn validate(&self) -> Result<(), SifDeliveryReceiptError> {
        if self.release_id.is_nil() {
            return Err(SifDeliveryReceiptError::NilReleaseId);
        }
        if self.transfer_id == 0 {
            return Err(SifDeliveryReceiptError::ZeroTransferId);
        }
        if self.session_id.is_nil() {
            return Err(SifDeliveryReceiptError::NilSessionId);
        }
        require_nonzero("transcript_hash", &self.transcript_hash)?;
        require_nonzero("sender_release_entry_hash", &self.sender_release_entry_hash)?;
        require_nonzero("result_digest", &self.result_digest)?;
        require_nonzero("expected_content_blake3", &self.expected_content_blake3)?;
        require_nonzero("receiver_key_id", &self.receiver_key_id)?;
        Ok(())
    }
}

/// Domain-separated identifier for an externally trusted receiver verification key.
pub fn sif_delivery_receiver_key_id(
    suite: SignatureSuite,
    public_key: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DELIVERY_RECEIVER_KEY_DOMAIN);
    hasher.update(&[0]);
    hasher.update(suite.stable_label().as_bytes());
    hasher.update(&[0]);
    hasher.update(&(public_key.len() as u64).to_be_bytes());
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

/// Exact domain-separated bytes signed by a SIF delivery receiver.
pub fn sif_delivery_receipt_message(binding: &SifDeliveryReceiptBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(420);
    out.extend_from_slice(DELIVERY_RECEIPT_MESSAGE_DOMAIN);
    out.push(0);
    out.extend_from_slice(SIF_DELIVERY_RECEIPT_SCHEMA.as_bytes());
    out.push(0);
    out.extend_from_slice(SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM.as_bytes());
    out.push(0);
    out.extend_from_slice(binding.release_id.as_bytes());
    out.extend_from_slice(&binding.transfer_id.to_be_bytes());
    out.extend_from_slice(binding.session.session_id.as_bytes());
    out.extend_from_slice(binding.session.transcript_hash_algorithm.as_bytes());
    out.push(0);
    out.extend_from_slice(&binding.session.transcript_hash);
    out.extend_from_slice(binding.session.transcript_signature.stable_label().as_bytes());
    out.push(0);
    out.extend_from_slice(&binding.sender_release_entry_hash);
    out.extend_from_slice(&binding.result_digest);
    out.extend_from_slice(&binding.expected_size.to_be_bytes());
    out.extend_from_slice(&binding.expected_content_blake3);
    out.extend_from_slice(binding.receiver_signature_suite.stable_label().as_bytes());
    out.push(0);
    out.extend_from_slice(&binding.receiver_key_id);
    out.push(match binding.disposition {
        SifDeliveryDisposition::PersistedVerified => 0,
        SifDeliveryDisposition::IntegrityMismatch => 1,
        SifDeliveryDisposition::Incomplete => 2,
        SifDeliveryDisposition::PersistenceFailed => 3,
    });
    out.extend_from_slice(&binding.received_bytes.to_be_bytes());
    match binding.observed_content_blake3 {
        Some(hash) => {
            out.push(1);
            out.extend_from_slice(&hash);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&binding.observed_at_unix_ms.to_be_bytes());
    out
}

/// Stable digest of the complete signed delivery-receipt artifact.
pub fn sif_delivery_receipt_digest(receipt: &SifDeliveryReceipt) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DELIVERY_RECEIPT_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&sif_delivery_receipt_message(&receipt.binding));
    hasher.update(&[0]);
    hasher.update(receipt.signature.algorithm.as_bytes());
    hasher.update(&(receipt.signature.signature.len() as u64).to_be_bytes());
    hasher.update(&receipt.signature.signature);
    *hasher.finalize().as_bytes()
}

/// Sign a validated delivery binding with an Ed25519 receiver key.
pub fn sign_sif_delivery_receipt_ed25519(
    binding: SifDeliveryReceiptBinding,
    signing_key: &SigningKey,
    manifest: EvidenceCryptoManifest,
) -> Result<SifDeliveryReceipt, SifDeliveryReceiptError> {
    binding.validate_against_manifest(manifest)?;
    if binding.receiver_signature_suite != SignatureSuite::Ed25519Rfc8032 {
        return Err(SifDeliveryReceiptError::SigningKeySuiteMismatch);
    }
    let expected_key_id = sif_delivery_receiver_key_id(
        SignatureSuite::Ed25519Rfc8032,
        &signing_key.verifying_key().to_bytes(),
    );
    if expected_key_id != binding.receiver_key_id {
        return Err(SifDeliveryReceiptError::ReceiverKeyIdMismatch);
    }
    let signature = signing_key
        .sign(&sif_delivery_receipt_message(&binding))
        .to_bytes();
    Ok(SifDeliveryReceipt {
        binding,
        signature: SignatureEnvelope::ed25519(signature),
    })
}

fn require_complete_verified_observation(
    binding: &SifDeliveryReceiptBinding,
) -> Result<(), SifDeliveryReceiptError> {
    if binding.received_bytes != binding.expected_size {
        return Err(SifDeliveryReceiptError::DispositionInvariant(
            "verified delivery state requires the full declared byte count",
        ));
    }
    let observed = binding.observed_content_blake3.ok_or(
        SifDeliveryReceiptError::DispositionInvariant(
            "verified delivery state requires a whole-file observed BLAKE3",
        ),
    )?;
    if observed != binding.expected_content_blake3 {
        return Err(SifDeliveryReceiptError::DispositionInvariant(
            "verified delivery state requires the expected whole-file BLAKE3",
        ));
    }
    Ok(())
}

fn require_expectation_match(
    binding: &SifDeliveryReceiptBinding,
    expectation: &SifDeliveryReceiptExpectation,
) -> Result<(), SifDeliveryReceiptError> {
    let mismatched = if binding.release_id != expectation.release_id {
        Some("release_id")
    } else if binding.transfer_id != expectation.transfer_id {
        Some("transfer_id")
    } else if binding.session.session_id != expectation.session_id {
        Some("session_id")
    } else if binding.session.transcript_hash != expectation.transcript_hash {
        Some("transcript_hash")
    } else if binding.sender_release_entry_hash != expectation.sender_release_entry_hash {
        Some("sender_release_entry_hash")
    } else if binding.result_digest != expectation.result_digest {
        Some("result_digest")
    } else if binding.expected_size != expectation.expected_size {
        Some("expected_size")
    } else if binding.expected_content_blake3 != expectation.expected_content_blake3 {
        Some("expected_content_blake3")
    } else if binding.receiver_signature_suite != expectation.receiver_signature_suite {
        Some("receiver_signature_suite")
    } else if binding.receiver_key_id != expectation.receiver_key_id {
        Some("receiver_key_id")
    } else {
        None
    };
    if let Some(field) = mismatched {
        return Err(SifDeliveryReceiptError::ExpectationMismatch { field });
    }
    Ok(())
}

fn require_nonzero(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), SifDeliveryReceiptError> {
    if *digest == [0u8; 32] {
        Err(SifDeliveryReceiptError::ZeroCommitment { field })
    } else {
        Ok(())
    }
}

/// Fail-closed delivery-receipt construction and verification errors.
#[derive(Debug, Error)]
pub enum SifDeliveryReceiptError {
    /// Nested authenticated transcript binding failed validation.
    #[error(transparent)]
    TranscriptBinding(#[from] TranscriptBindingError),
    /// Signature envelope shape or suite label was invalid.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Receiver signature verification failed.
    #[error(transparent)]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
    /// Receipt schema is unsupported.
    #[error("unsupported SIF delivery receipt schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the receipt.
        schema: String,
    },
    /// Receipt commitment algorithm is unsupported.
    #[error("unsupported SIF delivery receipt commitment algorithm: {algorithm}")]
    UnsupportedCommitmentAlgorithm {
        /// Algorithm label found in the receipt.
        algorithm: String,
    },
    /// Release ID must be non-nil.
    #[error("SIF delivery receipt release_id must not be nil")]
    NilReleaseId,
    /// Session ID in an expectation must be non-nil.
    #[error("SIF delivery receipt expected session_id must not be nil")]
    NilSessionId,
    /// Transfer ID zero is reserved and rejected.
    #[error("SIF delivery receipt transfer_id must be non-zero")]
    ZeroTransferId,
    /// Required digest/key identifier was an all-zero placeholder.
    #[error("SIF delivery receipt commitment {field} must not be all-zero")]
    ZeroCommitment {
        /// Field that contained the zero placeholder.
        field: &'static str,
    },
    /// Portable observation time cannot be the Unix epoch placeholder.
    #[error("SIF delivery receipt observation time must be non-zero")]
    ZeroObservationTime,
    /// Receiver reported more file-content bytes than the protected offer declared.
    #[error("SIF delivery receipt received {received} bytes beyond expected {expected}")]
    ReceivedBeyondExpected {
        /// Declared file size.
        expected: u64,
        /// Receiver-reported content bytes.
        received: u64,
    },
    /// Delivery disposition and byte/hash observations contradict one another.
    #[error("invalid SIF delivery receipt disposition: {0}")]
    DispositionInvariant(&'static str),
    /// Externally supplied receiver public key length does not match its suite.
    #[error("bad SIF delivery receiver public-key length: expected {expected}, found {found}")]
    BadReceiverPublicKeyLength {
        /// Fixed-size public-key length expected by the signature suite.
        expected: usize,
        /// Supplied key length.
        found: usize,
    },
    /// Signature suite in the envelope disagreed with the signed binding.
    #[error("SIF delivery receipt signature suite disagrees with signed binding")]
    SignatureSuiteBindingMismatch {
        /// Suite committed inside the signed binding.
        binding_suite: SignatureSuite,
        /// Suite declared by the signature envelope.
        signature_suite: SignatureSuite,
    },
    /// Selected verification backend disagreed with the receipt signature suite.
    #[error("SIF delivery receipt verifier backend disagrees with signature suite")]
    SignatureSuiteBackendMismatch {
        /// Suite implemented by the verification backend.
        backend_suite: SignatureSuite,
        /// Suite declared by the signature envelope.
        signature_suite: SignatureSuite,
    },
    /// Ed25519 signing helper was given a binding for another signature suite.
    #[error("SIF delivery receipt signing key suite does not match binding")]
    SigningKeySuiteMismatch,
    /// Trusted receiver key does not match the key identity signed into the receipt.
    #[error("SIF delivery receipt receiver key identity mismatch")]
    ReceiverKeyIdMismatch,
    /// Receipt disagreed with trusted sender-side expectation.
    #[error("SIF delivery receipt does not match expected {field}")]
    ExpectationMismatch {
        /// Field that differed from trusted expected state.
        field: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CURRENT_EVIDENCE_CRYPTO_MANIFEST, Ed25519EvidenceSignatureBackend};

    fn fixture(
        disposition: SifDeliveryDisposition,
        received_bytes: u64,
        observed_content_blake3: Option<[u8; 32]>,
    ) -> (SigningKey, SifDeliveryReceiptBinding, SifDeliveryReceiptExpectation) {
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let receiver_public_key = signing_key.verifying_key().to_bytes();
        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(10),
            [0x11; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let binding = SifDeliveryReceiptBinding::new(
            Uuid::from_u128(20),
            7,
            session,
            [0x22; 32],
            [0x33; 32],
            5,
            [0x55; 32],
            SignatureSuite::Ed25519Rfc8032,
            &receiver_public_key,
            disposition,
            received_bytes,
            observed_content_blake3,
            1_780_000_000_000,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let expectation = SifDeliveryReceiptExpectation {
            release_id: binding.release_id(),
            transfer_id: binding.transfer_id(),
            session_id: binding.session().session_id,
            transcript_hash: binding.session().transcript_hash,
            sender_release_entry_hash: binding.sender_release_entry_hash(),
            result_digest: binding.result_digest(),
            expected_size: binding.expected_size(),
            expected_content_blake3: binding.expected_content_blake3(),
            receiver_signature_suite: binding.receiver_signature_suite(),
            receiver_key_id: binding.receiver_key_id(),
        };
        (signing_key, binding, expectation)
    }

    #[test]
    fn persisted_verified_receipt_roundtrips_under_external_receiver_key() {
        let (signing_key, binding, expectation) = fixture(
            SifDeliveryDisposition::PersistedVerified,
            5,
            Some([0x55; 32]),
        );
        let receipt = sign_sif_delivery_receipt_ed25519(
            binding,
            &signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        receipt
            .verify_for_expectation(
                &expectation,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &signing_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert_ne!(sif_delivery_receipt_digest(&receipt), [0u8; 32]);
    }

    #[test]
    fn wrong_receiver_key_fails_even_when_receipt_signature_shape_is_valid() {
        let (signing_key, binding, expectation) = fixture(
            SifDeliveryDisposition::PersistedVerified,
            5,
            Some([0x55; 32]),
        );
        let receipt = sign_sif_delivery_receipt_ed25519(
            binding,
            &signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let wrong_key = SigningKey::from_bytes(&[0x45; 32]);
        assert!(matches!(
            receipt.verify_for_expectation(
                &expectation,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &wrong_key.verifying_key().to_bytes(),
            ),
            Err(SifDeliveryReceiptError::ReceiverKeyIdMismatch)
        ));
    }

    #[test]
    fn sender_expectation_prevents_release_or_result_substitution() {
        let (signing_key, binding, mut expectation) = fixture(
            SifDeliveryDisposition::PersistedVerified,
            5,
            Some([0x55; 32]),
        );
        let receipt = sign_sif_delivery_receipt_ed25519(
            binding,
            &signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();

        expectation.release_id = Uuid::from_u128(21);
        assert!(matches!(
            receipt.verify_for_expectation(
                &expectation,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &signing_key.verifying_key().to_bytes(),
            ),
            Err(SifDeliveryReceiptError::ExpectationMismatch {
                field: "release_id"
            })
        ));
    }

    #[test]
    fn delivery_dispositions_are_semantically_fail_closed() {
        let signing_key = SigningKey::from_bytes(&[0x66; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let session = SessionTranscriptBinding::from_hash(
            Uuid::from_u128(30),
            [0x77; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let make = |disposition, received_bytes, observed_content_blake3| {
            SifDeliveryReceiptBinding::new(
                Uuid::from_u128(31),
                9,
                session.clone(),
                [0x88; 32],
                [0x99; 32],
                10,
                [0xAA; 32],
                SignatureSuite::Ed25519Rfc8032,
                &public_key,
                disposition,
                received_bytes,
                observed_content_blake3,
                1_780_000_000_001,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
        };

        assert!(make(
            SifDeliveryDisposition::PersistedVerified,
            9,
            Some([0xAA; 32])
        )
        .is_err());
        assert!(make(
            SifDeliveryDisposition::PersistedVerified,
            10,
            Some([0xAB; 32])
        )
        .is_err());
        assert!(make(
            SifDeliveryDisposition::IntegrityMismatch,
            10,
            Some([0xAA; 32])
        )
        .is_err());
        assert!(make(
            SifDeliveryDisposition::Incomplete,
            9,
            Some([0xAB; 32])
        )
        .is_err());
        assert!(make(
            SifDeliveryDisposition::PersistenceFailed,
            10,
            Some([0xAA; 32])
        )
        .is_ok());
    }

    #[test]
    fn signed_message_binds_disposition_and_observation() {
        let (_, binding, _) = fixture(
            SifDeliveryDisposition::PersistedVerified,
            5,
            Some([0x55; 32]),
        );
        let base = sif_delivery_receipt_message(&binding);

        let (_, changed, _) = fixture(
            SifDeliveryDisposition::PersistenceFailed,
            5,
            Some([0x55; 32]),
        );
        assert_ne!(base, sif_delivery_receipt_message(&changed));
    }
}
