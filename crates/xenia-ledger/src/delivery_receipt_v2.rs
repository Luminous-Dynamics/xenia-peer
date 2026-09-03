// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Profile-bound receiver custody evidence for SIF protected releases.
//!
//! Delivery-receipt v1 proves the exact release/session/file custody statement but
//! predates authenticated SIF exact-profile negotiation. V2 is additive: it embeds the
//! already-validated v1 binding and additionally signs the exact negotiated SIF profile
//! digest. Historical v1 evidence remains representable; deployments requiring proof of
//! the protocol/security contract can require v2.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::delivery_receipt::{
    SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM, SifDeliveryReceiptBinding,
    SifDeliveryReceiptError, SifDeliveryReceiptExpectation, sif_delivery_receipt_message,
    sif_delivery_receiver_key_id,
};
use crate::policy::EvidenceCryptoManifest;
use crate::signature::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema for profile-bound SIF receiver custody evidence.
pub const SIF_DELIVERY_RECEIPT_V2_SCHEMA: &str = "xenia-sif-delivery-receipt-v2";
/// Commitment algorithm used by the v2 receipt profile.
pub const SIF_DELIVERY_RECEIPT_V2_COMMITMENT_ALGORITHM: &str = "blake3-256";

const DELIVERY_RECEIPT_V2_MESSAGE_DOMAIN: &[u8] = b"xenia:sif-delivery-receipt:message:v2";
const DELIVERY_RECEIPT_V2_DIGEST_DOMAIN: &[u8] = b"xenia:sif-delivery-receipt:digest:v2";

/// Canonical profile-bound receiver statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifDeliveryReceiptBindingV2 {
    schema: String,
    commitment_algorithm: String,
    base: SifDeliveryReceiptBinding,
    sif_profile_digest: [u8; 32],
}

impl SifDeliveryReceiptBindingV2 {
    /// Upgrade one canonical v1 custody statement into a profile-bound v2 statement.
    ///
    /// The exact v1 semantics are revalidated under `manifest`; v2 adds only the
    /// non-zero authenticated SIF profile digest and a new signing domain.
    pub fn new(
        base: SifDeliveryReceiptBinding,
        sif_profile_digest: [u8; 32],
        manifest: EvidenceCryptoManifest,
    ) -> Result<Self, SifDeliveryReceiptV2Error> {
        base.validate_against_manifest(manifest)?;
        require_nonzero_profile(&sif_profile_digest)?;
        Ok(Self {
            schema: SIF_DELIVERY_RECEIPT_V2_SCHEMA.to_string(),
            commitment_algorithm: SIF_DELIVERY_RECEIPT_V2_COMMITMENT_ALGORITHM.to_string(),
            base,
            sif_profile_digest,
        })
    }

    /// Underlying exact v1 custody statement retained by v2.
    pub fn base(&self) -> &SifDeliveryReceiptBinding {
        &self.base
    }

    /// Exact authenticated SIF profile under which this custody event occurred.
    pub const fn sif_profile_digest(&self) -> [u8; 32] {
        self.sif_profile_digest
    }

    /// Receiver signature suite inherited from the validated base statement.
    pub const fn receiver_signature_suite(&self) -> SignatureSuite {
        self.base.receiver_signature_suite()
    }

    /// Validate v2 schema/profile and all inherited v1 custody invariants.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), SifDeliveryReceiptV2Error> {
        if self.schema != SIF_DELIVERY_RECEIPT_V2_SCHEMA {
            return Err(SifDeliveryReceiptV2Error::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.commitment_algorithm != SIF_DELIVERY_RECEIPT_V2_COMMITMENT_ALGORITHM {
            return Err(SifDeliveryReceiptV2Error::UnsupportedCommitmentAlgorithm {
                algorithm: self.commitment_algorithm.clone(),
            });
        }
        require_nonzero_profile(&self.sif_profile_digest)?;
        self.base.validate_against_manifest(manifest)?;
        Ok(())
    }
}

/// Portable signed profile-bound SIF delivery receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifDeliveryReceiptV2 {
    binding: SifDeliveryReceiptBindingV2,
    signature: SignatureEnvelope,
}

impl SifDeliveryReceiptV2 {
    /// Canonical profile-bound receiver statement.
    pub fn binding(&self) -> &SifDeliveryReceiptBindingV2 {
        &self.binding
    }

    /// Algorithm-tagged receiver signature over the v2 statement.
    pub fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }

    /// Verify this receipt against sender-owned release/session/profile expectation and
    /// an externally trusted receiver key.
    pub fn verify_for_expectation(
        &self,
        expectation: &SifDeliveryReceiptExpectationV2,
        manifest: EvidenceCryptoManifest,
        backend: &impl EvidenceSignatureBackend,
        trusted_receiver_public_key: &[u8],
    ) -> Result<(), SifDeliveryReceiptV2Error> {
        self.binding.validate_against_manifest(manifest)?;
        expectation.validate()?;
        require_base_expectation_match(self.binding.base(), &expectation.base)?;
        if self.binding.sif_profile_digest != expectation.sif_profile_digest {
            return Err(SifDeliveryReceiptV2Error::ProfileDigestMismatch);
        }

        let suite = self.signature.validate_shape()?;
        if suite != self.binding.receiver_signature_suite() {
            return Err(SifDeliveryReceiptV2Error::SignatureSuiteBindingMismatch {
                binding_suite: self.binding.receiver_signature_suite(),
                signature_suite: suite,
            });
        }
        if suite != backend.suite() {
            return Err(SifDeliveryReceiptV2Error::SignatureSuiteBackendMismatch {
                backend_suite: backend.suite(),
                signature_suite: suite,
            });
        }
        if let Some(expected) = suite.fixed_public_key_len()
            && trusted_receiver_public_key.len() != expected
        {
            return Err(SifDeliveryReceiptV2Error::BadReceiverPublicKeyLength {
                expected,
                found: trusted_receiver_public_key.len(),
            });
        }
        let receiver_key_id = sif_delivery_receiver_key_id(suite, trusted_receiver_public_key);
        if receiver_key_id != self.binding.base().receiver_key_id()
            || receiver_key_id != expectation.base.receiver_key_id
        {
            return Err(SifDeliveryReceiptV2Error::ReceiverKeyIdMismatch);
        }
        backend.verify_signature(
            trusted_receiver_public_key,
            &sif_delivery_receipt_v2_message(&self.binding),
            &self.signature.signature,
        )?;
        Ok(())
    }
}

/// Sender-owned expectation for one profile-bound custody receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SifDeliveryReceiptExpectationV2 {
    /// Exact inherited v1 release/session/file/receiver expectation.
    pub base: SifDeliveryReceiptExpectation,
    /// Exact authenticated SIF security profile required for this release.
    pub sif_profile_digest: [u8; 32],
}

impl SifDeliveryReceiptExpectationV2 {
    /// Validate inherited v1 expectation and non-zero profile identity.
    pub fn validate(&self) -> Result<(), SifDeliveryReceiptV2Error> {
        self.base.validate()?;
        require_nonzero_profile(&self.sif_profile_digest)?;
        Ok(())
    }
}

/// Canonical bytes signed by a v2 receiver.
///
/// The complete v1 canonical message is length-prefixed and embedded rather than
/// re-specifying every field a second time. The v2 domain/schema/profile then make this
/// a distinct statement that a v1 signature cannot satisfy.
pub fn sif_delivery_receipt_v2_message(binding: &SifDeliveryReceiptBindingV2) -> Vec<u8> {
    let base = sif_delivery_receipt_message(binding.base());
    let mut out = Vec::with_capacity(
        DELIVERY_RECEIPT_V2_MESSAGE_DOMAIN.len()
            + SIF_DELIVERY_RECEIPT_V2_SCHEMA.len()
            + SIF_DELIVERY_RECEIPT_V2_COMMITMENT_ALGORITHM.len()
            + base.len()
            + 96,
    );
    out.extend_from_slice(DELIVERY_RECEIPT_V2_MESSAGE_DOMAIN);
    push_len_prefixed(&mut out, SIF_DELIVERY_RECEIPT_V2_SCHEMA.as_bytes());
    push_len_prefixed(
        &mut out,
        SIF_DELIVERY_RECEIPT_V2_COMMITMENT_ALGORITHM.as_bytes(),
    );
    push_len_prefixed(&mut out, &base);
    out.extend_from_slice(&binding.sif_profile_digest);
    out
}

/// BLAKE3-256 digest of the exact v2 receiver statement.
pub fn sif_delivery_receipt_v2_digest(binding: &SifDeliveryReceiptBindingV2) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DELIVERY_RECEIPT_V2_DIGEST_DOMAIN);
    hasher.update(&sif_delivery_receipt_v2_message(binding));
    *hasher.finalize().as_bytes()
}

/// Sign one profile-bound receipt under Ed25519.
pub fn sign_sif_delivery_receipt_v2_ed25519(
    binding: SifDeliveryReceiptBindingV2,
    signing_key: &SigningKey,
    manifest: EvidenceCryptoManifest,
) -> Result<SifDeliveryReceiptV2, SifDeliveryReceiptV2Error> {
    binding.validate_against_manifest(manifest)?;
    if binding.receiver_signature_suite() != SignatureSuite::Ed25519Rfc8032 {
        return Err(SifDeliveryReceiptV2Error::SignatureSuiteBindingMismatch {
            binding_suite: binding.receiver_signature_suite(),
            signature_suite: SignatureSuite::Ed25519Rfc8032,
        });
    }
    let expected_key_id = sif_delivery_receiver_key_id(
        SignatureSuite::Ed25519Rfc8032,
        &signing_key.verifying_key().to_bytes(),
    );
    if expected_key_id != binding.base().receiver_key_id() {
        return Err(SifDeliveryReceiptV2Error::ReceiverKeyIdMismatch);
    }
    let signature = signing_key.sign(&sif_delivery_receipt_v2_message(&binding));
    Ok(SifDeliveryReceiptV2 {
        binding,
        signature: SignatureEnvelope::ed25519(signature.to_bytes()),
    })
}

fn require_nonzero_profile(profile: &[u8; 32]) -> Result<(), SifDeliveryReceiptV2Error> {
    if profile.iter().all(|byte| *byte == 0) {
        return Err(SifDeliveryReceiptV2Error::ZeroProfileDigest);
    }
    Ok(())
}

fn require_base_expectation_match(
    binding: &SifDeliveryReceiptBinding,
    expectation: &SifDeliveryReceiptExpectation,
) -> Result<(), SifDeliveryReceiptV2Error> {
    let mismatch = if binding.release_id() != expectation.release_id {
        Some("release_id")
    } else if binding.transfer_id() != expectation.transfer_id {
        Some("transfer_id")
    } else if binding.session().session_id != expectation.session_id {
        Some("session_id")
    } else if binding.session().transcript_hash != expectation.transcript_hash {
        Some("transcript_hash")
    } else if binding.sender_release_entry_hash() != expectation.sender_release_entry_hash {
        Some("sender_release_entry_hash")
    } else if binding.result_digest() != expectation.result_digest {
        Some("result_digest")
    } else if binding.expected_size() != expectation.expected_size {
        Some("expected_size")
    } else if binding.expected_content_blake3() != expectation.expected_content_blake3 {
        Some("expected_content_blake3")
    } else if binding.receiver_signature_suite() != expectation.receiver_signature_suite {
        Some("receiver_signature_suite")
    } else if binding.receiver_key_id() != expectation.receiver_key_id {
        Some("receiver_key_id")
    } else {
        None
    };
    if let Some(field) = mismatch {
        return Err(SifDeliveryReceiptV2Error::BaseExpectationMismatch { field });
    }
    Ok(())
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Fail-closed profile-bound receipt errors.
#[derive(Debug, Error)]
pub enum SifDeliveryReceiptV2Error {
    /// Inherited v1 statement/expectation was invalid.
    #[error(transparent)]
    Base(#[from] SifDeliveryReceiptError),
    /// Signature envelope shape/suite label was invalid.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Cryptographic signature verification failed.
    #[error(transparent)]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
    /// V2 schema label was unsupported.
    #[error("unsupported SIF delivery receipt v2 schema {schema}")]
    UnsupportedSchema {
        /// Authenticated/deserialized schema label.
        schema: String,
    },
    /// V2 commitment algorithm label was unsupported.
    #[error("unsupported SIF delivery receipt v2 commitment algorithm {algorithm}")]
    UnsupportedCommitmentAlgorithm {
        /// Authenticated/deserialized algorithm label.
        algorithm: String,
    },
    /// Exact SIF profile digest must not be all-zero.
    #[error("SIF delivery receipt v2 profile digest must not be zero")]
    ZeroProfileDigest,
    /// Sender expectation and receiver binding named different SIF profiles.
    #[error("SIF delivery receipt v2 profile digest mismatch")]
    ProfileDigestMismatch,
    /// One inherited sender-owned field differed.
    #[error("SIF delivery receipt v2 base expectation mismatch at {field}")]
    BaseExpectationMismatch {
        /// Field that differed.
        field: &'static str,
    },
    /// Signature suite did not match the bound receiver suite.
    #[error("SIF delivery receipt v2 signature suite does not match binding")]
    SignatureSuiteBindingMismatch {
        /// Suite committed by the binding.
        binding_suite: SignatureSuite,
        /// Suite carried/attempted by the signature.
        signature_suite: SignatureSuite,
    },
    /// Signature suite did not match selected verification backend.
    #[error("SIF delivery receipt v2 signature suite does not match backend")]
    SignatureSuiteBackendMismatch {
        /// Selected backend suite.
        backend_suite: SignatureSuite,
        /// Signature suite carried by the receipt.
        signature_suite: SignatureSuite,
    },
    /// Trusted receiver public key length was invalid for the suite.
    #[error("bad receiver public key length: expected {expected}, found {found}")]
    BadReceiverPublicKeyLength {
        /// Expected fixed key length.
        expected: usize,
        /// Supplied key length.
        found: usize,
    },
    /// Trusted receiver key did not reproduce the signed receiver key ID.
    #[error("SIF delivery receipt v2 receiver key ID mismatch")]
    ReceiverKeyIdMismatch,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    use crate::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, Ed25519EvidenceSignatureBackend,
        SessionTranscriptBinding, SifDeliveryDisposition, SifDeliveryReceiptExpectation,
        SifDeliveryReceiptBinding, SignatureSuite, sif_delivery_receiver_key_id,
        sif_file_result_digest, sign_sif_delivery_receipt_ed25519,
    };

    use super::*;

    const PROFILE_A: [u8; 32] = [0xA1; 32];
    const PROFILE_B: [u8; 32] = [0xB2; 32];

    fn base_binding(signing_key: &SigningKey) -> SifDeliveryReceiptBinding {
        SifDeliveryReceiptBinding::new(
            Uuid::from_u128(1),
            7,
            SessionTranscriptBinding::from_hash(
                Uuid::from_u128(2),
                [0x22; 32],
                CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
            ),
            [0x33; 32],
            "evidence.bin",
            5,
            [0x44; 32],
            SignatureSuite::Ed25519Rfc8032,
            &signing_key.verifying_key().to_bytes(),
            SifDeliveryDisposition::PersistedVerified,
            5,
            Some([0x44; 32]),
            1_780_000_000_900,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap()
    }

    fn expectation(signing_key: &SigningKey, profile: [u8; 32]) -> SifDeliveryReceiptExpectationV2 {
        let result = sif_file_result_digest("evidence.bin", 5, [0x44; 32]).unwrap();
        SifDeliveryReceiptExpectationV2 {
            base: SifDeliveryReceiptExpectation {
                release_id: Uuid::from_u128(1),
                transfer_id: 7,
                session_id: Uuid::from_u128(2),
                transcript_hash: [0x22; 32],
                sender_release_entry_hash: [0x33; 32],
                result_digest: result,
                expected_size: 5,
                expected_content_blake3: [0x44; 32],
                receiver_signature_suite: SignatureSuite::Ed25519Rfc8032,
                receiver_key_id: sif_delivery_receiver_key_id(
                    SignatureSuite::Ed25519Rfc8032,
                    &signing_key.verifying_key().to_bytes(),
                ),
            },
            sif_profile_digest: profile,
        }
    }

    #[test]
    fn v2_roundtrip_verifies_exact_profile() {
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let binding = SifDeliveryReceiptBindingV2::new(
            base_binding(&signing_key),
            PROFILE_A,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let receipt = sign_sif_delivery_receipt_v2_ed25519(
            binding,
            &signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        assert_eq!(receipt.binding().sif_profile_digest(), PROFILE_A);
        receipt
            .verify_for_expectation(
                &expectation(&signing_key, PROFILE_A),
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &signing_key.verifying_key().to_bytes(),
            )
            .unwrap();
    }

    #[test]
    fn exact_same_custody_statement_under_other_profile_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let binding = SifDeliveryReceiptBindingV2::new(
            base_binding(&signing_key),
            PROFILE_A,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let receipt = sign_sif_delivery_receipt_v2_ed25519(
            binding,
            &signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        assert!(matches!(
            receipt.verify_for_expectation(
                &expectation(&signing_key, PROFILE_B),
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &signing_key.verifying_key().to_bytes(),
            ),
            Err(SifDeliveryReceiptV2Error::ProfileDigestMismatch)
        ));
    }

    #[test]
    fn v1_signature_cannot_be_reused_as_v2_signature() {
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let base = base_binding(&signing_key);
        let v1 = sign_sif_delivery_receipt_ed25519(
            base.clone(),
            &signing_key,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let binding = SifDeliveryReceiptBindingV2::new(
            base,
            PROFILE_A,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let forged = SifDeliveryReceiptV2 {
            binding,
            signature: v1.signature().clone(),
        };
        assert!(forged
            .verify_for_expectation(
                &expectation(&signing_key, PROFILE_A),
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                &signing_key.verifying_key().to_bytes(),
            )
            .is_err());
    }

    #[test]
    fn v2_digest_changes_when_profile_changes() {
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let a = SifDeliveryReceiptBindingV2::new(
            base_binding(&signing_key),
            PROFILE_A,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        let b = SifDeliveryReceiptBindingV2::new(
            base_binding(&signing_key),
            PROFILE_B,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )
        .unwrap();
        assert_ne!(sif_delivery_receipt_v2_digest(&a), sif_delivery_receipt_v2_digest(&b));
    }
}
