// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    MlDsa65, MlDsa87, MlDsaParams, Signature as MlDsaSignature, Verifier as MlDsaVerifier,
    VerifyingKey as MlDsaVerifyingKey,
};

/// Stable signature-suite labels used in evidence exports and verifier output.
///
/// These labels are used by evidence manifests and signature envelopes. The
/// current `LedgerEntry` storage path remains Ed25519-only for M1 compatibility,
/// but exported evidence should use [`SignatureEnvelope`] so PQ signatures can be
/// introduced without another export-schema break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureSuite {
    /// Ed25519 / RFC 8032. Classical signature suite; not quantum-resistant for signatures.
    #[serde(rename = "ed25519-rfc8032")]
    Ed25519Rfc8032,
    /// ML-DSA-65 / NIST FIPS 204. Planned online PQ signature baseline.
    #[serde(rename = "ml-dsa-65-fips204")]
    MlDsa65Fips204,
    /// ML-DSA-87 / NIST FIPS 204. Planned high-sensitivity PQ signature option.
    #[serde(rename = "ml-dsa-87-fips204")]
    MlDsa87Fips204,
    /// SLH-DSA / NIST FIPS 205. Planned conservative/offline PQ signature option.
    #[serde(rename = "slh-dsa-fips205")]
    SlhDsaFips205,
}

impl SignatureSuite {
    /// Stable machine-readable label for evidence manifests.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Ed25519Rfc8032 => "ed25519-rfc8032",
            Self::MlDsa65Fips204 => "ml-dsa-65-fips204",
            Self::MlDsa87Fips204 => "ml-dsa-87-fips204",
            Self::SlhDsaFips205 => "slh-dsa-fips205",
        }
    }

    /// Whether this suite is post-quantum for signature/authentication use.
    pub const fn is_post_quantum(self) -> bool {
        !matches!(self, Self::Ed25519Rfc8032)
    }

    /// Parse a stable machine-readable label back into a signature suite.
    pub fn from_stable_label(label: &str) -> Option<Self> {
        match label {
            "ed25519-rfc8032" => Some(Self::Ed25519Rfc8032),
            "ml-dsa-65-fips204" => Some(Self::MlDsa65Fips204),
            "ml-dsa-87-fips204" => Some(Self::MlDsa87Fips204),
            "slh-dsa-fips205" => Some(Self::SlhDsaFips205),
            _ => None,
        }
    }

    /// Signature byte length when this suite has a fixed-size signature in the
    /// current evidence profile.
    pub const fn fixed_signature_len(self) -> Option<usize> {
        match self {
            Self::Ed25519Rfc8032 => Some(64),
            Self::MlDsa65Fips204 => Some(3309),
            Self::MlDsa87Fips204 => Some(4627),
            // FIPS 205 exposes multiple SLH-DSA parameter sets. Xenia's label is
            // intentionally family-level until a concrete parameter set is chosen.
            Self::SlhDsaFips205 => None,
        }
    }

    /// Public-key byte length when this suite has a fixed-size verifying key in
    /// the current evidence profile.
    pub const fn fixed_public_key_len(self) -> Option<usize> {
        match self {
            Self::Ed25519Rfc8032 => Some(32),
            Self::MlDsa65Fips204 => Some(1952),
            Self::MlDsa87Fips204 => Some(2592),
            // FIPS 205 exposes multiple SLH-DSA parameter sets. Xenia's label is
            // intentionally family-level until a concrete parameter set is chosen.
            Self::SlhDsaFips205 => None,
        }
    }
}

/// Algorithm-tagged signature bytes for exported evidence.
///
/// This is the schema bridge from the current fixed-size Ed25519 ledger entry to
/// future ML-DSA/SLH-DSA evidence. The current verifier only accepts Ed25519
/// envelopes, but the exported shape can already carry PQ signature bytes with a
/// stable algorithm label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    /// Stable signature-suite label such as `ed25519-rfc8032` or `ml-dsa-65-fips204`.
    pub algorithm: String,
    /// Raw signature bytes for `algorithm`.
    pub signature: Vec<u8>,
}

impl SignatureEnvelope {
    /// Construct a signature envelope from a typed suite and raw signature bytes.
    pub fn new(suite: SignatureSuite, signature: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm: suite.stable_label().to_string(),
            signature: signature.into(),
        }
    }

    /// Construct an Ed25519 envelope from the fixed-size legacy ledger signature.
    pub fn ed25519(signature: [u8; 64]) -> Self {
        Self::new(SignatureSuite::Ed25519Rfc8032, signature)
    }

    /// Parse the envelope's algorithm label into a typed suite.
    pub fn suite(&self) -> Result<SignatureSuite, SignatureEnvelopeError> {
        SignatureSuite::from_stable_label(&self.algorithm).ok_or_else(|| {
            SignatureEnvelopeError::UnknownSignatureSuite {
                algorithm: self.algorithm.clone(),
            }
        })
    }

    /// Validate the envelope's algorithm label and any known fixed signature length.
    pub fn validate_shape(&self) -> Result<SignatureSuite, SignatureEnvelopeError> {
        let suite = self.suite()?;
        if let Some(expected) = suite.fixed_signature_len() {
            let found = self.signature.len();
            if found != expected {
                return Err(SignatureEnvelopeError::BadSignatureLength {
                    algorithm: self.algorithm.clone(),
                    expected,
                    found,
                });
            }
        }
        Ok(suite)
    }

    /// Whether the envelope declares a post-quantum signature suite.
    pub fn is_post_quantum(&self) -> Result<bool, SignatureEnvelopeError> {
        Ok(self.suite()?.is_post_quantum())
    }

    /// Convert the envelope into the fixed-size Ed25519 signature used by the
    /// current legacy ledger entry shape.
    pub fn to_legacy_ed25519(&self) -> Result<[u8; 64], SignatureEnvelopeError> {
        let suite = self.validate_shape()?;
        if suite != SignatureSuite::Ed25519Rfc8032 {
            return Err(SignatureEnvelopeError::UnsupportedLegacySuite {
                algorithm: self.algorithm.clone(),
            });
        }

        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&self.signature);
        Ok(bytes)
    }
}

/// Verification backend boundary for algorithm-tagged evidence signatures.
///
/// This trait is the implementation bridge from today's Ed25519 verifier to
/// future ML-DSA/SLH-DSA backends. It is intentionally byte-oriented so PQ
/// public keys and signatures can be carried without another evidence-schema
/// break.
pub trait EvidenceSignatureBackend {
    /// Signature suite handled by this backend.
    fn suite(&self) -> SignatureSuite;

    /// Verify `signature` over `message` under `public_key`.
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EvidenceSignatureBackendError>;
}

/// Ed25519 evidence-signature backend used by the current hybrid/pre-PQC profile.
pub struct Ed25519EvidenceSignatureBackend;

impl EvidenceSignatureBackend for Ed25519EvidenceSignatureBackend {
    fn suite(&self) -> SignatureSuite {
        SignatureSuite::Ed25519Rfc8032
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EvidenceSignatureBackendError> {
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
            EvidenceSignatureBackendError::BadPublicKeyLength {
                expected: 32,
                found: public_key.len(),
            }
        })?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| {
            EvidenceSignatureBackendError::BadSignatureLength {
                expected: 64,
                found: signature.len(),
            }
        })?;

        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| EvidenceSignatureBackendError::BadPublicKey)?;
        let signature = Signature::from_bytes(&signature);
        verifying_key
            .verify(message, &signature)
            .map_err(|_| EvidenceSignatureBackendError::BadSignature)
    }
}

/// Errors returned by evidence-signature backends.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceSignatureBackendError {
    /// The public key had the wrong byte length for the backend.
    #[error("bad public-key length: expected {expected}, found {found}")]
    BadPublicKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        found: usize,
    },
    /// The signature had the wrong byte length for the backend.
    #[error("bad signature length: expected {expected}, found {found}")]
    BadSignatureLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        found: usize,
    },
    /// The public key bytes could not be parsed by the backend.
    #[error("bad public key")]
    BadPublicKey,
    /// Signature bytes had the right length but could not be decoded by the backend.
    #[error("bad signature encoding")]
    BadSignatureEncoding,
    /// Signature verification failed.
    #[error("bad signature")]
    BadSignature,
    /// The selected signature suite has no fixed-length backend parameters.
    #[error("signature suite {suite:?} is not supported by this fixed-length backend")]
    UnsupportedSuite {
        /// Suite that cannot be handled by this backend.
        suite: SignatureSuite,
    },
}

/// ML-DSA-65 evidence-signature backend enabled by the `pqc-signatures` feature.
///
/// This is real FIPS-204 ML-DSA verification via the RustCrypto `ml-dsa` crate,
/// but production enablement still requires dependency review, vector pinning,
/// and release-policy approval.
#[cfg(feature = "pqc-signatures")]
pub struct MlDsa65EvidenceSignatureBackend;

#[cfg(feature = "pqc-signatures")]
impl EvidenceSignatureBackend for MlDsa65EvidenceSignatureBackend {
    fn suite(&self) -> SignatureSuite {
        SignatureSuite::MlDsa65Fips204
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EvidenceSignatureBackendError> {
        verify_ml_dsa::<MlDsa65>(self.suite(), public_key, message, signature)
    }
}

/// ML-DSA-87 evidence-signature backend enabled by the `pqc-signatures` feature.
///
/// This backend is intended for high-sensitivity profiles where the larger key
/// and signature sizes are acceptable.
#[cfg(feature = "pqc-signatures")]
pub struct MlDsa87EvidenceSignatureBackend;

#[cfg(feature = "pqc-signatures")]
impl EvidenceSignatureBackend for MlDsa87EvidenceSignatureBackend {
    fn suite(&self) -> SignatureSuite {
        SignatureSuite::MlDsa87Fips204
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EvidenceSignatureBackendError> {
        verify_ml_dsa::<MlDsa87>(self.suite(), public_key, message, signature)
    }
}

#[cfg(feature = "pqc-signatures")]
fn verify_ml_dsa<P: MlDsaParams>(
    suite: SignatureSuite,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), EvidenceSignatureBackendError> {
    let expected_public_key_len = suite
        .fixed_public_key_len()
        .ok_or(EvidenceSignatureBackendError::UnsupportedSuite { suite })?;
    let expected_signature_len = suite
        .fixed_signature_len()
        .ok_or(EvidenceSignatureBackendError::UnsupportedSuite { suite })?;

    if public_key.len() != expected_public_key_len {
        return Err(EvidenceSignatureBackendError::BadPublicKeyLength {
            expected: expected_public_key_len,
            found: public_key.len(),
        });
    }
    if signature.len() != expected_signature_len {
        return Err(EvidenceSignatureBackendError::BadSignatureLength {
            expected: expected_signature_len,
            found: signature.len(),
        });
    }

    let public_key = MlDsaEncodedVerifyingKey::<P>::try_from(public_key)
        .map_err(|_| EvidenceSignatureBackendError::BadPublicKey)?;
    let signature = MlDsaEncodedSignature::<P>::try_from(signature)
        .map_err(|_| EvidenceSignatureBackendError::BadSignatureEncoding)?;
    let verifying_key = MlDsaVerifyingKey::<P>::decode(&public_key);
    let signature = MlDsaSignature::<P>::decode(&signature)
        .ok_or(EvidenceSignatureBackendError::BadSignatureEncoding)?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| EvidenceSignatureBackendError::BadSignature)
}

/// PQ signature feature status.
///
/// Enabling `pqc-signatures` compiles the ML-DSA verifier backend. Runtime
/// acceptance remains gated by the selected evidence profile and verifier entry
/// point; legacy verifier entry points continue to reject PQ envelopes.
#[cfg(feature = "pqc-signatures")]
pub const PQC_SIGNATURE_BACKEND_STATUS: &str =
    "pqc-signatures feature enabled; ML-DSA evidence verification backend compiled";

/// Errors surfaced when parsing or adapting a signature envelope.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignatureEnvelopeError {
    /// The envelope used an unknown signature-suite label.
    #[error("unknown signature suite label: {algorithm}")]
    UnknownSignatureSuite {
        /// Algorithm label found in the envelope.
        algorithm: String,
    },
    /// The signature byte length did not match the fixed-size suite expectation.
    #[error("signature length for {algorithm} must be {expected} bytes, found {found}")]
    BadSignatureLength {
        /// Algorithm label found in the envelope.
        algorithm: String,
        /// Expected signature length in bytes.
        expected: usize,
        /// Actual signature length in bytes.
        found: usize,
    },
    /// The envelope is valid, but cannot be converted to the current Ed25519-only
    /// legacy ledger entry shape.
    #[error("signature suite {algorithm} cannot be converted to legacy Ed25519 entry")]
    UnsupportedLegacySuite {
        /// Algorithm label found in the envelope.
        algorithm: String,
    },
}

/// Current ledger signature suite used by [`crate::Chain::append`].
pub const CURRENT_LEDGER_SIGNATURE_SUITE: SignatureSuite = SignatureSuite::Ed25519Rfc8032;
