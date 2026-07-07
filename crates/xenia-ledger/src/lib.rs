// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// License exception: this crate is AGPL-3.0-or-later, unlike its sibling
// library crates in the xenia-peer workspace (xenia-peer-core, xenia-
// capture, xenia-handshake, xenia-inject) which ship under Apache-2.0 OR
// MIT per ADR-001 Decision 3. The exception is deliberate — xenia-ledger
// is the cryptographic moat of the Mycelix Sovereign commercial suite and
// is treated as application-layer rather than permissive-commons
// infrastructure. See README.md for the full rationale.

//! # xenia-ledger
//!
//! Append-only, hash-chained consent ledger with explicit signature-envelope agility.
//!
//! Every privileged session that flows through a Xenia peer produces a
//! sequence of [`ConsentEventRecord`]s (Request, Approval, Denial,
//! Revocation, Violation). Those records are appended to a
//! [`Chain`], which computes a blake3-based hash link to the previous
//! entry and signs the resulting `entry_hash` with the operator's
//! Ed25519 signing key. The current in-memory entry shape remains Ed25519-only,
//! but exported evidence can carry a tagged [`SignatureEnvelope`] so downstream
//! verifiers can distinguish today's hybrid/pre-PQC posture from future
//! ML-DSA/SLH-DSA ledger profiles without another schema break.
//! [`Verifier::verify_evidence_bundle`] then binds the declared manifest to
//! the exported chain so an artifact cannot claim a stronger ledger signature
//! suite than its entry envelopes actually use.
//! [`Verifier::verify_transcript_bound_evidence_bundle`] additionally binds
//! the ledger to a stable session-transcript hash so a valid consent chain
//! cannot be replayed beside the wrong handshake or session transcript.
//!
//! A downstream auditor — including a non-operator third party —
//! can use [`Verifier::verify_chain`] to reconstruct every hash link
//! and every signature offline, using only the operator's public key.
//! The operator cannot produce a chain with a rewritten past unless
//! they also re-sign every affected entry, which requires the
//! private key and is by construction visible to anyone holding the
//! public key.
//!
//! This is the "admin cannot rewrite the audit log" claim made in the
//! Mycelix Sovereign threat model, enforced cryptographically.
//!
//! ## Design choices
//!
//! - **blake3 for the hash chain.** Modern, tree-based, much faster than
//!   SHA-256 at large scales. The chain itself uses only the single-
//!   shot [`blake3::hash`] API for simplicity.
//! - **Ed25519 by default, ML-DSA behind an explicit feature.** The stable
//!   [`Chain`] remains Ed25519 for M1 compatibility. Builds with the
//!   `pqc-signatures` feature also expose ML-DSA-65/87 exported-evidence
//!   chain builders so full-PQC fixtures can be produced and verified without
//!   weakening the default hybrid/pre-PQC runtime claim.
//! - **bincode v1 for canonical serialization.** Deterministic across
//!   runs at a given bincode version. Version-locked via the workspace.
//!   If we migrate to bincode v2 or a different serializer, a schema-
//!   version field on each entry lets old ledgers verify against old
//!   code.
//! - **No persistence layer in this crate.** Callers decide whether to
//!   store the chain as JSON, CBOR, a SQLite table, or Holochain
//!   entries. `Chain::from_entries` lets any storage layer rehydrate.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

use std::time::SystemTime;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    Keypair as MlDsaKeypair, MlDsa65, MlDsa87, MlDsaParams, Signature as MlDsaSignature,
    Signer as MlDsaSigner, SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier,
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
        .expect("ML-DSA key length pinned");
    let expected_signature_len = suite
        .fixed_signature_len()
        .expect("ML-DSA signature length pinned");

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

/// Current ledger signature suite used by [`Chain::append`].
pub const CURRENT_LEDGER_SIGNATURE_SUITE: SignatureSuite = SignatureSuite::Ed25519Rfc8032;

/// Stable evidence-profile summary for this crate's current ledger format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LedgerEvidenceProfile {
    /// Schema label for this profile structure.
    pub schema: &'static str,
    /// Hash used for per-entry hash-chain links.
    pub hash_chain: &'static str,
    /// Serializer used by the hash preimage.
    pub serialization: &'static str,
    /// Stable description of the entry-hash preimage layout.
    pub entry_hash_preimage: &'static str,
    /// Signature suite used by current ledger entries.
    pub ledger_signature: SignatureSuite,
    /// Policy class represented by the current implementation.
    pub policy_profile: &'static str,
}

impl LedgerEvidenceProfile {
    /// Return true only when the ledger signature surface is post-quantum.
    pub const fn ledger_signature_is_post_quantum(self) -> bool {
        self.ledger_signature.is_post_quantum()
    }
}

/// Evidence-profile label for the current ledger implementation.
pub const CURRENT_LEDGER_EVIDENCE_PROFILE: LedgerEvidenceProfile = LedgerEvidenceProfile {
    schema: "xenia-ledger-evidence-profile-v1",
    hash_chain: "blake3-256",
    serialization: "bincode-1",
    entry_hash_preimage: "bincode-v1(seq,prev_hash,timestamp,event)",
    ledger_signature: CURRENT_LEDGER_SIGNATURE_SUITE,
    policy_profile: "hybrid-pre-pqc-v1",
};

/// Crypto policy class applied to an evidence manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoPolicyProfile {
    /// Current honest status: PQ key establishment with classical Ed25519 signatures.
    #[serde(rename = "hybrid-pre-pqc-v1")]
    HybridPrePqcV1,
    /// Target policy: PQ key establishment and PQ signatures on authority surfaces.
    #[serde(rename = "full-pqc-v1")]
    FullPqcV1,
}

impl CryptoPolicyProfile {
    /// Stable machine-readable label for evidence manifests.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::HybridPrePqcV1 => "hybrid-pre-pqc-v1",
            Self::FullPqcV1 => "full-pqc-v1",
        }
    }

    /// Whether this policy requires PQ signatures for transcript and ledger authority.
    pub const fn requires_post_quantum_signatures(self) -> bool {
        matches!(self, Self::FullPqcV1)
    }
}

/// Whether a manifest explicitly permits classical signature/authentication fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DowngradePolicy {
    /// Current compatibility mode: Ed25519 is allowed only because the manifest says so.
    #[serde(rename = "explicit-classical-signature-allowance")]
    ExplicitClassicalSignatureAllowance,
    /// Full-PQC mode: classical signature/authentication suites are rejected.
    #[serde(rename = "reject-classical-signatures")]
    RejectClassicalSignatures,
}

impl DowngradePolicy {
    /// Stable machine-readable label for evidence manifests.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::ExplicitClassicalSignatureAllowance => "explicit-classical-signature-allowance",
            Self::RejectClassicalSignatures => "reject-classical-signatures",
        }
    }
}

/// Machine-readable crypto manifest attached to exported Xenia evidence.
///
/// This is intentionally policy-oriented: it lets auditors reject a transcript
/// or ledger export before trusting individual entries when the artifact was
/// produced under a stronger policy than its algorithms satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EvidenceCryptoManifest {
    /// Schema label for this manifest shape.
    pub schema: &'static str,
    /// Policy class used to accept/reject algorithms.
    pub profile: CryptoPolicyProfile,
    /// Key-establishment suite.
    pub kem: &'static str,
    /// Signature suite authenticating the session transcript.
    pub transcript_signature: SignatureSuite,
    /// Signature suite used for consent-ledger entries.
    pub ledger_signature: SignatureSuite,
    /// Per-entry hash/link function.
    pub hash_chain: &'static str,
    /// Session-key derivation function.
    pub kdf: &'static str,
    /// Frame sealing primitive.
    pub aead: &'static str,
    /// Downgrade/fallback behavior allowed by this evidence policy.
    pub downgrade_policy: DowngradePolicy,
}

impl EvidenceCryptoManifest {
    /// Validate that the manifest algorithms satisfy the declared policy.
    pub const fn validate_against_policy(self) -> Result<(), EvidencePolicyError> {
        match self.profile {
            CryptoPolicyProfile::HybridPrePqcV1 => {
                if self.transcript_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::PqTranscriptSignatureInHybridPrePqc);
                }
                if self.ledger_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::PqLedgerSignatureInHybridPrePqc);
                }
                if !matches!(
                    self.downgrade_policy,
                    DowngradePolicy::ExplicitClassicalSignatureAllowance
                ) {
                    return Err(
                        EvidencePolicyError::HybridPrePqcRequiresExplicitClassicalAllowance,
                    );
                }
            }
            CryptoPolicyProfile::FullPqcV1 => {
                if !self.transcript_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::ClassicalTranscriptSignatureInFullPqc);
                }
                if !self.ledger_signature.is_post_quantum() {
                    return Err(EvidencePolicyError::ClassicalLedgerSignatureInFullPqc);
                }
                if !matches!(
                    self.downgrade_policy,
                    DowngradePolicy::RejectClassicalSignatures
                ) {
                    return Err(EvidencePolicyError::DowngradePolicyAllowsClassicalInFullPqc);
                }
            }
        }

        Ok(())
    }

    /// Whether both authority-bearing signature surfaces are post-quantum.
    pub const fn signatures_are_post_quantum(self) -> bool {
        self.transcript_signature.is_post_quantum() && self.ledger_signature.is_post_quantum()
    }
}

/// Evidence-policy validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidencePolicyError {
    /// A `hybrid-pre-pqc-v1` manifest declared a PQ transcript signature suite.
    #[error("hybrid-pre-pqc-v1 requires classical transcript signatures")]
    PqTranscriptSignatureInHybridPrePqc,
    /// A `hybrid-pre-pqc-v1` manifest declared a PQ ledger signature suite.
    #[error("hybrid-pre-pqc-v1 requires classical ledger signatures")]
    PqLedgerSignatureInHybridPrePqc,
    /// A `hybrid-pre-pqc-v1` manifest did not explicitly allow classical signatures.
    #[error("hybrid-pre-pqc-v1 requires explicit-classical-signature-allowance downgrade policy")]
    HybridPrePqcRequiresExplicitClassicalAllowance,
    /// A `full-pqc-v1` manifest declared a classical transcript signature suite.
    #[error("full-pqc-v1 rejects classical transcript signatures")]
    ClassicalTranscriptSignatureInFullPqc,
    /// A `full-pqc-v1` manifest declared a classical ledger signature suite.
    #[error("full-pqc-v1 rejects classical ledger signatures")]
    ClassicalLedgerSignatureInFullPqc,
    /// A `full-pqc-v1` manifest allowed classical-signature downgrade behavior.
    #[error("full-pqc-v1 requires reject-classical-signatures downgrade policy")]
    DowngradePolicyAllowsClassicalInFullPqc,
}

/// Current end-to-end evidence manifest emitted by Xenia's hybrid/pre-PQC stack.
pub const CURRENT_EVIDENCE_CRYPTO_MANIFEST: EvidenceCryptoManifest = EvidenceCryptoManifest {
    schema: "xenia-evidence-crypto-manifest-v1",
    profile: CryptoPolicyProfile::HybridPrePqcV1,
    kem: "ml-kem-768-fips203",
    transcript_signature: SignatureSuite::Ed25519Rfc8032,
    ledger_signature: CURRENT_LEDGER_SIGNATURE_SUITE,
    hash_chain: "blake3-256",
    kdf: "hkdf-sha256",
    aead: "chacha20-poly1305",
    downgrade_policy: DowngradePolicy::ExplicitClassicalSignatureAllowance,
};

/// Stable schema label for evidence public-key bindings.
pub const EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA: &str = "xenia-evidence-public-key-binding-v1";

/// Fingerprint algorithm used to bind evidence exports to their verifier key.
pub const EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM: &str = "blake3-256";

/// Public-key material and fingerprint used to verify exported evidence.
///
/// Evidence verifiers already require a caller-provided public key, but raw bytes
/// alone are easy to mix up when full-PQC fixtures carry much larger ML-DSA keys.
/// This binding makes the key's signature suite and fingerprint explicit before
/// any ledger signature is trusted. It is intentionally separate from
/// [`EvidenceCryptoManifest`] because fingerprints are artifact-specific while
/// manifests describe the policy/profile class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePublicKeyBinding {
    /// Schema label for this binding shape.
    pub schema: String,
    /// Signature suite this public key verifies.
    pub signature_suite: SignatureSuite,
    /// Raw public/verifying-key bytes for `signature_suite`.
    pub public_key: Vec<u8>,
    /// Hash algorithm used for `public_key_fingerprint`.
    pub fingerprint_algorithm: String,
    /// Fingerprint over `public_key`.
    pub public_key_fingerprint: [u8; 32],
}

impl EvidencePublicKeyBinding {
    /// Build a public-key binding and compute its fingerprint.
    pub fn new(signature_suite: SignatureSuite, public_key: impl Into<Vec<u8>>) -> Self {
        let public_key = public_key.into();
        Self {
            schema: EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA.to_string(),
            signature_suite,
            public_key_fingerprint: compute_evidence_public_key_fingerprint(&public_key),
            public_key,
            fingerprint_algorithm: EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM.to_string(),
        }
    }

    /// Validate this key binding against a manifest and selected ledger signature backend.
    pub fn validate_against_manifest_and_backend(
        &self,
        manifest: EvidenceCryptoManifest,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidencePublicKeyBindingError> {
        self.validate_against_signature_suite_and_backend(manifest.ledger_signature, backend)
    }

    /// Validate this key binding against an expected signature suite and backend.
    ///
    /// Use this when an artifact carries distinct verifier keys for different
    /// authority surfaces, such as transcript signatures and ledger signatures.
    pub fn validate_against_signature_suite_and_backend(
        &self,
        expected_suite: SignatureSuite,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidencePublicKeyBindingError> {
        if self.schema != EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA {
            return Err(EvidencePublicKeyBindingError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.fingerprint_algorithm != EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM {
            return Err(
                EvidencePublicKeyBindingError::UnsupportedFingerprintAlgorithm {
                    algorithm: self.fingerprint_algorithm.clone(),
                },
            );
        }
        if self.public_key.is_empty() {
            return Err(EvidencePublicKeyBindingError::EmptyPublicKey);
        }
        if self.signature_suite != expected_suite {
            return Err(
                EvidencePublicKeyBindingError::SignatureSuiteManifestMismatch {
                    manifest_suite: expected_suite,
                    binding_suite: self.signature_suite,
                },
            );
        }
        if self.signature_suite != backend.suite() {
            return Err(
                EvidencePublicKeyBindingError::SignatureSuiteBackendMismatch {
                    backend_suite: backend.suite(),
                    binding_suite: self.signature_suite,
                },
            );
        }
        if let Some(expected) = self.signature_suite.fixed_public_key_len() {
            let found = self.public_key.len();
            if found != expected {
                return Err(EvidencePublicKeyBindingError::BadPublicKeyLength {
                    signature_suite: self.signature_suite,
                    expected,
                    found,
                });
            }
        }
        let computed = compute_evidence_public_key_fingerprint(&self.public_key);
        if computed != self.public_key_fingerprint {
            return Err(EvidencePublicKeyBindingError::PublicKeyFingerprintMismatch);
        }
        Ok(())
    }
}

/// Compute the stable fingerprint for an evidence verifier public key.
pub fn compute_evidence_public_key_fingerprint(public_key: &[u8]) -> [u8; 32] {
    *blake3::hash(public_key).as_bytes()
}

/// Errors surfaced while validating an evidence public-key binding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidencePublicKeyBindingError {
    /// The binding schema label is unknown to this verifier.
    #[error("unsupported evidence public-key binding schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the binding.
        schema: String,
    },
    /// The fingerprint algorithm is unknown to this verifier.
    #[error("unsupported evidence public-key fingerprint algorithm: {algorithm}")]
    UnsupportedFingerprintAlgorithm {
        /// Fingerprint algorithm label found in the binding.
        algorithm: String,
    },
    /// The public key was empty.
    #[error("evidence public key must not be empty")]
    EmptyPublicKey,
    /// The key binding's suite did not match the manifest ledger signature suite.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match public-key binding {binding_suite:?}"
    )]
    SignatureSuiteManifestMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the public-key binding.
        binding_suite: SignatureSuite,
    },
    /// The key binding's suite did not match the selected verifier backend.
    #[error(
        "verifier backend {backend_suite:?} does not match public-key binding {binding_suite:?}"
    )]
    SignatureSuiteBackendMismatch {
        /// Signature suite handled by the selected backend.
        backend_suite: SignatureSuite,
        /// Signature suite declared by the public-key binding.
        binding_suite: SignatureSuite,
    },
    /// The public key length did not match the fixed-size suite expectation.
    #[error("bad public-key length for {signature_suite:?}: expected {expected}, found {found}")]
    BadPublicKeyLength {
        /// Signature suite declared by the binding.
        signature_suite: SignatureSuite,
        /// Expected public-key length in bytes.
        expected: usize,
        /// Actual public-key length in bytes.
        found: usize,
    },
    /// The stored fingerprint did not match the supplied public-key bytes.
    #[error("evidence public-key fingerprint mismatch")]
    PublicKeyFingerprintMismatch,
}

/// Stable schema label for session transcript bindings.
pub const SESSION_TRANSCRIPT_BINDING_SCHEMA: &str = "xenia-session-transcript-binding-v1";

/// Hash algorithm used for session transcript bindings.
pub const SESSION_TRANSCRIPT_HASH_ALGORITHM: &str = "blake3-256";

/// Bind an evidence bundle to the handshake/session transcript it claims to describe.
///
/// This structure does not store the transcript itself. It stores the stable hash of
/// the canonical transcript bytes, the session UUID those bytes established, and the
/// transcript signature suite declared by the evidence manifest. Bundle verifiers can
/// then reject a valid ledger chain that is replayed next to a different session
/// transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTranscriptBinding {
    /// Schema label for this binding shape.
    pub schema: String,
    /// UUID of the session established by the canonical transcript.
    pub session_id: Uuid,
    /// Hash algorithm used for `transcript_hash`.
    pub transcript_hash_algorithm: String,
    /// Hash of the canonical handshake/session transcript bytes.
    pub transcript_hash: [u8; 32],
    /// Signature suite used to authenticate the transcript.
    pub transcript_signature: SignatureSuite,
}

impl SessionTranscriptBinding {
    /// Build a binding from canonical transcript bytes.
    pub fn new(
        session_id: Uuid,
        transcript_bytes: &[u8],
        transcript_signature: SignatureSuite,
    ) -> Self {
        Self::from_hash(
            session_id,
            compute_session_transcript_hash(transcript_bytes),
            transcript_signature,
        )
    }

    /// Build a binding when the transcript hash was computed by another crate.
    pub fn from_hash(
        session_id: Uuid,
        transcript_hash: [u8; 32],
        transcript_signature: SignatureSuite,
    ) -> Self {
        Self {
            schema: SESSION_TRANSCRIPT_BINDING_SCHEMA.to_string(),
            session_id,
            transcript_hash_algorithm: SESSION_TRANSCRIPT_HASH_ALGORITHM.to_string(),
            transcript_hash,
            transcript_signature,
        }
    }

    /// Validate this binding against the declared evidence manifest.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), TranscriptBindingError> {
        if self.schema != SESSION_TRANSCRIPT_BINDING_SCHEMA {
            return Err(TranscriptBindingError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.transcript_hash_algorithm != SESSION_TRANSCRIPT_HASH_ALGORITHM {
            return Err(TranscriptBindingError::UnsupportedTranscriptHashAlgorithm {
                algorithm: self.transcript_hash_algorithm.clone(),
            });
        }
        if self.transcript_hash == [0u8; 32] {
            return Err(TranscriptBindingError::EmptyTranscriptHash);
        }
        if self.transcript_signature != manifest.transcript_signature {
            return Err(TranscriptBindingError::TranscriptSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                binding_suite: self.transcript_signature,
            });
        }
        Ok(())
    }
}

/// Stable schema label for session transcript signatures.
pub const SESSION_TRANSCRIPT_SIGNATURE_SCHEMA: &str = "xenia-session-transcript-signature-v1";

/// Algorithm-tagged signature over a session transcript binding.
///
/// This artifact makes the transcript authority explicit. A transcript hash can
/// bind a ledger to a session, but a full-PQC evidence bundle also needs a
/// signature over that transcript hash so the transcript authority cannot remain
/// classical or unsigned while the ledger entries are ML-DSA signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTranscriptSignature {
    /// Schema label for this signature artifact.
    pub schema: String,
    /// UUID of the session whose transcript was signed.
    pub session_id: Uuid,
    /// Hash algorithm used for `transcript_hash`.
    pub transcript_hash_algorithm: String,
    /// Hash of the canonical handshake/session transcript bytes.
    pub transcript_hash: [u8; 32],
    /// Algorithm-tagged signature over `transcript_hash`.
    pub signature: SignatureEnvelope,
}

impl SessionTranscriptSignature {
    /// Build a transcript-signature artifact from an existing transcript binding.
    pub fn from_binding(binding: &SessionTranscriptBinding, signature: SignatureEnvelope) -> Self {
        Self {
            schema: SESSION_TRANSCRIPT_SIGNATURE_SCHEMA.to_string(),
            session_id: binding.session_id,
            transcript_hash_algorithm: binding.transcript_hash_algorithm.clone(),
            transcript_hash: binding.transcript_hash,
            signature,
        }
    }

    /// Validate this transcript signature artifact before cryptographic verification.
    pub fn validate_against_binding_and_manifest(
        &self,
        binding: &SessionTranscriptBinding,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SignatureSuite, TranscriptSignatureError> {
        if self.schema != SESSION_TRANSCRIPT_SIGNATURE_SCHEMA {
            return Err(TranscriptSignatureError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.transcript_hash_algorithm != SESSION_TRANSCRIPT_HASH_ALGORITHM {
            return Err(
                TranscriptSignatureError::UnsupportedTranscriptHashAlgorithm {
                    algorithm: self.transcript_hash_algorithm.clone(),
                },
            );
        }
        if self.session_id != binding.session_id {
            return Err(TranscriptSignatureError::BindingSessionMismatch {
                binding_session_id: binding.session_id,
                signature_session_id: self.session_id,
            });
        }
        if self.transcript_hash_algorithm != binding.transcript_hash_algorithm {
            return Err(TranscriptSignatureError::BindingHashAlgorithmMismatch {
                binding_algorithm: binding.transcript_hash_algorithm.clone(),
                signature_algorithm: self.transcript_hash_algorithm.clone(),
            });
        }
        if self.transcript_hash != binding.transcript_hash {
            return Err(TranscriptSignatureError::BindingHashMismatch);
        }
        if self.transcript_hash == [0u8; 32] {
            return Err(TranscriptSignatureError::EmptyTranscriptHash);
        }

        let signature_suite = self.signature.validate_shape()?;
        if signature_suite != manifest.transcript_signature {
            return Err(TranscriptSignatureError::TranscriptSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                signature_suite,
            });
        }

        Ok(signature_suite)
    }
}

/// Return the domain-separated message signed by transcript signature artifacts.
///
/// The raw transcript hash is intentionally not signed directly. Including the
/// schema, session UUID, hash algorithm, and hash under an Xenia-specific domain
/// prevents a transcript signature from being replayed as some other 32-byte
/// message signature.
pub fn session_transcript_signature_message(binding: &SessionTranscriptBinding) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        b"xenia:session-transcript-signature:v1".len()
            + SESSION_TRANSCRIPT_SIGNATURE_SCHEMA.len()
            + SESSION_TRANSCRIPT_HASH_ALGORITHM.len()
            + 16
            + 32
            + 4,
    );
    message.extend_from_slice(b"xenia:session-transcript-signature:v1");
    message.push(0);
    message.extend_from_slice(SESSION_TRANSCRIPT_SIGNATURE_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(binding.session_id.as_bytes());
    message.extend_from_slice(binding.transcript_hash_algorithm.as_bytes());
    message.push(0);
    message.extend_from_slice(&binding.transcript_hash);
    message
}

/// Compute an Ed25519 transcript signature over an existing transcript binding.
pub fn sign_session_transcript_binding_ed25519(
    binding: &SessionTranscriptBinding,
    signing_key: &SigningKey,
) -> SessionTranscriptSignature {
    let message = session_transcript_signature_message(binding);
    let signature = signing_key.sign(&message).to_bytes();
    SessionTranscriptSignature::from_binding(binding, SignatureEnvelope::ed25519(signature))
}

/// Compute an ML-DSA-65 transcript signature over an existing transcript binding.
#[cfg(feature = "pqc-signatures")]
pub fn sign_session_transcript_binding_ml_dsa_65(
    binding: &SessionTranscriptBinding,
    signing_key: &MlDsaSigningKey<MlDsa65>,
) -> SessionTranscriptSignature {
    let message = session_transcript_signature_message(binding);
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    SessionTranscriptSignature::from_binding(
        binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, signature_bytes.to_vec()),
    )
}

/// Compute an ML-DSA-87 transcript signature over an existing transcript binding.
#[cfg(feature = "pqc-signatures")]
pub fn sign_session_transcript_binding_ml_dsa_87(
    binding: &SessionTranscriptBinding,
    signing_key: &MlDsaSigningKey<MlDsa87>,
) -> SessionTranscriptSignature {
    let message = session_transcript_signature_message(binding);
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    SessionTranscriptSignature::from_binding(
        binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa87Fips204, signature_bytes.to_vec()),
    )
}

/// Stable schema label for signed evidence-bundle seals.
pub const EVIDENCE_BUNDLE_SEAL_SCHEMA: &str = "xenia-evidence-bundle-seal-v1";

/// Algorithm-tagged signature over the full evidence-bundle context.
///
/// Transcript signatures prove the handshake transcript hash. Ledger signatures
/// prove individual consent entries. This seal binds the remaining artifact
/// context together: manifest profile, signature suites, transcript hash,
/// verifier-key fingerprints, and the ledger-chain endpoints. It prevents
/// otherwise-valid pieces from being recombined across sessions or bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundleSeal {
    /// Schema label for this seal shape.
    pub schema: String,
    /// UUID of the session described by the sealed bundle.
    pub session_id: Uuid,
    /// Evidence crypto policy profile declared by the manifest.
    pub profile: CryptoPolicyProfile,
    /// Signature suite authenticating the transcript authority surface.
    pub transcript_signature: SignatureSuite,
    /// Signature suite authenticating ledger entries.
    pub ledger_signature: SignatureSuite,
    /// Hash algorithm used for `transcript_hash`.
    pub transcript_hash_algorithm: String,
    /// Hash of the canonical handshake/session transcript bytes.
    pub transcript_hash: [u8; 32],
    /// Fingerprint of the transcript verifier public key.
    pub transcript_public_key_fingerprint: [u8; 32],
    /// Fingerprint of the ledger verifier public key.
    pub ledger_public_key_fingerprint: [u8; 32],
    /// Number of ledger entries covered by this seal.
    pub ledger_entry_count: u64,
    /// Entry hash of the first ledger entry covered by this seal.
    pub ledger_first_entry_hash: [u8; 32],
    /// Entry hash of the final ledger entry covered by this seal.
    pub ledger_last_entry_hash: [u8; 32],
    /// Algorithm-tagged signature over this seal's canonical message.
    pub signature: SignatureEnvelope,
}

impl EvidenceBundleSeal {
    /// Build a bundle-seal artifact from the verified evidence-bundle parts.
    pub fn from_parts(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
        signature: SignatureEnvelope,
    ) -> Result<Self, EvidenceBundleSealError> {
        let (ledger_entry_count, ledger_first_entry_hash, ledger_last_entry_hash) =
            ledger_chain_anchors(entries)?;
        Ok(Self {
            schema: EVIDENCE_BUNDLE_SEAL_SCHEMA.to_string(),
            session_id: transcript_binding.session_id,
            profile: manifest.profile,
            transcript_signature: manifest.transcript_signature,
            ledger_signature: manifest.ledger_signature,
            transcript_hash_algorithm: transcript_binding.transcript_hash_algorithm.clone(),
            transcript_hash: transcript_binding.transcript_hash,
            transcript_public_key_fingerprint: transcript_key_binding.public_key_fingerprint,
            ledger_public_key_fingerprint: ledger_key_binding.public_key_fingerprint,
            ledger_entry_count,
            ledger_first_entry_hash,
            ledger_last_entry_hash,
            signature,
        })
    }

    /// Validate this seal against the bundle parts it claims to cover.
    pub fn validate_against_bundle(
        &self,
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
    ) -> Result<SignatureSuite, EvidenceBundleSealError> {
        if self.schema != EVIDENCE_BUNDLE_SEAL_SCHEMA {
            return Err(EvidenceBundleSealError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.session_id != transcript_binding.session_id {
            return Err(EvidenceBundleSealError::SessionMismatch {
                binding_session_id: transcript_binding.session_id,
                seal_session_id: self.session_id,
            });
        }
        if self.profile != manifest.profile {
            return Err(EvidenceBundleSealError::ProfileMismatch {
                manifest_profile: manifest.profile,
                seal_profile: self.profile,
            });
        }
        if self.transcript_signature != manifest.transcript_signature {
            return Err(EvidenceBundleSealError::TranscriptSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                seal_suite: self.transcript_signature,
            });
        }
        if self.ledger_signature != manifest.ledger_signature {
            return Err(EvidenceBundleSealError::LedgerSignatureSuiteMismatch {
                manifest_suite: manifest.ledger_signature,
                seal_suite: self.ledger_signature,
            });
        }
        if self.transcript_hash_algorithm != transcript_binding.transcript_hash_algorithm {
            return Err(EvidenceBundleSealError::TranscriptHashAlgorithmMismatch {
                binding_algorithm: transcript_binding.transcript_hash_algorithm.clone(),
                seal_algorithm: self.transcript_hash_algorithm.clone(),
            });
        }
        if self.transcript_hash != transcript_binding.transcript_hash {
            return Err(EvidenceBundleSealError::TranscriptHashMismatch);
        }
        if self.transcript_public_key_fingerprint != transcript_key_binding.public_key_fingerprint {
            return Err(EvidenceBundleSealError::TranscriptPublicKeyFingerprintMismatch);
        }
        if self.ledger_public_key_fingerprint != ledger_key_binding.public_key_fingerprint {
            return Err(EvidenceBundleSealError::LedgerPublicKeyFingerprintMismatch);
        }

        let (ledger_entry_count, ledger_first_entry_hash, ledger_last_entry_hash) =
            ledger_chain_anchors(entries)?;
        if self.ledger_entry_count != ledger_entry_count {
            return Err(EvidenceBundleSealError::LedgerEntryCountMismatch {
                expected: ledger_entry_count,
                found: self.ledger_entry_count,
            });
        }
        if self.ledger_first_entry_hash != ledger_first_entry_hash {
            return Err(EvidenceBundleSealError::LedgerFirstEntryHashMismatch);
        }
        if self.ledger_last_entry_hash != ledger_last_entry_hash {
            return Err(EvidenceBundleSealError::LedgerLastEntryHashMismatch);
        }

        let signature_suite = self.signature.validate_shape()?;
        if signature_suite != manifest.transcript_signature {
            return Err(EvidenceBundleSealError::SealSignatureSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                seal_suite: signature_suite,
            });
        }
        Ok(signature_suite)
    }
}

/// Return the domain-separated message signed by evidence-bundle seals.
pub fn evidence_bundle_seal_message(seal: &EvidenceBundleSeal) -> Vec<u8> {
    let mut message = Vec::new();
    evidence_message_push_bytes(&mut message, b"xenia:evidence-bundle-seal:v1");
    evidence_message_push_bytes(&mut message, seal.schema.as_bytes());
    evidence_message_push_bytes(&mut message, seal.session_id.as_bytes());
    evidence_message_push_bytes(&mut message, seal.profile.stable_label().as_bytes());
    evidence_message_push_bytes(
        &mut message,
        seal.transcript_signature.stable_label().as_bytes(),
    );
    evidence_message_push_bytes(
        &mut message,
        seal.ledger_signature.stable_label().as_bytes(),
    );
    evidence_message_push_bytes(&mut message, seal.transcript_hash_algorithm.as_bytes());
    evidence_message_push_bytes(&mut message, &seal.transcript_hash);
    evidence_message_push_bytes(&mut message, &seal.transcript_public_key_fingerprint);
    evidence_message_push_bytes(&mut message, &seal.ledger_public_key_fingerprint);
    evidence_message_push_u64(&mut message, seal.ledger_entry_count);
    evidence_message_push_bytes(&mut message, &seal.ledger_first_entry_hash);
    evidence_message_push_bytes(&mut message, &seal.ledger_last_entry_hash);
    message
}

/// Return the domain-separated message for a seal over the provided bundle parts.
pub fn evidence_bundle_seal_message_from_parts(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
) -> Result<Vec<u8>, EvidenceBundleSealError> {
    let seal = EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::new(manifest.transcript_signature, Vec::<u8>::new()),
    )?;
    Ok(evidence_bundle_seal_message(&seal))
}

/// Compute an Ed25519 evidence-bundle seal signature.
pub fn sign_evidence_bundle_seal_ed25519(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
    signing_key: &SigningKey,
) -> Result<EvidenceBundleSeal, EvidenceBundleSealError> {
    let message = evidence_bundle_seal_message_from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
    )?;
    let signature = signing_key.sign(&message).to_bytes();
    EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::ed25519(signature),
    )
}

/// Compute an ML-DSA-65 evidence-bundle seal signature.
#[cfg(feature = "pqc-signatures")]
pub fn sign_evidence_bundle_seal_ml_dsa_65(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
    signing_key: &MlDsaSigningKey<MlDsa65>,
) -> Result<EvidenceBundleSeal, EvidenceBundleSealError> {
    let message = evidence_bundle_seal_message_from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
    )?;
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, signature_bytes.to_vec()),
    )
}

/// Compute an ML-DSA-87 evidence-bundle seal signature.
#[cfg(feature = "pqc-signatures")]
pub fn sign_evidence_bundle_seal_ml_dsa_87(
    manifest: EvidenceCryptoManifest,
    transcript_binding: &SessionTranscriptBinding,
    transcript_key_binding: &EvidencePublicKeyBinding,
    entries: &[LedgerEntryExport],
    ledger_key_binding: &EvidencePublicKeyBinding,
    signing_key: &MlDsaSigningKey<MlDsa87>,
) -> Result<EvidenceBundleSeal, EvidenceBundleSealError> {
    let message = evidence_bundle_seal_message_from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
    )?;
    let signature = signing_key.sign(&message).encode();
    let signature_bytes: &[u8] = signature.as_ref();
    EvidenceBundleSeal::from_parts(
        manifest,
        transcript_binding,
        transcript_key_binding,
        entries,
        ledger_key_binding,
        SignatureEnvelope::new(SignatureSuite::MlDsa87Fips204, signature_bytes.to_vec()),
    )
}

fn evidence_message_push_bytes(message: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u64;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(bytes);
}

fn evidence_message_push_u64(message: &mut Vec<u8>, value: u64) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn ledger_chain_anchors(
    entries: &[LedgerEntryExport],
) -> Result<(u64, [u8; 32], [u8; 32]), EvidenceBundleSealError> {
    let first = entries
        .first()
        .ok_or(EvidenceBundleSealError::EmptyTranscriptBoundBundle)?;
    let last = entries
        .last()
        .ok_or(EvidenceBundleSealError::EmptyTranscriptBoundBundle)?;
    Ok((entries.len() as u64, first.entry_hash, last.entry_hash))
}

/// Errors surfaced while validating a signed evidence-bundle seal.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceBundleSealError {
    /// The bundle seal schema label is unknown to this verifier.
    #[error("unsupported evidence-bundle seal schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the seal.
        schema: String,
    },
    /// The seal session UUID did not match the transcript binding.
    #[error(
        "transcript binding session {binding_session_id} does not match bundle seal session {seal_session_id}"
    )]
    SessionMismatch {
        /// Session UUID declared by the transcript binding.
        binding_session_id: Uuid,
        /// Session UUID declared by the bundle seal.
        seal_session_id: Uuid,
    },
    /// The seal profile did not match the manifest.
    #[error(
        "manifest profile {manifest_profile:?} does not match bundle seal profile {seal_profile:?}"
    )]
    ProfileMismatch {
        /// Crypto policy profile declared by the manifest.
        manifest_profile: CryptoPolicyProfile,
        /// Crypto policy profile declared by the seal.
        seal_profile: CryptoPolicyProfile,
    },
    /// The seal transcript signature suite did not match the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match bundle seal transcript signature {seal_suite:?}"
    )]
    TranscriptSignatureSuiteMismatch {
        /// Signature suite declared by the manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the seal.
        seal_suite: SignatureSuite,
    },
    /// The seal ledger signature suite did not match the manifest.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match bundle seal ledger signature {seal_suite:?}"
    )]
    LedgerSignatureSuiteMismatch {
        /// Signature suite declared by the manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the seal.
        seal_suite: SignatureSuite,
    },
    /// The seal transcript hash algorithm did not match the transcript binding.
    #[error(
        "transcript binding hash algorithm {binding_algorithm} does not match bundle seal hash algorithm {seal_algorithm}"
    )]
    TranscriptHashAlgorithmMismatch {
        /// Hash algorithm declared by the transcript binding.
        binding_algorithm: String,
        /// Hash algorithm declared by the seal.
        seal_algorithm: String,
    },
    /// The seal transcript hash did not match the transcript binding.
    #[error("bundle seal transcript hash does not match transcript binding hash")]
    TranscriptHashMismatch,
    /// The seal transcript key fingerprint did not match the transcript key binding.
    #[error("bundle seal transcript public-key fingerprint mismatch")]
    TranscriptPublicKeyFingerprintMismatch,
    /// The seal ledger key fingerprint did not match the ledger key binding.
    #[error("bundle seal ledger public-key fingerprint mismatch")]
    LedgerPublicKeyFingerprintMismatch,
    /// The seal ledger entry count did not match the supplied entries.
    #[error("bundle seal ledger entry count mismatch: expected {expected}, found {found}")]
    LedgerEntryCountMismatch {
        /// Ledger entry count computed from the supplied entries.
        expected: u64,
        /// Ledger entry count declared by the seal.
        found: u64,
    },
    /// The seal first entry hash did not match the supplied entries.
    #[error("bundle seal first ledger entry hash mismatch")]
    LedgerFirstEntryHashMismatch,
    /// The seal last entry hash did not match the supplied entries.
    #[error("bundle seal last ledger entry hash mismatch")]
    LedgerLastEntryHashMismatch,
    /// The seal signature envelope was malformed.
    #[error("bundle seal signature envelope rejected artifact: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// The seal signature suite did not match the manifest transcript authority suite.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match bundle seal signature {seal_suite:?}"
    )]
    SealSignatureSuiteMismatch {
        /// Signature suite declared by the manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the seal signature envelope.
        seal_suite: SignatureSuite,
    },
    /// A sealed transcript-bound evidence bundle had no ledger entries to seal.
    #[error("sealed transcript-bound evidence bundle must contain at least one ledger entry")]
    EmptyTranscriptBoundBundle,
}

/// Compute Xenia's stable session transcript binding hash.
pub fn compute_session_transcript_hash(transcript_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(transcript_bytes).as_bytes()
}

/// Errors surfaced while validating a session transcript binding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TranscriptBindingError {
    /// The binding schema label is unknown to this verifier.
    #[error("unsupported transcript binding schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the binding.
        schema: String,
    },
    /// The transcript hash algorithm is unknown to this verifier.
    #[error("unsupported transcript hash algorithm: {algorithm}")]
    UnsupportedTranscriptHashAlgorithm {
        /// Hash algorithm label found in the binding.
        algorithm: String,
    },
    /// The binding used an all-zero transcript hash placeholder.
    #[error("transcript hash must not be the all-zero placeholder")]
    EmptyTranscriptHash,
    /// The binding's transcript signature suite did not match the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match transcript binding {binding_suite:?}"
    )]
    TranscriptSignatureSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the transcript binding.
        binding_suite: SignatureSuite,
    },
}

/// Errors surfaced while validating a session transcript signature artifact.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TranscriptSignatureError {
    /// The transcript signature schema label is unknown to this verifier.
    #[error("unsupported transcript signature schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the signature artifact.
        schema: String,
    },
    /// The transcript hash algorithm is unknown to this verifier.
    #[error("unsupported transcript signature hash algorithm: {algorithm}")]
    UnsupportedTranscriptHashAlgorithm {
        /// Hash algorithm label found in the signature artifact.
        algorithm: String,
    },
    /// The signature artifact used an all-zero transcript hash placeholder.
    #[error("transcript signature hash must not be the all-zero placeholder")]
    EmptyTranscriptHash,
    /// The signature artifact's session UUID did not match the binding.
    #[error(
        "transcript binding session {binding_session_id} does not match transcript signature session {signature_session_id}"
    )]
    BindingSessionMismatch {
        /// Session UUID declared by the transcript binding.
        binding_session_id: Uuid,
        /// Session UUID declared by the transcript signature artifact.
        signature_session_id: Uuid,
    },
    /// The signature artifact's hash algorithm did not match the binding.
    #[error(
        "transcript binding hash algorithm {binding_algorithm} does not match transcript signature algorithm {signature_algorithm}"
    )]
    BindingHashAlgorithmMismatch {
        /// Hash algorithm declared by the transcript binding.
        binding_algorithm: String,
        /// Hash algorithm declared by the transcript signature artifact.
        signature_algorithm: String,
    },
    /// The signature artifact's transcript hash did not match the binding.
    #[error("transcript signature hash does not match transcript binding hash")]
    BindingHashMismatch,
    /// The signature envelope was malformed.
    #[error("transcript signature envelope rejected artifact: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// The signature artifact's suite did not match the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match transcript signature artifact {signature_suite:?}"
    )]
    TranscriptSignatureSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the transcript signature artifact.
        signature_suite: SignatureSuite,
    },
}

/// The kind of consent event recorded in the ledger. Mirrors the
/// state-transitions surfaced by `xenia-wire`'s consent state machine
/// (`Request` / `Response{approved: bool}` / `Revocation` /
/// `ConsentProtocolViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentKind {
    /// Admin / operator requested a privileged action on the user's machine.
    Request,
    /// User approved the request.
    Approval,
    /// User denied the request (explicit negative response).
    Denial,
    /// User revoked a previously-approved session mid-flight.
    Revocation,
    /// Protocol violation detected (e.g., a contradictory Response after a prior Revocation).
    Violation,
    /// Automated action triggered by Athena AI triage.
    AthenaTriage,
}

impl ConsentKind {
    /// Stable dot-namespaced audit event name for this consent event kind.
    ///
    /// These names are part of the operator/admin audit contract. They are
    /// intentionally decoupled from Rust enum variant spelling so UI labels,
    /// release evidence, and downstream audit consumers do not depend on
    /// `Debug` formatting.
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::Request => "consent.requested",
            Self::Approval => "consent.granted",
            Self::Denial => "consent.denied",
            Self::Revocation => "consent.revoked",
            Self::Violation => "consent.protocol_violation",
            Self::AthenaTriage => "admin.athena_triage",
        }
    }
}

/// A single consent event. Carries enough context for an auditor to
/// reconstruct which session, which request, and which party was
/// involved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentEventRecord {
    /// DID-bound source identifier of the operator requesting access
    /// (32 bytes; typically a hash of the Ed25519 verifying key, but
    /// any 32-byte opaque identifier is acceptable to this crate).
    pub source_id: [u8; 32],
    /// UUID of the Xenia session the event belongs to.
    pub session_id: Uuid,
    /// UUID of the specific consent request within the session.
    pub request_id: Uuid,
    /// Kind of event.
    pub kind: ConsentKind,
    /// Optional human-readable scope description (e.g.
    /// `"view screen, inject input on /dev/tty1"`). Audit trails
    /// benefit from this; verification does not depend on it.
    pub scope: String,
}

impl ConsentEventRecord {
    /// Stable dot-namespaced audit event name for this record.
    pub const fn stable_name(&self) -> &'static str {
        self.kind.stable_name()
    }
}

/// A signed, chained ledger entry. Every field is covered by
/// `entry_hash`; `signature` is the operator's Ed25519 signature over
/// `entry_hash`. Exported evidence should prefer [`LedgerEntryExport`] so the
/// signature carries an explicit algorithm label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Monotonic 0-based sequence number. The genesis entry is 0.
    pub seq: u64,
    /// `entry_hash` of the previous entry, or `[0; 32]` for the genesis entry.
    pub prev_hash: [u8; 32],
    /// Wall-clock time of the event, as recorded by the operator.
    pub timestamp: SystemTime,
    /// The consent event itself.
    pub event: ConsentEventRecord,
    /// blake3 hash over `(seq, prev_hash, timestamp, event)`. Covers
    /// every field except `signature` itself (which signs this hash).
    pub entry_hash: [u8; 32],
    /// Ed25519 signature over `entry_hash`, 64 bytes.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Export-safe ledger entry with an algorithm-tagged signature envelope.
///
/// This mirrors [`LedgerEntry`] but replaces the legacy fixed-size Ed25519
/// signature field with [`SignatureEnvelope`]. Use this shape for JSON/CBOR
/// evidence bundles and long-lived verifier fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntryExport {
    /// Monotonic 0-based sequence number. The genesis entry is 0.
    pub seq: u64,
    /// `entry_hash` of the previous entry, or `[0; 32]` for the genesis entry.
    pub prev_hash: [u8; 32],
    /// Wall-clock time of the event, as recorded by the operator.
    pub timestamp: SystemTime,
    /// The consent event itself.
    pub event: ConsentEventRecord,
    /// blake3 hash over `(seq, prev_hash, timestamp, event)`.
    pub entry_hash: [u8; 32],
    /// Algorithm-tagged signature over `entry_hash`.
    pub signature: SignatureEnvelope,
}

impl LedgerEntryExport {
    /// Convert a current legacy Ed25519 entry into an export-safe envelope entry.
    pub fn from_legacy_entry(entry: &LedgerEntry) -> Self {
        Self {
            seq: entry.seq,
            prev_hash: entry.prev_hash,
            timestamp: entry.timestamp,
            event: entry.event.clone(),
            entry_hash: entry.entry_hash,
            signature: entry.signature_envelope(),
        }
    }

    /// Convert an export entry back into the current legacy Ed25519 entry shape.
    pub fn to_legacy_entry(&self) -> Result<LedgerEntry, SignatureEnvelopeError> {
        Ok(LedgerEntry {
            seq: self.seq,
            prev_hash: self.prev_hash,
            timestamp: self.timestamp,
            event: self.event.clone(),
            entry_hash: self.entry_hash,
            signature: self.signature.to_legacy_ed25519()?,
        })
    }
}

impl LedgerEntry {
    /// Return the signature suite used by this legacy ledger entry.
    pub const fn signature_suite(&self) -> SignatureSuite {
        CURRENT_LEDGER_SIGNATURE_SUITE
    }

    /// Return an algorithm-tagged signature envelope for this entry.
    pub fn signature_envelope(&self) -> SignatureEnvelope {
        SignatureEnvelope::ed25519(self.signature)
    }

    /// Convert this entry into the export-safe signature-envelope shape.
    pub fn to_export_entry(&self) -> LedgerEntryExport {
        LedgerEntryExport::from_legacy_entry(self)
    }
}

/// Feature-gated exported-evidence chain signed with ML-DSA.
///
/// This type deliberately produces only [`LedgerEntryExport`] entries. It does
/// not pretend to be the stable Ed25519 [`Chain`] runtime shape; it exists to
/// make the full-PQC evidence path real enough for fixtures, verifier tests,
/// and future runtime promotion behind explicit policy gates.
#[cfg(feature = "pqc-signatures")]
pub struct MlDsaEvidenceChain<P: MlDsaParams> {
    entries: Vec<LedgerEntryExport>,
    signing_key: MlDsaSigningKey<P>,
    suite: SignatureSuite,
}

#[cfg(feature = "pqc-signatures")]
impl<P: MlDsaParams> MlDsaEvidenceChain<P> {
    /// Create an empty ML-DSA exported-evidence chain.
    fn new(signing_key: MlDsaSigningKey<P>, suite: SignatureSuite) -> Self {
        Self {
            entries: Vec::new(),
            signing_key,
            suite,
        }
    }

    /// Return the number of entries in the exported-evidence chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the exported-evidence chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `entry_hash` of the most recent entry, or `[0; 32]` before genesis.
    pub fn last_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|entry| entry.entry_hash)
            .unwrap_or([0u8; 32])
    }

    /// Return the raw encoded ML-DSA verifying key bytes for this chain.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let encoded = self.signing_key.verifying_key().encode();
        std::convert::AsRef::<[u8]>::as_ref(&encoded).to_vec()
    }

    /// Iterate over all exported entries in sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &LedgerEntryExport> {
        self.entries.iter()
    }

    /// Return a cloned exported-entry vector for persistence or evidence bundles.
    pub fn export_entries(&self) -> Vec<LedgerEntryExport> {
        self.entries.clone()
    }

    /// Append a consent event, computing the same hash-chain preimage as the
    /// default ledger but signing the resulting entry hash with ML-DSA.
    pub fn append(&mut self, event: ConsentEventRecord) -> Result<&LedgerEntryExport, LedgerError> {
        let entry_index = self.entries.len();
        let seq = entry_index as u64;
        let prev_hash = self.last_hash();
        let timestamp = SystemTime::now();

        let entry_hash = compute_entry_hash(seq, &prev_hash, &timestamp, &event)?;
        let signature = self.signing_key.sign(&entry_hash).encode();
        let signature_bytes: &[u8] = signature.as_ref();

        self.entries.push(LedgerEntryExport {
            seq,
            prev_hash,
            timestamp,
            event,
            entry_hash,
            signature: SignatureEnvelope::new(self.suite, signature_bytes.to_vec()),
        });
        self.entries
            .get(entry_index)
            .ok_or(LedgerError::AppendInvariant)
    }
}

/// ML-DSA-65 exported-evidence chain builder.
#[cfg(feature = "pqc-signatures")]
pub type MlDsa65EvidenceChain = MlDsaEvidenceChain<MlDsa65>;

/// ML-DSA-87 exported-evidence chain builder.
#[cfg(feature = "pqc-signatures")]
pub type MlDsa87EvidenceChain = MlDsaEvidenceChain<MlDsa87>;

/// Create an empty ML-DSA-65 exported-evidence chain.
#[cfg(feature = "pqc-signatures")]
pub fn new_ml_dsa_65_evidence_chain(signing_key: MlDsaSigningKey<MlDsa65>) -> MlDsa65EvidenceChain {
    MlDsaEvidenceChain::new(signing_key, SignatureSuite::MlDsa65Fips204)
}

/// Create an empty ML-DSA-87 exported-evidence chain.
#[cfg(feature = "pqc-signatures")]
pub fn new_ml_dsa_87_evidence_chain(signing_key: MlDsaSigningKey<MlDsa87>) -> MlDsa87EvidenceChain {
    MlDsaEvidenceChain::new(signing_key, SignatureSuite::MlDsa87Fips204)
}

/// Errors surfaced by [`Chain`] operations.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Serialization of an entry's pre-hash payload failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),

    /// An entry was pushed but could not be read back from the chain.
    #[error("ledger append invariant failed: pushed entry missing")]
    AppendInvariant,
}

/// Errors surfaced by [`Verifier`] operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Chain was empty where at least one entry was required.
    #[error("chain is empty")]
    Empty,
    /// A sequence number was out of order (gaps, duplicates, reversal).
    #[error("sequence at index {index}: expected {expected}, found {found}")]
    OutOfOrder {
        /// Position in the slice where the bad sequence number was found.
        index: usize,
        /// The sequence number this entry should have had.
        expected: u64,
        /// The sequence number it actually had.
        found: u64,
    },
    /// An entry's `prev_hash` did not match the prior entry's `entry_hash`.
    #[error("broken hash link at seq {seq}")]
    BrokenLink {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// An entry's `entry_hash` does not match a freshly-computed hash over its fields.
    #[error("entry_hash mismatch at seq {seq} — tampering detected")]
    EntryHashMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// An entry's signature failed to verify under the provided public key.
    #[error("signature invalid at seq {seq}")]
    BadSignature {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// The current verifier does not support the envelope's signature suite.
    #[error("unsupported signature suite {signature_suite:?} at seq {seq}")]
    UnsupportedSignatureSuite {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite declared by the envelope.
        signature_suite: SignatureSuite,
    },
    /// The envelope declared a signature-suite label unknown to this verifier.
    #[error("unknown signature suite {algorithm} at seq {seq}")]
    UnknownSignatureSuite {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Unknown signature-suite label declared by the envelope.
        algorithm: String,
    },
    /// The envelope's signature bytes had an invalid length for the declared suite.
    #[error("bad signature length at seq {seq}: expected {expected}, found {found}")]
    BadSignatureLength {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Expected signature length in bytes.
        expected: usize,
        /// Actual signature length in bytes.
        found: usize,
    },
    /// The provided public key was rejected by the selected signature backend.
    #[error("signature public key rejected for {signature_suite:?} at seq {seq}")]
    BadSignaturePublicKey {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite selected for verification.
        signature_suite: SignatureSuite,
    },
    /// The selected backend does not match the entry's signature suite.
    #[error(
        "signature backend {backend_suite:?} does not match entry envelope {entry_suite:?} at seq {seq}"
    )]
    SignatureBackendSuiteMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite declared by the entry signature envelope.
        entry_suite: SignatureSuite,
        /// Signature suite handled by the selected backend.
        backend_suite: SignatureSuite,
    },
    /// The genesis entry's `prev_hash` was not all zeros.
    #[error("genesis prev_hash must be all zeros")]
    BadGenesis,
}

/// Errors surfaced when verifying an evidence manifest together with its exported chain.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceBundleVerifyError {
    /// The evidence manifest did not satisfy its declared policy.
    #[error("evidence manifest policy rejected artifact: {0}")]
    ManifestPolicy(#[from] EvidencePolicyError),
    /// The session transcript binding failed validation.
    #[error("session transcript binding rejected artifact: {0}")]
    TranscriptBinding(#[from] TranscriptBindingError),
    /// A full-PQC transcript-bound verifier was called without a transcript signature artifact.
    #[error(
        "full-pqc-v1 transcript-bound evidence requires an explicit transcript signature artifact"
    )]
    MissingTranscriptSignatureInFullPqc,
    /// The session transcript signature artifact failed validation.
    #[error("session transcript signature rejected artifact: {0}")]
    TranscriptSignature(#[from] TranscriptSignatureError),
    /// The selected transcript signature backend does not satisfy the manifest.
    #[error(
        "manifest transcript signature {manifest_suite:?} does not match transcript verifier backend {backend_suite:?}"
    )]
    TranscriptBackendSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite handled by the selected transcript verifier backend.
        backend_suite: SignatureSuite,
    },
    /// The transcript signature failed backend verification.
    #[error("transcript signature verification failed for {signature_suite:?}: {source}")]
    TranscriptSignatureBackend {
        /// Signature suite selected for transcript verification.
        signature_suite: SignatureSuite,
        /// Backend verification error.
        source: EvidenceSignatureBackendError,
    },
    /// The evidence-bundle seal failed validation.
    #[error("evidence-bundle seal rejected artifact: {0}")]
    BundleSeal(#[from] EvidenceBundleSealError),
    /// The bundle seal signature failed backend verification.
    #[error("bundle seal signature verification failed for {signature_suite:?}: {source}")]
    BundleSealSignatureBackend {
        /// Signature suite selected for bundle-seal verification.
        signature_suite: SignatureSuite,
        /// Backend verification error.
        source: EvidenceSignatureBackendError,
    },
    /// The public-key binding failed validation.
    #[error("evidence public-key binding rejected artifact: {0}")]
    PublicKeyBinding(#[from] EvidencePublicKeyBindingError),
    /// A transcript-bound evidence bundle had no ledger entries to bind.
    #[error("transcript-bound evidence bundle must contain at least one ledger entry")]
    EmptyTranscriptBoundBundle,
    /// A ledger entry belongs to a different session than the transcript binding.
    #[error(
        "transcript binding session {binding_session_id} does not match entry session {entry_session_id} at seq {seq}"
    )]
    TranscriptSessionMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Session UUID declared by the transcript binding.
        binding_session_id: Uuid,
        /// Session UUID carried by the ledger entry.
        entry_session_id: Uuid,
    },
    /// The exported chain failed structural, hash-link, or signature verification.
    #[error("exported chain verification failed: {0}")]
    ExportedChain(#[from] VerifyError),
    /// The selected signature backend does not satisfy the manifest's ledger signature suite.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match verifier backend {backend_suite:?}"
    )]
    LedgerBackendSuiteMismatch {
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite handled by the selected backend.
        backend_suite: SignatureSuite,
    },
    /// The manifest's ledger signature suite did not match an entry signature envelope.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match entry envelope {entry_suite:?} at seq {seq}"
    )]
    LedgerSignatureSuiteMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
        /// Signature suite declared by the evidence manifest.
        manifest_suite: SignatureSuite,
        /// Signature suite declared by the entry signature envelope.
        entry_suite: SignatureSuite,
    },
}

/// Append-only, hash-chained ledger owned by an operator with a
/// signing key. See the crate-level docs for the semantics.
pub struct Chain {
    entries: Vec<LedgerEntry>,
    signing_key: SigningKey,
}

impl Chain {
    /// Create a new empty chain held by `signing_key`.
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            entries: Vec::new(),
            signing_key,
        }
    }

    /// Rehydrate a chain from a previously-persisted sequence of entries.
    ///
    /// Does NOT verify the rehydrated entries — the caller should run
    /// [`Verifier::verify_chain`] with the operator's public key to
    /// confirm integrity. This method only establishes the append
    /// frontier for subsequent [`Chain::append`] calls.
    pub fn from_entries(entries: Vec<LedgerEntry>, signing_key: SigningKey) -> Self {
        Self {
            entries,
            signing_key,
        }
    }

    /// Return the number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `entry_hash` of the most recent entry, or `[0; 32]` if the
    /// chain is empty (the implicit "pre-genesis" hash).
    pub fn last_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32])
    }

    /// Iterate over all entries in sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &LedgerEntry> {
        self.entries.iter()
    }

    /// Return entries converted to the export-safe signature-envelope shape.
    pub fn export_entries(&self) -> Vec<LedgerEntryExport> {
        self.entries
            .iter()
            .map(LedgerEntry::to_export_entry)
            .collect()
    }

    /// Append a new consent event, producing a signed, chained entry.
    pub fn append(&mut self, event: ConsentEventRecord) -> Result<&LedgerEntry, LedgerError> {
        let entry_index = self.entries.len();
        let seq = entry_index as u64;
        let prev_hash = self.last_hash();
        let timestamp = SystemTime::now();

        let entry_hash = compute_entry_hash(seq, &prev_hash, &timestamp, &event)?;
        let signature = self.signing_key.sign(&entry_hash).to_bytes();

        self.entries.push(LedgerEntry {
            seq,
            prev_hash,
            timestamp,
            event,
            entry_hash,
            signature,
        });
        self.entries
            .get(entry_index)
            .ok_or(LedgerError::AppendInvariant)
    }

    /// Consume the chain and return its entries. Useful for persistence.
    pub fn into_entries(self) -> Vec<LedgerEntry> {
        self.entries
    }
}

/// Stateless verifier. Separate from [`Chain`] so an auditor can verify
/// a chain using only the public key and the serialized entries, never
/// needing access to the signing key.
pub struct Verifier;

impl Verifier {
    /// Return the evidence-profile labels for the current ledger verifier.
    pub const fn evidence_profile() -> LedgerEvidenceProfile {
        CURRENT_LEDGER_EVIDENCE_PROFILE
    }

    /// Return the current end-to-end evidence crypto manifest.
    pub const fn evidence_crypto_manifest() -> EvidenceCryptoManifest {
        CURRENT_EVIDENCE_CRYPTO_MANIFEST
    }

    /// Validate that a manifest satisfies its declared policy.
    pub const fn verify_evidence_crypto_manifest(
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), EvidencePolicyError> {
        manifest.validate_against_policy()
    }

    /// Verify every entry in a chain: sequence continuity, hash link,
    /// entry_hash recomputation, and Ed25519 signature.
    ///
    /// An empty slice passes vacuously. Callers who require at least
    /// one entry should check length separately before calling this.
    pub fn verify_chain(
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), VerifyError> {
        let mut expected_prev = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            let expected_seq = index as u64;
            if entry.seq != expected_seq {
                return Err(VerifyError::OutOfOrder {
                    index,
                    expected: expected_seq,
                    found: entry.seq,
                });
            }

            if entry.seq == 0 && entry.prev_hash != [0u8; 32] {
                return Err(VerifyError::BadGenesis);
            }
            if entry.prev_hash != expected_prev {
                return Err(VerifyError::BrokenLink { seq: entry.seq });
            }

            let recomputed =
                compute_entry_hash(entry.seq, &entry.prev_hash, &entry.timestamp, &entry.event)
                    .map_err(|_| VerifyError::EntryHashMismatch { seq: entry.seq })?;
            if recomputed != entry.entry_hash {
                return Err(VerifyError::EntryHashMismatch { seq: entry.seq });
            }

            let sig = Signature::from_bytes(&entry.signature);
            public_key
                .verify(&entry.entry_hash, &sig)
                .map_err(|_| VerifyError::BadSignature { seq: entry.seq })?;

            expected_prev = entry.entry_hash;
        }
        Ok(())
    }

    /// Verify an evidence manifest and its exported ledger entries as one bundle.
    ///
    /// This is the verifier entry point for long-lived evidence artifacts. It
    /// first enforces the manifest's crypto policy, then confirms every entry
    /// envelope declares the same ledger signature suite as the manifest, then
    /// runs the chain/hash/signature verifier. This prevents a forged artifact
    /// from attaching a `full-pqc-v1` manifest to an Ed25519 export or otherwise
    /// overstating the evidence's actual crypto surface.
    pub fn verify_evidence_bundle(
        manifest: EvidenceCryptoManifest,
        entries: &[LedgerEntryExport],
        public_key: &VerifyingKey,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_bundle_with_backend(
            manifest,
            entries,
            &public_key.to_bytes(),
            &Ed25519EvidenceSignatureBackend,
        )
    }

    /// Verify an evidence manifest and exported ledger entries using an explicit
    /// signature backend.
    ///
    /// This is the verifier entry point for full-PQC evidence once a reviewed
    /// ML-DSA/SLH-DSA backend is selected. The manifest policy, the backend
    /// suite, and every entry envelope must agree before any signature bytes are
    /// trusted.
    pub fn verify_evidence_bundle_with_backend(
        manifest: EvidenceCryptoManifest,
        entries: &[LedgerEntryExport],
        public_key: &[u8],
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_crypto_manifest(manifest)?;

        if backend.suite() != manifest.ledger_signature {
            return Err(EvidenceBundleVerifyError::LedgerBackendSuiteMismatch {
                manifest_suite: manifest.ledger_signature,
                backend_suite: backend.suite(),
            });
        }

        for entry in entries {
            let entry_suite = entry_signature_suite(entry)?;
            if entry_suite != manifest.ledger_signature {
                return Err(EvidenceBundleVerifyError::LedgerSignatureSuiteMismatch {
                    seq: entry.seq,
                    manifest_suite: manifest.ledger_signature,
                    entry_suite,
                });
            }
        }

        Self::verify_exported_chain_with_backend(entries, public_key, backend)?;
        Ok(())
    }

    /// Verify an evidence bundle using a self-describing public-key binding.
    ///
    /// This is the preferred explicit-backend verifier for long-lived artifacts:
    /// it validates the manifest policy, selected backend, key suite, public-key
    /// length, and public-key fingerprint before any entry signature is checked.
    pub fn verify_evidence_bundle_with_key_binding(
        manifest: EvidenceCryptoManifest,
        entries: &[LedgerEntryExport],
        key_binding: &EvidencePublicKeyBinding,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_crypto_manifest(manifest)?;
        key_binding.validate_against_manifest_and_backend(manifest, backend)?;
        Self::verify_evidence_bundle_with_backend(
            manifest,
            entries,
            &key_binding.public_key,
            backend,
        )
    }

    /// Verify a manifest, session transcript binding, and exported ledger as one artifact.
    ///
    /// This is the preferred verifier for evidence bundles that include a canonical
    /// handshake/session transcript hash. It prevents a valid exported ledger chain
    /// from being replayed beside a different transcript by requiring every ledger
    /// entry to carry the same `session_id` as the transcript binding before the
    /// ordinary bundle verifier is trusted.
    pub fn verify_transcript_bound_evidence_bundle(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        entries: &[LedgerEntryExport],
        public_key: &VerifyingKey,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_transcript_bound_evidence_bundle_with_backend(
            manifest,
            transcript_binding,
            entries,
            &public_key.to_bytes(),
            &Ed25519EvidenceSignatureBackend,
        )
    }

    /// Verify a transcript-bound evidence bundle with an explicit signature backend.
    ///
    /// Use this for future full-PQC bundles whose ledger entries are ML-DSA or
    /// SLH-DSA signed. It keeps transcript binding, manifest policy, entry-suite
    /// matching, and backend selection in one fail-closed path.
    pub fn verify_transcript_bound_evidence_bundle_with_backend(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        entries: &[LedgerEntryExport],
        public_key: &[u8],
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        transcript_binding.validate_against_manifest(manifest)?;
        if manifest.profile.requires_post_quantum_signatures() {
            return Err(EvidenceBundleVerifyError::MissingTranscriptSignatureInFullPqc);
        }

        if entries.is_empty() {
            return Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle);
        }

        for entry in entries {
            if entry.event.session_id != transcript_binding.session_id {
                return Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
                    seq: entry.seq,
                    binding_session_id: transcript_binding.session_id,
                    entry_session_id: entry.event.session_id,
                });
            }
        }

        Self::verify_evidence_bundle_with_backend(manifest, entries, public_key, backend)
    }

    /// Verify a transcript-bound evidence bundle using a self-describing public-key binding.
    ///
    /// This keeps the full verifier surface self-describing: manifest, transcript
    /// binding, public-key provenance, signature backend, and exported ledger must
    /// agree before the artifact is accepted.
    pub fn verify_transcript_bound_evidence_bundle_with_key_binding(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        entries: &[LedgerEntryExport],
        key_binding: &EvidencePublicKeyBinding,
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        transcript_binding.validate_against_manifest(manifest)?;
        if manifest.profile.requires_post_quantum_signatures() {
            return Err(EvidenceBundleVerifyError::MissingTranscriptSignatureInFullPqc);
        }
        key_binding.validate_against_manifest_and_backend(manifest, backend)?;

        if entries.is_empty() {
            return Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle);
        }

        for entry in entries {
            if entry.event.session_id != transcript_binding.session_id {
                return Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
                    seq: entry.seq,
                    binding_session_id: transcript_binding.session_id,
                    entry_session_id: entry.event.session_id,
                });
            }
        }

        Self::verify_evidence_bundle_with_backend(
            manifest,
            entries,
            &key_binding.public_key,
            backend,
        )
    }

    /// Verify a signed transcript-bound evidence bundle using explicit key bindings.
    ///
    /// This is the strict verifier for `full-pqc-v1` artifacts. It requires a
    /// signature over the transcript hash, validates the transcript verifier key
    /// against `manifest.transcript_signature`, validates the ledger verifier key
    /// against `manifest.ledger_signature`, and only then verifies ledger entries.
    #[allow(clippy::too_many_arguments)] // distinct verification inputs (manifest, bindings, signatures, key fingerprints); a bundle struct would just re-spread them
    pub fn verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_signature: &SessionTranscriptSignature,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
        transcript_backend: &impl EvidenceSignatureBackend,
        ledger_backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_evidence_crypto_manifest(manifest)?;
        transcript_binding.validate_against_manifest(manifest)?;
        let transcript_signature_suite = transcript_signature
            .validate_against_binding_and_manifest(transcript_binding, manifest)?;

        if transcript_backend.suite() != manifest.transcript_signature {
            return Err(EvidenceBundleVerifyError::TranscriptBackendSuiteMismatch {
                manifest_suite: manifest.transcript_signature,
                backend_suite: transcript_backend.suite(),
            });
        }
        if transcript_signature_suite != transcript_backend.suite() {
            return Err(EvidenceBundleVerifyError::TranscriptBackendSuiteMismatch {
                manifest_suite: transcript_signature_suite,
                backend_suite: transcript_backend.suite(),
            });
        }
        transcript_key_binding.validate_against_signature_suite_and_backend(
            manifest.transcript_signature,
            transcript_backend,
        )?;
        ledger_key_binding.validate_against_manifest_and_backend(manifest, ledger_backend)?;

        transcript_backend
            .verify_signature(
                &transcript_key_binding.public_key,
                &session_transcript_signature_message(transcript_binding),
                &transcript_signature.signature.signature,
            )
            .map_err(
                |source| EvidenceBundleVerifyError::TranscriptSignatureBackend {
                    signature_suite: transcript_signature_suite,
                    source,
                },
            )?;

        if entries.is_empty() {
            return Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle);
        }

        for entry in entries {
            if entry.event.session_id != transcript_binding.session_id {
                return Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
                    seq: entry.seq,
                    binding_session_id: transcript_binding.session_id,
                    entry_session_id: entry.event.session_id,
                });
            }
        }

        Self::verify_evidence_bundle_with_key_binding(
            manifest,
            entries,
            ledger_key_binding,
            ledger_backend,
        )
    }

    /// Verify a signed transcript-bound bundle plus a signed bundle-level seal.
    ///
    /// This is the strongest verifier path for long-lived audit artifacts. In
    /// addition to the signed transcript and signed ledger entries, it verifies a
    /// bundle seal over the manifest profile, signature suites, transcript hash,
    /// verifier-key fingerprints, and ledger-chain endpoints.
    #[allow(clippy::too_many_arguments)] // distinct verification inputs; a bundle struct would just re-spread them
    pub fn verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
        manifest: EvidenceCryptoManifest,
        transcript_binding: &SessionTranscriptBinding,
        transcript_signature: &SessionTranscriptSignature,
        bundle_seal: &EvidenceBundleSeal,
        transcript_key_binding: &EvidencePublicKeyBinding,
        entries: &[LedgerEntryExport],
        ledger_key_binding: &EvidencePublicKeyBinding,
        transcript_backend: &impl EvidenceSignatureBackend,
        ledger_backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), EvidenceBundleVerifyError> {
        Self::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
            manifest,
            transcript_binding,
            transcript_signature,
            transcript_key_binding,
            entries,
            ledger_key_binding,
            transcript_backend,
            ledger_backend,
        )?;

        let seal_signature_suite = bundle_seal.validate_against_bundle(
            manifest,
            transcript_binding,
            transcript_key_binding,
            entries,
            ledger_key_binding,
        )?;

        transcript_backend
            .verify_signature(
                &transcript_key_binding.public_key,
                &evidence_bundle_seal_message(bundle_seal),
                &bundle_seal.signature.signature,
            )
            .map_err(
                |source| EvidenceBundleVerifyError::BundleSealSignatureBackend {
                    signature_suite: seal_signature_suite,
                    source,
                },
            )
    }

    /// Verify an export-safe chain whose signatures are algorithm-tagged.
    ///
    /// The current verifier accepts only Ed25519 envelopes. PQ signature suites
    /// are parsed and shape-checked, but return [`VerifyError::UnsupportedSignatureSuite`]
    /// until the ML-DSA/SLH-DSA verification backend lands.
    pub fn verify_exported_chain(
        entries: &[LedgerEntryExport],
        public_key: &VerifyingKey,
    ) -> Result<(), VerifyError> {
        for entry in entries {
            let suite = entry_signature_suite_for_verify(entry)?;
            if suite != SignatureSuite::Ed25519Rfc8032 {
                return Err(VerifyError::UnsupportedSignatureSuite {
                    seq: entry.seq,
                    signature_suite: suite,
                });
            }
        }

        Self::verify_exported_chain_with_backend(
            entries,
            &public_key.to_bytes(),
            &Ed25519EvidenceSignatureBackend,
        )
    }

    /// Verify an export-safe chain whose signatures are algorithm-tagged using
    /// an explicit signature backend and raw backend public key bytes.
    ///
    /// This keeps the legacy Ed25519 verifier stable while allowing full-PQC
    /// evidence verification to use ML-DSA backends under `pqc-signatures`.
    pub fn verify_exported_chain_with_backend(
        entries: &[LedgerEntryExport],
        public_key: &[u8],
        backend: &impl EvidenceSignatureBackend,
    ) -> Result<(), VerifyError> {
        let mut expected_prev = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            let expected_seq = index as u64;
            if entry.seq != expected_seq {
                return Err(VerifyError::OutOfOrder {
                    index,
                    expected: expected_seq,
                    found: entry.seq,
                });
            }

            if entry.seq == 0 && entry.prev_hash != [0u8; 32] {
                return Err(VerifyError::BadGenesis);
            }
            if entry.prev_hash != expected_prev {
                return Err(VerifyError::BrokenLink { seq: entry.seq });
            }

            let recomputed =
                compute_entry_hash(entry.seq, &entry.prev_hash, &entry.timestamp, &entry.event)
                    .map_err(|_| VerifyError::EntryHashMismatch { seq: entry.seq })?;
            if recomputed != entry.entry_hash {
                return Err(VerifyError::EntryHashMismatch { seq: entry.seq });
            }

            let suite = entry_signature_suite_for_verify(entry)?;
            if suite != backend.suite() {
                return Err(VerifyError::SignatureBackendSuiteMismatch {
                    seq: entry.seq,
                    entry_suite: suite,
                    backend_suite: backend.suite(),
                });
            }

            backend
                .verify_signature(public_key, &entry.entry_hash, &entry.signature.signature)
                .map_err(|err| backend_error_to_verify_error(entry.seq, suite, err))?;

            expected_prev = entry.entry_hash;
        }
        Ok(())
    }
}

fn entry_signature_suite_for_verify(
    entry: &LedgerEntryExport,
) -> Result<SignatureSuite, VerifyError> {
    entry
        .signature
        .validate_shape()
        .map_err(|err| signature_envelope_error_to_verify_error(entry.seq, err))
}

fn backend_error_to_verify_error(
    seq: u64,
    signature_suite: SignatureSuite,
    err: EvidenceSignatureBackendError,
) -> VerifyError {
    match err {
        EvidenceSignatureBackendError::BadPublicKeyLength { .. }
        | EvidenceSignatureBackendError::BadPublicKey => VerifyError::BadSignaturePublicKey {
            seq,
            signature_suite,
        },
        EvidenceSignatureBackendError::BadSignatureLength {
            expected, found, ..
        } => VerifyError::BadSignatureLength {
            seq,
            expected,
            found,
        },
        EvidenceSignatureBackendError::BadSignatureEncoding
        | EvidenceSignatureBackendError::BadSignature => VerifyError::BadSignature { seq },
    }
}

fn entry_signature_suite(
    entry: &LedgerEntryExport,
) -> Result<SignatureSuite, EvidenceBundleVerifyError> {
    entry.signature.validate_shape().map_err(|err| {
        EvidenceBundleVerifyError::ExportedChain(signature_envelope_error_to_verify_error(
            entry.seq, err,
        ))
    })
}

fn signature_envelope_error_to_verify_error(seq: u64, err: SignatureEnvelopeError) -> VerifyError {
    match err {
        SignatureEnvelopeError::UnknownSignatureSuite { algorithm } => {
            VerifyError::UnknownSignatureSuite { seq, algorithm }
        }
        SignatureEnvelopeError::BadSignatureLength {
            expected, found, ..
        } => VerifyError::BadSignatureLength {
            seq,
            expected,
            found,
        },
        SignatureEnvelopeError::UnsupportedLegacySuite { .. } => VerifyError::BadSignature { seq },
    }
}

// ─────────────────────────── internals ─────────────────────────────

/// Canonical pre-image for the entry hash. `bincode` v1 with default
/// options produces a deterministic, length-prefixed big-endian
/// encoding. Locked to the crate's bincode version (1.3 in the
/// workspace).
#[derive(Serialize)]
struct EntryPreimage<'a> {
    seq: u64,
    prev_hash: [u8; 32],
    timestamp: &'a SystemTime,
    event: &'a ConsentEventRecord,
}

fn compute_entry_hash(
    seq: u64,
    prev_hash: &[u8; 32],
    timestamp: &SystemTime,
    event: &ConsentEventRecord,
) -> Result<[u8; 32], LedgerError> {
    let preimage = EntryPreimage {
        seq,
        prev_hash: *prev_hash,
        timestamp,
        event,
    };
    let bytes = bincode::serialize(&preimage)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

// ────────────────────────────── Tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(kind: ConsentKind) -> ConsentEventRecord {
        ConsentEventRecord {
            source_id: [0xAB; 32],
            session_id: Uuid::from_bytes([1u8; 16]),
            request_id: Uuid::from_bytes([2u8; 16]),
            kind,
            scope: "view screen".to_string(),
        }
    }

    fn new_signing_key() -> SigningKey {
        new_signing_key_from_seed(7)
    }

    fn new_signing_key_from_seed(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn consent_kind_stable_names_are_contractual() {
        let cases = [
            (ConsentKind::Request, "consent.requested"),
            (ConsentKind::Approval, "consent.granted"),
            (ConsentKind::Denial, "consent.denied"),
            (ConsentKind::Revocation, "consent.revoked"),
            (ConsentKind::Violation, "consent.protocol_violation"),
            (ConsentKind::AthenaTriage, "admin.athena_triage"),
        ];

        for (kind, expected) in cases {
            assert_eq!(kind.stable_name(), expected);
            assert!(expected.contains('.'));
            assert_eq!(expected, expected.to_ascii_lowercase());
            assert!(!expected.contains(' '));
        }
    }

    #[test]
    fn consent_event_record_uses_stable_kind_name() {
        let event = sample_event(ConsentKind::Approval);
        assert_eq!(event.stable_name(), "consent.granted");
    }

    #[test]
    fn signature_suite_labels_are_contractual() {
        assert_eq!(
            SignatureSuite::Ed25519Rfc8032.stable_label(),
            "ed25519-rfc8032"
        );
        assert_eq!(
            SignatureSuite::MlDsa65Fips204.stable_label(),
            "ml-dsa-65-fips204"
        );
        assert_eq!(
            SignatureSuite::MlDsa87Fips204.stable_label(),
            "ml-dsa-87-fips204"
        );
        assert_eq!(
            SignatureSuite::SlhDsaFips205.stable_label(),
            "slh-dsa-fips205"
        );
        assert!(!SignatureSuite::Ed25519Rfc8032.is_post_quantum());
        assert!(SignatureSuite::MlDsa65Fips204.is_post_quantum());
    }

    #[test]
    fn stable_crypto_labels_are_used_for_json_serialization() {
        assert_eq!(
            serde_json::to_value(SignatureSuite::Ed25519Rfc8032).unwrap(),
            "ed25519-rfc8032"
        );
        assert_eq!(
            serde_json::to_value(SignatureSuite::MlDsa65Fips204).unwrap(),
            "ml-dsa-65-fips204"
        );
        assert_eq!(
            serde_json::to_value(CryptoPolicyProfile::HybridPrePqcV1).unwrap(),
            "hybrid-pre-pqc-v1"
        );
        assert_eq!(
            serde_json::to_value(CryptoPolicyProfile::FullPqcV1).unwrap(),
            "full-pqc-v1"
        );
        assert_eq!(
            serde_json::to_value(DowngradePolicy::ExplicitClassicalSignatureAllowance).unwrap(),
            "explicit-classical-signature-allowance"
        );
        assert_eq!(
            serde_json::to_value(DowngradePolicy::RejectClassicalSignatures).unwrap(),
            "reject-classical-signatures"
        );

        let manifest = serde_json::to_value(CURRENT_EVIDENCE_CRYPTO_MANIFEST).unwrap();
        assert_eq!(manifest["profile"], "hybrid-pre-pqc-v1");
        assert_eq!(manifest["transcript_signature"], "ed25519-rfc8032");
        assert_eq!(manifest["ledger_signature"], "ed25519-rfc8032");
        assert_eq!(
            manifest["downgrade_policy"],
            "explicit-classical-signature-allowance"
        );
    }

    #[test]
    fn stable_crypto_labels_are_used_for_json_deserialization() {
        assert_eq!(
            serde_json::from_str::<SignatureSuite>(r#""ml-dsa-65-fips204""#).unwrap(),
            SignatureSuite::MlDsa65Fips204
        );
        assert_eq!(
            serde_json::from_str::<CryptoPolicyProfile>(r#""full-pqc-v1""#).unwrap(),
            CryptoPolicyProfile::FullPqcV1
        );
        assert_eq!(
            serde_json::from_str::<DowngradePolicy>(r#""reject-classical-signatures""#).unwrap(),
            DowngradePolicy::RejectClassicalSignatures
        );
    }

    #[test]
    fn evidence_public_key_binding_computes_and_validates_fingerprint() {
        let signing_key = new_signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let binding = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
        let backend = Ed25519EvidenceSignatureBackend;

        assert_eq!(binding.schema, EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA);
        assert_eq!(binding.signature_suite, SignatureSuite::Ed25519Rfc8032);
        assert_eq!(binding.public_key.len(), 32);
        assert_eq!(
            binding.public_key_fingerprint,
            compute_evidence_public_key_fingerprint(&binding.public_key)
        );
        binding
            .validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend)
            .unwrap();
    }

    #[test]
    fn evidence_public_key_binding_rejects_tampered_fingerprint() {
        let signing_key = new_signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let mut binding = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
        binding.public_key_fingerprint[0] ^= 0x80;
        let backend = Ed25519EvidenceSignatureBackend;

        assert_eq!(
            binding
                .validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend,),
            Err(EvidencePublicKeyBindingError::PublicKeyFingerprintMismatch)
        );
    }

    #[test]
    fn evidence_public_key_binding_rejects_bad_suite_and_length() {
        let backend = Ed25519EvidenceSignatureBackend;
        let bad_suite =
            EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, vec![0u8; 1952]);
        assert_eq!(
            bad_suite
                .validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend,),
            Err(
                EvidencePublicKeyBindingError::SignatureSuiteManifestMismatch {
                    manifest_suite: SignatureSuite::Ed25519Rfc8032,
                    binding_suite: SignatureSuite::MlDsa65Fips204,
                }
            )
        );

        let bad_length =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, vec![0u8; 31]);
        assert_eq!(
            bad_length
                .validate_against_manifest_and_backend(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &backend,),
            Err(EvidencePublicKeyBindingError::BadPublicKeyLength {
                signature_suite: SignatureSuite::Ed25519Rfc8032,
                expected: 32,
                found: 31,
            })
        );
    }

    #[test]
    fn signature_envelope_uses_stable_algorithm_label() {
        let envelope = SignatureEnvelope::ed25519([0xA5; 64]);
        assert_eq!(envelope.algorithm, "ed25519-rfc8032");
        assert_eq!(envelope.signature.len(), 64);
        assert_eq!(envelope.suite().unwrap(), SignatureSuite::Ed25519Rfc8032);
        assert!(!envelope.is_post_quantum().unwrap());
        assert_eq!(envelope.to_legacy_ed25519().unwrap(), [0xA5; 64]);
    }

    #[test]
    fn pq_signature_envelope_shape_is_supported_before_verification_backend() {
        let envelope = SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, vec![0x5A; 3309]);
        assert_eq!(envelope.algorithm, "ml-dsa-65-fips204");
        assert_eq!(envelope.suite().unwrap(), SignatureSuite::MlDsa65Fips204);
        assert!(envelope.is_post_quantum().unwrap());
        assert!(matches!(
            envelope.to_legacy_ed25519(),
            Err(SignatureEnvelopeError::UnsupportedLegacySuite { .. })
        ));
    }

    #[test]
    fn ed25519_evidence_signature_backend_verifies_current_entries() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        let entry = chain.append(sample_event(ConsentKind::Request)).unwrap();
        let backend = Ed25519EvidenceSignatureBackend;

        assert_eq!(backend.suite(), SignatureSuite::Ed25519Rfc8032);
        backend
            .verify_signature(&pk.to_bytes(), &entry.entry_hash, &entry.signature)
            .expect("current Ed25519 backend should verify ledger entry signatures");
    }

    #[test]
    fn ed25519_evidence_signature_backend_rejects_bad_lengths() {
        let backend = Ed25519EvidenceSignatureBackend;

        assert!(matches!(
            backend.verify_signature(&[0u8; 31], b"message", &[0u8; 64]),
            Err(EvidenceSignatureBackendError::BadPublicKeyLength {
                expected: 32,
                found: 31
            })
        ));
        assert!(matches!(
            backend.verify_signature(&[0u8; 32], b"message", &[0u8; 63]),
            Err(EvidenceSignatureBackendError::BadSignatureLength {
                expected: 64,
                found: 63
            })
        ));
    }

    #[cfg(feature = "pqc-signatures")]
    #[test]
    fn ml_dsa_65_backend_verifies_real_signature_bytes() {
        use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};

        let seed = ml_dsa::B32::default();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let message = b"xenia-ledger ml-dsa-65 evidence backend smoke";
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.encode();
        let signature_bytes = signature.encode();
        let backend = MlDsa65EvidenceSignatureBackend;

        backend
            .verify_signature(public_key_bytes.as_ref(), message, signature_bytes.as_ref())
            .unwrap();
    }

    #[cfg(feature = "pqc-signatures")]
    #[test]
    fn ml_dsa_65_backend_rejects_tampered_signature() {
        use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};

        let seed = ml_dsa::B32::default();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let message = b"xenia-ledger ml-dsa tamper test";
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.encode();
        let mut signature_bytes = signature.encode().to_vec();
        signature_bytes[0] ^= 0x80;
        let backend = MlDsa65EvidenceSignatureBackend;

        assert_eq!(
            backend.verify_signature(public_key_bytes.as_ref(), message, &signature_bytes),
            Err(EvidenceSignatureBackendError::BadSignature)
        );
    }

    #[cfg(feature = "pqc-signatures")]
    #[test]
    fn full_pqc_evidence_bundle_can_verify_with_ml_dsa_backend() {
        use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};

        let seed = ml_dsa::B32::default();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.encode();
        let timestamp = SystemTime::UNIX_EPOCH;
        let event = sample_event(ConsentKind::Approval);
        let entry_hash = compute_entry_hash(0, &[0u8; 32], &timestamp, &event).unwrap();
        let signature = signing_key.sign(&entry_hash).encode();
        let entry = LedgerEntryExport {
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp,
            event,
            entry_hash,
            signature: SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, {
                let signature_bytes: &[u8] = signature.as_ref();
                signature_bytes.to_vec()
            }),
        };
        let manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        let backend = MlDsa65EvidenceSignatureBackend;

        Verifier::verify_evidence_bundle_with_backend(
            manifest,
            &[entry],
            public_key_bytes.as_ref(),
            &backend,
        )
        .unwrap();
    }

    #[cfg(feature = "pqc-signatures")]
    #[test]
    fn ml_dsa_65_evidence_chain_exports_real_pq_signed_entries() {
        use ml_dsa::{MlDsa65, SigningKey};

        let seed = ml_dsa::B32::default();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let mut chain = new_ml_dsa_65_evidence_chain(signing_key);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let entries = chain.export_entries();
        assert_eq!(chain.len(), 2);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[1].seq, 1);
        assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
        assert_eq!(
            entries[0].signature.suite().unwrap(),
            SignatureSuite::MlDsa65Fips204
        );
        assert_eq!(entries[0].signature.signature.len(), 3309);

        let manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        let backend = MlDsa65EvidenceSignatureBackend;
        Verifier::verify_evidence_bundle_with_backend(
            manifest,
            &entries,
            &chain.public_key_bytes(),
            &backend,
        )
        .unwrap();
    }

    #[cfg(feature = "pqc-signatures")]
    #[test]
    fn ml_dsa_65_evidence_bundle_can_verify_with_public_key_binding() {
        use ml_dsa::{MlDsa65, SigningKey};

        let seed = ml_dsa::B32::default();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let mut chain = new_ml_dsa_65_evidence_chain(signing_key);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let entries = chain.export_entries();
        let manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, chain.public_key_bytes());
        let backend = MlDsa65EvidenceSignatureBackend;

        assert_eq!(key_binding.public_key.len(), 1952);
        assert_eq!(
            key_binding.public_key_fingerprint,
            compute_evidence_public_key_fingerprint(&key_binding.public_key)
        );
        Verifier::verify_evidence_bundle_with_key_binding(
            manifest,
            &entries,
            &key_binding,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn current_evidence_profile_is_explicitly_hybrid_pre_pqc() {
        let profile = Verifier::evidence_profile();
        assert_eq!(profile.schema, "xenia-ledger-evidence-profile-v1");
        assert_eq!(profile.hash_chain, "blake3-256");
        assert_eq!(profile.ledger_signature.stable_label(), "ed25519-rfc8032");
        assert_eq!(profile.policy_profile, "hybrid-pre-pqc-v1");
        assert!(!profile.ledger_signature_is_post_quantum());
    }

    #[test]
    fn current_evidence_manifest_allows_hybrid_pre_pqc_only_explicitly() {
        let manifest = Verifier::evidence_crypto_manifest();
        assert_eq!(manifest.schema, "xenia-evidence-crypto-manifest-v1");
        assert_eq!(manifest.profile.stable_label(), "hybrid-pre-pqc-v1");
        assert_eq!(manifest.kem, "ml-kem-768-fips203");
        assert_eq!(
            manifest.transcript_signature.stable_label(),
            "ed25519-rfc8032"
        );
        assert_eq!(manifest.ledger_signature.stable_label(), "ed25519-rfc8032");
        assert_eq!(
            manifest.downgrade_policy.stable_label(),
            "explicit-classical-signature-allowance"
        );
        assert!(!manifest.signatures_are_post_quantum());
        Verifier::verify_evidence_crypto_manifest(manifest).unwrap();
    }

    #[test]
    fn hybrid_pre_pqc_manifest_rejects_pq_signature_surfaces() {
        let invalid_transcript = EvidenceCryptoManifest {
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        assert_eq!(
            Verifier::verify_evidence_crypto_manifest(invalid_transcript),
            Err(EvidencePolicyError::PqTranscriptSignatureInHybridPrePqc)
        );

        let invalid_ledger = EvidenceCryptoManifest {
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        assert_eq!(
            Verifier::verify_evidence_crypto_manifest(invalid_ledger),
            Err(EvidencePolicyError::PqLedgerSignatureInHybridPrePqc)
        );
    }

    #[test]
    fn hybrid_pre_pqc_manifest_requires_explicit_classical_allowance() {
        let invalid = EvidenceCryptoManifest {
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };

        assert_eq!(
            Verifier::verify_evidence_crypto_manifest(invalid),
            Err(EvidencePolicyError::HybridPrePqcRequiresExplicitClassicalAllowance)
        );
    }

    #[test]
    fn full_pqc_manifest_rejects_classical_signature_surfaces() {
        let invalid = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };

        assert_eq!(
            Verifier::verify_evidence_crypto_manifest(invalid),
            Err(EvidencePolicyError::ClassicalTranscriptSignatureInFullPqc)
        );
    }

    #[test]
    fn full_pqc_manifest_requires_reject_classical_downgrade_policy() {
        let invalid = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::ExplicitClassicalSignatureAllowance,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };

        assert_eq!(
            Verifier::verify_evidence_crypto_manifest(invalid),
            Err(EvidencePolicyError::DowngradePolicyAllowsClassicalInFullPqc)
        );
    }

    #[test]
    fn full_pqc_manifest_accepts_only_pq_signatures_and_reject_policy() {
        let valid = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };

        assert!(valid.signatures_are_post_quantum());
        Verifier::verify_evidence_crypto_manifest(valid).unwrap();
    }

    #[test]
    fn empty_chain_verifies_vacuously() {
        let sk = new_signing_key();
        let chain = Chain::new(sk.clone());
        let pk = sk.verifying_key();
        Verifier::verify_chain(chain.iter().cloned().collect::<Vec<_>>().as_slice(), &pk).unwrap();
    }

    #[test]
    fn genesis_entry_has_zero_prev_hash_and_seq_zero() {
        let sk = new_signing_key();
        let mut chain = Chain::new(sk);
        let entry = chain.append(sample_event(ConsentKind::Request)).unwrap();
        assert_eq!(entry.seq, 0);
        assert_eq!(entry.prev_hash, [0u8; 32]);
    }

    #[test]
    fn chain_of_five_entries_links_and_verifies() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);

        for kind in [
            ConsentKind::Request,
            ConsentKind::Approval,
            ConsentKind::Revocation,
            ConsentKind::Request,
            ConsentKind::Denial,
        ] {
            chain.append(sample_event(kind)).unwrap();
        }

        let entries: Vec<_> = chain.iter().cloned().collect();
        assert_eq!(entries.len(), 5);

        // Sequence monotone.
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq, i as u64);
        }

        // Hash link: each prev_hash matches previous entry_hash.
        for w in entries.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].entry_hash);
        }

        Verifier::verify_chain(&entries, &pk).unwrap();
    }

    #[test]
    fn exported_entries_verify_with_signature_envelopes() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let exported = chain.export_entries();
        assert_eq!(exported.len(), 2);
        assert_eq!(exported[0].signature.algorithm, "ed25519-rfc8032");
        assert_eq!(exported[0].signature.signature.len(), 64);
        Verifier::verify_exported_chain(&exported, &pk).unwrap();
    }

    #[test]
    fn exported_entry_round_trips_to_legacy_shape() {
        let sk = new_signing_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let legacy = chain.iter().next().unwrap().clone();
        let exported = legacy.to_export_entry();
        let restored = exported.to_legacy_entry().unwrap();
        assert_eq!(restored, legacy);
    }

    #[test]
    fn current_export_verifier_rejects_pq_signature_until_backend_lands() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let mut exported = chain.export_entries();
        exported[0].signature =
            SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, vec![0x42; 3309]);

        assert_eq!(
            Verifier::verify_exported_chain(&exported, &pk),
            Err(VerifyError::UnsupportedSignatureSuite {
                seq: 0,
                signature_suite: SignatureSuite::MlDsa65Fips204,
            })
        );
    }

    #[test]
    fn explicit_backend_rejects_entry_suite_mismatch() {
        let sk = new_signing_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        let mut exported = chain.export_entries();
        exported[0].signature =
            SignatureEnvelope::new(SignatureSuite::MlDsa65Fips204, vec![0x42; 3309]);

        assert_eq!(
            Verifier::verify_exported_chain_with_backend(
                &exported,
                &[0u8; 32],
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(VerifyError::SignatureBackendSuiteMismatch {
                seq: 0,
                entry_suite: SignatureSuite::MlDsa65Fips204,
                backend_suite: SignatureSuite::Ed25519Rfc8032,
            })
        );
    }

    #[test]
    fn current_export_verifier_rejects_unknown_signature_label() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let mut exported = chain.export_entries();
        exported[0].signature = SignatureEnvelope {
            algorithm: "unknown-sig-v1".to_string(),
            signature: vec![0; 64],
        };

        assert_eq!(
            Verifier::verify_exported_chain(&exported, &pk),
            Err(VerifyError::UnknownSignatureSuite {
                seq: 0,
                algorithm: "unknown-sig-v1".to_string(),
            })
        );
    }

    #[test]
    fn current_export_verifier_rejects_bad_ed25519_length() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let mut exported = chain.export_entries();
        exported[0].signature = SignatureEnvelope::new(SignatureSuite::Ed25519Rfc8032, vec![0; 63]);

        assert_eq!(
            Verifier::verify_exported_chain(&exported, &pk),
            Err(VerifyError::BadSignatureLength {
                seq: 0,
                expected: 64,
                found: 63,
            })
        );
    }

    #[test]
    fn tampering_with_event_kind_breaks_entry_hash() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        entries[0].event.kind = ConsentKind::Denial; // flip Approval to Denial after the fact

        match Verifier::verify_chain(&entries, &pk) {
            Err(VerifyError::EntryHashMismatch { seq: 0 }) => {}
            other => panic!("expected EntryHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampering_with_entry_hash_breaks_signature() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        // Mutate entry_hash to something "plausibly valid" — recompute
        // for a fake event to keep EntryHashMismatch from firing first.
        let fake_event = sample_event(ConsentKind::Denial);
        entries[0].event = fake_event.clone();
        entries[0].entry_hash = compute_entry_hash(
            entries[0].seq,
            &entries[0].prev_hash,
            &entries[0].timestamp,
            &fake_event,
        )
        .unwrap();

        // entry_hash now recomputes correctly, but the signature was
        // over the ORIGINAL entry_hash, so verification fails on the
        // signature step.
        match Verifier::verify_chain(&entries, &pk) {
            Err(VerifyError::BadSignature { seq: 0 }) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn reordering_entries_breaks_hash_link() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        entries.swap(0, 1); // reorder

        let err = Verifier::verify_chain(&entries, &pk).unwrap_err();
        // The OutOfOrder check fires before BrokenLink because sequence
        // numbers are checked first at each index.
        assert!(matches!(err, VerifyError::OutOfOrder { .. }));
    }

    #[test]
    fn wrong_public_key_rejects_valid_chain() {
        let sk = new_signing_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let entries: Vec<_> = chain.iter().cloned().collect();
        let valid_pk = new_signing_key().verifying_key();
        let wrong_pk = new_signing_key_from_seed(8).verifying_key();
        assert_ne!(valid_pk.to_bytes(), wrong_pk.to_bytes());

        match Verifier::verify_chain(&entries, &wrong_pk) {
            Err(VerifyError::BadSignature { seq: 0 }) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn rehydrated_chain_can_continue_appending() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();

        let entries_out = {
            let mut chain = Chain::new(sk.clone());
            chain.append(sample_event(ConsentKind::Request)).unwrap();
            chain.append(sample_event(ConsentKind::Approval)).unwrap();
            chain.into_entries()
        };

        let mut chain = Chain::from_entries(entries_out, sk);
        chain.append(sample_event(ConsentKind::Revocation)).unwrap();

        let entries: Vec<_> = chain.iter().cloned().collect();
        assert_eq!(entries.len(), 3);
        Verifier::verify_chain(&entries, &pk).unwrap();
    }

    #[test]
    fn forged_genesis_with_nonzero_prev_hash_is_rejected() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        // Forge a nonzero prev_hash on genesis. We have to also
        // recompute entry_hash and re-sign to get past those checks.
        entries[0].prev_hash = [0xFFu8; 32];
        entries[0].entry_hash = compute_entry_hash(
            entries[0].seq,
            &entries[0].prev_hash,
            &entries[0].timestamp,
            &entries[0].event,
        )
        .unwrap();
        entries[0].signature = sk.sign(&entries[0].entry_hash).to_bytes();

        match Verifier::verify_chain(&entries, &pk) {
            Err(VerifyError::BadGenesis) => {}
            other => panic!("expected BadGenesis, got {other:?}"),
        }
    }

    #[test]
    fn evidence_bundle_verification_accepts_current_manifest_and_exported_chain() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let exported = chain.export_entries();

        Verifier::verify_evidence_bundle(CURRENT_EVIDENCE_CRYPTO_MANIFEST, &exported, &pk).unwrap();
    }

    #[test]
    fn evidence_bundle_verification_accepts_public_key_binding() {
        let sk = SigningKey::from_bytes(&[52u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let exported = chain.export_entries();
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
        let backend = Ed25519EvidenceSignatureBackend;

        Verifier::verify_evidence_bundle_with_key_binding(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &exported,
            &key_binding,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn evidence_bundle_verification_rejects_tampered_public_key_binding() {
        let sk = SigningKey::from_bytes(&[53u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let mut key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
        key_binding.public_key_fingerprint[0] ^= 0x40;
        let backend = Ed25519EvidenceSignatureBackend;

        assert_eq!(
            Verifier::verify_evidence_bundle_with_key_binding(
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &exported,
                &key_binding,
                &backend,
            ),
            Err(EvidenceBundleVerifyError::PublicKeyBinding(
                EvidencePublicKeyBindingError::PublicKeyFingerprintMismatch
            ))
        );
    }

    #[test]
    fn evidence_bundle_verification_rejects_manifest_backend_suite_mismatch() {
        let sk = SigningKey::from_bytes(&[43u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let overstated_manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };

        assert_eq!(
            Verifier::verify_evidence_bundle(overstated_manifest, &exported, &pk),
            Err(EvidenceBundleVerifyError::LedgerBackendSuiteMismatch {
                manifest_suite: SignatureSuite::MlDsa65Fips204,
                backend_suite: SignatureSuite::Ed25519Rfc8032,
            })
        );
    }

    #[test]
    fn evidence_bundle_verification_rejects_manifest_policy_before_chain_trust() {
        let sk = SigningKey::from_bytes(&[44u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let invalid_full_pqc_manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };

        assert_eq!(
            Verifier::verify_evidence_bundle(invalid_full_pqc_manifest, &exported, &pk),
            Err(EvidenceBundleVerifyError::ManifestPolicy(
                EvidencePolicyError::ClassicalTranscriptSignatureInFullPqc
            ))
        );
    }

    #[test]
    fn session_transcript_binding_uses_stable_hash_and_labels() {
        let session_id = Uuid::from_bytes([1u8; 16]);
        let binding = SessionTranscriptBinding::new(
            session_id,
            b"canonical xenia handshake transcript v1",
            SignatureSuite::Ed25519Rfc8032,
        );

        assert_eq!(binding.schema, SESSION_TRANSCRIPT_BINDING_SCHEMA);
        assert_eq!(
            binding.transcript_hash_algorithm,
            SESSION_TRANSCRIPT_HASH_ALGORITHM
        );
        assert_eq!(binding.session_id, session_id);
        assert_eq!(binding.transcript_hash.len(), 32);
        assert_ne!(binding.transcript_hash, [0u8; 32]);
        binding
            .validate_against_manifest(CURRENT_EVIDENCE_CRYPTO_MANIFEST)
            .unwrap();
    }

    #[test]
    fn signed_transcript_bound_evidence_bundle_accepts_current_single_session_export() {
        let sk = SigningKey::from_bytes(&[55u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let exported = chain.export_entries();
        let binding = SessionTranscriptBinding::new(
            exported[0].event.session_id,
            b"canonical xenia signed handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
        let backend = Ed25519EvidenceSignatureBackend;

        Verifier::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &transcript_signature,
            &key_binding,
            &exported,
            &key_binding,
            &backend,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn signed_transcript_bound_evidence_bundle_rejects_tampered_transcript_signature() {
        let sk = SigningKey::from_bytes(&[56u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let binding = SessionTranscriptBinding::new(
            exported[0].event.session_id,
            b"canonical xenia signed handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let mut transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
        transcript_signature.signature.signature[0] ^= 0x80;
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
        let backend = Ed25519EvidenceSignatureBackend;

        assert!(matches!(
            Verifier::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &binding,
                &transcript_signature,
                &key_binding,
                &exported,
                &key_binding,
                &backend,
                &backend,
            ),
            Err(EvidenceBundleVerifyError::TranscriptSignatureBackend {
                signature_suite: SignatureSuite::Ed25519Rfc8032,
                source: EvidenceSignatureBackendError::BadSignature,
            })
        ));
    }

    #[test]
    fn unsigned_transcript_bound_full_pqc_bundle_is_rejected() {
        let sk = SigningKey::from_bytes(&[57u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        let binding = SessionTranscriptBinding::new(
            exported[0].event.session_id,
            b"canonical xenia unsigned full-pqc transcript",
            manifest.transcript_signature,
        );

        assert_eq!(
            Verifier::verify_transcript_bound_evidence_bundle(manifest, &binding, &exported, &pk,),
            Err(EvidenceBundleVerifyError::MissingTranscriptSignatureInFullPqc)
        );
    }

    #[cfg(feature = "pqc-signatures")]
    #[test]
    fn full_pqc_signed_transcript_bound_bundle_can_verify_with_ml_dsa() {
        use ml_dsa::{MlDsa65, SigningKey};

        let seed = ml_dsa::B32::default();
        let ledger_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let transcript_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let mut chain = new_ml_dsa_65_evidence_chain(ledger_signing_key);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let entries = chain.export_entries();
        let manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        let binding = SessionTranscriptBinding::new(
            entries[0].event.session_id,
            b"canonical xenia full-pqc signed handshake transcript v1",
            manifest.transcript_signature,
        );
        let transcript_signature =
            sign_session_transcript_binding_ml_dsa_65(&binding, &transcript_signing_key);
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, chain.public_key_bytes());
        let backend = MlDsa65EvidenceSignatureBackend;

        Verifier::verify_signed_transcript_bound_evidence_bundle_with_key_bindings(
            manifest,
            &binding,
            &transcript_signature,
            &key_binding,
            &entries,
            &key_binding,
            &backend,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn transcript_bound_evidence_bundle_accepts_current_single_session_export() {
        let sk = SigningKey::from_bytes(&[45u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let exported = chain.export_entries();
        let binding = SessionTranscriptBinding::new(
            exported[0].event.session_id,
            b"canonical xenia handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );

        Verifier::verify_transcript_bound_evidence_bundle(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &exported,
            &pk,
        )
        .unwrap();
    }

    #[test]
    fn transcript_bound_evidence_bundle_rejects_empty_ledger() {
        let sk = SigningKey::from_bytes(&[46u8; 32]);
        let pk = sk.verifying_key();
        let binding = SessionTranscriptBinding::new(
            Uuid::from_bytes([1u8; 16]),
            b"canonical xenia handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );

        assert_eq!(
            Verifier::verify_transcript_bound_evidence_bundle(
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &binding,
                &[],
                &pk,
            ),
            Err(EvidenceBundleVerifyError::EmptyTranscriptBoundBundle)
        );
    }

    #[test]
    fn transcript_bound_evidence_bundle_rejects_session_mismatch_before_chain_trust() {
        let sk = SigningKey::from_bytes(&[47u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let original_session = exported[0].event.session_id;
        let binding_session = Uuid::from_bytes([9u8; 16]);
        let binding = SessionTranscriptBinding::new(
            binding_session,
            b"canonical xenia handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );

        assert_eq!(
            Verifier::verify_transcript_bound_evidence_bundle(
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &binding,
                &exported,
                &pk,
            ),
            Err(EvidenceBundleVerifyError::TranscriptSessionMismatch {
                seq: 0,
                binding_session_id: binding_session,
                entry_session_id: original_session,
            })
        );
    }

    #[test]
    fn transcript_binding_rejects_manifest_signature_mismatch() {
        let binding = SessionTranscriptBinding::new(
            Uuid::from_bytes([1u8; 16]),
            b"canonical xenia handshake transcript v1",
            SignatureSuite::MlDsa65Fips204,
        );

        assert_eq!(
            binding.validate_against_manifest(CURRENT_EVIDENCE_CRYPTO_MANIFEST),
            Err(TranscriptBindingError::TranscriptSignatureSuiteMismatch {
                manifest_suite: SignatureSuite::Ed25519Rfc8032,
                binding_suite: SignatureSuite::MlDsa65Fips204,
            })
        );
    }

    #[test]
    fn transcript_binding_rejects_all_zero_hash_placeholder() {
        let binding = SessionTranscriptBinding::from_hash(
            Uuid::from_bytes([1u8; 16]),
            [0u8; 32],
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );

        assert_eq!(
            binding.validate_against_manifest(CURRENT_EVIDENCE_CRYPTO_MANIFEST),
            Err(TranscriptBindingError::EmptyTranscriptHash)
        );
    }

    #[test]
    fn sealed_signed_transcript_bound_bundle_accepts_current_single_session_export() {
        let sk = SigningKey::from_bytes(&[58u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let exported = chain.export_entries();
        let binding = SessionTranscriptBinding::new(
            exported[0].event.session_id,
            b"canonical xenia sealed signed handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
        let bundle_seal = sign_evidence_bundle_seal_ed25519(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &key_binding,
            &exported,
            &key_binding,
            &sk,
        )
        .unwrap();
        let backend = Ed25519EvidenceSignatureBackend;

        Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &transcript_signature,
            &bundle_seal,
            &key_binding,
            &exported,
            &key_binding,
            &backend,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn sealed_signed_transcript_bound_bundle_rejects_tampered_seal_fingerprint() {
        let sk = SigningKey::from_bytes(&[59u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let binding = SessionTranscriptBinding::new(
            exported[0].event.session_id,
            b"canonical xenia sealed signed handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
        let mut bundle_seal = sign_evidence_bundle_seal_ed25519(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &key_binding,
            &exported,
            &key_binding,
            &sk,
        )
        .unwrap();
        bundle_seal.ledger_public_key_fingerprint[0] ^= 0x01;
        let backend = Ed25519EvidenceSignatureBackend;

        assert_eq!(
            Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &binding,
                &transcript_signature,
                &bundle_seal,
                &key_binding,
                &exported,
                &key_binding,
                &backend,
                &backend,
            ),
            Err(EvidenceBundleVerifyError::BundleSeal(
                EvidenceBundleSealError::LedgerPublicKeyFingerprintMismatch
            ))
        );
    }

    #[test]
    fn sealed_signed_transcript_bound_bundle_rejects_tampered_seal_signature() {
        let sk = SigningKey::from_bytes(&[60u8; 32]);
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let exported = chain.export_entries();
        let binding = SessionTranscriptBinding::new(
            exported[0].event.session_id,
            b"canonical xenia sealed signed handshake transcript v1",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        );
        let transcript_signature = sign_session_transcript_binding_ed25519(&binding, &sk);
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, pk.to_bytes().to_vec());
        let mut bundle_seal = sign_evidence_bundle_seal_ed25519(
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &binding,
            &key_binding,
            &exported,
            &key_binding,
            &sk,
        )
        .unwrap();
        bundle_seal.signature.signature[0] ^= 0x80;
        let backend = Ed25519EvidenceSignatureBackend;

        assert!(matches!(
            Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &binding,
                &transcript_signature,
                &bundle_seal,
                &key_binding,
                &exported,
                &key_binding,
                &backend,
                &backend,
            ),
            Err(EvidenceBundleVerifyError::BundleSealSignatureBackend {
                signature_suite: SignatureSuite::Ed25519Rfc8032,
                source: EvidenceSignatureBackendError::BadSignature,
            })
        ));
    }

    #[cfg(feature = "pqc-signatures")]
    #[test]
    fn full_pqc_sealed_bundle_can_verify_with_ml_dsa() {
        use ml_dsa::{MlDsa65, SigningKey};

        let seed = ml_dsa::B32::default();
        let ledger_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let transcript_signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let mut chain = new_ml_dsa_65_evidence_chain(ledger_signing_key);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let entries = chain.export_entries();
        let manifest = EvidenceCryptoManifest {
            profile: CryptoPolicyProfile::FullPqcV1,
            transcript_signature: SignatureSuite::MlDsa65Fips204,
            ledger_signature: SignatureSuite::MlDsa65Fips204,
            downgrade_policy: DowngradePolicy::RejectClassicalSignatures,
            ..CURRENT_EVIDENCE_CRYPTO_MANIFEST
        };
        let binding = SessionTranscriptBinding::new(
            entries[0].event.session_id,
            b"canonical xenia full-pqc sealed signed handshake transcript v1",
            manifest.transcript_signature,
        );
        let transcript_signature =
            sign_session_transcript_binding_ml_dsa_65(&binding, &transcript_signing_key);
        let key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::MlDsa65Fips204, chain.public_key_bytes());
        let bundle_seal = sign_evidence_bundle_seal_ml_dsa_65(
            manifest,
            &binding,
            &key_binding,
            &entries,
            &key_binding,
            &transcript_signing_key,
        )
        .unwrap();
        let backend = MlDsa65EvidenceSignatureBackend;

        Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(
            manifest,
            &binding,
            &transcript_signature,
            &bundle_seal,
            &key_binding,
            &entries,
            &key_binding,
            &backend,
            &backend,
        )
        .unwrap();
    }
}
