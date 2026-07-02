// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! # xenia-handshake — ML-KEM session establishment
//!
//! Combines ML-KEM-768 key encapsulation with classical Ed25519 identity
//! verification to derive a hybrid root key, then derives transcript-bound
//! session keys suitable for ChaCha20-Poly1305 AEAD sealing of the xenia-wire
//! envelope.
//!
//! This crate is **not at the final PQ profile yet**: Ed25519 remains the
//! authentication signature. ML-DSA/SLH-DSA transcript authentication is
//! tracked in `docs/crypto/FULL_PQC_MIGRATION_PLAN.md`.
//!
//! Fresh implementation against RustCrypto primitives (`ml-kem`,
//! `ed25519-dalek`, `hkdf`, `sha2`). API shape aligned with Symthaea's
//! `swarm/pqc_handshake.rs` so the migration is mechanical, but zero
//! cross-repo coupling.
//!
//! ## Protocol
//!
//! ```text
//! Phase 1 — Identity exchange
//!   Both sides publish their Ed25519 verifying keys and fresh nonces.
//!
//! Phase 2 — KEM encapsulation
//!   Initiator receives responder's ML-KEM-768 public key.
//!   Initiator calls `encapsulate()`: generates shared secret, produces
//!   ciphertext, derives session key.
//!   Responder calls `decapsulate()`: recovers shared secret from the
//!   ciphertext, derives the same session key.
//!
//! Phase 3 — Root key derivation
//!   root_key = HKDF-SHA256(
//!       ikm  = classical_nonce || kem_shared_secret,
//!       salt = b"xenia-handshake-v1",
//!       info = b"xenia-session-key",
//!   )
//!
//! Phase 4 — Transcript-bound key schedule
//!   lane_key = HKDF-SHA256(
//!       ikm  = root_key,
//!       salt = b"xenia-session-key-schedule-v1",
//!       info = lane_label || b":" || canonical_transcript_hash,
//!   )
//! ```
//!
//! Both classical authentication (Ed25519 signature) and PQ key establishment
//! (ML-KEM) must succeed. ML-KEM mitigates passive harvest-now-decrypt-later
//! risk for session key establishment, but Ed25519 is still quantum-vulnerable
//! for active impersonation until transcript signatures move to ML-DSA/SLH-DSA.
//!
//! ## References
//! - NIST FIPS 203 (2024) — ML-KEM specification
//! - Bindel et al. (2019) — hybrid key exchange in TLS 1.3
//! - RFC 8032 — Ed25519 (current classical authentication layer)
//! - Full-PQC migration plan — `docs/crypto/FULL_PQC_MIGRATION_PLAN.md`

use std::collections::HashMap;
use std::time::SystemTime;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::{
    MlKem768, TryKeyInit,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    ml_kem_768::{
        Ciphertext as MlKemCiphertext, DecapsulationKey as MlKemDk, EncapsulationKey as MlKemEk,
    },
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// ML-KEM-768 encapsulation-key (public key) size in bytes (FIPS 203).
pub const ML_KEM_768_PK_LEN: usize = 1184;

/// ML-KEM-768 ciphertext size in bytes (FIPS 203).
pub const ML_KEM_768_CT_LEN: usize = 1088;

/// HKDF-SHA-256 salt (domain separator, v1 of this protocol).
const HKDF_SALT: &[u8] = b"xenia-handshake-v1";

/// HKDF-SHA-256 info (key-purpose label).
const HKDF_INFO: &[u8] = b"xenia-session-key";

/// Machine-readable KEM label for evidence manifests.
pub const KEM_SUITE_LABEL: &str = "ml-kem-768-fips203";

/// Machine-readable transcript-authentication label for the current implementation.
pub const TRANSCRIPT_SIGNATURE_SUITE_LABEL: &str = "ed25519-rfc8032";

/// Machine-readable KDF label for the current implementation.
pub const KDF_SUITE_LABEL: &str = "hkdf-sha256";

/// Machine-readable evidence profile represented by this crate today.
pub const HANDSHAKE_POLICY_PROFILE: &str = "hybrid-pre-pqc-v1";

/// Stable schema label for canonical handshake transcripts.
pub const HANDSHAKE_TRANSCRIPT_SCHEMA: &str = "xenia-handshake-transcript-v1";

/// Hash algorithm used for canonical handshake transcript hashes.
pub const HANDSHAKE_TRANSCRIPT_HASH_ALGORITHM: &str = "blake3-256";

/// HKDF-SHA-256 salt for transcript-bound session-lane derivation.
pub const SESSION_KEY_SCHEDULE_SCHEMA: &str = "xenia-session-key-schedule-v1";

/// Default AEAD key label used by the current xenia-wire session API.
pub const SESSION_AEAD_KEY_LABEL: &[u8] = b"xenia/session/aead";

/// Control-lane key label reserved for future per-lane sealing.
pub const SESSION_CONTROL_KEY_LABEL: &[u8] = b"xenia/session/control";

/// Video-lane key label reserved for future per-lane sealing.
pub const SESSION_VIDEO_KEY_LABEL: &[u8] = b"xenia/session/video";

/// Audio-lane key label reserved for future per-lane sealing.
pub const SESSION_AUDIO_KEY_LABEL: &[u8] = b"xenia/session/audio";

/// Telemetry-lane key label reserved for future per-lane sealing.
pub const SESSION_TELEMETRY_KEY_LABEL: &[u8] = b"xenia/session/telemetry";

/// Rekey-lane key label reserved for future rekey authentication.
pub const SESSION_REKEY_KEY_LABEL: &[u8] = b"xenia/session/rekey";

/// Post-handshake negotiated context key label.
pub const SESSION_CONTEXT_KEY_LABEL: &[u8] = b"xenia/session/context";

/// Stable evidence-profile summary for the current handshake implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HandshakeEvidenceProfile {
    /// Schema label for this profile structure.
    pub schema: &'static str,
    /// Key-establishment suite.
    pub kem: &'static str,
    /// Signature suite authenticating the transcript today.
    pub transcript_signature: &'static str,
    /// Key derivation suite.
    pub kdf: &'static str,
    /// Policy class represented by the current implementation.
    pub policy_profile: &'static str,
    /// Whether the current transcript signature is post-quantum.
    pub transcript_signature_post_quantum: bool,
}

/// Evidence profile for the current handshake implementation.
pub const CURRENT_HANDSHAKE_EVIDENCE_PROFILE: HandshakeEvidenceProfile = HandshakeEvidenceProfile {
    schema: "xenia-handshake-evidence-profile-v1",
    kem: KEM_SUITE_LABEL,
    transcript_signature: TRANSCRIPT_SIGNATURE_SUITE_LABEL,
    kdf: KDF_SUITE_LABEL,
    policy_profile: HANDSHAKE_POLICY_PROFILE,
    transcript_signature_post_quantum: false,
};

/// Runtime crypto profile requested for a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeCryptoProfile {
    /// Current hybrid/pre-PQC authentication profile.
    HybridPrePqcV1,
    /// Future post-quantum transcript-authentication profile. Refused by this implementation.
    FullPqcV1,
}

impl HandshakeCryptoProfile {
    /// Stable manifest label.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::HybridPrePqcV1 => "hybrid-pre-pqc-v1",
            Self::FullPqcV1 => "full-pqc-v1",
        }
    }
}

/// Explicit runtime policy for accepting the current handshake implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeCryptoPolicy {
    /// Requested crypto profile.
    pub profile: HandshakeCryptoProfile,
    /// Whether the policy permits the current classical Ed25519 transcript
    /// signature suite.
    pub allow_classical_transcript_signature: bool,
}

impl HandshakeCryptoPolicy {
    /// Current stable runtime policy.
    pub const fn current() -> Self {
        Self {
            profile: HandshakeCryptoProfile::HybridPrePqcV1,
            allow_classical_transcript_signature: true,
        }
    }

    /// Strict future policy. This intentionally refuses the current runtime
    /// until ML-DSA/SLH-DSA transcript signatures land.
    pub const fn full_pqc() -> Self {
        Self {
            profile: HandshakeCryptoProfile::FullPqcV1,
            allow_classical_transcript_signature: false,
        }
    }

    /// Validate this policy against the compiled handshake implementation.
    pub const fn validate_current_runtime(self) -> std::result::Result<(), HandshakePolicyError> {
        match self.profile {
            HandshakeCryptoProfile::HybridPrePqcV1 => {
                if !self.allow_classical_transcript_signature {
                    return Err(HandshakePolicyError::ClassicalSignatureNotAllowed);
                }
                Ok(())
            }
            HandshakeCryptoProfile::FullPqcV1 => {
                Err(HandshakePolicyError::FullPqcRequiresPostQuantumTranscriptSignature)
            }
        }
    }
}

/// Handshake policy validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandshakePolicyError {
    /// Current runtime still uses Ed25519 transcript signatures.
    #[error("current handshake uses classical Ed25519 transcript signatures")]
    ClassicalSignatureNotAllowed,
    /// The strict post-quantum transcript-authentication profile cannot be enabled until PQ transcript signatures land.
    #[error("full-pqc-v1 requires post-quantum transcript signatures")]
    FullPqcRequiresPostQuantumTranscriptSignature,
}

// ═══════════════════════════════════════════════════════════════════════════
// Canonical transcript evidence
// ═══════════════════════════════════════════════════════════════════════════

/// Public, non-secret handshake transcript material used for evidence binding.
///
/// This type intentionally contains only public handshake artifacts and stable
/// crypto-suite labels. It does not contain the derived session key or any KEM
/// shared secret. Its bincode-v1 serialization is the canonical byte stream used
/// to produce the session transcript hash consumed by `xenia-ledger` evidence
/// bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeTranscriptV1 {
    /// Stable schema label for the canonical transcript shape.
    pub schema: String,
    /// Key-establishment suite label.
    pub kem: String,
    /// Transcript-authentication signature suite label.
    pub transcript_signature: String,
    /// Key derivation suite label.
    pub kdf: String,
    /// Optional negotiated session context hash supplied by the runtime.
    pub negotiated_context_hash: Option<[u8; 32]>,
    /// Host Ed25519 verifying key.
    pub host_ed25519_pk: [u8; 32],
    /// Viewer Ed25519 verifying key.
    pub viewer_ed25519_pk: [u8; 32],
    /// Host ML-KEM-768 encapsulation key.
    pub host_kem_pk: Vec<u8>,
    /// Viewer ML-KEM-768 ciphertext sent to the host.
    pub kem_ciphertext: Vec<u8>,
    /// Host nonce used in the KDF binding.
    pub host_nonce: [u8; 32],
    /// Viewer nonce used in the KDF binding.
    pub viewer_nonce: [u8; 32],
    /// Viewer signature over the pre-finalize transcript.
    pub viewer_signature: Vec<u8>,
    /// Host signature over the finalized transcript.
    pub host_signature: Vec<u8>,
}

impl HandshakeTranscriptV1 {
    /// Build a canonical transcript from public handshake artifacts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host_ed25519_pk: [u8; 32],
        viewer_ed25519_pk: [u8; 32],
        host_kem_pk: impl Into<Vec<u8>>,
        kem_ciphertext: impl Into<Vec<u8>>,
        host_nonce: [u8; 32],
        viewer_nonce: [u8; 32],
        viewer_signature: impl Into<Vec<u8>>,
        host_signature: impl Into<Vec<u8>>,
        negotiated_context_hash: Option<[u8; 32]>,
    ) -> Result<Self> {
        let host_kem_pk = host_kem_pk.into();
        let kem_ciphertext = kem_ciphertext.into();
        let viewer_signature = viewer_signature.into();
        let host_signature = host_signature.into();

        validate_transcript_component("host_kem_pk", host_kem_pk.len(), ML_KEM_768_PK_LEN)?;
        validate_transcript_component("kem_ciphertext", kem_ciphertext.len(), ML_KEM_768_CT_LEN)?;
        validate_transcript_component("viewer_signature", viewer_signature.len(), 64)?;
        validate_transcript_component("host_signature", host_signature.len(), 64)?;

        Ok(Self {
            schema: HANDSHAKE_TRANSCRIPT_SCHEMA.to_string(),
            kem: KEM_SUITE_LABEL.to_string(),
            transcript_signature: TRANSCRIPT_SIGNATURE_SUITE_LABEL.to_string(),
            kdf: KDF_SUITE_LABEL.to_string(),
            negotiated_context_hash,
            host_ed25519_pk,
            viewer_ed25519_pk,
            host_kem_pk,
            kem_ciphertext,
            host_nonce,
            viewer_nonce,
            viewer_signature,
            host_signature,
        })
    }

    /// Return the canonical bincode-v1 bytes for this transcript.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_session_transcript_bytes(self)
    }

    /// Return the stable transcript hash used by evidence bindings.
    pub fn transcript_hash(&self) -> Result<[u8; 32]> {
        compute_session_transcript_hash(self)
    }
}

/// Serialize the canonical handshake transcript.
pub fn canonical_session_transcript_bytes(transcript: &HandshakeTranscriptV1) -> Result<Vec<u8>> {
    Ok(bincode::serialize(transcript)?)
}

/// Compute the canonical handshake transcript hash from the typed transcript.
pub fn compute_session_transcript_hash(transcript: &HandshakeTranscriptV1) -> Result<[u8; 32]> {
    let bytes = canonical_session_transcript_bytes(transcript)?;
    Ok(compute_session_transcript_hash_from_bytes(&bytes))
}

/// Compute the canonical handshake transcript hash from already-serialized bytes.
pub fn compute_session_transcript_hash_from_bytes(canonical_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(canonical_bytes).as_bytes()
}

fn validate_transcript_component(name: &'static str, got: usize, expected: usize) -> Result<()> {
    if got != expected {
        return Err(HandshakeError::InvalidTranscriptComponent {
            name,
            expected,
            got,
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("no KEM public key stored for peer '{0}'")]
    UnknownPeer(String),

    #[error("invalid KEM public key length: got {got}, expected {ML_KEM_768_PK_LEN}")]
    InvalidKemPublicKey { got: usize },

    #[error("invalid KEM ciphertext length: got {got}, expected {ML_KEM_768_CT_LEN}")]
    InvalidKemCiphertext { got: usize },

    #[error("ML-KEM encapsulation failed")]
    EncapsulationFailed,

    #[error("ML-KEM decapsulation failed")]
    DecapsulationFailed,

    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid Ed25519 public key")]
    InvalidVerifyingKey,

    #[error("invalid handshake transcript component {name}: got {got}, expected {expected}")]
    InvalidTranscriptComponent {
        /// Transcript component name.
        name: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },

    #[error("canonical handshake transcript serialization failed: {0}")]
    TranscriptSerialization(#[from] bincode::Error),
}

pub type Result<T> = std::result::Result<T, HandshakeError>;

// ═══════════════════════════════════════════════════════════════════════════
// Session key
// ═══════════════════════════════════════════════════════════════════════════

/// 32-byte session key derived from the hybrid handshake.
///
/// Zeroized on drop. Suitable for direct use as a ChaCha20-Poly1305 key
/// (when used as a static session key), or as input keying material for
/// a rekey schedule.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKey {
    key: [u8; 32],
    #[zeroize(skip)]
    established_at: SystemTime,
}

impl SessionKey {
    pub fn bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn established_at(&self) -> SystemTime {
        self.established_at
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("key", &"[32 bytes redacted]")
            .field("established_at", &self.established_at)
            .finish()
    }
}

/// Transcript-bound keys derived from the hybrid handshake root key.
///
/// `aead` is the key installed into the current xenia-wire session API. The
/// additional lane keys are exposed so future control/audio/video sealing can
/// move to explicit key separation without changing the handshake transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeySchedule {
    pub aead: [u8; 32],
    pub control: [u8; 32],
    pub video: [u8; 32],
    pub audio: [u8; 32],
    pub telemetry: [u8; 32],
    pub rekey: [u8; 32],
    pub context: [u8; 32],
}

/// Reason a rekey epoch was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RekeyReason {
    /// Operator/admin initiated rekey.
    Manual,
    /// Rekey after a frame-count threshold.
    FrameCount,
    /// Rekey after a byte-count threshold.
    ByteCount,
    /// Rekey after a time threshold.
    Time,
    /// Rekey after transport context changed.
    TransportChange,
}

/// Canonical context for deriving one rekey epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyEpochContextV1 {
    /// Stable schema label.
    pub schema: String,
    /// New epoch number. Epoch 0 is the initial handshake key.
    pub key_epoch: u64,
    /// Original canonical handshake transcript hash.
    pub base_transcript_hash: [u8; 32],
    /// Previous rekey epoch hash, or base transcript hash for epoch 1.
    pub previous_epoch_hash: [u8; 32],
    /// Rekey trigger reason.
    pub reason: RekeyReason,
}

impl RekeyEpochContextV1 {
    /// Build a canonical rekey context.
    pub fn new(
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: RekeyReason,
    ) -> Self {
        Self {
            schema: "xenia-rekey-epoch-context-v1".to_string(),
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
        }
    }

    /// Return canonical bincode-v1 bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    /// Return BLAKE3-256 hash over canonical context bytes.
    pub fn epoch_hash(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }
}

/// Transcript-bound keys for one rekey epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyEpochKeys {
    pub aead: [u8; 32],
    pub control: [u8; 32],
    pub video: [u8; 32],
    pub audio: [u8; 32],
    pub telemetry: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// Wire types (bincode-compatible; serde-derived)
// ═══════════════════════════════════════════════════════════════════════════

/// Phase 2 wire message: KEM public key + optional ciphertext.
///
/// Responder sends this with `kem_ciphertext == None` to publish their
/// encapsulation key. Initiator replies with `kem_ciphertext = Some(..)`
/// after calling [`HandshakeManager::encapsulate_for_peer`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemExchange {
    pub kem_public_key: Vec<u8>,
    pub kem_ciphertext: Option<Vec<u8>>,
    pub peer_node_id: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// HandshakeManager
// ═══════════════════════════════════════════════════════════════════════════

/// Owns this node's long-term Ed25519 identity key and a per-instance
/// ML-KEM-768 keypair. Holds per-peer session state.
///
/// Typical lifecycle on a node:
/// 1. `new()` — generate Ed25519 + ML-KEM keys on startup.
/// 2. Publish `identity_public_key()` and `kem_public_key_bytes()` to peers.
/// 3. For each peer:
///    - Initiator: `receive_kem_public_key(peer, pk)` →
///      `encapsulate_for_peer(peer, nonce)` → send ciphertext.
///    - Responder: receive ciphertext →
///      `decapsulate_and_derive(peer, ct, nonce)`.
/// 4. Use `session_key(peer)` to seal/open frames.
pub struct HandshakeManager {
    signing_key: SigningKey,
    kem_dk: MlKemDk,
    kem_ek_bytes: [u8; ML_KEM_768_PK_LEN],
    sessions: HashMap<String, SessionKey>,
    pending_kem: HashMap<String, Vec<u8>>,
}

impl HandshakeManager {
    /// Return machine-readable crypto-profile labels for evidence export.
    pub const fn evidence_profile() -> HandshakeEvidenceProfile {
        CURRENT_HANDSHAKE_EVIDENCE_PROFILE
    }

    /// Generate a fresh identity + KEM keypair on this node.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let (kem_dk, kem_ek) = MlKem768::generate_keypair();

        let ek_encoded = kem_ek.to_bytes();
        let mut kem_ek_bytes = [0u8; ML_KEM_768_PK_LEN];
        kem_ek_bytes.copy_from_slice(ek_encoded.as_slice());

        Self {
            signing_key,
            kem_dk,
            kem_ek_bytes,
            sessions: HashMap::new(),
            pending_kem: HashMap::new(),
        }
    }

    // ─── Identity ────────────────────────────────────────────────────────

    pub fn identity_public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn identity_public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature from a peer's `VerifyingKey`.
    pub fn verify(peer_pk: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
        peer_pk
            .verify(message, signature)
            .map_err(|_| HandshakeError::SignatureVerificationFailed)
    }

    /// Parse a 32-byte Ed25519 public key.
    pub fn parse_peer_public_key(bytes: &[u8; 32]) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(bytes).map_err(|_| HandshakeError::InvalidVerifyingKey)
    }

    // ─── KEM ─────────────────────────────────────────────────────────────

    /// Raw bytes of this node's ML-KEM-768 public key (1184 bytes).
    pub fn kem_public_key_bytes(&self) -> &[u8; ML_KEM_768_PK_LEN] {
        &self.kem_ek_bytes
    }

    // ─── Initiator side ──────────────────────────────────────────────────

    /// Store the responder's KEM public key for later use in
    /// [`Self::encapsulate_for_peer`].
    pub fn receive_kem_public_key(&mut self, peer_id: &str, kem_pk: &[u8]) -> Result<()> {
        if kem_pk.len() != ML_KEM_768_PK_LEN {
            return Err(HandshakeError::InvalidKemPublicKey { got: kem_pk.len() });
        }
        self.pending_kem
            .insert(peer_id.to_string(), kem_pk.to_vec());
        Ok(())
    }

    /// Encapsulate a shared secret to the peer's KEM public key. Returns
    /// the 1088-byte ciphertext that must be sent to the peer. Stores the
    /// derived session key keyed by `peer_id`.
    ///
    /// `classical_nonce` binds the derived key to whatever classical
    /// challenge was exchanged earlier (a fresh per-session random nonce,
    /// or a transcript hash). Must be at least 16 bytes in practice.
    pub fn encapsulate_for_peer(
        &mut self,
        peer_id: &str,
        classical_nonce: &[u8],
    ) -> Result<Vec<u8>> {
        let pk_bytes = self
            .pending_kem
            .remove(peer_id)
            .ok_or_else(|| HandshakeError::UnknownPeer(peer_id.to_string()))?;

        let ek: MlKemEk = <MlKemEk as TryKeyInit>::new_from_slice(&pk_bytes).map_err(|_| {
            HandshakeError::InvalidKemPublicKey {
                got: pk_bytes.len(),
            }
        })?;

        let (ct, shared) = <MlKemEk as Encapsulate>::encapsulate(&ek);

        let session_key = hkdf_derive(classical_nonce, shared.as_slice());

        self.sessions.insert(
            peer_id.to_string(),
            SessionKey {
                key: session_key,
                established_at: SystemTime::now(),
            },
        );

        Ok(ct.as_slice().to_vec())
    }

    // ─── Responder side ──────────────────────────────────────────────────

    /// Decapsulate the initiator's ciphertext and derive the session key.
    /// Stores it keyed by `peer_id`. Returns the 32-byte key for immediate
    /// verification-of-match by the caller.
    pub fn decapsulate_and_derive(
        &mut self,
        peer_id: &str,
        kem_ciphertext: &[u8],
        classical_nonce: &[u8],
    ) -> Result<[u8; 32]> {
        if kem_ciphertext.len() != ML_KEM_768_CT_LEN {
            return Err(HandshakeError::InvalidKemCiphertext {
                got: kem_ciphertext.len(),
            });
        }

        let ct = MlKemCiphertext::try_from(kem_ciphertext).map_err(|_| {
            HandshakeError::InvalidKemCiphertext {
                got: kem_ciphertext.len(),
            }
        })?;

        // ML-KEM decapsulate is infallible per FIPS 203 (implicit rejection:
        // invalid ciphertexts yield a pseudorandom shared secret rather than
        // an error). Authentication happens at the Ed25519/HKDF layer.
        let shared = self.kem_dk.decapsulate(&ct);

        let session_key = hkdf_derive(classical_nonce, shared.as_slice());

        self.sessions.insert(
            peer_id.to_string(),
            SessionKey {
                key: session_key,
                established_at: SystemTime::now(),
            },
        );

        Ok(session_key)
    }

    // ─── Session lifecycle ───────────────────────────────────────────────

    pub fn session_key(&self, peer_id: &str) -> Option<&SessionKey> {
        self.sessions.get(peer_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn remove_session(&mut self, peer_id: &str) {
        if let Some(mut key) = self.sessions.remove(peer_id) {
            key.key.zeroize();
        }
        self.pending_kem.remove(peer_id);
    }
}

impl Default for HandshakeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Key derivation
// ═══════════════════════════════════════════════════════════════════════════

/// HKDF-SHA-256 derivation used by both sides. Separated into a free
/// function so tests can exercise it directly and callers can pre-derive
/// session keys against a known transcript for conformance testing.
///
/// Layout:
/// - IKM  = `classical_nonce || kem_shared_secret`
/// - Salt = `b"xenia-handshake-v1"` (constant domain separator)
/// - Info = `b"xenia-session-key"` (key-purpose label)
pub fn hkdf_derive(classical_nonce: &[u8], kem_shared_secret: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(classical_nonce.len() + kem_shared_secret.len());
    ikm.extend_from_slice(classical_nonce);
    ikm.extend_from_slice(kem_shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    if hk.expand(HKDF_INFO, &mut okm).is_err() {
        // RFC 5869 HKDF expansion can only fail when the requested output length
        // exceeds the algorithm limit. This function requests exactly 32 bytes
        // from SHA-256, so failure would indicate a violated implementation
        // invariant rather than attacker-controlled input.
        debug_assert!(
            false,
            "HKDF-SHA256 32-byte expand failed for 32-byte output"
        );
    }
    okm
}

/// Derive transcript-bound session keys from a hybrid root key.
///
/// The transcript hash binds the installed traffic key to the actual public
/// handshake artifacts and suite labels. This prevents a valid KEM result from
/// being replayed under a different public transcript or downgraded suite
/// context without changing the final AEAD key.
pub fn derive_session_key_schedule(
    root_key: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> SessionKeySchedule {
    SessionKeySchedule {
        aead: derive_labeled_session_key(root_key, transcript_hash, SESSION_AEAD_KEY_LABEL),
        control: derive_labeled_session_key(root_key, transcript_hash, SESSION_CONTROL_KEY_LABEL),
        video: derive_labeled_session_key(root_key, transcript_hash, SESSION_VIDEO_KEY_LABEL),
        audio: derive_labeled_session_key(root_key, transcript_hash, SESSION_AUDIO_KEY_LABEL),
        telemetry: derive_labeled_session_key(
            root_key,
            transcript_hash,
            SESSION_TELEMETRY_KEY_LABEL,
        ),
        rekey: derive_labeled_session_key(root_key, transcript_hash, SESSION_REKEY_KEY_LABEL),
        context: derive_labeled_session_key(root_key, transcript_hash, SESSION_CONTEXT_KEY_LABEL),
    }
}

/// Derive a key that binds the transcript-bound session schedule to negotiated
/// post-handshake context such as selected transport and capabilities.
pub fn derive_negotiated_context_key(
    schedule: &SessionKeySchedule,
    context_hash: &[u8; 32],
) -> [u8; 32] {
    derive_labeled_session_key(
        &schedule.context,
        context_hash,
        b"xenia/session/context-binding",
    )
}

/// Derive lane keys for a rekey epoch from the transcript-bound rekey lane.
pub fn derive_rekey_epoch_keys(
    schedule: &SessionKeySchedule,
    context: &RekeyEpochContextV1,
) -> Result<RekeyEpochKeys> {
    let context_hash = context.epoch_hash()?;
    Ok(RekeyEpochKeys {
        aead: derive_labeled_session_key(&schedule.rekey, &context_hash, b"xenia/rekey/aead"),
        control: derive_labeled_session_key(&schedule.rekey, &context_hash, b"xenia/rekey/control"),
        video: derive_labeled_session_key(&schedule.rekey, &context_hash, b"xenia/rekey/video"),
        audio: derive_labeled_session_key(&schedule.rekey, &context_hash, b"xenia/rekey/audio"),
        telemetry: derive_labeled_session_key(
            &schedule.rekey,
            &context_hash,
            b"xenia/rekey/telemetry",
        ),
    })
}

fn derive_labeled_session_key(
    root_key: &[u8; 32],
    transcript_hash: &[u8; 32],
    label: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SESSION_KEY_SCHEDULE_SCHEMA.as_bytes()), root_key);
    let mut info = Vec::with_capacity(label.len() + 1 + transcript_hash.len());
    info.extend_from_slice(label);
    info.extend_from_slice(b":");
    info.extend_from_slice(transcript_hash);

    let mut okm = [0u8; 32];
    if hk.expand(&info, &mut okm).is_err() {
        debug_assert!(
            false,
            "HKDF-SHA256 32-byte expand failed for labeled session key"
        );
    }
    okm
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_public_key_is_1184_bytes() {
        let mgr = HandshakeManager::new();
        assert_eq!(mgr.kem_public_key_bytes().len(), ML_KEM_768_PK_LEN);
    }

    #[test]
    fn identity_public_key_is_32_bytes() {
        let mgr = HandshakeManager::new();
        assert_eq!(mgr.identity_public_key_bytes().len(), 32);
    }

    #[test]
    fn evidence_profile_labels_current_hybrid_boundary() {
        let profile = HandshakeManager::evidence_profile();
        assert_eq!(profile.schema, "xenia-handshake-evidence-profile-v1");
        assert_eq!(profile.kem, "ml-kem-768-fips203");
        assert_eq!(profile.transcript_signature, "ed25519-rfc8032");
        assert_eq!(profile.kdf, "hkdf-sha256");
        assert_eq!(profile.policy_profile, "hybrid-pre-pqc-v1");
        assert!(!profile.transcript_signature_post_quantum);
    }

    #[test]
    fn current_handshake_policy_accepts_current_runtime() {
        assert_eq!(
            HandshakeCryptoPolicy::current().validate_current_runtime(),
            Ok(())
        );
    }

    #[test]
    fn full_pqc_policy_refuses_current_classical_transcript_signature() {
        assert_eq!(
            HandshakeCryptoPolicy::full_pqc().validate_current_runtime(),
            Err(HandshakePolicyError::FullPqcRequiresPostQuantumTranscriptSignature)
        );
    }

    #[test]
    fn hybrid_policy_can_refuse_classical_signature_downgrade() {
        let policy = HandshakeCryptoPolicy {
            profile: HandshakeCryptoProfile::HybridPrePqcV1,
            allow_classical_transcript_signature: false,
        };
        assert_eq!(
            policy.validate_current_runtime(),
            Err(HandshakePolicyError::ClassicalSignatureNotAllowed)
        );
    }

    #[test]
    fn canonical_transcript_hash_is_stable_and_sensitive() {
        let transcript = HandshakeTranscriptV1::new(
            [0xA1; 32],
            [0xB2; 32],
            vec![0xC3; ML_KEM_768_PK_LEN],
            vec![0xD4; ML_KEM_768_CT_LEN],
            [0xE5; 32],
            [0xF6; 32],
            vec![0x11; 64],
            vec![0x22; 64],
            None,
        )
        .unwrap();

        let first = transcript.transcript_hash().unwrap();
        let second = compute_session_transcript_hash(&transcript).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, [0u8; 32]);

        let mut changed = transcript.clone();
        changed.host_signature[0] ^= 0x01;
        assert_ne!(first, changed.transcript_hash().unwrap());
    }

    #[test]
    fn canonical_transcript_rejects_wrong_component_lengths() {
        let err = HandshakeTranscriptV1::new(
            [0xA1; 32],
            [0xB2; 32],
            vec![0xC3; ML_KEM_768_PK_LEN - 1],
            vec![0xD4; ML_KEM_768_CT_LEN],
            [0xE5; 32],
            [0xF6; 32],
            vec![0x11; 64],
            vec![0x22; 64],
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            HandshakeError::InvalidTranscriptComponent {
                name: "host_kem_pk",
                ..
            }
        ));
    }

    #[test]
    fn hybrid_handshake_derives_matching_session_keys() {
        let mut initiator = HandshakeManager::new();
        let mut responder = HandshakeManager::new();

        let nonce = [0x42u8; 32];

        initiator
            .receive_kem_public_key("responder", responder.kem_public_key_bytes())
            .unwrap();

        let ct = initiator.encapsulate_for_peer("responder", &nonce).unwrap();
        assert_eq!(ct.len(), ML_KEM_768_CT_LEN);

        let responder_key = responder
            .decapsulate_and_derive("initiator", &ct, &nonce)
            .unwrap();

        let initiator_key = initiator.session_key("responder").unwrap().bytes();
        assert_eq!(initiator_key, &responder_key);
    }

    #[test]
    fn different_peers_yield_different_session_keys() {
        let mut me = HandshakeManager::new();
        let peer_a = HandshakeManager::new();
        let peer_b = HandshakeManager::new();
        let nonce = [0x42u8; 32];

        me.receive_kem_public_key("A", peer_a.kem_public_key_bytes())
            .unwrap();
        me.encapsulate_for_peer("A", &nonce).unwrap();

        me.receive_kem_public_key("B", peer_b.kem_public_key_bytes())
            .unwrap();
        me.encapsulate_for_peer("B", &nonce).unwrap();

        let a = me.session_key("A").unwrap().bytes();
        let b = me.session_key("B").unwrap().bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn different_nonces_yield_different_session_keys() {
        let mut init1 = HandshakeManager::new();
        let mut init2 = HandshakeManager::new();
        let responder = HandshakeManager::new();

        let rpk = *responder.kem_public_key_bytes();

        init1.receive_kem_public_key("R", &rpk).unwrap();
        init1.encapsulate_for_peer("R", &[0x01u8; 32]).unwrap();

        init2.receive_kem_public_key("R", &rpk).unwrap();
        init2.encapsulate_for_peer("R", &[0x02u8; 32]).unwrap();

        let k1 = init1.session_key("R").unwrap().bytes();
        let k2 = init2.session_key("R").unwrap().bytes();
        assert_ne!(k1, k2);
    }

    #[test]
    fn missing_peer_kem_pk_fails() {
        let mut mgr = HandshakeManager::new();
        let err = mgr.encapsulate_for_peer("nobody", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, HandshakeError::UnknownPeer(_)));
    }

    #[test]
    fn wrong_length_kem_public_key_rejected() {
        let mut mgr = HandshakeManager::new();
        let err = mgr.receive_kem_public_key("peer", &[0u8; 100]).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::InvalidKemPublicKey { got: 100 }
        ));
    }

    #[test]
    fn wrong_length_ciphertext_rejected() {
        let mut mgr = HandshakeManager::new();
        let err = mgr
            .decapsulate_and_derive("peer", &[0u8; 42], &[0u8; 32])
            .unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::InvalidKemCiphertext { got: 42 }
        ));
    }

    #[test]
    fn implicit_rejection_on_garbage_ciphertext() {
        // ML-KEM-768 is IND-CCA2 secure: decapsulating random garbage
        // returns a *random* shared secret rather than erroring out
        // (implicit rejection). The derived session key will simply not
        // match whatever the initiator thinks it is.
        let mut responder = HandshakeManager::new();
        let bad_ct = vec![0xFFu8; ML_KEM_768_CT_LEN];
        let result = responder.decapsulate_and_derive("peer", &bad_ct, &[0u8; 32]);
        assert!(
            result.is_ok(),
            "FIPS 203 implicit rejection must not surface as an error"
        );
    }

    #[test]
    fn signed_transcript_round_trip() {
        let alice = HandshakeManager::new();
        let bob_pk = alice.identity_public_key();

        let transcript = b"xenia:alice<->bob:session-42";
        let sig = alice.sign(transcript);

        assert!(HandshakeManager::verify(&bob_pk, transcript, &sig).is_ok());

        // Tampered transcript must fail.
        assert!(HandshakeManager::verify(&bob_pk, b"xenia:eve<->bob:session-42", &sig).is_err());
    }

    #[test]
    fn remove_session_clears_state() {
        let mut me = HandshakeManager::new();
        let peer = HandshakeManager::new();
        me.receive_kem_public_key("P", peer.kem_public_key_bytes())
            .unwrap();
        me.encapsulate_for_peer("P", &[0u8; 32]).unwrap();
        assert_eq!(me.session_count(), 1);

        me.remove_session("P");
        assert_eq!(me.session_count(), 0);
        assert!(me.session_key("P").is_none());
    }

    #[test]
    fn session_key_is_exactly_32_bytes() {
        let mut init = HandshakeManager::new();
        let resp = HandshakeManager::new();
        init.receive_kem_public_key("R", resp.kem_public_key_bytes())
            .unwrap();
        init.encapsulate_for_peer("R", &[0u8; 32]).unwrap();
        assert_eq!(init.session_key("R").unwrap().bytes().len(), 32);
    }

    #[test]
    fn hkdf_derive_is_deterministic() {
        let n = [0x42u8; 32];
        let s = [0xABu8; 32];
        assert_eq!(hkdf_derive(&n, &s), hkdf_derive(&n, &s));
    }

    #[test]
    fn hkdf_derive_changes_with_inputs() {
        let s = [0xABu8; 32];
        let k1 = hkdf_derive(&[0x01u8; 32], &s);
        let k2 = hkdf_derive(&[0x02u8; 32], &s);
        assert_ne!(k1, k2);

        let n = [0x42u8; 32];
        let k3 = hkdf_derive(&n, &[0xCDu8; 32]);
        let k4 = hkdf_derive(&n, &[0xCEu8; 32]);
        assert_ne!(k3, k4);
    }

    #[test]
    fn session_key_schedule_is_deterministic() {
        let root = [0xA5u8; 32];
        let transcript_hash = [0x5Au8; 32];

        let first = derive_session_key_schedule(&root, &transcript_hash);
        let second = derive_session_key_schedule(&root, &transcript_hash);

        assert_eq!(first, second);
        assert_ne!(first.aead, [0u8; 32]);
    }

    #[test]
    fn session_key_schedule_separates_lanes() {
        let root = [0xA5u8; 32];
        let transcript_hash = [0x5Au8; 32];
        let schedule = derive_session_key_schedule(&root, &transcript_hash);

        assert_ne!(schedule.aead, schedule.control);
        assert_ne!(schedule.aead, schedule.video);
        assert_ne!(schedule.aead, schedule.audio);
        assert_ne!(schedule.aead, schedule.telemetry);
        assert_ne!(schedule.aead, schedule.rekey);
        assert_ne!(schedule.aead, schedule.context);
    }

    #[test]
    fn session_key_schedule_binds_transcript_hash() {
        let root = [0xA5u8; 32];
        let first_hash = [0x5Au8; 32];
        let mut second_hash = first_hash;
        second_hash[0] ^= 0x01;

        let first = derive_session_key_schedule(&root, &first_hash);
        let second = derive_session_key_schedule(&root, &second_hash);

        assert_ne!(first.aead, second.aead);
        assert_ne!(first.audio, second.audio);
        assert_ne!(first.control, second.control);
    }

    #[test]
    fn negotiated_context_key_binds_context_hash() {
        let root = [0xA5u8; 32];
        let transcript_hash = [0x5Au8; 32];
        let schedule = derive_session_key_schedule(&root, &transcript_hash);
        let first = derive_negotiated_context_key(&schedule, &[0x11; 32]);
        let second = derive_negotiated_context_key(&schedule, &[0x12; 32]);

        assert_ne!(first, second);
        assert_ne!(first, schedule.context);
        assert_ne!(first, [0u8; 32]);
    }

    #[test]
    fn rekey_epoch_keys_are_deterministic_and_epoch_bound() {
        let schedule = derive_session_key_schedule(&[0xA5; 32], &[0x5A; 32]);
        let epoch1 = RekeyEpochContextV1::new(1, [0x11; 32], [0x11; 32], RekeyReason::FrameCount);
        let epoch1_again =
            RekeyEpochContextV1::new(1, [0x11; 32], [0x11; 32], RekeyReason::FrameCount);
        let epoch2 = RekeyEpochContextV1::new(2, [0x11; 32], [0x22; 32], RekeyReason::FrameCount);

        let keys1 = derive_rekey_epoch_keys(&schedule, &epoch1).unwrap();
        let keys1_again = derive_rekey_epoch_keys(&schedule, &epoch1_again).unwrap();
        let keys2 = derive_rekey_epoch_keys(&schedule, &epoch2).unwrap();

        assert_eq!(keys1, keys1_again);
        assert_ne!(keys1.aead, keys2.aead);
        assert_ne!(keys1.aead, schedule.aead);
        assert_ne!(keys1.aead, keys1.audio);
    }

    #[test]
    fn kem_exchange_roundtrips_bincode() {
        let exchange = KemExchange {
            kem_public_key: vec![0xAAu8; ML_KEM_768_PK_LEN],
            kem_ciphertext: Some(vec![0xBBu8; ML_KEM_768_CT_LEN]),
            peer_node_id: "peer-42".to_string(),
        };
        let bytes = bincode::serialize(&exchange).unwrap();
        let decoded: KemExchange = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.kem_public_key, exchange.kem_public_key);
        assert_eq!(decoded.kem_ciphertext, exchange.kem_ciphertext);
        assert_eq!(decoded.peer_node_id, exchange.peer_node_id);
    }
}
