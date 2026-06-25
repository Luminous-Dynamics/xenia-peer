// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! # xenia-handshake — post-quantum hybrid session establishment
//!
//! Combines classical Ed25519 identity verification with ML-KEM-768
//! (FIPS 203) key encapsulation to derive a 32-byte session key suitable
//! for ChaCha20-Poly1305 AEAD sealing of the xenia-wire envelope.
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
//! Phase 3 — Key derivation
//!   session_key = HKDF-SHA256(
//!       ikm  = classical_nonce || kem_shared_secret,
//!       salt = b"xenia-handshake-v1",
//!       info = b"xenia-session-key",
//!   )
//! ```
//!
//! Both classical (Ed25519 signature) and PQC (ML-KEM) must succeed. If
//! a quantum computer breaks Ed25519, the ML-KEM shared secret still
//! protects the session. If ML-KEM has an undiscovered flaw, Ed25519
//! still authenticates. Hybrid KDF security per Bindel et al. 2019.
//!
//! ## References
//! - NIST FIPS 203 (2024) — ML-KEM specification
//! - Bindel et al. (2019) — hybrid key exchange in TLS 1.3
//! - RFC 8032 — Ed25519

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
