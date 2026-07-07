// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Handshake implementation for Xenia.
//!
//! Performs a PQC-hybrid (ML-KEM-768 + Ed25519) handshake over a
//! [`Transport`] to establish a shared session key.

use crate::{frame::RawCapabilities, transport::Transport};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tracing::info;
use xenia_handshake::{
    HANDSHAKE_POLICY_PROFILE, HANDSHAKE_TRANSCRIPT_SCHEMA, HandshakeManager, HandshakeTranscriptV1,
    KDF_SUITE_LABEL, KEM_SUITE_LABEL, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, ML_KEM_768_CT_LEN,
    ML_KEM_768_PK_LEN, RekeyEpochContextV1, RekeyReason, SessionKeySchedule,
    TRANSCRIPT_SIGNATURE_SUITE_LABEL, derive_rekey_epoch_keys, derive_session_key_schedule,
};

const HANDSHAKE_SIGNATURE_CONTEXT_V1: &str = "xenia-handshake-signature-v1";
const NEGOTIATED_SESSION_CONTEXT_SCHEMA: &str = "xenia-negotiated-session-context-v1";

/// Handshake messages exchanged between host and viewer.
///
/// Every signature-bearing message carries both an Ed25519 and an
/// ML-DSA-65 signature over the identical transcript bytes -- both
/// must verify (see `viewer_signature_transcript`/
/// `host_signature_transcript`); there is no classical-only fallback.
/// See `docs/crypto/FULL_PQC_MIGRATION_PLAN.md` Stage 2.
// The variants differ a lot in size (HostHello/ViewerResponse carry ML-DSA-65
// keys/signatures; HostFinalize is small), but handshake messages are built
// and sent one at a time and never stored in bulk, so the per-instance size
// spread doesn't matter -- boxing would only add an indirection to a
// short-lived value.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Host starts by sending its identity and KEM public keys + a fresh nonce.
    HostHello {
        /// Ed25519 verifying key.
        ed25519_pk: [u8; 32],
        /// ML-DSA-65 verifying key.
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        /// ML-KEM-768 encapsulation key.
        #[serde(with = "BigArray")]
        kem_pk: [u8; ML_KEM_768_PK_LEN],
        /// Classical 32-byte nonce for KDF binding.
        nonce: [u8; 32],
        /// Optional negotiated session context hash bound into the transcript.
        negotiated_context_hash: Option<[u8; 32]>,
    },
    /// Viewer responds with its identity, KEM ciphertext, and its own nonce.
    /// Signed over (HostHello || ViewerResponse-payload).
    ViewerResponse {
        /// Ed25519 verifying key.
        ed25519_pk: [u8; 32],
        /// ML-DSA-65 verifying key.
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        /// ML-KEM-768 ciphertext.
        #[serde(with = "BigArray")]
        kem_ct: [u8; ML_KEM_768_CT_LEN],
        /// Viewer's fresh 32-byte nonce.
        nonce: [u8; 32],
        /// Ed25519 signature from viewer over the transcript.
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        /// ML-DSA-65 signature from viewer over the identical transcript.
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
    /// Host finalizes the handshake by verifying viewer's response and
    /// signing the final transcript.
    HostFinalize {
        /// Ed25519 signature from host over the full transcript.
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        /// ML-DSA-65 signature from host over the identical transcript.
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
}

/// Result of a completed handshake, including the canonical transcript hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeOutcome {
    /// The 32-byte session key installed into the Xenia wire session.
    pub session_key: [u8; 32],
    /// BLAKE3-256 hash of the canonical public handshake transcript.
    pub transcript_hash: [u8; 32],
    /// Transcript-bound key schedule reserved for lane-separated sealing.
    pub key_schedule: SessionKeySchedule,
    /// Optional negotiated session context hash included in HostHello.
    pub negotiated_context_hash: Option<[u8; 32]>,
    /// BLAKE3 fingerprint of the host's signing identity (Ed25519 ||
    /// ML-DSA-65). On the viewer path this is the peer being pinned for
    /// trust-on-first-use; on the host path it is the host's own identity.
    /// A viewer compares this against a previously-pinned value to detect an
    /// active MITM that substituted its own keys in HostHello.
    pub host_identity_fingerprint: [u8; 32],
}

/// Transport selected for the authenticated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NegotiatedTransport {
    /// Raw TCP length-prefixed envelopes.
    Tcp,
    /// Binary WebSocket envelopes.
    WebSocket,
    /// Iroh QUIC bidirectional stream envelopes.
    Quic,
}

/// Canonical post-handshake session context.
///
/// This context is sealed under the transcript-bound session key as the first
/// control frame. Hashing it gives the runtime an explicit binding between the
/// cryptographic transcript and negotiated session surface without changing the
/// existing three-message handshake wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedSessionContextV1 {
    /// Stable context schema label.
    pub schema: String,
    /// Selected transport for this session.
    pub transport: NegotiatedTransport,
    /// First sealed capabilities frame decoded as typed capabilities.
    pub capabilities: RawCapabilities,
}

impl NegotiatedSessionContextV1 {
    /// Build a canonical negotiated context.
    pub fn new(transport: NegotiatedTransport, capabilities: RawCapabilities) -> Self {
        Self {
            schema: NEGOTIATED_SESSION_CONTEXT_SCHEMA.to_string(),
            transport,
            capabilities,
        }
    }

    /// Return canonical bincode-v1 bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Return BLAKE3-256 hash over canonical context bytes.
    pub fn context_hash(&self) -> Result<[u8; 32], bincode::Error> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }
}

/// Compute the canonical negotiated session context hash.
pub fn negotiated_session_context_hash(
    transport: NegotiatedTransport,
    capabilities: RawCapabilities,
) -> Result<[u8; 32], bincode::Error> {
    NegotiatedSessionContextV1::new(transport, capabilities).context_hash()
}

/// Policy controlling when repeatable session rekeys are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyPolicy {
    /// Maximum video frames per epoch before a rekey should be requested.
    pub max_frames_per_epoch: u64,
    /// Maximum sealed media/control bytes per epoch before a rekey should be requested.
    pub max_bytes_per_epoch: u64,
    /// Minimum media frames between rekeys to prevent rekey spam.
    pub min_frames_between_rekeys: u64,
    /// Whether manual/admin rekey requests are allowed.
    pub manual_rekey_allowed: bool,
}

impl RekeyPolicy {
    /// Deterministic smoke-test policy: rekey after a small frame count.
    pub const fn smoke() -> Self {
        Self {
            max_frames_per_epoch: 4,
            max_bytes_per_epoch: 0,
            min_frames_between_rekeys: 1,
            manual_rekey_allowed: true,
        }
    }

    /// Build a policy from daemon CLI knobs.
    pub const fn from_limits(max_frames_per_epoch: u64, max_bytes_per_epoch: u64) -> Self {
        Self {
            max_frames_per_epoch,
            max_bytes_per_epoch,
            min_frames_between_rekeys: 1,
            manual_rekey_allowed: true,
        }
    }
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self::smoke()
    }
}

/// Local epoch bookkeeping for a transcript-bound session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEpochState {
    current_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    frames_in_epoch: u64,
    bytes_in_epoch: u64,
    audio_frames_in_epoch: u64,
    rejected_rekeys: u64,
    last_rekey_reason: Option<RekeyReason>,
    policy: RekeyPolicy,
}

impl SessionEpochState {
    /// Create epoch state for a completed handshake.
    pub fn new(base_transcript_hash: [u8; 32], policy: RekeyPolicy) -> Self {
        Self {
            current_epoch: 0,
            base_transcript_hash,
            previous_epoch_hash: base_transcript_hash,
            frames_in_epoch: 0,
            bytes_in_epoch: 0,
            audio_frames_in_epoch: 0,
            rejected_rekeys: 0,
            last_rekey_reason: None,
            policy,
        }
    }

    /// Current installed epoch.
    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Most recent accepted epoch hash.
    pub const fn previous_epoch_hash(&self) -> [u8; 32] {
        self.previous_epoch_hash
    }

    /// Number of rejected rekey proposals.
    pub const fn rejected_rekeys(&self) -> u64 {
        self.rejected_rekeys
    }

    /// Video frames sent/received in the current epoch.
    pub const fn frames_in_epoch(&self) -> u64 {
        self.frames_in_epoch
    }

    /// Bytes sent/received in the current epoch.
    pub const fn bytes_in_epoch(&self) -> u64 {
        self.bytes_in_epoch
    }

    /// Audio frames sent/received in the current epoch.
    pub const fn audio_frames_in_epoch(&self) -> u64 {
        self.audio_frames_in_epoch
    }

    /// Last accepted rekey reason.
    pub const fn last_rekey_reason(&self) -> Option<RekeyReason> {
        self.last_rekey_reason
    }

    /// Record one video frame in the current epoch.
    pub fn record_video_frame(&mut self, bytes: usize) {
        self.frames_in_epoch = self.frames_in_epoch.saturating_add(1);
        self.bytes_in_epoch = self.bytes_in_epoch.saturating_add(bytes as u64);
    }

    /// Record one audio frame in the current epoch.
    pub fn record_audio_frame(&mut self, bytes: usize) {
        self.audio_frames_in_epoch = self.audio_frames_in_epoch.saturating_add(1);
        self.bytes_in_epoch = self.bytes_in_epoch.saturating_add(bytes as u64);
    }

    /// Return the next deterministic rekey context if policy says to rekey.
    pub fn next_rekey_due(&self) -> Option<RekeyEpochContextV1> {
        if self.frames_in_epoch >= self.policy.min_frames_between_rekeys {
            if self.policy.max_frames_per_epoch != 0
                && self.frames_in_epoch >= self.policy.max_frames_per_epoch
            {
                return Some(self.next_rekey_context(RekeyReason::FrameCount));
            }
            if self.policy.max_bytes_per_epoch != 0
                && self.bytes_in_epoch >= self.policy.max_bytes_per_epoch
            {
                return Some(self.next_rekey_context(RekeyReason::ByteCount));
            }
        }
        None
    }

    /// Build the next rekey context for a given reason.
    pub fn next_rekey_context(&self, reason: RekeyReason) -> RekeyEpochContextV1 {
        RekeyEpochContextV1::new(
            self.current_epoch + 1,
            self.base_transcript_hash,
            self.previous_epoch_hash,
            reason,
        )
    }

    /// Accept locally-created rekey context and reset epoch counters.
    pub fn install_epoch(&mut self, context: &RekeyEpochContextV1) -> xenia_handshake::Result<()> {
        if context.key_epoch != self.current_epoch + 1
            || context.base_transcript_hash != self.base_transcript_hash
            || context.previous_epoch_hash != self.previous_epoch_hash
        {
            self.rejected_rekeys = self.rejected_rekeys.saturating_add(1);
            return Err(xenia_handshake::HandshakeError::SignatureVerificationFailed);
        }
        self.current_epoch = context.key_epoch;
        self.previous_epoch_hash = context.epoch_hash()?;
        self.frames_in_epoch = 0;
        self.bytes_in_epoch = 0;
        self.audio_frames_in_epoch = 0;
        self.last_rekey_reason = Some(context.reason);
        Ok(())
    }

    /// Validate a received proposal and return its context.
    pub fn validate_proposal(
        &mut self,
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: RekeyReason,
        epoch_hash: [u8; 32],
    ) -> xenia_handshake::Result<RekeyEpochContextV1> {
        let context =
            RekeyEpochContextV1::new(key_epoch, base_transcript_hash, previous_epoch_hash, reason);
        if key_epoch != self.current_epoch + 1
            || base_transcript_hash != self.base_transcript_hash
            || previous_epoch_hash != self.previous_epoch_hash
            || context.epoch_hash()? != epoch_hash
        {
            self.rejected_rekeys = self.rejected_rekeys.saturating_add(1);
            return Err(xenia_handshake::HandshakeError::SignatureVerificationFailed);
        }
        Ok(context)
    }

    /// Derive epoch keys and install the accepted epoch locally.
    pub fn derive_and_install(
        &mut self,
        schedule: &SessionKeySchedule,
        context: &RekeyEpochContextV1,
    ) -> xenia_handshake::Result<xenia_handshake::RekeyEpochKeys> {
        let keys = derive_rekey_epoch_keys(schedule, context)?;
        self.install_epoch(context)?;
        Ok(keys)
    }
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("handshake transcript component exceeds u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn signature_context_prefix() -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, HANDSHAKE_SIGNATURE_CONTEXT_V1.as_bytes());
    append_len_prefixed(&mut out, HANDSHAKE_TRANSCRIPT_SCHEMA.as_bytes());
    append_len_prefixed(&mut out, HANDSHAKE_POLICY_PROFILE.as_bytes());
    append_len_prefixed(&mut out, KEM_SUITE_LABEL.as_bytes());
    append_len_prefixed(&mut out, TRANSCRIPT_SIGNATURE_SUITE_LABEL.as_bytes());
    append_len_prefixed(&mut out, KDF_SUITE_LABEL.as_bytes());
    out
}

/// Build the transcript both sides sign at the viewer-response phase.
///
/// Both Ed25519 and ML-DSA-65 sign this identical byte sequence -- the
/// viewer's ML-DSA-65 verifying key is bound in here (alongside the
/// Ed25519 key) so an attacker can't strip or substitute the PQ
/// identity without invalidating the classical signature too. The
/// host's ML-DSA-65 key is already bound transitively via
/// `hello_bytes` (the full serialized `HostHello`, which now carries
/// `ml_dsa_pk`).
fn viewer_signature_transcript(
    hello_bytes: &[u8],
    viewer_ed25519_pk: &[u8; 32],
    viewer_ml_dsa_pk: &[u8; ML_DSA_65_PK_LEN],
    kem_ct: &[u8],
    viewer_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = signature_context_prefix();
    append_len_prefixed(&mut transcript, b"viewer-response");
    append_len_prefixed(&mut transcript, hello_bytes);
    append_len_prefixed(&mut transcript, viewer_ed25519_pk);
    append_len_prefixed(&mut transcript, viewer_ml_dsa_pk);
    append_len_prefixed(&mut transcript, kem_ct);
    append_len_prefixed(&mut transcript, viewer_nonce);
    transcript
}

/// Build the transcript both sides sign at the host-finalize phase --
/// the viewer-response transcript plus both of the viewer's signatures
/// (Ed25519 and ML-DSA-65), so the host's finalize signatures also
/// bind the viewer's complete signed response.
fn host_signature_transcript(
    hello_bytes: &[u8],
    viewer_ed25519_pk: &[u8; 32],
    viewer_ml_dsa_pk: &[u8; ML_DSA_65_PK_LEN],
    kem_ct: &[u8],
    viewer_nonce: &[u8; 32],
    viewer_signature: &[u8; 64],
    viewer_ml_dsa_signature: &[u8; ML_DSA_65_SIG_LEN],
) -> Vec<u8> {
    let mut transcript = viewer_signature_transcript(
        hello_bytes,
        viewer_ed25519_pk,
        viewer_ml_dsa_pk,
        kem_ct,
        viewer_nonce,
    );
    append_len_prefixed(&mut transcript, b"host-finalize");
    append_len_prefixed(&mut transcript, viewer_signature);
    append_len_prefixed(&mut transcript, viewer_ml_dsa_signature);
    transcript
}

/// Perform a host-side handshake and return only the session key.
pub async fn perform_host_handshake<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(
        perform_host_handshake_with_transcript(transport, mgr, peer_id)
            .await?
            .session_key,
    )
}

/// Perform a host-side handshake and return evidence binding material.
pub async fn perform_host_handshake_with_transcript<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
) -> Result<HandshakeOutcome, Box<dyn std::error::Error>> {
    perform_host_handshake_with_transcript_and_context(transport, mgr, peer_id, None).await
}

/// Perform a host-side handshake and bind an optional negotiated context hash.
pub async fn perform_host_handshake_with_transcript_and_context<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
    negotiated_context_hash: Option<[u8; 32]>,
) -> Result<HandshakeOutcome, Box<dyn std::error::Error>> {
    info!("Starting host-side handshake");
    let host_nonce = rand::random::<[u8; 32]>();
    let host_ed25519_pk = mgr.identity_public_key_bytes();
    let host_ml_dsa_pk = mgr.ml_dsa_public_key_bytes();
    let host_kem_pk = *mgr.kem_public_key_bytes();

    let hello = HandshakeMessage::HostHello {
        ed25519_pk: host_ed25519_pk,
        ml_dsa_pk: host_ml_dsa_pk,
        kem_pk: host_kem_pk,
        nonce: host_nonce,
        negotiated_context_hash,
    };

    let hello_bytes = bincode::serialize(&hello)?;
    transport.send_envelope(&hello_bytes).await?;

    let response_bytes = transport.recv_envelope().await?;
    let HandshakeMessage::ViewerResponse {
        ed25519_pk,
        ml_dsa_pk,
        kem_ct,
        nonce: viewer_nonce,
        signature,
        ml_dsa_signature,
    } = bincode::deserialize(&response_bytes)?
    else {
        return Err("Expected ViewerResponse".into());
    };

    // Verify viewer identity -- both Ed25519 and ML-DSA-65 must verify,
    // no classical-only fallback.
    let viewer_verifying_key = HandshakeManager::parse_peer_public_key(&ed25519_pk)?;

    // Domain-separated transcript for viewer's signatures.
    let transcript = viewer_signature_transcript(
        &hello_bytes,
        &ed25519_pk,
        &ml_dsa_pk,
        &kem_ct,
        &viewer_nonce,
    );

    let sig = ed25519_dalek::Signature::from_bytes(&signature);
    HandshakeManager::verify(&viewer_verifying_key, &transcript, &sig)?;
    HandshakeManager::verify_ml_dsa(&ml_dsa_pk, &transcript, &ml_dsa_signature)?;

    // Combined nonce for KDF.
    let mut combined_nonce = [0u8; 64];
    combined_nonce[..32].copy_from_slice(&host_nonce);
    combined_nonce[32..].copy_from_slice(&viewer_nonce);

    let root_key = mgr.decapsulate_and_derive(peer_id, &kem_ct, &combined_nonce)?;

    // Finalize: sign the transcript (including viewer's signatures) with
    // both algorithms.
    let final_transcript = host_signature_transcript(
        &hello_bytes,
        &ed25519_pk,
        &ml_dsa_pk,
        &kem_ct,
        &viewer_nonce,
        &signature,
        &ml_dsa_signature,
    );
    let host_sig = mgr.sign(&final_transcript).to_bytes();
    let host_ml_dsa_sig = mgr.sign_ml_dsa(&final_transcript);

    let finalize = HandshakeMessage::HostFinalize {
        signature: host_sig,
        ml_dsa_signature: host_ml_dsa_sig,
    };
    transport
        .send_envelope(&bincode::serialize(&finalize)?)
        .await?;

    let canonical_transcript = HandshakeTranscriptV1::new(
        host_ed25519_pk,
        ed25519_pk,
        host_ml_dsa_pk.to_vec(),
        ml_dsa_pk.to_vec(),
        host_kem_pk.to_vec(),
        kem_ct.to_vec(),
        host_nonce,
        viewer_nonce,
        signature.to_vec(),
        host_sig.to_vec(),
        ml_dsa_signature.to_vec(),
        host_ml_dsa_sig.to_vec(),
        negotiated_context_hash,
    )?;
    let transcript_hash = canonical_transcript.transcript_hash()?;
    let key_schedule = derive_session_key_schedule(&root_key, &transcript_hash);
    let session_key = key_schedule.aead;

    let host_identity_fingerprint =
        xenia_handshake::host_identity_fingerprint(&host_ed25519_pk, &host_ml_dsa_pk);

    info!("Host-side handshake complete");
    Ok(HandshakeOutcome {
        session_key,
        transcript_hash,
        key_schedule,
        negotiated_context_hash,
        host_identity_fingerprint,
    })
}

/// Perform a viewer-side handshake and return only the session key.
pub async fn perform_viewer_handshake<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(
        perform_viewer_handshake_with_transcript(transport, mgr, peer_id)
            .await?
            .session_key,
    )
}

/// Perform a viewer-side handshake and return evidence binding material.
pub async fn perform_viewer_handshake_with_transcript<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
) -> Result<HandshakeOutcome, Box<dyn std::error::Error>> {
    info!("Starting viewer-side handshake");

    let hello_bytes = transport.recv_envelope().await?;
    let hello = bincode::deserialize::<HandshakeMessage>(&hello_bytes)?;
    let HandshakeMessage::HostHello {
        ed25519_pk,
        ml_dsa_pk,
        kem_pk,
        nonce: host_nonce,
        negotiated_context_hash,
    } = hello
    else {
        return Err("Expected HostHello".into());
    };

    let host_verifying_key = HandshakeManager::parse_peer_public_key(&ed25519_pk)?;
    mgr.receive_kem_public_key(peer_id, &kem_pk)?;

    let viewer_nonce = rand::random::<[u8; 32]>();

    // Combined nonce for KDF.
    let mut combined_nonce = [0u8; 64];
    combined_nonce[..32].copy_from_slice(&host_nonce);
    combined_nonce[32..].copy_from_slice(&viewer_nonce);

    let kem_ct = mgr.encapsulate_for_peer(peer_id, &combined_nonce)?;

    let viewer_ed25519_pk = mgr.identity_public_key_bytes();
    let viewer_ml_dsa_pk = mgr.ml_dsa_public_key_bytes();

    // Sign the domain-separated transcript with both algorithms.
    let transcript = viewer_signature_transcript(
        &hello_bytes,
        &viewer_ed25519_pk,
        &viewer_ml_dsa_pk,
        &kem_ct,
        &viewer_nonce,
    );

    let viewer_sig = mgr.sign(&transcript).to_bytes();
    let viewer_ml_dsa_sig = mgr.sign_ml_dsa(&transcript);

    let response = HandshakeMessage::ViewerResponse {
        ed25519_pk: viewer_ed25519_pk,
        ml_dsa_pk: viewer_ml_dsa_pk,
        kem_ct: kem_ct
            .clone()
            .try_into()
            .map_err(|_| "Invalid KEM CT length")?,
        nonce: viewer_nonce,
        signature: viewer_sig,
        ml_dsa_signature: viewer_ml_dsa_sig,
    };

    let response_bytes = bincode::serialize(&response)?;
    transport.send_envelope(&response_bytes).await?;

    // Wait for Finalize.
    let finalize_bytes = transport.recv_envelope().await?;
    let HandshakeMessage::HostFinalize {
        signature: host_sig_bytes,
        ml_dsa_signature: host_ml_dsa_sig_bytes,
    } = bincode::deserialize(&finalize_bytes)?
    else {
        return Err("Expected HostFinalize".into());
    };

    // Verify host signatures over the finalized domain-separated
    // transcript -- both Ed25519 and ML-DSA-65 must verify, no
    // classical-only fallback.
    let final_transcript = host_signature_transcript(
        &hello_bytes,
        &viewer_ed25519_pk,
        &viewer_ml_dsa_pk,
        &kem_ct,
        &viewer_nonce,
        &viewer_sig,
        &viewer_ml_dsa_sig,
    );
    let host_sig = ed25519_dalek::Signature::from_bytes(&host_sig_bytes);
    HandshakeManager::verify(&host_verifying_key, &final_transcript, &host_sig)?;
    HandshakeManager::verify_ml_dsa(&ml_dsa_pk, &final_transcript, &host_ml_dsa_sig_bytes)?;

    let root_key = *mgr
        .session_key(peer_id)
        .ok_or("Session key missing after handshake")?
        .bytes();

    let canonical_transcript = HandshakeTranscriptV1::new(
        ed25519_pk,
        viewer_ed25519_pk,
        ml_dsa_pk.to_vec(),
        viewer_ml_dsa_pk.to_vec(),
        kem_pk.to_vec(),
        kem_ct.to_vec(),
        host_nonce,
        viewer_nonce,
        viewer_sig.to_vec(),
        host_sig_bytes.to_vec(),
        viewer_ml_dsa_sig.to_vec(),
        host_ml_dsa_sig_bytes.to_vec(),
        negotiated_context_hash,
    )?;
    let transcript_hash = canonical_transcript.transcript_hash()?;
    let key_schedule = derive_session_key_schedule(&root_key, &transcript_hash);
    let session_key = key_schedule.aead;

    let host_identity_fingerprint =
        xenia_handshake::host_identity_fingerprint(&ed25519_pk, &ml_dsa_pk);

    info!("Viewer-side handshake complete");
    Ok(HandshakeOutcome {
        session_key,
        transcript_hash,
        key_schedule,
        negotiated_context_hash,
        host_identity_fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_signature_transcript_binds_suite_context() {
        let hello_bytes = bincode::serialize(&HandshakeMessage::HostHello {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x99; ML_DSA_65_PK_LEN],
            kem_pk: [0x22; ML_KEM_768_PK_LEN],
            nonce: [0x33; 32],
            negotiated_context_hash: Some([0x99; 32]),
        })
        .unwrap();

        let transcript = viewer_signature_transcript(
            &hello_bytes,
            &[0x44; 32],
            &[0xAA; ML_DSA_65_PK_LEN],
            &[0x55; ML_KEM_768_CT_LEN],
            &[0x66; 32],
        );

        assert!(
            transcript
                .windows(HANDSHAKE_SIGNATURE_CONTEXT_V1.len())
                .any(|w| { w == HANDSHAKE_SIGNATURE_CONTEXT_V1.as_bytes() })
        );
        assert!(
            transcript
                .windows(HANDSHAKE_TRANSCRIPT_SCHEMA.len())
                .any(|w| { w == HANDSHAKE_TRANSCRIPT_SCHEMA.as_bytes() })
        );
        assert!(
            transcript
                .windows(KEM_SUITE_LABEL.len())
                .any(|w| { w == KEM_SUITE_LABEL.as_bytes() })
        );
    }

    #[test]
    fn viewer_signature_rejects_ciphertext_tampering() {
        let signer = HandshakeManager::new();
        let verifier = signer.identity_public_key();
        let hello_bytes = bincode::serialize(&HandshakeMessage::HostHello {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x99; ML_DSA_65_PK_LEN],
            kem_pk: [0x22; ML_KEM_768_PK_LEN],
            nonce: [0x33; 32],
            negotiated_context_hash: None,
        })
        .unwrap();
        let viewer_pk = [0x44; 32];
        let viewer_ml_dsa_pk = [0xAA; ML_DSA_65_PK_LEN];
        let mut kem_ct = [0x55; ML_KEM_768_CT_LEN];
        let viewer_nonce = [0x66; 32];

        let transcript = viewer_signature_transcript(
            &hello_bytes,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );
        let signature = signer.sign(&transcript);

        kem_ct[0] ^= 0x01;
        let tampered = viewer_signature_transcript(
            &hello_bytes,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );

        assert!(HandshakeManager::verify(&verifier, &transcript, &signature).is_ok());
        assert!(HandshakeManager::verify(&verifier, &tampered, &signature).is_err());
    }

    #[test]
    fn viewer_signature_rejects_host_hello_tampering() {
        let signer = HandshakeManager::new();
        let verifier = signer.identity_public_key();
        let hello = HandshakeMessage::HostHello {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x99; ML_DSA_65_PK_LEN],
            kem_pk: [0x22; ML_KEM_768_PK_LEN],
            nonce: [0x33; 32],
            negotiated_context_hash: None,
        };
        let hello_bytes = bincode::serialize(&hello).unwrap();
        let viewer_pk = [0x44; 32];
        let viewer_ml_dsa_pk = [0xAA; ML_DSA_65_PK_LEN];
        let kem_ct = [0x55; ML_KEM_768_CT_LEN];
        let viewer_nonce = [0x66; 32];

        let transcript = viewer_signature_transcript(
            &hello_bytes,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );
        let signature = signer.sign(&transcript);

        let mut tampered_hello = hello_bytes.clone();
        tampered_hello[8] ^= 0x01;
        let tampered = viewer_signature_transcript(
            &tampered_hello,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );

        assert!(HandshakeManager::verify(&verifier, &tampered, &signature).is_err());
    }

    #[test]
    fn viewer_signature_transcript_binds_negotiated_context_hash() {
        let viewer_pk = [0x44; 32];
        let viewer_ml_dsa_pk = [0xAA; ML_DSA_65_PK_LEN];
        let kem_ct = [0x55; ML_KEM_768_CT_LEN];
        let viewer_nonce = [0x66; 32];

        let first_hello = bincode::serialize(&HandshakeMessage::HostHello {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x99; ML_DSA_65_PK_LEN],
            kem_pk: [0x22; ML_KEM_768_PK_LEN],
            nonce: [0x33; 32],
            negotiated_context_hash: Some([0x01; 32]),
        })
        .unwrap();
        let second_hello = bincode::serialize(&HandshakeMessage::HostHello {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x99; ML_DSA_65_PK_LEN],
            kem_pk: [0x22; ML_KEM_768_PK_LEN],
            nonce: [0x33; 32],
            negotiated_context_hash: Some([0x02; 32]),
        })
        .unwrap();

        let first = viewer_signature_transcript(
            &first_hello,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );
        let second = viewer_signature_transcript(
            &second_hello,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );

        assert_ne!(first, second);
    }

    #[test]
    fn host_signature_rejects_viewer_signature_tampering() {
        let signer = HandshakeManager::new();
        let verifier = signer.identity_public_key();
        let hello_bytes = bincode::serialize(&HandshakeMessage::HostHello {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x99; ML_DSA_65_PK_LEN],
            kem_pk: [0x22; ML_KEM_768_PK_LEN],
            nonce: [0x33; 32],
            negotiated_context_hash: None,
        })
        .unwrap();
        let viewer_pk = [0x44; 32];
        let viewer_ml_dsa_pk = [0xAA; ML_DSA_65_PK_LEN];
        let kem_ct = [0x55; ML_KEM_768_CT_LEN];
        let viewer_nonce = [0x66; 32];
        let mut viewer_signature = [0x77; 64];
        let viewer_ml_dsa_signature = [0xBB; ML_DSA_65_SIG_LEN];

        let transcript = host_signature_transcript(
            &hello_bytes,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
            &viewer_signature,
            &viewer_ml_dsa_signature,
        );
        let signature = signer.sign(&transcript);

        viewer_signature[0] ^= 0x01;
        let tampered = host_signature_transcript(
            &hello_bytes,
            &viewer_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
            &viewer_signature,
            &viewer_ml_dsa_signature,
        );

        assert!(HandshakeManager::verify(&verifier, &transcript, &signature).is_ok());
        assert!(HandshakeManager::verify(&verifier, &tampered, &signature).is_err());
    }

    #[test]
    fn negotiated_session_context_hash_binds_transport() {
        let capabilities = RawCapabilities {
            frame_id: 1,
            timestamp_ms: 1_700_000_000_000,
            audio: None,
            video_format: crate::frame::PixelFormat::Passthrough,
            telemetry_enabled: false,
            input_control_enabled: false,
            clipboard_enabled: false,
            lane_envelope_version: crate::frame::LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: crate::frame::LANE_ENVELOPE_MAGIC,
        };

        let tcp = negotiated_session_context_hash(NegotiatedTransport::Tcp, capabilities.clone())
            .unwrap();
        let quic =
            negotiated_session_context_hash(NegotiatedTransport::Quic, capabilities).unwrap();

        assert_ne!(tcp, quic);
        assert_ne!(tcp, [0u8; 32]);
    }

    #[test]
    fn negotiated_session_context_hash_binds_capabilities() {
        let mut capabilities = RawCapabilities {
            frame_id: 1,
            timestamp_ms: 1_700_000_000_000,
            audio: None,
            video_format: crate::frame::PixelFormat::Passthrough,
            telemetry_enabled: false,
            input_control_enabled: false,
            clipboard_enabled: false,
            lane_envelope_version: crate::frame::LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: crate::frame::LANE_ENVELOPE_MAGIC,
        };

        let first = negotiated_session_context_hash(NegotiatedTransport::Tcp, capabilities.clone())
            .unwrap();
        capabilities.telemetry_enabled = true;
        let second =
            negotiated_session_context_hash(NegotiatedTransport::Tcp, capabilities).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn negotiated_session_context_hash_binds_lane_envelope_version() {
        let mut capabilities = RawCapabilities {
            frame_id: 1,
            timestamp_ms: 1_700_000_000_000,
            audio: None,
            video_format: crate::frame::PixelFormat::Passthrough,
            telemetry_enabled: false,
            input_control_enabled: false,
            clipboard_enabled: false,
            lane_envelope_version: crate::frame::LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: crate::frame::LANE_ENVELOPE_MAGIC,
        };

        let first = negotiated_session_context_hash(NegotiatedTransport::Tcp, capabilities.clone())
            .unwrap();
        capabilities.lane_envelope_version = capabilities.lane_envelope_version.saturating_add(1);
        let second =
            negotiated_session_context_hash(NegotiatedTransport::Tcp, capabilities).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn session_epoch_state_accepts_next_epoch_and_rejects_replay() {
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xA5; 32], &[0x5A; 32]);
        let mut state = SessionEpochState::new([0x11; 32], RekeyPolicy::smoke());
        let context = state.next_rekey_context(RekeyReason::FrameCount);
        let epoch_hash = context.epoch_hash().unwrap();

        let accepted = state
            .validate_proposal(
                context.key_epoch,
                context.base_transcript_hash,
                context.previous_epoch_hash,
                context.reason,
                epoch_hash,
            )
            .unwrap();
        let _keys = state.derive_and_install(&schedule, &accepted).unwrap();
        assert_eq!(state.current_epoch(), 1);

        let replay = state.validate_proposal(
            context.key_epoch,
            context.base_transcript_hash,
            context.previous_epoch_hash,
            context.reason,
            epoch_hash,
        );
        assert!(replay.is_err());
        assert_eq!(state.rejected_rekeys(), 1);
    }

    #[test]
    fn session_epoch_state_rejects_skipped_epoch_and_wrong_previous_hash() {
        let mut state = SessionEpochState::new([0x11; 32], RekeyPolicy::smoke());
        let skipped = RekeyEpochContextV1::new(2, [0x11; 32], [0x11; 32], RekeyReason::FrameCount);
        assert!(
            state
                .validate_proposal(
                    skipped.key_epoch,
                    skipped.base_transcript_hash,
                    skipped.previous_epoch_hash,
                    skipped.reason,
                    skipped.epoch_hash().unwrap(),
                )
                .is_err()
        );

        let wrong_prev =
            RekeyEpochContextV1::new(1, [0x11; 32], [0x22; 32], RekeyReason::FrameCount);
        assert!(
            state
                .validate_proposal(
                    wrong_prev.key_epoch,
                    wrong_prev.base_transcript_hash,
                    wrong_prev.previous_epoch_hash,
                    wrong_prev.reason,
                    wrong_prev.epoch_hash().unwrap(),
                )
                .is_err()
        );
    }

    #[test]
    fn session_epoch_state_rejects_wrong_epoch_hash() {
        let mut state = SessionEpochState::new([0x11; 32], RekeyPolicy::smoke());
        let context = state.next_rekey_context(RekeyReason::FrameCount);
        let mut wrong_hash = context.epoch_hash().unwrap();
        wrong_hash[0] ^= 0x01;

        assert!(
            state
                .validate_proposal(
                    context.key_epoch,
                    context.base_transcript_hash,
                    context.previous_epoch_hash,
                    context.reason,
                    wrong_hash,
                )
                .is_err()
        );
    }

    #[test]
    fn session_epoch_state_triggers_byte_count_rekey() {
        let mut state = SessionEpochState::new([0x11; 32], RekeyPolicy::from_limits(0, 1_024));
        state.record_video_frame(512);
        assert!(state.next_rekey_due().is_none());
        state.record_audio_frame(600);
        let context = state.next_rekey_due().unwrap();
        assert_eq!(context.reason, RekeyReason::ByteCount);
    }

    #[test]
    fn session_epoch_state_can_disable_automatic_rekey() {
        let mut state = SessionEpochState::new([0x11; 32], RekeyPolicy::from_limits(0, 0));
        state.record_video_frame(usize::MAX);
        state.record_audio_frame(usize::MAX);
        assert!(state.next_rekey_due().is_none());
    }
}
