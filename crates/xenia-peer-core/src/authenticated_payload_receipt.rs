// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Exact-payload authentication receipts for fully authenticated Xenia sessions.
//!
//! A [`BoundAuthenticatedSession`] can only be built from an opaque
//! [`AuthenticatedSessionEvidenceV1`] plus the exact [`HandshakeOutcome`] whose
//! transcript/context match that evidence. The wrapper installs only that outcome's
//! session key and does not expose a raw rekey/key-install surface.
//!
//! After a successful AEAD open + replay-window admission, Xenia mints an opaque
//! [`AuthenticatedOpenedPayload`]. A configured [`TransportReceiptSigner`] may turn
//! that local token into a short-lived hybrid-signed [`AuthenticatedPayloadReceiptV1`].
//! Both Ed25519 and ML-DSA-65 signatures cover the identical receipt digest; there is
//! no classical-only fallback.
//!
//! The serialized receipt is portable evidence, **not authority**. A relying party
//! must independently trust the attestor identity, bind the exact payload digest,
//! enforce freshness/capability requirements, and apply its own semantic/physical
//! policy before permitting any consequence.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use xenia_handshake::{
    HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, TRANSCRIPT_SIGNATURE_SUITE_LABEL,
};

use crate::handshake::HandshakeOutcome;
use crate::{
    AuthenticatedPeerRole, AuthenticatedSessionEvidenceError, AuthenticatedSessionEvidenceV1,
    Session, SessionRole,
};

/// Stable schema label for portable exact-payload receipts.
pub const AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA: &str = "xenia-authenticated-payload-receipt-v1";
/// Domain separator committed before both receipt signatures.
pub const AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN: &[u8] =
    b"xenia-authenticated-payload-receipt-v1\0";
/// Lowest payload type reserved for application-defined Xenia traffic.
pub const MIN_APPLICATION_PAYLOAD_TYPE: u8 = 0x30;
/// Maximum opened application plaintext accepted by this high-consequence channel.
pub const MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum validity of a portable transport receipt after AEAD/replay acceptance.
pub const MAX_TRANSPORT_RECEIPT_LIFETIME_MS: u64 = 5_000;
/// Maximum UTF-8 byte length of attestor/key identifiers carried in a receipt.
pub const MAX_TRANSPORT_ATTESTOR_LABEL_BYTES: usize = 128;

/// Portable vocabulary for the authenticated remote role recorded in a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptPeerRoleV1 {
    /// The authenticated remote peer is the controlled/serving host.
    Host,
    /// The authenticated remote peer is the viewer/operator side.
    Viewer,
}

impl From<AuthenticatedPeerRole> for ReceiptPeerRoleV1 {
    fn from(value: AuthenticatedPeerRole) -> Self {
        match value {
            AuthenticatedPeerRole::Host => Self::Host,
            AuthenticatedPeerRole::Viewer => Self::Viewer,
        }
    }
}

/// Opaque session binding an actually installed handshake key to the exact opaque
/// authenticated application-session evidence retained by this object.
///
/// There is deliberately no constructor accepting a raw key and no public method
/// that can replace the key independently of the evidence. Rekey support should be
/// another authenticated type transition rather than exposing ambient key mutation.
pub struct BoundAuthenticatedSession {
    session: Session,
    evidence: AuthenticatedSessionEvidenceV1,
    evidence_digest: [u8; 32],
}

impl std::fmt::Debug for BoundAuthenticatedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundAuthenticatedSession")
            .field("local_role", &self.session.role())
            .field("peer_role", &self.evidence.peer_role())
            .field(
                "peer_identity_fingerprint",
                &self.evidence.peer_identity_fingerprint(),
            )
            .field("transcript_hash", &self.evidence.transcript_hash())
            .field("session_context_hash", &self.evidence.session_context_hash())
            .finish_non_exhaustive()
    }
}

impl BoundAuthenticatedSession {
    /// Bind one local Xenia wire session to the exact verified handshake outcome and
    /// capability-authenticated application-session evidence.
    ///
    /// The evidence transcript/context must match the outcome exactly and the local
    /// role must be the opposite of the authenticated remote role. On success this
    /// consumes both values and installs only `outcome.session_key`.
    pub fn from_authenticated_handshake(
        local_role: SessionRole,
        outcome: HandshakeOutcome,
        evidence: AuthenticatedSessionEvidenceV1,
    ) -> Result<Self, AuthenticatedPayloadReceiptError> {
        if evidence.transcript_hash() != outcome.transcript_hash {
            return Err(AuthenticatedPayloadReceiptError::TranscriptMismatch);
        }
        if Some(evidence.session_context_hash()) != outcome.negotiated_context_hash {
            return Err(AuthenticatedPayloadReceiptError::SessionContextMismatch);
        }
        if !matches!(
            (local_role, evidence.peer_role()),
            (SessionRole::Host, AuthenticatedPeerRole::Viewer)
                | (SessionRole::Viewer, AuthenticatedPeerRole::Host)
        ) {
            return Err(AuthenticatedPayloadReceiptError::PeerRoleMismatch);
        }

        let evidence_digest = evidence.digest()?;
        let mut session = match local_role {
            SessionRole::Host => Session::host(),
            SessionRole::Viewer => Session::viewer(),
        };
        session.install_key(outcome.session_key);

        Ok(Self {
            session,
            evidence,
            evidence_digest,
        })
    }

    /// Read-only authenticated-session evidence bound to this wire session.
    pub fn evidence(&self) -> &AuthenticatedSessionEvidenceV1 {
        &self.evidence
    }

    /// Domain-separated commitment to the complete bound session evidence.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    /// Seal one non-empty bounded application payload under the bound Xenia session.
    ///
    /// This authenticates/encrypts bytes; it does not confer domain authority on
    /// those bytes. Consequential consumers must still apply their own semantics.
    pub fn seal_application_payload(
        &mut self,
        payload: &[u8],
        payload_type: u8,
    ) -> Result<Vec<u8>, AuthenticatedPayloadReceiptError> {
        validate_application_payload(payload, payload_type)?;
        self.session
            .wire()
            .seal(payload, payload_type)
            .map_err(Into::into)
    }

    /// AEAD-open and replay-admit one exact bounded application payload.
    ///
    /// The acceptance timestamp is obtained from the receiver's local system clock;
    /// callers cannot self-assert it through the production API.
    pub fn open_application_payload(
        &mut self,
        envelope: &[u8],
        expected_payload_type: u8,
    ) -> Result<AuthenticatedOpenedPayload, AuthenticatedPayloadReceiptError> {
        self.open_application_payload_at(envelope, expected_payload_type, unix_ms_now())
    }

    fn open_application_payload_at(
        &mut self,
        envelope: &[u8],
        expected_payload_type: u8,
        opened_at_unix_ms: u64,
    ) -> Result<AuthenticatedOpenedPayload, AuthenticatedPayloadReceiptError> {
        if expected_payload_type < MIN_APPLICATION_PAYLOAD_TYPE {
            return Err(AuthenticatedPayloadReceiptError::ReservedPayloadType);
        }
        let maximum_envelope = MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES + 28;
        if envelope.len() > maximum_envelope {
            return Err(AuthenticatedPayloadReceiptError::EnvelopeTooLarge {
                actual: envelope.len(),
                maximum: maximum_envelope,
            });
        }
        let actual_payload_type = xenia_wire::envelope_payload_type(envelope)
            .ok_or(AuthenticatedPayloadReceiptError::MalformedEnvelope)?;
        if actual_payload_type != expected_payload_type {
            return Err(AuthenticatedPayloadReceiptError::PayloadTypeMismatch {
                expected: expected_payload_type,
                actual: actual_payload_type,
            });
        }

        // `Session::open` performs AEAD verification and replay-window admission
        // before returning plaintext. No receipt token exists before this succeeds.
        let plaintext = self.session.wire().open(envelope)?;
        validate_application_payload(&plaintext, expected_payload_type)?;
        let payload_digest = *blake3::hash(&plaintext).as_bytes();
        let sealed_envelope_digest = *blake3::hash(envelope).as_bytes();

        Ok(AuthenticatedOpenedPayload {
            plaintext,
            payload_type: expected_payload_type,
            payload_digest,
            sealed_envelope_digest,
            opened_at_unix_ms,
            session_evidence_digest: self.evidence_digest,
            peer_role: self.evidence.peer_role().into(),
            peer_identity_fingerprint: self.evidence.peer_identity_fingerprint(),
            transcript_hash: self.evidence.transcript_hash(),
            session_context_hash: self.evidence.session_context_hash(),
            telemetry_enabled: self.evidence.telemetry_enabled(),
            input_control_enabled: self.evidence.input_control_enabled(),
        })
    }
}

fn validate_application_payload(
    payload: &[u8],
    payload_type: u8,
) -> Result<(), AuthenticatedPayloadReceiptError> {
    if payload_type < MIN_APPLICATION_PAYLOAD_TYPE {
        return Err(AuthenticatedPayloadReceiptError::ReservedPayloadType);
    }
    if payload.is_empty() {
        return Err(AuthenticatedPayloadReceiptError::EmptyPayload);
    }
    if payload.len() > MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES {
        return Err(AuthenticatedPayloadReceiptError::PayloadTooLarge {
            actual: payload.len(),
            maximum: MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Opaque in-process proof that one exact plaintext passed Xenia AEAD verification
/// and replay-window admission under one bound authenticated session.
///
/// This type is not serializable and has no public constructor. It is the only value
/// that [`TransportReceiptSigner`] accepts for receipt signing.
#[derive(Debug)]
pub struct AuthenticatedOpenedPayload {
    plaintext: Vec<u8>,
    payload_type: u8,
    payload_digest: [u8; 32],
    sealed_envelope_digest: [u8; 32],
    opened_at_unix_ms: u64,
    session_evidence_digest: [u8; 32],
    peer_role: ReceiptPeerRoleV1,
    peer_identity_fingerprint: [u8; 32],
    transcript_hash: [u8; 32],
    session_context_hash: [u8; 32],
    telemetry_enabled: bool,
    input_control_enabled: bool,
}

impl AuthenticatedOpenedPayload {
    /// Exact plaintext returned by the authenticated wire open.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// BLAKE3-256 commitment to the exact opened plaintext.
    pub const fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    /// BLAKE3-256 commitment to the exact sealed envelope that was admitted.
    pub const fn sealed_envelope_digest(&self) -> [u8; 32] {
        self.sealed_envelope_digest
    }

    /// Receiver-local Unix time in milliseconds at which AEAD/replay admission succeeded.
    pub const fn opened_at_unix_ms(&self) -> u64 {
        self.opened_at_unix_ms
    }
}

/// Signed portable body describing one exact AEAD-opened application payload.
///
/// These public fields are wire/audit data and are freely constructible. They gain
/// evidentiary meaning only when both signatures in [`AuthenticatedPayloadReceiptV1`]
/// verify under a relying party's separately trusted Xenia transport-attestor keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPayloadReceiptBodyV1 {
    /// Stable schema label.
    pub schema: String,
    /// Deployment/operator identifier for the receipt-signing service.
    pub attestor_id: String,
    /// Lifecycle key identifier understood by the downstream trust registry.
    pub key_id: String,
    /// Required signature-suite label; currently Xenia's hybrid transcript suite.
    pub signature_algorithm: String,
    /// Commitment to the opaque authenticated application-session evidence.
    pub session_evidence_digest: [u8; 32],
    /// Authenticated remote peer role.
    pub peer_role: ReceiptPeerRoleV1,
    /// BLAKE3 fingerprint of the authenticated remote Ed25519 + ML-DSA identity.
    pub peer_identity_fingerprint: [u8; 32],
    /// Canonical public handshake transcript commitment.
    pub transcript_hash: [u8; 32],
    /// Exact negotiated/capability-authenticated application-session context.
    pub session_context_hash: [u8; 32],
    /// Whether the sealed capabilities frame enabled telemetry.
    pub telemetry_enabled: bool,
    /// Whether the sealed capabilities frame enabled remote input/control.
    pub input_control_enabled: bool,
    /// Exact Xenia application payload type admitted by the receiver.
    pub payload_type: u8,
    /// Exact opened plaintext length in bytes.
    pub payload_len: u32,
    /// BLAKE3-256 of the exact opened plaintext.
    pub payload_digest: [u8; 32],
    /// BLAKE3-256 of the exact sealed envelope that passed AEAD/replay admission.
    pub sealed_envelope_digest: [u8; 32],
    /// Receiver-local acceptance time in Unix milliseconds.
    pub opened_at_unix_ms: u64,
    /// Exclusive receipt expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl AuthenticatedPayloadReceiptBodyV1 {
    /// Validate bounded receipt structure independent of cryptographic key trust.
    pub fn validate(&self) -> Result<(), AuthenticatedPayloadReceiptError> {
        if self.schema != AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA {
            return Err(AuthenticatedPayloadReceiptError::UnsupportedReceiptSchema);
        }
        if self.attestor_id.is_empty()
            || self.key_id.is_empty()
            || self.attestor_id.len() > MAX_TRANSPORT_ATTESTOR_LABEL_BYTES
            || self.key_id.len() > MAX_TRANSPORT_ATTESTOR_LABEL_BYTES
            || self.attestor_id.trim() != self.attestor_id
            || self.key_id.trim() != self.key_id
        {
            return Err(AuthenticatedPayloadReceiptError::InvalidAttestorIdentity);
        }
        if self.signature_algorithm != TRANSCRIPT_SIGNATURE_SUITE_LABEL {
            return Err(AuthenticatedPayloadReceiptError::UnsupportedSignatureAlgorithm);
        }
        if self.payload_type < MIN_APPLICATION_PAYLOAD_TYPE {
            return Err(AuthenticatedPayloadReceiptError::ReservedPayloadType);
        }
        if self.payload_len == 0
            || self.payload_len as usize > MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES
        {
            return Err(AuthenticatedPayloadReceiptError::InvalidPayloadLength);
        }
        if [
            self.session_evidence_digest,
            self.peer_identity_fingerprint,
            self.transcript_hash,
            self.session_context_hash,
            self.payload_digest,
            self.sealed_envelope_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(AuthenticatedPayloadReceiptError::ZeroSecurityDigest);
        }
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.opened_at_unix_ms)
            .ok_or(AuthenticatedPayloadReceiptError::InvalidReceiptLifetime)?;
        if lifetime == 0 || lifetime > MAX_TRANSPORT_RECEIPT_LIFETIME_MS {
            return Err(AuthenticatedPayloadReceiptError::InvalidReceiptLifetime);
        }
        Ok(())
    }

    /// Canonical bincode-v1 body bytes shared by both signature verifiers.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthenticatedPayloadReceiptError> {
        self.validate()?;
        bincode::serialize(self).map_err(Into::into)
    }

    /// Domain-separated BLAKE3-256 digest signed by both receipt signature suites.
    pub fn signing_digest(&self) -> Result<[u8; 32], AuthenticatedPayloadReceiptError> {
        let bytes = self.canonical_bytes()?;
        let mut h = blake3::Hasher::new();
        h.update(AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN);
        h.update(&bytes);
        Ok(*h.finalize().as_bytes())
    }
}

/// Portable evidence that one exact application payload crossed a fully authenticated
/// Xenia AEAD/replay boundary.
///
/// Both signatures are mandatory and cover the same body digest. The object remains
/// non-authorizing until a downstream relying party authenticates the attestor key
/// lifecycle and binds the receipt to its own domain policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPayloadReceiptV1 {
    /// Signed receipt body.
    pub body: AuthenticatedPayloadReceiptBodyV1,
    /// Ed25519 signature over `body.signing_digest()`.
    #[serde(with = "BigArray")]
    pub ed25519_signature: [u8; 64],
    /// ML-DSA-65 signature over the identical `body.signing_digest()`.
    #[serde(with = "BigArray")]
    pub ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
}

impl AuthenticatedPayloadReceiptV1 {
    /// Verify structure, freshness, Ed25519 and ML-DSA-65 signatures against an
    /// already-trusted hybrid attestor identity.
    ///
    /// This method deliberately does **not** decide whether the supplied key pair is
    /// authorized for a particular device or physical action. That belongs to the
    /// relying party's anti-rollback trust registry.
    pub fn verify_with_trusted_identity(
        &self,
        ed25519_public_key: &[u8; 32],
        ml_dsa_public_key: &[u8; ML_DSA_65_PK_LEN],
        now_unix_ms: u64,
    ) -> Result<(), AuthenticatedPayloadReceiptError> {
        self.body.validate()?;
        if now_unix_ms < self.body.opened_at_unix_ms || now_unix_ms >= self.body.expires_at_unix_ms {
            return Err(AuthenticatedPayloadReceiptError::ReceiptNotFresh);
        }
        let digest = self.body.signing_digest()?;
        let ed25519_key = HandshakeManager::parse_peer_public_key(ed25519_public_key)
            .map_err(|_| AuthenticatedPayloadReceiptError::InvalidAttestorPublicKey)?;
        HandshakeManager::verify(
            &ed25519_key,
            &digest,
            &Signature::from_bytes(&self.ed25519_signature),
        )
        .map_err(|_| AuthenticatedPayloadReceiptError::InvalidEd25519ReceiptSignature)?;
        HandshakeManager::verify_ml_dsa(ml_dsa_public_key, &digest, &self.ml_dsa_signature)
            .map_err(|_| AuthenticatedPayloadReceiptError::InvalidMlDsaReceiptSignature)?;
        Ok(())
    }
}

/// Configured local hybrid receipt signer.
///
/// The owned [`HandshakeManager`] is used only as a convenient persisted hybrid
/// identity container here. Authorization/rotation of that identity remains a
/// deployment responsibility and must be mirrored in the relying party's trust
/// registry.
pub struct TransportReceiptSigner {
    attestor_id: String,
    key_id: String,
    identity: HandshakeManager,
}

impl std::fmt::Debug for TransportReceiptSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportReceiptSigner")
            .field("attestor_id", &self.attestor_id)
            .field("key_id", &self.key_id)
            .field("identity_fingerprint", &self.identity.identity_fingerprint())
            .finish_non_exhaustive()
    }
}

impl TransportReceiptSigner {
    /// Configure one transport receipt signer around a persisted hybrid identity.
    pub fn new(
        attestor_id: impl Into<String>,
        key_id: impl Into<String>,
        identity: HandshakeManager,
    ) -> Result<Self, AuthenticatedPayloadReceiptError> {
        let attestor_id = attestor_id.into();
        let key_id = key_id.into();
        if attestor_id.is_empty()
            || key_id.is_empty()
            || attestor_id.len() > MAX_TRANSPORT_ATTESTOR_LABEL_BYTES
            || key_id.len() > MAX_TRANSPORT_ATTESTOR_LABEL_BYTES
            || attestor_id.trim() != attestor_id
            || key_id.trim() != key_id
        {
            return Err(AuthenticatedPayloadReceiptError::InvalidAttestorIdentity);
        }
        Ok(Self {
            attestor_id,
            key_id,
            identity,
        })
    }

    /// Ed25519 verifying-key bytes to provision into a relying-party trust registry.
    pub fn ed25519_public_key_bytes(&self) -> [u8; 32] {
        self.identity.identity_public_key_bytes()
    }

    /// ML-DSA-65 verifying-key bytes to provision into a relying-party trust registry.
    pub fn ml_dsa_public_key_bytes(&self) -> [u8; ML_DSA_65_PK_LEN] {
        self.identity.ml_dsa_public_key_bytes()
    }

    /// BLAKE3 fingerprint of the signer's complete hybrid identity.
    pub fn identity_fingerprint(&self) -> [u8; 32] {
        self.identity.identity_fingerprint()
    }

    /// Sign a receipt for one opaque AEAD-opened payload for a bounded lifetime.
    ///
    /// `lifetime_ms` must be in `1..=MAX_TRANSPORT_RECEIPT_LIFETIME_MS`.
    pub fn sign_opened_payload(
        &self,
        opened: &AuthenticatedOpenedPayload,
        lifetime_ms: u64,
    ) -> Result<AuthenticatedPayloadReceiptV1, AuthenticatedPayloadReceiptError> {
        if lifetime_ms == 0 || lifetime_ms > MAX_TRANSPORT_RECEIPT_LIFETIME_MS {
            return Err(AuthenticatedPayloadReceiptError::InvalidReceiptLifetime);
        }
        let expires_at_unix_ms = opened
            .opened_at_unix_ms
            .checked_add(lifetime_ms)
            .ok_or(AuthenticatedPayloadReceiptError::ReceiptTimeOverflow)?;
        let body = AuthenticatedPayloadReceiptBodyV1 {
            schema: AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA.to_string(),
            attestor_id: self.attestor_id.clone(),
            key_id: self.key_id.clone(),
            signature_algorithm: TRANSCRIPT_SIGNATURE_SUITE_LABEL.to_string(),
            session_evidence_digest: opened.session_evidence_digest,
            peer_role: opened.peer_role,
            peer_identity_fingerprint: opened.peer_identity_fingerprint,
            transcript_hash: opened.transcript_hash,
            session_context_hash: opened.session_context_hash,
            telemetry_enabled: opened.telemetry_enabled,
            input_control_enabled: opened.input_control_enabled,
            payload_type: opened.payload_type,
            payload_len: u32::try_from(opened.plaintext.len())
                .map_err(|_| AuthenticatedPayloadReceiptError::InvalidPayloadLength)?,
            payload_digest: opened.payload_digest,
            sealed_envelope_digest: opened.sealed_envelope_digest,
            opened_at_unix_ms: opened.opened_at_unix_ms,
            expires_at_unix_ms,
        };
        let digest = body.signing_digest()?;
        Ok(AuthenticatedPayloadReceiptV1 {
            body,
            ed25519_signature: self.identity.sign(&digest).to_bytes(),
            ml_dsa_signature: self.identity.sign_ml_dsa(&digest),
        })
    }
}

/// Failure at the exact authenticated-payload receipt boundary.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedPayloadReceiptError {
    /// The lower opaque authenticated-session evidence could not be encoded/bound.
    #[error("authenticated session evidence failed: {0}")]
    SessionEvidence(#[from] AuthenticatedSessionEvidenceError),
    /// The supplied evidence and handshake outcome bind different transcript hashes.
    #[error("authenticated session evidence does not match handshake transcript")]
    TranscriptMismatch,
    /// The supplied evidence and handshake outcome bind different session contexts.
    #[error("authenticated session evidence does not match negotiated session context")]
    SessionContextMismatch,
    /// Local and authenticated remote roles cannot form the expected peer pair.
    #[error("authenticated peer role is inconsistent with local session role")]
    PeerRoleMismatch,
    /// The underlying Xenia wire seal/open operation failed.
    #[error("xenia wire operation failed: {0}")]
    Wire(#[from] xenia_wire::WireError),
    /// A caller tried to use a protocol-reserved payload type as application traffic.
    #[error("payload type is reserved for Xenia protocol traffic")]
    ReservedPayloadType,
    /// Consequential application payloads must not be empty.
    #[error("application payload must not be empty")]
    EmptyPayload,
    /// Opened/sealed plaintext exceeded the configured high-consequence bound.
    #[error("application payload too large: {actual} > {maximum}")]
    PayloadTooLarge {
        /// Actual plaintext size.
        actual: usize,
        /// Maximum accepted plaintext size.
        maximum: usize,
    },
    /// Sealed application envelope exceeded plaintext bound plus AEAD overhead.
    #[error("sealed application envelope too large: {actual} > {maximum}")]
    EnvelopeTooLarge {
        /// Actual sealed-envelope size.
        actual: usize,
        /// Maximum accepted sealed-envelope size.
        maximum: usize,
    },
    /// Sealed bytes were too short to expose the required Xenia nonce metadata.
    #[error("sealed application envelope is malformed")]
    MalformedEnvelope,
    /// Clear nonce payload type did not equal the type expected by this receiver.
    #[error("sealed payload type mismatch: expected {expected:#04x}, got {actual:#04x}")]
    PayloadTypeMismatch {
        /// Receiver-required payload type.
        expected: u8,
        /// Payload type carried by the sealed Xenia nonce.
        actual: u8,
    },
    /// Portable receipt schema is unknown.
    #[error("unsupported authenticated-payload receipt schema")]
    UnsupportedReceiptSchema,
    /// Attestor/key identifier was empty, non-canonical, or oversized.
    #[error("transport attestor identity/key label is invalid")]
    InvalidAttestorIdentity,
    /// Receipt did not require Xenia's current hybrid Ed25519 + ML-DSA suite.
    #[error("unsupported receipt signature algorithm")]
    UnsupportedSignatureAlgorithm,
    /// Receipt plaintext length was zero or over the security bound.
    #[error("portable receipt contains an invalid payload length")]
    InvalidPayloadLength,
    /// One of the receipt's security commitments was all zero bytes.
    #[error("portable receipt contains a zero security commitment")]
    ZeroSecurityDigest,
    /// Receipt lifetime was zero, backwards, or above the five-second ceiling.
    #[error("portable receipt lifetime is invalid")]
    InvalidReceiptLifetime,
    /// Receipt expiry overflowed the Unix-millisecond representation.
    #[error("portable receipt expiry overflowed")]
    ReceiptTimeOverflow,
    /// Receipt is not valid at the relying party's current wall-clock value.
    #[error("portable receipt is not fresh at relying-party time")]
    ReceiptNotFresh,
    /// The configured Ed25519 attestor public key could not be parsed.
    #[error("transport attestor Ed25519 public key is invalid")]
    InvalidAttestorPublicKey,
    /// Ed25519 receipt signature did not verify.
    #[error("portable receipt Ed25519 signature is invalid")]
    InvalidEd25519ReceiptSignature,
    /// ML-DSA-65 receipt signature did not verify.
    #[error("portable receipt ML-DSA-65 signature is invalid")]
    InvalidMlDsaReceiptSignature,
    /// Canonical bincode-v1 receipt-body encoding failed.
    #[error("portable receipt encoding failed: {0}")]
    Encoding(#[from] bincode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated_session_evidence::test_authenticated_session_evidence;
    use crate::frame::{
        INPUT_EVENT_SCHEMA_VERSION, LANE_ENVELOPE_MAGIC, LANE_ENVELOPE_SCHEMA_VERSION, PixelFormat,
        RawCapabilities,
    };
    use crate::handshake::PendingSessionSurface;
    use crate::transport::{TransportKind, TransportProfileV1};
    use xenia_handshake::SessionKeySchedule;

    fn capabilities() -> RawCapabilities {
        RawCapabilities {
            frame_id: 1,
            timestamp_ms: 1,
            audio: None,
            video_format: PixelFormat::Passthrough,
            telemetry_enabled: false,
            input_control_enabled: true,
            clipboard_enabled: false,
            input_event_schema_version: INPUT_EVENT_SCHEMA_VERSION,
            lane_envelope_version: LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: LANE_ENVELOPE_MAGIC,
        }
    }

    fn schedule() -> SessionKeySchedule {
        SessionKeySchedule {
            aead: [0x44; 32],
            control: [0x45; 32],
            video: [0x46; 32],
            audio: [0x47; 32],
            telemetry: [0x48; 32],
            rekey: [0x49; 32],
            context: [0x4A; 32],
        }
    }

    fn bound_pair() -> (BoundAuthenticatedSession, BoundAuthenticatedSession) {
        let surface =
            PendingSessionSurface::new(None, TransportProfileV1::current(TransportKind::Tcp))
                .unwrap()
                .authenticate_capabilities(capabilities())
                .unwrap();
        let outcome = HandshakeOutcome {
            session_key: [0x44; 32],
            transcript_hash: [0x22; 32],
            key_schedule: schedule(),
            negotiated_context_hash: Some(surface.context_hash()),
            host_identity_fingerprint: [0x33; 32],
        };
        let host_ev = test_authenticated_session_evidence(
            AuthenticatedPeerRole::Viewer,
            [0x11; 32],
            outcome.transcript_hash,
            &surface,
        );
        let viewer_ev = test_authenticated_session_evidence(
            AuthenticatedPeerRole::Host,
            [0x33; 32],
            outcome.transcript_hash,
            &surface,
        );
        (
            BoundAuthenticatedSession::from_authenticated_handshake(
                SessionRole::Host,
                outcome,
                host_ev,
            )
            .unwrap(),
            BoundAuthenticatedSession::from_authenticated_handshake(
                SessionRole::Viewer,
                outcome,
                viewer_ev,
            )
            .unwrap(),
        )
    }

    fn signer() -> TransportReceiptSigner {
        TransportReceiptSigner::new(
            "xenia-host-a",
            "transport-attestor-1",
            HandshakeManager::from_identity_seeds([0x66; 32], [0x77; 32]),
        )
        .unwrap()
    }

    #[test]
    fn exact_payload_open_mints_hybrid_receipt_and_replay_fails() {
        let (mut host, mut viewer) = bound_pair();
        let payload = b"physical-effect-envelope";
        let sealed = viewer.seal_application_payload(payload, 0x70).unwrap();
        let opened = host
            .open_application_payload_at(&sealed, 0x70, 10_000)
            .unwrap();
        assert_eq!(opened.plaintext(), payload);

        let signer = signer();
        let receipt = signer.sign_opened_payload(&opened, 2_000).unwrap();
        receipt
            .verify_with_trusted_identity(
                &signer.ed25519_public_key_bytes(),
                &signer.ml_dsa_public_key_bytes(),
                11_000,
            )
            .unwrap();
        assert_eq!(receipt.body.payload_digest, *blake3::hash(payload).as_bytes());
        assert!(receipt.body.input_control_enabled);
        assert!(host
            .open_application_payload_at(&sealed, 0x70, 10_001)
            .is_err());
    }

    #[test]
    fn evidence_from_another_transcript_cannot_bind_session_key() {
        let (host, _) = bound_pair();
        let evidence = host.evidence.clone();
        let bad = HandshakeOutcome {
            session_key: [0x44; 32],
            transcript_hash: [0x99; 32],
            key_schedule: schedule(),
            negotiated_context_hash: Some(evidence.session_context_hash()),
            host_identity_fingerprint: [0x33; 32],
        };
        assert!(matches!(
            BoundAuthenticatedSession::from_authenticated_handshake(
                SessionRole::Host,
                bad,
                evidence
            ),
            Err(AuthenticatedPayloadReceiptError::TranscriptMismatch)
        ));
    }

    #[test]
    fn either_signature_tamper_and_expiry_fail_closed() {
        let (mut host, mut viewer) = bound_pair();
        let sealed = viewer.seal_application_payload(b"A", 0x70).unwrap();
        let opened = host
            .open_application_payload_at(&sealed, 0x70, 20_000)
            .unwrap();
        let signer = signer();

        let mut tampered_body = signer.sign_opened_payload(&opened, 1_000).unwrap();
        tampered_body.body.payload_digest = *blake3::hash(b"B").as_bytes();
        assert!(matches!(
            tampered_body.verify_with_trusted_identity(
                &signer.ed25519_public_key_bytes(),
                &signer.ml_dsa_public_key_bytes(),
                20_500,
            ),
            Err(AuthenticatedPayloadReceiptError::InvalidEd25519ReceiptSignature)
        ));

        let mut tampered_pq = signer.sign_opened_payload(&opened, 1_000).unwrap();
        tampered_pq.ml_dsa_signature[0] ^= 1;
        assert!(matches!(
            tampered_pq.verify_with_trusted_identity(
                &signer.ed25519_public_key_bytes(),
                &signer.ml_dsa_public_key_bytes(),
                20_500,
            ),
            Err(AuthenticatedPayloadReceiptError::InvalidMlDsaReceiptSignature)
        ));

        let receipt = signer.sign_opened_payload(&opened, 1_000).unwrap();
        assert!(matches!(
            receipt.verify_with_trusted_identity(
                &signer.ed25519_public_key_bytes(),
                &signer.ml_dsa_public_key_bytes(),
                21_000,
            ),
            Err(AuthenticatedPayloadReceiptError::ReceiptNotFresh)
        ));
    }
}
