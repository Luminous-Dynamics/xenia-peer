// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Exact-payload authentication receipts for fully authenticated Xenia sessions.
//!
//! This module solves a cross-process composition problem without making a portable
//! receipt itself into authority. A [`BoundAuthenticatedSession`] can only be built
//! from an opaque [`AuthenticatedSessionEvidenceV1`] plus the exact
//! [`HandshakeOutcome`] whose session key/transcript/context match that evidence.
//! It owns a normal Xenia [`Session`] and performs application-range AEAD open/seal.
//!
//! After a successful AEAD open + replay-window admission, the module can mint an
//! opaque [`AuthenticatedOpenedPayload`]. A configured [`TransportReceiptSigner`]
//! may sign a short-lived, bounded [`AuthenticatedPayloadReceiptV1`] over that exact
//! opened payload. The receipt is portable evidence for a downstream relying party;
//! it is **not** a Xenia session token, consent grant, or physical capability.
//!
//! A downstream cyber-physical system must independently trust the receipt signer,
//! bind `payload_digest` to its exact semantic envelope, enforce receipt freshness,
//! and still apply its own authority/safety/interlock policy.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{
    AuthenticatedPeerRole, AuthenticatedSessionEvidenceError, AuthenticatedSessionEvidenceV1,
    HandshakeOutcome, Session, SessionRole,
};

/// Stable portable-receipt schema label.
pub const AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA: &str = "xenia-authenticated-payload-receipt-v1";
/// Domain separator signed by the transport-attestor key.
pub const AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN: &[u8] =
    b"xenia-authenticated-payload-receipt-v1\0";
/// Xenia application payload range starts at 0x30.
pub const MIN_APPLICATION_PAYLOAD_TYPE: u8 = 0x30;
/// Bound a consequential application payload before AEAD processing.
pub const MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES: usize = 64 * 1024;
/// Receipts are intentionally very short lived.
pub const MAX_TRANSPORT_RECEIPT_LIFETIME_MS: u64 = 5_000;
/// Bound operator-controlled key/attestor labels in portable receipts.
pub const MAX_TRANSPORT_ATTESTOR_LABEL_BYTES: usize = 128;

/// Portable peer-role vocabulary used by a serialized receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptPeerRoleV1 {
    /// Remote peer is the controlled/serving host.
    Host,
    /// Remote peer is the viewer/operator.
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

/// Opaque session whose actual installed key is bound to the exact opaque
/// authenticated-session evidence retained by this object.
///
/// This type intentionally has no constructor accepting a raw key and no way to
/// replace the session key independently of the evidence. Rekey composition can be
/// added later as another authenticated type transition rather than exposing
/// `Session::install_key` through this wrapper.
pub struct BoundAuthenticatedSession {
    session: Session,
    evidence: AuthenticatedSessionEvidenceV1,
    evidence_digest: [u8; 32],
}

impl std::fmt::Debug for BoundAuthenticatedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundAuthenticatedSession")
            .field("role", &self.session.role())
            .field("peer_role", &self.evidence.peer_role())
            .field("peer_identity_fingerprint", &self.evidence.peer_identity_fingerprint())
            .field("transcript_hash", &self.evidence.transcript_hash())
            .field("session_context_hash", &self.evidence.session_context_hash())
            .finish_non_exhaustive()
    }
}

impl BoundAuthenticatedSession {
    /// Consume a verified handshake outcome + opaque application-session evidence
    /// and install exactly that handshake's session key into a newly owned session.
    ///
    /// The local role must be the opposite of the authenticated remote role.
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
        let role_matches = matches!(
            (local_role, evidence.peer_role()),
            (SessionRole::Host, AuthenticatedPeerRole::Viewer)
                | (SessionRole::Viewer, AuthenticatedPeerRole::Host)
        );
        if !role_matches {
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

    /// Domain-separated commitment to the authenticated-session evidence.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    /// Seal one bounded application-range payload under the authenticated session.
    pub fn seal_application_payload(
        &mut self,
        payload: &[u8],
        payload_type: u8,
    ) -> Result<Vec<u8>, AuthenticatedPayloadReceiptError> {
        validate_application_payload(payload, payload_type)?;
        self.session
            .wire()
            .seal(payload, payload_type)
            .map_err(AuthenticatedPayloadReceiptError::Wire)
    }

    /// AEAD-open + replay-admit one exact application-range envelope and mint an
    /// opaque local token containing the exact accepted plaintext.
    pub fn open_application_payload(
        &mut self,
        envelope: &[u8],
        expected_payload_type: u8,
        opened_at_unix_ms: u64,
    ) -> Result<AuthenticatedOpenedPayload, AuthenticatedPayloadReceiptError> {
        if expected_payload_type < MIN_APPLICATION_PAYLOAD_TYPE {
            return Err(AuthenticatedPayloadReceiptError::ReservedPayloadType);
        }
        if envelope.len() > MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES + 28 {
            return Err(AuthenticatedPayloadReceiptError::EnvelopeTooLarge {
                actual: envelope.len(),
                maximum: MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES + 28,
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

        let plaintext = self
            .session
            .wire()
            .open(envelope)
            .map_err(AuthenticatedPayloadReceiptError::Wire)?;
        validate_application_payload(&plaintext, expected_payload_type)?;

        Ok(AuthenticatedOpenedPayload {
            plaintext,
            payload_type: expected_payload_type,
            payload_digest: *blake3::hash(&plaintext).as_bytes(),
            sealed_envelope_digest: *blake3::hash(envelope).as_bytes(),
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

/// Opaque in-process proof that the exact plaintext was successfully AEAD-opened
/// and admitted by Xenia's replay window under one bound authenticated session.
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
    /// Exact opened plaintext.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// BLAKE3-256 of the exact opened plaintext.
    pub const fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    /// BLAKE3-256 of the exact sealed envelope admitted by AEAD + replay checks.
    pub const fn sealed_envelope_digest(&self) -> [u8; 32] {
        self.sealed_envelope_digest
    }
}

/// Signed portable evidence body for one exact AEAD-opened application payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPayloadReceiptBodyV1 {
    /// Stable receipt schema label.
    pub schema: String,
    /// Deployment/operator identity of the Xenia transport-attestation service.
    pub attestor_id: String,
    /// Key identity used to sign this receipt.
    pub key_id: String,
    /// Fixed signature algorithm label.
    pub signature_algorithm: String,
    /// Commitment to the opaque authenticated application-session evidence.
    pub session_evidence_digest: [u8; 32],
    /// Authenticated remote peer role.
    pub peer_role: ReceiptPeerRoleV1,
    /// Authenticated hybrid-signing identity fingerprint.
    pub peer_identity_fingerprint: [u8; 32],
    /// Canonical public handshake transcript commitment.
    pub transcript_hash: [u8; 32],
    /// Exact capability-authenticated application-session context.
    pub session_context_hash: [u8; 32],
    /// Sealed capability bit carried into the receipt for relying-party policy.
    pub telemetry_enabled: bool,
    /// Sealed capability bit carried into the receipt for relying-party policy.
    pub input_control_enabled: bool,
    /// Exact Xenia application payload type admitted by the receiver.
    pub payload_type: u8,
    /// Exact opened-plaintext length.
    pub payload_len: u32,
    /// BLAKE3-256 of the opened plaintext.
    pub payload_digest: [u8; 32],
    /// BLAKE3-256 of the sealed Xenia envelope that AEAD-opened successfully.
    pub sealed_envelope_digest: [u8; 32],
    /// Trusted local time at which the Xenia receiver accepted the payload.
    pub opened_at_unix_ms: u64,
    /// Exclusive receipt expiry.
    pub expires_at_unix_ms: u64,
}

impl AuthenticatedPayloadReceiptBodyV1 {
    /// Validate bounded portable-receipt structure independent of key trust.
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
        if self.signature_algorithm != "ed25519" {
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

    /// Canonical bincode-v1 body bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthenticatedPayloadReceiptError> {
        self.validate()?;
        bincode::serialize(self).map_err(AuthenticatedPayloadReceiptError::Encoding)
    }

    /// Domain-separated digest signed by the transport-attestor key.
    pub fn signing_digest(&self) -> Result<[u8; 32], AuthenticatedPayloadReceiptError> {
        let bytes = self.canonical_bytes()?;
        let mut h = blake3::Hasher::new();
        h.update(AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN);
        h.update(&bytes);
        Ok(*h.finalize().as_bytes())
    }
}

/// Portable, signed evidence that one exact application payload successfully crossed
/// Xenia's authenticated AEAD/replay boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPayloadReceiptV1 {
    /// Signed receipt body.
    pub body: AuthenticatedPayloadReceiptBodyV1,
    /// Detached Ed25519 signature over `body.signing_digest()`.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl AuthenticatedPayloadReceiptV1 {
    /// Cryptographically verify this receipt against one already-trusted key.
    ///
    /// This checks signature + structure + current time only. It does not decide
    /// whether this attestor/key is trusted for a particular physical device.
    pub fn verify_with_trusted_key(
        &self,
        key: &VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<(), AuthenticatedPayloadReceiptError> {
        self.body.validate()?;
        if now_unix_ms < self.body.opened_at_unix_ms || now_unix_ms >= self.body.expires_at_unix_ms {
            return Err(AuthenticatedPayloadReceiptError::ReceiptNotFresh);
        }
        let digest = self.body.signing_digest()?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&digest, &signature)
            .map_err(|_| AuthenticatedPayloadReceiptError::InvalidReceiptSignature)
    }
}

/// Configured Xenia transport-attestor signing key.
///
/// Key storage/rotation/authorization is deployment policy and remains outside this
/// helper. A downstream relying party must separately pin/authorize the corresponding
/// verifying key; embedding `key_id` in a valid receipt does not make it trusted.
pub struct TransportReceiptSigner {
    attestor_id: String,
    key_id: String,
    signing_key: SigningKey,
}

impl std::fmt::Debug for TransportReceiptSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportReceiptSigner")
            .field("attestor_id", &self.attestor_id)
            .field("key_id", &self.key_id)
            .field("verifying_key", &self.signing_key.verifying_key().to_bytes())
            .finish_non_exhaustive()
    }
}

impl TransportReceiptSigner {
    /// Configure one transport-attestation signer.
    pub fn new(
        attestor_id: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: SigningKey,
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
            signing_key,
        })
    }

    /// Verifying key corresponding to this signer.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a short-lived portable receipt for one opaque AEAD-opened payload.
    pub fn sign_opened_payload(
        &self,
        opened: &AuthenticatedOpenedPayload,
        expires_at_unix_ms: u64,
    ) -> Result<AuthenticatedPayloadReceiptV1, AuthenticatedPayloadReceiptError> {
        let body = AuthenticatedPayloadReceiptBodyV1 {
            schema: AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA.to_string(),
            attestor_id: self.attestor_id.clone(),
            key_id: self.key_id.clone(),
            signature_algorithm: "ed25519".to_string(),
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
        let signature = self.signing_key.sign(&digest).to_bytes();
        Ok(AuthenticatedPayloadReceiptV1 { body, signature })
    }
}

/// Errors at the exact-payload receipt boundary.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedPayloadReceiptError {
    /// Underlying authenticated-session evidence could not be encoded.
    #[error("authenticated session evidence failed: {0}")]
    SessionEvidence(#[from] AuthenticatedSessionEvidenceError),
    /// Evidence and handshake do not bind the same transcript.
    #[error("authenticated session evidence does not match handshake transcript")]
    TranscriptMismatch,
    /// Evidence and handshake do not bind the same negotiated session context.
    #[error("authenticated session evidence does not match negotiated session context")]
    SessionContextMismatch,
    /// Local/remote roles are inconsistent.
    #[error("authenticated peer role is inconsistent with local session role")]
    PeerRoleMismatch,
    /// Underlying Xenia wire operation failed.
    #[error("xenia wire operation failed: {0}")]
    Wire(#[from] xenia_wire::WireError),
    #[error("payload type is reserved for Xenia protocol traffic")]
    ReservedPayloadType,
    #[error("application payload must not be empty")]
    EmptyPayload,
    #[error("application payload too large: {actual} > {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("sealed application envelope too large: {actual} > {maximum}")]
    EnvelopeTooLarge { actual: usize, maximum: usize },
    #[error("sealed application envelope is malformed")]
    MalformedEnvelope,
    #[error("sealed payload type mismatch: expected {expected:#04x}, got {actual:#04x}")]
    PayloadTypeMismatch { expected: u8, actual: u8 },
    #[error("unsupported authenticated-payload receipt schema")]
    UnsupportedReceiptSchema,
    #[error("transport attestor identity/key label is invalid")]
    InvalidAttestorIdentity,
    #[error("unsupported receipt signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("portable receipt contains an invalid payload length")]
    InvalidPayloadLength,
    #[error("portable receipt contains a zero security commitment")]
    ZeroSecurityDigest,
    #[error("portable receipt lifetime is invalid")]
    InvalidReceiptLifetime,
    #[error("portable receipt is not fresh at relying-party time")]
    ReceiptNotFresh,
    #[error("portable receipt signature is invalid")]
    InvalidReceiptSignature,
    #[error("portable receipt encoding failed: {0}")]
    Encoding(#[from] bincode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated_session_evidence::AuthenticatedHandshakeEvidence;
    use crate::frame::{INPUT_EVENT_SCHEMA_VERSION, LANE_ENVELOPE_MAGIC, LANE_ENVELOPE_SCHEMA_VERSION, PixelFormat, RawCapabilities};
    use crate::handshake::PendingSessionSurface;
    use crate::transport::{TransportKind, TransportProfileV1};
    use xenia_handshake::derive_session_key_schedule;

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

    // Tests in this module are inside the crate, so they may construct the lower
    // opaque handshake token directly. Product code cannot.
    fn bound_pair() -> (BoundAuthenticatedSession, BoundAuthenticatedSession) {
        let surface = PendingSessionSurface::new(None, TransportProfileV1::current(TransportKind::Tcp))
            .unwrap()
            .authenticate_capabilities(capabilities())
            .unwrap();
        let context = surface.context_hash();
        let schedule = derive_session_key_schedule(&[0xA5; 32], &[0x5A; 32]);
        let outcome = HandshakeOutcome {
            session_key: [0x44; 32],
            transcript_hash: [0x22; 32],
            key_schedule: schedule,
            negotiated_context_hash: Some(context),
            host_identity_fingerprint: [0x33; 32],
        };

        let host_hs = AuthenticatedHandshakeEvidence {
            peer_role: AuthenticatedPeerRole::Viewer,
            peer_identity_fingerprint: [0x11; 32],
            transcript_hash: outcome.transcript_hash,
            negotiated_context_hash: outcome.negotiated_context_hash,
        };
        let host_ev = host_hs.bind_authenticated_surface(&surface).unwrap();
        let viewer_hs = AuthenticatedHandshakeEvidence {
            peer_role: AuthenticatedPeerRole::Host,
            peer_identity_fingerprint: [0x33; 32],
            transcript_hash: outcome.transcript_hash,
            negotiated_context_hash: outcome.negotiated_context_hash,
        };
        let viewer_ev = viewer_hs.bind_authenticated_surface(&surface).unwrap();

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

    #[test]
    fn exact_payload_open_mints_receipt_and_replay_fails() {
        let (mut host, mut viewer) = bound_pair();
        let payload = b"physical-effect-envelope";
        let sealed = viewer.seal_application_payload(payload, 0x70).unwrap();
        let opened = host.open_application_payload(&sealed, 0x70, 10_000).unwrap();
        assert_eq!(opened.plaintext(), payload);

        let signer = TransportReceiptSigner::new(
            "xenia-host-a",
            "transport-attestor-1",
            SigningKey::from_bytes(&[0x77; 32]),
        )
        .unwrap();
        let receipt = signer.sign_opened_payload(&opened, 12_000).unwrap();
        receipt
            .verify_with_trusted_key(&signer.verifying_key(), 11_000)
            .unwrap();
        assert_eq!(receipt.body.payload_digest, *blake3::hash(payload).as_bytes());
        assert!(receipt.body.input_control_enabled);

        assert!(host.open_application_payload(&sealed, 0x70, 10_001).is_err());
    }

    #[test]
    fn handshake_evidence_cannot_be_paired_with_other_transcript() {
        let (host, _) = bound_pair();
        let evidence = host.evidence.clone();
        let surface_context = evidence.session_context_hash();
        let bad = HandshakeOutcome {
            session_key: [0x44; 32],
            transcript_hash: [0x99; 32],
            key_schedule: derive_session_key_schedule(&[0xA5; 32], &[0x5A; 32]),
            negotiated_context_hash: Some(surface_context),
            host_identity_fingerprint: [0x33; 32],
        };
        assert!(matches!(
            BoundAuthenticatedSession::from_authenticated_handshake(SessionRole::Host, bad, evidence),
            Err(AuthenticatedPayloadReceiptError::TranscriptMismatch)
        ));
    }

    #[test]
    fn receipt_is_bound_to_exact_plaintext_and_short_lived() {
        let (mut host, mut viewer) = bound_pair();
        let sealed = viewer.seal_application_payload(b"A", 0x70).unwrap();
        let opened = host.open_application_payload(&sealed, 0x70, 20_000).unwrap();
        let signer = TransportReceiptSigner::new(
            "xenia-host-a",
            "transport-attestor-1",
            SigningKey::from_bytes(&[0x66; 32]),
        )
        .unwrap();
        let mut receipt = signer.sign_opened_payload(&opened, 21_000).unwrap();
        receipt.body.payload_digest = *blake3::hash(b"B").as_bytes();
        assert!(matches!(
            receipt.verify_with_trusted_key(&signer.verifying_key(), 20_500),
            Err(AuthenticatedPayloadReceiptError::InvalidReceiptSignature)
        ));

        let receipt = signer.sign_opened_payload(&opened, 21_000).unwrap();
        assert!(matches!(
            receipt.verify_with_trusted_key(&signer.verifying_key(), 21_000),
            Err(AuthenticatedPayloadReceiptError::ReceiptNotFresh)
        ));
    }
}
