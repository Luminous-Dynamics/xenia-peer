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
//! that local token into a short-lived signed [`AuthenticatedPayloadReceiptV1`].
//! The serialized receipt is portable evidence, not authority: a relying party must
//! independently trust the signer, bind the exact payload digest, enforce freshness,
//! and apply its own semantic/physical policy.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::handshake::HandshakeOutcome;
use crate::{
    AuthenticatedPeerRole, AuthenticatedSessionEvidenceError, AuthenticatedSessionEvidenceV1,
    Session, SessionRole,
};

pub const AUTHENTICATED_PAYLOAD_RECEIPT_SCHEMA: &str = "xenia-authenticated-payload-receipt-v1";
pub const AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN: &[u8] =
    b"xenia-authenticated-payload-receipt-v1\0";
pub const MIN_APPLICATION_PAYLOAD_TYPE: u8 = 0x30;
pub const MAX_AUTHENTICATED_APPLICATION_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_TRANSPORT_RECEIPT_LIFETIME_MS: u64 = 5_000;
pub const MAX_TRANSPORT_ATTESTOR_LABEL_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptPeerRoleV1 {
    Host,
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

/// Opaque session binding an actually installed handshake key to its opaque
/// authenticated application-session evidence.
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

    pub fn evidence(&self) -> &AuthenticatedSessionEvidenceV1 {
        &self.evidence
    }

    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

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

    /// AEAD-open and replay-admit one exact application payload.
    pub fn open_application_payload(
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

/// Opaque in-process proof that an exact plaintext passed Xenia AEAD + replay checks.
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
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub const fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    pub const fn sealed_envelope_digest(&self) -> [u8; 32] {
        self.sealed_envelope_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPayloadReceiptBodyV1 {
    pub schema: String,
    pub attestor_id: String,
    pub key_id: String,
    pub signature_algorithm: String,
    pub session_evidence_digest: [u8; 32],
    pub peer_role: ReceiptPeerRoleV1,
    pub peer_identity_fingerprint: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub session_context_hash: [u8; 32],
    pub telemetry_enabled: bool,
    pub input_control_enabled: bool,
    pub payload_type: u8,
    pub payload_len: u32,
    pub payload_digest: [u8; 32],
    pub sealed_envelope_digest: [u8; 32],
    pub opened_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl AuthenticatedPayloadReceiptBodyV1 {
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

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthenticatedPayloadReceiptError> {
        self.validate()?;
        bincode::serialize(self).map_err(Into::into)
    }

    pub fn signing_digest(&self) -> Result<[u8; 32], AuthenticatedPayloadReceiptError> {
        let bytes = self.canonical_bytes()?;
        let mut h = blake3::Hasher::new();
        h.update(AUTHENTICATED_PAYLOAD_RECEIPT_DOMAIN);
        h.update(&bytes);
        Ok(*h.finalize().as_bytes())
    }
}

/// Portable signed evidence. The public fields are audit/wire data, not authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPayloadReceiptV1 {
    pub body: AuthenticatedPayloadReceiptBodyV1,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl AuthenticatedPayloadReceiptV1 {
    /// Verify against a key that the caller already trusts.
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
        key.verify_strict(&digest, &Signature::from_bytes(&self.signature))
            .map_err(|_| AuthenticatedPayloadReceiptError::InvalidReceiptSignature)
    }
}

/// Configured local transport-attestation signer. Key lifecycle remains deployment policy.
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

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

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

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedPayloadReceiptError {
    #[error("authenticated session evidence failed: {0}")]
    SessionEvidence(#[from] AuthenticatedSessionEvidenceError),
    #[error("authenticated session evidence does not match handshake transcript")]
    TranscriptMismatch,
    #[error("authenticated session evidence does not match negotiated session context")]
    SessionContextMismatch,
    #[error("authenticated peer role is inconsistent with local session role")]
    PeerRoleMismatch,
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
    fn receipt_tamper_and_expiry_fail_closed() {
        let (mut host, mut viewer) = bound_pair();
        let sealed = viewer.seal_application_payload(b"A", 0x70).unwrap();
        let opened = host.open_application_payload(&sealed, 0x70, 20_000).unwrap();
        let signer = TransportReceiptSigner::new(
            "xenia-host-a",
            "transport-attestor-1",
            SigningKey::from_bytes(&[0x66; 32]),
        )
        .unwrap();

        let mut tampered = signer.sign_opened_payload(&opened, 21_000).unwrap();
        tampered.body.payload_digest = *blake3::hash(b"B").as_bytes();
        assert!(matches!(
            tampered.verify_with_trusted_key(&signer.verifying_key(), 20_500),
            Err(AuthenticatedPayloadReceiptError::InvalidReceiptSignature)
        ));

        let receipt = signer.sign_opened_payload(&opened, 21_000).unwrap();
        assert!(matches!(
            receipt.verify_with_trusted_key(&signer.verifying_key(), 21_000),
            Err(AuthenticatedPayloadReceiptError::ReceiptNotFresh)
        ));
    }
}
