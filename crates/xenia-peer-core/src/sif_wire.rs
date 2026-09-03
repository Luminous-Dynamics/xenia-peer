// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Dedicated authenticated wire domain for SIF protected-file semantics.
//!
//! This module deliberately knows nothing about `xenia-ledger` types. The permissive
//! peer-core owns only a typed-but-opaque, bounded semantic byte payload and the
//! AEAD/session mechanics needed to keep SIF traffic cryptographically
//! non-interchangeable with legacy file transfer.
//!
//! Host- and viewer-originated SIF envelopes use different application payload types.
//! That preserves the same nonce-safety rule as legacy bidirectional file transfer:
//! each payload-type nonce space has exactly one sealing side, even when both peers use
//! the same session `source_id`, epoch, control key and sequence values.
//!
//! Opening is stricter than the generic `xenia_wire::open`: the cleartext nonce's
//! payload-type byte is checked against the exact expected remote SIF direction before
//! AEAD open or replay-window mutation. Legacy file-transfer, clipboard and opposite-
//! direction SIF envelopes therefore never reach semantic decoding here.
//!
//! The encrypted wrapper uses a fixed 12-byte header rather than Serde/bincode for its
//! own framing. The declared semantic length and class-specific ceiling are checked
//! before allocating/copying the semantic `Vec<u8>`, so a valid-session peer cannot
//! turn a small authenticated envelope into an attacker-chosen large allocation.

use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_wire::{
    Sealable, Session as WireSession, WireError, envelope_payload_type, open, seal,
};

/// AEAD payload type for SIF protected-file messages sealed by the host.
pub const PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST: u8 = 0x33;
/// AEAD payload type for SIF protected-file messages sealed by the viewer.
pub const PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER: u8 = 0x34;

/// Stable opaque payload wrapper schema.
pub const SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION: u16 = 1;
/// Maximum encoded protected Offer bytes.
pub const MAX_SIF_PROTECTED_FILE_OFFER_BYTES: usize = 4 * 1024;
/// Maximum encoded protected Accept/Reject response bytes.
pub const MAX_SIF_PROTECTED_FILE_RESPONSE_BYTES: usize = 2 * 1024;
/// Maximum encoded protected Chunk semantic bytes.
pub const MAX_SIF_PROTECTED_FILE_CHUNK_WIRE_BYTES: usize = 72 * 1024;
/// Maximum encoded protected Complete bytes.
pub const MAX_SIF_PROTECTED_FILE_COMPLETE_BYTES: usize = 1024;
/// Largest semantic message accepted by the v1 wrapper.
pub const MAX_SIF_PROTECTED_FILE_SEMANTIC_BYTES: usize =
    MAX_SIF_PROTECTED_FILE_CHUNK_WIRE_BYTES;
/// Maximum complete sealed envelope accepted before attempting AEAD open.
pub const MAX_SIF_PROTECTED_FILE_ENVELOPE_BYTES: usize =
    MAX_SIF_PROTECTED_FILE_SEMANTIC_BYTES + 64;

const SIF_WIRE_MAGIC: [u8; 4] = *b"XSF1";
const SIF_WIRE_HEADER_LEN: usize = 12;
const SIF_WIRE_FLAGS_V1: u8 = 0;

/// Which endpoint owns this SIF wire channel instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SifProtectedFileWireRole {
    /// Host / controlled-machine side.
    Host,
    /// Viewer / operator-device side.
    Viewer,
}

impl SifProtectedFileWireRole {
    const fn outbound_payload_type(self) -> u8 {
        match self {
            Self::Host => PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
            Self::Viewer => PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER,
        }
    }

    const fn inbound_payload_type(self) -> u8 {
        match self {
            Self::Host => PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER,
            Self::Viewer => PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
        }
    }
}

/// Coarse encrypted semantic message class carried inside the dedicated SIF domain.
///
/// The numeric tags below are part of wrapper schema v1 and must not be reassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SifProtectedFileWireKind {
    /// Sender's exact release-bound Offer.
    Offer,
    /// Receiver Accept/Reject response to an exact Offer.
    Response,
    /// One release-bound file-content Chunk.
    Chunk,
    /// Sender's release-bound no-more-chunks marker.
    Complete,
}

impl SifProtectedFileWireKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Offer => 1,
            Self::Response => 2,
            Self::Chunk => 3,
            Self::Complete => 4,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Offer),
            2 => Some(Self::Response),
            3 => Some(Self::Chunk),
            4 => Some(Self::Complete),
            _ => None,
        }
    }

    /// Maximum opaque semantic bytes allowed for this message class.
    pub const fn max_semantic_bytes(self) -> usize {
        match self {
            Self::Offer => MAX_SIF_PROTECTED_FILE_OFFER_BYTES,
            Self::Response => MAX_SIF_PROTECTED_FILE_RESPONSE_BYTES,
            Self::Chunk => MAX_SIF_PROTECTED_FILE_CHUNK_WIRE_BYTES,
            Self::Complete => MAX_SIF_PROTECTED_FILE_COMPLETE_BYTES,
        }
    }
}

/// Bounded opaque application payload sealed in the dedicated SIF domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SifProtectedFileWirePayload {
    schema_version: u16,
    kind: SifProtectedFileWireKind,
    semantic_bytes: Vec<u8>,
}

impl SifProtectedFileWirePayload {
    /// Construct one bounded non-empty opaque semantic payload of an explicit class.
    pub fn new(
        kind: SifProtectedFileWireKind,
        semantic_bytes: Vec<u8>,
    ) -> Result<Self, SifProtectedFileWireError> {
        let payload = Self {
            schema_version: SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION,
            kind,
            semantic_bytes,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Encrypted coarse semantic message class.
    pub const fn kind(&self) -> SifProtectedFileWireKind {
        self.kind
    }

    /// Opaque higher-layer semantic bytes.
    pub fn semantic_bytes(&self) -> &[u8] {
        &self.semantic_bytes
    }

    /// Consume the wrapper and recover higher-layer semantic bytes.
    pub fn into_semantic_bytes(self) -> Vec<u8> {
        self.semantic_bytes
    }

    /// Validate schema and class-specific allocation bounds.
    pub fn validate(&self) -> Result<(), SifProtectedFileWireError> {
        if self.schema_version != SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION {
            return Err(SifProtectedFileWireError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        if self.semantic_bytes.is_empty() {
            return Err(SifProtectedFileWireError::EmptySemanticPayload);
        }
        let max = self.kind.max_semantic_bytes();
        if self.semantic_bytes.len() > max {
            return Err(SifProtectedFileWireError::SemanticPayloadTooLarge {
                kind: self.kind,
                max,
                found: self.semantic_bytes.len(),
            });
        }
        Ok(())
    }
}

impl Sealable for SifProtectedFileWirePayload {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        self.validate().map_err(WireError::encode)?;
        let semantic_len = u32::try_from(self.semantic_bytes.len()).map_err(WireError::encode)?;
        let mut out = Vec::with_capacity(SIF_WIRE_HEADER_LEN + self.semantic_bytes.len());
        out.extend_from_slice(&SIF_WIRE_MAGIC);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.push(self.kind.tag());
        out.push(SIF_WIRE_FLAGS_V1);
        out.extend_from_slice(&semantic_len.to_be_bytes());
        out.extend_from_slice(&self.semantic_bytes);
        Ok(out)
    }

    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < SIF_WIRE_HEADER_LEN {
            return Err(WireError::decode("truncated SIF protected-file wrapper"));
        }
        if bytes[..4] != SIF_WIRE_MAGIC {
            return Err(WireError::decode("bad SIF protected-file wrapper magic"));
        }

        let schema_version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if schema_version != SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION {
            return Err(WireError::decode(format!(
                "unsupported SIF protected-file wire schema {schema_version}"
            )));
        }
        let kind = SifProtectedFileWireKind::from_tag(bytes[6])
            .ok_or_else(|| WireError::decode("unknown SIF protected-file wire kind"))?;
        if bytes[7] != SIF_WIRE_FLAGS_V1 {
            return Err(WireError::decode("unsupported SIF protected-file wire flags"));
        }

        let declared_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let max = kind.max_semantic_bytes();
        if declared_len == 0 {
            return Err(WireError::decode("empty SIF protected-file semantic payload"));
        }
        if declared_len > max {
            return Err(WireError::decode(format!(
                "SIF protected-file {kind:?} semantic payload declares {declared_len} bytes; maximum is {max}"
            )));
        }
        let total_len = SIF_WIRE_HEADER_LEN
            .checked_add(declared_len)
            .ok_or_else(|| WireError::decode("SIF protected-file wrapper length overflow"))?;
        if bytes.len() != total_len {
            return Err(WireError::decode(
                "SIF protected-file wrapper length does not match authenticated bytes",
            ));
        }

        let payload = Self {
            schema_version,
            kind,
            semantic_bytes: bytes[SIF_WIRE_HEADER_LEN..].to_vec(),
        };
        payload.validate().map_err(WireError::decode)?;
        Ok(payload)
    }
}

/// Independent SIF control channel using the negotiated Xenia control key.
pub struct SifProtectedFileWireChannel {
    role: SifProtectedFileWireRole,
    wire: WireSession,
}

impl SifProtectedFileWireChannel {
    /// Create a channel with fresh wire-session source metadata.
    pub fn new(role: SifProtectedFileWireRole) -> Self {
        Self {
            role,
            wire: WireSession::new(),
        }
    }

    /// Create a deterministic channel for interoperability/nonce tests.
    pub fn with_fixture(role: SifProtectedFileWireRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            role,
            wire: WireSession::with_source_id(source_id, epoch),
        }
    }

    /// Endpoint role fixed for this channel.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.role
    }

    /// Exact AEAD payload type this endpoint seals under.
    pub const fn outbound_payload_type(&self) -> u8 {
        self.role.outbound_payload_type()
    }

    /// Exact remote AEAD payload type accepted by [`Self::open`].
    pub const fn inbound_payload_type(&self) -> u8 {
        self.role.inbound_payload_type()
    }

    /// Install an explicit 32-byte control key.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.wire.install_key(key);
    }

    /// Install the negotiated initial control key from the normal lane schedule.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.install_control_key(schedule.control);
    }

    /// Install the control key for a negotiated rekey epoch.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.install_control_key(keys.control);
    }

    /// Advance previous-key grace expiry.
    pub fn tick(&mut self) {
        self.wire.tick();
    }

    /// Seal one opaque semantic message under this endpoint's dedicated SIF direction.
    pub fn seal(
        &mut self,
        payload: &SifProtectedFileWirePayload,
    ) -> Result<Vec<u8>, SifProtectedFileWireError> {
        payload.validate()?;
        let payload_type = self.outbound_payload_type();
        Ok(seal(payload, &mut self.wire, payload_type)?)
    }

    /// Open one exact remote-direction SIF envelope.
    ///
    /// Size and payload type are checked before AEAD open. A legacy file-transfer
    /// envelope (`0x31`/`0x32`), clipboard envelope (`0x30`), or same-side SIF envelope
    /// never mutates this channel's replay window and is never decoded as SIF.
    pub fn open(
        &mut self,
        envelope: &[u8],
    ) -> Result<SifProtectedFileWirePayload, SifProtectedFileWireError> {
        if envelope.len() > MAX_SIF_PROTECTED_FILE_ENVELOPE_BYTES {
            return Err(SifProtectedFileWireError::EnvelopeTooLarge {
                max: MAX_SIF_PROTECTED_FILE_ENVELOPE_BYTES,
                found: envelope.len(),
            });
        }

        let expected = self.inbound_payload_type();
        let found = envelope_payload_type(envelope);
        if found != Some(expected) {
            return Err(SifProtectedFileWireError::UnexpectedPayloadType { expected, found });
        }

        self.wire.tick();
        let payload: SifProtectedFileWirePayload = open(envelope, &mut self.wire)?;
        payload.validate()?;
        Ok(payload)
    }
}

/// Dedicated SIF wire-domain failures.
#[derive(Debug, Error)]
pub enum SifProtectedFileWireError {
    /// Opaque semantic wrapper schema is unsupported.
    #[error("unsupported SIF protected-file wire schema {found}")]
    UnsupportedSchema {
        /// Schema version found in the decoded wrapper.
        found: u16,
    },
    /// Semantic payloads must not be empty.
    #[error("SIF protected-file semantic payload must not be empty")]
    EmptySemanticPayload,
    /// Semantic payload exceeded its class-specific v1 ceiling.
    #[error("SIF protected-file {kind:?} semantic payload is {found} bytes; maximum is {max}")]
    SemanticPayloadTooLarge {
        /// Coarse semantic class whose bound was exceeded.
        kind: SifProtectedFileWireKind,
        /// Maximum semantic payload bytes for this class.
        max: usize,
        /// Supplied semantic payload bytes.
        found: usize,
    },
    /// Sealed envelope exceeded the pre-decrypt receive bound.
    #[error("SIF protected-file envelope is {found} bytes; maximum is {max}")]
    EnvelopeTooLarge {
        /// Maximum accepted sealed-envelope bytes.
        max: usize,
        /// Received sealed-envelope bytes.
        found: usize,
    },
    /// Cleartext nonce payload type did not name the exact expected remote SIF domain.
    #[error("unexpected SIF protected-file payload type: expected {expected:#04x}, found {found:?}")]
    UnexpectedPayloadType {
        /// Exact remote-direction SIF payload type expected by this endpoint.
        expected: u8,
        /// Payload type read from the nonce, or `None` for a truncated envelope.
        found: Option<u8>,
    },
    /// Underlying Xenia codec/session/AEAD operation failed.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0xA5; 32];
    const SOURCE_ID: [u8; 8] = [0x17; 8];
    const EPOCH: u8 = 4;

    fn pair() -> (SifProtectedFileWireChannel, SifProtectedFileWireChannel) {
        let mut host = SifProtectedFileWireChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        let mut viewer = SifProtectedFileWireChannel::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
        );
        host.install_control_key(KEY);
        viewer.install_control_key(KEY);
        (host, viewer)
    }

    fn offer_payload(bytes: &[u8]) -> SifProtectedFileWirePayload {
        SifProtectedFileWirePayload::new(SifProtectedFileWireKind::Offer, bytes.to_vec()).unwrap()
    }

    #[test]
    fn fixed_wrapper_roundtrips_without_serde_allocation_framing() {
        let payload = offer_payload(b"offer");
        let encoded = payload.to_bin().unwrap();
        assert_eq!(&encoded[..4], b"XSF1");
        assert_eq!(encoded[6], SifProtectedFileWireKind::Offer.tag());
        assert_eq!(
            <SifProtectedFileWirePayload as Sealable>::from_bin(&encoded).unwrap(),
            payload
        );
    }

    #[test]
    fn declared_length_is_bounded_before_semantic_copy() {
        let mut forged = Vec::from(SIF_WIRE_MAGIC);
        forged.extend_from_slice(&SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION.to_be_bytes());
        forged.push(SifProtectedFileWireKind::Offer.tag());
        forged.push(SIF_WIRE_FLAGS_V1);
        forged.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(<SifProtectedFileWirePayload as Sealable>::from_bin(&forged).is_err());
    }

    #[test]
    fn wrapper_rejects_trailing_authenticated_bytes() {
        let payload = offer_payload(b"offer");
        let mut encoded = payload.to_bin().unwrap();
        encoded.push(0);
        assert!(<SifProtectedFileWirePayload as Sealable>::from_bin(&encoded).is_err());
    }

    #[test]
    fn sif_payload_ids_are_distinct_from_legacy_application_domains() {
        assert_eq!(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST, 0x33);
        assert_eq!(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER, 0x34);
        assert_ne!(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST, crate::PAYLOAD_TYPE_CLIPBOARD);
        assert_ne!(
            PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
            crate::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST
        );
        assert_ne!(
            PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER,
            crate::PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER
        );
    }

    #[test]
    fn directional_sif_roundtrip_uses_exact_remote_payload_domain() {
        let (mut host, mut viewer) = pair();
        let payload = offer_payload(b"offer");
        let sealed = host.seal(&payload).unwrap();
        assert_eq!(
            envelope_payload_type(&sealed),
            Some(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST)
        );
        assert_eq!(viewer.open(&sealed).unwrap(), payload);

        let response = SifProtectedFileWirePayload::new(
            SifProtectedFileWireKind::Response,
            b"accept".to_vec(),
        )
        .unwrap();
        let sealed = viewer.seal(&response).unwrap();
        assert_eq!(
            envelope_payload_type(&sealed),
            Some(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER)
        );
        assert_eq!(host.open(&sealed).unwrap(), response);
    }

    #[test]
    fn same_source_key_epoch_and_sequence_still_produce_distinct_bidirectional_nonces() {
        let (mut host, mut viewer) = pair();
        let payload = offer_payload(b"same");
        let host_envelope = host.seal(&payload).unwrap();
        let viewer_envelope = viewer.seal(&payload).unwrap();
        assert_ne!(&host_envelope[..12], &viewer_envelope[..12]);
        assert_eq!(host_envelope[6], PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST);
        assert_eq!(viewer_envelope[6], PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER);
    }

    #[test]
    fn legacy_file_transfer_payload_is_rejected_before_sif_open() {
        let (_, mut viewer) = pair();
        let payload = offer_payload(b"not-sif-domain");
        let mut legacy_sender = WireSession::with_source_id(SOURCE_ID, EPOCH);
        legacy_sender.install_key(KEY);
        let legacy = seal(
            &payload,
            &mut legacy_sender,
            crate::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST,
        )
        .unwrap();

        assert!(matches!(
            viewer.open(&legacy),
            Err(SifProtectedFileWireError::UnexpectedPayloadType {
                expected: PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
                found: Some(crate::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST),
            })
        ));

        let mut sif_sender = SifProtectedFileWireChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        sif_sender.install_control_key(KEY);
        let valid = sif_sender.seal(&payload).unwrap();
        assert_eq!(viewer.open(&valid).unwrap(), payload);
    }

    #[test]
    fn same_side_sif_direction_is_rejected_before_decrypt() {
        let (mut host_sender, _) = pair();
        let mut host_receiver = SifProtectedFileWireChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        host_receiver.install_control_key(KEY);
        let sealed = host_sender.seal(&offer_payload(b"offer")).unwrap();
        assert!(matches!(
            host_receiver.open(&sealed),
            Err(SifProtectedFileWireError::UnexpectedPayloadType {
                expected: PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER,
                found: Some(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST),
            })
        ));
    }

    #[test]
    fn truncated_or_oversized_envelopes_fail_before_aead_open() {
        let (_, mut viewer) = pair();
        assert!(matches!(
            viewer.open(&[0u8; 6]),
            Err(SifProtectedFileWireError::UnexpectedPayloadType {
                expected: PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
                found: None,
            })
        ));
        let oversized = vec![0u8; MAX_SIF_PROTECTED_FILE_ENVELOPE_BYTES + 1];
        assert!(matches!(
            viewer.open(&oversized),
            Err(SifProtectedFileWireError::EnvelopeTooLarge { .. })
        ));
    }

    #[test]
    fn message_classes_have_separate_allocation_bounds() {
        assert!(matches!(
            SifProtectedFileWirePayload::new(SifProtectedFileWireKind::Offer, Vec::new()),
            Err(SifProtectedFileWireError::EmptySemanticPayload)
        ));
        assert!(matches!(
            SifProtectedFileWirePayload::new(
                SifProtectedFileWireKind::Offer,
                vec![0u8; MAX_SIF_PROTECTED_FILE_OFFER_BYTES + 1],
            ),
            Err(SifProtectedFileWireError::SemanticPayloadTooLarge {
                kind: SifProtectedFileWireKind::Offer,
                ..
            })
        ));
        assert!(SifProtectedFileWirePayload::new(
            SifProtectedFileWireKind::Chunk,
            vec![0u8; MAX_SIF_PROTECTED_FILE_CHUNK_WIRE_BYTES],
        )
        .is_ok());
    }

    #[test]
    fn channel_continues_after_both_sides_rekey() {
        let (mut host, mut viewer) = pair();
        let payload = offer_payload(b"after-rekey");
        let first = host.seal(&payload).unwrap();
        assert_eq!(viewer.open(&first).unwrap(), payload);

        let new_key = [0xB6; 32];
        host.install_control_key(new_key);
        viewer.install_control_key(new_key);
        let second = host.seal(&payload).unwrap();
        assert_eq!(viewer.open(&second).unwrap(), payload);
    }
}
