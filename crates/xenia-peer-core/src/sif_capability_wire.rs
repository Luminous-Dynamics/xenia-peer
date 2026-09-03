// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Dedicated authenticated capability-negotiation carrier for SIF protected files.
//!
//! Capability negotiation is intentionally separated from protected evidence traffic.
//! It uses directional application payload types `0x35`/`0x36`, while Offer/Response/
//! Chunk/Complete use `0x33`/`0x34`. A pending negotiation channel can therefore be
//! dropped after agreement without handing nonce counters or replay state into the
//! protected-transfer channel.
//!
//! The payload remains opaque to peer-core. The AGPL application layer owns the exact
//! protected-file profile fingerprint and negotiation semantics. This layer provides
//! only a fixed, allocation-bounded wrapper and exact pre-decrypt direction checks.

use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_wire::{
    Sealable, Session as WireSession, WireError, envelope_payload_type, open, seal,
};

use crate::sif_wire::SifProtectedFileWireRole;

/// AEAD payload type for SIF capability messages sealed by the host.
pub const PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST: u8 = 0x35;
/// AEAD payload type for SIF capability messages sealed by the viewer.
pub const PAYLOAD_TYPE_SIF_CAPABILITY_FROM_VIEWER: u8 = 0x36;
/// Stable opaque capability-wrapper schema.
pub const SIF_CAPABILITY_WIRE_SCHEMA_VERSION: u16 = 1;
/// Maximum opaque capability bytes accepted by the peer-core carrier.
pub const MAX_SIF_CAPABILITY_SEMANTIC_BYTES: usize = 128;
/// Maximum complete sealed capability envelope accepted before AEAD open.
pub const MAX_SIF_CAPABILITY_ENVELOPE_BYTES: usize = MAX_SIF_CAPABILITY_SEMANTIC_BYTES + 64;

const CAPABILITY_WIRE_MAGIC: [u8; 4] = *b"XSC1";
const CAPABILITY_WIRE_HEADER_LEN: usize = 8;

/// Bounded opaque capability payload carried under the dedicated negotiation domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SifProtectedFileCapabilityWirePayload {
    semantic_bytes: Vec<u8>,
}

impl SifProtectedFileCapabilityWirePayload {
    /// Construct one non-empty bounded opaque capability payload.
    pub fn new(semantic_bytes: Vec<u8>) -> Result<Self, SifCapabilityWireError> {
        if semantic_bytes.is_empty() {
            return Err(SifCapabilityWireError::EmptyCapability);
        }
        if semantic_bytes.len() > MAX_SIF_CAPABILITY_SEMANTIC_BYTES {
            return Err(SifCapabilityWireError::CapabilityTooLarge {
                max: MAX_SIF_CAPABILITY_SEMANTIC_BYTES,
                found: semantic_bytes.len(),
            });
        }
        Ok(Self { semantic_bytes })
    }

    /// Opaque higher-layer capability bytes.
    pub fn semantic_bytes(&self) -> &[u8] {
        &self.semantic_bytes
    }

    /// Consume the wrapper and recover the higher-layer capability bytes.
    pub fn into_semantic_bytes(self) -> Vec<u8> {
        self.semantic_bytes
    }
}

impl Sealable for SifProtectedFileCapabilityWirePayload {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        if self.semantic_bytes.is_empty() || self.semantic_bytes.len() > MAX_SIF_CAPABILITY_SEMANTIC_BYTES {
            return Err(WireError::encode("invalid SIF capability payload length"));
        }
        let semantic_len = u16::try_from(self.semantic_bytes.len()).map_err(WireError::encode)?;
        let mut out = Vec::with_capacity(CAPABILITY_WIRE_HEADER_LEN + self.semantic_bytes.len());
        out.extend_from_slice(&CAPABILITY_WIRE_MAGIC);
        out.extend_from_slice(&SIF_CAPABILITY_WIRE_SCHEMA_VERSION.to_be_bytes());
        out.extend_from_slice(&semantic_len.to_be_bytes());
        out.extend_from_slice(&self.semantic_bytes);
        Ok(out)
    }

    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < CAPABILITY_WIRE_HEADER_LEN {
            return Err(WireError::decode("truncated SIF capability wrapper"));
        }
        if bytes[..4] != CAPABILITY_WIRE_MAGIC {
            return Err(WireError::decode("bad SIF capability wrapper magic"));
        }
        let schema = u16::from_be_bytes([bytes[4], bytes[5]]);
        if schema != SIF_CAPABILITY_WIRE_SCHEMA_VERSION {
            return Err(WireError::decode(format!(
                "unsupported SIF capability wrapper schema {schema}"
            )));
        }
        let declared_len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
        if declared_len == 0 {
            return Err(WireError::decode("empty SIF capability payload"));
        }
        if declared_len > MAX_SIF_CAPABILITY_SEMANTIC_BYTES {
            return Err(WireError::decode(format!(
                "SIF capability declares {declared_len} bytes; maximum is {MAX_SIF_CAPABILITY_SEMANTIC_BYTES}"
            )));
        }
        let total_len = CAPABILITY_WIRE_HEADER_LEN
            .checked_add(declared_len)
            .ok_or_else(|| WireError::decode("SIF capability wrapper length overflow"))?;
        if bytes.len() != total_len {
            return Err(WireError::decode(
                "SIF capability wrapper length does not match authenticated bytes",
            ));
        }
        Ok(Self {
            semantic_bytes: bytes[CAPABILITY_WIRE_HEADER_LEN..].to_vec(),
        })
    }
}

/// Independent SIF capability-negotiation channel using the negotiated control key.
pub struct SifProtectedFileCapabilityWireChannel {
    role: SifProtectedFileWireRole,
    wire: WireSession,
}

impl SifProtectedFileCapabilityWireChannel {
    /// Create a capability channel with fresh wire-session source metadata.
    pub fn new(role: SifProtectedFileWireRole) -> Self {
        Self {
            role,
            wire: WireSession::new(),
        }
    }

    /// Create a deterministic capability channel for qualification tests.
    pub fn with_fixture(role: SifProtectedFileWireRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            role,
            wire: WireSession::with_source_id(source_id, epoch),
        }
    }

    /// Endpoint role fixed for this capability channel.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.role
    }

    /// Exact AEAD payload type sealed by this endpoint.
    pub const fn outbound_payload_type(&self) -> u8 {
        match self.role {
            SifProtectedFileWireRole::Host => PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST,
            SifProtectedFileWireRole::Viewer => PAYLOAD_TYPE_SIF_CAPABILITY_FROM_VIEWER,
        }
    }

    /// Exact remote AEAD payload type accepted by this endpoint.
    pub const fn inbound_payload_type(&self) -> u8 {
        match self.role {
            SifProtectedFileWireRole::Host => PAYLOAD_TYPE_SIF_CAPABILITY_FROM_VIEWER,
            SifProtectedFileWireRole::Viewer => PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST,
        }
    }

    /// Install an explicit negotiated control key.
    pub fn install_control_key(&mut self, key: [u8; 32]) {
        self.wire.install_key(key);
    }

    /// Install the initial transcript-derived control key.
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

    /// Seal one bounded opaque capability under this endpoint's direction.
    pub fn seal(
        &mut self,
        payload: &SifProtectedFileCapabilityWirePayload,
    ) -> Result<Vec<u8>, SifCapabilityWireError> {
        let payload_type = self.outbound_payload_type();
        Ok(seal(payload, &mut self.wire, payload_type)?)
    }

    /// Open one exact remote-direction capability envelope.
    ///
    /// Envelope size and payload type are rejected before AEAD open, so protected-file
    /// evidence traffic (`0x33`/`0x34`) and legacy traffic cannot mutate capability
    /// replay state or be interpreted as negotiation bytes.
    pub fn open(
        &mut self,
        envelope: &[u8],
    ) -> Result<SifProtectedFileCapabilityWirePayload, SifCapabilityWireError> {
        if envelope.len() > MAX_SIF_CAPABILITY_ENVELOPE_BYTES {
            return Err(SifCapabilityWireError::EnvelopeTooLarge {
                max: MAX_SIF_CAPABILITY_ENVELOPE_BYTES,
                found: envelope.len(),
            });
        }
        let expected = self.inbound_payload_type();
        let found = envelope_payload_type(envelope);
        if found != Some(expected) {
            return Err(SifCapabilityWireError::UnexpectedPayloadType { expected, found });
        }
        self.wire.tick();
        Ok(open(envelope, &mut self.wire)?)
    }
}

/// Fail-closed capability-carrier errors.
#[derive(Debug, Error)]
pub enum SifCapabilityWireError {
    /// Capability payload must not be empty.
    #[error("SIF capability payload must not be empty")]
    EmptyCapability,
    /// Opaque capability bytes exceeded the carrier ceiling.
    #[error("SIF capability payload is {found} bytes; maximum is {max}")]
    CapabilityTooLarge {
        /// Maximum accepted capability bytes.
        max: usize,
        /// Supplied capability bytes.
        found: usize,
    },
    /// Sealed envelope exceeded the pre-decrypt bound.
    #[error("SIF capability envelope is {found} bytes; maximum is {max}")]
    EnvelopeTooLarge {
        /// Maximum accepted envelope bytes.
        max: usize,
        /// Received envelope bytes.
        found: usize,
    },
    /// Cleartext nonce payload type was not the exact expected remote capability domain.
    #[error("unexpected SIF capability payload type: expected {expected:#04x}, found {found:?}")]
    UnexpectedPayloadType {
        /// Exact remote-direction payload type expected here.
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
    use crate::{
        PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
        PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER,
    };

    const KEY: [u8; 32] = [0xA5; 32];
    const SOURCE_ID: [u8; 8] = [0x17; 8];
    const EPOCH: u8 = 4;

    fn pair() -> (
        SifProtectedFileCapabilityWireChannel,
        SifProtectedFileCapabilityWireChannel,
    ) {
        let mut host = SifProtectedFileCapabilityWireChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        let mut viewer = SifProtectedFileCapabilityWireChannel::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
        );
        host.install_control_key(KEY);
        viewer.install_control_key(KEY);
        (host, viewer)
    }

    #[test]
    fn capability_payload_ids_are_separate_from_transfer_and_legacy_domains() {
        assert_eq!(PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST, 0x35);
        assert_eq!(PAYLOAD_TYPE_SIF_CAPABILITY_FROM_VIEWER, 0x36);
        assert_ne!(PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST);
        assert_ne!(PAYLOAD_TYPE_SIF_CAPABILITY_FROM_VIEWER, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER);
        assert_ne!(PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST, PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST);
    }

    #[test]
    fn fixed_capability_wrapper_roundtrips() {
        let payload = SifProtectedFileCapabilityWirePayload::new(vec![0x42; 33]).unwrap();
        let encoded = payload.to_bin().unwrap();
        assert_eq!(&encoded[..4], b"XSC1");
        assert_eq!(
            <SifProtectedFileCapabilityWirePayload as Sealable>::from_bin(&encoded).unwrap(),
            payload
        );
    }

    #[test]
    fn declared_length_is_bounded_before_copy() {
        let mut forged = Vec::from(CAPABILITY_WIRE_MAGIC);
        forged.extend_from_slice(&SIF_CAPABILITY_WIRE_SCHEMA_VERSION.to_be_bytes());
        forged.extend_from_slice(&u16::MAX.to_be_bytes());
        assert!(
            <SifProtectedFileCapabilityWirePayload as Sealable>::from_bin(&forged).is_err()
        );
    }

    #[test]
    fn directional_capability_roundtrip_uses_own_domain() {
        let (mut host, mut viewer) = pair();
        let payload = SifProtectedFileCapabilityWirePayload::new(vec![0x55; 33]).unwrap();
        let envelope = host.seal(&payload).unwrap();
        assert_eq!(envelope_payload_type(&envelope), Some(PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST));
        assert_eq!(viewer.open(&envelope).unwrap(), payload);
    }

    #[test]
    fn protected_transfer_domain_is_rejected_before_capability_open() {
        let (_, mut viewer) = pair();
        let payload = SifProtectedFileCapabilityWirePayload::new(vec![0x55; 33]).unwrap();
        let mut wrong_sender = WireSession::with_source_id(SOURCE_ID, EPOCH);
        wrong_sender.install_key(KEY);
        let wrong = seal(&payload, &mut wrong_sender, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST)
            .unwrap();
        assert!(matches!(
            viewer.open(&wrong),
            Err(SifCapabilityWireError::UnexpectedPayloadType {
                expected: PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST,
                found: Some(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST),
            })
        ));
    }

    #[test]
    fn same_source_key_epoch_and_sequence_remain_nonce_distinct_from_transfer() {
        let mut capability = SifProtectedFileCapabilityWireChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        capability.install_control_key(KEY);
        let mut transfer = crate::SifProtectedFileWireChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        transfer.install_control_key(KEY);

        let cap_payload = SifProtectedFileCapabilityWirePayload::new(vec![0x55; 33]).unwrap();
        let transfer_payload = crate::SifProtectedFileWirePayload::new(
            crate::SifProtectedFileWireKind::Offer,
            b"offer".to_vec(),
        )
        .unwrap();
        let cap_envelope = capability.seal(&cap_payload).unwrap();
        let transfer_envelope = transfer.seal(&transfer_payload).unwrap();
        assert_ne!(&cap_envelope[..12], &transfer_envelope[..12]);
        assert_eq!(cap_envelope[6], PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST);
        assert_eq!(transfer_envelope[6], PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST);
    }
}
