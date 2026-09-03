// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Dedicated authenticated carrier for SIF receiver custody evidence.
//!
//! Custody evidence is intentionally cryptographically separated from capability
//! negotiation (`0x35`/`0x36`) and protected file semantics (`0x33`/`0x34`). A receipt
//! can therefore never be interpreted as an Offer/Chunk or consume their replay state.
//! Peer-core owns only a bounded opaque wrapper; the AGPL application layer owns the
//! receiver observation and signature semantics.

use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_wire::{
    Sealable, Session as WireSession, WireError, envelope_payload_type, open, seal,
};

use crate::sif_wire::SifProtectedFileWireRole;

/// AEAD payload type for SIF custody messages sealed by the host.
pub const PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST: u8 = 0x37;
/// AEAD payload type for SIF custody messages sealed by the viewer.
pub const PAYLOAD_TYPE_SIF_CUSTODY_FROM_VIEWER: u8 = 0x38;
/// Stable opaque custody-wrapper schema.
pub const SIF_CUSTODY_WIRE_SCHEMA_VERSION: u16 = 1;
/// Maximum opaque custody semantic bytes.
///
/// 8 KiB comfortably covers current fixed-size Ed25519/ML-DSA receipt signatures while
/// remaining tightly bounded. A future larger signature family requires an explicit
/// profile/schema update rather than silently expanding this allocation boundary.
pub const MAX_SIF_CUSTODY_SEMANTIC_BYTES: usize = 8 * 1024;
/// Maximum complete sealed custody envelope accepted before AEAD open.
pub const MAX_SIF_CUSTODY_ENVELOPE_BYTES: usize = MAX_SIF_CUSTODY_SEMANTIC_BYTES + 64;

const CUSTODY_WIRE_MAGIC: [u8; 4] = *b"XSR1";
const CUSTODY_WIRE_HEADER_LEN: usize = 8;

/// Bounded opaque custody payload carried under the dedicated receipt domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SifCustodyWirePayload {
    semantic_bytes: Vec<u8>,
}

impl SifCustodyWirePayload {
    /// Construct one non-empty bounded custody payload.
    pub fn new(semantic_bytes: Vec<u8>) -> Result<Self, SifCustodyWireError> {
        if semantic_bytes.is_empty() {
            return Err(SifCustodyWireError::EmptyCustodyPayload);
        }
        if semantic_bytes.len() > MAX_SIF_CUSTODY_SEMANTIC_BYTES {
            return Err(SifCustodyWireError::CustodyPayloadTooLarge {
                max: MAX_SIF_CUSTODY_SEMANTIC_BYTES,
                found: semantic_bytes.len(),
            });
        }
        Ok(Self { semantic_bytes })
    }

    /// Opaque higher-layer custody bytes.
    pub fn semantic_bytes(&self) -> &[u8] {
        &self.semantic_bytes
    }

    /// Consume the wrapper and recover higher-layer custody bytes.
    pub fn into_semantic_bytes(self) -> Vec<u8> {
        self.semantic_bytes
    }
}

impl Sealable for SifCustodyWirePayload {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        if self.semantic_bytes.is_empty() || self.semantic_bytes.len() > MAX_SIF_CUSTODY_SEMANTIC_BYTES {
            return Err(WireError::encode("invalid SIF custody payload length"));
        }
        let semantic_len = u16::try_from(self.semantic_bytes.len()).map_err(WireError::encode)?;
        let mut out = Vec::with_capacity(CUSTODY_WIRE_HEADER_LEN + self.semantic_bytes.len());
        out.extend_from_slice(&CUSTODY_WIRE_MAGIC);
        out.extend_from_slice(&SIF_CUSTODY_WIRE_SCHEMA_VERSION.to_be_bytes());
        out.extend_from_slice(&semantic_len.to_be_bytes());
        out.extend_from_slice(&self.semantic_bytes);
        Ok(out)
    }

    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < CUSTODY_WIRE_HEADER_LEN {
            return Err(WireError::decode("truncated SIF custody wrapper"));
        }
        if bytes[..4] != CUSTODY_WIRE_MAGIC {
            return Err(WireError::decode("bad SIF custody wrapper magic"));
        }
        let schema = u16::from_be_bytes([bytes[4], bytes[5]]);
        if schema != SIF_CUSTODY_WIRE_SCHEMA_VERSION {
            return Err(WireError::decode(format!(
                "unsupported SIF custody wrapper schema {schema}"
            )));
        }
        let declared_len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
        if declared_len == 0 {
            return Err(WireError::decode("empty SIF custody payload"));
        }
        if declared_len > MAX_SIF_CUSTODY_SEMANTIC_BYTES {
            return Err(WireError::decode(format!(
                "SIF custody declares {declared_len} bytes; maximum is {MAX_SIF_CUSTODY_SEMANTIC_BYTES}"
            )));
        }
        let total_len = CUSTODY_WIRE_HEADER_LEN
            .checked_add(declared_len)
            .ok_or_else(|| WireError::decode("SIF custody wrapper length overflow"))?;
        if bytes.len() != total_len {
            return Err(WireError::decode(
                "SIF custody wrapper length does not match authenticated bytes",
            ));
        }
        Ok(Self {
            semantic_bytes: bytes[CUSTODY_WIRE_HEADER_LEN..].to_vec(),
        })
    }
}

/// Independent SIF custody channel using the negotiated control key.
pub struct SifCustodyWireChannel {
    role: SifProtectedFileWireRole,
    wire: WireSession,
}

impl SifCustodyWireChannel {
    /// Create a custody channel with fresh wire-session source metadata.
    pub fn new(role: SifProtectedFileWireRole) -> Self {
        Self {
            role,
            wire: WireSession::new(),
        }
    }

    /// Create a deterministic custody channel for qualification tests.
    pub fn with_fixture(role: SifProtectedFileWireRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            role,
            wire: WireSession::with_source_id(source_id, epoch),
        }
    }

    /// Endpoint role fixed for this custody channel.
    pub const fn role(&self) -> SifProtectedFileWireRole {
        self.role
    }

    /// Exact AEAD payload type sealed by this endpoint.
    pub const fn outbound_payload_type(&self) -> u8 {
        match self.role {
            SifProtectedFileWireRole::Host => PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST,
            SifProtectedFileWireRole::Viewer => PAYLOAD_TYPE_SIF_CUSTODY_FROM_VIEWER,
        }
    }

    /// Exact remote AEAD payload type accepted by this endpoint.
    pub const fn inbound_payload_type(&self) -> u8 {
        match self.role {
            SifProtectedFileWireRole::Host => PAYLOAD_TYPE_SIF_CUSTODY_FROM_VIEWER,
            SifProtectedFileWireRole::Viewer => PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST,
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

    /// Seal one bounded opaque custody message.
    pub fn seal(&mut self, payload: &SifCustodyWirePayload) -> Result<Vec<u8>, SifCustodyWireError> {
        let payload_type = self.outbound_payload_type();
        Ok(seal(payload, &mut self.wire, payload_type)?)
    }

    /// Open one exact remote-direction custody envelope.
    ///
    /// Envelope size and payload type are checked before AEAD open/replay mutation.
    pub fn open(&mut self, envelope: &[u8]) -> Result<SifCustodyWirePayload, SifCustodyWireError> {
        if envelope.len() > MAX_SIF_CUSTODY_ENVELOPE_BYTES {
            return Err(SifCustodyWireError::EnvelopeTooLarge {
                max: MAX_SIF_CUSTODY_ENVELOPE_BYTES,
                found: envelope.len(),
            });
        }
        let expected = self.inbound_payload_type();
        let found = envelope_payload_type(envelope);
        if found != Some(expected) {
            return Err(SifCustodyWireError::UnexpectedPayloadType { expected, found });
        }
        self.wire.tick();
        Ok(open(envelope, &mut self.wire)?)
    }
}

/// Fail-closed custody-carrier errors.
#[derive(Debug, Error)]
pub enum SifCustodyWireError {
    /// Custody payload must not be empty.
    #[error("SIF custody payload must not be empty")]
    EmptyCustodyPayload,
    /// Opaque custody bytes exceeded the carrier ceiling.
    #[error("SIF custody payload is {found} bytes; maximum is {max}")]
    CustodyPayloadTooLarge {
        /// Maximum accepted custody bytes.
        max: usize,
        /// Supplied custody bytes.
        found: usize,
    },
    /// Sealed envelope exceeded the pre-decrypt bound.
    #[error("SIF custody envelope is {found} bytes; maximum is {max}")]
    EnvelopeTooLarge {
        /// Maximum accepted envelope bytes.
        max: usize,
        /// Received envelope bytes.
        found: usize,
    },
    /// Cleartext nonce payload type was not the exact expected remote custody domain.
    #[error("unexpected SIF custody payload type: expected {expected:#04x}, found {found:?}")]
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
        PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST, PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST,
        PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST,
    };

    const KEY: [u8; 32] = [0xA5; 32];
    const SOURCE_ID: [u8; 8] = [0x17; 8];
    const EPOCH: u8 = 4;

    fn pair() -> (SifCustodyWireChannel, SifCustodyWireChannel) {
        let mut host = SifCustodyWireChannel::with_fixture(
            SifProtectedFileWireRole::Host,
            SOURCE_ID,
            EPOCH,
        );
        let mut viewer = SifCustodyWireChannel::with_fixture(
            SifProtectedFileWireRole::Viewer,
            SOURCE_ID,
            EPOCH,
        );
        host.install_control_key(KEY);
        viewer.install_control_key(KEY);
        (host, viewer)
    }

    #[test]
    fn custody_ids_are_separate_from_transfer_capability_and_legacy_domains() {
        assert_eq!(PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST, 0x37);
        assert_eq!(PAYLOAD_TYPE_SIF_CUSTODY_FROM_VIEWER, 0x38);
        assert_ne!(PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST);
        assert_ne!(PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST, PAYLOAD_TYPE_SIF_CAPABILITY_FROM_HOST);
        assert_ne!(PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST, PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST);
    }

    #[test]
    fn fixed_custody_wrapper_roundtrips() {
        let payload = SifCustodyWirePayload::new(vec![0x42; 128]).unwrap();
        let encoded = payload.to_bin().unwrap();
        assert_eq!(&encoded[..4], b"XSR1");
        assert_eq!(
            <SifCustodyWirePayload as Sealable>::from_bin(&encoded).unwrap(),
            payload
        );
    }

    #[test]
    fn declared_length_is_bounded_before_copy() {
        let mut forged = Vec::from(CUSTODY_WIRE_MAGIC);
        forged.extend_from_slice(&SIF_CUSTODY_WIRE_SCHEMA_VERSION.to_be_bytes());
        forged.extend_from_slice(&u16::MAX.to_be_bytes());
        assert!(<SifCustodyWirePayload as Sealable>::from_bin(&forged).is_err());
    }

    #[test]
    fn directional_custody_roundtrip_uses_own_domain() {
        let (mut host, mut viewer) = pair();
        let payload = SifCustodyWirePayload::new(vec![0x55; 96]).unwrap();
        let envelope = host.seal(&payload).unwrap();
        assert_eq!(envelope_payload_type(&envelope), Some(PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST));
        assert_eq!(viewer.open(&envelope).unwrap(), payload);
    }

    #[test]
    fn protected_transfer_domain_is_rejected_before_custody_open() {
        let (_, mut viewer) = pair();
        let payload = SifCustodyWirePayload::new(vec![0x55; 96]).unwrap();
        let mut wrong_sender = WireSession::with_source_id(SOURCE_ID, EPOCH);
        wrong_sender.install_key(KEY);
        let wrong = seal(&payload, &mut wrong_sender, PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST)
            .unwrap();
        assert!(matches!(
            viewer.open(&wrong),
            Err(SifCustodyWireError::UnexpectedPayloadType {
                expected: PAYLOAD_TYPE_SIF_CUSTODY_FROM_HOST,
                found: Some(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST),
            })
        ));
    }
}
