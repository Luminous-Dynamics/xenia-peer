// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Dedicated authenticated wire domain for SIF protected-file semantics.
//!
//! This module deliberately knows nothing about `xenia-ledger` types. The permissive
//! peer-core owns only an opaque, bounded semantic byte payload and the AEAD/session
//! mechanics needed to keep SIF traffic cryptographically non-interchangeable with
//! legacy file transfer.
//!
//! Host- and viewer-originated SIF envelopes use different application payload types.
//! That preserves the same nonce-safety rule as legacy bidirectional file transfer:
//! each payload-type nonce space has exactly one sealing side, even when both peers use
//! the same session `source_id`, epoch, control key and sequence values.
//!
//! Opening is stricter than the generic `xenia_wire::open`: the cleartext nonce's
//! payload-type byte is checked against the exact expected remote SIF direction before
//! AEAD open or replay-window mutation. Legacy file-transfer, clipboard and opposite-
//! direction SIF envelopes therefore never reach semantic deserialization here.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_wire::{
    Sealable, Session as WireSession, WireError, envelope_payload_type, open, seal,
};

/// AEAD payload type for SIF protected-file messages sealed by the host.
///
/// `0x30` is clipboard and `0x31`/`0x32` are legacy directional file transfer;
/// `0x33` is the next application-reserved byte.
pub const PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST: u8 = 0x33;

/// AEAD payload type for SIF protected-file messages sealed by the viewer.
pub const PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER: u8 = 0x34;

/// Stable opaque payload wrapper schema.
pub const SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION: u16 = 1;

/// Maximum encoded SIF semantic message carried inside one protected envelope.
///
/// The current semantic Chunk ceiling is 64 KiB. 96 KiB leaves bounded room for
/// release IDs, Offer commitments, bincode enum/length metadata and future v1 fields
/// without making one authenticated control message an unbounded allocation surface.
pub const MAX_SIF_PROTECTED_FILE_SEMANTIC_BYTES: usize = 96 * 1024;

/// Maximum complete sealed envelope accepted before attempting AEAD open.
///
/// Bincode currently adds a small fixed wrapper around the semantic `Vec<u8>` and the
/// Xenia wire adds a 12-byte nonce plus 16-byte tag. The extra 64 bytes deliberately
/// over-approximates that framing so malformed oversized traffic is rejected before
/// decrypt while valid maximum-size payloads still fit.
pub const MAX_SIF_PROTECTED_FILE_ENVELOPE_BYTES: usize =
    MAX_SIF_PROTECTED_FILE_SEMANTIC_BYTES + 64;

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

/// Bounded opaque application payload sealed in the dedicated SIF domain.
///
/// The bytes are produced/consumed by the higher AGPL application layer, which owns
/// concrete SIF Offer/Response/Chunk/Complete semantics. Keeping those bytes opaque
/// here prevents a dependency from permissive peer-core back into `xenia-ledger`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SifProtectedFileWirePayload {
    schema_version: u16,
    semantic_bytes: Vec<u8>,
}

impl SifProtectedFileWirePayload {
    /// Construct one bounded non-empty opaque semantic payload.
    pub fn new(semantic_bytes: Vec<u8>) -> Result<Self, SifProtectedFileWireError> {
        let payload = Self {
            schema_version: SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION,
            semantic_bytes,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Opaque higher-layer semantic bytes.
    pub fn semantic_bytes(&self) -> &[u8] {
        &self.semantic_bytes
    }

    /// Consume the wrapper and recover higher-layer semantic bytes.
    pub fn into_semantic_bytes(self) -> Vec<u8> {
        self.semantic_bytes
    }

    /// Validate schema and allocation bounds after construction/deserialization.
    pub fn validate(&self) -> Result<(), SifProtectedFileWireError> {
        if self.schema_version != SIF_PROTECTED_FILE_WIRE_SCHEMA_VERSION {
            return Err(SifProtectedFileWireError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        if self.semantic_bytes.is_empty() {
            return Err(SifProtectedFileWireError::EmptySemanticPayload);
        }
        if self.semantic_bytes.len() > MAX_SIF_PROTECTED_FILE_SEMANTIC_BYTES {
            return Err(SifProtectedFileWireError::SemanticPayloadTooLarge {
                max: MAX_SIF_PROTECTED_FILE_SEMANTIC_BYTES,
                found: self.semantic_bytes.len(),
            });
        }
        Ok(())
    }
}

impl Sealable for SifProtectedFileWirePayload {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        self.validate().map_err(WireError::encode)?;
        bincode::serialize(self).map_err(WireError::encode)
    }

    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        let payload: Self = bincode::deserialize(bytes).map_err(WireError::decode)?;
        payload.validate().map_err(WireError::decode)?;
        Ok(payload)
    }
}

/// Independent SIF control channel using the negotiated Xenia control key.
///
/// This intentionally owns a separate [`WireSession`] from [`crate::LaneSession`].
/// Sharing the same negotiated control key is safe because SIF uses disjoint payload
/// types (`0x33`/`0x34`), which are embedded in Xenia's 12-byte nonce. The directional
/// split additionally ensures that the host and viewer can both begin at sequence zero
/// without ever producing the same `(source_id, payload_type, epoch, sequence)` nonce.
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
    ///
    /// Production code should prefer [`Self::new`] or explicitly reuse the same
    /// authenticated source metadata chosen for its enclosing Xenia session.
    pub fn with_fixture(
        role: SifProtectedFileWireRole,
        source_id: [u8; 8],
        epoch: u8,
    ) -> Self {
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
        Ok(seal(payload, &mut self.wire, self.outbound_payload_type())?)
    }

    /// Open one exact remote-direction SIF envelope.
    ///
    /// Size and payload type are checked before AEAD open. A legacy file-transfer
    /// envelope (`0x31`/`0x32`), clipboard envelope (`0x30`), or same-side SIF envelope
    /// never mutates this channel's replay window and is never deserialized as SIF.
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
    /// Semantic payload exceeded the bounded v1 envelope profile.
    #[error("SIF protected-file semantic payload is {found} bytes; maximum is {max}")]
    SemanticPayloadTooLarge {
        /// Maximum semantic payload bytes.
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
        let payload = SifProtectedFileWirePayload::new(b"offer".to_vec()).unwrap();
        let sealed = host.seal(&payload).unwrap();
        assert_eq!(
            envelope_payload_type(&sealed),
            Some(PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST)
        );
        assert_eq!(viewer.open(&sealed).unwrap(), payload);

        let response = SifProtectedFileWirePayload::new(b"accept".to_vec()).unwrap();
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
        let payload = SifProtectedFileWirePayload::new(b"same".to_vec()).unwrap();
        let host_envelope = host.seal(&payload).unwrap();
        let viewer_envelope = viewer.seal(&payload).unwrap();

        assert_ne!(&host_envelope[..12], &viewer_envelope[..12]);
        assert_eq!(host_envelope[6], PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_HOST);
        assert_eq!(
            viewer_envelope[6],
            PAYLOAD_TYPE_SIF_PROTECTED_FILE_FROM_VIEWER
        );
    }

    #[test]
    fn legacy_file_transfer_payload_is_rejected_before_sif_open() {
        let (_, mut viewer) = pair();
        let payload = SifProtectedFileWirePayload::new(b"not-sif-domain".to_vec()).unwrap();
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

        // A valid SIF envelope at the same sequence is still accepted, proving the
        // rejected legacy envelope did not consume SIF replay-window state.
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
        let payload = SifProtectedFileWirePayload::new(b"offer".to_vec()).unwrap();
        let sealed = host_sender.seal(&payload).unwrap();

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
    fn semantic_allocation_bound_is_fail_closed() {
        assert!(matches!(
            SifProtectedFileWirePayload::new(Vec::new()),
            Err(SifProtectedFileWireError::EmptySemanticPayload)
        ));
        assert!(matches!(
            SifProtectedFileWirePayload::new(vec![0u8; MAX_SIF_PROTECTED_FILE_SEMANTIC_BYTES + 1]),
            Err(SifProtectedFileWireError::SemanticPayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rekeyed_channels_continue_only_after_both_install_the_new_control_key() {
        let (mut host, mut viewer) = pair();
        let first = SifProtectedFileWirePayload::new(b"before".to_vec()).unwrap();
        assert_eq!(viewer.open(&host.seal(&first).unwrap()).unwrap(), first);

        let next_key = [0x5A; 32];
        host.install_control_key(next_key);
        viewer.install_control_key(next_key);
        let second = SifProtectedFileWirePayload::new(b"after".to_vec()).unwrap();
        assert_eq!(viewer.open(&host.seal(&second).unwrap()).unwrap(), second);
    }
}
