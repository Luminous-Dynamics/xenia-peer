// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Versioned authenticated-capability payload for native execution.
//!
//! `RawCapabilities` predates an explicit payload version and is encoded directly
//! with bincode. Extending that struct in place would make old and new payloads
//! share the same frame label while changing their canonical byte shape. V2
//! instead wraps the existing V1 capability set and adds execution advertisement
//! under an explicit fail-closed prefix.
//!
//! The 17-byte prefix is intentional: a legacy V1 bincode decoder consumes the
//! first sixteen bytes as `frame_id` + `timestamp_ms`, then sees byte 16 as the
//! discriminant for `Option<AudioAdvertisement>`. V2 fixes that byte to `2`,
//! which is invalid for bincode's Option encoding (only 0/1 are valid). Therefore
//! a legacy `RawCapabilities::from_frame` must reject a V2 payload rather than
//! silently interpreting it as V1. Tests pin that property against the actual V1
//! decoder.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_exec_proto::{ExecAdvertisementV1, ExecProtocolError};

use crate::frame::{PixelFormat, RawCapabilities, RawFrame};
use crate::handshake::negotiated_session_context_hash_with_profiles;
use crate::transport::{
    TransportAvailabilityProfileV1, TransportPreSessionProfileV1, TransportProfileV1,
};

/// Stable semantic schema label for V2 capabilities.
pub const CAPABILITIES_V2_SCHEMA: &str = "xenia-session-capabilities-v2";
/// Stable semantic schema label for the V5 negotiated context wrapper.
pub const NEGOTIATED_SESSION_CONTEXT_V5_SCHEMA: &str = "xenia-negotiated-session-context-v5";
/// Domain separator for the exact V2 capability-payload commitment.
pub const CAPABILITIES_V2_DIGEST_DOMAIN: &[u8] = b"xenia-session-capabilities-v2-digest";

/// Fail-closed prefix placed before the V2 bincode payload.
///
/// Bytes 0..8 are a human-recognizable magic, bytes 8..16 are reserved zeros,
/// and byte 16 is deliberately `2` so the legacy V1 bincode decoder rejects it
/// when it reaches the old `Option<AudioAdvertisement>` field.
pub const CAPABILITIES_V2_PREFIX: [u8; 17] = [
    b'X', b'C', b'A', b'P', b'V', b'2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];

/// V2 session capability contract.
///
/// `base` is the complete historical V1 capability set. `exec` is `None` when
/// native execution is unavailable. If present, the advertisement contains the
/// digest of the exact `xenia-exec-proto::ExecPolicyV1` the host intends to
/// enforce; this crate never carries the policy body as ambient mutable state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCapabilitiesV2 {
    /// Exact semantic schema label.
    pub schema: String,
    /// Historical capability surface retained byte-for-byte as typed V1 data.
    pub base: RawCapabilities,
    /// Optional native-execution advertisement and policy commitment.
    pub exec: Option<ExecAdvertisementV1>,
}

impl RawCapabilitiesV2 {
    /// Build V2 capabilities from the existing V1 surface and optional exec ad.
    pub fn new(base: RawCapabilities, exec: Option<ExecAdvertisementV1>) -> Self {
        Self {
            schema: CAPABILITIES_V2_SCHEMA.to_string(),
            base,
            exec,
        }
    }

    /// Validate both inherited V1 invariants and the optional execution ad.
    pub fn validate(&self) -> Result<(), CapabilitiesV2Error> {
        if self.schema != CAPABILITIES_V2_SCHEMA {
            return Err(CapabilitiesV2Error::UnsupportedSchema);
        }
        if !self.base.supports_current_input_event_schema() {
            return Err(CapabilitiesV2Error::UnsupportedInputEventSchema(
                self.base.input_event_schema_version,
            ));
        }
        if !self.base.supports_current_lane_envelope() {
            return Err(CapabilitiesV2Error::UnsupportedLaneEnvelope);
        }
        if let Some(exec) = &self.exec {
            exec.validate()?;
        }
        Ok(())
    }

    /// Encode the exact V2 payload bytes, including the fail-closed prefix.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, CapabilitiesV2Error> {
        self.validate()?;
        let encoded = bincode::serialize(self)?;
        let mut payload = Vec::with_capacity(CAPABILITIES_V2_PREFIX.len() + encoded.len());
        payload.extend_from_slice(&CAPABILITIES_V2_PREFIX);
        payload.extend_from_slice(&encoded);
        Ok(payload)
    }

    /// Domain-separated BLAKE3 commitment to the exact V2 payload bytes.
    pub fn payload_digest(&self) -> Result<[u8; 32], CapabilitiesV2Error> {
        let bytes = self.payload_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(CAPABILITIES_V2_DIGEST_DOMAIN);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Build a normal control-lane capabilities frame carrying the V2 payload.
    ///
    /// The outer `PixelFormat::Capabilities` is intentionally unchanged. V1/V2
    /// distinction is inside the payload and is fail-closed for legacy decoders.
    pub fn into_frame(self) -> Result<RawFrame, CapabilitiesV2Error> {
        let frame_id = self.base.frame_id;
        let timestamp_ms = self.base.timestamp_ms;
        let payload = self.payload_bytes()?;
        Ok(RawFrame::encoded(
            frame_id,
            timestamp_ms,
            0,
            0,
            PixelFormat::Capabilities,
            payload,
        ))
    }

    /// Decode and validate V2 capabilities from a control-lane frame.
    pub fn from_frame(frame: &RawFrame) -> Result<Self, CapabilitiesV2Error> {
        if frame.pixel_format != PixelFormat::Capabilities {
            return Err(CapabilitiesV2Error::WrongFrameType);
        }
        if !frame.pixels.starts_with(&CAPABILITIES_V2_PREFIX) {
            return Err(CapabilitiesV2Error::MissingPrefix);
        }
        let decoded: Self = bincode::deserialize(&frame.pixels[CAPABILITIES_V2_PREFIX.len()..])?;
        decoded.validate()?;
        if decoded.base.frame_id != frame.frame_id || decoded.base.timestamp_ms != frame.timestamp_ms
        {
            return Err(CapabilitiesV2Error::OuterMetadataMismatch);
        }
        Ok(decoded)
    }
}

/// V5 negotiated-session context.
///
/// Rather than duplicating all historical transport/session fields, V5 commits
/// the exact V4 base-context hash plus the exact V2 capability payload digest.
/// The V4 hash already binds transport, pre-session, availability, wire,
/// handshake, key-schedule, and V1 capabilities. The second digest binds the
/// versioned V2 envelope, including the execution advertisement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedSessionContextV5 {
    /// Exact semantic schema label.
    pub schema: String,
    /// Canonical V4 context hash over transport/session + base V1 capabilities.
    pub base_v4_context_hash: [u8; 32],
    /// Exact domain-separated V2 capability-payload digest.
    pub capabilities_v2_digest: [u8; 32],
}

impl NegotiatedSessionContextV5 {
    /// Canonical bincode-v1 bytes for the V5 wrapper.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// BLAKE3-256 of the canonical V5 wrapper.
    pub fn context_hash(&self) -> Result<[u8; 32], bincode::Error> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }
}

/// Compute the V5 context hash for a concrete live carrier and V2 capabilities.
pub fn negotiated_session_context_v5_hash_with_profiles(
    transport_profile: &TransportProfileV1,
    pre_session_profile: &TransportPreSessionProfileV1,
    availability_profile: &TransportAvailabilityProfileV1,
    capabilities: RawCapabilitiesV2,
) -> Result<[u8; 32], CapabilitiesV2Error> {
    capabilities.validate()?;
    let base_v4_context_hash = negotiated_session_context_hash_with_profiles(
        transport_profile,
        pre_session_profile,
        availability_profile,
        capabilities.base.clone(),
    )?;
    let context = NegotiatedSessionContextV5 {
        schema: NEGOTIATED_SESSION_CONTEXT_V5_SCHEMA.to_string(),
        base_v4_context_hash,
        capabilities_v2_digest: capabilities.payload_digest()?,
    };
    Ok(context.context_hash()?)
}

/// V2 capability/context validation failure.
#[derive(Debug, Error)]
pub enum CapabilitiesV2Error {
    /// The typed V2 schema label is not exact.
    #[error("unsupported capabilities-v2 schema")]
    UnsupportedSchema,
    /// The inherited input-event schema is unsupported.
    #[error("unsupported input-event schema version {0}")]
    UnsupportedInputEventSchema(u16),
    /// The inherited lane-envelope contract is unsupported.
    #[error("unsupported lane-envelope contract")]
    UnsupportedLaneEnvelope,
    /// Optional execution advertisement failed its own V1 validation.
    #[error("invalid execution advertisement: {0}")]
    Exec(#[from] ExecProtocolError),
    /// Frame was not a capabilities frame.
    #[error("raw frame is not a capabilities frame")]
    WrongFrameType,
    /// Capabilities frame does not carry the V2 fail-closed prefix.
    #[error("capabilities frame does not carry the V2 prefix")]
    MissingPrefix,
    /// Outer RawFrame metadata and inner base metadata disagree.
    #[error("capabilities-v2 outer/inner frame metadata mismatch")]
    OuterMetadataMismatch,
    /// Canonical bincode encoding/decoding failed.
    #[error("capabilities-v2 codec failure: {0}")]
    Codec(#[from] bincode::Error),
    /// Existing V4 negotiated-context construction rejected a transport/profile.
    #[error("base negotiated-session context rejected: {0}")]
    BaseContext(#[from] crate::handshake::NegotiatedSessionContextError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advertisement::{AdvertisedAudioCodec, AudioAdvertisement};
    use crate::frame::{INPUT_EVENT_SCHEMA_VERSION, LANE_ENVELOPE_MAGIC, LANE_ENVELOPE_SCHEMA_VERSION};
    use crate::transport::TransportKind;
    use xenia_exec_proto::{ExecInvocationV1, ExecPolicyV1};

    fn base_capabilities() -> RawCapabilities {
        RawCapabilities {
            frame_id: 7,
            timestamp_ms: 11,
            audio: Some(AudioAdvertisement {
                codecs: vec![AdvertisedAudioCodec::RawPcm],
                selected_codec: AdvertisedAudioCodec::RawPcm,
                sample_rate_hz: 48_000,
                max_channels: 2,
                frame_duration_ms: vec![20],
            }),
            video_format: PixelFormat::Passthrough,
            telemetry_enabled: false,
            input_control_enabled: false,
            clipboard_enabled: false,
            input_event_schema_version: INPUT_EVENT_SCHEMA_VERSION,
            lane_envelope_version: LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: LANE_ENVELOPE_MAGIC,
        }
    }

    fn exec_advertisement() -> ExecAdvertisementV1 {
        let invocation = ExecInvocationV1 {
            executable: "/usr/bin/uname".to_string(),
            argv: vec!["-a".to_string()],
            working_directory: "/tmp".to_string(),
            environment: vec![],
        };
        let policy = ExecPolicyV1::one_shot(vec![invocation], 5_000, 4096, 4096, 1);
        ExecAdvertisementV1::from_policy(&policy).unwrap()
    }

    #[test]
    fn v2_roundtrip_preserves_exact_capabilities() {
        let capabilities = RawCapabilitiesV2::new(base_capabilities(), Some(exec_advertisement()));
        let frame = capabilities.clone().into_frame().unwrap();
        assert_eq!(RawCapabilitiesV2::from_frame(&frame).unwrap(), capabilities);
    }

    #[test]
    fn legacy_v1_decoder_fails_closed_on_v2_prefix() {
        let frame = RawCapabilitiesV2::new(base_capabilities(), Some(exec_advertisement()))
            .into_frame()
            .unwrap();
        assert!(
            RawCapabilities::from_frame(&frame).is_err(),
            "legacy V1 decoder must reject rather than reinterpret a V2 payload"
        );
    }

    #[test]
    fn execution_advertisement_changes_v2_payload_digest() {
        let disabled = RawCapabilitiesV2::new(base_capabilities(), None);
        let enabled = RawCapabilitiesV2::new(base_capabilities(), Some(exec_advertisement()));
        assert_ne!(disabled.payload_digest().unwrap(), enabled.payload_digest().unwrap());
    }

    #[test]
    fn execution_advertisement_changes_v5_context_hash() {
        let transport = TransportProfileV1::current(TransportKind::Tcp);
        let pre_session = TransportPreSessionProfileV1::current(TransportKind::Tcp);
        let availability = TransportAvailabilityProfileV1::current(TransportKind::Tcp);

        let disabled = negotiated_session_context_v5_hash_with_profiles(
            &transport,
            &pre_session,
            &availability,
            RawCapabilitiesV2::new(base_capabilities(), None),
        )
        .unwrap();
        let enabled = negotiated_session_context_v5_hash_with_profiles(
            &transport,
            &pre_session,
            &availability,
            RawCapabilitiesV2::new(base_capabilities(), Some(exec_advertisement())),
        )
        .unwrap();

        assert_ne!(disabled, enabled);
    }

    #[test]
    fn malformed_exec_advertisement_is_rejected_before_context_hashing() {
        let mut exec = exec_advertisement();
        exec.interactive_pty_enabled = true;
        let capabilities = RawCapabilitiesV2::new(base_capabilities(), Some(exec));
        assert!(matches!(
            capabilities.validate(),
            Err(CapabilitiesV2Error::Exec(_))
        ));
    }

    #[test]
    fn outer_metadata_mismatch_fails_closed() {
        let capabilities = RawCapabilitiesV2::new(base_capabilities(), None);
        let mut frame = capabilities.into_frame().unwrap();
        frame.frame_id += 1;
        assert!(matches!(
            RawCapabilitiesV2::from_frame(&frame),
            Err(CapabilitiesV2Error::OuterMetadataMismatch)
        ));
    }
}
