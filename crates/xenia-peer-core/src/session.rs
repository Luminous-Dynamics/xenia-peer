// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Server-side session wrapper.
//!
//! A thin layer over [`xenia_wire::Session`] that tracks
//! host-specific framing state: a monotonic frame counter on the
//! forward (host → viewer) path, a monotonic input counter on the
//! reverse path, and which role (`Server` / `Viewer`) this instance
//! plays. All AEAD + replay + consent machinery lives in
//! `xenia-wire`; this struct is thin.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use xenia_wire::{Session as WireSession, WireError, open_frame, open_input};

use crate::frame::{RawFrame, RawInput};

/// Role played by a session instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Captures frames, accepts input. The side running on the
    /// machine being controlled.
    Host,
    /// Renders frames, sends input. The side running on the
    /// technician's device.
    Viewer,
}

/// Session errors surfaced from the host-side wrapper.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// Underlying `xenia-wire` operation failed.
    #[error("xenia-wire: {0}")]
    Wire(#[from] WireError),
}

/// A host or viewer session.
///
/// Wraps `xenia_wire::Session` with framing-side bookkeeping.
/// Caller installs a 32-byte AEAD key via [`Session::install_key`],
/// optionally drives the consent ceremony via
/// [`Session::observe_consent`], and then seals/opens application
/// payloads through the dedicated helpers here.
pub struct Session {
    role: SessionRole,
    wire: WireSession,
    /// Frame ID counter for outbound `RawFrame`s (host side only).
    next_frame_id: u64,
    /// Input sequence counter for outbound `RawInput`s (viewer side only).
    next_input_seq: u64,
    last_frame_sent_ms: u64,
}

impl Session {
    /// Construct a host-side session. Generates a random `source_id`
    /// and `epoch`; caller must install a key before sealing.
    pub fn host() -> Self {
        Self::with_role(SessionRole::Host)
    }

    /// Construct a viewer-side session.
    pub fn viewer() -> Self {
        Self::with_role(SessionRole::Viewer)
    }

    fn with_role(role: SessionRole) -> Self {
        Self {
            role,
            wire: WireSession::new(),
            next_frame_id: 0,
            next_input_seq: 0,
            last_frame_sent_ms: 0,
        }
    }

    /// Construct with deterministic `source_id` + `epoch`. Useful for
    /// test fixtures — MUST NOT be used in production because it
    /// breaks the per-session randomness assumption the wire relies on.
    pub fn with_fixture(role: SessionRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            role,
            wire: WireSession::with_source_id(source_id, epoch),
            next_frame_id: 0,
            next_input_seq: 0,
            last_frame_sent_ms: 0,
        }
    }

    /// Construct with deterministic `source_id` + `epoch` and require
    /// the xenia-wire consent ceremony before application frame/input
    /// payloads can flow.
    ///
    /// This is intended for pre-production daemon/runtime wiring and
    /// tests. It preserves fixture determinism while avoiding
    /// `LegacyBypass`.
    pub fn with_fixture_require_consent(role: SessionRole, source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            role,
            wire: WireSession::builder()
                .with_source_id(source_id, epoch)
                .require_consent(true)
                .build(),
            next_frame_id: 0,
            next_input_seq: 0,
            last_frame_sent_ms: 0,
        }
    }

    /// Install a 32-byte session key. Must be called before any
    /// `seal_*` or `open_*` call.
    pub fn install_key(&mut self, key: [u8; 32]) {
        self.wire.install_key(key);
    }

    /// Forward consent events to the underlying wire session. See
    /// [`xenia_wire::Session::observe_consent`].
    ///
    /// Returns `Result<ConsentState, ConsentViolation>` — legal
    /// transitions and benign no-ops return `Ok(state)`; protocol
    /// violations (SPEC draft-03 §12.6) return `Err(violation)`
    /// with the session state untouched. Callers SHOULD treat a
    /// violation as a hard fault signal and terminate the session.
    pub fn observe_consent(
        &mut self,
        event: xenia_wire::consent::ConsentEvent,
    ) -> Result<xenia_wire::consent::ConsentState, xenia_wire::consent::ConsentViolation> {
        self.wire.observe_consent(event)
    }

    /// Observe a local consent request event.
    pub fn observe_consent_request(
        &mut self,
        request_id: u64,
    ) -> Result<xenia_wire::consent::ConsentState, xenia_wire::consent::ConsentViolation> {
        self.observe_consent(xenia_wire::consent::ConsentEvent::Request { request_id })
    }

    /// Observe a local consent approval event.
    pub fn observe_consent_approved(
        &mut self,
        request_id: u64,
    ) -> Result<xenia_wire::consent::ConsentState, xenia_wire::consent::ConsentViolation> {
        self.observe_consent(xenia_wire::consent::ConsentEvent::ResponseApproved { request_id })
    }

    /// Observe a local consent denial event.
    pub fn observe_consent_denied(
        &mut self,
        request_id: u64,
    ) -> Result<xenia_wire::consent::ConsentState, xenia_wire::consent::ConsentViolation> {
        self.observe_consent(xenia_wire::consent::ConsentEvent::ResponseDenied { request_id })
    }

    /// Observe a local consent revocation event.
    pub fn observe_consent_revocation(
        &mut self,
        request_id: u64,
    ) -> Result<xenia_wire::consent::ConsentState, xenia_wire::consent::ConsentViolation> {
        self.observe_consent(xenia_wire::consent::ConsentEvent::Revocation { request_id })
    }

    /// Current consent state from the underlying wire session.
    pub fn consent_state(&self) -> xenia_wire::consent::ConsentState {
        self.wire.consent_state()
    }

    /// Borrow the underlying wire session for advanced callers who
    /// need the raw `seal` / `open` surface (custom payload types,
    /// rekey, tick, etc.).
    pub fn wire(&mut self) -> &mut WireSession {
        &mut self.wire
    }

    /// Return this session's role.
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// Allocate the next outbound frame ID. Called internally by
    /// [`Session::seal_captured_rgba`]; exposed for callers that batch
    /// frames or need the ID before sealing.
    pub fn next_frame_id(&mut self) -> u64 {
        let id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);
        id
    }

    /// Allocate the next outbound input sequence.
    pub fn next_input_seq(&mut self) -> u64 {
        let seq = self.next_input_seq;
        self.next_input_seq = self.next_input_seq.wrapping_add(1);
        seq
    }

    /// Seal a captured raw-RGBA frame on the forward path.
    ///
    /// Checks `ConsentState` to ensure the session is authorized.
    pub fn seal_captured_rgba(
        &mut self,
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        self.check_consent_for_frame()?;
        let now = now_ms();
        let frame = RawFrame::rgba8(self.next_frame_id(), now, width, height, pixels);
        self.last_frame_sent_ms = now;
        xenia_wire::seal_frame(&frame_as_wire(&frame)?, &mut self.wire).map_err(Into::into)
    }

    /// Return telemetry: time since last frame was sent (in ms).
    pub fn last_frame_latency_ms(&self) -> u64 {
        now_ms().saturating_sub(self.last_frame_sent_ms)
    }

    /// Seal a fully-constructed `RawFrame` on the forward path.
    /// Checks `ConsentState` to ensure the session is authorized.
    pub fn seal_frame(&mut self, frame: &RawFrame) -> Result<Vec<u8>, SessionError> {
        self.check_consent_for_frame()?;
        xenia_wire::seal_frame(&frame_as_wire(frame)?, &mut self.wire).map_err(Into::into)
    }

    /// Seal a session-control metadata frame on the forward path.
    ///
    /// This is intentionally limited to non-media setup metadata so
    /// post-handshake capabilities can be exchanged before runtime
    /// consent authorizes capture/audio/video flow.
    pub fn seal_control_frame(&mut self, frame: &RawFrame) -> Result<Vec<u8>, SessionError> {
        if frame.pixel_format != crate::frame::PixelFormat::Capabilities {
            return Err(SessionError::Wire(WireError::decode(
                "control frame must use a session-control pixel format",
            )));
        }
        xenia_wire::seal_frame(&frame_as_wire(frame)?, &mut self.wire).map_err(Into::into)
    }

    fn check_consent_for_frame(&self) -> Result<(), SessionError> {
        use xenia_wire::consent::ConsentState;
        match self.consent_state() {
            ConsentState::LegacyBypass | ConsentState::Approved => Ok(()),
            _ => Err(SessionError::Wire(WireError::decode(
                "Consent required for frame flow",
            ))),
        }
    }

    /// Open a sealed envelope as a `RawFrame` on the viewer side.
    /// Rejects envelopes whose pixel buffer doesn't match the declared
    /// width × height × format (returns `Codec(...)`).
    pub fn open_frame(&mut self, envelope: &[u8]) -> Result<RawFrame, SessionError> {
        let wire_frame = open_frame(envelope, &mut self.wire)?;
        let frame = frame_from_wire(&wire_frame)?;
        if !frame.validate() {
            return Err(SessionError::Wire(WireError::decode(
                "RawFrame buffer does not match declared dimensions",
            )));
        }
        Ok(frame)
    }

    /// Seal a viewer-captured input event on the reverse path. Fills
    /// in `sequence` (from [`Session::next_input_seq`]) and
    /// `timestamp_ms` automatically.
    pub fn seal_input_event(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        let input = RawInput {
            sequence: self.next_input_seq(),
            timestamp_ms: now_ms(),
            payload,
        };
        xenia_wire::seal_input(&input_as_wire(&input)?, &mut self.wire).map_err(Into::into)
    }

    /// Open a sealed input envelope on the host side.
    pub fn open_input(&mut self, envelope: &[u8]) -> Result<RawInput, SessionError> {
        let wire_input = open_input(envelope, &mut self.wire)?;
        input_from_wire(&wire_input).map_err(Into::into)
    }
}

// ─── Bridging RawFrame/RawInput ↔ xenia_wire::Frame/Input ─────────────
//
// xenia-wire's reference `Frame` type is intentionally opaque-bytes
// (per SPEC.md §4 — the wire doesn't know about pixel formats). We
// serialize the richer `RawFrame` into `xenia_wire::Frame.payload`
// via bincode, then seal as a regular FRAME.

fn frame_as_wire(frame: &RawFrame) -> Result<xenia_wire::Frame, WireError> {
    let payload = bincode::serialize(frame).map_err(WireError::encode)?;
    Ok(xenia_wire::Frame {
        frame_id: frame.frame_id,
        timestamp_ms: frame.timestamp_ms,
        payload,
    })
}

fn frame_from_wire(wire: &xenia_wire::Frame) -> Result<RawFrame, WireError> {
    bincode::deserialize(&wire.payload).map_err(WireError::decode)
}

fn input_as_wire(input: &RawInput) -> Result<xenia_wire::Input, WireError> {
    let payload = bincode::serialize(input).map_err(WireError::encode)?;
    Ok(xenia_wire::Input {
        sequence: input.sequence,
        timestamp_ms: input.timestamp_ms,
        payload,
    })
}

fn input_from_wire(wire: &xenia_wire::Input) -> Result<RawInput, WireError> {
    bincode::deserialize(&wire.payload).map_err(WireError::decode)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key() -> [u8; 32] {
        [0x42; 32]
    }

    fn paired() -> (Session, Session) {
        let mut host = Session::with_fixture(SessionRole::Host, [0x11; 8], 0xAB);
        let mut viewer = Session::with_fixture(SessionRole::Viewer, [0x11; 8], 0xAB);
        host.install_key(fixture_key());
        viewer.install_key(fixture_key());
        (host, viewer)
    }

    fn solid_blue(w: u32, h: u32) -> Vec<u8> {
        (0..(w * h)).flat_map(|_| [0u8, 0, 255, 255]).collect()
    }

    #[test]
    fn frame_seal_open_roundtrip_preserves_pixels() {
        let (mut host, mut viewer) = paired();
        let pixels = solid_blue(8, 4);
        let sealed = host.seal_captured_rgba(8, 4, pixels.clone()).unwrap();
        let opened = viewer.open_frame(&sealed).unwrap();
        assert_eq!(opened.width, 8);
        assert_eq!(opened.height, 4);
        assert_eq!(opened.pixels, pixels);
        assert_eq!(opened.pixel_format, crate::frame::PixelFormat::Rgba8);
        assert_eq!(opened.frame_id, 0);
    }

    #[test]
    fn frame_counter_advances_per_seal() {
        let (mut host, _viewer) = paired();
        for expected_id in 0u64..5 {
            let _ = host.seal_captured_rgba(2, 2, solid_blue(2, 2)).unwrap();
            // next_frame_id advances past what we just used.
            assert_eq!(host.next_frame_id, expected_id + 1);
        }
    }

    #[test]
    fn input_seal_open_roundtrip_preserves_payload() {
        let (mut host, mut viewer) = paired();
        let payload = br#"{"type":"mousemove","x":0.7,"y":0.3}"#.to_vec();
        let sealed = viewer.seal_input_event(payload.clone()).unwrap();
        let opened = host.open_input(&sealed).unwrap();
        assert_eq!(opened.payload, payload);
        assert_eq!(opened.sequence, 0);
    }

    #[test]
    fn open_frame_rejects_dimension_mismatch() {
        // Hand-craft a RawFrame whose declared dims don't match the
        // buffer, seal it, and verify the viewer catches it on open.
        let (mut host, mut viewer) = paired();
        let bad = RawFrame {
            frame_id: 0,
            timestamp_ms: 0,
            width: 100,
            height: 100,
            pixel_format: crate::frame::PixelFormat::Rgba8,
            pixels: vec![0u8; 10],
        };
        let sealed = host.seal_frame(&bad).unwrap();
        let err = viewer.open_frame(&sealed);
        assert!(err.is_err(), "dimension mismatch must be rejected");
    }

    #[test]
    fn telemetry_frame_seal_open_roundtrip() {
        let (mut host, mut viewer) = paired();
        let telemetry = crate::frame::RawTelemetry {
            frame_id: host.next_frame_id(),
            timestamp_ms: 1_700_000_000_500,
            backend: "test".to_string(),
            samples: vec![crate::frame::TelemetrySample {
                name: "memory.used.bytes".to_string(),
                value: crate::frame::TelemetryValue::U64(1024),
                unit: Some("bytes".to_string()),
                timestamp_ms: 1_700_000_000_500,
            }],
        };
        let frame = telemetry.clone().into_frame().unwrap();
        let sealed = host.seal_frame(&frame).unwrap();
        let opened = viewer.open_frame(&sealed).unwrap();
        assert_eq!(opened.pixel_format, crate::frame::PixelFormat::Telemetry);
        assert_eq!(
            crate::frame::RawTelemetry::from_frame(&opened).unwrap(),
            telemetry
        );
    }

    #[test]
    fn audio_frame_seal_open_roundtrip() {
        let (mut host, mut viewer) = paired();
        let mut source =
            crate::frame::SyntheticAudioSource::new(1, crate::frame::SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_700);
        let frame = audio.clone().into_frame(host.next_frame_id()).unwrap();
        let sealed = host.seal_frame(&frame).unwrap();
        let opened = viewer.open_frame(&sealed).unwrap();
        assert_eq!(opened.pixel_format, crate::frame::PixelFormat::Audio);
        assert_eq!(crate::frame::RawAudio::from_frame(&opened).unwrap(), audio);
    }

    #[test]
    fn capabilities_control_frame_seal_open_roundtrip() {
        let (mut host, mut viewer) = paired();
        let capabilities = crate::frame::RawCapabilities {
            frame_id: host.next_frame_id(),
            timestamp_ms: 1_700_000_000_900,
            audio: Some(crate::advertisement::AudioAdvertisement {
                codecs: vec![crate::advertisement::AdvertisedAudioCodec::RawPcm],
                selected_codec: crate::advertisement::AdvertisedAudioCodec::RawPcm,
                sample_rate_hz: crate::frame::RAW_AUDIO_SAMPLE_RATE_HZ,
                max_channels: crate::frame::RAW_AUDIO_MAX_CHANNELS,
                frame_duration_ms: vec![10, 20],
            }),
            video_format: crate::frame::PixelFormat::Passthrough,
            telemetry_enabled: true,
            input_control_enabled: false,
        };
        let frame = capabilities.clone().into_frame().unwrap();
        let sealed = host.seal_control_frame(&frame).unwrap();
        let opened = viewer.open_frame(&sealed).unwrap();

        assert_eq!(opened.pixel_format, crate::frame::PixelFormat::Capabilities);
        assert_eq!(
            crate::frame::RawCapabilities::from_frame(&opened).unwrap(),
            capabilities
        );
    }

    #[test]
    fn control_frame_rejects_media_formats() {
        let (mut host, _) = paired();
        let frame = RawFrame::rgba8(0, 1_700_000_000_900, 1, 1, vec![0, 0, 0, 255]);

        assert!(host.seal_control_frame(&frame).is_err());
    }

    #[test]
    fn role_preserved() {
        let host = Session::host();
        let viewer = Session::viewer();
        assert_eq!(host.role(), SessionRole::Host);
        assert_eq!(viewer.role(), SessionRole::Viewer);
    }
}
