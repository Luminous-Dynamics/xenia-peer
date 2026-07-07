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
use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_wire::{Session as WireSession, WireError, open_frame, open_input};

use crate::frame::{LANE_ENVELOPE_MAGIC, RawFrame, RawInput};

const LANE_ENVELOPE_HEADER_LEN: usize = 5;

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

/// Forward-path lane used to select the AEAD key for a [`RawFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameLane {
    /// Session setup/control metadata such as capabilities and rekey.
    Control,
    /// Video/captured display frames.
    Video,
    /// Audio timing/media frames.
    Audio,
    /// System telemetry frames.
    Telemetry,
}

impl FrameLane {
    const fn tag(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Video => 1,
            Self::Audio => 2,
            Self::Telemetry => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, WireError> {
        match tag {
            0 => Ok(Self::Control),
            1 => Ok(Self::Video),
            2 => Ok(Self::Audio),
            3 => Ok(Self::Telemetry),
            _ => Err(WireError::decode("unknown lane envelope tag")),
        }
    }

    fn for_frame(frame: &RawFrame) -> Self {
        match frame.pixel_format {
            crate::frame::PixelFormat::Capabilities
            | crate::frame::PixelFormat::Rekey
            | crate::frame::PixelFormat::Clipboard => Self::Control,
            crate::frame::PixelFormat::Audio => Self::Audio,
            crate::frame::PixelFormat::Telemetry => Self::Telemetry,
            _ => Self::Video,
        }
    }
}

/// Session errors surfaced from the host-side wrapper.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// Underlying `xenia-wire` operation failed.
    #[error("xenia-wire: {0}")]
    Wire(#[from] WireError),
}

/// Lane-separated forward-path session.
///
/// `xenia-wire` currently exposes one traffic key per [`WireSession`]. This
/// wrapper composes four wire sessions so Xenia can use the transcript-derived
/// control/video/audio/telemetry keys independently while keeping the existing
/// sealed-envelope transport unchanged.
pub struct LaneSession {
    control: WireSession,
    video: WireSession,
    audio: WireSession,
    telemetry: WireSession,
    next_frame_id: u64,
    next_input_seq: u64,
    next_clipboard_seq: u64,
    last_frame_sent_ms: u64,
}

impl LaneSession {
    /// Construct a lane-separated session with deterministic source metadata.
    pub fn with_fixture(source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            control: WireSession::with_source_id(source_id, epoch),
            video: WireSession::with_source_id(source_id, epoch),
            audio: WireSession::with_source_id(source_id, epoch),
            telemetry: WireSession::with_source_id(source_id, epoch),
            next_frame_id: 0,
            next_input_seq: 0,
            next_clipboard_seq: 0,
            last_frame_sent_ms: 0,
        }
    }

    /// Install initial transcript-derived lane keys.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.control.install_key(schedule.control);
        self.video.install_key(schedule.video);
        self.audio.install_key(schedule.audio);
        self.telemetry.install_key(schedule.telemetry);
    }

    /// Install rekey-epoch lane keys.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.control.install_key(keys.control);
        self.video.install_key(keys.video);
        self.audio.install_key(keys.audio);
        self.telemetry.install_key(keys.telemetry);
    }

    /// Advance previous-key grace expiry on every lane.
    pub fn tick(&mut self) {
        self.control.tick();
        self.video.tick();
        self.audio.tick();
        self.telemetry.tick();
    }

    /// Allocate the next outbound frame ID.
    pub fn next_frame_id(&mut self) -> u64 {
        let id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);
        id
    }

    /// Allocate the next outbound input sequence.
    fn next_input_seq(&mut self) -> u64 {
        let seq = self.next_input_seq;
        self.next_input_seq = self.next_input_seq.wrapping_add(1);
        seq
    }

    /// Return telemetry: time since last frame was sent (in ms).
    pub fn last_frame_latency_ms(&self) -> u64 {
        now_ms().saturating_sub(self.last_frame_sent_ms)
    }

    /// Seal a captured input event on the reverse path (viewer →
    /// host). Input does not ride the lane-envelope system used by
    /// [`LaneSession::seal_frame`] — it seals directly under the
    /// control lane's key, since input is a control-plane-adjacent
    /// concern and that lane's key is already installed immediately
    /// post-handshake. Fills in `sequence` and `timestamp_ms`
    /// automatically. See [`LaneSession::open_input`].
    pub fn seal_input_event(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        let input = RawInput {
            sequence: self.next_input_seq(),
            timestamp_ms: now_ms(),
            payload,
        };
        xenia_wire::seal_input(&input_as_wire(&input)?, &mut self.control).map_err(Into::into)
    }

    /// Open a sealed input envelope on the host side. See
    /// [`LaneSession::seal_input_event`] for why this uses the control
    /// lane's key directly rather than the `XLN1` lane-envelope format.
    pub fn open_input(&mut self, envelope: &[u8]) -> Result<RawInput, SessionError> {
        let wire_input = open_input(envelope, &mut self.control)?;
        input_from_wire(&wire_input).map_err(Into::into)
    }

    /// Allocate the next outbound clipboard-update sequence.
    fn next_clipboard_seq(&mut self) -> u64 {
        let seq = self.next_clipboard_seq;
        self.next_clipboard_seq = self.next_clipboard_seq.wrapping_add(1);
        seq
    }

    /// Seal a clipboard update this side originated, for the *reverse*
    /// direction only (viewer → host) -- bare envelope directly under
    /// the control lane's key, like [`LaneSession::seal_input_event`],
    /// but with its own wire payload type
    /// ([`crate::frame::PAYLOAD_TYPE_CLIPBOARD`]) so a receiver can
    /// distinguish the two bare-envelope streams by peeking
    /// [`xenia_wire::envelope_payload_type`] rather than guessing.
    ///
    /// The *forward* direction (host → viewer) instead rides the
    /// ordinary lane-envelope system as a `PixelFormat::Clipboard`
    /// frame via [`LaneSession::seal_control_frame`] -- see
    /// [`crate::frame::RawClipboard::into_frame`].
    pub fn seal_clipboard_event(
        &mut self,
        content: crate::frame::ClipboardContent,
    ) -> Result<Vec<u8>, SessionError> {
        let clip = crate::frame::RawClipboard {
            sequence: self.next_clipboard_seq(),
            timestamp_ms: now_ms(),
            content,
        };
        xenia_wire::seal(
            &clip,
            &mut self.control,
            crate::frame::PAYLOAD_TYPE_CLIPBOARD,
        )
        .map_err(Into::into)
    }

    /// Open a reverse-path (viewer → host) clipboard envelope sealed by
    /// [`LaneSession::seal_clipboard_event`].
    pub fn open_clipboard(
        &mut self,
        envelope: &[u8],
    ) -> Result<crate::frame::RawClipboard, SessionError> {
        xenia_wire::open(envelope, &mut self.control).map_err(Into::into)
    }

    /// Seal a file-transfer protocol message under the control lane's key.
    /// `is_host` selects which of the two payload types to seal under --
    /// pass the caller's own fixed role (`true` for `xenia-peer`, `false`
    /// for `xenia-viewer`), never the transfer's sender/receiver role;
    /// see [`crate::frame::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST`]'s doc
    /// comment for why this can't be a single shared payload type.
    pub fn seal_file_transfer_message(
        &mut self,
        message: crate::frame::FileTransferMessage,
        is_host: bool,
    ) -> Result<Vec<u8>, SessionError> {
        let payload_type = if is_host {
            crate::frame::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST
        } else {
            crate::frame::PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER
        };
        xenia_wire::seal(&message, &mut self.control, payload_type).map_err(Into::into)
    }

    /// Open a bare file-transfer envelope sealed by
    /// [`LaneSession::seal_file_transfer_message`].
    pub fn open_file_transfer_message(
        &mut self,
        envelope: &[u8],
    ) -> Result<crate::frame::FileTransferMessage, SessionError> {
        xenia_wire::open(envelope, &mut self.control).map_err(Into::into)
    }

    /// Seal a captured raw-RGBA frame on the video lane.
    pub fn seal_captured_rgba(
        &mut self,
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let now = now_ms();
        let frame = RawFrame::rgba8(self.next_frame_id(), now, width, height, pixels);
        self.last_frame_sent_ms = now;
        self.seal_frame(&frame)
    }

    /// Seal a frame on its semantic lane.
    pub fn seal_frame(&mut self, frame: &RawFrame) -> Result<Vec<u8>, SessionError> {
        let lane = FrameLane::for_frame(frame);
        let wire = self.lane_mut(lane);
        let sealed = xenia_wire::seal_frame(&frame_as_wire(frame)?, wire)?;
        Ok(wrap_lane_envelope(lane, sealed))
    }

    /// Seal a session-control metadata frame on the control lane.
    pub fn seal_control_frame(&mut self, frame: &RawFrame) -> Result<Vec<u8>, SessionError> {
        if FrameLane::for_frame(frame) != FrameLane::Control {
            return Err(SessionError::Wire(WireError::decode(
                "control frame must use a session-control pixel format",
            )));
        }
        self.seal_frame(frame)
    }

    /// Open a sealed envelope using explicit lane metadata.
    ///
    /// Unwrapped envelopes are still accepted by trying the bounded lane set as
    /// a compatibility path for older local tests and pre-lane peers.
    pub fn open_frame(&mut self, envelope: &[u8]) -> Result<RawFrame, SessionError> {
        self.tick();
        if let Some((lane, sealed)) = unwrap_lane_envelope(envelope)? {
            return self.open_frame_on_lane(sealed, lane);
        }
        let lanes = [
            FrameLane::Control,
            FrameLane::Audio,
            FrameLane::Telemetry,
            FrameLane::Video,
        ];
        let mut last_error = WireError::OpenFailed;
        for lane in lanes {
            match self.open_frame_on_lane(envelope, lane) {
                Ok(frame) => return Ok(frame),
                Err(SessionError::Wire(err)) => {
                    last_error = err;
                }
            }
        }
        Err(SessionError::Wire(last_error))
    }

    fn open_frame_on_lane(
        &mut self,
        envelope: &[u8],
        lane: FrameLane,
    ) -> Result<RawFrame, SessionError> {
        let opened = {
            let wire = self.lane_mut(lane);
            open_frame(envelope, wire)
        }?;
        let frame = frame_from_wire(&opened)?;
        if FrameLane::for_frame(&frame) != lane {
            return Err(SessionError::Wire(WireError::decode(
                "frame opened on an unexpected lane",
            )));
        }
        if !frame.validate() {
            return Err(SessionError::Wire(WireError::decode(
                "RawFrame buffer does not match declared dimensions",
            )));
        }
        Ok(frame)
    }

    fn lane_mut(&mut self, lane: FrameLane) -> &mut WireSession {
        match lane {
            FrameLane::Control => &mut self.control,
            FrameLane::Video => &mut self.video,
            FrameLane::Audio => &mut self.audio,
            FrameLane::Telemetry => &mut self.telemetry,
        }
    }
}

fn wrap_lane_envelope(lane: FrameLane, sealed: Vec<u8>) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(LANE_ENVELOPE_HEADER_LEN + sealed.len());
    envelope.extend_from_slice(&LANE_ENVELOPE_MAGIC);
    envelope.push(lane.tag());
    envelope.extend_from_slice(&sealed);
    envelope
}

fn unwrap_lane_envelope(envelope: &[u8]) -> Result<Option<(FrameLane, &[u8])>, SessionError> {
    if envelope.len() < LANE_ENVELOPE_HEADER_LEN {
        return Ok(None);
    }
    if envelope[..LANE_ENVELOPE_MAGIC.len()] != LANE_ENVELOPE_MAGIC {
        return Ok(None);
    }
    let lane = FrameLane::from_tag(envelope[LANE_ENVELOPE_MAGIC.len()])?;
    Ok(Some((lane, &envelope[LANE_ENVELOPE_HEADER_LEN..])))
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
    /// post-handshake capabilities/rekey messages can be exchanged before runtime
    /// consent authorizes capture/audio/video flow.
    pub fn seal_control_frame(&mut self, frame: &RawFrame) -> Result<Vec<u8>, SessionError> {
        if !matches!(
            frame.pixel_format,
            crate::frame::PixelFormat::Capabilities | crate::frame::PixelFormat::Rekey
        ) {
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
    fn lane_session_input_seal_open_roundtrip_uses_control_key_unwrapped() {
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xA5; 32], &[0x5A; 32]);
        let mut viewer = LaneSession::with_fixture([0x44; 8], 0xDE);
        viewer.install_schedule(&schedule);
        let mut host = LaneSession::with_fixture([0x44; 8], 0xDE);
        host.install_schedule(&schedule);

        let payload = br#"{"type":"mousemove","x":0.4,"y":0.6}"#.to_vec();
        let sealed = viewer.seal_input_event(payload.clone()).unwrap();

        // Input is NOT lane-enveloped -- no XLN1 magic prefix.
        assert_ne!(
            &sealed[..LANE_ENVELOPE_MAGIC.len().min(sealed.len())],
            &LANE_ENVELOPE_MAGIC
        );

        let opened = host.open_input(&sealed).unwrap();
        assert_eq!(opened.payload, payload);
        assert_eq!(opened.sequence, 0);

        // Wrong key (e.g. video lane's) must not open it.
        let mut wrong_key_host = LaneSession::with_fixture([0x44; 8], 0xDE);
        let mut tampered_schedule = schedule;
        tampered_schedule.control[0] ^= 0x01;
        wrong_key_host.install_schedule(&tampered_schedule);
        assert!(wrong_key_host.open_input(&sealed).is_err());
    }

    #[test]
    fn lane_session_clipboard_reverse_path_seal_open_roundtrip() {
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xB6; 32], &[0x6B; 32]);
        let mut viewer = LaneSession::with_fixture([0x55; 8], 0xEF);
        viewer.install_schedule(&schedule);
        let mut host = LaneSession::with_fixture([0x55; 8], 0xEF);
        host.install_schedule(&schedule);

        let sealed = viewer
            .seal_clipboard_event(crate::frame::ClipboardContent::Text("hello xenia".into()))
            .unwrap();

        // Clipboard is NOT lane-enveloped either -- same bare-envelope
        // convention as input, just a different wire payload type.
        assert_ne!(
            &sealed[..LANE_ENVELOPE_MAGIC.len().min(sealed.len())],
            &LANE_ENVELOPE_MAGIC
        );

        let opened = host.open_clipboard(&sealed).unwrap();
        assert_eq!(
            opened.content,
            crate::frame::ClipboardContent::Text("hello xenia".into())
        );
        assert_eq!(opened.sequence, 0);
    }

    #[test]
    fn lane_session_file_transfer_seal_open_roundtrip_is_symmetric() {
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xD8; 32], &[0x8D; 32]);
        let mut host = LaneSession::with_fixture([0x77; 8], 0x22);
        host.install_schedule(&schedule);
        let mut viewer = LaneSession::with_fixture([0x77; 8], 0x22);
        viewer.install_schedule(&schedule);

        // Either side can originate a transfer -- host offers here, but
        // the wire shape is identical if the viewer originates instead.
        // `is_host` always reflects the *sealing* side, not who is
        // logically sending/receiving this particular transfer.
        let offer = crate::frame::FileTransferMessage::Offer {
            transfer_id: 42,
            name: "notes.txt".into(),
            size: 11,
            blake3_hash: [0x9A; 32],
        };
        let sealed = host
            .seal_file_transfer_message(offer.clone(), true)
            .unwrap();
        assert_ne!(
            &sealed[..LANE_ENVELOPE_MAGIC.len().min(sealed.len())],
            &LANE_ENVELOPE_MAGIC
        );
        assert_eq!(
            xenia_wire::envelope_payload_type(&sealed),
            Some(crate::frame::PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST)
        );
        let opened = viewer.open_file_transfer_message(&sealed).unwrap();
        assert_eq!(opened, offer);

        // Viewer replies with an Accept -- same methods, opposite direction,
        // sealed under the *other* payload type.
        let accept = crate::frame::FileTransferMessage::Accept { transfer_id: 42 };
        let sealed = viewer
            .seal_file_transfer_message(accept.clone(), false)
            .unwrap();
        assert_eq!(
            xenia_wire::envelope_payload_type(&sealed),
            Some(crate::frame::PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER)
        );
        let opened = host.open_file_transfer_message(&sealed).unwrap();
        assert_eq!(opened, accept);
    }

    #[test]
    fn file_transfer_from_host_and_from_viewer_do_not_collide_on_first_nonce() {
        // Regression test for a real bug caught via live testing: host and
        // viewer share the same `source_id` (per --source-id-hex), and each
        // side's session-object nonce counter starts at 0 independently.
        // Sealing both sides' very first file-transfer message under one
        // shared payload type produced byte-identical nonces (the same
        // source_id, payload_type, epoch, and sequence=0) under the same
        // control-lane key -- an actual AEAD nonce reuse, not just a
        // replay-window false positive. Asserts the two sealed envelopes
        // differ (in the payload_type nonce byte) even though both sides
        // seal their very first message here.
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xE9; 32], &[0x9E; 32]);
        let mut host = LaneSession::with_fixture([0x88; 8], 0x33);
        host.install_schedule(&schedule);
        let mut viewer = LaneSession::with_fixture([0x88; 8], 0x33);
        viewer.install_schedule(&schedule);

        let host_msg = crate::frame::FileTransferMessage::Offer {
            transfer_id: 1,
            name: "a.bin".into(),
            size: 1,
            blake3_hash: [0; 32],
        };
        let viewer_msg = crate::frame::FileTransferMessage::Offer {
            transfer_id: 1,
            name: "b.bin".into(),
            size: 1,
            blake3_hash: [0; 32],
        };
        let host_sealed = host.seal_file_transfer_message(host_msg, true).unwrap();
        let viewer_sealed = viewer
            .seal_file_transfer_message(viewer_msg, false)
            .unwrap();

        // Nonce is the first 12 bytes; must differ despite both being each
        // side's first-ever seal under a shared source_id/epoch.
        assert_ne!(host_sealed[..12], viewer_sealed[..12]);
        // Each side must be able to open the OTHER's envelope but not its
        // own confused-for-the-other's (opening still works generically
        // here since open() doesn't care which of the two payload types it
        // sees -- the real safety property is the nonce disjointness above).
        assert!(viewer.open_file_transfer_message(&host_sealed).is_ok());
        assert!(host.open_file_transfer_message(&viewer_sealed).is_ok());
    }

    #[test]
    fn clipboard_and_input_bare_envelopes_are_distinguishable_by_payload_type_without_opening() {
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xC7; 32], &[0x7C; 32]);
        let mut viewer = LaneSession::with_fixture([0x66; 8], 0x11);
        viewer.install_schedule(&schedule);

        let clipboard_envelope = viewer
            .seal_clipboard_event(crate::frame::ClipboardContent::Cleared)
            .unwrap();
        let input_envelope = viewer.seal_input_event(b"tap".to_vec()).unwrap();

        assert_eq!(
            xenia_wire::envelope_payload_type(&clipboard_envelope),
            Some(crate::frame::PAYLOAD_TYPE_CLIPBOARD)
        );
        assert_ne!(
            xenia_wire::envelope_payload_type(&input_envelope),
            Some(crate::frame::PAYLOAD_TYPE_CLIPBOARD)
        );
    }

    #[test]
    fn lane_session_clipboard_forward_path_rides_control_lane_envelope() {
        // Forward direction (host -> viewer) uses the ordinary
        // lane-envelope RawFrame system instead, like Capabilities/Rekey.
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xD8; 32], &[0x8D; 32]);
        let mut host = LaneSession::with_fixture([0x77; 8], 0x22);
        host.install_schedule(&schedule);
        let mut viewer = LaneSession::with_fixture([0x77; 8], 0x22);
        viewer.install_schedule(&schedule);

        let clip = crate::frame::RawClipboard {
            sequence: 0,
            timestamp_ms: 1_700_000_000_900,
            content: crate::frame::ClipboardContent::Text("from host".into()),
        };
        let frame_id = host.next_frame_id();
        let frame = clip.clone().into_frame(frame_id).unwrap();
        let sealed = host.seal_control_frame(&frame).unwrap();

        // This direction IS lane-enveloped.
        assert_eq!(&sealed[..LANE_ENVELOPE_MAGIC.len()], &LANE_ENVELOPE_MAGIC);

        let opened = viewer.open_frame(&sealed).unwrap();
        assert_eq!(opened.pixel_format, crate::frame::PixelFormat::Clipboard);
        assert_eq!(
            crate::frame::RawClipboard::from_frame(&opened).unwrap(),
            clip
        );
    }

    #[test]
    fn lane_session_separates_audio_and_video_keys() {
        let mut schedule = xenia_handshake::derive_session_key_schedule(&[0xA5; 32], &[0x5A; 32]);
        let mut host = LaneSession::with_fixture([0x22; 8], 0xBC);
        host.install_schedule(&schedule);

        let mut viewer = LaneSession::with_fixture([0x22; 8], 0xBC);
        viewer.install_schedule(&schedule);

        let video = host.seal_captured_rgba(1, 1, solid_blue(1, 1)).unwrap();
        assert_eq!(&video[..LANE_ENVELOPE_MAGIC.len()], &LANE_ENVELOPE_MAGIC);
        assert_eq!(video[LANE_ENVELOPE_MAGIC.len()], FrameLane::Video.tag());
        assert_eq!(
            viewer.open_frame(&video).unwrap().pixel_format,
            crate::frame::PixelFormat::Rgba8
        );

        schedule.audio[0] ^= 0x01;
        let mut wrong_audio_viewer = LaneSession::with_fixture([0x22; 8], 0xBC);
        wrong_audio_viewer.install_schedule(&schedule);

        let mut source =
            crate::frame::SyntheticAudioSource::new(1, crate::frame::SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_700);
        let audio_frame = audio.into_frame(host.next_frame_id()).unwrap();
        let sealed_audio = host.seal_frame(&audio_frame).unwrap();
        assert_eq!(
            sealed_audio[LANE_ENVELOPE_MAGIC.len()],
            FrameLane::Audio.tag()
        );

        assert!(wrong_audio_viewer.open_frame(&sealed_audio).is_err());
        assert_eq!(
            viewer.open_frame(&sealed_audio).unwrap().pixel_format,
            crate::frame::PixelFormat::Audio
        );
    }

    #[test]
    fn lane_session_rejects_tampered_lane_tag() {
        let schedule = xenia_handshake::derive_session_key_schedule(&[0xA5; 32], &[0x5A; 32]);
        let mut host = LaneSession::with_fixture([0x33; 8], 0xCD);
        host.install_schedule(&schedule);
        let mut viewer = LaneSession::with_fixture([0x33; 8], 0xCD);
        viewer.install_schedule(&schedule);

        let mut source =
            crate::frame::SyntheticAudioSource::new(1, crate::frame::SyntheticAudioKind::Sine);
        let audio = source.next_frame(1_700_000_000_700);
        let audio_frame = audio.into_frame(host.next_frame_id()).unwrap();
        let mut sealed_audio = host.seal_frame(&audio_frame).unwrap();
        sealed_audio[LANE_ENVELOPE_MAGIC.len()] = FrameLane::Video.tag();

        assert!(viewer.open_frame(&sealed_audio).is_err());
    }

    #[test]
    fn installed_rekey_rejects_old_epoch_envelope_after_grace() {
        let mut host = Session::with_fixture(SessionRole::Host, [0x11; 8], 0xAB);
        let mut viewer = Session {
            role: SessionRole::Viewer,
            wire: WireSession::with_source_id([0x11; 8], 0xAB)
                .with_rekey_grace(Duration::from_millis(1)),
            next_frame_id: 0,
            next_input_seq: 0,
            last_frame_sent_ms: 0,
        };
        host.install_key(fixture_key());
        viewer.install_key(fixture_key());

        let old_epoch = host.seal_captured_rgba(1, 1, solid_blue(1, 1)).unwrap();

        let new_key = [0x99; 32];
        host.install_key(new_key);
        viewer.install_key(new_key);
        std::thread::sleep(Duration::from_millis(5));
        viewer.wire.tick();

        let new_epoch = host.seal_captured_rgba(1, 1, solid_blue(1, 1)).unwrap();
        assert!(viewer.open_frame(&new_epoch).is_ok());
        assert!(viewer.open_frame(&old_epoch).is_err());
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
            clipboard_enabled: false,
            lane_envelope_version: crate::frame::LANE_ENVELOPE_SCHEMA_VERSION,
            lane_envelope_magic: crate::frame::LANE_ENVELOPE_MAGIC,
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
