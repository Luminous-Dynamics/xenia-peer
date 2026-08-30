// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Direction-safe public facade for [`crate::session::LaneSession`].
//!
//! The underlying lane implementation remains the owner of framing, replay,
//! lane selection, and the normal sender counter. This facade adds one narrow
//! sender nonce domain for `RawRekey::Ack`: host and viewer share the control
//! traffic key, and both sender counters reset to zero on rekey, so using the
//! same source/epoch/FRAME tuple in both directions can reuse an AEAD nonce.
//! Acks therefore seal through a second `xenia_wire::Session` whose first
//! source-id byte is deterministically separated from the regular lane source.

use std::time::Duration;

use xenia_handshake::{RekeyEpochKeys, SessionKeySchedule};
use xenia_wire::{Session as WireSession, WireError};

use crate::frame::{
    ClipboardContent, FileTransferMessage, LANE_ENVELOPE_MAGIC, PixelFormat, RawClipboard,
    RawFrame, RawInput, RawRekey,
};
use crate::session::{LaneSession as InnerLaneSession, SessionError};

const CONTROL_LANE_TAG: u8 = 0;
const REKEY_ACK_SOURCE_DOMAIN_BIT: u8 = 0x80;

/// Lane-separated session with a dedicated sender nonce domain for rekey Acks.
///
/// All ordinary lane behavior delegates to the existing implementation. Only
/// viewer-style [`RawRekey::Ack`] control frames use the extra sender domain.
/// This keeps the current pre-alpha wire body and lane wrapper unchanged while
/// ensuring the Ack cannot share a ChaCha20-Poly1305 nonce with the host's first
/// control-frame seal under the same newly-installed key.
pub struct LaneSession {
    inner: InnerLaneSession,
    rekey_ack_tx: WireSession,
}

impl LaneSession {
    /// Construct with deterministic base source metadata.
    ///
    /// The ordinary lanes use `source_id` unchanged. Rekey Acks use the same
    /// metadata except bit 7 of the first source byte is toggled, guaranteeing
    /// a different six-byte wire source prefix for this connection.
    pub fn with_fixture(source_id: [u8; 8], epoch: u8) -> Self {
        let mut ack_source_id = source_id;
        ack_source_id[0] ^= REKEY_ACK_SOURCE_DOMAIN_BIT;
        Self {
            inner: InnerLaneSession::with_fixture(source_id, epoch),
            // This session never receives, so retaining superseded keys for a
            // receive-grace window serves no purpose. Keep grace at zero and
            // tick immediately after every replacement below.
            rekey_ack_tx: WireSession::with_source_id(ack_source_id, epoch)
                .with_rekey_grace(Duration::ZERO),
        }
    }

    /// Install the initial transcript-derived lane keys.
    pub fn install_schedule(&mut self, schedule: &SessionKeySchedule) {
        self.inner.install_schedule(schedule);
        self.rekey_ack_tx.install_key(schedule.control);
    }

    /// Install one rekey epoch's lane keys.
    pub fn install_rekey_keys(&mut self, keys: &RekeyEpochKeys) {
        self.inner.install_rekey_keys(keys);
        self.rekey_ack_tx.install_key(keys.control);
        self.rekey_ack_tx.tick();
    }

    /// Advance previous-key grace expiry for ordinary lanes and the Ack sender.
    pub fn tick(&mut self) {
        self.inner.tick();
        self.rekey_ack_tx.tick();
    }

    /// Allocate the next outbound frame id.
    pub fn next_frame_id(&mut self) -> u64 {
        self.inner.next_frame_id()
    }

    /// Return milliseconds since the last forward frame was sent.
    pub fn last_frame_latency_ms(&self) -> u64 {
        self.inner.last_frame_latency_ms()
    }

    /// Seal a reverse-path input event.
    pub fn seal_input_event(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        self.inner.seal_input_event(payload)
    }

    /// Open a reverse-path input event.
    pub fn open_input(&mut self, envelope: &[u8]) -> Result<RawInput, SessionError> {
        self.inner.open_input(envelope)
    }

    /// Seal a reverse-path clipboard update.
    pub fn seal_clipboard_event(
        &mut self,
        content: ClipboardContent,
    ) -> Result<Vec<u8>, SessionError> {
        self.inner.seal_clipboard_event(content)
    }

    /// Open a reverse-path clipboard update.
    pub fn open_clipboard(&mut self, envelope: &[u8]) -> Result<RawClipboard, SessionError> {
        self.inner.open_clipboard(envelope)
    }

    /// Seal a file-transfer protocol message under the caller-side payload type.
    pub fn seal_file_transfer_message(
        &mut self,
        message: FileTransferMessage,
        is_host: bool,
    ) -> Result<Vec<u8>, SessionError> {
        self.inner.seal_file_transfer_message(message, is_host)
    }

    /// Open a bare file-transfer protocol message.
    pub fn open_file_transfer_message(
        &mut self,
        envelope: &[u8],
    ) -> Result<FileTransferMessage, SessionError> {
        self.inner.open_file_transfer_message(envelope)
    }

    /// Seal captured RGBA pixels on the video lane.
    pub fn seal_captured_rgba(
        &mut self,
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        self.inner.seal_captured_rgba(width, height, pixels)
    }

    /// Seal a frame on its semantic lane.
    pub fn seal_frame(&mut self, frame: &RawFrame) -> Result<Vec<u8>, SessionError> {
        self.inner.seal_frame(frame)
    }

    /// Seal a session-control frame.
    ///
    /// `RawRekey::Ack` is the only currently supported control message that is
    /// sealed in the reverse direction with the same xenia-wire `FRAME` payload
    /// type as host-originated control frames. Acks therefore use the dedicated
    /// sender source domain. Proposals and every other control frame retain the
    /// existing path unchanged.
    pub fn seal_control_frame(&mut self, frame: &RawFrame) -> Result<Vec<u8>, SessionError> {
        if frame.pixel_format == PixelFormat::Rekey
            && matches!(RawRekey::from_frame(frame)?, RawRekey::Ack { .. })
        {
            let wire_frame = frame_as_wire(frame)?;
            let sealed = xenia_wire::seal_frame(&wire_frame, &mut self.rekey_ack_tx)?;
            return Ok(wrap_control_envelope(sealed));
        }
        self.inner.seal_control_frame(frame)
    }

    /// Open a lane-wrapped frame.
    ///
    /// xenia-wire authenticates the sender-provided nonce and keys replay state
    /// by the source bytes carried in that nonce, so the ordinary control
    /// receiver can open both the regular host domain and the separated Ack
    /// sender domain without a second receive key or grace path.
    pub fn open_frame(&mut self, envelope: &[u8]) -> Result<RawFrame, SessionError> {
        self.inner.open_frame(envelope)
    }
}

fn frame_as_wire(frame: &RawFrame) -> Result<xenia_wire::Frame, WireError> {
    let payload = bincode::serialize(frame).map_err(WireError::encode)?;
    Ok(xenia_wire::Frame {
        frame_id: frame.frame_id,
        timestamp_ms: frame.timestamp_ms,
        payload,
    })
}

fn wrap_control_envelope(sealed: Vec<u8>) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(LANE_ENVELOPE_MAGIC.len() + 1 + sealed.len());
    envelope.extend_from_slice(&LANE_ENVELOPE_MAGIC);
    envelope.push(CONTROL_LANE_TAG);
    envelope.extend_from_slice(&sealed);
    envelope
}
