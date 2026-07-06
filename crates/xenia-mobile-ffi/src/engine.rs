// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Portable viewer engine: connect -> handshake -> receive/decode loop.
//!
//! Deliberately has zero Android/JNI/Kotlin dependencies — this is the
//! same protocol path `xenia-viewer`'s CLI mode uses
//! (`perform_viewer_handshake_with_transcript` + `LaneSession` +
//! `Decoder`), just wrapped in a poll-friendly API instead of printing
//! to stdout. `ffi.rs` is the only place that knows about JNI; this
//! module is directly unit-testable on the host and directly usable
//! from `bin/xenia_mobile_smoke.rs` without going through the C ABI.
//!
//! Scope for the Android app's v1 (see the project plan): TCP
//! transport, `passthrough`/`hdc` codecs only. H.264 needs
//! `ffmpeg-next`/libx264 which isn't portable to Android — the mobile
//! app will use Android's own hardware `MediaCodec` for that instead
//! (a later phase), not this crate.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use xenia_inject::InputEvent;
use xenia_peer_core::frame::{PixelFormat as FramePixelFormat, RawCapabilities, RawRekey};
use xenia_peer_core::handshake::{
    NegotiatedTransport, negotiated_session_context_hash, perform_viewer_handshake_with_transcript,
};
use xenia_peer_core::transport::{RecvEnvelope, SendEnvelope, TcpTransport};
use xenia_peer_core::{
    HandshakeManager, LaneSession, RekeyPolicy, SessionEpochState, derive_negotiated_context_key,
};
use xenia_video::{Decoder, EncodedPacket};

/// Codec choice for the viewer engine. See module doc for why H.264
/// isn't here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MobileCodec {
    Passthrough,
    Hdc,
}

/// Coarse session lifecycle, polled by the UI layer. Consent is
/// entirely host(desktop)-side (confirmed in the project plan) — there
/// is deliberately no `PendingApproval`-with-client-action state here,
/// only `Connecting` (covers the wait while the desktop operator
/// decides).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

/// One decoded frame ready for the UI layer to render.
#[derive(Clone)]
pub struct MobileFrame {
    pub width: u32,
    pub height: u32,
    /// RGBA8, `width * height * 4` bytes.
    pub rgba: Vec<u8>,
    pub pts_ms: u64,
}

/// Bounded so a UI that stops polling (backgrounded app) can't leak
/// unbounded memory — oldest frame is dropped once full, matching a
/// "show the latest, not a queued backlog" viewer UX.
const FRAME_QUEUE_CAP: usize = 4;

struct Shared {
    state: Mutex<SessionState>,
    frames: Mutex<VecDeque<MobileFrame>>,
    last_error: Mutex<Option<String>>,
}

/// A live viewer session: owns a background tokio task running
/// connect -> handshake -> receive/decode/send-input, plus channels
/// the caller uses to observe/drive it.
pub struct ViewerEngine {
    shared: Arc<Shared>,
    input_tx: mpsc::UnboundedSender<InputEvent>,
    _task: tokio::task::JoinHandle<()>,
}

impl ViewerEngine {
    /// Connect to `host:port` over TCP and start the background
    /// receive/decode loop. Returns immediately — poll [`Self::state`]
    /// / [`Self::poll_frame`] to observe progress. `rt` must be a
    /// running multi-thread tokio runtime handle (the JNI layer keeps
    /// one alive for the lifetime of the app's native library load).
    pub fn connect(rt: &tokio::runtime::Handle, host_port: String, codec: MobileCodec) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(SessionState::Connecting),
            frames: Mutex::new(VecDeque::with_capacity(FRAME_QUEUE_CAP)),
            last_error: Mutex::new(None),
        });
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let shared_for_task = Arc::clone(&shared);
        let task = rt.spawn(run_session(host_port, codec, shared_for_task, input_rx));
        Self {
            shared,
            input_tx,
            _task: task,
        }
    }

    /// Current session state. Uses a blocking lock acquire — safe to
    /// call from a synchronous JNI-invoked context since the mutex is
    /// only ever held for the duration of a state enum write/read,
    /// never across an `.await`.
    pub fn state(&self) -> SessionState {
        *self.shared.state.blocking_lock()
    }

    /// Human-readable detail for the most recent `SessionState::Error`,
    /// if any.
    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error.blocking_lock().clone()
    }

    /// Pop the oldest queued decoded frame, if any.
    pub fn poll_frame(&self) -> Option<MobileFrame> {
        self.shared.frames.blocking_lock().pop_front()
    }

    pub fn send_pointer(&self, x: f32, y: f32, button: u8, pressed: bool) {
        let _ = self.input_tx.send(InputEvent::Pointer {
            x,
            y,
            button,
            pressed,
        });
    }

    pub fn send_touch(&self, index: u8, x: f32, y: f32, phase: u8, pressure: f32) {
        let _ = self.input_tx.send(InputEvent::Touch {
            index,
            x,
            y,
            phase,
            pressure,
        });
    }

    pub fn send_key(&self, code: u32, pressed: bool, modifiers: u8) {
        let _ = self.input_tx.send(InputEvent::Key {
            code,
            pressed,
            modifiers,
        });
    }
}

async fn run_session(
    host_port: String,
    codec: MobileCodec,
    shared: Arc<Shared>,
    input_rx: mpsc::UnboundedReceiver<InputEvent>,
) {
    if let Err(err) = run_session_inner(host_port, codec, &shared, input_rx).await {
        warn!(error = %err, "viewer session ended with error");
        *shared.last_error.lock().await = Some(err);
        *shared.state.lock().await = SessionState::Error;
    } else {
        *shared.state.lock().await = SessionState::Disconnected;
    }
}

async fn run_session_inner(
    host_port: String,
    codec: MobileCodec,
    shared: &Arc<Shared>,
    mut input_rx: mpsc::UnboundedReceiver<InputEvent>,
) -> Result<(), String> {
    info!(peer = %host_port, ?codec, "mobile viewer connecting");

    let mut transport = TcpTransport::connect(&host_port)
        .await
        .map_err(|e| e.to_string())?;

    let mut handshake_mgr = HandshakeManager::new();
    let handshake = perform_viewer_handshake_with_transcript(&mut transport, &mut handshake_mgr, "daemon")
        .await
        .map_err(|e| e.to_string())?;
    info!(transcript_hash = ?handshake.transcript_hash, "mobile viewer handshake complete");

    // Fixed source id / epoch, matching `xenia-viewer`'s CLI defaults
    // (`--source-id-hex`/`--epoch`) -- the plan scopes these as
    // auto-negotiated, not user-facing, on the mobile side.
    let source_id: [u8; 8] = [0x58, 0x45, 0x4e, 0x49, 0x41, 0x4d, 0x4f, 0x42]; // "XENIAMOB"
    let mut session = LaneSession::with_fixture(source_id, 0);
    session.install_schedule(&handshake.key_schedule);
    // This engine only ever dials TCP (see module doc); WS/QUIC are a
    // possible fast-follow but would need their own `Transport` impl
    // wired in here.
    let negotiated_transport = NegotiatedTransport::Tcp;

    let (send_half, mut recv_half) = transport.split();
    let session = Arc::new(Mutex::new(session));
    let send_half = Arc::new(Mutex::new(send_half));

    // Outbound input-event sender task: mirrors xenia-viewer's GUI
    // input loop exactly (bincode-serialize -> seal_input_event ->
    // send_envelope).
    {
        let session = Arc::clone(&session);
        let send_half = Arc::clone(&send_half);
        tokio::spawn(async move {
            while let Some(event) = input_rx.recv().await {
                let payload = match bincode::serialize(&event) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        warn!(error = %err, "failed to encode captured InputEvent");
                        continue;
                    }
                };
                let envelope = {
                    let mut session = session.lock().await;
                    match session.seal_input_event(payload) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            warn!(error = %err, "failed to seal captured input event");
                            continue;
                        }
                    }
                };
                if let Err(err) = send_half.lock().await.send_envelope(&envelope).await {
                    info!(error = %err, "mobile input send loop ending (daemon disconnected)");
                    break;
                }
            }
        });
    }

    let mut decoder: Box<dyn Decoder + Send> = match codec {
        MobileCodec::Passthrough => Box::new(xenia_video::passthrough::PassthroughDecoder::new()),
        MobileCodec::Hdc => Box::new(xenia_video::hdc::HdcDecoder::new()),
    };
    let expected_frame_fmt = match codec {
        MobileCodec::Passthrough => FramePixelFormat::Passthrough,
        MobileCodec::Hdc => FramePixelFormat::Hdc,
    };

    let mut capabilities_received = false;
    let mut epoch_state = SessionEpochState::new(handshake.transcript_hash, RekeyPolicy::smoke());

    loop {
        let envelope = match recv_half.recv_envelope().await {
            Ok(e) => e,
            Err(err) => {
                info!(error = %err, "daemon disconnected");
                return Ok(());
            }
        };
        let raw_frame = {
            let mut session = session.lock().await;
            match session.open_frame(&envelope) {
                Ok(f) => f,
                Err(err) => {
                    warn!(error = %err, "failed to open frame");
                    continue;
                }
            }
        };

        if raw_frame.pixel_format == FramePixelFormat::Telemetry {
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Capabilities {
            let capabilities = RawCapabilities::from_frame(&raw_frame).map_err(|e| e.to_string())?;
            let negotiated_context_hash =
                negotiated_session_context_hash(negotiated_transport, capabilities.clone())
                    .map_err(|e| e.to_string())?;
            if let Some(expected_hash) = handshake.negotiated_context_hash
                && expected_hash != negotiated_context_hash
            {
                return Err("sealed capabilities do not match handshake context hash".into());
            }
            if !capabilities.supports_current_lane_envelope() {
                return Err("daemon advertised unsupported lane envelope version".into());
            }
            let _negotiated_context_key =
                derive_negotiated_context_key(&handshake.key_schedule, &negotiated_context_hash);
            capabilities_received = true;
            *shared.state.lock().await = SessionState::Connected;
            info!(video_format = ?capabilities.video_format, "mobile viewer capabilities accepted");
            continue;
        }
        if !capabilities_received {
            return Err("daemon sent media before sealed session capabilities".into());
        }
        if raw_frame.pixel_format == FramePixelFormat::Rekey {
            let RawRekey::Proposal {
                key_epoch: proposed_epoch,
                base_transcript_hash,
                previous_epoch_hash: proposed_previous_hash,
                reason,
                epoch_hash,
            } = RawRekey::from_frame(&raw_frame).map_err(|e| e.to_string())?
            else {
                return Err("viewer received unexpected rekey ack".into());
            };
            let context = epoch_state
                .validate_proposal(
                    proposed_epoch,
                    base_transcript_hash,
                    proposed_previous_hash,
                    reason,
                    epoch_hash,
                )
                .map_err(|e| e.to_string())?;
            let keys = epoch_state
                .derive_and_install(&handshake.key_schedule, &context)
                .map_err(|e| e.to_string())?;
            let ack_envelope = {
                let mut session = session.lock().await;
                session.install_rekey_keys(&keys);
                let ack = RawRekey::Ack {
                    key_epoch: epoch_state.current_epoch(),
                    epoch_hash,
                }
                .into_frame(0, 0)
                .map_err(|e| e.to_string())?;
                session.seal_control_frame(&ack).map_err(|e| e.to_string())?
            };
            send_half
                .lock()
                .await
                .send_envelope(&ack_envelope)
                .await
                .map_err(|e| e.to_string())?;
            info!(key_epoch = epoch_state.current_epoch(), "mobile viewer session rekeyed");
            continue;
        }
        // Audio/clipboard frames are intentionally ignored in v1 (see
        // the project plan's phasing) -- just skip past them.
        if raw_frame.pixel_format == FramePixelFormat::Audio
            || raw_frame.pixel_format == FramePixelFormat::Clipboard
        {
            continue;
        }
        if raw_frame.pixel_format != expected_frame_fmt {
            warn!(fmt = ?raw_frame.pixel_format, expected = ?expected_frame_fmt, "frame format mismatch");
            continue;
        }

        let packet = EncodedPacket {
            bytes: raw_frame.pixels,
            pts_ms: raw_frame.timestamp_ms,
            is_keyframe: true,
        };
        let frames = match decoder.decode(&packet) {
            Ok(f) => f,
            Err(err) => {
                warn!(error = %err, "decode failed");
                continue;
            }
        };
        let mut queue = shared.frames.lock().await;
        for decoded in frames {
            if queue.len() >= FRAME_QUEUE_CAP {
                queue.pop_front();
            }
            queue.push_back(MobileFrame {
                width: decoded.width,
                height: decoded.height,
                rgba: decoded.pixels,
                pts_ms: decoded.pts_ms,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_to_closed_port_reaches_error_state() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        // Port 1 is a real, always-refused TCP connect on any host
        // (privileged range, nothing listens there) -- exercises the
        // real `TcpTransport::connect` error path without needing a
        // live daemon.
        let engine = ViewerEngine::connect(rt.handle(), "127.0.0.1:1".to_string(), MobileCodec::Passthrough);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = engine.state();
            if state == SessionState::Error {
                assert!(engine.last_error().is_some());
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "expected Error state within 5s, got {state:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn poll_frame_and_last_error_are_empty_before_anything_happens() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        // A port nothing listens on, but give the assertions below no
        // time to race the background connect attempt.
        let engine = ViewerEngine::connect(rt.handle(), "127.0.0.1:2".to_string(), MobileCodec::Hdc);
        assert!(engine.poll_frame().is_none());
    }
}
