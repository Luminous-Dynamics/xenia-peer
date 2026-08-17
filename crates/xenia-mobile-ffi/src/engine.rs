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
//! Scope: TCP transport. `passthrough`/`hdc` are decoded here (pure
//! Rust, portable) into RGBA via `xenia_video`. `h264` is NOT decoded
//! here -- `xenia_video::h264`'s decoder needs `ffmpeg-next`/libx264,
//! which isn't portable to Android -- instead this engine passes the
//! raw Annex-B NAL bytes straight through to the caller
//! (`MobileFrame::is_encoded == true`), for the Android app to feed
//! into its own hardware `android.media.MediaCodec` decoder (Phase 2).

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc, watch};
use tracing::{info, warn};

use xenia_inject::InputEvent;
use xenia_peer_core::frame::{PixelFormat as FramePixelFormat, RawCapabilities, RawRekey};
use xenia_peer_core::handshake::{
    AuthenticatedSessionSurface, PendingSessionSurface, perform_viewer_handshake_with_transcript,
};
use xenia_peer_core::transport::{RecvEnvelope, SendEnvelope, TcpTransport, Transport};
use xenia_peer_core::{
    ClipboardContent, FILE_TRANSFER_CHUNK_SIZE, FileTransferMessage,
    PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST, PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER, RawClipboard,
    persist_received_file,
};
use xenia_peer_core::{
    HandshakeManager, LaneSession, RekeyPolicy, SessionEpochState, derive_negotiated_context_key,
};
use xenia_video::{Decoder, EncodedPacket};

/// Codec choice for the viewer engine. See module doc for how `H264`
/// differs (raw pass-through, not decoded here).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MobileCodec {
    Passthrough,
    Hdc,
    H264,
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

/// One frame ready for the UI layer, either decoded or raw-encoded.
#[derive(Clone)]
pub struct MobileFrame {
    /// Logical frame width. For `is_encoded` frames this is the
    /// *declared* dimension from the wire, not necessarily what the
    /// bitstream's own SPS says (they should always agree, but the
    /// Android-side H.264 decoder learns its real dimensions from the
    /// SPS regardless, same as `xenia_video::h264::H264Decoder` does).
    pub width: u32,
    pub height: u32,
    /// RGBA8 (`width * height * 4` bytes) when `is_encoded` is false;
    /// raw Annex-B H.264 NAL bytes straight off the wire when true
    /// (see module doc). The field name predates H.264 support and
    /// is kept to avoid an FFI/JNI/Kotlin-wide rename for a cosmetic
    /// fix; `is_encoded` is the source of truth for how to interpret it.
    pub rgba: Vec<u8>,
    pub pts_ms: u64,
    pub is_encoded: bool,
}

/// Bounded so a UI that stops polling (backgrounded app) can't leak
/// unbounded memory — oldest frame is dropped once full, matching a
/// "show the latest, not a queued backlog" viewer UX.
const FRAME_QUEUE_CAP: usize = 4;
const _: [(); FRAME_QUEUE_CAP] =
    [(); xenia_peer_core::producer_flow::MOBILE_VIDEO_PRESENTATION_V1.capacity];
/// Bound on buffered viewer-to-host input events (pointer/touch/key) while
/// the network task drains them. V14 applies semantic overflow behavior:
/// motion samples may drop, while state transitions use bounded backpressure.
const INPUT_QUEUE_CAP: usize = 256;
const _: [(); INPUT_QUEUE_CAP] =
    [(); xenia_peer_core::producer_flow::INPUT_STATE_TRANSITION_V1.capacity];
/// Outbound clipboard is latest-value state. `watch` retains one pending
/// value and coalesces intermediate updates while the network sender is busy.
const CLIPBOARD_SLOT_CAP: usize = 1;
const _: [(); CLIPBOARD_SLOT_CAP] =
    [(); xenia_peer_core::producer_flow::MOBILE_CLIPBOARD_OUTBOUND_V1.capacity];
/// Bound on queued file-transfer UI events (offers/progress/done). A UI
/// that stops polling only loses stale progress ticks, not correctness --
/// the underlying transfer state machine doesn't live in this queue.
const FILE_TRANSFER_EVENT_QUEUE_CAP: usize = 64;
const _: [(); FILE_TRANSFER_EVENT_QUEUE_CAP] =
    [(); xenia_peer_core::producer_flow::MOBILE_FILE_TRANSFER_EVENTS_V1.capacity];
/// Bound on queued outgoing "send this file" commands from the UI.
/// Small: sending is a deliberate, rare user action (tap a picker
/// button), not a stream -- and only one outgoing transfer is in
/// flight at a time anyway (mirrors `xenia-viewer`'s `--send-file`,
/// which supports exactly one transfer per run).
const FILE_TRANSFER_CMD_QUEUE_CAP: usize = 2;
const _: [(); FILE_TRANSFER_CMD_QUEUE_CAP] =
    [(); xenia_peer_core::producer_flow::MOBILE_FILE_TRANSFER_COMMAND_V1.capacity];
/// Caps how many incoming transfers can be simultaneously buffered in
/// memory. Lower than the daemon's own `MAX_CONCURRENT_INCOMING_TRANSFERS`
/// (8) since phones have tighter RAM budgets than desktop hosts.
const MAX_CONCURRENT_INCOMING_TRANSFERS: usize = 4;

/// One thing that happened to a file transfer, surfaced to the UI via
/// [`ViewerEngine::poll_file_transfer_event`]. File transfer is
/// symmetric -- either side can send or receive any given
/// `transfer_id` -- so every variant carries `outgoing` to disambiguate
/// which role this side is playing for that transfer.
#[derive(Clone, Debug)]
pub enum FileTransferEvent {
    /// The host offered `name` (`total_bytes` from its `Offer`).
    /// Auto-accepted or auto-rejected based on whether a receive
    /// directory was configured at connect time -- mirrors
    /// `xenia-viewer`'s own no-prompt, flag-driven consent model (see
    /// the project plan: the viewer has no consent UI of its own).
    IncomingOffer {
        transfer_id: u64,
        name: String,
        total_bytes: u64,
        accepted: bool,
        reason: String,
    },
    /// Byte-count progress tick.
    Progress {
        transfer_id: u64,
        name: String,
        done_bytes: u64,
        total_bytes: u64,
        outgoing: bool,
    },
    /// Terminal state: verified+written (incoming) or verified-by-peer
    /// (outgoing), or failed for any reason (`detail` explains).
    Done {
        transfer_id: u64,
        name: String,
        outgoing: bool,
        ok: bool,
        detail: String,
    },
}

/// A transfer this side is sending. Only one at a time, matching
/// `xenia-viewer`'s own `--send-file` semantics (one transfer per
/// run) -- a second `send_file` call while one is in flight is
/// rejected rather than queued.
struct OutgoingTransfer {
    transfer_id: u64,
    name: String,
    data: Vec<u8>,
}

/// A transfer this side is receiving.
struct IncomingTransfer {
    name: String,
    expected_size: u64,
    expected_hash: [u8; 32],
    buffer: Vec<u8>,
}

/// A UI-initiated file-transfer action, delivered to the background
/// session task via [`ViewerEngine::send_file`].
enum FileTransferCommand {
    /// Offer `data` (already read fully into memory by the caller --
    /// e.g. via Android's Storage Access Framework, since arbitrary
    /// user-picked files aren't necessarily reachable by a plain
    /// filesystem path) to the host under `name`.
    SendFile { name: String, data: Vec<u8> },
}

/// Immediate result of trying to enqueue a user-triggered file transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileTransferEnqueueError {
    /// The requested payload exceeds the fixed V1 mobile transfer ceiling.
    FileTooLarge,
    /// The fixed command queue is full. No command was silently discarded.
    QueueFull,
    /// The background session task has ended and no longer accepts commands.
    SessionClosed,
}

/// Reduce a wire-provided filename to a bare basename with no path
/// separators, exactly mirroring `xenia-peer`/`xenia-viewer`'s
/// identically-named helper -- see their doc comments for why (a
/// malicious/buggy peer could otherwise offer `"../../etc/passwd"` and
/// have it joined onto `recv_dir` verbatim).
fn sanitize_transfer_filename(name: &str) -> Option<String> {
    let candidate = std::path::Path::new(name)
        .file_name()?
        .to_str()?
        .to_string();
    if candidate.is_empty() || candidate == "." || candidate == ".." {
        return None;
    }
    Some(candidate)
}

/// Latest host-to-viewer clipboard state. `None` (the field, not this
/// wrapper) means "cleared"; the wrapper itself distinguishes "no
/// update received yet" (nothing to apply to the OS clipboard) from
/// "an update arrived, here it is."
struct Shared {
    state: Mutex<SessionState>,
    frames: Mutex<VecDeque<MobileFrame>>,
    last_error: Mutex<Option<String>>,
    clipboard: Mutex<Option<Option<String>>>,
    file_transfer_events: Mutex<VecDeque<FileTransferEvent>>,
}

/// A live viewer session: owns a background tokio task running
/// connect -> handshake -> receive/decode/send-input, plus channels
/// the caller uses to observe/drive it.
pub struct ViewerEngine {
    shared: Arc<Shared>,
    input_tx: mpsc::Sender<InputEvent>,
    clipboard_tx: watch::Sender<Option<ClipboardContent>>,
    ft_cmd_tx: mpsc::Sender<FileTransferCommand>,
    _task: tokio::task::JoinHandle<()>,
}

impl ViewerEngine {
    /// Connect to `host:port` over TCP and start the background
    /// receive/decode loop. Returns immediately — poll [`Self::state`]
    /// / [`Self::poll_frame`] to observe progress. `rt` must be a
    /// running multi-thread tokio runtime handle (the JNI layer keeps
    /// one alive for the lifetime of the app's native library load).
    ///
    /// `recv_dir`: `None` disables receiving files entirely (every
    /// incoming `Offer` is auto-rejected), mirroring `xenia-viewer`'s
    /// own "no `--recv-file-dir` means disabled" default. `Some(dir)`
    /// must be a real, writable filesystem path -- on Android this is
    /// expected to be an app-private directory (e.g.
    /// `context.getExternalFilesDir(...)`), never an arbitrary
    /// user-chosen location, since incoming files are written via
    /// plain `std::fs::write`, not Storage Access Framework.
    /// `max_file_bytes` caps both directions and is also a hard
    /// in-memory buffering cap (the whole file lives in a `Vec<u8>`
    /// on both ends, exactly like the desktop implementation).
    pub fn connect(
        rt: &tokio::runtime::Handle,
        host_port: String,
        codec: MobileCodec,
        recv_dir: Option<PathBuf>,
        max_file_bytes: u64,
    ) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(SessionState::Connecting),
            frames: Mutex::new(VecDeque::with_capacity(FRAME_QUEUE_CAP)),
            last_error: Mutex::new(None),
            clipboard: Mutex::new(None),
            file_transfer_events: Mutex::new(VecDeque::with_capacity(
                FILE_TRANSFER_EVENT_QUEUE_CAP,
            )),
        });
        // Input uses a bounded event queue; outbound clipboard is state-like
        // and therefore uses a one-value watch slot so stale intermediate
        // clipboard contents cannot accumulate. User-triggered file commands
        // use a small bounded queue whose rejection is surfaced explicitly.
        let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE_CAP);
        let (clipboard_tx, clipboard_rx) = watch::channel(None);
        let (ft_cmd_tx, ft_cmd_rx) = mpsc::channel(FILE_TRANSFER_CMD_QUEUE_CAP);
        let shared_for_task = Arc::clone(&shared);
        let task = rt.spawn(run_session(
            host_port,
            codec,
            shared_for_task,
            input_rx,
            clipboard_rx,
            ft_cmd_rx,
            recv_dir,
            max_file_bytes,
        ));
        Self {
            shared,
            input_tx,
            clipboard_tx,
            ft_cmd_tx,
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

    /// Take the latest host-to-viewer clipboard update, if one has
    /// arrived since the last call. `Some(None)` means "clipboard was
    /// cleared"; `Some(Some(text))` is real text to apply to the OS
    /// clipboard; `None` means nothing new.
    pub fn poll_clipboard(&self) -> Option<Option<String>> {
        self.shared.clipboard.blocking_lock().take()
    }

    /// Send a viewer-to-host clipboard update (`None` = cleared).
    /// Requires the daemon side to be running with `--clipboard
    /// bidirectional` -- a `host-to-viewer`-only daemon will just log
    /// and drop it (mirrors `xenia-viewer`'s own behavior).
    pub fn send_clipboard(&self, text: Option<String>) {
        let content = match text {
            Some(t) => ClipboardContent::Text(t),
            None => ClipboardContent::Cleared,
        };
        self.clipboard_tx.send_replace(Some(content));
    }

    /// Enqueue a state transition with bounded backpressure. Mobile UI APIs are
    /// synchronous, so this may briefly block only when the fixed 256-event
    /// queue is saturated; the network sender itself remains bounded by the
    /// authenticated transport send-stall deadline and eventually closes the
    /// receiver on a dead session rather than allowing unbounded memory growth.
    fn send_stateful_input(&self, event: InputEvent) {
        let _ = self.input_tx.blocking_send(event);
    }

    /// Legacy ambiguous pointer API retained for ABI compatibility. New
    /// callers should use [`Self::send_pointer_move`] or
    /// [`Self::send_pointer_button`] so queue policy can distinguish lossy
    /// motion from state transitions.
    pub fn send_pointer(&self, x: f32, y: f32, button: u8, pressed: bool) {
        let _ = self.input_tx.try_send(InputEvent::Pointer {
            x,
            y,
            button,
            pressed,
        });
    }

    /// Send lossy/coalescible pointer motion with no button-state transition.
    pub fn send_pointer_move(&self, x: f32, y: f32) {
        let _ = self.input_tx.try_send(InputEvent::PointerMove { x, y });
    }

    /// Send a pointer-button state transition. This uses bounded backpressure
    /// rather than `try_send`: silently dropping a release can leave remote
    /// input logically stuck.
    pub fn send_pointer_button(&self, x: f32, y: f32, button: u8, pressed: bool) {
        self.send_stateful_input(InputEvent::PointerButton {
            x,
            y,
            button,
            pressed,
        });
    }

    pub fn send_touch(&self, index: u8, x: f32, y: f32, phase: u8, pressure: f32) {
        let event = InputEvent::Touch {
            index,
            x,
            y,
            phase,
            pressure,
        };
        // Move samples are spatially supersedable. Down/up/cancel establish or
        // clear touch state and therefore use bounded backpressure.
        if phase == 1 {
            let _ = self.input_tx.try_send(event);
        } else {
            self.send_stateful_input(event);
        }
    }

    pub fn send_key(&self, code: u32, pressed: bool, modifiers: u8) {
        self.send_stateful_input(InputEvent::Key {
            code,
            pressed,
            modifiers,
        });
    }

    /// Check whether a file command is worth materializing/copying now.
    ///
    /// This is deliberately an advisory preflight, not a reservation: another
    /// producer can consume queue capacity before the final `try_send`. The
    /// final [`send_file`](Self::send_file) call therefore performs the same
    /// size/session/queue checks again.
    pub fn check_file_transfer_admission(
        &self,
        data_len: usize,
    ) -> Result<(), FileTransferEnqueueError> {
        if data_len > xenia_peer_core::producer_flow::MOBILE_FILE_TRANSFER_MAX_BYTES_V1 {
            return Err(FileTransferEnqueueError::FileTooLarge);
        }
        if self.ft_cmd_tx.is_closed() {
            return Err(FileTransferEnqueueError::SessionClosed);
        }
        if self.ft_cmd_tx.capacity() == 0 {
            return Err(FileTransferEnqueueError::QueueFull);
        }
        Ok(())
    }

    /// Offer `data` to the host under `name`. `data` must already be
    /// fully read into memory by the caller (Android's Storage Access
    /// Framework hands back a `Uri`, not a plain path, so the JNI
    /// layer reads it via `ContentResolver` before calling this).
    /// Only one outgoing transfer is in flight at a time -- calling
    /// this while one is already active surfaces a `Done { ok: false
    /// }` event rather than queuing a second one.
    pub fn send_file(
        &self,
        name: String,
        data: Vec<u8>,
    ) -> Result<(), FileTransferEnqueueError> {
        self.check_file_transfer_admission(data.len())?;
        match self
            .ft_cmd_tx
            .try_send(FileTransferCommand::SendFile { name, data })
        {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(FileTransferEnqueueError::QueueFull),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(FileTransferEnqueueError::SessionClosed)
            }
        }
    }

    /// Pop the oldest queued file-transfer event, if any.
    pub fn poll_file_transfer_event(&self) -> Option<FileTransferEvent> {
        self.shared.file_transfer_events.blocking_lock().pop_front()
    }
}

impl Drop for ViewerEngine {
    fn drop(&mut self) {
        // Dropping a Tokio JoinHandle detaches its task. A disconnected mobile
        // session must instead terminate its network/background work, otherwise
        // a stale task can retain sockets and buffers after the registry id is
        // gone.
        self._task.abort();
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    host_port: String,
    codec: MobileCodec,
    shared: Arc<Shared>,
    input_rx: mpsc::Receiver<InputEvent>,
    clipboard_rx: watch::Receiver<Option<ClipboardContent>>,
    ft_cmd_rx: mpsc::Receiver<FileTransferCommand>,
    recv_dir: Option<PathBuf>,
    max_file_bytes: u64,
) {
    if let Err(err) = run_session_inner(
        host_port,
        codec,
        &shared,
        input_rx,
        clipboard_rx,
        ft_cmd_rx,
        recv_dir,
        max_file_bytes,
    )
    .await
    {
        warn!(error = %err, "viewer session ended with error");
        *shared.last_error.lock().await = Some(err);
        *shared.state.lock().await = SessionState::Error;
    } else {
        *shared.state.lock().await = SessionState::Disconnected;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session_inner(
    host_port: String,
    codec: MobileCodec,
    shared: &Arc<Shared>,
    mut input_rx: mpsc::Receiver<InputEvent>,
    mut clipboard_rx: watch::Receiver<Option<ClipboardContent>>,
    mut ft_cmd_rx: mpsc::Receiver<FileTransferCommand>,
    recv_dir: Option<PathBuf>,
    max_file_bytes: u64,
) -> Result<(), String> {
    info!(peer = %host_port, ?codec, "mobile viewer connecting");

    let mut transport = TcpTransport::connect(&host_port)
        .await
        .map_err(|e| e.to_string())?;

    let mut handshake_mgr = HandshakeManager::new();
    let handshake =
        perform_viewer_handshake_with_transcript(&mut transport, &mut handshake_mgr, "daemon")
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
    let transport_profile = transport.transport_profile();
    let pre_session_profile = transport.pre_session_profile();
    let availability_profile = transport.availability_profile();

    let (send_half, mut recv_half) = transport.split();
    let session = Arc::new(Mutex::new(session));
    let send_half = Arc::new(Mutex::new(send_half));
    let (surface_ready_tx, surface_ready_rx) = watch::channel(false);

    // Outbound input-event sender task: mirrors xenia-viewer's GUI
    // input loop exactly (bincode-serialize -> seal_input_event ->
    // send_envelope).
    {
        let session = Arc::clone(&session);
        let send_half = Arc::clone(&send_half);
        let mut surface_ready = surface_ready_rx.clone();
        tokio::spawn(async move {
            while !*surface_ready.borrow() {
                if surface_ready.changed().await.is_err() {
                    return;
                }
            }
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

    // Outbound clipboard-event sender task: mirrors the input task
    // above, just sealing under seal_clipboard_event instead of
    // seal_input_event (a real OS clipboard change is the trigger,
    // not a captured InputEvent).
    {
        let session = Arc::clone(&session);
        let send_half = Arc::clone(&send_half);
        let mut surface_ready = surface_ready_rx.clone();
        tokio::spawn(async move {
            while !*surface_ready.borrow() {
                if surface_ready.changed().await.is_err() {
                    return;
                }
            }
            loop {
                if clipboard_rx.changed().await.is_err() {
                    return;
                }
                let Some(content) = clipboard_rx.borrow_and_update().clone() else {
                    continue;
                };
                let envelope = {
                    let mut session = session.lock().await;
                    match session.seal_clipboard_event(content) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            warn!(error = %err, "failed to seal captured clipboard update");
                            continue;
                        }
                    }
                };
                if let Err(err) = send_half.lock().await.send_envelope(&envelope).await {
                    info!(error = %err, "mobile clipboard send loop ending (daemon disconnected)");
                    break;
                }
            }
        });
    }

    // No Decoder at all for H264 -- those frames pass through raw
    // (see module doc); building one would need xenia_video's h264
    // feature, which pulls in ffmpeg-next/libx264 and isn't portable
    // to Android.
    let mut decoder: Option<Box<dyn Decoder + Send>> = match codec {
        MobileCodec::Passthrough => {
            Some(Box::new(xenia_video::passthrough::PassthroughDecoder::new()))
        }
        MobileCodec::Hdc => Some(Box::new(xenia_video::hdc::HdcDecoder::new())),
        MobileCodec::H264 => None,
    };
    let expected_frame_fmt = match codec {
        MobileCodec::Passthrough => FramePixelFormat::Passthrough,
        MobileCodec::Hdc => FramePixelFormat::Hdc,
        MobileCodec::H264 => FramePixelFormat::H264,
    };

    let mut pending_surface = Some(
        PendingSessionSurface::new_with_profiles(
            handshake.negotiated_context_hash,
            transport_profile.clone(),
            pre_session_profile,
            availability_profile,
        )
        .map_err(|e| e.to_string())?,
    );
    let mut authenticated_surface: Option<AuthenticatedSessionSurface> = None;
    let mut epoch_state = SessionEpochState::new(handshake.transcript_hash, RekeyPolicy::smoke());

    // File-transfer state, owned exclusively by this loop (unlike
    // input/clipboard, file transfer needs no separate sender task --
    // a `send_file` command and an inbound file-transfer envelope both
    // need access to the same `outgoing`/`incoming` state, so both are
    // handled inline here via `tokio::select!` rather than splitting
    // across tasks that would need their own `Arc<Mutex<...>>` around
    // that state).
    let mut outgoing: Option<OutgoingTransfer> = None;
    let mut incoming: HashMap<u64, IncomingTransfer> = HashMap::new();
    let mut next_transfer_id: u64 = 1;

    loop {
        let envelope = tokio::select! {
            biased;
            Some(cmd) = ft_cmd_rx.recv() => {
                if authenticated_surface.is_none() {
                    warn!("ignoring file-transfer command before authenticated session surface");
                    continue;
                }
                handle_file_transfer_command(
                    cmd,
                    &session,
                    &send_half,
                    shared,
                    &mut outgoing,
                    &mut next_transfer_id,
                )
                .await;
                continue;
            }
            result = recv_half.recv_envelope() => match result {
                Ok(e) => e,
                Err(err) => {
                    info!(error = %err, "daemon disconnected");
                    return Ok(());
                }
            },
        };

        // File-transfer messages are bare envelopes (like input/clipboard
        // reverse-path), not lane-enveloped -- check before `open_frame`,
        // which only understands the lane-envelope shape.
        if matches!(
            xenia_wire::envelope_payload_type(&envelope),
            Some(PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST)
                | Some(PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER)
        ) {
            let _authenticated_surface = authenticated_surface
                .as_ref()
                .ok_or("daemon sent file-transfer payload before sealed capabilities")?;
            let message = {
                let mut session = session.lock().await;
                match session.open_file_transfer_message(&envelope) {
                    Ok(m) => m,
                    Err(err) => {
                        warn!(error = %err, "failed to open file-transfer envelope");
                        continue;
                    }
                }
            };
            handle_file_transfer_message(
                message,
                &session,
                &send_half,
                shared,
                &mut outgoing,
                &mut incoming,
                recv_dir.as_deref(),
                max_file_bytes,
            )
            .await;
            continue;
        }

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

        if raw_frame.pixel_format == FramePixelFormat::Capabilities {
            if authenticated_surface.is_some() {
                return Err("daemon advertised sealed capabilities more than once".into());
            }
            let capabilities =
                RawCapabilities::from_frame(&raw_frame).map_err(|e| e.to_string())?;
            let pending = pending_surface
                .take()
                .ok_or("missing pending session surface before capabilities")?;
            let surface = pending
                .authenticate_capabilities(capabilities)
                .map_err(|e| e.to_string())?;
            let negotiated_context_hash = surface.context_hash();
            let _negotiated_context_key =
                derive_negotiated_context_key(&handshake.key_schedule, &negotiated_context_hash);
            info!(video_format = ?surface.capabilities().video_format, "mobile viewer capabilities accepted");
            authenticated_surface = Some(surface);
            let _ = surface_ready_tx.send(true);
            *shared.state.lock().await = SessionState::Connected;
            continue;
        }
        let _authenticated_surface = authenticated_surface
            .as_ref()
            .ok_or("daemon sent media before sealed session capabilities")?;
        if raw_frame.pixel_format == FramePixelFormat::Telemetry {
            continue;
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
                session
                    .seal_control_frame(&ack)
                    .map_err(|e| e.to_string())?
            };
            send_half
                .lock()
                .await
                .send_envelope(&ack_envelope)
                .await
                .map_err(|e| e.to_string())?;
            info!(
                key_epoch = epoch_state.current_epoch(),
                "mobile viewer session rekeyed"
            );
            continue;
        }
        // Audio is intentionally ignored (out of scope for this
        // engine -- see the project plan's phasing).
        if raw_frame.pixel_format == FramePixelFormat::Audio {
            continue;
        }
        if raw_frame.pixel_format == FramePixelFormat::Clipboard {
            match RawClipboard::from_frame(&raw_frame) {
                Ok(clip) => {
                    let text = match clip.content {
                        ClipboardContent::Text(t) => Some(t),
                        ClipboardContent::Cleared => None,
                    };
                    *shared.clipboard.lock().await = Some(text);
                }
                Err(err) => warn!(error = %err, "failed to decode clipboard frame"),
            }
            continue;
        }
        if raw_frame.pixel_format != expected_frame_fmt {
            warn!(fmt = ?raw_frame.pixel_format, expected = ?expected_frame_fmt, "frame format mismatch");
            continue;
        }

        let Some(decoder) = decoder.as_mut() else {
            // H264: no software decode here (see module doc) -- pass
            // the raw Annex-B bytes straight to the queue for the
            // Android app's own MediaCodec to decode.
            let mut queue = shared.frames.lock().await;
            if queue.len() >= FRAME_QUEUE_CAP {
                queue.pop_front();
            }
            queue.push_back(MobileFrame {
                width: raw_frame.width,
                height: raw_frame.height,
                rgba: raw_frame.pixels,
                pts_ms: raw_frame.timestamp_ms,
                is_encoded: true,
            });
            continue;
        };

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
                is_encoded: false,
            });
        }
    }
}

/// Push a file-transfer event, dropping the oldest queued one if the
/// UI has stopped polling and the bound is reached.
async fn push_ft_event(shared: &Arc<Shared>, event: FileTransferEvent) {
    let mut queue = shared.file_transfer_events.lock().await;
    if queue.len() >= FILE_TRANSFER_EVENT_QUEUE_CAP {
        queue.pop_front();
    }
    queue.push_back(event);
}

/// Seal `message` under the control lane (always `is_host = false` --
/// this engine only ever plays the viewer role) and send it.
async fn seal_and_send<S: SendEnvelope>(
    session: &Arc<Mutex<LaneSession>>,
    send_half: &Arc<Mutex<S>>,
    message: FileTransferMessage,
) -> Result<(), String> {
    let envelope = {
        let mut session = session.lock().await;
        session
            .seal_file_transfer_message(message, false)
            .map_err(|e| e.to_string())?
    };
    send_half
        .lock()
        .await
        .send_envelope(&envelope)
        .await
        .map_err(|e| e.to_string())
}

/// Handle a UI-initiated [`FileTransferCommand`] (currently only
/// `SendFile`): hash + offer the file, then remember it as `outgoing`
/// so a later `Accept` can find the buffered bytes to chunk-send.
async fn handle_file_transfer_command<S: SendEnvelope>(
    cmd: FileTransferCommand,
    session: &Arc<Mutex<LaneSession>>,
    send_half: &Arc<Mutex<S>>,
    shared: &Arc<Shared>,
    outgoing: &mut Option<OutgoingTransfer>,
    next_transfer_id: &mut u64,
) {
    let FileTransferCommand::SendFile { name, data } = cmd;
    if outgoing.is_some() {
        warn!(
            name,
            "send_file while another outgoing transfer is in flight; dropping"
        );
        push_ft_event(
            shared,
            FileTransferEvent::Done {
                transfer_id: 0,
                name,
                outgoing: true,
                ok: false,
                detail: "another outgoing transfer is already in progress".to_string(),
            },
        )
        .await;
        return;
    }

    let transfer_id = *next_transfer_id;
    *next_transfer_id += 1;
    let size = data.len() as u64;
    let blake3_hash = *blake3::hash(&data).as_bytes();
    let offer = FileTransferMessage::Offer {
        transfer_id,
        name: name.clone(),
        size,
        blake3_hash,
    };
    if let Err(err) = seal_and_send(session, send_half, offer).await {
        warn!(error = %err, "failed to send file-transfer offer");
        push_ft_event(
            shared,
            FileTransferEvent::Done {
                transfer_id,
                name,
                outgoing: true,
                ok: false,
                detail: err,
            },
        )
        .await;
        return;
    }
    info!(transfer_id, name, size, "file transfer offered");
    push_ft_event(
        shared,
        FileTransferEvent::Progress {
            transfer_id,
            name: name.clone(),
            done_bytes: 0,
            total_bytes: size,
            outgoing: true,
        },
    )
    .await;
    *outgoing = Some(OutgoingTransfer {
        transfer_id,
        name,
        data,
    });
}

/// Handle one already-opened [`FileTransferMessage`] arriving from the
/// peer. Mirrors `xenia-viewer`'s `handle_file_transfer_message`
/// almost verbatim (same protocol, same no-consent-UI philosophy --
/// see its doc comment) with two adaptations: incoming files are
/// capped at [`MAX_CONCURRENT_INCOMING_TRANSFERS`] (tighter than the
/// daemon's own cap, since phones have less RAM to spare), and every
/// transition is also surfaced as a [`FileTransferEvent`] for the UI.
#[allow(clippy::too_many_arguments)]
async fn handle_file_transfer_message<S: SendEnvelope>(
    message: FileTransferMessage,
    session: &Arc<Mutex<LaneSession>>,
    send_half: &Arc<Mutex<S>>,
    shared: &Arc<Shared>,
    outgoing: &mut Option<OutgoingTransfer>,
    incoming: &mut HashMap<u64, IncomingTransfer>,
    recv_dir: Option<&std::path::Path>,
    max_bytes: u64,
) {
    match message {
        FileTransferMessage::Offer {
            transfer_id,
            name,
            size,
            blake3_hash,
        } => {
            let (safe_name, reason) = match (recv_dir, sanitize_transfer_filename(&name)) {
                (None, _) => (
                    None,
                    "file transfer is disabled on this viewer".to_string(),
                ),
                (Some(_), None) => (None, "unusable filename".to_string()),
                (Some(_), Some(_)) if size > max_bytes => {
                    (None, format!("file exceeds {max_bytes}-byte cap"))
                }
                (Some(_), Some(_)) if incoming.len() >= MAX_CONCURRENT_INCOMING_TRANSFERS => {
                    (None, "too many concurrent incoming transfers".to_string())
                }
                (Some(_), Some(safe_name)) => (Some(safe_name), String::new()),
            };
            let accept = safe_name.is_some();
            if let Some(safe_name) = safe_name {
                incoming.insert(
                    transfer_id,
                    IncomingTransfer {
                        name: safe_name.clone(),
                        expected_size: size,
                        expected_hash: blake3_hash,
                        buffer: Vec::with_capacity(size.min(max_bytes) as usize),
                    },
                );
                info!(
                    transfer_id,
                    name = safe_name,
                    size,
                    "file transfer offer accepted"
                );
                push_ft_event(
                    shared,
                    FileTransferEvent::IncomingOffer {
                        transfer_id,
                        name: safe_name,
                        total_bytes: size,
                        accepted: true,
                        reason: String::new(),
                    },
                )
                .await;
            } else {
                info!(
                    transfer_id,
                    name, size, reason, "file transfer offer rejected"
                );
                push_ft_event(
                    shared,
                    FileTransferEvent::IncomingOffer {
                        transfer_id,
                        name: name.clone(),
                        total_bytes: size,
                        accepted: false,
                        reason: reason.clone(),
                    },
                )
                .await;
            }
            let reply = if accept {
                FileTransferMessage::Accept { transfer_id }
            } else {
                FileTransferMessage::Reject {
                    transfer_id,
                    reason,
                }
            };
            if let Err(err) = seal_and_send(session, send_half, reply).await {
                warn!(error = %err, "failed to reply to file-transfer offer");
            }
        }
        FileTransferMessage::Accept { transfer_id } => {
            let Some(transfer) = outgoing.as_ref().filter(|t| t.transfer_id == transfer_id) else {
                warn!(transfer_id, "Accept for unknown/stale outgoing transfer");
                return;
            };
            let name = transfer.name.clone();
            let data = transfer.data.clone();
            let total = data.len() as u64;
            info!(
                transfer_id,
                bytes = total,
                "transfer accepted, sending chunks"
            );
            for (i, chunk) in data.chunks(FILE_TRANSFER_CHUNK_SIZE).enumerate() {
                let msg = FileTransferMessage::Chunk {
                    transfer_id,
                    offset: (i * FILE_TRANSFER_CHUNK_SIZE) as u64,
                    data: chunk.to_vec(),
                };
                if let Err(err) = seal_and_send(session, send_half, msg).await {
                    warn!(error = %err, "failed to send file-transfer chunk");
                    *outgoing = None;
                    push_ft_event(
                        shared,
                        FileTransferEvent::Done {
                            transfer_id,
                            name,
                            outgoing: true,
                            ok: false,
                            detail: err,
                        },
                    )
                    .await;
                    return;
                }
                let done = ((i + 1) * FILE_TRANSFER_CHUNK_SIZE).min(total as usize) as u64;
                push_ft_event(
                    shared,
                    FileTransferEvent::Progress {
                        transfer_id,
                        name: name.clone(),
                        done_bytes: done,
                        total_bytes: total,
                        outgoing: true,
                    },
                )
                .await;
            }
            if let Err(err) = seal_and_send(
                session,
                send_half,
                FileTransferMessage::Complete { transfer_id },
            )
            .await
            {
                warn!(error = %err, "failed to send file-transfer completion");
            }
            info!(transfer_id, "all chunks sent, awaiting verification");
        }
        FileTransferMessage::Reject {
            transfer_id,
            reason,
        } => {
            if outgoing
                .as_ref()
                .is_some_and(|t| t.transfer_id == transfer_id)
            {
                warn!(transfer_id, reason, "outgoing transfer rejected by peer");
                let Some(transfer) = outgoing.take() else {
                    warn!(transfer_id, "outgoing transfer disappeared before rejection handling");
                    return;
                };
                let name = transfer.name;
                push_ft_event(
                    shared,
                    FileTransferEvent::Done {
                        transfer_id,
                        name,
                        outgoing: true,
                        ok: false,
                        detail: reason,
                    },
                )
                .await;
            }
        }
        FileTransferMessage::Chunk {
            transfer_id,
            offset,
            data,
        } => {
            let Some(transfer) = incoming.get_mut(&transfer_id) else {
                warn!(transfer_id, "chunk for unknown/stale incoming transfer");
                return;
            };
            let off = offset as usize;
            if off.saturating_add(data.len()) > transfer.expected_size as usize {
                warn!(
                    transfer_id,
                    "chunk exceeds offered file size; dropping transfer"
                );
                let Some(dropped) = incoming.remove(&transfer_id) else {
                    warn!(transfer_id, "incoming transfer disappeared during overrun handling");
                    return;
                };
                let name = dropped.name;
                push_ft_event(
                    shared,
                    FileTransferEvent::Done {
                        transfer_id,
                        name,
                        outgoing: false,
                        ok: false,
                        detail: "chunk exceeded the offered file size".to_string(),
                    },
                )
                .await;
                return;
            }
            if transfer.buffer.len() < off + data.len() {
                transfer.buffer.resize(off + data.len(), 0);
            }
            transfer.buffer[off..off + data.len()].copy_from_slice(&data);
            push_ft_event(
                shared,
                FileTransferEvent::Progress {
                    transfer_id,
                    name: transfer.name.clone(),
                    done_bytes: transfer.buffer.len() as u64,
                    total_bytes: transfer.expected_size,
                    outgoing: false,
                },
            )
            .await;
        }
        FileTransferMessage::Complete { transfer_id } => {
            let Some(transfer) = incoming.remove(&transfer_id) else {
                warn!(transfer_id, "Complete for unknown/stale incoming transfer");
                return;
            };
            let actual_hash = *blake3::hash(&transfer.buffer).as_bytes();
            let hash_ok = actual_hash == transfer.expected_hash;
            let mut local_ok = hash_ok;
            let mut detail = String::new();
            if hash_ok {
                match recv_dir {
                    Some(dir) => {
                        let dest = dir.join(&transfer.name);
                        match persist_received_file(&dest, &transfer.buffer) {
                            Ok(()) => info!(
                                transfer_id,
                                path = %dest.display(),
                                bytes = transfer.buffer.len(),
                                "file transfer verified and persisted"
                            ),
                            Err(err) => {
                                warn!(transfer_id, error = %err, "verified file was not persisted");
                                local_ok = false;
                                detail = err.to_string();
                            }
                        }
                    }
                    None => {
                        // Can't actually happen: an Offer only ever
                        // reaches `incoming` (above) when `recv_dir`
                        // is `Some`. Kept as a defensive branch rather
                        // than `unreachable!()` since this is a
                        // cross-message invariant, not a
                        // same-function one.
                        local_ok = false;
                        detail = "no receive directory configured".to_string();
                    }
                }
            } else {
                warn!(
                    transfer_id,
                    "file transfer failed BLAKE3 verification, not written"
                );
                detail = "BLAKE3 verification failed".to_string();
            }
            push_ft_event(
                shared,
                FileTransferEvent::Done {
                    transfer_id,
                    name: transfer.name.clone(),
                    outgoing: false,
                    ok: local_ok,
                    detail,
                },
            )
            .await;
            // `Verified.ok` is a delivery receipt, not merely an integrity
            // bit: the sender may report success only after the receiver both
            // verified the hash and persisted the file locally.
            if let Err(err) = seal_and_send(
                session,
                send_half,
                FileTransferMessage::Verified {
                    transfer_id,
                    ok: local_ok,
                },
            )
            .await
            {
                warn!(error = %err, "failed to send file-transfer verification reply");
            }
        }
        FileTransferMessage::Verified { transfer_id, ok } => {
            if outgoing
                .as_ref()
                .is_some_and(|t| t.transfer_id == transfer_id)
            {
                info!(transfer_id, ok, "outgoing transfer verification result");
                let Some(transfer) = outgoing.take() else {
                    warn!(transfer_id, "outgoing transfer disappeared before verification handling");
                    return;
                };
                let name = transfer.name;
                push_ft_event(
                    shared,
                    FileTransferEvent::Done {
                        transfer_id,
                        name,
                        outgoing: true,
                        ok,
                        detail: String::new(),
                    },
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
const DEFAULT_TEST_MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;

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
        let engine = ViewerEngine::connect(
            rt.handle(),
            "127.0.0.1:1".to_string(),
            MobileCodec::Passthrough,
            None,
            DEFAULT_TEST_MAX_FILE_BYTES,
        );

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
        let engine = ViewerEngine::connect(
            rt.handle(),
            "127.0.0.1:2".to_string(),
            MobileCodec::Hdc,
            None,
            DEFAULT_TEST_MAX_FILE_BYTES,
        );
        assert!(engine.poll_frame().is_none());
        assert!(engine.poll_clipboard().is_none());
        assert!(engine.poll_file_transfer_event().is_none());
    }

    #[test]
    fn send_clipboard_before_any_connection_progress_does_not_panic() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let engine = ViewerEngine::connect(
            rt.handle(),
            "127.0.0.1:3".to_string(),
            MobileCodec::Passthrough,
            None,
            DEFAULT_TEST_MAX_FILE_BYTES,
        );
        // The outbound clipboard task isn't spawned until the handshake
        // completes. The one-value watch slot should retain only the latest
        // state without growing a stale clipboard backlog.
        engine.send_clipboard(Some("hello".to_string()));
        engine.send_clipboard(None);
    }

    #[test]
    fn file_transfer_admission_rejects_oversized_payload_before_queue_state() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let engine = ViewerEngine::connect(
            rt.handle(),
            "127.0.0.1:4".to_string(),
            MobileCodec::Passthrough,
            None,
            DEFAULT_TEST_MAX_FILE_BYTES,
        );
        assert_eq!(
            engine.check_file_transfer_admission(
                xenia_peer_core::producer_flow::MOBILE_FILE_TRANSFER_MAX_BYTES_V1 + 1,
            ),
            Err(FileTransferEnqueueError::FileTooLarge)
        );
    }

    #[test]
    fn send_file_before_any_connection_progress_does_not_panic() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let engine = ViewerEngine::connect(
            rt.handle(),
            "127.0.0.1:4".to_string(),
            MobileCodec::Passthrough,
            None,
            DEFAULT_TEST_MAX_FILE_BYTES,
        );
        // Mirrors `send_clipboard_before_any_connection_progress_does_not_panic`:
        // the file-transfer command isn't drained until the handshake
        // completes -- sending before then must just queue harmlessly.
        let result = engine.send_file("test.txt".to_string(), vec![1, 2, 3]);
        assert!(result.is_ok() || result == Err(FileTransferEnqueueError::SessionClosed));
    }

    #[test]
    fn sanitize_transfer_filename_strips_path_components() {
        assert_eq!(
            sanitize_transfer_filename("report.pdf"),
            Some("report.pdf".to_string())
        );
        assert_eq!(
            sanitize_transfer_filename("/etc/passwd"),
            Some("passwd".to_string())
        );
        assert_eq!(
            sanitize_transfer_filename("../../secret"),
            Some("secret".to_string())
        );
        assert_eq!(
            sanitize_transfer_filename("a/b/c/thing.txt"),
            Some("thing.txt".to_string())
        );
        assert_eq!(sanitize_transfer_filename(""), None);
        assert_eq!(sanitize_transfer_filename("."), None);
        assert_eq!(sanitize_transfer_filename(".."), None);
    }
}
