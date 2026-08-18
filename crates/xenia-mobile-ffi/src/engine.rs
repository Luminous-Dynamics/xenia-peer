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
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::time::Instant;

use tokio::sync::{Mutex, mpsc, watch};
use tracing::{info, warn};

use xenia_inject::InputEvent;
use xenia_peer_core::frame::{PixelFormat as FramePixelFormat, RawCapabilities, RawRekey};
use xenia_peer_core::handshake::{
    AuthenticatedSessionSurface, PendingSessionSurface, perform_viewer_handshake_with_transcript,
};
use xenia_peer_core::transport::{RecvEnvelope, SendEnvelope, TcpTransport, Transport};
use xenia_peer_core::{
    ClipboardContent, FILE_TRANSFER_CHUNK_SIZE, FileTransferMessage, IncomingFileStager,
    PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST, PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER, RawClipboard,
    cleanup_orphaned_receive_staging,
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
/// Reservation lease before the caller begins materializing/copying a file.
/// A leaked token cannot pin scarce command capacity indefinitely.
const FILE_TRANSFER_RESERVATION_TTL_MS: u64 = 30_000;
/// Once a reservation is *claimed* immediately before a potentially expensive
/// JNI/native copy, its capacity remains reserved for this bounded copy/commit
/// window. Claim is idempotent and does not keep extending the lease, so a
/// malicious caller cannot pin a slot forever by repeatedly claiming it.
const FILE_TRANSFER_COPY_LEASE_MS: u64 = 60_000;
/// Absolute lease for staging a SAF stream into app-private native storage.
/// It is intentionally not extended by each chunk: progress cannot pin a scarce
/// command slot forever. Five minutes is generous for the fixed 100 MiB ceiling
/// while remaining bounded under a stalled/abandoned provider.
const FILE_TRANSFER_STREAM_LEASE_MS: u64 = 5 * 60_000;
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
enum OutgoingTransferSource {
    Memory(Vec<u8>),
    StagedFile { path: PathBuf },
}

impl Drop for OutgoingTransferSource {
    fn drop(&mut self) {
        if let OutgoingTransferSource::StagedFile { path } = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct OutgoingTransfer {
    transfer_id: u64,
    name: String,
    size: u64,
    source: OutgoingTransferSource,
}

/// A transfer this side is receiving.
struct IncomingTransfer {
    name: String,
    expected_size: u64,
    stager: IncomingFileStager,
}

/// A UI-initiated file-transfer action, delivered to the background
/// session task via [`ViewerEngine::send_file`].
enum FileTransferCommand {
    /// Legacy in-memory enqueue retained for ABI compatibility.
    SendFile { name: String, data: Vec<u8> },
    /// Preferred mobile path: SAF bytes have already been staged and hashed
    /// incrementally in app-private storage, so neither Java nor Rust needs a
    /// whole-file heap allocation.
    SendStagedFile {
        name: String,
        path: PathBuf,
        size: u64,
        blake3_hash: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileTransferReservationState {
    Reserved,
    Copying,
}

/// Capacity reserved in the bounded file-command channel before JNI copies a
/// potentially large Java byte array. Dropping this value releases the slot.
struct FileTransferReservation {
    expected_len: usize,
    permit: mpsc::OwnedPermit<FileTransferCommand>,
    state: FileTransferReservationState,
    expires_at: Instant,
}

struct FileTransferStreamUpload {
    name: String,
    path: PathBuf,
    file: std::fs::File,
    hasher: blake3::Hasher,
    written: usize,
    expected_len: Option<usize>,
    permit: mpsc::OwnedPermit<FileTransferCommand>,
    expires_at: Instant,
}

fn remove_staged_upload(stream: FileTransferStreamUpload) {
    let path = stream.path.clone();
    drop(stream);
    let _ = std::fs::remove_file(path);
}

impl FileTransferReservation {
    fn claim(&mut self, data_len: usize, now: Instant) -> Result<(), FileTransferEnqueueError> {
        if data_len != self.expected_len {
            return Err(FileTransferEnqueueError::ReservationSizeMismatch);
        }
        if now >= self.expires_at {
            return Err(FileTransferEnqueueError::InvalidReservation);
        }
        if self.state == FileTransferReservationState::Reserved {
            self.state = FileTransferReservationState::Copying;
            self.expires_at = now + Duration::from_millis(FILE_TRANSFER_COPY_LEASE_MS);
        }
        Ok(())
    }
}

/// Immediate result of trying to enqueue a user-triggered file transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileTransferEnqueueError {
    /// The requested name/metadata is unusable before enqueue.
    InvalidArgument,
    /// The requested payload exceeds the fixed V1 mobile transfer ceiling.
    FileTooLarge,
    /// The fixed command queue is full. No command was silently discarded.
    QueueFull,
    /// The background session task has ended and no longer accepts commands.
    SessionClosed,
    /// Reservation token was unknown, already consumed, or unavailable.
    InvalidReservation,
    /// The committed payload length differs from the reserved byte length.
    ReservationSizeMismatch,
    /// App-private staging I/O failed.
    IoError,
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
/// Point-in-time local evidence for the bounded mobile file-command lane.
/// This is diagnostic state only; it is not authenticated protocol data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileTransferAdmissionSnapshotV1 {
    pub active_reserved: u32,
    pub active_copying: u32,
    pub available_command_slots: u32,
    pub command_capacity: u32,
}

/// V20 superset including disk-backed SAF staging. Bounded/local diagnostic
/// state only; it is not peer-authenticated protocol data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileTransferAdmissionSnapshotV2 {
    pub active_reserved: u32,
    pub active_copying: u32,
    pub active_streaming: u32,
    pub active_stream_bytes: u64,
    pub available_command_slots: u32,
    pub command_capacity: u32,
}

pub struct ViewerEngine {
    shared: Arc<Shared>,
    input_tx: mpsc::Sender<InputEvent>,
    clipboard_tx: watch::Sender<Option<ClipboardContent>>,
    ft_cmd_tx: mpsc::Sender<FileTransferCommand>,
    ft_reservations: Arc<StdMutex<HashMap<u64, FileTransferReservation>>>,
    ft_streams: Arc<StdMutex<HashMap<u64, FileTransferStreamUpload>>>,
    next_ft_reservation: AtomicU64,
    staging_dir: PathBuf,
    runtime: tokio::runtime::Handle,
    _task: tokio::task::JoinHandle<()>,
}

fn spawn_file_transfer_reservation_expiry(
    runtime: &tokio::runtime::Handle,
    reservations: Arc<StdMutex<HashMap<u64, FileTransferReservation>>>,
    token: u64,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        loop {
            let deadline = {
                let Ok(reservations) = reservations.lock() else {
                    return;
                };
                let Some(reservation) = reservations.get(&token) else {
                    return;
                };
                reservation.expires_at
            };

            tokio::time::sleep_until(deadline).await;

            let Ok(mut reservations) = reservations.lock() else {
                return;
            };
            let expired = reservations
                .get(&token)
                .is_some_and(|reservation| Instant::now() >= reservation.expires_at);
            if expired {
                reservations.remove(&token);
                return;
            }
            // A claim may have moved the deadline while this task slept. Loop
            // and sleep until the new absolute deadline; repeated claims cannot
            // extend it indefinitely because `claim()` is idempotent.
        }
    })
}

fn spawn_file_transfer_stream_expiry(
    runtime: &tokio::runtime::Handle,
    streams: Arc<StdMutex<HashMap<u64, FileTransferStreamUpload>>>,
    token: u64,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        let deadline = {
            let Ok(streams) = streams.lock() else {
                return;
            };
            let Some(stream) = streams.get(&token) else {
                return;
            };
            stream.expires_at
        };
        tokio::time::sleep_until(deadline).await;
        let Ok(mut streams) = streams.lock() else {
            return;
        };
        if streams
            .get(&token)
            .is_some_and(|stream| Instant::now() >= stream.expires_at)
            && let Some(stream) = streams.remove(&token)
        {
            remove_staged_upload(stream);
        }
    })
}

fn cleanup_orphaned_outbound_staging(staging_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(staging_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let token = name
            .strip_prefix("upload-")
            .and_then(|rest| rest.strip_suffix(".part"));
        if token.is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit())) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
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
    /// must be a real, writable filesystem path. `staging_dir` is a separate
    /// local pressure sink for preferred outbound SAF streaming; Android passes
    /// an internal no-backup directory so temporary user content is neither
    /// derived from the receive destination nor exposed through external app
    /// storage. `None` retains a process-temp fallback for non-Android callers.
    /// `max_file_bytes` caps incoming transfers. Legacy outbound callers may
    /// still enqueue a whole `Vec<u8>`, while V20's preferred Android path
    /// stages SAF input incrementally to app-private disk and later streams it
    /// to the peer in protocol-sized chunks after Offer acceptance.
    pub fn connect(
        rt: &tokio::runtime::Handle,
        host_port: String,
        codec: MobileCodec,
        recv_dir: Option<PathBuf>,
        staging_dir: Option<PathBuf>,
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
        let staging_dir = staging_dir
            .unwrap_or_else(|| std::env::temp_dir().join("xenia-mobile-outbound-staging"));
        if std::fs::create_dir_all(&staging_dir).is_ok() {
            cleanup_orphaned_outbound_staging(&staging_dir);
        }
        if let Some(recv_dir) = recv_dir.as_deref() {
            match cleanup_orphaned_receive_staging(recv_dir) {
                Ok(removed) if removed > 0 => {
                    info!(removed, dir = %recv_dir.display(), "removed orphaned receive staging files")
                }
                Ok(_) => {}
                Err(err) => warn!(
                    dir = %recv_dir.display(),
                    error = %err,
                    "could not scan receive directory for orphaned staging files"
                ),
            }
        }
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
            ft_reservations: Arc::new(StdMutex::new(HashMap::new())),
            ft_streams: Arc::new(StdMutex::new(HashMap::new())),
            next_ft_reservation: AtomicU64::new(1),
            staging_dir,
            runtime: rt.clone(),
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

    /// Snapshot bounded file-command admission state for local diagnostics.
    /// Expired entries are not counted even if their async reaper has not yet
    /// run; channel capacity remains the source of truth for actual admission.
    pub fn file_transfer_admission_snapshot(&self) -> Option<FileTransferAdmissionSnapshotV1> {
        let reservations = self.ft_reservations.lock().ok()?;
        let now = Instant::now();
        let mut active_reserved = 0_u32;
        let mut active_copying = 0_u32;
        for reservation in reservations.values().filter(|entry| now < entry.expires_at) {
            match reservation.state {
                FileTransferReservationState::Reserved => {
                    active_reserved = active_reserved.saturating_add(1);
                }
                FileTransferReservationState::Copying => {
                    active_copying = active_copying.saturating_add(1);
                }
            }
        }
        Some(FileTransferAdmissionSnapshotV1 {
            active_reserved,
            active_copying,
            available_command_slots: self.ft_cmd_tx.capacity() as u32,
            command_capacity: FILE_TRANSFER_CMD_QUEUE_CAP as u32,
        })
    }

    pub fn file_transfer_admission_snapshot_v2(&self) -> Option<FileTransferAdmissionSnapshotV2> {
        let base = self.file_transfer_admission_snapshot()?;
        let streams = self.ft_streams.lock().ok()?;
        let now = Instant::now();
        let mut active_streaming = 0_u32;
        let mut active_stream_bytes = 0_u64;
        for stream in streams.values().filter(|entry| now < entry.expires_at) {
            active_streaming = active_streaming.saturating_add(1);
            active_stream_bytes = active_stream_bytes.saturating_add(stream.written as u64);
        }
        Some(FileTransferAdmissionSnapshotV2 {
            active_reserved: base.active_reserved,
            active_copying: base.active_copying,
            active_streaming,
            active_stream_bytes,
            available_command_slots: base.available_command_slots,
            command_capacity: base.command_capacity,
        })
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

    /// Reserve one bounded file-command slot before materializing/copying a
    /// potentially large payload. The token is process-local and single-use.
    pub fn reserve_file_transfer(&self, data_len: usize) -> Result<u64, FileTransferEnqueueError> {
        if data_len > xenia_peer_core::producer_flow::MOBILE_FILE_TRANSFER_MAX_BYTES_V1 {
            return Err(FileTransferEnqueueError::FileTooLarge);
        }
        let permit = match self.ft_cmd_tx.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(FileTransferEnqueueError::QueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(FileTransferEnqueueError::SessionClosed);
            }
        };
        let Ok(mut reservations) = self.ft_reservations.lock() else {
            return Err(FileTransferEnqueueError::InvalidReservation);
        };
        loop {
            let token = self.next_ft_reservation.fetch_add(1, Ordering::Relaxed);
            if token == 0 || reservations.contains_key(&token) {
                continue;
            }
            reservations.insert(
                token,
                FileTransferReservation {
                    expected_len: data_len,
                    permit,
                    state: FileTransferReservationState::Reserved,
                    expires_at: Instant::now()
                        + Duration::from_millis(FILE_TRANSFER_RESERVATION_TTL_MS),
                },
            );
            drop(reservations);
            spawn_file_transfer_reservation_expiry(
                &self.runtime,
                Arc::clone(&self.ft_reservations),
                token,
            );
            return Ok(token);
        }
    }

    /// Validate that a live reservation exists for exactly `data_len` bytes
    /// without consuming it. C/JNI boundaries use this before copying payload
    /// bytes; [`Self::send_file_reserved`] still rechecks atomically on consume.
    pub fn check_file_transfer_reservation(
        &self,
        token: u64,
        data_len: usize,
    ) -> Result<(), FileTransferEnqueueError> {
        let mut reservations = self
            .ft_reservations
            .lock()
            .map_err(|_| FileTransferEnqueueError::InvalidReservation)?;
        let Some((expected_len, expires_at)) = reservations
            .get(&token)
            .map(|reservation| (reservation.expected_len, reservation.expires_at))
        else {
            return Err(FileTransferEnqueueError::InvalidReservation);
        };
        if Instant::now() >= expires_at {
            reservations.remove(&token);
            return Err(FileTransferEnqueueError::InvalidReservation);
        }
        if expected_len != data_len {
            return Err(FileTransferEnqueueError::ReservationSizeMismatch);
        }
        Ok(())
    }

    /// Atomically move a live reservation into the bounded copy/commit phase.
    /// The first successful claim extends the original admission TTL into a
    /// separate copy lease; repeated claims are idempotent and do not extend it.
    pub fn claim_file_transfer_reservation(
        &self,
        token: u64,
        data_len: usize,
    ) -> Result<(), FileTransferEnqueueError> {
        let mut reservations = self
            .ft_reservations
            .lock()
            .map_err(|_| FileTransferEnqueueError::InvalidReservation)?;
        let now = Instant::now();
        let expired = reservations
            .get(&token)
            .is_some_and(|reservation| now >= reservation.expires_at);
        if expired {
            reservations.remove(&token);
            return Err(FileTransferEnqueueError::InvalidReservation);
        }
        let reservation = reservations
            .get_mut(&token)
            .ok_or(FileTransferEnqueueError::InvalidReservation)?;
        reservation.claim(data_len, now)
    }

    /// Release an unused reservation and return its channel capacity.
    pub fn cancel_file_transfer_reservation(&self, token: u64) -> bool {
        if token == 0 {
            return false;
        }
        self.ft_reservations
            .lock()
            .ok()
            .and_then(|mut reservations| reservations.remove(&token))
            .is_some()
    }

    /// Commit a file command into a capacity slot reserved before payload copy.
    pub fn send_file_reserved(
        &self,
        token: u64,
        name: String,
        data: Vec<u8>,
    ) -> Result<(), FileTransferEnqueueError> {
        let reservation = self
            .ft_reservations
            .lock()
            .ok()
            .and_then(|mut reservations| reservations.remove(&token))
            .ok_or(FileTransferEnqueueError::InvalidReservation)?;
        if Instant::now() >= reservation.expires_at
            || reservation.state != FileTransferReservationState::Copying
        {
            return Err(FileTransferEnqueueError::InvalidReservation);
        }
        if data.len() != reservation.expected_len {
            return Err(FileTransferEnqueueError::ReservationSizeMismatch);
        }
        reservation
            .permit
            .send(FileTransferCommand::SendFile { name, data });
        Ok(())
    }

    /// Legacy in-memory outbound path. New Android picker code uses the V20
    /// staged stream API so a SAF file is not materialized as a whole-file
    /// Java `ByteArray` plus Rust `Vec<u8>`.
    /// Only one outgoing transfer is in flight at a time -- calling
    /// this while one is already active surfaces a `Done { ok: false
    /// }` event rather than queuing a second one.
    pub fn send_file(&self, name: String, data: Vec<u8>) -> Result<(), FileTransferEnqueueError> {
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

    /// Begin a disk-backed outbound stream. A real file-command channel slot
    /// is reserved before any SAF bytes are copied into native code. `None`
    /// means the provider did not expose a stable length; the fixed mobile
    /// ceiling is still enforced incrementally while chunks are staged.
    pub fn begin_file_transfer_stream(
        &self,
        name: String,
        expected_len: Option<usize>,
    ) -> Result<u64, FileTransferEnqueueError> {
        if expected_len.is_some_and(|len| {
            len > xenia_peer_core::producer_flow::MOBILE_FILE_TRANSFER_MAX_BYTES_V1
        }) {
            return Err(FileTransferEnqueueError::FileTooLarge);
        }
        if self.ft_cmd_tx.is_closed() {
            return Err(FileTransferEnqueueError::SessionClosed);
        }
        let safe_name =
            sanitize_transfer_filename(&name).ok_or(FileTransferEnqueueError::InvalidArgument)?;
        let permit = match self.ft_cmd_tx.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(FileTransferEnqueueError::QueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(FileTransferEnqueueError::SessionClosed);
            }
        };
        std::fs::create_dir_all(&self.staging_dir)
            .map_err(|_| FileTransferEnqueueError::IoError)?;
        let mut streams = self
            .ft_streams
            .lock()
            .map_err(|_| FileTransferEnqueueError::InvalidReservation)?;
        loop {
            let token = self.next_ft_reservation.fetch_add(1, Ordering::Relaxed);
            if token == 0
                || streams.contains_key(&token)
                || self
                    .ft_reservations
                    .lock()
                    .ok()
                    .is_some_and(|reservations| reservations.contains_key(&token))
            {
                continue;
            }
            let path = self.staging_dir.join(format!("upload-{token:016x}.part"));
            let file = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(FileTransferEnqueueError::IoError),
            };
            streams.insert(
                token,
                FileTransferStreamUpload {
                    name: safe_name,
                    path,
                    file,
                    hasher: blake3::Hasher::new(),
                    written: 0,
                    expected_len,
                    permit,
                    expires_at: Instant::now()
                        + Duration::from_millis(FILE_TRANSFER_STREAM_LEASE_MS),
                },
            );
            drop(streams);
            spawn_file_transfer_stream_expiry(&self.runtime, Arc::clone(&self.ft_streams), token);
            return Ok(token);
        }
    }

    /// Append one bounded SAF chunk to a native staging file. Chunks are
    /// hashed as they arrive; no whole-file Rust allocation is created.
    pub fn append_file_transfer_stream(
        &self,
        token: u64,
        bytes: &[u8],
    ) -> Result<(), FileTransferEnqueueError> {
        let mut streams = self
            .ft_streams
            .lock()
            .map_err(|_| FileTransferEnqueueError::InvalidReservation)?;
        let expired = streams
            .get(&token)
            .is_some_and(|stream| Instant::now() >= stream.expires_at);
        if expired {
            if let Some(stream) = streams.remove(&token) {
                remove_staged_upload(stream);
            }
            return Err(FileTransferEnqueueError::InvalidReservation);
        }
        let stream = streams
            .get_mut(&token)
            .ok_or(FileTransferEnqueueError::InvalidReservation)?;
        let new_len = stream
            .written
            .checked_add(bytes.len())
            .ok_or(FileTransferEnqueueError::FileTooLarge)?;
        if new_len > xenia_peer_core::producer_flow::MOBILE_FILE_TRANSFER_MAX_BYTES_V1 {
            return Err(FileTransferEnqueueError::FileTooLarge);
        }
        if stream
            .expected_len
            .is_some_and(|expected| new_len > expected)
        {
            return Err(FileTransferEnqueueError::ReservationSizeMismatch);
        }
        stream
            .file
            .write_all(bytes)
            .map_err(|_| FileTransferEnqueueError::IoError)?;
        stream.hasher.update(bytes);
        stream.written = new_len;
        Ok(())
    }

    /// Finish staging and consume the reserved command slot. The background
    /// session later reads the app-private file in protocol-sized chunks only
    /// after the peer accepts the authenticated whole-file hash/size offer.
    pub fn finish_file_transfer_stream(&self, token: u64) -> Result<(), FileTransferEnqueueError> {
        let mut stream = self
            .ft_streams
            .lock()
            .ok()
            .and_then(|mut streams| streams.remove(&token))
            .ok_or(FileTransferEnqueueError::InvalidReservation)?;
        if Instant::now() >= stream.expires_at {
            remove_staged_upload(stream);
            return Err(FileTransferEnqueueError::InvalidReservation);
        }
        if stream
            .expected_len
            .is_some_and(|expected| expected != stream.written)
        {
            remove_staged_upload(stream);
            return Err(FileTransferEnqueueError::ReservationSizeMismatch);
        }
        if stream.file.flush().is_err() {
            remove_staged_upload(stream);
            return Err(FileTransferEnqueueError::IoError);
        }
        let hash = *stream.hasher.finalize().as_bytes();
        let path = stream.path;
        let name = stream.name;
        let size = stream.written as u64;
        let permit = stream.permit;
        permit.send(FileTransferCommand::SendStagedFile {
            name,
            path,
            size,
            blake3_hash: hash,
        });
        Ok(())
    }

    /// Cancel a staged stream and return its queue permit; dropping the stream
    /// also removes its app-private partial file.
    pub fn cancel_file_transfer_stream(&self, token: u64) -> bool {
        if token == 0 {
            return false;
        }
        let removed = self
            .ft_streams
            .lock()
            .ok()
            .and_then(|mut streams| streams.remove(&token));
        if let Some(stream) = removed {
            remove_staged_upload(stream);
            true
        } else {
            false
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
        // gone. Outstanding pre-copy file reservations are also released
        // immediately rather than waiting for their short lease to expire.
        self._task.abort();
        if let Ok(mut reservations) = self.ft_reservations.lock() {
            reservations.clear();
        }
        if let Ok(mut streams) = self.ft_streams.lock() {
            for (_, stream) in streams.drain() {
                remove_staged_upload(stream);
            }
        }
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
            Some(cmd) = ft_cmd_rx.recv(), if can_activate_file_transfer_command(
                authenticated_surface.is_some(),
                outgoing.is_some(),
            ) => {
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

/// A staged/mobile file command is expensive producer work. Keep it in the
/// bounded MPSC lane until it can actually become the one active outgoing
/// transfer. This prevents pre-authentication or already-busy consumers from
/// dequeuing and discarding a fully staged file.
fn can_activate_file_transfer_command(authenticated: bool, outgoing_active: bool) -> bool {
    authenticated && !outgoing_active
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
    // Unpack first so the defensive busy path owns the staged source. If this
    // function is ever called while busy despite the select guard above,
    // dropping `source` also removes a staged file rather than leaking it.
    let (name, size, blake3_hash, source) = match cmd {
        FileTransferCommand::SendFile { name, data } => {
            let size = data.len() as u64;
            let hash = *blake3::hash(&data).as_bytes();
            (name, size, hash, OutgoingTransferSource::Memory(data))
        }
        FileTransferCommand::SendStagedFile {
            name,
            path,
            size,
            blake3_hash,
        } => (
            name,
            size,
            blake3_hash,
            OutgoingTransferSource::StagedFile { path },
        ),
    };
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
        // `source` drops here. Disk-backed sources remove their staging file.
        return;
    }

    let transfer_id = *next_transfer_id;
    *next_transfer_id += 1;
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
        size,
        source,
    });
}

async fn send_outgoing_transfer_chunks<S: SendEnvelope>(
    transfer: &OutgoingTransfer,
    session: &Arc<Mutex<LaneSession>>,
    send_half: &Arc<Mutex<S>>,
    shared: &Arc<Shared>,
) -> Result<(), String> {
    let transfer_id = transfer.transfer_id;
    let name = transfer.name.clone();
    let total = transfer.size;
    let mut offset = 0_u64;
    match &transfer.source {
        OutgoingTransferSource::Memory(data) => {
            for chunk in data.chunks(FILE_TRANSFER_CHUNK_SIZE) {
                let msg = FileTransferMessage::Chunk {
                    transfer_id,
                    offset,
                    data: chunk.to_vec(),
                };
                seal_and_send(session, send_half, msg).await?;
                offset = offset.saturating_add(chunk.len() as u64);
                push_ft_event(
                    shared,
                    FileTransferEvent::Progress {
                        transfer_id,
                        name: name.clone(),
                        done_bytes: offset,
                        total_bytes: total,
                        outgoing: true,
                    },
                )
                .await;
            }
        }
        OutgoingTransferSource::StagedFile { path } => {
            use tokio::io::AsyncReadExt;
            let mut file = tokio::fs::File::open(path)
                .await
                .map_err(|e| format!("open staged file: {e}"))?;
            let mut buffer = vec![0_u8; FILE_TRANSFER_CHUNK_SIZE];
            loop {
                let read = file
                    .read(&mut buffer)
                    .await
                    .map_err(|e| format!("read staged file: {e}"))?;
                if read == 0 {
                    break;
                }
                let msg = FileTransferMessage::Chunk {
                    transfer_id,
                    offset,
                    data: buffer[..read].to_vec(),
                };
                seal_and_send(session, send_half, msg).await?;
                offset = offset.saturating_add(read as u64);
                push_ft_event(
                    shared,
                    FileTransferEvent::Progress {
                        transfer_id,
                        name: name.clone(),
                        done_bytes: offset,
                        total_bytes: total,
                        outgoing: true,
                    },
                )
                .await;
            }
        }
    }
    if offset != total {
        return Err(format!(
            "outgoing source length changed after offer: expected {total}, read {offset}"
        ));
    }
    Ok(())
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
            let (staging_candidate, mut reason) =
                match (recv_dir, sanitize_transfer_filename(&name)) {
                    (None, _) => (None, "file transfer is disabled on this viewer".to_string()),
                    (Some(_), None) => (None, "unusable filename".to_string()),
                    (Some(_), Some(_)) if size > max_bytes => {
                        (None, format!("file exceeds {max_bytes}-byte cap"))
                    }
                    (Some(_), Some(_)) if incoming.len() >= MAX_CONCURRENT_INCOMING_TRANSFERS => {
                        (None, "too many concurrent incoming transfers".to_string())
                    }
                    (Some(recv_dir), Some(safe_name)) => {
                        (Some((recv_dir, safe_name)), String::new())
                    }
                };
            let staged = staging_candidate.and_then(|(recv_dir, safe_name)| {
                let dest = recv_dir.join(&safe_name);
                match IncomingFileStager::create(&dest, size, blake3_hash) {
                    Ok(stager) => Some((safe_name, stager)),
                    Err(err) => {
                        warn!(transfer_id, error = %err, "file receive staging could not be created");
                        reason = "receiver could not allocate private staging".to_string();
                        None
                    }
                }
            });
            let accept = staged.is_some();
            if let Some((safe_name, stager)) = staged {
                incoming.insert(
                    transfer_id,
                    IncomingTransfer {
                        name: safe_name.clone(),
                        expected_size: size,
                        stager,
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
            let total = transfer.size;
            info!(
                transfer_id,
                bytes = total,
                "transfer accepted, sending chunks"
            );
            let send_result =
                send_outgoing_transfer_chunks(transfer, session, send_half, shared).await;
            if let Err(err) = send_result {
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
                    warn!(
                        transfer_id,
                        "outgoing transfer disappeared before rejection handling"
                    );
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
            let name = transfer.name.clone();
            let total_bytes = transfer.expected_size;
            let staged_bytes = match transfer.stager.append(offset, &data) {
                Ok(staged_bytes) => staged_bytes,
                Err(err) => {
                    warn!(transfer_id, error = %err, "invalid incoming file chunk; dropping transfer");
                    incoming.remove(&transfer_id);
                    push_ft_event(
                        shared,
                        FileTransferEvent::Done {
                            transfer_id,
                            name,
                            outgoing: false,
                            ok: false,
                            detail: err.to_string(),
                        },
                    )
                    .await;
                    return;
                }
            };
            push_ft_event(
                shared,
                FileTransferEvent::Progress {
                    transfer_id,
                    name,
                    done_bytes: staged_bytes,
                    total_bytes,
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
            let name = transfer.name;
            let expected_size = transfer.expected_size;
            let finish = transfer.stager.finish();
            let local_ok = finish.is_ok();
            let detail = match &finish {
                Ok(()) => {
                    info!(
                        transfer_id,
                        name,
                        bytes = expected_size,
                        "file transfer verified and persisted"
                    );
                    String::new()
                }
                Err(err) => {
                    warn!(transfer_id, error = %err, "incoming file verification/publication failed");
                    err.to_string()
                }
            };
            push_ft_event(
                shared,
                FileTransferEvent::Done {
                    transfer_id,
                    name,
                    outgoing: false,
                    ok: local_ok,
                    detail,
                },
            )
            .await;
            // Match desktop receiver semantics: Verified(true) means integrity
            // verification and final no-clobber publication both succeeded.
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
                    warn!(
                        transfer_id,
                        "outgoing transfer disappeared before verification handling"
                    );
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
    fn owned_file_command_permit_holds_capacity_until_used_or_dropped() {
        let (tx, mut rx) = mpsc::channel::<FileTransferCommand>(1);
        let permit = tx.clone().try_reserve_owned().expect("reserve one slot");
        assert!(matches!(
            tx.try_send(FileTransferCommand::SendFile {
                name: "other.txt".to_string(),
                data: vec![9],
            }),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        drop(permit);
        tx.try_send(FileTransferCommand::SendFile {
            name: "after-cancel.txt".to_string(),
            data: vec![1],
        })
        .expect("dropping reservation returns capacity");
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn file_reservation_claim_extends_once_and_binds_length() {
        let (tx, _rx) = mpsc::channel::<FileTransferCommand>(1);
        let permit = tx.clone().try_reserve_owned().expect("reserve one slot");
        let now = Instant::now();
        let original_expiry = now + Duration::from_millis(10);
        let mut reservation = FileTransferReservation {
            expected_len: 8,
            permit,
            state: FileTransferReservationState::Reserved,
            expires_at: original_expiry,
        };

        reservation.claim(8, now).expect("first claim");
        let copy_expiry = reservation.expires_at;
        assert_eq!(reservation.state, FileTransferReservationState::Copying);
        assert!(copy_expiry > original_expiry);

        reservation
            .claim(8, now + Duration::from_millis(1))
            .expect("idempotent repeated claim");
        assert_eq!(
            reservation.expires_at, copy_expiry,
            "repeat claim must not extend lease"
        );
        assert_eq!(
            reservation.claim(9, now + Duration::from_millis(2)),
            Err(FileTransferEnqueueError::ReservationSizeMismatch)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reservation_expiry_tracks_claimed_copy_lease_and_restores_capacity() {
        let (tx, _rx) = mpsc::channel::<FileTransferCommand>(1);
        let permit = tx.clone().try_reserve_owned().expect("reserve one slot");
        let reservations = Arc::new(StdMutex::new(HashMap::new()));
        let token = 41_u64;
        let now = Instant::now();
        reservations.lock().unwrap().insert(
            token,
            FileTransferReservation {
                expected_len: 8,
                permit,
                state: FileTransferReservationState::Reserved,
                expires_at: now + Duration::from_millis(FILE_TRANSFER_RESERVATION_TTL_MS),
            },
        );
        let expiry_task = spawn_file_transfer_reservation_expiry(
            &tokio::runtime::Handle::current(),
            Arc::clone(&reservations),
            token,
        );
        tokio::task::yield_now().await;
        assert_eq!(tx.capacity(), 0, "reservation must hold the only slot");

        tokio::time::advance(Duration::from_millis(FILE_TRANSFER_RESERVATION_TTL_MS - 1)).await;
        reservations
            .lock()
            .unwrap()
            .get_mut(&token)
            .expect("live reservation before admission expiry")
            .claim(8, Instant::now())
            .expect("claim just before admission expiry");
        let copy_expiry = reservations.lock().unwrap()[&token].expires_at;

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(
            reservations.lock().unwrap().contains_key(&token),
            "original admission deadline must not reap a claimed copy lease"
        );

        let remaining = copy_expiry.saturating_duration_since(Instant::now());
        assert!(remaining > Duration::from_millis(1));
        tokio::time::advance(remaining - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(reservations.lock().unwrap().contains_key(&token));

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(reservations.lock().unwrap().get(&token).is_none());
        assert_eq!(tx.capacity(), 1, "expiry must return channel capacity");
        expiry_task.await.expect("expiry worker exits cleanly");
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_claim_does_not_extend_copy_lease_under_paused_time() {
        let (tx, _rx) = mpsc::channel::<FileTransferCommand>(1);
        let permit = tx.clone().try_reserve_owned().expect("reserve one slot");
        let now = Instant::now();
        let mut reservation = FileTransferReservation {
            expected_len: 4,
            permit,
            state: FileTransferReservationState::Reserved,
            expires_at: now + Duration::from_secs(1),
        };
        reservation.claim(4, now).expect("first claim");
        let first_copy_expiry = reservation.expires_at;
        tokio::time::advance(Duration::from_secs(10)).await;
        reservation
            .claim(4, Instant::now())
            .expect("repeat claim while copy lease is live");
        assert_eq!(reservation.expires_at, first_copy_expiry);
    }

    #[tokio::test(start_paused = true)]
    async fn staged_stream_expiry_removes_partial_file_and_restores_capacity() {
        let (tx, _rx) = mpsc::channel::<FileTransferCommand>(1);
        let permit = tx.clone().try_reserve_owned().expect("reserve one slot");
        let token = 0x20_u64;
        let path = std::env::temp_dir().join(format!(
            "xenia-v20-stream-expiry-{}-{token}.part",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create staged test file");
        file.write_all(b"partial").expect("stage partial bytes");

        let streams = Arc::new(StdMutex::new(HashMap::new()));
        streams.lock().unwrap().insert(
            token,
            FileTransferStreamUpload {
                name: "partial.bin".into(),
                path: path.clone(),
                file,
                hasher: blake3::Hasher::new(),
                written: 7,
                expected_len: None,
                permit,
                expires_at: Instant::now() + Duration::from_millis(FILE_TRANSFER_STREAM_LEASE_MS),
            },
        );
        let expiry_task = spawn_file_transfer_stream_expiry(
            &tokio::runtime::Handle::current(),
            Arc::clone(&streams),
            token,
        );
        tokio::task::yield_now().await;
        assert_eq!(tx.capacity(), 0);
        assert!(path.exists());

        tokio::time::advance(Duration::from_millis(FILE_TRANSFER_STREAM_LEASE_MS)).await;
        tokio::task::yield_now().await;
        assert!(streams.lock().unwrap().is_empty());
        assert!(
            !path.exists(),
            "expiry must delete the partial staging file"
        );
        assert_eq!(tx.capacity(), 1, "expiry must return command capacity");
        expiry_task
            .await
            .expect("stream expiry worker exits cleanly");
    }

    #[test]
    fn file_reservation_claim_rejects_expired_token() {
        let (tx, _rx) = mpsc::channel::<FileTransferCommand>(1);
        let permit = tx.clone().try_reserve_owned().expect("reserve one slot");
        let now = Instant::now();
        let mut reservation = FileTransferReservation {
            expected_len: 1,
            permit,
            state: FileTransferReservationState::Reserved,
            expires_at: now,
        };
        assert_eq!(
            reservation.claim(1, now),
            Err(FileTransferEnqueueError::InvalidReservation)
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
    fn orphan_cleanup_only_removes_owned_upload_part_names() {
        let root = std::env::temp_dir().join(format!(
            "xenia-v20-staging-cleanup-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let owned = root.join("upload-0123456789abcdef.part");
        let malformed = root.join("upload-not-a-token.part");
        let unrelated = root.join("notes.part");
        std::fs::write(&owned, b"stale").unwrap();
        std::fs::write(&malformed, b"keep").unwrap();
        std::fs::write(&unrelated, b"keep").unwrap();

        cleanup_orphaned_outbound_staging(&root);

        assert!(!owned.exists());
        assert!(malformed.exists());
        assert!(unrelated.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_command_activation_requires_authentication_and_an_idle_sender() {
        assert!(!can_activate_file_transfer_command(false, false));
        assert!(!can_activate_file_transfer_command(false, true));
        assert!(!can_activate_file_transfer_command(true, true));
        assert!(can_activate_file_transfer_command(true, false));
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
