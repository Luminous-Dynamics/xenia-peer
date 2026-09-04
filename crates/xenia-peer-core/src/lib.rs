// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # xenia-peer-core
//!
//! Core session + transport primitives for `xenia-peer`. **M0 — not
//! usable as a real product yet**: no screen capture, no video encoding,
//! no input injection. What this crate gives you today:
//!
//! - [`RawFrame`] + [`RawInput`] — framing types that carry raw RGBA
//!   pixel data and opaque input bytes.
//! - [`Session`] — a thin wrapper around `xenia_wire::Session` that
//!   tracks framing state (frame ID counter, input sequence counter)
//!   alongside the wire's crypto state.
//! - [`transport::TcpTransport`] — the simplest possible network
//!   transport: length-prefixed sealed envelopes over a
//!   `tokio::net::TcpStream`. Not production — QUIC/Iroh is the
//!   primary transport for M1+.
//!
//! ## What this crate deliberately does NOT do yet
//!
//! - **No screen capture.** A real capture backend (X11 / Wayland /
//!   ScreenCaptureKit / Windows Graphics Capture) lives in
//!   `xenia-capture`, planned for M1.
//! - **No video encoding.** Raw RGBA frames only. Hardware H.264 /
//!   VP9 via `ffmpeg-next` is `xenia-video`, planned for M1.
//! - **No input injection.** Viewer-captured events are shipped but
//!   never actually applied. `xenia-inject` is M2.
//! - **Handshake policy stays in `xenia-handshake`.** This crate composes the
//!   hybrid handshake with transport/session profiles, but it does not own the
//!   cryptographic primitive implementations.
//!
//! ## Relationship to Symthaea's in-tree RDP stack
//!
//! The
//! [Track A viewer plan](https://github.com/Luminous-Dynamics/xenia-wire/blob/main/plans/VIEWER_PLAN.md)
//! originally framed M0 as *extracting* 11 `rdp_*.rs` modules from the
//! Symthaea research monorepo into this crate. That framing treated
//! Symthaea as the source of production-ready code. In practice,
//! `xenia-wire 0.1.0-alpha.3` already owns the load-bearing primitives
//! — AEAD seal/open, replay window, session key lifecycle, consent
//! state machine — so the *actual* cleanest M0 is to write fresh code
//! that depends on `xenia-wire` and treats Symthaea's `rdp_*` modules
//! as reference material rather than copy-paste targets.
//!
//! The result: this crate is small (a few hundred lines) instead of
//! thousands, with a much tighter dependency surface. Symthaea's
//! in-tree work on content classification, HDC tile codecs, and
//! consciousness-gated telemetry remains in Symthaea — this crate
//! stays focused on the MSP product shape.

#![warn(missing_docs)]

pub mod advertisement;
pub mod authenticated_peer_session;
pub mod file_transfer;
pub mod frame;
pub mod handshake;
pub mod m1_session;
pub mod producer_flow;
pub mod receive_reservation;
mod session;
pub mod transfer_source;
pub mod transport;

pub use authenticated_peer_session::{
    AuthenticatedPeerSessionV1, perform_host_handshake_authenticated_peer_session,
};
pub use file_transfer::{
    IncomingFileStageError, IncomingFileStager, cleanup_orphaned_receive_staging,
    persist_received_file,
};
#[cfg(feature = "opus")]
pub use frame::OpusAudioCodec;
pub use frame::{
    AudioCodec, AudioCodecError, AudioJitterBuffer, AudioSampleFormat, ClipboardContent,
    FILE_TRANSFER_CHUNK_SIZE, FileTransferMessage, JitterInsert, JitterStats,
    PAYLOAD_TYPE_CLIPBOARD, PAYLOAD_TYPE_FILE_TRANSFER_FROM_HOST,
    PAYLOAD_TYPE_FILE_TRANSFER_FROM_VIEWER, PixelFormat, RawAudio, RawCapabilities, RawClipboard,
    RawFrame, RawInput, RawPcmAudioCodec, RawRekey, RawTelemetry, SyntheticAudioKind,
    SyntheticAudioSource, TelemetrySample, TelemetryValue,
};
pub use handshake::{RekeyPolicy, SessionEpochState};
pub use m1_session::{
    M1AuditEvent, M1Permission, M1PermissionSet, M1SessionError, M1SessionMachine, M1SessionState,
};
pub use receive_reservation::{
    ReceiveReservation, ReceiveReservationError, ReceiveReservationPool,
};
pub use session::{FrameLane, LaneSession, Session, SessionError, SessionRole};
pub use transfer_source::{TransferChunk, TransferSource, TransferSourceError};
pub use xenia_handshake::{
    HandshakeManager, RekeyEpochContextV1, RekeyReason, derive_negotiated_context_key,
    derive_rekey_epoch_keys,
};

/// Semantic-version string for the xenia-wire crate this server
/// binds against. Exposed so the transport layer can log it on
/// connect and detect mismatches.
pub const XENIA_WIRE_VERSION: &str = "0.2.0-alpha.9";
