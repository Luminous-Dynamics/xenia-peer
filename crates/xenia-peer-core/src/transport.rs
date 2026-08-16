// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Transport abstractions for M0.
//!
//! Defines a minimal [`Transport`] trait and one implementation:
//! [`TcpTransport`], which ships length-prefixed sealed envelopes
//! over a single `tokio::net::TcpStream`.
//!
//! **TCP is a deliberately boring choice for M0.** It's not the
//! production transport — that's QUIC (via `iroh` or `quinn`) and
//! WebSocket (for browsers), both planned as separate crates
//! (`xenia-transport-quic`, `xenia-transport-ws`). TCP is here
//! because it's the smallest thing that can exercise the full
//! xenia-wire seal/open path through a real network syscall, which
//! is what M0's exit criterion requires.

use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};


/// Maximum encoded handshake message accepted before deserialization. The
/// current ML-KEM-768 + Ed25519 + ML-DSA-65 exchange is well below this.
pub const MAX_HANDSHAKE_ENVELOPE_BYTES: u32 = 16 * 1024;

/// Stable schema label for the transport profile committed into the
/// authenticated session context.
pub const TRANSPORT_PROFILE_SCHEMA: &str = "xenia-transport-profile-v1";

/// Stable Xenia-over-TCP protocol identifier for the current framing.
pub const TCP_PROTOCOL_ID: &str = "xenia/transport/tcp/0";
/// Stable Xenia-over-WebSocket protocol identifier for the current framing.
pub const WEBSOCKET_PROTOCOL_ID: &str = "xenia/transport/websocket/1";
/// Stable Xenia-over-QUIC protocol identifier. This intentionally matches
/// the QUIC ALPN used by `xenia-transport-quic`.
pub const QUIC_PROTOCOL_ID: &str = "xenia/transport/quic/0";

/// The concrete carrier used for a Xenia session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportKind {
    /// Raw TCP byte stream.
    Tcp,
    /// Binary WebSocket messages.
    WebSocket,
    /// One ordered Iroh QUIC bidirectional stream.
    Quic,
}

/// Envelope-boundary semantics exposed by a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeFramingV1 {
    /// Four-byte big-endian length prefix followed by exactly one envelope.
    U32BeLengthPrefix,
    /// Exactly one Xenia envelope per binary WebSocket message.
    WebSocketBinaryMessage,
}

/// Canonical Layer-4/5 transport contract authenticated by the Xenia
/// handshake. The profile intentionally describes *semantics*, not socket
/// addresses or ephemeral connection identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportProfileV1 {
    /// Stable profile schema.
    pub schema: String,
    /// Concrete carrier.
    pub kind: TransportKind,
    /// Stable Xenia protocol identifier for the carrier profile.
    pub protocol_id: String,
    /// Protocol revision within `protocol_id`. Current deployed profiles are 0.
    pub protocol_version: u16,
    /// How sealed envelope boundaries are preserved.
    pub framing: EnvelopeFramingV1,
    /// Hard transport envelope ceiling.
    pub max_envelope_bytes: u32,
    /// Smaller unauthenticated handshake parser ceiling.
    pub max_handshake_envelope_bytes: u32,
    /// Whether the carrier preserves reliable delivery while connected.
    pub reliable: bool,
    /// Whether the carrier preserves envelope order on the Xenia logical stream.
    pub ordered: bool,
    /// Number of logical Xenia envelope streams used by the current profile.
    /// The current TCP, WebSocket, and QUIC profiles all intentionally expose
    /// one ordered stream to the session layer.
    pub logical_streams: u16,
}

impl TransportProfileV1 {
    /// Return Xenia's current exact transport profile for `kind`.
    pub fn current(kind: TransportKind) -> Self {
        let (protocol_id, framing) = match kind {
            TransportKind::Tcp => (TCP_PROTOCOL_ID, EnvelopeFramingV1::U32BeLengthPrefix),
            TransportKind::WebSocket => (
                WEBSOCKET_PROTOCOL_ID,
                EnvelopeFramingV1::WebSocketBinaryMessage,
            ),
            TransportKind::Quic => (QUIC_PROTOCOL_ID, EnvelopeFramingV1::U32BeLengthPrefix),
        };
        let protocol_version = match kind {
            TransportKind::WebSocket => 1,
            TransportKind::Tcp | TransportKind::Quic => 0,
        };
        Self {
            schema: TRANSPORT_PROFILE_SCHEMA.to_string(),
            kind,
            protocol_id: protocol_id.to_string(),
            protocol_version,
            framing,
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            max_handshake_envelope_bytes: MAX_HANDSHAKE_ENVELOPE_BYTES,
            reliable: true,
            ordered: true,
            logical_streams: 1,
        }
    }

    /// Canonical bincode-v1 representation used only as input to authenticated
    /// transcript/context hashing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// BLAKE3-256 digest of the canonical transport profile.
    pub fn profile_hash(&self) -> Result<[u8; 32], bincode::Error> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }

    /// Return true only for an exact currently-supported profile. This is a
    /// fail-closed downgrade/ambiguity check: changing framing, limits, stream
    /// semantics, or the protocol identifier requires a new explicit profile.
    pub fn is_current_supported_profile(&self) -> bool {
        self == &Self::current(self.kind)
    }
}

/// Maximum envelope size this transport will accept. Guards against
/// a malicious peer sending a length prefix that would cause the
/// receiver to allocate gigabytes. 16 MiB covers any realistic
/// frame — a 4K RGBA frame is ~33 MiB, so this is actually tight
/// for uncompressed; real deployments using encoded frames (H.264
/// I-frames ~1-2 MiB) are well under.
pub const MAX_ENVELOPE_BYTES: u32 = 16 * 1024 * 1024;

/// Transport-level errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Network I/O failure (connection reset, read timeout, etc.).
    #[error("transport I/O: {0}")]
    Io(#[from] io::Error),

    /// Peer sent a length prefix larger than [`MAX_ENVELOPE_BYTES`].
    #[error("transport: envelope too large ({0} bytes > {MAX_ENVELOPE_BYTES} byte limit)")]
    EnvelopeTooLarge(u32),

    /// Peer closed the connection mid-envelope.
    #[error("transport: connection closed mid-envelope")]
    UnexpectedEof,
}

/// A bidirectional, best-effort-reliable channel for sealed envelope
/// bytes. Implementations MUST preserve envelope boundaries — the
/// caller passes a complete `Vec<u8>` to `send_envelope` and expects
/// to receive a complete `Vec<u8>` back from `recv_envelope`.
///
/// The trait is deliberately async and takes `&mut self` so
/// implementations can back-pressure on the send side without
/// interior mutability. For concurrent send + recv from two different
/// tasks (e.g. an inbound `RawInput` receive loop running alongside
/// the outbound video/audio/telemetry send loop), split into
/// [`SendEnvelope`] / [`RecvEnvelope`] halves — see `TcpTransport::split`
/// and the equivalent `split` on `WsTransport` (`xenia-transport-ws`)
/// and `QuicTransport` (`xenia-transport-quic`).
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Exact Layer-4/5 transport profile whose semantics are bound into the
    /// authenticated session context. Implementations must return the profile
    /// that actually describes the connection they carry.
    fn transport_profile(&self) -> TransportProfileV1;

    /// Send a single sealed envelope.
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// Receive a single sealed envelope. Blocks until one arrives
    /// or the connection closes.
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError>;
}

/// Send-only half of a split [`Transport`]. See [`Transport`]'s doc
/// comment for why splitting exists.
#[allow(async_fn_in_trait)]
pub trait SendEnvelope: Send {
    /// Send a single sealed envelope.
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError>;
}

/// Receive-only half of a split [`Transport`]. See [`Transport`]'s doc
/// comment for why splitting exists.
#[allow(async_fn_in_trait)]
pub trait RecvEnvelope: Send {
    /// Receive a single sealed envelope. Blocks until one arrives or
    /// the connection closes.
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError>;
}

/// Write one length-prefixed envelope to any `AsyncWrite` half.
/// Shared by [`TcpTransport`] and [`TcpSendHalf`] so the framing logic
/// exists in exactly one place.
async fn write_envelope(
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<(), TransportError> {
    let len = u32::try_from(bytes.len()).map_err(|_| TransportError::EnvelopeTooLarge(u32::MAX))?;
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::EnvelopeTooLarge(len));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed envelope from any `AsyncRead` half. Shared
/// by [`TcpTransport`] and [`TcpRecvHalf`].
async fn read_envelope(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            TransportError::UnexpectedEof
        } else {
            TransportError::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::EnvelopeTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            TransportError::UnexpectedEof
        } else {
            TransportError::Io(e)
        }
    })?;
    Ok(buf)
}

/// TCP transport: 4-byte big-endian length prefix + envelope bytes.
///
/// Not framing to any existing protocol. Just the simplest thing
/// that reliably delimits sealed envelopes on a byte stream.
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Wrap an existing `TcpStream`.
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Convenience constructor: connect to a server address.
    pub async fn connect(addr: &str) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Self::new(stream))
    }

    /// Split into independently-owned send/recv halves (via
    /// `TcpStream::into_split`) so a caller can run concurrent send
    /// and recv loops on separate tasks. See [`Transport`]'s doc
    /// comment for why this exists.
    pub fn split(self) -> (TcpSendHalf, TcpRecvHalf) {
        let (read, write) = self.stream.into_split();
        (TcpSendHalf(write), TcpRecvHalf(read))
    }
}

impl Transport for TcpTransport {
    fn transport_profile(&self) -> TransportProfileV1 {
        TransportProfileV1::current(TransportKind::Tcp)
    }

    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        write_envelope(&mut self.stream, bytes).await
    }

    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        read_envelope(&mut self.stream).await
    }
}

/// Send-only half of a split [`TcpTransport`].
pub struct TcpSendHalf(OwnedWriteHalf);

impl SendEnvelope for TcpSendHalf {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        write_envelope(&mut self.0, bytes).await
    }
}

/// Receive-only half of a split [`TcpTransport`].
pub struct TcpRecvHalf(OwnedReadHalf);

impl RecvEnvelope for TcpRecvHalf {
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        read_envelope(&mut self.0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_transport_profiles_are_distinct_and_canonical() {
        let tcp = TransportProfileV1::current(TransportKind::Tcp);
        let ws = TransportProfileV1::current(TransportKind::WebSocket);
        let quic = TransportProfileV1::current(TransportKind::Quic);

        assert!(tcp.is_current_supported_profile());
        assert!(ws.is_current_supported_profile());
        assert!(quic.is_current_supported_profile());
        assert_ne!(tcp.profile_hash().unwrap(), ws.profile_hash().unwrap());
        assert_ne!(tcp.profile_hash().unwrap(), quic.profile_hash().unwrap());
        assert_ne!(ws.profile_hash().unwrap(), quic.profile_hash().unwrap());
    }

    #[test]
    fn profile_mutations_are_not_silently_current() {
        let base = TransportProfileV1::current(TransportKind::Quic);

        let mut changed = base.clone();
        changed.protocol_version = changed.protocol_version.saturating_add(1);
        assert!(!changed.is_current_supported_profile());

        let mut changed = base.clone();
        changed.max_envelope_bytes = changed.max_envelope_bytes.saturating_sub(1);
        assert!(!changed.is_current_supported_profile());

        let mut changed = base.clone();
        changed.max_handshake_envelope_bytes =
            changed.max_handshake_envelope_bytes.saturating_sub(1);
        assert!(!changed.is_current_supported_profile());

        let mut changed = base.clone();
        changed.logical_streams = 2;
        assert!(!changed.is_current_supported_profile());
    }
}
