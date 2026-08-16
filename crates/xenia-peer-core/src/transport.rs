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
use std::time::Duration;

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


/// Stable schema label for pre-session resource/deadline policy. These
/// semantics are enforced before the cryptographic handshake can authenticate
/// the peer, then committed into the post-handshake session context so both
/// endpoints can prove which unauthenticated resource policy was in force.
pub const TRANSPORT_PRE_SESSION_PROFILE_SCHEMA: &str = "xenia-transport-pre-session-profile-v1";

/// Maximum time allowed for a TCP/WebSocket carrier connection attempt.
pub const TCP_CONNECT_TIMEOUT_MS: u64 = 10_000;
/// Maximum total time allowed for the client-side WebSocket connect + HTTP
/// upgrade operation. `tokio-tungstenite` exposes those phases as one future.
pub const WEBSOCKET_CONNECT_UPGRADE_TIMEOUT_MS: u64 = 20_000;
/// Maximum time an already-accepted TCP stream may spend in the WebSocket HTTP
/// upgrade before the unauthenticated peer is dropped.
pub const WEBSOCKET_UPGRADE_TIMEOUT_MS: u64 = 10_000;
/// Maximum time allowed for a QUIC connection handshake.
pub const QUIC_CONNECT_TIMEOUT_MS: u64 = 15_000;
/// Maximum time allowed to open/accept the one logical Xenia QUIC stream and
/// validate its profile preface.
pub const QUIC_STREAM_OPEN_TIMEOUT_MS: u64 = 10_000;

/// Pre-authentication resource/deadline policy for carrier establishment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPreSessionProfileV1 {
    /// Stable profile schema.
    pub schema: String,
    /// Carrier whose pre-session behavior is described.
    pub kind: TransportKind,
    /// Client-side carrier connection establishment budget. Zero means the
    /// carrier has no distinct connect phase in this profile.
    pub connect_timeout_ms: u64,
    /// Protocol-upgrade budget after a base carrier exists. For the WebSocket
    /// client this is represented by the combined connect+upgrade ceiling.
    pub protocol_upgrade_timeout_ms: u64,
    /// Logical application-stream establishment/preface budget.
    pub logical_stream_open_timeout_ms: u64,
}

impl TransportPreSessionProfileV1 {
    /// Return Xenia's exact current pre-session policy for `kind`.
    pub fn current(kind: TransportKind) -> Self {
        let (connect_timeout_ms, protocol_upgrade_timeout_ms, logical_stream_open_timeout_ms) =
            match kind {
                TransportKind::Tcp => (TCP_CONNECT_TIMEOUT_MS, 0, 0),
                TransportKind::WebSocket => (
                    WEBSOCKET_CONNECT_UPGRADE_TIMEOUT_MS,
                    WEBSOCKET_UPGRADE_TIMEOUT_MS,
                    0,
                ),
                TransportKind::Quic => (QUIC_CONNECT_TIMEOUT_MS, 0, QUIC_STREAM_OPEN_TIMEOUT_MS),
            };
        Self {
            schema: TRANSPORT_PRE_SESSION_PROFILE_SCHEMA.to_string(),
            kind,
            connect_timeout_ms,
            protocol_upgrade_timeout_ms,
            logical_stream_open_timeout_ms,
        }
    }

    /// Return true only for the exact currently-supported pre-session profile.
    pub fn is_current_supported_profile(&self) -> bool {
        self == &Self::current(self.kind)
    }

    /// Canonical bincode-v1 bytes used only for authenticated context hashing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// BLAKE3-256 digest of the canonical pre-session profile.
    pub fn profile_hash(&self) -> Result<[u8; 32], bincode::Error> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }
}

/// Stable schema label for the transport availability profile committed into
/// the authenticated session context.
pub const TRANSPORT_AVAILABILITY_PROFILE_SCHEMA: &str = "xenia-transport-availability-profile-v1";

/// Maximum time an application send may remain backpressured before the
/// current profile fails the session closed.
pub const SEND_STALL_TIMEOUT_MS: u64 = 15_000;
/// Maximum time a receive operation may wait for one complete Xenia envelope.
/// Carrier keepalive/control frames do not reset this deadline.
pub const RECEIVE_ENVELOPE_TIMEOUT_MS: u64 = 120_000;
/// Maximum grace period callers should allow for transport close/teardown.
pub const GRACEFUL_CLOSE_TIMEOUT_MS: u64 = 3_000;

/// Availability/failure semantics authenticated alongside a carrier profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAvailabilityProfileV1 {
    /// Stable profile schema.
    pub schema: String,
    /// Concrete carrier whose failure semantics are described.
    pub kind: TransportKind,
    /// Send-side backpressure deadline.
    pub send_stall_timeout_ms: u64,
    /// Deadline for receiving one complete application envelope.
    pub receive_envelope_timeout_ms: u64,
    /// Graceful transport teardown budget.
    pub graceful_close_timeout_ms: u64,
    /// Xenia application keepalive interval. Zero means no synthetic
    /// application keepalive is emitted by the current profile.
    pub application_keepalive_interval_ms: u64,
    /// Carrier control traffic (WebSocket ping/pong, QUIC transport traffic)
    /// must not reset the application-envelope receive deadline.
    pub carrier_keepalive_resets_application_idle: bool,
}

impl TransportAvailabilityProfileV1 {
    /// Return the exact current availability/failure contract for `kind`.
    pub fn current(kind: TransportKind) -> Self {
        Self {
            schema: TRANSPORT_AVAILABILITY_PROFILE_SCHEMA.to_string(),
            kind,
            send_stall_timeout_ms: SEND_STALL_TIMEOUT_MS,
            receive_envelope_timeout_ms: RECEIVE_ENVELOPE_TIMEOUT_MS,
            graceful_close_timeout_ms: GRACEFUL_CLOSE_TIMEOUT_MS,
            application_keepalive_interval_ms: 0,
            carrier_keepalive_resets_application_idle: false,
        }
    }

    /// Return true only for the exact currently-supported availability profile.
    pub fn is_current_supported_profile(&self) -> bool {
        self == &Self::current(self.kind)
    }

    /// Canonical bincode-v1 bytes used only for authenticated context hashing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// BLAKE3-256 digest of the canonical availability profile.
    pub fn profile_hash(&self) -> Result<[u8; 32], bincode::Error> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
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

    /// A bounded transport operation made no acceptable progress before the
    /// authenticated availability deadline. This is session-fatal: callers
    /// must not continue using a stream that may contain a partial envelope.
    #[error("transport: {operation} timed out after {timeout_ms} ms")]
    TimedOut {
        /// Stable operation label suitable for logs/evidence.
        operation: &'static str,
        /// Deadline from the applicable pre-session or authenticated
        /// availability profile.
        timeout_ms: u64,
    },
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

    /// Exact unauthenticated carrier-establishment policy that was enforced
    /// before this transport reached the cryptographic handshake.
    fn pre_session_profile(&self) -> TransportPreSessionProfileV1 {
        TransportPreSessionProfileV1::current(self.transport_profile().kind)
    }

    /// Exact failure/liveness semantics bound into the authenticated session
    /// context. Current carriers use one shared policy but the carrier kind is
    /// committed so future revisions can diverge explicitly.
    fn availability_profile(&self) -> TransportAvailabilityProfileV1 {
        TransportAvailabilityProfileV1::current(self.transport_profile().kind)
    }

    /// Send a single sealed envelope. Any timeout/error is session-fatal; the
    /// caller must tear down rather than reuse potentially partial framing.
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// Receive a single sealed envelope. Blocks until one arrives, the
    /// connection closes, or the authenticated availability deadline expires.
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
    /// Receive a single sealed envelope. Blocks until one arrives, the
    /// connection closes, or the authenticated availability deadline expires.
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError>;
}

/// Write one length-prefixed envelope to any `AsyncWrite` half.
/// Shared by [`TcpTransport`] and [`TcpSendHalf`] so the framing logic
/// exists in exactly one place.
async fn write_envelope_with_timeout(
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), TransportError> {
    let len = u32::try_from(bytes.len()).map_err(|_| TransportError::EnvelopeTooLarge(u32::MAX))?;
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::EnvelopeTooLarge(len));
    }
    tokio::time::timeout(timeout, async {
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(bytes).await?;
        w.flush().await?;
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| TransportError::TimedOut {
        operation: "send_envelope",
        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
    })??;
    Ok(())
}

async fn write_envelope(
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<(), TransportError> {
    write_envelope_with_timeout(w, bytes, Duration::from_millis(SEND_STALL_TIMEOUT_MS)).await
}

async fn read_envelope_with_timeout(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
    timeout: Duration,
) -> Result<Vec<u8>, TransportError> {
    tokio::time::timeout(timeout, async {
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
    })
    .await
    .map_err(|_| TransportError::TimedOut {
        operation: "recv_envelope",
        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
    })?
}

async fn read_envelope(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>, TransportError> {
    read_envelope_with_timeout(r, Duration::from_millis(RECEIVE_ENVELOPE_TIMEOUT_MS)).await
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
        let timeout_ms = TransportPreSessionProfileV1::current(TransportKind::Tcp).connect_timeout_ms;
        let stream = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| TransportError::TimedOut {
            operation: "tcp_connect",
            timeout_ms,
        })??;
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

    #[test]
    fn availability_profile_v1_tcp_bincode_vector_is_stable() {
        let expected: [u8; 84] = [
            0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x65, 0x6e, 0x69,
            0x61, 0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2d,
            0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79,
            0x2d, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x2d, 0x76, 0x31, 0x00,
            0x00, 0x00, 0x00, 0x98, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
            0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            TransportAvailabilityProfileV1::current(TransportKind::Tcp)
                .canonical_bytes()
                .unwrap(),
            expected,
        );
    }

    #[test]
    fn availability_profiles_are_exact_and_carrier_bound() {
        for kind in [TransportKind::Tcp, TransportKind::WebSocket, TransportKind::Quic] {
            let profile = TransportAvailabilityProfileV1::current(kind);
            assert!(profile.is_current_supported_profile());
            assert_eq!(profile.application_keepalive_interval_ms, 0);
            assert!(!profile.carrier_keepalive_resets_application_idle);
            let mut changed = profile.clone();
            changed.send_stall_timeout_ms += 1;
            assert!(!changed.is_current_supported_profile());
        }
        assert_ne!(
            TransportAvailabilityProfileV1::current(TransportKind::Tcp).profile_hash().unwrap(),
            TransportAvailabilityProfileV1::current(TransportKind::Quic).profile_hash().unwrap(),
        );
    }

    #[test]
    fn pre_session_profiles_are_exact_and_carrier_bound() {
        for kind in [TransportKind::Tcp, TransportKind::WebSocket, TransportKind::Quic] {
            let profile = TransportPreSessionProfileV1::current(kind);
            assert!(profile.is_current_supported_profile());
            let mut changed = profile.clone();
            changed.connect_timeout_ms = changed.connect_timeout_ms.saturating_add(1);
            assert!(!changed.is_current_supported_profile());
        }
        assert_ne!(
            TransportPreSessionProfileV1::current(TransportKind::Tcp).profile_hash().unwrap(),
            TransportPreSessionProfileV1::current(TransportKind::Quic).profile_hash().unwrap(),
        );
    }

    #[tokio::test]
    async fn partial_tcp_envelope_times_out_fail_closed() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            writer.write_all(&8u32.to_be_bytes()).await.unwrap();
            writer.write_all(&[1, 2]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let err = read_envelope_with_timeout(&mut reader, Duration::from_millis(25))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::TimedOut { operation: "recv_envelope", .. }));
    }

    #[tokio::test]
    async fn stalled_tcp_send_times_out_fail_closed() {
        let (mut writer, _reader) = tokio::io::duplex(8);
        let payload = vec![7u8; 1024];
        let err = write_envelope_with_timeout(&mut writer, &payload, Duration::from_millis(25))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::TimedOut { operation: "send_envelope", .. }));
    }

}
