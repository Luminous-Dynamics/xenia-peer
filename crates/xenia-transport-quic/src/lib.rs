// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # xenia-transport-quic
//!
//! Iroh QUIC implementation of the
//! [`xenia_peer_core::transport::Transport`] trait.
//!
//! Xenia envelopes are already end-to-end sealed by `xenia-wire`. This crate
//! uses Iroh for NAT traversal, endpoint identity, multiplexing, and QUIC stream
//! semantics; the application payload remains transport-independent.
//!
//! The transport wraps one long-lived bidirectional QUIC stream. Inside that
//! stream it uses the same 4-byte big-endian envelope length prefix as the TCP
//! transport, so callers get identical envelope boundary behavior across TCP,
//! WebSocket, and QUIC.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::io;

use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use thiserror::Error;
use tracing::debug;
use xenia_peer_core::transport::{
    MAX_ENVELOPE_BYTES, RecvEnvelope, SendEnvelope, Transport, TransportError,
};

/// Re-export of the Iroh crate for endpoint ownership in callers.
pub use iroh;

/// ALPN used by the Xenia QUIC transport.
pub const XENIA_QUIC_ALPN: &[u8] = b"xenia/transport/quic/0";

const STREAM_PREFACE: &[u8; 8] = b"XENIAQ0\0";
const ADDR_PREFIX: &str = "iroh:";

/// Errors specific to the Iroh QUIC transport.
#[derive(Debug, Error)]
pub enum QuicError {
    /// Endpoint connection attempt failed.
    #[error("iroh connect: {0}")]
    Connect(String),

    /// Incoming connection accept failed.
    #[error("iroh accept: {0}")]
    Accept(String),

    /// QUIC stream open/accept failed.
    #[error("iroh stream: {0}")]
    Stream(String),

    /// QUIC stream read/write failed.
    #[error("iroh I/O: {0}")]
    Io(String),

    /// Endpoint closed before a connection arrived.
    #[error("iroh endpoint closed before accepting a connection")]
    EndpointClosed,

    /// Endpoint address string could not be encoded or decoded.
    #[error("iroh address: {0}")]
    Address(String),
}

impl From<QuicError> for TransportError {
    fn from(value: QuicError) -> Self {
        match value {
            QuicError::EndpointClosed => TransportError::UnexpectedEof,
            other => TransportError::Io(io::Error::other(other.to_string())),
        }
    }
}

/// Bind an Iroh endpoint configured for the Xenia QUIC ALPN.
///
/// This uses Iroh's minimal preset: no public relay or DNS dependency is
/// required. The resulting [`Endpoint::addr`] contains direct addresses that
/// work for loopback and reachable LAN interfaces.
pub async fn bind_xenia_endpoint() -> Result<Endpoint, TransportError> {
    Endpoint::builder(presets::Minimal)
        .alpns(vec![XENIA_QUIC_ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| TransportError::from(QuicError::Accept(e.to_string())))
}

/// Encode an Iroh endpoint address into a copyable CLI token.
pub fn encode_endpoint_addr(addr: &EndpointAddr) -> Result<String, TransportError> {
    let json = serde_json::to_vec(addr)
        .map_err(|e| TransportError::from(QuicError::Address(e.to_string())))?;
    Ok(format!("{ADDR_PREFIX}{}", bs58::encode(json).into_string()))
}

/// Decode an endpoint address previously returned by [`encode_endpoint_addr`].
pub fn decode_endpoint_addr(s: &str) -> Result<EndpointAddr, TransportError> {
    let encoded = s.strip_prefix(ADDR_PREFIX).unwrap_or(s);
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| TransportError::from(QuicError::Address(e.to_string())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| TransportError::from(QuicError::Address(e.to_string())))
}

/// Iroh QUIC transport over one bidirectional stream.
pub struct QuicTransport {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl QuicTransport {
    /// Wrap an already-opened bidirectional stream.
    pub fn new(conn: Connection, send: SendStream, recv: RecvStream) -> Self {
        Self { conn, send, recv }
    }

    /// Connect to an Iroh endpoint address and open the transport stream.
    pub async fn connect(
        endpoint: &Endpoint,
        addr: impl Into<EndpointAddr>,
    ) -> Result<Self, TransportError> {
        let conn = endpoint
            .connect(addr, XENIA_QUIC_ALPN)
            .await
            .map_err(|e| TransportError::from(QuicError::Connect(e.to_string())))?;
        Self::open(conn).await
    }

    /// Accept one incoming Iroh connection and its first bidirectional stream.
    pub async fn accept_one(endpoint: &Endpoint) -> Result<Self, TransportError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::from(QuicError::EndpointClosed))?;
        let conn = incoming
            .await
            .map_err(|e| TransportError::from(QuicError::Accept(e.to_string())))?;
        Self::accept_stream(conn).await
    }

    /// Open a new bidirectional stream on an established connection.
    pub async fn open(conn: Connection) -> Result<Self, TransportError> {
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::from(QuicError::Stream(e.to_string())))?;
        send.write_all(STREAM_PREFACE)
            .await
            .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))?;
        debug!("iroh quic stream opened");
        Ok(Self::new(conn, send, recv))
    }

    /// Accept the next bidirectional stream on an established connection.
    pub async fn accept_stream(conn: Connection) -> Result<Self, TransportError> {
        let (send, recv) = conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::from(QuicError::Stream(e.to_string())))?;
        Self::accept_stream_pair(conn, send, recv).await
    }

    /// Gracefully finish the sending side of the transport stream.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        self.send
            .finish()
            .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))
    }

    /// Wait until the peer closes the underlying QUIC connection.
    pub async fn closed(&self) {
        let _ = self.conn.closed().await;
    }

    /// Split into independently-owned send/recv halves — Iroh's
    /// `SendStream`/`RecvStream` are already separate fields
    /// internally, so this just repackages them. See
    /// [`xenia_peer_core::transport::Transport`]'s doc comment for why
    /// this exists. The connection handle (needed for `finish`/`closed`
    /// during teardown) stays with the send half.
    pub fn split(self) -> (QuicSendHalf, QuicRecvHalf) {
        (
            QuicSendHalf {
                conn: self.conn,
                send: self.send,
            },
            QuicRecvHalf { recv: self.recv },
        )
    }

    async fn accept_stream_pair(
        conn: Connection,
        send: SendStream,
        mut recv: RecvStream,
    ) -> Result<Self, TransportError> {
        let mut preface = [0u8; STREAM_PREFACE.len()];
        recv.read_exact(&mut preface).await.map_err(|e| {
            let msg = e.to_string();
            if is_stream_eof(&msg) {
                TransportError::UnexpectedEof
            } else {
                TransportError::from(QuicError::Io(msg))
            }
        })?;
        if &preface != STREAM_PREFACE {
            return Err(TransportError::from(QuicError::Stream(
                "invalid stream preface".to_string(),
            )));
        }

        debug!("iroh quic stream accepted");
        Ok(Self::new(conn, send, recv))
    }
}

fn is_stream_eof(msg: &str) -> bool {
    msg.contains("end of stream") || msg.contains("closed") || msg.contains("reset")
}

/// Write one length-prefixed envelope to a QUIC send stream. Shared by
/// [`QuicTransport`] and [`QuicSendHalf`].
async fn write_envelope(send: &mut SendStream, bytes: &[u8]) -> Result<(), TransportError> {
    let len = u32::try_from(bytes.len()).map_err(|_| TransportError::EnvelopeTooLarge(u32::MAX))?;
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::EnvelopeTooLarge(len));
    }

    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))?;
    send.write_all(bytes)
        .await
        .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))?;
    Ok(())
}

/// Read one length-prefixed envelope from a QUIC recv stream. Shared
/// by [`QuicTransport`] and [`QuicRecvHalf`].
async fn read_envelope(recv: &mut RecvStream) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| {
        let msg = e.to_string();
        if is_stream_eof(&msg) {
            TransportError::UnexpectedEof
        } else {
            TransportError::from(QuicError::Io(msg))
        }
    })?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::EnvelopeTooLarge(len));
    }

    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await.map_err(|e| {
        let msg = e.to_string();
        if is_stream_eof(&msg) {
            TransportError::UnexpectedEof
        } else {
            TransportError::from(QuicError::Io(msg))
        }
    })?;
    Ok(buf)
}

impl Transport for QuicTransport {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        write_envelope(&mut self.send, bytes).await
    }

    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        read_envelope(&mut self.recv).await
    }
}

/// Send-only half of a split [`QuicTransport`]. Also carries the
/// `Connection` handle so callers can still `finish`/`closed` during
/// teardown after splitting.
pub struct QuicSendHalf {
    conn: Connection,
    send: SendStream,
}

impl QuicSendHalf {
    /// Gracefully finish the sending side of the stream.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        self.send
            .finish()
            .map_err(|e| TransportError::from(QuicError::Io(e.to_string())))
    }

    /// Wait until the peer closes the underlying QUIC connection.
    pub async fn closed(&self) {
        let _ = self.conn.closed().await;
    }
}

impl SendEnvelope for QuicSendHalf {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        write_envelope(&mut self.send, bytes).await
    }
}

/// Receive-only half of a split [`QuicTransport`].
pub struct QuicRecvHalf {
    recv: RecvStream,
}

impl RecvEnvelope for QuicRecvHalf {
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        read_envelope(&mut self.recv).await
    }
}
