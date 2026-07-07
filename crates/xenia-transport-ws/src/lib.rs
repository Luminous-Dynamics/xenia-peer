// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # xenia-transport-ws
//!
//! WebSocket implementation of the
//! [`xenia_peer_core::transport::Transport`] trait.
//!
//! Sealed envelopes (as produced by `xenia-wire`) are carried as
//! **binary** WebSocket messages — one envelope per message. The
//! framing is thus delegated entirely to the WebSocket protocol
//! layer; there is no second length prefix. Compare `TcpTransport`
//! which adds a 4-byte big-endian length prefix on top of a raw
//! stream.
//!
//! ## Why WebSocket
//!
//! Per `VIEWER_PLAN.md` §4.5, WebSocket is the fallback transport
//! when the primary Iroh QUIC path is unavailable:
//!
//! - **Browser compatibility.** A browser-based `xenia-viewer` can
//!   connect via the platform `WebSocket` object and receive sealed
//!   envelopes without any native code. Iroh QUIC has no browser
//!   client.
//! - **CGN / strict-egress networks.** Corporate and carrier
//!   networks that block raw UDP but allow outbound TCP-over-80 / -443
//!   will let a `ws://` or `wss://` session through where QUIC fails.
//! - **Simplicity.** `tokio-tungstenite` handles the WebSocket
//!   framing, close handshake, and ping/pong keepalive for us.
//!
//! ## Threat-model note
//!
//! Xenia's entire security guarantee is end-to-end via `xenia-wire`.
//! This crate provides **no** transport-level security on its own —
//! `ws://` is cleartext at the TCP level. That's fine because the
//! envelope payload is already AEAD-sealed. Callers who still want
//! TLS at the transport boundary (e.g. to hide message-size
//! metadata from a passive observer) can front this with a reverse
//! proxy or wrap with `tokio-rustls` in a later crate. No TLS
//! machinery lives in `xenia-transport-ws` itself.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use futures_util::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{accept_async, connect_async, WebSocketStream};
use tracing::debug;

use xenia_peer_core::transport::{
    RecvEnvelope, SendEnvelope, Transport, TransportError, MAX_ENVELOPE_BYTES,
};

/// Errors specific to the WebSocket transport. Coerced into
/// [`TransportError::Io`] or `::UnexpectedEof` where possible so the
/// trait contract stays uniform across transports.
#[derive(Debug, Error)]
pub enum WsError {
    /// Underlying tungstenite protocol failure — handshake refused,
    /// mid-stream corruption, unexpected opcode, etc.
    #[error("websocket: {0}")]
    Protocol(tokio_tungstenite::tungstenite::Error),

    /// Peer closed the WebSocket gracefully. Returned only on
    /// receive; equivalent to [`TransportError::UnexpectedEof`].
    #[error("websocket: closed by peer")]
    Closed,

    /// Remote sent a text frame where we expected a binary envelope.
    /// Xenia envelopes are always binary; text means the peer is
    /// speaking the wrong protocol.
    #[error("websocket: received non-binary message (text / ping / etc.)")]
    NonBinaryMessage,
}

impl From<tokio_tungstenite::tungstenite::Error> for WsError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        WsError::Protocol(e)
    }
}

impl From<WsError> for TransportError {
    fn from(e: WsError) -> Self {
        match e {
            WsError::Closed => TransportError::UnexpectedEof,
            WsError::NonBinaryMessage => TransportError::UnexpectedEof,
            WsError::Protocol(inner) => {
                TransportError::Io(std::io::Error::other(inner.to_string()))
            }
        }
    }
}

/// WebSocket transport wrapping a `tokio-tungstenite` stream.
///
/// Internally an enum over the two possible underlying streams
/// (client-side goes through `MaybeTlsStream`, server-side owns a
/// plain `TcpStream`). Both variants implement the same `Transport`
/// trait surface; the enum is an implementation detail.
pub enum WsTransport {
    /// Client-side connection established via `connect_async`.
    Client(WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>),
    /// Server-side connection established via `accept_async`.
    Server(WebSocketStream<TcpStream>),
}

impl WsTransport {
    /// Connect to `ws://host:port[/path]`. The path component is
    /// ignored server-side by the MVP implementation.
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let (ws, _resp) = connect_async(url)
            .await
            .map_err(|e| TransportError::from(WsError::from(e)))?;
        debug!(url = %url, "websocket client connected");
        Ok(WsTransport::Client(ws))
    }

    /// Bind a TCP listener on `addr`, accept the first connection,
    /// and upgrade it to WebSocket. Returns the transport plus the
    /// bound address (useful when `addr` had port 0 and the kernel
    /// picked one).
    pub async fn bind_and_accept_one(addr: &str) -> Result<(Self, String), TransportError> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?.to_string();
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let transport = Self::accept_stream(stream).await?;
        debug!(peer = %peer, "websocket server accepted + upgraded");
        Ok((transport, local))
    }

    /// Upgrade an already-accepted TCP stream into a WebSocket transport.
    pub async fn accept_stream(stream: TcpStream) -> Result<Self, TransportError> {
        let ws = accept_async(stream)
            .await
            .map_err(|e| TransportError::from(WsError::from(e)))?;
        Ok(WsTransport::Server(ws))
    }

    /// Send a message on whichever variant we are.
    async fn send_msg(
        &mut self,
        msg: Message,
    ) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        match self {
            WsTransport::Client(ws) => ws.send(msg).await,
            WsTransport::Server(ws) => ws.send(msg).await,
        }
    }

    /// Pull the next framed message off the underlying stream.
    async fn next_msg(&mut self) -> Option<Result<Message, tokio_tungstenite::tungstenite::Error>> {
        match self {
            WsTransport::Client(ws) => ws.next().await,
            WsTransport::Server(ws) => ws.next().await,
        }
    }

    /// Split into independently-owned send/recv halves via
    /// `futures_util::StreamExt::split`, so a caller can run concurrent
    /// send and recv loops on separate tasks. See
    /// [`xenia_peer_core::transport::Transport`]'s doc comment for why
    /// this exists.
    pub fn split(self) -> (WsSendHalf, WsRecvHalf) {
        match self {
            WsTransport::Client(ws) => {
                let (sink, stream) = ws.split();
                (WsSendHalf::Client(sink), WsRecvHalf::Client(stream))
            }
            WsTransport::Server(ws) => {
                let (sink, stream) = ws.split();
                (WsSendHalf::Server(sink), WsRecvHalf::Server(stream))
            }
        }
    }
}

fn ensure_envelope_size(len: usize) -> Result<(), TransportError> {
    if len > MAX_ENVELOPE_BYTES as usize {
        let reported = u32::try_from(len).unwrap_or(u32::MAX);
        return Err(TransportError::EnvelopeTooLarge(reported));
    }
    Ok(())
}

/// Interpret one received tungstenite frame as an envelope, applying
/// the same binary-only / size-limit / close-handling rules used by
/// both the unsplit [`WsTransport`] and the split halves below.
fn interpret_recv(
    msg: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
) -> Result<Option<Vec<u8>>, TransportError> {
    match msg {
        Some(Ok(Message::Binary(data))) => {
            ensure_envelope_size(data.len())?;
            Ok(Some(data.to_vec()))
        }
        Some(Ok(Message::Close(_))) => Err(TransportError::from(WsError::Closed)),
        Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
            // tungstenite auto-replies to pings; pong is informational.
            // Caller should loop to the next frame.
            Ok(None)
        }
        Some(Ok(Message::Text(_))) | Some(Ok(Message::Frame(_))) => {
            Err(TransportError::from(WsError::NonBinaryMessage))
        }
        Some(Err(e)) => Err(TransportError::from(WsError::from(e))),
        None => Err(TransportError::from(WsError::Closed)),
    }
}

impl Transport for WsTransport {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        ensure_envelope_size(bytes.len())?;
        self.send_msg(Message::Binary(bytes.to_vec()))
            .await
            .map_err(|e| TransportError::from(WsError::from(e)))?;
        Ok(())
    }

    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            if let Some(env) = interpret_recv(self.next_msg().await)? {
                return Ok(env);
            }
        }
    }
}

/// Send-only half of a split [`WsTransport`].
pub enum WsSendHalf {
    /// Client-side split sink.
    Client(
        futures_util::stream::SplitSink<
            WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            Message,
        >,
    ),
    /// Server-side split sink.
    Server(futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>),
}

impl SendEnvelope for WsSendHalf {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        ensure_envelope_size(bytes.len())?;
        let msg = Message::Binary(bytes.to_vec());
        let result = match self {
            WsSendHalf::Client(sink) => sink.send(msg).await,
            WsSendHalf::Server(sink) => sink.send(msg).await,
        };
        result.map_err(|e| TransportError::from(WsError::from(e)))
    }
}

/// Receive-only half of a split [`WsTransport`].
pub enum WsRecvHalf {
    /// Client-side split stream.
    Client(
        futures_util::stream::SplitStream<
            WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        >,
    ),
    /// Server-side split stream.
    Server(futures_util::stream::SplitStream<WebSocketStream<TcpStream>>),
}

impl RecvEnvelope for WsRecvHalf {
    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            let next = match self {
                WsRecvHalf::Client(stream) => stream.next().await,
                WsRecvHalf::Server(stream) => stream.next().await,
            };
            if let Some(env) = interpret_recv(next)? {
                return Ok(env);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_envelope_size_check_rejects_oversize_binary_payload() {
        let err = ensure_envelope_size(MAX_ENVELOPE_BYTES as usize + 1).unwrap_err();
        assert!(matches!(err, TransportError::EnvelopeTooLarge(_)));
    }

    #[test]
    fn envelope_size_check_allows_the_boundary() {
        assert!(ensure_envelope_size(MAX_ENVELOPE_BYTES as usize).is_ok());
        assert!(ensure_envelope_size(0).is_ok());
    }

    #[test]
    fn interpret_recv_returns_binary_payloads_verbatim() {
        let msg = Some(Ok(Message::Binary(vec![1, 2, 3, 4].into())));
        assert_eq!(interpret_recv(msg).unwrap(), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn interpret_recv_rejects_oversize_binary() {
        let big = vec![0u8; MAX_ENVELOPE_BYTES as usize + 1];
        let err = interpret_recv(Some(Ok(Message::Binary(big.into())))).unwrap_err();
        assert!(matches!(err, TransportError::EnvelopeTooLarge(_)));
    }

    #[test]
    fn interpret_recv_treats_close_and_stream_end_as_eof() {
        // Graceful peer close.
        assert!(matches!(
            interpret_recv(Some(Ok(Message::Close(None)))).unwrap_err(),
            TransportError::UnexpectedEof
        ));
        // Stream exhausted (None).
        assert!(matches!(
            interpret_recv(None).unwrap_err(),
            TransportError::UnexpectedEof
        ));
    }

    #[test]
    fn interpret_recv_skips_ping_and_pong() {
        // Control frames yield no envelope; the caller loops to the next frame.
        assert_eq!(
            interpret_recv(Some(Ok(Message::Ping(Vec::new().into())))).unwrap(),
            None
        );
        assert_eq!(
            interpret_recv(Some(Ok(Message::Pong(Vec::new().into())))).unwrap(),
            None
        );
    }

    #[test]
    fn interpret_recv_rejects_text_frames() {
        // Xenia envelopes are always binary; a text frame means wrong protocol.
        assert!(matches!(
            interpret_recv(Some(Ok(Message::Text("hello".into())))).unwrap_err(),
            TransportError::UnexpectedEof
        ));
    }

    #[test]
    fn wserror_maps_to_uniform_transport_error() {
        assert!(matches!(
            TransportError::from(WsError::Closed),
            TransportError::UnexpectedEof
        ));
        assert!(matches!(
            TransportError::from(WsError::NonBinaryMessage),
            TransportError::UnexpectedEof
        ));
    }

    /// Bind to an ephemeral port, listen on a background task,
    /// connect a client, exchange 20 binary envelopes of varying
    /// sizes in each direction, verify the bytes round-trip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roundtrip_over_real_websocket() {
        use tokio::sync::oneshot;

        let (port_tx, port_rx) = oneshot::channel::<String>();

        let server = tokio::spawn(async move {
            // Bind on :0, discover the kernel-picked port, publish
            // it to the client via the channel, then accept exactly
            // one connection and echo 20 envelopes.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local = listener.local_addr().unwrap();
            port_tx.send(local.to_string()).unwrap();

            let (stream, _peer) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let ws = accept_async(stream).await.unwrap();
            let mut t = WsTransport::Server(ws);

            for i in 0..20u32 {
                let env = t.recv_envelope().await.unwrap();
                assert_eq!(env.len(), 32 + i as usize);
                t.send_envelope(&env).await.unwrap();
            }
        });

        let addr = port_rx.await.unwrap();
        let mut client = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
        for i in 0..20u32 {
            let payload: Vec<u8> = (0..(32 + i as usize)).map(|b| b as u8).collect();
            client.send_envelope(&payload).await.unwrap();
            let echoed = client.recv_envelope().await.unwrap();
            assert_eq!(echoed, payload);
        }
        server.await.unwrap();
    }
}
