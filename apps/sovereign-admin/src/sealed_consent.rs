// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The **browser side** of the sealed operator channel (see xenia-peer
//! `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`, Slice 3).
//!
//! When the daemon runs with `--operator-sealed`, consent decisions travel over
//! a PQC-sealed, handshake-authenticated channel instead of the plaintext
//! consent socket. This module drives the viewer half:
//!
//! 1. Open a WebSocket to the daemon's `--operator-sealed-port`.
//! 2. Complete the [`ViewerHandshake`] using the operator's *enrolled* seeds —
//!    so the handshake itself authenticates the operator (the daemon authorizes
//!    the handshaked identity against its `OperatorPolicy`; no separate token).
//! 3. Install the derived AEAD key into a [`Session`] and seal the same consent
//!    payload the plaintext path sends, so the daemon decodes it identically
//!    (keeping the per-action Ed25519 signature for ledger non-repudiation).
//!
//! The handshake and session sealing come from the `xenia-wire` crate's
//! `handshake` feature — the exact wire-compatible implementation the daemon's
//! native host handshake speaks (proven by `handshake_cross_compat`).

use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, WebSocketError, futures::WebSocket};

use xenia_wire::handshake::ViewerHandshake;
use xenia_wire::{PAYLOAD_TYPE_APPLICATION_MIN, Session};

/// Shared `source_id` for the sealed operator channel — MUST match the daemon's
/// `OPERATOR_CHANNEL_SOURCE_ID` (`operator_sealed_channel.rs`) so the console's
/// sealed-envelope nonces line up with what the daemon opens.
const OPERATOR_CHANNEL_SOURCE_ID: [u8; 8] = *b"xnaopch1";

/// Handshake with the daemon's sealed operator endpoint at `sealed_ws_url`
/// using the operator's persisted `(ed25519_secret, ml_dsa_seed)` seeds, then
/// seal `payload` and send it over the established channel.
///
/// `payload` is the exact bytes the plaintext consent path would send (either a
/// signed, token-bearing consent request or a bare action string) — the daemon
/// decodes it the same way after opening the envelope.
pub async fn send_sealed_consent(
    sealed_ws_url: &str,
    ed25519_secret: &[u8; 32],
    ml_dsa_seed: &[u8; 32],
    payload: &[u8],
) -> Result<(), String> {
    let ws = WebSocket::open(sealed_ws_url)
        .map_err(|e| format!("failed to open sealed channel {sealed_ws_url}: {e}"))?;
    let (mut writer, mut reader) = ws.split();

    let mut handshake = ViewerHandshake::from_identity(ed25519_secret, ml_dsa_seed)
        .map_err(|e| format!("bad operator identity seeds: {e}"))?;

    // 1. Host's HostHello -> our ViewerResponse.
    let hello = recv_binary(&mut reader).await?;
    let response = handshake
        .begin(&hello)
        .map_err(|e| format!("handshake begin failed: {e}"))?;
    send_binary(&mut writer, response).await?;

    // 2. Host's HostFinalize -> the derived key schedule.
    let finalize = recv_binary(&mut reader).await?;
    let schedule = handshake
        .finish(&finalize)
        .map_err(|e| format!("handshake finish failed (host rejected or MITM): {e}"))?;

    // 3. Seal the consent payload over the channel key and send it.
    let mut session = Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
    session.install_key(schedule.aead);
    let envelope = session
        .seal(payload, PAYLOAD_TYPE_APPLICATION_MIN)
        .map_err(|e| format!("sealing consent decision failed: {e}"))?;
    send_binary(&mut writer, envelope).await?;

    Ok(())
}

/// Receive the next WebSocket frame, requiring it to be binary (the handshake
/// and sealed envelopes are always binary).
async fn recv_binary<S>(reader: &mut S) -> Result<Vec<u8>, String>
where
    S: futures_util::Stream<Item = Result<Message, WebSocketError>> + Unpin,
{
    match reader.next().await {
        Some(Ok(Message::Bytes(bytes))) => Ok(bytes),
        Some(Ok(Message::Text(_))) => {
            Err("sealed channel sent a text frame during the handshake".to_string())
        }
        Some(Err(e)) => Err(format!("sealed channel receive failed: {e}")),
        None => Err("sealed channel closed during the handshake".to_string()),
    }
}

/// Send one binary WebSocket frame (each `send_envelope` on the daemon side is a
/// single binary frame, so we mirror that exactly).
async fn send_binary<S>(writer: &mut S, bytes: Vec<u8>) -> Result<(), String>
where
    S: futures_util::Sink<Message, Error = WebSocketError> + Unpin,
{
    writer
        .send(Message::Bytes(bytes))
        .await
        .map_err(|e| format!("sealed channel send failed: {e}"))
}
