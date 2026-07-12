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
//!
//! [`handle_operator_rekey_envelope`] handles the daemon's forward-secrecy
//! rekey proposals (see xenia-peer's `operator_sealed_channel.rs` module doc
//! comment, "Forward secrecy"). [`send_sealed_consent`] doesn't call it today
//! — it's a one-shot "connect, decide, close" driver that never keeps a
//! connection open long enough for a proposal to arrive — but the function is
//! here, real, and proven wire-compatible against the live daemon endpoint
//! (see xenia-peer's `operator_rekey_proposal_installs_new_key_and_channel_keeps_serving`
//! test, which drives this exact `xenia_wire::operator_rekey` logic natively),
//! ready for a future persistent-console mode (a live-updating admin view
//! that holds one connection across many decisions) to call from its own read
//! loop.

use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message, WebSocketError};

use xenia_wire::handshake::{SessionKeySchedule, ViewerHandshake};
use xenia_wire::handshake_highsec::{
    derive_ml_dsa_87_seed_from_ed25519_secret, ViewerHandshakeHighSec,
};
use xenia_wire::operator_rekey::{self, OperatorRekeyMessage};
use xenia_wire::{Session, PAYLOAD_TYPE_APPLICATION_MIN};

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

/// Like [`send_sealed_consent`], but drives the high-security handshake
/// suite (ML-KEM-1024 + Ed25519 + ML-DSA-87) via
/// [`ViewerHandshakeHighSec`] — for a daemon running `--operator-sealed
/// --operator-high-security`.
///
/// Takes only `ed25519_secret`, not a separate ML-DSA-87 seed: the operator
/// enrolls one Ed25519 key regardless of suite (policy lookup is keyed by
/// Ed25519 only — see xenia-peer's `OperatorPolicy::lookup`), and the
/// ML-DSA-87 identity is derived from that same secret via
/// [`derive_ml_dsa_87_seed_from_ed25519_secret`] — the same derivation the
/// daemon's `load_or_create_host_identity_highsec` uses from its own
/// persisted secret, so both sides land on a suite-specific identity tied to
/// the one enrolled key without a second key file or a second enrollment
/// step.
pub async fn send_sealed_consent_highsec(
    sealed_ws_url: &str,
    ed25519_secret: &[u8; 32],
    payload: &[u8],
) -> Result<(), String> {
    let ws = WebSocket::open(sealed_ws_url)
        .map_err(|e| format!("failed to open sealed channel {sealed_ws_url}: {e}"))?;
    let (mut writer, mut reader) = ws.split();

    let ml_dsa_seed = derive_ml_dsa_87_seed_from_ed25519_secret(ed25519_secret);
    let mut handshake = ViewerHandshakeHighSec::from_identity(ed25519_secret, &ml_dsa_seed)
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

/// Handle one sealed operator-channel envelope already identified (via
/// `xenia_wire::envelope_payload_type`) as
/// [`operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY`]: open it under the
/// *current* key, verify the proposed epoch's self-consistency
/// ([`operator_rekey::verify_proposal_epoch_hash`]), derive and install the
/// new key, and return the Ack envelope (already sealed under the *new* key)
/// ready to send. See the module doc comment for why nothing calls this yet.
///
/// Errors (a malformed/tampered envelope, or a message that isn't a Proposal
/// — the console never proposes, only the daemon does) are returned rather
/// than panicking, matching every other function in this module.
// Not yet called from this crate -- see the module doc comment. Real,
// tested (via xenia-peer's native E2E test), and public so a future
// persistent-console read loop can call it directly.
#[allow(dead_code)]
pub fn handle_operator_rekey_envelope(
    session: &mut Session,
    schedule: &SessionKeySchedule,
    envelope: &[u8],
) -> Result<Vec<u8>, String> {
    let plaintext = session
        .open(envelope)
        .map_err(|e| format!("failed to open sealed operator rekey envelope: {e}"))?;
    let OperatorRekeyMessage::Proposal {
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        epoch_hash,
    } = OperatorRekeyMessage::decode(&plaintext)
        .map_err(|e| format!("failed to decode operator rekey message: {e}"))?
    else {
        return Err("expected an operator rekey Proposal (only the daemon proposes)".to_string());
    };
    let verified = operator_rekey::verify_proposal_epoch_hash(
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        epoch_hash,
    )
    .map_err(|e| format!("operator rekey proposal failed its self-consistency check: {e}"))?;

    let new_key = operator_rekey::derive_operator_rekey_key(&schedule.rekey, &verified);
    session.install_key(new_key);

    let ack = OperatorRekeyMessage::Ack {
        key_epoch,
        epoch_hash: verified,
    };
    session
        .seal(
            &ack.encode()
                .map_err(|e| format!("failed to encode operator rekey ack: {e}"))?,
            operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY,
        )
        .map_err(|e| format!("failed to seal operator rekey ack: {e}"))
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
