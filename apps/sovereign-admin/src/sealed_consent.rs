// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The **browser side** of the sealed operator channel (see xenia-peer
//! `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`, Slice 3).
//!
//! When the daemon runs with `--operator-sealed`, consent decisions travel over
//! a PQC-sealed, handshake-authenticated channel instead of the plaintext
//! consent socket. This module drives the viewer half of that channel, but —
//! since `docs/security/SIGNER_DELEGATION_DESIGN.md` Step 6 landed — it no
//! longer holds the operator's raw Ed25519/ML-DSA seeds or runs
//! `ViewerHandshake`/`ViewerHandshakeHighSec` itself. Instead:
//!
//! 1. Open a WebSocket to the daemon's `--operator-sealed-port`.
//! 2. Relay the daemon's `HostHello`/`HostFinalize` bytes through the local
//!    agent's `POST /v1/handshake/begin` / `POST /v1/handshake/finish` (see
//!    `xenia-operator-agent`'s `handshake_state` module) — the agent runs the
//!    actual handshake against the operator's seeds, which never leave the
//!    agent process, and only returns session key material once its own
//!    host-trust policy accepts the authenticated fingerprint the handshake
//!    produced.
//! 3. Install the agent-derived AEAD key into a [`Session`] and seal the same
//!    consent payload the plaintext path sends, so the daemon decodes it
//!    identically (keeping the per-action Ed25519 signature for ledger
//!    non-repudiation).
//!
//! The wire messages this module relays (`HostHello`/`ViewerResponse`/
//! `HostFinalize`) are exactly what the daemon's native host handshake speaks
//! (`xenia-wire`'s `handshake` feature) — this module itself now only
//! handles them as opaque bytes; the agent is the side that proves them
//! wire-compatible (see `xenia-operator-agent`'s own `/v1/handshake/*`
//! end-to-end tests, which drive a real host role against the agent's
//! viewer role over a loopback socket).
//!
//! [`handle_operator_rekey_envelope`] handles the daemon's forward-secrecy
//! rekey proposals (see xenia-peer's `operator_sealed_channel.rs` module doc
//! comment, "Forward secrecy"). Neither [`send_sealed_consent`] nor
//! [`send_sealed_consent_highsec`] calls it today — they're one-shot
//! "connect, decide, close" drivers that never keep a connection open long
//! enough for a proposal to arrive — but the function is here, real, and
//! proven wire-compatible against the live daemon endpoint (see xenia-peer's
//! `operator_rekey_proposal_installs_new_key_and_channel_keeps_serving`
//! test, which drives this exact `xenia_wire::operator_rekey` logic natively),
//! ready for a future persistent-console mode (a live-updating admin view
//! that holds one connection across many decisions) to call from its own read
//! loop.

use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, WebSocketError, futures::WebSocket};

use xenia_operator_agent_proto::{
    AgentSessionToken, HandshakeBeginRequest, HandshakeFinishRequest, HandshakeRequestCommon,
    SCHEMA_VERSION,
};
use xenia_wire::handshake::SessionKeySchedule;
use xenia_wire::operator_rekey::{self, OperatorRekeyMessage};
use xenia_wire::{PAYLOAD_TYPE_APPLICATION_MIN, Session};

/// Shared `source_id` for the sealed operator channel — MUST match the daemon's
/// `OPERATOR_CHANNEL_SOURCE_ID` (`operator_sealed_channel.rs`) so the console's
/// sealed-envelope nonces line up with what the daemon opens.
const OPERATOR_CHANNEL_SOURCE_ID: [u8; 8] = *b"xnaopch1";

/// Exact RFC 6455 subprotocol required by `xenia-transport-ws` for the current
/// browser-compatible Xenia WebSocket profile. Browser WebSocket APIs cannot
/// add arbitrary headers, so this must be requested through the constructor's
/// protocol argument rather than `Sec-WebSocket-Protocol` directly.
const XENIA_WEBSOCKET_SUBPROTOCOL: &str = "xenia.transport.websocket.v1";

/// Shared driver for both [`send_sealed_consent`] (`suite = "standard"`) and
/// [`send_sealed_consent_highsec`] (`suite = "highsec"`): the browser no
/// longer holds the operator's raw seeds or drives `ViewerHandshake`/
/// `ViewerHandshakeHighSec` itself — it relays `HostHello`/`HostFinalize`
/// bytes through the local agent's `/v1/handshake/begin` and
/// `/v1/handshake/finish` (see `xenia-operator-agent`'s `handshake_state`
/// module), which performs the handshake against the operator's seeds and
/// only releases session key material once its own host-trust policy
/// accepts the resulting authenticated fingerprint. The suite string alone
/// is enough for the agent to pick the right handshake type — the two wire
/// messages (`HostHello`/`HostFinalize`) are opaque bytes to this module
/// either way.
async fn drive_agent_handshake(
    sealed_ws_url: &str,
    agent_url: &str,
    agent_session: &AgentSessionToken,
    suite: &str,
    payload: &[u8],
) -> Result<(), String> {
    let ws = WebSocket::open_with_protocol(sealed_ws_url, XENIA_WEBSOCKET_SUBPROTOCOL)
        .map_err(|e| format!("failed to open sealed channel {sealed_ws_url}: {e}"))?;
    let (mut writer, mut reader) = ws.split();

    // 1. Host's HostHello -> ask the agent to run the viewer's begin step.
    let hello = recv_binary(&mut reader).await?;
    let begin_resp = crate::agent_client::handshake_begin(
        agent_url,
        agent_session,
        &HandshakeBeginRequest {
            common: HandshakeRequestCommon {
                schema_version: SCHEMA_VERSION,
                daemon_endpoint: sealed_ws_url.to_string(),
                suite: suite.to_string(),
                request_id: request_id(),
            },
            host_hello_hex: hex::encode(&hello),
        },
    )
    .await?;
    let viewer_response = decode_hex(&begin_resp.viewer_response_hex)?;
    send_binary(&mut writer, viewer_response).await?;

    // 2. Host's HostFinalize -> ask the agent to finish. The agent only
    // returns session material once its own host-trust policy accepts the
    // authenticated fingerprint the handshake itself produced -- there is
    // nothing further for this module to verify beyond the TOFU pin below.
    let finalize = recv_binary(&mut reader).await?;
    let finish_resp = crate::agent_client::handshake_finish(
        agent_url,
        agent_session,
        &HandshakeFinishRequest {
            schema_version: SCHEMA_VERSION,
            handshake_id_hex: begin_resp.handshake_id_hex,
            host_finalize_hex: hex::encode(&finalize),
        },
    )
    .await?;

    // 2.5. TOFU-pin the authenticated host identity fingerprint *before*
    // sending anything sealed under this channel's key -- defense in depth
    // on top of the agent's own (authoritative) host-trust check: a
    // mismatch here means either a legitimate daemon key rotation (operator
    // must explicitly `host_pin::forget`) or an active MITM between this
    // browser and the agent, and either way the console must not proceed
    // silently.
    let fingerprint = decode32(&finish_resp.authenticated_host_fingerprint_hex)?;
    check_host_pin(sealed_ws_url, suite, fingerprint)?;

    // 3. Seal the consent payload over the agent-derived channel key and
    // send it.
    let aead = decode32(&finish_resp.aead_key_hex)?;
    let mut session = Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
    session.install_key(aead);
    let envelope = session
        .seal(payload, PAYLOAD_TYPE_APPLICATION_MIN)
        .map_err(|e| format!("sealing consent decision failed: {e}"))?;
    send_binary(&mut writer, envelope).await?;

    Ok(())
}

/// Complete the sealed operator channel handshake via the local agent
/// (standard suite: ML-KEM-768 + Ed25519 + ML-DSA-65) at `sealed_ws_url`,
/// then seal `payload` and send it over the established channel.
///
/// `payload` is the exact bytes the plaintext consent path would send (either a
/// signed, token-bearing consent request or a bare action string) — the daemon
/// decodes it the same way after opening the envelope.
pub async fn send_sealed_consent(
    sealed_ws_url: &str,
    agent_url: &str,
    agent_session: &AgentSessionToken,
    payload: &[u8],
) -> Result<(), String> {
    drive_agent_handshake(sealed_ws_url, agent_url, agent_session, "standard", payload).await
}

/// Like [`send_sealed_consent`], but selects the high-security handshake
/// suite (ML-KEM-1024 + Ed25519 + ML-DSA-87) — for a daemon running
/// `--operator-sealed --operator-high-security`. Pinned separately from the
/// standard suite by [`drive_agent_handshake`]: the two suites' host
/// identities are cryptographically distinct (Ed25519 || ML-DSA-65 vs
/// Ed25519 || ML-DSA-87), even though a real daemon shares the underlying
/// Ed25519 secret across both.
pub async fn send_sealed_consent_highsec(
    sealed_ws_url: &str,
    agent_url: &str,
    agent_session: &AgentSessionToken,
    payload: &[u8],
) -> Result<(), String> {
    drive_agent_handshake(sealed_ws_url, agent_url, agent_session, "highsec", payload).await
}

/// TOFU-check `fingerprint` against the pin stored for `(sealed_ws_url,
/// suite)`. Returns `Ok(())` to proceed (logging on first trust, since that's
/// the one point where an already-present MITM would go undetected); returns
/// `Err` -- which the caller propagates, refusing the channel -- on a
/// mismatch.
fn check_host_pin(sealed_ws_url: &str, suite: &str, fingerprint: [u8; 32]) -> Result<(), String> {
    let key = crate::host_pin::storage_key(sealed_ws_url, suite);
    match crate::host_pin::verify_or_pin(&key, fingerprint) {
        Ok(crate::host_pin::PinOutcome::FirstConnection) => {
            leptos::logging::warn!(
                "trusting {suite} host identity fingerprint {} for {sealed_ws_url} on first connection (TOFU)",
                hex::encode(fingerprint)
            );
            Ok(())
        }
        Ok(crate::host_pin::PinOutcome::Matched) => Ok(()),
        // Covers both a real fingerprint mismatch and any storage-layer
        // failure (unavailable/corrupt/write-failed) -- `PinCheckError`
        // fails closed either way, so this refuses the channel either way
        // rather than treating "couldn't check the pin" as "pin matched."
        Err(err) => Err(err.to_string()),
    }
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

/// A caller-generated id for correlating a `/v1/handshake/*` request through
/// logs -- not itself a security boundary, so a UUID is sufficient (mirrors
/// `operator_session.rs`'s identical helper for `/v1/sign/*` requests).
fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Decode a variable-length hex string from an agent response (handshake
/// message bytes aren't fixed-size, unlike a key or fingerprint).
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|e| format!("operator agent returned malformed hex: {e}"))
}

/// Decode a fixed 32-byte hex string from an agent response (a key or
/// fingerprint).
fn decode32(s: &str) -> Result<[u8; 32], String> {
    decode_hex(s)?
        .try_into()
        .map_err(|_| "operator agent returned a malformed 32-byte value".to_string())
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
