// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hardened daemon-side sealed operator channel.
//!
//! The pre-hardening implementation is preserved byte-for-byte in
//! `operator_sealed_channel_legacy.rs` so its existing regression tests remain
//! available. This module owns the production endpoint and tightens the
//! forward-secrecy transition around three invariants:
//!
//! 1. host and console transmissions use distinct AEAD nonce source domains;
//! 2. once a rekey Proposal may have left the process, there is no rollback;
//! 3. authority-bearing receive traffic is current-key-only, including the Ack.

#[path = "operator_sealed_channel_legacy.rs"]
#[allow(dead_code)]
mod legacy;
#[path = "operator_rekey_initiator.rs"]
mod initiator;

pub(crate) use legacy::{OperatorHostIdentity, SealedConsentDeps};

use std::fmt;

use tokio::net::TcpListener;
use tokio::time::Instant;
use xenia_peer_core::transport::Transport;
use xenia_transport_ws::WsTransport;
use xenia_wire::operator_rekey;

use crate::operator::OperatorPolicy;
use initiator::{OPERATOR_REKEY_ACK_TIMEOUT, OperatorRekeyInitiator};

/// Existing console-to-daemon source domain. Kept stable for compatibility.
const OPERATOR_CONSOLE_SOURCE_ID: [u8; 8] = *b"xnaopch1";
/// Daemon-to-console source domain. The first six bytes deliberately differ
/// from `OPERATOR_CONSOLE_SOURCE_ID`, because those are the bytes committed
/// into xenia-wire's 96-bit AEAD nonce.
const OPERATOR_HOST_SOURCE_ID: [u8; 8] = *b"xnaophs1";
const OPERATOR_SESSION_EPOCH: u8 = 1;

#[derive(Debug)]
enum ServeError {
    Channel(legacy::OperatorChannelError),
    Protocol(String),
}

impl From<legacy::OperatorChannelError> for ServeError {
    fn from(value: legacy::OperatorChannelError) -> Self {
        Self::Channel(value)
    }
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::Channel(err) => err.fmt(f),
            ServeError::Protocol(err) => write!(f, "sealed operator protocol failed: {err}"),
        }
    }
}

impl std::error::Error for ServeError {}

/// Return true only when an inbound post-handshake envelope claims the console
/// transmit nonce domain used by this operator-channel profile.
fn has_console_nonce_domain(envelope: &[u8]) -> bool {
    envelope.len() >= 12 + 16
        && envelope[..6] == OPERATOR_CONSOLE_SOURCE_ID[..6]
        && envelope[7] == OPERATOR_SESSION_EPOCH
}

/// Serve one authenticated operator connection with fail-closed rekey state.
async fn serve_hardened_operator_channel<T: Transport>(
    transport: &mut T,
    identity: &mut OperatorHostIdentity,
    policy: &OperatorPolicy,
    deps: &SealedConsentDeps,
    grant_tx: &mut Option<tokio::sync::oneshot::Sender<bool>>,
) -> Result<bool, ServeError> {
    let channel = legacy::establish_operator_channel(transport, identity, policy).await?;
    if deps.revocations.is_revoked(&channel.operator_id) {
        return Err(legacy::OperatorChannelError::Revoked(channel.operator_id).into());
    }
    tracing::info!(
        operator = %channel.operator_id,
        role = ?channel.role,
        "sealed operator channel established"
    );

    // Sending and authority-bearing receiving deliberately use separate
    // sessions. Besides giving each direction a distinct nonce source domain,
    // this lets the receive session be replaced at rekey instead of calling
    // `install_key` in place and inheriting generic previous-key grace.
    let mut tx_session =
        xenia_wire::Session::with_source_id(OPERATOR_HOST_SOURCE_ID, OPERATOR_SESSION_EPOCH);
    tx_session.install_key(channel.aead_key);
    let mut authority_rx_session =
        xenia_wire::Session::with_source_id(OPERATOR_CONSOLE_SOURCE_ID, OPERATOR_SESSION_EPOCH);
    authority_rx_session.install_key(channel.aead_key);

    let mut rekey = OperatorRekeyInitiator::new(
        channel.transcript_hash,
        &channel.aead_key,
        OPERATOR_CONSOLE_SOURCE_ID,
        OPERATOR_SESSION_EPOCH,
    );

    let mut interval = deps.rekey_interval.map(tokio::time::interval);
    if let Some(interval) = interval.as_mut() {
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await; // consume the immediate first tick
    }

    loop {
        let ack_deadline = rekey.ack_deadline();
        let may_propose = interval.is_some() && !rekey.is_pending_ack();

        tokio::select! {
            _ = async {
                if let Some(interval) = interval.as_mut() {
                    interval.tick().await
                } else {
                    std::future::pending::<tokio::time::Instant>().await
                }
            }, if may_propose => {
                rekey
                    .prepare_interval(&mut tx_session, &channel.rekey_root)
                    .map_err(|err| ServeError::Protocol(err.to_string()))?;
                let key_epoch = rekey
                    .prepared_epoch()
                    .map_err(|err| ServeError::Protocol(err.to_string()))?;
                let proposal = rekey
                    .prepared_envelope()
                    .map_err(|err| ServeError::Protocol(err.to_string()))?;

                // Per the Transport contract, any send error is session-fatal.
                // Success still does not prove remote processing, which is why
                // the following commit is one-way until a new-key Ack arrives.
                transport
                    .send_envelope(proposal)
                    .await
                    .map_err(|err| ServeError::Protocol(format!(
                        "rekey Proposal send failed after local preparation: {err}"
                    )))?;

                let committed_epoch = rekey
                    .commit_sent(
                        &mut tx_session,
                        &mut authority_rx_session,
                        Instant::now() + OPERATOR_REKEY_ACK_TIMEOUT,
                    )
                    .map_err(|err| ServeError::Protocol(err.to_string()))?;
                debug_assert_eq!(committed_epoch, key_epoch);
                tracing::info!(
                    key_epoch = committed_epoch,
                    ack_timeout_ms = OPERATOR_REKEY_ACK_TIMEOUT.as_millis() as u64,
                    "operator rekey Proposal sent; new key committed pending exact-key Ack"
                );
            }

            _ = async {
                if let Some(deadline) = ack_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if ack_deadline.is_some() => {
                return Err(ServeError::Protocol(
                    "operator rekey Ack deadline expired; connection state is ambiguous and must be re-handshaken"
                        .to_string(),
                ));
            }

            recv = transport.recv_envelope() => {
                let envelope = match recv {
                    Ok(envelope) => envelope,
                    Err(err) if rekey.is_pending_ack() => {
                        return Err(ServeError::Protocol(format!(
                            "transport failed while awaiting operator rekey Ack: {err}"
                        )));
                    }
                    Err(_) => return Ok(false),
                };

                // The post-handshake transport is reliable/ordered; a nonce from
                // a different sender domain is a protocol violation, not a
                // benign out-of-order packet.
                if !has_console_nonce_domain(&envelope) {
                    return Err(ServeError::Protocol(
                        "inbound sealed operator envelope used the wrong console nonce domain"
                            .to_string(),
                    ));
                }

                if xenia_wire::envelope_payload_type(&envelope)
                    == Some(operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY)
                {
                    let key_epoch = rekey
                        .accept_ack(&mut authority_rx_session, &envelope, Instant::now())
                        .map_err(|err| ServeError::Protocol(err.to_string()))?;
                    tracing::info!(key_epoch, "operator rekey acknowledged under exact new key");
                    continue;
                }

                // No application authority crosses a half-confirmed rekey.
                if !rekey.application_allowed() {
                    return Err(ServeError::Protocol(
                        "application authority envelope arrived before rekey confirmation"
                            .to_string(),
                    ));
                }

                // This receive session contains only the current authority key.
                // After any rekey, old-key application decisions fail here even
                // though a generic xenia-wire Session would still have grace.
                let plaintext = authority_rx_session
                    .open(&envelope)
                    .map_err(|_| ServeError::Protocol(
                        "failed to authenticate operator envelope under the current authority key"
                            .to_string(),
                    ))?;
                let Ok(text) = std::str::from_utf8(&plaintext) else {
                    continue;
                };
                let Some(decoded) = crate::decode_consent_decision(
                    text,
                    deps.require_operator_auth,
                    &deps.auth_state,
                    &deps.session_id,
                    &deps.scope_digest,
                    &deps.revocations,
                ) else {
                    continue;
                };
                match crate::consent_server::apply_consent_decision(
                    decoded,
                    grant_tx,
                    &deps.revoked,
                    &deps.ledger,
                    deps.ledger_persister.as_ref(),
                    deps.session_uuid,
                )
                .await
                {
                    crate::consent_server::ConsentFollowup::KeepServing => {}
                    crate::consent_server::ConsentFollowup::Stop => return Ok(true),
                }
            }
        }
    }
}

/// Production `--operator-sealed` endpoint.
///
/// A protocol failure after the authenticated handshake always tears down that
/// connection. Reconnect is allowed, but it starts from a fresh cryptographic
/// handshake and therefore resolves any delivery ambiguity instead of trying to
/// roll key state backward.
pub(crate) async fn run_sealed_operator_endpoint(
    listener: TcpListener,
    mut identity: OperatorHostIdentity,
    policy: OperatorPolicy,
    deps: SealedConsentDeps,
    grant_tx: tokio::sync::oneshot::Sender<bool>,
    metrics: std::sync::Arc<crate::operator_channel_metrics::OperatorChannelMetrics>,
) {
    let mut grant_tx = Some(grant_tx);
    'accept: loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::error!(error = %err, "sealed operator endpoint accept failed");
                break 'accept;
            }
        };
        stream.set_nodelay(true).ok();
        let mut transport = match WsTransport::accept_stream(stream).await {
            Ok(t) => t,
            Err(err) => {
                let total = metrics.record_handshake_failure();
                tracing::warn!(
                    error = %err,
                    peer = %peer,
                    handshake_failures_total = total,
                    "sealed operator websocket upgrade failed"
                );
                continue 'accept;
            }
        };
        metrics.record_connection();
        tracing::info!(peer = %peer, "sealed operator channel connection accepted");

        match serve_hardened_operator_channel(
            &mut transport,
            &mut identity,
            &policy,
            &deps,
            &mut grant_tx,
        )
        .await
        {
            Ok(true) => {
                metrics.record_established();
                metrics.record_terminal();
                break 'accept;
            }
            Ok(false) => {
                metrics.record_established();
                continue 'accept;
            }
            Err(ServeError::Channel(err @ legacy::OperatorChannelError::NotEnrolled)) => {
                let total = metrics.record_not_enrolled();
                tracing::warn!(
                    error = %err,
                    peer = %peer,
                    not_enrolled_total = total,
                    "unenrolled key attempted the sealed operator channel"
                );
                continue 'accept;
            }
            Err(ServeError::Channel(err @ legacy::OperatorChannelError::Handshake(_))) => {
                let total = metrics.record_handshake_failure();
                tracing::warn!(
                    error = %err,
                    peer = %peer,
                    handshake_failures_total = total,
                    "sealed operator handshake failed"
                );
                continue 'accept;
            }
            Err(ServeError::Channel(err @ legacy::OperatorChannelError::Revoked(_))) => {
                let total = metrics.record_revoked();
                tracing::warn!(
                    error = %err,
                    peer = %peer,
                    revoked_total = total,
                    "revoked operator attempted the sealed operator channel"
                );
                continue 'accept;
            }
            Err(ServeError::Protocol(err)) => {
                // This connection necessarily passed the authenticated channel
                // establishment step; record that fact even though the protocol
                // later failed closed.
                metrics.record_established();
                tracing::warn!(
                    error = %err,
                    peer = %peer,
                    "authenticated sealed operator channel failed closed; fresh handshake required"
                );
                continue 'accept;
            }
        }
    }

    let s = metrics.snapshot();
    tracing::info!(
        connections_accepted = s.connections_accepted,
        handshake_failures = s.handshake_failures,
        not_enrolled_rejections = s.not_enrolled_rejections,
        revoked_rejections = s.revoked_rejections,
        channels_established = s.channels_established,
        terminal_decisions = s.terminal_decisions,
        "sealed operator endpoint closed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_console_nonce_prefixes_are_directionally_distinct() {
        assert_ne!(&OPERATOR_HOST_SOURCE_ID[..6], &OPERATOR_CONSOLE_SOURCE_ID[..6]);
    }

    #[test]
    fn console_nonce_domain_check_rejects_host_and_wrong_epoch() {
        let mut console = vec![0u8; 28];
        console[..6].copy_from_slice(&OPERATOR_CONSOLE_SOURCE_ID[..6]);
        console[7] = OPERATOR_SESSION_EPOCH;
        assert!(has_console_nonce_domain(&console));

        let mut host = console.clone();
        host[..6].copy_from_slice(&OPERATOR_HOST_SOURCE_ID[..6]);
        assert!(!has_console_nonce_domain(&host));

        let mut wrong_epoch = console;
        wrong_epoch[7] = OPERATOR_SESSION_EPOCH.wrapping_add(1);
        assert!(!has_console_nonce_domain(&wrong_epoch));
    }
}
