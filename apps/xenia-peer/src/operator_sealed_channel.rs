// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The daemon-side `xenia-wire`-sealed operator channel (Slices 2–3 +
//! endpoint of `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`).
//!
//! [`establish_operator_channel`] runs the PQC-hybrid host handshake over a
//! transport (the WebSocket the console opened), then authorizes the
//! *authenticated* peer against the [`OperatorPolicy`]. Because the handshake
//! already proved possession of the peer's Ed25519 + ML-DSA-65 keys, a
//! successful policy lookup means "this live, confidential channel belongs to
//! enrolled operator X with role R" — the handshake *is* the proof-of-possession
//! the `/auth` ceremony used to provide, and the resulting key schedule seals
//! every subsequent operator payload. [`serve_sealed_operator_channel`] then
//! reads sealed consent decisions over it, and [`run_sealed_operator_endpoint`]
//! is the `--operator-sealed` daemon endpoint that drives the whole thing.
//!
//! Fail-closed: a cryptographically valid handshake from a key that is not
//! enrolled is still refused.
//!
//! ## Forward secrecy
//!
//! A connection that stays open across multiple decisions (the serve loop
//! below doesn't close after one — see its doc comment) would otherwise keep
//! the single key derived at handshake time for its entire lifetime. When
//! `SealedConsentDeps::rekey_interval` is set, the daemon periodically
//! proposes a new key epoch (`xenia_wire::operator_rekey::OperatorRekeyMessage`)
//! and installs it right after sending — mirroring `xenia-peer-core`'s
//! lane-session `perform_rekey` ordering. Off by default (today's console
//! usage opens a fresh connection, and therefore a fresh handshake key, per
//! action — see `apps/sovereign-admin/src/sealed_consent.rs`'s doc comment).

use tokio::net::TcpListener;
use xenia_handshake::{OperatorRekeyEpochContext, OperatorRekeyReason};
use xenia_peer_core::HandshakeManager;
use xenia_peer_core::handshake::perform_host_handshake_authenticating_peer;
use xenia_peer_core::transport::Transport;
use xenia_transport_ws::WsTransport;
use xenia_wire::handshake_highsec::HostHandshakeHighSec;
use xenia_wire::operator_rekey::{self, OperatorRekeyMessage};

use crate::operator::{OperatorPolicy, OperatorRole};

/// Which handshake suite establishes an operator channel. See
/// `xenia_wire::handshake_highsec`'s module doc comment for why the two
/// suites are non-interoperable, non-negotiated alternatives rather than a
/// negotiated wire option.
pub(crate) enum OperatorHostIdentity {
    /// ML-KEM-768 + Ed25519 + ML-DSA-65 (the original, still-default suite).
    /// Boxed, matching `HighSecurity` -- both variants hold multi-KB signing
    /// state, and an unboxed enum would size every `OperatorHostIdentity` to
    /// its largest variant regardless of which one is actually held.
    Standard(Box<HandshakeManager>),
    /// ML-KEM-1024 + Ed25519 + ML-DSA-87 (NIST security category 5).
    HighSecurity(Box<HostHandshakeHighSec>),
}

/// An authenticated, sealed operator channel. The handshake proved the peer's
/// key possession and the peer was found in the operator policy, so we know the
/// operator id + role and hold the key material used to seal/open operator
/// payloads on this channel. Deliberately suite-agnostic (raw key bytes, not
/// a suite-specific `SessionKeySchedule` type) so the rest of this module
/// doesn't need to know or care which handshake suite established the
/// channel.
pub(crate) struct AuthenticatedOperatorChannel {
    /// The enrolled operator this channel is authenticated as.
    pub(crate) operator_id: String,
    /// The role the operator is enrolled with (gates privileged actions).
    pub(crate) role: OperatorRole,
    /// The transcript-bound AEAD key installed into this channel's `Session`.
    pub(crate) aead_key: [u8; 32],
    /// Root key for deriving forward-secrecy rekey epochs (see the module
    /// doc comment's "Forward secrecy" section).
    pub(crate) rekey_root: [u8; 32],
    /// Canonical handshake transcript hash. Root of the rekey-epoch chain
    /// (`base_transcript_hash` on the first proposed epoch).
    pub(crate) transcript_hash: [u8; 32],
}

/// Why establishing an operator channel failed. Both are denials, kept distinct
/// for audit/messaging.
#[derive(Debug)]
pub(crate) enum OperatorChannelError {
    /// The PQC-hybrid handshake itself failed (bad signature, transport error).
    Handshake(String),
    /// The handshake was cryptographically valid, but the peer's key is not an
    /// enrolled operator — refused fail-closed.
    NotEnrolled,
    /// The handshake authenticated an enrolled operator, but that operator id is
    /// on the live revocation list — refused fail-closed without a restart.
    Revoked(String),
}

impl std::fmt::Display for OperatorChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorChannelError::Handshake(e) => write!(f, "operator handshake failed: {e}"),
            OperatorChannelError::NotEnrolled => {
                write!(f, "authenticated peer is not an enrolled operator")
            }
            OperatorChannelError::Revoked(id) => {
                write!(f, "operator '{id}' is revoked")
            }
        }
    }
}

impl std::error::Error for OperatorChannelError {}

/// Establish an authenticated sealed operator channel over `transport`: run the
/// host handshake (whichever suite `identity` holds), then authorize the
/// authenticated peer against `policy`.
pub(crate) async fn establish_operator_channel<T: Transport>(
    transport: &mut T,
    identity: &mut OperatorHostIdentity,
    policy: &OperatorPolicy,
) -> Result<AuthenticatedOperatorChannel, OperatorChannelError> {
    let (aead_key, rekey_root, transcript_hash, authorized) = match identity {
        OperatorHostIdentity::Standard(host_mgr) => {
            let (outcome, peer) =
                perform_host_handshake_authenticating_peer(transport, host_mgr, "operator", None)
                    .await
                    .map_err(|e| OperatorChannelError::Handshake(e.to_string()))?;
            // `lookup_verified` (not plain `lookup`) is required: the
            // handshake verified both signatures, but only checking the
            // enrolled record against the Ed25519 key would let an attacker
            // who controls the enrolled Ed25519 secret pair it with a
            // self-generated ML-DSA keypair and still be authorized as this
            // operator.
            let authorized = policy
                .lookup_verified(&peer.ed25519_pk, &peer.ml_dsa_pk)
                .map(|op| (op.operator_id.clone(), op.role));
            (
                outcome.key_schedule.aead,
                outcome.key_schedule.rekey,
                outcome.transcript_hash,
                authorized,
            )
        }
        OperatorHostIdentity::HighSecurity(host_hs) => {
            let hello = host_hs.hello(None);
            transport
                .send_envelope(&hello)
                .await
                .map_err(|e| OperatorChannelError::Handshake(e.to_string()))?;
            let response_bytes = transport
                .recv_envelope()
                .await
                .map_err(|e| OperatorChannelError::Handshake(e.to_string()))?;
            let (finalize_bytes, schedule, peer) = host_hs
                .finish(&response_bytes)
                .map_err(|e| OperatorChannelError::Handshake(e.to_string()))?;
            transport
                .send_envelope(&finalize_bytes)
                .await
                .map_err(|e| OperatorChannelError::Handshake(e.to_string()))?;
            // The high-security suite's ML-DSA key is ML-DSA-**87**, checked
            // against each operator's separately-enrolled `ml_dsa_87_pubkey`
            // (`lookup_verified_highsec`, not `lookup_verified`) -- an
            // operator's standard ML-DSA-65 enrollment does not, by itself,
            // authorize them for the high-security channel.
            let authorized = policy
                .lookup_verified_highsec(&peer.ed25519_pk, &peer.ml_dsa_pk)
                .map(|op| (op.operator_id.clone(), op.role));
            (
                schedule.aead,
                schedule.rekey,
                schedule.transcript_hash,
                authorized,
            )
        }
    };

    match authorized {
        Some((operator_id, role)) => Ok(AuthenticatedOperatorChannel {
            operator_id,
            role,
            aead_key,
            rekey_root,
            transcript_hash,
        }),
        None => Err(OperatorChannelError::NotEnrolled),
    }
}

/// Fixed `xenia-wire` source id for the operator channel, shared by the daemon
/// (opener) and the console (sealer) so the sealed-envelope nonces line up.
const OPERATOR_CHANNEL_SOURCE_ID: [u8; 8] = *b"xnaopch1";

/// Session-scoped state the sealed serve loop needs once the channel is up —
/// the same state the plaintext consent server takes, minus the grant oneshot
/// (which the endpoint owns and threads across reconnects). Passed by reference
/// so it survives multiple connections.
pub(crate) struct SealedConsentDeps {
    pub(crate) require_operator_auth: bool,
    pub(crate) auth_state: std::sync::Arc<crate::operator_http::OperatorAuthState>,
    pub(crate) session_id: [u8; 16],
    /// Digest of this session's offered consent scope
    /// (`xenia_operator_proto::scope_digest`), bound into each per-action
    /// signature -- see `consent_server::ConsentServer`'s field of the same
    /// name for the full rationale (this is the sealed-channel twin).
    pub(crate) scope_digest: [u8; 32],
    pub(crate) session_uuid: uuid::Uuid,
    pub(crate) ledger: std::sync::Arc<tokio::sync::Mutex<xenia_ledger::Chain>>,
    /// Durable path `ledger`'s entries are atomically persisted to on every
    /// authenticated append -- see `consent_server::apply_consent_decision`.
    pub(crate) ledger_path: std::sync::Arc<std::path::PathBuf>,
    pub(crate) revoked: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Live operator revocation list. Consulted after the handshake authenticates
    /// the peer, so a compromised operator is refused without a daemon restart.
    pub(crate) revocations: crate::operator_revocations::OperatorRevocations,
    /// Forward-secrecy key rotation interval for a connection that stays open
    /// across multiple decisions. `None` (the default) never rekeys -- see
    /// the module doc comment's "Forward secrecy" section.
    pub(crate) rekey_interval: Option<std::time::Duration>,
}

/// Serve one sealed operator channel over `transport`: establish the
/// authenticated channel (handshake + policy), then read sealed consent
/// envelopes. Each envelope opens (with the channel key) to the **same** message
/// the plaintext consent port accepts, decoded via `decode_consent_decision` —
/// so this adds PQC confidentiality + handshake channel-auth while auth,
/// per-action non-repudiation, and ledger attribution are preserved unchanged.
/// Drives the grant/revoke via the shared `apply_consent_decision`.
///
/// Returns `Ok(true)` if a **terminal** decision (Deny/Revoke) ended the
/// channel, `Ok(false)` if the connection simply closed (so the endpoint can
/// accept a reconnect and still take a later Revoke). `grant_tx` is threaded by
/// `&mut Option` so a dropped-then-reconnected console keeps the same session
/// grant.
pub(crate) async fn serve_sealed_operator_channel<T: Transport>(
    transport: &mut T,
    identity: &mut OperatorHostIdentity,
    policy: &OperatorPolicy,
    deps: &SealedConsentDeps,
    grant_tx: &mut Option<tokio::sync::oneshot::Sender<bool>>,
) -> Result<bool, OperatorChannelError> {
    let channel = establish_operator_channel(transport, identity, policy).await?;
    // The key is enrolled, but it may have been revoked at runtime — check the
    // live list before trusting the channel. Fail-closed.
    if deps.revocations.is_revoked(&channel.operator_id) {
        return Err(OperatorChannelError::Revoked(channel.operator_id));
    }
    tracing::info!(
        operator = %channel.operator_id,
        role = ?channel.role,
        "sealed operator channel established"
    );

    let mut session = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
    session.install_key(channel.aead_key);

    // Forward-secrecy rekey state (see the module doc comment). `interval`
    // fires only when `deps.rekey_interval` is configured; `awaiting_ack`
    // gates against proposing a second epoch before the first is confirmed.
    let mut interval = deps.rekey_interval.map(tokio::time::interval);
    if let Some(interval) = interval.as_mut() {
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await; // consume the immediate first tick
    }
    let mut current_epoch: u64 = 0;
    let base_transcript_hash = channel.transcript_hash;
    let mut previous_epoch_hash = channel.transcript_hash;
    let mut awaiting_ack: Option<(u64, [u8; 32])> = None;

    // Read sealed consent decisions (and, if enabled, rekey Acks) for the
    // life of the connection.
    loop {
        tokio::select! {
            _ = async { interval.as_mut().unwrap().tick().await },
                if interval.is_some() && awaiting_ack.is_none() =>
            {
                let next_epoch = current_epoch + 1;
                let epoch_hash = match OperatorRekeyEpochContext::new(
                    next_epoch,
                    base_transcript_hash,
                    previous_epoch_hash,
                    OperatorRekeyReason::Interval,
                )
                .epoch_hash()
                {
                    Ok(h) => h,
                    Err(err) => {
                        tracing::error!(error = %err, "failed to hash operator rekey epoch context");
                        continue;
                    }
                };
                let proposal = OperatorRekeyMessage::Proposal {
                    key_epoch: next_epoch,
                    base_transcript_hash,
                    previous_epoch_hash,
                    reason: operator_rekey::OperatorRekeyReason::Interval,
                    epoch_hash,
                };
                let Ok(bytes) = proposal.encode() else {
                    tracing::error!("failed to encode operator rekey proposal");
                    continue;
                };
                let Ok(envelope) = session.seal(&bytes, operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY)
                else {
                    tracing::error!("failed to seal operator rekey proposal");
                    continue;
                };
                if transport.send_envelope(&envelope).await.is_err() {
                    // Connection is going away; let the next recv_envelope()
                    // observe the close and return Ok(false).
                    continue;
                }
                let new_key =
                    xenia_handshake::derive_operator_rekey_key(&channel.rekey_root, &epoch_hash);
                session.install_key(new_key);
                awaiting_ack = Some((next_epoch, epoch_hash));
                tracing::info!(key_epoch = next_epoch, "operator rekey proposed");
            }
            recv = transport.recv_envelope() => {
                let Ok(envelope) = recv else {
                    // Connection closed without a terminal decision.
                    return Ok(false);
                };
                if xenia_wire::envelope_payload_type(&envelope)
                    == Some(operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY)
                {
                    let Ok(plaintext) = session.open(&envelope) else {
                        tracing::warn!("failed to open sealed operator rekey envelope");
                        continue;
                    };
                    match OperatorRekeyMessage::decode(&plaintext) {
                        Ok(OperatorRekeyMessage::Ack { key_epoch, epoch_hash }) => {
                            match awaiting_ack {
                                Some((expected_epoch, expected_hash))
                                    if expected_epoch == key_epoch && expected_hash == epoch_hash =>
                                {
                                    current_epoch = key_epoch;
                                    previous_epoch_hash = epoch_hash;
                                    awaiting_ack = None;
                                    tracing::info!(key_epoch, "operator rekey acknowledged");
                                }
                                _ => {
                                    tracing::warn!(
                                        key_epoch,
                                        "operator rekey ack did not match the outstanding proposal"
                                    );
                                }
                            }
                        }
                        Ok(OperatorRekeyMessage::Proposal { .. }) => {
                            tracing::warn!(
                                "console sent an operator rekey proposal; only the daemon proposes"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to decode operator rekey message");
                        }
                    }
                    continue;
                }

                let Ok(plaintext) = session.open(&envelope) else {
                    tracing::warn!("failed to open sealed consent envelope");
                    continue;
                };
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
                    &deps.ledger_path,
                    deps.session_uuid,
                )
                .await
                {
                    crate::consent_server::ConsentFollowup::KeepServing => {}
                    // Terminal (Deny/Revoke): the session is decided; stop for good.
                    crate::consent_server::ConsentFollowup::Stop => return Ok(true),
                }
            }
        }
    }
}

/// The `--operator-sealed` daemon endpoint: accept sealed operator connections
/// over `listener` for the life of the session, wrapping each as a `WsTransport`
/// and serving the sealed operator channel. Loops on `accept()` with the same
/// reconnect/revoke semantics as the plaintext [`ConsentServer`]:
/// - a terminal decision (Deny/Revoke) ends the endpoint;
/// - a connection that drops mid-Approve, or a failed/un-enrolled handshake,
///   just loops back to accept the next — so a reconnecting console can still
///   revoke, and a rejected first connection yields to a later legitimate one.
///
/// Fail-closed throughout: only a policy-authorized operator's handshake
/// establishes a channel, and `grant_tx` is threaded across reconnects so the
/// single per-session grant is resolved at most once.
///
/// [`ConsentServer`]: crate::consent_server::ConsentServer
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
                // A failed WS upgrade on the operator port is a malformed/hostile
                // probe as much as a benign misconnect — count it.
                let total = metrics.record_handshake_failure();
                tracing::warn!(error = %err, peer = %peer, handshake_failures_total = total, "sealed operator websocket upgrade failed");
                continue 'accept;
            }
        };
        metrics.record_connection();
        tracing::info!(peer = %peer, "sealed operator channel connection accepted");
        match serve_sealed_operator_channel(
            &mut transport,
            &mut identity,
            &policy,
            &deps,
            &mut grant_tx,
        )
        .await
        {
            // Terminal decision (Deny/Revoke): the session is decided.
            Ok(true) => {
                metrics.record_established();
                metrics.record_terminal();
                break 'accept;
            }
            // Connection closed without a terminal decision: accept a reconnect
            // so the operator can still approve a pending grant or revoke.
            Ok(false) => {
                metrics.record_established();
                continue 'accept;
            }
            // A cryptographically valid handshake from a key that is not an
            // enrolled operator — the strongest probe signal on this surface.
            Err(err @ OperatorChannelError::NotEnrolled) => {
                let total = metrics.record_not_enrolled();
                tracing::warn!(error = %err, peer = %peer, not_enrolled_total = total, "unenrolled key attempted the sealed operator channel");
                continue 'accept;
            }
            // The handshake itself failed (bad signature, transport error, probe).
            Err(err @ OperatorChannelError::Handshake(_)) => {
                let total = metrics.record_handshake_failure();
                tracing::warn!(error = %err, peer = %peer, handshake_failures_total = total, "sealed operator handshake failed");
                continue 'accept;
            }
            // An enrolled operator that has been revoked at runtime — refused
            // fail-closed. A distinct signal from a probe: a *known* operator's
            // key is being used after revocation (possible key compromise).
            Err(err @ OperatorChannelError::Revoked(_)) => {
                let total = metrics.record_revoked();
                tracing::warn!(error = %err, peer = %peer, revoked_total = total, "revoked operator attempted the sealed operator channel");
                continue 'accept;
            }
        }
    }
    // Session summary once the endpoint stops (terminal decision or accept
    // error) — a single line carrying the whole probe picture for this run.
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
    use crate::operator::EnrolledOperator;
    use crate::operator_auth::{AUTH_RATE_MAX, AUTH_RATE_WINDOW_SECS};
    use crate::operator_http::OperatorAuthState;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex as TokioMutex, oneshot};
    use uuid::Uuid;
    use xenia_handshake::ML_DSA_65_PK_LEN;
    use xenia_ledger::Chain;
    use xenia_peer_core::handshake::perform_viewer_handshake_with_transcript;
    // `Transport` (for `send_envelope`) comes in via `use super::*`.
    use xenia_peer_core::transport::TcpTransport;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sealed_channel_serves_a_consent_decision() {
        // An enrolled operator drives the whole path: establish the sealed
        // channel, then send a sealed consent decision over it.
        let op_ed = [11u8; 32];
        let op_ml = [12u8; 32];
        let operator = HandshakeManager::from_identity_seeds(op_ed, op_ml);
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "carol".to_string(),
            ed25519_pubkey: operator.identity_public_key_bytes(),
            ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Operator,
        }])
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, grant_rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        let revoked_daemon = revoked.clone();

        // Daemon: establish the channel, then serve sealed consent.
        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut identity = OperatorHostIdentity::Standard(Box::new(HandshakeManager::new()));
            let daemon = SigningKey::generate(&mut rand::thread_rng());
            let auth_state = Arc::new(OperatorAuthState::new(
                OperatorPolicy::default(),
                daemon.clone(),
                xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
                HandshakeManager::new(),
                AUTH_RATE_MAX,
                AUTH_RATE_WINDOW_SECS,
            ));
            let ledger = Arc::new(TokioMutex::new(Chain::new(daemon)));
            let deps = SealedConsentDeps {
                // Auth off: the sealed payload is a plaintext action, so this
                // exercises the sealed transport + serve wiring (the token/auth
                // path is covered by operator_http/operator_live_smoke).
                require_operator_auth: false,
                auth_state,
                session_id: [0x5a; 16],
                scope_digest: [0u8; 32],
                session_uuid: Uuid::from_u128(3),
                ledger,
                ledger_path: std::sync::Arc::new(
                    std::env::temp_dir().join("xenia-sealed-channel-test.ledger"),
                ),
                revoked: revoked_daemon,
                revocations: crate::operator_revocations::OperatorRevocations::empty(),
                rekey_interval: None,
            };
            let mut grant_tx = Some(grant_tx);
            serve_sealed_operator_channel(&mut t, &mut identity, &policy, &deps, &mut grant_tx)
                .await
        });

        // Console (viewer): handshake with the enrolled identity, then seal an
        // "Approve" over the channel key.
        let viewer = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::from_identity_seeds(op_ed, op_ml);
            let outcome = perform_viewer_handshake_with_transcript(&mut t, &mut mgr, "daemon")
                .await
                .unwrap();
            let mut sess = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
            sess.install_key(outcome.key_schedule.aead);
            let envelope = sess
                .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
                .unwrap();
            t.send_envelope(&envelope).await.unwrap();
            // Hold the connection open briefly so the daemon reads the decision.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        assert!(
            grant_rx.await.unwrap(),
            "a sealed Approve resolves the grant to true"
        );
        assert!(!revoked.load(Ordering::SeqCst));
        let _ = viewer.await;
        let _ = host.await;
    }

    /// End-to-end (Slice 4, native): the operator console's **exact** wire
    /// handshake — `xenia_wire::handshake::ViewerHandshake`, the same code the
    /// browser runs — drives the **real** `run_sealed_operator_endpoint` over a
    /// **real WebSocket** (`WsTransport`), then seals an Approve that resolves the
    /// grant. This proves the production host path
    /// (`perform_host_handshake_authenticating_peer`) and the production browser
    /// path (`ViewerHandshake`) are wire-compatible over the actual transport —
    /// the highest-fidelity check short of a headless browser.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn browser_viewer_handshake_drives_the_live_ws_endpoint() {
        // The enrolled identity IS the seeds the browser reconstructs:
        // HandshakeManager::from_identity_seeds and ViewerHandshake::from_identity
        // derive the same keys, so enrolling via HandshakeManager enrolls exactly
        // the browser identity.
        let op_ed = [21u8; 32];
        let op_ml = [22u8; 32];
        let operator = HandshakeManager::from_identity_seeds(op_ed, op_ml);
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "browser-op".to_string(),
            ed25519_pubkey: operator.identity_public_key_bytes(),
            ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Operator,
        }])
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, grant_rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));

        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState::new(
            OperatorPolicy::default(),
            daemon.clone(),
            xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
            HandshakeManager::new(),
            AUTH_RATE_MAX,
            AUTH_RATE_WINDOW_SECS,
        ));
        let deps = SealedConsentDeps {
            require_operator_auth: false,
            auth_state,
            session_id: [0x33; 16],
            scope_digest: [0u8; 32],
            session_uuid: Uuid::from_u128(21),
            ledger: Arc::new(TokioMutex::new(Chain::new(daemon))),
            ledger_path: std::sync::Arc::new(
                std::env::temp_dir().join("xenia-sealed-channel-test.ledger"),
            ),
            revoked: revoked.clone(),
            revocations: crate::operator_revocations::OperatorRevocations::empty(),
            rekey_interval: None,
        };
        let identity = OperatorHostIdentity::Standard(Box::new(HandshakeManager::new()));
        let metrics = Arc::new(crate::operator_channel_metrics::OperatorChannelMetrics::default());

        // Daemon: the real `--operator-sealed` endpoint (accept-loop + reconnect).
        tokio::spawn(run_sealed_operator_endpoint(
            listener,
            identity,
            policy,
            deps,
            grant_tx,
            metrics.clone(),
        ));

        // "Browser": connect over a real WebSocket and drive the exact
        // ViewerHandshake the sovereign-admin console uses.
        let mut transport = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
        let mut hs = xenia_wire::handshake::ViewerHandshake::from_identity(&op_ed, &op_ml).unwrap();

        let hello = transport.recv_envelope().await.unwrap();
        let response = hs.begin(&hello).unwrap();
        transport.send_envelope(&response).await.unwrap();

        let finalize = transport.recv_envelope().await.unwrap();
        let schedule = hs.finish(&finalize).unwrap();

        // Seal "Approve" exactly as the console does and send it.
        let mut session = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
        session.install_key(schedule.aead);
        let envelope = session
            .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .unwrap();
        transport.send_envelope(&envelope).await.unwrap();

        assert!(
            grant_rx.await.unwrap(),
            "a sealed Approve from the browser's ViewerHandshake over the live WS endpoint resolves the grant"
        );
        assert!(!revoked.load(Ordering::SeqCst));
        // The endpoint records the connection before the handshake begins, so by
        // the time the grant resolved it must be counted — proves the metrics are
        // wired live on the endpoint path.
        assert_eq!(metrics.snapshot().connections_accepted, 1);
    }

    /// Forward secrecy (native E2E, mirrors Slice 4's fidelity): a long-lived
    /// connection with `rekey_interval` configured gets a real rekey Proposal
    /// from the live `run_sealed_operator_endpoint`, the browser's exact
    /// `xenia_wire::operator_rekey` functions verify + derive + install the
    /// new key and Ack it, and a subsequent consent decision sealed under the
    /// *new* key is still accepted — proving the full
    /// propose-then-install/verify-then-install-then-ack cycle is wire- and
    /// key-compatible end to end, not just unit-tested in isolation on either
    /// side.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn operator_rekey_proposal_installs_new_key_and_channel_keeps_serving() {
        let op_ed = [41u8; 32];
        let op_ml = [42u8; 32];
        let operator = HandshakeManager::from_identity_seeds(op_ed, op_ml);
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "rekey-op".to_string(),
            ed25519_pubkey: operator.identity_public_key_bytes(),
            ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Operator,
        }])
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, grant_rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));

        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState::new(
            OperatorPolicy::default(),
            daemon.clone(),
            xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
            HandshakeManager::new(),
            AUTH_RATE_MAX,
            AUTH_RATE_WINDOW_SECS,
        ));
        let deps = SealedConsentDeps {
            require_operator_auth: false,
            auth_state,
            session_id: [0x44; 16],
            scope_digest: [0u8; 32],
            session_uuid: Uuid::from_u128(41),
            ledger: Arc::new(TokioMutex::new(Chain::new(daemon))),
            ledger_path: std::sync::Arc::new(
                std::env::temp_dir().join("xenia-sealed-channel-test.ledger"),
            ),
            revoked: revoked.clone(),
            revocations: crate::operator_revocations::OperatorRevocations::empty(),
            // Short enough that the test doesn't need to wait long, long
            // enough that the immediate first tick (consumed at connection
            // start) doesn't race the handshake itself.
            rekey_interval: Some(std::time::Duration::from_millis(20)),
        };
        let identity = OperatorHostIdentity::Standard(Box::new(HandshakeManager::new()));
        let metrics = Arc::new(crate::operator_channel_metrics::OperatorChannelMetrics::default());

        tokio::spawn(run_sealed_operator_endpoint(
            listener,
            identity,
            policy,
            deps,
            grant_tx,
            metrics.clone(),
        ));

        // "Browser": the exact ViewerHandshake the sovereign-admin console uses.
        let mut transport = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
        let mut hs = xenia_wire::handshake::ViewerHandshake::from_identity(&op_ed, &op_ml).unwrap();

        let hello = transport.recv_envelope().await.unwrap();
        let response = hs.begin(&hello).unwrap();
        transport.send_envelope(&response).await.unwrap();

        let finalize = transport.recv_envelope().await.unwrap();
        let schedule = hs.finish(&finalize).unwrap();

        let mut session = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
        session.install_key(schedule.aead);

        // The daemon proposes a rekey shortly after the channel is up (20ms
        // interval). Receive it, exactly as a persistent console would.
        let proposal_envelope = transport.recv_envelope().await.unwrap();
        assert_eq!(
            xenia_wire::envelope_payload_type(&proposal_envelope),
            Some(operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY),
        );
        let proposal_plaintext = session.open(&proposal_envelope).unwrap();
        let OperatorRekeyMessage::Proposal {
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
        } = OperatorRekeyMessage::decode(&proposal_plaintext).unwrap()
        else {
            panic!("expected a rekey Proposal");
        };
        assert_eq!(key_epoch, 1);
        assert_eq!(base_transcript_hash, schedule.transcript_hash);

        let verified = operator_rekey::verify_proposal_epoch_hash(
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
        )
        .expect("the browser's own epoch-hash verification must agree with the daemon's");
        let new_key = operator_rekey::derive_operator_rekey_key(&schedule.rekey, &verified);
        session.install_key(new_key);

        let ack = OperatorRekeyMessage::Ack {
            key_epoch,
            epoch_hash,
        };
        let ack_envelope = session
            .seal(
                &ack.encode().unwrap(),
                operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY,
            )
            .unwrap();
        transport.send_envelope(&ack_envelope).await.unwrap();

        // A consent decision sealed under the *new* (post-rekey) key must
        // still be accepted by the still-open channel.
        let envelope = session
            .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .unwrap();
        transport.send_envelope(&envelope).await.unwrap();

        assert!(
            grant_rx.await.unwrap(),
            "an Approve sealed under the post-rekey key resolves the grant"
        );
        assert!(!revoked.load(Ordering::SeqCst));
    }

    /// High-security suite (native E2E, mirrors
    /// `browser_viewer_handshake_drives_the_live_ws_endpoint`): a real
    /// `OperatorHostIdentity::HighSecurity` daemon endpoint completes the
    /// ML-KEM-1024 + Ed25519 + ML-DSA-87 handshake with the browser's exact
    /// `xenia_wire::handshake_highsec::ViewerHandshakeHighSec`, and a sealed
    /// Approve over the resulting channel resolves the grant -- proving the
    /// high-security suite is wire-compatible end to end over the real
    /// endpoint, not just correct in the isolated round-trip unit test in
    /// `xenia-wire`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn high_security_handshake_drives_the_live_ws_endpoint() {
        let op_ed = [51u8; 32];
        let op_ml = [52u8; 32];
        let operator_viewer =
            xenia_wire::handshake_highsec::ViewerHandshakeHighSec::from_identity(&op_ed, &op_ml)
                .unwrap();
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "highsec-op".to_string(),
            ed25519_pubkey: operator_viewer.ed25519_public_key(),
            // This operator only ever authenticates via the high-security
            // suite in this test, so the required standard ML-DSA-65
            // identity is an unused placeholder -- the real key goes in
            // `ml_dsa_87_pubkey`, which `lookup_verified_highsec` actually
            // checks for the high-security suite (see
            // `enrolled_ed25519_key_with_a_foreign_ml_dsa_key_is_rejected`
            // below for the negative case this binding closes).
            ml_dsa_pubkey: vec![0u8; ML_DSA_65_PK_LEN],
            ml_dsa_87_pubkey: Some(operator_viewer.ml_dsa_public_key_bytes().to_vec()),
            role: OperatorRole::Operator,
        }])
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, grant_rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));

        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState::new(
            OperatorPolicy::default(),
            daemon.clone(),
            xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
            HandshakeManager::new(),
            AUTH_RATE_MAX,
            AUTH_RATE_WINDOW_SECS,
        ));
        let deps = SealedConsentDeps {
            require_operator_auth: false,
            auth_state,
            session_id: [0x55; 16],
            scope_digest: [0u8; 32],
            session_uuid: Uuid::from_u128(51),
            ledger: Arc::new(TokioMutex::new(Chain::new(daemon))),
            ledger_path: std::sync::Arc::new(
                std::env::temp_dir().join("xenia-sealed-channel-test.ledger"),
            ),
            revoked: revoked.clone(),
            revocations: crate::operator_revocations::OperatorRevocations::empty(),
            rekey_interval: None,
        };
        let identity = OperatorHostIdentity::HighSecurity(Box::new(
            xenia_wire::handshake_highsec::HostHandshakeHighSec::new(),
        ));
        let metrics = Arc::new(crate::operator_channel_metrics::OperatorChannelMetrics::default());

        tokio::spawn(run_sealed_operator_endpoint(
            listener,
            identity,
            policy,
            deps,
            grant_tx,
            metrics.clone(),
        ));

        // "Browser": the exact ViewerHandshakeHighSec the console would use in
        // high-security mode.
        let mut transport = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
        let mut viewer = operator_viewer;

        let hello = transport.recv_envelope().await.unwrap();
        let response = viewer.begin(&hello).unwrap();
        transport.send_envelope(&response).await.unwrap();

        let finalize = transport.recv_envelope().await.unwrap();
        let schedule = viewer.finish(&finalize).unwrap();

        let mut session = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
        session.install_key(schedule.aead);
        let envelope = session
            .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .unwrap();
        transport.send_envelope(&envelope).await.unwrap();

        assert!(
            grant_rx.await.unwrap(),
            "a sealed Approve from the browser's ViewerHandshakeHighSec over the live WS endpoint resolves the grant"
        );
        assert!(!revoked.load(Ordering::SeqCst));
        assert_eq!(metrics.snapshot().connections_accepted, 1);
    }

    /// The bug class `lookup_verified` closes, end to end over the live
    /// high-security WS endpoint: a peer who reuses the *enrolled* Ed25519
    /// identity (e.g. because the classical secret leaked, or a future
    /// quantum attacker broke it) but presents a *different*, self-generated
    /// ML-DSA-87 keypair completes a fully valid cryptographic handshake --
    /// both signatures verify, self-consistently -- yet must still be
    /// refused, because the ML-DSA-87 key was never enrolled for this
    /// operator. Before `OperatorPolicy::lookup_verified` existed, this
    /// connection would have been silently granted (see the deleted
    /// `ml_dsa_pubkey: vec![0u8; 1]` placeholder that used to sit in the
    /// happy-path test above).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enrolled_ed25519_key_with_a_foreign_ml_dsa_key_is_rejected() {
        let op_ed = [61u8; 32];
        let op_ml = [62u8; 32];
        let genuine_viewer =
            xenia_wire::handshake_highsec::ViewerHandshakeHighSec::from_identity(&op_ed, &op_ml)
                .unwrap();
        // The policy enrolls the *real* pair (ML-DSA-65 unused/placeholder,
        // as above -- this operator only authenticates via high-security here).
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "highsec-op".to_string(),
            ed25519_pubkey: genuine_viewer.ed25519_public_key(),
            ml_dsa_pubkey: vec![0u8; ML_DSA_65_PK_LEN],
            ml_dsa_87_pubkey: Some(genuine_viewer.ml_dsa_public_key_bytes().to_vec()),
            role: OperatorRole::Operator,
        }])
        .unwrap();

        // The attacker: same Ed25519 seed (the "leaked classical secret"),
        // but a different ML-DSA-87 seed than the enrolled operator's --
        // e.g. their own freshly-generated post-quantum identity.
        let attacker_ml = [63u8; 32];
        let mut attacker = xenia_wire::handshake_highsec::ViewerHandshakeHighSec::from_identity(
            &op_ed,
            &attacker_ml,
        )
        .unwrap();
        assert_ne!(
            attacker.ml_dsa_public_key_bytes(),
            genuine_viewer.ml_dsa_public_key_bytes(),
            "the attacker's ML-DSA-87 key must differ from the enrolled one for this test to be meaningful"
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, mut grant_rx) = oneshot::channel();

        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState::new(
            OperatorPolicy::default(),
            daemon.clone(),
            xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
            HandshakeManager::new(),
            AUTH_RATE_MAX,
            AUTH_RATE_WINDOW_SECS,
        ));
        let deps = SealedConsentDeps {
            require_operator_auth: false,
            auth_state,
            session_id: [0x56; 16],
            scope_digest: [0u8; 32],
            session_uuid: Uuid::from_u128(61),
            ledger: Arc::new(TokioMutex::new(Chain::new(daemon))),
            ledger_path: std::sync::Arc::new(
                std::env::temp_dir().join("xenia-sealed-channel-test.ledger"),
            ),
            revoked: Arc::new(AtomicBool::new(false)),
            revocations: crate::operator_revocations::OperatorRevocations::empty(),
            rekey_interval: None,
        };
        let identity = OperatorHostIdentity::HighSecurity(Box::new(
            xenia_wire::handshake_highsec::HostHandshakeHighSec::new(),
        ));
        let metrics = Arc::new(crate::operator_channel_metrics::OperatorChannelMetrics::default());

        tokio::spawn(run_sealed_operator_endpoint(
            listener,
            identity,
            policy,
            deps,
            grant_tx,
            metrics.clone(),
        ));

        let mut transport = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
        let hello = transport.recv_envelope().await.unwrap();
        let response = attacker.begin(&hello).unwrap();
        transport.send_envelope(&response).await.unwrap();
        // The host completes the handshake -- both signatures verify -- but
        // then refuses at the policy lookup, so it never sends Finalize.
        // Confirm no grant appears within a short window rather than hanging
        // forever on a Finalize that will never arrive.
        let closed_without_grant =
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut grant_rx).await;
        assert!(
            closed_without_grant.is_err() || matches!(closed_without_grant, Ok(Err(_))),
            "an unenrolled ML-DSA-87 key must never resolve a grant"
        );
        assert_eq!(metrics.snapshot().not_enrolled_rejections, 1);
    }

    /// The deployment path, not just an in-memory test fixture: builds an
    /// enrollment record the way the console's `OperatorIdentity` actually
    /// would (same derivation calls -- `HandshakeManager::from_identity_seeds`
    /// for the standard identity,
    /// `derive_ml_dsa_87_seed_from_ed25519_secret` +
    /// `ViewerHandshakeHighSec::from_identity` for the derived high-security
    /// one -- into the same shared `xenia_operator_proto::OperatorEnrollmentRecord`
    /// type `OperatorIdentity::enrollment_record_json` serializes), serializes
    /// it to JSON, parses that JSON through `OperatorPolicy::from_json` (the
    /// same parser the daemon runs on `--operators-file` at startup), and
    /// only then drives a real high-security handshake against it.
    ///
    /// This is the gap the in-memory `EnrolledOperator { .. }` fixtures in
    /// the other high-security tests don't cover: before
    /// `ml_dsa_87_pubkey` existed as a policy-file field at all, a record
    /// generated this way could never have satisfied the high-security suite
    /// -- `OperatorPolicy::from_json` had no field to carry the ML-DSA-87 key
    /// through in the first place, so no real `--operators-file` could ever
    /// have enrolled an operator for it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn console_generated_enrollment_record_authorizes_a_real_highsec_channel() {
        let ed_seed = [71u8; 32];
        let ml_seed = [72u8; 32];

        // Exactly what `OperatorIdentity::from_seeds` computes.
        let standard_identity = HandshakeManager::from_identity_seeds(ed_seed, ml_seed);
        let ml87_seed =
            xenia_wire::handshake_highsec::derive_ml_dsa_87_seed_from_ed25519_secret(&ed_seed);
        let highsec_identity =
            xenia_wire::handshake_highsec::ViewerHandshakeHighSec::from_identity(
                &ed_seed, &ml87_seed,
            )
            .unwrap();

        // Exactly what `OperatorIdentity::enrollment_record_json` builds and serializes.
        let record = xenia_operator_proto::OperatorEnrollmentRecord {
            operator_id: "console-op".to_string(),
            ed25519_pubkey: hex::encode(standard_identity.identity_public_key_bytes()),
            ml_dsa_pubkey: hex::encode(standard_identity.ml_dsa_public_key_bytes()),
            ml_dsa_87_pubkey: Some(hex::encode(highsec_identity.ml_dsa_public_key_bytes())),
            role: OperatorRole::Operator,
        };
        let policy_file_json = format!(r#"{{"operators":[{}]}}"#, record.to_json_string());

        // Exactly what the daemon does with `--operators-file` at startup.
        let policy = OperatorPolicy::from_json(policy_file_json.as_bytes())
            .expect("a console-generated enrollment record must parse as a valid policy file");

        // Now drive a real high-security handshake with that exact identity
        // against the real live endpoint and confirm it's authorized.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, grant_rx) = oneshot::channel();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState::new(
            OperatorPolicy::default(),
            daemon.clone(),
            xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
            HandshakeManager::new(),
            AUTH_RATE_MAX,
            AUTH_RATE_WINDOW_SECS,
        ));
        let deps = SealedConsentDeps {
            require_operator_auth: false,
            auth_state,
            session_id: [0x71; 16],
            scope_digest: [0u8; 32],
            session_uuid: Uuid::from_u128(71),
            ledger: Arc::new(TokioMutex::new(Chain::new(daemon))),
            ledger_path: std::sync::Arc::new(
                std::env::temp_dir().join("xenia-sealed-channel-test.ledger"),
            ),
            revoked: Arc::new(AtomicBool::new(false)),
            revocations: crate::operator_revocations::OperatorRevocations::empty(),
            rekey_interval: None,
        };
        let identity = OperatorHostIdentity::HighSecurity(Box::new(
            xenia_wire::handshake_highsec::HostHandshakeHighSec::new(),
        ));
        let metrics = Arc::new(crate::operator_channel_metrics::OperatorChannelMetrics::default());
        tokio::spawn(run_sealed_operator_endpoint(
            listener,
            identity,
            policy,
            deps,
            grant_tx,
            metrics.clone(),
        ));

        let mut transport = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
        let mut viewer = highsec_identity;
        let hello = transport.recv_envelope().await.unwrap();
        let response = viewer.begin(&hello).unwrap();
        transport.send_envelope(&response).await.unwrap();
        let finalize = transport.recv_envelope().await.unwrap();
        let schedule = viewer.finish(&finalize).unwrap();

        let mut session = xenia_wire::Session::with_source_id(OPERATOR_CHANNEL_SOURCE_ID, 1);
        session.install_key(schedule.aead);
        let envelope = session
            .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .unwrap();
        transport.send_envelope(&envelope).await.unwrap();

        assert!(
            grant_rx.await.unwrap(),
            "a console-generated, JSON-round-tripped high-security enrollment must authorize a real handshake"
        );
        assert_eq!(metrics.snapshot().not_enrolled_rejections, 0);
    }

    /// Live revocation: an operator whose key is still enrolled but whose id is
    /// on the revocation list completes a valid handshake and is then refused
    /// post-authentication — the "revoke a compromised key without a restart"
    /// guarantee.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoked_operator_is_refused_after_a_valid_handshake() {
        let op_ed = [31u8; 32];
        let op_ml = [32u8; 32];
        let operator = HandshakeManager::from_identity_seeds(op_ed, op_ml);
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "dave".to_string(),
            ed25519_pubkey: operator.identity_public_key_bytes(),
            ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Operator,
        }])
        .unwrap();

        // Dave is enrolled but revoked at runtime.
        let revocations = crate::operator_revocations::OperatorRevocations::empty();
        revocations.revoke("dave");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (grant_tx, _grant_rx) = oneshot::channel();

        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut identity = OperatorHostIdentity::Standard(Box::new(HandshakeManager::new()));
            let daemon = SigningKey::generate(&mut rand::thread_rng());
            let auth_state = Arc::new(OperatorAuthState::new(
                OperatorPolicy::default(),
                daemon.clone(),
                xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
                HandshakeManager::new(),
                AUTH_RATE_MAX,
                AUTH_RATE_WINDOW_SECS,
            ));
            let deps = SealedConsentDeps {
                require_operator_auth: false,
                auth_state,
                session_id: [0x77; 16],
                scope_digest: [0u8; 32],
                session_uuid: Uuid::from_u128(31),
                ledger: Arc::new(TokioMutex::new(Chain::new(daemon))),
                ledger_path: std::sync::Arc::new(
                    std::env::temp_dir().join("xenia-sealed-channel-test.ledger"),
                ),
                revoked: Arc::new(AtomicBool::new(false)),
                revocations,
                rekey_interval: None,
            };
            let mut grant_tx = Some(grant_tx);
            serve_sealed_operator_channel(&mut t, &mut identity, &policy, &deps, &mut grant_tx)
                .await
        });

        // Viewer: complete a valid handshake as the (revoked) enrolled operator.
        let viewer = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::from_identity_seeds(op_ed, op_ml);
            // The handshake itself succeeds; the daemon rejects post-auth.
            let _ = perform_viewer_handshake_with_transcript(&mut t, &mut mgr, "operator").await;
        });

        let result = host.await.unwrap();
        assert!(
            matches!(&result, Err(OperatorChannelError::Revoked(id)) if id == "dave"),
            "a revoked enrolled operator must be refused post-handshake, got {result:?}"
        );
        let _ = viewer.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enrolled_operator_establishes_a_usable_sealed_channel() {
        let op_ed_seed = [3u8; 32];
        let op_ml_seed = [4u8; 32];
        let operator = HandshakeManager::from_identity_seeds(op_ed_seed, op_ml_seed);
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "bob".to_string(),
            ed25519_pubkey: operator.identity_public_key_bytes(),
            ml_dsa_pubkey: operator.ml_dsa_public_key_bytes().to_vec(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Operator,
        }])
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut identity = OperatorHostIdentity::Standard(Box::new(HandshakeManager::new()));
            establish_operator_channel(&mut t, &mut identity, &policy).await
        });
        let viewer = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::from_identity_seeds(op_ed_seed, op_ml_seed);
            perform_viewer_handshake_with_transcript(&mut t, &mut mgr, "daemon")
                .await
                .unwrap()
        });

        let channel = host
            .await
            .unwrap()
            .expect("enrolled operator establishes a channel");
        let viewer_outcome = viewer.await.unwrap();

        // The channel is authenticated as the enrolled operator, with its role.
        assert_eq!(channel.operator_id, "bob");
        assert_eq!(channel.role, OperatorRole::Operator);
        // Both sides hold the same sealed-channel key.
        assert_eq!(channel.aead_key, viewer_outcome.key_schedule.aead);

        // The channel actually carries sealed operator payloads: seal a consent
        // decision host-side, open it viewer-side.
        let mut host_sess = xenia_wire::Session::with_source_id([0x5a; 8], 1);
        host_sess.install_key(channel.aead_key);
        let mut viewer_sess = xenia_wire::Session::with_source_id([0x5a; 8], 1);
        viewer_sess.install_key(viewer_outcome.key_schedule.aead);

        let payload = br#"{"action":"Approve"}"#;
        let envelope = host_sess
            .seal(payload, xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .expect("seal operator payload");
        let opened = viewer_sess.open(&envelope).expect("open operator payload");
        assert_eq!(opened, *payload);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unenrolled_peer_is_refused_after_a_valid_handshake() {
        // A valid operator identity that is simply NOT in the policy.
        let stranger_ed = [5u8; 32];
        let stranger_ml = [6u8; 32];
        // Empty policy: nobody is enrolled.
        let policy = OperatorPolicy::from_operators(vec![]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut identity = OperatorHostIdentity::Standard(Box::new(HandshakeManager::new()));
            establish_operator_channel(&mut t, &mut identity, &policy).await
        });
        let viewer = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).ok();
            let mut t = TcpTransport::new(stream);
            let mut mgr = HandshakeManager::from_identity_seeds(stranger_ed, stranger_ml);
            // The viewer's own handshake still completes (the crypto is valid);
            // the host is the one that refuses on policy. Discard the result so
            // the task output is `Send` (Box<dyn Error> is not).
            let _ = perform_viewer_handshake_with_transcript(&mut t, &mut mgr, "daemon").await;
        });

        let result = host.await.unwrap();
        viewer.await.unwrap();
        assert!(
            matches!(result, Err(OperatorChannelError::NotEnrolled)),
            "a valid handshake from an un-enrolled key must be refused"
        );
    }
}
