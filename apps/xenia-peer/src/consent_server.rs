// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The daemon's consent server, extracted from the 3000-line `main()` so its
//! reconnect/revoke behavior is **independently testable** (P3 /
//! `MASTER_ROADMAP` #10 — the first daemon-runtime extraction, and the pattern
//! the sealed-channel `--operator-sealed` endpoint will follow).
//!
//! It accepts operator consent connections for the life of one session over a
//! pre-bound listener: the first `Approve`/`Deny` resolves the grant (via a
//! oneshot), and a later `Revoke` — on the still-open socket **or a reconnected
//! one** — flips the shared `revoked` flag. It loops on `accept()` so a dropped
//! console can reconnect and still revoke (the "revocation always nearby"
//! property; see the fix in commit `725741d`). With operator auth on, each
//! decision is a signed, role-authorized action attributed in the ledger; with
//! it off, legacy plaintext `Approve`/`Deny`/`Revoke`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;
use xenia_ledger::Chain;

use crate::operator_auth::ConsentAction;
use crate::operator_http::OperatorAuthState;

/// Whether the accept/serve loop should keep going after a decision.
pub(crate) enum ConsentFollowup {
    /// Non-terminal (an Approve): keep the socket open for a later Revoke.
    KeepServing,
    /// Terminal (Deny or Revoke): stop.
    Stop,
}

/// Apply one decoded consent decision, independent of the transport that
/// delivered it: attribute an authenticated decision in the tamper-evident
/// ledger, resolve the grant exactly once (Approve → true, Deny → false), or
/// set the `revoked` flag. Shared by the plaintext [`ConsentServer`] and the
/// sealed operator channel, so the decision semantics live in one tested place.
pub(crate) async fn apply_consent_decision(
    decoded: crate::DecodedConsent,
    grant_tx: &mut Option<oneshot::Sender<bool>>,
    revoked: &AtomicBool,
    ledger: &Mutex<Chain>,
    session_uuid: Uuid,
) -> ConsentFollowup {
    // Attribute an authenticated decision in the tamper-evident ledger.
    if let Some(authorized) = &decoded.authorized {
        let event = crate::operator_audit::operator_consent_audit_event(
            authorized,
            session_uuid,
            Uuid::new_v4(),
        );
        if let Err(err) = ledger.lock().await.append(event) {
            tracing::warn!(error = %err, "failed to append operator-action audit entry");
        }
    }
    match decoded.action {
        ConsentAction::Approve => {
            tracing::info!(approved = true, "consent decision received");
            if let Some(tx) = grant_tx.take() {
                let _ = tx.send(true);
            }
            ConsentFollowup::KeepServing
        }
        ConsentAction::Deny => {
            tracing::info!(approved = false, "consent decision received");
            if let Some(tx) = grant_tx.take() {
                let _ = tx.send(false);
            }
            ConsentFollowup::Stop
        }
        ConsentAction::Revoke => {
            tracing::info!("consent revocation received");
            revoked.store(true, Ordering::SeqCst);
            ConsentFollowup::Stop
        }
    }
}

/// The consent server for a single session.
pub(crate) struct ConsentServer {
    /// Require signed, role-authorized operator actions (vs legacy plaintext).
    pub(crate) require_operator_auth: bool,
    /// Operator auth surface (policy, daemon key) used to verify signed actions.
    pub(crate) auth_state: Arc<OperatorAuthState>,
    /// This session's id, bound into each per-action signature.
    pub(crate) session_id: [u8; 16],
    /// This session's uuid, used for ledger attribution.
    pub(crate) session_uuid: Uuid,
    /// The tamper-evident consent ledger.
    pub(crate) ledger: Arc<Mutex<Chain>>,
    /// Resolves the initial grant exactly once (Approve → true, Deny → false).
    pub(crate) grant_tx: oneshot::Sender<bool>,
    /// Set true on a Revoke so the main send loop tears the session down.
    pub(crate) revoked: Arc<AtomicBool>,
}

impl ConsentServer {
    /// Run the accept loop over a pre-bound `listener`. Returns when the grant
    /// is denied, the session is revoked, or the listener fails.
    pub(crate) async fn run(self, listener: TcpListener) {
        let ConsentServer {
            require_operator_auth,
            auth_state,
            session_id,
            session_uuid,
            ledger,
            grant_tx,
            revoked,
        } = self;
        let mut grant_tx = Some(grant_tx);

        'accept: loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(error = %err, "consent websocket accept failed");
                    break 'accept;
                }
            };
            let mut ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(err) => {
                    tracing::warn!(error = %err, "consent websocket handshake failed");
                    continue 'accept;
                }
            };
            while let Some(result) = ws_stream.next().await {
                let msg = match result {
                    Ok(msg) => msg,
                    Err(err) => {
                        tracing::warn!(error = %err, "consent websocket receive failed");
                        break;
                    }
                };
                let Ok(text) = msg.to_text() else {
                    continue;
                };
                let Some(decoded) = crate::decode_consent_decision(
                    text,
                    require_operator_auth,
                    &auth_state,
                    &session_id,
                ) else {
                    continue;
                };
                match apply_consent_decision(
                    decoded,
                    &mut grant_tx,
                    &revoked,
                    &ledger,
                    session_uuid,
                )
                .await
                {
                    // Approve keeps the socket open for a later Revoke.
                    ConsentFollowup::KeepServing => {}
                    ConsentFollowup::Stop => break 'accept,
                }
            }
            // The connection ended without a terminal decision (Deny/Revoke):
            // loop back to accept the next socket so a reconnecting operator can
            // still approve a pending grant or revoke a live session.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use futures::SinkExt;
    use tokio::sync::Mutex as TokioMutex;
    use tokio_tungstenite::tungstenite::Message;

    fn test_server(grant_tx: oneshot::Sender<bool>, revoked: Arc<AtomicBool>) -> ConsentServer {
        // Operator auth OFF: the legacy plaintext path, so the test drives it
        // with bare "Approve"/"Deny"/"Revoke" text frames.
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState {
            policy: crate::operator::OperatorPolicy::default(),
            challenges: TokioMutex::new(crate::operator_auth::ChallengeStore::new()),
            daemon_key: daemon.clone(),
            rate_limiter: TokioMutex::new(crate::operator_auth::RateLimiter::new(
                crate::operator_auth::AUTH_RATE_MAX,
                crate::operator_auth::AUTH_RATE_WINDOW_SECS,
            )),
        });
        let ledger = Arc::new(TokioMutex::new(Chain::new(daemon)));
        ConsentServer {
            require_operator_auth: false,
            auth_state,
            session_id: [0x5a; 16],
            session_uuid: Uuid::from_u128(1),
            ledger,
            grant_tx,
            revoked,
        }
    }

    async fn connect(
        addr: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        ws
    }

    // The decision semantics, tested directly (no transport) via the shared
    // helper the sealed operator channel will also use.
    #[tokio::test]
    async fn apply_consent_decision_resolves_grant_and_terminates() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = TokioMutex::new(Chain::new(daemon));
        let uuid = Uuid::from_u128(2);

        // Approve -> grant true, keep serving, no revoke.
        let (tx, rx) = oneshot::channel();
        let mut tx = Some(tx);
        let revoked = AtomicBool::new(false);
        let f = apply_consent_decision(
            crate::DecodedConsent {
                action: ConsentAction::Approve,
                authorized: None,
            },
            &mut tx,
            &revoked,
            &ledger,
            uuid,
        )
        .await;
        assert!(matches!(f, ConsentFollowup::KeepServing));
        assert!(rx.await.unwrap());
        assert!(!revoked.load(Ordering::SeqCst));

        // Revoke -> revoked flag set, terminal.
        let (tx2, _rx2) = oneshot::channel();
        let mut tx2 = Some(tx2);
        let f2 = apply_consent_decision(
            crate::DecodedConsent {
                action: ConsentAction::Revoke,
                authorized: None,
            },
            &mut tx2,
            &revoked,
            &ledger,
            uuid,
        )
        .await;
        assert!(matches!(f2, ConsentFollowup::Stop));
        assert!(revoked.load(Ordering::SeqCst));

        // Deny -> grant false, terminal.
        let (tx3, rx3) = oneshot::channel();
        let mut tx3 = Some(tx3);
        let revoked2 = AtomicBool::new(false);
        let f3 = apply_consent_decision(
            crate::DecodedConsent {
                action: ConsentAction::Deny,
                authorized: None,
            },
            &mut tx3,
            &revoked2,
            &ledger,
            uuid,
        )
        .await;
        assert!(matches!(f3, ConsentFollowup::Stop));
        assert!(!rx3.await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn approve_resolves_the_grant() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        tokio::spawn(test_server(tx, revoked.clone()).run(listener));

        let mut ws = connect(&addr).await;
        ws.send(Message::Text("Approve".into())).await.unwrap();
        assert!(rx.await.unwrap(), "Approve resolves the grant to true");
        assert!(!revoked.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoke_after_reconnect_still_revokes() {
        // The P2 property: Approve on one connection, drop it, reconnect, and a
        // later Revoke still lands (the server loops on accept()).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        tokio::spawn(test_server(tx, revoked.clone()).run(listener));

        // Approve, then drop the socket (end of scope closes the connection).
        {
            let mut ws = connect(&addr).await;
            ws.send(Message::Text("Approve".into())).await.unwrap();
            assert!(rx.await.unwrap());
        }
        // Reconnect and revoke.
        let mut ws2 = connect(&addr).await;
        ws2.send(Message::Text("Revoke".into())).await.unwrap();

        // The revoke flag flips (poll briefly; the server sets it on receive).
        for _ in 0..50 {
            if revoked.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            revoked.load(Ordering::SeqCst),
            "a Revoke after reconnect must still revoke the session"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deny_resolves_the_grant_false() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        tokio::spawn(test_server(tx, revoked.clone()).run(listener));

        let mut ws = connect(&addr).await;
        ws.send(Message::Text("Deny".into())).await.unwrap();
        assert!(!rx.await.unwrap(), "Deny resolves the grant to false");
    }
}
