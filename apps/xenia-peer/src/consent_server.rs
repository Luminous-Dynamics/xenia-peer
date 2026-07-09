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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;
use xenia_ledger::Chain;

use crate::operator_auth::ConsentAction;
use crate::operator_http::OperatorAuthState;

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
                // Attribute an authenticated decision in the tamper-evident
                // ledger.
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
                        // Keep the socket open: the operator can still send
                        // "Revoke" to end the live session.
                    }
                    ConsentAction::Deny => {
                        tracing::info!(approved = false, "consent decision received");
                        if let Some(tx) = grant_tx.take() {
                            let _ = tx.send(false);
                        }
                        break 'accept;
                    }
                    ConsentAction::Revoke => {
                        tracing::info!("consent revocation received");
                        revoked.store(true, Ordering::SeqCst);
                        break 'accept;
                    }
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
