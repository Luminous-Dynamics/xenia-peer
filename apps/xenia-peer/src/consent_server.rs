// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Plain WebSocket transport for one session's consent authority.
//!
//! This module owns only accept/reconnect behavior. Authorization, revocation,
//! durable audit, and decision semantics live in
//! [`crate::consent_authority::ConsentDecisionService`] and are shared with the
//! sealed operator transport.

use std::sync::Arc;

use futures::StreamExt;
use tokio::net::TcpListener;

use crate::consent_authority::{
    ConsentDecisionService, ConsentFollowup, MAX_CONSENT_ACTION_BYTES,
};

/// The plaintext consent transport for a single session.
pub(crate) struct ConsentServer {
    /// Shared transport-independent consent authority.
    pub(crate) service: Arc<ConsentDecisionService>,
}

impl ConsentServer {
    /// Run the accept loop over a pre-bound `listener`. Returns when the grant
    /// is denied, the session is revoked, or the listener fails.
    pub(crate) async fn run(self, listener: TcpListener) {
        let ConsentServer { service } = self;

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
                if text.len() > MAX_CONSENT_ACTION_BYTES {
                    tracing::warn!(
                        bytes = text.len(),
                        limit = MAX_CONSENT_ACTION_BYTES,
                        "oversized consent action; closing this operator connection"
                    );
                    break;
                }
                let Some(decoded) = service.decode(text) else {
                    continue;
                };
                match service.apply(decoded).await {
                    ConsentFollowup::KeepServing => {}
                    ConsentFollowup::Stop => break 'accept,
                }
            }
            // A dropped console can reconnect and still approve a pending
            // request or revoke an already-approved session.
        }
        service.fail_pending().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use futures::SinkExt;
    use tokio::sync::{Mutex as TokioMutex, oneshot};
    use tokio_tungstenite::tungstenite::Message;
    use uuid::Uuid;
    use xenia_ledger::Chain;

    use crate::consent_authority::{
        ConsentDecisionService, ConsentFollowup, ConsentSessionState, DecodedConsent,
    };
    use crate::operator_auth::ConsentAction;
    use crate::operator_http::OperatorAuthState;

    fn service(
        grant_tx: oneshot::Sender<bool>,
        ledger: Arc<TokioMutex<Chain>>,
        ledger_path: std::path::PathBuf,
        session_uuid: Uuid,
    ) -> Arc<ConsentDecisionService> {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState::new(
            crate::operator::OperatorPolicy::default(),
            daemon,
            xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
            xenia_handshake::HandshakeManager::new(),
            crate::operator_auth::AUTH_RATE_MAX,
            crate::operator_auth::AUTH_RATE_WINDOW_SECS,
        ));
        Arc::new(ConsentDecisionService::new(
            false,
            auth_state,
            xenia_operator_proto::ConsentOfferV2::new(
                *session_uuid.as_bytes(),
                [0x31; 32],
                xenia_operator_proto::ConsentScopeV1::screen_only(),
                1,
                u64::MAX,
            ),
            0,
            crate::operator_revocations::OperatorRevocations::empty(),
            ledger,
            Arc::new(
                crate::consent_ledger_persistence::CompleteConsentLedgerPersister::new(
                    ledger_path,
                ),
            ),
            crate::consent_authority::ConsentHistoricalIndexes::default(),
            grant_tx,
        ))
    }

    fn test_server(
        grant_tx: oneshot::Sender<bool>,
    ) -> (ConsentServer, Arc<ConsentDecisionService>) {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(TokioMutex::new(Chain::new(daemon)));
        let service = service(
            grant_tx,
            ledger,
            std::env::temp_dir().join("xenia-consent-server-test.ledger"),
            Uuid::from_u128(1),
        );
        (
            ConsentServer {
                service: Arc::clone(&service),
            },
            service,
        )
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

    #[tokio::test]
    async fn service_applies_approve_deny_and_revoke() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(TokioMutex::new(Chain::new(daemon)));
        let (approve_tx, approve_rx) = oneshot::channel();
        let service = service(
            approve_tx,
            ledger,
            std::env::temp_dir().join("xenia-consent-decisions-test.ledger"),
            Uuid::from_u128(2),
        );

        let followup = service
            .apply(DecodedConsent {
                action: ConsentAction::Approve,
                authorized: None,
            })
            .await;
        assert!(matches!(followup, ConsentFollowup::KeepServing));
        assert!(approve_rx.await.unwrap());
        assert_eq!(service.state(), ConsentSessionState::Approved);

        let followup = service
            .apply(DecodedConsent {
                action: ConsentAction::Revoke,
                authorized: None,
            })
            .await;
        assert!(matches!(followup, ConsentFollowup::Stop));
        assert!(service.is_session_revoked());

        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let (deny_tx, deny_rx) = oneshot::channel();
        let deny_service = service(
            deny_tx,
            Arc::new(TokioMutex::new(Chain::new(daemon))),
            std::env::temp_dir().join("xenia-consent-deny-test.ledger"),
            Uuid::from_u128(3),
        );
        let followup = deny_service
            .apply(DecodedConsent {
                action: ConsentAction::Deny,
                authorized: None,
            })
            .await;
        assert!(matches!(followup, ConsentFollowup::Stop));
        assert!(!deny_rx.await.unwrap());
        assert_eq!(deny_service.state(), ConsentSessionState::Denied);
    }

    fn authorized_action(action: ConsentAction) -> crate::operator_auth::AuthorizedConsentAction {
        crate::operator_auth::AuthorizedConsentAction {
            action,
            action_id: [0x55; 16],
            offer_digest: [0x66; 32],
            operator_id: "alice".to_string(),
            role: crate::operator::OperatorRole::Admin,
            ed25519_pubkey: [0x11; 32],
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_decision_is_persisted_before_grant() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-consent-service-durable-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ledger_path = dir.join("consent.ledger");
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let (tx, rx) = oneshot::channel();
        let service = service(
            tx,
            Arc::new(TokioMutex::new(Chain::new(daemon))),
            ledger_path.clone(),
            Uuid::from_u128(9),
        );
        let outcome = service
            .apply(DecodedConsent {
                action: ConsentAction::Approve,
                authorized: Some(authorized_action(ConsentAction::Approve)),
            })
            .await;
        assert!(matches!(outcome, ConsentFollowup::KeepServing));
        assert!(rx.await.unwrap());
        let bytes = std::fs::read(&ledger_path).unwrap();
        let entries: Vec<xenia_ledger::LedgerEntry> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(entries.len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_action_closes_only_the_offending_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        let (server, service) = test_server(tx);
        tokio::spawn(server.run(listener));

        let mut oversized = connect(&addr).await;
        oversized
            .send(Message::Text("x".repeat(MAX_CONSENT_ACTION_BYTES + 1).into()))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(service.state(), ConsentSessionState::Pending);

        let mut legitimate = connect(&addr).await;
        legitimate
            .send(Message::Text("Approve".into()))
            .await
            .unwrap();
        assert!(rx.await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn approve_resolves_the_grant() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        let (server, service) = test_server(tx);
        tokio::spawn(server.run(listener));

        let mut ws = connect(&addr).await;
        ws.send(Message::Text("Approve".into())).await.unwrap();
        assert!(rx.await.unwrap());
        assert_eq!(service.state(), ConsentSessionState::Approved);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deny_resolves_the_grant_false() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        let (server, service) = test_server(tx);
        tokio::spawn(server.run(listener));

        let mut ws = connect(&addr).await;
        ws.send(Message::Text("Deny".into())).await.unwrap();
        assert!(!rx.await.unwrap());
        assert_eq!(service.state(), ConsentSessionState::Denied);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoke_after_reconnect_still_revokes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        let (server, service) = test_server(tx);
        tokio::spawn(server.run(listener));

        {
            let mut ws = connect(&addr).await;
            ws.send(Message::Text("Approve".into())).await.unwrap();
            assert!(rx.await.unwrap());
        }
        let mut ws = connect(&addr).await;
        ws.send(Message::Text("Revoke".into())).await.unwrap();
        for _ in 0..50 {
            if service.is_session_revoked() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(service.is_session_revoked());
    }
}
