// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport-independent consent authorization and decision application.
//!
//! Plain WebSocket consent and the sealed operator channel are only delivery
//! mechanisms. They both hand received text to [`ConsentDecisionService`],
//! which owns the daemon-authoritative offer digest, operator authorization,
//! live revocation check, durable audit append, and exactly-once grant/revoke
//! state transition. Keeping those invariants in one service prevents a future
//! transport from accidentally implementing weaker consent semantics.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;
use xenia_ledger::{Chain, LedgerEntry};

use crate::audit_ledger_store::AuditLedgerStoreError;
use crate::operator_auth::{AuthorizedConsentAction, ConsentAction};
use crate::operator_http::OperatorAuthState;
use crate::operator_revocations::OperatorRevocations;

type PersistLedger = fn(&std::path::Path, &[LedgerEntry]) -> Result<(), AuditLedgerStoreError>;

/// A decoded consent decision plus authenticated operator attribution, when
/// operator authorization is enabled.
pub(crate) struct DecodedConsent {
    pub(crate) action: ConsentAction,
    pub(crate) authorized: Option<AuthorizedConsentAction>,
}

/// Whether a transport should remain available after applying a decision.
pub(crate) enum ConsentFollowup {
    /// Approval resolves the initial grant but leaves revocation available.
    KeepServing,
    /// Denial, revocation, or a failed durable audit append is terminal.
    Stop,
}

/// Session-scoped authority shared by every consent transport.
pub(crate) struct ConsentDecisionService {
    require_operator_auth: bool,
    auth_state: Arc<OperatorAuthState>,
    /// Digest of the daemon-attested offer authored for this session.
    offer_digest: [u8; 32],
    revocations: OperatorRevocations,
    session_uuid: Uuid,
    ledger: Arc<Mutex<Chain>>,
    ledger_path: Arc<PathBuf>,
    revoked: Arc<AtomicBool>,
    persist_ledger: PersistLedger,
}

impl ConsentDecisionService {
    /// Construct the single consent authority for a daemon session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        require_operator_auth: bool,
        auth_state: Arc<OperatorAuthState>,
        offer_digest: [u8; 32],
        revocations: OperatorRevocations,
        session_uuid: Uuid,
        ledger: Arc<Mutex<Chain>>,
        ledger_path: Arc<PathBuf>,
        revoked: Arc<AtomicBool>,
    ) -> Self {
        Self {
            require_operator_auth,
            auth_state,
            offer_digest,
            revocations,
            session_uuid,
            ledger,
            ledger_path,
            revoked,
            persist_ledger: crate::audit_ledger_store::persist_entries_atomic,
        }
    }

    #[cfg(test)]
    fn with_persist_ledger(mut self, persist_ledger: PersistLedger) -> Self {
        self.persist_ledger = persist_ledger;
        self
    }

    /// Whether an authenticated operator is currently revoked. Sealed
    /// transports use this immediately after channel authentication, before
    /// reading any action payloads.
    pub(crate) fn is_operator_revoked(&self, operator_id: &str) -> bool {
        self.revocations.is_revoked(operator_id)
    }

    /// Decode and authorize a transport-delivered decision. The transport is
    /// deliberately absent from this API: plaintext and sealed callers receive
    /// exactly the same authorization behavior.
    pub(crate) fn decode(&self, text: &str) -> Option<DecodedConsent> {
        if !self.require_operator_auth {
            let action = match text {
                "Approve" => ConsentAction::Approve,
                "Deny" => ConsentAction::Deny,
                "Revoke" => ConsentAction::Revoke,
                other => {
                    tracing::info!(text = other, "ignoring unrecognized consent message");
                    return None;
                }
            };
            return Some(DecodedConsent {
                action,
                authorized: None,
            });
        }

        let request = match crate::operator_http::parse_authenticated_consent_action(text) {
            Ok(request) => request,
            Err(err) => {
                tracing::warn!(error = %err, "malformed authenticated consent action; refused");
                return None;
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        match crate::operator_auth::authorize_consent_action(
            &self.auth_state.policy,
            &self.auth_state.daemon_key.verifying_key(),
            &self.auth_state.daemon_ml_dsa.public_key_bytes(),
            now,
            &self.offer_digest,
            &request,
        ) {
            Ok(authorized) => {
                if self.revocations.is_revoked(&authorized.operator_id) {
                    tracing::warn!(
                        operator = %authorized.operator_id,
                        "consent action refused: operator revoked"
                    );
                    return None;
                }
                tracing::info!(
                    operator = %authorized.operator_id,
                    role = ?authorized.role,
                    action = ?authorized.action,
                    "authenticated consent action authorized"
                );
                Some(DecodedConsent {
                    action: authorized.action,
                    authorized: Some(authorized),
                })
            }
            Err(err) => {
                tracing::warn!(error = %err, "consent action refused by operator auth");
                None
            }
        }
    }

    /// Apply one authorized decision. Authenticated actions are durably
    /// appended before privilege takes effect; append failure is fail-closed.
    pub(crate) async fn apply(
        &self,
        decoded: DecodedConsent,
        grant_tx: &mut Option<oneshot::Sender<bool>>,
    ) -> ConsentFollowup {
        if let Some(authorized) = &decoded.authorized {
            let event = crate::operator_audit::operator_consent_audit_event(
                authorized,
                self.session_uuid,
                Uuid::new_v4(),
            );
            let mut chain = self.ledger.lock().await;
            let committed = tokio::task::block_in_place(|| {
                chain
                    .append_transactional(event, |entries| {
                        (self.persist_ledger)(self.ledger_path.as_path(), entries)
                    })
                    .map(|_entry| ())
            });
            drop(chain);
            if let Err(err) = committed {
                tracing::error!(
                    error = %err,
                    "operator action refused: its audit entry could not be durably committed"
                );
                return ConsentFollowup::Stop;
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
                self.revoked.store(true, Ordering::SeqCst);
                ConsentFollowup::Stop
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;

    fn authorized_approval() -> AuthorizedConsentAction {
        AuthorizedConsentAction {
            action: ConsentAction::Approve,
            operator_id: "alice".to_string(),
            role: crate::operator::OperatorRole::Admin,
            ed25519_pubkey: [0x11; 32],
        }
    }

    fn fail_persist(
        _path: &std::path::Path,
        _entries: &[LedgerEntry],
    ) -> Result<(), AuditLedgerStoreError> {
        Err(AuditLedgerStoreError::Io(std::io::Error::other("forced persistence failure")))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_failure_rolls_back_and_refuses_the_grant() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon.clone())));
        let auth_state = Arc::new(OperatorAuthState::new(
            crate::operator::OperatorPolicy::default(),
            daemon,
            xenia_handshake::MlDsaIdentity::from_seed([0xAA; 32]),
            xenia_handshake::HandshakeManager::new(),
            crate::operator_auth::AUTH_RATE_MAX,
            crate::operator_auth::AUTH_RATE_WINDOW_SECS,
        ));
        let service = ConsentDecisionService::new(
            false,
            auth_state,
            [0; 32],
            OperatorRevocations::empty(),
            Uuid::from_u128(10),
            ledger.clone(),
            Arc::new(std::env::temp_dir().join("unused-consent-ledger")),
            Arc::new(AtomicBool::new(false)),
        )
        .with_persist_ledger(fail_persist);

        let (grant_tx, grant_rx) = oneshot::channel();
        let mut grant_tx = Some(grant_tx);
        let outcome = service
            .apply(
                DecodedConsent {
                    action: ConsentAction::Approve,
                    authorized: Some(authorized_approval()),
                },
                &mut grant_tx,
            )
            .await;

        assert!(matches!(outcome, ConsentFollowup::Stop));
        drop(grant_tx);
        assert!(grant_rx.await.is_err(), "the grant must not resolve");
        assert_eq!(ledger.lock().await.len(), 0, "the append must roll back");
    }
}
