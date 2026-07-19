// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport-independent consent authorization and decision application.
//!
//! Plain WebSocket consent and the sealed operator channel are only delivery
//! mechanisms. They both hand received text to [`ConsentDecisionService`],
//! which owns the daemon-authoritative offer digest, operator authorization,
//! live operator-revocation checks, durable audit append, and the complete
//! consent-session lifecycle. Keeping those invariants in one service prevents
//! a future transport from accidentally implementing weaker state semantics.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
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

/// Authoritative lifecycle state for one consent ceremony.
///
/// The state machine is deliberately small and terminal-state-heavy:
///
/// - `Pending -> Approved -> Revoked`
/// - `Pending -> Denied`
/// - `Pending -> Failed`
///
/// A revoke received while still pending is treated as a fail-safe denial. A
/// deny received after approval is not silently reinterpreted as revocation;
/// the operator must issue the explicit `Revoke` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ConsentSessionState {
    /// No initial decision has been durably accepted yet.
    Pending = 0,
    /// The initial grant was accepted and the session may run.
    Approved = 1,
    /// The initial grant was explicitly refused.
    Denied = 2,
    /// A previously-approved session was explicitly revoked.
    Revoked = 3,
    /// The ceremony failed before an initial decision could be committed.
    Failed = 4,
}

impl ConsentSessionState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Approved,
            2 => Self::Denied,
            3 => Self::Revoked,
            _ => Self::Failed,
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Denied | Self::Revoked | Self::Failed)
    }
}

/// Whether a transport should remain available after applying a decision.
pub(crate) enum ConsentFollowup {
    /// Approval resolves the initial grant but leaves revocation available.
    KeepServing,
    /// Denial, revocation, failure, or a terminal prior state ends the server.
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
    /// Serializes audit + lifecycle transitions across every transport.
    transition_lock: Mutex<()>,
    /// Lock-free mirror for the runtime's hot-path revocation check.
    state: AtomicU8,
    /// Resolves exactly once when the initial ceremony reaches Approved or
    /// Denied. It is dropped on Failed so the waiter receives channel closure.
    grant_tx: Mutex<Option<oneshot::Sender<bool>>>,
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
        grant_tx: oneshot::Sender<bool>,
    ) -> Self {
        Self {
            require_operator_auth,
            auth_state,
            offer_digest,
            revocations,
            session_uuid,
            ledger,
            ledger_path,
            transition_lock: Mutex::new(()),
            state: AtomicU8::new(ConsentSessionState::Pending as u8),
            grant_tx: Mutex::new(Some(grant_tx)),
            persist_ledger: crate::audit_ledger_store::persist_entries_atomic,
        }
    }

    #[cfg(test)]
    fn with_persist_ledger(mut self, persist_ledger: PersistLedger) -> Self {
        self.persist_ledger = persist_ledger;
        self
    }

    /// Current authoritative session state.
    pub(crate) fn state(&self) -> ConsentSessionState {
        ConsentSessionState::from_u8(self.state.load(Ordering::SeqCst))
    }

    /// Whether the live runtime must stop privileged frame flow.
    pub(crate) fn is_session_revoked(&self) -> bool {
        self.state() == ConsentSessionState::Revoked
    }

    /// Mark a still-pending ceremony failed, dropping the initial decision
    /// sender so the main task cannot wait indefinitely after a transport dies.
    pub(crate) async fn fail_pending(&self) {
        let _transition = self.transition_lock.lock().await;
        if self.state() != ConsentSessionState::Pending {
            return;
        }
        self.state
            .store(ConsentSessionState::Failed as u8, Ordering::SeqCst);
        self.grant_tx.lock().await.take();
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

    /// Apply one authorized decision. Valid authenticated transitions are
    /// durably appended before state or privilege changes; append failure is
    /// fail-closed. The transition lock makes plaintext and sealed delivery
    /// race-safe and prevents duplicate audit entries for replayed decisions.
    pub(crate) async fn apply(&self, decoded: DecodedConsent) -> ConsentFollowup {
        let _transition = self.transition_lock.lock().await;
        let current = self.state();

        let (next, followup, initial_decision) = match (current, decoded.action) {
            (ConsentSessionState::Pending, ConsentAction::Approve) => (
                ConsentSessionState::Approved,
                ConsentFollowup::KeepServing,
                Some(true),
            ),
            (ConsentSessionState::Pending, ConsentAction::Deny) => (
                ConsentSessionState::Denied,
                ConsentFollowup::Stop,
                Some(false),
            ),
            // A pre-grant revoke is fail-safe: no grant can escape, and the
            // waiter receives an explicit negative decision rather than a hang.
            (ConsentSessionState::Pending, ConsentAction::Revoke) => (
                ConsentSessionState::Denied,
                ConsentFollowup::Stop,
                Some(false),
            ),
            (ConsentSessionState::Approved, ConsentAction::Revoke) => (
                ConsentSessionState::Revoked,
                ConsentFollowup::Stop,
                None,
            ),
            // Replays of the already-effective action are idempotent and do not
            // append duplicate audit records.
            (ConsentSessionState::Approved, ConsentAction::Approve) => {
                return ConsentFollowup::KeepServing;
            }
            (ConsentSessionState::Denied, ConsentAction::Deny)
            | (ConsentSessionState::Revoked, ConsentAction::Revoke) => {
                return ConsentFollowup::Stop;
            }
            // Deny after approval is not an alias for revoke; terminal states
            // never reopen, and a failed ceremony accepts no later decisions.
            (state, action) => {
                tracing::warn!(?state, ?action, "consent action invalid for current lifecycle state");
                return if state.is_terminal() {
                    ConsentFollowup::Stop
                } else {
                    ConsentFollowup::KeepServing
                };
            }
        };

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
                self.state
                    .store(ConsentSessionState::Failed as u8, Ordering::SeqCst);
                self.grant_tx.lock().await.take();
                return ConsentFollowup::Stop;
            }
        }

        self.state.store(next as u8, Ordering::SeqCst);
        if let Some(decision) = initial_decision
            && let Some(tx) = self.grant_tx.lock().await.take()
        {
            let _ = tx.send(decision);
        }

        match next {
            ConsentSessionState::Approved => {
                tracing::info!(approved = true, "consent decision committed")
            }
            ConsentSessionState::Denied => {
                tracing::info!(approved = false, "consent decision committed")
            }
            ConsentSessionState::Revoked => tracing::info!("consent revocation committed"),
            ConsentSessionState::Pending | ConsentSessionState::Failed => {}
        }
        followup
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
        Err(AuditLedgerStoreError::Io(std::io::Error::other(
            "forced persistence failure",
        )))
    }

    fn service_with_sender(
        grant_tx: oneshot::Sender<bool>,
        ledger: Arc<Mutex<Chain>>,
    ) -> ConsentDecisionService {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let auth_state = Arc::new(OperatorAuthState::new(
            crate::operator::OperatorPolicy::default(),
            daemon,
            xenia_handshake::MlDsaIdentity::from_seed([0xAA; 32]),
            xenia_handshake::HandshakeManager::new(),
            crate::operator_auth::AUTH_RATE_MAX,
            crate::operator_auth::AUTH_RATE_WINDOW_SECS,
        ));
        ConsentDecisionService::new(
            false,
            auth_state,
            [0; 32],
            OperatorRevocations::empty(),
            Uuid::from_u128(10),
            ledger,
            Arc::new(std::env::temp_dir().join("unused-consent-ledger")),
            grant_tx,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_failure_rolls_back_and_refuses_the_grant() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger.clone()).with_persist_ledger(fail_persist);

        let outcome = service
            .apply(DecodedConsent {
                action: ConsentAction::Approve,
                authorized: Some(authorized_approval()),
            })
            .await;

        assert!(matches!(outcome, ConsentFollowup::Stop));
        assert!(grant_rx.await.is_err(), "the grant must not resolve");
        assert_eq!(service.state(), ConsentSessionState::Failed);
        assert_eq!(ledger.lock().await.len(), 0, "the append must roll back");
    }

    #[tokio::test]
    async fn lifecycle_is_explicit_and_replays_are_idempotent() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger);

        assert_eq!(service.state(), ConsentSessionState::Pending);
        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Approve,
                    authorized: None,
                })
                .await,
            ConsentFollowup::KeepServing
        ));
        assert!(grant_rx.await.unwrap());
        assert_eq!(service.state(), ConsentSessionState::Approved);

        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Approve,
                    authorized: None,
                })
                .await,
            ConsentFollowup::KeepServing
        ));
        assert_eq!(service.state(), ConsentSessionState::Approved);

        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Deny,
                    authorized: None,
                })
                .await,
            ConsentFollowup::KeepServing
        ));
        assert_eq!(service.state(), ConsentSessionState::Approved);

        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Revoke,
                    authorized: None,
                })
                .await,
            ConsentFollowup::Stop
        ));
        assert!(service.is_session_revoked());
    }

    #[tokio::test]
    async fn transport_failure_closes_a_pending_waiter() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger);

        service.fail_pending().await;
        assert_eq!(service.state(), ConsentSessionState::Failed);
        assert!(grant_rx.await.is_err());
    }
}
