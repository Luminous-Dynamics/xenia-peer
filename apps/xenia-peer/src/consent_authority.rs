// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport-independent consent authorization and decision application.
//!
//! Plain WebSocket consent and the sealed operator channel are only delivery
//! mechanisms. They both hand received text to [`ConsentDecisionService`],
//! which owns the complete daemon-authoritative offer, operator authorization,
//! live operator-revocation checks, durable audit append, and the complete
//! consent-session lifecycle. Keeping those invariants in one service prevents
//! a future transport from accidentally implementing weaker state semantics.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, oneshot, watch};
use uuid::Uuid;
use xenia_ledger::{Chain, LedgerEntry};

use crate::audit_ledger_store::AuditLedgerStoreError;
use crate::operator_auth::{AuthorizedConsentAction, ConsentAction};
use crate::operator_http::OperatorAuthState;
use crate::operator_revocations::OperatorRevocations;

type PersistLedger = fn(&std::path::Path, &[LedgerEntry]) -> Result<(), AuditLedgerStoreError>;

/// Maximum decoded consent-action payload accepted by either operator transport.
/// Authenticated requests are only a few kilobytes even with ML-DSA signatures.
pub(crate) const MAX_CONSENT_ACTION_BYTES: usize = 32 * 1024;

/// A decoded consent decision plus authenticated operator attribution, when
/// operator authorization is enabled.
pub(crate) struct DecodedConsent {
    pub(crate) action: ConsentAction,
    pub(crate) authorized: Option<AuthorizedConsentAction>,
}

/// Durable authorization receipt produced only after an authenticated approval
/// has been committed to the daemon ledger. The M1 runtime copies this receipt
/// into its own evidence chain so the operator audit and runtime evidence can be
/// joined by exact action id and offer digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsentApprovalReceipt {
    pub(crate) action_id: [u8; 16],
    pub(crate) offer_digest: [u8; 32],
    pub(crate) operator_id: String,
    pub(crate) operator_ed25519_pubkey: [u8; 32],
    /// Host-local authorization deadline that was active when approval was
    /// durably committed. `None` preserves the historical unlimited-session
    /// behavior. The runtime evidence ledger copies this value so restart or
    /// offline rehydration cannot silently forget a restrictive lease.
    pub(crate) authorization_deadline_unix_secs: Option<u64>,
}

/// Daemon-generated reason for a terminal lifecycle transition that was not
/// itself an authenticated operator action. Each reason is persisted with a
/// stable machine-readable label before or alongside the fail-closed state
/// transition, making automatic termination auditable offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentTerminationReason {
    TransportFailure,
    OfferExpired,
    ApproverRevoked,
    AuthorizationLeaseExpired,
}

impl ConsentTerminationReason {
    const fn stable_name(self) -> &'static str {
        match self {
            Self::TransportFailure => "transport_failure",
            Self::OfferExpired => "offer_expired",
            Self::ApproverRevoked => "approver_revoked",
            Self::AuthorizationLeaseExpired => "authorization_lease_expired",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::TransportFailure => 1,
            Self::OfferExpired => 2,
            Self::ApproverRevoked => 3,
            Self::AuthorizationLeaseExpired => 4,
        }
    }
}

/// Authoritative lifecycle state for one consent ceremony.
///
/// The state machine is deliberately small and terminal-state-heavy:
///
/// - `Pending -> Approved -> Revoked`
/// - `Pending -> Denied`
/// - `Pending -> Failed`
/// - `Pending -> Expired`
/// - `Approved -> LeaseExpired`
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
    /// The daemon-authored approval window elapsed before an initial decision.
    Expired = 5,
    /// A locally configured maximum authorization lifetime elapsed after an
    /// approved session became active. This is a stricter host-side limit, not
    /// an expansion of the operator-signed grant.
    LeaseExpired = 6,
}

impl ConsentSessionState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Approved,
            2 => Self::Denied,
            3 => Self::Revoked,
            4 => Self::Failed,
            5 => Self::Expired,
            6 => Self::LeaseExpired,
            _ => Self::Failed,
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied
                | Self::Revoked
                | Self::Failed
                | Self::Expired
                | Self::LeaseExpired
        )
    }

    /// Stable machine-readable label used when joining consent lifecycle
    /// termination into the independently signed M1 runtime evidence chain.
    pub(crate) const fn stable_name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
            Self::Failed => "failed",
            Self::Expired => "offer_expired",
            Self::LeaseExpired => "authorization_lease_expired",
        }
    }

    /// Parse a label produced by [`Self::stable_name`].
    pub(crate) fn from_stable_name(name: &str) -> Option<Self> {
        match name {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "revoked" => Some(Self::Revoked),
            "failed" => Some(Self::Failed),
            "offer_expired" => Some(Self::Expired),
            "authorization_lease_expired" => Some(Self::LeaseExpired),
            _ => None,
        }
    }

    /// Whether a live M1 runtime must stop privileged work immediately.
    /// Terminal ceremony states are fail-closed. `Pending` is retained only for
    /// the explicitly pre-production auto-consent fixture, whose M1 state is
    /// activated without a transport-delivered consent decision.
    pub(crate) fn runtime_must_stop(self) -> bool {
        self.is_terminal()
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
    /// Complete daemon-authored offer. Keeping the typed offer, rather than
    /// only its digest, lets the authority independently enforce the approval
    /// window and derive the audit session identity from the same signed data.
    offer: xenia_operator_proto::ConsentOfferV2,
    /// Optional host-local maximum lifetime for an approved authorization. A
    /// value of zero preserves historical unlimited-session behavior.
    authorization_lease_secs: u64,
    /// Unix second at which approval was durably committed; zero while no
    /// approval is active. Written before publishing the Approved state.
    approved_at: AtomicU64,
    revocations: OperatorRevocations,
    ledger: Arc<Mutex<Chain>>,
    ledger_path: Arc<PathBuf>,
    /// Serializes audit + lifecycle transitions across every transport.
    transition_lock: Mutex<()>,
    /// Lock-free mirror for synchronous state inspection.
    state: AtomicU8,
    /// Broadcasts every lifecycle transition to live runtime tasks. This lets
    /// input, file-transfer, and media loops stop immediately instead of
    /// discovering revocation on their next polling interval.
    state_tx: watch::Sender<ConsentSessionState>,
    /// Resolves exactly once when the initial ceremony reaches Approved or
    /// Denied. It is dropped on Failed or Expired so the waiter receives
    /// channel closure. An active lease expiry occurs only after this sender
    /// has already resolved and therefore needs no second decision signal.
    grant_tx: Mutex<Option<oneshot::Sender<bool>>>,
    /// Operator whose authenticated approval activated this session. The
    /// approval remains valid only while this identity remains non-revoked.
    approving_operator_id: RwLock<Option<String>>,
    /// Authenticated approval identity available only after durable commit.
    approval_receipt: RwLock<Option<ConsentApprovalReceipt>>,
    /// Authenticated action ids already durably committed for this ceremony.
    /// Kept behind the transition lock so check-and-insert is race-free across
    /// plaintext and sealed transports.
    seen_action_ids: Mutex<HashSet<[u8; 16]>>,
    persist_ledger: PersistLedger,
}

impl ConsentDecisionService {
    /// Construct the single consent authority for a daemon session.
    pub(crate) fn new(
        require_operator_auth: bool,
        auth_state: Arc<OperatorAuthState>,
        offer: xenia_operator_proto::ConsentOfferV2,
        authorization_lease_secs: u64,
        revocations: OperatorRevocations,
        ledger: Arc<Mutex<Chain>>,
        ledger_path: Arc<PathBuf>,
        grant_tx: oneshot::Sender<bool>,
    ) -> Self {
        let (state_tx, _state_rx) = watch::channel(ConsentSessionState::Pending);
        Self {
            require_operator_auth,
            auth_state,
            offer,
            authorization_lease_secs,
            approved_at: AtomicU64::new(0),
            revocations,
            ledger,
            ledger_path,
            transition_lock: Mutex::new(()),
            state: AtomicU8::new(ConsentSessionState::Pending as u8),
            state_tx,
            grant_tx: Mutex::new(Some(grant_tx)),
            approving_operator_id: RwLock::new(None),
            approval_receipt: RwLock::new(None),
            seen_action_ids: Mutex::new(HashSet::new()),
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

    /// Subscribe to authoritative lifecycle changes. The receiver immediately
    /// exposes the current state and then wakes on every later transition.
    pub(crate) fn subscribe_state(&self) -> watch::Receiver<ConsentSessionState> {
        self.state_tx.subscribe()
    }

    /// Return the authenticated approval receipt after it has been durably
    /// committed. Unauthenticated compatibility approvals intentionally return
    /// `None` and therefore cannot claim operator-attributed runtime evidence.
    pub(crate) fn approval_receipt(&self) -> Option<ConsentApprovalReceipt> {
        self.approval_receipt
            .read()
            .map(|receipt| receipt.clone())
            .unwrap_or(None)
    }

    fn publish_state(&self, next: ConsentSessionState) {
        self.state.store(next as u8, Ordering::SeqCst);
        self.state_tx.send_replace(next);
    }

    /// Whether the live runtime must stop privileged frame flow.
    pub(crate) fn is_session_revoked(&self) -> bool {
        self.state() == ConsentSessionState::Revoked
    }

    fn lifecycle_event(
        &self,
        reason: ConsentTerminationReason,
        target: ConsentSessionState,
        approving_operator: Option<&str>,
    ) -> xenia_ledger::ConsentEventRecord {
        let mut id_material = Vec::with_capacity(
            32 + self.offer.session_id.len() + 1 + approving_operator.map(str::len).unwrap_or(0),
        );
        id_material.extend_from_slice(b"xenia-consent-lifecycle-request-v1\0");
        id_material.extend_from_slice(&self.offer.session_id);
        id_material.push(reason.tag());
        if let Some(operator) = approving_operator {
            id_material.extend_from_slice(operator.as_bytes());
        }
        let digest = blake3::hash(&id_material);
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&digest.as_bytes()[..16]);
        xenia_ledger::ConsentEventRecord {
            source_id: self.auth_state.host_identity.identity_public_key_bytes(),
            session_id: Uuid::from_bytes(self.offer.session_id),
            request_id: Uuid::from_bytes(request_id),
            kind: xenia_ledger::ConsentKind::LifecycleTermination,
            scope: format!(
                "xenia-consent-lifecycle-v1;reason={};state={target:?};approver={};offer_digest={}",
                reason.stable_name(),
                approving_operator.unwrap_or("none"),
                hex::encode(self.offer.digest()),
            ),
        }
    }

    async fn persist_lifecycle_transition(
        &self,
        reason: ConsentTerminationReason,
        target: ConsentSessionState,
        approving_operator: Option<&str>,
    ) {
        let event = self.lifecycle_event(reason, target, approving_operator);
        let mut chain = self.ledger.lock().await;
        let committed = chain
            .append_transactional(event, |entries| {
                (self.persist_ledger)(self.ledger_path.as_path(), entries)
            })
            .map(|_entry| ());
        if let Err(err) = committed {
            // Loss of audit durability must never delay a safety transition.
            // The runtime still terminates; the explicit error prevents an
            // operator from mistaking the resulting evidence as complete.
            tracing::error!(
                error = %err,
                reason = reason.stable_name(),
                ?target,
                "consent lifecycle termination could not be durably audited"
            );
        }
    }

    /// Mark a still-pending ceremony failed, dropping the initial decision
    /// sender so the main task cannot wait indefinitely after a transport dies.
    pub(crate) async fn fail_pending(&self) {
        let _transition = self.transition_lock.lock().await;
        if self.state() != ConsentSessionState::Pending {
            return;
        }
        self.persist_lifecycle_transition(
            ConsentTerminationReason::TransportFailure,
            ConsentSessionState::Failed,
            None,
        )
        .await;
        self.publish_state(ConsentSessionState::Failed);
        self.grant_tx.lock().await.take();
    }

    /// Close a still-pending ceremony because its daemon-authored approval
    /// window elapsed. This is distinct from transport failure for lifecycle
    /// diagnostics, while remaining fail-closed to the grant waiter.
    pub(crate) async fn expire_pending(&self) {
        let _transition = self.transition_lock.lock().await;
        if self.state() != ConsentSessionState::Pending {
            return;
        }
        self.persist_lifecycle_transition(
            ConsentTerminationReason::OfferExpired,
            ConsentSessionState::Expired,
            None,
        )
        .await;
        self.publish_state(ConsentSessionState::Expired);
        self.grant_tx.lock().await.take();
    }

    /// Runtime authorization deadline after durable approval, when a local
    /// lease limit is configured. The signed scope is not expanded by this
    /// value; the host is only choosing to terminate authority sooner.
    pub(crate) fn authorization_lease_deadline(&self) -> Option<u64> {
        let approved_at = self.approved_at.load(Ordering::SeqCst);
        (self.authorization_lease_secs > 0 && approved_at > 0)
            .then(|| approved_at.saturating_add(self.authorization_lease_secs))
    }

    /// Terminate an approved session whose host-local authorization lease has
    /// elapsed. Rechecked under the transition lock so an explicit revoke or
    /// other terminal transition wins without duplicate audit events.
    pub(crate) async fn expire_active_lease(&self) -> bool {
        self.expire_active_lease_at(unix_now_secs()).await
    }

    async fn expire_active_lease_at(&self, now: u64) -> bool {
        let _transition = self.transition_lock.lock().await;
        if self.state() != ConsentSessionState::Approved {
            return false;
        }
        let Some(deadline) = self.authorization_lease_deadline() else {
            return false;
        };
        if now < deadline {
            return false;
        }
        let approving_operator = self
            .approving_operator_id
            .read()
            .ok()
            .and_then(|operator| operator.clone());
        self.persist_lifecycle_transition(
            ConsentTerminationReason::AuthorizationLeaseExpired,
            ConsentSessionState::LeaseExpired,
            approving_operator.as_deref(),
        )
        .await;
        self.publish_state(ConsentSessionState::LeaseExpired);
        true
    }

    /// Whether an authenticated operator is currently revoked. Sealed
    /// transports use this immediately after channel authentication, before
    /// reading any action payloads.
    pub(crate) fn is_operator_revoked(&self, operator_id: &str) -> bool {
        self.revocations.is_revoked(operator_id)
    }

    /// Revoke an active session when the operator whose authenticated approval
    /// created the grant has since been revoked. This couples live session
    /// authority to live operator validity rather than treating approval
    /// attribution as historical metadata only.
    pub(crate) async fn revoke_if_approver_revoked(&self) -> bool {
        let _transition = self.transition_lock.lock().await;
        if self.state() != ConsentSessionState::Approved {
            return false;
        }
        let approving_operator = match self.approving_operator_id.read() {
            Ok(operator) => operator.clone(),
            Err(_) => {
                tracing::error!("approving-operator lock poisoned; revoking session fail-closed");
                self.persist_lifecycle_transition(
                    ConsentTerminationReason::ApproverRevoked,
                    ConsentSessionState::Revoked,
                    None,
                )
                .await;
                self.publish_state(ConsentSessionState::Revoked);
                return true;
            }
        };
        let Some(operator_id) = approving_operator else {
            return false;
        };
        if !self.revocations.is_revoked(&operator_id) {
            return false;
        }
        tracing::warn!(operator = %operator_id, "approving operator was revoked; terminating active session");
        self.persist_lifecycle_transition(
            ConsentTerminationReason::ApproverRevoked,
            ConsentSessionState::Revoked,
            Some(&operator_id),
        )
        .await;
        self.publish_state(ConsentSessionState::Revoked);
        true
    }

    /// Decode and authorize a transport-delivered decision. The transport is
    /// deliberately absent from this API: plaintext and sealed callers receive
    /// exactly the same authorization behavior.
    pub(crate) fn decode(&self, text: &str) -> Option<DecodedConsent> {
        self.decode_at(text, unix_now_secs())
    }

    fn decode_at(&self, text: &str, now: u64) -> Option<DecodedConsent> {
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
            if action == ConsentAction::Approve && !self.offer.can_approve_at(now, 0) {
                tracing::warn!("consent approval refused: daemon offer window has expired");
                return None;
            }
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
        if request.action == ConsentAction::Approve && !self.offer.can_approve_at(now, 0) {
            tracing::warn!("consent approval refused: daemon offer window has expired");
            return None;
        }
        let offer_digest = self.offer.digest();
        match crate::operator_auth::authorize_consent_action(
            &self.auth_state.policy,
            &self.auth_state.daemon_key.verifying_key(),
            &self.auth_state.daemon_ml_dsa.public_key_bytes(),
            now,
            &offer_digest,
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
        self.apply_with_commit_clock(decoded, unix_now_secs(), unix_now_secs)
            .await
    }

    async fn apply_at(&self, decoded: DecodedConsent, now: u64) -> ConsentFollowup {
        self.apply_with_commit_clock(decoded, now, move || now).await
    }

    async fn apply_with_commit_clock<F>(
        &self,
        decoded: DecodedConsent,
        now: u64,
        commit_clock: F,
    ) -> ConsentFollowup
    where
        F: FnOnce() -> u64 + Send,
    {
        let _transition = self.transition_lock.lock().await;
        let current = self.state();

        // Authorization is checked again under the transition lock. A valid
        // action can be decoded immediately before its operator is revoked;
        // commit must never rely on the earlier snapshot.
        if let Some(authorized) = &decoded.authorized
            && self.revocations.is_revoked(&authorized.operator_id)
        {
            tracing::warn!(
                operator = %authorized.operator_id,
                action = ?authorized.action,
                "consent action refused at commit: operator was revoked after decode"
            );
            return if current.is_terminal() {
                ConsentFollowup::Stop
            } else {
                ConsentFollowup::KeepServing
            };
        }

        // Recheck under the transition lock. A decision may have been decoded
        // immediately before expiry and then delayed before durable commit.
        if current == ConsentSessionState::Pending
            && decoded.action == ConsentAction::Approve
            && !self.offer.can_approve_at(now, 0)
        {
            tracing::warn!("consent approval refused at commit: daemon offer window expired");
            self.persist_lifecycle_transition(
                ConsentTerminationReason::OfferExpired,
                ConsentSessionState::Expired,
                None,
            )
            .await;
            self.publish_state(ConsentSessionState::Expired);
            self.grant_tx.lock().await.take();
            return ConsentFollowup::Stop;
        }

        if let Some(authorized) = &decoded.authorized {
            if self
                .seen_action_ids
                .lock()
                .await
                .contains(&authorized.action_id)
            {
                tracing::warn!(
                    action_id = %hex::encode(authorized.action_id),
                    action = ?authorized.action,
                    "replayed authenticated consent action ignored"
                );
                return if current.is_terminal() {
                    ConsentFollowup::Stop
                } else {
                    ConsentFollowup::KeepServing
                };
            }

            // The in-memory set provides idempotence during one daemon run.
            // The verified durable ledger is the restart boundary: an action
            // already present there but absent from this process-local set is a
            // stale cross-restart replay, not a retry whose prior lifecycle
            // state we can safely reconstruct.
            let request_id = Uuid::from_bytes(authorized.action_id);
            let already_persisted = self
                .ledger
                .lock()
                .await
                .iter()
                .any(|entry| entry.event.request_id == request_id);
            if already_persisted {
                tracing::error!(
                    action_id = %hex::encode(authorized.action_id),
                    action = ?authorized.action,
                    "durably committed consent action replayed after authority restart; refusing fail-closed"
                );
                if current == ConsentSessionState::Pending {
                    self.publish_state(ConsentSessionState::Failed);
                    self.grant_tx.lock().await.take();
                }
                return ConsentFollowup::Stop;
            }
        }

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
                Uuid::from_bytes(self.offer.session_id),
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
                self.publish_state(ConsentSessionState::Failed);
                self.grant_tx.lock().await.take();
                return ConsentFollowup::Stop;
            }
            self.seen_action_ids
                .lock()
                .await
                .insert(authorized.action_id);
        }

        // Sample the lease epoch only after any authenticated action has been
        // durably committed. A slow fsync therefore cannot consume part of the
        // configured authorization lifetime before the grant exists.
        let approval_committed_at =
            (next == ConsentSessionState::Approved).then(commit_clock);

        if next == ConsentSessionState::Approved {
            let approved_at = approval_committed_at
                .expect("approved transition must sample its durable commit time");
            let approving_operator = decoded
                .authorized
                .as_ref()
                .map(|authorized| authorized.operator_id.clone());
            let authorization_deadline_unix_secs = (self.authorization_lease_secs > 0)
                .then(|| approved_at.saturating_add(self.authorization_lease_secs));
            let approval_receipt = decoded.authorized.as_ref().map(|authorized| {
                ConsentApprovalReceipt {
                    action_id: authorized.action_id,
                    offer_digest: authorized.offer_digest,
                    operator_id: authorized.operator_id.clone(),
                    operator_ed25519_pubkey: authorized.ed25519_pubkey,
                    authorization_deadline_unix_secs,
                }
            });
            match self.approving_operator_id.write() {
                Ok(mut stored) => *stored = approving_operator,
                Err(_) => {
                    tracing::error!("approving-operator lock poisoned; refusing grant fail-closed");
                    self.publish_state(ConsentSessionState::Failed);
                    self.grant_tx.lock().await.take();
                    return ConsentFollowup::Stop;
                }
            }
            match self.approval_receipt.write() {
                Ok(mut stored) => *stored = approval_receipt,
                Err(_) => {
                    tracing::error!("approval-receipt lock poisoned; refusing grant fail-closed");
                    self.publish_state(ConsentSessionState::Failed);
                    self.grant_tx.lock().await.take();
                    return ConsentFollowup::Stop;
                }
            }
        }
        if let Some(approved_at) = approval_committed_at {
            self.approved_at.store(approved_at, Ordering::SeqCst);
        }
        self.publish_state(next);
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
            ConsentSessionState::Pending
            | ConsentSessionState::Failed
            | ConsentSessionState::Expired
            | ConsentSessionState::LeaseExpired => {}
        }
        followup
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;

    fn test_offer(session_uuid: Uuid) -> xenia_operator_proto::ConsentOfferV2 {
        xenia_operator_proto::ConsentOfferV2::new(
            *session_uuid.as_bytes(),
            [0x31; 32],
            xenia_operator_proto::ConsentScopeV1::screen_only(),
            1,
            u64::MAX,
        )
    }

    fn authorized_approval() -> AuthorizedConsentAction {
        AuthorizedConsentAction {
            action: ConsentAction::Approve,
            action_id: [0x44; 16],
            offer_digest: test_offer(Uuid::from_u128(10)).digest(),
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
            test_offer(Uuid::from_u128(10)),
            0,
            OperatorRevocations::empty(),
            ledger,
            Arc::new(
                std::env::temp_dir()
                    .join(format!("unused-consent-ledger-{}", Uuid::new_v4())),
            ),
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
    #[tokio::test]
    async fn expired_offer_rejects_approval_but_still_accepts_fail_safe_denial() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let mut service = service_with_sender(grant_tx, ledger);
        service.offer = xenia_operator_proto::ConsentOfferV2::new(
            *Uuid::from_u128(10).as_bytes(),
            [0x31; 32],
            xenia_operator_proto::ConsentScopeV1::screen_only(),
            100,
            200,
        );

        assert!(service.decode_at("Approve", 201).is_none());
        let denial = service
            .decode_at("Deny", 201)
            .expect("denial must remain available after approval expiry");
        assert!(matches!(
            service.apply_at(denial, 201).await,
            ConsentFollowup::Stop
        ));
        assert!(!grant_rx.await.unwrap());
        assert_eq!(service.state(), ConsentSessionState::Denied);
    }

    #[tokio::test]
    async fn approval_is_rechecked_under_transition_lock() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let mut service = service_with_sender(grant_tx, ledger);
        service.offer = xenia_operator_proto::ConsentOfferV2::new(
            *Uuid::from_u128(10).as_bytes(),
            [0x31; 32],
            xenia_operator_proto::ConsentScopeV1::screen_only(),
            100,
            200,
        );
        let decoded = service
            .decode_at("Approve", 200)
            .expect("approval is valid at the final offered second");

        assert!(matches!(
            service.apply_at(decoded, 201).await,
            ConsentFollowup::Stop
        ));
        assert_eq!(service.state(), ConsentSessionState::Expired);
        assert!(grant_rx.await.is_err(), "an expired grant must not resolve");
    }

    #[tokio::test]
    async fn approved_session_can_still_be_revoked_after_offer_expiry() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let mut service = service_with_sender(grant_tx, ledger);
        service.offer = xenia_operator_proto::ConsentOfferV2::new(
            *Uuid::from_u128(10).as_bytes(),
            [0x31; 32],
            xenia_operator_proto::ConsentScopeV1::screen_only(),
            100,
            200,
        );

        assert!(matches!(
            service
                .apply_at(
                    DecodedConsent {
                        action: ConsentAction::Approve,
                        authorized: None,
                    },
                    200,
                )
                .await,
            ConsentFollowup::KeepServing
        ));
        assert!(grant_rx.await.unwrap());
        assert!(matches!(
            service
                .apply_at(
                    DecodedConsent {
                        action: ConsentAction::Revoke,
                        authorized: None,
                    },
                    201,
                )
                .await,
            ConsentFollowup::Stop
        ));
        assert_eq!(service.state(), ConsentSessionState::Revoked);
    }

    #[tokio::test]
    async fn explicit_timeout_marks_pending_ceremony_expired() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger);

        service.expire_pending().await;
        assert_eq!(service.state(), ConsentSessionState::Expired);
        assert!(grant_rx.await.is_err());
        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Approve,
                    authorized: None,
                })
                .await,
            ConsentFollowup::Stop
        ));
    }

    #[tokio::test]
    async fn operator_revoked_after_decode_cannot_commit_approval() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, mut grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger.clone());
        service.revocations.revoke("alice");

        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Approve,
                    authorized: Some(authorized_approval()),
                })
                .await,
            ConsentFollowup::KeepServing
        ));
        assert_eq!(service.state(), ConsentSessionState::Pending);
        assert_eq!(ledger.lock().await.len(), 0);
        assert!(grant_rx.try_recv().is_err(), "grant must remain unresolved");
    }

    #[tokio::test]
    async fn revoking_the_approving_operator_revokes_the_active_session() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger);

        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Approve,
                    authorized: Some(authorized_approval()),
                })
                .await,
            ConsentFollowup::KeepServing
        ));
        assert!(grant_rx.await.unwrap());
        service.revocations.revoke("alice");
        assert!(service.revoke_if_approver_revoked().await);
        assert_eq!(service.state(), ConsentSessionState::Revoked);
    }

    #[tokio::test]
    async fn lifecycle_subscribers_observe_approval_and_revocation() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger);
        let mut states = service.subscribe_state();

        assert_eq!(*states.borrow(), ConsentSessionState::Pending);
        assert!(!states.borrow().runtime_must_stop());
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
        states.changed().await.unwrap();
        assert_eq!(*states.borrow(), ConsentSessionState::Approved);
        assert!(!states.borrow().runtime_must_stop());

        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Revoke,
                    authorized: None,
                })
                .await,
            ConsentFollowup::Stop
        ));
        states.changed().await.unwrap();
        assert_eq!(*states.borrow(), ConsentSessionState::Revoked);
        assert!(states.borrow().runtime_must_stop());
    }

    #[tokio::test]
    async fn persisted_action_id_replay_after_restart_is_refused_fail_closed() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let authorized = authorized_approval();
        ledger
            .lock()
            .await
            .append(crate::operator_audit::operator_consent_audit_event(
                &authorized,
                Uuid::from_u128(10),
            ))
            .unwrap();
        let original_len = ledger.lock().await.len();
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger.clone());

        assert!(matches!(
            service
                .apply(DecodedConsent {
                    action: ConsentAction::Approve,
                    authorized: Some(authorized),
                })
                .await,
            ConsentFollowup::Stop
        ));
        assert_eq!(service.state(), ConsentSessionState::Failed);
        assert!(grant_rx.await.is_err());
        assert_eq!(ledger.lock().await.len(), original_len);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_action_id_replay_is_not_reaudited() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-consent-replay-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let mut service = service_with_sender(grant_tx, ledger.clone());
        service.ledger_path = Arc::new(dir.join("consent.ledger"));

        let first = service
            .apply(DecodedConsent {
                action: ConsentAction::Approve,
                authorized: Some(authorized_approval()),
            })
            .await;
        assert!(matches!(first, ConsentFollowup::KeepServing));
        assert!(grant_rx.await.unwrap());
        let receipt = service.approval_receipt().expect("authenticated receipt");
        assert_eq!(receipt.action_id, [0x44; 16]);
        assert_eq!(receipt.operator_id, "alice");
        assert_eq!(receipt.authorization_deadline_unix_secs, None);
        assert_eq!(ledger.lock().await.len(), 1);

        let replay = service
            .apply(DecodedConsent {
                action: ConsentAction::Approve,
                authorized: Some(authorized_approval()),
            })
            .await;
        assert!(matches!(replay, ConsentFollowup::KeepServing));
        assert_eq!(ledger.lock().await.len(), 1, "replay must not append");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn automatic_terminal_transitions_are_durably_attributed_to_the_daemon() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let service = service_with_sender(grant_tx, ledger.clone());

        service.fail_pending().await;
        assert!(grant_rx.await.is_err());
        let entries = ledger.lock().await.iter().cloned().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].event.kind,
            xenia_ledger::ConsentKind::LifecycleTermination
        );
        assert!(entries[0].event.scope.contains("reason=transport_failure"));
        assert_eq!(
            entries[0].event.source_id,
            service.auth_state.host_identity.identity_public_key_bytes()
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_authorization_lease_terminates_an_approved_session() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger = Arc::new(Mutex::new(Chain::new(daemon)));
        let (grant_tx, grant_rx) = oneshot::channel();
        let mut service = service_with_sender(grant_tx, ledger.clone());
        service.authorization_lease_secs = 10;

        assert!(matches!(
            service
                .apply_at(
                    DecodedConsent {
                        action: ConsentAction::Approve,
                        authorized: Some(authorized_approval()),
                    },
                    100,
                )
                .await,
            ConsentFollowup::KeepServing
        ));
        assert!(grant_rx.await.unwrap());
        assert_eq!(service.authorization_lease_deadline(), Some(110));
        assert_eq!(
            service
                .approval_receipt()
                .expect("authenticated approval receipt")
                .authorization_deadline_unix_secs,
            Some(110)
        );
        assert!(!service.expire_active_lease_at(109).await);
        assert!(service.expire_active_lease_at(110).await);
        assert_eq!(service.state(), ConsentSessionState::LeaseExpired);

        let entries = ledger.lock().await.iter().cloned().collect::<Vec<_>>();
        assert!(entries.iter().any(|entry| {
            entry.event.kind == xenia_ledger::ConsentKind::LifecycleTermination
                && entry
                    .event
                    .scope
                    .contains("reason=authorization_lease_expired")
        }));
    }
}
