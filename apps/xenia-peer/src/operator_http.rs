// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP surface for operator authentication (Phase 3a of
//! `docs/security/OPERATOR_RBAC_PLAN.md`).
//!
//! Two additive routes on the admin-port router:
//!   * `POST /auth/challenge` -> issues a single-use nonce.
//!   * `POST /auth/verify`    -> verifies a challenge response (both
//!     signatures + enrollment) and returns a daemon-signed, role-scoped
//!     token.
//!
//! The handlers are thin: they decode hex, call the already-tested pure core
//! in [`crate::operator_auth`], and encode the result. They add a real
//! operator-authentication surface without changing any existing behavior --
//! enforcement of the returned token on privileged actions is Phase 3b.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, MlDsaIdentity};
use xenia_ledger::{Chain, LedgerCheckpoint, LedgerEntry};
use xenia_operator_proto::{DaemonIdentityCertificate, challenge_host_attestation_transcript};

use crate::operator::{OperatorPolicy, OperatorRole};
use crate::operator_auth::{
    AuthenticatedConsentAction, AuthenticatedRevocation, CHALLENGE_TTL_SECS, ChallengeResponse,
    ChallengeStore, ConsentAction, OperatorToken, RateLimiter, SignedOperatorToken, TOKEN_TTL_SECS,
    issue_token, verify_challenge_response,
};
use crate::operator_revocations::OperatorRevocations;

/// Shared state for the operator-auth routes.
pub(crate) struct OperatorAuthState {
    pub(crate) policy: OperatorPolicy,
    pub(crate) challenges: Mutex<ChallengeStore>,
    /// The daemon's own signing key, used to sign issued tokens. Also the
    /// key `xenia_ledger::Chain` signs the consent hash-chain with -- it
    /// predates hybridization and stays Ed25519-only; see
    /// `daemon_ml_dsa`'s doc comment for why the ML-DSA half lives in a
    /// separate key rather than being folded in here.
    pub(crate) daemon_key: SigningKey,
    /// The daemon's HTTP-auth ML-DSA-65 identity: a *separate* key from
    /// `daemon_key`, signing the exact same bytes `daemon_key` signs
    /// (issued tokens, challenge/consent-action/revoke transcripts) as a
    /// second, independently-verified algorithm -- AND-verified together,
    /// no classical-only fallback, matching this project's hybrid posture
    /// everywhere else. Kept separate from `daemon_key` rather than
    /// bolted onto it because `daemon_key` already has an established,
    /// independently-used role (the ledger's signing key) that
    /// hybridizing shouldn't disturb.
    pub(crate) daemon_ml_dsa: MlDsaIdentity,
    /// Bounds auth attempts against brute-force / flooding.
    pub(crate) rate_limiter: Mutex<RateLimiter>,
    /// The daemon's *host* identity (the same one the sealed-channel
    /// handshake uses and `host_pin.rs`/`host_trust.rs` pin) -- used to
    /// sign each challenge's host attestation at issuance time. Kept
    /// separate from `daemon_key`/`daemon_ml_dsa`; see
    /// [`DaemonIdentityCertificate`]'s doc comment for why the three
    /// aren't unified.
    pub(crate) host_identity: HandshakeManager,
    /// Host identity's delegation of trust to `daemon_key`/`daemon_ml_dsa`,
    /// computed once at startup and served verbatim over
    /// `GET /auth/daemon-identity`.
    pub(crate) daemon_certificate: DaemonIdentityCertificate,
}

impl OperatorAuthState {
    /// Build a state, computing `daemon_certificate` from `host_identity`,
    /// `daemon_key`, and `daemon_ml_dsa` once here (all three are static
    /// for the state's lifetime, so there's no reason to recompute it per
    /// request). The single constructor keeps every call site (`main.rs`'s
    /// real daemon bootstrap, and the several test harnesses across this
    /// crate) from having to know how the certificate is built.
    pub(crate) fn new(
        policy: OperatorPolicy,
        daemon_key: SigningKey,
        daemon_ml_dsa: MlDsaIdentity,
        host_identity: HandshakeManager,
        rate_limit_max: u32,
        rate_limit_window_secs: u64,
    ) -> Self {
        let http_auth_ed_pubkey = daemon_key.verifying_key().to_bytes();
        let http_auth_ml_dsa_pubkey = daemon_ml_dsa.public_key_bytes();
        let transcript = xenia_operator_proto::daemon_delegation_transcript(
            &http_auth_ed_pubkey,
            &http_auth_ml_dsa_pubkey,
        );
        let daemon_certificate = DaemonIdentityCertificate {
            host_ed25519_pubkey: hex::encode(host_identity.identity_public_key_bytes()),
            host_ml_dsa_pubkey: hex::encode(host_identity.ml_dsa_public_key_bytes()),
            http_auth_ed25519_pubkey: hex::encode(http_auth_ed_pubkey),
            http_auth_ml_dsa_pubkey: hex::encode(http_auth_ml_dsa_pubkey),
            host_ed_signature: hex::encode(host_identity.sign(&transcript).to_bytes()),
            host_ml_dsa_signature: hex::encode(host_identity.sign_ml_dsa(&transcript)),
        };
        Self {
            policy,
            challenges: Mutex::new(ChallengeStore::new()),
            daemon_key,
            daemon_ml_dsa,
            rate_limiter: Mutex::new(RateLimiter::new(rate_limit_max, rate_limit_window_secs)),
            host_identity,
            daemon_certificate,
        }
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Serialize)]
struct ChallengeResponseDto {
    nonce: String,
    expires_at: u64,
    /// Host identity's Ed25519 signature over
    /// `challenge_host_attestation_transcript(nonce)`, hex -- proof this
    /// *specific* nonce was really issued by this daemon's attested host
    /// identity, so a caller with no live connection to the daemon (the
    /// operator agent) can verify it rather than trust a bare label. New
    /// field, additive -- existing callers that only read `nonce`/
    /// `expires_at` are unaffected.
    host_ed_attestation_hex: String,
    /// Host identity's ML-DSA-65 signature over the same transcript, hex.
    host_ml_dsa_attestation_hex: String,
}

#[derive(Deserialize)]
struct VerifyRequestDto {
    nonce: String,
    ed_pubkey: String,
    ml_dsa_pubkey: String,
    ed_signature: String,
    ml_dsa_signature: String,
}

#[derive(Serialize, Deserialize)]
struct TokenDto {
    operator_id: String,
    role: OperatorRole,
    issued_at: u64,
    expires_at: u64,
    token_nonce: String,
    signature: String,
    /// Hex ML-DSA-65 signature over the same canonical bytes `signature`
    /// covers -- both are required, no classical-only fallback.
    ml_dsa_signature: String,
}

impl TokenDto {
    fn from_signed(signed: &SignedOperatorToken) -> Self {
        Self {
            operator_id: signed.token.operator_id.clone(),
            role: signed.token.role,
            issued_at: signed.token.issued_at,
            expires_at: signed.token.expires_at,
            token_nonce: hex::encode(signed.token.token_nonce),
            signature: hex::encode(signed.signature),
            ml_dsa_signature: hex::encode(signed.ml_dsa_signature),
        }
    }
}

/// `POST /auth/challenge` -- issue a fresh single-use challenge, host-
/// attested so a caller with no live connection to the daemon can verify
/// this exact nonce was really issued by an attested host identity.
async fn challenge_handler(
    State(state): State<Arc<OperatorAuthState>>,
) -> Json<ChallengeResponseDto> {
    let now = unix_now_secs();
    let nonce: [u8; 32] = rand::random();
    {
        let mut challenges = state.challenges.lock().await;
        challenges.gc(now);
        challenges.issue(nonce, now, CHALLENGE_TTL_SECS);
    }
    let attestation_transcript = challenge_host_attestation_transcript(&nonce);
    Json(ChallengeResponseDto {
        nonce: hex::encode(nonce),
        expires_at: now + CHALLENGE_TTL_SECS,
        host_ed_attestation_hex: hex::encode(
            state.host_identity.sign(&attestation_transcript).to_bytes(),
        ),
        host_ml_dsa_attestation_hex: hex::encode(
            state.host_identity.sign_ml_dsa(&attestation_transcript),
        ),
    })
}

/// `GET /auth/daemon-identity` -- the daemon's host-identity delegation of
/// trust to its separate HTTP-auth signing key. No authentication required:
/// this *is* the daemon's own public, independently-verifiable identity
/// evidence -- the same trust model as the sealed-channel handshake's host
/// identity, which any peer can already learn by connecting.
async fn daemon_identity_handler(
    State(state): State<Arc<OperatorAuthState>>,
) -> Json<DaemonIdentityCertificate> {
    Json(state.daemon_certificate.clone())
}

fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], (StatusCode, String)> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("expected {N} hex bytes")))
}

/// `POST /auth/verify` -- verify a challenge response and mint a token.
async fn verify_handler(
    State(state): State<Arc<OperatorAuthState>>,
    Json(req): Json<VerifyRequestDto>,
) -> Result<Json<TokenDto>, (StatusCode, String)> {
    // Rate-limit auth attempts before doing any (relatively expensive)
    // signature verification, to bound brute-force / flooding.
    if !state.rate_limiter.lock().await.allow(unix_now_secs()) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many authentication attempts; slow down".to_string(),
        ));
    }
    let nonce = decode_fixed::<32>(&req.nonce)?;
    let ed_pubkey = decode_fixed::<32>(&req.ed_pubkey)?;
    let ed_signature = decode_fixed::<64>(&req.ed_signature)?;
    let ml_dsa_signature = decode_fixed::<ML_DSA_65_SIG_LEN>(&req.ml_dsa_signature)?;
    let ml_dsa_pubkey = hex::decode(req.ml_dsa_pubkey.trim())
        .ok()
        .filter(|b| b.len() == ML_DSA_65_PK_LEN)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("ml_dsa_pubkey must be {ML_DSA_65_PK_LEN} hex bytes"),
            )
        })?;

    let response = ChallengeResponse {
        nonce,
        ed_pubkey,
        ml_dsa_pubkey,
        ed_signature,
        ml_dsa_signature,
    };

    let now = unix_now_secs();
    let authed = {
        let mut challenges = state.challenges.lock().await;
        verify_challenge_response(&state.policy, &mut challenges, now, &response)
            // Auth failures are 401; do not leak which step failed beyond the
            // stable Display text.
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?
    };

    let token_nonce: [u8; 16] = rand::random();
    let signed = issue_token(
        &state.daemon_key,
        &state.daemon_ml_dsa,
        &authed,
        now,
        TOKEN_TTL_SECS,
        token_nonce,
    );
    Ok(Json(TokenDto::from_signed(&signed)))
}

impl TokenDto {
    /// Reconstruct a `SignedOperatorToken` from the wire form (reverse of
    /// [`Self::from_signed`]). Used when parsing an authenticated consent
    /// action off the consent socket.
    fn into_signed(self) -> Result<SignedOperatorToken, String> {
        Ok(SignedOperatorToken {
            token: OperatorToken {
                operator_id: self.operator_id,
                role: self.role,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                token_nonce: decode_fixed::<16>(&self.token_nonce).map_err(|(_, m)| m)?,
            },
            signature: decode_fixed::<64>(&self.signature).map_err(|(_, m)| m)?,
            ml_dsa_signature: decode_fixed::<ML_DSA_65_SIG_LEN>(&self.ml_dsa_signature)
                .map_err(|(_, m)| m)?,
        })
    }
}

/// The JSON an operator sends on the consent port when
/// `--require-operator-auth` is on.
#[derive(Deserialize)]
struct AuthenticatedConsentActionDto {
    token: TokenDto,
    /// `"Approve"`, `"Deny"`, or `"Revoke"`.
    action: String,
    action_signature: String,
    /// Hex ML-DSA-65 signature over the same transcript `action_signature`
    /// covers -- both required.
    ml_dsa_action_signature: String,
}

/// Parse a JSON authenticated consent action from the consent socket into the
/// verifiable [`AuthenticatedConsentAction`]. Decode/shape errors only -- the
/// cryptographic authorization is [`crate::operator_auth::authorize_consent_action`].
pub(crate) fn parse_authenticated_consent_action(
    json: &str,
) -> Result<AuthenticatedConsentAction, String> {
    let dto: AuthenticatedConsentActionDto =
        serde_json::from_str(json).map_err(|e| e.to_string())?;
    let action = match dto.action.as_str() {
        "Approve" => ConsentAction::Approve,
        "Deny" => ConsentAction::Deny,
        "Revoke" => ConsentAction::Revoke,
        other => return Err(format!("unknown consent action: {other:?}")),
    };
    let action_signature = decode_fixed::<64>(&dto.action_signature).map_err(|(_, m)| m)?;
    let ml_dsa_action_signature =
        decode_fixed::<ML_DSA_65_SIG_LEN>(&dto.ml_dsa_action_signature).map_err(|(_, m)| m)?;
    Ok(AuthenticatedConsentAction {
        token: dto.token.into_signed()?,
        action,
        action_signature,
        ml_dsa_action_signature,
    })
}

/// Wire form of an admin's operator-revocation request:
/// `{ token, target_operator_id, action_signature, ml_dsa_action_signature }`.
#[derive(Deserialize)]
struct AuthenticatedRevocationDto {
    token: TokenDto,
    target_operator_id: String,
    /// Hex Ed25519 signature over `revoke_operator_transcript(target, token_nonce)`.
    action_signature: String,
    /// Hex ML-DSA-65 signature over the same transcript -- both required.
    ml_dsa_action_signature: String,
}

/// Parse the JSON body of a `/operator/revoke` request into an
/// [`AuthenticatedRevocation`], mirroring [`parse_authenticated_consent_action`].
pub(crate) fn parse_authenticated_revocation(
    json: &str,
) -> Result<AuthenticatedRevocation, String> {
    let dto: AuthenticatedRevocationDto = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let action_signature = decode_fixed::<64>(&dto.action_signature).map_err(|(_, m)| m)?;
    let ml_dsa_action_signature =
        decode_fixed::<ML_DSA_65_SIG_LEN>(&dto.ml_dsa_action_signature).map_err(|(_, m)| m)?;
    Ok(AuthenticatedRevocation {
        token: dto.token.into_signed()?,
        target_operator_id: dto.target_operator_id,
        action_signature,
        ml_dsa_action_signature,
    })
}

/// State for privileged admin mutation routes that need both the auth state and
/// the live revocation list.
#[derive(Clone)]
struct AdminMutationState {
    auth: Arc<OperatorAuthState>,
    revocations: OperatorRevocations,
}

/// `POST /operator/revoke` — an authenticated `Admin` revokes another operator
/// live (no restart). Fail-closed: only a valid, unexpired, `Admin`-role token
/// whose per-action signature verifies over the exact target may revoke; every
/// auth failure returns `403` without disclosing which check failed.
async fn revoke_operator_handler(
    State(state): State<AdminMutationState>,
    body: String,
) -> Result<StatusCode, (StatusCode, String)> {
    let request = parse_authenticated_revocation(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed revocation request: {e}"),
        )
    })?;
    match crate::operator_auth::authorize_operator_revocation(
        &state.auth.policy,
        &state.auth.daemon_key.verifying_key(),
        &state.auth.daemon_ml_dsa.public_key_bytes(),
        unix_now_secs(),
        &request,
    ) {
        Ok(authorized) => {
            state.revocations.revoke(&authorized.target_operator_id);
            tracing::warn!(
                target = %authorized.target_operator_id,
                by = %authorized.operator_id,
                "operator revoked via admin endpoint"
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(err) => {
            tracing::warn!(error = %err, "operator revocation refused");
            Err((StatusCode::FORBIDDEN, "revocation refused".to_string()))
        }
    }
}

/// State for the `/v1/audit/*` routes: the auth state (token/role
/// verification) plus the live ledger to read from.
#[derive(Clone)]
struct AuditState {
    auth: Arc<OperatorAuthState>,
    ledger: Arc<Mutex<Chain>>,
}

/// State for `GET /health`: just enough to report liveness, no auth state.
#[derive(Clone)]
struct HealthState {
    started_at: std::time::Instant,
    ledger: Arc<Mutex<Chain>>,
}

/// Response body for `GET /health`. Deliberately minimal, mirroring
/// `xenia-operator-agent`'s `GET /v1/health` shape -- a liveness probe
/// needs to know the process is up and roughly how long it's been
/// running, not anything an operator would consider sensitive.
/// `ledger_entry_count` is already public via `GET /v1/audit/checkpoint`'s
/// `entry_count` field; repeating it here just saves a probe an extra
/// round trip.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_secs: u64,
    ledger_entry_count: u64,
}

/// `GET /health` -- unauthenticated liveness probe. No secret material,
/// no operator state, no session tokens.
async fn health_handler(State(state): State<HealthState>) -> Json<HealthResponse> {
    let ledger = state.ledger.lock().await;
    Json(HealthResponse {
        status: "ok",
        uptime_secs: state.started_at.elapsed().as_secs(),
        ledger_entry_count: ledger.len() as u64,
    })
}

/// `GET /v1/audit/checkpoint` -- a public, signed commitment to the ledger's
/// current length and head hash. No authentication required: it reveals
/// nothing beyond what `xenia_ledger::LedgerCheckpoint`'s doc comment
/// explains is already safe to publish (see
/// `docs/security/POST_DELEGATION_HARDENING_PLAN.md` item 3's "private
/// contents, public commitments" model).
async fn audit_checkpoint_handler(State(state): State<AuditState>) -> Json<LedgerCheckpoint> {
    let ledger = state.ledger.lock().await;
    Json(ledger.sign_checkpoint(unix_now_secs()))
}

/// Response body for `GET /v1/audit/ledger`: the full in-memory ledger plus
/// a checkpoint over the same state, so a caller can confirm
/// `entries.last().entry_hash == checkpoint.head_hash` (or, for an empty
/// ledger, that both agree it's empty) without trusting the daemon that
/// served the export.
#[derive(Serialize)]
struct AuditLedgerExportDto {
    entries: Vec<LedgerEntry>,
    checkpoint: LedgerCheckpoint,
}

/// `GET /v1/audit/ledger` -- an authenticated, role-gated export of the
/// full in-memory consent ledger. Requires a valid, unexpired operator
/// token in the `X-Operator-Token` header (same JSON shape `POST
/// /operator/revoke` embeds in its body) whose role permits
/// [`crate::operator_auth::authorize_ledger_read`] (`ReadAudit`, `Viewer`
/// and above -- every enrolled role). Every auth failure returns `403`
/// without disclosing which check failed, matching `revoke_operator_handler`.
async fn audit_ledger_handler(
    State(state): State<AuditState>,
    headers: HeaderMap,
) -> Result<Json<AuditLedgerExportDto>, (StatusCode, String)> {
    let token_header = headers
        .get("X-Operator-Token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing X-Operator-Token header".to_string(),
            )
        })?;
    let token_dto: TokenDto = serde_json::from_str(token_header).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed X-Operator-Token: {e}"),
        )
    })?;
    let signed = token_dto
        .into_signed()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    if crate::operator_auth::authorize_ledger_read(
        &state.auth.policy,
        &state.auth.daemon_key.verifying_key(),
        &state.auth.daemon_ml_dsa.public_key_bytes(),
        unix_now_secs(),
        &signed,
    )
    .is_err()
    {
        tracing::warn!("ledger read refused");
        return Err((StatusCode::FORBIDDEN, "ledger read refused".to_string()));
    }

    let ledger = state.ledger.lock().await;
    let checkpoint = ledger.sign_checkpoint(unix_now_secs());
    let entries: Vec<LedgerEntry> = ledger.iter().cloned().collect();
    Ok(Json(AuditLedgerExportDto {
        entries,
        checkpoint,
    }))
}

/// A `Router` carrying the auth routes plus the admin revoke route and the
/// `/v1/audit/*` routes, each with its own state already applied, so it can
/// be `.merge()`d into the stateless admin router. `revocations` is the
/// *same* handle the sealed endpoint consults; `ledger` is the *same*
/// shared ledger every consent path appends to.
pub(crate) fn router(
    state: Arc<OperatorAuthState>,
    revocations: OperatorRevocations,
    ledger: Arc<Mutex<Chain>>,
) -> Router {
    let mutation = AdminMutationState {
        auth: state.clone(),
        revocations,
    };
    let audit = AuditState {
        auth: state.clone(),
        ledger: ledger.clone(),
    };
    let health = HealthState {
        started_at: std::time::Instant::now(),
        ledger,
    };
    Router::new()
        .route("/auth/challenge", post(challenge_handler))
        .route("/auth/verify", post(verify_handler))
        .route(
            "/auth/daemon-identity",
            axum::routing::get(daemon_identity_handler),
        )
        .with_state(state)
        .merge(
            Router::new()
                .route("/v1/audit/checkpoint", get(audit_checkpoint_handler))
                .route("/v1/audit/ledger", get(audit_ledger_handler))
                .with_state(audit),
        )
        .merge(
            Router::new()
                .route("/operator/revoke", post(revoke_operator_handler))
                .with_state(mutation),
        )
        .merge(
            Router::new()
                .route("/health", get(health_handler))
                .with_state(health),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::EnrolledOperator;
    use crate::operator_auth::verify_token;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`
    use xenia_handshake::HandshakeManager;

    /// Fixed seed for every test's daemon ML-DSA identity, so a test that
    /// only has the daemon's Ed25519 `SigningKey` in hand (not the
    /// `OperatorAuthState` it built) can still reconstruct the matching
    /// public key deterministically.
    const TEST_DAEMON_ML_DSA_SEED: [u8; 32] = [0xAAu8; 32];

    fn test_daemon_ml_dsa() -> MlDsaIdentity {
        MlDsaIdentity::from_seed(TEST_DAEMON_ML_DSA_SEED)
    }

    fn state_with(op: &HandshakeManager, daemon: SigningKey) -> Arc<OperatorAuthState> {
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "alice".to_string(),
            ed25519_pubkey: op.identity_public_key_bytes(),
            ml_dsa_pubkey: op.ml_dsa_public_key_bytes().to_vec(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Admin,
        }])
        .unwrap();
        Arc::new(OperatorAuthState::new(
            policy,
            daemon,
            test_daemon_ml_dsa(),
            HandshakeManager::new(),
            crate::operator_auth::AUTH_RATE_MAX,
            crate::operator_auth::AUTH_RATE_WINDOW_SECS,
        ))
    }

    /// A fresh, empty ledger for tests that don't care about its contents --
    /// just need `router()`'s new third parameter satisfied.
    fn empty_ledger() -> Arc<Mutex<Chain>> {
        Arc::new(Mutex::new(Chain::new(SigningKey::generate(
            &mut rand::thread_rng(),
        ))))
    }

    #[tokio::test]
    async fn verify_is_rate_limited() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        // A state that allows just one auth attempt per window.
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "alice".to_string(),
            ed25519_pubkey: op.identity_public_key_bytes(),
            ml_dsa_pubkey: op.ml_dsa_public_key_bytes().to_vec(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Admin,
        }])
        .unwrap();
        let state = Arc::new(OperatorAuthState::new(
            policy,
            daemon,
            xenia_handshake::MlDsaIdentity::from_seed([0xAAu8; 32]),
            HandshakeManager::new(),
            1,
            3600,
        ));
        let router = router(state, OperatorRevocations::empty(), empty_ledger());
        // A well-formed VerifyRequestDto (all fields present) so the handler
        // runs -- the crypto is garbage, but the rate limiter fires before
        // verification. (Malformed JSON is rejected by the extractor before
        // the handler; brute-forcing requires well-formed requests anyway.)
        let body = serde_json::json!({
            "nonce": "",
            "ed_pubkey": "",
            "ml_dsa_pubkey": "",
            "ed_signature": "",
            "ml_dsa_signature": "",
        })
        .to_string();
        // First attempt: rate limiter allows it (then fails to decode -> 400).
        let (first, _) = post_json(&router, "/auth/verify", body.clone()).await;
        assert_ne!(first, StatusCode::TOO_MANY_REQUESTS);
        // Second attempt in the same window: rate-limited.
        let (second, _) = post_json(&router, "/auth/verify", body).await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    }

    async fn post_json(router: &Router, path: &str, body: String) -> (StatusCode, String) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn get_json(router: &Router, path: &str) -> (StatusCode, String) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn get_json_with_header(
        router: &Router,
        path: &str,
        header: &str,
        value: &str,
    ) -> (StatusCode, String) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn daemon_identity_certificate_is_self_consistent_and_matches_the_daemon_key() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let daemon_pk = daemon.verifying_key();
        let router = router(
            state_with(&op, daemon),
            OperatorRevocations::empty(),
            empty_ledger(),
        );

        let (status, body) = get_json(&router, "/auth/daemon-identity").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let cert: DaemonIdentityCertificate = serde_json::from_str(&body).unwrap();

        // The certificate's delegated keys really are this daemon's
        // HTTP-auth (token-signing) identity, both algorithms.
        let http_auth_pk: [u8; 32] = decode_fixed(&cert.http_auth_ed25519_pubkey).unwrap();
        assert_eq!(http_auth_pk, daemon_pk.to_bytes());
        let http_auth_ml_dsa_pk = hex::decode(&cert.http_auth_ml_dsa_pubkey).unwrap();
        assert_eq!(http_auth_ml_dsa_pk, test_daemon_ml_dsa().public_key_bytes());

        // Both of the host identity's signatures over the delegation
        // transcript verify against the certificate's own presented host
        // public keys -- this is exactly what a caller with no live
        // connection to the daemon (the operator agent) checks before
        // trusting anything else in the certificate.
        let host_ed_pk_bytes: [u8; 32] = decode_fixed(&cert.host_ed25519_pubkey).unwrap();
        let host_ed_pk = HandshakeManager::parse_peer_public_key(&host_ed_pk_bytes).unwrap();
        let host_ml_pk: [u8; ML_DSA_65_PK_LEN] = hex::decode(&cert.host_ml_dsa_pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        let transcript =
            xenia_operator_proto::daemon_delegation_transcript(&http_auth_pk, &http_auth_ml_dsa_pk);

        let ed_sig_bytes: [u8; 64] = decode_fixed(&cert.host_ed_signature).unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        assert!(HandshakeManager::verify(&host_ed_pk, &transcript, &ed_sig).is_ok());

        let ml_sig: [u8; ML_DSA_65_SIG_LEN] = hex::decode(&cert.host_ml_dsa_signature)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(HandshakeManager::verify_ml_dsa(&host_ml_pk, &transcript, &ml_sig).is_ok());
    }

    #[tokio::test]
    async fn challenge_host_attestation_verifies_against_the_daemon_identity_certificate() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon),
            OperatorRevocations::empty(),
            empty_ledger(),
        );

        let (status, cert_body) = get_json(&router, "/auth/daemon-identity").await;
        assert_eq!(status, StatusCode::OK);
        let cert: DaemonIdentityCertificate = serde_json::from_str(&cert_body).unwrap();
        let host_ed_pk_bytes: [u8; 32] = decode_fixed(&cert.host_ed25519_pubkey).unwrap();
        let host_ed_pk = HandshakeManager::parse_peer_public_key(&host_ed_pk_bytes).unwrap();
        let host_ml_pk: [u8; ML_DSA_65_PK_LEN] = hex::decode(&cert.host_ml_dsa_pubkey)
            .unwrap()
            .try_into()
            .unwrap();

        let (status, chal_body) = post_json(&router, "/auth/challenge", "{}".to_string()).await;
        assert_eq!(status, StatusCode::OK);
        let chal: serde_json::Value = serde_json::from_str(&chal_body).unwrap();
        let nonce: [u8; 32] = decode_fixed(chal["nonce"].as_str().unwrap()).unwrap();

        let attestation_transcript =
            xenia_operator_proto::challenge_host_attestation_transcript(&nonce);
        let ed_sig_bytes: [u8; 64] =
            decode_fixed(chal["host_ed_attestation_hex"].as_str().unwrap()).unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        assert!(HandshakeManager::verify(&host_ed_pk, &attestation_transcript, &ed_sig).is_ok());

        let ml_sig: [u8; ML_DSA_65_SIG_LEN] =
            hex::decode(chal["host_ml_dsa_attestation_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        assert!(
            HandshakeManager::verify_ml_dsa(&host_ml_pk, &attestation_transcript, &ml_sig).is_ok()
        );

        // An attestation for a *different* nonce must not verify -- proves
        // the attestation is really bound to this specific nonce, not just
        // "some nonce this daemon once issued."
        let other_nonce = [0xEEu8; 32];
        let other_transcript =
            xenia_operator_proto::challenge_host_attestation_transcript(&other_nonce);
        assert!(HandshakeManager::verify(&host_ed_pk, &other_transcript, &ed_sig).is_err());
    }

    #[tokio::test]
    async fn challenge_then_verify_issues_a_valid_token() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let daemon_pk = daemon.verifying_key();
        let state = state_with(&op, daemon);
        let router = router(state, OperatorRevocations::empty(), empty_ledger());

        // 1. get a challenge.
        let (status, body) = post_json(&router, "/auth/challenge", "{}".to_string()).await;
        assert_eq!(status, StatusCode::OK);
        let chal: serde_json::Value = serde_json::from_str(&body).unwrap();
        let nonce_hex = chal["nonce"].as_str().unwrap().to_string();
        let nonce: [u8; 32] = decode_fixed(&nonce_hex).unwrap();

        // 2. sign the transcript and verify.
        let ml_pk = op.ml_dsa_public_key_bytes().to_vec();
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"xenia-operator-auth-challenge-v1");
        transcript.extend_from_slice(&nonce);
        transcript.extend_from_slice(&op.identity_public_key_bytes());
        transcript.extend_from_slice(&ml_pk);
        let ed_sig = op.sign(&transcript).to_bytes();
        let ml_sig = op.sign_ml_dsa(&transcript);
        let verify_body = serde_json::json!({
            "nonce": nonce_hex,
            "ed_pubkey": hex::encode(op.identity_public_key_bytes()),
            "ml_dsa_pubkey": hex::encode(&ml_pk),
            "ed_signature": hex::encode(ed_sig),
            "ml_dsa_signature": hex::encode(ml_sig),
        })
        .to_string();
        let (status, body) = post_json(&router, "/auth/verify", verify_body).await;
        assert_eq!(status, StatusCode::OK, "verify failed: {body}");
        let token: TokenDto = serde_json::from_str(&body).unwrap();
        assert_eq!(token.operator_id, "alice");
        assert_eq!(token.role, OperatorRole::Admin);

        // 3. the returned token verifies under the daemon's keys, both
        // algorithms.
        let signed = SignedOperatorToken {
            token: crate::operator_auth::OperatorToken {
                operator_id: token.operator_id,
                role: token.role,
                issued_at: token.issued_at,
                expires_at: token.expires_at,
                token_nonce: decode_fixed(&token.token_nonce).unwrap(),
            },
            signature: decode_fixed(&token.signature).unwrap(),
            ml_dsa_signature: decode_fixed(&token.ml_dsa_signature).unwrap(),
        };
        assert!(
            verify_token(
                &daemon_pk,
                &test_daemon_ml_dsa().public_key_bytes(),
                token.issued_at + 1,
                &signed
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn verify_without_a_challenge_is_unauthorized() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon),
            OperatorRevocations::empty(),
            empty_ledger(),
        );
        // A well-formed but never-issued nonce.
        let ml_pk = op.ml_dsa_public_key_bytes().to_vec();
        let body = serde_json::json!({
            "nonce": hex::encode([0u8; 32]),
            "ed_pubkey": hex::encode(op.identity_public_key_bytes()),
            "ml_dsa_pubkey": hex::encode(&ml_pk),
            "ed_signature": hex::encode([0u8; 64]),
            "ml_dsa_signature": hex::encode([0u8; ML_DSA_65_SIG_LEN]),
        })
        .to_string();
        let (status, _) = post_json(&router, "/auth/verify", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Mint a daemon-signed token JSON for operator "alice" at `role`, plus its
    /// token nonce (needed to sign the revoke transcript).
    fn token_json_for(
        daemon: &SigningKey,
        role: OperatorRole,
        now: u64,
    ) -> (serde_json::Value, [u8; 16]) {
        let authed = crate::operator_auth::AuthenticatedOperator {
            operator_id: "alice".to_string(),
            role,
        };
        let nonce = [0x2b; 16];
        let signed = issue_token(
            daemon,
            &test_daemon_ml_dsa(),
            &authed,
            now,
            TOKEN_TTL_SECS,
            nonce,
        );
        (
            serde_json::to_value(TokenDto::from_signed(&signed)).unwrap(),
            nonce,
        )
    }

    /// Build a signed `POST /operator/revoke` body for `target`, signed by `op`.
    fn revoke_body(
        op: &HandshakeManager,
        token_json: serde_json::Value,
        target: &str,
        nonce: &[u8; 16],
    ) -> String {
        let transcript = crate::operator_auth::revoke_operator_transcript(target, nonce);
        serde_json::json!({
            "token": token_json,
            "target_operator_id": target,
            "action_signature": hex::encode(op.sign(&transcript).to_bytes()),
            "ml_dsa_action_signature": hex::encode(op.sign_ml_dsa(&transcript)),
        })
        .to_string()
    }

    #[tokio::test]
    async fn admin_revoke_endpoint_revokes_target_and_gates_by_role() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with(&op, daemon.clone()); // "alice" enrolled as Admin
        let revocations = OperatorRevocations::empty();
        let router = router(state, revocations.clone(), empty_ledger());
        let now = now_secs();

        // An Admin token authorizes the revocation: 204 + target revoked.
        let (admin_token, nonce) = token_json_for(&daemon, OperatorRole::Admin, now);
        let body = revoke_body(&op, admin_token, "mallory", &nonce);
        let (status, _) = post_json(&router, "/operator/revoke", body).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(revocations.is_revoked("mallory"));

        // An honestly-issued NON-Admin token is refused (403) and revokes nothing
        // -- the daemon gates on the token's own role, not on any client UI.
        let (approver_token, nonce2) = token_json_for(&daemon, OperatorRole::Approver, now);
        let body2 = revoke_body(&op, approver_token, "victim", &nonce2);
        let (status2, _) = post_json(&router, "/operator/revoke", body2).await;
        assert_eq!(status2, StatusCode::FORBIDDEN);
        assert!(!revocations.is_revoked("victim"));

        // Signature is over "mallory" but the body claims "eve": the per-action
        // signature no longer verifies -> refused, nothing revoked.
        let (admin_token2, nonce3) = token_json_for(&daemon, OperatorRole::Admin, now);
        let tampered = revoke_body(&op, admin_token2, "mallory", &nonce3).replace("mallory", "eve");
        let (status3, _) = post_json(&router, "/operator/revoke", tampered).await;
        assert_eq!(status3, StatusCode::FORBIDDEN);
        assert!(!revocations.is_revoked("eve"));
    }

    // ─── /v1/audit/* ────────────────────────────────────────────────────

    fn ledger_with_entries(sk: SigningKey, count: usize) -> Arc<Mutex<Chain>> {
        use uuid::Uuid;
        use xenia_ledger::{ConsentEventRecord, ConsentKind};
        let mut chain = Chain::new(sk);
        for _ in 0..count {
            chain
                .append(ConsentEventRecord {
                    source_id: [0xABu8; 32],
                    session_id: Uuid::new_v4(),
                    request_id: Uuid::new_v4(),
                    kind: ConsentKind::Approval,
                    scope: "view screen".to_string(),
                })
                .unwrap();
        }
        Arc::new(Mutex::new(chain))
    }

    #[tokio::test]
    async fn audit_checkpoint_is_public_and_signed() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger_key = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon),
            OperatorRevocations::empty(),
            ledger_with_entries(ledger_key, 3),
        );

        // No auth header at all -- the checkpoint is public.
        let (status, body) = get_json(&router, "/v1/audit/checkpoint").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let checkpoint: LedgerCheckpoint = serde_json::from_str(&body).unwrap();
        assert_eq!(checkpoint.entry_count, 3);
        xenia_ledger::Verifier::verify_checkpoint(&checkpoint).unwrap();
    }

    #[tokio::test]
    async fn health_is_public_and_reports_ledger_entry_count() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger_key = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon),
            OperatorRevocations::empty(),
            ledger_with_entries(ledger_key, 3),
        );

        // No auth header at all -- health is public, like the checkpoint.
        let (status, body) = get_json(&router, "/health").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["ledger_entry_count"], 3);
        assert!(parsed["uptime_secs"].is_u64());
    }

    #[tokio::test]
    async fn audit_ledger_requires_a_token_header() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon),
            OperatorRevocations::empty(),
            empty_ledger(),
        );

        let (status, _) = get_json(&router, "/v1/audit/ledger").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_ledger_succeeds_for_the_lowest_permitted_role_and_matches_the_checkpoint() {
        // "Viewer" is the lowest role in the hierarchy, and ReadAudit's
        // min_role is Viewer -- if the wiring is right, every enrolled
        // operator can read the ledger regardless of role.
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let ledger_key = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon.clone()),
            OperatorRevocations::empty(),
            ledger_with_entries(ledger_key, 2),
        );
        let (token, _nonce) = token_json_for(&daemon, OperatorRole::Viewer, now_secs());

        let (status, body) = get_json_with_header(
            &router,
            "/v1/audit/ledger",
            "X-Operator-Token",
            &token.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let entries = parsed["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let checkpoint: LedgerCheckpoint =
            serde_json::from_value(parsed["checkpoint"].clone()).unwrap();
        assert_eq!(checkpoint.entry_count, 2);
        xenia_ledger::Verifier::verify_checkpoint(&checkpoint).unwrap();
    }

    #[tokio::test]
    async fn audit_ledger_rejects_a_missing_or_unenrolled_operator() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon.clone()),
            OperatorRevocations::empty(),
            empty_ledger(),
        );

        // A token for an operator id that was never enrolled (state_with
        // only enrolls "alice").
        let authed = crate::operator_auth::AuthenticatedOperator {
            operator_id: "not-alice".to_string(),
            role: OperatorRole::Admin,
        };
        let signed = issue_token(
            &daemon,
            &test_daemon_ml_dsa(),
            &authed,
            now_secs(),
            TOKEN_TTL_SECS,
            [0x77; 16],
        );
        let token = serde_json::to_value(TokenDto::from_signed(&signed))
            .unwrap()
            .to_string();

        let (status, _) =
            get_json_with_header(&router, "/v1/audit/ledger", "X-Operator-Token", &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_ledger_rejects_an_expired_token() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon.clone()),
            OperatorRevocations::empty(),
            empty_ledger(),
        );

        let authed = crate::operator_auth::AuthenticatedOperator {
            operator_id: "alice".to_string(),
            role: OperatorRole::Viewer,
        };
        // issued and already-expired well in the past.
        let signed = issue_token(
            &daemon,
            &test_daemon_ml_dsa(),
            &authed,
            1_000,
            1,
            [0x11; 16],
        );
        let token = serde_json::to_value(TokenDto::from_signed(&signed))
            .unwrap()
            .to_string();

        let (status, _) =
            get_json_with_header(&router, "/v1/audit/ledger", "X-Operator-Token", &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_ledger_rejects_a_token_with_a_tampered_signature() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon.clone()),
            OperatorRevocations::empty(),
            empty_ledger(),
        );

        let (token_json, _nonce) = token_json_for(&daemon, OperatorRole::Viewer, now_secs());
        let mut token: TokenDto = serde_json::from_value(token_json).unwrap();
        token.signature = "ff".repeat(64);
        let tampered = serde_json::to_string(&token).unwrap();

        let (status, _) =
            get_json_with_header(&router, "/v1/audit/ledger", "X-Operator-Token", &tampered).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_ledger_rejects_a_malformed_token_header() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(
            state_with(&op, daemon),
            OperatorRevocations::empty(),
            empty_ledger(),
        );

        let (status, _) =
            get_json_with_header(&router, "/v1/audit/ledger", "X-Operator-Token", "not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
