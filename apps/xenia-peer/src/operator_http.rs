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

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use xenia_handshake::{ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

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
    /// The daemon's own signing key, used to sign issued tokens.
    pub(crate) daemon_key: SigningKey,
    /// Bounds auth attempts against brute-force / flooding.
    pub(crate) rate_limiter: Mutex<RateLimiter>,
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
        }
    }
}

/// `POST /auth/challenge` -- issue a fresh single-use challenge.
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
    Json(ChallengeResponseDto {
        nonce: hex::encode(nonce),
        expires_at: now + CHALLENGE_TTL_SECS,
    })
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
    let signed = issue_token(&state.daemon_key, &authed, now, TOKEN_TTL_SECS, token_nonce);
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
    Ok(AuthenticatedConsentAction {
        token: dto.token.into_signed()?,
        action,
        action_signature,
    })
}

/// Wire form of an admin's operator-revocation request:
/// `{ token, target_operator_id, action_signature }`.
#[derive(Deserialize)]
struct AuthenticatedRevocationDto {
    token: TokenDto,
    target_operator_id: String,
    /// Hex Ed25519 signature over `revoke_operator_transcript(target, token_nonce)`.
    action_signature: String,
}

/// Parse the JSON body of a `/operator/revoke` request into an
/// [`AuthenticatedRevocation`], mirroring [`parse_authenticated_consent_action`].
pub(crate) fn parse_authenticated_revocation(
    json: &str,
) -> Result<AuthenticatedRevocation, String> {
    let dto: AuthenticatedRevocationDto = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let action_signature = decode_fixed::<64>(&dto.action_signature).map_err(|(_, m)| m)?;
    Ok(AuthenticatedRevocation {
        token: dto.token.into_signed()?,
        target_operator_id: dto.target_operator_id,
        action_signature,
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

/// A `Router` carrying the auth routes plus the admin revoke route, each with its
/// own state already applied, so it can be `.merge()`d into the stateless admin
/// router. `revocations` is the *same* handle the sealed endpoint consults.
pub(crate) fn router(state: Arc<OperatorAuthState>, revocations: OperatorRevocations) -> Router {
    let mutation = AdminMutationState {
        auth: state.clone(),
        revocations,
    };
    Router::new()
        .route("/auth/challenge", post(challenge_handler))
        .route("/auth/verify", post(verify_handler))
        .with_state(state)
        .merge(
            Router::new()
                .route("/operator/revoke", post(revoke_operator_handler))
                .with_state(mutation),
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

    fn state_with(op: &HandshakeManager, daemon: SigningKey) -> Arc<OperatorAuthState> {
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "alice".to_string(),
            ed25519_pubkey: op.identity_public_key_bytes(),
            ml_dsa_pubkey: op.ml_dsa_public_key_bytes().to_vec(),
            role: OperatorRole::Admin,
        }])
        .unwrap();
        Arc::new(OperatorAuthState {
            policy,
            challenges: Mutex::new(ChallengeStore::new()),
            daemon_key: daemon,
            rate_limiter: Mutex::new(RateLimiter::new(
                crate::operator_auth::AUTH_RATE_MAX,
                crate::operator_auth::AUTH_RATE_WINDOW_SECS,
            )),
        })
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
            role: OperatorRole::Admin,
        }])
        .unwrap();
        let state = Arc::new(OperatorAuthState {
            policy,
            challenges: Mutex::new(ChallengeStore::new()),
            daemon_key: daemon,
            rate_limiter: Mutex::new(RateLimiter::new(1, 3600)),
        });
        let router = router(state, OperatorRevocations::empty());
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

    #[tokio::test]
    async fn challenge_then_verify_issues_a_valid_token() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let daemon_pk = daemon.verifying_key();
        let state = state_with(&op, daemon);
        let router = router(state, OperatorRevocations::empty());

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

        // 3. the returned token verifies under the daemon key.
        let signed = SignedOperatorToken {
            token: crate::operator_auth::OperatorToken {
                operator_id: token.operator_id,
                role: token.role,
                issued_at: token.issued_at,
                expires_at: token.expires_at,
                token_nonce: decode_fixed(&token.token_nonce).unwrap(),
            },
            signature: decode_fixed(&token.signature).unwrap(),
        };
        assert!(verify_token(&daemon_pk, token.issued_at + 1, &signed).is_ok());
    }

    #[tokio::test]
    async fn verify_without_a_challenge_is_unauthorized() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let router = router(state_with(&op, daemon), OperatorRevocations::empty());
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
}
