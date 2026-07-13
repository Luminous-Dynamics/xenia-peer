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

use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};
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
    /// The daemon's own signing key, used to sign issued tokens.
    pub(crate) daemon_key: SigningKey,
    /// Bounds auth attempts against brute-force / flooding.
    pub(crate) rate_limiter: Mutex<RateLimiter>,
    /// The daemon's *host* identity (the same one the sealed-channel
    /// handshake uses and `host_pin.rs`/`host_trust.rs` pin) -- used to
    /// sign each challenge's host attestation at issuance time. Kept
    /// separate from `daemon_key`; see [`DaemonIdentityCertificate`]'s doc
    /// comment for why the two aren't unified.
    pub(crate) host_identity: HandshakeManager,
    /// Host identity's delegation of trust to `daemon_key`, computed once
    /// at startup and served verbatim over `GET /auth/daemon-identity`.
    pub(crate) daemon_certificate: DaemonIdentityCertificate,
}

impl OperatorAuthState {
    /// Build a state, computing `daemon_certificate` from `host_identity`
    /// and `daemon_key` once here (both keys are static for the state's
    /// lifetime, so there's no reason to recompute it per-request). The
    /// single constructor keeps every call site (`main.rs`'s real daemon
    /// bootstrap, and the several test harnesses across this crate) from
    /// having to know how the certificate is built, and means adding a
    /// future field to this struct doesn't require touching every one of
    /// them.
    pub(crate) fn new(
        policy: OperatorPolicy,
        daemon_key: SigningKey,
        host_identity: HandshakeManager,
        rate_limit_max: u32,
        rate_limit_window_secs: u64,
    ) -> Self {
        let http_auth_pubkey = daemon_key.verifying_key().to_bytes();
        let transcript = xenia_operator_proto::daemon_delegation_transcript(&http_auth_pubkey);
        let daemon_certificate = DaemonIdentityCertificate {
            host_ed25519_pubkey: hex::encode(host_identity.identity_public_key_bytes()),
            host_ml_dsa_pubkey: hex::encode(host_identity.ml_dsa_public_key_bytes()),
            http_auth_ed25519_pubkey: hex::encode(http_auth_pubkey),
            host_ed_signature: hex::encode(host_identity.sign(&transcript).to_bytes()),
            host_ml_dsa_signature: hex::encode(host_identity.sign_ml_dsa(&transcript)),
        };
        Self {
            policy,
            challenges: Mutex::new(ChallengeStore::new()),
            daemon_key,
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
        .route(
            "/auth/daemon-identity",
            axum::routing::get(daemon_identity_handler),
        )
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
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Admin,
        }])
        .unwrap();
        Arc::new(OperatorAuthState::new(
            policy,
            daemon,
            HandshakeManager::new(),
            crate::operator_auth::AUTH_RATE_MAX,
            crate::operator_auth::AUTH_RATE_WINDOW_SECS,
        ))
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
            HandshakeManager::new(),
            1,
            3600,
        ));
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

    #[tokio::test]
    async fn daemon_identity_certificate_is_self_consistent_and_matches_the_daemon_key() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let daemon_pk = daemon.verifying_key();
        let router = router(state_with(&op, daemon), OperatorRevocations::empty());

        let (status, body) = get_json(&router, "/auth/daemon-identity").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let cert: DaemonIdentityCertificate = serde_json::from_str(&body).unwrap();

        // The certificate's delegated key really is this daemon's HTTP-auth
        // (token-signing) key.
        let http_auth_pk: [u8; 32] = decode_fixed(&cert.http_auth_ed25519_pubkey).unwrap();
        assert_eq!(http_auth_pk, daemon_pk.to_bytes());

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
        let transcript = xenia_operator_proto::daemon_delegation_transcript(&http_auth_pk);

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
        let router = router(state_with(&op, daemon), OperatorRevocations::empty());

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
        let signed = issue_token(daemon, &authed, now, TOKEN_TTL_SECS, nonce);
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
        })
        .to_string()
    }

    #[tokio::test]
    async fn admin_revoke_endpoint_revokes_target_and_gates_by_role() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with(&op, daemon.clone()); // "alice" enrolled as Admin
        let revocations = OperatorRevocations::empty();
        let router = router(state, revocations.clone());
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
}
