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
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
    routing::{get, post},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, MlDsaIdentity};
use xenia_ledger::{Chain, LedgerCheckpoint, LedgerEntry};
use xenia_operator_proto::{DaemonIdentityCertificate, challenge_host_attestation_transcript};
use xenia_wire::handshake_highsec::ML_DSA_87_PK_LEN;

use crate::operator::{OperatorPolicy, OperatorRole};
use crate::operator_auth::{
    AuthenticatedConsentAction, AuthenticatedKeyReplacement, AuthenticatedRevocation,
    CHALLENGE_TTL_SECS, ChallengeResponse, ChallengeStore, ConsentAction,
    MAX_OUTSTANDING_CHALLENGES, OperatorToken, RateLimiter, SignedOperatorToken, TOKEN_TTL_SECS,
    issue_token, verify_challenge_response,
};
use crate::operator_revocations::OperatorRevocations;

const MAX_OPERATOR_HTTP_BODY_BYTES: usize = 64 * 1024;

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
) -> Result<Json<ChallengeResponseDto>, (StatusCode, String)> {
    let now = unix_now_secs();
    let nonce: [u8; 32] = rand::random();
    {
        let mut challenges = state.challenges.lock().await;
        challenges.gc(now);
        if !challenges.issue(nonce, now, CHALLENGE_TTL_SECS) {
            tracing::warn!(
                outstanding = MAX_OUTSTANDING_CHALLENGES,
                "operator challenge store is full"
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "too many outstanding authentication challenges".to_string(),
            ));
        }
    }
    let attestation_transcript = challenge_host_attestation_transcript(&nonce);
    Ok(Json(ChallengeResponseDto {
        nonce: hex::encode(nonce),
        expires_at: now + CHALLENGE_TTL_SECS,
        host_ed_attestation_hex: hex::encode(
            state.host_identity.sign(&attestation_transcript).to_bytes(),
        ),
        host_ml_dsa_attestation_hex: hex::encode(
            state.host_identity.sign_ml_dsa(&attestation_transcript),
        ),
    }))
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

/// State for `POST /auth/verify`: the auth state plus the live revocation
/// list. Unlike `challenge_handler`/`daemon_identity_handler` (unauthenticated,
/// no operator identity involved), this route mints a fresh token for a
/// specific operator -- without checking `revocations` here, a revoked
/// operator's key (still enrolled; revocation != de-enrollment) could
/// re-authenticate indefinitely after being revoked, defeating the whole
/// point of `OperatorRevocations` as a live, no-restart kill switch.
#[derive(Clone)]
struct VerifyState {
    auth: Arc<OperatorAuthState>,
    revocations: OperatorRevocations,
}

/// `POST /auth/verify` -- verify a challenge response and mint a token.
async fn verify_handler(
    State(state): State<VerifyState>,
    Json(req): Json<VerifyRequestDto>,
) -> Result<Json<TokenDto>, (StatusCode, String)> {
    let auth = &state.auth;
    // Rate-limit auth attempts before doing any (relatively expensive)
    // signature verification, to bound brute-force / flooding.
    if !auth.rate_limiter.lock().await.allow(unix_now_secs()) {
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
        let mut challenges = auth.challenges.lock().await;
        verify_challenge_response(&auth.policy, &mut challenges, now, &response)
            // Auth failures are 401; do not leak which step failed beyond the
            // stable Display text.
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?
    };

    if state.revocations.is_revoked(&authed.operator_id) {
        tracing::warn!(operator = %authed.operator_id, "token issuance refused: operator is revoked");
        return Err((
            StatusCode::UNAUTHORIZED,
            "operator is revoked".to_string(),
        ));
    }

    let token_nonce: [u8; 16] = rand::random();
    let signed = issue_token(
        &auth.daemon_key,
        &auth.daemon_ml_dsa,
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
    /// Caller-generated UUID bytes, hex encoded.
    action_id: String,
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
    let action_id = decode_fixed::<16>(&dto.action_id).map_err(|(_, m)| m)?;
    let action_signature = decode_fixed::<64>(&dto.action_signature).map_err(|(_, m)| m)?;
    let ml_dsa_action_signature =
        decode_fixed::<ML_DSA_65_SIG_LEN>(&dto.ml_dsa_action_signature).map_err(|(_, m)| m)?;
    Ok(AuthenticatedConsentAction {
        token: dto.token.into_signed()?,
        action,
        action_id,
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
    /// Where to persist the live operator policy after a
    /// `replace_operator_key_handler` mutation, so an operator-key
    /// recovery survives a restart -- `None` if the daemon wasn't given
    /// an `--operators-file` (the live mutation still applies in-process;
    /// there is simply nowhere durable to write it back to).
    operators_file: Option<std::path::PathBuf>,
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
            // A revoked admin's token is otherwise still cryptographically
            // valid (revocation != de-enrollment) -- without this check
            // they could keep revoking (or un-revoking, by replacing keys)
            // other operators indefinitely after being revoked themselves.
            // Mirrors main.rs's identical check on the plaintext consent
            // path.
            if state.revocations.is_revoked(&authorized.operator_id) {
                tracing::warn!(
                    operator = %authorized.operator_id,
                    "operator revocation refused: acting operator is revoked"
                );
                return Err((StatusCode::FORBIDDEN, "revocation refused".to_string()));
            }
            if let Err(err) = state
                .revocations
                .revoke_durable(&authorized.target_operator_id)
            {
                tracing::error!(
                    target = %authorized.target_operator_id,
                    by = %authorized.operator_id,
                    error = %err,
                    "operator revoked in memory but durable persistence failed"
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "operator revoked for this daemon run, but persistence failed".to_string(),
                ));
            }
            tracing::warn!(
                target = %authorized.target_operator_id,
                by = %authorized.operator_id,
                "operator revoked via admin endpoint and persisted when configured"
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(err) => {
            tracing::warn!(error = %err, "operator revocation refused");
            Err((StatusCode::FORBIDDEN, "revocation refused".to_string()))
        }
    }
}

/// Wire form of an admin's operator-key-replacement request:
/// `{ token, target_operator_id, new_ed25519_pubkey, new_ml_dsa_pubkey,
/// new_ml_dsa_87_pubkey?, action_signature, ml_dsa_action_signature }` --
/// operator-key recovery.
#[derive(Deserialize)]
struct AuthenticatedKeyReplacementDto {
    token: TokenDto,
    target_operator_id: String,
    /// Hex Ed25519 public key of the operator's replacement identity.
    new_ed25519_pubkey: String,
    /// Hex ML-DSA-65 public key of the replacement identity -- required,
    /// mirroring `crate::operator::OperatorRecord`'s `ml_dsa_pubkey` field
    /// (private to that module, so not a linkable intra-doc reference here).
    new_ml_dsa_pubkey: String,
    /// Hex ML-DSA-87 public key, only if the operator is re-enrolling for
    /// the high-security sealed channel -- omitted (not null) otherwise,
    /// mirroring `crate::operator::OperatorRecord`'s `ml_dsa_87_pubkey` field.
    #[serde(default)]
    new_ml_dsa_87_pubkey: Option<String>,
    /// Hex Ed25519 signature over
    /// `replace_operator_key_transcript(target, new keys, token_nonce)`.
    action_signature: String,
    /// Hex ML-DSA-65 signature over the same transcript -- both required.
    ml_dsa_action_signature: String,
}

/// Parse the JSON body of a `/operator/replace-key` request into an
/// [`AuthenticatedKeyReplacement`], mirroring [`parse_authenticated_revocation`].
pub(crate) fn parse_authenticated_key_replacement(
    json: &str,
) -> Result<AuthenticatedKeyReplacement, String> {
    let dto: AuthenticatedKeyReplacementDto =
        serde_json::from_str(json).map_err(|e| e.to_string())?;
    let new_ed25519_pubkey = decode_fixed::<32>(&dto.new_ed25519_pubkey).map_err(|(_, m)| m)?;
    let new_ml_dsa_pubkey =
        decode_fixed::<ML_DSA_65_PK_LEN>(&dto.new_ml_dsa_pubkey).map_err(|(_, m)| m)?;
    let new_ml_dsa_87_pubkey = match dto.new_ml_dsa_87_pubkey {
        None => None,
        Some(hex_str) => Some(
            decode_fixed::<ML_DSA_87_PK_LEN>(&hex_str)
                .map_err(|(_, m)| m)?
                .to_vec(),
        ),
    };
    let action_signature = decode_fixed::<64>(&dto.action_signature).map_err(|(_, m)| m)?;
    let ml_dsa_action_signature =
        decode_fixed::<ML_DSA_65_SIG_LEN>(&dto.ml_dsa_action_signature).map_err(|(_, m)| m)?;
    Ok(AuthenticatedKeyReplacement {
        token: dto.token.into_signed()?,
        target_operator_id: dto.target_operator_id,
        new_ed25519_pubkey,
        new_ml_dsa_pubkey: new_ml_dsa_pubkey.to_vec(),
        new_ml_dsa_87_pubkey,
        action_signature,
        ml_dsa_action_signature,
    })
}

/// `POST /operator/replace-key` — an authenticated `Admin` replaces another
/// operator's enrolled key material live (no restart): operator-key
/// recovery. Fail-closed exactly like [`revoke_operator_handler`]: only a
/// valid, unexpired, `Admin`-role token whose per-action signature verifies
/// over the exact target and new key material may replace it; every auth
/// failure returns `403` without disclosing which check failed.
///
/// On success the live policy is also persisted back to `--operators-file`
/// (if the daemon was given one) so the replacement survives a restart --
/// unlike [`crate::operator_revocations::OperatorRevocations::revoke`],
/// whose own doc comment accepts that gap for revocation. A persist
/// failure (e.g. a full or read-only disk) is logged but does not undo the
/// already-applied in-process mutation or fail the request: the operator
/// is unblocked immediately, which is the whole point of recovery, and a
/// failed durability write is an operational issue for the daemon operator
/// to fix, not a reason to leave the recovering operator locked out.
async fn replace_operator_key_handler(
    State(state): State<AdminMutationState>,
    body: String,
) -> Result<StatusCode, (StatusCode, String)> {
    let request = parse_authenticated_key_replacement(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed key-replacement request: {e}"),
        )
    })?;
    let authorized = match crate::operator_auth::authorize_operator_key_replacement(
        &state.auth.policy,
        &state.auth.daemon_key.verifying_key(),
        &state.auth.daemon_ml_dsa.public_key_bytes(),
        unix_now_secs(),
        &request,
    ) {
        Ok(authorized) => authorized,
        Err(err) => {
            tracing::warn!(error = %err, "operator key replacement refused");
            return Err((StatusCode::FORBIDDEN, "key replacement refused".to_string()));
        }
    };

    // See the identical check in revoke_operator_handler: a revoked admin's
    // token is otherwise still valid, and this endpoint's blast radius is
    // worse -- it lets the caller seize any other enrolled operator's
    // (including other admins') identity.
    if state.revocations.is_revoked(&authorized.operator_id) {
        tracing::warn!(
            operator = %authorized.operator_id,
            "operator key replacement refused: acting operator is revoked"
        );
        return Err((StatusCode::FORBIDDEN, "key replacement refused".to_string()));
    }

    if let Err(err) = state.auth.policy.replace_operator_key(
        &authorized.target_operator_id,
        authorized.new_ed25519_pubkey,
        authorized.new_ml_dsa_pubkey,
        authorized.new_ml_dsa_87_pubkey,
    ) {
        tracing::warn!(
            error = %err,
            target = %authorized.target_operator_id,
            "operator key replacement refused"
        );
        return Err((StatusCode::FORBIDDEN, "key replacement refused".to_string()));
    }

    if let Some(path) = &state.operators_file
        && let Err(err) = state.auth.policy.persist_to(path)
    {
        tracing::error!(
            error = %err,
            path = %path.display(),
            target = %authorized.target_operator_id,
            "failed to persist operator policy after key replacement -- \
             the replacement is live but will not survive a restart until fixed"
        );
    }

    tracing::warn!(
        target = %authorized.target_operator_id,
        by = %authorized.operator_id,
        "operator key replaced via admin endpoint"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// State for the `/v1/audit/*` routes: the auth state (token/role
/// verification), the live ledger to read from, and the live revocation
/// list (a de-enrolled operator's token is already refused by
/// `authorize_ledger_read` via `OperatorPolicy::lookup_by_id`; a merely
/// *revoked*-but-still-enrolled one is a separate check this state exists
/// to make possible).
#[derive(Clone)]
struct AuditState {
    auth: Arc<OperatorAuthState>,
    ledger: Arc<Mutex<Chain>>,
    revocations: OperatorRevocations,
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

const AUDIT_EXTENSION_WITNESS_SCHEMA: &str = "xenia-ledger-extension-witness-v1";
const MAX_AUDIT_WITNESS_ENTRIES: usize = 4_096;

/// Query for `GET /v1/audit/witness`. `after_entry_count` is the retained
/// checkpoint height; every entry after that height is returned so the caller
/// can prove append-only extension rather than merely compare two checkpoints.
#[derive(Debug, Deserialize)]
struct AuditWitnessQuery {
    after_entry_count: u64,
}

/// Authenticated extension proof from a retained checkpoint height to the
/// daemon's current signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditExtensionWitnessDto {
    schema: String,
    base_entry_count: u64,
    entries: Vec<LedgerEntry>,
    checkpoint: LedgerCheckpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditWitnessBuildError {
    BaseAheadOfLedger { base: u64, ledger: u64 },
    TooManyEntries { requested: usize, maximum: usize },
}

fn build_audit_extension_witness(
    ledger: &Chain,
    after_entry_count: u64,
    timestamp_unix_secs: u64,
) -> Result<AuditExtensionWitnessDto, AuditWitnessBuildError> {
    let ledger_len = ledger.len() as u64;
    if after_entry_count > ledger_len {
        return Err(AuditWitnessBuildError::BaseAheadOfLedger {
            base: after_entry_count,
            ledger: ledger_len,
        });
    }
    let requested = usize::try_from(ledger_len - after_entry_count)
        .expect("ledger length is already bounded by usize");
    if requested > MAX_AUDIT_WITNESS_ENTRIES {
        return Err(AuditWitnessBuildError::TooManyEntries {
            requested,
            maximum: MAX_AUDIT_WITNESS_ENTRIES,
        });
    }
    let after_index = usize::try_from(after_entry_count)
        .expect("entry count is already bounded by the in-memory ledger length");
    let entries = ledger
        .iter()
        .skip(after_index)
        .cloned()
        .collect();
    Ok(AuditExtensionWitnessDto {
        schema: AUDIT_EXTENSION_WITNESS_SCHEMA.to_string(),
        base_entry_count: after_entry_count,
        entries,
        checkpoint: ledger.sign_checkpoint(timestamp_unix_secs),
    })
}

/// Authenticate and authorize one reader for the private audit endpoints.
/// Public checkpoint access deliberately bypasses this helper.
fn authorize_audit_reader(
    state: &AuditState,
    headers: &HeaderMap,
) -> Result<OperatorToken, (StatusCode, String)> {
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
    let token = crate::operator_auth::authorize_ledger_read(
        &state.auth.policy,
        &state.auth.daemon_key.verifying_key(),
        &state.auth.daemon_ml_dsa.public_key_bytes(),
        unix_now_secs(),
        &signed,
    )
    .map_err(|_| {
        tracing::warn!("ledger read refused");
        (StatusCode::FORBIDDEN, "ledger read refused".to_string())
    })?;
    if state.revocations.is_revoked(&token.operator_id) {
        tracing::warn!(operator = %token.operator_id, "ledger read refused: operator is revoked");
        return Err((StatusCode::FORBIDDEN, "ledger read refused".to_string()));
    }
    Ok(token)
}

/// `GET /v1/audit/ledger` -- an authenticated, role-gated export of the
/// full in-memory consent ledger. Requires a valid, unexpired operator token
/// whose role permits [`crate::operator_auth::authorize_ledger_read`].
async fn audit_ledger_handler(
    State(state): State<AuditState>,
    headers: HeaderMap,
) -> Result<Json<AuditLedgerExportDto>, (StatusCode, String)> {
    authorize_audit_reader(&state, &headers)?;
    let ledger = state.ledger.lock().await;
    let checkpoint = ledger.sign_checkpoint(unix_now_secs());
    let entries: Vec<LedgerEntry> = ledger.iter().cloned().collect();
    Ok(Json(AuditLedgerExportDto {
        entries,
        checkpoint,
    }))
}

/// `GET /v1/audit/witness` -- authenticated append-only extension proof from
/// an externally retained checkpoint height to the current ledger head.
///
/// The endpoint is deliberately bounded. An auditor that falls more than
/// `MAX_AUDIT_WITNESS_ENTRIES` behind must fetch the full authenticated ledger
/// rather than force the daemon to allocate an unbounded response.
async fn audit_witness_handler(
    State(state): State<AuditState>,
    headers: HeaderMap,
    Query(query): Query<AuditWitnessQuery>,
) -> Result<Json<AuditExtensionWitnessDto>, (StatusCode, String)> {
    authorize_audit_reader(&state, &headers)?;
    let ledger = state.ledger.lock().await;
    let witness = build_audit_extension_witness(
        &ledger,
        query.after_entry_count,
        unix_now_secs(),
    )
    .map_err(|err| match err {
        AuditWitnessBuildError::BaseAheadOfLedger { base, ledger } => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            format!("retained entry count {base} is ahead of current ledger length {ledger}"),
        ),
        AuditWitnessBuildError::TooManyEntries { requested, maximum } => (
            StatusCode::CONFLICT,
            format!(
                "extension requires {requested} entries, exceeding witness maximum {maximum}; fetch /v1/audit/ledger"
            ),
        ),
    })?;
    Ok(Json(witness))
}

/// A `Router` carrying the auth routes plus the admin revoke/replace-key
/// routes and the `/v1/audit/*` routes, each with its own state already
/// applied, so it can be `.merge()`d into the stateless admin router.
/// `revocations` is the *same* handle the sealed endpoint consults;
/// `ledger` is the *same* shared ledger every consent path appends to;
/// `operators_file` is where `replace_operator_key_handler` persists a live
/// key replacement so it survives a restart (`None` if the daemon wasn't
/// given an `--operators-file`).
///
/// `allowed_origins` gates every route here with the same Origin-allowlist
/// and CORS-header pattern `xenia-operator-agent`'s `auth_and_cors_middleware`
/// already uses (see that function's doc comment) -- these routes are the
/// console's own `fetch()` targets, always cross-origin from the console's
/// perspective (it's served on a fixed Trunk dev-serve port, the daemon's
/// admin port is operator-configured and never the same port). Without
/// this, no browser can call any of them at all: found live running the
/// real console against a real daemon for the first time (item 6's
/// browser-driven vertical slice), every `fetch()` failed with a generic
/// `TypeError: Failed to fetch` and no clearer signal -- these routes had
/// never actually been exercised from a real browser before.
pub(crate) fn router(
    state: Arc<OperatorAuthState>,
    revocations: OperatorRevocations,
    ledger: Arc<Mutex<Chain>>,
    allowed_origins: Arc<Vec<String>>,
    operators_file: Option<std::path::PathBuf>,
) -> Router {
    let mutation = AdminMutationState {
        auth: state.clone(),
        revocations: revocations.clone(),
        operators_file,
    };
    let audit = AuditState {
        auth: state.clone(),
        ledger: ledger.clone(),
        revocations: revocations.clone(),
    };
    let verify = VerifyState {
        auth: state.clone(),
        revocations,
    };
    let health = HealthState {
        started_at: std::time::Instant::now(),
        ledger,
    };
    Router::new()
        .route("/auth/challenge", post(challenge_handler))
        .route(
            "/auth/daemon-identity",
            axum::routing::get(daemon_identity_handler),
        )
        .with_state(state)
        .merge(Router::new().route("/auth/verify", post(verify_handler)).with_state(verify))
        .merge(
            Router::new()
                .route("/v1/audit/checkpoint", get(audit_checkpoint_handler))
                .route("/v1/audit/ledger", get(audit_ledger_handler))
                .route("/v1/audit/witness", get(audit_witness_handler))
                .with_state(audit),
        )
        .merge(
            Router::new()
                .route("/operator/revoke", post(revoke_operator_handler))
                .route("/operator/replace-key", post(replace_operator_key_handler))
                .with_state(mutation),
        )
        .merge(
            Router::new()
                .route("/health", get(health_handler))
                .with_state(health),
        )
        .layer(DefaultBodyLimit::max(MAX_OPERATOR_HTTP_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            allowed_origins,
            cors_middleware,
        ))
}

/// Answers CORS preflight (`OPTIONS`) requests and stamps
/// `Access-Control-Allow-Origin` on every response so a browser will
/// actually let the console's JS read them. Unlike the operator agent's
/// `auth_and_cors_middleware`, this does **not** enforce an Origin
/// allowlist as a security boundary -- every route it wraps already does
/// its own real authentication (a signed token, a challenge/response
/// ceremony, or is deliberately public per
/// `docs/security/POST_DELEGATION_HARDENING_PLAN.md` item 3's "private
/// contents, public commitments, portable proofs" model). `allowed_origins`
/// only controls which `Origin` a *browser* will actually deliver the
/// response body to -- a non-browser client (curl, the audit smoke
/// scripts) is unaffected either way, since CORS is enforced by the
/// browser, not the server.
async fn cors_middleware(
    axum::extract::State(allowed_origins): axum::extract::State<Arc<Vec<String>>>,
    method: Method,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| allowed_origins.iter().any(|a| a == o));

    if method == Method::OPTIONS {
        return with_cors_headers(origin, Response::new(axum::body::Body::empty()));
    }

    with_cors_headers(origin, next.run(request).await)
}

fn with_cors_headers(origin: Option<&str>, mut response: Response) -> Response {
    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            response
                .headers_mut()
                .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("x-operator-token, content-type"),
        );
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
    }
    response
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
        let router = router(
            state,
            OperatorRevocations::empty(),
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
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
        let router = router(
            state,
            OperatorRevocations::empty(),
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );

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
            Arc::new(Vec::new()),
            None,
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

    /// Like [`state_with`], but also enrolls a second operator `mallory`
    /// (role `target_role`) with her own real handshake identity `target_op`
    /// -- needed to test replacing *her* key material while `alice` (Admin)
    /// authorizes the replacement.
    fn state_with_target(
        admin_op: &HandshakeManager,
        daemon: SigningKey,
        target_op: &HandshakeManager,
        target_role: OperatorRole,
    ) -> Arc<OperatorAuthState> {
        let policy = OperatorPolicy::from_operators(vec![
            EnrolledOperator {
                operator_id: "alice".to_string(),
                ed25519_pubkey: admin_op.identity_public_key_bytes(),
                ml_dsa_pubkey: admin_op.ml_dsa_public_key_bytes().to_vec(),
                ml_dsa_87_pubkey: None,
                role: OperatorRole::Admin,
            },
            EnrolledOperator {
                operator_id: "mallory".to_string(),
                ed25519_pubkey: target_op.identity_public_key_bytes(),
                ml_dsa_pubkey: target_op.ml_dsa_public_key_bytes().to_vec(),
                ml_dsa_87_pubkey: None,
                role: target_role,
            },
        ])
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

    /// Build a signed `POST /operator/replace-key` body replacing `target`'s
    /// key material with `new_ed`/`new_ml`, signed by `op` (the authorizing
    /// admin).
    #[allow(clippy::too_many_arguments)]
    fn replace_key_body(
        op: &HandshakeManager,
        token_json: serde_json::Value,
        target: &str,
        new_ed: [u8; 32],
        new_ml: &[u8],
        new_ml_87: Option<&[u8]>,
        nonce: &[u8; 16],
    ) -> String {
        let transcript = crate::operator_auth::replace_operator_key_transcript(
            target, &new_ed, new_ml, new_ml_87, nonce,
        );
        serde_json::json!({
            "token": token_json,
            "target_operator_id": target,
            "new_ed25519_pubkey": hex::encode(new_ed),
            "new_ml_dsa_pubkey": hex::encode(new_ml),
            "new_ml_dsa_87_pubkey": new_ml_87.map(hex::encode),
            "action_signature": hex::encode(op.sign(&transcript).to_bytes()),
            "ml_dsa_action_signature": hex::encode(op.sign_ml_dsa(&transcript)),
        })
        .to_string()
    }

    #[tokio::test]
    async fn admin_replace_key_endpoint_replaces_target_and_gates_by_role() {
        let admin_op = HandshakeManager::new();
        let target_op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with_target(
            &admin_op,
            daemon.clone(),
            &target_op,
            OperatorRole::Operator,
        );
        let router = router(
            state.clone(),
            OperatorRevocations::empty(),
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );
        let now = now_secs();

        let old_ed = target_op.identity_public_key_bytes();
        let new_ed = [0x77u8; 32];
        let new_ml = vec![0xEEu8; ML_DSA_65_PK_LEN];

        // An Admin token authorizes the replacement: 204 + the target's key
        // is live-replaced -- the old key no longer authenticates, the new
        // one does, and the role/id are preserved.
        let (admin_token, nonce) = token_json_for(&daemon, OperatorRole::Admin, now);
        let body = replace_key_body(
            &admin_op,
            admin_token,
            "mallory",
            new_ed,
            &new_ml,
            None,
            &nonce,
        );
        let (status, _) = post_json(&router, "/operator/replace-key", body).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            state.policy.lookup(&old_ed).is_none(),
            "the old key must no longer authenticate"
        );
        let replaced = state
            .policy
            .lookup(&new_ed)
            .expect("new key must be enrolled");
        assert_eq!(replaced.operator_id, "mallory");
        assert_eq!(
            replaced.role,
            OperatorRole::Operator,
            "role must be preserved"
        );

        // A follow-up request signed with the OLD (now-replaced) key must be
        // refused by the *sealed channel*'s enrollment lookup -- this HTTP
        // test only proves the policy itself was mutated; the cross-surface
        // effect (sealed channel, /auth/challenge) is exercised by
        // `operator_sealed_channel`'s own tests against a live-mutated
        // `OperatorPolicy`.

        // An honestly-issued NON-Admin token is refused (403) and replaces
        // nothing -- the daemon gates on the token's own role, not on any
        // client UI.
        let target_op2 = HandshakeManager::new();
        let (approver_token, nonce2) = token_json_for(&daemon, OperatorRole::Approver, now);
        let body2 = replace_key_body(
            &admin_op,
            approver_token,
            "mallory",
            target_op2.identity_public_key_bytes(),
            &new_ml,
            None,
            &nonce2,
        );
        let (status2, _) = post_json(&router, "/operator/replace-key", body2).await;
        assert_eq!(status2, StatusCode::FORBIDDEN);
        assert!(
            state.policy.lookup(&new_ed).is_some(),
            "the successful replacement from above must be untouched by a refused request"
        );

        // Signature is over "mallory" but the body claims "eve": the
        // per-action signature no longer verifies -> refused, nothing
        // replaced.
        let (admin_token2, nonce3) = token_json_for(&daemon, OperatorRole::Admin, now);
        let mut tampered_body = serde_json::from_str::<serde_json::Value>(&replace_key_body(
            &admin_op,
            admin_token2,
            "mallory",
            target_op2.identity_public_key_bytes(),
            &new_ml,
            None,
            &nonce3,
        ))
        .unwrap();
        tampered_body["target_operator_id"] = serde_json::json!("eve");
        let (status3, _) =
            post_json(&router, "/operator/replace-key", tampered_body.to_string()).await;
        assert_eq!(status3, StatusCode::FORBIDDEN);
        assert!(
            state.policy.lookup(&new_ed).is_some(),
            "a tampered request must not mutate the policy"
        );
    }

    #[tokio::test]
    async fn admin_replace_key_endpoint_persists_to_the_operators_file() {
        // A full round trip proving the daemon's own durability promise:
        // replace a key over HTTP, then re-load a *fresh* `OperatorPolicy`
        // from the same `--operators-file` path (simulating a restart) and
        // confirm the replacement survived, closing the gap
        // `OperatorRevocations::revoke`'s own doc comment accepts for
        // revocation.
        let admin_op = HandshakeManager::new();
        let target_op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with_target(&admin_op, daemon.clone(), &target_op, OperatorRole::Viewer);

        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-http-persist-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let operators_file = dir.join("operators.json");
        // Seed the file with the same starting policy the daemon would have
        // loaded it from at startup, so the round trip is realistic.
        state.policy.persist_to(&operators_file).unwrap();

        let router = router(
            state.clone(),
            OperatorRevocations::empty(),
            empty_ledger(),
            Arc::new(Vec::new()),
            Some(operators_file.clone()),
        );
        let now = now_secs();
        let new_ed = [0x99u8; 32];
        let new_ml = vec![0xCCu8; ML_DSA_65_PK_LEN];

        let (admin_token, nonce) = token_json_for(&daemon, OperatorRole::Admin, now);
        let body = replace_key_body(
            &admin_op,
            admin_token,
            "mallory",
            new_ed,
            &new_ml,
            None,
            &nonce,
        );
        let (status, _) = post_json(&router, "/operator/replace-key", body).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Simulate a restart: load a brand-new `OperatorPolicy` from disk,
        // sharing nothing in-process with `state.policy`.
        let reloaded = OperatorPolicy::load(&operators_file).unwrap();
        assert!(
            reloaded
                .lookup(&target_op.identity_public_key_bytes())
                .is_none(),
            "the old key must not reappear after a reload"
        );
        let op = reloaded
            .lookup(&new_ed)
            .expect("the replacement must have been persisted to disk");
        assert_eq!(op.operator_id, "mallory");
        assert_eq!(op.role, OperatorRole::Viewer);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn admin_revoke_endpoint_revokes_target_and_gates_by_role() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with(&op, daemon.clone()); // "alice" enrolled as Admin
        let revocations = OperatorRevocations::empty();
        let router = router(
            state,
            revocations.clone(),
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );
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

    // ─── revoked-operator refusal (an operator can be revoked while their
    // enrollment key stays valid -- these prove every authenticated path
    // that used to only check enrollment also checks the live revocation
    // list) ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn revoked_operator_cannot_mint_a_fresh_token() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with(&op, daemon); // "alice" enrolled as Admin
        let revocations = OperatorRevocations::empty();
        revocations.revoke("alice");
        let router = router(
            state,
            revocations,
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );

        let (status, chal_body) = post_json(&router, "/auth/challenge", "{}".to_string()).await;
        assert_eq!(status, StatusCode::OK);
        let chal: serde_json::Value = serde_json::from_str(&chal_body).unwrap();
        let nonce: [u8; 32] = decode_fixed(chal["nonce"].as_str().unwrap()).unwrap();

        let ed_pubkey = op.identity_public_key_bytes();
        let ml_dsa_pubkey = op.ml_dsa_public_key_bytes().to_vec();
        let transcript =
            xenia_operator_proto::challenge_transcript(&nonce, &ed_pubkey, &ml_dsa_pubkey);
        let body = serde_json::json!({
            "nonce": hex::encode(nonce),
            "ed_pubkey": hex::encode(ed_pubkey),
            "ml_dsa_pubkey": hex::encode(&ml_dsa_pubkey),
            "ed_signature": hex::encode(op.sign(&transcript).to_bytes()),
            "ml_dsa_signature": hex::encode(op.sign_ml_dsa(&transcript)),
        })
        .to_string();
        let (status, resp_body) = post_json(&router, "/auth/verify", body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "revoked operator must not be able to mint a fresh token: {resp_body}"
        );
    }

    #[tokio::test]
    async fn revoked_admin_cannot_revoke_another_operator() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with(&op, daemon.clone()); // "alice" enrolled as Admin
        let revocations = OperatorRevocations::empty();
        revocations.revoke("alice");
        let router = router(
            state,
            revocations.clone(),
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );
        // "alice"'s token is otherwise entirely valid -- unexpired, correctly
        // signed, Admin role -- it's only her own revoked status that must
        // stop this.
        let (admin_token, nonce) = token_json_for(&daemon, OperatorRole::Admin, now_secs());
        let body = revoke_body(&op, admin_token, "bob", &nonce);
        let (status, _) = post_json(&router, "/operator/revoke", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            !revocations.is_revoked("bob"),
            "a revoked admin must not be able to revoke anyone else"
        );
    }

    #[tokio::test]
    async fn revoked_admin_cannot_replace_another_operators_key() {
        let admin_op = HandshakeManager::new();
        let target_op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with_target(&admin_op, daemon.clone(), &target_op, OperatorRole::Viewer);
        let revocations = OperatorRevocations::empty();
        revocations.revoke("alice");
        let router = router(
            state.clone(),
            revocations,
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );
        let (admin_token, nonce) = token_json_for(&daemon, OperatorRole::Admin, now_secs());
        let new_ed = [0x99u8; 32];
        let new_ml = vec![0xCCu8; ML_DSA_65_PK_LEN];
        let body = replace_key_body(
            &admin_op,
            admin_token,
            "mallory",
            new_ed,
            &new_ml,
            None,
            &nonce,
        );
        let (status, _) = post_json(&router, "/operator/replace-key", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            state.policy.lookup(&new_ed).is_none(),
            "a revoked admin must not be able to seize another operator's identity"
        );
    }

    #[tokio::test]
    async fn revoked_operator_cannot_read_the_audit_ledger() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let state = state_with(&op, daemon.clone()); // "alice" enrolled as Admin
        let revocations = OperatorRevocations::empty();
        revocations.revoke("alice");
        let router = router(
            state,
            revocations,
            empty_ledger(),
            Arc::new(Vec::new()),
            None,
        );
        let (token, _nonce) = token_json_for(&daemon, OperatorRole::Admin, now_secs());
        let (status, _) = get_json_with_header(
            &router,
            "/v1/audit/ledger",
            "X-Operator-Token",
            &token.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
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
            Arc::new(Vec::new()),
            None,
        );

        let (status, _) =
            get_json_with_header(&router, "/v1/audit/ledger", "X-Operator-Token", "not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn audit_witness_proves_extension_from_a_retained_checkpoint() {
        use xenia_ledger::{ConsentEventRecord, ConsentKind, Verifier};

        let signing_key = SigningKey::from_bytes(&[83u8; 32]);
        let mut ledger = Chain::new(signing_key);
        let event = |request: u8, kind| ConsentEventRecord {
            source_id: [7u8; 32],
            session_id: uuid::Uuid::from_bytes([8u8; 16]),
            request_id: uuid::Uuid::from_bytes([request; 16]),
            kind,
            scope: "test".to_string(),
        };
        ledger.append(event(1, ConsentKind::Request)).unwrap();
        let retained = ledger.sign_checkpoint(100);
        ledger.append(event(2, ConsentKind::Approval)).unwrap();
        ledger.append(event(3, ConsentKind::Revocation)).unwrap();

        let witness = build_audit_extension_witness(&ledger, retained.entry_count, 101).unwrap();
        assert_eq!(witness.schema, AUDIT_EXTENSION_WITNESS_SCHEMA);
        assert_eq!(witness.entries.len(), 2);
        Verifier::verify_checkpoint_extension(
            &retained,
            &witness.checkpoint,
            &witness.entries,
        )
        .unwrap();
    }

    #[test]
    fn audit_witness_refuses_a_base_ahead_of_the_current_ledger() {
        let ledger = Chain::new(SigningKey::from_bytes(&[84u8; 32]));
        assert_eq!(
            build_audit_extension_witness(&ledger, 1, 100),
            Err(AuditWitnessBuildError::BaseAheadOfLedger { base: 1, ledger: 0 })
        );
    }
}
