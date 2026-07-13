// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator-RBAC ceremony — the **browser side** of `OPERATOR_RBAC_PLAN.md`
//! Phase 5, revised by Step 5 of
//! `docs/security/SIGNER_DELEGATION_DESIGN.md`. This is the console's half
//! of the exact flow the daemon already enforces:
//!
//! ```text
//!   GET  /auth/daemon-identity -> DaemonIdentityCertificate
//!   POST /auth/challenge       -> host-attested nonce
//!   ask the local agent to sign the challenge (both keys) -- it verifies
//!     the certificate + attestation itself; the raw seeds never reach
//!     this process
//!   POST /auth/verify          -> daemon-signed, role-scoped token
//!   ask the local agent to sign consent_action_transcript(action,
//!     session_id, token_nonce) per action, relaying the full session
//!     token so the agent can verify it
//!   send  { token, action, action_signature }  on the consent socket
//! ```
//!
//! **Scope note**: this is Track A only (the plain-HTTP `/auth/*`
//! ceremony). Since Steps 6 and 7 of
//! `docs/security/SIGNER_DELEGATION_DESIGN.md` landed, nothing in this
//! crate holds the operator's raw seeds at all, for any purpose -- the
//! sealed-channel handshake ("Track B", `crate::sealed_consent`) relays the
//! handshake's own wire bytes through the local agent, and the Sessions-page
//! enrollment display (`crate::app::OperatorIdentityState`) fetches only
//! *public* info via `crate::agent_client::fetch_identity_info`. This module
//! no longer needs a local operator-identity type at all.
//!
//! Correctness rests on shared crates, so nothing can drift from the
//! daemon or the agent:
//! - [`xenia_operator_proto`] provides the *exact* signed transcripts,
//!   role model, and [`xenia_operator_proto::DaemonIdentityCertificate`]
//!   shape the daemon and agent both use.
//! - [`xenia_operator_agent_proto`] provides the *exact* `/v1/sign/*`
//!   request/response shapes the agent parses -- see
//!   `apps/xenia-operator-agent`'s `daemon_evidence` module for what it
//!   verifies before signing anything.

use serde::Deserialize;

use xenia_operator_agent_proto::{
    SignChallengeRequest, SignConsentActionRequest, SignRequestCommon, SignRevokeRequest,
    SignedTokenDto,
};
use xenia_operator_proto::{
    ConsentAction, DaemonIdentityCertificate, OperatorAction, OperatorRole,
};

/// Track A (the plain-HTTP `/auth/*` ceremony -- challenge/consent-action/
/// revoke) is suite-independent: the daemon's host-identity certificate
/// vouches for the HTTP-auth key regardless of which sealed-channel suite
/// (if any) is later negotiated -- there's only one host identity. This is
/// just a stable pin-store key for Track A; it is *not* the same knob as
/// `DaemonConfig::high_security`, which selects an actual different suite
/// for Track B's sealed channel.
const TRACK_A_SUITE: &str = "standard";

/// A daemon-issued, role-scoped session token. The raw `token_json` is
/// re-embedded verbatim into every consent request (the daemon re-verifies its
/// own signature); the other fields are parsed out so the console can gate
/// the UI and (via [`Self::to_signed_token_dto`]) ask the agent to verify
/// and sign against this exact token.
#[derive(Clone)]
pub struct OperatorSession {
    /// The enrolled operator id the daemon attributed this session to.
    pub operator_id: String,
    /// The role the daemon scoped the token to. UI gating uses exactly this.
    pub role: OperatorRole,
    /// Token expiry (unix secs) — the console stops using it past this.
    pub expires_at: u64,
    issued_at: u64,
    token_nonce: [u8; 16],
    signature_hex: String,
    token_json: serde_json::Value,
}

impl OperatorSession {
    /// Whether this session's role permits `action` — identical logic to the
    /// daemon's authorization (both call [`OperatorRole::permits`]).
    pub fn permits(&self, action: OperatorAction) -> bool {
        self.role.permits(action)
    }

    /// Whether the token is still within its validity window per the browser
    /// wall-clock. An expired token would be refused by the daemon anyway; the
    /// console stops offering actions once it lapses so the operator re-auths
    /// instead of clicking into a rejection.
    pub fn is_valid(&self) -> bool {
        let now_secs = (js_sys::Date::now() / 1000.0) as u64;
        now_secs < self.expires_at
    }

    /// This session's token in the shape the agent's `/v1/sign/*` endpoints
    /// expect, so it can verify the daemon's own signature over it before
    /// trusting the `token_nonce` bound into a consent-action/revoke
    /// transcript. Built from fields already parsed at `authenticate()`
    /// time -- infallible, no re-parsing of `token_json`.
    fn to_signed_token_dto(&self) -> SignedTokenDto {
        SignedTokenDto {
            operator_id: self.operator_id.clone(),
            role: self.role,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            token_nonce_hex: hex::encode(self.token_nonce),
            signature_hex: self.signature_hex.clone(),
        }
    }
}

#[derive(Deserialize)]
struct ChallengeDto {
    nonce: String,
    host_ed_attestation_hex: String,
    host_ml_dsa_attestation_hex: String,
}

// Every field the console needs, including the ones (`issued_at`,
// `signature`) only [`OperatorSession::to_signed_token_dto`] uses -- the
// rest of the token JSON (there is none beyond these) is preserved intact
// in `token_json` and re-sent verbatim.
#[derive(Deserialize)]
struct TokenFields {
    operator_id: String,
    role: OperatorRole,
    issued_at: u64,
    expires_at: u64,
    token_nonce: String,
    signature: String,
}

/// Run the full challenge → agent-sign → verify ceremony against the
/// daemon's `/auth/*` routes at `endpoint`, returning a role-scoped
/// session. The operator's seeds never reach this process: the agent (at
/// `agent_url`, authenticated with `agent_token`) verifies the daemon's
/// identity evidence and signs on the console's behalf.
pub async fn authenticate(
    endpoint: &str,
    agent_url: &str,
    agent_token: &str,
) -> Result<OperatorSession, String> {
    let base = endpoint.trim_end_matches('/');

    // 1. Fetch the daemon's host-identity delegation certificate -- the
    //    evidence the agent verifies (and computes the fingerprint from)
    //    before it will sign anything. See
    //    docs/security/SIGNER_DELEGATION_DESIGN.md's "typed transcripts
    //    are not enough" section for why a bare fingerprint isn't enough.
    let cert = fetch_daemon_certificate(base).await?;

    // 2. Ask for a fresh, host-attested single-use challenge.
    let chal: ChallengeDto = post_json(&format!("{base}/auth/challenge"), "{}".to_string()).await?;

    // 3. Ask the local agent to sign it. The agent verifies `cert` and the
    //    attestation itself, then signs with both algorithms.
    let signed = crate::agent_client::sign_challenge(
        agent_url,
        agent_token,
        &SignChallengeRequest {
            common: SignRequestCommon {
                schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
                daemon_certificate: cert,
                daemon_endpoint: endpoint.to_string(),
                suite: TRACK_A_SUITE.to_string(),
                request_id: request_id(),
            },
            nonce_hex: chal.nonce.clone(),
            host_ed_attestation_hex: chal.host_ed_attestation_hex.clone(),
            host_ml_dsa_attestation_hex: chal.host_ml_dsa_attestation_hex.clone(),
        },
    )
    .await?;

    // 4. Exchange the signed response for a daemon-signed, role-scoped token.
    let verify_body = serde_json::json!({
        "nonce": chal.nonce,
        "ed_pubkey": signed.ed25519_pubkey_hex,
        "ml_dsa_pubkey": signed.ml_dsa_pubkey_hex,
        "ed_signature": signed.ed_signature_hex,
        "ml_dsa_signature": signed.ml_dsa_signature_hex,
    })
    .to_string();
    let token_json: serde_json::Value =
        post_json(&format!("{base}/auth/verify"), verify_body).await?;
    let fields: TokenFields =
        serde_json::from_value(token_json.clone()).map_err(|e| format!("bad token: {e}"))?;
    let token_nonce =
        decode16(&fields.token_nonce).map_err(|_| "token nonce malformed".to_string())?;

    Ok(OperatorSession {
        operator_id: fields.operator_id,
        role: fields.role,
        expires_at: fields.expires_at,
        issued_at: fields.issued_at,
        token_nonce,
        signature_hex: fields.signature,
        token_json,
    })
}

/// Build the authenticated consent-action JSON the daemon parses on the consent
/// socket: `{ token, action, action_signature }`. The per-action Ed25519
/// signature binds the action to the exact session and token, so a captured
/// signature can't be replayed for a different action/session/token. The
/// agent verifies `session`'s token before signing -- see
/// [`OperatorSession::to_signed_token_dto`].
pub async fn build_consent_request(
    endpoint: &str,
    agent_url: &str,
    agent_token: &str,
    session: &OperatorSession,
    action: ConsentAction,
    session_id: &[u8; 16],
) -> Result<String, String> {
    let base = endpoint.trim_end_matches('/');
    let cert = fetch_daemon_certificate(base).await?;
    let signed = crate::agent_client::sign_consent_action(
        agent_url,
        agent_token,
        &SignConsentActionRequest {
            common: SignRequestCommon {
                schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
                daemon_certificate: cert,
                daemon_endpoint: endpoint.to_string(),
                suite: TRACK_A_SUITE.to_string(),
                request_id: request_id(),
            },
            action,
            session_id_hex: hex::encode(session_id),
            token: session.to_signed_token_dto(),
        },
    )
    .await?;
    Ok(serde_json::json!({
        "token": session.token_json,
        "action": action.as_str(),
        "action_signature": signed.ed_signature_hex,
    })
    .to_string())
}

/// Build the authenticated `POST /operator/revoke` body the daemon parses:
/// `{ token, target_operator_id, action_signature }`. The per-action Ed25519
/// signature is over the shared `revoke_operator_transcript(target,
/// token_nonce)` -- built by the agent, which also verifies `session`'s
/// token first (see [`OperatorSession::to_signed_token_dto`]) -- so it binds
/// this revocation to the exact target and the admin's current token,
/// byte-identical to what the daemon verifies. Only an Admin session's
/// token will be authorized daemon-side. Privileged: the agent runs its own
/// mandatory native confirmation for this action regardless of how
/// well-trusted the daemon already is.
pub async fn build_revoke_request(
    endpoint: &str,
    agent_url: &str,
    agent_token: &str,
    session: &OperatorSession,
    target_operator_id: &str,
) -> Result<String, String> {
    let base = endpoint.trim_end_matches('/');
    let cert = fetch_daemon_certificate(base).await?;
    let signed = crate::agent_client::sign_revoke(
        agent_url,
        agent_token,
        &SignRevokeRequest {
            common: SignRequestCommon {
                schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
                daemon_certificate: cert,
                daemon_endpoint: endpoint.to_string(),
                suite: TRACK_A_SUITE.to_string(),
                request_id: request_id(),
            },
            target_operator_id: target_operator_id.to_string(),
            token: session.to_signed_token_dto(),
        },
    )
    .await?;
    Ok(serde_json::json!({
        "token": session.token_json,
        "target_operator_id": target_operator_id,
        "action_signature": signed.ed_signature_hex,
    })
    .to_string())
}

/// Fetch the daemon's host-identity delegation certificate. No local
/// caching (deliberately -- see the Step 5 design note): each of the three
/// operations above is human-paced (sign-in, an approve/deny/revoke
/// click), so one extra small `GET` per call is cheap and avoids any
/// cache-invalidation-on-endpoint-change bug.
async fn fetch_daemon_certificate(base: &str) -> Result<DaemonIdentityCertificate, String> {
    get_json(&format!("{base}/auth/daemon-identity")).await
}

/// A caller-generated id for correlating a `/v1/sign/*` request through
/// logs -- not itself a security boundary, so a UUID is sufficient (no
/// need for a CSPRNG-sourced value here specifically).
fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ─── small helpers ───────────────────────────────────────────────────────────

fn decode16(s: &str) -> Result<[u8; 16], ()> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(())
}

/// POST `body` as JSON to `url` and deserialize the JSON response. Any non-2xx
/// status is surfaced as an error string (the daemon's stable message).
async fn post_json<T: for<'de> Deserialize<'de>>(url: &str, body: String) -> Result<T, String> {
    use gloo_net::http::Request;
    let resp = Request::post(url)
        .header("content-type", "application/json")
        .body(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    if !resp.ok() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("{status}: {text}"));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

/// GET `url` and deserialize the JSON response. Mirrors [`post_json`]'s
/// error handling.
async fn get_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T, String> {
    use gloo_net::http::Request;
    let resp = Request::get(url)
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    if !resp.ok() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("{status}: {text}"));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}
