// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Browser-side client for the local `xenia-operator-agent` process (see
//! that crate's module doc comment for the full security model this
//! replaces).
//!
//! The console used to generate the operator's Ed25519 + ML-DSA seeds
//! itself and persist them in `localStorage` — plaintext hex, readable by
//! an XSS bug, a malicious browser extension, or a compromised same-origin
//! dependency. Instead, the seeds now live in a permission-restricted file
//! held by a small native agent process the operator runs locally, and this
//! module fetches them into memory once per page session over a
//! token-authenticated, origin-restricted `127.0.0.1` API.
//!
//! **Scope note** (updated — Step 5 of
//! `docs/security/SIGNER_DELEGATION_DESIGN.md` landed): the `/auth/*` HTTP
//! ceremony (challenge / consent-action / revoke — "Track A") now asks the
//! agent to sign via [`sign_challenge`]/[`sign_consent_action`]/
//! [`sign_revoke`] instead of holding the seeds in memory and signing
//! locally with them. [`fetch_seeds`] still exists and is still called:
//! the sealed-channel handshake ("Track B",
//! `crate::sealed_consent`/`crate::pages::consent`) hasn't been migrated
//! yet, so the console still needs the raw seeds for that one path. Once
//! Track B migrates too (a separately reviewed follow-up), `GET /seeds`
//! and this function are retired entirely.

use leptos::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use web_sys::Storage;

use xenia_operator_agent_proto::{
    AgentErrorResponse, SignChallengeRequest, SignChallengeResponse, SignConsentActionRequest,
    SignConsentActionResponse, SignRevokeRequest, SignRevokeResponse,
};

const AGENT_URL_KEY: &str = "xenia-admin.agent.url";
const AGENT_TOKEN_KEY: &str = "xenia-admin.agent.token";

const DEFAULT_AGENT_URL: &str = "http://127.0.0.1:8180";

fn local_storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok()?
}

/// The operator agent's connection settings: its URL and pairing token.
///
/// Unlike the seeds themselves, these *are* persisted in `localStorage` --
/// they're configuration, not secret key material. The token alone lets a
/// caller fetch seeds from the agent, but only from `127.0.0.1` on the same
/// machine the agent is running on (the agent never binds a wider address),
/// so a leaked token isn't independently exploitable the way a leaked
/// signing key would be.
#[derive(Clone, Copy)]
pub struct AgentConfig {
    pub agent_url: RwSignal<String>,
    pub agent_token: RwSignal<String>,
}

impl AgentConfig {
    pub fn new() -> Self {
        let agent_url = RwSignal::new(
            load_from_storage(AGENT_URL_KEY).unwrap_or_else(|| DEFAULT_AGENT_URL.to_string()),
        );
        let agent_token = RwSignal::new(load_from_storage(AGENT_TOKEN_KEY).unwrap_or_default());
        Self {
            agent_url,
            agent_token,
        }
    }

    pub fn save(&self) {
        persist_to_storage(AGENT_URL_KEY, &self.agent_url.get());
        persist_to_storage(AGENT_TOKEN_KEY, &self.agent_token.get());
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn load_from_storage(key: &str) -> Option<String> {
    local_storage()?.get_item(key).ok().flatten()
}

fn persist_to_storage(key: &str, val: &str) {
    if let Some(storage) = local_storage() {
        let _ = storage.set_item(key, val);
    }
}

#[derive(Deserialize)]
struct SeedsDto {
    ed25519_secret_hex: String,
    ml_dsa_seed_hex: String,
}

/// Fetch the operator's seeds from the agent at `agent_url`, authenticated
/// with `token`. The caller is responsible for holding the result only in
/// memory (never persisting it) -- see the module doc comment.
pub async fn fetch_seeds(agent_url: &str, token: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let dto: SeedsDto = agent_get(agent_url, token, "/seeds").await?;
    let ed = decode32(&dto.ed25519_secret_hex)?;
    let ml = decode32(&dto.ml_dsa_seed_hex)?;
    Ok((ed, ml))
}

async fn agent_get<T: for<'de> Deserialize<'de>>(
    agent_url: &str,
    token: &str,
    path: &str,
) -> Result<T, String> {
    use gloo_net::http::Request;
    let url = format!("{}{path}", agent_url.trim_end_matches('/'));
    let resp = Request::get(&url)
        .header("X-Agent-Token", token)
        .send()
        .await
        .map_err(|e| {
            format!("couldn't reach the operator agent at {agent_url} -- is it running? ({e})")
        })?;
    if !resp.ok() {
        return Err(format!(
            "operator agent at {agent_url} refused the request (HTTP {})",
            resp.status()
        ));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

fn decode32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "operator agent returned a malformed seed".to_string())
}

/// Ask the local agent to sign the daemon's `/auth/challenge` nonce (both
/// algorithms), proving possession of the enrolled operator key without
/// the raw seeds ever leaving the agent process. See
/// `crate::operator_session::authenticate`, the only caller.
pub async fn sign_challenge(
    agent_url: &str,
    token: &str,
    req: &SignChallengeRequest,
) -> Result<SignChallengeResponse, String> {
    agent_post(agent_url, token, "/v1/sign/challenge", req).await
}

/// Ask the local agent to sign a session-bound consent decision. See
/// `crate::operator_session::build_consent_request`, the only caller.
pub async fn sign_consent_action(
    agent_url: &str,
    token: &str,
    req: &SignConsentActionRequest,
) -> Result<SignConsentActionResponse, String> {
    agent_post(agent_url, token, "/v1/sign/consent-action", req).await
}

/// Ask the local agent to sign an admin's authorization to revoke another
/// operator. See `crate::operator_session::build_revoke_request`, the only
/// caller.
pub async fn sign_revoke(
    agent_url: &str,
    token: &str,
    req: &SignRevokeRequest,
) -> Result<SignRevokeResponse, String> {
    agent_post(agent_url, token, "/v1/sign/revoke", req).await
}

/// POST a typed `/v1/sign/*` request and decode the typed response. On a
/// non-2xx, tries to parse the agent's typed [`AgentErrorResponse`] for an
/// accurate message (e.g. "host not trusted, confirm on the agent's
/// terminal") rather than surfacing a bare status code; falls back to the
/// raw response body if that parse fails. Reads the body exactly once (as
/// text) either way, since a `fetch` response body can only be consumed
/// once.
async fn agent_post<Req: Serialize, Resp: DeserializeOwned>(
    agent_url: &str,
    token: &str,
    path: &str,
    body: &Req,
) -> Result<Resp, String> {
    use gloo_net::http::Request;
    let url = format!("{}{path}", agent_url.trim_end_matches('/'));
    let json_body = serde_json::to_string(body).map_err(|e| e.to_string())?;
    let resp = Request::post(&url)
        .header("X-Agent-Token", token)
        .header("content-type", "application/json")
        .body(json_body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| {
            format!("couldn't reach the operator agent at {agent_url} -- is it running? ({e})")
        })?;
    let ok = resp.ok();
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !ok {
        if let Ok(err) = serde_json::from_str::<AgentErrorResponse>(&text) {
            return Err(format!(
                "operator agent refused ({:?}): {}",
                err.code, err.message
            ));
        }
        return Err(format!(
            "operator agent at {agent_url} refused the request (HTTP {status}): {text}"
        ));
    }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}
