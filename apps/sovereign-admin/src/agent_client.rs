// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Browser-side client for the local `xenia-operator-agent` process (see
//! that crate's module doc comment for the full security model this
//! replaces).
//!
//! The console used to generate the operator's Ed25519 + ML-DSA seeds
//! itself and persist them in `localStorage` — plaintext hex, readable by
//! an XSS bug, a malicious browser extension, or a compromised same-origin
//! dependency. Later revisions moved the seeds into a permission-restricted
//! file held by a small native agent process, but still fetched them into
//! the browser's memory each page session to sign/handshake locally.
//!
//! **Scope note** (updated — all seven steps of
//! `docs/security/SIGNER_DELEGATION_DESIGN.md` have landed): the raw seeds
//! no longer reach this process at all, not even transiently. The `/auth/*`
//! HTTP ceremony (challenge / consent-action / revoke — "Track A") asks the
//! agent to sign via [`sign_challenge`]/[`sign_consent_action`]/
//! [`sign_revoke`]; the sealed-channel handshake ("Track B",
//! `crate::sealed_consent`) asks the agent to drive the handshake itself via
//! [`handshake_begin`]/[`handshake_finish`]; and the Sessions-page
//! enrollment display (`crate::app::OperatorIdentityState`) fetches only
//! *public* data via [`fetch_identity_info`]. `GET /seeds` and this
//! module's old `fetch_seeds` are gone -- there is no HTTP surface left, on
//! either side, that transmits the seeds.
//!
//! **Item 4 of `docs/security/POST_DELEGATION_HARDENING_PLAN.md`** (updated
//! again): the raw pairing token used to be the credential sent on every
//! agent request, and this module used to persist it in `localStorage`
//! indefinitely -- unlike the seeds, it never expired. It's now
//! bootstrap-only: [`pair`] exchanges it for a short-lived
//! [`AgentSessionToken`], and every other function here takes that session
//! (not the raw token). [`ensure_fresh_session`] is what call sites
//! actually use day-to-day: it returns the current session, transparently
//! renewing it via [`refresh_session`] when it's close to expiry (so an
//! actively-used console never needs the raw token again), and surfaces a
//! clear "please re-pair" error once it's actually expired rather than
//! attempting a request that would just fail agent-side. See
//! `apps/xenia-operator-agent`'s `agent_session` module for the full
//! rationale and the [`AgentSessionToken`] doc comment for why there's no
//! single-session revocation.

use leptos::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use web_sys::Storage;

pub use xenia_operator_agent_proto::AgentSessionToken;
use xenia_operator_agent_proto::{
    AgentErrorResponse, HandshakeBeginRequest, HandshakeBeginResponse, HandshakeFinishRequest,
    HandshakeFinishResponse, SignChallengeRequest, SignChallengeResponse, SignConsentActionRequest,
    SignConsentActionResponse, SignRevokeRequest, SignRevokeResponse,
};

const AGENT_URL_KEY: &str = "xenia-admin.agent.url";
const AGENT_SESSION_KEY: &str = "xenia-admin.agent.session";

const DEFAULT_AGENT_URL: &str = "http://127.0.0.1:8180";

/// A session within this many seconds of `expires_at` is proactively
/// renewed by [`ensure_fresh_session`] rather than waited out -- long
/// enough that a renewal attempt has time to complete (and, if it fails,
/// for a retry on the *next* call) before the session actually lapses
/// mid-operation.
const REFRESH_MARGIN_SECS: u64 = 300;

fn local_storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// The operator agent's connection settings: its URL, and the current
/// short-lived session (if paired). The raw pairing token is deliberately
/// **not** a field here -- it's only ever held transiently (the Sessions
/// page's own input signal) for exactly as long as it takes to call
/// [`pair`], never persisted. `agent_session` *is* persisted in
/// `localStorage`: unlike the raw token, it expires, so a leaked copy is
/// only useful until then -- see the module doc comment.
#[derive(Clone, Copy)]
pub struct AgentConfig {
    pub agent_url: RwSignal<String>,
    pub agent_session: RwSignal<Option<AgentSessionToken>>,
}

impl AgentConfig {
    pub fn new() -> Self {
        let agent_url = RwSignal::new(
            load_from_storage(AGENT_URL_KEY).unwrap_or_else(|| DEFAULT_AGENT_URL.to_string()),
        );
        let agent_session = RwSignal::new(
            load_from_storage(AGENT_SESSION_KEY).and_then(|s| serde_json::from_str(&s).ok()),
        );
        Self {
            agent_url,
            agent_session,
        }
    }

    pub fn save(&self) {
        persist_to_storage(AGENT_URL_KEY, &self.agent_url.get());
    }

    /// Set the current session (from a fresh [`pair`] or [`refresh_session`]
    /// call) and persist it immediately -- sessions matter to persist as
    /// soon as they're minted, not only when the operator happens to click
    /// a "Save" button elsewhere on the page.
    pub fn set_session(&self, session: AgentSessionToken) {
        if let Ok(json) = serde_json::to_string(&session) {
            persist_to_storage(AGENT_SESSION_KEY, &json);
        }
        self.agent_session.set(Some(session));
    }

    /// Clear the current session (e.g. once it's confirmed expired) and
    /// remove it from storage, so a stale, unusable session doesn't linger
    /// and doesn't get echoed back as if it were still good.
    pub fn clear_session(&self) {
        if let Some(storage) = local_storage() {
            let _ = storage.remove_item(AGENT_SESSION_KEY);
        }
        self.agent_session.set(None);
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

/// Exchange the raw pairing token for a fresh session
/// (`POST /v1/pair`, `X-Agent-Token`). The one call site in this crate that
/// still touches the raw token -- see the module doc comment.
pub async fn pair(agent_url: &str, pairing_token: &str) -> Result<AgentSessionToken, String> {
    agent_post_empty(agent_url, "x-agent-token", pairing_token, "/v1/pair").await
}

/// Exchange a still-valid session for a fresh one
/// (`POST /v1/session/refresh`, `X-Agent-Session`). Called by
/// [`ensure_fresh_session`], not directly by UI code.
pub async fn refresh_session(
    agent_url: &str,
    session: &AgentSessionToken,
) -> Result<AgentSessionToken, String> {
    agent_post_empty(
        agent_url,
        "x-agent-session",
        &session.to_header_value(),
        "/v1/session/refresh",
    )
    .await
}

/// The credential every other `/v1/sign/*`/`/v1/handshake/*`/`/identity`
/// call needs: the current session, refreshed first if it's within
/// [`REFRESH_MARGIN_SECS`] of expiring. Returns a clear error -- without
/// attempting any agent request that would just be refused -- if there is
/// no session, or it's already expired.
///
/// A refresh failure (agent unreachable, momentarily) doesn't block the
/// caller: it falls back to the still-technically-valid current session
/// for *this* call, and the next call tries the refresh again. Only an
/// actually-expired session is a hard error.
pub async fn ensure_fresh_session(
    agent_url: &str,
    config: &AgentConfig,
) -> Result<AgentSessionToken, String> {
    let Some(current) = config.agent_session.get_untracked() else {
        return Err(
            "not paired with the operator agent -- pair on the Sessions page first".to_string(),
        );
    };
    let now = now_secs();
    if now >= current.expires_at {
        config.clear_session();
        return Err(
            "operator agent session expired -- pair again on the Sessions page".to_string(),
        );
    }
    if now + REFRESH_MARGIN_SECS < current.expires_at {
        return Ok(current);
    }
    match refresh_session(agent_url, &current).await {
        Ok(fresh) => {
            config.set_session(fresh.clone());
            Ok(fresh)
        }
        Err(_) => Ok(current),
    }
}

/// The fields of the agent's `GET /identity` response this console actually
/// uses -- the fingerprint and a paste-ready enrollment record, never the
/// seeds those are derived from. The response also carries the individual
/// public keys (`ed25519_pubkey_hex`/`ml_dsa_pubkey_hex`/
/// `ml_dsa_87_pubkey_hex`); serde ignores them here since nothing in this
/// crate needs them separately from the record they're already embedded in.
#[derive(Deserialize)]
pub struct IdentityDto {
    pub fingerprint_hex: String,
    pub enrollment_record_json: String,
}

/// Fetch the operator's *public* identity info from the agent at
/// `agent_url`, authenticated with `session`. Never returns seed material --
/// see the module doc comment.
pub async fn fetch_identity_info(
    agent_url: &str,
    session: &AgentSessionToken,
) -> Result<IdentityDto, String> {
    agent_get(agent_url, session, "/identity").await
}

async fn agent_get<T: for<'de> Deserialize<'de>>(
    agent_url: &str,
    session: &AgentSessionToken,
    path: &str,
) -> Result<T, String> {
    use gloo_net::http::Request;
    let url = format!("{}{path}", agent_url.trim_end_matches('/'));
    let resp = Request::get(&url)
        .header("X-Agent-Session", &session.to_header_value())
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

/// Ask the local agent to sign the daemon's `/auth/challenge` nonce (both
/// algorithms), proving possession of the enrolled operator key without
/// the raw seeds ever leaving the agent process. See
/// `crate::operator_session::authenticate`, the only caller.
pub async fn sign_challenge(
    agent_url: &str,
    session: &AgentSessionToken,
    req: &SignChallengeRequest,
) -> Result<SignChallengeResponse, String> {
    agent_post(agent_url, session, "/v1/sign/challenge", req).await
}

/// Ask the local agent to sign a session-bound consent decision. See
/// `crate::operator_session::build_consent_request`, the only caller.
pub async fn sign_consent_action(
    agent_url: &str,
    session: &AgentSessionToken,
    req: &SignConsentActionRequest,
) -> Result<SignConsentActionResponse, String> {
    agent_post(agent_url, session, "/v1/sign/consent-action", req).await
}

/// Ask the local agent to sign an admin's authorization to revoke another
/// operator. See `crate::operator_session::build_revoke_request`, the only
/// caller.
pub async fn sign_revoke(
    agent_url: &str,
    session: &AgentSessionToken,
    req: &SignRevokeRequest,
) -> Result<SignRevokeResponse, String> {
    agent_post(agent_url, session, "/v1/sign/revoke", req).await
}

/// Ask the local agent to run the viewer half of the sealed-channel
/// handshake against a daemon's `HostHello`. See
/// `crate::sealed_consent::drive_agent_handshake`, the only caller.
pub async fn handshake_begin(
    agent_url: &str,
    session: &AgentSessionToken,
    req: &HandshakeBeginRequest,
) -> Result<HandshakeBeginResponse, String> {
    agent_post(agent_url, session, "/v1/handshake/begin", req).await
}

/// Ask the local agent to finish a pending handshake against a daemon's
/// `HostFinalize`, releasing session key material once its host-trust
/// policy accepts the resulting authenticated fingerprint. See
/// `crate::sealed_consent::drive_agent_handshake`, the only caller.
pub async fn handshake_finish(
    agent_url: &str,
    session: &AgentSessionToken,
    req: &HandshakeFinishRequest,
) -> Result<HandshakeFinishResponse, String> {
    agent_post(agent_url, session, "/v1/handshake/finish", req).await
}

/// POST a typed `/v1/sign/*` or `/v1/handshake/*` request and decode the
/// typed response. On a
/// non-2xx, tries to parse the agent's typed [`AgentErrorResponse`] for an
/// accurate message (e.g. "host not trusted, confirm on the agent's
/// terminal") rather than surfacing a bare status code; falls back to the
/// raw response body if that parse fails. Reads the body exactly once (as
/// text) either way, since a `fetch` response body can only be consumed
/// once.
async fn agent_post<Req: Serialize, Resp: DeserializeOwned>(
    agent_url: &str,
    session: &AgentSessionToken,
    path: &str,
    body: &Req,
) -> Result<Resp, String> {
    use gloo_net::http::Request;
    let url = format!("{}{path}", agent_url.trim_end_matches('/'));
    let json_body = serde_json::to_string(body).map_err(|e| e.to_string())?;
    let resp = Request::post(&url)
        .header("X-Agent-Session", &session.to_header_value())
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

/// POST with no body, presenting `header_value` under `header_name` --
/// backs [`pair`] (`x-agent-token`) and [`refresh_session`]
/// (`x-agent-session`). Both endpoints just mint a session; the only thing
/// that differs between them is which credential authenticates the call.
async fn agent_post_empty(
    agent_url: &str,
    header_name: &str,
    header_value: &str,
    path: &str,
) -> Result<AgentSessionToken, String> {
    use gloo_net::http::Request;
    let url = format!("{}{path}", agent_url.trim_end_matches('/'));
    let resp = Request::post(&url)
        .header(header_name, header_value)
        .body(String::new())
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
        return Err(format!(
            "operator agent at {agent_url} refused the request (HTTP {status}): {text}"
        ));
    }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}
