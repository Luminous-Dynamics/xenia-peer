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
//! **Scope note**: this removes the seeds' *persistent* browser-side
//! storage, not their presence in the browser process's memory during a
//! session — the console still holds the fetched seeds in memory and signs
//! locally with them (both the `/auth/*` ceremony and the sealed-channel
//! handshake). A follow-up that has the agent perform the signing itself,
//! so raw key material never reaches the browser process at all, is scoped
//! but not built — see `docs/security/OPERATOR_SECURITY_MODEL.md` §9.

use leptos::prelude::*;
use serde::Deserialize;
use web_sys::Storage;

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
