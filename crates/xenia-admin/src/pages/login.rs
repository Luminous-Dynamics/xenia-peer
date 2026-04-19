// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Login page. Calls mycelix-identity's `resolve_did` zome function via
// the public `mycelix-leptos-client` crate — a pure-Rust WASM Holochain
// client (replaces `@holochain/client`).
//
// Flow on submit:
//   1. Shape-check the DID string (must start with "did:", min length 8)
//   2. Connect BrowserWsTransport to the conductor's app interface
//   3. Call did_registry::resolve_did(did)
//   4. If Some(Record) → sign in + navigate to /devices
//      If None         → show "DID not found in registry"
//      If Err(_)       → show the error text (connection / zome / auth)
//
// TODO (W1 tail-end):
// - Add MFA challenge step (TOTP / WebAuthn) per NIS2 Art. 21(j) default
// - Persist a bridge-common session token with expiry, not just the DID
// - Cache the VerifyingKey from the returned Record for later ledger
//   verification (instead of re-generating one each mount on /sessions)

use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;
use mycelix_leptos_client::{BrowserWsTransport, HolochainClient};

use crate::auth::AuthState;

/// Build-time overridable conductor + role config. Defaults match the
/// shared dev conductor in CLAUDE.md. Operators deploying for a
/// specific customer can override at trunk-build time:
///
/// ```sh
/// XENIA_ADMIN_CONDUCTOR_URL=wss://sovereign.example.org:8888 \
/// XENIA_ADMIN_APP_ID=mycelix-unified \
/// XENIA_ADMIN_IDENTITY_ROLE=identity \
/// trunk build --release
/// ```
const CONDUCTOR_URL: &str = match option_env!("XENIA_ADMIN_CONDUCTOR_URL") {
    Some(v) => v,
    None => "ws://localhost:8888",
};
const APP_ID: &str = match option_env!("XENIA_ADMIN_APP_ID") {
    Some(v) => v,
    None => "mycelix-unified",
};
const IDENTITY_ROLE: &str = match option_env!("XENIA_ADMIN_IDENTITY_ROLE") {
    Some(v) => v,
    None => "identity",
};

#[derive(Clone, Debug)]
enum LoginStatus {
    Idle,
    InvalidShape(String),
    Resolving,
    NotFound,
    Error(String),
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_context::<AuthState>().expect("AuthState provided at App root");
    let navigate = use_navigate();

    let did_value = RwSignal::new(String::new());
    let status = RwSignal::new(LoginStatus::Idle);

    let submit = move |_| {
        let did = did_value.get().trim().to_string();
        if !did.starts_with("did:") {
            status.set(LoginStatus::InvalidShape("A DID must start with 'did:'.".into()));
            return;
        }
        if did.len() < 8 {
            status.set(LoginStatus::InvalidShape("DID looks too short — paste the full identifier.".into()));
            return;
        }
        status.set(LoginStatus::Resolving);

        let nav = navigate.clone();
        let auth_copy = auth;
        let did_for_task = did.clone();
        spawn_local(async move {
            match resolve_did(&did_for_task).await {
                Ok(true) => {
                    auth_copy.sign_in(did_for_task);
                    nav("/devices", Default::default());
                }
                Ok(false) => {
                    status.set(LoginStatus::NotFound);
                }
                Err(e) => {
                    status.set(LoginStatus::Error(e));
                }
            }
        });
    };

    view! {
        <section class="login-page">
            <h1>"Sign in"</h1>
            <p class="prose">
                "Paste a DID registered with the Mycelix identity cluster. "
                "On submit, we call "
                <code>"did_registry::resolve_did"</code>
                " on the conductor at "
                <code>{CONDUCTOR_URL}</code>
                " — no server intermediary, zero trust in our infrastructure."
            </p>
            <form
                class="login-form"
                on:submit=move |ev| { ev.prevent_default(); submit(()); }
            >
                <label for="did-input">"DID"</label>
                <input
                    id="did-input"
                    type="text"
                    autocomplete="off"
                    placeholder="did:mycelix:… or did:key:…"
                    prop:value=move || did_value.get()
                    on:input=move |ev| did_value.set(event_target_value(&ev))
                    prop:disabled=move || matches!(status.get(), LoginStatus::Resolving)
                />
                <StatusBanner status/>
                <button
                    type="submit"
                    class="primary"
                    prop:disabled=move || matches!(status.get(), LoginStatus::Resolving)
                >
                    {move || match status.get() {
                        LoginStatus::Resolving => "Resolving…",
                        _ => "Sign in",
                    }}
                </button>
            </form>
            <p class="footnote">
                "App ID " <code>{APP_ID}</code>
                " · role " <code>{IDENTITY_ROLE}</code>
                ". Override at build time via "
                <code>"XENIA_ADMIN_*"</code>
                " env vars — see the component docs."
            </p>
        </section>
    }
}

#[component]
fn StatusBanner(status: RwSignal<LoginStatus>) -> impl IntoView {
    view! {
        {move || match status.get() {
            LoginStatus::Idle => view! { <span class="status-placeholder"></span> }.into_any(),
            LoginStatus::InvalidShape(msg) => view! {
                <p class="form-error">{msg}</p>
            }.into_any(),
            LoginStatus::Resolving => view! {
                <p class="form-info">"Calling resolve_did on the conductor…"</p>
            }.into_any(),
            LoginStatus::NotFound => view! {
                <p class="form-error">"DID not found in the identity registry. Check the spelling or register it first via the identity hApp."</p>
            }.into_any(),
            LoginStatus::Error(e) => view! {
                <p class="form-error">{format!("Zome call failed: {e}")}</p>
            }.into_any(),
        }}
    }
}

/// Call `did_registry::resolve_did` on the identity hApp and return
/// whether the DID resolved to a chain record.
///
/// Returns:
/// - `Ok(true)`  if the conductor returned `Some(Record)`
/// - `Ok(false)` if the conductor returned `None`
/// - `Err(msg)`  on connect / zome / deserialization failure
async fn resolve_did(did: &str) -> Result<bool, String> {
    let transport = BrowserWsTransport::new();
    let client = HolochainClient::new(transport, APP_ID, IDENTITY_ROLE);

    client
        .connect(CONDUCTOR_URL, None)
        .await
        .map_err(|e| format!("connect {CONDUCTOR_URL}: {e}"))?;

    // resolve_did(did: String) -> ExternResult<Option<Record>>
    // Pass an owned String (the trait bound requires Sized). We only
    // need existence, so deserialize the Record as an opaque
    // serde_json::Value — avoids pulling holochain_types into wasm.
    let did_owned: String = did.to_string();
    let found: Option<serde_json::Value> = client
        .call_zome("did_registry", "resolve_did", &did_owned)
        .await
        .map_err(|e| format!("{e}"))?;

    Ok(found.is_some())
}
