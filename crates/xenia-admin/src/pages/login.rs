// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Login page. Scaffold: accepts a DID string, validates shape
// (starts with "did:"), stores in AuthState + localStorage, navigates
// to /devices.
//
// TODO (W1 follow-up):
// - Replace string-shape validation with a real call to
//   mycelix-identity's `resolve_did` zome function via
//   mycelix-bridge-common.
// - Add MFA challenge step (TOTP / WebAuthn) per the NIS2 Art. 21(j)
//   MFA-required default.
// - Persist a bridge-common session token, not just the DID.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::auth::AuthState;

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_context::<AuthState>().expect("AuthState provided at App root");
    let navigate = use_navigate();

    let did_value = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);

    let submit = move |_| {
        let did = did_value.get();
        let trimmed = did.trim();
        if !trimmed.starts_with("did:") {
            error.set(Some("A DID must start with 'did:'.".into()));
            return;
        }
        if trimmed.len() < 8 {
            error.set(Some("DID looks too short — paste the full identifier.".into()));
            return;
        }
        error.set(None);
        auth.sign_in(trimmed.to_string());
        navigate("/devices", Default::default());
    };

    view! {
        <section class="login-page">
            <h1>"Sign in"</h1>
            <p class="prose">
                "Scaffold sign-in. Paste a DID to proceed; no cryptographic "
                "verification happens yet. Real "
                <code>"resolve_did"</code>
                " integration is a W1 follow-up."
            </p>
            <form class="login-form" on:submit=move |ev| { ev.prevent_default(); submit(()); }>
                <label for="did-input">"DID"</label>
                <input
                    id="did-input"
                    type="text"
                    autocomplete="off"
                    placeholder="did:mycelix:… or did:key:…"
                    prop:value=move || did_value.get()
                    on:input=move |ev| did_value.set(event_target_value(&ev))
                />
                <Show when=move || error.get().is_some()>
                    <p class="form-error">{move || error.get().unwrap_or_default()}</p>
                </Show>
                <button type="submit" class="primary">"Sign in"</button>
            </form>
        </section>
    }
}
