// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Policy page. Scaffold stub — the admin console's CRUD surface for
// operator access policies (tier thresholds, session TTLs, MFA
// requirements, etc.) lands in W1 tail-end alongside the cross-cluster
// auth-context threading via mycelix-bridge-common.

use leptos::prelude::*;

use crate::context::{auth_context, missing_context_view};

#[component]
pub fn PolicyPage() -> impl IntoView {
    let Ok(auth) = auth_context() else {
        return missing_context_view("AuthState").into_any();
    };
    view! {
        <Show
            when=move || auth.is_authenticated()
            fallback=|| view! { <a href="/login" class="primary">"Sign in to manage policy"</a> }
        >
            <section class="policy-page">
                <h1>"Policy"</h1>
                <p class="prose">
                    "Coming later in W1. This surface will expose the "
                    "operator-tier thresholds, session TTL configuration, MFA "
                    "enforcement toggles, and per-device capability grants. "
                    "All mutations will produce "
                    <code>"ConsentKind::"</code>
                    "-tagged entries in the xenia-ledger so policy drift is "
                    "itself auditable."
                </p>
                <ul class="planned-controls">
                    <li>"Tier configuration (Observer → Guardian, vote-weight presets)"</li>
                    <li>"Session TTL + maximum idle window"</li>
                    <li>"MFA enforcement level (default: required, NIS2 Art. 21(j))"</li>
                    <li>"Per-device capability grants (with xenia-ledger audit trail)"</li>
                    <li>"Emergency revocation of all active sessions"</li>
                </ul>
            </section>
        </Show>
    }
    .into_any()
}
