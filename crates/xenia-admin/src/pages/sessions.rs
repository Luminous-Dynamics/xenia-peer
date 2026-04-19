// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Sessions page. Shows active + historical Xenia sessions. Each
// session row links to a ledger viewer that will verify the xenia-
// ledger entries cryptographically (via `xenia_ledger::Verifier`).
//
// Scaffold: mock rows only; real integration with xenia-peer's session
// registry + xenia-ledger comes in W1 Stream A tail-end.

use leptos::prelude::*;

use crate::auth::AuthState;

struct MockSession {
    id: &'static str,
    target_device: &'static str,
    operator_did: &'static str,
    started_at: &'static str,
    state: &'static str,
    consent_entries: u32,
}

const MOCK_SESSIONS: &[MockSession] = &[
    MockSession {
        id: "ses-2026-04-19-001",
        target_device: "ops-laptop-01",
        operator_did: "did:mycelix:z6MkE5…",
        started_at: "just now",
        state: "active",
        consent_entries: 2,
    },
    MockSession {
        id: "ses-2026-04-18-014",
        target_device: "jumphost-euw1",
        operator_did: "did:mycelix:z6MkE5…",
        started_at: "yesterday, 14:22",
        state: "completed",
        consent_entries: 17,
    },
    MockSession {
        id: "ses-2026-04-17-008",
        target_device: "pixel-8-pro",
        operator_did: "did:mycelix:z6MkQ9…",
        started_at: "Apr 17, 09:08",
        state: "revoked",
        consent_entries: 4,
    },
];

#[component]
pub fn SessionsPage() -> impl IntoView {
    let auth = use_context::<AuthState>().expect("AuthState provided at App root");
    view! {
        <Show
            when=move || auth.is_authenticated()
            fallback=|| view! { <a href="/login" class="primary">"Sign in to view sessions"</a> }
        >
            <SessionsTable/>
        </Show>
    }
}

#[component]
fn SessionsTable() -> impl IntoView {
    view! {
        <section class="sessions-page">
            <h1>"Sessions"</h1>
            <p class="prose">
                "Every active and historical Xenia session. Each row links to "
                "its "
                <code>"xenia-ledger"</code>
                " chain, which any third party can verify offline with the "
                "operator's public key — see ADR 0001 §f and the ledger "
                "README."
            </p>
            <table class="sessions-table">
                <thead>
                    <tr>
                        <th>"ID"</th>
                        <th>"Target"</th>
                        <th>"Operator"</th>
                        <th>"Started"</th>
                        <th>"State"</th>
                        <th>"Ledger entries"</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    {MOCK_SESSIONS.iter().map(|s| view! {
                        <tr>
                            <td><code>{s.id}</code></td>
                            <td>{s.target_device}</td>
                            <td><code class="did-mono">{s.operator_did}</code></td>
                            <td class="dim">{s.started_at}</td>
                            <td class={format!("state state-{}", s.state)}>{s.state}</td>
                            <td class="numeric">{s.consent_entries}</td>
                            <td>
                                <button disabled class="secondary" title="Ledger viewer pending W1 tail-end">
                                    "Verify ledger →"
                                </button>
                            </td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </section>
    }
}
