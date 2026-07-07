// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Root App component: provides AuthState, wires the router, and
// renders the top navigation.

use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::{
    components::{A, Route, Router, Routes},
    path,
};

use crate::auth::AuthState;
use crate::config::DaemonConfig;
use crate::context::{auth_context, daemon_config_context, missing_context_view};
use crate::operator_session::{OperatorIdentity, OperatorSession, authenticate};
use crate::pages::{
    ConsentModal, DevicesPage, GovernancePage, LoginPage, MonitorPage, PolicyPage, SessionsPage,
};

/// Shared operator-RBAC session: `Some` once the operator completes the
/// challenge/verify ceremony against the daemon, carrying the role the daemon
/// scoped the token to. Provided at the root so the consent modal (and any
/// privileged control) can gate on the real role rather than a client claim.
pub type OperatorSessionCtx = RwSignal<Option<OperatorSession>>;

#[component]
pub fn App() -> impl IntoView {
    let auth = AuthState::new();
    provide_context(auth);

    let config = DaemonConfig::new();
    provide_context(config);

    let operator_session: OperatorSessionCtx = RwSignal::new(None);
    provide_context(operator_session);

    view! {
        <Router>
            <ConsentModal/>
            <header class="topbar">
                <a class="brand" href="/">
                    <span class="brand-name">"Sovereign"</span>
                    <span class="brand-suite">"Operations Center"</span>
                </a>
                <Nav/>
                <OperatorAuthPanel/>
                <AuthStatus/>
            </header>
            <main class="content">
                <Routes fallback=|| view! { <NotFound/> }>
                    <Route path=path!("/") view=DevicesPage/>
                    <Route path=path!("/login") view=LoginPage/>
                    <Route path=path!("/devices") view=DevicesPage/>
                    <Route path=path!("/sessions") view=SessionsPage/>
                    <Route path=path!("/governance") view=GovernancePage/>
                    <Route path=path!("/monitor") view=MonitorPage/>
                    <Route path=path!("/policy") view=PolicyPage/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn Nav() -> impl IntoView {
    view! {
        <nav class="primary-nav">
            <A href="/devices">"Devices"</A>
            <A href="/sessions">"Sessions"</A>
            <A href="/governance">"Governance"</A>
            <A href="/monitor">"AI Monitor"</A>
            <A href="/policy">"Policy"</A>
        </nav>
    }
}

#[component]
fn AuthStatus() -> impl IntoView {
    let Ok(auth) = auth_context() else {
        return missing_context_view("AuthState").into_any();
    };
    view! {
        <div class="auth-status">
            <Show
                when=move || auth.is_authenticated()
                fallback=|| view! { <A href="/login" attr:class="sign-in">"Sign in"</A> }
            >
                <span class="did-chip">
                    {move || auth.did.with(|d| d.clone().unwrap_or_default())}
                </span>
                <button class="sign-out" on:click=move |_| auth.sign_out()>"Sign out"</button>
            </Show>
        </div>
    }
    .into_any()
}

/// Operator-RBAC status + the challenge/verify ceremony trigger. Distinct from
/// [`AuthStatus`] (the DID login): this proves possession of an *enrolled
/// operator key* to the daemon and obtains the role-scoped token that gates
/// privileged actions. Shows the enrolled role when authenticated, and the
/// operator's enrollment fingerprint (to paste into the daemon's operators
/// file) before that.
#[component]
fn OperatorAuthPanel() -> impl IntoView {
    let Ok(session) = use_context::<OperatorSessionCtx>().ok_or(()) else {
        return missing_context_view("OperatorSession").into_any();
    };
    let Ok(config) = daemon_config_context() else {
        return missing_context_view("DaemonConfig").into_any();
    };
    let (busy, set_busy) = signal(false);
    let (error, set_error) = signal(None::<String>);

    // Compute the operator's enrollment fingerprint once at mount (constructing
    // the identity does ML-KEM keygen, so we don't want it on every render).
    let fingerprint = OperatorIdentity::load_or_generate().fingerprint_hex();
    let fp_short = fingerprint.chars().take(16).collect::<String>();

    let sign_in = move |_| {
        set_busy.set(true);
        set_error.set(None);
        let endpoint = config.endpoint.get();
        spawn_local(async move {
            // Constructed from the persisted seeds, so this is the same
            // enrolled identity every time.
            let identity = OperatorIdentity::load_or_generate();
            match authenticate(&endpoint, &identity).await {
                Ok(s) => session.set(Some(s)),
                Err(e) => set_error.set(Some(e)),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="operator-auth">
            <Show
                when=move || session.with(|s| s.is_some())
                fallback=move || {
                    let fp = fingerprint.clone();
                    let short = fp_short.clone();
                    view! {
                        <button
                            class="operator-signin"
                            prop:disabled=move || busy.get()
                            on:click=sign_in
                        >
                            {move || if busy.get() { "Authenticating…" } else { "Operator sign-in" }}
                        </button>
                        <span class="operator-fingerprint" title=fp>
                            "key " {short} "…"
                        </span>
                        {move || error.get().map(|e| view! {
                            <span class="operator-error">{e}</span>
                        })}
                    }
                }
            >
                <span class="operator-role-chip">
                    {move || session.with(|s| {
                        s.as_ref().map(|s| format!("{} · {}", s.operator_id, s.role.as_str()))
                            .unwrap_or_default()
                    })}
                </span>
                <button class="operator-signout" on:click=move |_| session.set(None)>
                    "End operator session"
                </button>
            </Show>
        </div>
    }
    .into_any()
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <section class="not-found">
            <h1>"Not found"</h1>
            <p>
                "That path isn't a thing in xenia-admin. Try "
                <A href="/devices">"Devices"</A> "."
            </p>
        </section>
    }
}
