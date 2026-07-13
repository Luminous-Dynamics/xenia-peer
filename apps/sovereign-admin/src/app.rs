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

use crate::agent_client::AgentConfig;
use crate::auth::AuthState;
use crate::config::DaemonConfig;
use crate::context::{auth_context, daemon_config_context, missing_context_view};
use crate::operator_session::{OperatorSession, authenticate};
use crate::pages::{
    ConsentModal, DevicesPage, GovernancePage, LoginPage, MonitorPage, PolicyPage, SessionsPage,
};

/// Shared operator-RBAC session: `Some` once the operator completes the
/// challenge/verify ceremony against the daemon, carrying the role the daemon
/// scoped the token to. Provided at the root so the consent modal (and any
/// privileged control) can gate on the real role rather than a client claim.
pub type OperatorSessionCtx = RwSignal<Option<OperatorSession>>;

/// The operator's *public* identity info, fetched from the local agent's
/// `GET /identity` (see `crate::agent_client::fetch_identity_info`) --
/// never the raw seeds, which no longer reach this process at all (Step 7 of
/// `docs/security/SIGNER_DELEGATION_DESIGN.md`). Used only for the
/// Sessions-page enrollment display; nothing here signs or handshakes.
#[derive(Clone)]
pub enum OperatorIdentityState {
    /// Fetch in flight (or not yet started).
    Loading,
    Ready {
        fingerprint_hex: String,
        enrollment_record_json: String,
    },
    /// No token configured, or the agent fetch failed -- carries a
    /// user-facing reason.
    Unavailable(String),
}

impl OperatorIdentityState {
    /// Whether the agent has reported its identity info -- used as a
    /// reachability heartbeat (see [`OperatorAuthPanel`]'s `sign_in`).
    pub fn is_ready(&self) -> bool {
        matches!(self, OperatorIdentityState::Ready { .. })
    }
}

pub type OperatorIdentityCtx = RwSignal<OperatorIdentityState>;

#[component]
pub fn App() -> impl IntoView {
    let auth = AuthState::new();
    provide_context(auth);

    let config = DaemonConfig::new();
    provide_context(config);

    let agent_config = AgentConfig::new();
    provide_context(agent_config);

    let operator_session: OperatorSessionCtx = RwSignal::new(None);
    provide_context(operator_session);

    let identity_state: OperatorIdentityCtx = RwSignal::new(OperatorIdentityState::Loading);
    provide_context(identity_state);

    // Fetch the operator identity from the agent whenever its connection
    // settings change (including once, on mount, with whatever was
    // persisted from a prior session).
    Effect::new(move |_| {
        let url = agent_config.agent_url.get();
        let token = agent_config.agent_token.get();
        identity_state.set(OperatorIdentityState::Loading);
        spawn_local(async move {
            if token.trim().is_empty() {
                identity_state.set(OperatorIdentityState::Unavailable(
                    "Operator agent not configured -- set its URL and pairing token on the \
                     Sessions page to enable operator sign-in."
                        .to_string(),
                ));
                return;
            }
            match crate::agent_client::fetch_identity_info(&url, &token).await {
                Ok(info) => identity_state.set(OperatorIdentityState::Ready {
                    fingerprint_hex: info.fingerprint_hex,
                    enrollment_record_json: info.enrollment_record_json,
                }),
                Err(e) => identity_state.set(OperatorIdentityState::Unavailable(e)),
            }
        });
    });

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
    let identity_state = use_context::<OperatorIdentityCtx>();
    let sign_out = move |_| {
        auth.sign_out();
        // Drop this page's fetched copy of the operator's public identity
        // info out of the reactive graph on sign-out. Re-fetched from the
        // agent on demand afterward.
        if let Some(sig) = identity_state {
            sig.set(OperatorIdentityState::Loading);
        }
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
                <button class="sign-out" on:click=sign_out>"Sign out"</button>
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
    let Some(identity_state) = use_context::<OperatorIdentityCtx>() else {
        return missing_context_view("OperatorIdentity").into_any();
    };
    let Some(agent_config) = use_context::<AgentConfig>() else {
        return missing_context_view("AgentConfig").into_any();
    };
    let (busy, set_busy) = signal(false);
    let (error, set_error) = signal(None::<String>);

    let sign_in = move |_| {
        // `authenticate()` doesn't need the operator's public identity info
        // at all (the agent signs, and returns the operator's public keys
        // itself) -- this check is purely a reachability heartbeat: if the
        // agent can't even answer `GET /identity`, `/v1/sign/challenge` will
        // fail too, so there's no point attempting the ceremony.
        if !identity_state.get_untracked().is_ready() {
            set_error.set(Some(
                "Operator agent identity isn't ready -- check the agent settings on the \
                 Sessions page."
                    .to_string(),
            ));
            return;
        }
        set_busy.set(true);
        set_error.set(None);
        let endpoint = config.endpoint.get();
        let agent_url = agent_config.agent_url.get_untracked();
        let agent_token = agent_config.agent_token.get_untracked();
        spawn_local(async move {
            match authenticate(&endpoint, &agent_url, &agent_token).await {
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
                fallback=move || view! {
                    {move || match identity_state.get() {
                        OperatorIdentityState::Loading => view! {
                            <span class="operator-agent-status">"Connecting to operator agent…"</span>
                        }.into_any(),
                        OperatorIdentityState::Unavailable(reason) => view! {
                            <span class="operator-agent-status operator-error">{reason}</span>
                        }.into_any(),
                        OperatorIdentityState::Ready { fingerprint_hex, enrollment_record_json } => {
                            // Template record (built by the agent's `GET /identity` --
                            // see `crate::agent_client::IdentityDto`): the admin sets
                            // operator_id + role, then adds it to the daemon's
                            // --operators-file. All three public keys matter --
                            // omitting ml_dsa_87_pubkey means this operator can never
                            // use the high-security sealed channel, even if they select
                            // it in the console.
                            let fingerprint = fingerprint_hex;
                            let fp_short = fingerprint.chars().take(16).collect::<String>();
                            let record = enrollment_record_json;
                            view! {
                                <button
                                    class="operator-signin"
                                    prop:disabled=move || busy.get()
                                    on:click=sign_in
                                >
                                    {move || if busy.get() { "Authenticating…" } else { "Operator sign-in" }}
                                </button>
                                <details class="operator-enroll">
                                    <summary class="operator-fingerprint" title=fingerprint.clone()>
                                        "key " {fp_short} "…"
                                    </summary>
                                    <p class="operator-enroll-hint">
                                        "Add to the daemon's --operators-file (set operator_id + role):"
                                    </p>
                                    <code class="operator-enroll-record">{record}</code>
                                </details>
                                {move || error.get().map(|e| view! {
                                    <span class="operator-error">{e}</span>
                                })}
                            }.into_any()
                        }
                    }}
                }
            >
                <span class="operator-role-chip">
                    {move || session.with(|s| {
                        s.as_ref().map(|s| format!("{} · {}", s.operator_id, s.role.as_str()))
                            .unwrap_or_default()
                    })}
                </span>
                <button
                    class="operator-signout"
                    on:click=move |_| {
                        session.set(None);
                        // Best-effort hygiene, matching AuthStatus's sign-out --
                        // see that handler's comment.
                        identity_state.set(OperatorIdentityState::Loading);
                    }
                >
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
