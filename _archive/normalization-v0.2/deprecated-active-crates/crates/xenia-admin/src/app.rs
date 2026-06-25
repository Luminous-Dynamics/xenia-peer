// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Root App component: provides AuthState, wires the router, and
// renders the top navigation.

use leptos::prelude::*;
use leptos_router::{
    components::{Route, Router, Routes, A},
    path,
};

use crate::auth::AuthState;
use crate::pages::{DevicesPage, LoginPage, PolicyPage, SessionsPage};

#[component]
pub fn App() -> impl IntoView {
    let auth = AuthState::new();
    provide_context(auth);

    view! {
        <Router>
            <header class="topbar">
                <a class="brand" href="/">
                    <span class="brand-name">"Xenia"</span>
                    <span class="brand-suite">"Mycelix Sovereign · Admin"</span>
                </a>
                <Nav/>
                <AuthStatus/>
            </header>
            <main class="content">
                <Routes fallback=|| view! { <NotFound/> }>
                    <Route path=path!("/") view=DevicesPage/>
                    <Route path=path!("/login") view=LoginPage/>
                    <Route path=path!("/devices") view=DevicesPage/>
                    <Route path=path!("/sessions") view=SessionsPage/>
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
            <A href="/policy">"Policy"</A>
        </nav>
    }
}

#[component]
fn AuthStatus() -> impl IntoView {
    let auth = use_context::<AuthState>().expect("AuthState provided at App root");
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
