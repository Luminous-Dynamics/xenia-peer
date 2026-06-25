// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// xenia-admin — Leptos CSR admin console for Xenia.
//
// The operator surface of the Mycelix Sovereign suite: DID login,
// device inventory, active/historical session review with xenia-ledger
// verification, policy CRUD.
//
// This crate is AGPL-3.0-or-later per the Mycelix Sovereign license
// policy (application-layer = AGPL, protocol-layer = Apache/MIT).

use leptos::prelude::*;

mod app;
mod auth;
mod config;
mod context;
mod pages;

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(app::App);
}
