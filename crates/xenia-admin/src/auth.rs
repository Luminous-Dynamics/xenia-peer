// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared authentication state.
//
// Today this is a thin wrapper around an `Option<String>` (the admin's
// DID). As the real DID-login flow lands (mycelix-identity's
// `resolve_did` + `check_authentication` via `mycelix-bridge-common`),
// this grows into a session token with expiry + tier + signing key ref.

use leptos::prelude::*;
use web_sys::Storage;

const STORAGE_KEY: &str = "xenia-admin.did";

/// Context holding the current admin session state. Provided once at
/// the `App` root and consumed by every page.
#[derive(Clone, Copy)]
pub struct AuthState {
    /// `Some(did)` if the admin has authenticated in this browser,
    /// `None` otherwise.
    pub did: RwSignal<Option<String>>,
}

impl AuthState {
    /// Construct a fresh `AuthState`. Rehydrates `did` from
    /// `localStorage` if present (session persistence across page
    /// reloads — the obvious-but-important UX property).
    pub fn new() -> Self {
        let did = RwSignal::new(load_did_from_storage());
        Self { did }
    }

    /// Sign in with a DID (no cryptographic verification yet — this is
    /// the scaffold). Persists to localStorage.
    pub fn sign_in(&self, did: String) {
        persist_did_to_storage(Some(&did));
        self.did.set(Some(did));
    }

    /// Sign out. Clears localStorage.
    pub fn sign_out(&self) {
        persist_did_to_storage(None);
        self.did.set(None);
    }

    /// Whether the admin is currently authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.did.with(|d| d.is_some())
    }
}

fn local_storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn load_did_from_storage() -> Option<String> {
    local_storage()?.get_item(STORAGE_KEY).ok().flatten()
}

fn persist_did_to_storage(did: Option<&str>) {
    let Some(storage) = local_storage() else { return };
    match did {
        Some(d) => {
            let _ = storage.set_item(STORAGE_KEY, d);
        }
        None => {
            let _ = storage.remove_item(STORAGE_KEY);
        }
    }
}
