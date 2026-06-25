// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Daemon connection configuration.

use leptos::prelude::*;
use web_sys::Storage;

const ENDPOINT_KEY: &str = "xenia-admin.daemon-endpoint";
const SECRET_KEY: &str = "xenia-admin.daemon-secret";

/// Context holding the daemon connection settings.
#[derive(Clone, Copy)]
pub struct DaemonConfig {
    pub endpoint: RwSignal<String>,
    pub hmac_secret: RwSignal<String>,
}

impl DaemonConfig {
    pub fn new() -> Self {
        let endpoint = RwSignal::new(
            load_from_storage(ENDPOINT_KEY).unwrap_or_else(|| "http://127.0.0.1:8134".into()),
        );
        let hmac_secret = RwSignal::new(load_from_storage(SECRET_KEY).unwrap_or_default());
        Self {
            endpoint,
            hmac_secret,
        }
    }

    pub fn save(&self) {
        persist_to_storage(ENDPOINT_KEY, &self.endpoint.get());
        persist_to_storage(SECRET_KEY, &self.hmac_secret.get());
    }
}

fn local_storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn load_from_storage(key: &str) -> Option<String> {
    local_storage()?.get_item(key).ok().flatten()
}

fn persist_to_storage(key: &str, val: &str) {
    if let Some(storage) = local_storage() {
        let _ = storage.set_item(key, val);
    }
}
