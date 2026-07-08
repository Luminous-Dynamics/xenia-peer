// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Daemon connection configuration — the single source of truth for every
// daemon URL the console talks to: the HTTP admin base (`/auth/*`, ledger),
// the admin WebSocket the daemon broadcasts consent prompts on, and the
// consent WebSocket the console sends signed decisions to.

use leptos::prelude::*;
use web_sys::Storage;

const ENDPOINT_KEY: &str = "xenia-admin.daemon-endpoint";
const SECRET_KEY: &str = "xenia-admin.daemon-secret";
const CONSENT_PORT_KEY: &str = "xenia-admin.daemon-consent-port";

/// The daemon's default admin HTTP port (xenia-peer `--admin-port`); the
/// `/auth/*` routes and the `/ws` consent broadcast both live here. (The old
/// `8134` default pointed at the console's *own* port, which can never be the
/// daemon API — corrected here.)
const DEFAULT_ADMIN_ENDPOINT: &str = "http://127.0.0.1:8081";
/// The daemon's default consent port (xenia-peer `--consent-port`), a raw WS
/// server distinct from the admin port.
const DEFAULT_CONSENT_PORT: u16 = 8082;

/// Context holding the daemon connection settings.
#[derive(Clone, Copy)]
pub struct DaemonConfig {
    pub endpoint: RwSignal<String>,
    pub hmac_secret: RwSignal<String>,
    /// The daemon's consent port. The admin port is taken from `endpoint`; the
    /// consent decisions go to this separate port on the same host.
    pub consent_port: RwSignal<u16>,
}

impl DaemonConfig {
    pub fn new() -> Self {
        let endpoint = RwSignal::new(
            load_from_storage(ENDPOINT_KEY).unwrap_or_else(|| DEFAULT_ADMIN_ENDPOINT.into()),
        );
        let hmac_secret = RwSignal::new(load_from_storage(SECRET_KEY).unwrap_or_default());
        let consent_port = RwSignal::new(
            load_from_storage(CONSENT_PORT_KEY)
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_CONSENT_PORT),
        );
        Self {
            endpoint,
            hmac_secret,
            consent_port,
        }
    }

    pub fn save(&self) {
        persist_to_storage(ENDPOINT_KEY, &self.endpoint.get());
        persist_to_storage(SECRET_KEY, &self.hmac_secret.get());
        persist_to_storage(CONSENT_PORT_KEY, &self.consent_port.get().to_string());
    }

    /// The `ws://host:adminport` authority derived from the HTTP `endpoint`
    /// (http→ws, https→wss), dropping any path.
    fn ws_authority(&self) -> String {
        let ep = self.endpoint.get();
        let (scheme, rest) = if let Some(r) = ep.strip_prefix("https://") {
            ("wss", r)
        } else if let Some(r) = ep.strip_prefix("http://") {
            ("ws", r)
        } else {
            ("ws", ep.as_str())
        };
        // Keep only the authority (host[:port]); drop any trailing path.
        let authority = rest.split('/').next().unwrap_or(rest);
        format!("{scheme}://{authority}")
    }

    /// The WebSocket URL the daemon broadcasts consent prompts on (admin
    /// port's `/ws`). The console listens here for incoming session requests.
    pub fn admin_ws_url(&self) -> String {
        format!("{}/ws", self.ws_authority())
    }

    /// The WebSocket URL the console sends signed consent decisions to (the
    /// daemon's separate consent port on the same host).
    pub fn consent_ws_url(&self) -> String {
        let authority = self.ws_authority();
        // Replace the admin port with the consent port: take scheme://host,
        // then append :consent_port.
        let host = authority
            .rsplit_once(':')
            .map(|(head, _port)| head)
            .unwrap_or(&authority);
        format!("{host}:{}", self.consent_port.get())
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
