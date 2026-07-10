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
const SEALED_PORT_KEY: &str = "xenia-admin.daemon-sealed-port";

/// The daemon's default admin HTTP port (xenia-peer `--admin-port`); the
/// `/auth/*` routes and the `/ws` consent broadcast both live here. (The old
/// `8134` default pointed at the console's *own* port, which can never be the
/// daemon API — corrected here.)
const DEFAULT_ADMIN_ENDPOINT: &str = "http://127.0.0.1:8081";
/// The daemon's default consent port (xenia-peer `--consent-port`), a raw WS
/// server distinct from the admin port.
const DEFAULT_CONSENT_PORT: u16 = 8082;
/// The daemon's default sealed operator-channel port (xenia-peer
/// `--operator-sealed-port`), where consent decisions are wrapped in PQC-sealed
/// envelopes over a handshake-authenticated channel instead of sent plaintext.
const DEFAULT_SEALED_PORT: u16 = 8083;

/// Context holding the daemon connection settings.
#[derive(Clone, Copy)]
pub struct DaemonConfig {
    pub endpoint: RwSignal<String>,
    pub hmac_secret: RwSignal<String>,
    /// The daemon's consent port. The admin port is taken from `endpoint`; the
    /// consent decisions go to this separate port on the same host.
    pub consent_port: RwSignal<u16>,
    /// The daemon's sealed operator-channel port (`--operator-sealed-port`). When
    /// the daemon runs with `--operator-sealed`, decisions go here inside PQC
    /// envelopes over the authenticated handshake channel.
    pub sealed_port: RwSignal<u16>,
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
        let sealed_port = RwSignal::new(
            load_from_storage(SEALED_PORT_KEY)
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_SEALED_PORT),
        );
        Self {
            endpoint,
            hmac_secret,
            consent_port,
            sealed_port,
        }
    }

    pub fn save(&self) {
        persist_to_storage(ENDPOINT_KEY, &self.endpoint.get());
        persist_to_storage(SECRET_KEY, &self.hmac_secret.get());
        persist_to_storage(CONSENT_PORT_KEY, &self.consent_port.get().to_string());
        persist_to_storage(SEALED_PORT_KEY, &self.sealed_port.get().to_string());
    }

    /// The `ws://host:adminport` authority derived from the HTTP `endpoint`
    /// (http→ws, https→wss), dropping any path.
    fn ws_authority(&self) -> String {
        ws_authority_from(&self.endpoint.get())
    }

    /// The WebSocket URL the daemon broadcasts consent prompts on (admin
    /// port's `/ws`). The console listens here for incoming session requests.
    pub fn admin_ws_url(&self) -> String {
        format!("{}/ws", self.ws_authority())
    }

    /// A `ws(s)://host:port` URL on the same host as the admin endpoint, with the
    /// admin port replaced by `port`. Shared by the consent and sealed URLs.
    fn ws_url_for_port(&self, port: u16) -> String {
        ws_url_for_port_from(&self.endpoint.get(), port)
    }

    /// The WebSocket URL the console sends signed consent decisions to (the
    /// daemon's separate consent port on the same host).
    pub fn consent_ws_url(&self) -> String {
        self.ws_url_for_port(self.consent_port.get())
    }

    /// The WebSocket URL of the daemon's sealed operator channel
    /// (`--operator-sealed-port`). The console performs the PQC handshake here
    /// and sends consent decisions inside sealed envelopes.
    //
    // Consumed by the pending sealed-consent WS driver, which lands once the
    // wasm-safe handshake (xenia-wire `WasmHandshake::fromIdentity`, PR #7) is
    // exposed as a consumable library. Kept here as the URL foundation so that
    // wiring is a one-line call, not a config change.
    #[allow(dead_code)]
    pub fn sealed_ws_url(&self) -> String {
        self.ws_url_for_port(self.sealed_port.get())
    }
}

/// Pure `endpoint` → `ws(s)://host[:adminport]` derivation (http→ws, https→wss),
/// dropping any path. Free function so it is testable without a reactive runtime.
fn ws_authority_from(ep: &str) -> String {
    let (scheme, rest) = if let Some(r) = ep.strip_prefix("https://") {
        ("wss", r)
    } else if let Some(r) = ep.strip_prefix("http://") {
        ("ws", r)
    } else {
        ("ws", ep)
    };
    // Keep only the authority (host[:port]); drop any trailing path.
    let authority = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{authority}")
}

/// Pure `(endpoint, port)` → `ws(s)://host:port`, replacing the admin port.
fn ws_url_for_port_from(ep: &str, port: u16) -> String {
    let authority = ws_authority_from(ep);
    let host = authority
        .rsplit_once(':')
        .map(|(head, _port)| head)
        .unwrap_or(&authority);
    format!("{host}:{port}")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_authority_maps_schemes_and_drops_path() {
        assert_eq!(
            ws_authority_from("http://127.0.0.1:8081"),
            "ws://127.0.0.1:8081"
        );
        assert_eq!(
            ws_authority_from("https://host:8081/admin"),
            "wss://host:8081"
        );
        // No scheme falls back to ws://.
        assert_eq!(ws_authority_from("box:8081"), "ws://box:8081");
    }

    #[test]
    fn sealed_and_consent_ports_swap_onto_the_admin_host() {
        // Admin on 8081 → sealed on 8083, consent on 8082, same host, ws scheme.
        assert_eq!(
            ws_url_for_port_from("http://127.0.0.1:8081", DEFAULT_SEALED_PORT),
            "ws://127.0.0.1:8083"
        );
        assert_eq!(
            ws_url_for_port_from("http://127.0.0.1:8081", DEFAULT_CONSENT_PORT),
            "ws://127.0.0.1:8082"
        );
        // https carries through to wss.
        assert_eq!(
            ws_url_for_port_from("https://ops.example:9000", DEFAULT_SEALED_PORT),
            "wss://ops.example:8083"
        );
    }
}
