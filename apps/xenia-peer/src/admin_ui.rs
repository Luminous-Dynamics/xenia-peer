// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Optionally embeds the built `sovereign-admin` (Leptos/WASM) operator
//! console directly into the `xenia-peer` binary and serves it from the same
//! axum router that already handles the WS admin broadcast (`--admin-port`) —
//! so visiting `http://127.0.0.1:<admin-port>/` in a browser gets the real
//! consent-ceremony UI with no separate `trunk serve` process.
//!
//! Gated behind the off-by-default `embedded-console` feature: embedding
//! requires `apps/sovereign-admin/dist/` to exist at `xenia-peer` *build*
//! time (`cd apps/sovereign-admin && trunk build --release`), which is a WASM
//! build artifact not present in a plain source checkout / CI. With the
//! feature off, [`mount`] is a no-op and the daemon still serves `/ws` and the
//! `/auth/*` routes; run the console separately via `trunk serve`, or enable
//! `--features embedded-console` (after a `trunk build`) for a bundled binary.

use axum::Router;

#[cfg(feature = "embedded-console")]
use axum::{
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
#[cfg(feature = "embedded-console")]
use rust_embed::Embed;

#[cfg(feature = "embedded-console")]
#[derive(Embed)]
#[folder = "../sovereign-admin/dist/"]
struct AdminUiAssets;

#[cfg(feature = "embedded-console")]
struct AdminUiFile(String);

#[cfg(feature = "embedded-console")]
impl IntoResponse for AdminUiFile {
    fn into_response(self) -> Response {
        match AdminUiAssets::get(&self.0) {
            Some(content) => {
                let mime = mime_guess::from_path(&self.0).first_or_octet_stream();
                ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
            }
            None => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
        }
    }
}

#[cfg(feature = "embedded-console")]
async fn index_handler() -> impl IntoResponse {
    AdminUiFile("index.html".to_string())
}

#[cfg(feature = "embedded-console")]
async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    AdminUiFile(path)
}

/// Mount the embedded admin console onto an existing router at `/` and every
/// other path (the console's own asset filenames are content-hashed by trunk,
/// so a flat namespace alongside `/ws` is safe).
#[cfg(feature = "embedded-console")]
pub fn mount(router: Router) -> Router {
    router
        .route("/", get(index_handler))
        .route("/{*file}", get(static_handler))
}

/// No-op: the operator console is not embedded in this build (build with
/// `--features embedded-console` to bundle it). The daemon still serves `/ws`
/// and `/auth/*`.
#[cfg(not(feature = "embedded-console"))]
pub fn mount(router: Router) -> Router {
    router
}
