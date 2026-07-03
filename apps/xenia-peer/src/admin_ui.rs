// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Embeds the built `sovereign-admin` (Leptos/WASM) operator console
//! directly into the `xenia-peer` binary and serves it from the same
//! axum router that already handles the WS admin broadcast
//! (`--admin-port`) — so visiting `http://127.0.0.1:<admin-port>/` in a
//! browser gets the real consent-ceremony UI with no separate `trunk
//! serve` process or standalone app to run. Closes ROADMAP.md's B3 row:
//! `sovereign-admin` now ships as part of `xenia-peer`'s own UX instead
//! of a separate incubator app.
//!
//! Requires `apps/sovereign-admin/dist/` to exist at `xenia-peer`
//! *build* time: `cd apps/sovereign-admin && trunk build --release`,
//! then rebuild `xenia-peer` to pick up any UI changes (the assets are
//! compiled into the binary, not read from disk at runtime).

use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../sovereign-admin/dist/"]
struct AdminUiAssets;

struct AdminUiFile(String);

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

async fn index_handler() -> impl IntoResponse {
    AdminUiFile("index.html".to_string())
}

async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    AdminUiFile(path)
}

/// Mount the embedded admin console onto an existing router at `/` and
/// every other path (the console's own asset filenames are content-hashed
/// by trunk, so a flat namespace alongside `/ws` is safe).
pub fn mount(router: Router) -> Router {
    router
        .route("/", get(index_handler))
        .route("/{*file}", get(static_handler))
}
