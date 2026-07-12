// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local signing agent for the Xenia operator identity.
//!
//! `apps/sovereign-admin`'s browser console used to persist the operator's
//! Ed25519 + ML-DSA seeds as plaintext hex in `localStorage` -- readable by
//! an XSS bug, a malicious browser extension, or a compromised same-origin
//! dependency (see `docs/security/OPERATOR_SECURITY_MODEL.md` §9, and the
//! external review that flagged it). This binary is the interim fix: it
//! holds the seeds in a permission-restricted file on disk instead, and
//! serves them to the console over a token-authenticated, origin-restricted
//! `127.0.0.1`-only HTTP API. The console fetches them into memory once per
//! page session and never writes them to `localStorage`.
//!
//! **Scope note** (see `docs/security/OPERATOR_SECURITY_MODEL.md` for the
//! full explanation): this moves the *persistent storage* of the seeds out
//! of the browser. It does not (yet) move the *signing operations*
//! themselves out of the browser -- the console still holds the seeds in
//! memory and signs locally with them, for both the `/auth/*` HTTP
//! ceremony and the sealed-channel handshake. A follow-up that has the
//! agent perform the signing itself (so raw key material never reaches the
//! browser process at all, not even transiently) is scoped but not built;
//! it needs an async signing-callback abstraction in `xenia-wire`'s
//! `ViewerHandshake`/`ViewerHandshakeHighSec` (which currently own raw
//! keys internally), a larger change to a published crate that was
//! deliberately deferred rather than rushed.
//!
//! ## Security model
//!
//! - Binds to `127.0.0.1` only -- never configurable to a wider address.
//! - Every request must present the pairing token (`X-Agent-Token` header),
//!   generated on first run and persisted alongside the identity. The
//!   operator copies it into the console's agent settings once.
//! - Every request must carry an `Origin` header matching an allowed origin
//!   (`--allowed-origin`, repeatable; defaults to the console's dev
//!   origins) -- a missing, malformed, or unrecognized `Origin` is refused,
//!   not treated as trusted. The agent and console are different origins
//!   by construction (different ports), so any genuine browser request is
//!   cross-origin and always carries this header; a request without one is
//!   not the console. (An earlier revision let a missing `Origin` through
//!   on the theory that the token was the primary defense -- tightened
//!   after review, since "trust absence" is exactly the failure mode this
//!   check exists to close.)
//! - The identity file and token file are created **atomically** with
//!   owner-only (`0600`) permissions set *at creation*, not chmod'd
//!   afterward (closing the window where a racing process could read them
//!   between write and chmod), and refuse to open an existing path that
//!   isn't a regular file they own (defends against a symlink swapped in
//!   for the real file, or a file created by a different local user).
//! - The seeds are held zeroize-on-drop (`zeroize::Zeroizing`) for as long
//!   as this process holds them in memory.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use serde::Serialize;
use xenia_handshake::HandshakeManager;
use xenia_operator_proto::{OperatorEnrollmentRecord, OperatorRole};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "xenia-operator-agent",
    about = "Local signing-key agent for the Xenia operator console (see module docs for the security model)"
)]
struct Args {
    /// Port to listen on. Always binds 127.0.0.1 -- never configurable to a
    /// wider address.
    #[arg(long, default_value_t = 8180)]
    port: u16,

    /// Operator identity path (Ed25519 secret + ML-DSA-65 seed, 64 bytes).
    /// Generated on first run with owner-only (0600) permissions and reused
    /// thereafter, mirroring xenia-peer's own host-identity file.
    #[arg(long, default_value = "operator-agent-identity.key")]
    identity_path: PathBuf,

    /// Pairing-token path (32 random bytes, hex-encoded). Generated on
    /// first run (0600); the operator copies this value into the
    /// console's agent settings once.
    #[arg(long, default_value = "operator-agent-token.key")]
    token_path: PathBuf,

    /// Origin the console is served from. Repeatable. A request whose
    /// `Origin` header doesn't match any of these is refused. Defaults
    /// cover the console's Trunk dev-serve origins.
    #[arg(
        long,
        default_values = ["http://localhost:8134", "http://127.0.0.1:8134"]
    )]
    allowed_origin: Vec<String>,
}

struct AgentState {
    manager: HandshakeManager,
    ed25519_secret: Zeroizing<[u8; 32]>,
    ml_dsa_seed: Zeroizing<[u8; 32]>,
    token: String,
    allowed_origins: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let (ed25519_secret, ml_dsa_seed) = load_or_create_identity_seeds(&args.identity_path)?;
    let manager = HandshakeManager::from_identity_seeds(ed25519_secret, ml_dsa_seed);
    let token = load_or_create_token(&args.token_path)?;

    tracing::info!(
        fingerprint = %hex::encode(manager.identity_fingerprint()),
        identity_path = %args.identity_path.display(),
        allowed_origins = ?args.allowed_origin,
        "operator agent identity loaded"
    );
    println!(
        "xenia-operator-agent listening on http://127.0.0.1:{}",
        args.port
    );
    println!("pairing token (paste into the console's agent settings):");
    println!("  {token}");
    println!("token also persisted at: {}", args.token_path.display());

    let state = Arc::new(AgentState {
        manager,
        ed25519_secret: Zeroizing::new(ed25519_secret),
        ml_dsa_seed: Zeroizing::new(ml_dsa_seed),
        token,
        allowed_origins: args.allowed_origin,
    });

    let app = build_router(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Build the axum app: routes + the auth/CORS middleware. Split out from
/// `main` so tests can drive it with `tower::ServiceExt::oneshot` instead of
/// binding a real socket.
fn build_router(state: Arc<AgentState>) -> Router {
    Router::new()
        .route("/identity", get(get_identity))
        .route("/seeds", get(get_seeds))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_and_cors_middleware,
        ))
        .with_state(state)
}

/// Enforces both defenses on every route: the `Origin` allowlist and the
/// pairing token. Also answers CORS preflight (`OPTIONS`) requests and
/// stamps `Access-Control-Allow-Origin` on real responses so the browser
/// will actually let the console's JS read them.
///
/// A missing, malformed (non-UTF-8), or unrecognized `Origin` is refused --
/// not treated as trusted. The agent and console are different origins by
/// construction, so a genuine console request is always cross-origin and
/// always carries this header; a request without one is not the console
/// (see the module doc comment).
async fn auth_and_cors_middleware(
    State(state): State<Arc<AgentState>>,
    method: Method,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    let origin_allowed = origin.is_some_and(|o| state.allowed_origins.iter().any(|a| a == o));

    if !origin_allowed {
        return (StatusCode::FORBIDDEN, "missing or disallowed Origin header").into_response();
    }

    if method == Method::OPTIONS {
        return cors_headers(
            origin,
            axum::response::Response::new(axum::body::Body::empty()),
        );
    }

    let presented = headers
        .get("x-agent-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq(presented.as_bytes(), state.token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid X-Agent-Token").into_response();
    }

    cors_headers(origin, next.run(request).await)
}

fn cors_headers(origin: Option<&str>, mut response: Response) -> Response {
    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            response
                .headers_mut()
                .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("x-agent-token, content-type"),
        );
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, OPTIONS"),
        );
    }
    response
}

/// Byte-for-byte comparison that doesn't short-circuit on the first
/// mismatch. The threat model here is a same-machine process, not a remote
/// network timing attack, but this is free to get right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Serialize)]
struct IdentityResponse {
    ed25519_pubkey_hex: String,
    ml_dsa_pubkey_hex: String,
    ml_dsa_87_pubkey_hex: String,
    fingerprint_hex: String,
    /// A paste-ready enrollment record for the daemon's `--operators-file`
    /// (with `your-operator-id` / `Viewer` as placeholders the admin
    /// fills in) -- the same shape `sovereign-admin`'s
    /// `OperatorIdentity::enrollment_record_json` used to build locally.
    enrollment_record_json: String,
}

async fn get_identity(State(state): State<Arc<AgentState>>) -> Json<IdentityResponse> {
    let ml_dsa_87_seed = xenia_wire::handshake_highsec::derive_ml_dsa_87_seed_from_ed25519_secret(
        &state.ed25519_secret,
    );
    let highsec = xenia_wire::handshake_highsec::ViewerHandshakeHighSec::from_identity(
        &state.ed25519_secret[..],
        &ml_dsa_87_seed,
    )
    .expect("32-byte seeds always produce a valid high-security identity");

    let record = OperatorEnrollmentRecord {
        operator_id: "your-operator-id".to_string(),
        ed25519_pubkey: hex::encode(state.manager.identity_public_key_bytes()),
        ml_dsa_pubkey: hex::encode(state.manager.ml_dsa_public_key_bytes()),
        ml_dsa_87_pubkey: Some(hex::encode(highsec.ml_dsa_public_key_bytes())),
        role: OperatorRole::Viewer,
    };

    Json(IdentityResponse {
        ed25519_pubkey_hex: hex::encode(state.manager.identity_public_key_bytes()),
        ml_dsa_pubkey_hex: hex::encode(state.manager.ml_dsa_public_key_bytes()),
        ml_dsa_87_pubkey_hex: hex::encode(highsec.ml_dsa_public_key_bytes()),
        fingerprint_hex: hex::encode(state.manager.identity_fingerprint()),
        enrollment_record_json: record.to_json_string(),
    })
}

#[derive(Serialize)]
struct SeedsResponse {
    ed25519_secret_hex: String,
    ml_dsa_seed_hex: String,
}

/// The sensitive endpoint: returns the raw seeds. The console fetches this
/// once per page session into memory and never persists the result --
/// see the module doc comment's scope note for what this does and doesn't
/// protect against today.
async fn get_seeds(State(state): State<Arc<AgentState>>) -> Json<SeedsResponse> {
    Json(SeedsResponse {
        ed25519_secret_hex: hex::encode(*state.ed25519_secret),
        ml_dsa_seed_hex: hex::encode(*state.ml_dsa_seed),
    })
}

/// Load the operator identity from `path`, or generate and persist a fresh
/// one (0600) on first use. 64-byte blob: 32-byte Ed25519 secret followed
/// by a 32-byte ML-DSA-65 seed. Mirrors `xenia-peer`'s
/// `load_or_create_host_identity` byte layout (not its permission-handling
/// -- see [`load_or_create_secure_file`]).
fn load_or_create_identity_seeds(
    path: &Path,
) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    let blob = load_or_create_secure_file(path, || {
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob.extend_from_slice(&rand::random::<[u8; 32]>());
        blob
    })?;
    if blob.len() != 64 {
        return Err("operator agent identity file must be exactly 64 bytes".into());
    }
    let mut ed25519_secret = [0u8; 32];
    let mut ml_dsa_seed = [0u8; 32];
    ed25519_secret.copy_from_slice(&blob[..32]);
    ml_dsa_seed.copy_from_slice(&blob[32..64]);
    Ok((ed25519_secret, ml_dsa_seed))
}

/// Load the pairing token from `path`, or generate and persist a fresh one
/// (0600, 32 random bytes hex-encoded) on first use.
fn load_or_create_token(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = load_or_create_secure_file(path, || {
        hex::encode(rand::random::<[u8; 32]>()).into_bytes()
    })?;
    Ok(String::from_utf8(bytes)?.trim().to_string())
}

/// Atomically create `path` with owner-only (`0600`) permissions set *at
/// creation* (not chmod'd afterward -- there is no window where a racing
/// process could open it before permissions are tightened) if it doesn't
/// exist yet, writing `generate()`'s output and returning it. If `path`
/// already exists, refuse to use it unless it's a regular file (not a
/// symlink) owned by this process's user, then return its contents --
/// closing off a symlink-swap or different-local-user substitution attack
/// on a file this process is about to trust as key material.
fn load_or_create_secure_file(
    path: &Path,
    generate: impl FnOnce() -> Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match secure_create_new(path) {
        Ok(mut file) => {
            use std::io::Write;
            let contents = generate();
            file.write_all(&contents)?;
            Ok(contents)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            check_existing_file_is_safe(path)?;
            Ok(std::fs::read(path)?)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn secure_create_new(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
#[cfg(not(unix))]
fn secure_create_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn check_existing_file_is_safe(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink -- refusing to use it for sensitive material",
            path.display()
        )
        .into());
    }
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()).into());
    }
    let owner_uid = meta.uid();
    let current_uid = rustix::process::getuid().as_raw();
    if owner_uid != current_uid {
        return Err(format!(
            "{} is owned by uid {owner_uid}, not this process's uid {current_uid} -- refusing to use it",
            path.display()
        )
        .into());
    }
    // Re-tighten permissions in case they drifted since creation (defense
    // in depth).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn check_existing_file_is_safe(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_and_rejects_different_or_wrong_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn identity_seeds_round_trip_through_a_file() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-agent-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");

        let (ed1, ml1) = load_or_create_identity_seeds(&path).unwrap();
        let (ed2, ml2) = load_or_create_identity_seeds(&path).unwrap();
        assert_eq!(ed1, ed2, "second load must reuse the persisted identity");
        assert_eq!(ml1, ml2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn token_round_trips_and_is_reused() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-agent-test-token-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token.key");

        let t1 = load_or_create_token(&path).unwrap();
        let t2 = load_or_create_token(&path).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64, "32 random bytes, hex-encoded");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn refuses_a_symlink_swapped_in_for_the_identity_file() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-agent-test-symlink-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let real_secret = dir.join("some-other-secret");
        std::fs::write(&real_secret, b"not an operator identity").unwrap();
        let path = dir.join("identity.key");
        std::os::unix::fs::symlink(&real_secret, &path).unwrap();

        let err = load_or_create_identity_seeds(&path).unwrap_err();
        assert!(err.to_string().contains("symlink"), "got: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_a_directory_where_the_identity_file_should_be() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-agent-test-dir-{}",
            rand::random::<u64>()
        ));
        let path = dir.join("identity.key");
        std::fs::create_dir_all(&path).unwrap();

        let err = load_or_create_identity_seeds(&path).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "got: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    fn test_state(token: &str, allowed_origins: &[&str]) -> Arc<AgentState> {
        Arc::new(AgentState {
            manager: HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]),
            ed25519_secret: Zeroizing::new([1u8; 32]),
            ml_dsa_seed: Zeroizing::new([2u8; 32]),
            token: token.to_string(),
            allowed_origins: allowed_origins.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[tokio::test]
    async fn missing_origin_is_refused_even_with_a_valid_token() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("x-agent-token", "secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn wrong_origin_is_refused() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("origin", "http://evil.example")
            .header("x-agent-token", "secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn right_origin_but_wrong_token_is_refused() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("origin", "http://localhost:8134")
            .header("x-agent-token", "not-the-secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn right_origin_and_token_succeeds() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("origin", "http://localhost:8134")
            .header("x-agent-token", "secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:8134"
        );
    }
}
