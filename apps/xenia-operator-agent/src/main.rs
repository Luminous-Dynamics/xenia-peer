// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local signing agent for the Xenia operator identity.
//!
//! `apps/sovereign-admin`'s browser console used to persist the operator's
//! Ed25519 + ML-DSA seeds as plaintext hex in `localStorage` -- readable by
//! an XSS bug, a malicious browser extension, or a compromised same-origin
//! dependency (see `docs/security/OPERATOR_SECURITY_MODEL.md` §9, and the
//! external review that flagged it). This binary is the fix: it holds the
//! seeds in a permission-restricted file on disk and never releases them --
//! not to `localStorage`, and not even into the console's memory
//! transiently. Instead it signs and handshakes on the console's behalf:
//! `POST /v1/sign/challenge`/`/v1/sign/consent-action`/`/v1/sign/revoke` for
//! the `/auth/*` HTTP ceremony (see `docs/security/SIGNER_DELEGATION_DESIGN.md`
//! "Track A"), and `POST /v1/handshake/begin`/`/v1/handshake/finish` for the
//! sealed-channel handshake ("Track B"). `GET /identity` exposes the
//! operator's *public* keys/fingerprint/enrollment-record for display --
//! the one HTTP surface here that returns identity data, and it never
//! includes the seeds.
//!
//! **History**: an earlier revision of this binary only moved the
//! *persistent storage* of the seeds out of the browser -- the console
//! still fetched them into memory each page session and signed locally
//! with them (via a since-removed `GET /seeds`). That window (seeds live in
//! browser memory for the session, though never on disk) is now fully
//! closed: every signing and handshaking operation happens in this
//! process, and the seeds never leave it.
//!
//! ## Security model
//!
//! - Binds to `127.0.0.1` only -- never configurable to a wider address.
//! - The pairing token (`X-Agent-Token` header, generated on first run and
//!   persisted alongside the identity) is bootstrap-only: it authenticates
//!   exactly one route, `POST /v1/pair`, which mints a short-lived
//!   [`xenia_operator_agent_proto::AgentSessionToken`]. Every other route
//!   requires that session token (`X-Agent-Session` header) instead --
//!   see [`agent_session`]'s module doc comment for why a permanent bearer
//!   secret sent on every request was replaced with one that expires. The
//!   operator copies the raw pairing token into the console's agent
//!   settings once, to pair; from then on the console renews its own
//!   session via `POST /v1/session/refresh` and doesn't need the raw token
//!   again unless it goes idle past the session TTL.
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
//! - The identity file, token file, and host-trust pin store all default to
//!   living under a dedicated `xenia-operator-agent-state/` directory
//!   (still overridable per-file via `--xxx-path`), created and re-verified
//!   `0700` on every access. Every file is created **atomically** with
//!   owner-only (`0600`) permissions set *at creation*, not chmod'd
//!   afterward (closing the window where a racing process could read them
//!   between write and chmod), and every open -- of the parent directory
//!   and the leaf file alike -- is descriptor-relative and `O_NOFOLLOW`,
//!   so neither a symlinked parent path component nor a symlink swapped in
//!   for the leaf file itself can be followed, and each is also checked
//!   owned by this process's uid. See `secure_file.rs`'s module doc comment
//!   for the full reasoning.
//! - The seeds are held zeroize-on-drop (`zeroize::Zeroizing`) for as long
//!   as this process holds them in memory.

// `host_trust` (native host-fingerprint trust policy), step 1 of
// SIGNER_DELEGATION_DESIGN.md's recommended PR sequence, is wired in
// (step 2: `POST /v1/sign/challenge`; step 3: `POST /v1/sign/consent-action`;
// step 4: `POST /v1/sign/revoke`). `daemon_evidence` (PR "4.5b") replaces
// the caller-supplied `daemon_fingerprint_hex` those steps originally used
// with daemon-signed evidence the agent verifies itself -- see that
// module's doc comment for the confused-deputy gap this closes.
mod agent_session;
mod audit_log;
mod daemon_evidence;
mod handshake_state;
mod host_trust;
mod secure_file;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use serde::Serialize;
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN};
use xenia_operator_agent_proto::{
    AgentErrorCode, AgentErrorResponse, AgentSessionToken, HandshakeBeginRequest,
    HandshakeBeginResponse, HandshakeFinishRequest, HandshakeFinishResponse, SignChallengeRequest,
    SignChallengeResponse, SignConsentActionRequest, SignConsentActionResponse,
    SignReplaceKeyRequest, SignReplaceKeyResponse, SignRevokeRequest, SignRevokeResponse,
};
use xenia_operator_proto::{OperatorEnrollmentRecord, OperatorRole};
use xenia_wire::handshake::ViewerHandshake;
use xenia_wire::handshake_highsec::{
    derive_ml_dsa_87_seed_from_ed25519_secret, ViewerHandshakeHighSec, ML_DSA_87_PK_LEN,
};
use zeroize::Zeroizing;

use daemon_evidence::{decode_fixed_hex, decode_hex_vec};
use handshake_state::{HandshakeState, PendingSuite};
use host_trust::HostTrustStore;

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
    #[arg(
        long,
        default_value = "xenia-operator-agent-state/operator-agent-identity.key"
    )]
    identity_path: PathBuf,

    /// Pairing-token path (32 random bytes, hex-encoded). Generated on
    /// first run (0600); the operator copies this value into the
    /// console's agent settings once.
    #[arg(
        long,
        default_value = "xenia-operator-agent-state/operator-agent-token.key"
    )]
    token_path: PathBuf,

    /// Origin the console is served from. Repeatable. A request whose
    /// `Origin` header doesn't match any of these is refused. Defaults
    /// cover the console's Trunk dev-serve origins.
    #[arg(
        long,
        default_values = ["http://localhost:8134", "http://127.0.0.1:8134"]
    )]
    allowed_origin: Vec<String>,

    /// Native host-trust pin-store path (`host_trust::HostTrustStore`).
    /// Grows over time as `/v1/sign/*` and `/v1/handshake/*` requests name
    /// daemon fingerprints to trust; unlike the identity/token files this
    /// has no fixed first-run content, so it's simply created empty on
    /// first use.
    #[arg(
        long,
        default_value = "xenia-operator-agent-state/operator-agent-host-trust.json"
    )]
    pin_store_path: PathBuf,

    /// Allow a privileged confirmation (first trust of a daemon
    /// fingerprint, a fingerprint change, or -- in later steps --
    /// revocation/enrollment) to proceed automatically when no interactive
    /// terminal is attached, instead of failing closed. Off by default;
    /// see `host_trust`'s module docs for why there's no silent fallback.
    #[arg(long, default_value_t = false)]
    allow_noninteractive_privileged_confirmation: bool,

    /// How long a session minted by `POST /v1/pair` or
    /// `POST /v1/session/refresh` stays valid, in seconds. See
    /// `agent_session`'s module doc comment for the tradeoff this bounds.
    #[arg(long, default_value_t = agent_session::DEFAULT_SESSION_TTL_SECS)]
    session_ttl_secs: u64,

    /// Durable audit-trail path (`audit_log::AgentAuditChain`) -- host-trust
    /// first-use/rotation, pairing, session refresh, and revocation, each
    /// hash-chained and signed with this agent's own identity key. Unlike
    /// the pin store, this file must never partially load or silently
    /// truncate: a corrupt or tampered audit log fails startup outright
    /// rather than serving an audit trail that looks intact but isn't.
    #[arg(long, default_value = "xenia-operator-agent-state/audit.log")]
    audit_log_path: PathBuf,
}

struct AgentState {
    manager: HandshakeManager,
    ed25519_secret: Zeroizing<[u8; 32]>,
    ml_dsa_seed: Zeroizing<[u8; 32]>,
    /// The raw, file-persisted pairing token -- accepted only on
    /// `POST /v1/pair` (see `agent_session`'s module doc comment). Every
    /// other route requires `session_mac_key` to verify an
    /// `X-Agent-Session` header instead.
    token: String,
    /// Derived from `token` once at startup (`agent_session::session_mac_key`).
    /// Cached rather than recomputed per-request; stable across restarts
    /// since it's deterministic in the persisted `token`.
    session_mac_key: [u8; 32],
    /// Lifetime of a freshly minted or refreshed session, in seconds.
    session_ttl_secs: u64,
    allowed_origins: Vec<String>,
    /// Native host-trust policy for `/v1/sign/*` and `/v1/handshake/*`.
    /// `HostTrustStore::check` blocks on terminal I/O, so callers must
    /// reach it through `tokio::task::spawn_blocking` rather than locking
    /// it directly on an async worker thread.
    host_trust: StdMutex<HostTrustStore>,
    /// Pending Track B handshakes (`handshake_state`'s module doc
    /// comment). Locked only for brief map operations -- the crypto work
    /// itself (`ViewerHandshake::begin`/`finish`) runs on an owned local
    /// value outside the lock.
    handshake_state: StdMutex<HandshakeState>,
    /// Durable audit trail of this agent's own trust decisions
    /// (`audit_log`'s module doc comment). Locked only for brief
    /// append/read operations -- no blocking I/O happens under the lock
    /// itself beyond the transactional persist, which is a plain local
    /// file write.
    audit_log: StdMutex<audit_log::AgentAuditChain>,
    audit_log_path: PathBuf,
    /// Wall-clock time this process started, for `GET /v1/health`'s
    /// `uptime_secs`.
    started_at: std::time::Instant,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    // Captured before `load_or_create_identity_seeds` (below) can create
    // it -- used after `audit_log::load_verified` to detect a suspicious
    // combination: an identity that already existed (this agent has run
    // before) but no audit log (see that call site's comment).
    let identity_existed = args.identity_path.exists();

    let (ed25519_secret, ml_dsa_seed) = load_or_create_identity_seeds(&args.identity_path)?;
    let manager = HandshakeManager::from_identity_seeds(ed25519_secret, ml_dsa_seed);
    let token = load_or_create_token(&args.token_path)?;
    let host_trust = HostTrustStore::load(
        args.pin_store_path.clone(),
        args.allow_noninteractive_privileged_confirmation,
    )?;
    // Same identity key as `manager`'s Ed25519 half -- no new key material.
    // `ed25519_secret` is `[u8; 32]: Copy`, so reusing it here doesn't
    // conflict with `manager`'s own earlier construction above.
    let audit_signing_key = ed25519_dalek::SigningKey::from_bytes(&ed25519_secret);
    // `load_verified` treats a missing file as a legitimate fresh chain
    // (the right call for a genuine first run -- hard-failing here would
    // let an attacker with local write access, but no signing key,
    // permanently brick the agent by deleting one file). But a missing
    // audit log *combined with* a pre-existing identity is suspicious --
    // it means this agent has run before, so a prior audit trail should
    // exist. Loudly flag that combination rather than silently starting a
    // fresh chain with no record anything was ever lost.
    if identity_existed && !args.audit_log_path.exists() {
        tracing::warn!(
            audit_log_path = %args.audit_log_path.display(),
            "this agent's identity already exists but its audit log is missing -- \
             audit history was likely deleted; starting a fresh, empty chain"
        );
    }
    let audit_log = audit_log::load_verified(&args.audit_log_path, audit_signing_key)?;

    tracing::info!(
        fingerprint = %hex::encode(manager.identity_fingerprint()),
        identity_path = %args.identity_path.display(),
        allowed_origins = ?args.allowed_origin,
        pin_store_path = %args.pin_store_path.display(),
        audit_log_path = %args.audit_log_path.display(),
        audit_log_entries = audit_log.len(),
        "operator agent identity loaded"
    );
    println!(
        "xenia-operator-agent listening on http://127.0.0.1:{}",
        args.port
    );
    println!("pairing token (paste into the console's agent settings once, to pair):");
    println!("  {token}");
    println!("token also persisted at: {}", args.token_path.display());
    println!(
        "sessions minted from it last {}s before the console must re-pair",
        args.session_ttl_secs
    );

    let session_mac_key = agent_session::session_mac_key(&token);
    let state = Arc::new(AgentState {
        manager,
        ed25519_secret: Zeroizing::new(ed25519_secret),
        ml_dsa_seed: Zeroizing::new(ml_dsa_seed),
        token,
        session_mac_key,
        session_ttl_secs: args.session_ttl_secs,
        allowed_origins: args.allowed_origin,
        host_trust: StdMutex::new(host_trust),
        handshake_state: StdMutex::new(HandshakeState::new(handshake_state::DEFAULT_TTL)),
        audit_log: StdMutex::new(audit_log),
        audit_log_path: args.audit_log_path,
        started_at: std::time::Instant::now(),
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
    let authenticated = Router::new()
        .route("/identity", get(get_identity))
        .route("/v1/audit", get(get_audit_log))
        .route("/v1/pair", post(pair_handler))
        .route("/v1/session/refresh", post(refresh_handler))
        .route("/v1/sign/challenge", post(sign_challenge))
        .route("/v1/sign/consent-action", post(sign_consent_action))
        .route("/v1/sign/revoke", post(sign_revoke))
        .route("/v1/sign/replace-key", post(sign_replace_key))
        .route("/v1/handshake/begin", post(handshake_begin))
        .route("/v1/handshake/finish", post(handshake_finish))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_and_cors_middleware,
        ));
    // `/v1/health` deliberately sits outside `auth_and_cors_middleware`
    // entirely (own router, merged in below, no `.layer()`) rather than a
    // path special-case inside that function: a liveness probe (systemd,
    // a monitoring script) has no reason to send an Origin header or hold
    // a session, and the health response itself carries no secret
    // material -- see `get_health`'s doc comment.
    let health = Router::new().route("/v1/health", get(get_health));
    authenticated
        .merge(health)
        // The `/v1/sign/*` bodies are small, fixed-shape JSON, but no
        // longer just "a handful of hex strings" now that they carry a
        // `DaemonIdentityCertificate` (ML-DSA-65 alone is ~1952-byte
        // pubkeys / ~3309-byte signatures, hex-doubled) plus, for
        // /v1/sign/challenge, a second ML-DSA host attestation on top --
        // a genuine such request runs ~17-18KB. `/v1/handshake/*` bodies
        // stay small (a single bincode-encoded handshake message, at most
        // a few KB for the ML-KEM-1024 high-security suite). 64KiB gives
        // headroom for all of these while still refusing anything wildly
        // larger up front, before typed parsing even starts. GET routes
        // have no body, so this only bounds the POST routes in practice.
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

/// Enforces both defenses on every route: the `Origin` allowlist, then a
/// per-route credential check. Also answers CORS preflight (`OPTIONS`)
/// requests and stamps `Access-Control-Allow-Origin` on real responses so
/// the browser will actually let the console's JS read them.
///
/// A missing, malformed (non-UTF-8), or unrecognized `Origin` is refused --
/// not treated as trusted. The agent and console are different origins by
/// construction, so a genuine console request is always cross-origin and
/// always carries this header; a request without one is not the console
/// (see the module doc comment).
///
/// **Credential check is per-route**: `POST /v1/pair` is the one place the
/// raw pairing token (`X-Agent-Token`) still works -- it's how a session
/// gets minted in the first place. Every other route, including
/// `POST /v1/session/refresh`, requires a live session
/// (`X-Agent-Session`) instead; see [`agent_session`]'s module doc comment
/// for why. The raw pairing token is never accepted on any route other
/// than `/v1/pair`, so a leaked session token can't be used to mint
/// another session the way a leaked pairing token could re-derive one --
/// only the pairing token itself can do that.
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

    if request.uri().path() == "/v1/pair" {
        let presented = headers
            .get("x-agent-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !constant_time_eq(presented.as_bytes(), state.token.as_bytes()) {
            return (StatusCode::UNAUTHORIZED, "missing or invalid X-Agent-Token").into_response();
        }
    } else {
        let presented = headers
            .get("x-agent-session")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if let Err(e) = agent_session::verify(&state.session_mac_key, unix_now_secs(), presented) {
            return (StatusCode::UNAUTHORIZED, e.message()).into_response();
        }
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
            HeaderValue::from_static("x-agent-token, x-agent-session, content-type"),
        );
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
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

/// `POST /v1/pair` (raw-pairing-token-gated): the credential
/// `auth_and_cors_middleware` demanded to reach here proves the caller
/// holds the pairing token, so this is a genuine pairing event -- audited
/// distinctly from a session refresh.
async fn pair_handler(
    State(state): State<Arc<AgentState>>,
) -> Result<Json<AgentSessionToken>, (StatusCode, Json<AgentErrorResponse>)> {
    let token = mint_session_inner(&state);
    record_audit_event(&state, audit_log::AgentAuditEvent::Paired).await?;
    Ok(Json(token))
}

/// `POST /v1/session/refresh` (session-gated): the caller already held a
/// valid session and is renewing it before it expires.
async fn refresh_handler(
    State(state): State<Arc<AgentState>>,
) -> Result<Json<AgentSessionToken>, (StatusCode, Json<AgentErrorResponse>)> {
    let token = mint_session_inner(&state);
    record_audit_event(&state, audit_log::AgentAuditEvent::SessionRefreshed).await?;
    Ok(Json(token))
}

/// Shared by [`pair_handler`] and [`refresh_handler`] -- both just mint a
/// fresh session; the only difference between them is which credential
/// `auth_and_cors_middleware` demanded to reach here, and which audit
/// event that implies. See [`agent_session`]'s module doc comment.
fn mint_session_inner(state: &AgentState) -> AgentSessionToken {
    agent_session::mint(
        &state.session_mac_key,
        unix_now_secs(),
        state.session_ttl_secs,
    )
}

/// Current Unix time in seconds. Falls back to 0 only if the system clock
/// is somehow set before 1970 -- not a case worth failing requests over;
/// see `xenia-peer`'s identical `unix_now_secs` for the same reasoning.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

/// Response body for `GET /v1/health`. Deliberately minimal: a liveness
/// probe needs to know the process is up and roughly how long it's been
/// running, not anything an operator would consider sensitive.
/// `fingerprint_hex` is already public (the same value `GET /identity`
/// exposes, and what an operator names when enrolling this agent), and
/// `active` is always `true` once this handler is reachable at all --
/// kept as a field rather than the response's mere existence so the
/// shape stays extensible if a future check needs to report degraded
/// (not just up/down) state.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_secs: u64,
    fingerprint_hex: String,
    active: bool,
}

/// `GET /v1/health` -- unauthenticated liveness probe (see `build_router`'s
/// doc comment for why this sits outside `auth_and_cors_middleware`
/// entirely). No secret material, no pairing token, no session state.
async fn get_health(State(state): State<Arc<AgentState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_secs: state.started_at.elapsed().as_secs(),
        fingerprint_hex: hex::encode(state.manager.identity_fingerprint()),
        active: true,
    })
}

/// Response body for `GET /v1/audit`: the full in-memory audit trail plus
/// a checkpoint over the same state, mirroring the daemon's
/// `AuditLedgerExportDto` shape (`operator_http.rs`) so a caller can
/// confirm `entries.last().entry_hash == checkpoint.head_hash` without
/// trusting the agent that served the export.
#[derive(Serialize)]
struct AgentAuditExportDto {
    entries: Vec<audit_log::AgentAuditEntry>,
    checkpoint: audit_log::AgentAuditCheckpoint,
}

/// `GET /v1/audit` -- this agent's own durable audit trail (host-trust
/// first-use/rotation, pairing, session refresh, revocation). Gated by
/// the same `X-Agent-Session` requirement `auth_and_cors_middleware`
/// already applies to every route but `/v1/pair` -- no separate
/// authorization check needed here.
async fn get_audit_log(State(state): State<Arc<AgentState>>) -> Json<AgentAuditExportDto> {
    let chain = state.audit_log.lock().expect("audit-log mutex poisoned");
    let checkpoint = chain.sign_checkpoint(unix_now_secs());
    let entries = chain.entries().to_vec();
    Json(AgentAuditExportDto {
        entries,
        checkpoint,
    })
}

/// `POST /v1/sign/challenge` -- sign the daemon's `/auth/challenge` nonce
/// with both algorithms, proving possession of the enrolled operator key,
/// without the raw seeds ever leaving this process. Step 2 of
/// `docs/security/SIGNER_DELEGATION_DESIGN.md`'s PR sequence (Track A);
/// its host-trust gate was hardened in PR "4.5b" (see
/// [`daemon_evidence`]'s module doc comment).
///
/// Local-caller authentication (Origin + `X-Agent-Session`) already
/// happened in `auth_and_cors_middleware` before this handler runs. What
/// follows:
/// 1. Reject an unrecognized `schema_version` or malformed `suite`
///    ([`validate_common`]).
/// 2. Decode the typed hex fields; reject anything that isn't exactly the
///    expected length.
/// 3. Verify `req.common.daemon_certificate`'s own signatures, compute the
///    daemon's fingerprint from it, and check that fingerprint against
///    native host-trust policy ([`enforce_host_trust`]) -- never trusting
///    a caller-supplied fingerprint.
/// 4. Verify the challenge host attestation proves *this exact nonce* was
///    issued by that same, now-trusted daemon identity -- otherwise a
///    compromised browser could ask the agent to sign an attacker-chosen
///    nonce under an otherwise-legitimate daemon certificate.
/// 5. Build the canonical transcript via `xenia_operator_proto`'s own
///    `challenge_transcript` -- never a caller-supplied byte string, so a
///    compromised browser can't use this endpoint as a blind signing
///    oracle.
/// 6. Sign with both required algorithms and return the envelope.
async fn sign_challenge(
    State(state): State<Arc<AgentState>>,
    Json(req): Json<SignChallengeRequest>,
) -> Result<Json<SignChallengeResponse>, (StatusCode, Json<AgentErrorResponse>)> {
    validate_common(&req.common)?;
    let nonce = decode_fixed_hex::<32>(&req.nonce_hex)
        .ok_or_else(|| bad_request("nonce_hex must be 64 hex characters"))?;
    let identity = enforce_host_trust(&state, &req.common, "/v1/sign/challenge").await?;
    daemon_evidence::verify_challenge_attestation(
        &identity,
        &nonce,
        &req.host_ed_attestation_hex,
        &req.host_ml_dsa_attestation_hex,
    )
    .map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;

    let ed_pubkey = state.manager.identity_public_key_bytes();
    let ml_dsa_pubkey = state.manager.ml_dsa_public_key_bytes();
    let transcript = xenia_operator_proto::challenge_transcript(&nonce, &ed_pubkey, &ml_dsa_pubkey);
    let ed_signature = state.manager.sign(&transcript);
    let ml_dsa_signature = state.manager.sign_ml_dsa(&transcript);

    Ok(Json(SignChallengeResponse {
        ed25519_pubkey_hex: hex::encode(ed_pubkey),
        ml_dsa_pubkey_hex: hex::encode(ml_dsa_pubkey),
        ed_signature_hex: hex::encode(ed_signature.to_bytes()),
        ml_dsa_signature_hex: hex::encode(ml_dsa_signature),
    }))
}

/// `POST /v1/sign/consent-action` -- sign a session-bound consent decision
/// (Approve/Deny/Revoke -- see [`xenia_operator_proto::ConsentAction`];
/// `Revoke` here means revoking a *consent grant*, e.g. ending an
/// already-approved screen-share session, not revoking an operator's
/// enrollment -- that's the separate, mandatory-confirmation
/// `/v1/sign/revoke` from step 4). Step 3 of the design doc's PR sequence.
///
/// Same processing shape as [`sign_challenge`], except the evidence
/// verified after host-trust is the relayed session token
/// ([`daemon_evidence::verify_token`]) rather than a challenge attestation
/// -- its signature must verify against the certificate's now-trusted
/// delegated HTTP-auth key before its `token_nonce` is bound into the
/// consent-action transcript. Per the confirmation policy, an ordinary
/// approve/deny/consent-revoke against an already-pinned host needs no
/// *additional* confirmation beyond the host-trust check itself -- it
/// isn't on the design doc's mandatory-confirmation list (that list is
/// enrollment, operator revocation, role/capability elevation, trust-root
/// changes, and unusually broad *grants*, none of which this action shape
/// can express).
async fn sign_consent_action(
    State(state): State<Arc<AgentState>>,
    Json(req): Json<SignConsentActionRequest>,
) -> Result<Json<SignConsentActionResponse>, (StatusCode, Json<AgentErrorResponse>)> {
    validate_common(&req.common)?;
    let session_id = decode_fixed_hex::<16>(&req.session_id_hex)
        .ok_or_else(|| bad_request("session_id_hex must be 32 hex characters"))?;
    let identity = enforce_host_trust(&state, &req.common, "/v1/sign/consent-action").await?;
    let token_nonce = daemon_evidence::verify_token(&identity, &req.token).map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;

    let transcript =
        xenia_operator_proto::consent_action_transcript(req.action, &session_id, &token_nonce);
    let ed_signature = state.manager.sign(&transcript);
    let ml_dsa_signature = state.manager.sign_ml_dsa(&transcript);

    Ok(Json(SignConsentActionResponse {
        ed_signature_hex: hex::encode(ed_signature.to_bytes()),
        ml_dsa_signature_hex: hex::encode(ml_dsa_signature),
    }))
}

/// `POST /v1/sign/revoke` -- sign an admin's authorization to revoke
/// *another operator's enrollment*. Step 4 of the design doc's PR
/// sequence, and the first endpoint that actually exercises the
/// mandatory-*action*-confirmation path: "operator revocation" is on the
/// design doc's mandatory-confirmation list regardless of how
/// well-trusted the target daemon already is, so this handler runs a
/// *second*, independent confirmation
/// (`host_trust::HostTrustStore::confirm_action`) on top of
/// [`enforce_host_trust`]'s host-identity gate -- an already-pinned host
/// does not exempt a revocation from being confirmed. Like
/// [`sign_consent_action`], the relayed session token is verified
/// ([`daemon_evidence::verify_token`]) before its `token_nonce` is trusted.
async fn sign_revoke(
    State(state): State<Arc<AgentState>>,
    Json(req): Json<SignRevokeRequest>,
) -> Result<Json<SignRevokeResponse>, (StatusCode, Json<AgentErrorResponse>)> {
    validate_common(&req.common)?;
    if req.target_operator_id.trim().is_empty() {
        return Err(bad_request("target_operator_id must not be empty"));
    }
    let identity = enforce_host_trust(&state, &req.common, "/v1/sign/revoke").await?;
    let token_nonce = daemon_evidence::verify_token(&identity, &req.token).map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;

    let confirm_state = state.clone();
    let target = req.target_operator_id.clone();
    let daemon_endpoint = normalize_daemon_endpoint(&req.common.daemon_endpoint);
    let daemon_fingerprint_hex = hex::encode(identity.fingerprint);
    let suite = req.common.suite.clone();
    let confirmed = tokio::task::spawn_blocking(move || {
        confirm_state
            .host_trust
            .lock()
            .expect("host-trust mutex poisoned")
            .confirm_action(
                "Revoke operator enrollment?",
                &[
                    ("target operator id", target),
                    ("daemon endpoint", daemon_endpoint),
                    ("daemon fingerprint", daemon_fingerprint_hex),
                    ("suite", suite),
                ],
            )
    })
    .await
    .map_err(|_| internal_error("revoke confirmation task panicked"))?
    .map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;
    if !confirmed {
        let agent_err = AgentErrorResponse {
            code: AgentErrorCode::ConfirmationDeclined,
            message: format!(
                "operator declined to confirm revocation of '{}'",
                req.target_operator_id
            ),
        };
        return Err((status_for(agent_err.code), Json(agent_err)));
    }

    let transcript =
        xenia_operator_proto::revoke_operator_transcript(&req.target_operator_id, &token_nonce);
    let ed_signature = state.manager.sign(&transcript);
    let ml_dsa_signature = state.manager.sign_ml_dsa(&transcript);

    record_audit_event(
        &state,
        audit_log::AgentAuditEvent::RevocationSigned {
            target_operator_id: req.target_operator_id.clone(),
            daemon_endpoint: normalize_daemon_endpoint(&req.common.daemon_endpoint),
        },
    )
    .await?;

    Ok(Json(SignRevokeResponse {
        ed_signature_hex: hex::encode(ed_signature.to_bytes()),
        ml_dsa_signature_hex: hex::encode(ml_dsa_signature),
    }))
}

/// `POST /v1/sign/replace-key` -- sign an admin's authorization to replace
/// *another operator's* enrolled key material: operator-key recovery for
/// an operator who lost their signing key. `docs/security/SIGNER_DELEGATION_DESIGN.md`
/// already lists "recovery-key or trust-root changes" on the
/// mandatory-*action*-confirmation list, so this handler runs its own
/// [`host_trust::HostTrustStore::confirm_action`] on top of
/// [`enforce_host_trust`]'s host-identity gate, mirroring [`sign_revoke`]
/// exactly. The relayed session token is verified
/// ([`daemon_evidence::verify_token`]) before its `token_nonce` is trusted,
/// same as every other privileged `/v1/sign/*` handler.
async fn sign_replace_key(
    State(state): State<Arc<AgentState>>,
    Json(req): Json<SignReplaceKeyRequest>,
) -> Result<Json<SignReplaceKeyResponse>, (StatusCode, Json<AgentErrorResponse>)> {
    validate_common(&req.common)?;
    if req.target_operator_id.trim().is_empty() {
        return Err(bad_request("target_operator_id must not be empty"));
    }
    let new_ed25519_pubkey = decode_fixed_hex::<32>(&req.new_ed25519_pubkey_hex)
        .ok_or_else(|| bad_request("new_ed25519_pubkey_hex must be 32 bytes of hex"))?;
    let new_ml_dsa_pubkey = decode_fixed_hex::<ML_DSA_65_PK_LEN>(&req.new_ml_dsa_pubkey_hex)
        .ok_or_else(|| bad_request("new_ml_dsa_pubkey_hex must be a valid ML-DSA-65 public key"))?;
    let new_ml_dsa_87_pubkey =
        match &req.new_ml_dsa_87_pubkey_hex {
            None => None,
            Some(hex_str) => Some(decode_fixed_hex::<ML_DSA_87_PK_LEN>(hex_str).ok_or_else(
                || bad_request("new_ml_dsa_87_pubkey_hex must be a valid ML-DSA-87 public key"),
            )?),
        };

    let identity = enforce_host_trust(&state, &req.common, "/v1/sign/replace-key").await?;
    let token_nonce = daemon_evidence::verify_token(&identity, &req.token).map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;

    let confirm_state = state.clone();
    let target = req.target_operator_id.clone();
    let daemon_endpoint = normalize_daemon_endpoint(&req.common.daemon_endpoint);
    let daemon_fingerprint_hex = hex::encode(identity.fingerprint);
    let suite = req.common.suite.clone();
    let new_ed25519_pubkey_hex = req.new_ed25519_pubkey_hex.clone();
    let confirmed = tokio::task::spawn_blocking(move || {
        confirm_state
            .host_trust
            .lock()
            .expect("host-trust mutex poisoned")
            .confirm_action(
                "Replace operator enrollment key?",
                &[
                    ("target operator id", target),
                    ("new Ed25519 public key", new_ed25519_pubkey_hex),
                    ("daemon endpoint", daemon_endpoint),
                    ("daemon fingerprint", daemon_fingerprint_hex),
                    ("suite", suite),
                ],
            )
    })
    .await
    .map_err(|_| internal_error("key-replacement confirmation task panicked"))?
    .map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;
    if !confirmed {
        let agent_err = AgentErrorResponse {
            code: AgentErrorCode::ConfirmationDeclined,
            message: format!(
                "operator declined to confirm key replacement for '{}'",
                req.target_operator_id
            ),
        };
        return Err((status_for(agent_err.code), Json(agent_err)));
    }

    let transcript = xenia_operator_proto::replace_operator_key_transcript(
        &req.target_operator_id,
        &new_ed25519_pubkey,
        &new_ml_dsa_pubkey,
        new_ml_dsa_87_pubkey.as_ref().map(|k| k.as_slice()),
        &token_nonce,
    );
    let ed_signature = state.manager.sign(&transcript);
    let ml_dsa_signature = state.manager.sign_ml_dsa(&transcript);

    record_audit_event(
        &state,
        audit_log::AgentAuditEvent::KeyReplacementSigned {
            target_operator_id: req.target_operator_id.clone(),
            new_ed25519_pubkey_hex: req.new_ed25519_pubkey_hex.clone(),
            daemon_endpoint: normalize_daemon_endpoint(&req.common.daemon_endpoint),
        },
    )
    .await?;

    Ok(Json(SignReplaceKeyResponse {
        ed_signature_hex: hex::encode(ed_signature.to_bytes()),
        ml_dsa_signature_hex: hex::encode(ml_dsa_signature),
    }))
}

/// `POST /v1/handshake/begin` -- Track B of
/// `docs/security/SIGNER_DELEGATION_DESIGN.md`: runs the viewer half of
/// the sealed-channel handshake against the daemon's relayed `HostHello`,
/// using the agent's own persisted operator identity (the seeds never
/// leave this process). Holds the resulting pending state (see
/// [`handshake_state`]) for the matching `/v1/handshake/finish` call.
///
/// Unlike every `/v1/sign/*` handler, there is no host-trust check here --
/// `begin` doesn't yet know the daemon's identity (that's only revealed by
/// *completing* the handshake); the check happens in
/// [`handshake_finish`], gating whether any session material is ever
/// released.
async fn handshake_begin(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(req): Json<HandshakeBeginRequest>,
) -> Result<Json<HandshakeBeginResponse>, (StatusCode, Json<AgentErrorResponse>)> {
    if req.common.schema_version != xenia_operator_agent_proto::SCHEMA_VERSION {
        return Err(bad_request(format!(
            "unsupported schema_version {} (expected {})",
            req.common.schema_version,
            xenia_operator_agent_proto::SCHEMA_VERSION
        )));
    }
    if req.common.daemon_endpoint.trim().is_empty() {
        return Err(bad_request("daemon_endpoint must not be empty"));
    }
    let origin = origin_header(&headers)?;
    let hello = decode_hex_vec(&req.host_hello_hex)
        .ok_or_else(|| bad_request("host_hello_hex must be valid hex"))?;

    let (pending, viewer_response) = match req.common.suite.as_str() {
        "standard" => {
            let mut vh = ViewerHandshake::from_identity(
                &state.ed25519_secret[..],
                &state.ml_dsa_seed[..],
            )
            .map_err(|e| bad_request(format!("could not construct viewer handshake: {e}")))?;
            let resp = vh
                .begin(&hello)
                .map_err(|e| bad_request(format!("handshake begin failed: {e}")))?;
            (PendingSuite::Standard(Box::new(vh)), resp)
        }
        "highsec" => {
            let ml_dsa_87_seed = derive_ml_dsa_87_seed_from_ed25519_secret(&state.ed25519_secret);
            let mut vh = ViewerHandshakeHighSec::from_identity(
                &state.ed25519_secret[..],
                &ml_dsa_87_seed,
            )
            .map_err(|e| bad_request(format!("could not construct viewer handshake: {e}")))?;
            let resp = vh
                .begin(&hello)
                .map_err(|e| bad_request(format!("handshake begin failed: {e}")))?;
            (PendingSuite::HighSec(Box::new(vh)), resp)
        }
        _ => {
            return Err(bad_request(format!(
                "suite must be \"standard\" or \"highsec\", got {:?}",
                req.common.suite
            )));
        }
    };

    let daemon_endpoint = normalize_daemon_endpoint(&req.common.daemon_endpoint);
    let handshake_id = {
        let mut hs = state
            .handshake_state
            .lock()
            .expect("handshake-state mutex poisoned");
        hs.purge_expired();
        hs.begin(&origin, pending, daemon_endpoint.clone())
            .map_err(|e| bad_request(e.message()))?
    };

    tracing::info!(
        request_id = %req.common.request_id,
        daemon_endpoint = %daemon_endpoint,
        suite = %req.common.suite,
        handshake_id = %hex::encode(handshake_id),
        "handshake begin succeeded, pending finish"
    );

    Ok(Json(HandshakeBeginResponse {
        handshake_id_hex: hex::encode(handshake_id),
        viewer_response_hex: hex::encode(viewer_response),
        expires_in_secs: handshake_state::DEFAULT_TTL.as_secs(),
    }))
}

/// `POST /v1/handshake/finish` -- completes the pending handshake with the
/// daemon's relayed `HostFinalize`. The resulting
/// `host_identity_fingerprint` is the *authenticated* host identity --
/// derived from the handshake's own signature verification inside
/// `ViewerHandshake::finish`/`ViewerHandshakeHighSec::finish`, never a
/// caller assertion -- checked against native trust policy via
/// [`check_host_trust_fingerprint`] before any session material is
/// returned. The pending entry is consumed (single-use) regardless of
/// whether `finish` or the trust check succeeds or fails.
async fn handshake_finish(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(req): Json<HandshakeFinishRequest>,
) -> Result<Json<HandshakeFinishResponse>, (StatusCode, Json<AgentErrorResponse>)> {
    if req.schema_version != xenia_operator_agent_proto::SCHEMA_VERSION {
        return Err(bad_request(format!(
            "unsupported schema_version {} (expected {})",
            req.schema_version,
            xenia_operator_agent_proto::SCHEMA_VERSION
        )));
    }
    let origin = origin_header(&headers)?;
    let handshake_id = decode_fixed_hex::<16>(&req.handshake_id_hex)
        .ok_or_else(|| bad_request("handshake_id_hex must be 32 hex characters"))?;
    let finalize = decode_hex_vec(&req.host_finalize_hex)
        .ok_or_else(|| bad_request("host_finalize_hex must be valid hex"))?;

    let taken = {
        let mut hs = state
            .handshake_state
            .lock()
            .expect("handshake-state mutex poisoned");
        hs.take(&handshake_id, &origin)
            .map_err(|e| bad_request(e.not_found_message()))?
    };
    let daemon_endpoint = taken.daemon_endpoint;

    let (schedule, suite_label) = match taken.suite {
        PendingSuite::Standard(mut vh) => {
            let schedule = vh.finish(&finalize).map_err(|e| {
                bad_request(format!(
                    "handshake finish failed (host rejected or MITM): {e}"
                ))
            })?;
            (schedule, "standard")
        }
        PendingSuite::HighSec(mut vh) => {
            let schedule = vh.finish(&finalize).map_err(|e| {
                bad_request(format!(
                    "handshake finish failed (host rejected or MITM): {e}"
                ))
            })?;
            (schedule, "highsec")
        }
    };

    let outcome = check_host_trust_fingerprint(
        &state,
        schedule.host_identity_fingerprint,
        &daemon_endpoint,
        suite_label,
    )
    .await?;
    tracing::info!(
        handshake_id = %req.handshake_id_hex,
        daemon_endpoint = %daemon_endpoint,
        suite = suite_label,
        outcome = ?outcome,
        "host trust check passed for /v1/handshake/finish"
    );

    Ok(Json(HandshakeFinishResponse {
        aead_key_hex: hex::encode(schedule.aead),
        rekey_root_hex: hex::encode(schedule.rekey),
        transcript_hash_hex: hex::encode(schedule.transcript_hash),
        authenticated_host_fingerprint_hex: hex::encode(schedule.host_identity_fingerprint),
    }))
}

/// The `Origin` header value, already validated (present + allowlisted) by
/// `auth_and_cors_middleware` before any handler runs -- re-extracted here
/// only to *record* which caller a pending handshake belongs to. Missing
/// would mean the middleware didn't actually run, which would be a bug in
/// this binary, not a caller error -- hence `internal_error`, not
/// `bad_request`.
fn origin_header(headers: &HeaderMap) -> Result<String, (StatusCode, Json<AgentErrorResponse>)> {
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            internal_error("missing Origin header past auth middleware (should be unreachable)")
        })
}

/// Steps 1-2 shared by every `/v1/sign/*` handler: reject an unrecognized
/// `schema_version`, malformed `suite`, or empty `daemon_endpoint` rather
/// than guessing at compatibility.
fn validate_common(
    common: &xenia_operator_agent_proto::SignRequestCommon,
) -> Result<(), (StatusCode, Json<AgentErrorResponse>)> {
    if common.schema_version != xenia_operator_agent_proto::SCHEMA_VERSION {
        return Err(bad_request(format!(
            "unsupported schema_version {} (expected {})",
            common.schema_version,
            xenia_operator_agent_proto::SCHEMA_VERSION
        )));
    }
    if common.suite != "standard" && common.suite != "highsec" {
        return Err(bad_request(format!(
            "suite must be \"standard\" or \"highsec\", got {:?}",
            common.suite
        )));
    }
    if common.daemon_endpoint.trim().is_empty() {
        return Err(bad_request("daemon_endpoint must not be empty"));
    }
    Ok(())
}

/// Normalize a caller-supplied `daemon_endpoint` before using it as a
/// host-trust pin-store scope key: trim surrounding whitespace and
/// lowercase it, so trivial variance (a trailing space, a differently-cased
/// scheme) doesn't fragment one daemon into two pin-store slots. This is
/// *not* a security check -- `daemon_endpoint` is a label, not identity
/// evidence (see [`xenia_operator_agent_proto::SignRequestCommon::daemon_endpoint`]'s
/// doc comment); the agent never trusts it for anything beyond picking
/// which pin-store entry to compare the *verified* fingerprint against.
fn normalize_daemon_endpoint(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Step 3, shared by every `/v1/sign/*` handler: verify
/// `common.daemon_certificate`'s own signatures
/// ([`daemon_evidence::verify_daemon_certificate`]), then check the
/// fingerprint it computes against native host-trust policy via
/// [`check_host_trust_fingerprint`], scoped by `common.daemon_endpoint`
/// (normalized). Returns the verified identity so callers can check
/// further evidence (a challenge attestation or a session token) against
/// its now-trusted keys.
async fn enforce_host_trust(
    state: &Arc<AgentState>,
    common: &xenia_operator_agent_proto::SignRequestCommon,
    endpoint_label: &'static str,
) -> Result<daemon_evidence::VerifiedDaemonIdentity, (StatusCode, Json<AgentErrorResponse>)> {
    let identity =
        daemon_evidence::verify_daemon_certificate(&common.daemon_certificate).map_err(|e| {
            let agent_err = e.to_agent_error();
            (status_for(agent_err.code), Json(agent_err))
        })?;

    let host_alias = normalize_daemon_endpoint(&common.daemon_endpoint);
    let outcome =
        check_host_trust_fingerprint(state, identity.fingerprint, &host_alias, &common.suite)
            .await?;
    tracing::info!(
        request_id = %common.request_id,
        daemon_endpoint = %host_alias,
        suite = %common.suite,
        outcome = ?outcome,
        endpoint = endpoint_label,
        "host trust check passed"
    );
    Ok(identity)
}

/// Check `fingerprint` (already agent-computed -- from a verified
/// [`daemon_evidence::VerifiedDaemonIdentity`] for Track A, or from
/// completing a handshake for Track B; never one a caller simply asserts)
/// against native host-trust policy (`host_trust::HostTrustStore::check`),
/// scoped by `host_alias` (the caller's normalized `daemon_endpoint` --
/// see [`xenia_operator_agent_proto::SignRequestCommon::daemon_endpoint`]'s
/// doc comment for why this is a stable label, not the fingerprint itself).
/// Blocks on a native terminal confirmation for an unpinned or changed
/// fingerprint under that scope. `check()` blocks on terminal I/O, so this
/// runs via `spawn_blocking` rather than on an async worker thread.
///
/// Shared by [`enforce_host_trust`] (Track A) and [`handshake_finish`]
/// (Track B, which reads its own copy of `daemon_endpoint` back out of the
/// pending-handshake state `/v1/handshake/begin` stored, since `begin` is
/// where the caller supplied it and `finish` is where the fingerprint
/// becomes known).
async fn check_host_trust_fingerprint(
    state: &Arc<AgentState>,
    fingerprint: [u8; 32],
    host_alias: &str,
    suite: &str,
) -> Result<host_trust::PinOutcome, (StatusCode, Json<AgentErrorResponse>)> {
    let host_alias_owned = host_alias.to_string();
    let suite_owned = suite.to_string();
    let check_state = state.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        check_state
            .host_trust
            .lock()
            .expect("host-trust mutex poisoned")
            .check(&host_alias_owned, &suite_owned, fingerprint)
    })
    .await
    .map_err(|_| internal_error("host-trust check task panicked"))?
    .map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;

    // First-use and rotation are trust *decisions* worth a durable
    // record; `Matched` is the steady-state case and would otherwise
    // dominate the audit trail with no new information.
    let audit_event = match outcome {
        host_trust::PinOutcome::TrustedOnFirstUse => {
            Some(audit_log::AgentAuditEvent::HostTrustFirstUse {
                daemon_endpoint: host_alias.to_string(),
                suite: suite.to_string(),
                fingerprint_hex: hex::encode(fingerprint),
            })
        }
        host_trust::PinOutcome::Rotated { old_fingerprint } => {
            Some(audit_log::AgentAuditEvent::HostTrustRotation {
                daemon_endpoint: host_alias.to_string(),
                suite: suite.to_string(),
                old_fingerprint_hex: hex::encode(old_fingerprint),
                new_fingerprint_hex: hex::encode(fingerprint),
            })
        }
        host_trust::PinOutcome::Matched => None,
    };
    if let Some(event) = audit_event
        && let Err(err) = record_audit_event(state, event).await
    {
        // `check()` (above) already durably committed this pin via its
        // own transactional persist-then-adopt discipline before we
        // got here -- if we can't also durably record *why* we
        // trusted it, best-effort roll the pin back via `forget()`
        // (which uses the identical transactional discipline for
        // removal) rather than leave a permanently-trusted fingerprint
        // with zero audit record and no way to self-heal (a retry
        // would otherwise just see `PinOutcome::Matched`, which isn't
        // audit-worthy, and the gap would persist forever). For a
        // rotation specifically, the rollback removes the pin
        // entirely rather than restoring the *old* fingerprint -- a
        // retry re-presents as first-use, not the original rotation,
        // but still gets a fresh confirmation and a fresh chance to
        // record it, which is what matters here. Best-effort: if the
        // rollback itself also fails, we've already lost the durable
        // pairing between trust decision and audit record either way,
        // so surface the original audit error, not a rollback error.
        let rollback_state = state.clone();
        let host_alias_owned = host_alias.to_string();
        let suite_owned = suite.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            rollback_state
                .host_trust
                .lock()
                .expect("host-trust mutex poisoned")
                .forget(&host_alias_owned, &suite_owned)
        })
        .await;
        return Err(err);
    }

    Ok(outcome)
}

fn bad_request(message: impl Into<String>) -> (StatusCode, Json<AgentErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(AgentErrorResponse {
            code: AgentErrorCode::BadRequest,
            message: message.into(),
        }),
    )
}

fn internal_error(message: impl Into<String>) -> (StatusCode, Json<AgentErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(AgentErrorResponse {
            code: AgentErrorCode::Internal,
            message: message.into(),
        }),
    )
}

/// Durably append `event` to this agent's audit trail before the caller's
/// action is considered complete -- fails closed, matching the daemon's
/// own consent-ledger discipline (item 9: "if persistence fails, the
/// decision is refused... rather than silently applying a privileged
/// action with no durable record of who authorized it"). Runs the
/// transactional append + file write via `spawn_blocking`, matching how
/// every other blocking op in this file (`host_trust`'s `check`/
/// `confirm_action`) is already handled.
async fn record_audit_event(
    state: &Arc<AgentState>,
    event: audit_log::AgentAuditEvent,
) -> Result<(), (StatusCode, Json<AgentErrorResponse>)> {
    let event_name = event.stable_name();
    let task_state = state.clone();
    tokio::task::spawn_blocking(move || {
        let mut chain = task_state
            .audit_log
            .lock()
            .expect("audit-log mutex poisoned");
        chain
            .append_transactional(event, |entries| {
                audit_log::persist(&task_state.audit_log_path, entries)
            })
            .map(|_entry| ())
    })
    .await
    .map_err(|_| internal_error("audit log append task panicked"))?
    .map_err(|e| internal_error(format!("failed to durably record audit event: {e}")))?;
    tracing::info!(event = event_name, "audit event recorded");
    Ok(())
}

/// Maps a typed [`AgentErrorCode`] to the HTTP status the console sees.
/// The console should match on `code`, not this status, for behavior --
/// this exists only to give tooling (logs, curl, browser devtools) a
/// sane-looking status alongside the typed body.
fn status_for(code: AgentErrorCode) -> StatusCode {
    match code {
        AgentErrorCode::HostNotTrusted => StatusCode::FORBIDDEN,
        AgentErrorCode::ConfirmationRequired => StatusCode::PRECONDITION_REQUIRED,
        AgentErrorCode::ConfirmationDeclined => StatusCode::FORBIDDEN,
        AgentErrorCode::BadRequest => StatusCode::BAD_REQUEST,
        AgentErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        AgentErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
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
/// on a file this process is about to trust as key material. See
/// `secure_file` for the implementation, shared with `host_trust`'s pin
/// store.
use secure_file::load_or_create_secure_file;

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared `daemon_endpoint` for tests that don't specifically exercise
    /// scoping -- keeps `test_state_with_pinned_host`'s pre-seeded pin and
    /// the request bodies built by the `*_request_body`/`handshake_begin_body`
    /// helpers pointed at the same pin-store slot.
    const TEST_DAEMON_ENDPOINT: &str = "https://daemon.test.example";

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

    fn temp_pin_store_path(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-agent-main-test-{label}-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("pins.json")
    }

    fn test_state(token: &str, allowed_origins: &[&str]) -> Arc<AgentState> {
        test_state_with_host_trust(token, allowed_origins, true)
    }

    /// Like [`test_state`], but with control over
    /// `allow_noninteractive_privileged_confirmation` -- tests exercising
    /// `/v1/sign/challenge`'s host-trust gate need `true` (so `confirm()`
    /// resolves deterministically without a real terminal) or `false`
    /// (to exercise the fail-closed path) depending on what they check.
    fn test_state_with_host_trust(
        token: &str,
        allowed_origins: &[&str],
        allow_noninteractive_privileged: bool,
    ) -> Arc<AgentState> {
        let pin_store_path = temp_pin_store_path("state");
        Arc::new(AgentState {
            manager: HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]),
            ed25519_secret: Zeroizing::new([1u8; 32]),
            ml_dsa_seed: Zeroizing::new([2u8; 32]),
            session_mac_key: agent_session::session_mac_key(token),
            session_ttl_secs: agent_session::DEFAULT_SESSION_TTL_SECS,
            token: token.to_string(),
            allowed_origins: allowed_origins.iter().map(|s| s.to_string()).collect(),
            host_trust: StdMutex::new(
                HostTrustStore::load(pin_store_path, allow_noninteractive_privileged).unwrap(),
            ),
            handshake_state: StdMutex::new(HandshakeState::new(handshake_state::DEFAULT_TTL)),
            audit_log: StdMutex::new(audit_log::AgentAuditChain::new(
                ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            )),
            audit_log_path: temp_pin_store_path("audit"),
            started_at: std::time::Instant::now(),
        })
    }

    /// Like [`test_state_with_host_trust`], but with `host`'s fingerprint
    /// already pinned (for `suite`) before the router is even built -- so a
    /// test can exercise a *second*, action-level confirmation gate
    /// (`sign_revoke`'s) in isolation, without the host-trust step's own
    /// first-use confirmation getting in the way first. Pins the *real*
    /// fingerprint `daemon_evidence::verify_daemon_certificate` would
    /// compute for `host`, so a request presenting a genuine certificate
    /// for the same `host` passes host-trust cleanly.
    fn test_state_with_pinned_host(
        token: &str,
        allowed_origins: &[&str],
        host: &HandshakeManager,
        suite: &str,
        allow_noninteractive_privileged: bool,
    ) -> Arc<AgentState> {
        let pin_store_path = temp_pin_store_path("pinned");
        let fingerprint = xenia_handshake::host_identity_fingerprint(
            &host.identity_public_key_bytes(),
            &host.ml_dsa_public_key_bytes(),
        );
        // Scoped by the same `daemon_endpoint` the `*_request_body` helpers
        // put in their requests (normalized the same way the real handlers
        // do), not the fingerprint itself -- see `normalize_daemon_endpoint`.
        let host_alias = normalize_daemon_endpoint(TEST_DAEMON_ENDPOINT);
        {
            // Seed with a permissive store so seeding itself never needs
            // the confirmation surface a test using this helper is trying
            // to isolate.
            let mut seed = HostTrustStore::load(pin_store_path.clone(), true).unwrap();
            seed.check(&host_alias, suite, fingerprint).unwrap();
        }
        Arc::new(AgentState {
            manager: HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]),
            ed25519_secret: Zeroizing::new([1u8; 32]),
            ml_dsa_seed: Zeroizing::new([2u8; 32]),
            session_mac_key: agent_session::session_mac_key(token),
            session_ttl_secs: agent_session::DEFAULT_SESSION_TTL_SECS,
            token: token.to_string(),
            allowed_origins: allowed_origins.iter().map(|s| s.to_string()).collect(),
            host_trust: StdMutex::new(
                HostTrustStore::load(pin_store_path, allow_noninteractive_privileged).unwrap(),
            ),
            handshake_state: StdMutex::new(HandshakeState::new(handshake_state::DEFAULT_TTL)),
            audit_log: StdMutex::new(audit_log::AgentAuditChain::new(
                ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            )),
            audit_log_path: temp_pin_store_path("audit"),
            started_at: std::time::Instant::now(),
        })
    }

    // ─── daemon-evidence test fixtures ──────────────────────────────────
    //
    // Every `/v1/sign/*` request now carries verifiable daemon-signed
    // evidence rather than a bare caller-asserted fingerprint (PR "4.5b"),
    // so tests build a real (host identity, HTTP-auth key) pair and sign
    // real certificates/attestations/tokens with them -- exactly what a
    // genuine daemon does, per `apps/xenia-peer`'s own equivalent test
    // fixtures in `operator_http.rs`.

    use ed25519_dalek::{Signer, SigningKey};
    use xenia_handshake::MlDsaIdentity;
    use xenia_operator_agent_proto::{DaemonIdentityCertificate, SignedTokenDto};

    /// A daemon's host identity + its separate HTTP-auth signing identity
    /// (both algorithms).
    fn test_daemon_identity() -> (HandshakeManager, SigningKey, MlDsaIdentity) {
        (
            HandshakeManager::new(),
            SigningKey::generate(&mut rand::thread_rng()),
            MlDsaIdentity::from_seed(rand::random()),
        )
    }

    fn test_certificate(
        host: &HandshakeManager,
        http_auth: &SigningKey,
        http_auth_ml_dsa: &MlDsaIdentity,
    ) -> DaemonIdentityCertificate {
        let http_auth_pk = http_auth.verifying_key().to_bytes();
        let http_auth_ml_dsa_pk = http_auth_ml_dsa.public_key_bytes();
        let transcript =
            xenia_operator_proto::daemon_delegation_transcript(&http_auth_pk, &http_auth_ml_dsa_pk);
        DaemonIdentityCertificate {
            host_ed25519_pubkey: hex::encode(host.identity_public_key_bytes()),
            host_ml_dsa_pubkey: hex::encode(host.ml_dsa_public_key_bytes()),
            http_auth_ed25519_pubkey: hex::encode(http_auth_pk),
            http_auth_ml_dsa_pubkey: hex::encode(http_auth_ml_dsa_pk),
            host_ed_signature: hex::encode(host.sign(&transcript).to_bytes()),
            host_ml_dsa_signature: hex::encode(host.sign_ml_dsa(&transcript)),
        }
    }

    fn test_token(
        http_auth: &SigningKey,
        http_auth_ml_dsa: &MlDsaIdentity,
        token_nonce: [u8; 16],
    ) -> SignedTokenDto {
        let canonical = xenia_operator_proto::operator_token_canonical_bytes(
            "alice",
            OperatorRole::Admin,
            1000,
            2000,
            &token_nonce,
        );
        SignedTokenDto {
            operator_id: "alice".to_string(),
            role: OperatorRole::Admin,
            issued_at: 1000,
            expires_at: 2000,
            token_nonce_hex: hex::encode(token_nonce),
            signature_hex: hex::encode(http_auth.sign(&canonical).to_bytes()),
            ml_dsa_signature_hex: hex::encode(http_auth_ml_dsa.sign(&canonical)),
        }
    }

    fn merge_overrides(body: &mut serde_json::Value, overrides: serde_json::Value) {
        if let (Some(body_map), Some(override_map)) = (body.as_object_mut(), overrides.as_object())
        {
            for (k, v) in override_map {
                body_map.insert(k.clone(), v.clone());
            }
        }
    }

    // ─── pairing-token tests (`POST /v1/pair`) ──────────────────────────
    //
    // `/v1/pair` is the one route the raw pairing token still authenticates
    // (see `agent_session`'s module doc comment) -- these mirror the old
    // "every route needs the pairing token" tests, just retargeted at the
    // one route that still works that way.

    #[tokio::test]
    async fn missing_origin_is_refused_even_with_a_valid_pairing_token() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/pair")
            .header("x-agent-token", "secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn wrong_origin_is_refused_on_pair() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/pair")
            .header("origin", "http://evil.example")
            .header("x-agent-token", "secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn right_origin_but_wrong_pairing_token_is_refused() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/pair")
            .header("origin", "http://localhost:8134")
            .header("x-agent-token", "not-the-secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn right_origin_and_pairing_token_mints_a_session() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/pair")
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let session: AgentSessionToken = serde_json::from_slice(&bytes).unwrap();
        assert!(session.expires_at > session.issued_at);
    }

    #[tokio::test]
    async fn the_raw_pairing_token_does_not_authenticate_any_other_route() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("origin", "http://localhost:8134")
            .header("x-agent-token", "secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the raw pairing token must not double as a session credential"
        );
    }

    // ─── session tests (`X-Agent-Session`, everything but `/v1/pair`) ───

    /// Pairs against `app` and returns the resulting session's compact
    /// `X-Agent-Session` header value. The one place `"secret"` (the
    /// pairing token every `test_state*` helper seeds) is actually used as
    /// a bearer credential in most tests -- everything else in this module
    /// goes through a minted session instead, matching production.
    async fn pair(app: Router, pairing_token: &str) -> String {
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/pair")
            .header("origin", "http://localhost:8134")
            .header("x-agent-token", pairing_token)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "test fixture pairing failed");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let session: AgentSessionToken = serde_json::from_slice(&bytes).unwrap();
        session.to_header_value()
    }

    #[tokio::test]
    async fn identity_refuses_a_missing_session() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("origin", "http://localhost:8134")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_requires_neither_origin_nor_session() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        // Deliberately no `origin` and no `x-agent-session` header -- the
        // whole point of `/v1/health` sitting outside
        // `auth_and_cors_middleware` is that a liveness probe shouldn't
        // need either.
        let req = axum::http::Request::builder()
            .uri("/v1/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["active"], true);
        assert!(parsed["fingerprint_hex"].is_string());
        assert!(parsed["uptime_secs"].is_u64());
    }

    #[tokio::test]
    async fn identity_refuses_a_session_minted_under_a_different_pairing_token() {
        use tower::ServiceExt;
        // Mint a session against one agent's pairing token, then present it
        // to a *different* agent instance (different token -> different
        // session-MAC key) -- simulating a stale session surviving a
        // pairing-token rotation.
        let minted_elsewhere = pair(
            build_router(test_state("other-secret", &["http://localhost:8134"])),
            "other-secret",
        )
        .await;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("origin", "http://localhost:8134")
            .header("x-agent-session", minted_elsewhere)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn identity_succeeds_with_a_freshly_paired_session() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let session = pair(app.clone(), "secret").await;
        let req = axum::http::Request::builder()
            .uri("/identity")
            .header("origin", "http://localhost:8134")
            .header("x-agent-session", session)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn session_refresh_mints_a_new_session_from_a_valid_one() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let session = pair(app.clone(), "secret").await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/session/refresh")
            .header("origin", "http://localhost:8134")
            .header("x-agent-session", &session)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let refreshed: AgentSessionToken = serde_json::from_slice(&bytes).unwrap();
        assert_ne!(
            refreshed.to_header_value(),
            session,
            "a refresh must mint a genuinely new session, not echo the old one"
        );
    }

    #[tokio::test]
    async fn session_refresh_refuses_the_raw_pairing_token() {
        use tower::ServiceExt;
        let app = build_router(test_state("secret", &["http://localhost:8134"]));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/session/refresh")
            .header("origin", "http://localhost:8134")
            .header("x-agent-session", "secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the raw pairing token is not a well-formed session and must not refresh one"
        );
    }

    async fn post_signed_json(
        app: Router,
        path: &str,
        pairing_token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let session = pair(app.clone(), pairing_token).await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("origin", "http://localhost:8134")
            .header("x-agent-session", session)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn post_sign_challenge(
        app: Router,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_signed_json(app, "/v1/sign/challenge", token, body).await
    }

    /// Builds a valid `/v1/sign/challenge` body signed by `host`'s
    /// identity (both the certificate delegation and the nonce
    /// attestation), then applies `overrides` on top -- so a test that
    /// only cares about one bad field doesn't have to hand-build the rest.
    fn challenge_request_body(
        cert: &DaemonIdentityCertificate,
        host: &HandshakeManager,
        nonce: [u8; 32],
        overrides: serde_json::Value,
    ) -> serde_json::Value {
        let attestation_transcript =
            xenia_operator_proto::challenge_host_attestation_transcript(&nonce);
        let mut body = serde_json::json!({
            "schema_version": xenia_operator_agent_proto::SCHEMA_VERSION,
            "daemon_certificate": cert,
            "daemon_endpoint": TEST_DAEMON_ENDPOINT,
            "suite": "standard",
            "request_id": "test-req-1",
            "nonce_hex": hex::encode(nonce),
            "host_ed_attestation_hex": hex::encode(host.sign(&attestation_transcript).to_bytes()),
            "host_ml_dsa_attestation_hex": hex::encode(host.sign_ml_dsa(&attestation_transcript)),
        });
        merge_overrides(&mut body, overrides);
        body
    }

    #[tokio::test]
    async fn sign_challenge_trusts_a_new_daemon_on_first_use_and_returns_valid_signatures() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let nonce = [0xbbu8; 32];
        let body = challenge_request_body(&cert, &host, nonce, serde_json::json!({}));
        let (status, json) = post_sign_challenge(app, "secret", body).await;
        assert_eq!(status, StatusCode::OK, "body: {json}");

        let resp: SignChallengeResponse = serde_json::from_value(json).unwrap();
        let expected_manager = HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]);
        assert_eq!(
            resp.ed25519_pubkey_hex,
            hex::encode(expected_manager.identity_public_key_bytes())
        );
        assert_eq!(
            resp.ml_dsa_pubkey_hex,
            hex::encode(expected_manager.ml_dsa_public_key_bytes())
        );

        // The signature must actually verify over the canonical transcript
        // the agent is supposed to have built itself -- not just be present.
        let ed_pubkey = expected_manager.identity_public_key_bytes();
        let ml_dsa_pubkey = expected_manager.ml_dsa_public_key_bytes();
        let transcript =
            xenia_operator_proto::challenge_transcript(&nonce, &ed_pubkey, &ml_dsa_pubkey);
        let ed_sig_bytes: [u8; 64] = decode_fixed_hex(&resp.ed_signature_hex).unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        HandshakeManager::verify(
            &expected_manager.identity_public_key(),
            &transcript,
            &ed_sig,
        )
        .expect("agent's Ed25519 signature must verify over the challenge transcript");
    }

    /// The behavioral proof this whole PR is about: pinning by
    /// `daemon_endpoint` (not the bare fingerprint) means a *different*
    /// daemon identity presenting itself at the *same* `daemon_endpoint`
    /// is recognized as "this known daemon changed identity"
    /// (`FingerprintChanged`), not silently treated as a brand-new,
    /// unrelated host the way fingerprint-as-alias pinning did (two
    /// different fingerprints always produced two different pin-store
    /// keys, so `FingerprintChanged` was effectively unreachable through
    /// the real endpoints).
    #[tokio::test]
    async fn sign_challenge_detects_a_rotated_fingerprint_at_the_same_daemon_endpoint() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state.clone());

        let (host_a, http_auth_a, http_auth_a_ml_dsa) = test_daemon_identity();
        let cert_a = test_certificate(&host_a, &http_auth_a, &http_auth_a_ml_dsa);
        let body_a = challenge_request_body(&cert_a, &host_a, [0x01u8; 32], serde_json::json!({}));
        let (status_a, json_a) = post_sign_challenge(app.clone(), "secret", body_a).await;
        assert_eq!(status_a, StatusCode::OK, "body: {json_a}");

        // A second, unrelated daemon identity -- different Ed25519/ML-DSA
        // keys entirely -- claiming the exact same `daemon_endpoint`.
        let (host_b, http_auth_b, http_auth_b_ml_dsa) = test_daemon_identity();
        let cert_b = test_certificate(&host_b, &http_auth_b, &http_auth_b_ml_dsa);
        let body_b = challenge_request_body(&cert_b, &host_b, [0x02u8; 32], serde_json::json!({}));
        let (status_b, json_b) = post_sign_challenge(app, "secret", body_b).await;
        assert_eq!(status_b, StatusCode::OK, "body: {json_b}");

        // Both requests used `test_state`'s permissive
        // (`allow_noninteractive_privileged: true`) store, so both a
        // first-use *and* a rotation auto-confirm and return 200 -- the
        // HTTP status alone can't distinguish the two. What proves the fix
        // is inspecting the agent's *own* pin store afterward: it must now
        // hold host B's fingerprint (the later one) under the shared
        // `daemon_endpoint` scope. Under the old fingerprint-as-alias
        // scheme, host A and host B would have pinned under two entirely
        // separate keys (`hex::encode(fp_a)` vs `hex::encode(fp_b)`), and
        // the store would hold *both*, with no rotation ever having
        // happened -- exactly the bug this PR closes.
        let fp_b = xenia_handshake::host_identity_fingerprint(
            &host_b.identity_public_key_bytes(),
            &host_b.ml_dsa_public_key_bytes(),
        );
        let fp_a = xenia_handshake::host_identity_fingerprint(
            &host_a.identity_public_key_bytes(),
            &host_a.ml_dsa_public_key_bytes(),
        );
        assert_ne!(fp_a, fp_b, "test fixture bug: hosts must differ");
        let host_alias = normalize_daemon_endpoint(TEST_DAEMON_ENDPOINT);
        let trust = state.host_trust.lock().expect("host-trust mutex poisoned");
        assert_eq!(
            trust.lookup(&host_alias, "standard"),
            Some(fp_b),
            "the shared daemon_endpoint scope must hold the rotated (latest) fingerprint"
        );
    }

    #[tokio::test]
    async fn sign_challenge_rejects_an_unsupported_schema_version() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let body = challenge_request_body(
            &cert,
            &host,
            [0xbbu8; 32],
            serde_json::json!({ "schema_version": 999 }),
        );
        let (status, json) = post_sign_challenge(app, "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_challenge_rejects_an_unrecognized_suite() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let body = challenge_request_body(
            &cert,
            &host,
            [0xbbu8; 32],
            serde_json::json!({ "suite": "quantum" }),
        );
        let (status, json) = post_sign_challenge(app, "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_challenge_rejects_malformed_hex_fields() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let body = challenge_request_body(
            &cert,
            &host,
            [0xbbu8; 32],
            serde_json::json!({ "nonce_hex": "not-hex" }),
        );
        let (status, json) = post_sign_challenge(app, "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_challenge_fails_closed_when_a_new_host_needs_confirmation_and_none_is_available()
    {
        let state = test_state_with_host_trust("secret", &["http://localhost:8134"], false);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let body = challenge_request_body(&cert, &host, [0xbbu8; 32], serde_json::json!({}));
        let (status, json) = post_sign_challenge(app, "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_challenge_rejects_a_certificate_whose_delegation_signature_does_not_verify() {
        // The certificate claims to delegate to a different HTTP-auth key
        // than the one the signature was actually computed over -- the
        // exact confused-deputy shape "4.5b" closes: a compromised browser
        // can no longer get the agent to trust a fabricated certificate.
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let mut cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let (_other_host, other_http_auth, _other_http_auth_ml_dsa) = test_daemon_identity();
        cert.http_auth_ed25519_pubkey = hex::encode(other_http_auth.verifying_key().to_bytes());
        let body = challenge_request_body(&cert, &host, [0xbbu8; 32], serde_json::json!({}));
        let (status, json) = post_sign_challenge(app, "secret", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {json}");
        assert_eq!(json["code"], "host_not_trusted");
    }

    #[tokio::test]
    async fn sign_challenge_rejects_a_host_attestation_for_a_different_nonce() {
        // A compromised browser relays an attestation for one nonce while
        // asking the agent to sign a different one -- must be refused even
        // though the certificate itself is genuine and already trusted.
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let attested_nonce = [0xbbu8; 32];
        let mut body = challenge_request_body(&cert, &host, attested_nonce, serde_json::json!({}));
        // Ask the agent to sign a *different* nonce than the one the
        // attestation actually covers.
        body["nonce_hex"] = serde_json::json!(hex::encode([0xccu8; 32]));
        let (status, json) = post_sign_challenge(app, "secret", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {json}");
        assert_eq!(json["code"], "host_not_trusted");
    }

    #[tokio::test]
    async fn sign_challenge_requires_origin_and_token_like_every_other_route() {
        use tower::ServiceExt;
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let body = challenge_request_body(&cert, &host, [0xbbu8; 32], serde_json::json!({}));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/sign/challenge")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Builds a valid `/v1/sign/consent-action` body carrying `cert` and
    /// `token`, then applies `overrides` on top.
    fn consent_action_request_body(
        cert: &DaemonIdentityCertificate,
        token: &SignedTokenDto,
        overrides: serde_json::Value,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "schema_version": xenia_operator_agent_proto::SCHEMA_VERSION,
            "daemon_certificate": cert,
            "daemon_endpoint": TEST_DAEMON_ENDPOINT,
            "suite": "highsec",
            "request_id": "test-req-2",
            "action": "Approve",
            "session_id_hex": "dd".repeat(16),
            "token": token,
        });
        merge_overrides(&mut body, overrides);
        body
    }

    #[tokio::test]
    async fn sign_consent_action_trusts_a_new_daemon_on_first_use_and_returns_a_valid_signature() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token_nonce = [0xeeu8; 16];
        let token = test_token(&http_auth, &http_auth_ml_dsa, token_nonce);
        let body = consent_action_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/consent-action", "secret", body).await;
        assert_eq!(status, StatusCode::OK, "body: {json}");

        let resp: SignConsentActionResponse = serde_json::from_value(json).unwrap();
        let expected_manager = HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]);
        let session_id: [u8; 16] = decode_fixed_hex(&"dd".repeat(16)).unwrap();
        let transcript = xenia_operator_proto::consent_action_transcript(
            xenia_operator_proto::ConsentAction::Approve,
            &session_id,
            &token_nonce,
        );
        let ed_sig_bytes: [u8; 64] = decode_fixed_hex(&resp.ed_signature_hex).unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        HandshakeManager::verify(
            &expected_manager.identity_public_key(),
            &transcript,
            &ed_sig,
        )
        .expect("agent's Ed25519 signature must verify over the consent-action transcript");
    }

    #[tokio::test]
    async fn sign_consent_action_binds_the_signature_to_the_exact_action() {
        // A signature for Deny must not verify against an Approve transcript
        // -- the whole point of consent_action_transcript embedding the
        // action tag.
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token_nonce = [0xeeu8; 16];
        let token = test_token(&http_auth, &http_auth_ml_dsa, token_nonce);
        let body =
            consent_action_request_body(&cert, &token, serde_json::json!({ "action": "Deny" }));
        let (status, json) = post_signed_json(app, "/v1/sign/consent-action", "secret", body).await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        let resp: SignConsentActionResponse = serde_json::from_value(json).unwrap();

        let expected_manager = HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]);
        let session_id: [u8; 16] = decode_fixed_hex(&"dd".repeat(16)).unwrap();
        let wrong_transcript = xenia_operator_proto::consent_action_transcript(
            xenia_operator_proto::ConsentAction::Approve,
            &session_id,
            &token_nonce,
        );
        let ed_sig_bytes: [u8; 64] = decode_fixed_hex(&resp.ed_signature_hex).unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        assert!(HandshakeManager::verify(
            &expected_manager.identity_public_key(),
            &wrong_transcript,
            &ed_sig,
        )
        .is_err());
    }

    #[tokio::test]
    async fn sign_consent_action_rejects_an_unsupported_schema_version() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0xeeu8; 16]);
        let body = consent_action_request_body(
            &cert,
            &token,
            serde_json::json!({ "schema_version": 999 }),
        );
        let (status, json) = post_signed_json(app, "/v1/sign/consent-action", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_consent_action_rejects_malformed_hex_fields() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0xeeu8; 16]);
        let body = consent_action_request_body(
            &cert,
            &token,
            serde_json::json!({ "session_id_hex": "nope" }),
        );
        let (status, json) = post_signed_json(app, "/v1/sign/consent-action", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_consent_action_rejects_an_unrecognized_action() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0xeeu8; 16]);
        let body = consent_action_request_body(
            &cert,
            &token,
            serde_json::json!({ "action": "Frobnicate" }),
        );
        let (status, _json) =
            post_signed_json(app, "/v1/sign/consent-action", "secret", body).await;
        // `ConsentAction` derives `Deserialize` over its exact variant
        // names -- an unrecognized action fails the `Json<T>` extractor
        // itself before the handler runs, so this is axum's own rejection
        // status rather than the typed `AgentErrorResponse` shape.
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn sign_consent_action_fails_closed_when_a_new_host_needs_confirmation_and_none_is_available(
    ) {
        let state = test_state_with_host_trust("secret", &["http://localhost:8134"], false);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0xeeu8; 16]);
        let body = consent_action_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/consent-action", "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_consent_action_rejects_a_token_signed_by_the_wrong_key() {
        // The relayed token's signature doesn't verify against the
        // certificate's delegated HTTP-auth key -- e.g. a compromised
        // browser inventing its own token_nonce, the same confused-deputy
        // shape "4.5b" closes for tokens.
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let (_other_host, attacker_http_auth, attacker_http_auth_ml_dsa) = test_daemon_identity();
        let token = test_token(
            &attacker_http_auth,
            &attacker_http_auth_ml_dsa,
            [0xeeu8; 16],
        );
        let body = consent_action_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/consent-action", "secret", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {json}");
        assert_eq!(json["code"], "host_not_trusted");
    }

    /// Builds a valid `/v1/sign/revoke` body carrying `cert` and `token`,
    /// then applies `overrides` on top.
    fn revoke_request_body(
        cert: &DaemonIdentityCertificate,
        token: &SignedTokenDto,
        overrides: serde_json::Value,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "schema_version": xenia_operator_agent_proto::SCHEMA_VERSION,
            "daemon_certificate": cert,
            "daemon_endpoint": TEST_DAEMON_ENDPOINT,
            "suite": "standard",
            "request_id": "test-req-3",
            "target_operator_id": "op-42",
            "token": token,
        });
        merge_overrides(&mut body, overrides);
        body
    }

    #[tokio::test]
    async fn sign_revoke_signs_with_confirmation_when_allowed() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token_nonce = [0x11u8; 16];
        let token = test_token(&http_auth, &http_auth_ml_dsa, token_nonce);
        let body = revoke_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::OK, "body: {json}");

        let resp: SignRevokeResponse = serde_json::from_value(json).unwrap();
        let expected_manager = HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]);
        let transcript = xenia_operator_proto::revoke_operator_transcript("op-42", &token_nonce);
        let ed_sig_bytes: [u8; 64] = decode_fixed_hex(&resp.ed_signature_hex).unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        HandshakeManager::verify(
            &expected_manager.identity_public_key(),
            &transcript,
            &ed_sig,
        )
        .expect("agent's Ed25519 signature must verify over the revoke transcript");
    }

    #[tokio::test]
    async fn sign_revoke_requires_its_own_confirmation_even_when_the_host_is_already_pinned() {
        // The host-trust step alone would pass here (the fingerprint is
        // already pinned) -- this proves sign_revoke's mandatory
        // *action*-level confirmation is a genuinely separate gate, not
        // just a side effect of host-trust's own first-use check.
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let state = test_state_with_pinned_host(
            "secret",
            &["http://localhost:8134"],
            &host,
            "standard",
            false,
        );
        let app = build_router(state);
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x11u8; 16]);
        let body = revoke_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_revoke_fails_closed_when_the_host_itself_needs_confirmation_and_none_is_available(
    ) {
        let state = test_state_with_host_trust("secret", &["http://localhost:8134"], false);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x11u8; 16]);
        let body = revoke_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_revoke_rejects_an_empty_target_operator_id() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x11u8; 16]);
        let body = revoke_request_body(
            &cert,
            &token,
            serde_json::json!({ "target_operator_id": "" }),
        );
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_revoke_rejects_malformed_hex_fields() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let mut token =
            serde_json::to_value(test_token(&http_auth, &http_auth_ml_dsa, [0x11u8; 16])).unwrap();
        token["token_nonce_hex"] = serde_json::json!("nope");
        let body = serde_json::json!({
            "schema_version": xenia_operator_agent_proto::SCHEMA_VERSION,
            "daemon_certificate": cert,
            "daemon_endpoint": TEST_DAEMON_ENDPOINT,
            "suite": "standard",
            "request_id": "test-req-3",
            "target_operator_id": "op-42",
            "token": token,
        });
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_revoke_rejects_an_unsupported_schema_version() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x11u8; 16]);
        let body = revoke_request_body(&cert, &token, serde_json::json!({ "schema_version": 999 }));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_revoke_rejects_a_token_signed_by_the_wrong_key() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let (_other_host, attacker_http_auth, attacker_http_auth_ml_dsa) = test_daemon_identity();
        let token = test_token(
            &attacker_http_auth,
            &attacker_http_auth_ml_dsa,
            [0x11u8; 16],
        );
        let body = revoke_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {json}");
        assert_eq!(json["code"], "host_not_trusted");
    }

    #[tokio::test]
    async fn sign_revoke_requires_origin_and_token_like_every_other_route() {
        use tower::ServiceExt;
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x11u8; 16]);
        let body = revoke_request_body(&cert, &token, serde_json::json!({}));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/sign/revoke")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Builds a valid `/v1/sign/replace-key` body carrying `cert` and
    /// `token`, then applies `overrides` on top. Mirrors
    /// [`revoke_request_body`].
    fn replace_key_request_body(
        cert: &DaemonIdentityCertificate,
        token: &SignedTokenDto,
        overrides: serde_json::Value,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "schema_version": xenia_operator_agent_proto::SCHEMA_VERSION,
            "daemon_certificate": cert,
            "daemon_endpoint": TEST_DAEMON_ENDPOINT,
            "suite": "standard",
            "request_id": "test-req-4",
            "target_operator_id": "op-42",
            "new_ed25519_pubkey_hex": "11".repeat(32),
            "new_ml_dsa_pubkey_hex": "22".repeat(ML_DSA_65_PK_LEN),
            "new_ml_dsa_87_pubkey_hex": null,
            "token": token,
        });
        merge_overrides(&mut body, overrides);
        body
    }

    #[tokio::test]
    async fn sign_replace_key_signs_with_confirmation_when_allowed() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token_nonce = [0x22u8; 16];
        let token = test_token(&http_auth, &http_auth_ml_dsa, token_nonce);
        let body = replace_key_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::OK, "body: {json}");

        let resp: SignReplaceKeyResponse = serde_json::from_value(json).unwrap();
        let expected_manager = HandshakeManager::from_identity_seeds([1u8; 32], [2u8; 32]);
        let new_ed: [u8; 32] = decode_fixed_hex(&"11".repeat(32)).unwrap();
        let new_ml: Vec<u8> = hex::decode("22".repeat(ML_DSA_65_PK_LEN)).unwrap();
        let transcript = xenia_operator_proto::replace_operator_key_transcript(
            "op-42",
            &new_ed,
            &new_ml,
            None,
            &token_nonce,
        );
        let ed_sig_bytes: [u8; 64] = decode_fixed_hex(&resp.ed_signature_hex).unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        HandshakeManager::verify(
            &expected_manager.identity_public_key(),
            &transcript,
            &ed_sig,
        )
        .expect("agent's Ed25519 signature must verify over the key-replacement transcript");
    }

    #[tokio::test]
    async fn sign_replace_key_requires_its_own_confirmation_even_when_the_host_is_already_pinned() {
        // Mirrors sign_revoke's equivalent test: the host-trust step alone
        // would pass here (the fingerprint is already pinned) -- this
        // proves the mandatory *action*-level confirmation
        // (SIGNER_DELEGATION_DESIGN.md's "recovery-key or trust-root
        // changes") is a genuinely separate gate.
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let state = test_state_with_pinned_host(
            "secret",
            &["http://localhost:8134"],
            &host,
            "standard",
            false,
        );
        let app = build_router(state);
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body = replace_key_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_replace_key_fails_closed_when_the_host_itself_needs_confirmation_and_none_is_available(
    ) {
        let state = test_state_with_host_trust("secret", &["http://localhost:8134"], false);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body = replace_key_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_replace_key_rejects_an_empty_target_operator_id() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body = replace_key_request_body(
            &cert,
            &token,
            serde_json::json!({ "target_operator_id": "" }),
        );
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_replace_key_rejects_malformed_new_ed25519_pubkey_hex() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body = replace_key_request_body(
            &cert,
            &token,
            serde_json::json!({ "new_ed25519_pubkey_hex": "nope" }),
        );
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_replace_key_rejects_a_wrong_length_new_ml_dsa_pubkey_hex() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body = replace_key_request_body(
            &cert,
            &token,
            serde_json::json!({ "new_ml_dsa_pubkey_hex": "ab" }),
        );
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_replace_key_rejects_a_wrong_length_new_ml_dsa_87_pubkey_hex() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body = replace_key_request_body(
            &cert,
            &token,
            serde_json::json!({ "new_ml_dsa_87_pubkey_hex": "ab" }),
        );
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_replace_key_rejects_an_unsupported_schema_version() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body =
            replace_key_request_body(&cert, &token, serde_json::json!({ "schema_version": 999 }));
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_replace_key_rejects_a_token_signed_by_the_wrong_key() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let (_other_host, attacker_http_auth, attacker_http_auth_ml_dsa) = test_daemon_identity();
        let token = test_token(
            &attacker_http_auth,
            &attacker_http_auth_ml_dsa,
            [0x22u8; 16],
        );
        let body = replace_key_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/replace-key", "secret", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {json}");
        assert_eq!(json["code"], "host_not_trusted");
    }

    #[tokio::test]
    async fn sign_replace_key_requires_origin_and_token_like_every_other_route() {
        use tower::ServiceExt;
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth, http_auth_ml_dsa) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth, &http_auth_ml_dsa);
        let token = test_token(&http_auth, &http_auth_ml_dsa, [0x22u8; 16]);
        let body = replace_key_request_body(&cert, &token, serde_json::json!({}));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/sign/replace-key")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ─── Track B: /v1/handshake/* ───────────────────────────────────────

    fn handshake_begin_body(suite: &str, hello: &[u8]) -> serde_json::Value {
        serde_json::to_value(HandshakeBeginRequest {
            common: xenia_operator_agent_proto::HandshakeRequestCommon {
                schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
                daemon_endpoint: TEST_DAEMON_ENDPOINT.to_string(),
                suite: suite.to_string(),
                request_id: "test-hs".to_string(),
            },
            host_hello_hex: hex::encode(hello),
        })
        .unwrap()
    }

    fn handshake_finish_body(handshake_id_hex: &str, finalize: &[u8]) -> serde_json::Value {
        serde_json::to_value(HandshakeFinishRequest {
            schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
            handshake_id_hex: handshake_id_hex.to_string(),
            host_finalize_hex: hex::encode(finalize),
        })
        .unwrap()
    }

    /// Genuine end-to-end round trip for the standard suite, against a
    /// *real* host counterpart (`xenia_peer_core::handshake::
    /// perform_host_handshake_authenticating_peer`, the exact function the
    /// real daemon calls) over a real loopback TCP socket -- proving the
    /// agent's viewer handling is genuinely wire-compatible, not just
    /// internally self-consistent.
    #[tokio::test]
    async fn handshake_round_trip_standard_suite_against_a_real_host() {
        use xenia_peer_core::handshake::perform_host_handshake_authenticating_peer;
        use xenia_peer_core::transport::{TcpTransport, Transport};

        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut transport = TcpTransport::new(stream);
            let mut host_mgr = HandshakeManager::new();
            perform_host_handshake_authenticating_peer(
                &mut transport,
                &mut host_mgr,
                "operator",
                None,
            )
            .await
            .unwrap()
        });
        let client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client_transport = TcpTransport::new(client_stream);

        // 1. Host's HostHello -> POST /v1/handshake/begin.
        let hello = client_transport.recv_envelope().await.unwrap();
        let (status, json) = post_signed_json(
            app.clone(),
            "/v1/handshake/begin",
            "secret",
            handshake_begin_body("standard", &hello),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        let begin_resp: HandshakeBeginResponse = serde_json::from_value(json).unwrap();

        // 2. Relay the viewer response to the host.
        let viewer_response = decode_hex_vec(&begin_resp.viewer_response_hex).unwrap();
        client_transport
            .send_envelope(&viewer_response)
            .await
            .unwrap();

        // 3. Host's HostFinalize -> POST /v1/handshake/finish.
        let finalize = client_transport.recv_envelope().await.unwrap();
        let (status, json) = post_signed_json(
            app,
            "/v1/handshake/finish",
            "secret",
            handshake_finish_body(&begin_resp.handshake_id_hex, &finalize),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        let finish_resp: HandshakeFinishResponse = serde_json::from_value(json).unwrap();

        let (outcome, _peer) = host_task.await.unwrap();
        // The agent's derived session material matches what the real host
        // independently derived -- not just "no error," genuine agreement.
        assert_eq!(
            finish_resp.aead_key_hex,
            hex::encode(outcome.key_schedule.aead)
        );
        assert_eq!(
            finish_resp.authenticated_host_fingerprint_hex,
            hex::encode(outcome.host_identity_fingerprint)
        );
        assert_eq!(
            finish_resp.transcript_hash_hex,
            hex::encode(outcome.transcript_hash)
        );
    }

    /// Same shape as the standard-suite round trip, but for the
    /// high-security suite -- `HostHandshakeHighSec` is plain byte-in/
    /// byte-out (no `Transport`/socket needed), so this test drives it
    /// directly.
    #[tokio::test]
    async fn handshake_round_trip_highsec_suite_against_a_real_host() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);

        let mut host = xenia_wire::handshake_highsec::HostHandshakeHighSec::new();
        let hello = host.hello(None);

        let (status, json) = post_signed_json(
            app.clone(),
            "/v1/handshake/begin",
            "secret",
            handshake_begin_body("highsec", &hello),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        let begin_resp: HandshakeBeginResponse = serde_json::from_value(json).unwrap();

        let viewer_response = decode_hex_vec(&begin_resp.viewer_response_hex).unwrap();
        let (finalize, schedule, _peer) = host.finish(&viewer_response).unwrap();

        let (status, json) = post_signed_json(
            app,
            "/v1/handshake/finish",
            "secret",
            handshake_finish_body(&begin_resp.handshake_id_hex, &finalize),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        let finish_resp: HandshakeFinishResponse = serde_json::from_value(json).unwrap();

        assert_eq!(finish_resp.aead_key_hex, hex::encode(schedule.aead));
        assert_eq!(
            finish_resp.authenticated_host_fingerprint_hex,
            hex::encode(schedule.host_identity_fingerprint)
        );
        assert_eq!(
            finish_resp.transcript_hash_hex,
            hex::encode(schedule.transcript_hash)
        );
    }

    #[tokio::test]
    async fn handshake_begin_rejects_an_unrecognized_suite() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (status, json) = post_signed_json(
            app,
            "/v1/handshake/begin",
            "secret",
            handshake_begin_body("quantum", b"whatever"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn handshake_begin_rejects_a_malformed_host_hello() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (status, json) = post_signed_json(
            app,
            "/v1/handshake/begin",
            "secret",
            handshake_begin_body("standard", b"not a real host hello"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn handshake_finish_rejects_an_unknown_handshake_id() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (status, json) = post_signed_json(
            app,
            "/v1/handshake/finish",
            "secret",
            handshake_finish_body(&"aa".repeat(16), b"whatever"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn handshake_finish_rejects_a_forged_host_finalize_and_still_consumes_the_id() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);

        let mut host = xenia_wire::handshake_highsec::HostHandshakeHighSec::new();
        let hello = host.hello(None);
        let (status, json) = post_signed_json(
            app.clone(),
            "/v1/handshake/begin",
            "secret",
            handshake_begin_body("highsec", &hello),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        let begin_resp: HandshakeBeginResponse = serde_json::from_value(json).unwrap();

        // Forged/garbage HostFinalize instead of the real one.
        let (status, json) = post_signed_json(
            app.clone(),
            "/v1/handshake/finish",
            "secret",
            handshake_finish_body(&begin_resp.handshake_id_hex, b"forged finalize bytes"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");

        // The id is burned -- a second attempt (even with a well-formed
        // finalize, hypothetically) gets "unknown handshake" now, not
        // another crypto-failure message.
        let (status, json) = post_signed_json(
            app,
            "/v1/handshake/finish",
            "secret",
            handshake_finish_body(&begin_resp.handshake_id_hex, b"forged finalize bytes"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn handshake_finish_fails_closed_when_the_new_host_needs_confirmation_and_none_is_available(
    ) {
        let state = test_state_with_host_trust("secret", &["http://localhost:8134"], false);
        let app = build_router(state);

        let mut host = xenia_wire::handshake_highsec::HostHandshakeHighSec::new();
        let hello = host.hello(None);
        let (status, json) = post_signed_json(
            app.clone(),
            "/v1/handshake/begin",
            "secret",
            handshake_begin_body("highsec", &hello),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        let begin_resp: HandshakeBeginResponse = serde_json::from_value(json).unwrap();

        let viewer_response = decode_hex_vec(&begin_resp.viewer_response_hex).unwrap();
        let (finalize, _schedule, _peer) = host.finish(&viewer_response).unwrap();

        let (status, json) = post_signed_json(
            app,
            "/v1/handshake/finish",
            "secret",
            handshake_finish_body(&begin_resp.handshake_id_hex, &finalize),
        )
        .await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn handshake_begin_requires_origin_and_token_like_every_other_route() {
        use tower::ServiceExt;
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/handshake/begin")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                handshake_begin_body("standard", b"whatever").to_string(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
