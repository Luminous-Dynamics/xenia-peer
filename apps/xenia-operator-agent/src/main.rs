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

// `host_trust` (native host-fingerprint trust policy), step 1 of
// SIGNER_DELEGATION_DESIGN.md's recommended PR sequence, is wired in
// (step 2: `POST /v1/sign/challenge`; step 3: `POST /v1/sign/consent-action`;
// step 4: `POST /v1/sign/revoke`). `daemon_evidence` (PR "4.5b") replaces
// the caller-supplied `daemon_fingerprint_hex` those steps originally used
// with daemon-signed evidence the agent verifies itself -- see that
// module's doc comment for the confused-deputy gap this closes.
mod daemon_evidence;
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
use xenia_handshake::HandshakeManager;
use xenia_operator_agent_proto::{
    AgentErrorCode, AgentErrorResponse, SignChallengeRequest, SignChallengeResponse,
    SignConsentActionRequest, SignConsentActionResponse, SignRevokeRequest, SignRevokeResponse,
};
use xenia_operator_proto::{OperatorEnrollmentRecord, OperatorRole};
use zeroize::Zeroizing;

use daemon_evidence::decode_fixed_hex;
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

    /// Native host-trust pin-store path (`host_trust::HostTrustStore`).
    /// Grows over time as `/v1/sign/*` and (later) `/v1/handshake/*`
    /// requests name daemon fingerprints to trust; unlike the identity/
    /// token files this has no fixed first-run content, so it's simply
    /// created empty on first use.
    #[arg(long, default_value = "operator-agent-host-trust.json")]
    pin_store_path: PathBuf,

    /// Allow a privileged confirmation (first trust of a daemon
    /// fingerprint, a fingerprint change, or -- in later steps --
    /// revocation/enrollment) to proceed automatically when no interactive
    /// terminal is attached, instead of failing closed. Off by default;
    /// see `host_trust`'s module docs for why there's no silent fallback.
    #[arg(long, default_value_t = false)]
    allow_noninteractive_privileged_confirmation: bool,
}

struct AgentState {
    manager: HandshakeManager,
    ed25519_secret: Zeroizing<[u8; 32]>,
    ml_dsa_seed: Zeroizing<[u8; 32]>,
    token: String,
    allowed_origins: Vec<String>,
    /// Native host-trust policy for `/v1/sign/*` and (later)
    /// `/v1/handshake/*`. `HostTrustStore::check` blocks on terminal I/O,
    /// so callers must reach it through `tokio::task::spawn_blocking`
    /// rather than locking it directly on an async worker thread.
    host_trust: StdMutex<HostTrustStore>,
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
    let host_trust = HostTrustStore::load(
        args.pin_store_path.clone(),
        args.allow_noninteractive_privileged_confirmation,
    )?;

    tracing::info!(
        fingerprint = %hex::encode(manager.identity_fingerprint()),
        identity_path = %args.identity_path.display(),
        allowed_origins = ?args.allowed_origin,
        pin_store_path = %args.pin_store_path.display(),
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
        host_trust: StdMutex::new(host_trust),
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
        .route("/v1/sign/challenge", post(sign_challenge))
        .route("/v1/sign/consent-action", post(sign_consent_action))
        .route("/v1/sign/revoke", post(sign_revoke))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_and_cors_middleware,
        ))
        // The `/v1/sign/*` bodies are small, fixed-shape JSON, but no
        // longer just "a handful of hex strings" now that they carry a
        // `DaemonIdentityCertificate` (ML-DSA-65 alone is ~1952-byte
        // pubkeys / ~3309-byte signatures, hex-doubled) plus, for
        // /v1/sign/challenge, a second ML-DSA host attestation on top --
        // a genuine such request runs ~17-18KB. 64KiB gives headroom while
        // still refusing anything wildly larger up front, before typed
        // parsing even starts. GET routes have no body, so this only
        // bounds the POST routes in practice.
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
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

/// `POST /v1/sign/challenge` -- sign the daemon's `/auth/challenge` nonce
/// with both algorithms, proving possession of the enrolled operator key,
/// without the raw seeds ever leaving this process. Step 2 of
/// `docs/security/SIGNER_DELEGATION_DESIGN.md`'s PR sequence (Track A);
/// its host-trust gate was hardened in PR "4.5b" (see
/// [`daemon_evidence`]'s module doc comment).
///
/// Local-caller authentication (Origin + `X-Agent-Token`) already happened
/// in `auth_and_cors_middleware` before this handler runs. What follows:
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

    Ok(Json(SignConsentActionResponse {
        ed_signature_hex: hex::encode(ed_signature.to_bytes()),
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

    Ok(Json(SignRevokeResponse {
        ed_signature_hex: hex::encode(ed_signature.to_bytes()),
    }))
}

/// Steps 1-2 shared by every `/v1/sign/*` handler: reject an unrecognized
/// `schema_version` or malformed `suite` rather than guessing at
/// compatibility.
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
    Ok(())
}

/// Step 3, shared by every `/v1/sign/*` handler: verify
/// `common.daemon_certificate`'s own signatures
/// ([`daemon_evidence::verify_daemon_certificate`]), then check the
/// fingerprint *it computes* -- never one the caller supplies -- against
/// native host-trust policy (`host_trust::HostTrustStore::check`),
/// blocking on a native terminal confirmation for an unpinned or changed
/// fingerprint. `check()` blocks on terminal I/O, so it runs via
/// `spawn_blocking` rather than on an async worker thread. Returns the
/// verified identity so callers can check further evidence (a challenge
/// attestation or a session token) against its now-trusted keys.
///
/// Track A has no separate `host_alias` field (unlike Track B's
/// `/v1/handshake/begin`, which names an intended host *before*
/// authentication completes) -- the fingerprint itself is the pin key.
/// This still gives the core TOFU property: a fingerprint the operator
/// has never confirmed before requires confirmation; a rotated
/// fingerprint for what the daemon claims is the same host looks like
/// "first use of a new fingerprint" rather than a flagged rotation, since
/// there's no stable name to rotate *against*. That distinction is
/// exactly what Track B's alias-based pinning adds later.
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

    let host_alias = hex::encode(identity.fingerprint);
    let suite = common.suite.clone();
    let fingerprint = identity.fingerprint;
    let check_state = state.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        check_state
            .host_trust
            .lock()
            .expect("host-trust mutex poisoned")
            .check(&host_alias, &suite, fingerprint)
    })
    .await
    .map_err(|_| internal_error("host-trust check task panicked"))?
    .map_err(|e| {
        let agent_err = e.to_agent_error();
        (status_for(agent_err.code), Json(agent_err))
    })?;
    tracing::info!(
        request_id = %common.request_id,
        suite = %common.suite,
        outcome = ?outcome,
        endpoint = endpoint_label,
        "host trust check passed"
    );
    Ok(identity)
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
            token: token.to_string(),
            allowed_origins: allowed_origins.iter().map(|s| s.to_string()).collect(),
            host_trust: StdMutex::new(
                HostTrustStore::load(pin_store_path, allow_noninteractive_privileged).unwrap(),
            ),
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
        let host_alias = hex::encode(fingerprint);
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
            token: token.to_string(),
            allowed_origins: allowed_origins.iter().map(|s| s.to_string()).collect(),
            host_trust: StdMutex::new(
                HostTrustStore::load(pin_store_path, allow_noninteractive_privileged).unwrap(),
            ),
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
    use xenia_operator_agent_proto::{DaemonIdentityCertificate, SignedTokenDto};

    /// A daemon's host identity + its separate HTTP-auth signing key.
    fn test_daemon_identity() -> (HandshakeManager, SigningKey) {
        (
            HandshakeManager::new(),
            SigningKey::generate(&mut rand::thread_rng()),
        )
    }

    fn test_certificate(
        host: &HandshakeManager,
        http_auth: &SigningKey,
    ) -> DaemonIdentityCertificate {
        let http_auth_pk = http_auth.verifying_key().to_bytes();
        let transcript = xenia_operator_proto::daemon_delegation_transcript(&http_auth_pk);
        DaemonIdentityCertificate {
            host_ed25519_pubkey: hex::encode(host.identity_public_key_bytes()),
            host_ml_dsa_pubkey: hex::encode(host.ml_dsa_public_key_bytes()),
            http_auth_ed25519_pubkey: hex::encode(http_auth_pk),
            host_ed_signature: hex::encode(host.sign(&transcript).to_bytes()),
            host_ml_dsa_signature: hex::encode(host.sign_ml_dsa(&transcript)),
        }
    }

    fn test_token(http_auth: &SigningKey, token_nonce: [u8; 16]) -> SignedTokenDto {
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

    async fn post_signed_json(
        app: Router,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("origin", "http://localhost:8134")
            .header("x-agent-token", token)
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
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

    #[tokio::test]
    async fn sign_challenge_rejects_an_unsupported_schema_version() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
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
        let (host, http_auth) = test_daemon_identity();
        let mut cert = test_certificate(&host, &http_auth);
        let (_other_host, other_http_auth) = test_daemon_identity();
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token_nonce = [0xeeu8; 16];
        let token = test_token(&http_auth, token_nonce);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token_nonce = [0xeeu8; 16];
        let token = test_token(&http_auth, token_nonce);
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
        assert!(
            HandshakeManager::verify(
                &expected_manager.identity_public_key(),
                &wrong_transcript,
                &ed_sig,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn sign_consent_action_rejects_an_unsupported_schema_version() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0xeeu8; 16]);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0xeeu8; 16]);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0xeeu8; 16]);
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
    async fn sign_consent_action_fails_closed_when_a_new_host_needs_confirmation_and_none_is_available()
     {
        let state = test_state_with_host_trust("secret", &["http://localhost:8134"], false);
        let app = build_router(state);
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0xeeu8; 16]);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let (_other_host, attacker_http_auth) = test_daemon_identity();
        let token = test_token(&attacker_http_auth, [0xeeu8; 16]);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token_nonce = [0x11u8; 16];
        let token = test_token(&http_auth, token_nonce);
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
        let (host, http_auth) = test_daemon_identity();
        let state = test_state_with_pinned_host(
            "secret",
            &["http://localhost:8134"],
            &host,
            "standard",
            false,
        );
        let app = build_router(state);
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0x11u8; 16]);
        let body = revoke_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_revoke_fails_closed_when_the_host_itself_needs_confirmation_and_none_is_available()
     {
        let state = test_state_with_host_trust("secret", &["http://localhost:8134"], false);
        let app = build_router(state);
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0x11u8; 16]);
        let body = revoke_request_body(&cert, &token, serde_json::json!({}));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "body: {json}");
        assert_eq!(json["code"], "confirmation_required");
    }

    #[tokio::test]
    async fn sign_revoke_rejects_an_empty_target_operator_id() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0x11u8; 16]);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let mut token = serde_json::to_value(test_token(&http_auth, [0x11u8; 16])).unwrap();
        token["token_nonce_hex"] = serde_json::json!("nope");
        let body = serde_json::json!({
            "schema_version": xenia_operator_agent_proto::SCHEMA_VERSION,
            "daemon_certificate": cert,
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0x11u8; 16]);
        let body = revoke_request_body(&cert, &token, serde_json::json!({ "schema_version": 999 }));
        let (status, json) = post_signed_json(app, "/v1/sign/revoke", "secret", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
        assert_eq!(json["code"], "bad_request");
    }

    #[tokio::test]
    async fn sign_revoke_rejects_a_token_signed_by_the_wrong_key() {
        let state = test_state("secret", &["http://localhost:8134"]);
        let app = build_router(state);
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let (_other_host, attacker_http_auth) = test_daemon_identity();
        let token = test_token(&attacker_http_auth, [0x11u8; 16]);
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
        let (host, http_auth) = test_daemon_identity();
        let cert = test_certificate(&host, &http_auth);
        let token = test_token(&http_auth, [0x11u8; 16]);
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
}
