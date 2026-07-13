// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator-RBAC ceremony — the **browser side** of `OPERATOR_RBAC_PLAN.md`
//! Phase 5, revised by Step 5 of
//! `docs/security/SIGNER_DELEGATION_DESIGN.md`. This is the console's half
//! of the exact flow the daemon already enforces:
//!
//! ```text
//!   GET  /auth/daemon-identity -> DaemonIdentityCertificate
//!   POST /auth/challenge       -> host-attested nonce
//!   ask the local agent to sign the challenge (both keys) -- it verifies
//!     the certificate + attestation itself; the raw seeds never reach
//!     this process
//!   POST /auth/verify          -> daemon-signed, role-scoped token
//!   ask the local agent to sign consent_action_transcript(action,
//!     session_id, token_nonce) per action, relaying the full session
//!     token so the agent can verify it
//!   send  { token, action, action_signature }  on the consent socket
//! ```
//!
//! **Scope note**: this is Track A only (the plain-HTTP `/auth/*`
//! ceremony). Since Step 6 of `docs/security/SIGNER_DELEGATION_DESIGN.md`
//! landed, the sealed-channel handshake ("Track B",
//! `crate::sealed_consent`) no longer needs the operator's raw seeds
//! either -- it relays the handshake's own wire bytes through the local
//! agent instead. [`OperatorIdentity`] therefore no longer retains seeds at
//! all past the moment [`OperatorIdentity::from_seeds`] derives its public
//! keys from them; it's kept purely for *display* (the enrollment
//! record/fingerprint shown on the Sessions page), fed by
//! [`crate::agent_client::fetch_seeds`], and is no longer used for
//! *signing* or *handshaking* anything in this crate.
//!
//! Correctness rests on shared crates, so nothing can drift from the
//! daemon or the agent:
//! - [`xenia_operator_proto`] provides the *exact* signed transcripts,
//!   role model, and [`xenia_operator_proto::DaemonIdentityCertificate`]
//!   shape the daemon and agent both use.
//! - [`xenia_operator_agent_proto`] provides the *exact* `/v1/sign/*`
//!   request/response shapes the agent parses -- see
//!   `apps/xenia-operator-agent`'s `daemon_evidence` module for what it
//!   verifies before signing anything.
//! - [`xenia_handshake::HandshakeManager`] provides the *same* Ed25519 +
//!   ML-DSA-65 keygen the daemon's enrolled operators use, still needed
//!   here for [`OperatorIdentity`]'s non-signing uses (display). We only
//!   ever call its keygen methods (never the `SystemTime`-using
//!   `establish()` paths), so it is wasm-safe at runtime.

use serde::Deserialize;
use zeroize::Zeroize;

use xenia_handshake::HandshakeManager;
use xenia_operator_agent_proto::{
    SignChallengeRequest, SignConsentActionRequest, SignRequestCommon, SignRevokeRequest,
    SignedTokenDto,
};
use xenia_operator_proto::{
    ConsentAction, DaemonIdentityCertificate, OperatorAction, OperatorEnrollmentRecord,
    OperatorRole,
};
use xenia_wire::handshake_highsec::{
    ViewerHandshakeHighSec, derive_ml_dsa_87_seed_from_ed25519_secret,
};

/// Track A (the plain-HTTP `/auth/*` ceremony -- challenge/consent-action/
/// revoke) is suite-independent: the daemon's host-identity certificate
/// vouches for the HTTP-auth key regardless of which sealed-channel suite
/// (if any) is later negotiated -- there's only one host identity. This is
/// just a stable pin-store key for Track A; it is *not* the same knob as
/// `DaemonConfig::high_security`, which selects an actual different suite
/// for Track B's sealed channel.
const TRACK_A_SUITE: &str = "standard";

/// A stable operator identity: Ed25519 + ML-DSA-65 (standard suite) plus a
/// *derived* ML-DSA-87 identity (high-security suite). Wraps a
/// [`HandshakeManager`] purely as the signing engine.
///
/// The ML-DSA-87 public key is derived deterministically from the same
/// Ed25519 secret via [`derive_ml_dsa_87_seed_from_ed25519_secret`] -- the
/// same derivation [`crate::sealed_consent::send_sealed_consent_highsec`]
/// uses to drive the actual handshake -- so this type is the single source
/// of truth for "what would this operator's high-security identity be,"
/// and [`Self::enrollment_record_json`] can enroll it without a second key
/// file or a second enrollment ceremony.
///
/// Unlike an earlier revision of this type, `OperatorIdentity` does not
/// retain the raw seeds past construction: [`Self::from_seeds`] zeroizes its
/// local copies as soon as every derivation that needs them is done (see its
/// doc comment). Since Step 6 of `docs/security/SIGNER_DELEGATION_DESIGN.md`
/// landed, nothing in this crate needs the raw seeds again after that point
/// -- the sealed-channel handshake now relays wire bytes through the local
/// agent instead of driving `ViewerHandshake`/`ViewerHandshakeHighSec` here.
/// This is best-effort hygiene, not a guarantee: `hm` (the
/// [`HandshakeManager`]) holds its own internal copy of the derived signing
/// keys, which this does not reach, and Rust may have left other transient
/// stack copies behind before `from_seeds` was even called (e.g. in
/// [`crate::agent_client::fetch_seeds`]'s decode step). See
/// `docs/security/OPERATOR_SECURITY_MODEL.md` §9 for the honest scope of
/// what's protected today.
pub struct OperatorIdentity {
    hm: HandshakeManager,
    ed_pubkey: [u8; 32],
    ml_pubkey: Vec<u8>,
    ml87_pubkey: Vec<u8>,
}

impl OperatorIdentity {
    /// Build the identity from seeds already fetched from the operator
    /// agent (see [`crate::agent_client::fetch_seeds`]). Deterministic in
    /// the seeds, so the returned public keys (and hence the enrollment
    /// fingerprint) are stable across page reloads as long as the agent's
    /// identity file doesn't change.
    ///
    /// Zeroizes its local seed copies before returning -- nothing this type
    /// exposes needs them again; see the struct doc comment.
    pub fn from_seeds(mut ed_seed: [u8; 32], mut ml_seed: [u8; 32]) -> Self {
        let hm = HandshakeManager::from_identity_seeds(ed_seed, ml_seed);
        let ed_pubkey = hm.identity_public_key_bytes();
        let ml_pubkey = hm.ml_dsa_public_key_bytes().to_vec();
        // The ML-DSA-87 seed is *derived*, not separately persisted -- a
        // 32-byte Ed25519 secret plus this deterministic derivation is all
        // that's needed to reproduce the same high-security identity every
        // time. The `ed_seed`/`ml87_seed` pair are both always exactly 32
        // bytes here, so `from_identity` cannot actually fail.
        let mut ml87_seed = derive_ml_dsa_87_seed_from_ed25519_secret(&ed_seed);
        let ml87_pubkey = ViewerHandshakeHighSec::from_identity(&ed_seed, &ml87_seed)
            .expect("32-byte seeds always produce a valid high-security identity")
            .ml_dsa_public_key_bytes()
            .to_vec();
        ed_seed.zeroize();
        ml_seed.zeroize();
        ml87_seed.zeroize();
        Self {
            hm,
            ed_pubkey,
            ml_pubkey,
            ml87_pubkey,
        }
    }

    /// The Ed25519 public key, hex — what an admin enrolls in the daemon's
    /// `--operators-file`.
    pub fn ed_pubkey_hex(&self) -> String {
        hex::encode(self.ed_pubkey)
    }

    /// The ML-DSA-65 public key, hex — the standard-suite half of the
    /// enrollment record.
    pub fn ml_pubkey_hex(&self) -> String {
        hex::encode(&self.ml_pubkey)
    }

    /// The *derived* ML-DSA-87 public key, hex — the high-security-suite
    /// half of the enrollment record. See the struct doc comment for how
    /// this is derived.
    pub fn ml87_pubkey_hex(&self) -> String {
        hex::encode(&self.ml87_pubkey)
    }

    /// The host-identity fingerprint (BLAKE3 over both public keys) an admin
    /// can eyeball when enrolling this operator.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.hm.identity_fingerprint())
    }

    /// A paste-ready enrollment record for the daemon's `--operators-file`,
    /// carrying all three public keys (Ed25519, ML-DSA-65, and the derived
    /// ML-DSA-87). The admin adds this to the `operators` array (with a
    /// chosen `operator_id` + `role`) so this browser identity becomes an
    /// enrolled operator for *both* sealed-channel suites at once -- without
    /// this the fingerprint alone can't enroll, and omitting the ML-DSA-87
    /// key here is exactly what left the high-security suite unusable via
    /// any real enrollment (a policy file generated from this record could
    /// never satisfy `OperatorPolicy::lookup_verified_highsec`).
    ///
    /// Built from [`xenia_operator_proto::OperatorEnrollmentRecord`] --
    /// the same type an integration test can deserialize a daemon-side
    /// `OperatorPolicy` from -- so this can't silently drift from what the
    /// daemon actually parses the way the old hand-built `serde_json::json!`
    /// call here once did.
    pub fn enrollment_record_json(&self, operator_id: &str, role: OperatorRole) -> String {
        OperatorEnrollmentRecord {
            operator_id: operator_id.to_string(),
            ed25519_pubkey: self.ed_pubkey_hex(),
            ml_dsa_pubkey: self.ml_pubkey_hex(),
            ml_dsa_87_pubkey: Some(self.ml87_pubkey_hex()),
            role,
        }
        .to_json_string()
    }
}

/// A daemon-issued, role-scoped session token. The raw `token_json` is
/// re-embedded verbatim into every consent request (the daemon re-verifies its
/// own signature); the other fields are parsed out so the console can gate
/// the UI and (via [`Self::to_signed_token_dto`]) ask the agent to verify
/// and sign against this exact token.
#[derive(Clone)]
pub struct OperatorSession {
    /// The enrolled operator id the daemon attributed this session to.
    pub operator_id: String,
    /// The role the daemon scoped the token to. UI gating uses exactly this.
    pub role: OperatorRole,
    /// Token expiry (unix secs) — the console stops using it past this.
    pub expires_at: u64,
    issued_at: u64,
    token_nonce: [u8; 16],
    signature_hex: String,
    token_json: serde_json::Value,
}

impl OperatorSession {
    /// Whether this session's role permits `action` — identical logic to the
    /// daemon's authorization (both call [`OperatorRole::permits`]).
    pub fn permits(&self, action: OperatorAction) -> bool {
        self.role.permits(action)
    }

    /// Whether the token is still within its validity window per the browser
    /// wall-clock. An expired token would be refused by the daemon anyway; the
    /// console stops offering actions once it lapses so the operator re-auths
    /// instead of clicking into a rejection.
    pub fn is_valid(&self) -> bool {
        let now_secs = (js_sys::Date::now() / 1000.0) as u64;
        now_secs < self.expires_at
    }

    /// This session's token in the shape the agent's `/v1/sign/*` endpoints
    /// expect, so it can verify the daemon's own signature over it before
    /// trusting the `token_nonce` bound into a consent-action/revoke
    /// transcript. Built from fields already parsed at `authenticate()`
    /// time -- infallible, no re-parsing of `token_json`.
    fn to_signed_token_dto(&self) -> SignedTokenDto {
        SignedTokenDto {
            operator_id: self.operator_id.clone(),
            role: self.role,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            token_nonce_hex: hex::encode(self.token_nonce),
            signature_hex: self.signature_hex.clone(),
        }
    }
}

#[derive(Deserialize)]
struct ChallengeDto {
    nonce: String,
    host_ed_attestation_hex: String,
    host_ml_dsa_attestation_hex: String,
}

// Every field the console needs, including the ones (`issued_at`,
// `signature`) only [`OperatorSession::to_signed_token_dto`] uses -- the
// rest of the token JSON (there is none beyond these) is preserved intact
// in `token_json` and re-sent verbatim.
#[derive(Deserialize)]
struct TokenFields {
    operator_id: String,
    role: OperatorRole,
    issued_at: u64,
    expires_at: u64,
    token_nonce: String,
    signature: String,
}

/// Run the full challenge → agent-sign → verify ceremony against the
/// daemon's `/auth/*` routes at `endpoint`, returning a role-scoped
/// session. The operator's seeds never reach this process: the agent (at
/// `agent_url`, authenticated with `agent_token`) verifies the daemon's
/// identity evidence and signs on the console's behalf.
pub async fn authenticate(
    endpoint: &str,
    agent_url: &str,
    agent_token: &str,
) -> Result<OperatorSession, String> {
    let base = endpoint.trim_end_matches('/');

    // 1. Fetch the daemon's host-identity delegation certificate -- the
    //    evidence the agent verifies (and computes the fingerprint from)
    //    before it will sign anything. See
    //    docs/security/SIGNER_DELEGATION_DESIGN.md's "typed transcripts
    //    are not enough" section for why a bare fingerprint isn't enough.
    let cert = fetch_daemon_certificate(base).await?;

    // 2. Ask for a fresh, host-attested single-use challenge.
    let chal: ChallengeDto = post_json(&format!("{base}/auth/challenge"), "{}".to_string()).await?;

    // 3. Ask the local agent to sign it. The agent verifies `cert` and the
    //    attestation itself, then signs with both algorithms.
    let signed = crate::agent_client::sign_challenge(
        agent_url,
        agent_token,
        &SignChallengeRequest {
            common: SignRequestCommon {
                schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
                daemon_certificate: cert,
                suite: TRACK_A_SUITE.to_string(),
                request_id: request_id(),
            },
            nonce_hex: chal.nonce.clone(),
            host_ed_attestation_hex: chal.host_ed_attestation_hex.clone(),
            host_ml_dsa_attestation_hex: chal.host_ml_dsa_attestation_hex.clone(),
        },
    )
    .await?;

    // 4. Exchange the signed response for a daemon-signed, role-scoped token.
    let verify_body = serde_json::json!({
        "nonce": chal.nonce,
        "ed_pubkey": signed.ed25519_pubkey_hex,
        "ml_dsa_pubkey": signed.ml_dsa_pubkey_hex,
        "ed_signature": signed.ed_signature_hex,
        "ml_dsa_signature": signed.ml_dsa_signature_hex,
    })
    .to_string();
    let token_json: serde_json::Value =
        post_json(&format!("{base}/auth/verify"), verify_body).await?;
    let fields: TokenFields =
        serde_json::from_value(token_json.clone()).map_err(|e| format!("bad token: {e}"))?;
    let token_nonce =
        decode16(&fields.token_nonce).map_err(|_| "token nonce malformed".to_string())?;

    Ok(OperatorSession {
        operator_id: fields.operator_id,
        role: fields.role,
        expires_at: fields.expires_at,
        issued_at: fields.issued_at,
        token_nonce,
        signature_hex: fields.signature,
        token_json,
    })
}

/// Build the authenticated consent-action JSON the daemon parses on the consent
/// socket: `{ token, action, action_signature }`. The per-action Ed25519
/// signature binds the action to the exact session and token, so a captured
/// signature can't be replayed for a different action/session/token. The
/// agent verifies `session`'s token before signing -- see
/// [`OperatorSession::to_signed_token_dto`].
pub async fn build_consent_request(
    endpoint: &str,
    agent_url: &str,
    agent_token: &str,
    session: &OperatorSession,
    action: ConsentAction,
    session_id: &[u8; 16],
) -> Result<String, String> {
    let base = endpoint.trim_end_matches('/');
    let cert = fetch_daemon_certificate(base).await?;
    let signed = crate::agent_client::sign_consent_action(
        agent_url,
        agent_token,
        &SignConsentActionRequest {
            common: SignRequestCommon {
                schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
                daemon_certificate: cert,
                suite: TRACK_A_SUITE.to_string(),
                request_id: request_id(),
            },
            action,
            session_id_hex: hex::encode(session_id),
            token: session.to_signed_token_dto(),
        },
    )
    .await?;
    Ok(serde_json::json!({
        "token": session.token_json,
        "action": action.as_str(),
        "action_signature": signed.ed_signature_hex,
    })
    .to_string())
}

/// Build the authenticated `POST /operator/revoke` body the daemon parses:
/// `{ token, target_operator_id, action_signature }`. The per-action Ed25519
/// signature is over the shared `revoke_operator_transcript(target,
/// token_nonce)` -- built by the agent, which also verifies `session`'s
/// token first (see [`OperatorSession::to_signed_token_dto`]) -- so it binds
/// this revocation to the exact target and the admin's current token,
/// byte-identical to what the daemon verifies. Only an Admin session's
/// token will be authorized daemon-side. Privileged: the agent runs its own
/// mandatory native confirmation for this action regardless of how
/// well-trusted the daemon already is.
pub async fn build_revoke_request(
    endpoint: &str,
    agent_url: &str,
    agent_token: &str,
    session: &OperatorSession,
    target_operator_id: &str,
) -> Result<String, String> {
    let base = endpoint.trim_end_matches('/');
    let cert = fetch_daemon_certificate(base).await?;
    let signed = crate::agent_client::sign_revoke(
        agent_url,
        agent_token,
        &SignRevokeRequest {
            common: SignRequestCommon {
                schema_version: xenia_operator_agent_proto::SCHEMA_VERSION,
                daemon_certificate: cert,
                suite: TRACK_A_SUITE.to_string(),
                request_id: request_id(),
            },
            target_operator_id: target_operator_id.to_string(),
            token: session.to_signed_token_dto(),
        },
    )
    .await?;
    Ok(serde_json::json!({
        "token": session.token_json,
        "target_operator_id": target_operator_id,
        "action_signature": signed.ed_signature_hex,
    })
    .to_string())
}

/// Fetch the daemon's host-identity delegation certificate. No local
/// caching (deliberately -- see the Step 5 design note): each of the three
/// operations above is human-paced (sign-in, an approve/deny/revoke
/// click), so one extra small `GET` per call is cheap and avoids any
/// cache-invalidation-on-endpoint-change bug.
async fn fetch_daemon_certificate(base: &str) -> Result<DaemonIdentityCertificate, String> {
    get_json(&format!("{base}/auth/daemon-identity")).await
}

/// A caller-generated id for correlating a `/v1/sign/*` request through
/// logs -- not itself a security boundary, so a UUID is sufficient (no
/// need for a CSPRNG-sourced value here specifically).
fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ─── small helpers ───────────────────────────────────────────────────────────

fn decode16(s: &str) -> Result<[u8; 16], ()> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(())
}

/// POST `body` as JSON to `url` and deserialize the JSON response. Any non-2xx
/// status is surfaced as an error string (the daemon's stable message).
async fn post_json<T: for<'de> Deserialize<'de>>(url: &str, body: String) -> Result<T, String> {
    use gloo_net::http::Request;
    let resp = Request::post(url)
        .header("content-type", "application/json")
        .body(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    if !resp.ok() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("{status}: {text}"));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

/// GET `url` and deserialize the JSON response. Mirrors [`post_json`]'s
/// error handling.
async fn get_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T, String> {
    use gloo_net::http::Request;
    let resp = Request::get(url)
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    if !resp.ok() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("{status}: {text}"));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}
