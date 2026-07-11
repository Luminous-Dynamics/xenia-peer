// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator-RBAC ceremony — the **browser side** of `OPERATOR_RBAC_PLAN.md`
//! Phase 5. This is the console's half of the exact flow the daemon already
//! enforces:
//!
//! ```text
//!   POST /auth/challenge  -> nonce
//!   sign  challenge_transcript(nonce, ed_pk, ml_pk)  with BOTH keys
//!   POST /auth/verify     -> daemon-signed, role-scoped token
//!   sign  consent_action_transcript(action, session_id, token_nonce)  per action
//!   send  { token, action, action_signature }  on the consent socket
//! ```
//!
//! Correctness rests on two shared crates, so nothing can drift from the
//! daemon:
//! - [`xenia_operator_proto`] provides the *exact* signed transcripts + role
//!   model the daemon verifies against.
//! - [`xenia_handshake::HandshakeManager`] provides the *same* Ed25519 +
//!   ML-DSA-65 keygen/signing the daemon's enrolled operators use — so a
//!   browser-produced signature is byte-identical to what the daemon expects.
//!   We only ever call its keygen/sign methods (never the `SystemTime`-using
//!   `establish()` paths), so it is wasm-safe at runtime.

use serde::Deserialize;
use web_sys::Storage;

use xenia_handshake::HandshakeManager;
use xenia_operator_proto::{
    ConsentAction, OperatorAction, OperatorRole, challenge_transcript, consent_action_transcript,
    revoke_operator_transcript,
};

/// localStorage keys for the operator's persisted identity seeds (hex). Two
/// 32-byte seeds fully determine the Ed25519 + ML-DSA-65 identity, so the same
/// enrolled key survives reloads (see [`HandshakeManager::from_identity_seeds`]).
const ED_SEED_KEY: &str = "xenia-admin.operator.ed-seed";
const ML_SEED_KEY: &str = "xenia-admin.operator.ml-seed";

fn local_storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok()?
}

/// A stable operator identity: Ed25519 + ML-DSA-65, persisted as two seeds so
/// the enrolled key is the same across page loads. Wraps a
/// [`HandshakeManager`] purely as the signing engine.
pub struct OperatorIdentity {
    hm: HandshakeManager,
    ed_pubkey: [u8; 32],
    ml_pubkey: Vec<u8>,
    ed_seed: [u8; 32],
    ml_seed: [u8; 32],
}

impl OperatorIdentity {
    /// Load the persisted identity, or generate + persist a fresh one on first
    /// use. Deterministic in the seeds, so the returned public keys (and hence
    /// the enrollment fingerprint) are stable across reloads.
    pub fn load_or_generate() -> Self {
        let (ed_seed, ml_seed) = load_seeds().unwrap_or_else(|| {
            let seeds = generate_seeds();
            save_seeds(&seeds.0, &seeds.1);
            seeds
        });
        Self::from_seeds(ed_seed, ml_seed)
    }

    fn from_seeds(ed_seed: [u8; 32], ml_seed: [u8; 32]) -> Self {
        let hm = HandshakeManager::from_identity_seeds(ed_seed, ml_seed);
        let ed_pubkey = hm.identity_public_key_bytes();
        let ml_pubkey = hm.ml_dsa_public_key_bytes().to_vec();
        Self {
            hm,
            ed_pubkey,
            ml_pubkey,
            ed_seed,
            ml_seed,
        }
    }

    /// The persisted identity seeds (Ed25519 secret, ML-DSA-65 seed). Used to
    /// drive the sealed operator channel's PQC handshake with *this* enrolled
    /// identity, so the handshake authenticates the operator (see
    /// [`crate::sealed_consent`]). These never leave the browser except as the
    /// public keys they derive.
    pub fn seeds(&self) -> ([u8; 32], [u8; 32]) {
        (self.ed_seed, self.ml_seed)
    }

    /// The Ed25519 public key, hex — what an admin enrolls in the daemon's
    /// `--operators-file`.
    pub fn ed_pubkey_hex(&self) -> String {
        hex::encode(self.ed_pubkey)
    }

    /// The ML-DSA-65 public key, hex — the other half of the enrollment record.
    pub fn ml_pubkey_hex(&self) -> String {
        hex::encode(&self.ml_pubkey)
    }

    /// The host-identity fingerprint (BLAKE3 over both public keys) an admin
    /// can eyeball when enrolling this operator.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.hm.identity_fingerprint())
    }

    /// A paste-ready enrollment record for the daemon's `--operators-file`,
    /// carrying both public keys. The admin adds this to the `operators` array
    /// (with a chosen `operator_id` + `role`) so this browser identity becomes
    /// an enrolled operator. Without this the fingerprint alone can't enroll.
    pub fn enrollment_record_json(&self, operator_id: &str, role: OperatorRole) -> String {
        serde_json::json!({
            "operator_id": operator_id,
            "ed25519_pubkey": self.ed_pubkey_hex(),
            "ml_dsa_pubkey": self.ml_pubkey_hex(),
            "role": role.as_str(),
        })
        .to_string()
    }
}

fn generate_seeds() -> ([u8; 32], [u8; 32]) {
    use rand_core::{OsRng, RngCore};
    let mut ed = [0u8; 32];
    let mut ml = [0u8; 32];
    OsRng.fill_bytes(&mut ed);
    OsRng.fill_bytes(&mut ml);
    (ed, ml)
}

fn load_seeds() -> Option<([u8; 32], [u8; 32])> {
    let storage = local_storage()?;
    let ed_hex = storage.get_item(ED_SEED_KEY).ok().flatten()?;
    let ml_hex = storage.get_item(ML_SEED_KEY).ok().flatten()?;
    let ed = decode32(&ed_hex).ok()?;
    let ml = decode32(&ml_hex).ok()?;
    Some((ed, ml))
}

fn save_seeds(ed: &[u8; 32], ml: &[u8; 32]) {
    if let Some(storage) = local_storage() {
        let _ = storage.set_item(ED_SEED_KEY, &hex::encode(ed));
        let _ = storage.set_item(ML_SEED_KEY, &hex::encode(ml));
    }
}

/// A daemon-issued, role-scoped session token. The raw `token_json` is
/// re-embedded verbatim into every consent request (the daemon re-verifies its
/// own signature); `role` and `token_nonce` are parsed out so the console can
/// gate the UI and bind per-action signatures.
#[derive(Clone)]
pub struct OperatorSession {
    /// The enrolled operator id the daemon attributed this session to.
    pub operator_id: String,
    /// The role the daemon scoped the token to. UI gating uses exactly this.
    pub role: OperatorRole,
    /// Token expiry (unix secs) — the console stops using it past this.
    pub expires_at: u64,
    token_nonce: [u8; 16],
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
}

#[derive(Deserialize)]
struct ChallengeDto {
    nonce: String,
}

// Only the fields the console needs; serde ignores the rest of the token JSON,
// which is preserved intact in `token_json` and re-sent verbatim.
#[derive(Deserialize)]
struct TokenFields {
    operator_id: String,
    role: OperatorRole,
    expires_at: u64,
    token_nonce: String,
}

/// Run the full challenge → sign(both keys) → verify ceremony against the
/// daemon's `/auth/*` routes at `endpoint`, returning a role-scoped session.
pub async fn authenticate(
    endpoint: &str,
    id: &OperatorIdentity,
) -> Result<OperatorSession, String> {
    let base = endpoint.trim_end_matches('/');

    // 1. Ask for a fresh single-use challenge.
    let chal: ChallengeDto = post_json(&format!("{base}/auth/challenge"), "{}".to_string()).await?;
    let nonce = decode32(&chal.nonce).map_err(|_| "daemon sent a malformed nonce".to_string())?;

    // 2. Sign the exact transcript the daemon will reconstruct, with BOTH keys.
    let transcript = challenge_transcript(&nonce, &id.ed_pubkey, &id.ml_pubkey);
    let ed_sig = id.hm.sign(&transcript).to_bytes();
    let ml_sig = id.hm.sign_ml_dsa(&transcript);
    let verify_body = serde_json::json!({
        "nonce": chal.nonce,
        "ed_pubkey": id.ed_pubkey_hex(),
        "ml_dsa_pubkey": id.ml_pubkey_hex(),
        "ed_signature": hex::encode(ed_sig),
        "ml_dsa_signature": hex::encode(ml_sig),
    })
    .to_string();

    // 3. Exchange the signed response for a daemon-signed, role-scoped token.
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
        token_nonce,
        token_json,
    })
}

/// Build the authenticated consent-action JSON the daemon parses on the consent
/// socket: `{ token, action, action_signature }`. The per-action Ed25519
/// signature binds the action to the exact session and token, so a captured
/// signature can't be replayed for a different action/session/token.
pub fn build_consent_request(
    id: &OperatorIdentity,
    session: &OperatorSession,
    action: ConsentAction,
    session_id: &[u8; 16],
) -> String {
    let transcript = consent_action_transcript(action, session_id, &session.token_nonce);
    let sig = id.hm.sign(&transcript).to_bytes();
    serde_json::json!({
        "token": session.token_json,
        "action": action.as_str(),
        "action_signature": hex::encode(sig),
    })
    .to_string()
}

/// Build the authenticated `POST /operator/revoke` body the daemon parses:
/// `{ token, target_operator_id, action_signature }`. The per-action Ed25519
/// signature is over the shared `revoke_operator_transcript(target,
/// token_nonce)`, so it binds this revocation to the exact target and the
/// admin's current token — byte-identical to what the daemon verifies. Only an
/// Admin session's token will be authorized daemon-side.
pub fn build_revoke_request(
    id: &OperatorIdentity,
    session: &OperatorSession,
    target_operator_id: &str,
) -> String {
    let transcript = revoke_operator_transcript(target_operator_id, &session.token_nonce);
    let sig = id.hm.sign(&transcript).to_bytes();
    serde_json::json!({
        "token": session.token_json,
        "target_operator_id": target_operator_id,
        "action_signature": hex::encode(sig),
    })
    .to_string()
}

// ─── small helpers ───────────────────────────────────────────────────────────

fn decode32(s: &str) -> Result<[u8; 32], ()> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(())
}

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
