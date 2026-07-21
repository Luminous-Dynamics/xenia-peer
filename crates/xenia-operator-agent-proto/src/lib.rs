// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # xenia-operator-agent-proto
//!
//! The **shared** browser-console <-> native-operator-agent protocol: the
//! exact typed request/response shapes for the agent's `/v1/sign/*`
//! signing-delegation API (see `docs/security/SIGNER_DELEGATION_DESIGN.md`
//! in the `xenia-peer` monorepo). Both `apps/xenia-operator-agent` (which
//! parses these) and `apps/sovereign-admin` (which builds them) depend on
//! this crate, so neither side can drift from the other -- the same reason
//! `xenia-operator-proto` exists for the daemon <-> console protocol one
//! layer up.
//!
//! This crate is deliberately **crypto-free and I/O-free** -- just typed
//! request/response shapes and an error taxonomy -- so it compiles
//! unchanged for `wasm32-unknown-unknown` (the console) and native (the
//! agent). It reuses [`xenia_operator_proto::ConsentAction`] for the
//! consent-action shape rather than redefining it, since that's already
//! the canonical enum both the daemon and console agree on.
//!
//! **No endpoint here accepts arbitrary bytes, an arbitrary transcript
//! string, a caller-supplied domain separator, or a caller-supplied hash
//! without the typed fields it's a hash of.** The agent reconstructs every
//! transcript itself from these typed fields via `xenia_operator_proto`'s
//! existing transcript functions -- these types exist specifically so it
//! never has to trust a byte string the browser hands it. See the design
//! doc's "typed transcripts are not enough" section for why that alone
//! doesn't cover host-authentication, which is a separate, native-only
//! concern (`apps/xenia-operator-agent`'s `host_trust` module) deliberately
//! kept out of this shared, wasm-compiled crate.
//!
//! Handshake-delegation (Track B: [`HandshakeBeginRequest`]/
//! [`HandshakeFinishRequest`], for `/v1/handshake/begin` /
//! `/v1/handshake/finish`) needs no equivalent "typed transcripts are not
//! enough" caveat: the handshake's own cryptography *is* the
//! host-authentication evidence, verified inside
//! `ViewerHandshake::finish`/`ViewerHandshakeHighSec::finish` -- there's no
//! separate daemon-signed certificate to relay the way Track A needs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

pub use xenia_operator_proto::{
    AttestedConsentOfferV2, ConsentAction, ConsentScopeV1, DaemonIdentityCertificate, OperatorRole,
};

/// Current schema version for the `/v1/sign/*` request/response shapes.
/// Bump when a breaking change to any request/response shape ships; the
/// agent should refuse a request whose `schema_version` it doesn't
/// recognize rather than guessing at compatibility.
pub const SCHEMA_VERSION: u32 = 8;

/// Fields common to every `/v1/sign/*` request: who the caller believes
/// they are, which daemon they're targeting, and enough to correlate a
/// request through logs. None of these fields are secret.
///
/// **`daemon_certificate` is evidence, not an assertion.** An earlier
/// revision of this type (schema version 1) carried a bare
/// `daemon_fingerprint_hex` string the caller simply asserted -- the agent
/// had no way to verify it actually corresponded to anything, so a
/// compromised browser could label any request with an already-trusted
/// fingerprint regardless of what it was actually asking to be signed.
/// `daemon_certificate` fixes that: the agent verifies both of its
/// signatures itself and computes the daemon's fingerprint from the
/// certificate's own presented keys
/// (`xenia_handshake::host_identity_fingerprint`) -- it never trusts a
/// fingerprint the caller names directly. See
/// `docs/security/SIGNER_DELEGATION_DESIGN.md` and
/// `DaemonIdentityCertificate`'s own doc comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequestCommon {
    /// Must equal [`SCHEMA_VERSION`] the agent was built against, or the
    /// agent refuses the request rather than guessing at compatibility.
    pub schema_version: u32,
    /// The target daemon's host-identity delegation certificate, fetched
    /// by the caller from that daemon's `GET /auth/daemon-identity` and
    /// relayed verbatim. The agent verifies this itself (both signatures,
    /// then derives the fingerprint) before checking it against native
    /// host-trust policy (`host_trust::HostTrustStore`) -- see the design
    /// doc's "typed transcripts are not enough" section for why a bare
    /// caller-supplied fingerprint isn't sufficient.
    pub daemon_certificate: DaemonIdentityCertificate,
    /// The daemon endpoint the caller believes it's talking to (e.g. the
    /// console's configured `http://host:port`), used **only** as a stable
    /// scope key for the native host-trust pin store -- never as identity
    /// evidence. Schema version 2 and earlier pinned by the *fingerprint
    /// itself*, which meant a rotated or spoofed identity always looked
    /// like a brand-new host to the pin store rather than "the daemon at
    /// this known endpoint changed identity" -- the
    /// `FingerprintChanged`/rotation-confirmation path was effectively
    /// unreachable in practice. The agent normalizes this string (not the
    /// caller) before using it as a pin-store key; a compromised or
    /// careless caller can at worst cause a spurious first-use/rotation
    /// prompt under the wrong scope, never bypass the fingerprint
    /// verification itself, which is unaffected by this field.
    pub daemon_endpoint: String,
    /// Which sealed-channel suite this request is scoped to
    /// (`"standard"` or `"highsec"`) -- the two suites pin daemon
    /// identity under separate host-trust entries, mirroring
    /// `sovereign-admin`'s browser-side `host_pin` scoping.
    pub suite: String,
    /// A caller-generated id for this request. Correlation/logging only --
    /// not itself a security boundary.
    pub request_id: String,
}

/// `POST /v1/sign/challenge` request: sign the daemon's `/auth/challenge`
/// nonce with both algorithms, proving possession of the enrolled operator
/// key.
///
/// `host_ed_attestation_hex`/`host_ml_dsa_attestation_hex` are the host
/// identity's own signatures (relayed verbatim from the daemon's
/// `/auth/challenge` response) proving *this specific nonce* was really
/// issued by the daemon named in `common.daemon_certificate` -- without
/// them, a compromised browser could ask the agent to sign an
/// attacker-chosen nonce under an otherwise-legitimate, already-trusted
/// daemon label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignChallengeRequest {
    /// Fields shared by every `/v1/sign/*` request.
    #[serde(flatten)]
    pub common: SignRequestCommon,
    /// The challenge nonce the daemon issued, hex-encoded.
    pub nonce_hex: String,
    /// Host identity's Ed25519 signature over
    /// `challenge_host_attestation_transcript(nonce)`, hex-encoded.
    pub host_ed_attestation_hex: String,
    /// Host identity's ML-DSA-65 signature over the same transcript,
    /// hex-encoded.
    pub host_ml_dsa_attestation_hex: String,
}

/// Response to [`SignChallengeRequest`]: everything the caller needs to
/// build the `POST /auth/verify` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignChallengeResponse {
    /// The operator's Ed25519 public key, hex-encoded.
    pub ed25519_pubkey_hex: String,
    /// The operator's ML-DSA-65 public key, hex-encoded.
    pub ml_dsa_pubkey_hex: String,
    /// Ed25519 signature over the challenge transcript, hex-encoded.
    pub ed_signature_hex: String,
    /// ML-DSA-65 signature over the challenge transcript, hex-encoded.
    pub ml_dsa_signature_hex: String,
}

/// A daemon-issued, daemon-signed operator session token, exactly as the
/// console received it from `POST /auth/verify` -- relayed in full (not
/// just its `token_nonce`) so the agent can independently verify the
/// signature itself before trusting anything the token claims. Verified
/// against `SignRequestCommon.daemon_certificate`'s (now agent-verified)
/// `http_auth_ed25519_pubkey`, by reconstructing
/// `xenia_operator_proto::operator_token_canonical_bytes(...)` -- the exact
/// bytes the daemon's own signature covers, so there is no separate,
/// possibly-drifted copy of that layout on the agent side.
///
/// Relaying the full token (rather than a bare `token_nonce_hex` the
/// caller simply asserts) is what closes the same confused-deputy gap here
/// that [`DaemonIdentityCertificate`] closes for the daemon's identity
/// itself: without it, a compromised browser could ask the agent to sign
/// a consent-action/revoke transcript for a `token_nonce` it invented,
/// under an otherwise-legitimate, already-trusted daemon label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTokenDto {
    /// The enrolled operator id the daemon attributed this token to.
    pub operator_id: String,
    /// The role the daemon scoped this token to.
    pub role: OperatorRole,
    /// Unix seconds the daemon issued this token at.
    pub issued_at: u64,
    /// Unix seconds this token expires at.
    pub expires_at: u64,
    /// This token's nonce, hex-encoded -- once the token's signature is
    /// verified, this is what gets bound into the consent-action/revoke
    /// transcript.
    pub token_nonce_hex: String,
    /// The daemon's Ed25519 signature over
    /// `xenia_operator_proto::operator_token_canonical_bytes(...)` for
    /// this token's fields, hex-encoded.
    pub signature_hex: String,
    /// The daemon's ML-DSA-65 signature over the same canonical bytes,
    /// hex-encoded -- both are required, no classical-only fallback.
    pub ml_dsa_signature_hex: String,
}

/// `POST /v1/sign/consent-action` request: sign a session-bound consent
/// decision (Approve/Deny/Revoke).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignConsentActionRequest {
    /// Fields shared by every `/v1/sign/*` request.
    #[serde(flatten)]
    pub common: SignRequestCommon,
    /// Which decision is being authorized.
    pub action: ConsentAction,
    /// Caller-generated UUID for this exact decision, encoded as 32 hex
    /// characters. The agent binds it into the signature and the daemon stores
    /// it as the audit event request id, making retries and replays explicit.
    pub action_id_hex: String,
    /// Daemon-host-attested consent offer. The agent verifies both host
    /// signatures before signing, then binds the operator decision to the
    /// offer digest. The browser may relay this envelope but cannot fabricate
    /// or alter its session, viewer transcript, scope, or lifetime.
    pub attested_offer: AttestedConsentOfferV2,
    /// The operator's current daemon-issued session token, verified by the
    /// agent before its `token_nonce_hex` is trusted (see
    /// [`SignedTokenDto`]).
    pub token: SignedTokenDto,
}

/// Response to [`SignConsentActionRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignConsentActionResponse {
    /// Ed25519 signature over the consent-action transcript, hex-encoded.
    pub ed_signature_hex: String,
    /// ML-DSA-65 signature over the same transcript, hex-encoded -- both
    /// required, the daemon AND-verifies them.
    pub ml_dsa_signature_hex: String,
}

/// `POST /v1/sign/revoke` request: sign an admin's authorization to revoke
/// another operator. Privileged -- see the design doc's confirmation
/// policy; this is on the mandatory-native-confirmation list regardless of
/// how well-trusted the target daemon already is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRevokeRequest {
    /// Fields shared by every `/v1/sign/*` request.
    #[serde(flatten)]
    pub common: SignRequestCommon,
    /// The operator id being revoked.
    pub target_operator_id: String,
    /// The admin's current daemon-issued session token, verified by the
    /// agent before its `token_nonce_hex` is trusted (see
    /// [`SignedTokenDto`]).
    pub token: SignedTokenDto,
}

/// Response to [`SignRevokeRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRevokeResponse {
    /// Ed25519 signature over the revoke transcript, hex-encoded.
    pub ed_signature_hex: String,
    /// ML-DSA-65 signature over the same transcript, hex-encoded -- both
    /// required, the daemon AND-verifies them.
    pub ml_dsa_signature_hex: String,
}

/// `POST /v1/sign/replace-key` request: sign an admin's authorization to
/// replace *another operator's* enrolled key material -- operator-key
/// recovery for an operator who lost their signing key. Privileged --
/// `docs/security/SIGNER_DELEGATION_DESIGN.md` already names "recovery-key
/// or trust-root changes" on the mandatory-native-confirmation list, so
/// this is confirmed the same way [`SignRevokeRequest`] is, regardless of
/// how well-trusted the target daemon already is.
///
/// The new key material is relayed here as typed, individually-verified
/// hex fields -- not a caller-supplied transcript -- for the same reason
/// every other `/v1/sign/*` request is: the agent reconstructs
/// `xenia_operator_proto::replace_operator_key_transcript(...)` itself from
/// these fields, so a compromised browser can never smuggle bytes the
/// operator didn't actually see and confirm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignReplaceKeyRequest {
    /// Fields shared by every `/v1/sign/*` request.
    #[serde(flatten)]
    pub common: SignRequestCommon,
    /// The operator id whose key material is being replaced.
    pub target_operator_id: String,
    /// Hex Ed25519 public key of the operator's replacement identity
    /// (their freshly-generated agent's own public key).
    pub new_ed25519_pubkey_hex: String,
    /// Hex ML-DSA-65 public key of the replacement identity -- required,
    /// every operator has a standard-suite identity.
    pub new_ml_dsa_pubkey_hex: String,
    /// Hex ML-DSA-87 public key, only if the operator is re-enrolling for
    /// the high-security sealed channel -- `None`, not an empty string, if
    /// they are not.
    pub new_ml_dsa_87_pubkey_hex: Option<String>,
    /// The admin's current daemon-issued session token, verified by the
    /// agent before its `token_nonce_hex` is trusted (see
    /// [`SignedTokenDto`]).
    pub token: SignedTokenDto,
}

/// Response to [`SignReplaceKeyRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignReplaceKeyResponse {
    /// Ed25519 signature over the key-replacement transcript, hex-encoded.
    pub ed_signature_hex: String,
    /// ML-DSA-65 signature over the same transcript, hex-encoded -- both
    /// required, the daemon AND-verifies them.
    pub ml_dsa_signature_hex: String,
}

/// Domain-separation tag for an agent session token's MAC (see
/// [`agent_session_mac_message`]). Distinct from the key-derivation context
/// the agent uses to turn the raw pairing token into a MAC key -- that
/// context string lives natively in `apps/xenia-operator-agent` (the only
/// place that ever computes a MAC), since deriving keys is cryptographic
/// work this deliberately crypto-free crate doesn't do. This constant only
/// domain-separates the *message* the MAC covers, the same role
/// `xenia_operator_proto::OPERATOR_TOKEN_DOMAIN` plays for daemon session
/// tokens.
pub const AGENT_SESSION_MAC_DOMAIN: &[u8] = b"xenia-operator-agent-session-mac-v1";

/// The canonical bytes an agent session token's MAC covers. Exposed here
/// (pure byte-layout construction, no hashing) so the agent -- the only
/// party that ever computes or verifies this MAC -- has exactly one
/// implementation to reconstruct it from, mirroring
/// `xenia_operator_proto::operator_token_canonical_bytes`'s reasoning.
///
/// Layout: `AGENT_SESSION_MAC_DOMAIN || session_id(16) || issued_at(8, le)
/// || expires_at(8, le)`.
pub fn agent_session_mac_message(
    session_id: &[u8; 16],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(AGENT_SESSION_MAC_DOMAIN.len() + 16 + 8 + 8);
    b.extend_from_slice(AGENT_SESSION_MAC_DOMAIN);
    b.extend_from_slice(session_id);
    b.extend_from_slice(&issued_at.to_le_bytes());
    b.extend_from_slice(&expires_at.to_le_bytes());
    b
}

/// A short-lived bearer credential minted by `POST /v1/pair` (authenticated
/// with the raw, file-persisted pairing token) or renewed by
/// `POST /v1/session/refresh` (authenticated with a still-valid session of
/// this same shape), and presented as the `X-Agent-Session` header on every
/// other request -- replacing the raw pairing token as the credential used
/// day-to-day.
///
/// **Why**: the raw pairing token used to be sent, unbounded in time, on
/// every single request, and the console persisted it in `localStorage`
/// indefinitely -- a one-time read of `localStorage` (XSS, a malicious
/// extension, a compromised dependency) yielded indefinite ability to
/// command the agent. A session token bounds that: it expires
/// (`expires_at`), so a leaked *unused* one is only good until then, and an
/// *idle* console (closed past the TTL) can't silently keep operating --
/// it must re-present the raw pairing token to `/v1/pair` again. An
/// *actively used* console renews via `/v1/session/refresh` before expiry
/// and never needs to re-pair. There is deliberately no way to revoke a
/// single outstanding session before its natural expiry (verification is
/// stateless -- the agent keeps no session table); the only revocation
/// lever is regenerating the pairing-token file, which changes the MAC key
/// and invalidates every outstanding session at once. That's the same
/// blunt-instrument revocation the old static pairing token already had
/// (delete the token file to force a new one) -- this change only adds the
/// time bound, it doesn't regress revocation.
///
/// The four fields are carried as a single compact, dot-joined bearer
/// string (see [`AgentSessionToken::to_header_value`]/
/// [`AgentSessionToken::from_header_value`]) so both sides format/parse it
/// identically rather than risking drift between two ad hoc
/// implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionToken {
    /// Random 128 bits identifying this session, hex-encoded. Not secret by
    /// itself -- it's part of what the MAC covers, not a credential on its
    /// own -- but unique per mint so two sessions issued in the same second
    /// never collide.
    pub session_id_hex: String,
    /// Unix seconds this session was minted at.
    pub issued_at: u64,
    /// Unix seconds this session expires at.
    pub expires_at: u64,
    /// The agent's keyed-hash MAC over
    /// [`agent_session_mac_message`]`(session_id, issued_at, expires_at)`,
    /// hex-encoded. The key is derived from the raw pairing token but is
    /// never the pairing token's own bytes -- see
    /// `apps/xenia-operator-agent`'s `agent_session` module.
    pub mac_hex: String,
}

impl AgentSessionToken {
    /// Format as the single string sent in the `X-Agent-Session` header:
    /// `session_id_hex.issued_at.expires_at.mac_hex`. `.` is safe as a
    /// separator since none of the fields can themselves contain one (hex
    /// digits and decimal digits only).
    pub fn to_header_value(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.session_id_hex, self.issued_at, self.expires_at, self.mac_hex
        )
    }

    /// Parse a `X-Agent-Session` header value produced by
    /// [`to_header_value`](Self::to_header_value). Rejects anything that
    /// isn't exactly four dot-separated parts (too few, too many, or a
    /// non-numeric `issued_at`/`expires_at`) rather than guessing -- this is
    /// a shape check only, not a MAC/expiry check (see the agent's
    /// `agent_session::verify`).
    pub fn from_header_value(s: &str) -> Option<Self> {
        let mut parts = s.split('.');
        let session_id_hex = parts.next()?.to_string();
        let issued_at: u64 = parts.next()?.parse().ok()?;
        let expires_at: u64 = parts.next()?.parse().ok()?;
        let mac_hex = parts.next()?.to_string();
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            session_id_hex,
            issued_at,
            expires_at,
            mac_hex,
        })
    }
}

/// A typed error the agent returns instead of a bare HTTP status, so the
/// console can render an accurate message rather than guessing from a
/// status code alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentErrorResponse {
    /// The stable, machine-matchable error category.
    pub code: AgentErrorCode,
    /// A human-readable detail message. Not stable/matchable -- match on
    /// `code`, display `message`.
    pub message: String,
}

/// Stable error taxonomy for `/v1/sign/*` (and, later, `/v1/handshake/*`)
/// failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCode {
    /// `daemon_certificate` (or, for `/v1/sign/challenge`, the challenge
    /// host attestation; or, for `/v1/sign/consent-action`/`/v1/sign/revoke`,
    /// the relayed token) failed to verify, or verified but the resulting
    /// fingerprint isn't trusted and confirming it (TOFU or rotation)
    /// wasn't possible or was declined.
    HostNotTrusted,
    /// This request requires native confirmation and none was obtainable
    /// (no interactive terminal, and noninteractive privileged
    /// confirmation isn't enabled).
    ConfirmationRequired,
    /// The operator was asked and explicitly declined.
    ConfirmationDeclined,
    /// `schema_version` is unrecognized, or the request doesn't match its
    /// declared shape.
    BadRequest,
    /// Local-caller authentication failed (Origin/token) -- included for
    /// completeness; in practice this fails before a typed body is even
    /// parsed, at the same middleware layer as every other agent route.
    Unauthorized,
    /// Anything else.
    Internal,
}

/// Fields common to every `/v1/handshake/*` request (Track B: the
/// agent-driven sealed-channel handshake). Unlike [`SignRequestCommon`],
/// there is no `daemon_certificate` field here -- Track B doesn't need one.
/// The handshake itself *is* the host-authentication evidence: the daemon's
/// identity is proven by the signature the agent verifies inside
/// `ViewerHandshake::finish`/`ViewerHandshakeHighSec::finish`, and the
/// resulting fingerprint is checked against native trust policy the same
/// way Track A's agent-computed fingerprint is -- see
/// `apps/xenia-operator-agent`'s `handshake_state` module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequestCommon {
    /// Must equal [`SCHEMA_VERSION`], same as every `/v1/sign/*` request.
    pub schema_version: u32,
    /// The daemon endpoint (the sealed-channel WebSocket URL) the caller
    /// believes it's connecting to -- used **only** as a stable host-trust
    /// pin-store scope key, never as identity evidence. See
    /// [`SignRequestCommon::daemon_endpoint`] for why this replaced pinning
    /// by the bare fingerprint. The agent stores this alongside the
    /// pending handshake state (`/v1/handshake/begin`) so
    /// `/v1/handshake/finish` can check the *completed* handshake's
    /// authenticated fingerprint against the same scope.
    pub daemon_endpoint: String,
    /// Which sealed-channel suite this handshake negotiates
    /// (`"standard"` or `"highsec"`) -- selects
    /// `ViewerHandshake`/`ViewerHandshakeHighSec` and scopes the resulting
    /// fingerprint's host-trust pin, matching `suite`'s role in
    /// [`SignRequestCommon`].
    pub suite: String,
    /// A caller-generated id for this request. Correlation/logging only --
    /// not itself a security boundary.
    pub request_id: String,
}

/// `POST /v1/handshake/begin` request: the browser relays the daemon's
/// `HostHello` bytes (received over its own WebSocket connection to the
/// daemon -- the agent never originates that connection) and asks the
/// agent to run the viewer half of the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeBeginRequest {
    /// Fields shared by every `/v1/handshake/*` request.
    #[serde(flatten)]
    pub common: HandshakeRequestCommon,
    /// The daemon's `HostHello` message, exactly as received, hex-encoded.
    pub host_hello_hex: String,
}

/// Response to [`HandshakeBeginRequest`]: the bytes to relay back to the
/// daemon, and an opaque id identifying the now-pending handshake state the
/// agent is holding (consumed by [`HandshakeFinishRequest`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeBeginResponse {
    /// Identifies this pending handshake for the matching
    /// `/v1/handshake/finish` call, hex-encoded (at least 128 random
    /// bits). Single-use and short-lived -- see `handshake_state`'s module
    /// doc comment for the exact lifetime/concurrency limits.
    pub handshake_id_hex: String,
    /// The viewer's response message, to relay to the daemon over the
    /// browser's own connection, hex-encoded.
    pub viewer_response_hex: String,
    /// How many seconds from now this pending handshake expires --
    /// informational only (the agent enforces this server-side
    /// regardless); a caller doesn't need to track it precisely.
    pub expires_in_secs: u64,
}

/// `POST /v1/handshake/finish` request: the browser relays the daemon's
/// `HostFinalize` bytes. No daemon evidence or typed action fields are
/// needed here beyond `handshake_id_hex` -- unlike Track A, there's nothing
/// else to bind a transcript to; the handshake's own cryptography is the
/// entire authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeFinishRequest {
    /// Must equal [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The id returned by the matching `/v1/handshake/begin` call.
    pub handshake_id_hex: String,
    /// The daemon's `HostFinalize` message, exactly as received,
    /// hex-encoded.
    pub host_finalize_hex: String,
}

/// Response to [`HandshakeFinishRequest`]: the session material the
/// browser needs to seal/open envelopes on its own -- no long-term
/// identity material. Returned only once the authenticated host identity
/// (derived from completing the handshake, not asserted by the caller)
/// satisfies native trust policy; see `handshake_state`'s module doc
/// comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeFinishResponse {
    /// The derived AEAD key for sealing/opening application-layer
    /// envelopes on this channel, hex-encoded.
    pub aead_key_hex: String,
    /// The root key for deriving a later forward-secrecy rekey, hex-encoded
    /// (see `xenia_wire::operator_rekey`).
    pub rekey_root_hex: String,
    /// The handshake transcript hash, hex-encoded -- carried through for
    /// completeness/future evidence export; not currently consumed by any
    /// browser-side code.
    pub transcript_hash_hex: String,
    /// The daemon's authenticated host-identity fingerprint, hex-encoded --
    /// the same value the agent already checked against native trust
    /// policy before returning this response.
    pub authenticated_host_fingerprint_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_certificate() -> DaemonIdentityCertificate {
        DaemonIdentityCertificate {
            host_ed25519_pubkey: "11".repeat(32),
            host_ml_dsa_pubkey: "22".repeat(1952),
            http_auth_ed25519_pubkey: "33".repeat(32),
            http_auth_ml_dsa_pubkey: "77".repeat(1952),
            host_ed_signature: "44".repeat(64),
            host_ml_dsa_signature: "55".repeat(3309),
        }
    }

    fn test_token() -> SignedTokenDto {
        SignedTokenDto {
            operator_id: "alice".to_string(),
            role: OperatorRole::Admin,
            issued_at: 1000,
            expires_at: 2000,
            token_nonce_hex: "ee".repeat(16),
            signature_hex: "66".repeat(64),
            ml_dsa_signature_hex: "88".repeat(3309),
        }
    }

    #[test]
    fn sign_challenge_request_round_trips_and_flattens_common_fields() {
        let req = SignChallengeRequest {
            common: SignRequestCommon {
                schema_version: SCHEMA_VERSION,
                daemon_certificate: test_certificate(),
                daemon_endpoint: "https://daemon.test.example".to_string(),
                suite: "standard".to_string(),
                request_id: "req-1".to_string(),
            },
            nonce_hex: "bb".repeat(32),
            host_ed_attestation_hex: "77".repeat(64),
            host_ml_dsa_attestation_hex: "88".repeat(3309),
        };
        let json = serde_json::to_string(&req).unwrap();
        // `#[serde(flatten)]` means the common fields sit alongside
        // nonce_hex at the top level, not nested under a "common" key --
        // that's the wire shape the agent expects to parse.
        assert!(json.contains(&format!("\"schema_version\":{SCHEMA_VERSION}")));
        assert!(json.contains("\"nonce_hex\""));
        assert!(json.contains("\"daemon_certificate\""));
        assert!(!json.contains("\"common\""));
        let parsed: SignChallengeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn consent_action_request_carries_the_shared_consent_action_enum_and_full_token() {
        let req = SignConsentActionRequest {
            common: SignRequestCommon {
                schema_version: SCHEMA_VERSION,
                daemon_certificate: test_certificate(),
                daemon_endpoint: "https://daemon.test.example".to_string(),
                suite: "highsec".to_string(),
                request_id: "req-2".to_string(),
            },
            action: ConsentAction::Approve,
            action_id_hex: "ab".repeat(16),
            attested_offer: AttestedConsentOfferV2 {
                offer: xenia_operator_proto::ConsentOfferV2::new(
                    [0xddu8; 16],
                    [0x77u8; 32],
                    ConsentScopeV1::screen_only(),
                    100,
                    200,
                ),
                host_ed_signature_hex: "11".repeat(64),
                host_ml_dsa_signature_hex: "22".repeat(3309),
            },
            token: test_token(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"Approve\""));
        assert!(json.contains("\"token\""));
        assert!(json.contains("\"attested_offer\""));
        assert!(json.contains("\"ScreenStream\""));
        let parsed: SignConsentActionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, ConsentAction::Approve);
        assert_eq!(
            parsed.attested_offer.offer.scope,
            ConsentScopeV1::screen_only()
        );
        assert_eq!(
            parsed.attested_offer.offer.session_transcript_hash,
            [0x77; 32]
        );
        assert_eq!(parsed.token, req.token);
    }

    #[test]
    fn agent_session_mac_message_layout_is_exact_and_field_bound() {
        let id_a = [0x11u8; 16];
        let id_b = [0x22u8; 16];
        let m = agent_session_mac_message(&id_a, 1000, 2000);
        assert_eq!(
            &m[..AGENT_SESSION_MAC_DOMAIN.len()],
            AGENT_SESSION_MAC_DOMAIN
        );
        assert_eq!(m.len(), AGENT_SESSION_MAC_DOMAIN.len() + 16 + 8 + 8);
        // Every field the MAC covers actually changes the bytes -- a
        // forged token can't reuse another session's MAC by only changing
        // the field(s) the verifier doesn't happen to check.
        assert_ne!(m, agent_session_mac_message(&id_b, 1000, 2000));
        assert_ne!(m, agent_session_mac_message(&id_a, 1001, 2000));
        assert_ne!(m, agent_session_mac_message(&id_a, 1000, 2001));
    }

    #[test]
    fn agent_session_token_header_value_round_trips() {
        let token = AgentSessionToken {
            session_id_hex: "aa".repeat(16),
            issued_at: 1000,
            expires_at: 4600,
            mac_hex: "bb".repeat(32),
        };
        let header = token.to_header_value();
        assert_eq!(
            header,
            format!("{}.1000.4600.{}", "aa".repeat(16), "bb".repeat(32))
        );
        let parsed = AgentSessionToken::from_header_value(&header).unwrap();
        assert_eq!(parsed, token);
    }

    #[test]
    fn agent_session_token_header_value_rejects_malformed_shapes() {
        // Too few parts.
        assert!(AgentSessionToken::from_header_value("a.1000.4600").is_none());
        // Too many parts (trailing garbage appended by a tampering attempt).
        assert!(AgentSessionToken::from_header_value("a.1000.4600.bb.extra").is_none());
        // Non-numeric issued_at/expires_at.
        assert!(AgentSessionToken::from_header_value("a.not-a-number.4600.bb").is_none());
        assert!(AgentSessionToken::from_header_value("a.1000.not-a-number.bb").is_none());
        // Empty string.
        assert!(AgentSessionToken::from_header_value("").is_none());
    }

    #[test]
    fn error_code_serializes_snake_case_and_round_trips() {
        let err = AgentErrorResponse {
            code: AgentErrorCode::HostNotTrusted,
            message: "fingerprint not pinned".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"host_not_trusted\""));
        let parsed: AgentErrorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, AgentErrorCode::HostNotTrusted);
    }

    #[test]
    fn handshake_begin_request_round_trips_and_flattens_common_fields() {
        let req = HandshakeBeginRequest {
            common: HandshakeRequestCommon {
                schema_version: SCHEMA_VERSION,
                daemon_endpoint: "wss://daemon.test.example/operator".to_string(),
                suite: "standard".to_string(),
                request_id: "req-3".to_string(),
            },
            host_hello_hex: "aa".repeat(40),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"host_hello_hex\""));
        assert!(!json.contains("\"common\""));
        let parsed: HandshakeBeginRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn handshake_finish_request_and_response_round_trip() {
        let req = HandshakeFinishRequest {
            schema_version: SCHEMA_VERSION,
            handshake_id_hex: "bb".repeat(16),
            host_finalize_hex: "cc".repeat(40),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HandshakeFinishRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);

        let resp = HandshakeFinishResponse {
            aead_key_hex: "dd".repeat(32),
            rekey_root_hex: "ee".repeat(32),
            transcript_hash_hex: "ff".repeat(32),
            authenticated_host_fingerprint_hex: "11".repeat(32),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HandshakeFinishResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }
}
