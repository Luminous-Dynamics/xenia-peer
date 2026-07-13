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
//! Handshake-delegation (Track B: `/v1/handshake/begin` /
//! `/v1/handshake/finish`) types land in a later addition to this crate,
//! once that track is actually built -- see the design doc's recommended
//! PR sequence.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

pub use xenia_operator_proto::ConsentAction;

/// Current schema version for the `/v1/sign/*` request/response shapes.
/// Bump when a breaking change to any request/response shape ships; the
/// agent should refuse a request whose `schema_version` it doesn't
/// recognize rather than guessing at compatibility.
pub const SCHEMA_VERSION: u32 = 1;

/// Fields common to every `/v1/sign/*` request: who the caller believes
/// they are, which daemon they're targeting, and enough to correlate a
/// request through logs. None of these fields are secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequestCommon {
    /// Must equal [`SCHEMA_VERSION`] the agent was built against, or the
    /// agent refuses the request rather than guessing at compatibility.
    pub schema_version: u32,
    /// Hex-encoded BLAKE3 fingerprint of the daemon this signature is
    /// intended to authenticate to. Checked against the agent's native
    /// host-trust policy (`host_trust::HostTrustStore`) before anything is
    /// signed -- see the design doc's "typed transcripts are not enough"
    /// section for why this field exists at all.
    pub daemon_fingerprint_hex: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignChallengeRequest {
    /// Fields shared by every `/v1/sign/*` request.
    #[serde(flatten)]
    pub common: SignRequestCommon,
    /// The challenge nonce the daemon issued, hex-encoded.
    pub nonce_hex: String,
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

/// `POST /v1/sign/consent-action` request: sign a session-bound consent
/// decision (Approve/Deny/Revoke).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignConsentActionRequest {
    /// Fields shared by every `/v1/sign/*` request.
    #[serde(flatten)]
    pub common: SignRequestCommon,
    /// Which decision is being authorized.
    pub action: ConsentAction,
    /// The daemon session this decision is bound to, hex-encoded.
    pub session_id_hex: String,
    /// The operator's current daemon-issued session token's nonce,
    /// hex-encoded -- binds this signature to that exact token so it can't
    /// be replayed against a different one.
    pub token_nonce_hex: String,
}

/// Response to [`SignConsentActionRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignConsentActionResponse {
    /// Ed25519 signature over the consent-action transcript, hex-encoded.
    pub ed_signature_hex: String,
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
    /// The admin's current daemon-issued session token's nonce,
    /// hex-encoded -- binds this signature to that exact token.
    pub token_nonce_hex: String,
}

/// Response to [`SignRevokeRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRevokeResponse {
    /// Ed25519 signature over the revoke transcript, hex-encoded.
    pub ed_signature_hex: String,
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
    /// `daemon_fingerprint_hex` isn't trusted, and confirming it (TOFU or
    /// rotation) wasn't possible or was declined.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_challenge_request_round_trips_and_flattens_common_fields() {
        let req = SignChallengeRequest {
            common: SignRequestCommon {
                schema_version: SCHEMA_VERSION,
                daemon_fingerprint_hex: "aa".repeat(32),
                suite: "standard".to_string(),
                request_id: "req-1".to_string(),
            },
            nonce_hex: "bb".repeat(32),
        };
        let json = serde_json::to_string(&req).unwrap();
        // `#[serde(flatten)]` means the common fields sit alongside
        // nonce_hex at the top level, not nested under a "common" key --
        // that's the wire shape the agent expects to parse.
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"nonce_hex\""));
        assert!(!json.contains("\"common\""));
        let parsed: SignChallengeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn consent_action_request_carries_the_shared_consent_action_enum() {
        let req = SignConsentActionRequest {
            common: SignRequestCommon {
                schema_version: SCHEMA_VERSION,
                daemon_fingerprint_hex: "cc".repeat(32),
                suite: "highsec".to_string(),
                request_id: "req-2".to_string(),
            },
            action: ConsentAction::Approve,
            session_id_hex: "dd".repeat(16),
            token_nonce_hex: "ee".repeat(16),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"Approve\""));
        let parsed: SignConsentActionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, ConsentAction::Approve);
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
}
