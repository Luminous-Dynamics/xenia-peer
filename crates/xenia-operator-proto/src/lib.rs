// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # xenia-operator-proto
//!
//! The **shared** operator-RBAC protocol: the role/action model and the exact
//! domain-separated byte transcripts an operator signs. Both the `xenia-peer`
//! daemon (which verifies) and the `sovereign-admin` browser console (which
//! signs) depend on this crate, so a signature produced in the browser is
//! byte-identical to what the daemon expects. If these transcripts lived in
//! two places they would drift; here they cannot.
//!
//! This crate is deliberately **crypto-free and I/O-free** — just roles,
//! actions, and `Vec<u8>` transcripts — so it compiles unchanged for
//! `wasm32-unknown-unknown` (the console) and native (the daemon + tests).
//! Each side brings its own Ed25519 / ML-DSA implementation and signs/verifies
//! the bytes this crate produces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Domain-separation tag for the challenge an operator signs to prove key
/// possession. Bump the `-vN` suffix on any breaking transcript change.
pub const CHALLENGE_DOMAIN: &[u8] = b"xenia-operator-auth-challenge-v1";

/// Domain-separation tag for a per-consent-action signature.
pub const CONSENT_ACTION_DOMAIN: &[u8] = b"xenia-operator-consent-action-v1";

/// Domain-separation tag for an admin's signature authorizing the revocation of
/// another operator (the `/operator/revoke` admin action).
pub const REVOKE_OPERATOR_DOMAIN: &[u8] = b"xenia-operator-revoke-operator-v1";

/// Domain-separation tag for the daemon's *host identity* delegating trust
/// to its separate HTTP-auth signing key (see [`DaemonIdentityCertificate`]).
pub const DAEMON_DELEGATION_DOMAIN: &[u8] = b"xenia-daemon-identity-delegation-v1";

/// Domain-separation tag for the daemon's host-identity attestation over an
/// issued `/auth/challenge` nonce (see [`challenge_host_attestation_transcript`]).
pub const CHALLENGE_HOST_ATTESTATION_DOMAIN: &[u8] = b"xenia-challenge-host-attestation-v1";

/// Domain-separation tag for an operator session token's daemon signature
/// (see [`operator_token_canonical_bytes`]).
pub const OPERATOR_TOKEN_DOMAIN: &[u8] = b"xenia-operator-token-v1";

/// An operator's role. Strictly hierarchical: a higher role can do everything
/// a lower one can, plus more (see [`OperatorRole::rank`]). Serializes to the
/// variant name (`"Viewer"`, `"Admin"`, …) — the console gates its UI on the
/// same value the daemon authorizes against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorRole {
    /// Read-only: see inventory and the audit ledger.
    Viewer,
    /// Viewer + approve/deny/revoke a consent ceremony.
    Approver,
    /// Approver + initiate sessions.
    Operator,
    /// Operator + enroll/revoke operators, change trust policy, rotate keys.
    Admin,
}

impl OperatorRole {
    /// Ordering rank. Authorization is `actor.rank() >= action.min_role().rank()`.
    pub fn rank(self) -> u8 {
        match self {
            OperatorRole::Viewer => 0,
            OperatorRole::Approver => 1,
            OperatorRole::Operator => 2,
            OperatorRole::Admin => 3,
        }
    }

    /// Whether this role is permitted to perform `action`. Total and
    /// fail-closed by construction — identical logic on daemon and console.
    pub fn permits(self, action: OperatorAction) -> bool {
        self.rank() >= action.min_role().rank()
    }

    /// The role's stable string name (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            OperatorRole::Viewer => "Viewer",
            OperatorRole::Approver => "Approver",
            OperatorRole::Operator => "Operator",
            OperatorRole::Admin => "Admin",
        }
    }
}

/// A privileged operator action the daemon can be asked to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorAction {
    /// View device/session inventory.
    ViewInventory,
    /// Read the audit ledger.
    ReadAudit,
    /// Approve a consent ceremony.
    ApproveConsent,
    /// Deny a consent ceremony.
    DenyConsent,
    /// Revoke consent for a live session.
    RevokeConsent,
    /// Initiate a new session.
    InitiateSession,
    /// Change the sealed-evidence / consent trust policy.
    ChangePolicy,
    /// Enroll or revoke an operator.
    EnrollOperator,
    /// Rotate the host / consent signing keys.
    RotateKeys,
}

impl OperatorAction {
    /// The minimum role that may perform this action.
    pub fn min_role(self) -> OperatorRole {
        match self {
            OperatorAction::ViewInventory | OperatorAction::ReadAudit => OperatorRole::Viewer,
            OperatorAction::ApproveConsent
            | OperatorAction::DenyConsent
            | OperatorAction::RevokeConsent => OperatorRole::Approver,
            OperatorAction::InitiateSession => OperatorRole::Operator,
            OperatorAction::ChangePolicy
            | OperatorAction::EnrollOperator
            | OperatorAction::RotateKeys => OperatorRole::Admin,
        }
    }
}

/// Whether `role` is permitted to perform `action`. Free-function form of
/// [`OperatorRole::permits`], kept for call-site readability.
pub fn role_permits(role: OperatorRole, action: OperatorAction) -> bool {
    role.permits(action)
}

/// A consent decision an operator can authorize on a live/pending session.
/// Serializes to the variant name (`"Approve"`, `"Deny"`, `"Revoke"`),
/// byte-identical to [`Self::as_str`] -- used directly (not just via
/// `as_str`) by `xenia-operator-agent-proto`'s typed signing requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentAction {
    /// Grant the session.
    Approve,
    /// Refuse the session.
    Deny,
    /// End a session already granted (mid-session revocation).
    Revoke,
}

impl ConsentAction {
    /// The one-byte tag bound into the signed transcript. Stable wire value —
    /// do not renumber.
    pub fn tag(self) -> u8 {
        match self {
            ConsentAction::Approve => 1,
            ConsentAction::Deny => 2,
            ConsentAction::Revoke => 3,
        }
    }

    /// The RBAC action a consent decision requires.
    pub fn required_permission(self) -> OperatorAction {
        match self {
            ConsentAction::Approve => OperatorAction::ApproveConsent,
            ConsentAction::Deny => OperatorAction::DenyConsent,
            ConsentAction::Revoke => OperatorAction::RevokeConsent,
        }
    }

    /// The stable wire string for this action.
    pub fn as_str(self) -> &'static str {
        match self {
            ConsentAction::Approve => "Approve",
            ConsentAction::Deny => "Deny",
            ConsentAction::Revoke => "Revoke",
        }
    }

    /// Parse the wire string back into an action (exact, case-sensitive).
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "Approve" => Some(ConsentAction::Approve),
            "Deny" => Some(ConsentAction::Deny),
            "Revoke" => Some(ConsentAction::Revoke),
            _ => None,
        }
    }
}

/// The transcript an operator signs to prove possession of their key for a
/// given challenge. Domain-separated and bound to the exact keys presented, so
/// a signature can't be replayed against a different challenge or key.
///
/// Layout: `CHALLENGE_DOMAIN || nonce(32) || ed_pubkey(32) || ml_dsa_pubkey`.
pub fn challenge_transcript(
    nonce: &[u8; 32],
    ed_pubkey: &[u8; 32],
    ml_dsa_pubkey: &[u8],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(CHALLENGE_DOMAIN.len() + 32 + 32 + ml_dsa_pubkey.len());
    t.extend_from_slice(CHALLENGE_DOMAIN);
    t.extend_from_slice(nonce);
    t.extend_from_slice(ed_pubkey);
    t.extend_from_slice(ml_dsa_pubkey);
    t
}

/// The bytes an operator signs to authorize a specific consent action. Binds
/// the action to the exact session and token, so a captured signature can't be
/// replayed for a different action, session, or token.
///
/// Layout: `CONSENT_ACTION_DOMAIN || action.tag()(1) || session_id(16) || token_nonce(16)`.
pub fn consent_action_transcript(
    action: ConsentAction,
    session_id: &[u8; 16],
    token_nonce: &[u8; 16],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(CONSENT_ACTION_DOMAIN.len() + 1 + 16 + 16);
    t.extend_from_slice(CONSENT_ACTION_DOMAIN);
    t.push(action.tag());
    t.extend_from_slice(session_id);
    t.extend_from_slice(token_nonce);
    t
}

/// The bytes an Admin signs to authorize revoking `target_operator_id`. Bound to
/// the admin's current token (via `token_nonce`) so a captured signature can't
/// be replayed against a different token; the target id is length-prefixed so it
/// can't be ambiguously concatenated with the trailing nonce.
///
/// Layout: `REVOKE_OPERATOR_DOMAIN || len(target)(4, be) || target || token_nonce(16)`.
pub fn revoke_operator_transcript(target_operator_id: &str, token_nonce: &[u8; 16]) -> Vec<u8> {
    let target = target_operator_id.as_bytes();
    let mut t = Vec::with_capacity(REVOKE_OPERATOR_DOMAIN.len() + 4 + target.len() + 16);
    t.extend_from_slice(REVOKE_OPERATOR_DOMAIN);
    t.extend_from_slice(&(target.len() as u32).to_be_bytes());
    t.extend_from_slice(target);
    t.extend_from_slice(token_nonce);
    t
}

/// The bytes the daemon's *host identity* signs to delegate trust to its
/// separate HTTP-auth signing identity: "this Ed25519 key and this ML-DSA-65
/// key together issue this daemon's HTTP auth tokens and challenge
/// attestations." Exists because the daemon deliberately uses different keys
/// for different roles -- `host_identity_key_path` (the sealed-channel
/// identity, the one thing peers already pin) and `operator_key_path`
/// (`daemon_key`, which signs HTTP session tokens -- and the ledger's hash
/// chain, so it can't simply be replaced wholesale) -- and a caller with no
/// live connection to the daemon (e.g. the operator agent) has no other way
/// to learn that the HTTP-auth identity is genuinely vouched for by the host
/// identity. See [`DaemonIdentityCertificate`].
///
/// `http_auth_ml_dsa_pubkey` is a *separate* key from `daemon_key`'s own
/// Ed25519 key, not a second algorithm bolted onto the same keypair --
/// `xenia-peer`'s `operator_key_path` predates this hybridization and stays
/// Ed25519-only (see above), so the ML-DSA half of HTTP-auth token signing
/// lives in its own dedicated `xenia_handshake::MlDsaIdentity`.
///
/// Layout: `DAEMON_DELEGATION_DOMAIN || http_auth_ed25519_pubkey(32) ||
/// http_auth_ml_dsa_pubkey(1952)`.
pub fn daemon_delegation_transcript(
    http_auth_ed25519_pubkey: &[u8; 32],
    http_auth_ml_dsa_pubkey: &[u8],
) -> Vec<u8> {
    let mut t =
        Vec::with_capacity(DAEMON_DELEGATION_DOMAIN.len() + 32 + http_auth_ml_dsa_pubkey.len());
    t.extend_from_slice(DAEMON_DELEGATION_DOMAIN);
    t.extend_from_slice(http_auth_ed25519_pubkey);
    t.extend_from_slice(http_auth_ml_dsa_pubkey);
    t
}

/// The bytes the daemon's host identity signs to attest that it issued a
/// specific `/auth/challenge` nonce. Lets a caller with no live connection
/// to the daemon (the operator agent) verify that a *specific* nonce really
/// came from a host it trusts, rather than trusting a caller-supplied label
/// detached from the bytes actually being signed.
///
/// Layout: `CHALLENGE_HOST_ATTESTATION_DOMAIN || nonce(32)`.
pub fn challenge_host_attestation_transcript(nonce: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(CHALLENGE_HOST_ATTESTATION_DOMAIN.len() + 32);
    t.extend_from_slice(CHALLENGE_HOST_ATTESTATION_DOMAIN);
    t.extend_from_slice(nonce);
    t
}

/// The canonical bytes an operator session token's daemon signature covers.
/// Exposed here (rather than living only inside the daemon's own auth
/// module) so a caller that never talks to the daemon directly -- the
/// operator agent, verifying a token the browser relayed to it -- can
/// reconstruct the exact same bytes and independently check the token's
/// signature, with no risk of the two implementations drifting apart.
///
/// Layout: `OPERATOR_TOKEN_DOMAIN || len(operator_id)(8, le) || operator_id
/// || role_tag(1) || issued_at(8, le) || expires_at(8, le) || token_nonce(16)`.
pub fn operator_token_canonical_bytes(
    operator_id: &str,
    role: OperatorRole,
    issued_at: u64,
    expires_at: u64,
    token_nonce: &[u8; 16],
) -> Vec<u8> {
    let id = operator_id.as_bytes();
    let mut b = Vec::with_capacity(OPERATOR_TOKEN_DOMAIN.len() + 8 + id.len() + 1 + 8 + 8 + 16);
    b.extend_from_slice(OPERATOR_TOKEN_DOMAIN);
    b.extend_from_slice(&(id.len() as u64).to_le_bytes());
    b.extend_from_slice(id);
    b.push(role_tag(role));
    b.extend_from_slice(&issued_at.to_le_bytes());
    b.extend_from_slice(&expires_at.to_le_bytes());
    b.extend_from_slice(token_nonce);
    b
}

/// Stable one-byte wire tag for a role, used inside
/// [`operator_token_canonical_bytes`]. Not the same as any serde
/// representation -- this is a fixed-width tag inside a signed byte
/// transcript, not JSON.
fn role_tag(role: OperatorRole) -> u8 {
    match role {
        OperatorRole::Viewer => 0,
        OperatorRole::Approver => 1,
        OperatorRole::Operator => 2,
        OperatorRole::Admin => 3,
    }
}

/// The daemon's host identity vouching for its separate HTTP-auth signing
/// key (see [`daemon_delegation_transcript`]). Computed once by the daemon
/// at startup (both keys are static for the process's lifetime) and served
/// over `GET /auth/daemon-identity` -- no authentication required, since
/// this *is* the daemon's own public, independently-verifiable identity
/// evidence, the same trust model as the sealed-channel handshake's host
/// identity.
///
/// A caller verifies both signatures against the presented host public
/// keys, then computes the daemon's fingerprint itself via
/// `xenia_handshake::host_identity_fingerprint(host_ed25519_pubkey,
/// host_ml_dsa_pubkey)` -- never accepting a fingerprint asserted directly
/// by an untrusted caller. Both Ed25519 and ML-DSA-65 signatures are
/// required (no classical-only fallback), matching this project's hybrid
/// posture everywhere else a daemon or peer identity is proven.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonIdentityCertificate {
    /// The daemon's host (sealed-channel) identity Ed25519 public key, hex.
    pub host_ed25519_pubkey: String,
    /// The daemon's host (sealed-channel) identity ML-DSA-65 public key, hex.
    pub host_ml_dsa_pubkey: String,
    /// The daemon's separate HTTP-auth signing identity's Ed25519 public
    /// key, hex -- together with `http_auth_ml_dsa_pubkey`, the pair that
    /// actually signs issued session tokens and challenge attestations.
    pub http_auth_ed25519_pubkey: String,
    /// The daemon's separate HTTP-auth signing identity's ML-DSA-65 public
    /// key, hex. A distinct key from `http_auth_ed25519_pubkey`'s pair, not
    /// the same key under a different algorithm -- see
    /// [`daemon_delegation_transcript`]'s doc comment for why.
    pub http_auth_ml_dsa_pubkey: String,
    /// Host identity's Ed25519 signature over
    /// `daemon_delegation_transcript(http_auth_ed25519_pubkey,
    /// http_auth_ml_dsa_pubkey)`, hex.
    pub host_ed_signature: String,
    /// Host identity's ML-DSA-65 signature over the same transcript, hex.
    pub host_ml_dsa_signature: String,
}

/// The daemon's `--operators-file` enrollment record shape, shared so the
/// console (which generates one per identity) and the daemon (which parses
/// it) can never drift on field names or casing -- the exact drift that let
/// the console's high-security identity go unenrollable: the console had no
/// shared type to generate the record from, so it never emitted an
/// `ml_dsa_87_pubkey` field, and the daemon's ad hoc parser only ever
/// recognized the ML-DSA-65 key length.
///
/// `ml_dsa_pubkey` (ML-DSA-65) is required -- every operator has a standard
/// identity, since the HTTP challenge/response auth ceremony
/// (`/auth/challenge` + `/auth/verify`) always uses it regardless of which
/// suite the sealed channel later negotiates. `ml_dsa_87_pubkey` is optional:
/// only an operator who will use the high-security sealed channel needs one
/// enrolled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorEnrollmentRecord {
    /// The operator id an admin assigns when enrolling this identity.
    pub operator_id: String,
    /// Ed25519 public key, hex-encoded.
    pub ed25519_pubkey: String,
    /// ML-DSA-65 public key, hex-encoded (the standard-suite identity).
    pub ml_dsa_pubkey: String,
    /// ML-DSA-87 public key, hex-encoded (the high-security-suite identity).
    /// Present only if this operator has enrolled for the high-security
    /// sealed channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_87_pubkey: Option<String>,
    /// The role this enrollment grants.
    pub role: OperatorRole,
}

impl OperatorEnrollmentRecord {
    /// Serialize to the exact JSON object shape the daemon's
    /// `--operators-file` `operators` array element expects.
    pub fn to_json_string(&self) -> String {
        // `OperatorEnrollmentRecord` derives `Serialize` with no custom
        // field renaming, so this can't drift from the struct's own field
        // names -- unlike hand-built `serde_json::json!` call sites, which
        // is exactly how the console's `ml_dsa_87_pubkey` field went missing
        // in the first place.
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_hierarchy_is_fail_closed() {
        use OperatorAction::*;
        use OperatorRole::*;
        assert!(Viewer.permits(ViewInventory));
        assert!(Viewer.permits(ReadAudit));
        assert!(!Viewer.permits(ApproveConsent));
        assert!(Approver.permits(RevokeConsent));
        assert!(!Approver.permits(InitiateSession));
        assert!(Operator.permits(InitiateSession));
        assert!(!Operator.permits(EnrollOperator));
        for action in [
            ViewInventory,
            ReadAudit,
            ApproveConsent,
            DenyConsent,
            RevokeConsent,
            InitiateSession,
            ChangePolicy,
            EnrollOperator,
            RotateKeys,
        ] {
            assert!(Admin.permits(action), "admin denied {action:?}");
        }
        // free-fn form agrees with the method
        assert_eq!(
            role_permits(Approver, ApproveConsent),
            Approver.permits(ApproveConsent)
        );
    }

    #[test]
    fn role_serde_is_the_variant_name() {
        assert_eq!(
            serde_json::to_string(&OperatorRole::Admin).unwrap(),
            "\"Admin\""
        );
        let r: OperatorRole = serde_json::from_str("\"Approver\"").unwrap();
        assert_eq!(r, OperatorRole::Approver);
        assert_eq!(OperatorRole::Operator.as_str(), "Operator");
    }

    #[test]
    fn enrollment_record_round_trips_with_and_without_the_highsec_key() {
        let with_highsec = OperatorEnrollmentRecord {
            operator_id: "alice".to_string(),
            ed25519_pubkey: "aa".repeat(32),
            ml_dsa_pubkey: "bb".repeat(1952),
            ml_dsa_87_pubkey: Some("cc".repeat(2592)),
            role: OperatorRole::Admin,
        };
        let json = with_highsec.to_json_string();
        assert!(json.contains("ml_dsa_87_pubkey"));
        let parsed: OperatorEnrollmentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, with_highsec);

        let without_highsec = OperatorEnrollmentRecord {
            ml_dsa_87_pubkey: None,
            ..with_highsec
        };
        let json = without_highsec.to_json_string();
        // Omitted, not null -- so a daemon parser that only checks
        // `.contains_key(...)` (rather than treating an explicit null as
        // "absent") can't be tricked either way.
        assert!(!json.contains("ml_dsa_87_pubkey"));
        let parsed: OperatorEnrollmentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, without_highsec);
    }

    #[test]
    fn consent_action_tags_and_permissions_are_stable() {
        assert_eq!(ConsentAction::Approve.tag(), 1);
        assert_eq!(ConsentAction::Deny.tag(), 2);
        assert_eq!(ConsentAction::Revoke.tag(), 3);
        assert_eq!(
            ConsentAction::Revoke.required_permission(),
            OperatorAction::RevokeConsent
        );
        assert_eq!(
            ConsentAction::from_wire("Approve"),
            Some(ConsentAction::Approve)
        );
        assert_eq!(ConsentAction::from_wire("approve"), None);
        assert_eq!(ConsentAction::from_wire("nonsense"), None);
        assert_eq!(ConsentAction::Deny.as_str(), "Deny");
    }

    #[test]
    fn consent_action_serde_is_the_variant_name() {
        assert_eq!(
            serde_json::to_string(&ConsentAction::Revoke).unwrap(),
            "\"Revoke\""
        );
        let a: ConsentAction = serde_json::from_str("\"Deny\"").unwrap();
        assert_eq!(a, ConsentAction::Deny);
    }

    #[test]
    fn challenge_transcript_layout_is_exact() {
        let nonce = [0xABu8; 32];
        let ed = [0xCDu8; 32];
        let ml = vec![0xEFu8; 7];
        let t = challenge_transcript(&nonce, &ed, &ml);
        assert_eq!(&t[..CHALLENGE_DOMAIN.len()], CHALLENGE_DOMAIN);
        let mut off = CHALLENGE_DOMAIN.len();
        assert_eq!(&t[off..off + 32], &nonce);
        off += 32;
        assert_eq!(&t[off..off + 32], &ed);
        off += 32;
        assert_eq!(&t[off..], &ml[..]);
        assert_eq!(t.len(), CHALLENGE_DOMAIN.len() + 32 + 32 + 7);
    }

    #[test]
    fn consent_transcript_layout_is_exact_and_action_bound() {
        let sid = [0x11u8; 16];
        let tn = [0x22u8; 16];
        let approve = consent_action_transcript(ConsentAction::Approve, &sid, &tn);
        let revoke = consent_action_transcript(ConsentAction::Revoke, &sid, &tn);
        // Same session/token, different action -> different bytes (can't replay).
        assert_ne!(approve, revoke);
        assert_eq!(
            &approve[..CONSENT_ACTION_DOMAIN.len()],
            CONSENT_ACTION_DOMAIN
        );
        assert_eq!(approve[CONSENT_ACTION_DOMAIN.len()], 1);
        assert_eq!(revoke[CONSENT_ACTION_DOMAIN.len()], 3);
        assert_eq!(approve.len(), CONSENT_ACTION_DOMAIN.len() + 1 + 16 + 16);
    }

    #[test]
    fn daemon_delegation_transcript_layout_is_exact_and_key_bound() {
        let ed_a = [0x33u8; 32];
        let ed_b = [0x44u8; 32];
        let ml_a = vec![0x55u8; 1952];
        let ml_b = vec![0x66u8; 1952];
        let t = daemon_delegation_transcript(&ed_a, &ml_a);
        assert_eq!(
            &t[..DAEMON_DELEGATION_DOMAIN.len()],
            DAEMON_DELEGATION_DOMAIN
        );
        assert_eq!(
            &t[DAEMON_DELEGATION_DOMAIN.len()..DAEMON_DELEGATION_DOMAIN.len() + 32],
            &ed_a
        );
        assert_eq!(&t[DAEMON_DELEGATION_DOMAIN.len() + 32..], ml_a.as_slice());
        assert_eq!(t.len(), DAEMON_DELEGATION_DOMAIN.len() + 32 + 1952);
        // Either delegated key changing -> different bytes (a certificate
        // for one HTTP-auth identity can't be replayed as vouching for a
        // different Ed25519 key, a different ML-DSA key, or both).
        assert_ne!(t, daemon_delegation_transcript(&ed_b, &ml_a));
        assert_ne!(t, daemon_delegation_transcript(&ed_a, &ml_b));
    }

    #[test]
    fn challenge_host_attestation_transcript_layout_is_exact_and_nonce_bound() {
        let nonce_a = [0x55u8; 32];
        let nonce_b = [0x66u8; 32];
        let t = challenge_host_attestation_transcript(&nonce_a);
        assert_eq!(
            &t[..CHALLENGE_HOST_ATTESTATION_DOMAIN.len()],
            CHALLENGE_HOST_ATTESTATION_DOMAIN
        );
        assert_eq!(&t[CHALLENGE_HOST_ATTESTATION_DOMAIN.len()..], &nonce_a);
        assert_eq!(t.len(), CHALLENGE_HOST_ATTESTATION_DOMAIN.len() + 32);
        // An attestation over one nonce can't be replayed as attesting a
        // different one -- that's the whole point of this transcript.
        assert_ne!(t, challenge_host_attestation_transcript(&nonce_b));
    }

    #[test]
    fn operator_token_canonical_bytes_layout_is_exact_and_field_bound() {
        let base =
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1000, 2000, &[9u8; 16]);
        assert_eq!(&base[..OPERATOR_TOKEN_DOMAIN.len()], OPERATOR_TOKEN_DOMAIN);
        // Changing any one field must change the bytes -- otherwise a
        // tampered token field wouldn't actually invalidate the signature.
        assert_ne!(
            base,
            operator_token_canonical_bytes("bob", OperatorRole::Admin, 1000, 2000, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Viewer, 1000, 2000, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1001, 2000, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1000, 2001, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1000, 2000, &[8u8; 16])
        );
    }
}
