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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}
