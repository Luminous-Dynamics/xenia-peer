// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator identity + role-based authorization (RBAC) core.
//!
//! Phase 1 of `docs/security/OPERATOR_RBAC_PLAN.md`: the self-contained,
//! locally-enrolled operator model. An operator is an Ed25519 + ML-DSA-65
//! keypair enrolled in a policy file with a role; a privileged daemon action
//! is permitted only if the acting operator's role ranks high enough for it.
//!
//! Everything here is pure and I/O-light: [`role_permits`] is a total
//! function over (role, action), and [`OperatorPolicy::authorize`] is a
//! lookup plus that check. The challenge/response proof-of-possession and the
//! per-action signature verification that decide *which* operator is acting
//! live in later phases; this module answers "is this enrolled key allowed to
//! do this?" and nothing else. It never trusts a role asserted by the client
//! -- the role is whatever the enrollment file bound to the verified key.

// Phase 1 foundation: this module is fully exercised by its own unit tests
// but not yet called from the daemon runtime. Phase 2 (the challenge/response
// auth endpoint) and Phase 3 (enforcing authorization on privileged actions)
// wire it in; the allow is removed then.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use xenia_handshake::ML_DSA_65_PK_LEN;
use xenia_wire::handshake_highsec::ML_DSA_87_PK_LEN;

// The role/action model + fail-closed authorization logic now live in the
// shared `xenia-operator-proto` crate, so the daemon and the sovereign-admin
// console authorize against *identical* rules: a role the console greys out is
// exactly a role the daemon also refuses. Only the enrollment/policy-file
// machinery below is daemon-specific.
pub(crate) use xenia_operator_proto::{role_permits, OperatorAction, OperatorRole};

/// The outcome of an authorization check, kept distinct so the caller can
/// audit and message "not enrolled" separately from "enrolled but role too
/// low" -- both are denials, but they mean different things.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthzDecision {
    /// Allowed; carries the operator id + role for the audit entry.
    Allowed {
        operator_id: String,
        role: OperatorRole,
    },
    /// The presented key is not enrolled at all.
    NotEnrolled,
    /// Enrolled, but the role does not permit this action.
    RoleDenied {
        operator_id: String,
        role: OperatorRole,
    },
}

/// On-disk enrollment record (the policy-file shape). Public keys are hex for
/// human readability; decoded and validated at load. Mirrors
/// [`xenia_operator_proto::OperatorEnrollmentRecord`] field-for-field (kept
/// as a separate type here since this one needs `#[serde(default)]` on the
/// optional field for backward compatibility with pre-existing policy files
/// that predate it -- `xenia_operator_proto`'s version is what a *generator*,
/// like the console, should build from, so it always emits the field
/// explicitly when present).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperatorRecord {
    operator_id: String,
    ed25519_pubkey: String,
    /// ML-DSA-65 public key, hex -- required. Every operator has a
    /// standard-suite identity, since the HTTP challenge/response auth
    /// ceremony (`/auth/challenge` + `/auth/verify`) always uses it
    /// regardless of which suite the sealed channel later negotiates.
    ml_dsa_pubkey: String,
    /// ML-DSA-87 public key, hex -- optional. Only an operator who will use
    /// the high-security sealed channel needs one enrolled; omitted (not
    /// merely absent-but-present-as-null) in existing policy files parses as
    /// `None` via `#[serde(default)]`.
    #[serde(default)]
    ml_dsa_87_pubkey: Option<String>,
    role: OperatorRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperatorPolicyFile {
    operators: Vec<OperatorRecord>,
}

/// A validated, in-memory enrolled operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnrolledOperator {
    pub(crate) operator_id: String,
    pub(crate) ed25519_pubkey: [u8; 32],
    /// ML-DSA-65 public key -- required (see [`OperatorRecord::ml_dsa_pubkey`]).
    pub(crate) ml_dsa_pubkey: Vec<u8>,
    /// ML-DSA-87 public key -- present only if this operator enrolled for
    /// the high-security sealed channel (see
    /// [`OperatorRecord::ml_dsa_87_pubkey`]).
    pub(crate) ml_dsa_87_pubkey: Option<Vec<u8>>,
    pub(crate) role: OperatorRole,
}

/// The set of enrolled operators, indexed by Ed25519 public key.
#[derive(Debug, Clone, Default)]
pub(crate) struct OperatorPolicy {
    by_ed25519: HashMap<[u8; 32], EnrolledOperator>,
}

impl OperatorPolicy {
    /// Build a policy from validated operators, rejecting duplicate keys.
    pub(crate) fn from_operators(
        operators: Vec<EnrolledOperator>,
    ) -> Result<Self, OperatorPolicyError> {
        let mut by_ed25519 = HashMap::new();
        for op in operators {
            if by_ed25519.insert(op.ed25519_pubkey, op.clone()).is_some() {
                return Err(OperatorPolicyError::DuplicateKey(op.operator_id));
            }
        }
        Ok(Self { by_ed25519 })
    }

    /// Parse and validate a policy from JSON bytes.
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self, OperatorPolicyError> {
        let file: OperatorPolicyFile =
            serde_json::from_slice(bytes).map_err(|e| OperatorPolicyError::Parse(e.to_string()))?;
        let mut operators = Vec::with_capacity(file.operators.len());
        for rec in file.operators {
            let ed = decode_fixed_hex::<32>(&rec.ed25519_pubkey)
                .ok_or_else(|| OperatorPolicyError::BadKey(rec.operator_id.clone()))?;
            let ml = hex::decode(rec.ml_dsa_pubkey.trim())
                .ok()
                .filter(|b| b.len() == ML_DSA_65_PK_LEN)
                .ok_or_else(|| OperatorPolicyError::BadKey(rec.operator_id.clone()))?;
            let ml_87 = match rec.ml_dsa_87_pubkey {
                None => None,
                Some(hex_str) => Some(
                    hex::decode(hex_str.trim())
                        .ok()
                        .filter(|b| b.len() == ML_DSA_87_PK_LEN)
                        .ok_or_else(|| OperatorPolicyError::BadKey(rec.operator_id.clone()))?,
                ),
            };
            operators.push(EnrolledOperator {
                operator_id: rec.operator_id,
                ed25519_pubkey: ed,
                ml_dsa_pubkey: ml,
                ml_dsa_87_pubkey: ml_87,
                role: rec.role,
            });
        }
        Self::from_operators(operators)
    }

    /// Load and validate a policy from a file. The file's permissions are
    /// re-tightened to `0600` on load (it names who can operate the host --
    /// it must not be group/world-readable), mirroring the key-file loaders.
    pub(crate) fn load(path: &Path) -> Result<Self, OperatorPolicyError> {
        let bytes = std::fs::read(path).map_err(|e| OperatorPolicyError::Io(e.to_string()))?;
        restrict_permissions(path);
        Self::from_json(&bytes)
    }

    /// Look up an enrolled operator by Ed25519 public key.
    ///
    /// This alone is **not sufficient for hybrid authentication** -- it only
    /// confirms an Ed25519 key is enrolled, not that a presented ML-DSA key
    /// belongs to the same enrollment record. A handshake/challenge that
    /// verified both a classical and a post-quantum signature must call
    /// [`Self::lookup_verified`] instead, or the ML-DSA signature buys
    /// nothing: an attacker holding only the enrolled Ed25519 secret could
    /// pair it with a self-generated ML-DSA keypair and still authenticate.
    pub(crate) fn lookup(&self, ed25519_pubkey: &[u8; 32]) -> Option<&EnrolledOperator> {
        self.by_ed25519.get(ed25519_pubkey)
    }

    /// Look up an enrolled operator, requiring **both** the Ed25519 and
    /// ML-DSA public keys presented in a verified hybrid handshake/challenge
    /// to match the same enrollment record. This is the correct lookup for
    /// any caller that verified both signatures and wants the hybrid
    /// authentication to mean something: enrollment binds a *pair* of keys,
    /// not either key independently.
    pub(crate) fn lookup_verified(
        &self,
        ed25519_pubkey: &[u8; 32],
        ml_dsa_pubkey: &[u8],
    ) -> Option<&EnrolledOperator> {
        self.by_ed25519.get(ed25519_pubkey).filter(|op| {
            // Constant-time-ish is not required here (both are public keys),
            // but a plain slice comparison is exact and simple.
            op.ml_dsa_pubkey.as_slice() == ml_dsa_pubkey
        })
    }

    /// [`Self::lookup_verified`]'s counterpart for the high-security sealed
    /// channel: requires the presented Ed25519 key and ML-DSA-**87** key to
    /// match the same enrollment record's `ml_dsa_87_pubkey`. An operator who
    /// never enrolled a high-security identity (`ml_dsa_87_pubkey: None`) is
    /// refused here even if their Ed25519 + standard ML-DSA-65 pair is
    /// enrolled -- enrollment for the high-security suite is opt-in per
    /// operator, not implied by the standard enrollment.
    pub(crate) fn lookup_verified_highsec(
        &self,
        ed25519_pubkey: &[u8; 32],
        ml_dsa_87_pubkey: &[u8],
    ) -> Option<&EnrolledOperator> {
        self.by_ed25519.get(ed25519_pubkey).filter(|op| {
            op.ml_dsa_87_pubkey
                .as_deref()
                .is_some_and(|enrolled| enrolled == ml_dsa_87_pubkey)
        })
    }

    /// Look up an enrolled operator by operator id. Used to re-check
    /// enrollment and recover the signing key at action time (so a token
    /// issued to an operator who has since been de-enrolled no longer
    /// authorizes anything).
    pub(crate) fn lookup_by_id(&self, operator_id: &str) -> Option<&EnrolledOperator> {
        self.by_ed25519
            .values()
            .find(|op| op.operator_id == operator_id)
    }

    /// Authorize `action` for the operator holding `ed25519_pubkey`.
    /// Fail-closed: an unenrolled key or an insufficient role is denied.
    pub(crate) fn authorize(
        &self,
        ed25519_pubkey: &[u8; 32],
        action: OperatorAction,
    ) -> AuthzDecision {
        match self.lookup(ed25519_pubkey) {
            None => AuthzDecision::NotEnrolled,
            Some(op) if role_permits(op.role, action) => AuthzDecision::Allowed {
                operator_id: op.operator_id.clone(),
                role: op.role,
            },
            Some(op) => AuthzDecision::RoleDenied {
                operator_id: op.operator_id.clone(),
                role: op.role,
            },
        }
    }

    /// Number of enrolled operators.
    pub(crate) fn len(&self) -> usize {
        self.by_ed25519.len()
    }

    /// Whether any operator is enrolled.
    pub(crate) fn is_empty(&self) -> bool {
        self.by_ed25519.is_empty()
    }
}

fn decode_fixed_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(s.trim()).ok()?;
    bytes.try_into().ok()
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// Errors loading or validating an operator policy.
#[derive(Debug)]
pub(crate) enum OperatorPolicyError {
    Io(String),
    Parse(String),
    /// A record's public key was malformed or the wrong length.
    BadKey(String),
    /// Two records share an Ed25519 public key.
    DuplicateKey(String),
}

impl std::fmt::Display for OperatorPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorPolicyError::Io(e) => write!(f, "operator policy I/O error: {e}"),
            OperatorPolicyError::Parse(e) => write!(f, "operator policy parse error: {e}"),
            OperatorPolicyError::BadKey(id) => {
                write!(f, "operator {id:?} has a malformed/wrong-length public key")
            }
            OperatorPolicyError::DuplicateKey(id) => {
                write!(
                    f,
                    "operator {id:?} shares an Ed25519 key with another operator"
                )
            }
        }
    }
}

impl std::error::Error for OperatorPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_permits_everything_at_or_below_role() {
        use OperatorAction::*;
        use OperatorRole::*;
        // Viewer: read-only.
        assert!(role_permits(Viewer, ViewInventory));
        assert!(role_permits(Viewer, ReadAudit));
        assert!(!role_permits(Viewer, ApproveConsent));
        assert!(!role_permits(Viewer, RevokeConsent));
        // Approver: + consent decisions, not sessions/policy.
        assert!(role_permits(Approver, ApproveConsent));
        assert!(role_permits(Approver, RevokeConsent));
        assert!(role_permits(Approver, ReadAudit));
        assert!(!role_permits(Approver, InitiateSession));
        assert!(!role_permits(Approver, ChangePolicy));
        // Operator: + sessions, not admin.
        assert!(role_permits(Operator, InitiateSession));
        assert!(role_permits(Operator, ApproveConsent));
        assert!(!role_permits(Operator, EnrollOperator));
        assert!(!role_permits(Operator, ChangePolicy));
        // Admin: everything.
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
            assert!(role_permits(Admin, action), "admin denied {action:?}");
        }
    }

    fn record(id: &str, ed: [u8; 32], role: OperatorRole) -> EnrolledOperator {
        EnrolledOperator {
            operator_id: id.to_string(),
            ed25519_pubkey: ed,
            ml_dsa_pubkey: vec![0u8; ML_DSA_65_PK_LEN],
            ml_dsa_87_pubkey: None,
            role,
        }
    }

    #[test]
    fn authorize_is_fail_closed_for_unenrolled_and_low_role() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let stranger = [9u8; 32];
        let policy = OperatorPolicy::from_operators(vec![
            record("alice", alice, OperatorRole::Admin),
            record("bob", bob, OperatorRole::Viewer),
        ])
        .unwrap();

        // Admin allowed for an admin-only action, with attribution.
        assert_eq!(
            policy.authorize(&alice, OperatorAction::EnrollOperator),
            AuthzDecision::Allowed {
                operator_id: "alice".to_string(),
                role: OperatorRole::Admin
            }
        );
        // Viewer denied for a consent action (enrolled, role too low).
        assert_eq!(
            policy.authorize(&bob, OperatorAction::ApproveConsent),
            AuthzDecision::RoleDenied {
                operator_id: "bob".to_string(),
                role: OperatorRole::Viewer
            }
        );
        // Unknown key: not enrolled.
        assert_eq!(
            policy.authorize(&stranger, OperatorAction::ReadAudit),
            AuthzDecision::NotEnrolled
        );
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let key = [7u8; 32];
        let err = OperatorPolicy::from_operators(vec![
            record("a", key, OperatorRole::Admin),
            record("b", key, OperatorRole::Viewer),
        ])
        .unwrap_err();
        assert!(matches!(err, OperatorPolicyError::DuplicateKey(_)));
    }

    #[test]
    fn lookup_verified_requires_both_keys_to_match_the_same_enrollment() {
        let alice_ed = [1u8; 32];
        let alice_ml = vec![0xAAu8; ML_DSA_65_PK_LEN];
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "alice".to_string(),
            ed25519_pubkey: alice_ed,
            ml_dsa_pubkey: alice_ml.clone(),
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Admin,
        }])
        .unwrap();

        // The genuine pair matches.
        assert!(policy.lookup_verified(&alice_ed, &alice_ml).is_some());

        // An enrolled Ed25519 key paired with a *different* ML-DSA key (e.g.
        // an attacker who only holds the classical secret and supplies their
        // own post-quantum keypair) must be refused, even though plain
        // `lookup` (Ed25519-only) would still find the record.
        let foreign_ml = vec![0xBBu8; ML_DSA_65_PK_LEN];
        assert!(policy.lookup_verified(&alice_ed, &foreign_ml).is_none());
        assert!(policy.lookup(&alice_ed).is_some());

        // An unenrolled Ed25519 key is refused regardless of the ML-DSA key.
        assert!(policy.lookup_verified(&[9u8; 32], &alice_ml).is_none());
    }

    #[test]
    fn json_round_trips_and_validates() {
        let ed_hex = "01".repeat(32);
        let ml_hex = "ab".repeat(ML_DSA_65_PK_LEN);
        let json = format!(
            r#"{{"operators":[{{"operator_id":"alice","ed25519_pubkey":"{ed_hex}","ml_dsa_pubkey":"{ml_hex}","role":"Approver"}}]}}"#
        );
        let policy = OperatorPolicy::from_json(json.as_bytes()).unwrap();
        assert_eq!(policy.len(), 1);
        let op = policy.lookup(&[1u8; 32]).unwrap();
        assert_eq!(op.operator_id, "alice");
        assert_eq!(op.role, OperatorRole::Approver);
        assert_eq!(op.ml_dsa_pubkey.len(), ML_DSA_65_PK_LEN);
    }

    #[test]
    fn json_rejects_wrong_length_keys() {
        let json = r#"{"operators":[{"operator_id":"x","ed25519_pubkey":"00","ml_dsa_pubkey":"00","role":"Viewer"}]}"#;
        assert!(matches!(
            OperatorPolicy::from_json(json.as_bytes()),
            Err(OperatorPolicyError::BadKey(_))
        ));
    }

    #[test]
    fn json_accepts_and_validates_the_optional_ml_dsa_87_key() {
        let ed_hex = "02".repeat(32);
        let ml65_hex = "ab".repeat(ML_DSA_65_PK_LEN);
        let ml87_hex = "cd".repeat(ML_DSA_87_PK_LEN);
        let json = format!(
            r#"{{"operators":[{{"operator_id":"highsec-alice","ed25519_pubkey":"{ed_hex}","ml_dsa_pubkey":"{ml65_hex}","ml_dsa_87_pubkey":"{ml87_hex}","role":"Operator"}}]}}"#
        );
        let policy = OperatorPolicy::from_json(json.as_bytes()).unwrap();
        let op = policy.lookup(&[2u8; 32]).unwrap();
        assert_eq!(
            op.ml_dsa_87_pubkey.as_ref().map(Vec::len),
            Some(ML_DSA_87_PK_LEN)
        );

        // A wrong-length ml_dsa_87_pubkey is rejected the same way a
        // wrong-length ml_dsa_pubkey is -- the optional field is validated,
        // not merely accepted-if-present.
        let short_json = format!(
            r#"{{"operators":[{{"operator_id":"x","ed25519_pubkey":"{ed_hex}","ml_dsa_pubkey":"{ml65_hex}","ml_dsa_87_pubkey":"00","role":"Viewer"}}]}}"#
        );
        assert!(matches!(
            OperatorPolicy::from_json(short_json.as_bytes()),
            Err(OperatorPolicyError::BadKey(_))
        ));
    }

    #[test]
    fn lookup_verified_highsec_requires_the_enrolled_ml_dsa_87_key_and_refuses_standard_only_operators(
    ) {
        let ed = [3u8; 32];
        let ml65 = vec![0xAAu8; ML_DSA_65_PK_LEN];
        let ml87 = vec![0xBBu8; ML_DSA_87_PK_LEN];
        let policy_with_highsec = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "highsec-op".to_string(),
            ed25519_pubkey: ed,
            ml_dsa_pubkey: ml65.clone(),
            ml_dsa_87_pubkey: Some(ml87.clone()),
            role: OperatorRole::Admin,
        }])
        .unwrap();
        assert!(policy_with_highsec
            .lookup_verified_highsec(&ed, &ml87)
            .is_some());
        // A foreign ML-DSA-87 key is refused even though the Ed25519 key is enrolled.
        let foreign_ml87 = vec![0xCCu8; ML_DSA_87_PK_LEN];
        assert!(policy_with_highsec
            .lookup_verified_highsec(&ed, &foreign_ml87)
            .is_none());

        // An operator enrolled only for the standard suite (no
        // ml_dsa_87_pubkey at all) must be refused for the high-security
        // suite even by their own real ML-DSA-87 identity -- enrollment for
        // that suite is opt-in, not implied.
        let standard_only = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "standard-op".to_string(),
            ed25519_pubkey: ed,
            ml_dsa_pubkey: ml65,
            ml_dsa_87_pubkey: None,
            role: OperatorRole::Admin,
        }])
        .unwrap();
        assert!(standard_only.lookup_verified_highsec(&ed, &ml87).is_none());
    }
}
