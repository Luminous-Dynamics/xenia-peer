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
/// human readability; decoded and validated at load.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperatorRecord {
    operator_id: String,
    ed25519_pubkey: String,
    ml_dsa_pubkey: String,
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
    pub(crate) ml_dsa_pubkey: Vec<u8>,
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
            operators.push(EnrolledOperator {
                operator_id: rec.operator_id,
                ed25519_pubkey: ed,
                ml_dsa_pubkey: ml,
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
    pub(crate) fn lookup(&self, ed25519_pubkey: &[u8; 32]) -> Option<&EnrolledOperator> {
        self.by_ed25519.get(ed25519_pubkey)
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
}
