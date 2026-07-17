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
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use xenia_handshake::ML_DSA_65_PK_LEN;
use xenia_wire::handshake_highsec::ML_DSA_87_PK_LEN;

// The role/action model + fail-closed authorization logic now live in the
// shared `xenia-operator-proto` crate, so the daemon and the sovereign-admin
// console authorize against *identical* rules: a role the console greys out is
// exactly a role the daemon also refuses. Only the enrollment/policy-file
// machinery below is daemon-specific.
pub(crate) use xenia_operator_proto::{OperatorAction, OperatorRole, role_permits};

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
///
/// `by_ed25519` is `Arc<RwLock<...>>`, not a plain `HashMap`, so that
/// [`Self::replace_operator_key`] can mutate the *live* policy in place --
/// mirroring [`crate::operator_revocations::OperatorRevocations`]'s exact
/// shape. `#[derive(Clone)]` therefore gives a cheap, *shared* clone (same
/// underlying map, same lock): every place that already holds a cloned
/// `OperatorPolicy` (the sealed-channel task, the admin mutation state, …)
/// sees a key replacement immediately, the same way a live revocation
/// already reaches the sealed channel today. All read methods return an
/// owned [`EnrolledOperator`] rather than a reference, since a reference
/// borrowed from inside the lock guard cannot outlive the guard.
#[derive(Debug, Clone, Default)]
pub(crate) struct OperatorPolicy {
    by_ed25519: Arc<RwLock<HashMap<[u8; 32], EnrolledOperator>>>,
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
        Ok(Self {
            by_ed25519: Arc::new(RwLock::new(by_ed25519)),
        })
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
    pub(crate) fn lookup(&self, ed25519_pubkey: &[u8; 32]) -> Option<EnrolledOperator> {
        self.read_map()?.get(ed25519_pubkey).cloned()
    }

    /// Read-lock the map, failing closed (returning `None`, as if the map
    /// were empty) if the lock is poisoned -- a write-side panic must never
    /// turn into every subsequent lookup silently succeeding against
    /// whatever pre-panic state happened to be readable, matching
    /// [`crate::operator_revocations::OperatorRevocations`]'s documented
    /// fail-closed poison handling.
    fn read_map(
        &self,
    ) -> Option<std::sync::RwLockReadGuard<'_, HashMap<[u8; 32], EnrolledOperator>>> {
        self.by_ed25519.read().ok()
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
    ) -> Option<EnrolledOperator> {
        self.read_map()?.get(ed25519_pubkey).cloned().filter(|op| {
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
    ) -> Option<EnrolledOperator> {
        self.read_map()?.get(ed25519_pubkey).cloned().filter(|op| {
            op.ml_dsa_87_pubkey
                .as_deref()
                .is_some_and(|enrolled| enrolled == ml_dsa_87_pubkey)
        })
    }

    /// Look up an enrolled operator by operator id. Used to re-check
    /// enrollment and recover the signing key at action time (so a token
    /// issued to an operator who has since been de-enrolled no longer
    /// authorizes anything).
    pub(crate) fn lookup_by_id(&self, operator_id: &str) -> Option<EnrolledOperator> {
        self.read_map()?
            .values()
            .find(|op| op.operator_id == operator_id)
            .cloned()
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
        self.read_map().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether any operator is enrolled.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Replace an enrolled operator's key material live, in-process -- the
    /// entry point for the authenticated admin `POST /operator/replace-key`
    /// endpoint (and used by tests). Mirrors
    /// [`crate::operator_revocations::OperatorRevocations::revoke`]'s
    /// interior-mutability shape (`&self`, not `&mut self`): every clone of
    /// this `OperatorPolicy` shares the same underlying map, so the change
    /// is visible everywhere immediately, no restart required.
    ///
    /// Preserves `operator_id` and `role`; only the key material changes.
    /// Refuses (fail-closed, no partial mutation) if:
    /// - `operator_id` is not currently enrolled -- recovering an identity
    ///   that was never there makes no sense, and would let a caller mint a
    ///   brand-new enrollment through what is supposed to be a narrow
    ///   "replace an existing key" action;
    /// - the new Ed25519 key collides with a *different* already-enrolled
    ///   operator (mirrors [`Self::from_operators`]'s duplicate-key
    ///   rejection);
    /// - the write lock is poisoned.
    ///
    /// Durability is a separate concern: this only updates the in-memory
    /// map. Callers that need the change to survive a restart must also
    /// call [`Self::persist_to`].
    pub(crate) fn replace_operator_key(
        &self,
        operator_id: &str,
        new_ed25519_pubkey: [u8; 32],
        new_ml_dsa_pubkey: Vec<u8>,
        new_ml_dsa_87_pubkey: Option<Vec<u8>>,
    ) -> Result<(), OperatorPolicyError> {
        let mut map = self
            .by_ed25519
            .write()
            .map_err(|_| OperatorPolicyError::Io("operator policy lock poisoned".to_string()))?;

        let old_key = map
            .iter()
            .find(|(_, op)| op.operator_id == operator_id)
            .map(|(k, _)| *k)
            .ok_or_else(|| OperatorPolicyError::UnknownOperator(operator_id.to_string()))?;

        if let Some(existing) = map.get(&new_ed25519_pubkey)
            && existing.operator_id != operator_id
        {
            return Err(OperatorPolicyError::DuplicateKey(operator_id.to_string()));
        }

        // Safe to unwrap: `old_key` was just found in this same map above.
        let role = map.get(&old_key).unwrap().role;
        map.remove(&old_key);
        map.insert(
            new_ed25519_pubkey,
            EnrolledOperator {
                operator_id: operator_id.to_string(),
                ed25519_pubkey: new_ed25519_pubkey,
                ml_dsa_pubkey: new_ml_dsa_pubkey,
                ml_dsa_87_pubkey: new_ml_dsa_87_pubkey,
                role,
            },
        );
        Ok(())
    }

    /// Serialize the current live operator set back to the
    /// `--operators-file` JSON shape and atomically replace `path` with it:
    /// write a temp file in the same directory (owner-only permissions on
    /// Unix), `fsync` its data, rename it over `path`, then `fsync` the
    /// containing directory so the rename itself survives a crash --
    /// mirroring `audit_ledger_store.rs::persist_entries_atomic`'s exact
    /// sequence. Closes the durability gap
    /// [`crate::operator_revocations::OperatorRevocations::revoke`]'s own
    /// doc comment flags and accepts for revocation: without this, a live
    /// [`Self::replace_operator_key`] would vanish on the next restart or
    /// reload from `path`.
    pub(crate) fn persist_to(&self, path: &Path) -> std::io::Result<()> {
        let file = {
            let map = self
                .read_map()
                .ok_or_else(|| std::io::Error::other("operator policy lock poisoned"))?;
            let mut operators: Vec<OperatorRecord> = map
                .values()
                .map(|op| OperatorRecord {
                    operator_id: op.operator_id.clone(),
                    ed25519_pubkey: hex::encode(op.ed25519_pubkey),
                    ml_dsa_pubkey: hex::encode(&op.ml_dsa_pubkey),
                    ml_dsa_87_pubkey: op.ml_dsa_87_pubkey.as_deref().map(hex::encode),
                    role: op.role,
                })
                .collect();
            // Deterministic output (stable diffs, easier to audit) --
            // otherwise HashMap iteration order would reshuffle the file on
            // every persist even when nothing changed.
            operators.sort_by(|a, b| a.operator_id.cmp(&b.operator_id));
            OperatorPolicyFile { operators }
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        write_atomic(path, &bytes)
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

/// Atomically replace `path` with `bytes`: write a temp file in the same
/// directory (owner-only permissions on Unix), `fsync` its data, rename it
/// over `path`, then `fsync` the containing directory so the rename itself
/// survives a crash. A failed write leaves the previous file untouched.
/// Mirrors `audit_ledger_store.rs::persist_entries_atomic`, generalized to
/// arbitrary bytes rather than bincode-encoded ledger entries.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("operators.json");
    let temp_path = parent.join(format!(".{name}.tmp-{}-{nanos}", std::process::id()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let write_result: std::io::Result<()> = (|| {
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        sync_directory(parent)
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

/// `fsync` a directory so a prior `rename` into it is durable across a
/// crash -- POSIX only.
fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Errors loading or validating an operator policy.
#[derive(Debug)]
pub(crate) enum OperatorPolicyError {
    Io(String),
    Parse(String),
    /// A record's public key was malformed or the wrong length.
    BadKey(String),
    /// Two records share an Ed25519 public key.
    DuplicateKey(String),
    /// [`OperatorPolicy::replace_operator_key`] was asked to replace an
    /// operator id that isn't currently enrolled.
    UnknownOperator(String),
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
            OperatorPolicyError::UnknownOperator(id) => {
                write!(f, "operator {id:?} is not currently enrolled")
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
    fn lookup_verified_highsec_requires_the_enrolled_ml_dsa_87_key_and_refuses_standard_only_operators()
     {
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
        assert!(
            policy_with_highsec
                .lookup_verified_highsec(&ed, &ml87)
                .is_some()
        );
        // A foreign ML-DSA-87 key is refused even though the Ed25519 key is enrolled.
        let foreign_ml87 = vec![0xCCu8; ML_DSA_87_PK_LEN];
        assert!(
            policy_with_highsec
                .lookup_verified_highsec(&ed, &foreign_ml87)
                .is_none()
        );

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

    #[test]
    fn replace_operator_key_preserves_id_and_role_and_drops_the_old_key() {
        let old_ed = [4u8; 32];
        let new_ed = [5u8; 32];
        let policy =
            OperatorPolicy::from_operators(vec![record("alice", old_ed, OperatorRole::Operator)])
                .unwrap();

        let new_ml = vec![0xEEu8; ML_DSA_65_PK_LEN];
        policy
            .replace_operator_key("alice", new_ed, new_ml.clone(), None)
            .unwrap();

        assert!(
            policy.lookup(&old_ed).is_none(),
            "old key must no longer authenticate"
        );
        let replaced = policy.lookup(&new_ed).unwrap();
        assert_eq!(replaced.operator_id, "alice");
        assert_eq!(
            replaced.role,
            OperatorRole::Operator,
            "role must be preserved"
        );
        assert_eq!(replaced.ml_dsa_pubkey, new_ml);
        assert_eq!(
            policy.len(),
            1,
            "replace must not change the enrolled count"
        );
    }

    #[test]
    fn replace_operator_key_is_visible_through_a_shared_clone_immediately() {
        // `OperatorPolicy::clone()` is a shared (Arc) clone -- a caller that
        // stashed one earlier (e.g. the sealed-channel task) must see a
        // live replacement without re-fetching from `OperatorAuthState`.
        let old_ed = [6u8; 32];
        let new_ed = [7u8; 32];
        let policy =
            OperatorPolicy::from_operators(vec![record("bob", old_ed, OperatorRole::Admin)])
                .unwrap();
        let shared = policy.clone();

        policy
            .replace_operator_key("bob", new_ed, vec![0xAAu8; ML_DSA_65_PK_LEN], None)
            .unwrap();

        assert!(shared.lookup(&old_ed).is_none());
        assert!(shared.lookup(&new_ed).is_some());
    }

    #[test]
    fn replace_operator_key_refuses_an_unenrolled_operator_id() {
        let policy =
            OperatorPolicy::from_operators(vec![record("alice", [1u8; 32], OperatorRole::Admin)])
                .unwrap();
        let err = policy
            .replace_operator_key("nobody", [9u8; 32], vec![0u8; ML_DSA_65_PK_LEN], None)
            .unwrap_err();
        assert!(matches!(err, OperatorPolicyError::UnknownOperator(id) if id == "nobody"));
        // Nothing changed.
        assert!(policy.lookup(&[1u8; 32]).is_some());
        assert_eq!(policy.len(), 1);
    }

    #[test]
    fn replace_operator_key_refuses_a_key_already_enrolled_to_someone_else() {
        let alice_ed = [1u8; 32];
        let bob_ed = [2u8; 32];
        let policy = OperatorPolicy::from_operators(vec![
            record("alice", alice_ed, OperatorRole::Admin),
            record("bob", bob_ed, OperatorRole::Viewer),
        ])
        .unwrap();

        // Trying to replace alice's key with bob's already-enrolled key must
        // be refused -- and must not have deleted alice's original entry
        // first (fail-closed: check before mutate).
        let err = policy
            .replace_operator_key("alice", bob_ed, vec![0u8; ML_DSA_65_PK_LEN], None)
            .unwrap_err();
        assert!(matches!(err, OperatorPolicyError::DuplicateKey(id) if id == "alice"));
        assert!(
            policy.lookup(&alice_ed).is_some(),
            "alice's original key must survive a refused replace"
        );
        assert_eq!(policy.len(), 2);
    }

    #[test]
    fn replace_operator_key_allows_reusing_the_same_ed25519_key_the_operator_already_has() {
        // Not a realistic recovery case (the point of recovery is a *new*
        // key), but the collision check must compare against *other*
        // operators, not refuse a no-op replace of one's own key.
        let ed = [3u8; 32];
        let policy =
            OperatorPolicy::from_operators(vec![record("alice", ed, OperatorRole::Admin)]).unwrap();
        let new_ml = vec![0x11u8; ML_DSA_65_PK_LEN];
        policy
            .replace_operator_key("alice", ed, new_ml.clone(), None)
            .unwrap();
        assert_eq!(policy.lookup(&ed).unwrap().ml_dsa_pubkey, new_ml);
    }

    #[test]
    fn persist_to_round_trips_through_load() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-policy-persist-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("operators.json");

        let ed = [8u8; 32];
        let ml = vec![0x22u8; ML_DSA_65_PK_LEN];
        let ml87 = vec![0x33u8; ML_DSA_87_PK_LEN];
        let policy = OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "alice".to_string(),
            ed25519_pubkey: ed,
            ml_dsa_pubkey: ml.clone(),
            ml_dsa_87_pubkey: Some(ml87.clone()),
            role: OperatorRole::Admin,
        }])
        .unwrap();
        policy.persist_to(&path).unwrap();

        let reloaded = OperatorPolicy::load(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
        let op = reloaded.lookup(&ed).unwrap();
        assert_eq!(op.operator_id, "alice");
        assert_eq!(op.role, OperatorRole::Admin);
        assert_eq!(op.ml_dsa_pubkey, ml);
        assert_eq!(op.ml_dsa_87_pubkey, Some(ml87));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persist_to_reflects_a_live_replace_operator_key() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-policy-persist-replace-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("operators.json");

        let old_ed = [9u8; 32];
        let new_ed = [10u8; 32];
        let policy =
            OperatorPolicy::from_operators(vec![record("alice", old_ed, OperatorRole::Admin)])
                .unwrap();
        policy.persist_to(&path).unwrap();

        policy
            .replace_operator_key("alice", new_ed, vec![0x44u8; ML_DSA_65_PK_LEN], None)
            .unwrap();
        policy.persist_to(&path).unwrap();

        let reloaded = OperatorPolicy::load(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.lookup(&old_ed).is_none());
        assert!(reloaded.lookup(&new_ed).is_some());

        std::fs::remove_dir_all(&dir).ok();
    }
}
