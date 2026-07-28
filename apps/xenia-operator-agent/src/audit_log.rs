// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A durable, hash-chained, signed audit trail for this agent's own trust
//! decisions -- host-trust first-use/rotation, pairing, session refresh,
//! and revocation. `xenia_ledger::Chain` (used by the daemon for *consent*
//! decisions) can't be reused directly: its `LedgerEntry.event` is
//! hard-typed to `ConsentEventRecord` (`session_id`, `request_id`,
//! `ConsentKind`, `scope`), which doesn't fit "host X's identity changed"
//! or "pairing token consumed" without distorting a consent-specific
//! shape. This module is a small, purpose-built type that **mirrors**
//! `xenia_ledger::Chain`'s proven pattern instead: hash-chained entries,
//! signed with this agent's own already-loaded Ed25519 identity key (no
//! new key material), transactional persist-then-commit appends. See
//! `docs/security/PRE_PRODUCTION_GATES.md` Gate 5 ("admin actions...
//! produce durable audit records") -- consent already has this via item 9;
//! this closes the same gap for the agent's own trust decisions.
//!
//! Before this module, every one of these decisions produced nothing but
//! an ephemeral `tracing` call -- nothing survives process exit, nothing
//! is queryable, and nothing can be independently verified after the
//! fact. `AgentAuditChain` fixes that; `GET /v1/audit` (in `main.rs`)
//! exposes it, session-token-gated like every other `/v1/*` route.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::path::Path;
use std::time::SystemTime;

use xenia_secure_file as secure_file;

/// One trust decision this agent made. Deliberately carries only what an
/// auditor needs to reconstruct *which* daemon/operator/session was
/// involved and *what* happened -- never secret material (no seeds, no raw
/// pairing/session tokens).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAuditEvent {
    /// A daemon fingerprint was trusted for the first time under
    /// `(daemon_endpoint, suite)` -- see `host_trust::PinOutcome::TrustedOnFirstUse`.
    HostTrustFirstUse {
        daemon_endpoint: String,
        suite: String,
        fingerprint_hex: String,
    },
    /// A previously-pinned daemon fingerprint changed and the operator
    /// confirmed the rotation -- see `host_trust::PinOutcome::Rotated`.
    HostTrustRotation {
        daemon_endpoint: String,
        suite: String,
        old_fingerprint_hex: String,
        new_fingerprint_hex: String,
    },
    /// `POST /v1/pair` succeeded: the raw pairing token was presented and
    /// a session was minted.
    Paired,
    /// `POST /v1/session/refresh` succeeded: an already-valid session
    /// minted a fresh one.
    SessionRefreshed,
    /// `POST /v1/sign/revoke` succeeded: the operator confirmed and this
    /// agent signed a revocation transcript for `target_operator_id`.
    RevocationSigned {
        target_operator_id: String,
        daemon_endpoint: String,
    },
    /// `POST /v1/sign/replace-key` succeeded: the operator confirmed and
    /// this agent signed a key-replacement transcript, authorizing
    /// `target_operator_id`'s enrolled key to be replaced with
    /// `new_ed25519_pubkey_hex` -- operator-key recovery.
    KeyReplacementSigned {
        target_operator_id: String,
        new_ed25519_pubkey_hex: String,
        daemon_endpoint: String,
    },
    /// `POST /v1/sign/consent-action` succeeded for an `Approve` whose
    /// scope was classified as a broad grant (input injection, clipboard,
    /// or file-transfer beyond pure screen viewing) -- the operator
    /// confirmed this specific scope before the agent signed it. Appended
    /// last to preserve every existing entry's bincode discriminant.
    BroadGrantConfirmed {
        scope: String,
        daemon_endpoint: String,
    },
}

impl AgentAuditEvent {
    /// Stable dot-namespaced audit event name, mirroring
    /// `xenia_ledger::ConsentEventRecord::stable_name`'s convention.
    pub const fn stable_name(&self) -> &'static str {
        match self {
            Self::HostTrustFirstUse { .. } => "host_trust.first_use",
            Self::HostTrustRotation { .. } => "host_trust.rotation",
            Self::Paired => "session.paired",
            Self::SessionRefreshed => "session.refreshed",
            Self::RevocationSigned { .. } => "revocation.signed",
            Self::KeyReplacementSigned { .. } => "key_replacement.signed",
            Self::BroadGrantConfirmed { .. } => "consent_action.broad_grant_confirmed",
        }
    }
}

/// A signed, chained audit entry. Every field is covered by `entry_hash`;
/// `signature` is this agent's Ed25519 signature over `entry_hash`. Same
/// shape as `xenia_ledger::LedgerEntry`, just over `AgentAuditEvent`
/// instead of `ConsentEventRecord`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuditEntry {
    /// Monotonic 0-based sequence number. The genesis entry is 0.
    pub seq: u64,
    /// `entry_hash` of the previous entry, or `[0; 32]` for the genesis entry.
    pub prev_hash: [u8; 32],
    /// Wall-clock time of the event, as recorded by the agent.
    pub timestamp: SystemTime,
    /// The audit event itself.
    pub event: AgentAuditEvent,
    /// blake3 hash over `(seq, prev_hash, timestamp, event)`. Covers
    /// every field except `signature` itself (which signs this hash).
    pub entry_hash: [u8; 32],
    /// Ed25519 signature over `entry_hash`, 64 bytes.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Debug)]
pub enum AuditLogError {
    Codec(bincode::Error),
}

impl std::fmt::Display for AuditLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditLogError::Codec(e) => {
                write!(f, "audit log entry hash preimage failed to serialize: {e}")
            }
        }
    }
}

impl std::error::Error for AuditLogError {}

impl From<bincode::Error> for AuditLogError {
    fn from(e: bincode::Error) -> Self {
        AuditLogError::Codec(e)
    }
}

#[derive(Debug)]
pub enum AuditVerifyError {
    OutOfOrder {
        seq: usize,
        expected: u64,
        found: u64,
    },
    BadGenesis,
    BrokenLink {
        seq: u64,
    },
    EntryHashMismatch {
        seq: u64,
    },
    BadSignature {
        seq: u64,
    },
}

impl std::fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditVerifyError::OutOfOrder {
                seq,
                expected,
                found,
            } => write!(
                f,
                "entry {seq} is out of sequence order (expected {expected}, found {found})"
            ),
            AuditVerifyError::BadGenesis => {
                write!(f, "genesis entry (seq 0) has a non-zero prev_hash")
            }
            AuditVerifyError::BrokenLink { seq } => write!(
                f,
                "entry {seq}'s prev_hash does not match the previous entry's entry_hash"
            ),
            AuditVerifyError::EntryHashMismatch { seq } => {
                write!(
                    f,
                    "entry {seq}'s entry_hash does not match its recomputed hash"
                )
            }
            AuditVerifyError::BadSignature { seq } => {
                write!(f, "entry {seq}'s signature does not verify")
            }
        }
    }
}

impl std::error::Error for AuditVerifyError {}

/// Error returned by [`AgentAuditChain::append_transactional`]: either the
/// append itself failed, or it succeeded but persisting it failed (in
/// which case the append was rolled back -- the caller never observes a
/// committed-but-unpersisted entry).
#[derive(Debug)]
pub enum TransactionalAppendError<E> {
    Audit(AuditLogError),
    Persist(E),
}

impl<E: std::fmt::Display> std::fmt::Display for TransactionalAppendError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionalAppendError::Audit(e) => write!(f, "audit log append failed: {e}"),
            TransactionalAppendError::Persist(e) => write!(f, "audit log persist failed: {e}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for TransactionalAppendError<E> {}

impl<E> From<AuditLogError> for TransactionalAppendError<E> {
    fn from(e: AuditLogError) -> Self {
        TransactionalAppendError::Audit(e)
    }
}

/// Canonical pre-image for the entry hash. `bincode` v1 with default
/// options produces a deterministic, length-prefixed encoding -- same
/// discipline as `xenia_ledger`'s own `EntryPreimage`.
#[derive(Serialize)]
struct EntryPreimage<'a> {
    seq: u64,
    prev_hash: [u8; 32],
    timestamp: &'a SystemTime,
    event: &'a AgentAuditEvent,
}

fn compute_entry_hash(
    seq: u64,
    prev_hash: &[u8; 32],
    timestamp: &SystemTime,
    event: &AgentAuditEvent,
) -> Result<[u8; 32], AuditLogError> {
    let preimage = EntryPreimage {
        seq,
        prev_hash: *prev_hash,
        timestamp,
        event,
    };
    let bytes = bincode::serialize(&preimage)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// A hash-chained, Ed25519-signed sequence of [`AgentAuditEntry`], held by
/// the agent's own signing key.
pub struct AgentAuditChain {
    entries: Vec<AgentAuditEntry>,
    signing_key: SigningKey,
}

impl AgentAuditChain {
    /// Create a new empty chain held by `signing_key`.
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            entries: Vec::new(),
            signing_key,
        }
    }

    /// Rehydrate a chain from previously-persisted entries. Does NOT
    /// verify them -- the caller should run [`verify_chain`] with the
    /// agent's own verifying key first (see `load_verified` in `main.rs`).
    pub fn from_entries(entries: Vec<AgentAuditEntry>, signing_key: SigningKey) -> Self {
        Self {
            entries,
            signing_key,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn last_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32])
    }

    pub fn entries(&self) -> &[AgentAuditEntry] {
        &self.entries
    }

    /// Produce a signed [`AgentAuditCheckpoint`] committing to this
    /// chain's current length and head hash. Mirrors
    /// `xenia_ledger::Chain::sign_checkpoint` exactly, over this agent's
    /// own audit trail instead of the daemon's consent ledger.
    pub fn sign_checkpoint(&self, timestamp_unix_secs: u64) -> AgentAuditCheckpoint {
        let entry_count = self.entries.len() as u64;
        let head_hash = self.last_hash();
        let audit_public_key = self.signing_key.verifying_key().to_bytes();
        let message = checkpoint_message(
            entry_count,
            &head_hash,
            &audit_public_key,
            timestamp_unix_secs,
        );
        let signature = self.signing_key.sign(&message).to_bytes();
        AgentAuditCheckpoint {
            schema: AGENT_AUDIT_CHECKPOINT_SCHEMA.to_string(),
            entry_count,
            head_hash,
            audit_public_key,
            timestamp_unix_secs,
            signature,
        }
    }

    fn append(&mut self, event: AgentAuditEvent) -> Result<&AgentAuditEntry, AuditLogError> {
        let seq = self.entries.len() as u64;
        let prev_hash = self.last_hash();
        let timestamp = SystemTime::now();

        let entry_hash = compute_entry_hash(seq, &prev_hash, &timestamp, &event)?;
        let signature = self.signing_key.sign(&entry_hash).to_bytes();

        self.entries.push(AgentAuditEntry {
            seq,
            prev_hash,
            timestamp,
            event,
            entry_hash,
            signature,
        });
        Ok(self.entries.last().expect("append: entry was just pushed"))
    }

    /// Append a new event, persist the resulting entry list via `persist`,
    /// and only keep the append if persistence succeeds -- the caller
    /// never observes a committed-but-unpersisted entry. Mirrors
    /// `xenia_ledger::Chain::append_transactional` exactly.
    pub fn append_transactional<E>(
        &mut self,
        event: AgentAuditEvent,
        persist: impl FnOnce(&[AgentAuditEntry]) -> Result<(), E>,
    ) -> Result<&AgentAuditEntry, TransactionalAppendError<E>> {
        self.append(event)
            .map_err(TransactionalAppendError::Audit)?;
        if let Err(err) = persist(&self.entries) {
            self.entries.pop();
            return Err(TransactionalAppendError::Persist(err));
        }
        Ok(self
            .entries
            .last()
            .expect("append_transactional: entry was just pushed and persist succeeded"))
    }
}

/// Verify every entry in a chain: sequence continuity, hash link,
/// entry_hash recomputation, and Ed25519 signature. Mirrors
/// `xenia_ledger::Verifier::verify_chain` exactly, over `AgentAuditEntry`.
///
/// An empty slice passes vacuously.
pub fn verify_chain(
    entries: &[AgentAuditEntry],
    public_key: &VerifyingKey,
) -> Result<(), AuditVerifyError> {
    let mut expected_prev = [0u8; 32];
    for (index, entry) in entries.iter().enumerate() {
        let expected_seq = index as u64;
        if entry.seq != expected_seq {
            return Err(AuditVerifyError::OutOfOrder {
                seq: index,
                expected: expected_seq,
                found: entry.seq,
            });
        }
        if entry.seq == 0 && entry.prev_hash != [0u8; 32] {
            return Err(AuditVerifyError::BadGenesis);
        }
        if entry.prev_hash != expected_prev {
            return Err(AuditVerifyError::BrokenLink { seq: entry.seq });
        }

        let recomputed =
            compute_entry_hash(entry.seq, &entry.prev_hash, &entry.timestamp, &entry.event)
                .map_err(|_| AuditVerifyError::EntryHashMismatch { seq: entry.seq })?;
        if recomputed != entry.entry_hash {
            return Err(AuditVerifyError::EntryHashMismatch { seq: entry.seq });
        }

        let sig = Signature::from_bytes(&entry.signature);
        public_key
            .verify(&entry.entry_hash, &sig)
            .map_err(|_| AuditVerifyError::BadSignature { seq: entry.seq })?;

        expected_prev = entry.entry_hash;
    }
    Ok(())
}

/// Stable schema label for [`AgentAuditCheckpoint`].
pub const AGENT_AUDIT_CHECKPOINT_SCHEMA: &str = "xenia-agent-audit-checkpoint-v1";

/// A public commitment to the current state of an [`AgentAuditChain`] --
/// mirrors `xenia_ledger::LedgerCheckpoint`'s shape and "reveals only
/// length + head hash + signing key + timestamp, never entry contents"
/// reasoning exactly, over this agent's audit trail instead of the
/// daemon's consent ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuditCheckpoint {
    /// Must equal [`AGENT_AUDIT_CHECKPOINT_SCHEMA`].
    pub schema: String,
    /// Number of entries in the chain when this checkpoint was produced.
    pub entry_count: u64,
    /// [`AgentAuditChain::last_hash`] at the time this checkpoint was
    /// produced -- `[0; 32]` for an empty chain.
    pub head_hash: [u8; 32],
    /// This agent's Ed25519 identity public key (the same key that signs
    /// every audit entry).
    pub audit_public_key: [u8; 32],
    /// Unix seconds this checkpoint was produced.
    pub timestamp_unix_secs: u64,
    /// Ed25519 signature over [`checkpoint_message`] for this
    /// checkpoint's own fields.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// The domain-separated message an [`AgentAuditCheckpoint`]'s signature
/// covers. Mirrors `xenia_ledger::checkpoint_message` exactly (distinct
/// domain-separation tag, so a checkpoint from one chain can never be
/// mistaken for the other's).
pub fn checkpoint_message(
    entry_count: u64,
    head_hash: &[u8; 32],
    audit_public_key: &[u8; 32],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(64 + AGENT_AUDIT_CHECKPOINT_SCHEMA.len());
    message.extend_from_slice(b"xenia:agent-audit-checkpoint:v1");
    message.push(0);
    message.extend_from_slice(AGENT_AUDIT_CHECKPOINT_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(&entry_count.to_be_bytes());
    message.extend_from_slice(head_hash);
    message.extend_from_slice(audit_public_key);
    message.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    message
}

/// Load `path` and verify every persisted entry under `signing_key` before
/// trusting it; if `path` doesn't exist yet, return a fresh empty chain.
/// Fails closed, mirroring `xenia-peer`'s `audit_ledger_store::load_verified`
/// discipline: a present-but-corrupt-or-tampered file is an error, never
/// silently discarded or partially trusted. Reuses `secure_file`'s
/// descriptor-relative, `0700`-dir, `O_NOFOLLOW` file access (item 7) --
/// no new filesystem-safety code needed here.
pub fn load_verified(
    path: &Path,
    signing_key: SigningKey,
) -> Result<AgentAuditChain, Box<dyn std::error::Error>> {
    match secure_file::read_secure_file_if_exists(path)? {
        None => Ok(AgentAuditChain::new(signing_key)),
        Some(bytes) => {
            let entries: Vec<AgentAuditEntry> = bincode::deserialize(&bytes)?;
            verify_chain(&entries, &signing_key.verifying_key())?;
            Ok(AgentAuditChain::from_entries(entries, signing_key))
        }
    }
}

/// Serialize `entries` and atomically replace `path`'s contents, via
/// `secure_file::secure_overwrite`. The closure shape callers pass to
/// [`AgentAuditChain::append_transactional`].
///
/// Returns `Box<dyn Error + Send + Sync>`, not the plain `Box<dyn Error>`
/// `secure_file` itself returns: this runs inside `main.rs`'s
/// `spawn_blocking`, and `tokio::task::spawn_blocking` requires its
/// closure's return type to be `Send` -- a plain `Box<dyn Error>` isn't
/// (the underlying error values are, but the trait object's static type
/// doesn't say so), so the boundary is crossed here via a string-message
/// re-wrap rather than at every call site.
pub fn persist(
    path: &Path,
    entries: &[AgentAuditEntry],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = bincode::serialize(entries)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    secure_file::secure_overwrite(path, &bytes)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn append_then_verify_round_trips() {
        let mut chain = AgentAuditChain::new(test_key(1));
        chain
            .append(AgentAuditEvent::Paired)
            .expect("append succeeds");
        chain
            .append(AgentAuditEvent::HostTrustFirstUse {
                daemon_endpoint: "http://localhost:8090".to_string(),
                suite: "standard".to_string(),
                fingerprint_hex: "aa".repeat(32),
            })
            .expect("append succeeds");

        assert_eq!(chain.len(), 2);
        let public = test_key(1).verifying_key();
        verify_chain(chain.entries(), &public).expect("chain verifies");
    }

    #[test]
    fn empty_chain_verifies_vacuously() {
        verify_chain(&[], &test_key(1).verifying_key()).expect("empty chain verifies");
    }

    #[test]
    fn tampered_event_fails_verification() {
        let mut chain = AgentAuditChain::new(test_key(2));
        chain
            .append(AgentAuditEvent::SessionRefreshed)
            .expect("append succeeds");
        let mut entries = chain.entries().to_vec();
        entries[0].event = AgentAuditEvent::Paired;

        let public = test_key(2).verifying_key();
        let result = verify_chain(&entries, &public);
        assert!(matches!(
            result,
            Err(AuditVerifyError::EntryHashMismatch { seq: 0 })
        ));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let mut chain = AgentAuditChain::new(test_key(3));
        chain
            .append(AgentAuditEvent::Paired)
            .expect("append succeeds");
        let mut entries = chain.entries().to_vec();
        entries[0].signature[0] ^= 0xFF;

        let public = test_key(3).verifying_key();
        let result = verify_chain(&entries, &public);
        assert!(matches!(
            result,
            Err(AuditVerifyError::BadSignature { seq: 0 })
        ));
    }

    #[test]
    fn wrong_verifying_key_fails_verification() {
        let mut chain = AgentAuditChain::new(test_key(4));
        chain
            .append(AgentAuditEvent::Paired)
            .expect("append succeeds");

        let wrong_public = test_key(5).verifying_key();
        let result = verify_chain(chain.entries(), &wrong_public);
        assert!(matches!(
            result,
            Err(AuditVerifyError::BadSignature { seq: 0 })
        ));
    }

    #[test]
    fn broken_link_fails_verification() {
        let mut chain = AgentAuditChain::new(test_key(6));
        chain
            .append(AgentAuditEvent::Paired)
            .expect("append succeeds");
        chain
            .append(AgentAuditEvent::SessionRefreshed)
            .expect("append succeeds");
        let mut entries = chain.entries().to_vec();
        // Swap the two entries' order without fixing seq/prev_hash --
        // simulates a reordering/splicing attack on a persisted file.
        entries.swap(0, 1);

        let public = test_key(6).verifying_key();
        let result = verify_chain(&entries, &public);
        assert!(result.is_err());
    }

    #[test]
    fn append_transactional_rolls_back_on_persist_failure() {
        let mut chain = AgentAuditChain::new(test_key(7));
        let result: Result<_, TransactionalAppendError<&str>> =
            chain.append_transactional(AgentAuditEvent::Paired, |_entries| Err("disk full"));
        assert!(matches!(
            result,
            Err(TransactionalAppendError::Persist("disk full"))
        ));
        assert_eq!(
            chain.len(),
            0,
            "a failed persist must not leave the entry committed in memory"
        );
    }

    #[test]
    fn append_transactional_commits_on_persist_success() {
        let mut chain = AgentAuditChain::new(test_key(8));
        let result: Result<_, TransactionalAppendError<std::convert::Infallible>> =
            chain.append_transactional(AgentAuditEvent::SessionRefreshed, |_entries| Ok(()));
        assert!(result.is_ok());
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn stable_names_are_distinct_and_dot_namespaced() {
        let events = [
            AgentAuditEvent::HostTrustFirstUse {
                daemon_endpoint: String::new(),
                suite: String::new(),
                fingerprint_hex: String::new(),
            },
            AgentAuditEvent::HostTrustRotation {
                daemon_endpoint: String::new(),
                suite: String::new(),
                old_fingerprint_hex: String::new(),
                new_fingerprint_hex: String::new(),
            },
            AgentAuditEvent::Paired,
            AgentAuditEvent::SessionRefreshed,
            AgentAuditEvent::RevocationSigned {
                target_operator_id: String::new(),
                daemon_endpoint: String::new(),
            },
            AgentAuditEvent::KeyReplacementSigned {
                target_operator_id: String::new(),
                new_ed25519_pubkey_hex: String::new(),
                daemon_endpoint: String::new(),
            },
            AgentAuditEvent::BroadGrantConfirmed {
                scope: String::new(),
                daemon_endpoint: String::new(),
            },
        ];
        let names: Vec<&str> = events.iter().map(|e| e.stable_name()).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "stable names must be distinct");
        for name in names {
            assert!(name.contains('.'), "{name} should be dot-namespaced");
        }
    }

    /// Pins the exact literal name every variant emits, mirroring
    /// `xenia_ledger::tests::consent_kind_stable_names_are_contractual`'s
    /// convention on the daemon side. The structural test above
    /// (`stable_names_are_distinct_and_dot_namespaced`) would happily pass
    /// if a variant's name were silently renamed -- distinctness and
    /// dot-namespacing survive a rename just fine. This test exists so a
    /// rename shows up as a diff a reviewer has to consciously accept: any
    /// external consumer of `GET /v1/audit` (a dashboard, a SIEM rule, an
    /// operator's own tooling) matches against these exact strings, per
    /// `docs/roadmap/POST_RC1_HARDENING_PLAN.md` Track 4's "audit event
    /// names remain stable" acceptance criterion.
    #[test]
    fn stable_names_are_contractual() {
        let cases: [(AgentAuditEvent, &str); 7] = [
            (
                AgentAuditEvent::HostTrustFirstUse {
                    daemon_endpoint: String::new(),
                    suite: String::new(),
                    fingerprint_hex: String::new(),
                },
                "host_trust.first_use",
            ),
            (
                AgentAuditEvent::HostTrustRotation {
                    daemon_endpoint: String::new(),
                    suite: String::new(),
                    old_fingerprint_hex: String::new(),
                    new_fingerprint_hex: String::new(),
                },
                "host_trust.rotation",
            ),
            (AgentAuditEvent::Paired, "session.paired"),
            (AgentAuditEvent::SessionRefreshed, "session.refreshed"),
            (
                AgentAuditEvent::RevocationSigned {
                    target_operator_id: String::new(),
                    daemon_endpoint: String::new(),
                },
                "revocation.signed",
            ),
            (
                AgentAuditEvent::KeyReplacementSigned {
                    target_operator_id: String::new(),
                    new_ed25519_pubkey_hex: String::new(),
                    daemon_endpoint: String::new(),
                },
                "key_replacement.signed",
            ),
            (
                AgentAuditEvent::BroadGrantConfirmed {
                    scope: String::new(),
                    daemon_endpoint: String::new(),
                },
                "consent_action.broad_grant_confirmed",
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(event.stable_name(), expected);
            assert_eq!(expected, expected.to_ascii_lowercase());
            assert!(!expected.contains(' '));
        }
    }
}
