// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// License exception: this crate is AGPL-3.0-or-later, unlike its sibling
// library crates in the xenia-peer workspace (xenia-peer-core, xenia-
// capture, xenia-handshake, xenia-inject) which ship under Apache-2.0 OR
// MIT per ADR-001 Decision 3. The exception is deliberate — xenia-ledger
// is the cryptographic moat of the Mycelix Sovereign commercial suite and
// is treated as application-layer rather than permissive-commons
// infrastructure. See README.md for the full rationale.

//! # xenia-ledger
//!
//! Append-only, hash-chained, Ed25519-signed consent ledger.
//!
//! Every privileged session that flows through a Xenia peer produces a
//! sequence of [`ConsentEventRecord`]s (Request, Approval, Denial,
//! Revocation, Violation). Those records are appended to a
//! [`Chain`], which computes a blake3-based hash link to the previous
//! entry and signs the resulting `entry_hash` with the operator's
//! Ed25519 signing key.
//!
//! A downstream auditor — including a non-operator third party —
//! can use [`Verifier::verify_chain`] to reconstruct every hash link
//! and every signature offline, using only the operator's public key.
//! The operator cannot produce a chain with a rewritten past unless
//! they also re-sign every affected entry, which requires the
//! private key and is by construction visible to anyone holding the
//! public key.
//!
//! This is the "admin cannot rewrite the audit log" claim made in the
//! Mycelix Sovereign threat model, enforced cryptographically.
//!
//! ## Design choices
//!
//! - **blake3 for the hash chain.** Modern, tree-based, much faster than
//!   SHA-256 at large scales. The chain itself uses only the single-
//!   shot [`blake3::hash`] API for simplicity.
//! - **Ed25519 for signatures.** Pair with the rest of the Xenia PQC
//!   hybrid story (`xenia-handshake` uses Ed25519 + ML-KEM-768). PQC-
//!   signed variants (Dilithium / ML-DSA) are a future extension tracked
//!   separately.
//! - **bincode v1 for canonical serialization.** Deterministic across
//!   runs at a given bincode version. Version-locked via the workspace.
//!   If we migrate to bincode v2 or a different serializer, a schema-
//!   version field on each entry lets old ledgers verify against old
//!   code.
//! - **No persistence layer in this crate.** Callers decide whether to
//!   store the chain as JSON, CBOR, a SQLite table, or Holochain
//!   entries. `Chain::from_entries` lets any storage layer rehydrate.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

use std::time::SystemTime;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use uuid::Uuid;

/// The kind of consent event recorded in the ledger. Mirrors the
/// state-transitions surfaced by `xenia-wire`'s consent state machine
/// (`Request` / `Response{approved: bool}` / `Revocation` /
/// `ConsentProtocolViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentKind {
    /// Admin / operator requested a privileged action on the user's machine.
    Request,
    /// User approved the request.
    Approval,
    /// User denied the request (explicit negative response).
    Denial,
    /// User revoked a previously-approved session mid-flight.
    Revocation,
    /// Protocol violation detected (e.g., a contradictory Response after a prior Revocation).
    Violation,
    /// Automated action triggered by Athena AI triage.
    AthenaTriage,
}

impl ConsentKind {
    /// Stable dot-namespaced audit event name for this consent event kind.
    ///
    /// These names are part of the operator/admin audit contract. They are
    /// intentionally decoupled from Rust enum variant spelling so UI labels,
    /// release evidence, and downstream audit consumers do not depend on
    /// `Debug` formatting.
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::Request => "consent.requested",
            Self::Approval => "consent.granted",
            Self::Denial => "consent.denied",
            Self::Revocation => "consent.revoked",
            Self::Violation => "consent.protocol_violation",
            Self::AthenaTriage => "admin.athena_triage",
        }
    }
}

/// A single consent event. Carries enough context for an auditor to
/// reconstruct which session, which request, and which party was
/// involved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentEventRecord {
    /// DID-bound source identifier of the operator requesting access
    /// (32 bytes; typically a hash of the Ed25519 verifying key, but
    /// any 32-byte opaque identifier is acceptable to this crate).
    pub source_id: [u8; 32],
    /// UUID of the Xenia session the event belongs to.
    pub session_id: Uuid,
    /// UUID of the specific consent request within the session.
    pub request_id: Uuid,
    /// Kind of event.
    pub kind: ConsentKind,
    /// Optional human-readable scope description (e.g.
    /// `"view screen, inject input on /dev/tty1"`). Audit trails
    /// benefit from this; verification does not depend on it.
    pub scope: String,
}

impl ConsentEventRecord {
    /// Stable dot-namespaced audit event name for this record.
    pub const fn stable_name(&self) -> &'static str {
        self.kind.stable_name()
    }
}

/// A signed, chained ledger entry. Every field is covered by
/// `entry_hash`; `signature` is the operator's Ed25519 signature over
/// `entry_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Monotonic 0-based sequence number. The genesis entry is 0.
    pub seq: u64,
    /// `entry_hash` of the previous entry, or `[0; 32]` for the genesis entry.
    pub prev_hash: [u8; 32],
    /// Wall-clock time of the event, as recorded by the operator.
    pub timestamp: SystemTime,
    /// The consent event itself.
    pub event: ConsentEventRecord,
    /// blake3 hash over `(seq, prev_hash, timestamp, event)`. Covers
    /// every field except `signature` itself (which signs this hash).
    pub entry_hash: [u8; 32],
    /// Ed25519 signature over `entry_hash`, 64 bytes.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Errors surfaced by [`Chain`] operations.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Serialization of an entry's pre-hash payload failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),

    /// An entry was pushed but could not be read back from the chain.
    #[error("ledger append invariant failed: pushed entry missing")]
    AppendInvariant,
}

/// Errors surfaced by [`Verifier`] operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Chain was empty where at least one entry was required.
    #[error("chain is empty")]
    Empty,
    /// A sequence number was out of order (gaps, duplicates, reversal).
    #[error("sequence at index {index}: expected {expected}, found {found}")]
    OutOfOrder {
        /// Position in the slice where the bad sequence number was found.
        index: usize,
        /// The sequence number this entry should have had.
        expected: u64,
        /// The sequence number it actually had.
        found: u64,
    },
    /// An entry's `prev_hash` did not match the prior entry's `entry_hash`.
    #[error("broken hash link at seq {seq}")]
    BrokenLink {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// An entry's `entry_hash` does not match a freshly-computed hash over its fields.
    #[error("entry_hash mismatch at seq {seq} — tampering detected")]
    EntryHashMismatch {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// An entry's signature failed to verify under the provided public key.
    #[error("signature invalid at seq {seq}")]
    BadSignature {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// The genesis entry's `prev_hash` was not all zeros.
    #[error("genesis prev_hash must be all zeros")]
    BadGenesis,
}

/// Append-only, hash-chained ledger owned by an operator with a
/// signing key. See the crate-level docs for the semantics.
pub struct Chain {
    entries: Vec<LedgerEntry>,
    signing_key: SigningKey,
}

impl Chain {
    /// Create a new empty chain held by `signing_key`.
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            entries: Vec::new(),
            signing_key,
        }
    }

    /// Rehydrate a chain from a previously-persisted sequence of entries.
    ///
    /// Does NOT verify the rehydrated entries — the caller should run
    /// [`Verifier::verify_chain`] with the operator's public key to
    /// confirm integrity. This method only establishes the append
    /// frontier for subsequent [`Chain::append`] calls.
    pub fn from_entries(entries: Vec<LedgerEntry>, signing_key: SigningKey) -> Self {
        Self {
            entries,
            signing_key,
        }
    }

    /// Return the number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `entry_hash` of the most recent entry, or `[0; 32]` if the
    /// chain is empty (the implicit "pre-genesis" hash).
    pub fn last_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32])
    }

    /// Iterate over all entries in sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &LedgerEntry> {
        self.entries.iter()
    }

    /// Append a new consent event, producing a signed, chained entry.
    pub fn append(&mut self, event: ConsentEventRecord) -> Result<&LedgerEntry, LedgerError> {
        let entry_index = self.entries.len();
        let seq = entry_index as u64;
        let prev_hash = self.last_hash();
        let timestamp = SystemTime::now();

        let entry_hash = compute_entry_hash(seq, &prev_hash, &timestamp, &event)?;
        let signature = self.signing_key.sign(&entry_hash).to_bytes();

        self.entries.push(LedgerEntry {
            seq,
            prev_hash,
            timestamp,
            event,
            entry_hash,
            signature,
        });
        self.entries
            .get(entry_index)
            .ok_or(LedgerError::AppendInvariant)
    }

    /// Consume the chain and return its entries. Useful for persistence.
    pub fn into_entries(self) -> Vec<LedgerEntry> {
        self.entries
    }
}

/// Stateless verifier. Separate from [`Chain`] so an auditor can verify
/// a chain using only the public key and the serialized entries, never
/// needing access to the signing key.
pub struct Verifier;

impl Verifier {
    /// Verify every entry in a chain: sequence continuity, hash link,
    /// entry_hash recomputation, and Ed25519 signature.
    ///
    /// An empty slice passes vacuously. Callers who require at least
    /// one entry should check length separately before calling this.
    pub fn verify_chain(
        entries: &[LedgerEntry],
        public_key: &VerifyingKey,
    ) -> Result<(), VerifyError> {
        let mut expected_prev = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            let expected_seq = index as u64;
            if entry.seq != expected_seq {
                return Err(VerifyError::OutOfOrder {
                    index,
                    expected: expected_seq,
                    found: entry.seq,
                });
            }

            if entry.seq == 0 && entry.prev_hash != [0u8; 32] {
                return Err(VerifyError::BadGenesis);
            }
            if entry.prev_hash != expected_prev {
                return Err(VerifyError::BrokenLink { seq: entry.seq });
            }

            let recomputed =
                compute_entry_hash(entry.seq, &entry.prev_hash, &entry.timestamp, &entry.event)
                    .map_err(|_| VerifyError::EntryHashMismatch { seq: entry.seq })?;
            if recomputed != entry.entry_hash {
                return Err(VerifyError::EntryHashMismatch { seq: entry.seq });
            }

            let sig = Signature::from_bytes(&entry.signature);
            public_key
                .verify(&entry.entry_hash, &sig)
                .map_err(|_| VerifyError::BadSignature { seq: entry.seq })?;

            expected_prev = entry.entry_hash;
        }
        Ok(())
    }
}

// ─────────────────────────── internals ─────────────────────────────

/// Canonical pre-image for the entry hash. `bincode` v1 with default
/// options produces a deterministic, length-prefixed big-endian
/// encoding. Locked to the crate's bincode version (1.3 in the
/// workspace).
#[derive(Serialize)]
struct EntryPreimage<'a> {
    seq: u64,
    prev_hash: [u8; 32],
    timestamp: &'a SystemTime,
    event: &'a ConsentEventRecord,
}

fn compute_entry_hash(
    seq: u64,
    prev_hash: &[u8; 32],
    timestamp: &SystemTime,
    event: &ConsentEventRecord,
) -> Result<[u8; 32], LedgerError> {
    let preimage = EntryPreimage {
        seq,
        prev_hash: *prev_hash,
        timestamp,
        event,
    };
    let bytes = bincode::serialize(&preimage)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

// ────────────────────────────── Tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(kind: ConsentKind) -> ConsentEventRecord {
        ConsentEventRecord {
            source_id: [0xAB; 32],
            session_id: Uuid::from_bytes([1u8; 16]),
            request_id: Uuid::from_bytes([2u8; 16]),
            kind,
            scope: "view screen".to_string(),
        }
    }

    fn new_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn consent_kind_stable_names_are_contractual() {
        let cases = [
            (ConsentKind::Request, "consent.requested"),
            (ConsentKind::Approval, "consent.granted"),
            (ConsentKind::Denial, "consent.denied"),
            (ConsentKind::Revocation, "consent.revoked"),
            (ConsentKind::Violation, "consent.protocol_violation"),
            (ConsentKind::AthenaTriage, "admin.athena_triage"),
        ];

        for (kind, expected) in cases {
            assert_eq!(kind.stable_name(), expected);
            assert!(expected.contains('.'));
            assert_eq!(expected, expected.to_ascii_lowercase());
            assert!(!expected.contains(' '));
        }
    }

    #[test]
    fn consent_event_record_uses_stable_kind_name() {
        let event = sample_event(ConsentKind::Approval);
        assert_eq!(event.stable_name(), "consent.granted");
    }

    #[test]
    fn empty_chain_verifies_vacuously() {
        let sk = new_signing_key();
        let chain = Chain::new(sk.clone());
        let pk = sk.verifying_key();
        Verifier::verify_chain(chain.iter().cloned().collect::<Vec<_>>().as_slice(), &pk).unwrap();
    }

    #[test]
    fn genesis_entry_has_zero_prev_hash_and_seq_zero() {
        let sk = new_signing_key();
        let mut chain = Chain::new(sk);
        let entry = chain.append(sample_event(ConsentKind::Request)).unwrap();
        assert_eq!(entry.seq, 0);
        assert_eq!(entry.prev_hash, [0u8; 32]);
    }

    #[test]
    fn chain_of_five_entries_links_and_verifies() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);

        for kind in [
            ConsentKind::Request,
            ConsentKind::Approval,
            ConsentKind::Revocation,
            ConsentKind::Request,
            ConsentKind::Denial,
        ] {
            chain.append(sample_event(kind)).unwrap();
        }

        let entries: Vec<_> = chain.iter().cloned().collect();
        assert_eq!(entries.len(), 5);

        // Sequence monotone.
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq, i as u64);
        }

        // Hash link: each prev_hash matches previous entry_hash.
        for w in entries.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].entry_hash);
        }

        Verifier::verify_chain(&entries, &pk).unwrap();
    }

    #[test]
    fn tampering_with_event_kind_breaks_entry_hash() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        entries[0].event.kind = ConsentKind::Denial; // flip Approval to Denial after the fact

        match Verifier::verify_chain(&entries, &pk) {
            Err(VerifyError::EntryHashMismatch { seq: 0 }) => {}
            other => panic!("expected EntryHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampering_with_entry_hash_breaks_signature() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        // Mutate entry_hash to something "plausibly valid" — recompute
        // for a fake event to keep EntryHashMismatch from firing first.
        let fake_event = sample_event(ConsentKind::Denial);
        entries[0].event = fake_event.clone();
        entries[0].entry_hash = compute_entry_hash(
            entries[0].seq,
            &entries[0].prev_hash,
            &entries[0].timestamp,
            &fake_event,
        )
        .unwrap();

        // entry_hash now recomputes correctly, but the signature was
        // over the ORIGINAL entry_hash, so verification fails on the
        // signature step.
        match Verifier::verify_chain(&entries, &pk) {
            Err(VerifyError::BadSignature { seq: 0 }) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn reordering_entries_breaks_hash_link() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();
        chain.append(sample_event(ConsentKind::Approval)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        entries.swap(0, 1); // reorder

        let err = Verifier::verify_chain(&entries, &pk).unwrap_err();
        // The OutOfOrder check fires before BrokenLink because sequence
        // numbers are checked first at each index.
        assert!(matches!(err, VerifyError::OutOfOrder { .. }));
    }

    #[test]
    fn wrong_public_key_rejects_valid_chain() {
        let sk = new_signing_key();
        let mut chain = Chain::new(sk);
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let entries: Vec<_> = chain.iter().cloned().collect();
        let wrong_pk = new_signing_key().verifying_key();
        match Verifier::verify_chain(&entries, &wrong_pk) {
            Err(VerifyError::BadSignature { seq: 0 }) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn rehydrated_chain_can_continue_appending() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();

        let entries_out = {
            let mut chain = Chain::new(sk.clone());
            chain.append(sample_event(ConsentKind::Request)).unwrap();
            chain.append(sample_event(ConsentKind::Approval)).unwrap();
            chain.into_entries()
        };

        let mut chain = Chain::from_entries(entries_out, sk);
        chain.append(sample_event(ConsentKind::Revocation)).unwrap();

        let entries: Vec<_> = chain.iter().cloned().collect();
        assert_eq!(entries.len(), 3);
        Verifier::verify_chain(&entries, &pk).unwrap();
    }

    #[test]
    fn forged_genesis_with_nonzero_prev_hash_is_rejected() {
        let sk = new_signing_key();
        let pk = sk.verifying_key();
        let mut chain = Chain::new(sk.clone());
        chain.append(sample_event(ConsentKind::Request)).unwrap();

        let mut entries: Vec<_> = chain.iter().cloned().collect();
        // Forge a nonzero prev_hash on genesis. We have to also
        // recompute entry_hash and re-sign to get past those checks.
        entries[0].prev_hash = [0xFFu8; 32];
        entries[0].entry_hash = compute_entry_hash(
            entries[0].seq,
            &entries[0].prev_hash,
            &entries[0].timestamp,
            &entries[0].event,
        )
        .unwrap();
        entries[0].signature = sk.sign(&entries[0].entry_hash).to_bytes();

        match Verifier::verify_chain(&entries, &pk) {
            Err(VerifyError::BadGenesis) => {}
            other => panic!("expected BadGenesis, got {other:?}"),
        }
    }
}
