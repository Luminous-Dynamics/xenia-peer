// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed, commitment-only Xenia anchoring for external witness frontiers.
//!
//! This module deliberately does not overload [`crate::ConsentEventRecord`].
//! Witness chronology is separate from human consent chronology even though both
//! are authenticated by the same Xenia ledger authority key.
//!
//! The protocol has two distinct signed objects:
//!
//! 1. [`SignedWitnessFrontierAnchorV1`] is the durable monotonic record written
//!    through an external compare-and-swap store.
//! 2. [`SignedWitnessFrontierObservationV1`] is a fresh challenge-bound statement
//!    of what that store says is current *now*.
//!
//! A stored anchor alone is therefore not treated as freshness proof. The
//! consent-ledger count/head carried by these records is signed context only; it
//! is not, by itself, proof that the consent ledger was durably persisted.

use ed25519_dalek::{Signature, Signer, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Chain, PersistenceDisposition, SignatureEnvelope, SignatureSuite};

/// Schema version for the Xenia witness-anchor protocol.
pub const WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION: u16 = 1;
/// Symthaea's independent V1 witness-frontier statement schema version.
pub const SYMTHAEA_WITNESS_FRONTIER_STATEMENT_SCHEMA_VERSION: u16 = 1;
/// Exact Symthaea operation-id domain. Cross-repository byte compatibility is normative.
pub const SYMTHAEA_WITNESS_ANCHOR_OPERATION_DOMAIN: &[u8] =
    b"symthaea.qualification-witness.anchor-operation.v1\0";
/// Exact Symthaea witness-frontier statement domain.
pub const SYMTHAEA_WITNESS_FRONTIER_STATEMENT_DOMAIN: &[u8] =
    b"symthaea.qualification-witness.sequence-frontier.v1\0";
/// Xenia signature domain for durable witness-frontier anchor records.
pub const XENIA_WITNESS_FRONTIER_ANCHOR_DOMAIN: &[u8] = b"xenia.witness-frontier-anchor.v1\0";
/// Xenia fingerprint domain for one complete signed anchor record.
pub const XENIA_WITNESS_FRONTIER_ANCHOR_FINGERPRINT_DOMAIN: &[u8] =
    b"xenia.witness-frontier-anchor-fingerprint.v1\0";
/// Xenia signature domain for fresh current-frontier observations.
pub const XENIA_WITNESS_FRONTIER_OBSERVATION_DOMAIN: &[u8] =
    b"xenia.witness-frontier-observation.v1\0";
/// Xenia fingerprint domain for a complete signed current-frontier observation.
pub const XENIA_WITNESS_FRONTIER_OBSERVATION_FINGERPRINT_DOMAIN: &[u8] =
    b"xenia.witness-frontier-observation-fingerprint.v1\0";
/// Domain used to derive a compact source namespace from the Xenia key + policy.
pub const XENIA_WITNESS_FRONTIER_SOURCE_DOMAIN: &[u8] = b"xenia.witness-frontier-source-id.v1\0";

const ZERO16: [u8; 16] = [0; 16];
const ZERO32: [u8; 32] = [0; 32];

/// Source policy configured by the Xenia witness-anchor service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XeniaWitnessFrontierSourcePolicyV1 {
    /// Monotonic source epoch. A recovery/key-policy transition advances it.
    pub source_epoch: u64,
    /// Commitment to concrete CAS-store, freshness, retention and transport policy.
    pub anchor_policy_digest: [u8; 32],
}

impl XeniaWitnessFrontierSourcePolicyV1 {
    /// Fail closed on placeholder policy state.
    pub fn validate(self) -> Result<(), WitnessFrontierAnchorError> {
        if self.source_epoch == 0 || self.anchor_policy_digest == ZERO32 {
            return Err(WitnessFrontierAnchorError::InvalidSourcePolicy);
        }
        Ok(())
    }
}

/// Derive the 16-byte external-source namespace bound to one Xenia ledger key
/// and one reviewed anchor policy. Changing either changes the source identity.
pub fn derive_xenia_witness_frontier_source_id(
    ledger_public_key: [u8; 32],
    anchor_policy_digest: [u8; 32],
) -> Result<[u8; 16], WitnessFrontierAnchorError> {
    if ledger_public_key == ZERO32 || anchor_policy_digest == ZERO32 {
        return Err(WitnessFrontierAnchorError::InvalidSourcePolicy);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(XENIA_WITNESS_FRONTIER_SOURCE_DOMAIN);
    hasher.update(&ledger_public_key);
    hasher.update(&anchor_policy_digest);
    let digest = hasher.finalize();
    let mut source_id = [0u8; 16];
    source_id.copy_from_slice(&digest.as_bytes()[..16]);
    if source_id == ZERO16 {
        return Err(WitnessFrontierAnchorError::InvalidSourcePolicy);
    }
    Ok(source_id)
}

/// Crypto-free target copied from Symthaea's guarded V1 anchor operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFrontierAnchorTargetV1 {
    /// Must equal [`WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// BLAKE3 commitment to the exact Symthaea operation transcript.
    pub operation_id: [u8; 32],
    /// Xenia source namespace.
    pub source_id: [u8; 16],
    /// Xenia source epoch.
    pub source_epoch: u64,
    /// Commitment to the source-specific anchor policy.
    pub anchor_policy_digest: [u8; 32],
    /// Qualification witness identity.
    pub witness_id: [u8; 16],
    /// Durable local witness reservation high watermark.
    pub high_watermark: u64,
    /// Durable local reservation-chain head.
    pub reservation_head: [u8; 32],
    /// Canonical witness-frontier statement commitment.
    pub frontier_statement_digest: [u8; 32],
}

impl WitnessFrontierAnchorTargetV1 {
    /// Validate the target and independently recompute both Symthaea commitments.
    pub fn validate(&self) -> Result<(), WitnessFrontierAnchorError> {
        if self.schema_version != WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION
            || self.operation_id == ZERO32
            || self.source_id == ZERO16
            || self.source_epoch == 0
            || self.anchor_policy_digest == ZERO32
            || self.witness_id == ZERO16
            || self.high_watermark == 0
            || self.reservation_head == ZERO32
            || self.frontier_statement_digest == ZERO32
        {
            return Err(WitnessFrontierAnchorError::MalformedTarget);
        }
        if self.frontier_statement_digest != self.recompute_frontier_statement_digest() {
            return Err(WitnessFrontierAnchorError::FrontierStatementDigestMismatch);
        }
        if self.operation_id != self.recompute_operation_id() {
            return Err(WitnessFrontierAnchorError::OperationIdMismatch);
        }
        Ok(())
    }

    /// Recompute Symthaea's canonical witness-frontier statement digest.
    pub fn recompute_frontier_statement_digest(&self) -> [u8; 32] {
        witness_frontier_statement_digest(
            self.witness_id,
            self.high_watermark,
            self.reservation_head,
        )
    }

    /// Canonical operation bytes defined by Symthaea #457.
    pub fn canonical_operation_message(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(224);
        bytes.extend_from_slice(SYMTHAEA_WITNESS_ANCHOR_OPERATION_DOMAIN);
        bytes.extend_from_slice(&WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.source_id);
        bytes.extend_from_slice(&self.source_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.anchor_policy_digest);
        bytes.extend_from_slice(&self.witness_id);
        bytes.extend_from_slice(&self.high_watermark.to_be_bytes());
        bytes.extend_from_slice(&self.reservation_head);
        bytes.extend_from_slice(&self.frontier_statement_digest);
        bytes
    }

    /// Recompute the deterministic Symthaea operation id.
    pub fn recompute_operation_id(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_operation_message()).as_bytes()
    }
}

/// Durable signed Xenia record for one exact witness frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWitnessFrontierAnchorV1 {
    /// Protocol schema version.
    pub schema_version: u16,
    /// Exact Symthaea target.
    pub target: WitnessFrontierAnchorTargetV1,
    /// Monotonic sequence inside this `(source_id, source_epoch, witness_id)` domain.
    pub anchor_sequence: u64,
    /// Fingerprint of the immediately previous signed anchor, or zero for sequence 1.
    pub previous_anchor_fingerprint: [u8; 32],
    /// Xenia consent-ledger entry count at signing time. Context only, not durability proof.
    pub ledger_entry_count: u64,
    /// Xenia consent-ledger head at signing time. Context only, not durability proof.
    pub ledger_head_hash: [u8; 32],
    /// Xenia ledger public key that signed this record.
    pub ledger_public_key: [u8; 32],
    /// Caller-supplied trusted wall-clock instant used for the signed issue record.
    pub issued_at_unix_s: u64,
    /// Ed25519 signature over [`SignedWitnessFrontierAnchorV1::canonical_message`].
    pub signature: SignatureEnvelope,
}

impl SignedWitnessFrontierAnchorV1 {
    /// Canonical hand-written signed message.
    pub fn canonical_message(&self) -> Result<Vec<u8>, WitnessFrontierAnchorError> {
        self.validate_unsigned_shape()?;
        let mut bytes = Vec::with_capacity(384);
        bytes.extend_from_slice(XENIA_WITNESS_FRONTIER_ANCHOR_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.target.canonical_operation_message());
        bytes.extend_from_slice(&self.target.operation_id);
        bytes.extend_from_slice(&self.anchor_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.previous_anchor_fingerprint);
        bytes.extend_from_slice(&self.ledger_entry_count.to_be_bytes());
        bytes.extend_from_slice(&self.ledger_head_hash);
        bytes.extend_from_slice(&self.ledger_public_key);
        bytes.extend_from_slice(&self.issued_at_unix_s.to_be_bytes());
        Ok(bytes)
    }

    /// Verify structure and Ed25519 signature under the embedded Xenia key.
    pub fn verify(&self) -> Result<(), WitnessFrontierAnchorError> {
        let message = self.canonical_message()?;
        let suite = self.signature.validate_shape()?;
        if suite != SignatureSuite::Ed25519Rfc8032 {
            return Err(WitnessFrontierAnchorError::UnsupportedAnchorSignatureSuite);
        }
        let public_key = VerifyingKey::from_bytes(&self.ledger_public_key)
            .map_err(|_| WitnessFrontierAnchorError::BadLedgerPublicKey)?;
        let signature_bytes: [u8; 64] = self
            .signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| WitnessFrontierAnchorError::BadAnchorSignature)?;
        public_key
            .verify(&message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| WitnessFrontierAnchorError::BadAnchorSignature)
    }

    /// Stable fingerprint used as the next anchor's CAS predecessor.
    pub fn fingerprint(&self) -> Result<[u8; 32], WitnessFrontierAnchorError> {
        self.verify()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(XENIA_WITNESS_FRONTIER_ANCHOR_FINGERPRINT_DOMAIN);
        hasher.update(&self.canonical_message()?);
        hasher.update(self.signature.algorithm.as_bytes());
        hasher.update(&(self.signature.signature.len() as u64).to_be_bytes());
        hasher.update(&self.signature.signature);
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate_unsigned_shape(&self) -> Result<(), WitnessFrontierAnchorError> {
        if self.schema_version != WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION
            || self.anchor_sequence == 0
            || self.ledger_entry_count == 0
            || self.ledger_head_hash == ZERO32
            || self.ledger_public_key == ZERO32
            || self.issued_at_unix_s == 0
        {
            return Err(WitnessFrontierAnchorError::MalformedAnchor);
        }
        self.target.validate()?;
        let expected_source = derive_xenia_witness_frontier_source_id(
            self.ledger_public_key,
            self.target.anchor_policy_digest,
        )?;
        if self.target.source_id != expected_source {
            return Err(WitnessFrontierAnchorError::SourceBindingMismatch);
        }
        if self.anchor_sequence == 1 {
            if self.previous_anchor_fingerprint != ZERO32 {
                return Err(WitnessFrontierAnchorError::PreviousAnchorMismatch);
            }
        } else if self.previous_anchor_fingerprint == ZERO32 {
            return Err(WitnessFrontierAnchorError::PreviousAnchorMismatch);
        }
        Ok(())
    }
}

/// Minimal signed-current summary retained in a fresh observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFrontierAnchorSummaryV1 {
    /// Current source sequence.
    pub anchor_sequence: u64,
    /// Fingerprint of the exact signed current anchor record.
    pub anchor_fingerprint: [u8; 32],
    /// Operation id that produced the current anchor.
    pub operation_id: [u8; 32],
    /// Current witness high watermark.
    pub high_watermark: u64,
    /// Current witness reservation head.
    pub reservation_head: [u8; 32],
    /// Current witness frontier statement digest.
    pub frontier_statement_digest: [u8; 32],
}

/// Fresh challenge-bound statement of the current Xenia anchor-store state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWitnessFrontierObservationV1 {
    /// Protocol schema version.
    pub schema_version: u16,
    /// Derived Xenia source namespace.
    pub source_id: [u8; 16],
    /// Source epoch.
    pub source_epoch: u64,
    /// Reviewed anchor policy commitment.
    pub anchor_policy_digest: [u8; 32],
    /// Witness whose current state was queried.
    pub witness_id: [u8; 16],
    /// Verifier-provided anti-replay challenge.
    pub challenge: [u8; 32],
    /// Trusted wall-clock instant at observation signing.
    pub observed_at_unix_s: u64,
    /// Current anchor, or `None` when this source domain has never anchored the witness.
    pub current: Option<WitnessFrontierAnchorSummaryV1>,
    /// Current Xenia consent-ledger entry count. Context only, not durability proof.
    pub ledger_entry_count: u64,
    /// Current Xenia consent-ledger head. Context only, not durability proof.
    pub ledger_head_hash: [u8; 32],
    /// Xenia ledger authority public key.
    pub ledger_public_key: [u8; 32],
    /// Ed25519 signature over the canonical observation.
    pub signature: SignatureEnvelope,
}

impl SignedWitnessFrontierObservationV1 {
    /// Verify a fresh observation against externally trusted expectations.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_fresh(
        &self,
        expected_challenge: [u8; 32],
        trusted_ledger_public_key: [u8; 32],
        expected_source_id: [u8; 16],
        expected_source_epoch: u64,
        expected_anchor_policy_digest: [u8; 32],
        expected_witness_id: [u8; 16],
        now_unix_s: u64,
        max_age_secs: u64,
        max_future_skew_secs: u64,
    ) -> Result<(), WitnessFrontierAnchorError> {
        self.verify_signature()?;
        if self.challenge != expected_challenge
            || expected_challenge == ZERO32
            || self.ledger_public_key != trusted_ledger_public_key
            || self.source_id != expected_source_id
            || self.source_epoch != expected_source_epoch
            || self.anchor_policy_digest != expected_anchor_policy_digest
            || self.witness_id != expected_witness_id
        {
            return Err(WitnessFrontierAnchorError::ObservationBindingMismatch);
        }
        let expected_source = derive_xenia_witness_frontier_source_id(
            trusted_ledger_public_key,
            expected_anchor_policy_digest,
        )?;
        if expected_source != expected_source_id {
            return Err(WitnessFrontierAnchorError::ObservationBindingMismatch);
        }
        let oldest = now_unix_s.saturating_sub(max_age_secs);
        let latest = now_unix_s.saturating_add(max_future_skew_secs);
        if self.observed_at_unix_s < oldest || self.observed_at_unix_s > latest {
            return Err(WitnessFrontierAnchorError::ObservationStaleOrFuture);
        }
        Ok(())
    }

    /// Verify that this fresh observation names the exact durable anchor record
    /// supplied by the caller, including its signed fingerprint and frontier.
    pub fn verify_current_anchor(
        &self,
        anchor: &SignedWitnessFrontierAnchorV1,
    ) -> Result<(), WitnessFrontierAnchorError> {
        self.verify_signature()?;
        anchor.verify()?;
        let current = self
            .current
            .ok_or(WitnessFrontierAnchorError::ObservationCurrentAnchorMismatch)?;
        let expected = WitnessFrontierAnchorSummaryV1 {
            anchor_sequence: anchor.anchor_sequence,
            anchor_fingerprint: anchor.fingerprint()?,
            operation_id: anchor.target.operation_id,
            high_watermark: anchor.target.high_watermark,
            reservation_head: anchor.target.reservation_head,
            frontier_statement_digest: anchor.target.frontier_statement_digest,
        };
        if current != expected
            || anchor.ledger_public_key != self.ledger_public_key
            || anchor.target.source_id != self.source_id
            || anchor.target.source_epoch != self.source_epoch
            || anchor.target.anchor_policy_digest != self.anchor_policy_digest
            || anchor.target.witness_id != self.witness_id
        {
            return Err(WitnessFrontierAnchorError::ObservationCurrentAnchorMismatch);
        }
        Ok(())
    }

    /// Stable commitment suitable for a higher-level freshness-evidence digest.
    pub fn fingerprint(&self) -> Result<[u8; 32], WitnessFrontierAnchorError> {
        self.verify_signature()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(XENIA_WITNESS_FRONTIER_OBSERVATION_FINGERPRINT_DOMAIN);
        hasher.update(&self.canonical_message()?);
        hasher.update(self.signature.algorithm.as_bytes());
        hasher.update(&(self.signature.signature.len() as u64).to_be_bytes());
        hasher.update(&self.signature.signature);
        Ok(*hasher.finalize().as_bytes())
    }

    fn canonical_message(&self) -> Result<Vec<u8>, WitnessFrontierAnchorError> {
        if self.schema_version != WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION
            || self.source_id == ZERO16
            || self.source_epoch == 0
            || self.anchor_policy_digest == ZERO32
            || self.witness_id == ZERO16
            || self.challenge == ZERO32
            || self.observed_at_unix_s == 0
            || self.ledger_entry_count == 0
            || self.ledger_head_hash == ZERO32
            || self.ledger_public_key == ZERO32
        {
            return Err(WitnessFrontierAnchorError::MalformedObservation);
        }
        let expected_source = derive_xenia_witness_frontier_source_id(
            self.ledger_public_key,
            self.anchor_policy_digest,
        )?;
        if self.source_id != expected_source {
            return Err(WitnessFrontierAnchorError::SourceBindingMismatch);
        }
        if let Some(current) = self.current
            && (current.anchor_sequence == 0
                || current.anchor_fingerprint == ZERO32
                || current.operation_id == ZERO32
                || current.high_watermark == 0
                || current.reservation_head == ZERO32
                || current.frontier_statement_digest == ZERO32
                || current.frontier_statement_digest
                    != witness_frontier_statement_digest(
                        self.witness_id,
                        current.high_watermark,
                        current.reservation_head,
                    ))
        {
            return Err(WitnessFrontierAnchorError::MalformedObservation);
        }
        let mut bytes = Vec::with_capacity(384);
        bytes.extend_from_slice(XENIA_WITNESS_FRONTIER_OBSERVATION_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.source_id);
        bytes.extend_from_slice(&self.source_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.anchor_policy_digest);
        bytes.extend_from_slice(&self.witness_id);
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(&self.observed_at_unix_s.to_be_bytes());
        match self.current {
            None => bytes.push(0),
            Some(current) => {
                bytes.push(1);
                bytes.extend_from_slice(&current.anchor_sequence.to_be_bytes());
                bytes.extend_from_slice(&current.anchor_fingerprint);
                bytes.extend_from_slice(&current.operation_id);
                bytes.extend_from_slice(&current.high_watermark.to_be_bytes());
                bytes.extend_from_slice(&current.reservation_head);
                bytes.extend_from_slice(&current.frontier_statement_digest);
            }
        }
        bytes.extend_from_slice(&self.ledger_entry_count.to_be_bytes());
        bytes.extend_from_slice(&self.ledger_head_hash);
        bytes.extend_from_slice(&self.ledger_public_key);
        Ok(bytes)
    }

    fn verify_signature(&self) -> Result<(), WitnessFrontierAnchorError> {
        let message = self.canonical_message()?;
        if self.signature.validate_shape()? != SignatureSuite::Ed25519Rfc8032 {
            return Err(WitnessFrontierAnchorError::UnsupportedAnchorSignatureSuite);
        }
        let key = VerifyingKey::from_bytes(&self.ledger_public_key)
            .map_err(|_| WitnessFrontierAnchorError::BadLedgerPublicKey)?;
        let signature_bytes: [u8; 64] = self
            .signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| WitnessFrontierAnchorError::BadAnchorSignature)?;
        key.verify(&message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| WitnessFrontierAnchorError::BadAnchorSignature)
    }
}

/// Durable-store contract for Xenia witness-frontier anchors.
///
/// A successful `None` lookup is authoritative for the queried namespace.
/// `compare_and_swap` MUST be atomic/linearizable and MUST interpret
/// `PersistenceDisposition::Persisted` as a durable exact-candidate commit.
/// Diagnostic digests returned on failures must be nonzero and contain no raw
/// application payload.
pub trait WitnessFrontierAnchorStore {
    /// Lookup one idempotency operation.
    fn lookup_operation(
        &mut self,
        source_id: [u8; 16],
        source_epoch: u64,
        operation_id: [u8; 32],
    ) -> Result<Option<SignedWitnessFrontierAnchorV1>, [u8; 32]>;

    /// Read the latest anchor for one witness within one source epoch.
    fn current_for_witness(
        &mut self,
        source_id: [u8; 16],
        source_epoch: u64,
        witness_id: [u8; 16],
    ) -> Result<Option<SignedWitnessFrontierAnchorV1>, [u8; 32]>;

    /// Atomically install `candidate` iff the current fingerprint is exactly
    /// `expected_previous` (`None` means no prior anchor in this namespace).
    fn compare_and_swap(
        &mut self,
        expected_previous: Option<[u8; 32]>,
        candidate: &SignedWitnessFrontierAnchorV1,
    ) -> PersistenceDisposition<[u8; 32]>;
}

/// Result after the durable store effect boundary.
#[derive(Debug)]
pub enum WitnessFrontierAnchorAppendOutcomeV1 {
    /// Exact candidate is durably persisted.
    Persisted(SignedWitnessFrontierAnchorV1),
    /// Store proved the candidate was not persisted; safe to retry the exact operation.
    ProvenNotPersisted {
        /// Privacy-minimized store diagnostic commitment.
        diagnostic_digest: [u8; 32],
        /// Exact signed candidate that was rejected.
        candidate: SignedWitnessFrontierAnchorV1,
    },
    /// Commit may have happened; must reconcile by operation id before retry.
    OutcomeUnknown {
        /// Privacy-minimized store diagnostic commitment.
        diagnostic_digest: [u8; 32],
        /// Exact signed candidate whose persistence is ambiguous.
        candidate: SignedWitnessFrontierAnchorV1,
    },
}

/// Result of explicit idempotency reconciliation.
#[derive(Debug)]
pub enum WitnessFrontierAnchorReconciliationV1 {
    /// Exact operation is present and authenticated.
    Persisted(Box<SignedWitnessFrontierAnchorV1>),
    /// Authoritative store lookup proves the operation is absent.
    ProvenNotPersisted,
    /// Store state could not be established safely.
    OutcomeUnknown {
        /// Privacy-minimized store diagnostic commitment.
        diagnostic_digest: [u8; 32],
    },
}

impl Chain {
    /// Sign and atomically persist one witness frontier.
    ///
    /// Pre-dispatch validation and authoritative reads may return `Err`. Once
    /// `store.compare_and_swap` has been invoked, every outcome is represented by
    /// [`WitnessFrontierAnchorAppendOutcomeV1`] so persistence ambiguity cannot
    /// collapse into an ordinary retryable error.
    pub fn append_witness_frontier_anchor_v1<S: WitnessFrontierAnchorStore>(
        &self,
        target: WitnessFrontierAnchorTargetV1,
        policy: XeniaWitnessFrontierSourcePolicyV1,
        issued_at_unix_s: u64,
        store: &mut S,
    ) -> Result<WitnessFrontierAnchorAppendOutcomeV1, WitnessFrontierAnchorError> {
        target.validate()?;
        policy.validate()?;
        self.ensure_anchor_signing_ready()?;
        let ledger_public_key = self.signing_key.verifying_key().to_bytes();
        let expected_source_id = derive_xenia_witness_frontier_source_id(
            ledger_public_key,
            policy.anchor_policy_digest,
        )?;
        if target.source_id != expected_source_id
            || target.source_epoch != policy.source_epoch
            || target.anchor_policy_digest != policy.anchor_policy_digest
        {
            return Err(WitnessFrontierAnchorError::SourceBindingMismatch);
        }
        if issued_at_unix_s == 0 {
            return Err(WitnessFrontierAnchorError::InvalidTimestamp);
        }

        if let Some(existing) = store
            .lookup_operation(target.source_id, target.source_epoch, target.operation_id)
            .map_err(WitnessFrontierAnchorError::PreDispatchStore)?
        {
            existing.verify()?;
            if existing.target != target || existing.ledger_public_key != ledger_public_key {
                return Err(WitnessFrontierAnchorError::OperationIdCollision);
            }
            return Ok(WitnessFrontierAnchorAppendOutcomeV1::Persisted(existing));
        }

        let current = store
            .current_for_witness(target.source_id, target.source_epoch, target.witness_id)
            .map_err(WitnessFrontierAnchorError::PreDispatchStore)?;
        let (anchor_sequence, previous_anchor_fingerprint) = match current {
            None => (1, ZERO32),
            Some(previous) => {
                previous.verify()?;
                if previous.ledger_public_key != ledger_public_key {
                    return Err(WitnessFrontierAnchorError::CurrentAnchorSignerMismatch);
                }
                validate_previous_namespace(&previous, &target)?;
                if target.high_watermark <= previous.target.high_watermark {
                    return Err(WitnessFrontierAnchorError::NonMonotonicWitnessFrontier);
                }
                let next = previous
                    .anchor_sequence
                    .checked_add(1)
                    .ok_or(WitnessFrontierAnchorError::AnchorSequenceOverflow)?;
                (next, previous.fingerprint()?)
            }
        };

        let mut candidate = SignedWitnessFrontierAnchorV1 {
            schema_version: WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION,
            target,
            anchor_sequence,
            previous_anchor_fingerprint,
            ledger_entry_count: self.entry_count(),
            ledger_head_hash: self.last_hash(),
            ledger_public_key,
            issued_at_unix_s,
            signature: SignatureEnvelope::ed25519([0; 64]),
        };
        let signature = self
            .signing_key
            .sign(&candidate.canonical_message()?)
            .to_bytes();
        candidate.signature = SignatureEnvelope::ed25519(signature);
        candidate.verify()?;

        let expected_previous = if anchor_sequence == 1 {
            None
        } else {
            Some(previous_anchor_fingerprint)
        };
        match store.compare_and_swap(expected_previous, &candidate) {
            PersistenceDisposition::Persisted => {
                Ok(WitnessFrontierAnchorAppendOutcomeV1::Persisted(candidate))
            }
            PersistenceDisposition::ProvenNotPersisted(diagnostic_digest) => {
                if diagnostic_digest == ZERO32 {
                    return Ok(WitnessFrontierAnchorAppendOutcomeV1::OutcomeUnknown {
                        diagnostic_digest: diagnostic_label(b"zero-proven-not-persisted"),
                        candidate,
                    });
                }
                Ok(WitnessFrontierAnchorAppendOutcomeV1::ProvenNotPersisted {
                    diagnostic_digest,
                    candidate,
                })
            }
            PersistenceDisposition::OutcomeUnknown(diagnostic_digest) => {
                Ok(WitnessFrontierAnchorAppendOutcomeV1::OutcomeUnknown {
                    diagnostic_digest: if diagnostic_digest == ZERO32 {
                        diagnostic_label(b"zero-outcome-unknown")
                    } else {
                        diagnostic_digest
                    },
                    candidate,
                })
            }
        }
    }

    /// Reconcile one deterministic operation id without creating a new anchor.
    pub fn reconcile_witness_frontier_anchor_v1<S: WitnessFrontierAnchorStore>(
        &self,
        target: WitnessFrontierAnchorTargetV1,
        policy: XeniaWitnessFrontierSourcePolicyV1,
        store: &mut S,
    ) -> Result<WitnessFrontierAnchorReconciliationV1, WitnessFrontierAnchorError> {
        target.validate()?;
        policy.validate()?;
        self.ensure_anchor_signing_ready()?;
        let key = self.signing_key.verifying_key().to_bytes();
        let source_id = derive_xenia_witness_frontier_source_id(key, policy.anchor_policy_digest)?;
        if target.source_id != source_id
            || target.source_epoch != policy.source_epoch
            || target.anchor_policy_digest != policy.anchor_policy_digest
        {
            return Err(WitnessFrontierAnchorError::SourceBindingMismatch);
        }
        match store.lookup_operation(target.source_id, target.source_epoch, target.operation_id) {
            Ok(None) => Ok(WitnessFrontierAnchorReconciliationV1::ProvenNotPersisted),
            Ok(Some(anchor)) => {
                if anchor.verify().is_err()
                    || anchor.target != target
                    || anchor.ledger_public_key != key
                {
                    return Ok(WitnessFrontierAnchorReconciliationV1::OutcomeUnknown {
                        diagnostic_digest: diagnostic_label(b"reconcile-record-mismatch"),
                    });
                }
                Ok(WitnessFrontierAnchorReconciliationV1::Persisted(Box::new(
                    anchor,
                )))
            }
            Err(diagnostic_digest) => Ok(WitnessFrontierAnchorReconciliationV1::OutcomeUnknown {
                diagnostic_digest: if diagnostic_digest == ZERO32 {
                    diagnostic_label(b"zero-reconcile-store-error")
                } else {
                    diagnostic_digest
                },
            }),
        }
    }

    /// Produce a fresh signed statement of the source's current witness anchor.
    pub fn observe_witness_frontier_v1<S: WitnessFrontierAnchorStore>(
        &self,
        witness_id: [u8; 16],
        challenge: [u8; 32],
        policy: XeniaWitnessFrontierSourcePolicyV1,
        observed_at_unix_s: u64,
        store: &mut S,
    ) -> Result<SignedWitnessFrontierObservationV1, WitnessFrontierAnchorError> {
        if witness_id == ZERO16 || challenge == ZERO32 || observed_at_unix_s == 0 {
            return Err(WitnessFrontierAnchorError::MalformedObservation);
        }
        policy.validate()?;
        self.ensure_anchor_signing_ready()?;
        let ledger_public_key = self.signing_key.verifying_key().to_bytes();
        let source_id = derive_xenia_witness_frontier_source_id(
            ledger_public_key,
            policy.anchor_policy_digest,
        )?;
        let current = store
            .current_for_witness(source_id, policy.source_epoch, witness_id)
            .map_err(WitnessFrontierAnchorError::PreDispatchStore)?;
        let current = current
            .map(|anchor| {
                anchor.verify()?;
                if anchor.ledger_public_key != ledger_public_key
                    || anchor.target.source_id != source_id
                    || anchor.target.source_epoch != policy.source_epoch
                    || anchor.target.anchor_policy_digest != policy.anchor_policy_digest
                    || anchor.target.witness_id != witness_id
                {
                    return Err(WitnessFrontierAnchorError::CurrentAnchorNamespaceMismatch);
                }
                Ok(WitnessFrontierAnchorSummaryV1 {
                    anchor_sequence: anchor.anchor_sequence,
                    anchor_fingerprint: anchor.fingerprint()?,
                    operation_id: anchor.target.operation_id,
                    high_watermark: anchor.target.high_watermark,
                    reservation_head: anchor.target.reservation_head,
                    frontier_statement_digest: anchor.target.frontier_statement_digest,
                })
            })
            .transpose()?;

        let mut observation = SignedWitnessFrontierObservationV1 {
            schema_version: WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION,
            source_id,
            source_epoch: policy.source_epoch,
            anchor_policy_digest: policy.anchor_policy_digest,
            witness_id,
            challenge,
            observed_at_unix_s,
            current,
            ledger_entry_count: self.entry_count(),
            ledger_head_hash: self.last_hash(),
            ledger_public_key,
            signature: SignatureEnvelope::ed25519([0; 64]),
        };
        let signature = self
            .signing_key
            .sign(&observation.canonical_message()?)
            .to_bytes();
        observation.signature = SignatureEnvelope::ed25519(signature);
        observation.verify_signature()?;
        Ok(observation)
    }

    fn ensure_anchor_signing_ready(&self) -> Result<(), WitnessFrontierAnchorError> {
        if self.has_uncertain_persistence() {
            return Err(WitnessFrontierAnchorError::ConsentLedgerPersistenceUncertain);
        }
        if self.entry_count() == 0 || self.last_hash() == ZERO32 {
            return Err(WitnessFrontierAnchorError::PreGenesisLedger);
        }
        Ok(())
    }
}

fn witness_frontier_statement_digest(
    witness_id: [u8; 16],
    high_watermark: u64,
    reservation_head: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(SYMTHAEA_WITNESS_FRONTIER_STATEMENT_DOMAIN);
    bytes.extend_from_slice(&SYMTHAEA_WITNESS_FRONTIER_STATEMENT_SCHEMA_VERSION.to_be_bytes());
    bytes.extend_from_slice(&witness_id);
    bytes.extend_from_slice(&high_watermark.to_be_bytes());
    bytes.extend_from_slice(&reservation_head);
    *blake3::hash(&bytes).as_bytes()
}

fn validate_previous_namespace(
    previous: &SignedWitnessFrontierAnchorV1,
    target: &WitnessFrontierAnchorTargetV1,
) -> Result<(), WitnessFrontierAnchorError> {
    if previous.target.source_id != target.source_id
        || previous.target.source_epoch != target.source_epoch
        || previous.target.anchor_policy_digest != target.anchor_policy_digest
        || previous.target.witness_id != target.witness_id
    {
        return Err(WitnessFrontierAnchorError::CurrentAnchorNamespaceMismatch);
    }
    Ok(())
}

fn diagnostic_label(label: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia.witness-frontier-anchor-diagnostic.v1\0");
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

/// Fail-closed anchor protocol errors before or outside the durable store effect boundary.
#[derive(Debug, Error)]
pub enum WitnessFrontierAnchorError {
    /// Source policy contained zero/invalid fields.
    #[error("invalid Xenia witness-frontier source policy")]
    InvalidSourcePolicy,
    /// Target structure is malformed.
    #[error("malformed witness-frontier anchor target")]
    MalformedTarget,
    /// Frontier statement digest does not reproduce Symthaea's canonical commitment.
    #[error("witness-frontier statement commitment mismatch")]
    FrontierStatementDigestMismatch,
    /// Operation id does not reproduce Symthaea's canonical operation commitment.
    #[error("witness-frontier operation id mismatch")]
    OperationIdMismatch,
    /// Target source namespace differs from the configured Xenia source.
    #[error("witness-frontier source binding mismatch")]
    SourceBindingMismatch,
    /// Consent ledger has an unresolved persistence outcome.
    #[error("Xenia consent-ledger persistence is unresolved")]
    ConsentLedgerPersistenceUncertain,
    /// A pre-genesis ledger key cannot anchor witness chronology.
    #[error("witness-frontier anchoring requires a non-genesis Xenia ledger")]
    PreGenesisLedger,
    /// Timestamp placeholder is invalid.
    #[error("witness-frontier anchor timestamp must be nonzero")]
    InvalidTimestamp,
    /// Authoritative pre-dispatch store read failed.
    #[error("witness-frontier anchor store unavailable before dispatch")]
    PreDispatchStore([u8; 32]),
    /// Existing operation id resolves to a different target.
    #[error("witness-frontier operation id collision or store corruption")]
    OperationIdCollision,
    /// Current stored anchor belongs to another namespace.
    #[error("current witness-frontier anchor namespace mismatch")]
    CurrentAnchorNamespaceMismatch,
    /// Current anchor was signed by a different Xenia ledger key.
    #[error("current witness-frontier anchor signer mismatch")]
    CurrentAnchorSignerMismatch,
    /// New witness frontier does not advance the currently anchored watermark.
    #[error("witness-frontier high watermark is not monotonic")]
    NonMonotonicWitnessFrontier,
    /// Anchor sequence overflow.
    #[error("witness-frontier anchor sequence exhausted")]
    AnchorSequenceOverflow,
    /// Anchor structure is malformed.
    #[error("malformed signed witness-frontier anchor")]
    MalformedAnchor,
    /// Previous-anchor chaining is inconsistent with the anchor sequence.
    #[error("witness-frontier previous anchor mismatch")]
    PreviousAnchorMismatch,
    /// Embedded ledger public key is malformed.
    #[error("witness-frontier anchor has malformed Xenia public key")]
    BadLedgerPublicKey,
    /// Anchor signature is invalid.
    #[error("witness-frontier anchor signature invalid")]
    BadAnchorSignature,
    /// V1 only issues/verifies Ed25519 anchor signatures.
    #[error("unsupported witness-frontier anchor signature suite")]
    UnsupportedAnchorSignatureSuite,
    /// Observation structure is malformed.
    #[error("malformed witness-frontier observation")]
    MalformedObservation,
    /// Fresh observation does not bind the caller's exact expectations.
    #[error("witness-frontier observation binding mismatch")]
    ObservationBindingMismatch,
    /// Observation does not name the exact durable anchor supplied by the verifier.
    #[error("witness-frontier observation/current-anchor mismatch")]
    ObservationCurrentAnchorMismatch,
    /// Observation is stale or implausibly future-dated.
    #[error("witness-frontier observation is stale or future-dated")]
    ObservationStaleOrFuture,
    /// Signature envelope structure is malformed.
    #[error("witness-frontier signature envelope invalid: {0}")]
    SignatureEnvelope(#[from] crate::SignatureEnvelopeError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    use super::*;
    use crate::{ConsentEventRecord, ConsentKind};

    #[derive(Default)]
    struct MemoryStore {
        by_operation: BTreeMap<([u8; 16], u64, [u8; 32]), SignedWitnessFrontierAnchorV1>,
        current: BTreeMap<([u8; 16], u64, [u8; 16]), SignedWitnessFrontierAnchorV1>,
        next_disposition: Option<PersistenceDisposition<[u8; 32]>>,
        cas_calls: usize,
    }

    impl WitnessFrontierAnchorStore for MemoryStore {
        fn lookup_operation(
            &mut self,
            source_id: [u8; 16],
            source_epoch: u64,
            operation_id: [u8; 32],
        ) -> Result<Option<SignedWitnessFrontierAnchorV1>, [u8; 32]> {
            Ok(self
                .by_operation
                .get(&(source_id, source_epoch, operation_id))
                .cloned())
        }

        fn current_for_witness(
            &mut self,
            source_id: [u8; 16],
            source_epoch: u64,
            witness_id: [u8; 16],
        ) -> Result<Option<SignedWitnessFrontierAnchorV1>, [u8; 32]> {
            Ok(self
                .current
                .get(&(source_id, source_epoch, witness_id))
                .cloned())
        }

        fn compare_and_swap(
            &mut self,
            expected_previous: Option<[u8; 32]>,
            candidate: &SignedWitnessFrontierAnchorV1,
        ) -> PersistenceDisposition<[u8; 32]> {
            self.cas_calls += 1;
            if let Some(outcome) = self.next_disposition.take() {
                match outcome {
                    PersistenceDisposition::Persisted => {}
                    other => return other,
                }
            }
            let key = (
                candidate.target.source_id,
                candidate.target.source_epoch,
                candidate.target.witness_id,
            );
            let actual = self
                .current
                .get(&key)
                .and_then(|record| record.fingerprint().ok());
            if actual != expected_previous {
                return PersistenceDisposition::ProvenNotPersisted([0xE1; 32]);
            }
            self.current.insert(key, candidate.clone());
            self.by_operation.insert(
                (
                    candidate.target.source_id,
                    candidate.target.source_epoch,
                    candidate.target.operation_id,
                ),
                candidate.clone(),
            );
            PersistenceDisposition::Persisted
        }
    }

    fn seeded_chain() -> Chain {
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        chain
            .append(ConsentEventRecord {
                source_id: [0x11; 32],
                session_id: Uuid::from_bytes([0x22; 16]),
                request_id: Uuid::from_bytes([0x33; 16]),
                kind: ConsentKind::Approval,
                scope: "witness anchor test".into(),
            })
            .unwrap();
        chain
    }

    fn policy(chain: &Chain) -> (XeniaWitnessFrontierSourcePolicyV1, [u8; 16]) {
        let policy = XeniaWitnessFrontierSourcePolicyV1 {
            source_epoch: 7,
            anchor_policy_digest: [0x62; 32],
        };
        let source_id = derive_xenia_witness_frontier_source_id(
            chain.signing_key.verifying_key().to_bytes(),
            policy.anchor_policy_digest,
        )
        .unwrap();
        (policy, source_id)
    }

    fn target(
        source_id: [u8; 16],
        policy: XeniaWitnessFrontierSourcePolicyV1,
        high_watermark: u64,
        head_byte: u8,
    ) -> WitnessFrontierAnchorTargetV1 {
        let mut target = WitnessFrontierAnchorTargetV1 {
            schema_version: WITNESS_FRONTIER_ANCHOR_SCHEMA_VERSION,
            operation_id: [1; 32],
            source_id,
            source_epoch: policy.source_epoch,
            anchor_policy_digest: policy.anchor_policy_digest,
            witness_id: [0x51; 16],
            high_watermark,
            reservation_head: [head_byte; 32],
            frontier_statement_digest: [1; 32],
        };
        target.frontier_statement_digest = target.recompute_frontier_statement_digest();
        target.operation_id = target.recompute_operation_id();
        target
    }

    #[test]
    fn exact_operation_is_idempotent_and_current_observation_is_fresh_bound() {
        let chain = seeded_chain();
        let (policy, source_id) = policy(&chain);
        let target = target(source_id, policy, 3, 0x33);
        let mut store = MemoryStore::default();

        let first = chain
            .append_witness_frontier_anchor_v1(target, policy, 100, &mut store)
            .unwrap();
        let anchor = match first {
            WitnessFrontierAnchorAppendOutcomeV1::Persisted(anchor) => anchor,
            _ => panic!("expected persisted anchor"),
        };
        assert_eq!(anchor.anchor_sequence, 1);
        assert_eq!(store.cas_calls, 1);

        let second = chain
            .append_witness_frontier_anchor_v1(target, policy, 101, &mut store)
            .unwrap();
        let second_anchor = match second {
            WitnessFrontierAnchorAppendOutcomeV1::Persisted(anchor) => anchor,
            _ => panic!("expected idempotent persisted anchor"),
        };
        assert_eq!(second_anchor, anchor);
        assert_eq!(
            store.cas_calls, 1,
            "idempotent lookup must avoid a second CAS"
        );

        let observation = chain
            .observe_witness_frontier_v1([0x51; 16], [0xA5; 32], policy, 120, &mut store)
            .unwrap();
        observation
            .verify_fresh(
                [0xA5; 32],
                chain.signing_key.verifying_key().to_bytes(),
                source_id,
                policy.source_epoch,
                policy.anchor_policy_digest,
                [0x51; 16],
                120,
                5,
                1,
            )
            .unwrap();
        observation.verify_current_anchor(&anchor).unwrap();
        assert_eq!(observation.current.unwrap().anchor_sequence, 1);

        assert!(
            observation
                .verify_fresh(
                    [0xA6; 32],
                    chain.signing_key.verifying_key().to_bytes(),
                    source_id,
                    policy.source_epoch,
                    policy.anchor_policy_digest,
                    [0x51; 16],
                    120,
                    5,
                    1,
                )
                .is_err()
        );
    }

    #[test]
    fn successor_is_cas_chained_and_lower_frontier_is_rejected() {
        let chain = seeded_chain();
        let (policy, source_id) = policy(&chain);
        let mut store = MemoryStore::default();
        let first_target = target(source_id, policy, 2, 0x22);
        let first = match chain
            .append_witness_frontier_anchor_v1(first_target, policy, 100, &mut store)
            .unwrap()
        {
            WitnessFrontierAnchorAppendOutcomeV1::Persisted(anchor) => anchor,
            _ => panic!("expected persisted"),
        };
        let second_target = target(source_id, policy, 3, 0x33);
        let second = match chain
            .append_witness_frontier_anchor_v1(second_target, policy, 101, &mut store)
            .unwrap()
        {
            WitnessFrontierAnchorAppendOutcomeV1::Persisted(anchor) => anchor,
            _ => panic!("expected persisted"),
        };
        assert_eq!(second.anchor_sequence, 2);
        assert_eq!(
            second.previous_anchor_fingerprint,
            first.fingerprint().unwrap()
        );

        let lower = target(source_id, policy, 2, 0x44);
        assert!(matches!(
            chain.append_witness_frontier_anchor_v1(lower, policy, 102, &mut store),
            Err(WitnessFrontierAnchorError::NonMonotonicWitnessFrontier)
        ));
    }

    #[test]
    fn unknown_store_commit_requires_reconciliation_and_never_claims_applied() {
        let chain = seeded_chain();
        let (policy, source_id) = policy(&chain);
        let target = target(source_id, policy, 3, 0x33);
        let mut store = MemoryStore::default();
        store.next_disposition = Some(PersistenceDisposition::OutcomeUnknown([0xEE; 32]));

        let outcome = chain
            .append_witness_frontier_anchor_v1(target, policy, 100, &mut store)
            .unwrap();
        assert!(matches!(
            outcome,
            WitnessFrontierAnchorAppendOutcomeV1::OutcomeUnknown { .. }
        ));
        assert!(matches!(
            chain
                .reconcile_witness_frontier_anchor_v1(target, policy, &mut store)
                .unwrap(),
            WitnessFrontierAnchorReconciliationV1::ProvenNotPersisted
        ));
    }

    #[test]
    fn unresolved_consent_ledger_blocks_anchor_before_store_write() {
        let mut chain = seeded_chain();
        let (policy, source_id) = policy(&chain);
        let target = target(source_id, policy, 3, 0x33);
        let event = ConsentEventRecord {
            source_id: [0x11; 32],
            session_id: Uuid::from_bytes([0x22; 16]),
            request_id: Uuid::from_bytes([0x44; 16]),
            kind: ConsentKind::Approval,
            scope: "ambiguous".into(),
        };
        let _ = chain
            .append_transactional_outcome(event, |_| {
                PersistenceDisposition::OutcomeUnknown([0xAB; 32])
            })
            .unwrap();
        let mut store = MemoryStore::default();
        assert!(matches!(
            chain.append_witness_frontier_anchor_v1(target, policy, 100, &mut store),
            Err(WitnessFrontierAnchorError::ConsentLedgerPersistenceUncertain)
        ));
        assert_eq!(store.cas_calls, 0);
    }

    #[test]
    fn target_rejects_cross_repository_operation_or_frontier_drift() {
        let chain = seeded_chain();
        let (policy, source_id) = policy(&chain);
        let mut value = target(source_id, policy, 3, 0x33);
        let expected_len =
            SYMTHAEA_WITNESS_ANCHOR_OPERATION_DOMAIN.len() + 2 + 16 + 8 + 32 + 16 + 8 + 32 + 32;
        assert_eq!(value.canonical_operation_message().len(), expected_len);
        value.operation_id[0] ^= 1;
        assert!(matches!(
            value.validate(),
            Err(WitnessFrontierAnchorError::OperationIdMismatch)
        ));

        let mut value = target(source_id, policy, 3, 0x33);
        value.frontier_statement_digest[0] ^= 1;
        assert!(matches!(
            value.validate(),
            Err(WitnessFrontierAnchorError::FrontierStatementDigestMismatch)
        ));
    }

    #[test]
    fn signed_anchor_cannot_be_relabelled_to_another_source() {
        let chain = seeded_chain();
        let (policy, source_id) = policy(&chain);
        let target = target(source_id, policy, 3, 0x33);
        let mut store = MemoryStore::default();
        let mut anchor = match chain
            .append_witness_frontier_anchor_v1(target, policy, 100, &mut store)
            .unwrap()
        {
            WitnessFrontierAnchorAppendOutcomeV1::Persisted(anchor) => anchor,
            _ => panic!("expected persisted"),
        };
        anchor.target.source_id[0] ^= 1;
        anchor.target.operation_id = anchor.target.recompute_operation_id();
        assert!(matches!(
            anchor.verify(),
            Err(WitnessFrontierAnchorError::SourceBindingMismatch)
                | Err(WitnessFrontierAnchorError::BadAnchorSignature)
        ));
    }
}
