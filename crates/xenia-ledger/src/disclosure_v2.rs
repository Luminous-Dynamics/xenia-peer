// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential-gated, single-lineage disclosure permits.
//!
//! This v1 runtime boundary accepts only an [`ExecutionBoundReleaseCredential`]: a
//! private capability produced after Xenia verifies both the Mycelix release-authority
//! threshold and the exact Xenia execution proof named by that credential. A raw
//! caller-provided bundle digest cannot reach permit preparation.
//!
//! Authorization continuity is intentionally strict. The exact resident consent
//! `Approval` that anchored the execution must remain the latest event for that
//! authenticated session/requester at permit preparation **and** journal commit time.
//! Any later matching consent event — including another Approval — requires a fresh
//! execution/bundle/credential. This avoids accidentally resurrecting an old release
//! after revocation or scope change.
//!
//! A prepared permit is not release authority. It must be durably appended to the
//! signed release journal before [`CommittedDisclosurePermit`] exists. Credential IDs
//! are statefully constrained to one linear release lineage: one initial release, then
//! only explicit non-branching retries of `Aborted`/`Partial` outcomes.
//!
//! The hash-chained journal makes divergent histories detectable once heads are
//! compared; it cannot by itself prevent a malicious signer/storage layer from
//! maintaining two valid forks. High-assurance deployments should add atomic
//! compare-and-swap persistence and independent release-head witnessing.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::binding::SessionTranscriptBinding;
use crate::chain::Chain;
use crate::entry::{ConsentKind, LedgerEntry, TranscriptBindingError};
use crate::policy::EvidenceCryptoManifest;
use crate::release_credential::ExecutionBoundReleaseCredential;
use crate::signature::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend, EvidenceSignatureBackendError,
    SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema for the release authorization binding.
pub const ACCOUNTABILITY_DISCLOSURE_BINDING_SCHEMA: &str =
    "xenia-accountability-disclosure-binding-v2";
/// Stable schema for the signed release permit.
pub const ACCOUNTABILITY_DISCLOSURE_PERMIT_SCHEMA: &str =
    "xenia-accountability-disclosure-permit-v2";
/// Stable schema for the signed release journal.
pub const ACCOUNTABILITY_RELEASE_ENTRY_SCHEMA: &str =
    "xenia-accountability-release-entry-v2";
/// Commitment algorithm used throughout this profile.
pub const ACCOUNTABILITY_DISCLOSURE_COMMITMENT_ALGORITHM: &str = "blake3-256";

const DISCLOSURE_BINDING_DOMAIN: &[u8] = b"xenia:accountability-disclosure-binding:v2";
const DISCLOSURE_PERMIT_DIGEST_DOMAIN: &[u8] =
    b"xenia:accountability-disclosure-permit-digest:v2";
const RELEASE_ENTRY_DOMAIN: &[u8] = b"xenia:accountability-release-entry:v2";

/// Release phase represented by a v2 permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountabilityDisclosurePhase {
    /// Credential/execution/authorization were checked; durable release commit is
    /// still required before protected output.
    PreparedForRelease,
}

/// Canonical signed release statement.
///
/// Fields are private so external crates cannot manufacture a permit binding. Audit
/// and adapter code can inspect the commitment-only values through getters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilityDisclosureBinding {
    schema: String,
    commitment_algorithm: String,
    release_id: Uuid,
    retry_of: Option<Uuid>,
    credential_id: [u8; 32],
    operation_id: Uuid,
    session: SessionTranscriptBinding,
    requester_source_id: [u8; 32],
    receipt_digest: [u8; 32],
    evidence_bundle_digest: [u8; 32],
    execution_binding_digest: [u8; 32],
    result_digest: Option<[u8; 32]>,
    authorization_entry_count: u64,
    authorization_entry_hash: [u8; 32],
    permit_ledger_entry_count: u64,
    permit_ledger_head_hash: [u8; 32],
    phase: AccountabilityDisclosurePhase,
}

impl AccountabilityDisclosureBinding {
    /// Single-use release ID.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Explicit retry parent, when present.
    pub const fn retry_of(&self) -> Option<Uuid> {
        self.retry_of
    }

    /// Mycelix release-lineage credential ID.
    pub const fn credential_id(&self) -> [u8; 32] {
        self.credential_id
    }

    /// Logical Xenia operation ID.
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Authenticated Xenia session ID.
    pub const fn session_id(&self) -> Uuid {
        self.session.session_id
    }

    /// Opaque authenticated requester fingerprint.
    pub const fn requester_source_id(&self) -> [u8; 32] {
        self.requester_source_id
    }

    /// Frozen Mycelix receipt statement.
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    /// Final witnessed Mycelix evidence-bundle commitment.
    pub const fn evidence_bundle_digest(&self) -> [u8; 32] {
        self.evidence_bundle_digest
    }

    /// Exact Xenia execution-proof/binding identifier.
    pub const fn execution_binding_digest(&self) -> [u8; 32] {
        self.execution_binding_digest
    }

    /// Minimum-necessary result commitment.
    pub const fn result_digest(&self) -> Option<[u8; 32]> {
        self.result_digest
    }

    /// Exact consent-ledger entry count that authorized the execution.
    pub const fn authorization_entry_count(&self) -> u64 {
        self.authorization_entry_count
    }

    /// Exact consent-ledger entry hash that authorized the execution.
    pub const fn authorization_entry_hash(&self) -> [u8; 32] {
        self.authorization_entry_hash
    }

    /// Consent-ledger size when the permit itself was prepared.
    pub const fn permit_ledger_entry_count(&self) -> u64 {
        self.permit_ledger_entry_count
    }

    /// Consent-ledger head when the permit itself was prepared.
    pub const fn permit_ledger_head_hash(&self) -> [u8; 32] {
        self.permit_ledger_head_hash
    }

    /// Validate schema, identifiers, commitments and nested session binding.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), AccountabilityDisclosureError> {
        if self.schema != ACCOUNTABILITY_DISCLOSURE_BINDING_SCHEMA {
            return Err(AccountabilityDisclosureError::UnsupportedBindingSchema {
                schema: self.schema.clone(),
            });
        }
        if self.commitment_algorithm != ACCOUNTABILITY_DISCLOSURE_COMMITMENT_ALGORITHM {
            return Err(AccountabilityDisclosureError::UnsupportedCommitmentAlgorithm {
                algorithm: self.commitment_algorithm.clone(),
            });
        }
        if self.release_id.is_nil() {
            return Err(AccountabilityDisclosureError::NilReleaseId);
        }
        if self.operation_id.is_nil() {
            return Err(AccountabilityDisclosureError::NilOperationId);
        }
        if self.retry_of == Some(self.release_id) {
            return Err(AccountabilityDisclosureError::SelfRetry);
        }
        require_nonzero("credential_id", &self.credential_id)?;
        require_nonzero("requester_source_id", &self.requester_source_id)?;
        require_nonzero("receipt_digest", &self.receipt_digest)?;
        require_nonzero("evidence_bundle_digest", &self.evidence_bundle_digest)?;
        require_nonzero("execution_binding_digest", &self.execution_binding_digest)?;
        require_nonzero("authorization_entry_hash", &self.authorization_entry_hash)?;
        require_nonzero("permit_ledger_head_hash", &self.permit_ledger_head_hash)?;
        if let Some(result) = &self.result_digest {
            require_nonzero("result_digest", result)?;
        }
        if self.authorization_entry_count == 0 || self.permit_ledger_entry_count == 0 {
            return Err(AccountabilityDisclosureError::EmptyLedgerAnchor);
        }
        if self.authorization_entry_count > self.permit_ledger_entry_count {
            return Err(AccountabilityDisclosureError::AuthorizationAfterPermitFrontier);
        }
        self.session.validate_against_manifest(manifest)?;
        Ok(())
    }
}

/// Signed prepared release permit.
///
/// The type is intentionally non-`Clone`. Deserialization is allowed for audit or
/// recovery, but signature verification and journal commit are still mandatory.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilityDisclosurePermit {
    schema: String,
    binding: AccountabilityDisclosureBinding,
    signature: SignatureEnvelope,
}

impl AccountabilityDisclosurePermit {
    /// Read the signed binding.
    pub fn binding(&self) -> &AccountabilityDisclosureBinding {
        &self.binding
    }

    /// Verify shape, session binding and current Ed25519 release-authority signature.
    pub fn verify(
        &self,
        manifest: EvidenceCryptoManifest,
        ledger_public_key: &[u8],
    ) -> Result<(), AccountabilityDisclosureError> {
        if self.schema != ACCOUNTABILITY_DISCLOSURE_PERMIT_SCHEMA {
            return Err(AccountabilityDisclosureError::UnsupportedPermitSchema {
                schema: self.schema.clone(),
            });
        }
        self.binding.validate_against_manifest(manifest)?;
        let suite = self.signature.validate_shape()?;
        if suite != SignatureSuite::Ed25519Rfc8032 {
            return Err(AccountabilityDisclosureError::UnsupportedPermitSignatureSuite {
                suite,
            });
        }
        Ed25519EvidenceSignatureBackend.verify_signature(
            ledger_public_key,
            &accountability_disclosure_message(&self.binding),
            &self.signature.signature,
        )?;
        Ok(())
    }
}

/// Exact bytes signed by the Xenia disclosure authority.
pub fn accountability_disclosure_message(binding: &AccountabilityDisclosureBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(420);
    out.extend_from_slice(DISCLOSURE_BINDING_DOMAIN);
    out.push(0);
    out.extend_from_slice(ACCOUNTABILITY_DISCLOSURE_BINDING_SCHEMA.as_bytes());
    out.push(0);
    out.extend_from_slice(ACCOUNTABILITY_DISCLOSURE_COMMITMENT_ALGORITHM.as_bytes());
    out.push(0);
    out.extend_from_slice(binding.release_id.as_bytes());
    match binding.retry_of {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(id.as_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(&binding.credential_id);
    out.extend_from_slice(binding.operation_id.as_bytes());
    out.extend_from_slice(binding.session.session_id.as_bytes());
    out.extend_from_slice(&binding.session.transcript_hash);
    out.extend_from_slice(&binding.requester_source_id);
    out.extend_from_slice(&binding.receipt_digest);
    out.extend_from_slice(&binding.evidence_bundle_digest);
    out.extend_from_slice(&binding.execution_binding_digest);
    match binding.result_digest {
        Some(result) => {
            out.push(1);
            out.extend_from_slice(&result);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&binding.authorization_entry_count.to_be_bytes());
    out.extend_from_slice(&binding.authorization_entry_hash);
    out.extend_from_slice(&binding.permit_ledger_entry_count.to_be_bytes());
    out.extend_from_slice(&binding.permit_ledger_head_hash);
    out.push(match binding.phase {
        AccountabilityDisclosurePhase::PreparedForRelease => 1,
    });
    out
}

/// Stable digest of the complete signed permit artifact.
pub fn accountability_disclosure_permit_digest(
    permit: &AccountabilityDisclosurePermit,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DISCLOSURE_PERMIT_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&accountability_disclosure_message(&permit.binding));
    hasher.update(&[0]);
    hasher.update(permit.signature.algorithm.as_bytes());
    hasher.update(&(permit.signature.signature.len() as u64).to_be_bytes());
    hasher.update(&permit.signature.signature);
    *hasher.finalize().as_bytes()
}

impl Chain {
    /// Prepare a release permit from a credential already verified and bound to an
    /// exact Xenia execution.
    ///
    /// The exact execution authorization must still be resident, be an `Approval`,
    /// and remain the latest matching consent event. The permit records a separate
    /// current-ledger frontier so later commit can prove no history replacement.
    pub fn prepare_accountability_disclosure(
        &self,
        credential: &ExecutionBoundReleaseCredential,
        release_id: Uuid,
        retry_of: Option<Uuid>,
        manifest: EvidenceCryptoManifest,
    ) -> Result<AccountabilityDisclosurePermit, AccountabilityDisclosureError> {
        let anchor = resident_authorization_anchor(
            self,
            credential.ledger_entry_count(),
            credential.ledger_head_hash(),
            credential.session().session_id,
            credential.requester_source_id(),
        )
        .ok_or(AccountabilityDisclosureError::ExecutionAuthorizationNotResident)?;
        if anchor.event.kind != ConsentKind::Approval {
            return Err(AccountabilityDisclosureError::ExecutionAnchorNotApproved);
        }
        require_authorization_continuity(
            self,
            credential.session().session_id,
            credential.requester_source_id(),
            credential.ledger_head_hash(),
        )?;

        let binding = AccountabilityDisclosureBinding {
            schema: ACCOUNTABILITY_DISCLOSURE_BINDING_SCHEMA.to_string(),
            commitment_algorithm: ACCOUNTABILITY_DISCLOSURE_COMMITMENT_ALGORITHM.to_string(),
            release_id,
            retry_of,
            credential_id: credential.credential_id(),
            operation_id: credential.operation_id(),
            session: credential.session().clone(),
            requester_source_id: credential.requester_source_id(),
            receipt_digest: credential.receipt_digest(),
            evidence_bundle_digest: credential.finalized_evidence_bundle_digest(),
            execution_binding_digest: credential.execution_binding_digest(),
            result_digest: credential.result_digest(),
            authorization_entry_count: credential.ledger_entry_count(),
            authorization_entry_hash: credential.ledger_head_hash(),
            permit_ledger_entry_count: self.entry_count(),
            permit_ledger_head_hash: self.last_hash(),
            phase: AccountabilityDisclosurePhase::PreparedForRelease,
        };
        binding.validate_against_manifest(manifest)?;
        let signature = self
            .signing_key
            .sign(&accountability_disclosure_message(&binding))
            .to_bytes();
        Ok(AccountabilityDisclosurePermit {
            schema: ACCOUNTABILITY_DISCLOSURE_PERMIT_SCHEMA.to_string(),
            binding,
            signature: SignatureEnvelope::ed25519(signature),
        })
    }
}

/// Terminal observation after a committed permit is consumed by output code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureReleaseOutcome {
    /// Intended protected payload was completely emitted.
    Completed,
    /// No protected bytes were emitted; explicit retry is allowed.
    Aborted,
    /// Some protected bytes were emitted; explicit retry is allowed.
    Partial {
        /// Number of bytes known to have left the protected boundary.
        bytes_released: u64,
    },
}

/// Event stored in the signed release journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureReleaseEvent {
    /// A permit was durably committed before output.
    Commit {
        /// Digest of the exact signed permit.
        permit_digest: [u8; 32],
        /// Mycelix authorization lineage credential.
        credential_id: [u8; 32],
        /// Explicit retry parent, when present.
        retry_of: Option<Uuid>,
    },
    /// Terminal output result.
    Outcome(DisclosureReleaseOutcome),
}

/// One signed, hash-chained release-journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureReleaseEntry {
    schema: String,
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    event: DisclosureReleaseEvent,
    entry_hash: [u8; 32],
    signature: SignatureEnvelope,
}

impl DisclosureReleaseEntry {
    /// Monotonic release-journal sequence.
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Release governed by this event.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Signed release event.
    pub fn event(&self) -> &DisclosureReleaseEvent {
        &self.event
    }

    /// Domain-separated entry hash.
    pub const fn entry_hash(&self) -> [u8; 32] {
        self.entry_hash
    }
}

/// Verified append-only release state.
#[derive(Debug, Default)]
pub struct DisclosureReleaseState {
    entries: Vec<DisclosureReleaseEntry>,
}

impl DisclosureReleaseState {
    /// Verify and rehydrate persisted release state in one fail-closed operation.
    pub fn from_verified_entries(
        entries: Vec<DisclosureReleaseEntry>,
        ledger_public_key: &[u8],
    ) -> Result<Self, AccountabilityDisclosureError> {
        verify_disclosure_release_entries(&entries, ledger_public_key)?;
        Ok(Self { entries })
    }

    /// Read entries for persistence or audit.
    pub fn entries(&self) -> &[DisclosureReleaseEntry] {
        &self.entries
    }

    /// Consume state into its serializable entries.
    pub fn into_entries(self) -> Vec<DisclosureReleaseEntry> {
        self.entries
    }

    /// Transactionally commit a prepared permit before protected output.
    ///
    /// On persistence failure the in-memory append is rolled back and no committed
    /// capability is returned. Authorization-anchor continuity is rechecked at the
    /// last possible point before the durable commit.
    pub fn commit_permit_transactional<E>(
        &mut self,
        chain: &Chain,
        permit: AccountabilityDisclosurePermit,
        manifest: EvidenceCryptoManifest,
        persist: impl FnOnce(&[DisclosureReleaseEntry]) -> Result<(), E>,
    ) -> Result<CommittedDisclosurePermit, TransactionalDisclosureError<E>> {
        permit
            .verify(manifest, chain.signing_key.verifying_key().as_bytes())
            .map_err(TransactionalDisclosureError::Protocol)?;
        if !chain_contains_frontier(
            chain,
            permit.binding.permit_ledger_entry_count,
            permit.binding.permit_ledger_head_hash,
        ) {
            return Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::PermitLedgerNotAncestor,
            ));
        }
        require_authorization_continuity(
            chain,
            permit.binding.session.session_id,
            permit.binding.requester_source_id,
            permit.binding.authorization_entry_hash,
        )
        .map_err(TransactionalDisclosureError::Protocol)?;
        self.validate_new_commit(&permit.binding)
            .map_err(TransactionalDisclosureError::Protocol)?;

        let event = DisclosureReleaseEvent::Commit {
            permit_digest: accountability_disclosure_permit_digest(&permit),
            credential_id: permit.binding.credential_id,
            retry_of: permit.binding.retry_of,
        };
        let entry = build_release_entry(
            &chain.signing_key,
            self.entries.len() as u64,
            self.entries
                .last()
                .map(|entry| entry.entry_hash)
                .unwrap_or([0u8; 32]),
            permit.binding.release_id,
            event,
        );
        self.entries.push(entry);
        if let Err(error) = persist(&self.entries) {
            self.entries.pop();
            return Err(TransactionalDisclosureError::Persist(error));
        }

        let release_entry_hash = self
            .entries
            .last()
            .ok_or(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::ReleaseAppendInvariant,
            ))?
            .entry_hash;
        Ok(CommittedDisclosurePermit {
            release_id: permit.binding.release_id,
            credential_id: permit.binding.credential_id,
            operation_id: permit.binding.operation_id,
            session_id: permit.binding.session.session_id,
            result_digest: permit.binding.result_digest,
            evidence_bundle_digest: permit.binding.evidence_bundle_digest,
            release_entry_hash,
        })
    }

    /// Transactionally record exactly one terminal output result.
    pub fn record_outcome_transactional<E>(
        &mut self,
        chain: &Chain,
        release_id: Uuid,
        outcome: DisclosureReleaseOutcome,
        persist: impl FnOnce(&[DisclosureReleaseEntry]) -> Result<(), E>,
    ) -> Result<(), TransactionalDisclosureError<E>> {
        let index = build_release_index(&self.entries)
            .map_err(TransactionalDisclosureError::Protocol)?;
        match index.records.get(&release_id).map(|record| record.lifecycle) {
            None => {
                return Err(TransactionalDisclosureError::Protocol(
                    AccountabilityDisclosureError::OutcomeWithoutCommit,
                ));
            }
            Some(ReleaseLifecycle::Terminal(_)) => {
                return Err(TransactionalDisclosureError::Protocol(
                    AccountabilityDisclosureError::DuplicateOutcome,
                ));
            }
            Some(ReleaseLifecycle::Committed) => {}
        }
        validate_outcome(outcome).map_err(TransactionalDisclosureError::Protocol)?;

        let entry = build_release_entry(
            &chain.signing_key,
            self.entries.len() as u64,
            self.entries
                .last()
                .map(|entry| entry.entry_hash)
                .unwrap_or([0u8; 32]),
            release_id,
            DisclosureReleaseEvent::Outcome(outcome),
        );
        self.entries.push(entry);
        if let Err(error) = persist(&self.entries) {
            self.entries.pop();
            return Err(TransactionalDisclosureError::Persist(error));
        }
        Ok(())
    }

    fn validate_new_commit(
        &self,
        binding: &AccountabilityDisclosureBinding,
    ) -> Result<(), AccountabilityDisclosureError> {
        let index = build_release_index(&self.entries)?;
        validate_lineage_commit(
            &index,
            binding.release_id,
            binding.credential_id,
            binding.retry_of,
        )
    }
}

/// Move-only capability proving durable release-journal commit.
///
/// Protected-output adapters should require this type by value. Its fields are
/// private and it intentionally does not implement `Clone`.
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedDisclosurePermit {
    release_id: Uuid,
    credential_id: [u8; 32],
    operation_id: Uuid,
    session_id: Uuid,
    result_digest: Option<[u8; 32]>,
    evidence_bundle_digest: [u8; 32],
    release_entry_hash: [u8; 32],
}

impl CommittedDisclosurePermit {
    /// Single-use release ID.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Release-lineage credential ID.
    pub const fn credential_id(&self) -> [u8; 32] {
        self.credential_id
    }

    /// Bound logical operation.
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Bound authenticated session.
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Minimum-necessary result commitment.
    pub const fn result_digest(&self) -> Option<[u8; 32]> {
        self.result_digest
    }

    /// Final witnessed Mycelix evidence bundle.
    pub const fn evidence_bundle_digest(&self) -> [u8; 32] {
        self.evidence_bundle_digest
    }

    /// Signed release-journal commit entry.
    pub const fn release_entry_hash(&self) -> [u8; 32] {
        self.release_entry_hash
    }
}

/// Persistence failure versus protocol failure while advancing release state.
#[derive(Debug)]
pub enum TransactionalDisclosureError<E> {
    /// Protocol, authorization, cryptographic, or lifecycle validation failed.
    Protocol(AccountabilityDisclosureError),
    /// Durable persistence failed; in-memory append was rolled back.
    Persist(E),
}

/// Verify a persisted release journal's signatures, hash chain, lifecycle and
/// one-credential/one-linear-lineage invariant.
pub fn verify_disclosure_release_entries(
    entries: &[DisclosureReleaseEntry],
    ledger_public_key: &[u8],
) -> Result<(), AccountabilityDisclosureError> {
    let backend = Ed25519EvidenceSignatureBackend;
    let mut previous = [0u8; 32];
    let mut index = ReleaseIndex::default();

    for (position, entry) in entries.iter().enumerate() {
        if entry.schema != ACCOUNTABILITY_RELEASE_ENTRY_SCHEMA {
            return Err(AccountabilityDisclosureError::UnsupportedReleaseEntrySchema {
                schema: entry.schema.clone(),
            });
        }
        if entry.seq != position as u64 || entry.prev_hash != previous {
            return Err(AccountabilityDisclosureError::ReleaseJournalChainMismatch);
        }
        let expected = release_entry_hash(
            entry.seq,
            entry.prev_hash,
            entry.release_id,
            &entry.event,
        );
        if entry.entry_hash != expected {
            return Err(AccountabilityDisclosureError::ReleaseJournalHashMismatch);
        }
        let suite = entry.signature.validate_shape()?;
        if suite != SignatureSuite::Ed25519Rfc8032 {
            return Err(AccountabilityDisclosureError::UnsupportedPermitSignatureSuite {
                suite,
            });
        }
        backend.verify_signature(
            ledger_public_key,
            &entry.entry_hash,
            &entry.signature.signature,
        )?;
        apply_entry_to_index(&mut index, entry)?;
        previous = entry.entry_hash;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseLifecycle {
    Committed,
    Terminal(DisclosureReleaseOutcome),
}

#[derive(Debug, Clone, Copy)]
struct ReleaseRecord {
    credential_id: [u8; 32],
    lifecycle: ReleaseLifecycle,
}

#[derive(Debug, Default)]
struct ReleaseIndex {
    records: BTreeMap<Uuid, ReleaseRecord>,
    credential_roots: BTreeMap<[u8; 32], Uuid>,
    retried_parents: BTreeSet<Uuid>,
}

fn build_release_index(
    entries: &[DisclosureReleaseEntry],
) -> Result<ReleaseIndex, AccountabilityDisclosureError> {
    let mut index = ReleaseIndex::default();
    for entry in entries {
        apply_entry_to_index(&mut index, entry)?;
    }
    Ok(index)
}

fn apply_entry_to_index(
    index: &mut ReleaseIndex,
    entry: &DisclosureReleaseEntry,
) -> Result<(), AccountabilityDisclosureError> {
    match &entry.event {
        DisclosureReleaseEvent::Commit {
            permit_digest,
            credential_id,
            retry_of,
        } => {
            require_nonzero("permit_digest", permit_digest)?;
            require_nonzero("credential_id", credential_id)?;
            validate_lineage_commit(index, entry.release_id, *credential_id, *retry_of)?;
            if let Some(parent) = retry_of {
                index.retried_parents.insert(*parent);
            } else {
                index.credential_roots.insert(*credential_id, entry.release_id);
            }
            index.records.insert(
                entry.release_id,
                ReleaseRecord {
                    credential_id: *credential_id,
                    lifecycle: ReleaseLifecycle::Committed,
                },
            );
        }
        DisclosureReleaseEvent::Outcome(outcome) => {
            validate_outcome(*outcome)?;
            let record = index
                .records
                .get_mut(&entry.release_id)
                .ok_or(AccountabilityDisclosureError::OutcomeWithoutCommit)?;
            if matches!(record.lifecycle, ReleaseLifecycle::Terminal(_)) {
                return Err(AccountabilityDisclosureError::DuplicateOutcome);
            }
            record.lifecycle = ReleaseLifecycle::Terminal(*outcome);
        }
    }
    Ok(())
}

fn validate_lineage_commit(
    index: &ReleaseIndex,
    release_id: Uuid,
    credential_id: [u8; 32],
    retry_of: Option<Uuid>,
) -> Result<(), AccountabilityDisclosureError> {
    if index.records.contains_key(&release_id) {
        return Err(AccountabilityDisclosureError::ReleaseIdAlreadyUsed);
    }
    match retry_of {
        None => {
            if index.credential_roots.contains_key(&credential_id) {
                return Err(AccountabilityDisclosureError::CredentialAlreadyHasLineage);
            }
            Ok(())
        }
        Some(parent) => {
            if index.retried_parents.contains(&parent) {
                return Err(AccountabilityDisclosureError::RetryWouldForkLineage);
            }
            let parent_record = index
                .records
                .get(&parent)
                .ok_or(AccountabilityDisclosureError::RetryTargetMissing)?;
            if parent_record.credential_id != credential_id {
                return Err(AccountabilityDisclosureError::RetryCredentialMismatch);
            }
            match parent_record.lifecycle {
                ReleaseLifecycle::Committed => {
                    Err(AccountabilityDisclosureError::RetryOfUnresolvedRelease)
                }
                ReleaseLifecycle::Terminal(DisclosureReleaseOutcome::Completed) => {
                    Err(AccountabilityDisclosureError::RetryOfCompletedRelease)
                }
                ReleaseLifecycle::Terminal(DisclosureReleaseOutcome::Aborted)
                | ReleaseLifecycle::Terminal(DisclosureReleaseOutcome::Partial { .. }) => Ok(()),
            }
        }
    }
}

fn resident_authorization_anchor(
    chain: &Chain,
    entry_count: u64,
    entry_hash: [u8; 32],
    session_id: Uuid,
    requester_source_id: [u8; 32],
) -> Option<&LedgerEntry> {
    chain.iter().find(|entry| {
        entry.seq.checked_add(1) == Some(entry_count)
            && entry.entry_hash == entry_hash
            && entry.event.session_id == session_id
            && entry.event.source_id == requester_source_id
    })
}

fn require_authorization_continuity(
    chain: &Chain,
    session_id: Uuid,
    requester_source_id: [u8; 32],
    authorization_entry_hash: [u8; 32],
) -> Result<(), AccountabilityDisclosureError> {
    let latest = chain
        .iter()
        .filter(|entry| {
            entry.event.session_id == session_id && entry.event.source_id == requester_source_id
        })
        .last()
        .ok_or(AccountabilityDisclosureError::CurrentAuthorizationNotResident)?;
    if latest.entry_hash != authorization_entry_hash || latest.event.kind != ConsentKind::Approval {
        return Err(AccountabilityDisclosureError::AuthorizationChangedAfterExecution);
    }
    Ok(())
}

fn chain_contains_frontier(chain: &Chain, entry_count: u64, head_hash: [u8; 32]) -> bool {
    if chain.entry_count() == entry_count && chain.last_hash() == head_hash {
        return true;
    }
    if let Some(checkpoint) = chain.base_checkpoint()
        && checkpoint.entry_count == entry_count
        && checkpoint.head_hash == head_hash
    {
        return true;
    }
    chain.iter().any(|entry| {
        entry.seq.checked_add(1) == Some(entry_count) && entry.entry_hash == head_hash
    })
}

fn validate_outcome(
    outcome: DisclosureReleaseOutcome,
) -> Result<(), AccountabilityDisclosureError> {
    if matches!(
        outcome,
        DisclosureReleaseOutcome::Partial { bytes_released: 0 }
    ) {
        return Err(AccountabilityDisclosureError::ZeroPartialRelease);
    }
    Ok(())
}

fn build_release_entry(
    signing_key: &SigningKey,
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    event: DisclosureReleaseEvent,
) -> DisclosureReleaseEntry {
    let entry_hash = release_entry_hash(seq, prev_hash, release_id, &event);
    let signature = signing_key.sign(&entry_hash).to_bytes();
    DisclosureReleaseEntry {
        schema: ACCOUNTABILITY_RELEASE_ENTRY_SCHEMA.to_string(),
        seq,
        prev_hash,
        release_id,
        event,
        entry_hash,
        signature: SignatureEnvelope::ed25519(signature),
    }
}

fn release_entry_hash(
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    event: &DisclosureReleaseEvent,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_ENTRY_DOMAIN);
    hasher.update(&[0]);
    hasher.update(ACCOUNTABILITY_RELEASE_ENTRY_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(&seq.to_be_bytes());
    hasher.update(&prev_hash);
    hasher.update(release_id.as_bytes());
    match event {
        DisclosureReleaseEvent::Commit {
            permit_digest,
            credential_id,
            retry_of,
        } => {
            hasher.update(&[0]);
            hasher.update(permit_digest);
            hasher.update(credential_id);
            match retry_of {
                Some(id) => {
                    hasher.update(&[1]);
                    hasher.update(id.as_bytes());
                }
                None => hasher.update(&[0]),
            }
        }
        DisclosureReleaseEvent::Outcome(DisclosureReleaseOutcome::Completed) => {
            hasher.update(&[1, 0]);
        }
        DisclosureReleaseEvent::Outcome(DisclosureReleaseOutcome::Aborted) => {
            hasher.update(&[1, 1]);
        }
        DisclosureReleaseEvent::Outcome(DisclosureReleaseOutcome::Partial { bytes_released }) => {
            hasher.update(&[1, 2]);
            hasher.update(&bytes_released.to_be_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

fn require_nonzero(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), AccountabilityDisclosureError> {
    if *digest == [0u8; 32] {
        return Err(AccountabilityDisclosureError::ZeroCommitment { field });
    }
    Ok(())
}

/// Fail-closed credential-gated disclosure errors.
#[derive(Debug, Error)]
pub enum AccountabilityDisclosureError {
    /// Nested authenticated session/transcript validation failed.
    #[error(transparent)]
    TranscriptBinding(#[from] TranscriptBindingError),
    /// Signature envelope shape was invalid.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Signature verification failed.
    #[error(transparent)]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
    /// Binding schema is unsupported.
    #[error("unsupported accountability disclosure binding schema: {schema}")]
    UnsupportedBindingSchema {
        /// Schema found in artifact.
        schema: String,
    },
    /// Permit schema is unsupported.
    #[error("unsupported accountability disclosure permit schema: {schema}")]
    UnsupportedPermitSchema {
        /// Schema found in artifact.
        schema: String,
    },
    /// Release journal schema is unsupported.
    #[error("unsupported accountability release entry schema: {schema}")]
    UnsupportedReleaseEntrySchema {
        /// Schema found in artifact.
        schema: String,
    },
    /// Commitment algorithm is unsupported.
    #[error("unsupported disclosure commitment algorithm: {algorithm}")]
    UnsupportedCommitmentAlgorithm {
        /// Algorithm found in artifact.
        algorithm: String,
    },
    /// v2 release permit/journal currently require Ed25519 ledger authority.
    #[error("unsupported disclosure signature suite: {suite:?}")]
    UnsupportedPermitSignatureSuite {
        /// Suite carried by artifact.
        suite: SignatureSuite,
    },
    /// Release UUID is nil.
    #[error("accountability release ID must not be nil")]
    NilReleaseId,
    /// Operation UUID is nil.
    #[error("accountability operation ID must not be nil")]
    NilOperationId,
    /// Release cannot retry itself.
    #[error("accountability release cannot retry itself")]
    SelfRetry,
    /// Required commitment used all-zero placeholder.
    #[error("accountability disclosure commitment {field} must not be all-zero")]
    ZeroCommitment {
        /// Invalid commitment field.
        field: &'static str,
    },
    /// Ledger anchor count/hash is empty.
    #[error("accountability disclosure requires non-empty ledger anchors")]
    EmptyLedgerAnchor,
    /// Authorization anchor cannot occur after permit preparation frontier.
    #[error("execution authorization anchor occurs after permit ledger frontier")]
    AuthorizationAfterPermitFrontier,
    /// Exact execution authorization is no longer resident for semantic checking.
    #[error("execution authorization anchor is not resident")]
    ExecutionAuthorizationNotResident,
    /// Execution authorization anchor was not an Approval.
    #[error("execution authorization anchor is not an approved consent event")]
    ExecutionAnchorNotApproved,
    /// Permit-preparation ledger frontier is not an ancestor of current chain state.
    #[error("disclosure permit ledger frontier is not an ancestor of current ledger")]
    PermitLedgerNotAncestor,
    /// No resident matching authorization event exists at release time.
    #[error("current execution authorization is not resident")]
    CurrentAuthorizationNotResident,
    /// Matching authorization changed after the execution was bound.
    #[error("execution authorization changed after execution binding")]
    AuthorizationChangedAfterExecution,
    /// Release UUID was already committed.
    #[error("accountability release ID has already been used")]
    ReleaseIdAlreadyUsed,
    /// Credential already has an initial release lineage.
    #[error("release credential already has an initial release lineage")]
    CredentialAlreadyHasLineage,
    /// Retry target does not exist.
    #[error("accountability retry target does not exist")]
    RetryTargetMissing,
    /// Retry attempted under a different credential lineage.
    #[error("accountability retry credential does not match its parent lineage")]
    RetryCredentialMismatch,
    /// Two retries attempted to branch from the same release.
    #[error("accountability retry would fork an existing release lineage")]
    RetryWouldForkLineage,
    /// Unresolved commit cannot be retried automatically.
    #[error("accountability retry target is unresolved")]
    RetryOfUnresolvedRelease,
    /// Completed release cannot be retried.
    #[error("completed accountability release cannot be retried")]
    RetryOfCompletedRelease,
    /// Outcome appeared without a preceding commit.
    #[error("accountability release outcome has no preceding commit")]
    OutcomeWithoutCommit,
    /// More than one terminal outcome was recorded.
    #[error("accountability release already has a terminal outcome")]
    DuplicateOutcome,
    /// Partial release must report at least one byte.
    #[error("partial accountability release must report at least one emitted byte")]
    ZeroPartialRelease,
    /// Release journal sequence/previous hash is invalid.
    #[error("accountability release journal chain mismatch")]
    ReleaseJournalChainMismatch,
    /// Release entry digest is invalid.
    #[error("accountability release journal entry hash mismatch")]
    ReleaseJournalHashMismatch,
    /// Internal append invariant failed after persistence.
    #[error("accountability release append invariant violated")]
    ReleaseAppendInvariant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::accountability::accountability_execution_binding_digest;
    use crate::accountability_interop::accountability_verifier_key_id;
    use crate::release_credential::{
        ReleaseCredentialTrustPolicy, SIF_RELEASE_CREDENTIAL_ED25519,
        SIF_RELEASE_CREDENTIAL_SCHEMA, SifReleaseCredential, SifReleaseCredentialSignature,
        SifReleaseCredentialStatement, TrustedReleaseAuthority,
        bind_release_credential_to_execution, release_authority_key_id,
        release_credential_message, verify_release_credential,
    };
    use crate::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, ConsentEventRecord, Ed25519EvidenceSignatureBackend,
        SignatureSuite,
    };

    const EXECUTION_DOMAIN: [u8; 32] = [77u8; 32];

    fn chain_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn release_authority_key() -> SigningKey {
        SigningKey::from_bytes(&[55u8; 32])
    }

    fn session(session_id: Uuid) -> SessionTranscriptBinding {
        SessionTranscriptBinding::new(
            session_id,
            b"credential-gated disclosure session",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        )
    }

    fn seeded_chain() -> Chain {
        let mut chain = Chain::new(chain_key());
        chain
            .append(ConsentEventRecord {
                source_id: [9u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(2),
                kind: ConsentKind::Approval,
                scope: "purpose-bound lookup".into(),
            })
            .unwrap();
        chain
    }

    fn bound_credential(chain: &Chain, credential_id: [u8; 32]) -> ExecutionBoundReleaseCredential {
        let execution = chain
            .attest_accountability_execution(
                session(Uuid::from_u128(1)),
                Uuid::from_u128(3),
                [9u8; 32],
                [10u8; 32],
                [11u8; 32],
                [12u8; 32],
                Some([13u8; 32]),
                [14u8; 32],
            )
            .unwrap();
        let chain_public_key = chain.signing_key.verifying_key().to_bytes();
        let statement = SifReleaseCredentialStatement {
            schema: SIF_RELEASE_CREDENTIAL_SCHEMA.into(),
            credential_id,
            receipt_statement_digest: execution.binding.receipt_digest,
            pre_witness_bundle_digest: [19u8; 32],
            finalized_evidence_bundle_digest: [20u8; 32],
            accountability_policy_digest: execution.binding.policy_digest,
            non_witness_trust_policy_digest: [21u8; 32],
            witness_policy_digest: [22u8; 32],
            execution_proof_digest: accountability_execution_binding_digest(&execution.binding),
            execution_verifier_id: accountability_verifier_key_id(
                SignatureSuite::Ed25519Rfc8032,
                &chain_public_key,
            ),
            execution_trust_domain_id: EXECUTION_DOMAIN,
            result_digest: execution.binding.result_digest,
        };
        let authority = release_authority_key();
        let signature = SifReleaseCredentialSignature {
            algorithm: SIF_RELEASE_CREDENTIAL_ED25519.into(),
            signer_key_id: release_authority_key_id(&authority.verifying_key().to_bytes()),
            signature: authority
                .sign(&release_credential_message(&statement))
                .to_bytes()
                .to_vec(),
        };
        let credential = SifReleaseCredential {
            statement,
            signatures: vec![signature],
        };
        let trusted = [TrustedReleaseAuthority {
            public_key: authority.verifying_key().to_bytes(),
            trust_domain_id: [66u8; 32],
        }];
        let verified = verify_release_credential(
            &credential,
            &trusted,
            ReleaseCredentialTrustPolicy {
                min_valid_signatures: 1,
                min_distinct_trust_domains: 1,
            },
        )
        .unwrap();
        bind_release_credential_to_execution(
            &verified,
            &execution,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &Ed25519EvidenceSignatureBackend,
            &chain_public_key,
            EXECUTION_DOMAIN,
        )
        .unwrap()
    }

    fn permit(
        chain: &Chain,
        credential: &ExecutionBoundReleaseCredential,
        release_id: Uuid,
        retry_of: Option<Uuid>,
    ) -> AccountabilityDisclosurePermit {
        chain
            .prepare_accountability_disclosure(
                credential,
                release_id,
                retry_of,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            )
            .unwrap()
    }

    fn commit(
        state: &mut DisclosureReleaseState,
        chain: &Chain,
        permit: AccountabilityDisclosurePermit,
    ) -> Result<CommittedDisclosurePermit, TransactionalDisclosureError<()>> {
        state.commit_permit_transactional(
            chain,
            permit,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            |_| Ok(()),
        )
    }

    #[test]
    fn credential_is_bound_into_signed_permit() {
        let chain = seeded_chain();
        let credential = bound_credential(&chain, [31u8; 32]);
        let permit = permit(&chain, &credential, Uuid::from_u128(30), None);
        assert_eq!(permit.binding().credential_id(), [31u8; 32]);
        assert_eq!(permit.binding().evidence_bundle_digest(), [20u8; 32]);
    }

    #[test]
    fn later_matching_approval_does_not_resurrect_old_execution() {
        let mut chain = seeded_chain();
        let credential = bound_credential(&chain, [31u8; 32]);
        chain
            .append(ConsentEventRecord {
                source_id: [9u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(99),
                kind: ConsentKind::Approval,
                scope: "different later authorization".into(),
            })
            .unwrap();
        assert!(matches!(
            chain.prepare_accountability_disclosure(
                &credential,
                Uuid::from_u128(30),
                None,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            ),
            Err(AccountabilityDisclosureError::AuthorizationChangedAfterExecution)
        ));
    }

    #[test]
    fn revocation_after_permit_prepare_blocks_commit() {
        let mut chain = seeded_chain();
        let credential = bound_credential(&chain, [31u8; 32]);
        let permit = permit(&chain, &credential, Uuid::from_u128(30), None);
        chain
            .append(ConsentEventRecord {
                source_id: [9u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(4),
                kind: ConsentKind::Revocation,
                scope: "revoke before output".into(),
            })
            .unwrap();
        let mut state = DisclosureReleaseState::default();
        assert!(matches!(
            commit(&mut state, &chain, permit),
            Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::AuthorizationChangedAfterExecution
            ))
        ));
    }

    #[test]
    fn persistence_failure_returns_no_committed_capability() {
        let chain = seeded_chain();
        let credential = bound_credential(&chain, [31u8; 32]);
        let permit = permit(&chain, &credential, Uuid::from_u128(30), None);
        let mut state = DisclosureReleaseState::default();
        let result = state.commit_permit_transactional(
            &chain,
            permit,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            |_| Err::<(), _>("disk unavailable"),
        );
        assert!(matches!(result, Err(TransactionalDisclosureError::Persist(_))));
        assert!(state.entries().is_empty());
    }

    #[test]
    fn credential_cannot_create_second_initial_release() {
        let chain = seeded_chain();
        let credential = bound_credential(&chain, [31u8; 32]);
        let mut state = DisclosureReleaseState::default();
        commit(
            &mut state,
            &chain,
            permit(&chain, &credential, Uuid::from_u128(30), None),
        )
        .unwrap();
        let result = commit(
            &mut state,
            &chain,
            permit(&chain, &credential, Uuid::from_u128(31), None),
        );
        assert!(matches!(
            result,
            Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::CredentialAlreadyHasLineage
            ))
        ));
    }

    #[test]
    fn retry_lineage_cannot_branch() {
        let chain = seeded_chain();
        let credential = bound_credential(&chain, [31u8; 32]);
        let mut state = DisclosureReleaseState::default();
        let root = Uuid::from_u128(30);
        commit(&mut state, &chain, permit(&chain, &credential, root, None)).unwrap();
        state
            .record_outcome_transactional(
                &chain,
                root,
                DisclosureReleaseOutcome::Partial { bytes_released: 7 },
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        commit(
            &mut state,
            &chain,
            permit(&chain, &credential, Uuid::from_u128(31), Some(root)),
        )
        .unwrap();
        let branch = commit(
            &mut state,
            &chain,
            permit(&chain, &credential, Uuid::from_u128(32), Some(root)),
        );
        assert!(matches!(
            branch,
            Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::RetryWouldForkLineage
            ))
        ));
    }

    #[test]
    fn verified_rehydration_preserves_lineage_rules() {
        let chain = seeded_chain();
        let credential = bound_credential(&chain, [31u8; 32]);
        let mut state = DisclosureReleaseState::default();
        let root = Uuid::from_u128(30);
        commit(&mut state, &chain, permit(&chain, &credential, root, None)).unwrap();
        state
            .record_outcome_transactional(
                &chain,
                root,
                DisclosureReleaseOutcome::Aborted,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        let entries = state.into_entries();
        let restored = DisclosureReleaseState::from_verified_entries(
            entries,
            chain.signing_key.verifying_key().as_bytes(),
        )
        .unwrap();
        assert_eq!(restored.entries().len(), 2);
    }
}
