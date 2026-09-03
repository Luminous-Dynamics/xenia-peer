// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single-use disclosure permits for reciprocal accountability.
//!
//! This module is deliberately commitment-only. It never receives citizen identity,
//! case text, query text, or protected record bytes. A permit binds a witnessed
//! higher-layer evidence bundle to the exact Xenia execution, authenticated session,
//! requester, result commitment, and signed consent-ledger frontier.
//!
//! A prepared permit is **not** sufficient to release data. It must first be
//! transactionally committed to [`DisclosureReleaseState`]. The resulting
//! [`CommittedDisclosurePermit`] is move-only and intended to be consumed by a
//! protected-output adapter. Persistence failure fails closed before that token is
//! returned.
//!
//! Consent is checked twice: the original execution anchor must be a resident signed
//! `Approval`, and commit-time state must still have `Approval` as the latest event
//! for the same authenticated session/requester. A later denial, revocation,
//! violation, or unresolved request therefore prevents release.
//!
//! Release outcomes are explicit. A crash after commit but before an outcome leaves
//! an unresolved commit and MUST NOT be replayed automatically. A retry uses a new
//! release ID and may reference only an earlier `Aborted` or `Partial` release.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::accountability::{
    AccountabilityBindingError, AccountabilityExecutionAttestation,
    accountability_execution_binding_digest,
};
use crate::binding::SessionTranscriptBinding;
use crate::chain::Chain;
use crate::entry::{ConsentKind, LedgerEntry, TranscriptBindingError};
use crate::policy::EvidenceCryptoManifest;
use crate::signature::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend, EvidenceSignatureBackendError,
    SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema for the release authorization binding.
pub const ACCOUNTABILITY_DISCLOSURE_BINDING_SCHEMA: &str =
    "xenia-accountability-disclosure-binding-v1";
/// Stable schema for the signed release permit.
pub const ACCOUNTABILITY_DISCLOSURE_PERMIT_SCHEMA: &str =
    "xenia-accountability-disclosure-permit-v1";
/// Stable schema for the separate signed release journal.
pub const ACCOUNTABILITY_RELEASE_ENTRY_SCHEMA: &str =
    "xenia-accountability-release-entry-v1";
/// Commitment algorithm used throughout this profile.
pub const ACCOUNTABILITY_DISCLOSURE_COMMITMENT_ALGORITHM: &str = "blake3-256";

const DISCLOSURE_BINDING_DOMAIN: &[u8] = b"xenia:accountability-disclosure-binding:v1";
const DISCLOSURE_PERMIT_DIGEST_DOMAIN: &[u8] =
    b"xenia:accountability-disclosure-permit-digest:v1";
const RELEASE_ENTRY_DOMAIN: &[u8] = b"xenia:accountability-release-entry:v1";

/// Release phase represented by a v1 disclosure permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountabilityDisclosurePhase {
    /// The witnessed evidence bundle has been bound to the authenticated execution,
    /// but no protected output is authorized until the permit is journal-committed.
    PreparedForRelease,
}

/// Commitment-only release binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilityDisclosureBinding {
    /// Stable schema label.
    pub schema: String,
    /// Commitment algorithm label.
    pub commitment_algorithm: String,
    /// Unique single-use release identifier.
    pub release_id: Uuid,
    /// Explicit previous release when this is an authorized retry.
    pub retry_of: Option<Uuid>,
    /// Logical operation from the verified execution binding.
    pub operation_id: Uuid,
    /// Authenticated Xenia session transcript.
    pub session: SessionTranscriptBinding,
    /// Opaque authenticated requester fingerprint.
    pub requester_source_id: [u8; 32],
    /// Frozen Mycelix receipt statement.
    pub receipt_digest: [u8; 32],
    /// Exact witnessed/high-assurance evidence-bundle commitment.
    pub evidence_bundle_digest: [u8; 32],
    /// Exact signed Xenia execution-binding digest.
    pub execution_binding_digest: [u8; 32],
    /// Minimum-necessary result commitment, when a disclosure result exists.
    pub result_digest: Option<[u8; 32]>,
    /// Consent-ledger entry count when the permit was prepared.
    pub ledger_entry_count: u64,
    /// Consent-ledger head when the permit was prepared.
    pub ledger_head_hash: [u8; 32],
    /// v1 release phase.
    pub phase: AccountabilityDisclosurePhase,
}

impl AccountabilityDisclosureBinding {
    /// Validate schema, identifiers, commitments and nested transcript shape.
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
        require_nonzero("requester_source_id", &self.requester_source_id)?;
        require_nonzero("receipt_digest", &self.receipt_digest)?;
        require_nonzero("evidence_bundle_digest", &self.evidence_bundle_digest)?;
        require_nonzero("execution_binding_digest", &self.execution_binding_digest)?;
        if let Some(result) = &self.result_digest {
            require_nonzero("result_digest", result)?;
        }
        if self.ledger_entry_count == 0 || self.ledger_head_hash == [0u8; 32] {
            return Err(AccountabilityDisclosureError::EmptyLedgerAnchor);
        }
        self.session.validate_against_manifest(manifest)?;
        Ok(())
    }
}

/// Signed prepared release permit.
///
/// This type intentionally does not implement `Clone`: callers should treat a
/// permit as a capability that advances into a committed release token.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilityDisclosurePermit {
    /// Stable permit schema.
    pub schema: String,
    /// Bound release statement.
    pub binding: AccountabilityDisclosureBinding,
    /// Current Xenia ledger-authority signature. v1 permit signing is Ed25519.
    pub signature: SignatureEnvelope,
}

impl AccountabilityDisclosurePermit {
    /// Verify shape, transcript binding and current Ed25519 ledger-authority signature.
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

/// Exact expected live release context supplied by the protected-output boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountabilityDisclosureExpectation {
    /// Expected release identifier.
    pub release_id: Uuid,
    /// Expected operation identifier.
    pub operation_id: Uuid,
    /// Expected authenticated session identifier.
    pub session_id: Uuid,
    /// Expected requester fingerprint.
    pub requester_source_id: [u8; 32],
    /// Expected receipt statement.
    pub receipt_digest: [u8; 32],
    /// Expected witnessed evidence bundle.
    pub evidence_bundle_digest: [u8; 32],
    /// Expected Xenia execution binding.
    pub execution_binding_digest: [u8; 32],
    /// Expected minimum-necessary result.
    pub result_digest: Option<[u8; 32]>,
}

/// Produce canonical bytes signed by the release-permit authority.
pub fn accountability_disclosure_message(binding: &AccountabilityDisclosureBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(320);
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
    out.extend_from_slice(&binding.ledger_entry_count.to_be_bytes());
    out.extend_from_slice(&binding.ledger_head_hash);
    out.push(match binding.phase {
        AccountabilityDisclosurePhase::PreparedForRelease => 1,
    });
    out
}

/// Stable identifier for a signed release permit.
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
    /// Prepare and sign a release permit after verifying the exact execution
    /// attestation whose result will be disclosed.
    ///
    /// The execution anchor must still be resident and must itself be an explicit
    /// consent `Approval`. A compacted checkpoint proves chain continuity but does
    /// not expose enough semantics to authorize release, so that case fails closed.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_accountability_disclosure(
        &self,
        execution: &AccountabilityExecutionAttestation,
        evidence_bundle_digest: [u8; 32],
        release_id: Uuid,
        retry_of: Option<Uuid>,
        manifest: EvidenceCryptoManifest,
        execution_backend: &impl EvidenceSignatureBackend,
        execution_public_key: &[u8],
    ) -> Result<AccountabilityDisclosurePermit, AccountabilityDisclosureError> {
        execution.verify(manifest, execution_backend, execution_public_key)?;
        let anchor = resident_execution_anchor(self, execution)
            .ok_or(AccountabilityDisclosureError::ExecutionAuthorizationNotResident)?;
        if anchor.event.kind != ConsentKind::Approval {
            return Err(AccountabilityDisclosureError::ExecutionAnchorNotApproved);
        }
        require_nonzero("evidence_bundle_digest", &evidence_bundle_digest)?;

        let binding = AccountabilityDisclosureBinding {
            schema: ACCOUNTABILITY_DISCLOSURE_BINDING_SCHEMA.to_string(),
            commitment_algorithm: ACCOUNTABILITY_DISCLOSURE_COMMITMENT_ALGORITHM.to_string(),
            release_id,
            retry_of,
            operation_id: execution.binding.operation_id,
            session: execution.binding.session.clone(),
            requester_source_id: execution.binding.requester_source_id,
            receipt_digest: execution.binding.receipt_digest,
            evidence_bundle_digest,
            execution_binding_digest: accountability_execution_binding_digest(&execution.binding),
            result_digest: execution.binding.result_digest,
            ledger_entry_count: self.entry_count(),
            ledger_head_hash: self.last_hash(),
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

/// Terminal result recorded after an output adapter consumes a committed permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureReleaseOutcome {
    /// The intended protected payload was completely emitted.
    Completed,
    /// No protected bytes were emitted. A new release may explicitly retry this ID.
    Aborted,
    /// Some bytes were emitted and the release stopped. Any retry must be explicit.
    Partial {
        /// Number of protected bytes known to have been emitted.
        bytes_released: u64,
    },
}

/// Event recorded in the separate signed release journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureReleaseEvent {
    /// A prepared permit was durably committed before protected output.
    Commit {
        /// Stable digest of the exact signed permit.
        permit_digest: [u8; 32],
        /// Prior terminal release when this is an explicit retry.
        retry_of: Option<Uuid>,
    },
    /// Terminal observation reported by the output adapter.
    Outcome(DisclosureReleaseOutcome),
}

/// One signed hash-chained release-journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureReleaseEntry {
    /// Stable entry schema.
    pub schema: String,
    /// Monotonic journal sequence number.
    pub seq: u64,
    /// Previous release-entry hash, all zero for genesis.
    pub prev_hash: [u8; 32],
    /// Release governed by this event.
    pub release_id: Uuid,
    /// Commit or terminal outcome event.
    pub event: DisclosureReleaseEvent,
    /// Domain-separated hash of the complete entry statement.
    pub entry_hash: [u8; 32],
    /// Algorithm-tagged ledger-authority signature over `entry_hash`.
    pub signature: SignatureEnvelope,
}

/// Append-only release state. Persistence is supplied transactionally by the caller.
#[derive(Debug, Default)]
pub struct DisclosureReleaseState {
    entries: Vec<DisclosureReleaseEntry>,
}

impl DisclosureReleaseState {
    /// Rehydrate release state. Call [`verify_disclosure_release_entries`] before
    /// trusting externally loaded entries.
    pub fn from_entries(entries: Vec<DisclosureReleaseEntry>) -> Self {
        Self { entries }
    }

    /// Read all journal entries for persistence/audit.
    pub fn entries(&self) -> &[DisclosureReleaseEntry] {
        &self.entries
    }

    /// Consume state into its persisted representation.
    pub fn into_entries(self) -> Vec<DisclosureReleaseEntry> {
        self.entries
    }

    /// Transactionally commit a prepared permit and return the move-only token
    /// required by a protected-output adapter.
    ///
    /// The current consent ledger is re-checked immediately before the release
    /// journal commit. The latest event for the permit's session/requester must
    /// still be an explicit `Approval`.
    pub fn commit_permit_transactional<E>(
        &mut self,
        chain: &Chain,
        permit: AccountabilityDisclosurePermit,
        expected: &AccountabilityDisclosureExpectation,
        manifest: EvidenceCryptoManifest,
        persist: impl FnOnce(&[DisclosureReleaseEntry]) -> Result<(), E>,
    ) -> Result<CommittedDisclosurePermit, TransactionalDisclosureError<E>> {
        permit
            .verify(manifest, chain.signing_key.verifying_key().as_bytes())
            .map_err(TransactionalDisclosureError::Protocol)?;
        verify_expectation(&permit.binding, expected)
            .map_err(TransactionalDisclosureError::Protocol)?;
        if !chain_contains_frontier(
            chain,
            permit.binding.ledger_entry_count,
            permit.binding.ledger_head_hash,
        ) {
            return Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::PermitLedgerNotAncestor,
            ));
        }
        require_live_approval(chain, &permit.binding)
            .map_err(TransactionalDisclosureError::Protocol)?;
        self.validate_new_commit(&permit.binding)
            .map_err(TransactionalDisclosureError::Protocol)?;

        let permit_digest = accountability_disclosure_permit_digest(&permit);
        let event = DisclosureReleaseEvent::Commit {
            permit_digest,
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
            operation_id: permit.binding.operation_id,
            session_id: permit.binding.session.session_id,
            result_digest: permit.binding.result_digest,
            evidence_bundle_digest: permit.binding.evidence_bundle_digest,
            release_entry_hash,
        })
    }

    /// Transactionally record the terminal output result for one committed release.
    pub fn record_outcome_transactional<E>(
        &mut self,
        chain: &Chain,
        release_id: Uuid,
        outcome: DisclosureReleaseOutcome,
        persist: impl FnOnce(&[DisclosureReleaseEntry]) -> Result<(), E>,
    ) -> Result<(), TransactionalDisclosureError<E>> {
        match self.release_lifecycle(release_id) {
            ReleaseLifecycle::Missing => {
                return Err(TransactionalDisclosureError::Protocol(
                    AccountabilityDisclosureError::OutcomeWithoutCommit,
                ));
            }
            ReleaseLifecycle::Terminal(_) => {
                return Err(TransactionalDisclosureError::Protocol(
                    AccountabilityDisclosureError::DuplicateOutcome,
                ));
            }
            ReleaseLifecycle::Committed => {}
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
        if !matches!(
            self.release_lifecycle(binding.release_id),
            ReleaseLifecycle::Missing
        ) {
            return Err(AccountabilityDisclosureError::ReleaseIdAlreadyUsed);
        }
        validate_retry_target(&self.lifecycle_map(), binding.retry_of)
    }

    fn lifecycle_map(&self) -> BTreeMap<Uuid, ReleaseLifecycle> {
        let mut map = BTreeMap::new();
        for entry in &self.entries {
            match entry.event {
                DisclosureReleaseEvent::Commit { .. } => {
                    map.insert(entry.release_id, ReleaseLifecycle::Committed);
                }
                DisclosureReleaseEvent::Outcome(value) => {
                    map.insert(entry.release_id, ReleaseLifecycle::Terminal(value));
                }
            }
        }
        map
    }

    fn release_lifecycle(&self, release_id: Uuid) -> ReleaseLifecycle {
        self.lifecycle_map()
            .get(&release_id)
            .copied()
            .unwrap_or(ReleaseLifecycle::Missing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseLifecycle {
    Missing,
    Committed,
    Terminal(DisclosureReleaseOutcome),
}

/// Move-only proof that the release decision was durably journal-committed.
///
/// Output adapters should require this type by value. It cannot be constructed by
/// downstream crates because its fields are private, and it intentionally does not
/// implement `Clone`.
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedDisclosurePermit {
    release_id: Uuid,
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

    /// Witnessed evidence-bundle commitment that qualified this release.
    pub const fn evidence_bundle_digest(&self) -> [u8; 32] {
        self.evidence_bundle_digest
    }

    /// Signed release-journal entry that durably committed this release.
    pub const fn release_entry_hash(&self) -> [u8; 32] {
        self.release_entry_hash
    }
}

/// Persistence failure vs protocol failure when advancing release state.
#[derive(Debug)]
pub enum TransactionalDisclosureError<E> {
    /// Protocol/cryptographic validation failed before release authorization.
    Protocol(AccountabilityDisclosureError),
    /// Durable persistence failed; the in-memory append was rolled back.
    Persist(E),
}

/// Verify a persisted release journal's hash chain, retry graph, lifecycle, and
/// Ed25519 signatures.
pub fn verify_disclosure_release_entries(
    entries: &[DisclosureReleaseEntry],
    ledger_public_key: &[u8],
) -> Result<(), AccountabilityDisclosureError> {
    let backend = Ed25519EvidenceSignatureBackend;
    let mut previous = [0u8; 32];
    let mut lifecycle: BTreeMap<Uuid, ReleaseLifecycle> = BTreeMap::new();

    for (index, entry) in entries.iter().enumerate() {
        if entry.schema != ACCOUNTABILITY_RELEASE_ENTRY_SCHEMA {
            return Err(AccountabilityDisclosureError::UnsupportedReleaseEntrySchema {
                schema: entry.schema.clone(),
            });
        }
        if entry.seq != index as u64 || entry.prev_hash != previous {
            return Err(AccountabilityDisclosureError::ReleaseJournalChainMismatch);
        }
        let expected_hash =
            release_entry_hash(entry.seq, entry.prev_hash, entry.release_id, &entry.event);
        if entry.entry_hash != expected_hash {
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

        let current = lifecycle
            .get(&entry.release_id)
            .copied()
            .unwrap_or(ReleaseLifecycle::Missing);
        let next = match (current, &entry.event) {
            (
                ReleaseLifecycle::Missing,
                DisclosureReleaseEvent::Commit {
                    permit_digest,
                    retry_of,
                },
            ) => {
                require_nonzero("permit_digest", permit_digest)?;
                validate_retry_target(&lifecycle, *retry_of)?;
                ReleaseLifecycle::Committed
            }
            (ReleaseLifecycle::Committed, DisclosureReleaseEvent::Outcome(value)) => {
                validate_outcome(*value)?;
                ReleaseLifecycle::Terminal(*value)
            }
            _ => return Err(AccountabilityDisclosureError::InvalidReleaseJournalLifecycle),
        };
        lifecycle.insert(entry.release_id, next);
        previous = entry.entry_hash;
    }
    Ok(())
}

fn verify_expectation(
    binding: &AccountabilityDisclosureBinding,
    expected: &AccountabilityDisclosureExpectation,
) -> Result<(), AccountabilityDisclosureError> {
    if binding.release_id != expected.release_id {
        return Err(AccountabilityDisclosureError::ExpectationMismatch(
            "release_id",
        ));
    }
    if binding.operation_id != expected.operation_id {
        return Err(AccountabilityDisclosureError::ExpectationMismatch(
            "operation_id",
        ));
    }
    if binding.session.session_id != expected.session_id {
        return Err(AccountabilityDisclosureError::ExpectationMismatch(
            "session_id",
        ));
    }
    require_equal(
        "requester_source_id",
        &binding.requester_source_id,
        &expected.requester_source_id,
    )?;
    require_equal(
        "receipt_digest",
        &binding.receipt_digest,
        &expected.receipt_digest,
    )?;
    require_equal(
        "evidence_bundle_digest",
        &binding.evidence_bundle_digest,
        &expected.evidence_bundle_digest,
    )?;
    require_equal(
        "execution_binding_digest",
        &binding.execution_binding_digest,
        &expected.execution_binding_digest,
    )?;
    if binding.result_digest != expected.result_digest {
        return Err(AccountabilityDisclosureError::ExpectationMismatch(
            "result_digest",
        ));
    }
    Ok(())
}

fn resident_execution_anchor<'a>(
    chain: &'a Chain,
    execution: &AccountabilityExecutionAttestation,
) -> Option<&'a LedgerEntry> {
    chain.iter().find(|entry| {
        entry.seq.checked_add(1) == Some(execution.binding.ledger_entry_count)
            && entry.entry_hash == execution.binding.ledger_head_hash
            && entry.event.session_id == execution.binding.session.session_id
            && entry.event.source_id == execution.binding.requester_source_id
    })
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

fn require_live_approval(
    chain: &Chain,
    binding: &AccountabilityDisclosureBinding,
) -> Result<(), AccountabilityDisclosureError> {
    let latest = chain.iter().rev().find(|entry| {
        entry.event.session_id == binding.session.session_id
            && entry.event.source_id == binding.requester_source_id
    });
    match latest {
        Some(entry) if entry.event.kind == ConsentKind::Approval => Ok(()),
        Some(_) => Err(AccountabilityDisclosureError::CurrentConsentNotApproved),
        None => Err(AccountabilityDisclosureError::CurrentConsentNotResident),
    }
}

fn validate_retry_target(
    lifecycle: &BTreeMap<Uuid, ReleaseLifecycle>,
    retry_of: Option<Uuid>,
) -> Result<(), AccountabilityDisclosureError> {
    let Some(previous) = retry_of else {
        return Ok(());
    };
    match lifecycle.get(&previous).copied() {
        Some(ReleaseLifecycle::Terminal(DisclosureReleaseOutcome::Aborted))
        | Some(ReleaseLifecycle::Terminal(DisclosureReleaseOutcome::Partial { .. })) => Ok(()),
        Some(ReleaseLifecycle::Terminal(DisclosureReleaseOutcome::Completed)) => {
            Err(AccountabilityDisclosureError::RetryOfCompletedRelease)
        }
        Some(ReleaseLifecycle::Committed) => {
            Err(AccountabilityDisclosureError::RetryOfUnresolvedRelease)
        }
        Some(ReleaseLifecycle::Missing) | None => {
            Err(AccountabilityDisclosureError::RetryTargetMissing)
        }
    }
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
            retry_of,
        } => {
            hasher.update(&[0]);
            hasher.update(permit_digest);
            match retry_of {
                Some(id) => {
                    hasher.update(&[1]);
                    hasher.update(id.as_bytes());
                }
                None => {
                    hasher.update(&[0]);
                }
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

fn require_equal(
    field: &'static str,
    actual: &[u8; 32],
    expected: &[u8; 32],
) -> Result<(), AccountabilityDisclosureError> {
    if actual != expected {
        return Err(AccountabilityDisclosureError::ExpectationMismatch(field));
    }
    Ok(())
}

/// Fail-closed release-permit and release-journal errors.
#[derive(Debug, Error)]
pub enum AccountabilityDisclosureError {
    /// The execution proof supplied to permit preparation was invalid.
    #[error(transparent)]
    ExecutionBinding(#[from] AccountabilityBindingError),
    /// Nested authenticated-session transcript validation failed.
    #[error(transparent)]
    TranscriptBinding(#[from] TranscriptBindingError),
    /// Signature-envelope shape was invalid.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Cryptographic signature verification failed.
    #[error(transparent)]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
    /// Binding schema is unsupported.
    #[error("unsupported accountability disclosure binding schema: {schema}")]
    UnsupportedBindingSchema {
        /// Schema found in the artifact.
        schema: String,
    },
    /// Permit schema is unsupported.
    #[error("unsupported accountability disclosure permit schema: {schema}")]
    UnsupportedPermitSchema {
        /// Schema found in the artifact.
        schema: String,
    },
    /// Release-entry schema is unsupported.
    #[error("unsupported accountability release entry schema: {schema}")]
    UnsupportedReleaseEntrySchema {
        /// Schema found in the artifact.
        schema: String,
    },
    /// Commitment algorithm is unsupported.
    #[error("unsupported disclosure commitment algorithm: {algorithm}")]
    UnsupportedCommitmentAlgorithm {
        /// Algorithm found in the artifact.
        algorithm: String,
    },
    /// v1 release permits/journal entries are signed by the current Ed25519 authority.
    #[error("unsupported disclosure signature suite: {suite:?}")]
    UnsupportedPermitSignatureSuite {
        /// Suite found in the artifact.
        suite: SignatureSuite,
    },
    /// Release UUID must be non-nil.
    #[error("accountability release ID must not be nil")]
    NilReleaseId,
    /// Operation UUID must be non-nil.
    #[error("accountability operation ID must not be nil")]
    NilOperationId,
    /// A retry cannot reference itself.
    #[error("accountability release cannot retry itself")]
    SelfRetry,
    /// Required fixed-size commitment was all zero.
    #[error("accountability disclosure commitment {field} must not be all-zero")]
    ZeroCommitment {
        /// Zero-valued field.
        field: &'static str,
    },
    /// Permit was anchored to an empty consent ledger.
    #[error("accountability disclosure requires a non-empty consent-ledger anchor")]
    EmptyLedgerAnchor,
    /// Exact execution authorization entry is not resident and cannot be semantically inspected.
    #[error("accountability execution authorization anchor is not resident")]
    ExecutionAuthorizationNotResident,
    /// Exact execution anchor was not an explicit consent approval.
    #[error("accountability execution anchor is not an approved consent event")]
    ExecutionAnchorNotApproved,
    /// Permit ledger frontier is not in the current chain history.
    #[error("accountability permit ledger frontier is not an ancestor of the current ledger")]
    PermitLedgerNotAncestor,
    /// No current resident consent event can establish release authority.
    #[error("current accountability consent state is not resident")]
    CurrentConsentNotResident,
    /// Latest matching consent event is no longer an approval.
    #[error("current accountability consent state is not approved")]
    CurrentConsentNotApproved,
    /// A permit field differed from the protected-output boundary's expected context.
    #[error("accountability disclosure expectation mismatch: {0}")]
    ExpectationMismatch(&'static str),
    /// Release ID was previously committed.
    #[error("accountability release ID has already been used")]
    ReleaseIdAlreadyUsed,
    /// Retry target does not exist.
    #[error("accountability retry target does not exist")]
    RetryTargetMissing,
    /// Unresolved commit cannot be automatically retried.
    #[error("accountability retry target is unresolved; record an explicit outcome first")]
    RetryOfUnresolvedRelease,
    /// A completed release cannot be retried.
    #[error("completed accountability release cannot be retried")]
    RetryOfCompletedRelease,
    /// Outcome cannot precede commit.
    #[error("accountability release outcome has no preceding commit")]
    OutcomeWithoutCommit,
    /// A release has only one terminal outcome.
    #[error("accountability release already has a terminal outcome")]
    DuplicateOutcome,
    /// Partial output must report at least one emitted byte.
    #[error("partial accountability release must report at least one emitted byte")]
    ZeroPartialRelease,
    /// Release journal sequence/previous-hash chain is invalid.
    #[error("accountability release journal chain mismatch")]
    ReleaseJournalChainMismatch,
    /// Release journal entry hash is invalid.
    #[error("accountability release journal entry hash mismatch")]
    ReleaseJournalHashMismatch,
    /// Release journal event lifecycle is invalid.
    #[error("accountability release journal has an invalid event lifecycle")]
    InvalidReleaseJournalLifecycle,
    /// Internal append invariant was violated after successful persistence.
    #[error("accountability release append invariant violated")]
    ReleaseAppendInvariant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, ConsentEventRecord, Ed25519EvidenceSignatureBackend,
    };

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn session(session_id: Uuid) -> SessionTranscriptBinding {
        SessionTranscriptBinding::new(
            session_id,
            b"authenticated disclosure session",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        )
    }

    fn seeded_chain(kind: ConsentKind) -> Chain {
        let mut chain = Chain::new(key());
        chain
            .append(ConsentEventRecord {
                source_id: [9u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(2),
                kind,
                scope: "purpose-bound lookup".into(),
            })
            .unwrap();
        chain
    }

    fn execution(chain: &Chain) -> AccountabilityExecutionAttestation {
        chain
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
            .unwrap()
    }

    fn permit(
        chain: &Chain,
        release_id: Uuid,
        retry_of: Option<Uuid>,
    ) -> AccountabilityDisclosurePermit {
        let execution = execution(chain);
        chain
            .prepare_accountability_disclosure(
                &execution,
                [20u8; 32],
                release_id,
                retry_of,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                chain.signing_key.verifying_key().as_bytes(),
            )
            .unwrap()
    }

    fn expected(permit: &AccountabilityDisclosurePermit) -> AccountabilityDisclosureExpectation {
        AccountabilityDisclosureExpectation {
            release_id: permit.binding.release_id,
            operation_id: permit.binding.operation_id,
            session_id: permit.binding.session.session_id,
            requester_source_id: permit.binding.requester_source_id,
            receipt_digest: permit.binding.receipt_digest,
            evidence_bundle_digest: permit.binding.evidence_bundle_digest,
            execution_binding_digest: permit.binding.execution_binding_digest,
            result_digest: permit.binding.result_digest,
        }
    }

    #[test]
    fn execution_anchor_must_be_explicit_approval() {
        let chain = seeded_chain(ConsentKind::Denial);
        let execution = execution(&chain);
        let result = chain.prepare_accountability_disclosure(
            &execution,
            [20u8; 32],
            Uuid::from_u128(30),
            None,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &Ed25519EvidenceSignatureBackend,
            chain.signing_key.verifying_key().as_bytes(),
        );
        assert!(matches!(
            result,
            Err(AccountabilityDisclosureError::ExecutionAnchorNotApproved)
        ));
    }

    #[test]
    fn revocation_after_prepare_blocks_commit() {
        let mut chain = seeded_chain(ConsentKind::Approval);
        let permit = permit(&chain, Uuid::from_u128(30), None);
        let expectation = expected(&permit);
        chain
            .append(ConsentEventRecord {
                source_id: [9u8; 32],
                session_id: Uuid::from_u128(1),
                request_id: Uuid::from_u128(4),
                kind: ConsentKind::Revocation,
                scope: "revoke before disclosure".into(),
            })
            .unwrap();

        let mut state = DisclosureReleaseState::default();
        let result = state.commit_permit_transactional(
            &chain,
            permit,
            &expectation,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(
            result,
            Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::CurrentConsentNotApproved
            ))
        ));
    }

    #[test]
    fn persistence_failure_fails_closed_and_rolls_back() {
        let chain = seeded_chain(ConsentKind::Approval);
        let permit = permit(&chain, Uuid::from_u128(30), None);
        let expectation = expected(&permit);
        let mut state = DisclosureReleaseState::default();
        let result = state.commit_permit_transactional(
            &chain,
            permit,
            &expectation,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            |_| Err::<(), _>("disk unavailable"),
        );
        assert!(matches!(
            result,
            Err(TransactionalDisclosureError::Persist(_))
        ));
        assert!(state.entries().is_empty());
    }

    #[test]
    fn witnessed_bundle_mismatch_fails_closed() {
        let chain = seeded_chain(ConsentKind::Approval);
        let permit = permit(&chain, Uuid::from_u128(30), None);
        let mut expectation = expected(&permit);
        expectation.evidence_bundle_digest = [99u8; 32];
        let mut state = DisclosureReleaseState::default();
        let result = state.commit_permit_transactional(
            &chain,
            permit,
            &expectation,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(
            result,
            Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::ExpectationMismatch("evidence_bundle_digest")
            ))
        ));
    }

    #[test]
    fn unresolved_commit_cannot_be_retried() {
        let chain = seeded_chain(ConsentKind::Approval);
        let mut state = DisclosureReleaseState::default();
        let first_id = Uuid::from_u128(30);
        let first = permit(&chain, first_id, None);
        let first_expected = expected(&first);
        state
            .commit_permit_transactional(
                &chain,
                first,
                &first_expected,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();

        let retry = permit(&chain, Uuid::from_u128(31), Some(first_id));
        let retry_expected = expected(&retry);
        let result = state.commit_permit_transactional(
            &chain,
            retry,
            &retry_expected,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(
            result,
            Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::RetryOfUnresolvedRelease
            ))
        ));
    }

    #[test]
    fn aborted_release_can_be_explicitly_retried() {
        let chain = seeded_chain(ConsentKind::Approval);
        let mut state = DisclosureReleaseState::default();
        let first_id = Uuid::from_u128(30);
        let first = permit(&chain, first_id, None);
        let first_expected = expected(&first);
        state
            .commit_permit_transactional(
                &chain,
                first,
                &first_expected,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        state
            .record_outcome_transactional(
                &chain,
                first_id,
                DisclosureReleaseOutcome::Aborted,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();

        let retry = permit(&chain, Uuid::from_u128(31), Some(first_id));
        let retry_expected = expected(&retry);
        state
            .commit_permit_transactional(
                &chain,
                retry,
                &retry_expected,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        assert_eq!(state.entries().len(), 3);
    }

    #[test]
    fn completed_release_cannot_be_retried() {
        let chain = seeded_chain(ConsentKind::Approval);
        let mut state = DisclosureReleaseState::default();
        let first_id = Uuid::from_u128(30);
        let first = permit(&chain, first_id, None);
        let first_expected = expected(&first);
        state
            .commit_permit_transactional(
                &chain,
                first,
                &first_expected,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        state
            .record_outcome_transactional(
                &chain,
                first_id,
                DisclosureReleaseOutcome::Completed,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();

        let retry = permit(&chain, Uuid::from_u128(31), Some(first_id));
        let retry_expected = expected(&retry);
        let result = state.commit_permit_transactional(
            &chain,
            retry,
            &retry_expected,
            CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(
            result,
            Err(TransactionalDisclosureError::Protocol(
                AccountabilityDisclosureError::RetryOfCompletedRelease
            ))
        ));
    }

    #[test]
    fn release_journal_verifies_offline_and_rejects_tamper() {
        let chain = seeded_chain(ConsentKind::Approval);
        let mut state = DisclosureReleaseState::default();
        let release_id = Uuid::from_u128(30);
        let permit = permit(&chain, release_id, None);
        let expectation = expected(&permit);
        state
            .commit_permit_transactional(
                &chain,
                permit,
                &expectation,
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        state
            .record_outcome_transactional(
                &chain,
                release_id,
                DisclosureReleaseOutcome::Partial { bytes_released: 7 },
                |_| Ok::<_, ()>(()),
            )
            .unwrap();

        verify_disclosure_release_entries(
            state.entries(),
            chain.signing_key.verifying_key().as_bytes(),
        )
        .unwrap();

        let mut entries = state.into_entries();
        entries[0].entry_hash = [99u8; 32];
        assert!(verify_disclosure_release_entries(
            &entries,
            chain.signing_key.verifying_key().as_bytes()
        )
        .is_err());
    }
}
