// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Additive profile-bound disclosure authority for high-assurance SIF releases.
//!
//! Historical disclosure-v2 permits/journals remain valid historical artifacts. This
//! module defines a separate profile-required lane whose signed permit and durable
//! release Commit both bind the exact upstream-authorized SIF profile. Output adapters
//! must consume the move-only committed capability and compare that profile with the
//! authenticated negotiated profile before constructing any protected Offer.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::binding::SessionTranscriptBinding;
use crate::chain::Chain;
use crate::disclosure_v2::DisclosureReleaseOutcome;
use crate::entry::{ConsentKind, LedgerEntry, TranscriptBindingError};
use crate::policy::EvidenceCryptoManifest;
use crate::release_credential_v2::ProfileBoundExecutionReleaseCredential;
use crate::signature::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend, EvidenceSignatureBackendError,
    SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
};

/// Stable profile-bound disclosure statement schema.
pub const PROFILE_BOUND_DISCLOSURE_BINDING_SCHEMA: &str =
    "xenia-accountability-profile-disclosure-binding-v1";
/// Stable signed profile-bound permit schema.
pub const PROFILE_BOUND_DISCLOSURE_PERMIT_SCHEMA: &str =
    "xenia-accountability-profile-disclosure-permit-v1";
/// Stable signed profile-bound release-journal entry schema.
pub const PROFILE_BOUND_RELEASE_ENTRY_SCHEMA: &str =
    "xenia-accountability-profile-release-entry-v1";
/// Commitment algorithm for this additive profile.
pub const PROFILE_BOUND_DISCLOSURE_COMMITMENT_ALGORITHM: &str = "blake3-256";

const PROFILE_DISCLOSURE_DOMAIN: &[u8] = b"xenia:accountability-profile-disclosure:v1";
const PROFILE_PERMIT_DIGEST_DOMAIN: &[u8] =
    b"xenia:accountability-profile-disclosure-permit-digest:v1";
const PROFILE_RELEASE_ENTRY_DOMAIN: &[u8] = b"xenia:accountability-profile-release-entry:v1";

/// Canonical signed authorization for one exact profile-required release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileBoundDisclosureBinding {
    schema: String,
    commitment_algorithm: String,
    release_id: Uuid,
    retry_of: Option<Uuid>,
    credential_id: [u8; 32],
    required_sif_profile_digest: [u8; 32],
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
}

impl ProfileBoundDisclosureBinding {
    /// Single-use release identifier.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Explicit retry parent, when present.
    pub const fn retry_of(&self) -> Option<Uuid> {
        self.retry_of
    }

    /// Upstream profile-bound credential identifier.
    pub const fn credential_id(&self) -> [u8; 32] {
        self.credential_id
    }

    /// Exact SIF profile required by upstream authorization.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.required_sif_profile_digest
    }

    /// Authenticated Xenia session identifier.
    pub const fn session_id(&self) -> Uuid {
        self.session.session_id
    }

    /// Minimum-necessary output result, when one exists.
    pub const fn result_digest(&self) -> Option<[u8; 32]> {
        self.result_digest
    }

    /// Final witnessed Mycelix evidence-bundle commitment.
    pub const fn evidence_bundle_digest(&self) -> [u8; 32] {
        self.evidence_bundle_digest
    }

    /// Validate shape and nested authenticated-session binding.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), ProfileBoundDisclosureError> {
        if self.schema != PROFILE_BOUND_DISCLOSURE_BINDING_SCHEMA {
            return Err(ProfileBoundDisclosureError::UnsupportedBindingSchema);
        }
        if self.commitment_algorithm != PROFILE_BOUND_DISCLOSURE_COMMITMENT_ALGORITHM {
            return Err(ProfileBoundDisclosureError::UnsupportedCommitmentAlgorithm);
        }
        if self.release_id.is_nil() {
            return Err(ProfileBoundDisclosureError::NilReleaseId);
        }
        if self.operation_id.is_nil() {
            return Err(ProfileBoundDisclosureError::NilOperationId);
        }
        if self.retry_of == Some(self.release_id) {
            return Err(ProfileBoundDisclosureError::SelfRetry);
        }
        for (field, digest) in [
            ("credential_id", self.credential_id),
            (
                "required_sif_profile_digest",
                self.required_sif_profile_digest,
            ),
            ("requester_source_id", self.requester_source_id),
            ("receipt_digest", self.receipt_digest),
            ("evidence_bundle_digest", self.evidence_bundle_digest),
            ("execution_binding_digest", self.execution_binding_digest),
            ("authorization_entry_hash", self.authorization_entry_hash),
            ("permit_ledger_head_hash", self.permit_ledger_head_hash),
        ] {
            require_nonzero(field, &digest)?;
        }
        if self.result_digest == Some([0u8; 32]) {
            return Err(ProfileBoundDisclosureError::ZeroCommitment {
                field: "result_digest",
            });
        }
        if self.authorization_entry_count == 0 || self.permit_ledger_entry_count == 0 {
            return Err(ProfileBoundDisclosureError::EmptyLedgerAnchor);
        }
        if self.authorization_entry_count > self.permit_ledger_entry_count {
            return Err(ProfileBoundDisclosureError::AuthorizationAfterPermitFrontier);
        }
        self.session.validate_against_manifest(manifest)?;
        Ok(())
    }
}

/// Signed permit. This is still not output authority until durably committed.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileBoundDisclosurePermit {
    schema: String,
    binding: ProfileBoundDisclosureBinding,
    signature: SignatureEnvelope,
}

impl ProfileBoundDisclosurePermit {
    /// Signed profile-required binding.
    pub fn binding(&self) -> &ProfileBoundDisclosureBinding {
        &self.binding
    }

    /// Verify schema, binding and Ed25519 ledger-authority signature.
    pub fn verify(
        &self,
        manifest: EvidenceCryptoManifest,
        ledger_public_key: &[u8],
    ) -> Result<(), ProfileBoundDisclosureError> {
        if self.schema != PROFILE_BOUND_DISCLOSURE_PERMIT_SCHEMA {
            return Err(ProfileBoundDisclosureError::UnsupportedPermitSchema);
        }
        self.binding.validate_against_manifest(manifest)?;
        let suite = self.signature.validate_shape()?;
        if suite != SignatureSuite::Ed25519Rfc8032 {
            return Err(ProfileBoundDisclosureError::UnsupportedSignatureSuite { suite });
        }
        Ed25519EvidenceSignatureBackend.verify_signature(
            ledger_public_key,
            &profile_bound_disclosure_message(&self.binding),
            &self.signature.signature,
        )?;
        Ok(())
    }
}

/// Exact canonical bytes signed by the profile-bound disclosure authority.
pub fn profile_bound_disclosure_message(binding: &ProfileBoundDisclosureBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(480);
    out.extend_from_slice(PROFILE_DISCLOSURE_DOMAIN);
    out.push(0);
    out.extend_from_slice(PROFILE_BOUND_DISCLOSURE_BINDING_SCHEMA.as_bytes());
    out.push(0);
    out.extend_from_slice(PROFILE_BOUND_DISCLOSURE_COMMITMENT_ALGORITHM.as_bytes());
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
    out.extend_from_slice(&binding.required_sif_profile_digest);
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
    out
}

/// Stable identifier for the complete signed permit artifact.
pub fn profile_bound_disclosure_permit_digest(
    permit: &ProfileBoundDisclosurePermit,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROFILE_PERMIT_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&profile_bound_disclosure_message(&permit.binding));
    hasher.update(&[0]);
    hasher.update(permit.signature.algorithm.as_bytes());
    hasher.update(&(permit.signature.signature.len() as u64).to_be_bytes());
    hasher.update(&permit.signature.signature);
    *hasher.finalize().as_bytes()
}

impl Chain {
    /// Prepare an additive profile-bound release permit from a verified v2 credential.
    ///
    /// The exact resident Approval that anchored execution must still be the latest
    /// event for this authenticated session/requester. Any later consent transition,
    /// including another Approval, requires fresh execution and release authority.
    pub fn prepare_profile_bound_disclosure(
        &self,
        credential: &ProfileBoundExecutionReleaseCredential,
        release_id: Uuid,
        retry_of: Option<Uuid>,
        manifest: EvidenceCryptoManifest,
    ) -> Result<ProfileBoundDisclosurePermit, ProfileBoundDisclosureError> {
        let anchor = resident_authorization_anchor(
            self,
            credential.ledger_entry_count(),
            credential.ledger_head_hash(),
            credential.session().session_id,
            credential.requester_source_id(),
        )
        .ok_or(ProfileBoundDisclosureError::ExecutionAuthorizationNotResident)?;
        if anchor.event.kind != ConsentKind::Approval {
            return Err(ProfileBoundDisclosureError::ExecutionAnchorNotApproved);
        }
        require_authorization_continuity(
            self,
            credential.session().session_id,
            credential.requester_source_id(),
            credential.ledger_head_hash(),
        )?;

        let binding = ProfileBoundDisclosureBinding {
            schema: PROFILE_BOUND_DISCLOSURE_BINDING_SCHEMA.to_string(),
            commitment_algorithm: PROFILE_BOUND_DISCLOSURE_COMMITMENT_ALGORITHM.to_string(),
            release_id,
            retry_of,
            credential_id: credential.credential_id(),
            required_sif_profile_digest: credential.required_sif_profile_digest(),
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
        };
        binding.validate_against_manifest(manifest)?;
        let signature = self
            .signing_key
            .sign(&profile_bound_disclosure_message(&binding))
            .to_bytes();
        Ok(ProfileBoundDisclosurePermit {
            schema: PROFILE_BOUND_DISCLOSURE_PERMIT_SCHEMA.to_string(),
            binding,
            signature: SignatureEnvelope::ed25519(signature),
        })
    }
}

/// Signed release-journal event for the profile-required lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileBoundReleaseEvent {
    /// Permit became durable before any protected output was allowed.
    Commit {
        /// Digest of the exact signed profile-bound permit.
        permit_digest: [u8; 32],
        /// V2 profile-bound credential lineage.
        credential_id: [u8; 32],
        /// Required profile redundantly committed for offline audit/indexing.
        required_sif_profile_digest: [u8; 32],
        /// Explicit retry parent, when present.
        retry_of: Option<Uuid>,
    },
    /// Terminal output observation.
    Outcome(DisclosureReleaseOutcome),
}

/// One signed, hash-chained profile-required release entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileBoundReleaseEntry {
    schema: String,
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    event: ProfileBoundReleaseEvent,
    entry_hash: [u8; 32],
    signature: SignatureEnvelope,
}

impl ProfileBoundReleaseEntry {
    /// Monotonic journal sequence.
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Release governed by this entry.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Signed event.
    pub fn event(&self) -> &ProfileBoundReleaseEvent {
        &self.event
    }

    /// Domain-separated signed entry hash.
    pub const fn entry_hash(&self) -> [u8; 32] {
        self.entry_hash
    }
}

/// Move-only capability proving a profile-required release was durably committed.
#[derive(Debug, PartialEq, Eq)]
pub struct ProfileBoundCommittedDisclosurePermit {
    release_id: Uuid,
    credential_id: [u8; 32],
    required_sif_profile_digest: [u8; 32],
    operation_id: Uuid,
    session_id: Uuid,
    result_digest: Option<[u8; 32]>,
    evidence_bundle_digest: [u8; 32],
    release_entry_hash: [u8; 32],
}

impl ProfileBoundCommittedDisclosurePermit {
    /// Single-use release identifier.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Profile-bound credential lineage.
    pub const fn credential_id(&self) -> [u8; 32] {
        self.credential_id
    }

    /// Exact profile required by the signed upstream authorization and durable Commit.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.required_sif_profile_digest
    }

    /// Bound logical Xenia operation.
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Bound authenticated Xenia session.
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Minimum-necessary result commitment.
    pub const fn result_digest(&self) -> Option<[u8; 32]> {
        self.result_digest
    }

    /// Final witnessed evidence bundle.
    pub const fn evidence_bundle_digest(&self) -> [u8; 32] {
        self.evidence_bundle_digest
    }

    /// Signed durable release-Commit entry hash.
    pub const fn release_entry_hash(&self) -> [u8; 32] {
        self.release_entry_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseLifecycle {
    Committed,
    Terminal(DisclosureReleaseOutcome),
}

#[derive(Debug, Clone, Copy)]
struct ReleaseRecord {
    credential_id: [u8; 32],
    required_sif_profile_digest: [u8; 32],
    lifecycle: ReleaseLifecycle,
}

#[derive(Debug, Default)]
struct ReleaseIndex {
    records: BTreeMap<Uuid, ReleaseRecord>,
    credential_roots: BTreeMap<[u8; 32], Uuid>,
    retried_parents: BTreeSet<Uuid>,
}

/// Raw verified profile-bound release state. Public mutation is exposed through CAS.
#[derive(Debug, Default)]
struct RawProfileBoundReleaseState {
    entries: Vec<ProfileBoundReleaseEntry>,
}

impl RawProfileBoundReleaseState {
    fn from_verified_entries(
        entries: Vec<ProfileBoundReleaseEntry>,
        ledger_public_key: &[u8],
    ) -> Result<Self, ProfileBoundDisclosureError> {
        verify_profile_bound_release_entries(&entries, ledger_public_key)?;
        Ok(Self { entries })
    }

    fn entries(&self) -> &[ProfileBoundReleaseEntry] {
        &self.entries
    }

    fn commit_permit_transactional<E>(
        &mut self,
        chain: &Chain,
        permit: ProfileBoundDisclosurePermit,
        manifest: EvidenceCryptoManifest,
        persist: impl FnOnce(&[ProfileBoundReleaseEntry]) -> Result<(), E>,
    ) -> Result<ProfileBoundCommittedDisclosurePermit, ProfileTransactionalDisclosureError<E>> {
        permit
            .verify(manifest, chain.signing_key.verifying_key().as_bytes())
            .map_err(ProfileTransactionalDisclosureError::Protocol)?;
        if !chain_contains_frontier(
            chain,
            permit.binding.permit_ledger_entry_count,
            permit.binding.permit_ledger_head_hash,
        ) {
            return Err(ProfileTransactionalDisclosureError::Protocol(
                ProfileBoundDisclosureError::PermitLedgerNotAncestor,
            ));
        }
        require_authorization_continuity(
            chain,
            permit.binding.session.session_id,
            permit.binding.requester_source_id,
            permit.binding.authorization_entry_hash,
        )
        .map_err(ProfileTransactionalDisclosureError::Protocol)?;
        let index = build_release_index(&self.entries)
            .map_err(ProfileTransactionalDisclosureError::Protocol)?;
        validate_lineage_commit(
            &index,
            permit.binding.release_id,
            permit.binding.credential_id,
            permit.binding.required_sif_profile_digest,
            permit.binding.retry_of,
        )
        .map_err(ProfileTransactionalDisclosureError::Protocol)?;

        let event = ProfileBoundReleaseEvent::Commit {
            permit_digest: profile_bound_disclosure_permit_digest(&permit),
            credential_id: permit.binding.credential_id,
            required_sif_profile_digest: permit.binding.required_sif_profile_digest,
            retry_of: permit.binding.retry_of,
        };
        let entry = build_release_entry(
            &chain.signing_key,
            self.entries.len() as u64,
            self.entries
                .last()
                .map(ProfileBoundReleaseEntry::entry_hash)
                .unwrap_or([0u8; 32]),
            permit.binding.release_id,
            event,
        );
        self.entries.push(entry);
        if let Err(error) = persist(&self.entries) {
            self.entries.pop();
            return Err(ProfileTransactionalDisclosureError::Persist(error));
        }
        let release_entry_hash = self
            .entries
            .last()
            .ok_or(ProfileTransactionalDisclosureError::Protocol(
                ProfileBoundDisclosureError::ReleaseAppendInvariant,
            ))?
            .entry_hash;
        Ok(ProfileBoundCommittedDisclosurePermit {
            release_id: permit.binding.release_id,
            credential_id: permit.binding.credential_id,
            required_sif_profile_digest: permit.binding.required_sif_profile_digest,
            operation_id: permit.binding.operation_id,
            session_id: permit.binding.session.session_id,
            result_digest: permit.binding.result_digest,
            evidence_bundle_digest: permit.binding.evidence_bundle_digest,
            release_entry_hash,
        })
    }

    fn record_outcome_transactional<E>(
        &mut self,
        chain: &Chain,
        release_id: Uuid,
        outcome: DisclosureReleaseOutcome,
        persist: impl FnOnce(&[ProfileBoundReleaseEntry]) -> Result<(), E>,
    ) -> Result<(), ProfileTransactionalDisclosureError<E>> {
        let index = build_release_index(&self.entries)
            .map_err(ProfileTransactionalDisclosureError::Protocol)?;
        match index.records.get(&release_id).map(|record| record.lifecycle) {
            None => {
                return Err(ProfileTransactionalDisclosureError::Protocol(
                    ProfileBoundDisclosureError::OutcomeWithoutCommit,
                ));
            }
            Some(ReleaseLifecycle::Terminal(_)) => {
                return Err(ProfileTransactionalDisclosureError::Protocol(
                    ProfileBoundDisclosureError::DuplicateOutcome,
                ));
            }
            Some(ReleaseLifecycle::Committed) => {}
        }
        validate_outcome(outcome).map_err(ProfileTransactionalDisclosureError::Protocol)?;
        let entry = build_release_entry(
            &chain.signing_key,
            self.entries.len() as u64,
            self.entries
                .last()
                .map(ProfileBoundReleaseEntry::entry_hash)
                .unwrap_or([0u8; 32]),
            release_id,
            ProfileBoundReleaseEvent::Outcome(outcome),
        );
        self.entries.push(entry);
        if let Err(error) = persist(&self.entries) {
            self.entries.pop();
            return Err(ProfileTransactionalDisclosureError::Persist(error));
        }
        Ok(())
    }
}

/// Durable signed-journal frontier used as a compare-and-swap token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileBoundReleaseFrontier {
    /// Number of durable signed entries.
    pub entry_count: u64,
    /// Last signed entry hash, or all-zero for an empty journal.
    pub head_hash: [u8; 32],
}

impl ProfileBoundReleaseFrontier {
    /// Empty-journal frontier.
    pub const GENESIS: Self = Self {
        entry_count: 0,
        head_hash: [0u8; 32],
    };
}

/// Atomic persistence contract for profile-bound release transitions.
pub trait ProfileBoundReleaseStore {
    /// Store-specific failure.
    type Error;

    /// Persist `next_entries` only if durable state still equals `expected`.
    fn compare_and_swap(
        &mut self,
        expected: ProfileBoundReleaseFrontier,
        next_entries: &[ProfileBoundReleaseEntry],
    ) -> Result<(), Self::Error>;
}

/// Public profile-bound release state whose mutation always requires CAS persistence.
#[derive(Debug, Default)]
pub struct ProfileBoundReleaseState {
    inner: RawProfileBoundReleaseState,
}

impl ProfileBoundReleaseState {
    /// Verify and rehydrate persisted entries before permitting mutation.
    pub fn from_verified_entries(
        entries: Vec<ProfileBoundReleaseEntry>,
        ledger_public_key: &[u8],
    ) -> Result<Self, ProfileBoundDisclosureError> {
        Ok(Self {
            inner: RawProfileBoundReleaseState::from_verified_entries(
                entries,
                ledger_public_key,
            )?,
        })
    }

    /// Current signed-journal frontier.
    pub fn frontier(&self) -> ProfileBoundReleaseFrontier {
        ProfileBoundReleaseFrontier {
            entry_count: self.inner.entries.len() as u64,
            head_hash: self
                .inner
                .entries
                .last()
                .map(ProfileBoundReleaseEntry::entry_hash)
                .unwrap_or([0u8; 32]),
        }
    }

    /// Signed entries for persistence/audit.
    pub fn entries(&self) -> &[ProfileBoundReleaseEntry] {
        self.inner.entries()
    }

    /// Commit a signed permit only through atomic compare-and-swap persistence.
    pub fn commit_permit<S: ProfileBoundReleaseStore>(
        &mut self,
        chain: &Chain,
        permit: ProfileBoundDisclosurePermit,
        manifest: EvidenceCryptoManifest,
        store: &mut S,
    ) -> Result<
        ProfileBoundCommittedDisclosurePermit,
        ProfileTransactionalDisclosureError<S::Error>,
    > {
        let expected = self.frontier();
        self.inner
            .commit_permit_transactional(chain, permit, manifest, |next_entries| {
                store.compare_and_swap(expected, next_entries)
            })
    }

    /// Record one terminal outcome only through atomic compare-and-swap persistence.
    pub fn record_outcome<S: ProfileBoundReleaseStore>(
        &mut self,
        chain: &Chain,
        release_id: Uuid,
        outcome: DisclosureReleaseOutcome,
        store: &mut S,
    ) -> Result<(), ProfileTransactionalDisclosureError<S::Error>> {
        let expected = self.frontier();
        self.inner.record_outcome_transactional(
            chain,
            release_id,
            outcome,
            |next_entries| store.compare_and_swap(expected, next_entries),
        )
    }
}

/// Protocol/persistence failure while advancing profile-bound release state.
#[derive(Debug)]
pub enum ProfileTransactionalDisclosureError<E> {
    /// Protocol, authorization, signature or lifecycle validation failed.
    Protocol(ProfileBoundDisclosureError),
    /// Atomic durable persistence failed; in-memory append was rolled back.
    Persist(E),
}

/// Verify a persisted profile-bound release journal offline.
pub fn verify_profile_bound_release_entries(
    entries: &[ProfileBoundReleaseEntry],
    ledger_public_key: &[u8],
) -> Result<(), ProfileBoundDisclosureError> {
    let backend = Ed25519EvidenceSignatureBackend;
    let mut previous = [0u8; 32];
    let mut index = ReleaseIndex::default();
    for (position, entry) in entries.iter().enumerate() {
        if entry.schema != PROFILE_BOUND_RELEASE_ENTRY_SCHEMA {
            return Err(ProfileBoundDisclosureError::UnsupportedReleaseEntrySchema);
        }
        if entry.seq != position as u64 || entry.prev_hash != previous {
            return Err(ProfileBoundDisclosureError::ReleaseJournalChainMismatch);
        }
        let expected = release_entry_hash(
            entry.seq,
            entry.prev_hash,
            entry.release_id,
            &entry.event,
        );
        if entry.entry_hash != expected {
            return Err(ProfileBoundDisclosureError::ReleaseJournalHashMismatch);
        }
        let suite = entry.signature.validate_shape()?;
        if suite != SignatureSuite::Ed25519Rfc8032 {
            return Err(ProfileBoundDisclosureError::UnsupportedSignatureSuite { suite });
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

fn build_release_index(
    entries: &[ProfileBoundReleaseEntry],
) -> Result<ReleaseIndex, ProfileBoundDisclosureError> {
    let mut index = ReleaseIndex::default();
    for entry in entries {
        apply_entry_to_index(&mut index, entry)?;
    }
    Ok(index)
}

fn apply_entry_to_index(
    index: &mut ReleaseIndex,
    entry: &ProfileBoundReleaseEntry,
) -> Result<(), ProfileBoundDisclosureError> {
    match &entry.event {
        ProfileBoundReleaseEvent::Commit {
            permit_digest,
            credential_id,
            required_sif_profile_digest,
            retry_of,
        } => {
            require_nonzero("permit_digest", permit_digest)?;
            require_nonzero("credential_id", credential_id)?;
            require_nonzero("required_sif_profile_digest", required_sif_profile_digest)?;
            validate_lineage_commit(
                index,
                entry.release_id,
                *credential_id,
                *required_sif_profile_digest,
                *retry_of,
            )?;
            if let Some(parent) = retry_of {
                index.retried_parents.insert(*parent);
            } else {
                index.credential_roots.insert(*credential_id, entry.release_id);
            }
            index.records.insert(
                entry.release_id,
                ReleaseRecord {
                    credential_id: *credential_id,
                    required_sif_profile_digest: *required_sif_profile_digest,
                    lifecycle: ReleaseLifecycle::Committed,
                },
            );
        }
        ProfileBoundReleaseEvent::Outcome(outcome) => {
            validate_outcome(*outcome)?;
            let record = index
                .records
                .get_mut(&entry.release_id)
                .ok_or(ProfileBoundDisclosureError::OutcomeWithoutCommit)?;
            if matches!(record.lifecycle, ReleaseLifecycle::Terminal(_)) {
                return Err(ProfileBoundDisclosureError::DuplicateOutcome);
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
    required_sif_profile_digest: [u8; 32],
    retry_of: Option<Uuid>,
) -> Result<(), ProfileBoundDisclosureError> {
    if index.records.contains_key(&release_id) {
        return Err(ProfileBoundDisclosureError::ReleaseIdAlreadyUsed);
    }
    match retry_of {
        None => {
            if index.credential_roots.contains_key(&credential_id) {
                return Err(ProfileBoundDisclosureError::CredentialAlreadyHasLineage);
            }
            Ok(())
        }
        Some(parent) => {
            if index.retried_parents.contains(&parent) {
                return Err(ProfileBoundDisclosureError::RetryWouldForkLineage);
            }
            let parent_record = index
                .records
                .get(&parent)
                .ok_or(ProfileBoundDisclosureError::RetryTargetMissing)?;
            if parent_record.credential_id != credential_id {
                return Err(ProfileBoundDisclosureError::RetryCredentialMismatch);
            }
            if parent_record.required_sif_profile_digest != required_sif_profile_digest {
                return Err(ProfileBoundDisclosureError::RetryProfileMismatch);
            }
            match parent_record.lifecycle {
                ReleaseLifecycle::Committed => {
                    Err(ProfileBoundDisclosureError::RetryOfUnresolvedRelease)
                }
                ReleaseLifecycle::Terminal(DisclosureReleaseOutcome::Completed) => {
                    Err(ProfileBoundDisclosureError::RetryOfCompletedRelease)
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
) -> Result<(), ProfileBoundDisclosureError> {
    let latest = chain
        .iter()
        .filter(|entry| {
            entry.event.session_id == session_id && entry.event.source_id == requester_source_id
        })
        .last()
        .ok_or(ProfileBoundDisclosureError::CurrentAuthorizationNotResident)?;
    if latest.entry_hash != authorization_entry_hash || latest.event.kind != ConsentKind::Approval {
        return Err(ProfileBoundDisclosureError::AuthorizationChangedAfterExecution);
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

fn validate_outcome(outcome: DisclosureReleaseOutcome) -> Result<(), ProfileBoundDisclosureError> {
    if matches!(
        outcome,
        DisclosureReleaseOutcome::Partial { bytes_released: 0 }
    ) {
        return Err(ProfileBoundDisclosureError::ZeroPartialRelease);
    }
    Ok(())
}

fn build_release_entry(
    signing_key: &SigningKey,
    seq: u64,
    prev_hash: [u8; 32],
    release_id: Uuid,
    event: ProfileBoundReleaseEvent,
) -> ProfileBoundReleaseEntry {
    let entry_hash = release_entry_hash(seq, prev_hash, release_id, &event);
    let signature = signing_key.sign(&entry_hash).to_bytes();
    ProfileBoundReleaseEntry {
        schema: PROFILE_BOUND_RELEASE_ENTRY_SCHEMA.to_string(),
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
    event: &ProfileBoundReleaseEvent,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROFILE_RELEASE_ENTRY_DOMAIN);
    hasher.update(&[0]);
    hasher.update(PROFILE_BOUND_RELEASE_ENTRY_SCHEMA.as_bytes());
    hasher.update(&[0]);
    hasher.update(&seq.to_be_bytes());
    hasher.update(&prev_hash);
    hasher.update(release_id.as_bytes());
    match event {
        ProfileBoundReleaseEvent::Commit {
            permit_digest,
            credential_id,
            required_sif_profile_digest,
            retry_of,
        } => {
            hasher.update(&[0]);
            hasher.update(permit_digest);
            hasher.update(credential_id);
            hasher.update(required_sif_profile_digest);
            match retry_of {
                Some(id) => {
                    hasher.update(&[1]);
                    hasher.update(id.as_bytes());
                }
                None => hasher.update(&[0]),
            }
        }
        ProfileBoundReleaseEvent::Outcome(DisclosureReleaseOutcome::Completed) => {
            hasher.update(&[1, 0]);
        }
        ProfileBoundReleaseEvent::Outcome(DisclosureReleaseOutcome::Aborted) => {
            hasher.update(&[1, 1]);
        }
        ProfileBoundReleaseEvent::Outcome(DisclosureReleaseOutcome::Partial {
            bytes_released,
        }) => {
            hasher.update(&[1, 2]);
            hasher.update(&bytes_released.to_be_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

fn require_nonzero(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), ProfileBoundDisclosureError> {
    if *digest == [0u8; 32] {
        return Err(ProfileBoundDisclosureError::ZeroCommitment { field });
    }
    Ok(())
}

/// Fail-closed profile-bound disclosure failures.
#[derive(Debug, Error)]
pub enum ProfileBoundDisclosureError {
    /// Nested authenticated-session validation failed.
    #[error(transparent)]
    TranscriptBinding(#[from] TranscriptBindingError),
    /// Signature envelope was malformed.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Signature verification failed.
    #[error(transparent)]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
    /// Binding schema mismatch.
    #[error("unsupported profile-bound disclosure binding schema")]
    UnsupportedBindingSchema,
    /// Permit schema mismatch.
    #[error("unsupported profile-bound disclosure permit schema")]
    UnsupportedPermitSchema,
    /// Release-entry schema mismatch.
    #[error("unsupported profile-bound release entry schema")]
    UnsupportedReleaseEntrySchema,
    /// Commitment algorithm mismatch.
    #[error("unsupported profile-bound disclosure commitment algorithm")]
    UnsupportedCommitmentAlgorithm,
    /// Signature suite mismatch.
    #[error("unsupported profile-bound disclosure signature suite: {suite:?}")]
    UnsupportedSignatureSuite {
        /// Signature suite carried by the rejected artifact.
        suite: SignatureSuite,
    },
    /// Nil release identifier.
    #[error("profile-bound release ID must not be nil")]
    NilReleaseId,
    /// Nil operation identifier.
    #[error("profile-bound operation ID must not be nil")]
    NilOperationId,
    /// Release cannot retry itself.
    #[error("profile-bound release cannot retry itself")]
    SelfRetry,
    /// Required commitment used an all-zero placeholder.
    #[error("profile-bound disclosure commitment {field} must not be all-zero")]
    ZeroCommitment {
        /// Invalid commitment field.
        field: &'static str,
    },
    /// Ledger anchor count/hash is empty.
    #[error("profile-bound disclosure requires non-empty ledger anchors")]
    EmptyLedgerAnchor,
    /// Execution anchor occurs after permit-preparation frontier.
    #[error("profile-bound execution anchor occurs after permit frontier")]
    AuthorizationAfterPermitFrontier,
    /// Execution authorization anchor is no longer resident.
    #[error("profile-bound execution authorization is not resident")]
    ExecutionAuthorizationNotResident,
    /// Execution anchor was not an Approval.
    #[error("profile-bound execution anchor is not approved")]
    ExecutionAnchorNotApproved,
    /// Permit ledger frontier is not an ancestor of current chain state.
    #[error("profile-bound permit ledger frontier is not an ancestor")]
    PermitLedgerNotAncestor,
    /// No current resident authorization exists.
    #[error("current profile-bound authorization is not resident")]
    CurrentAuthorizationNotResident,
    /// Consent changed after execution binding.
    #[error("profile-bound authorization changed after execution")]
    AuthorizationChangedAfterExecution,
    /// Release ID was already used.
    #[error("profile-bound release ID already used")]
    ReleaseIdAlreadyUsed,
    /// Credential already owns an initial release lineage.
    #[error("profile-bound credential already has a release lineage")]
    CredentialAlreadyHasLineage,
    /// Retry target does not exist.
    #[error("profile-bound retry target missing")]
    RetryTargetMissing,
    /// Retry uses a different credential.
    #[error("profile-bound retry credential mismatch")]
    RetryCredentialMismatch,
    /// Retry attempts to change the authorized SIF profile.
    #[error("profile-bound retry SIF profile mismatch")]
    RetryProfileMismatch,
    /// Retry would branch an already-retried parent.
    #[error("profile-bound retry would fork release lineage")]
    RetryWouldForkLineage,
    /// Retry targets unresolved release.
    #[error("profile-bound retry targets unresolved release")]
    RetryOfUnresolvedRelease,
    /// Completed release cannot be retried.
    #[error("profile-bound completed release cannot be retried")]
    RetryOfCompletedRelease,
    /// Terminal outcome has no matching Commit.
    #[error("profile-bound outcome has no matching Commit")]
    OutcomeWithoutCommit,
    /// Release already has terminal outcome.
    #[error("profile-bound release already has terminal outcome")]
    DuplicateOutcome,
    /// Partial with zero bytes is invalid; use Aborted.
    #[error("profile-bound Partial outcome must contain nonzero bytes")]
    ZeroPartialRelease,
    /// Append succeeded in memory but resulting entry was unexpectedly absent.
    #[error("profile-bound release append invariant failed")]
    ReleaseAppendInvariant,
    /// Persisted release hash chain is invalid.
    #[error("profile-bound release journal chain mismatch")]
    ReleaseJournalChainMismatch,
    /// Persisted entry hash is invalid.
    #[error("profile-bound release journal hash mismatch")]
    ReleaseJournalHashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_bound_release_state_has_genesis_frontier() {
        assert_eq!(
            ProfileBoundReleaseState::default().frontier(),
            ProfileBoundReleaseFrontier::GENESIS
        );
    }

    #[test]
    fn profile_changes_release_commit_hash() {
        let event_p1 = ProfileBoundReleaseEvent::Commit {
            permit_digest: [1u8; 32],
            credential_id: [2u8; 32],
            required_sif_profile_digest: [3u8; 32],
            retry_of: None,
        };
        let event_p2 = ProfileBoundReleaseEvent::Commit {
            required_sif_profile_digest: [4u8; 32],
            ..event_p1.clone()
        };
        let release_id = Uuid::from_u128(1);
        assert_ne!(
            release_entry_hash(0, [0u8; 32], release_id, &event_p1),
            release_entry_hash(0, [0u8; 32], release_id, &event_p2)
        );
    }
}
