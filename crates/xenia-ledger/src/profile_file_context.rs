// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime context retained beside one profile-bound committed file authority.
//!
//! Historical signed permit/release schemas already bind the complete authenticated
//! session, requester identity and authorization anchor. The earlier move-only runtime
//! capability intentionally projected that down to only the fields needed by its first
//! consumer. High-assurance live sending needs more: exact transcript-generation
//! equality, the release-ledger verifier key, and the signed consent anchor required to
//! notice a later Revocation before another Chunk is emitted.
//!
//! This module adds those runtime facts **without changing any canonical signed or wire
//! artifact**. [`commit_context_bound_file_authority`] captures the complete execution
//! context before the signed permit is consumed, performs all fallible file/profile Offer
//! preflight before the durable Commit where possible, commits through the existing CAS
//! release state, then returns [`ContextBoundFileOfferAuthority`].

use uuid::Uuid;

use crate::binding::SessionTranscriptBinding;
use crate::chain::Chain;
use crate::disclosure_v2::DisclosureReleaseOutcome;
use crate::entry::ConsentKind;
use crate::file_disclosure::{FileDisclosureError, sif_file_result_digest};
use crate::policy::EvidenceCryptoManifest;
use crate::profile_disclosure::{
    ProfileBoundDisclosureError, ProfileBoundReleaseState, ProfileBoundReleaseStore,
    ProfileTransactionalDisclosureError,
};
use crate::profile_file_disclosure::{
    ProfileBoundCommittedFileDisclosure, ProfileBoundFileDisclosureError,
    ProfileBoundFileOfferAuthority,
};
use crate::protected_file_protocol::SifProtectedFileOffer;
use crate::release_credential_v2::ProfileBoundExecutionReleaseCredential;

/// Exact runtime authorization context retained beside one committed file authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedReleaseContext {
    session: SessionTranscriptBinding,
    requester_source_id: [u8; 32],
    authorization_entry_count: u64,
    authorization_entry_hash: [u8; 32],
    release_ledger_public_key: [u8; 32],
    required_sif_profile_digest: [u8; 32],
    credential_id: [u8; 32],
}

impl AuthorizedReleaseContext {
    /// Complete authenticated transcript generation that authorized this release.
    pub fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    /// Opaque requester/source identity used by the consent-ledger lookup.
    pub const fn requester_source_id(&self) -> [u8; 32] {
        self.requester_source_id
    }

    /// One-past sequence count of the exact Approval that anchored execution.
    pub const fn authorization_entry_count(&self) -> u64 {
        self.authorization_entry_count
    }

    /// Exact signed ledger-entry hash of the Approval that anchored execution.
    pub const fn authorization_entry_hash(&self) -> [u8; 32] {
        self.authorization_entry_hash
    }

    /// Ed25519 verifier key of the release/consent ledger that minted this authority.
    pub const fn release_ledger_public_key(&self) -> [u8; 32] {
        self.release_ledger_public_key
    }

    /// Exact protected-transfer profile required by upstream authorization.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.required_sif_profile_digest
    }

    /// Profile-bound upstream credential lineage.
    pub const fn credential_id(&self) -> [u8; 32] {
        self.credential_id
    }

    /// Recheck the current resident consent state against this exact authorization anchor.
    ///
    /// A later Approval does not reactivate the old release: the exact signed anchor must
    /// still be the latest matching consent event. The supplied [`Chain`] must also be
    /// owned by the exact same ledger verifier key captured at release Commit.
    ///
    /// For an anchored/compacted chain, inability to find the matching live consent event
    /// fails closed. A future durable-generation index can relax that availability cost
    /// without weakening the exact-generation rule.
    pub fn require_current_authorization(
        &self,
        chain: &Chain,
    ) -> Result<(), CurrentReleaseAuthorizationError> {
        let current_key = chain.signing_key.verifying_key().to_bytes();
        if current_key != self.release_ledger_public_key {
            return Err(CurrentReleaseAuthorizationError::LedgerSignerMismatch);
        }

        let latest = chain
            .iter()
            .filter(|entry| {
                entry.event.session_id == self.session.session_id
                    && entry.event.source_id == self.requester_source_id
            })
            .last()
            .ok_or(CurrentReleaseAuthorizationError::AuthorizationNotResident)?;

        let count_matches = latest.seq.checked_add(1) == Some(self.authorization_entry_count);
        if !count_matches
            || latest.entry_hash != self.authorization_entry_hash
            || latest.event.kind != ConsentKind::Approval
        {
            return Err(CurrentReleaseAuthorizationError::AuthorizationGenerationChanged);
        }
        Ok(())
    }
}

/// Exact file Offer authority plus the complete runtime context needed by live output.
#[derive(Debug)]
pub struct ContextBoundFileOfferAuthority {
    inner: ProfileBoundFileOfferAuthority,
    context: AuthorizedReleaseContext,
}

impl ContextBoundFileOfferAuthority {
    /// Exact authority-derived protected Offer.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Complete runtime authorization context captured at durable Commit.
    pub fn context(&self) -> &AuthorizedReleaseContext {
        &self.context
    }

    /// Consume into the existing move-only file authority plus its required runtime context.
    ///
    /// This split exists for application-layer typestate composition. High-assurance callers
    /// must retain and enforce the context; discarding it intentionally falls back to the
    /// weaker historical runtime surface and must not be described as context-bound output.
    pub fn into_parts(self) -> (ProfileBoundFileOfferAuthority, AuthorizedReleaseContext) {
        (self.inner, self.context)
    }
}

/// Prepare, durably commit and bind one exact context-retaining file authority.
///
/// All file-result/profile/display-name/transfer-ID checks are performed before the
/// durable release Commit using the same canonical constructors. The post-Commit binding
/// is still checked defensively; if that supposedly unreachable step fails, this function
/// immediately tries to durably record `Aborted` so a failed adapter cannot strand an
/// unresolved committed lineage silently.
pub fn commit_context_bound_file_authority<S: ProfileBoundReleaseStore>(
    release_state: &mut ProfileBoundReleaseState,
    chain: &Chain,
    credential: &ProfileBoundExecutionReleaseCredential,
    release_id: Uuid,
    retry_of: Option<Uuid>,
    manifest: EvidenceCryptoManifest,
    display_name: impl Into<String>,
    size: u64,
    content_blake3: [u8; 32],
    negotiated_sif_profile_digest: [u8; 32],
    transfer_id: u64,
    store: &mut S,
) -> Result<ContextBoundFileOfferAuthority, ContextBoundFileCommitError<S::Error>> {
    let display_name = display_name.into();
    let expected_result = sif_file_result_digest(&display_name, size, content_blake3)
        .map_err(|error| ContextBoundFileCommitError::PreflightFile(error.into()))?;
    match credential.result_digest() {
        None => {
            return Err(ContextBoundFileCommitError::PreflightFile(
                FileDisclosureError::MissingResultCommitment.into(),
            ));
        }
        Some(actual) if actual != expected_result => {
            return Err(ContextBoundFileCommitError::PreflightFile(
                FileDisclosureError::ResultCommitmentMismatch.into(),
            ));
        }
        Some(_) => {}
    }
    if negotiated_sif_profile_digest == [0u8; 32] {
        return Err(ContextBoundFileCommitError::PreflightFile(
            ProfileBoundFileDisclosureError::ZeroNegotiatedProfile,
        ));
    }
    if negotiated_sif_profile_digest != credential.required_sif_profile_digest() {
        return Err(ContextBoundFileCommitError::PreflightFile(
            ProfileBoundFileDisclosureError::ProfileMismatch,
        ));
    }

    // Preflight every fallible semantic Offer field before durable Commit. The release
    // entry hash is not known yet, so a fixed non-zero placeholder exercises identical
    // validation for release/transfer/result/name/size/content fields without becoming an
    // artifact that can leave this function.
    SifProtectedFileOffer::new(
        release_id,
        transfer_id,
        [1u8; 32],
        expected_result,
        display_name.clone(),
        size,
        content_blake3,
    )
    .map_err(ProfileBoundFileDisclosureError::from)
    .map_err(ContextBoundFileCommitError::PreflightFile)?;

    let context = AuthorizedReleaseContext {
        session: credential.session().clone(),
        requester_source_id: credential.requester_source_id(),
        authorization_entry_count: credential.ledger_entry_count(),
        authorization_entry_hash: credential.ledger_head_hash(),
        release_ledger_public_key: chain.signing_key.verifying_key().to_bytes(),
        required_sif_profile_digest: credential.required_sif_profile_digest(),
        credential_id: credential.credential_id(),
    };

    let permit = chain
        .prepare_profile_bound_disclosure(credential, release_id, retry_of, manifest)
        .map_err(ContextBoundFileCommitError::Prepare)?;
    let committed = match release_state.commit_permit(chain, permit, manifest, store) {
        Ok(committed) => committed,
        Err(ProfileTransactionalDisclosureError::Protocol(error)) => {
            return Err(ContextBoundFileCommitError::CommitProtocol(error));
        }
        Err(ProfileTransactionalDisclosureError::Persist(error)) => {
            return Err(ContextBoundFileCommitError::CommitPersist(error));
        }
    };

    let file = match ProfileBoundCommittedFileDisclosure::new(
        committed,
        display_name,
        size,
        content_blake3,
    ) {
        Ok(file) => file,
        Err(binding) => {
            return Err(record_post_commit_abort(
                release_state,
                chain,
                release_id,
                binding,
                store,
            ));
        }
    };
    let inner = match file.bind_negotiated_profile(negotiated_sif_profile_digest, transfer_id) {
        Ok(authority) => authority,
        Err(binding) => {
            return Err(record_post_commit_abort(
                release_state,
                chain,
                release_id,
                binding,
                store,
            ));
        }
    };

    Ok(ContextBoundFileOfferAuthority { inner, context })
}

fn record_post_commit_abort<S: ProfileBoundReleaseStore>(
    release_state: &mut ProfileBoundReleaseState,
    chain: &Chain,
    release_id: Uuid,
    binding: ProfileBoundFileDisclosureError,
    store: &mut S,
) -> ContextBoundFileCommitError<S::Error> {
    match release_state.record_outcome(
        chain,
        release_id,
        DisclosureReleaseOutcome::Aborted,
        store,
    ) {
        Ok(()) => ContextBoundFileCommitError::PostCommitBindingAborted(binding),
        Err(ProfileTransactionalDisclosureError::Protocol(outcome)) => {
            ContextBoundFileCommitError::PostCommitBindingOutcomeProtocol { binding, outcome }
        }
        Err(ProfileTransactionalDisclosureError::Persist(store)) => {
            ContextBoundFileCommitError::PostCommitBindingOutcomePersist { binding, store }
        }
    }
}

/// Current live authorization no longer matches the exact committed release context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CurrentReleaseAuthorizationError {
    /// Caller supplied a consent ledger controlled by another verifier key.
    #[error("current release authorization ledger signer differs from the committed release signer")]
    LedgerSignerMismatch,
    /// Exact requester/session authorization state is not resident for live rechecking.
    #[error("current release authorization is not resident in the live consent ledger")]
    AuthorizationNotResident,
    /// A later consent event or different approval generation superseded the committed anchor.
    #[error("current release authorization generation changed after release Commit")]
    AuthorizationGenerationChanged,
}

/// Failure while constructing a context-retaining durable file authority.
#[derive(Debug)]
pub enum ContextBoundFileCommitError<E> {
    /// File/profile/Offer preflight failed before durable Commit.
    PreflightFile(ProfileBoundFileDisclosureError),
    /// Signed profile-bound permit preparation failed.
    Prepare(ProfileBoundDisclosureError),
    /// Durable release Commit failed protocol/authorization validation.
    CommitProtocol(ProfileBoundDisclosureError),
    /// Durable release Commit could not be atomically persisted.
    CommitPersist(E),
    /// Defensive post-Commit file binding failed and `Aborted` was persisted successfully.
    PostCommitBindingAborted(ProfileBoundFileDisclosureError),
    /// Defensive post-Commit binding failed and the attempted `Aborted` outcome was rejected.
    PostCommitBindingOutcomeProtocol {
        /// Unexpected file/Offer binding failure.
        binding: ProfileBoundFileDisclosureError,
        /// Release-journal outcome failure.
        outcome: ProfileBoundDisclosureError,
    },
    /// Defensive post-Commit binding failed and the attempted `Aborted` outcome could not persist.
    PostCommitBindingOutcomePersist {
        /// Unexpected file/Offer binding failure.
        binding: ProfileBoundFileDisclosureError,
        /// Release-store persistence failure while recording `Aborted`.
        store: E,
    },
}
