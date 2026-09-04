// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-journal signer binding for high-assurance protected-file output.
//!
//! The profile-bound release journal and the write-ahead protected-file send journal are
//! distinct evidence structures. This module proves they are administered by the same
//! Xenia ledger signer before the send journal is created, while keeping the private
//! signing key encapsulated inside [`Chain`].

use thiserror::Error;
use uuid::Uuid;

use crate::chain::Chain;
use crate::profile_disclosure::{
    ProfileBoundDisclosureError, ProfileBoundReleaseEvent, ProfileBoundReleaseState,
    verify_profile_bound_release_entries,
};
use crate::protected_file_protocol::SifProtectedFileOffer;

/// Verified evidence that one exact Offer's release Commit is signed by the current Chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedProfileReleaseSigner {
    release_id: Uuid,
    release_entry_hash: [u8; 32],
    ledger_public_key: [u8; 32],
}

impl VerifiedProfileReleaseSigner {
    /// Exact durable release governed by this signer proof.
    pub const fn release_id(&self) -> Uuid {
        self.release_id
    }

    /// Exact signed Commit entry referenced by the protected Offer.
    pub const fn release_entry_hash(&self) -> [u8; 32] {
        self.release_entry_hash
    }

    /// Ed25519 public key that verified the complete profile-release journal.
    pub const fn ledger_public_key(&self) -> [u8; 32] {
        self.ledger_public_key
    }

    /// Require that this proof still governs the same exact Offer.
    pub fn validate_offer(
        &self,
        offer: &SifProtectedFileOffer,
    ) -> Result<(), ProfileReleaseSignerError> {
        if self.release_id != offer.release_id()
            || self.release_entry_hash != offer.sender_release_entry_hash()
        {
            return Err(ProfileReleaseSignerError::OfferBindingMismatch);
        }
        Ok(())
    }
}

/// Verify that the current Chain signer owns the exact durable release Commit in `offer`.
///
/// Verification covers the complete persisted profile-bound release journal, not merely
/// the named Commit entry. The function then resolves the exact release ID to its Commit
/// and requires the Commit's signed entry hash to equal the Offer's immutable
/// `sender_release_entry_hash`.
pub fn verify_profile_release_signer_for_offer(
    chain: &Chain,
    release_state: &ProfileBoundReleaseState,
    offer: &SifProtectedFileOffer,
) -> Result<VerifiedProfileReleaseSigner, ProfileReleaseSignerError> {
    offer.validate()?;
    let ledger_public_key = chain.signing_key.verifying_key().to_bytes();
    verify_profile_bound_release_entries(release_state.entries(), &ledger_public_key)?;

    let commit = release_state
        .entries()
        .iter()
        .find(|entry| {
            entry.release_id() == offer.release_id()
                && matches!(entry.event(), ProfileBoundReleaseEvent::Commit { .. })
        })
        .ok_or(ProfileReleaseSignerError::ReleaseCommitNotFound)?;

    if commit.entry_hash() != offer.sender_release_entry_hash() {
        return Err(ProfileReleaseSignerError::ReleaseCommitHashMismatch);
    }

    Ok(VerifiedProfileReleaseSigner {
        release_id: offer.release_id(),
        release_entry_hash: commit.entry_hash(),
        ledger_public_key,
    })
}

/// Fail-closed cross-journal signer binding failures.
#[derive(Debug, Error)]
pub enum ProfileReleaseSignerError {
    /// Exact protected Offer shape is invalid.
    #[error(transparent)]
    Protocol(#[from] crate::protected_file_protocol::SifProtectedFileProtocolError),
    /// Profile release journal failed cryptographic/offline verification.
    #[error(transparent)]
    ReleaseJournal(#[from] ProfileBoundDisclosureError),
    /// No durable Commit exists for the Offer release ID.
    #[error("protected Offer release has no durable profile-bound Commit")]
    ReleaseCommitNotFound,
    /// Offer names a different release-Commit hash than the verified journal.
    #[error("protected Offer release-Commit hash does not match verified release journal")]
    ReleaseCommitHashMismatch,
    /// A previously verified signer token was applied to another Offer.
    #[error("verified profile-release signer token does not match protected Offer")]
    OfferBindingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_binding_mismatch_is_explicit() {
        assert_eq!(
            ProfileReleaseSignerError::OfferBindingMismatch.to_string(),
            "verified profile-release signer token does not match protected Offer"
        );
    }
}
