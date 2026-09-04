// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-file output authority derived from a durable profile-bound release Commit.
//!
//! This layer closes two separate substitution gaps before a protected Offer exists:
//! the committed result must equal the canonical filename/size/content commitment, and
//! the upstream-required SIF profile must equal the authenticated negotiated profile.
//! Only then can the move-only authority derive a [`SifProtectedFileOffer`].

use thiserror::Error;
use uuid::Uuid;

use crate::disclosure_v2::DisclosureReleaseOutcome;
use crate::file_disclosure::{
    FileDisclosureByteAccounting, FileDisclosureError, FileDisclosureTerminal,
    sif_file_result_digest,
};
use crate::profile_disclosure::ProfileBoundCommittedDisclosurePermit;
use crate::protected_file_protocol::{SifProtectedFileOffer, SifProtectedFileProtocolError};

/// Move-only tracker for one exact file under a durable profile-bound release.
#[derive(Debug)]
pub struct ProfileBoundCommittedFileDisclosure {
    permit: ProfileBoundCommittedDisclosurePermit,
    display_name: String,
    expected_size: u64,
    content_blake3: [u8; 32],
    accounted_bytes: u64,
    byte_accounting: FileDisclosureByteAccounting,
}

impl ProfileBoundCommittedFileDisclosure {
    /// Bind a durable profile-required permit to exact authenticated file metadata.
    pub fn new(
        permit: ProfileBoundCommittedDisclosurePermit,
        display_name: impl Into<String>,
        size: u64,
        content_blake3: [u8; 32],
    ) -> Result<Self, ProfileBoundFileDisclosureError> {
        let display_name = display_name.into();
        let expected = sif_file_result_digest(&display_name, size, content_blake3)?;
        match permit.result_digest() {
            None => {
                return Err(ProfileBoundFileDisclosureError::File(
                    FileDisclosureError::MissingResultCommitment,
                ));
            }
            Some(actual) if actual != expected => {
                return Err(ProfileBoundFileDisclosureError::File(
                    FileDisclosureError::ResultCommitmentMismatch,
                ));
            }
            Some(_) => {}
        }
        Ok(Self {
            permit,
            display_name,
            expected_size: size,
            content_blake3,
            accounted_bytes: 0,
            byte_accounting: FileDisclosureByteAccounting::Exact,
        })
    }

    /// Durable release identifier backing this file authority.
    pub const fn release_id(&self) -> Uuid {
        self.permit.release_id()
    }

    /// Authenticated Xenia session UUID carried by the durable permit.
    ///
    /// This is intentionally exposed so the application sender can reject moving a
    /// profile/file authority onto a different authenticated session. The current
    /// committed capability stores the session UUID, not the complete transcript
    /// binding; preserving the full generation is a separate hardening step.
    pub const fn authorized_session_id(&self) -> Uuid {
        self.permit.session_id()
    }

    /// Exact profile required by upstream authorization and the durable Commit.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.permit.required_sif_profile_digest()
    }

    /// Signed release-journal Commit entry hash.
    pub const fn release_entry_hash(&self) -> [u8; 32] {
        self.permit.release_entry_hash()
    }

    /// Authenticated wire-visible basename committed by this authority.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Exact committed file length.
    pub const fn expected_size(&self) -> u64 {
        self.expected_size
    }

    /// Whole-file BLAKE3 committed by this authority.
    pub const fn content_blake3(&self) -> [u8; 32] {
        self.content_blake3
    }

    /// File-content bytes currently charged to the release.
    pub const fn emitted_bytes(&self) -> u64 {
        self.accounted_bytes
    }

    /// Whether current byte accounting is exact or a conservative upper bound.
    pub const fn byte_accounting(&self) -> FileDisclosureByteAccounting {
        self.byte_accounting
    }

    /// Consume this authority into an Offer-capable state only when the exact
    /// authenticated negotiated profile equals the upstream-required profile.
    pub fn bind_negotiated_profile(
        self,
        negotiated_sif_profile_digest: [u8; 32],
        transfer_id: u64,
    ) -> Result<ProfileBoundFileOfferAuthority, ProfileBoundFileDisclosureError> {
        if negotiated_sif_profile_digest == [0u8; 32] {
            return Err(ProfileBoundFileDisclosureError::ZeroNegotiatedProfile);
        }
        if negotiated_sif_profile_digest != self.permit.required_sif_profile_digest() {
            return Err(ProfileBoundFileDisclosureError::ProfileMismatch);
        }
        let committed_result_digest = self
            .permit
            .result_digest()
            .ok_or(ProfileBoundFileDisclosureError::File(
                FileDisclosureError::MissingResultCommitment,
            ))?;
        let offer = SifProtectedFileOffer::new(
            self.permit.release_id(),
            transfer_id,
            self.permit.release_entry_hash(),
            committed_result_digest,
            self.display_name.clone(),
            self.expected_size,
            self.content_blake3,
        )?;
        Ok(ProfileBoundFileOfferAuthority { offer, file: self })
    }

    /// Account bytes only after the carrier reports a successful content send.
    pub fn note_emitted(&mut self, bytes: usize) -> Result<(), ProfileBoundFileDisclosureError> {
        self.add_accounted_bytes(bytes)
    }

    /// Conservatively charge a complete attempted content chunk after an ambiguous
    /// carrier failure. The caller must terminate the transfer after this transition.
    pub fn note_transport_uncertain(
        &mut self,
        bytes: usize,
    ) -> Result<(), ProfileBoundFileDisclosureError> {
        if bytes == 0 {
            return Err(ProfileBoundFileDisclosureError::File(
                FileDisclosureError::ZeroUncertainChunk,
            ));
        }
        self.add_accounted_bytes(bytes)?;
        self.byte_accounting = FileDisclosureByteAccounting::ConservativeUpperBound;
        Ok(())
    }

    fn add_accounted_bytes(
        &mut self,
        bytes: usize,
    ) -> Result<(), ProfileBoundFileDisclosureError> {
        let bytes = u64::try_from(bytes).map_err(|_| {
            ProfileBoundFileDisclosureError::File(FileDisclosureError::ByteCountOverflow)
        })?;
        let accounted = self.accounted_bytes.checked_add(bytes).ok_or(
            ProfileBoundFileDisclosureError::File(FileDisclosureError::ByteCountOverflow),
        )?;
        if accounted > self.expected_size {
            return Err(ProfileBoundFileDisclosureError::File(
                FileDisclosureError::EmittedBeyondDeclaredSize {
                    declared: self.expected_size,
                    emitted: accounted,
                },
            ));
        }
        self.accounted_bytes = accounted;
        Ok(())
    }

    /// Consume after independent final source length/hash verification and complete
    /// transport-confirmed output.
    pub fn completed(self) -> Result<FileDisclosureTerminal, ProfileBoundFileDisclosureError> {
        if self.byte_accounting != FileDisclosureByteAccounting::Exact {
            return Err(ProfileBoundFileDisclosureError::File(
                FileDisclosureError::CompletionAfterTransportUncertainty,
            ));
        }
        if self.accounted_bytes != self.expected_size {
            return Err(ProfileBoundFileDisclosureError::File(
                FileDisclosureError::IncompleteCompletion {
                    expected: self.expected_size,
                    emitted: self.accounted_bytes,
                },
            ));
        }
        Ok(FileDisclosureTerminal {
            release_id: self.permit.release_id(),
            outcome: DisclosureReleaseOutcome::Completed,
            byte_accounting: FileDisclosureByteAccounting::Exact,
        })
    }

    /// Consume when output stops before verified complete send.
    pub fn interrupted(self) -> FileDisclosureTerminal {
        let outcome = if self.accounted_bytes == 0 {
            DisclosureReleaseOutcome::Aborted
        } else {
            DisclosureReleaseOutcome::Partial {
                bytes_released: self.accounted_bytes,
            }
        };
        FileDisclosureTerminal {
            release_id: self.permit.release_id(),
            outcome,
            byte_accounting: self.byte_accounting,
        }
    }
}

/// One-shot authority to create exactly the Offer derived from a durable file release.
///
/// The type is intentionally non-`Clone`. Application transfer typestate should consume
/// it rather than accepting a caller-authored [`SifProtectedFileOffer`].
#[derive(Debug)]
pub struct ProfileBoundFileOfferAuthority {
    offer: SifProtectedFileOffer,
    file: ProfileBoundCommittedFileDisclosure,
}

impl ProfileBoundFileOfferAuthority {
    /// Exact derived protected Offer.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        &self.offer
    }

    /// Authenticated session UUID retained by the durable release authority.
    pub const fn authorized_session_id(&self) -> Uuid {
        self.file.authorized_session_id()
    }

    /// Exact upstream-required SIF profile retained by the durable authority.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.file.required_sif_profile_digest()
    }

    /// Consume into the exact Offer and its associated move-only file tracker.
    pub fn into_parts(self) -> (SifProtectedFileOffer, ProfileBoundCommittedFileDisclosure) {
        (self.offer, self.file)
    }
}

/// Profile-bound file/Offer construction failures.
#[derive(Debug, Error)]
pub enum ProfileBoundFileDisclosureError {
    /// Existing canonical file-disclosure invariant failed.
    #[error(transparent)]
    File(#[from] FileDisclosureError),
    /// Protected-file semantic Offer construction failed.
    #[error(transparent)]
    Protocol(#[from] SifProtectedFileProtocolError),
    /// Negotiated profile used an all-zero placeholder.
    #[error("negotiated SIF profile digest must not be all-zero")]
    ZeroNegotiatedProfile,
    /// Upstream-required and authenticated negotiated profiles differ.
    #[error("authorized SIF profile does not match authenticated negotiated profile")]
    ProfileMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_mismatch_is_a_distinct_fail_closed_error() {
        assert_eq!(
            ProfileBoundFileDisclosureError::ProfileMismatch.to_string(),
            "authorized SIF profile does not match authenticated negotiated profile"
        );
    }
}
