// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session-generation binding for high-assurance profile-bound file releases.
//!
//! Historical profile-bound permit/release artifacts deliberately remain unchanged.
//! Their signed authorization already commits the complete authenticated session
//! transcript, but the move-only committed permit retains only its session UUID. This
//! additive layer re-binds that durable capability to the exact already-verified
//! execution credential before file authority is constructed, preserving the complete
//! [`SessionTranscriptBinding`] for the live output boundary.
//!
//! A protected Offer can then exist only after both independent checks succeed:
//! the negotiated SIF profile equals upstream authorization, and the live authenticated
//! session equals the exact transcript generation that produced the execution evidence.

use thiserror::Error;
use uuid::Uuid;

use crate::binding::SessionTranscriptBinding;
use crate::profile_disclosure::ProfileBoundCommittedDisclosurePermit;
use crate::profile_file_disclosure::{
    ProfileBoundCommittedFileDisclosure, ProfileBoundFileDisclosureError,
    ProfileBoundFileOfferAuthority,
};
use crate::protected_file_protocol::SifProtectedFileOffer;
use crate::release_credential_v2::ProfileBoundExecutionReleaseCredential;

/// Move-only durable release authority restored to its exact authenticated session generation.
#[derive(Debug)]
pub struct SessionBoundCommittedDisclosure {
    permit: ProfileBoundCommittedDisclosurePermit,
    session: SessionTranscriptBinding,
}

impl SessionBoundCommittedDisclosure {
    /// Durable release identifier.
    pub const fn release_id(&self) -> Uuid {
        self.permit.release_id()
    }

    /// Exact upstream-required SIF profile.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.permit.required_sif_profile_digest()
    }

    /// Complete authenticated Xenia session generation bound by the verified execution.
    pub fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    /// Signed durable release-Commit entry hash.
    pub const fn release_entry_hash(&self) -> [u8; 32] {
        self.permit.release_entry_hash()
    }
}

/// Restore the complete authenticated session generation to one durable profile release.
///
/// The permit and execution credential must describe the same verified authority lineage
/// on every field still available after durable Commit. A caller therefore cannot pair a
/// committed release with a different execution merely because the session UUID matches.
pub fn bind_profile_release_to_execution_session(
    permit: ProfileBoundCommittedDisclosurePermit,
    credential: &ProfileBoundExecutionReleaseCredential,
) -> Result<SessionBoundCommittedDisclosure, SessionBoundProfileFileError> {
    if permit.credential_id() != credential.credential_id() {
        return Err(SessionBoundProfileFileError::CredentialMismatch {
            field: "credential_id",
        });
    }
    if permit.required_sif_profile_digest() != credential.required_sif_profile_digest() {
        return Err(SessionBoundProfileFileError::CredentialMismatch {
            field: "required_sif_profile_digest",
        });
    }
    if permit.operation_id() != credential.operation_id() {
        return Err(SessionBoundProfileFileError::CredentialMismatch {
            field: "operation_id",
        });
    }
    if permit.session_id() != credential.session().session_id {
        return Err(SessionBoundProfileFileError::CredentialMismatch {
            field: "session_id",
        });
    }
    if permit.result_digest() != credential.result_digest() {
        return Err(SessionBoundProfileFileError::CredentialMismatch {
            field: "result_digest",
        });
    }
    if permit.evidence_bundle_digest() != credential.finalized_evidence_bundle_digest() {
        return Err(SessionBoundProfileFileError::CredentialMismatch {
            field: "evidence_bundle_digest",
        });
    }

    Ok(SessionBoundCommittedDisclosure {
        permit,
        session: credential.session().clone(),
    })
}

/// Exact-file authority that retains the full execution-authenticated session generation.
#[derive(Debug)]
pub struct SessionBoundCommittedFileDisclosure {
    file: ProfileBoundCommittedFileDisclosure,
    session: SessionTranscriptBinding,
}

impl SessionBoundCommittedFileDisclosure {
    /// Bind the session-restored durable release to exact file metadata/content commitment.
    pub fn new(
        authority: SessionBoundCommittedDisclosure,
        display_name: impl Into<String>,
        size: u64,
        content_blake3: [u8; 32],
    ) -> Result<Self, SessionBoundProfileFileError> {
        let SessionBoundCommittedDisclosure { permit, session } = authority;
        Ok(Self {
            file: ProfileBoundCommittedFileDisclosure::new(
                permit,
                display_name,
                size,
                content_blake3,
            )?,
            session,
        })
    }

    /// Durable release identifier.
    pub const fn release_id(&self) -> Uuid {
        self.file.release_id()
    }

    /// Exact profile required by upstream authorization and durable Commit.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.file.required_sif_profile_digest()
    }

    /// Exact authenticated session generation required by this release.
    pub fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    /// Exact committed file length.
    pub const fn expected_size(&self) -> u64 {
        self.file.expected_size()
    }

    /// Whole-file BLAKE3 committed by this release.
    pub const fn content_blake3(&self) -> [u8; 32] {
        self.file.content_blake3()
    }

    /// Consume into Offer authority only under the exact live session generation/profile.
    pub fn bind_live_session_and_profile(
        self,
        live_session: &SessionTranscriptBinding,
        negotiated_sif_profile_digest: [u8; 32],
        transfer_id: u64,
    ) -> Result<SessionBoundFileOfferAuthority, SessionBoundProfileFileError> {
        if self.session != *live_session {
            return Err(SessionBoundProfileFileError::SessionGenerationMismatch);
        }
        let offer = self
            .file
            .bind_negotiated_profile(negotiated_sif_profile_digest, transfer_id)?;
        Ok(SessionBoundFileOfferAuthority {
            inner: offer,
            session: self.session,
        })
    }
}

/// One-shot Offer authority proven against exact durable file, profile and session generation.
///
/// This type is intentionally non-`Clone`. The public high-assurance sender should consume
/// it rather than accepting a caller-authored [`SifProtectedFileOffer`].
#[derive(Debug)]
pub struct SessionBoundFileOfferAuthority {
    inner: ProfileBoundFileOfferAuthority,
    session: SessionTranscriptBinding,
}

impl SessionBoundFileOfferAuthority {
    /// Exact protected Offer derived from durable authority.
    pub fn offer(&self) -> &SifProtectedFileOffer {
        self.inner.offer()
    }

    /// Exact authenticated session generation required for this Offer.
    pub fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    /// Consume into the existing move-only file tracker plus exact session generation.
    pub fn into_parts(
        self,
    ) -> (
        SifProtectedFileOffer,
        ProfileBoundCommittedFileDisclosure,
        SessionTranscriptBinding,
    ) {
        let (offer, file) = self.inner.into_parts();
        (offer, file, self.session)
    }
}

/// Fail-closed session/profile/file authority failures.
#[derive(Debug, Error)]
pub enum SessionBoundProfileFileError {
    /// Durable permit and verified execution credential do not describe one lineage.
    #[error("profile-bound durable release does not match execution credential field {field}")]
    CredentialMismatch {
        /// Mismatching lineage field.
        field: &'static str,
    },
    /// Current authenticated session differs from the execution-authorized transcript generation.
    #[error("live authenticated session does not match authorized transcript generation")]
    SessionGenerationMismatch,
    /// Existing profile-bound exact-file/profile validation failed.
    #[error(transparent)]
    File(#[from] ProfileBoundFileDisclosureError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SignatureSuite;

    fn session(hash: u8) -> SessionTranscriptBinding {
        SessionTranscriptBinding::from_hash(
            Uuid::from_u128(7),
            [hash; 32],
            SignatureSuite::Ed25519Rfc8032,
        )
    }

    #[test]
    fn same_session_uuid_does_not_mean_same_authenticated_generation() {
        let a = session(0x11);
        let b = session(0x22);
        assert_eq!(a.session_id, b.session_id);
        assert_ne!(a, b);
    }

    #[test]
    fn session_generation_mismatch_is_explicit() {
        assert_eq!(
            SessionBoundProfileFileError::SessionGenerationMismatch.to_string(),
            "live authenticated session does not match authorized transcript generation"
        );
    }
}
