// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Narrow SIF authority adapter over the daemon's existing M1 consent ledger.
//!
//! `M1RuntimeSession` remains the owner of the live consent state machine and its
//! private `Chain`. This adapter never mutates or reaches into those private fields.
//! Instead, while the caller holds the runtime mutex, it consumes the runtime's
//! immutable signed-entry export plus transcript binding, reloads the already-enrolled
//! M1 signing key from hardened storage, verifies the complete chain under that key,
//! and reconstructs a short-lived signing snapshot.
//!
//! The key file is **read-only** here: missing state fails closed. This module never
//! generates or replaces an M1 authority key.
//!
//! A prepared permit is deliberately **not** committable through an old snapshot.
//! Commit reconstructs the M1 authority from the live runtime immediately before the
//! durable release-journal CAS. This closes the Approval-snapshot -> live Revocation ->
//! stale Commit race. After Commit, a narrower outcome authority is returned so an
//! in-flight release can still record `Aborted`/`Partial` after consent is revoked,
//! without retaining an API capable of authorizing another release.

#![allow(dead_code)]

use std::path::Path;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use uuid::Uuid;
use xenia_ledger::{
    AccountabilityBindingError, AccountabilityDisclosureError, AccountabilityDisclosurePermit,
    AccountabilityExecutionAttestation, Chain, CommittedDisclosurePermit, ConsentKind,
    DisclosureReleaseOutcome, DisclosureReleaseState, DisclosureReleaseStore,
    Ed25519EvidenceSignatureBackend, ExecutionBoundReleaseCredential, ReleaseCredentialError,
    ReleaseCredentialTrustPolicy, SifReleaseCredential, TransactionalDisclosureError,
    TrustedReleaseAuthority, Verifier, VerifyError, bind_release_credential_to_execution,
    verify_release_credential,
};

use crate::m1_runtime::M1RuntimeSession;

/// Verified short-lived view of the exact M1 ledger authority that controls the
/// runtime's consent state.
///
/// This type can attest/verify/prepare, but intentionally cannot commit a release.
/// Durable Commit requires [`commit_disclosure_from_current_runtime`], which rebuilds
/// authority from the caller's currently locked live runtime.
pub(crate) struct M1SifAuthoritySnapshot {
    chain: Chain,
    ledger_public_key: [u8; 32],
    transcript: xenia_ledger::SessionTranscriptBinding,
    requester_source_id: [u8; 32],
}

impl M1SifAuthoritySnapshot {
    /// Reconstruct a signing snapshot from the live runtime's immutable evidence.
    ///
    /// The current signed M1 anchor must be an `Approval`. A later Denial,
    /// Revocation, Violation, Request, or other event therefore prevents a fresh
    /// authorization snapshot from being created.
    pub(crate) fn from_runtime(
        runtime: &M1RuntimeSession,
        key_path: &Path,
    ) -> Result<Self, M1SifAuthorityError> {
        let key_bytes = xenia_secure_file::read_secure_file_if_exists(key_path)
            .map_err(|error| M1SifAuthorityError::SecureKey(error.to_string()))?
            .ok_or(M1SifAuthorityError::MissingKey)?;
        let seed: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| M1SifAuthorityError::InvalidKeyLength)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let ledger_public_key = verifying_key.to_bytes();

        let entries = runtime.entries();
        Verifier::verify_chain(&entries, &verifying_key)?;
        let anchor = entries
            .last()
            .ok_or(M1SifAuthorityError::MissingAuthorizationAnchor)?;
        if anchor.event.kind != ConsentKind::Approval {
            return Err(M1SifAuthorityError::AuthorizationNotApproved {
                found: anchor.event.kind,
            });
        }
        let transcript = runtime
            .session_transcript_binding()
            .ok_or(M1SifAuthorityError::MissingTranscriptBinding)?;
        if anchor.event.session_id != transcript.session_id {
            return Err(M1SifAuthorityError::AuthorizationSessionMismatch);
        }

        Ok(Self {
            chain: Chain::from_entries(entries, signing_key),
            ledger_public_key,
            transcript,
            requester_source_id: anchor.event.source_id,
        })
    }

    /// Public key of the exact M1 authority whose signed entries were verified.
    pub(crate) fn ledger_public_key(&self) -> [u8; 32] {
        self.ledger_public_key
    }

    /// Build/sign the Xenia execution evidence that Mycelix/Symthaea will bind.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn attest_execution(
        &self,
        operation_id: Uuid,
        query_digest: [u8; 32],
        purpose_digest: [u8; 32],
        policy_digest: [u8; 32],
        result_digest: Option<[u8; 32]>,
        receipt_digest: [u8; 32],
    ) -> Result<AccountabilityExecutionAttestation, M1SifAuthorityError> {
        Ok(self.chain.attest_accountability_execution(
            self.transcript.clone(),
            operation_id,
            self.requester_source_id,
            query_digest,
            purpose_digest,
            policy_digest,
            result_digest,
            receipt_digest,
        )?)
    }

    /// Verify Mycelix release-authority consensus and bind it to this exact Xenia
    /// execution under a locally configured execution administration domain.
    pub(crate) fn verify_and_bind_credential(
        &self,
        credential: &SifReleaseCredential,
        trusted_release_authorities: &[TrustedReleaseAuthority],
        release_policy: ReleaseCredentialTrustPolicy,
        execution: &AccountabilityExecutionAttestation,
        local_execution_trust_domain_id: [u8; 32],
    ) -> Result<ExecutionBoundReleaseCredential, M1SifAuthorityError> {
        let verified = verify_release_credential(
            credential,
            trusted_release_authorities,
            release_policy,
        )?;
        Ok(bind_release_credential_to_execution(
            &verified,
            execution,
            xenia_ledger::CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            &Ed25519EvidenceSignatureBackend,
            &self.ledger_public_key,
            local_execution_trust_domain_id,
        )?)
    }

    /// Prepare a release permit only from an already execution-bound credential.
    ///
    /// This does not create output authority. The returned permit must still pass
    /// a fresh live-runtime check in [`commit_disclosure_from_current_runtime`].
    pub(crate) fn prepare_disclosure(
        &self,
        credential: &ExecutionBoundReleaseCredential,
        release_id: Uuid,
        retry_of: Option<Uuid>,
    ) -> Result<AccountabilityDisclosurePermit, M1SifAuthorityError> {
        Ok(self.chain.prepare_accountability_disclosure(
            credential,
            release_id,
            retry_of,
            xenia_ledger::CURRENT_EVIDENCE_CRYPTO_MANIFEST,
        )?)
    }
}

/// Move-only authority for closing one already-committed release.
///
/// It deliberately exposes no execution, credential, permit-preparation, or Commit
/// operation. Retaining it across a mid-transfer revocation is necessary so Xenia can
/// still durably record exactly what escaped (`Aborted`/`Partial`) after the live M1
/// gate has closed.
pub(crate) struct M1SifOutcomeAuthority {
    chain: Chain,
}

impl M1SifOutcomeAuthority {
    pub(crate) fn record_outcome<S: DisclosureReleaseStore>(
        &self,
        state: &mut DisclosureReleaseState,
        release_id: Uuid,
        outcome: DisclosureReleaseOutcome,
        store: &mut S,
    ) -> Result<(), TransactionalDisclosureError<S::Error>> {
        state.record_outcome(&self.chain, release_id, outcome, store)
    }
}

/// Result of a successful durable Commit: the move-only generic release permit plus
/// a narrower signer that can only close this release lineage with a terminal outcome.
pub(crate) struct M1SifCommittedRelease {
    permit: CommittedDisclosurePermit,
    outcome_authority: M1SifOutcomeAuthority,
}

impl M1SifCommittedRelease {
    pub(crate) fn into_parts(self) -> (CommittedDisclosurePermit, M1SifOutcomeAuthority) {
        (self.permit, self.outcome_authority)
    }
}

/// Revalidate the **current** live M1 runtime and only then perform the durable CAS
/// release Commit.
///
/// Callers in the daemon invoke this while holding the `AsyncMutex<M1RuntimeSession>`
/// guard. No revocation can interleave between this fresh reconstruction and the
/// synchronous release-store CAS. An earlier `M1SifAuthoritySnapshot` is intentionally
/// not accepted by this API.
pub(crate) fn commit_disclosure_from_current_runtime<S: DisclosureReleaseStore>(
    runtime: &M1RuntimeSession,
    key_path: &Path,
    state: &mut DisclosureReleaseState,
    permit: AccountabilityDisclosurePermit,
    store: &mut S,
) -> Result<M1SifCommittedRelease, M1SifCommitError<S::Error>> {
    let current =
        M1SifAuthoritySnapshot::from_runtime(runtime, key_path).map_err(M1SifCommitError::Authority)?;
    let committed = state
        .commit_permit(
            &current.chain,
            permit,
            xenia_ledger::CURRENT_EVIDENCE_CRYPTO_MANIFEST,
            store,
        )
        .map_err(M1SifCommitError::Release)?;

    Ok(M1SifCommittedRelease {
        permit: committed,
        outcome_authority: M1SifOutcomeAuthority {
            chain: current.chain,
        },
    })
}

/// Fresh-authority failure versus release-journal Commit failure.
#[derive(Debug)]
pub(crate) enum M1SifCommitError<E> {
    /// Current M1 runtime/key/Approval reconstruction failed before CAS.
    Authority(M1SifAuthorityError),
    /// Permit validation or durable release-journal CAS failed.
    Release(TransactionalDisclosureError<E>),
}

/// Fail-closed M1/SIF authority snapshot failures.
#[derive(Debug, Error)]
pub(crate) enum M1SifAuthorityError {
    /// Hardened key storage could not be read safely.
    #[error("M1 SIF authority key read failed: {0}")]
    SecureKey(String),
    /// The already-enrolled M1 key does not exist; this adapter never generates it.
    #[error("M1 SIF authority key is missing")]
    MissingKey,
    /// M1 key file is not an Ed25519 32-byte seed.
    #[error("M1 SIF authority key must contain exactly 32 bytes")]
    InvalidKeyLength,
    /// The runtime's persisted signed M1 ledger did not verify under the enrolled key.
    #[error(transparent)]
    LedgerVerify(#[from] VerifyError),
    /// No signed M1 consent anchor exists.
    #[error("M1 SIF authority requires a signed consent anchor")]
    MissingAuthorizationAnchor,
    /// The current signed M1 consent anchor is not an Approval.
    #[error("M1 SIF authority requires current Approval anchor, found {found:?}")]
    AuthorizationNotApproved { found: ConsentKind },
    /// Runtime has not bound the authenticated handshake transcript.
    #[error("M1 SIF authority requires the authenticated session transcript")]
    MissingTranscriptBinding,
    /// Signed consent anchor and authenticated transcript name different sessions.
    #[error("M1 SIF consent anchor does not match authenticated transcript session")]
    AuthorizationSessionMismatch,
    /// Execution binding/signature construction failed.
    #[error(transparent)]
    Execution(#[from] AccountabilityBindingError),
    /// Mycelix release credential failed Xenia verification/binding.
    #[error(transparent)]
    Credential(#[from] ReleaseCredentialError),
    /// Release permit construction failed.
    #[error(transparent)]
    Disclosure(#[from] AccountabilityDisclosureError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_ledger::ACCOUNTABILITY_COMMITMENT_ALGORITHM;

    fn temp_key(seed: [u8; 32]) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "xenia-m1-sif-authority-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m1.key");
        xenia_secure_file::load_or_create_secure_file(&path, || seed.to_vec()).unwrap();
        (dir, path)
    }

    #[test]
    fn missing_key_never_generates_replacement() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-m1-sif-missing-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("missing.key");
        let runtime = M1RuntimeSession::new(
            SigningKey::from_bytes(&[3u8; 32]),
            [4u8; 32],
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            "test",
        );
        assert!(matches!(
            M1SifAuthoritySnapshot::from_runtime(&runtime, &path),
            Err(M1SifAuthorityError::MissingKey)
        ));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verified_snapshot_requires_current_approval() {
        let seed = [7u8; 32];
        let (dir, path) = temp_key(seed);
        let mut runtime = M1RuntimeSession::new(
            SigningKey::from_bytes(&seed),
            [8u8; 32],
            Uuid::from_u128(11),
            Uuid::from_u128(12),
            "file send",
        );
        runtime.bind_session_transcript_hash([9u8; 32]);
        runtime.offer().unwrap();
        assert!(matches!(
            M1SifAuthoritySnapshot::from_runtime(&runtime, &path),
            Err(M1SifAuthorityError::AuthorizationNotApproved {
                found: ConsentKind::Request
            })
        ));
        runtime.grant_consent().unwrap();
        M1SifAuthoritySnapshot::from_runtime(&runtime, &path).unwrap();
        runtime.revoke().unwrap();
        assert!(matches!(
            M1SifAuthoritySnapshot::from_runtime(&runtime, &path),
            Err(M1SifAuthorityError::AuthorizationNotApproved {
                found: ConsentKind::Revocation
            })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mismatched_key_cannot_reconstruct_authority() {
        let runtime_seed = [21u8; 32];
        let file_seed = [22u8; 32];
        let (dir, path) = temp_key(file_seed);
        let mut runtime = M1RuntimeSession::new(
            SigningKey::from_bytes(&runtime_seed),
            [23u8; 32],
            Uuid::from_u128(31),
            Uuid::from_u128(32),
            "file send",
        );
        runtime.bind_session_transcript_hash([24u8; 32]);
        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        assert!(matches!(
            M1SifAuthoritySnapshot::from_runtime(&runtime, &path),
            Err(M1SifAuthorityError::LedgerVerify(_))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn execution_uses_runtime_transcript_and_approval_principal() {
        let seed = [31u8; 32];
        let (dir, path) = temp_key(seed);
        let source = [32u8; 32];
        let session = Uuid::from_u128(41);
        let mut runtime = M1RuntimeSession::new(
            SigningKey::from_bytes(&seed),
            source,
            session,
            Uuid::from_u128(42),
            "file send",
        );
        runtime.bind_session_transcript_hash([33u8; 32]);
        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();
        let authority = M1SifAuthoritySnapshot::from_runtime(&runtime, &path).unwrap();
        let execution = authority
            .attest_execution(
                Uuid::from_u128(43),
                [34u8; 32],
                [35u8; 32],
                [36u8; 32],
                Some([37u8; 32]),
                [38u8; 32],
            )
            .unwrap();
        assert_eq!(execution.binding.session.session_id, session);
        assert_eq!(execution.binding.session.transcript_hash, [33u8; 32]);
        assert_eq!(execution.binding.requester_source_id, source);
        assert_eq!(execution.binding.commitment_algorithm, ACCOUNTABILITY_COMMITMENT_ALGORITHM);
        assert_eq!(
            authority.ledger_public_key(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_snapshot_cannot_be_used_as_commit_api_after_revocation() {
        let seed = [41u8; 32];
        let (dir, path) = temp_key(seed);
        let mut runtime = M1RuntimeSession::new(
            SigningKey::from_bytes(&seed),
            [42u8; 32],
            Uuid::from_u128(51),
            Uuid::from_u128(52),
            "file send",
        );
        runtime.bind_session_transcript_hash([43u8; 32]);
        runtime.offer().unwrap();
        runtime.grant_consent().unwrap();

        // A historical snapshot can still describe/attest the Approval that really
        // existed. Durable release authorization is intentionally not a method on it.
        let historical = M1SifAuthoritySnapshot::from_runtime(&runtime, &path).unwrap();
        assert_eq!(historical.ledger_public_key(), SigningKey::from_bytes(&seed).verifying_key().to_bytes());

        runtime.revoke().unwrap();
        assert!(matches!(
            M1SifAuthoritySnapshot::from_runtime(&runtime, &path),
            Err(M1SifAuthorityError::AuthorizationNotApproved {
                found: ConsentKind::Revocation
            })
        ));

        // The actual commit entry point reconstructs from `runtime`; callers cannot
        // pass `historical` to it. A full permit/commit regression belongs with the
        // protected-file integration, where the portable credential fixture exists.
        let _ = std::fs::remove_dir_all(dir);
    }
}
