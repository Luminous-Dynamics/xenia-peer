// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Store-authenticated persistence proofs for Xenia operation authority V2.
//!
//! A semantic admission digest or authority object can be computed in memory. That is not
//! proof that the operation store atomically reserved the operation id/use slot and committed
//! the admission. Likewise, a fresh arm authorization is not proof that the write-ahead
//! `EffectArmed` receipt was durably appended.
//!
//! This contract introduces explicit persistence proofs for both boundaries. The serialized
//! records do not authenticate themselves: validation requires exact backend/profile/commit
//! evidence supplied by the trusted persistence path.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_epoch::{
    AuthorityEpochBindingV1, AuthorityEpochError, OperationAuthorityEpochV1,
};
use xenia_operation_authority_v2::{
    AdmissionAuthorityV2, AuthorityV2Error, EffectArmAuthorityV2, StoreAuthorityV2,
};

/// Schema for [`AdmissionPersistenceProofV2`].
pub const ADMISSION_PERSISTENCE_PROOF_SCHEMA_V2: &str =
    "xenia-operation-admission-persistence-proof-v2";
/// Schema for [`EffectArmedPersistenceProofV2`].
pub const EFFECT_ARMED_PERSISTENCE_PROOF_SCHEMA_V2: &str =
    "xenia-effect-armed-persistence-proof-v2";
/// Domain separator for admission persistence proofs.
pub const ADMISSION_PERSISTENCE_PROOF_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-operation-admission-persistence-proof-digest-v2";
/// Domain separator for effect-armed persistence proofs.
pub const EFFECT_ARMED_PERSISTENCE_PROOF_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-effect-armed-persistence-proof-digest-v2";

/// Authenticated facts supplied by the trusted persistence backend.
///
/// These values must come from the persistence trust boundary, not from untrusted wire input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPersistenceContextV2 {
    /// Identity/configuration commitment of the backend implementation allowed to issue proofs.
    pub backend_authority_digest: [u8; 32],
    /// Exact named durability/profile commitment (SQLite profile, filesystem profile, etc.).
    pub persistence_profile_digest: [u8; 32],
    /// Exact commit/evidence commitment for this successful durable mutation.
    pub commit_evidence_digest: [u8; 32],
}

impl AuthenticatedPersistenceContextV2 {
    fn validate(self) -> Result<(), PersistenceProofV2Error> {
        require_nonzero(
            self.backend_authority_digest,
            PersistenceProofV2Error::ZeroBackendAuthorityDigest,
        )?;
        require_nonzero(
            self.persistence_profile_digest,
            PersistenceProofV2Error::ZeroPersistenceProfileDigest,
        )?;
        require_nonzero(
            self.commit_evidence_digest,
            PersistenceProofV2Error::ZeroCommitEvidenceDigest,
        )
    }
}

/// Proof that the exact V2 admission authority was durably committed by the trusted store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPersistenceProofV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact admitted operation.
    pub operation_id: [u8; 16],
    /// Exact V2 admission authority that the store committed.
    pub admission_authority_digest: [u8; 32],
    /// Exact persistent store authority serving the commit.
    pub store_authority_digest: [u8; 32],
    /// Exact monotonic durable admission sequence.
    pub admission_sequence: u64,
    /// Commitment to the exact atomically reserved grant/use slot.
    pub use_slot_reservation_digest: [u8; 32],
    /// Exact store frontier/checkpoint containing the committed admission.
    pub committed_frontier_digest: [u8; 32],
    /// Exact authority epoch at commit time.
    pub authority_epoch: AuthorityEpochBindingV1,
    /// Trusted backend identity/configuration commitment.
    pub backend_authority_digest: [u8; 32],
    /// Named persistence/durability profile commitment.
    pub persistence_profile_digest: [u8; 32],
    /// Exact backend commit/evidence commitment.
    pub commit_evidence_digest: [u8; 32],
    /// Evidence timestamp for the durable commit.
    pub persisted_at_unix_ms: u64,
}

impl AdmissionPersistenceProofV2 {
    /// Construct a proof returned by the trusted store after a successful durable admission.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission: &AdmissionAuthorityV2,
        store: &StoreAuthorityV2,
        current: &OperationAuthorityEpochV1,
        admission_sequence: u64,
        use_slot_reservation_digest: [u8; 32],
        committed_frontier_digest: [u8; 32],
        persistence: AuthenticatedPersistenceContextV2,
        persisted_at_unix_ms: u64,
    ) -> Result<Self, PersistenceProofV2Error> {
        admission.validate()?;
        admission.authority_epoch.validate_against(current)?;
        store.validate_against(current)?;
        persistence.validate()?;
        require_nonzero(
            use_slot_reservation_digest,
            PersistenceProofV2Error::ZeroUseSlotReservationDigest,
        )?;
        require_nonzero(
            committed_frontier_digest,
            PersistenceProofV2Error::ZeroCommittedFrontierDigest,
        )?;
        if persisted_at_unix_ms < current.established_at_unix_ms {
            return Err(PersistenceProofV2Error::PersistencePredatesEpoch);
        }
        let value = Self {
            schema: ADMISSION_PERSISTENCE_PROOF_SCHEMA_V2.to_string(),
            operation_id: admission.operation_id,
            admission_authority_digest: admission.authority_digest()?,
            store_authority_digest: store.authority_digest()?,
            admission_sequence,
            use_slot_reservation_digest,
            committed_frontier_digest,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
            backend_authority_digest: persistence.backend_authority_digest,
            persistence_profile_digest: persistence.persistence_profile_digest,
            commit_evidence_digest: persistence.commit_evidence_digest,
            persisted_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax without authenticating the persistence backend.
    pub fn validate(&self) -> Result<(), PersistenceProofV2Error> {
        if self.schema != ADMISSION_PERSISTENCE_PROOF_SCHEMA_V2 {
            return Err(PersistenceProofV2Error::UnsupportedAdmissionProofSchema);
        }
        require_operation(self.operation_id)?;
        require_nonzero(
            self.admission_authority_digest,
            PersistenceProofV2Error::ZeroAdmissionAuthorityDigest,
        )?;
        require_nonzero(
            self.store_authority_digest,
            PersistenceProofV2Error::ZeroStoreAuthorityDigest,
        )?;
        require_nonzero(
            self.use_slot_reservation_digest,
            PersistenceProofV2Error::ZeroUseSlotReservationDigest,
        )?;
        require_nonzero(
            self.committed_frontier_digest,
            PersistenceProofV2Error::ZeroCommittedFrontierDigest,
        )?;
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        require_nonzero(
            self.backend_authority_digest,
            PersistenceProofV2Error::ZeroBackendAuthorityDigest,
        )?;
        require_nonzero(
            self.persistence_profile_digest,
            PersistenceProofV2Error::ZeroPersistenceProfileDigest,
        )?;
        require_nonzero(
            self.commit_evidence_digest,
            PersistenceProofV2Error::ZeroCommitEvidenceDigest,
        )?;
        Ok(())
    }

    /// Require exact admission/store/epoch and exact authenticated backend evidence.
    pub fn validate_against(
        &self,
        admission: &AdmissionAuthorityV2,
        store: &StoreAuthorityV2,
        current: &OperationAuthorityEpochV1,
        authenticated: AuthenticatedPersistenceContextV2,
    ) -> Result<(), PersistenceProofV2Error> {
        self.validate()?;
        admission.validate()?;
        store.validate_against(current)?;
        self.authority_epoch.validate_against(current)?;
        admission.authority_epoch.validate_against(current)?;
        authenticated.validate()?;
        if self.persisted_at_unix_ms < current.established_at_unix_ms {
            return Err(PersistenceProofV2Error::PersistencePredatesEpoch);
        }
        if self.operation_id != admission.operation_id {
            return Err(PersistenceProofV2Error::OperationIdMismatch);
        }
        if self.admission_authority_digest != admission.authority_digest()? {
            return Err(PersistenceProofV2Error::AdmissionAuthorityDigestMismatch);
        }
        if self.store_authority_digest != store.authority_digest()? {
            return Err(PersistenceProofV2Error::StoreAuthorityDigestMismatch);
        }
        validate_authenticated_context(self, authenticated)?;
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PersistenceProofV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable proof commitment used by later arm/evidence records.
    pub fn proof_digest(&self) -> Result<[u8; 32], PersistenceProofV2Error> {
        Ok(domain_digest(
            ADMISSION_PERSISTENCE_PROOF_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// Proof that the exact write-ahead `EffectArmed` receipt for an authority V2 arm was durably committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectArmedPersistenceProofV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact operation being armed.
    pub operation_id: [u8; 16],
    /// Exact V2 arm authority authorized for this operation.
    pub effect_arm_authority_digest: [u8; 32],
    /// Exact admission persistence proof that preceded arming.
    pub admission_persistence_proof_digest: [u8; 32],
    /// Exact durable `EffectArmed` receipt-event commitment.
    pub effect_armed_receipt_digest: [u8; 32],
    /// Exact persistent store authority serving the write-ahead receipt.
    pub store_authority_digest: [u8; 32],
    /// Exact store frontier/checkpoint containing `EffectArmed`.
    pub committed_frontier_digest: [u8; 32],
    /// Exact authority epoch at the write-ahead boundary.
    pub authority_epoch: AuthorityEpochBindingV1,
    /// Trusted backend identity/configuration commitment.
    pub backend_authority_digest: [u8; 32],
    /// Named persistence/durability profile commitment.
    pub persistence_profile_digest: [u8; 32],
    /// Exact backend commit/evidence commitment for the arm receipt append.
    pub commit_evidence_digest: [u8; 32],
    /// Evidence timestamp for durable `EffectArmed` persistence.
    pub persisted_at_unix_ms: u64,
}

impl EffectArmedPersistenceProofV2 {
    /// Construct after the trusted store durably appends the write-ahead `EffectArmed` event.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        arm: &EffectArmAuthorityV2,
        admission_proof: &AdmissionPersistenceProofV2,
        store: &StoreAuthorityV2,
        current: &OperationAuthorityEpochV1,
        effect_armed_receipt_digest: [u8; 32],
        committed_frontier_digest: [u8; 32],
        persistence: AuthenticatedPersistenceContextV2,
        persisted_at_unix_ms: u64,
    ) -> Result<Self, PersistenceProofV2Error> {
        arm.validate()?;
        arm.authority_epoch.validate_against(current)?;
        admission_proof.validate()?;
        admission_proof.authority_epoch.validate_against(current)?;
        store.validate_against(current)?;
        persistence.validate()?;
        require_nonzero(
            effect_armed_receipt_digest,
            PersistenceProofV2Error::ZeroEffectArmedReceiptDigest,
        )?;
        require_nonzero(
            committed_frontier_digest,
            PersistenceProofV2Error::ZeroCommittedFrontierDigest,
        )?;
        if arm.operation_id != admission_proof.operation_id {
            return Err(PersistenceProofV2Error::OperationIdMismatch);
        }
        if persisted_at_unix_ms < admission_proof.persisted_at_unix_ms {
            return Err(PersistenceProofV2Error::PersistenceTimestampRegression);
        }
        let value = Self {
            schema: EFFECT_ARMED_PERSISTENCE_PROOF_SCHEMA_V2.to_string(),
            operation_id: arm.operation_id,
            effect_arm_authority_digest: arm.authority_digest()?,
            admission_persistence_proof_digest: admission_proof.proof_digest()?,
            effect_armed_receipt_digest,
            store_authority_digest: store.authority_digest()?,
            committed_frontier_digest,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
            backend_authority_digest: persistence.backend_authority_digest,
            persistence_profile_digest: persistence.persistence_profile_digest,
            commit_evidence_digest: persistence.commit_evidence_digest,
            persisted_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax without authenticating backend evidence.
    pub fn validate(&self) -> Result<(), PersistenceProofV2Error> {
        if self.schema != EFFECT_ARMED_PERSISTENCE_PROOF_SCHEMA_V2 {
            return Err(PersistenceProofV2Error::UnsupportedEffectArmedProofSchema);
        }
        require_operation(self.operation_id)?;
        require_nonzero(
            self.effect_arm_authority_digest,
            PersistenceProofV2Error::ZeroEffectArmAuthorityDigest,
        )?;
        require_nonzero(
            self.admission_persistence_proof_digest,
            PersistenceProofV2Error::ZeroAdmissionPersistenceProofDigest,
        )?;
        require_nonzero(
            self.effect_armed_receipt_digest,
            PersistenceProofV2Error::ZeroEffectArmedReceiptDigest,
        )?;
        require_nonzero(
            self.store_authority_digest,
            PersistenceProofV2Error::ZeroStoreAuthorityDigest,
        )?;
        require_nonzero(
            self.committed_frontier_digest,
            PersistenceProofV2Error::ZeroCommittedFrontierDigest,
        )?;
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        require_nonzero(
            self.backend_authority_digest,
            PersistenceProofV2Error::ZeroBackendAuthorityDigest,
        )?;
        require_nonzero(
            self.persistence_profile_digest,
            PersistenceProofV2Error::ZeroPersistenceProfileDigest,
        )?;
        require_nonzero(
            self.commit_evidence_digest,
            PersistenceProofV2Error::ZeroCommitEvidenceDigest,
        )?;
        Ok(())
    }

    /// Final persistence-aware effect gate.
    ///
    /// Callers must separately perform the semantic V2 arm final gate. This method proves that
    /// the exact arm authority was durably write-ahead recorded by the trusted store under the
    /// exact current store/epoch and backend profile.
    pub fn validate_final_gate(
        &self,
        arm: &EffectArmAuthorityV2,
        admission_proof: &AdmissionPersistenceProofV2,
        store: &StoreAuthorityV2,
        current: &OperationAuthorityEpochV1,
        authenticated: AuthenticatedPersistenceContextV2,
    ) -> Result<(), PersistenceProofV2Error> {
        self.validate()?;
        arm.validate()?;
        store.validate_against(current)?;
        self.authority_epoch.validate_against(current)?;
        admission_proof.authority_epoch.validate_against(current)?;
        authenticated.validate()?;
        if self.operation_id != arm.operation_id || self.operation_id != admission_proof.operation_id {
            return Err(PersistenceProofV2Error::OperationIdMismatch);
        }
        if self.effect_arm_authority_digest != arm.authority_digest()? {
            return Err(PersistenceProofV2Error::EffectArmAuthorityDigestMismatch);
        }
        if self.admission_persistence_proof_digest != admission_proof.proof_digest()? {
            return Err(PersistenceProofV2Error::AdmissionPersistenceProofDigestMismatch);
        }
        if self.store_authority_digest != store.authority_digest()? {
            return Err(PersistenceProofV2Error::StoreAuthorityDigestMismatch);
        }
        validate_authenticated_context_effect(self, authenticated)?;
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PersistenceProofV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable write-ahead persistence commitment.
    pub fn proof_digest(&self) -> Result<[u8; 32], PersistenceProofV2Error> {
        Ok(domain_digest(
            EFFECT_ARMED_PERSISTENCE_PROOF_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// Persistence-proof validation failure.
#[derive(Debug, Error)]
pub enum PersistenceProofV2Error {
    /// Admission persistence proof schema mismatch.
    #[error("unsupported admission persistence proof v2 schema")]
    UnsupportedAdmissionProofSchema,
    /// Effect-armed persistence proof schema mismatch.
    #[error("unsupported effect-armed persistence proof v2 schema")]
    UnsupportedEffectArmedProofSchema,
    /// Operation id is unset.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Admission authority digest is unset.
    #[error("admission authority digest must not be all zero")]
    ZeroAdmissionAuthorityDigest,
    /// Store authority digest is unset.
    #[error("store authority digest must not be all zero")]
    ZeroStoreAuthorityDigest,
    /// Use-slot reservation commitment is unset.
    #[error("use-slot reservation digest must not be all zero")]
    ZeroUseSlotReservationDigest,
    /// Committed frontier/checkpoint is unset.
    #[error("committed frontier digest must not be all zero")]
    ZeroCommittedFrontierDigest,
    /// Trusted persistence backend identity is unset.
    #[error("backend authority digest must not be all zero")]
    ZeroBackendAuthorityDigest,
    /// Persistence profile commitment is unset.
    #[error("persistence profile digest must not be all zero")]
    ZeroPersistenceProfileDigest,
    /// Backend commit evidence is unset.
    #[error("commit evidence digest must not be all zero")]
    ZeroCommitEvidenceDigest,
    /// Authority domain is unset.
    #[error("authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Authority epoch commitment is unset.
    #[error("authority epoch digest must not be all zero")]
    ZeroAuthorityEpochDigest,
    /// Arm authority digest is unset.
    #[error("effect-arm authority digest must not be all zero")]
    ZeroEffectArmAuthorityDigest,
    /// Admission persistence proof digest is unset.
    #[error("admission persistence proof digest must not be all zero")]
    ZeroAdmissionPersistenceProofDigest,
    /// Durable EffectArmed receipt commitment is unset.
    #[error("effect-armed receipt digest must not be all zero")]
    ZeroEffectArmedReceiptDigest,
    /// Operation identity differs across the proof chain.
    #[error("operation id mismatch across persistence proof chain")]
    OperationIdMismatch,
    /// Admission authority predecessor differs.
    #[error("admission authority digest mismatch")]
    AdmissionAuthorityDigestMismatch,
    /// Store authority predecessor differs.
    #[error("store authority digest mismatch")]
    StoreAuthorityDigestMismatch,
    /// Arm authority predecessor differs.
    #[error("effect-arm authority digest mismatch")]
    EffectArmAuthorityDigestMismatch,
    /// Admission proof predecessor differs.
    #[error("admission persistence proof digest mismatch")]
    AdmissionPersistenceProofDigestMismatch,
    /// Authenticated backend identity differs from the proof.
    #[error("authenticated persistence backend does not match proof")]
    BackendAuthorityMismatch,
    /// Authenticated persistence profile differs from the proof.
    #[error("authenticated persistence profile does not match proof")]
    PersistenceProfileMismatch,
    /// Authenticated commit evidence differs from the proof.
    #[error("authenticated commit evidence does not match proof")]
    CommitEvidenceMismatch,
    /// Persistence timestamp predates the authority epoch.
    #[error("persistence evidence predates current authority epoch")]
    PersistencePredatesEpoch,
    /// Later persistence evidence timestamp moved backward.
    #[error("persistence evidence timestamp regressed")]
    PersistenceTimestampRegression,
    /// Authority V2 validation failed.
    #[error(transparent)]
    AuthorityV2(#[from] AuthorityV2Error),
    /// Authority epoch validation failed.
    #[error(transparent)]
    Epoch(#[from] AuthorityEpochError),
    /// Canonical encoding failed.
    #[error("failed to encode persistence proof v2: {0}")]
    Encoding(#[from] bincode::Error),
}

fn validate_authenticated_context(
    proof: &AdmissionPersistenceProofV2,
    authenticated: AuthenticatedPersistenceContextV2,
) -> Result<(), PersistenceProofV2Error> {
    if proof.backend_authority_digest != authenticated.backend_authority_digest {
        return Err(PersistenceProofV2Error::BackendAuthorityMismatch);
    }
    if proof.persistence_profile_digest != authenticated.persistence_profile_digest {
        return Err(PersistenceProofV2Error::PersistenceProfileMismatch);
    }
    if proof.commit_evidence_digest != authenticated.commit_evidence_digest {
        return Err(PersistenceProofV2Error::CommitEvidenceMismatch);
    }
    Ok(())
}

fn validate_authenticated_context_effect(
    proof: &EffectArmedPersistenceProofV2,
    authenticated: AuthenticatedPersistenceContextV2,
) -> Result<(), PersistenceProofV2Error> {
    if proof.backend_authority_digest != authenticated.backend_authority_digest {
        return Err(PersistenceProofV2Error::BackendAuthorityMismatch);
    }
    if proof.persistence_profile_digest != authenticated.persistence_profile_digest {
        return Err(PersistenceProofV2Error::PersistenceProfileMismatch);
    }
    if proof.commit_evidence_digest != authenticated.commit_evidence_digest {
        return Err(PersistenceProofV2Error::CommitEvidenceMismatch);
    }
    Ok(())
}

fn validate_epoch_binding_syntax(
    binding: &AuthorityEpochBindingV1,
) -> Result<(), PersistenceProofV2Error> {
    if binding.authority_domain_id == [0u8; 16] {
        return Err(PersistenceProofV2Error::ZeroAuthorityDomainId);
    }
    require_nonzero(
        binding.authority_epoch_digest,
        PersistenceProofV2Error::ZeroAuthorityEpochDigest,
    )
}

fn require_operation(operation_id: [u8; 16]) -> Result<(), PersistenceProofV2Error> {
    if operation_id == [0u8; 16] {
        Err(PersistenceProofV2Error::ZeroOperationId)
    } else {
        Ok(())
    }
}

fn require_nonzero(
    value: [u8; 32],
    error: PersistenceProofV2Error,
) -> Result<(), PersistenceProofV2Error> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operation_authority_epoch::{
        AuthorityEpochReasonV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1,
    };
    use xenia_operation_authority_v2::{
        AdmissionAuthorityV2, AuthenticatedIssuanceContextV2, GrantAuthorityV2,
        UseAuthorityV2,
    };

    fn epoch() -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
            authority_domain_id: [1; 16],
            epoch_id: [2; 16],
            epoch_sequence: 0,
            previous_epoch_digest: [0; 32],
            store_id: [3; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::Genesis,
            established_at_unix_ms: 1_000,
        }
    }

    fn issuance() -> AuthenticatedIssuanceContextV2 {
        AuthenticatedIssuanceContextV2 {
            issuer_authority_digest: [0xA1; 32],
            issuance_evidence_digest: [0xA2; 32],
        }
    }

    fn persistence(commit_byte: u8) -> AuthenticatedPersistenceContextV2 {
        AuthenticatedPersistenceContextV2 {
            backend_authority_digest: [0xB1; 32],
            persistence_profile_digest: [0xB2; 32],
            commit_evidence_digest: [commit_byte; 32],
        }
    }

    fn authority_chain(
        current: &OperationAuthorityEpochV1,
    ) -> (AdmissionAuthorityV2, StoreAuthorityV2, EffectArmAuthorityV2) {
        let issue = issuance();
        let grant = GrantAuthorityV2::new([0x11; 32], current, issue, 1_100).unwrap();
        let use_authority =
            UseAuthorityV2::new([0x22; 16], [0x33; 32], &grant, current, issue).unwrap();
        let admission = AdmissionAuthorityV2::new(
            [0x44; 32],
            &use_authority,
            &grant,
            current,
            issue,
        )
        .unwrap();
        let store = StoreAuthorityV2::from_epoch(current).unwrap();
        let arm = EffectArmAuthorityV2::new([0x55; 32], &admission, &store, current).unwrap();
        (admission, store, arm)
    }

    #[test]
    fn admission_proof_requires_exact_authenticated_commit() {
        let current = epoch();
        let (admission, store, _) = authority_chain(&current);
        let proof = AdmissionPersistenceProofV2::new(
            &admission,
            &store,
            &current,
            7,
            [0x61; 32],
            [0x62; 32],
            persistence(0x63),
            1_200,
        )
        .unwrap();
        proof
            .validate_against(&admission, &store, &current, persistence(0x63))
            .unwrap();
        assert!(matches!(
            proof.validate_against(&admission, &store, &current, persistence(0x64)),
            Err(PersistenceProofV2Error::CommitEvidenceMismatch)
        ));
    }

    #[test]
    fn effect_armed_proof_chains_admission_and_write_ahead_commit() {
        let current = epoch();
        let (admission, store, arm) = authority_chain(&current);
        let admission_proof = AdmissionPersistenceProofV2::new(
            &admission,
            &store,
            &current,
            7,
            [0x61; 32],
            [0x62; 32],
            persistence(0x63),
            1_200,
        )
        .unwrap();
        let armed_proof = EffectArmedPersistenceProofV2::new(
            &arm,
            &admission_proof,
            &store,
            &current,
            [0x71; 32],
            [0x72; 32],
            persistence(0x73),
            1_300,
        )
        .unwrap();
        armed_proof
            .validate_final_gate(
                &arm,
                &admission_proof,
                &store,
                &current,
                persistence(0x73),
            )
            .unwrap();
    }

    #[test]
    fn fabricated_in_memory_admission_does_not_match_store_proof() {
        let current = epoch();
        let (admission, store, _) = authority_chain(&current);
        let proof = AdmissionPersistenceProofV2::new(
            &admission,
            &store,
            &current,
            7,
            [0x61; 32],
            [0x62; 32],
            persistence(0x63),
            1_200,
        )
        .unwrap();
        let mut fabricated = admission.clone();
        fabricated.raw_admission_digest[0] ^= 1;
        assert!(matches!(
            proof.validate_against(&fabricated, &store, &current, persistence(0x63)),
            Err(PersistenceProofV2Error::AdmissionAuthorityDigestMismatch)
        ));
    }

    #[test]
    fn final_gate_rejects_wrong_effect_commit_evidence() {
        let current = epoch();
        let (admission, store, arm) = authority_chain(&current);
        let admission_proof = AdmissionPersistenceProofV2::new(
            &admission,
            &store,
            &current,
            7,
            [0x61; 32],
            [0x62; 32],
            persistence(0x63),
            1_200,
        )
        .unwrap();
        let armed_proof = EffectArmedPersistenceProofV2::new(
            &arm,
            &admission_proof,
            &store,
            &current,
            [0x71; 32],
            [0x72; 32],
            persistence(0x73),
            1_300,
        )
        .unwrap();
        assert!(matches!(
            armed_proof.validate_final_gate(
                &arm,
                &admission_proof,
                &store,
                &current,
                persistence(0x74),
            ),
            Err(PersistenceProofV2Error::CommitEvidenceMismatch)
        ));
    }
}
