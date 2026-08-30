// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! End-to-end operation-authority epoch binding for durable admission and effect arming.
//!
//! The existing grant/use, admission, and effect-arm contracts were developed in ordered
//! draft tranches. Rather than silently rewriting every earlier serialized V1 record while
//! qualification is still queued, this contract composes their exact commitments into an
//! explicit authority chain rooted in the current [`OperationAuthorityEpochV1`].
//!
//! Recovery-capable runtimes must treat the raw predecessor commitments as insufficient on
//! their own. Each downstream stage validates the live authority epoch and the exact bound
//! predecessor before it may advance.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_envelope::{
    AuthorityEnvelopeError, EpochBoundGrantV1, EpochBoundUseV1,
};
use xenia_operation_authority_epoch::{
    AuthorityEpochBindingV1, AuthorityEpochError, OperationAuthorityEpochV1,
};

/// Exact schema label for [`EpochBoundAdmissionV1`].
pub const EPOCH_BOUND_ADMISSION_SCHEMA_V1: &str = "xenia-epoch-bound-operation-admission-v1";
/// Exact schema label for [`EpochBoundArmV1`].
pub const EPOCH_BOUND_ARM_SCHEMA_V1: &str = "xenia-epoch-bound-effect-arm-v1";
/// Exact schema label for [`StoreAuthorityBindingV1`].
pub const STORE_AUTHORITY_BINDING_SCHEMA_V1: &str = "xenia-operation-store-authority-binding-v1";
/// Domain separator for epoch-bound admission commitments.
pub const EPOCH_BOUND_ADMISSION_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-epoch-bound-operation-admission-digest-v1";
/// Domain separator for epoch-bound arm commitments.
pub const EPOCH_BOUND_ARM_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-epoch-bound-effect-arm-digest-v1";
/// Domain separator for persistent store-authority binding commitments.
pub const STORE_AUTHORITY_BINDING_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-store-authority-binding-digest-v1";

/// Durable-admission commitment bound to the exact epoch-bound operation use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBoundAdmissionV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Exact operation id being admitted.
    pub operation_id: [u8; 16],
    /// Commitment to the existing immutable admission record.
    pub raw_admission_digest: [u8; 32],
    /// Commitment to the exact epoch-bound use authorized for admission.
    pub epoch_bound_use_digest: [u8; 32],
    /// Exact authority epoch serving this admission.
    pub authority_epoch: AuthorityEpochBindingV1,
}

impl EpochBoundAdmissionV1 {
    /// Construct a durable-admission authority binding from an already-validated raw admission.
    pub fn new(
        raw_admission_digest: [u8; 32],
        use_envelope: &EpochBoundUseV1,
        grant_envelope: &EpochBoundGrantV1,
        current: &OperationAuthorityEpochV1,
    ) -> Result<Self, AuthorityChainError> {
        use_envelope.validate_against(grant_envelope, current)?;
        require_nonzero(
            raw_admission_digest,
            AuthorityChainError::ZeroRawAdmissionDigest,
        )?;
        let value = Self {
            schema: EPOCH_BOUND_ADMISSION_SCHEMA_V1.to_string(),
            operation_id: use_envelope.operation_id,
            raw_admission_digest,
            epoch_bound_use_digest: use_envelope.epoch_bound_use_digest()?,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax independent of current epoch state.
    pub fn validate(&self) -> Result<(), AuthorityChainError> {
        if self.schema != EPOCH_BOUND_ADMISSION_SCHEMA_V1 {
            return Err(AuthorityChainError::UnsupportedAdmissionSchema);
        }
        require_nonzero_operation(self.operation_id)?;
        require_nonzero(
            self.raw_admission_digest,
            AuthorityChainError::ZeroRawAdmissionDigest,
        )?;
        require_nonzero(
            self.epoch_bound_use_digest,
            AuthorityChainError::ZeroEpochBoundUseDigest,
        )?;
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        Ok(())
    }

    /// Validate against the exact predecessor use/grant envelopes and live authority epoch.
    pub fn validate_against(
        &self,
        use_envelope: &EpochBoundUseV1,
        grant_envelope: &EpochBoundGrantV1,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityChainError> {
        self.validate()?;
        use_envelope.validate_against(grant_envelope, current)?;
        self.authority_epoch.validate_against(current)?;
        if self.operation_id != use_envelope.operation_id {
            return Err(AuthorityChainError::OperationIdMismatch);
        }
        if self.epoch_bound_use_digest != use_envelope.epoch_bound_use_digest()? {
            return Err(AuthorityChainError::EpochBoundUseDigestMismatch);
        }
        Ok(())
    }

    /// Deterministic canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityChainError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable commitment consumed by the effect-arm authority chain.
    pub fn epoch_bound_admission_digest(&self) -> Result<[u8; 32], AuthorityChainError> {
        Ok(domain_digest(
            EPOCH_BOUND_ADMISSION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Fresh effect-arm commitment bound to the exact epoch-bound admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBoundArmV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Exact operation being armed.
    pub operation_id: [u8; 16],
    /// Commitment to the existing fresh effect-arm authorization record.
    pub raw_arm_authorization_digest: [u8; 32],
    /// Commitment to the exact epoch-bound admission being armed.
    pub epoch_bound_admission_digest: [u8; 32],
    /// Exact current authority epoch at arm time.
    pub authority_epoch: AuthorityEpochBindingV1,
}

impl EpochBoundArmV1 {
    /// Construct a fresh arm binding after the raw arm authorization has passed its own checks.
    pub fn new(
        raw_arm_authorization_digest: [u8; 32],
        admission: &EpochBoundAdmissionV1,
        current: &OperationAuthorityEpochV1,
    ) -> Result<Self, AuthorityChainError> {
        admission.validate()?;
        admission.authority_epoch.validate_against(current)?;
        require_nonzero(
            raw_arm_authorization_digest,
            AuthorityChainError::ZeroRawArmAuthorizationDigest,
        )?;
        let value = Self {
            schema: EPOCH_BOUND_ARM_SCHEMA_V1.to_string(),
            operation_id: admission.operation_id,
            raw_arm_authorization_digest,
            epoch_bound_admission_digest: admission.epoch_bound_admission_digest()?,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax independent of current epoch state.
    pub fn validate(&self) -> Result<(), AuthorityChainError> {
        if self.schema != EPOCH_BOUND_ARM_SCHEMA_V1 {
            return Err(AuthorityChainError::UnsupportedArmSchema);
        }
        require_nonzero_operation(self.operation_id)?;
        require_nonzero(
            self.raw_arm_authorization_digest,
            AuthorityChainError::ZeroRawArmAuthorizationDigest,
        )?;
        require_nonzero(
            self.epoch_bound_admission_digest,
            AuthorityChainError::ZeroEpochBoundAdmissionDigest,
        )?;
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        Ok(())
    }

    /// Validate the arm against its exact admission and live authority epoch.
    pub fn validate_against(
        &self,
        admission: &EpochBoundAdmissionV1,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityChainError> {
        self.validate()?;
        admission.validate()?;
        self.authority_epoch.validate_against(current)?;
        admission.authority_epoch.validate_against(current)?;
        if self.operation_id != admission.operation_id {
            return Err(AuthorityChainError::OperationIdMismatch);
        }
        if self.epoch_bound_admission_digest != admission.epoch_bound_admission_digest()? {
            return Err(AuthorityChainError::EpochBoundAdmissionDigestMismatch);
        }
        Ok(())
    }

    /// Deterministic canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityChainError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable authority commitment consumed by the final live effect gate/receipt evidence.
    pub fn epoch_bound_arm_digest(&self) -> Result<[u8; 32], AuthorityChainError> {
        Ok(domain_digest(
            EPOCH_BOUND_ARM_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Persistent binding between one receipt-store identity/generation and the authority epoch it serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreAuthorityBindingV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Exact receipt-store identity.
    pub store_id: [u8; 16],
    /// Exact receipt-store generation.
    pub store_generation: u64,
    /// Exact authority epoch allowed to spend against this store state.
    pub authority_epoch: AuthorityEpochBindingV1,
}

impl StoreAuthorityBindingV1 {
    /// Construct the exact persistent store binding for a current authority epoch.
    pub fn from_epoch(current: &OperationAuthorityEpochV1) -> Result<Self, AuthorityChainError> {
        current.validate()?;
        let value = Self {
            schema: STORE_AUTHORITY_BINDING_SCHEMA_V1.to_string(),
            store_id: current.store_id,
            store_generation: current.store_generation,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(current)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax.
    pub fn validate(&self) -> Result<(), AuthorityChainError> {
        if self.schema != STORE_AUTHORITY_BINDING_SCHEMA_V1 {
            return Err(AuthorityChainError::UnsupportedStoreBindingSchema);
        }
        if self.store_id == [0u8; 16] {
            return Err(AuthorityChainError::ZeroStoreId);
        }
        validate_epoch_binding_syntax(&self.authority_epoch)?;
        Ok(())
    }

    /// Require this persisted binding to match the exact current authority epoch and store generation.
    pub fn validate_against(
        &self,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityChainError> {
        self.validate()?;
        current.validate()?;
        self.authority_epoch.validate_against(current)?;
        if self.store_id != current.store_id || self.store_generation != current.store_generation {
            return Err(AuthorityChainError::StoreBindingMismatch);
        }
        Ok(())
    }

    /// Deterministic canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityChainError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable persistent store-authority commitment.
    pub fn binding_digest(&self) -> Result<[u8; 32], AuthorityChainError> {
        Ok(domain_digest(
            STORE_AUTHORITY_BINDING_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// End-to-end authority-chain validation failure.
#[derive(Debug, Error)]
pub enum AuthorityChainError {
    /// Admission wrapper schema mismatch.
    #[error("unsupported epoch-bound admission schema")]
    UnsupportedAdmissionSchema,
    /// Arm wrapper schema mismatch.
    #[error("unsupported epoch-bound arm schema")]
    UnsupportedArmSchema,
    /// Store binding schema mismatch.
    #[error("unsupported operation-store authority binding schema")]
    UnsupportedStoreBindingSchema,
    /// Operation id is unset.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Existing admission commitment is unset.
    #[error("raw admission digest must not be all zero")]
    ZeroRawAdmissionDigest,
    /// Existing arm-authorization commitment is unset.
    #[error("raw arm authorization digest must not be all zero")]
    ZeroRawArmAuthorizationDigest,
    /// Bound use commitment is unset.
    #[error("epoch-bound use digest must not be all zero")]
    ZeroEpochBoundUseDigest,
    /// Bound admission commitment is unset.
    #[error("epoch-bound admission digest must not be all zero")]
    ZeroEpochBoundAdmissionDigest,
    /// Authority domain id is unset.
    #[error("authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Authority epoch commitment is unset.
    #[error("authority epoch digest must not be all zero")]
    ZeroAuthorityEpochDigest,
    /// Receipt store identity is unset.
    #[error("receipt store id must not be all zero")]
    ZeroStoreId,
    /// Operation id differs from predecessor binding.
    #[error("operation id differs from bound predecessor")]
    OperationIdMismatch,
    /// Admission names a different bound use.
    #[error("epoch-bound use digest mismatch")]
    EpochBoundUseDigestMismatch,
    /// Arm names a different bound admission.
    #[error("epoch-bound admission digest mismatch")]
    EpochBoundAdmissionDigestMismatch,
    /// Persisted store id/generation differs from the current authority epoch.
    #[error("operation-store authority binding mismatch")]
    StoreBindingMismatch,
    /// Grant/use envelope validation failed.
    #[error(transparent)]
    Envelope(#[from] AuthorityEnvelopeError),
    /// Authority-epoch validation failed.
    #[error(transparent)]
    AuthorityEpoch(#[from] AuthorityEpochError),
    /// Deterministic serialization failed.
    #[error("failed to encode authority-chain record: {0}")]
    Encoding(#[from] bincode::Error),
}

fn validate_epoch_binding_syntax(
    binding: &AuthorityEpochBindingV1,
) -> Result<(), AuthorityChainError> {
    if binding.authority_domain_id == [0u8; 16] {
        return Err(AuthorityChainError::ZeroAuthorityDomainId);
    }
    require_nonzero(
        binding.authority_epoch_digest,
        AuthorityChainError::ZeroAuthorityEpochDigest,
    )
}

fn require_nonzero(value: [u8; 32], error: AuthorityChainError) -> Result<(), AuthorityChainError> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn require_nonzero_operation(operation_id: [u8; 16]) -> Result<(), AuthorityChainError> {
    if operation_id == [0u8; 16] {
        Err(AuthorityChainError::ZeroOperationId)
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

    fn genesis() -> OperationAuthorityEpochV1 {
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

    fn revoked(previous: &OperationAuthorityEpochV1) -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
            authority_domain_id: previous.authority_domain_id,
            epoch_id: [4; 16],
            epoch_sequence: previous.epoch_sequence + 1,
            previous_epoch_digest: previous.epoch_digest().unwrap(),
            store_id: previous.store_id,
            store_generation: previous.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: [0x90; 32],
            },
            established_at_unix_ms: 2_000,
        }
    }

    fn envelopes(
        epoch: &OperationAuthorityEpochV1,
    ) -> (EpochBoundGrantV1, EpochBoundUseV1) {
        let grant = EpochBoundGrantV1::new([0x11; 32], epoch).unwrap();
        let use_envelope = EpochBoundUseV1::new([0x22; 16], [0x33; 32], &grant, epoch).unwrap();
        (grant, use_envelope)
    }

    #[test]
    fn admission_chains_exact_use_and_epoch() {
        let epoch = genesis();
        let (grant, use_envelope) = envelopes(&epoch);
        let admission = EpochBoundAdmissionV1::new(
            [0x44; 32],
            &use_envelope,
            &grant,
            &epoch,
        )
        .unwrap();
        admission
            .validate_against(&use_envelope, &grant, &epoch)
            .unwrap();
        assert_ne!(admission.epoch_bound_admission_digest().unwrap(), [0; 32]);
    }

    #[test]
    fn arm_chains_exact_admission_and_epoch() {
        let epoch = genesis();
        let (grant, use_envelope) = envelopes(&epoch);
        let admission = EpochBoundAdmissionV1::new(
            [0x44; 32],
            &use_envelope,
            &grant,
            &epoch,
        )
        .unwrap();
        let arm = EpochBoundArmV1::new([0x55; 32], &admission, &epoch).unwrap();
        arm.validate_against(&admission, &epoch).unwrap();
        assert_ne!(arm.epoch_bound_arm_digest().unwrap(), [0; 32]);
    }

    #[test]
    fn global_revocation_stales_admission_and_arm() {
        let epoch = genesis();
        let (grant, use_envelope) = envelopes(&epoch);
        let admission = EpochBoundAdmissionV1::new(
            [0x44; 32],
            &use_envelope,
            &grant,
            &epoch,
        )
        .unwrap();
        let arm = EpochBoundArmV1::new([0x55; 32], &admission, &epoch).unwrap();
        let next = revoked(&epoch);
        next.validate_successor(&epoch).unwrap();

        assert!(admission
            .validate_against(&use_envelope, &grant, &next)
            .is_err());
        assert!(arm.validate_against(&admission, &next).is_err());
    }

    #[test]
    fn store_binding_tracks_exact_generation_and_epoch() {
        let epoch = genesis();
        let binding = StoreAuthorityBindingV1::from_epoch(&epoch).unwrap();
        binding.validate_against(&epoch).unwrap();

        let next = revoked(&epoch);
        assert!(binding.validate_against(&next).is_err());
    }

    #[test]
    fn predecessor_tampering_is_rejected() {
        let epoch = genesis();
        let (grant, use_envelope) = envelopes(&epoch);
        let admission = EpochBoundAdmissionV1::new(
            [0x44; 32],
            &use_envelope,
            &grant,
            &epoch,
        )
        .unwrap();
        let mut tampered = admission.clone();
        tampered.epoch_bound_use_digest[0] ^= 1;
        assert!(matches!(
            tampered.validate_against(&use_envelope, &grant, &epoch),
            Err(AuthorityChainError::EpochBoundUseDigestMismatch)
        ));
    }
}
