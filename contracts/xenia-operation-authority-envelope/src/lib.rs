// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Epoch-bound authority envelopes for Xenia privileged operations.
//!
//! The earlier privileged-operation grant/use contracts were drafted before
//! governed receipt-store recovery introduced an operation-authority epoch.
//! Rather than silently changing those draft serialized bytes in-place, this
//! contract composes their exact existing commitments with the current
//! [`AuthorityEpochBindingV1`].
//!
//! A recovery-capable runtime must not treat a raw grant digest or raw use
//! digest as sufficient authority for durable admission. It must first validate
//! the underlying grant/use contract and then validate these envelopes against
//! the live authority epoch.
//!
//! These records are evidence/binding objects, not bearer credentials.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_epoch::{
    AuthorityEpochBindingV1, AuthorityEpochError, OperationAuthorityEpochV1,
};

/// Exact schema label for [`EpochBoundGrantV1`].
pub const EPOCH_BOUND_GRANT_SCHEMA_V1: &str = "xenia-epoch-bound-operation-grant-v1";
/// Exact schema label for [`EpochBoundUseV1`].
pub const EPOCH_BOUND_USE_SCHEMA_V1: &str = "xenia-epoch-bound-operation-use-v1";
/// Domain separator for epoch-bound grant commitments.
pub const EPOCH_BOUND_GRANT_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-epoch-bound-operation-grant-digest-v1";
/// Domain separator for epoch-bound use commitments.
pub const EPOCH_BOUND_USE_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-epoch-bound-operation-use-digest-v1";

/// Existing operation-grant commitment composed with one exact authority epoch.
///
/// `raw_grant_digest` is expected to be the validated digest produced by the
/// existing `CapabilityGrantV1`. This crate deliberately does not reimplement
/// grant semantics; it adds the recovery/global-revocation binding layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBoundGrantV1 {
    /// Exact V1 envelope schema.
    pub schema: String,
    /// Exact commitment to the already-validated underlying grant bytes.
    pub raw_grant_digest: [u8; 32],
    /// Exact operation-authority epoch in which this grant was issued.
    pub authority_epoch: AuthorityEpochBindingV1,
}

impl EpochBoundGrantV1 {
    /// Construct an envelope for an already-validated raw grant commitment.
    pub fn new(
        raw_grant_digest: [u8; 32],
        epoch: &OperationAuthorityEpochV1,
    ) -> Result<Self, AuthorityEnvelopeError> {
        require_nonzero(
            raw_grant_digest,
            AuthorityEnvelopeError::ZeroRawGrantDigest,
        )?;
        let value = Self {
            schema: EPOCH_BOUND_GRANT_SCHEMA_V1.to_string(),
            raw_grant_digest,
            authority_epoch: AuthorityEpochBindingV1::from_epoch(epoch)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax independent of the current authority epoch.
    pub fn validate(&self) -> Result<(), AuthorityEnvelopeError> {
        if self.schema != EPOCH_BOUND_GRANT_SCHEMA_V1 {
            return Err(AuthorityEnvelopeError::UnsupportedGrantEnvelopeSchema);
        }
        require_nonzero(
            self.raw_grant_digest,
            AuthorityEnvelopeError::ZeroRawGrantDigest,
        )?;
        require_nonzero_domain(self.authority_epoch.authority_domain_id)?;
        require_nonzero(
            self.authority_epoch.authority_epoch_digest,
            AuthorityEnvelopeError::ZeroAuthorityEpochDigest,
        )?;
        Ok(())
    }

    /// Require this grant envelope to belong to the exact current authority epoch.
    pub fn validate_against(
        &self,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityEnvelopeError> {
        self.validate()?;
        self.authority_epoch.validate_against(current)?;
        Ok(())
    }

    /// Deterministic canonical envelope bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityEnvelopeError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Commitment used by all recovery-capable downstream authority records.
    pub fn epoch_bound_grant_digest(&self) -> Result<[u8; 32], AuthorityEnvelopeError> {
        Ok(domain_digest(
            EPOCH_BOUND_GRANT_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Existing operation-use commitment bound to the exact epoch-bound grant.
///
/// The underlying `CapabilityUseV1` must still be validated against its raw
/// grant and live session/subject/use counter. This envelope is the additional
/// authority-continuity object consumed by durable admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBoundUseV1 {
    /// Exact V1 envelope schema.
    pub schema: String,
    /// Exact operation id from the validated underlying use record.
    pub operation_id: [u8; 16],
    /// Exact commitment to the validated underlying use record.
    pub raw_use_digest: [u8; 32],
    /// Exact commitment to the epoch-bound grant envelope.
    pub epoch_bound_grant_digest: [u8; 32],
}

impl EpochBoundUseV1 {
    /// Construct a use envelope for an already-validated raw use commitment.
    pub fn new(
        operation_id: [u8; 16],
        raw_use_digest: [u8; 32],
        grant: &EpochBoundGrantV1,
        current: &OperationAuthorityEpochV1,
    ) -> Result<Self, AuthorityEnvelopeError> {
        grant.validate_against(current)?;
        require_nonzero_operation(operation_id)?;
        require_nonzero(raw_use_digest, AuthorityEnvelopeError::ZeroRawUseDigest)?;
        let value = Self {
            schema: EPOCH_BOUND_USE_SCHEMA_V1.to_string(),
            operation_id,
            raw_use_digest,
            epoch_bound_grant_digest: grant.epoch_bound_grant_digest()?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax independent of current epoch state.
    pub fn validate(&self) -> Result<(), AuthorityEnvelopeError> {
        if self.schema != EPOCH_BOUND_USE_SCHEMA_V1 {
            return Err(AuthorityEnvelopeError::UnsupportedUseEnvelopeSchema);
        }
        require_nonzero_operation(self.operation_id)?;
        require_nonzero(self.raw_use_digest, AuthorityEnvelopeError::ZeroRawUseDigest)?;
        require_nonzero(
            self.epoch_bound_grant_digest,
            AuthorityEnvelopeError::ZeroEpochBoundGrantDigest,
        )?;
        Ok(())
    }

    /// Validate against the exact grant envelope and live authority epoch.
    pub fn validate_against(
        &self,
        grant: &EpochBoundGrantV1,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityEnvelopeError> {
        self.validate()?;
        grant.validate_against(current)?;
        if self.epoch_bound_grant_digest != grant.epoch_bound_grant_digest()? {
            return Err(AuthorityEnvelopeError::EpochBoundGrantDigestMismatch);
        }
        Ok(())
    }

    /// Deterministic canonical use-envelope bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityEnvelopeError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable authority commitment that durable admission should bind.
    pub fn epoch_bound_use_digest(&self) -> Result<[u8; 32], AuthorityEnvelopeError> {
        Ok(domain_digest(
            EPOCH_BOUND_USE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Authority-envelope validation failure.
#[derive(Debug, Error)]
pub enum AuthorityEnvelopeError {
    /// Grant-envelope schema is not exact V1.
    #[error("unsupported epoch-bound grant schema")]
    UnsupportedGrantEnvelopeSchema,
    /// Use-envelope schema is not exact V1.
    #[error("unsupported epoch-bound use schema")]
    UnsupportedUseEnvelopeSchema,
    /// Raw grant commitment is unset.
    #[error("raw operation-grant digest must not be all zero")]
    ZeroRawGrantDigest,
    /// Raw use commitment is unset.
    #[error("raw operation-use digest must not be all zero")]
    ZeroRawUseDigest,
    /// Operation id is unset.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Authority domain is unset.
    #[error("authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Authority epoch commitment is unset.
    #[error("authority epoch digest must not be all zero")]
    ZeroAuthorityEpochDigest,
    /// Epoch-bound grant commitment is unset.
    #[error("epoch-bound grant digest must not be all zero")]
    ZeroEpochBoundGrantDigest,
    /// Use envelope names a different epoch-bound grant.
    #[error("epoch-bound operation-use grant digest mismatch")]
    EpochBoundGrantDigestMismatch,
    /// Authority-epoch validation failed.
    #[error(transparent)]
    AuthorityEpoch(#[from] AuthorityEpochError),
    /// Deterministic serialization failed.
    #[error("failed to encode authority envelope: {0}")]
    Encoding(#[from] bincode::Error),
}

fn require_nonzero(
    value: [u8; 32],
    error: AuthorityEnvelopeError,
) -> Result<(), AuthorityEnvelopeError> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn require_nonzero_domain(value: [u8; 16]) -> Result<(), AuthorityEnvelopeError> {
    if value == [0u8; 16] {
        Err(AuthorityEnvelopeError::ZeroAuthorityDomainId)
    } else {
        Ok(())
    }
}

fn require_nonzero_operation(value: [u8; 16]) -> Result<(), AuthorityEnvelopeError> {
    if value == [0u8; 16] {
        Err(AuthorityEnvelopeError::ZeroOperationId)
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
    use xenia_operation_authority_epoch::{AuthorityEpochReasonV1, OperationAuthorityEpochV1};

    fn genesis() -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: xenia_operation_authority_epoch::OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
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
            schema: xenia_operation_authority_epoch::OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
            authority_domain_id: previous.authority_domain_id,
            epoch_id: [4; 16],
            epoch_sequence: 1,
            previous_epoch_digest: previous.epoch_digest().unwrap(),
            store_id: previous.store_id,
            store_generation: previous.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: [9; 32],
            },
            established_at_unix_ms: 2_000,
        }
    }

    #[test]
    fn raw_grant_is_bound_to_exact_current_epoch() {
        let epoch = genesis();
        let bound = EpochBoundGrantV1::new([0x11; 32], &epoch).unwrap();
        bound.validate_against(&epoch).unwrap();
        assert_ne!(bound.epoch_bound_grant_digest().unwrap(), [0; 32]);
    }

    #[test]
    fn global_revocation_invalidates_old_bound_grant() {
        let epoch = genesis();
        let bound = EpochBoundGrantV1::new([0x11; 32], &epoch).unwrap();
        let next = revoked(&epoch);
        next.validate_successor(&epoch).unwrap();
        assert!(matches!(
            bound.validate_against(&next),
            Err(AuthorityEnvelopeError::AuthorityEpoch(
                AuthorityEpochError::StaleAuthorityEpoch
            ))
        ));
    }

    #[test]
    fn use_envelope_commits_raw_use_and_bound_grant() {
        let epoch = genesis();
        let grant = EpochBoundGrantV1::new([0x11; 32], &epoch).unwrap();
        let use_one =
            EpochBoundUseV1::new([0x33; 16], [0x22; 32], &grant, &epoch).unwrap();
        let mut use_two = use_one.clone();
        use_two.raw_use_digest[0] ^= 1;
        assert_ne!(
            use_one.epoch_bound_use_digest().unwrap(),
            use_two.epoch_bound_use_digest().unwrap()
        );
    }

    #[test]
    fn use_rejects_different_bound_grant() {
        let epoch = genesis();
        let grant_a = EpochBoundGrantV1::new([0x11; 32], &epoch).unwrap();
        let grant_b = EpochBoundGrantV1::new([0x12; 32], &epoch).unwrap();
        let use_record =
            EpochBoundUseV1::new([0x33; 16], [0x22; 32], &grant_a, &epoch).unwrap();
        assert!(matches!(
            use_record.validate_against(&grant_b, &epoch),
            Err(AuthorityEnvelopeError::EpochBoundGrantDigestMismatch)
        ));
    }

    #[test]
    fn zero_sentinels_are_rejected() {
        let epoch = genesis();
        assert!(matches!(
            EpochBoundGrantV1::new([0; 32], &epoch),
            Err(AuthorityEnvelopeError::ZeroRawGrantDigest)
        ));
        let grant = EpochBoundGrantV1::new([1; 32], &epoch).unwrap();
        assert!(matches!(
            EpochBoundUseV1::new([0; 16], [2; 32], &grant, &epoch),
            Err(AuthorityEnvelopeError::ZeroOperationId)
        ));
    }
}
