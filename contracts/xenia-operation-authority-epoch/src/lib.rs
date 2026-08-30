// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime-free operation-authority epoch contracts for Xenia privileged operations.
//!
//! A durable operation store may be recovered, rolled to a new generation, replaced, or
//! globally invalidated. Those events must not accidentally let still-live pre-transition
//! grants spend authority against a fresh store that no longer remembers their use slots.
//!
//! This crate therefore defines a monotonic authority epoch above the receipt-store
//! generation. Capability grants, admissions, and effect-arm decisions are expected to
//! commit the exact current epoch digest before privileged-operation V1 is frozen.
//! Serialized epoch records are evidence/state commitments, not bearer credentials.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact schema label for [`OperationAuthorityEpochV1`].
pub const OPERATION_AUTHORITY_EPOCH_SCHEMA_V1: &str = "xenia-operation-authority-epoch-v1";
/// Domain separator for complete authority-epoch commitments.
pub const OPERATION_AUTHORITY_EPOCH_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-authority-epoch-digest-v1";

/// Why a new authority epoch was established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityEpochReasonV1 {
    /// First epoch for one operation-authority domain.
    Genesis,
    /// The same receipt store advanced to the exact next governed generation.
    RecoveryGenerationRollover {
        /// Commitment to the recovery decision/evidence authorizing the rollover.
        recovery_decision_digest: [u8; 32],
    },
    /// The authority domain replaced its receipt store entirely after governed recovery.
    StoreReplacement {
        /// Commitment to the recovery decision/evidence authorizing replacement.
        recovery_decision_digest: [u8; 32],
    },
    /// Invalidate all previously issued operation grants without changing store generation.
    GlobalRevocation {
        /// Commitment to the emergency/policy decision that invalidated old authority.
        revocation_decision_digest: [u8; 32],
    },
}

impl AuthorityEpochReasonV1 {
    fn validate(&self) -> Result<(), AuthorityEpochError> {
        match self {
            Self::Genesis => Ok(()),
            Self::RecoveryGenerationRollover {
                recovery_decision_digest,
            }
            | Self::StoreReplacement {
                recovery_decision_digest,
            } => require_nonzero(
                *recovery_decision_digest,
                AuthorityEpochError::ZeroTransitionDecisionDigest,
            ),
            Self::GlobalRevocation {
                revocation_decision_digest,
            } => require_nonzero(
                *revocation_decision_digest,
                AuthorityEpochError::ZeroTransitionDecisionDigest,
            ),
        }
    }
}

/// Monotonic authority epoch governing issuance and use of privileged-operation grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationAuthorityEpochV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Stable identity of the local operation-authority domain.
    pub authority_domain_id: [u8; 16],
    /// Unique identity of this authority epoch.
    pub epoch_id: [u8; 16],
    /// Monotonic zero-based epoch sequence within the authority domain.
    pub epoch_sequence: u64,
    /// Exact previous epoch commitment, or all-zero for genesis.
    pub previous_epoch_digest: [u8; 32],
    /// Receipt store currently serving this authority epoch.
    pub store_id: [u8; 16],
    /// Exact receipt-store generation currently serving this authority epoch.
    pub store_generation: u64,
    /// Governed reason for this epoch.
    pub reason: AuthorityEpochReasonV1,
    /// Trusted-enough establishment time for evidence/audit purposes.
    pub established_at_unix_ms: u64,
}

impl OperationAuthorityEpochV1 {
    /// Validate epoch-local syntax independent of predecessor state.
    pub fn validate(&self) -> Result<(), AuthorityEpochError> {
        if self.schema != OPERATION_AUTHORITY_EPOCH_SCHEMA_V1 {
            return Err(AuthorityEpochError::UnsupportedSchema);
        }
        if self.authority_domain_id == [0u8; 16] {
            return Err(AuthorityEpochError::ZeroAuthorityDomainId);
        }
        if self.epoch_id == [0u8; 16] {
            return Err(AuthorityEpochError::ZeroEpochId);
        }
        if self.store_id == [0u8; 16] {
            return Err(AuthorityEpochError::ZeroStoreId);
        }
        self.reason.validate()?;

        match (&self.reason, self.epoch_sequence) {
            (AuthorityEpochReasonV1::Genesis, 0) => {
                if self.previous_epoch_digest != [0u8; 32] {
                    return Err(AuthorityEpochError::GenesisHasPreviousDigest);
                }
            }
            (AuthorityEpochReasonV1::Genesis, _) => {
                return Err(AuthorityEpochError::NonGenesisUsesGenesisReason);
            }
            (_, 0) => return Err(AuthorityEpochError::GenesisMustUseGenesisReason),
            (_, _) if self.previous_epoch_digest == [0u8; 32] => {
                return Err(AuthorityEpochError::MissingPreviousEpochDigest);
            }
            _ => {}
        }
        Ok(())
    }

    /// Deterministic canonical bincode-v1 bytes for evidence/binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityEpochError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3-256 commitment to the complete epoch.
    pub fn epoch_digest(&self) -> Result<[u8; 32], AuthorityEpochError> {
        Ok(domain_digest(
            OPERATION_AUTHORITY_EPOCH_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    /// Validate this epoch as the exact governed successor of `previous`.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), AuthorityEpochError> {
        previous.validate()?;
        self.validate()?;

        if self.authority_domain_id != previous.authority_domain_id {
            return Err(AuthorityEpochError::AuthorityDomainMismatch);
        }
        if self.epoch_id == previous.epoch_id {
            return Err(AuthorityEpochError::EpochIdReused);
        }
        let expected_sequence = previous
            .epoch_sequence
            .checked_add(1)
            .ok_or(AuthorityEpochError::EpochSequenceOverflow)?;
        if self.epoch_sequence != expected_sequence {
            return Err(AuthorityEpochError::EpochSequenceMismatch);
        }
        if self.previous_epoch_digest != previous.epoch_digest()? {
            return Err(AuthorityEpochError::PreviousEpochDigestMismatch);
        }
        if self.established_at_unix_ms < previous.established_at_unix_ms {
            return Err(AuthorityEpochError::TimestampRegression);
        }

        match &self.reason {
            AuthorityEpochReasonV1::Genesis => {
                return Err(AuthorityEpochError::NonGenesisUsesGenesisReason);
            }
            AuthorityEpochReasonV1::RecoveryGenerationRollover { .. } => {
                if self.store_id != previous.store_id {
                    return Err(AuthorityEpochError::RolloverChangedStoreId);
                }
                let expected_generation = previous
                    .store_generation
                    .checked_add(1)
                    .ok_or(AuthorityEpochError::StoreGenerationOverflow)?;
                if self.store_generation != expected_generation {
                    return Err(AuthorityEpochError::StoreGenerationMismatch);
                }
            }
            AuthorityEpochReasonV1::StoreReplacement { .. } => {
                if self.store_id == previous.store_id {
                    return Err(AuthorityEpochError::ReplacementReusedStoreId);
                }
                if self.store_generation != 0 {
                    return Err(AuthorityEpochError::ReplacementMustStartGenerationZero);
                }
            }
            AuthorityEpochReasonV1::GlobalRevocation { .. } => {
                if self.store_id != previous.store_id
                    || self.store_generation != previous.store_generation
                {
                    return Err(AuthorityEpochError::RevocationChangedStoreBinding);
                }
            }
        }
        Ok(())
    }
}

/// Compact binding embedded into a grant/admission/arm decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityEpochBindingV1 {
    /// Exact authority domain.
    pub authority_domain_id: [u8; 16],
    /// Exact current [`OperationAuthorityEpochV1`] commitment.
    pub authority_epoch_digest: [u8; 32],
}

impl AuthorityEpochBindingV1 {
    /// Construct the exact binding for `epoch`.
    pub fn from_epoch(epoch: &OperationAuthorityEpochV1) -> Result<Self, AuthorityEpochError> {
        epoch.validate()?;
        Ok(Self {
            authority_domain_id: epoch.authority_domain_id,
            authority_epoch_digest: epoch.epoch_digest()?,
        })
    }

    /// Require this binding to match the current epoch exactly.
    pub fn validate_against(
        &self,
        current: &OperationAuthorityEpochV1,
    ) -> Result<(), AuthorityEpochError> {
        current.validate()?;
        if self.authority_domain_id != current.authority_domain_id {
            return Err(AuthorityEpochError::AuthorityDomainMismatch);
        }
        if self.authority_epoch_digest != current.epoch_digest()? {
            return Err(AuthorityEpochError::StaleAuthorityEpoch);
        }
        Ok(())
    }
}

/// Validate a retained authority-epoch history in exact successor order.
pub fn validate_epoch_chain(epochs: &[OperationAuthorityEpochV1]) -> Result<(), AuthorityEpochError> {
    let Some(first) = epochs.first() else {
        return Ok(());
    };
    first.validate()?;
    if first.epoch_sequence != 0 || !matches!(first.reason, AuthorityEpochReasonV1::Genesis) {
        return Err(AuthorityEpochError::ChainDoesNotBeginAtGenesis);
    }
    for pair in epochs.windows(2) {
        pair[1].validate_successor(&pair[0])?;
    }
    Ok(())
}

/// Authority-epoch contract failure.
#[derive(Debug, Error)]
pub enum AuthorityEpochError {
    /// Schema is not the exact V1 schema.
    #[error("unsupported operation authority epoch schema")]
    UnsupportedSchema,
    /// Authority domain id is unset.
    #[error("authority domain id must not be all zero")]
    ZeroAuthorityDomainId,
    /// Epoch id is unset.
    #[error("authority epoch id must not be all zero")]
    ZeroEpochId,
    /// Receipt store id is unset.
    #[error("receipt store id must not be all zero")]
    ZeroStoreId,
    /// Transition decision commitment is unset.
    #[error("authority epoch transition requires a non-zero decision digest")]
    ZeroTransitionDecisionDigest,
    /// Genesis unexpectedly names a predecessor.
    #[error("genesis authority epoch must not have a previous digest")]
    GenesisHasPreviousDigest,
    /// Sequence zero must use the genesis reason.
    #[error("authority epoch sequence zero must use Genesis")]
    GenesisMustUseGenesisReason,
    /// A nonzero sequence attempted to use the Genesis reason.
    #[error("only authority epoch sequence zero may use Genesis")]
    NonGenesisUsesGenesisReason,
    /// Non-genesis epoch lacks predecessor commitment.
    #[error("non-genesis authority epoch requires previous digest")]
    MissingPreviousEpochDigest,
    /// Authority domains differ.
    #[error("operation authority domain mismatch")]
    AuthorityDomainMismatch,
    /// Epoch identity was reused.
    #[error("authority epoch id must be unique across a transition")]
    EpochIdReused,
    /// Epoch sequence is not the exact successor.
    #[error("authority epoch sequence is not the exact successor")]
    EpochSequenceMismatch,
    /// Epoch sequence overflowed.
    #[error("authority epoch sequence overflow")]
    EpochSequenceOverflow,
    /// Previous-epoch commitment is wrong.
    #[error("previous authority epoch digest mismatch")]
    PreviousEpochDigestMismatch,
    /// Establishment time moved backward.
    #[error("authority epoch timestamp regressed")]
    TimestampRegression,
    /// Same-store generation rollover unexpectedly changed store identity.
    #[error("generation rollover must retain receipt store id")]
    RolloverChangedStoreId,
    /// Store generation is not the required next value.
    #[error("receipt store generation mismatch for authority epoch transition")]
    StoreGenerationMismatch,
    /// Receipt store generation overflowed.
    #[error("receipt store generation overflow")]
    StoreGenerationOverflow,
    /// Store replacement reused the old store id.
    #[error("store replacement must establish a new receipt store id")]
    ReplacementReusedStoreId,
    /// Replacement must start at generation zero.
    #[error("replacement receipt store must begin at generation zero")]
    ReplacementMustStartGenerationZero,
    /// Global revocation changed store identity/generation.
    #[error("global revocation must not change receipt store binding")]
    RevocationChangedStoreBinding,
    /// A grant/admission/arm binding refers to an older or different epoch.
    #[error("authority epoch binding is stale")]
    StaleAuthorityEpoch,
    /// Serialization failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

fn require_nonzero(value: [u8; 32], error: AuthorityEpochError) -> Result<(), AuthorityEpochError> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: [1u8; 16],
            epoch_id: [2u8; 16],
            epoch_sequence: 0,
            previous_epoch_digest: [0u8; 32],
            store_id: [3u8; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::Genesis,
            established_at_unix_ms: 100,
        }
    }

    fn rollover(previous: &OperationAuthorityEpochV1) -> OperationAuthorityEpochV1 {
        OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: previous.authority_domain_id,
            epoch_id: [4u8; 16],
            epoch_sequence: previous.epoch_sequence + 1,
            previous_epoch_digest: previous.epoch_digest().unwrap(),
            store_id: previous.store_id,
            store_generation: previous.store_generation + 1,
            reason: AuthorityEpochReasonV1::RecoveryGenerationRollover {
                recovery_decision_digest: [5u8; 32],
            },
            established_at_unix_ms: previous.established_at_unix_ms + 1,
        }
    }

    #[test]
    fn genesis_binding_matches_only_exact_epoch() {
        let first = genesis();
        let binding = AuthorityEpochBindingV1::from_epoch(&first).unwrap();
        assert!(binding.validate_against(&first).is_ok());

        let second = rollover(&first);
        assert!(matches!(
            binding.validate_against(&second),
            Err(AuthorityEpochError::StaleAuthorityEpoch)
        ));
    }

    #[test]
    fn governed_generation_rollover_is_exact_successor() {
        let first = genesis();
        let second = rollover(&first);
        assert!(second.validate_successor(&first).is_ok());
        assert!(validate_epoch_chain(&[first, second]).is_ok());
    }

    #[test]
    fn rollover_cannot_skip_store_generation() {
        let first = genesis();
        let mut second = rollover(&first);
        second.store_generation = 2;
        assert!(matches!(
            second.validate_successor(&first),
            Err(AuthorityEpochError::StoreGenerationMismatch)
        ));
    }

    #[test]
    fn global_revocation_invalidates_old_binding_without_replacing_store() {
        let first = genesis();
        let next = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: first.authority_domain_id,
            epoch_id: [6u8; 16],
            epoch_sequence: 1,
            previous_epoch_digest: first.epoch_digest().unwrap(),
            store_id: first.store_id,
            store_generation: first.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: [7u8; 32],
            },
            established_at_unix_ms: 101,
        };
        assert!(next.validate_successor(&first).is_ok());
        let old = AuthorityEpochBindingV1::from_epoch(&first).unwrap();
        assert!(matches!(
            old.validate_against(&next),
            Err(AuthorityEpochError::StaleAuthorityEpoch)
        ));
    }

    #[test]
    fn store_replacement_requires_new_store_and_generation_zero() {
        let first = genesis();
        let replacement = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: first.authority_domain_id,
            epoch_id: [8u8; 16],
            epoch_sequence: 1,
            previous_epoch_digest: first.epoch_digest().unwrap(),
            store_id: [9u8; 16],
            store_generation: 0,
            reason: AuthorityEpochReasonV1::StoreReplacement {
                recovery_decision_digest: [10u8; 32],
            },
            established_at_unix_ms: 101,
        };
        assert!(replacement.validate_successor(&first).is_ok());
    }

    #[test]
    fn store_replacement_cannot_reuse_old_store_id() {
        let first = genesis();
        let replacement = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.to_string(),
            authority_domain_id: first.authority_domain_id,
            epoch_id: [8u8; 16],
            epoch_sequence: 1,
            previous_epoch_digest: first.epoch_digest().unwrap(),
            store_id: first.store_id,
            store_generation: 0,
            reason: AuthorityEpochReasonV1::StoreReplacement {
                recovery_decision_digest: [10u8; 32],
            },
            established_at_unix_ms: 101,
        };
        assert!(matches!(
            replacement.validate_successor(&first),
            Err(AuthorityEpochError::ReplacementReusedStoreId)
        ));
    }
}
