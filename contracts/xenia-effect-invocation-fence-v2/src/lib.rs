// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Linearization model for the final privileged-effect boundary.
//!
//! A final live authorization check still has a race if a global revocation can commit between
//! that check and the adapter actually beginning an external effect. This contract models the
//! final boundary as an RAII lease tied to mutable authority-fence state.
//!
//! In a real runtime the [`InvocationFenceStateV2`] must live behind the synchronization guard
//! that also serializes authority-epoch transitions. The caller keeps that guard for the full
//! lifetime of [`InvocationStartLeaseV2`] and crosses the adapter's start boundary before
//! resolving the lease. That yields a precise order: either revocation obtains the fence first,
//! or this invocation reservation does.
//!
//! Dropping an unresolved lease conservatively marks the operation `OutcomeUnknown`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_admission_proof_v2::{
    AdmissionPersistenceProofV2, AuthenticatedPersistenceContextV2,
    EffectArmedPersistenceProofV2, PersistenceProofV2Error,
};
use xenia_operation_authority_epoch::{AuthorityEpochError, OperationAuthorityEpochV1};
use xenia_operation_authority_v2::{
    AdmissionAuthorityV2, AuthorityV2Error, EffectArmAuthorityV2, StoreAuthorityV2,
};

/// Schema for [`InvocationLinearizationEvidenceV2`].
pub const INVOCATION_LINEARIZATION_SCHEMA_V2: &str = "xenia-effect-invocation-linearization-v2";
/// Domain separator for invocation linearization commitments.
pub const INVOCATION_LINEARIZATION_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-effect-invocation-linearization-digest-v2";
/// Domain separator for explicit invocation-start evidence.
pub const INVOCATION_STARTED_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-effect-invocation-started-digest-v2";
/// Domain separator for explicit known-not-started evidence.
pub const INVOCATION_NOT_STARTED_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-effect-invocation-not-started-digest-v2";
/// Domain separator for explicit unknown-start evidence.
pub const INVOCATION_UNKNOWN_DIGEST_DOMAIN_V2: &[u8] =
    b"xenia-effect-invocation-unknown-digest-v2";

/// Runtime state tracked for an operation that reached the invocation fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationRuntimeStateV2 {
    /// The operation owns the fence lease; external start has not yet been classified.
    Reserved {
        /// Exact linearization evidence commitment.
        linearization_digest: [u8; 32],
    },
    /// The adapter start boundary was positively crossed.
    Started {
        /// Exact linearization evidence commitment.
        linearization_digest: [u8; 32],
        /// Exact adapter/start evidence commitment.
        start_evidence_digest: [u8; 32],
    },
    /// The runtime positively proved the adapter did not begin the effect.
    NotStartedKnown {
        /// Exact linearization evidence commitment.
        linearization_digest: [u8; 32],
        /// Exact no-start evidence commitment.
        no_start_evidence_digest: [u8; 32],
    },
    /// The runtime cannot prove whether the external effect began.
    OutcomeUnknown {
        /// Exact linearization evidence commitment.
        linearization_digest: [u8; 32],
        /// Optional explicit uncertainty evidence. `None` is used when a lease is dropped.
        uncertainty_evidence_digest: Option<[u8; 32]>,
    },
}

/// Evidence captured at the linearization point before the adapter start boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationLinearizationEvidenceV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Exact operation reserving the start boundary.
    pub operation_id: [u8; 16],
    /// Exact authority epoch current while the fence was held.
    pub authority_epoch_digest: [u8; 32],
    /// Fence revision current while the reservation was created.
    pub fence_revision: u64,
    /// Exact V2 arm-authority commitment.
    pub effect_arm_authority_digest: [u8; 32],
    /// Exact durable admission persistence proof commitment.
    pub admission_persistence_proof_digest: [u8; 32],
    /// Exact durable write-ahead `EffectArmed` persistence proof commitment.
    pub effect_armed_persistence_proof_digest: [u8; 32],
    /// Exact persistent store-authority commitment.
    pub store_authority_digest: [u8; 32],
    /// Commitment proving the semantic arm contract was revalidated live.
    pub semantic_final_gate_evidence_digest: [u8; 32],
    /// Commitment proving the deployment's rollback/anchor requirement was satisfied.
    pub rollback_assurance_evidence_digest: [u8; 32],
    /// Trusted-enough reservation timestamp.
    pub reserved_at_unix_ms: u64,
}

impl InvocationLinearizationEvidenceV2 {
    /// Validate non-sentinel local syntax.
    pub fn validate(&self) -> Result<(), InvocationFenceV2Error> {
        if self.schema != INVOCATION_LINEARIZATION_SCHEMA_V2 {
            return Err(InvocationFenceV2Error::UnsupportedLinearizationSchema);
        }
        require_operation(self.operation_id)?;
        require_nonzero(
            self.authority_epoch_digest,
            InvocationFenceV2Error::ZeroAuthorityEpochDigest,
        )?;
        require_nonzero(
            self.effect_arm_authority_digest,
            InvocationFenceV2Error::ZeroEffectArmAuthorityDigest,
        )?;
        require_nonzero(
            self.admission_persistence_proof_digest,
            InvocationFenceV2Error::ZeroAdmissionProofDigest,
        )?;
        require_nonzero(
            self.effect_armed_persistence_proof_digest,
            InvocationFenceV2Error::ZeroEffectArmedProofDigest,
        )?;
        require_nonzero(
            self.store_authority_digest,
            InvocationFenceV2Error::ZeroStoreAuthorityDigest,
        )?;
        require_nonzero(
            self.semantic_final_gate_evidence_digest,
            InvocationFenceV2Error::ZeroSemanticGateEvidenceDigest,
        )?;
        require_nonzero(
            self.rollback_assurance_evidence_digest,
            InvocationFenceV2Error::ZeroRollbackAssuranceEvidenceDigest,
        )?;
        Ok(())
    }

    /// Canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InvocationFenceV2Error> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable linearization commitment.
    pub fn linearization_digest(&self) -> Result<[u8; 32], InvocationFenceV2Error> {
        Ok(domain_digest(
            INVOCATION_LINEARIZATION_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }
}

/// Positive evidence that the adapter start boundary was crossed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationStartedEvidenceV2 {
    /// Exact operation.
    pub operation_id: [u8; 16],
    /// Exact pre-start linearization commitment.
    pub linearization_digest: [u8; 32],
    /// Exact adapter/start evidence commitment.
    pub start_evidence_digest: [u8; 32],
    /// Trusted-enough time at which the start boundary was classified as crossed.
    pub started_at_unix_ms: u64,
}

impl InvocationStartedEvidenceV2 {
    /// Stable evidence commitment.
    pub fn evidence_digest(&self) -> Result<[u8; 32], InvocationFenceV2Error> {
        validate_resolution_common(
            self.operation_id,
            self.linearization_digest,
            self.start_evidence_digest,
        )?;
        Ok(domain_digest(
            INVOCATION_STARTED_DIGEST_DOMAIN_V2,
            &bincode::serialize(self)?,
        ))
    }
}

/// Positive evidence that the adapter start boundary was not crossed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationNotStartedEvidenceV2 {
    /// Exact operation.
    pub operation_id: [u8; 16],
    /// Exact pre-start linearization commitment.
    pub linearization_digest: [u8; 32],
    /// Exact positive no-start evidence commitment.
    pub no_start_evidence_digest: [u8; 32],
    /// Trusted-enough classification time.
    pub classified_at_unix_ms: u64,
}

impl InvocationNotStartedEvidenceV2 {
    /// Stable evidence commitment.
    pub fn evidence_digest(&self) -> Result<[u8; 32], InvocationFenceV2Error> {
        validate_resolution_common(
            self.operation_id,
            self.linearization_digest,
            self.no_start_evidence_digest,
        )?;
        Ok(domain_digest(
            INVOCATION_NOT_STARTED_DIGEST_DOMAIN_V2,
            &bincode::serialize(self)?,
        ))
    }
}

/// Explicit evidence that start outcome cannot be proved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationUnknownEvidenceV2 {
    /// Exact operation.
    pub operation_id: [u8; 16],
    /// Exact pre-start linearization commitment.
    pub linearization_digest: [u8; 32],
    /// Exact uncertainty evidence commitment.
    pub uncertainty_evidence_digest: [u8; 32],
    /// Trusted-enough classification time.
    pub classified_at_unix_ms: u64,
}

impl InvocationUnknownEvidenceV2 {
    /// Stable evidence commitment.
    pub fn evidence_digest(&self) -> Result<[u8; 32], InvocationFenceV2Error> {
        validate_resolution_common(
            self.operation_id,
            self.linearization_digest,
            self.uncertainty_evidence_digest,
        )?;
        Ok(domain_digest(
            INVOCATION_UNKNOWN_DIGEST_DOMAIN_V2,
            &bincode::serialize(self)?,
        ))
    }
}

/// In-process reference model for the authority/revocation synchronization fence.
///
/// Production code should protect this state with the same lock/guard used to commit authority
/// epoch transitions. A mutable borrow represents exclusive access to that guarded state.
pub struct InvocationFenceStateV2 {
    current_epoch: OperationAuthorityEpochV1,
    revision: u64,
    inhibited: bool,
    operations: BTreeMap<[u8; 16], InvocationRuntimeStateV2>,
}

impl InvocationFenceStateV2 {
    /// Establish a fence at one validated authority epoch.
    pub fn new(current_epoch: OperationAuthorityEpochV1) -> Result<Self, InvocationFenceV2Error> {
        current_epoch.validate()?;
        Ok(Self {
            current_epoch,
            revision: 0,
            inhibited: false,
            operations: BTreeMap::new(),
        })
    }

    /// Current authority epoch.
    pub fn current_epoch(&self) -> &OperationAuthorityEpochV1 {
        &self.current_epoch
    }

    /// Monotonic in-process fence revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Whether new external effect starts are inhibited.
    pub fn inhibited(&self) -> bool {
        self.inhibited
    }

    /// Runtime state for one operation that reached this fence.
    pub fn operation_state(&self, operation_id: [u8; 16]) -> Option<&InvocationRuntimeStateV2> {
        self.operations.get(&operation_id)
    }

    /// Begin an emergency/policy inhibit before committing an authority-epoch transition.
    pub fn inhibit(&mut self, decision_digest: [u8; 32]) -> Result<u64, InvocationFenceV2Error> {
        require_nonzero(
            decision_digest,
            InvocationFenceV2Error::ZeroFenceDecisionDigest,
        )?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(InvocationFenceV2Error::FenceRevisionOverflow)?;
        self.inhibited = true;
        Ok(self.revision)
    }

    /// Commit an exact authority-epoch successor while effect starts remain inhibited.
    pub fn transition_epoch(
        &mut self,
        next: OperationAuthorityEpochV1,
    ) -> Result<u64, InvocationFenceV2Error> {
        if !self.inhibited {
            return Err(InvocationFenceV2Error::EpochTransitionRequiresInhibit);
        }
        next.validate_successor(&self.current_epoch)?;
        self.current_epoch = next;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(InvocationFenceV2Error::FenceRevisionOverflow)?;
        Ok(self.revision)
    }

    /// Explicitly permit fresh effect starts after the new epoch/policy state is ready.
    pub fn resume(&mut self, decision_digest: [u8; 32]) -> Result<u64, InvocationFenceV2Error> {
        require_nonzero(
            decision_digest,
            InvocationFenceV2Error::ZeroFenceDecisionDigest,
        )?;
        if !self.inhibited {
            return Err(InvocationFenceV2Error::FenceNotInhibited);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(InvocationFenceV2Error::FenceRevisionOverflow)?;
        self.inhibited = false;
        Ok(self.revision)
    }

    /// Validate every authority/persistence gate and reserve the invocation linearization point.
    ///
    /// The returned lease borrows this fence mutably. The runtime must retain the corresponding
    /// synchronization guard and cross the adapter start boundary before resolving/dropping it.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_start<'a>(
        &'a mut self,
        admission: &AdmissionAuthorityV2,
        admission_proof: &AdmissionPersistenceProofV2,
        arm: &EffectArmAuthorityV2,
        effect_armed_proof: &EffectArmedPersistenceProofV2,
        store: &StoreAuthorityV2,
        authenticated_admission_persistence: AuthenticatedPersistenceContextV2,
        authenticated_arm_persistence: AuthenticatedPersistenceContextV2,
        semantic_final_gate_evidence_digest: [u8; 32],
        rollback_assurance_evidence_digest: [u8; 32],
        reserved_at_unix_ms: u64,
    ) -> Result<InvocationStartLeaseV2<'a>, InvocationFenceV2Error> {
        if self.inhibited {
            return Err(InvocationFenceV2Error::EffectStartsInhibited);
        }
        require_nonzero(
            semantic_final_gate_evidence_digest,
            InvocationFenceV2Error::ZeroSemanticGateEvidenceDigest,
        )?;
        require_nonzero(
            rollback_assurance_evidence_digest,
            InvocationFenceV2Error::ZeroRollbackAssuranceEvidenceDigest,
        )?;

        let current = &self.current_epoch;
        admission_proof.validate_against(
            admission,
            store,
            current,
            authenticated_admission_persistence,
        )?;
        arm.validate_final_gate(admission, store, current)?;
        effect_armed_proof.validate_final_gate(
            arm,
            admission_proof,
            store,
            current,
            authenticated_arm_persistence,
        )?;

        let operation_id = arm.operation_id;
        if self.operations.contains_key(&operation_id) {
            return Err(InvocationFenceV2Error::OperationAlreadyLinearized);
        }
        if reserved_at_unix_ms < effect_armed_proof.persisted_at_unix_ms {
            return Err(InvocationFenceV2Error::ReservationPredatesEffectArmedPersistence);
        }

        let evidence = InvocationLinearizationEvidenceV2 {
            schema: INVOCATION_LINEARIZATION_SCHEMA_V2.to_string(),
            operation_id,
            authority_epoch_digest: current.epoch_digest()?,
            fence_revision: self.revision,
            effect_arm_authority_digest: arm.authority_digest()?,
            admission_persistence_proof_digest: admission_proof.proof_digest()?,
            effect_armed_persistence_proof_digest: effect_armed_proof.proof_digest()?,
            store_authority_digest: store.authority_digest()?,
            semantic_final_gate_evidence_digest,
            rollback_assurance_evidence_digest,
            reserved_at_unix_ms,
        };
        let linearization_digest = evidence.linearization_digest()?;
        self.operations.insert(
            operation_id,
            InvocationRuntimeStateV2::Reserved {
                linearization_digest,
            },
        );

        Ok(InvocationStartLeaseV2 {
            fence: self,
            evidence,
            resolved: false,
        })
    }
}

/// RAII lease that holds the authority fence across the actual adapter start boundary.
///
/// This type is intentionally neither `Clone` nor serializable. Dropping it unresolved marks
/// the operation outcome unknown in the in-process fence model.
pub struct InvocationStartLeaseV2<'a> {
    fence: &'a mut InvocationFenceStateV2,
    evidence: InvocationLinearizationEvidenceV2,
    resolved: bool,
}

impl InvocationStartLeaseV2<'_> {
    /// Linearization evidence captured before the adapter start boundary.
    pub fn evidence(&self) -> &InvocationLinearizationEvidenceV2 {
        &self.evidence
    }

    /// Classify the adapter start boundary as positively crossed.
    pub fn mark_started(
        mut self,
        start_evidence_digest: [u8; 32],
        started_at_unix_ms: u64,
    ) -> Result<InvocationStartedEvidenceV2, InvocationFenceV2Error> {
        require_nonzero(
            start_evidence_digest,
            InvocationFenceV2Error::ZeroStartEvidenceDigest,
        )?;
        if started_at_unix_ms < self.evidence.reserved_at_unix_ms {
            return Err(InvocationFenceV2Error::ResolutionTimestampRegression);
        }
        let linearization_digest = self.evidence.linearization_digest()?;
        self.require_reserved(linearization_digest)?;
        self.fence.operations.insert(
            self.evidence.operation_id,
            InvocationRuntimeStateV2::Started {
                linearization_digest,
                start_evidence_digest,
            },
        );
        self.resolved = true;
        Ok(InvocationStartedEvidenceV2 {
            operation_id: self.evidence.operation_id,
            linearization_digest,
            start_evidence_digest,
            started_at_unix_ms,
        })
    }

    /// Classify the adapter start boundary as positively not crossed.
    pub fn mark_not_started(
        mut self,
        no_start_evidence_digest: [u8; 32],
        classified_at_unix_ms: u64,
    ) -> Result<InvocationNotStartedEvidenceV2, InvocationFenceV2Error> {
        require_nonzero(
            no_start_evidence_digest,
            InvocationFenceV2Error::ZeroNoStartEvidenceDigest,
        )?;
        if classified_at_unix_ms < self.evidence.reserved_at_unix_ms {
            return Err(InvocationFenceV2Error::ResolutionTimestampRegression);
        }
        let linearization_digest = self.evidence.linearization_digest()?;
        self.require_reserved(linearization_digest)?;
        self.fence.operations.insert(
            self.evidence.operation_id,
            InvocationRuntimeStateV2::NotStartedKnown {
                linearization_digest,
                no_start_evidence_digest,
            },
        );
        self.resolved = true;
        Ok(InvocationNotStartedEvidenceV2 {
            operation_id: self.evidence.operation_id,
            linearization_digest,
            no_start_evidence_digest,
            classified_at_unix_ms,
        })
    }

    /// Explicitly classify start outcome as unknowable.
    pub fn mark_unknown(
        mut self,
        uncertainty_evidence_digest: [u8; 32],
        classified_at_unix_ms: u64,
    ) -> Result<InvocationUnknownEvidenceV2, InvocationFenceV2Error> {
        require_nonzero(
            uncertainty_evidence_digest,
            InvocationFenceV2Error::ZeroUncertaintyEvidenceDigest,
        )?;
        if classified_at_unix_ms < self.evidence.reserved_at_unix_ms {
            return Err(InvocationFenceV2Error::ResolutionTimestampRegression);
        }
        let linearization_digest = self.evidence.linearization_digest()?;
        self.require_reserved(linearization_digest)?;
        self.fence.operations.insert(
            self.evidence.operation_id,
            InvocationRuntimeStateV2::OutcomeUnknown {
                linearization_digest,
                uncertainty_evidence_digest: Some(uncertainty_evidence_digest),
            },
        );
        self.resolved = true;
        Ok(InvocationUnknownEvidenceV2 {
            operation_id: self.evidence.operation_id,
            linearization_digest,
            uncertainty_evidence_digest,
            classified_at_unix_ms,
        })
    }

    fn require_reserved(&self, expected: [u8; 32]) -> Result<(), InvocationFenceV2Error> {
        match self.fence.operations.get(&self.evidence.operation_id) {
            Some(InvocationRuntimeStateV2::Reserved {
                linearization_digest,
            }) if *linearization_digest == expected => Ok(()),
            _ => Err(InvocationFenceV2Error::LeaseStateMismatch),
        }
    }
}

impl Drop for InvocationStartLeaseV2<'_> {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        let Ok(linearization_digest) = self.evidence.linearization_digest() else {
            return;
        };
        let still_reserved = matches!(
            self.fence.operations.get(&self.evidence.operation_id),
            Some(InvocationRuntimeStateV2::Reserved {
                linearization_digest: current,
            }) if *current == linearization_digest
        );
        if still_reserved {
            self.fence.operations.insert(
                self.evidence.operation_id,
                InvocationRuntimeStateV2::OutcomeUnknown {
                    linearization_digest,
                    uncertainty_evidence_digest: None,
                },
            );
        }
    }
}

/// Invocation-fence validation failure.
#[derive(Debug, Error)]
pub enum InvocationFenceV2Error {
    /// Linearization schema mismatch.
    #[error("unsupported invocation linearization v2 schema")]
    UnsupportedLinearizationSchema,
    /// New starts are currently inhibited.
    #[error("privileged effect starts are inhibited")]
    EffectStartsInhibited,
    /// Epoch transition was attempted without inhibit.
    #[error("authority epoch transition requires an active effect-start inhibit")]
    EpochTransitionRequiresInhibit,
    /// Resume was requested while not inhibited.
    #[error("invocation fence is not inhibited")]
    FenceNotInhibited,
    /// Fence revision overflow.
    #[error("invocation fence revision overflow")]
    FenceRevisionOverflow,
    /// Fence/revocation decision commitment is unset.
    #[error("invocation fence decision digest must not be all zero")]
    ZeroFenceDecisionDigest,
    /// Operation id is unset.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Authority epoch commitment is unset.
    #[error("authority epoch digest must not be all zero")]
    ZeroAuthorityEpochDigest,
    /// Arm authority commitment is unset.
    #[error("effect-arm authority digest must not be all zero")]
    ZeroEffectArmAuthorityDigest,
    /// Admission persistence proof commitment is unset.
    #[error("admission persistence proof digest must not be all zero")]
    ZeroAdmissionProofDigest,
    /// EffectArmed persistence proof commitment is unset.
    #[error("effect-armed persistence proof digest must not be all zero")]
    ZeroEffectArmedProofDigest,
    /// Store authority commitment is unset.
    #[error("store authority digest must not be all zero")]
    ZeroStoreAuthorityDigest,
    /// Semantic live-gate evidence is unset.
    #[error("semantic final-gate evidence digest must not be all zero")]
    ZeroSemanticGateEvidenceDigest,
    /// Rollback/anchor assurance evidence is unset.
    #[error("rollback assurance evidence digest must not be all zero")]
    ZeroRollbackAssuranceEvidenceDigest,
    /// Adapter start evidence is unset.
    #[error("adapter start evidence digest must not be all zero")]
    ZeroStartEvidenceDigest,
    /// Positive no-start evidence is unset.
    #[error("no-start evidence digest must not be all zero")]
    ZeroNoStartEvidenceDigest,
    /// Explicit uncertainty evidence is unset.
    #[error("uncertainty evidence digest must not be all zero")]
    ZeroUncertaintyEvidenceDigest,
    /// Same operation already reached the invocation fence.
    #[error("operation already has invocation linearization state")]
    OperationAlreadyLinearized,
    /// Reservation timestamp predates durable EffectArmed persistence.
    #[error("invocation reservation predates effect-armed persistence")]
    ReservationPredatesEffectArmedPersistence,
    /// Resolution timestamp moved backward.
    #[error("invocation resolution timestamp regressed")]
    ResolutionTimestampRegression,
    /// Lease no longer refers to the exact reserved state.
    #[error("invocation lease state mismatch")]
    LeaseStateMismatch,
    /// Resolution evidence had an invalid common field.
    #[error("invalid invocation resolution evidence")]
    InvalidResolutionEvidence,
    /// Authority V2 validation failed.
    #[error(transparent)]
    AuthorityV2(#[from] AuthorityV2Error),
    /// Persistence-proof validation failed.
    #[error(transparent)]
    Persistence(#[from] PersistenceProofV2Error),
    /// Authority epoch validation failed.
    #[error(transparent)]
    Epoch(#[from] AuthorityEpochError),
    /// Canonical encoding failed.
    #[error("failed to encode invocation evidence: {0}")]
    Encoding(#[from] bincode::Error),
}

fn validate_resolution_common(
    operation_id: [u8; 16],
    linearization_digest: [u8; 32],
    evidence_digest: [u8; 32],
) -> Result<(), InvocationFenceV2Error> {
    require_operation(operation_id)?;
    if linearization_digest == [0u8; 32] || evidence_digest == [0u8; 32] {
        return Err(InvocationFenceV2Error::InvalidResolutionEvidence);
    }
    Ok(())
}

fn require_operation(operation_id: [u8; 16]) -> Result<(), InvocationFenceV2Error> {
    if operation_id == [0u8; 16] {
        Err(InvocationFenceV2Error::ZeroOperationId)
    } else {
        Ok(())
    }
}

fn require_nonzero(
    value: [u8; 32],
    error: InvocationFenceV2Error,
) -> Result<(), InvocationFenceV2Error> {
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
        AuthenticatedIssuanceContextV2, GrantAuthorityV2, UseAuthorityV2,
    };

    struct Fixture {
        epoch: OperationAuthorityEpochV1,
        admission: AdmissionAuthorityV2,
        admission_proof: AdmissionPersistenceProofV2,
        arm: EffectArmAuthorityV2,
        armed_proof: EffectArmedPersistenceProofV2,
        store: StoreAuthorityV2,
        admission_persistence: AuthenticatedPersistenceContextV2,
        arm_persistence: AuthenticatedPersistenceContextV2,
    }

    fn issuance() -> AuthenticatedIssuanceContextV2 {
        AuthenticatedIssuanceContextV2 {
            issuer_authority_digest: [0xA1; 32],
            issuance_evidence_digest: [0xA2; 32],
        }
    }

    fn persistence(commit: u8) -> AuthenticatedPersistenceContextV2 {
        AuthenticatedPersistenceContextV2 {
            backend_authority_digest: [0xB1; 32],
            persistence_profile_digest: [0xB2; 32],
            commit_evidence_digest: [commit; 32],
        }
    }

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

    fn fixture() -> Fixture {
        let current = epoch();
        let issue = issuance();
        let grant = GrantAuthorityV2::new([0x11; 32], &current, issue, 1_050).unwrap();
        let use_authority =
            UseAuthorityV2::new([0x22; 16], [0x33; 32], &grant, &current, issue).unwrap();
        let admission = AdmissionAuthorityV2::new(
            [0x44; 32],
            &use_authority,
            &grant,
            &current,
            issue,
        )
        .unwrap();
        let store = StoreAuthorityV2::from_epoch(&current).unwrap();
        let admission_persistence = persistence(0x61);
        let admission_proof = AdmissionPersistenceProofV2::new(
            &admission,
            &store,
            &current,
            7,
            [0x62; 32],
            [0x63; 32],
            admission_persistence,
            1_100,
        )
        .unwrap();
        let arm = EffectArmAuthorityV2::new([0x71; 32], &admission, &store, &current).unwrap();
        let arm_persistence = persistence(0x72);
        let armed_proof = EffectArmedPersistenceProofV2::new(
            &arm,
            &admission_proof,
            &store,
            &current,
            [0x73; 32],
            [0x74; 32],
            arm_persistence,
            1_200,
        )
        .unwrap();
        Fixture {
            epoch: current,
            admission,
            admission_proof,
            arm,
            armed_proof,
            store,
            admission_persistence,
            arm_persistence,
        }
    }

    fn begin<'a>(
        fence: &'a mut InvocationFenceStateV2,
        fixture: &Fixture,
    ) -> InvocationStartLeaseV2<'a> {
        fence
            .begin_start(
                &fixture.admission,
                &fixture.admission_proof,
                &fixture.arm,
                &fixture.armed_proof,
                &fixture.store,
                fixture.admission_persistence,
                fixture.arm_persistence,
                [0x81; 32],
                [0x82; 32],
                1_300,
            )
            .unwrap()
    }

    #[test]
    fn started_effect_is_ordered_before_later_inhibit() {
        let fixture = fixture();
        let mut fence = InvocationFenceStateV2::new(fixture.epoch.clone()).unwrap();
        let lease = begin(&mut fence, &fixture);
        let started = lease.mark_started([0x91; 32], 1_301).unwrap();
        assert_ne!(started.evidence_digest().unwrap(), [0; 32]);

        fence.inhibit([0x92; 32]).unwrap();
        assert!(matches!(
            fence.operation_state(fixture.arm.operation_id),
            Some(InvocationRuntimeStateV2::Started { .. })
        ));
    }

    #[test]
    fn inhibit_first_blocks_start() {
        let fixture = fixture();
        let mut fence = InvocationFenceStateV2::new(fixture.epoch.clone()).unwrap();
        fence.inhibit([0x92; 32]).unwrap();
        assert!(matches!(
            fence.begin_start(
                &fixture.admission,
                &fixture.admission_proof,
                &fixture.arm,
                &fixture.armed_proof,
                &fixture.store,
                fixture.admission_persistence,
                fixture.arm_persistence,
                [0x81; 32],
                [0x82; 32],
                1_300,
            ),
            Err(InvocationFenceV2Error::EffectStartsInhibited)
        ));
    }

    #[test]
    fn dropping_unresolved_lease_becomes_unknown() {
        let fixture = fixture();
        let mut fence = InvocationFenceStateV2::new(fixture.epoch.clone()).unwrap();
        {
            let _lease = begin(&mut fence, &fixture);
        }
        assert!(matches!(
            fence.operation_state(fixture.arm.operation_id),
            Some(InvocationRuntimeStateV2::OutcomeUnknown {
                uncertainty_evidence_digest: None,
                ..
            })
        ));
    }

    #[test]
    fn positive_not_started_remains_non_retryable_same_operation() {
        let fixture = fixture();
        let mut fence = InvocationFenceStateV2::new(fixture.epoch.clone()).unwrap();
        let lease = begin(&mut fence, &fixture);
        let not_started = lease.mark_not_started([0x93; 32], 1_301).unwrap();
        assert_ne!(not_started.evidence_digest().unwrap(), [0; 32]);
        assert!(matches!(
            fence.begin_start(
                &fixture.admission,
                &fixture.admission_proof,
                &fixture.arm,
                &fixture.armed_proof,
                &fixture.store,
                fixture.admission_persistence,
                fixture.arm_persistence,
                [0x81; 32],
                [0x82; 32],
                1_302,
            ),
            Err(InvocationFenceV2Error::OperationAlreadyLinearized)
        ));
    }

    #[test]
    fn epoch_transition_requires_inhibit_and_stales_old_evidence() {
        let fixture = fixture();
        let mut fence = InvocationFenceStateV2::new(fixture.epoch.clone()).unwrap();
        let next = OperationAuthorityEpochV1 {
            schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
            authority_domain_id: fixture.epoch.authority_domain_id,
            epoch_id: [4; 16],
            epoch_sequence: 1,
            previous_epoch_digest: fixture.epoch.epoch_digest().unwrap(),
            store_id: fixture.epoch.store_id,
            store_generation: fixture.epoch.store_generation,
            reason: AuthorityEpochReasonV1::GlobalRevocation {
                revocation_decision_digest: [0x94; 32],
            },
            established_at_unix_ms: 1_400,
        };
        assert!(matches!(
            fence.transition_epoch(next.clone()),
            Err(InvocationFenceV2Error::EpochTransitionRequiresInhibit)
        ));
        fence.inhibit([0x95; 32]).unwrap();
        fence.transition_epoch(next).unwrap();
        fence.resume([0x96; 32]).unwrap();
        assert!(begin(&mut fence, &fixture).evidence().authority_epoch_digest != [0; 32]);
    }
}
