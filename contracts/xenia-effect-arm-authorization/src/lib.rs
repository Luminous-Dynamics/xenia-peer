// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime-free contracts for fresh privileged-operation effect-arm authorization.
//!
//! Durable admission permanently reserves one grant-use slot, but it does not preserve
//! permission to start an effect indefinitely. This crate defines a short-lived positive
//! authorization commitment produced by a fresh live reevaluation immediately before the
//! durable `EffectArmed` transition, plus preparation/final-gate evidence for deployments
//! that require an externally anchored operation-store frontier before effect.
//!
//! These serialized records are evidence objects, not bearer credentials. A runtime must
//! still validate current authenticated session/subject state, the current durable receipt
//! head, operation-store health, prepared-frontier ancestry, and every deployment-specific
//! policy gate before invoking an adapter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_store_frontier::{
    OperationStoreFrontierError, OperationStoreFrontierV1, validate_frontier_chain,
};

/// Exact schema label for [`EffectArmAuthorizationV1`].
pub const EFFECT_ARM_AUTHORIZATION_SCHEMA_V1: &str = "xenia-effect-arm-authorization-v1";
/// Exact schema label for [`EffectArmPreparationEvidenceV1`].
pub const EFFECT_ARM_PREPARATION_EVIDENCE_SCHEMA_V1: &str =
    "xenia-effect-arm-preparation-evidence-v1";
/// Domain separator for effect-arm authorization commitments.
pub const EFFECT_ARM_AUTHORIZATION_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-effect-arm-authorization-digest-v1";
/// Domain separator for effect-arm preparation evidence commitments.
pub const EFFECT_ARM_PREPARATION_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-effect-arm-preparation-digest-v1";
/// Maximum absolute lifetime of one V1 positive arm authorization.
pub const MAX_EFFECT_ARM_AUTHORIZATION_LIFETIME_MS_V1: u64 = 60_000;

/// Rollback-assurance gate required before the external effect may begin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectAnchorRequirementV1 {
    /// Local durable `EffectArmed` is sufficient for the deployment's intentionally narrow claim.
    LocalDurableOnly,
    /// The exact store frontier containing `EffectArmed` must be anchored outside the relevant
    /// rollback scope before the adapter may cross its external-effect boundary.
    ExternalFrontierBeforeEffect {
        /// Commitment identifying the exact external anchor policy/domain.
        anchor_domain_digest: [u8; 32],
    },
}

impl EffectAnchorRequirementV1 {
    /// Validate that high-assurance anchoring identifies an explicit non-zero anchor domain.
    pub fn validate(&self) -> Result<(), EffectArmAuthorizationError> {
        match self {
            Self::LocalDurableOnly => Ok(()),
            Self::ExternalFrontierBeforeEffect {
                anchor_domain_digest,
            } if *anchor_domain_digest == [0u8; 32] => {
                Err(EffectArmAuthorizationError::ZeroAnchorDomainDigest)
            }
            Self::ExternalFrontierBeforeEffect { .. } => Ok(()),
        }
    }

    /// Whether this deployment requires an externally authenticated frontier before effect.
    pub fn requires_external_anchor(&self) -> bool {
        matches!(self, Self::ExternalFrontierBeforeEffect { .. })
    }
}

/// Short-lived positive authorization produced by a fresh live reevaluation before effect arming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectArmAuthorizationV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Exact operation being prepared for effect.
    pub operation_id: [u8; 16],
    /// Exact immutable operation-admission commitment.
    pub admission_digest: [u8; 32],
    /// Exact session-bound grant commitment already consumed at admission.
    pub grant_digest: [u8; 32],
    /// Exact validated capability-use commitment already consumed at admission.
    pub use_digest: [u8; 32],
    /// Current authenticated session-context commitment at arm reevaluation.
    pub live_session_context_hash: [u8; 32],
    /// Current authenticated subject commitment at arm reevaluation.
    pub live_subject_fingerprint: [u8; 32],
    /// Commitment to the current consent/approval state that permitted arming.
    pub consent_state_digest: [u8; 32],
    /// Commitment to the current policy decision/state that permitted arming.
    pub policy_state_digest: [u8; 32],
    /// Commitment to the current security/posture state that permitted arming.
    pub posture_state_digest: [u8; 32],
    /// Exact rollback-assurance requirement applied to this effect.
    pub anchor_requirement: EffectAnchorRequirementV1,
    /// Monotonic authorization epoch from the reevaluation authority domain.
    pub authorization_epoch: u64,
    /// Trusted-enough evaluation time.
    pub evaluated_at_unix_ms: u64,
    /// Exclusive hard expiry for this positive arm authorization.
    pub expires_at_unix_ms: u64,
}

impl EffectArmAuthorizationV1 {
    /// Validate canonical V1 syntax and the short absolute lifetime bound.
    pub fn validate(&self) -> Result<(), EffectArmAuthorizationError> {
        if self.schema != EFFECT_ARM_AUTHORIZATION_SCHEMA_V1 {
            return Err(EffectArmAuthorizationError::UnsupportedAuthorizationSchema);
        }
        if self.operation_id == [0u8; 16] {
            return Err(EffectArmAuthorizationError::ZeroOperationId);
        }
        require_nonzero(self.admission_digest, EffectArmAuthorizationError::ZeroAdmissionDigest)?;
        require_nonzero(self.grant_digest, EffectArmAuthorizationError::ZeroGrantDigest)?;
        require_nonzero(self.use_digest, EffectArmAuthorizationError::ZeroUseDigest)?;
        require_nonzero(
            self.live_session_context_hash,
            EffectArmAuthorizationError::ZeroSessionContextHash,
        )?;
        require_nonzero(
            self.live_subject_fingerprint,
            EffectArmAuthorizationError::ZeroSubjectFingerprint,
        )?;
        require_nonzero(
            self.consent_state_digest,
            EffectArmAuthorizationError::ZeroConsentStateDigest,
        )?;
        require_nonzero(
            self.policy_state_digest,
            EffectArmAuthorizationError::ZeroPolicyStateDigest,
        )?;
        require_nonzero(
            self.posture_state_digest,
            EffectArmAuthorizationError::ZeroPostureStateDigest,
        )?;
        self.anchor_requirement.validate()?;

        if self.expires_at_unix_ms <= self.evaluated_at_unix_ms {
            return Err(EffectArmAuthorizationError::InvalidAuthorizationWindow);
        }
        let lifetime = self.expires_at_unix_ms - self.evaluated_at_unix_ms;
        if lifetime > MAX_EFFECT_ARM_AUTHORIZATION_LIFETIME_MS_V1 {
            return Err(EffectArmAuthorizationError::AuthorizationLifetimeTooLong);
        }
        Ok(())
    }

    /// Return whether this valid authorization is live at `now_unix_ms`.
    ///
    /// Expiry is exclusive: `now == expires_at_unix_ms` is no longer live.
    pub fn is_live_at(&self, now_unix_ms: u64) -> Result<bool, EffectArmAuthorizationError> {
        self.validate()?;
        Ok(now_unix_ms >= self.evaluated_at_unix_ms && now_unix_ms < self.expires_at_unix_ms)
    }

    /// Require this authorization to be live at `now_unix_ms`.
    pub fn require_live_at(&self, now_unix_ms: u64) -> Result<(), EffectArmAuthorizationError> {
        if self.is_live_at(now_unix_ms)? {
            Ok(())
        } else {
            Err(EffectArmAuthorizationError::AuthorizationNotLive)
        }
    }

    /// Deterministic canonical bincode-v1 bytes for receipt/evidence binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EffectArmAuthorizationError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3-256 commitment to the complete arm authorization.
    pub fn authorization_digest(&self) -> Result<[u8; 32], EffectArmAuthorizationError> {
        Ok(domain_digest(
            EFFECT_ARM_AUTHORIZATION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Durable preparation evidence assembled after the local `EffectArmed` receipt exists.
///
/// In external-anchor mode this also commits to the exact externally authenticated store
/// frontier. The object is useful for audit and final-gate comparison but is not a portable
/// permission token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectArmPreparationEvidenceV1 {
    /// Exact V1 preparation-evidence schema label.
    pub schema: String,
    /// Exact operation being prepared.
    pub operation_id: [u8; 16],
    /// Exact immutable admission commitment.
    pub admission_digest: [u8; 32],
    /// Exact fresh arm-authorization commitment bound by `EffectArmed`.
    pub arm_authorization_digest: [u8; 32],
    /// Exact durable `EffectArmed` receipt-event commitment.
    pub effect_armed_event_digest: [u8; 32],
    /// Exact local operation-store frontier containing the `EffectArmed` event.
    pub store_frontier_digest: [u8; 32],
    /// Exact external anchor/evidence commitment when required by the authorization.
    pub external_anchor_digest: Option<[u8; 32]>,
    /// Time when all required durable preparation gates were assembled.
    pub prepared_at_unix_ms: u64,
}

impl EffectArmPreparationEvidenceV1 {
    /// Validate preparation evidence against the exact fresh authorization it claims to satisfy.
    pub fn validate_against(
        &self,
        authorization: &EffectArmAuthorizationV1,
    ) -> Result<(), EffectArmAuthorizationError> {
        authorization.validate()?;
        if self.schema != EFFECT_ARM_PREPARATION_EVIDENCE_SCHEMA_V1 {
            return Err(EffectArmAuthorizationError::UnsupportedPreparationSchema);
        }
        if self.operation_id != authorization.operation_id {
            return Err(EffectArmAuthorizationError::OperationIdMismatch);
        }
        if self.admission_digest != authorization.admission_digest {
            return Err(EffectArmAuthorizationError::AdmissionDigestMismatch);
        }
        if self.arm_authorization_digest != authorization.authorization_digest()? {
            return Err(EffectArmAuthorizationError::AuthorizationDigestMismatch);
        }
        require_nonzero(
            self.effect_armed_event_digest,
            EffectArmAuthorizationError::ZeroEffectArmedEventDigest,
        )?;
        require_nonzero(
            self.store_frontier_digest,
            EffectArmAuthorizationError::ZeroStoreFrontierDigest,
        )?;
        if self.prepared_at_unix_ms < authorization.evaluated_at_unix_ms
            || self.prepared_at_unix_ms >= authorization.expires_at_unix_ms
        {
            return Err(EffectArmAuthorizationError::PreparationOutsideAuthorizationWindow);
        }

        match &authorization.anchor_requirement {
            EffectAnchorRequirementV1::LocalDurableOnly => {
                if self.external_anchor_digest.is_some() {
                    return Err(EffectArmAuthorizationError::UnexpectedExternalAnchor);
                }
            }
            EffectAnchorRequirementV1::ExternalFrontierBeforeEffect { .. } => {
                match self.external_anchor_digest {
                    Some(digest) if digest != [0u8; 32] => {}
                    _ => return Err(EffectArmAuthorizationError::MissingExternalAnchor),
                }
            }
        }
        Ok(())
    }

    /// Deterministic canonical bytes after validation against `authorization`.
    pub fn canonical_bytes_against(
        &self,
        authorization: &EffectArmAuthorizationV1,
    ) -> Result<Vec<u8>, EffectArmAuthorizationError> {
        self.validate_against(authorization)?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated commitment to this preparation evidence.
    pub fn preparation_digest(
        &self,
        authorization: &EffectArmAuthorizationV1,
    ) -> Result<[u8; 32], EffectArmAuthorizationError> {
        Ok(domain_digest(
            EFFECT_ARM_PREPARATION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes_against(authorization)?,
        ))
    }
}

/// Non-persistent current-state inputs checked immediately before adapter invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectArmFinalGateContextV1 {
    /// Current trusted-enough time.
    pub now_unix_ms: u64,
    /// Current authenticated session-context commitment.
    pub live_session_context_hash: [u8; 32],
    /// Current authenticated subject commitment.
    pub live_subject_fingerprint: [u8; 32],
    /// Current consent/approval-state commitment.
    pub consent_state_digest: [u8; 32],
    /// Current policy-state commitment.
    pub policy_state_digest: [u8; 32],
    /// Current security/posture-state commitment.
    pub posture_state_digest: [u8; 32],
    /// Current durable receipt head, which must still be the expected `EffectArmed` event.
    pub current_effect_armed_event_digest: [u8; 32],
    /// Current verified external anchor commitment, when required.
    pub current_external_anchor_digest: Option<[u8; 32]>,
}

/// Prove that the prepared frontier is still retained in one valid current frontier lineage.
///
/// Unrelated operations may advance the store after preparation. Therefore the final gate must
/// prove ancestry, not require equality with the latest frontier. V1 intentionally requires the
/// exact prepared frontier to remain retained; destructive frontier-history pruning is unsupported.
pub fn verify_prepared_frontier_ancestry(
    preparation: &EffectArmPreparationEvidenceV1,
    local_frontiers: &[OperationStoreFrontierV1],
) -> Result<(), EffectArmAuthorizationError> {
    validate_frontier_chain(local_frontiers)?;
    if local_frontiers.is_empty() {
        return Err(EffectArmAuthorizationError::PreparedFrontierMissing);
    }

    for frontier in local_frontiers {
        if frontier.frontier_digest()? == preparation.store_frontier_digest {
            return Ok(());
        }
    }
    Err(EffectArmAuthorizationError::PreparedFrontierMissing)
}

/// Validate the final live gate immediately before the adapter crosses its external-effect boundary.
///
/// Success proves that current live authority still matches the short-lived arm decision, this
/// operation's receipt head is still the prepared `EffectArmed` event, the prepared store frontier
/// remains an ancestor of current verified store state, and the required external anchor has not
/// changed. The caller must additionally enforce store-health and adapter-specific invariants.
pub fn validate_final_gate(
    authorization: &EffectArmAuthorizationV1,
    preparation: &EffectArmPreparationEvidenceV1,
    current: &EffectArmFinalGateContextV1,
    local_frontiers: &[OperationStoreFrontierV1],
) -> Result<(), EffectArmAuthorizationError> {
    authorization.require_live_at(current.now_unix_ms)?;
    preparation.validate_against(authorization)?;
    verify_prepared_frontier_ancestry(preparation, local_frontiers)?;

    if current.live_session_context_hash != authorization.live_session_context_hash {
        return Err(EffectArmAuthorizationError::LiveSessionChanged);
    }
    if current.live_subject_fingerprint != authorization.live_subject_fingerprint {
        return Err(EffectArmAuthorizationError::LiveSubjectChanged);
    }
    if current.consent_state_digest != authorization.consent_state_digest {
        return Err(EffectArmAuthorizationError::ConsentStateChanged);
    }
    if current.policy_state_digest != authorization.policy_state_digest {
        return Err(EffectArmAuthorizationError::PolicyStateChanged);
    }
    if current.posture_state_digest != authorization.posture_state_digest {
        return Err(EffectArmAuthorizationError::PostureStateChanged);
    }
    if current.current_effect_armed_event_digest != preparation.effect_armed_event_digest {
        return Err(EffectArmAuthorizationError::ReceiptHeadChanged);
    }
    if current.current_external_anchor_digest != preparation.external_anchor_digest {
        return Err(EffectArmAuthorizationError::ExternalAnchorChanged);
    }
    Ok(())
}

fn require_nonzero(
    digest: [u8; 32],
    error: EffectArmAuthorizationError,
) -> Result<(), EffectArmAuthorizationError> {
    if digest == [0u8; 32] { Err(error) } else { Ok(()) }
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Validation failure for fresh effect-arm authorization and preparation evidence.
#[derive(Debug, Error)]
pub enum EffectArmAuthorizationError {
    /// Authorization schema is not the exact V1 label.
    #[error("unsupported effect-arm authorization schema")]
    UnsupportedAuthorizationSchema,
    /// Preparation-evidence schema is not the exact V1 label.
    #[error("unsupported effect-arm preparation schema")]
    UnsupportedPreparationSchema,
    /// Operation id is unset.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Admission commitment is unset.
    #[error("admission digest must not be all zero")]
    ZeroAdmissionDigest,
    /// Grant commitment is unset.
    #[error("grant digest must not be all zero")]
    ZeroGrantDigest,
    /// Capability-use commitment is unset.
    #[error("use digest must not be all zero")]
    ZeroUseDigest,
    /// Live session commitment is unset.
    #[error("live session context hash must not be all zero")]
    ZeroSessionContextHash,
    /// Live subject commitment is unset.
    #[error("live subject fingerprint must not be all zero")]
    ZeroSubjectFingerprint,
    /// Consent/approval-state commitment is unset.
    #[error("consent state digest must not be all zero")]
    ZeroConsentStateDigest,
    /// Policy-state commitment is unset.
    #[error("policy state digest must not be all zero")]
    ZeroPolicyStateDigest,
    /// Posture-state commitment is unset.
    #[error("posture state digest must not be all zero")]
    ZeroPostureStateDigest,
    /// External anchor policy/domain commitment is unset.
    #[error("external anchor domain digest must not be all zero")]
    ZeroAnchorDomainDigest,
    /// Authorization expiry is not strictly after evaluation.
    #[error("invalid effect-arm authorization time window")]
    InvalidAuthorizationWindow,
    /// Authorization lifetime exceeds the V1 ceiling.
    #[error("effect-arm authorization lifetime exceeds V1 ceiling")]
    AuthorizationLifetimeTooLong,
    /// Authorization is not live at the requested final-gate time.
    #[error("effect-arm authorization is not currently live")]
    AuthorizationNotLive,
    /// Preparation operation id does not match authorization.
    #[error("preparation operation id mismatch")]
    OperationIdMismatch,
    /// Preparation admission commitment does not match authorization.
    #[error("preparation admission digest mismatch")]
    AdmissionDigestMismatch,
    /// Preparation does not bind the exact authorization digest.
    #[error("preparation arm-authorization digest mismatch")]
    AuthorizationDigestMismatch,
    /// Durable `EffectArmed` receipt commitment is unset.
    #[error("effect-armed event digest must not be all zero")]
    ZeroEffectArmedEventDigest,
    /// Store frontier commitment is unset.
    #[error("store frontier digest must not be all zero")]
    ZeroStoreFrontierDigest,
    /// Preparation was assembled outside the authorization lifetime.
    #[error("effect-arm preparation occurred outside authorization lifetime")]
    PreparationOutsideAuthorizationWindow,
    /// Local-only authorization unexpectedly carried an external anchor.
    #[error("local-durable-only preparation must not carry an external anchor")]
    UnexpectedExternalAnchor,
    /// External-anchor mode is missing a non-zero external anchor commitment.
    #[error("external-anchor-before-effect mode requires a non-zero external anchor")]
    MissingExternalAnchor,
    /// Prepared store frontier is not retained in the verified current lineage.
    #[error("prepared operation store frontier is missing from current verified lineage")]
    PreparedFrontierMissing,
    /// Current live session differs from the arm reevaluation.
    #[error("live session changed after effect-arm authorization")]
    LiveSessionChanged,
    /// Current live subject differs from the arm reevaluation.
    #[error("live subject changed after effect-arm authorization")]
    LiveSubjectChanged,
    /// Consent/approval state changed after arm reevaluation.
    #[error("consent state changed after effect-arm authorization")]
    ConsentStateChanged,
    /// Policy state changed after arm reevaluation.
    #[error("policy state changed after effect-arm authorization")]
    PolicyStateChanged,
    /// Security/posture state changed after arm reevaluation.
    #[error("posture state changed after effect-arm authorization")]
    PostureStateChanged,
    /// Durable receipt head no longer equals the prepared `EffectArmed` event.
    #[error("durable receipt head changed after effect-arm preparation")]
    ReceiptHeadChanged,
    /// Current external anchor differs from the prepared anchor evidence.
    #[error("external anchor changed after effect-arm preparation")]
    ExternalAnchorChanged,
    /// Operation-store frontier validation failed.
    #[error("operation store frontier validation failed: {0}")]
    StoreFrontier(#[from] OperationStoreFrontierError),
    /// Canonical bincode serialization failed.
    #[error("bincode serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization(anchor_requirement: EffectAnchorRequirementV1) -> EffectArmAuthorizationV1 {
        EffectArmAuthorizationV1 {
            schema: EFFECT_ARM_AUTHORIZATION_SCHEMA_V1.to_string(),
            operation_id: [1u8; 16],
            admission_digest: [2u8; 32],
            grant_digest: [3u8; 32],
            use_digest: [4u8; 32],
            live_session_context_hash: [5u8; 32],
            live_subject_fingerprint: [6u8; 32],
            consent_state_digest: [7u8; 32],
            policy_state_digest: [8u8; 32],
            posture_state_digest: [9u8; 32],
            anchor_requirement,
            authorization_epoch: 44,
            evaluated_at_unix_ms: 1_000,
            expires_at_unix_ms: 31_000,
        }
    }

    fn frontier_zero() -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            [21u8; 16],
            0,
            0,
            [22u8; 32],
            [0u8; 32],
            1_500,
            &[],
            &[],
        )
        .unwrap()
    }

    fn frontier_one(previous: &OperationStoreFrontierV1) -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            previous.store_id,
            previous.generation,
            previous.checkpoint_sequence + 1,
            previous.store_schema_digest,
            previous.frontier_digest().unwrap(),
            previous.recorded_at_unix_ms + 1,
            &[],
            &[],
        )
        .unwrap()
    }

    fn preparation(
        auth: &EffectArmAuthorizationV1,
        frontier: &OperationStoreFrontierV1,
    ) -> EffectArmPreparationEvidenceV1 {
        EffectArmPreparationEvidenceV1 {
            schema: EFFECT_ARM_PREPARATION_EVIDENCE_SCHEMA_V1.to_string(),
            operation_id: auth.operation_id,
            admission_digest: auth.admission_digest,
            arm_authorization_digest: auth.authorization_digest().unwrap(),
            effect_armed_event_digest: [10u8; 32],
            store_frontier_digest: frontier.frontier_digest().unwrap(),
            external_anchor_digest: None,
            prepared_at_unix_ms: 2_000,
        }
    }

    fn final_context(
        auth: &EffectArmAuthorizationV1,
        prep: &EffectArmPreparationEvidenceV1,
    ) -> EffectArmFinalGateContextV1 {
        EffectArmFinalGateContextV1 {
            now_unix_ms: prep.prepared_at_unix_ms,
            live_session_context_hash: auth.live_session_context_hash,
            live_subject_fingerprint: auth.live_subject_fingerprint,
            consent_state_digest: auth.consent_state_digest,
            policy_state_digest: auth.policy_state_digest,
            posture_state_digest: auth.posture_state_digest,
            current_effect_armed_event_digest: prep.effect_armed_event_digest,
            current_external_anchor_digest: prep.external_anchor_digest,
        }
    }

    #[test]
    fn authorization_lifetime_is_bounded() {
        let mut auth = authorization(EffectAnchorRequirementV1::LocalDurableOnly);
        auth.expires_at_unix_ms =
            auth.evaluated_at_unix_ms + MAX_EFFECT_ARM_AUTHORIZATION_LIFETIME_MS_V1 + 1;
        assert!(matches!(
            auth.validate(),
            Err(EffectArmAuthorizationError::AuthorizationLifetimeTooLong)
        ));
    }

    #[test]
    fn expiry_is_exclusive() {
        let auth = authorization(EffectAnchorRequirementV1::LocalDurableOnly);
        assert!(!auth.is_live_at(auth.expires_at_unix_ms).unwrap());
    }

    #[test]
    fn external_mode_requires_anchor_evidence() {
        let auth = authorization(EffectAnchorRequirementV1::ExternalFrontierBeforeEffect {
            anchor_domain_digest: [13u8; 32],
        });
        let frontier = frontier_zero();
        let prep = preparation(&auth, &frontier);
        assert!(matches!(
            prep.validate_against(&auth),
            Err(EffectArmAuthorizationError::MissingExternalAnchor)
        ));
    }

    #[test]
    fn final_gate_detects_revocation_state_change() {
        let auth = authorization(EffectAnchorRequirementV1::LocalDurableOnly);
        let frontier = frontier_zero();
        let prep = preparation(&auth, &frontier);
        let mut current = final_context(&auth, &prep);
        current.consent_state_digest = [99u8; 32];
        assert!(matches!(
            validate_final_gate(&auth, &prep, &current, &[frontier]),
            Err(EffectArmAuthorizationError::ConsentStateChanged)
        ));
    }

    #[test]
    fn unrelated_frontier_advancement_does_not_cancel_effect() {
        let auth = authorization(EffectAnchorRequirementV1::LocalDurableOnly);
        let prepared_frontier = frontier_zero();
        let prep = preparation(&auth, &prepared_frontier);
        let current_frontier = frontier_one(&prepared_frontier);
        let current = final_context(&auth, &prep);
        assert!(validate_final_gate(
            &auth,
            &prep,
            &current,
            &[prepared_frontier, current_frontier],
        )
        .is_ok());
    }

    #[test]
    fn missing_prepared_frontier_fails_closed() {
        let auth = authorization(EffectAnchorRequirementV1::LocalDurableOnly);
        let prepared_frontier = frontier_zero();
        let prep = preparation(&auth, &prepared_frontier);
        let current_frontier = frontier_one(&prepared_frontier);
        let current = final_context(&auth, &prep);
        assert!(matches!(
            validate_final_gate(&auth, &prep, &current, &[current_frontier]),
            Err(EffectArmAuthorizationError::PreparedFrontierMissing)
        ));
    }

    #[test]
    fn final_gate_detects_receipt_head_change() {
        let auth = authorization(EffectAnchorRequirementV1::LocalDurableOnly);
        let frontier = frontier_zero();
        let prep = preparation(&auth, &frontier);
        let mut current = final_context(&auth, &prep);
        current.current_effect_armed_event_digest = [88u8; 32];
        assert!(matches!(
            validate_final_gate(&auth, &prep, &current, &[frontier]),
            Err(EffectArmAuthorizationError::ReceiptHeadChanged)
        ));
    }
}
