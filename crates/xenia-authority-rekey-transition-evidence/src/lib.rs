// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Native self-describing evidence for one already-verified Xenia rekey transition.
//!
//! Unlike a bare epoch hash, this evidence records the exact public rekey domain,
//! reason, epoch, handshake root, and parent hash. The epoch hash is recomputed by
//! the existing production `xenia-handshake` context implementation, so this crate
//! does not maintain a second copy of the lane/operator bincode schema.
//!
//! This crate does not authenticate a rekey proposal, derive keys, install keys,
//! or mutate a live session. The existing rekey verifier remains authoritative.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xenia_authority_activation_evidence::AuthorityActivationReceiptV1;
use xenia_authority_lineage_epoch_evidence::{
    AuthorityLineageEpochEvidenceError, AuthorityLineageEpochEvidenceV1,
};
use xenia_handshake::{
    OperatorRekeyEpochContext, OperatorRekeyReason, RekeyEpochContextV1, RekeyReason,
};

/// Schema version for canonical transition evidence.
pub const AUTHORITY_REKEY_TRANSITION_SCHEMA_VERSION: u8 = 1;
/// Domain separator shared with the independent Wire implementation.
pub const AUTHORITY_REKEY_TRANSITION_V1_DOMAIN: &[u8] =
    b"xenia.authority-rekey-transition-evidence.v1\0";

/// Exact historical rekey hash domain represented by a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RekeyTransitionProfileV1 {
    /// Multi-lane/session `RekeyEpochContextV1` domain.
    LaneSessionV1 = 1,
    /// Single-key operator-channel `OperatorRekeyEpochContext` domain.
    OperatorChannelV1 = 2,
}

/// Stable public evidence code for the exact semantic rekey reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RekeyTransitionReasonV1 {
    /// Lane/session operator-initiated rekey.
    LaneManual = 1,
    /// Lane/session frame-count threshold.
    LaneFrameCount = 2,
    /// Lane/session byte-count threshold.
    LaneByteCount = 3,
    /// Lane/session time threshold.
    LaneTime = 4,
    /// Lane/session transport-context change.
    LaneTransportChange = 5,
    /// Operator-channel periodic rotation.
    OperatorInterval = 16,
    /// Operator-channel explicit/manual rotation.
    OperatorManual = 17,
}

impl RekeyTransitionReasonV1 {
    fn profile(self) -> RekeyTransitionProfileV1 {
        match self {
            Self::LaneManual
            | Self::LaneFrameCount
            | Self::LaneByteCount
            | Self::LaneTime
            | Self::LaneTransportChange => RekeyTransitionProfileV1::LaneSessionV1,
            Self::OperatorInterval | Self::OperatorManual => {
                RekeyTransitionProfileV1::OperatorChannelV1
            }
        }
    }
}

/// Durable public context for one accepted rekey transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRekeyTransitionEvidenceV1 {
    /// Evidence schema version.
    pub schema_version: u8,
    /// Rekey hash domain/profile.
    pub profile: RekeyTransitionProfileV1,
    /// Exact semantic rekey reason.
    pub reason: RekeyTransitionReasonV1,
    /// New key epoch; epoch zero remains the authenticated handshake root.
    pub key_epoch: u64,
    /// Original authenticated handshake transcript hash.
    pub base_transcript_hash: [u8; 32],
    /// Previous accepted epoch hash, or handshake root for epoch one.
    pub previous_epoch_hash: [u8; 32],
    /// Exact production BLAKE3 rekey-context hash.
    pub epoch_hash: [u8; 32],
}

impl AuthorityRekeyTransitionEvidenceV1 {
    /// Build evidence using production `RekeyEpochContextV1` semantics.
    pub fn lane(
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: RekeyTransitionReasonV1,
    ) -> Result<Self, AuthorityRekeyTransitionEvidenceError> {
        if reason.profile() != RekeyTransitionProfileV1::LaneSessionV1 {
            return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch);
        }
        Self::new(
            RekeyTransitionProfileV1::LaneSessionV1,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
        )
    }

    /// Build evidence using production `OperatorRekeyEpochContext` semantics.
    pub fn operator(
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: RekeyTransitionReasonV1,
    ) -> Result<Self, AuthorityRekeyTransitionEvidenceError> {
        if reason.profile() != RekeyTransitionProfileV1::OperatorChannelV1 {
            return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch);
        }
        Self::new(
            RekeyTransitionProfileV1::OperatorChannelV1,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
        )
    }

    fn new(
        profile: RekeyTransitionProfileV1,
        reason: RekeyTransitionReasonV1,
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
    ) -> Result<Self, AuthorityRekeyTransitionEvidenceError> {
        if key_epoch == 0 {
            return Err(AuthorityRekeyTransitionEvidenceError::ZeroRekeyEpoch);
        }
        require_nonzero(&base_transcript_hash)?;
        require_nonzero(&previous_epoch_hash)?;
        let epoch_hash = production_epoch_hash(
            profile,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
        )?;
        Ok(Self {
            schema_version: AUTHORITY_REKEY_TRANSITION_SCHEMA_VERSION,
            profile,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            epoch_hash,
        })
    }

    /// Recompute the exact production epoch hash and validate all public fields.
    pub fn validate(&self) -> Result<(), AuthorityRekeyTransitionEvidenceError> {
        if self.schema_version != AUTHORITY_REKEY_TRANSITION_SCHEMA_VERSION {
            return Err(AuthorityRekeyTransitionEvidenceError::UnsupportedSchemaVersion);
        }
        if self.key_epoch == 0 {
            return Err(AuthorityRekeyTransitionEvidenceError::ZeroRekeyEpoch);
        }
        if self.reason.profile() != self.profile {
            return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch);
        }
        require_nonzero(&self.base_transcript_hash)?;
        require_nonzero(&self.previous_epoch_hash)?;
        require_nonzero(&self.epoch_hash)?;
        let computed = production_epoch_hash(
            self.profile,
            self.reason,
            self.key_epoch,
            self.base_transcript_hash,
            self.previous_epoch_hash,
        )?;
        if computed != self.epoch_hash {
            return Err(AuthorityRekeyTransitionEvidenceError::EpochHashMismatch);
        }
        Ok(())
    }

    /// Canonical fixed-width bytes shared with Wire.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            AUTHORITY_REKEY_TRANSITION_V1_DOMAIN.len() + 1 + 1 + 1 + 8 + 32 + 32 + 32,
        );
        out.extend_from_slice(AUTHORITY_REKEY_TRANSITION_V1_DOMAIN);
        out.push(self.schema_version);
        out.push(self.profile as u8);
        out.push(self.reason as u8);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out.extend_from_slice(&self.base_transcript_hash);
        out.extend_from_slice(&self.previous_epoch_hash);
        out.extend_from_slice(&self.epoch_hash);
        out
    }

    /// SHA-256 digest of canonical public transition evidence.
    pub fn evidence_digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

/// Advance lineage evidence only after the transition context validates against
/// production rekey semantics and the original activation root.
pub fn advance_lineage_after_verified_transition(
    lineage: &AuthorityLineageEpochEvidenceV1,
    activation: &AuthorityActivationReceiptV1,
    transition: &AuthorityRekeyTransitionEvidenceV1,
) -> Result<AuthorityLineageEpochEvidenceV1, AuthorityRekeyTransitionEvidenceError> {
    transition.validate()?;
    if activation.lineage_id != lineage.lineage_id
        || activation.activation_id != lineage.activation_id
    {
        return Err(AuthorityRekeyTransitionEvidenceError::ActivationLineageMismatch);
    }
    if transition.base_transcript_hash != activation.handshake_transcript_hash {
        return Err(AuthorityRekeyTransitionEvidenceError::BaseTranscriptMismatch);
    }
    lineage
        .advance_after_verified_rekey(
            transition.key_epoch,
            transition.previous_epoch_hash,
            transition.epoch_hash,
        )
        .map_err(AuthorityRekeyTransitionEvidenceError::Lineage)
}

fn production_epoch_hash(
    profile: RekeyTransitionProfileV1,
    reason: RekeyTransitionReasonV1,
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
) -> Result<[u8; 32], AuthorityRekeyTransitionEvidenceError> {
    match profile {
        RekeyTransitionProfileV1::LaneSessionV1 => {
            let reason = match reason {
                RekeyTransitionReasonV1::LaneManual => RekeyReason::Manual,
                RekeyTransitionReasonV1::LaneFrameCount => RekeyReason::FrameCount,
                RekeyTransitionReasonV1::LaneByteCount => RekeyReason::ByteCount,
                RekeyTransitionReasonV1::LaneTime => RekeyReason::Time,
                RekeyTransitionReasonV1::LaneTransportChange => RekeyReason::TransportChange,
                _ => return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch),
            };
            RekeyEpochContextV1::new(
                key_epoch,
                base_transcript_hash,
                previous_epoch_hash,
                reason,
            )
            .epoch_hash()
            .map_err(AuthorityRekeyTransitionEvidenceError::Handshake)
        }
        RekeyTransitionProfileV1::OperatorChannelV1 => {
            let reason = match reason {
                RekeyTransitionReasonV1::OperatorInterval => OperatorRekeyReason::Interval,
                RekeyTransitionReasonV1::OperatorManual => OperatorRekeyReason::Manual,
                _ => return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch),
            };
            OperatorRekeyEpochContext::new(
                key_epoch,
                base_transcript_hash,
                previous_epoch_hash,
                reason,
            )
            .epoch_hash()
            .map_err(AuthorityRekeyTransitionEvidenceError::Handshake)
        }
    }
}

fn require_nonzero(value: &[u8; 32]) -> Result<(), AuthorityRekeyTransitionEvidenceError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(AuthorityRekeyTransitionEvidenceError::ZeroCommitment)
    } else {
        Ok(())
    }
}

/// Failure while constructing or linking public rekey transition evidence.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityRekeyTransitionEvidenceError {
    /// Evidence schema version is unsupported.
    #[error("unsupported authority rekey transition evidence schema version")]
    UnsupportedSchemaVersion,
    /// Rekey epoch zero is reserved for the handshake root.
    #[error("rekey transition epoch must be greater than zero")]
    ZeroRekeyEpoch,
    /// Required commitment was the all-zero sentinel.
    #[error("rekey transition evidence contains an all-zero commitment")]
    ZeroCommitment,
    /// Reason does not belong to the selected rekey profile.
    #[error("rekey transition reason does not match its rekey profile")]
    ReasonProfileMismatch,
    /// Production rekey-context hashing failed.
    #[error("production rekey context hashing failed: {0}")]
    Handshake(#[source] xenia_handshake::HandshakeError),
    /// Stored epoch hash does not equal the production context hash.
    #[error("rekey transition epoch hash does not match production context")]
    EpochHashMismatch,
    /// Transition was paired with a different activation/lineage.
    #[error("rekey transition activation does not match local lineage")]
    ActivationLineageMismatch,
    /// Rekey context is rooted in a different handshake transcript.
    #[error("rekey transition base transcript does not match authority activation")]
    BaseTranscriptMismatch,
    /// Existing lineage continuity checks rejected the transition.
    #[error(transparent)]
    Lineage(#[from] AuthorityLineageEpochEvidenceError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activation() -> AuthorityActivationReceiptV1 {
        AuthorityActivationReceiptV1 {
            schema_version: 1,
            handshake_transcript_hash: [0x11; 32],
            base_v4_context_hash: core::array::from_fn(|index| index as u8),
            final_v5_context_hash: [0x22; 32],
            host_offer_hash: [0x33; 32],
            viewer_offer_hash: [0x44; 32],
            selected_context_hash: [0x55; 32],
            negotiation_binding_hash: [0x66; 32],
            local_policy_hash: [0x77; 32],
            host_identity_fingerprint: [0x88; 32],
            lineage_id: [0x99; 32],
            activation_id: [0xaa; 32],
        }
    }

    #[test]
    fn directly_matches_production_lane_and_operator_context_hashes() {
        let base = [0x11; 32];
        let previous = [0x22; 32];

        let lane = AuthorityRekeyTransitionEvidenceV1::lane(
            7,
            base,
            previous,
            RekeyTransitionReasonV1::LaneTransportChange,
        )
        .unwrap();
        assert_eq!(
            lane.epoch_hash,
            RekeyEpochContextV1::new(7, base, previous, RekeyReason::TransportChange)
                .epoch_hash()
                .unwrap()
        );

        let operator = AuthorityRekeyTransitionEvidenceV1::operator(
            7,
            base,
            previous,
            RekeyTransitionReasonV1::OperatorManual,
        )
        .unwrap();
        assert_eq!(
            operator.epoch_hash,
            OperatorRekeyEpochContext::new(7, base, previous, OperatorRekeyReason::Manual)
                .epoch_hash()
                .unwrap()
        );
    }

    #[test]
    fn validates_and_advances_matching_lineage() {
        let activation = activation();
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation).unwrap();
        let transition = AuthorityRekeyTransitionEvidenceV1::lane(
            1,
            activation.handshake_transcript_hash,
            initial.current_epoch_hash,
            RekeyTransitionReasonV1::LaneManual,
        )
        .unwrap();
        transition.validate().unwrap();
        let next = advance_lineage_after_verified_transition(&initial, &activation, &transition)
            .unwrap();
        assert_eq!(next.current_epoch_hash, transition.epoch_hash);
        assert_eq!(next.lineage_id, initial.lineage_id);
        assert_eq!(next.activation_id, initial.activation_id);
    }

    #[test]
    fn cross_domain_reason_and_tampered_hash_fail_closed() {
        assert!(matches!(
            AuthorityRekeyTransitionEvidenceV1::operator(
                1,
                [0x11; 32],
                [0x11; 32],
                RekeyTransitionReasonV1::LaneManual,
            ),
            Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch)
        ));

        let mut transition = AuthorityRekeyTransitionEvidenceV1::operator(
            1,
            [0x11; 32],
            [0x11; 32],
            RekeyTransitionReasonV1::OperatorInterval,
        )
        .unwrap();
        transition.epoch_hash[0] ^= 1;
        assert!(matches!(
            transition.validate(),
            Err(AuthorityRekeyTransitionEvidenceError::EpochHashMismatch)
        ));
    }
}
