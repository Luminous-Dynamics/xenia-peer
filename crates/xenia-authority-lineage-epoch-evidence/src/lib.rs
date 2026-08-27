// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Native independent reproduction of durable authority-lineage epoch evidence.
//!
//! This crate does not authenticate rekey proposals and does not derive or
//! install keys. It records already-verified Xenia epoch-chain facts and enforces
//! strict continuity for audit evidence.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xenia_authority_activation_evidence::AuthorityActivationReceiptV1;

/// Evidence schema version.
pub const AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION: u8 = 1;
/// Domain separator for canonical lineage-epoch evidence bytes.
pub const AUTHORITY_LINEAGE_EPOCH_V1_DOMAIN: &[u8] =
    b"xenia.authority-lineage-epoch-evidence.v1\0";

/// Durable evidence for one point in an authority-capable Xenia rekey lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLineageEpochEvidenceV1 {
    /// Evidence schema version.
    pub schema_version: u8,
    /// Stable public session-lineage identifier.
    pub lineage_id: [u8; 32],
    /// Local policy-bound activation identifier.
    pub activation_id: [u8; 32],
    /// Current Xenia key epoch. Epoch 0 is rooted in the handshake transcript.
    pub key_epoch: u64,
    /// Previous verified epoch-chain hash.
    pub previous_epoch_hash: [u8; 32],
    /// Current verified epoch-chain head.
    pub current_epoch_hash: [u8; 32],
}

impl AuthorityLineageEpochEvidenceV1 {
    /// Create epoch-0 evidence from an activation receipt.
    pub fn initial(
        activation: &AuthorityActivationReceiptV1,
    ) -> Result<Self, AuthorityLineageEpochEvidenceError> {
        require_nonzero(&activation.lineage_id)?;
        require_nonzero(&activation.activation_id)?;
        require_nonzero(&activation.handshake_transcript_hash)?;
        Ok(Self {
            schema_version: AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION,
            lineage_id: activation.lineage_id,
            activation_id: activation.activation_id,
            key_epoch: 0,
            previous_epoch_hash: activation.handshake_transcript_hash,
            current_epoch_hash: activation.handshake_transcript_hash,
        })
    }

    /// Advance after the existing Xenia rekey implementation has verified and
    /// accepted the next epoch-chain transition.
    pub fn advance_after_verified_rekey(
        &self,
        next_epoch: u64,
        previous_epoch_hash: [u8; 32],
        current_epoch_hash: [u8; 32],
    ) -> Result<Self, AuthorityLineageEpochEvidenceError> {
        if self.schema_version != AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION {
            return Err(AuthorityLineageEpochEvidenceError::UnsupportedSchemaVersion);
        }
        let expected_epoch = self
            .key_epoch
            .checked_add(1)
            .ok_or(AuthorityLineageEpochEvidenceError::EpochOverflow)?;
        if next_epoch != expected_epoch {
            return Err(AuthorityLineageEpochEvidenceError::NonContiguousEpoch);
        }
        if previous_epoch_hash != self.current_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::PreviousEpochHashMismatch);
        }
        require_nonzero(&current_epoch_hash)?;
        if current_epoch_hash == previous_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::UnchangedEpochHash);
        }
        Ok(Self {
            schema_version: AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION,
            lineage_id: self.lineage_id,
            activation_id: self.activation_id,
            key_epoch: next_epoch,
            previous_epoch_hash,
            current_epoch_hash,
        })
    }

    /// Canonical fixed-width evidence bytes shared with Wire.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTHORITY_LINEAGE_EPOCH_V1_DOMAIN.len() + 1 + 32 + 32 + 8 + 32 + 32);
        out.extend_from_slice(AUTHORITY_LINEAGE_EPOCH_V1_DOMAIN);
        out.push(self.schema_version);
        out.extend_from_slice(&self.lineage_id);
        out.extend_from_slice(&self.activation_id);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out.extend_from_slice(&self.previous_epoch_hash);
        out.extend_from_slice(&self.current_epoch_hash);
        out
    }

    /// SHA-256 digest of the canonical evidence bytes.
    pub fn evidence_digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Validate deserialized evidence shape without advancing it.
    pub fn validate(&self) -> Result<(), AuthorityLineageEpochEvidenceError> {
        if self.schema_version != AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION {
            return Err(AuthorityLineageEpochEvidenceError::UnsupportedSchemaVersion);
        }
        require_nonzero(&self.lineage_id)?;
        require_nonzero(&self.activation_id)?;
        require_nonzero(&self.previous_epoch_hash)?;
        require_nonzero(&self.current_epoch_hash)?;
        if self.key_epoch == 0 && self.previous_epoch_hash != self.current_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::InvalidInitialEpoch);
        }
        if self.key_epoch > 0 && self.previous_epoch_hash == self.current_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::UnchangedEpochHash);
        }
        Ok(())
    }
}

fn require_nonzero(value: &[u8; 32]) -> Result<(), AuthorityLineageEpochEvidenceError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(AuthorityLineageEpochEvidenceError::ZeroCommitment)
    } else {
        Ok(())
    }
}

/// Failure while constructing or validating lineage epoch evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityLineageEpochEvidenceError {
    /// Evidence schema version is unsupported.
    #[error("unsupported authority lineage epoch evidence schema version")]
    UnsupportedSchemaVersion,
    /// Epoch increment overflowed u64.
    #[error("authority lineage key epoch overflow")]
    EpochOverflow,
    /// Next epoch was not exactly current+1.
    #[error("authority lineage rekey epoch is not contiguous")]
    NonContiguousEpoch,
    /// Previous epoch hash does not equal the local chain head.
    #[error("authority lineage previous epoch hash does not match local chain head")]
    PreviousEpochHashMismatch,
    /// Required commitment is the all-zero sentinel.
    #[error("authority lineage epoch evidence contains an all-zero commitment")]
    ZeroCommitment,
    /// Accepted rekey did not change the epoch-chain hash.
    #[error("authority lineage rekey must advance to a distinct epoch hash")]
    UnchangedEpochHash,
    /// Epoch 0 does not use one consistent handshake root.
    #[error("authority lineage epoch-0 evidence has inconsistent handshake root")]
    InvalidInitialEpoch,
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
            lineage_id: [
                0xcb, 0x7a, 0x0b, 0xc3, 0x7f, 0xb0, 0x4a, 0x28, 0x64, 0x79, 0xa9, 0xbe, 0xde,
                0x74, 0x0b, 0x68, 0xcb, 0x9c, 0x6a, 0x86, 0xf6, 0x02, 0x57, 0x82, 0x29, 0x89,
                0xc2, 0x84, 0x30, 0x28, 0xa0, 0xda,
            ],
            activation_id: [
                0x1b, 0xa7, 0x07, 0x73, 0xca, 0x41, 0x79, 0x59, 0x3c, 0x90, 0x27, 0x9e, 0x44,
                0xf4, 0x07, 0x68, 0x85, 0x83, 0xb9, 0x76, 0xbd, 0x70, 0x28, 0xd0, 0x5c, 0x3f,
                0xec, 0xcf, 0xbc, 0x68, 0x40, 0xc3,
            ],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn reproduces_wire_epoch_zero_and_one_vectors() {
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation()).unwrap();
        assert_eq!(initial.canonical_bytes().len(), 179);
        assert_eq!(
            hex(&initial.evidence_digest()),
            "47eb22fe9ff6baf4b1a9b64c6643a2f08e3de67c4c17411710f57a17fed423af"
        );
        let next = initial
            .advance_after_verified_rekey(1, [0x11; 32], [0x66; 32])
            .unwrap();
        assert_eq!(next.lineage_id, initial.lineage_id);
        assert_eq!(next.activation_id, initial.activation_id);
        assert_eq!(
            hex(&next.evidence_digest()),
            "4d2bcc3eec6d1b8e3c9fb56b329865ab73b45ca1099f52262d55a2e4adf7ad52"
        );
    }

    #[test]
    fn invalid_transitions_fail_closed() {
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation()).unwrap();
        assert_eq!(
            initial
                .advance_after_verified_rekey(2, [0x11; 32], [0x66; 32])
                .unwrap_err(),
            AuthorityLineageEpochEvidenceError::NonContiguousEpoch
        );
        assert_eq!(
            initial
                .advance_after_verified_rekey(1, [0x77; 32], [0x66; 32])
                .unwrap_err(),
            AuthorityLineageEpochEvidenceError::PreviousEpochHashMismatch
        );
        assert_eq!(
            initial
                .advance_after_verified_rekey(1, [0x11; 32], [0x11; 32])
                .unwrap_err(),
            AuthorityLineageEpochEvidenceError::UnchangedEpochHash
        );
    }
}
