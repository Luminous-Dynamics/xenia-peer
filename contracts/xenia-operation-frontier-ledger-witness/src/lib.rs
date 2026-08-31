// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Signed external witness contracts for Xenia operation-store anti-rollback frontiers.
//!
//! The operation-store frontier contract intentionally does not prescribe a signature or
//! transport. This crate defines one concrete V1 composition with Xenia's ledger authority:
//! an operation-store frontier anchor is bound to one already-authenticated ledger checkpoint
//! and signed by the same Ed25519 authority key.
//!
//! The serialized witness does not authenticate the referenced ledger checkpoint by itself.
//! Verification that makes an anti-rollback decision requires an
//! [`AuthenticatedLedgerCheckpointV1`] obtained from the ledger/checkpoint trust path (for
//! example `xenia-ledger` checkpoint verification plus a retained trusted-key binding).
//!
//! V1 deliberately keeps witness lineage within one operation-store identity/generation and one
//! ledger public key. Store-generation replacement/rollover requires a separately governed
//! recovery transition rather than being smuggled through an ordinary witness successor.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use xenia_operation_store_frontier::{
    OperationStoreFrontierAnchorV1, OperationStoreFrontierError, OperationStoreFrontierV1,
    verify_anchor_lineage,
};

/// Exact payload schema for a ledger-backed operation-frontier witness.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_PAYLOAD_SCHEMA_V1: &str =
    "xenia-operation-frontier-ledger-witness-payload-v1";
/// Exact signed witness schema.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_SCHEMA_V1: &str =
    "xenia-operation-frontier-ledger-witness-v1";
/// Exact checkpoint-binding schema.
pub const LEDGER_CHECKPOINT_BINDING_SCHEMA_V1: &str =
    "xenia-operation-frontier-ledger-checkpoint-binding-v1";
/// Domain separator for the Ed25519 message signed by a witness.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_MESSAGE_DOMAIN_V1: &[u8] =
    b"xenia-operation-frontier-ledger-witness-message-v1";
/// Domain separator for exact signed-witness commitments used by successor chains.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-frontier-ledger-witness-digest-v1";

/// Already-authenticated checkpoint facts supplied by the ledger trust path.
///
/// This context is intentionally not serializable. A caller must obtain it by verifying the
/// actual ledger checkpoint/signature and trusted ledger-key continuity. Constructing matching
/// serialized witness bytes is therefore insufficient to manufacture checkpoint authenticity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedLedgerCheckpointV1 {
    /// Fingerprint of the exact signed checkpoint object.
    pub checkpoint_fingerprint: [u8; 32],
    /// Number of ledger entries covered by that checkpoint.
    pub entry_count: u64,
    /// Exact ledger head committed by the checkpoint.
    pub head_hash: [u8; 32],
    /// Trusted ledger Ed25519 public key.
    pub ledger_public_key: [u8; 32],
    /// Signed checkpoint timestamp in Unix seconds.
    pub timestamp_unix_secs: u64,
}

impl AuthenticatedLedgerCheckpointV1 {
    /// Validate unset sentinels before using this trusted context.
    pub fn validate(self) -> Result<(), FrontierLedgerWitnessError> {
        require_nonzero32(
            self.checkpoint_fingerprint,
            FrontierLedgerWitnessError::ZeroLedgerCheckpointFingerprint,
        )?;
        require_nonzero32(
            self.ledger_public_key,
            FrontierLedgerWitnessError::ZeroLedgerPublicKey,
        )?;
        if self.entry_count == 0 {
            if self.head_hash != [0u8; 32] {
                return Err(FrontierLedgerWitnessError::EmptyLedgerHasHead);
            }
        } else {
            require_nonzero32(
                self.head_hash,
                FrontierLedgerWitnessError::NonEmptyLedgerMissingHead,
            )?;
        }
        VerifyingKey::from_bytes(&self.ledger_public_key)
            .map_err(|_| FrontierLedgerWitnessError::MalformedLedgerPublicKey)?;
        Ok(())
    }
}

/// Serializable commitment to one authenticated Xenia ledger checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpointBindingV1 {
    /// Exact schema.
    pub schema: String,
    /// Fingerprint of the exact signed checkpoint object.
    pub checkpoint_fingerprint: [u8; 32],
    /// Number of ledger entries covered by the checkpoint.
    pub entry_count: u64,
    /// Exact ledger head committed by the checkpoint.
    pub head_hash: [u8; 32],
    /// Ledger Ed25519 public key that signs both the checkpoint and witness.
    pub ledger_public_key: [u8; 32],
    /// Signed checkpoint timestamp in Unix seconds.
    pub timestamp_unix_secs: u64,
}

impl LedgerCheckpointBindingV1 {
    /// Build a serialized binding from already-authenticated checkpoint facts.
    pub fn from_authenticated(
        authenticated: AuthenticatedLedgerCheckpointV1,
    ) -> Result<Self, FrontierLedgerWitnessError> {
        authenticated.validate()?;
        let value = Self {
            schema: LEDGER_CHECKPOINT_BINDING_SCHEMA_V1.to_string(),
            checkpoint_fingerprint: authenticated.checkpoint_fingerprint,
            entry_count: authenticated.entry_count,
            head_hash: authenticated.head_hash,
            ledger_public_key: authenticated.ledger_public_key,
            timestamp_unix_secs: authenticated.timestamp_unix_secs,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax without authenticating the referenced checkpoint.
    pub fn validate(&self) -> Result<(), FrontierLedgerWitnessError> {
        if self.schema != LEDGER_CHECKPOINT_BINDING_SCHEMA_V1 {
            return Err(FrontierLedgerWitnessError::UnsupportedCheckpointBindingSchema);
        }
        AuthenticatedLedgerCheckpointV1 {
            checkpoint_fingerprint: self.checkpoint_fingerprint,
            entry_count: self.entry_count,
            head_hash: self.head_hash,
            ledger_public_key: self.ledger_public_key,
            timestamp_unix_secs: self.timestamp_unix_secs,
        }
        .validate()
    }

    /// Require exact equality with the independently authenticated checkpoint context.
    pub fn validate_against(
        &self,
        authenticated: AuthenticatedLedgerCheckpointV1,
    ) -> Result<(), FrontierLedgerWitnessError> {
        self.validate()?;
        authenticated.validate()?;
        if self.checkpoint_fingerprint != authenticated.checkpoint_fingerprint {
            return Err(FrontierLedgerWitnessError::LedgerCheckpointFingerprintMismatch);
        }
        if self.entry_count != authenticated.entry_count {
            return Err(FrontierLedgerWitnessError::LedgerEntryCountMismatch);
        }
        if self.head_hash != authenticated.head_hash {
            return Err(FrontierLedgerWitnessError::LedgerHeadMismatch);
        }
        if self.ledger_public_key != authenticated.ledger_public_key {
            return Err(FrontierLedgerWitnessError::LedgerPublicKeyMismatch);
        }
        if self.timestamp_unix_secs != authenticated.timestamp_unix_secs {
            return Err(FrontierLedgerWitnessError::LedgerCheckpointTimestampMismatch);
        }
        Ok(())
    }
}

/// Unsigned semantic payload authenticated by one ledger-backed witness signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationFrontierLedgerWitnessPayloadV1 {
    /// Exact payload schema.
    pub schema: String,
    /// Exact externally storable operation-store frontier anchor being witnessed.
    pub frontier_anchor: OperationStoreFrontierAnchorV1,
    /// Exact ledger checkpoint state serving as the witness authority/continuity binding.
    pub ledger_checkpoint: LedgerCheckpointBindingV1,
    /// Monotonic sequence in this witness lineage.
    pub witness_sequence: u64,
    /// Digest of the previous exact signed witness, or all zeros for witness zero.
    pub previous_witness_digest: [u8; 32],
    /// Time the witness was created, in Unix milliseconds.
    pub witnessed_at_unix_ms: u64,
}

impl OperationFrontierLedgerWitnessPayloadV1 {
    /// Construct one witness payload from an operation frontier anchor and verified checkpoint.
    pub fn new(
        frontier_anchor: OperationStoreFrontierAnchorV1,
        checkpoint: AuthenticatedLedgerCheckpointV1,
        witness_sequence: u64,
        previous_witness_digest: [u8; 32],
        witnessed_at_unix_ms: u64,
    ) -> Result<Self, FrontierLedgerWitnessError> {
        frontier_anchor.validate()?;
        checkpoint.validate()?;
        let checkpoint_ms = checkpoint_timestamp_ms(checkpoint.timestamp_unix_secs)?;
        if witnessed_at_unix_ms < frontier_anchor.anchored_at_unix_ms {
            return Err(FrontierLedgerWitnessError::WitnessPredatesFrontierAnchor);
        }
        if witnessed_at_unix_ms < checkpoint_ms {
            return Err(FrontierLedgerWitnessError::WitnessPredatesLedgerCheckpoint);
        }
        if witness_sequence == 0 {
            if previous_witness_digest != [0u8; 32] {
                return Err(FrontierLedgerWitnessError::GenesisWitnessHasPrevious);
            }
        } else if previous_witness_digest == [0u8; 32] {
            return Err(FrontierLedgerWitnessError::MissingPreviousWitnessDigest);
        }
        let value = Self {
            schema: OPERATION_FRONTIER_LEDGER_WITNESS_PAYLOAD_SCHEMA_V1.to_string(),
            frontier_anchor,
            ledger_checkpoint: LedgerCheckpointBindingV1::from_authenticated(checkpoint)?,
            witness_sequence,
            previous_witness_digest,
            witnessed_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate payload-local invariants without authenticating the ledger checkpoint.
    pub fn validate(&self) -> Result<(), FrontierLedgerWitnessError> {
        if self.schema != OPERATION_FRONTIER_LEDGER_WITNESS_PAYLOAD_SCHEMA_V1 {
            return Err(FrontierLedgerWitnessError::UnsupportedPayloadSchema);
        }
        self.frontier_anchor.validate()?;
        self.ledger_checkpoint.validate()?;
        let checkpoint_ms = checkpoint_timestamp_ms(self.ledger_checkpoint.timestamp_unix_secs)?;
        if self.witnessed_at_unix_ms < self.frontier_anchor.anchored_at_unix_ms {
            return Err(FrontierLedgerWitnessError::WitnessPredatesFrontierAnchor);
        }
        if self.witnessed_at_unix_ms < checkpoint_ms {
            return Err(FrontierLedgerWitnessError::WitnessPredatesLedgerCheckpoint);
        }
        if self.witness_sequence == 0 {
            if self.previous_witness_digest != [0u8; 32] {
                return Err(FrontierLedgerWitnessError::GenesisWitnessHasPrevious);
            }
        } else if self.previous_witness_digest == [0u8; 32] {
            return Err(FrontierLedgerWitnessError::MissingPreviousWitnessDigest);
        }
        Ok(())
    }

    /// Deterministic bytes signed by the ledger authority.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FrontierLedgerWitnessError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }
}

/// Signed external witness joining an operation-store frontier to one ledger checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationFrontierLedgerWitnessV1 {
    /// Exact signed-witness schema.
    pub schema: String,
    /// Semantic payload authenticated by `signature`.
    pub payload: OperationFrontierLedgerWitnessPayloadV1,
    /// Ed25519 signature by the exact ledger key embedded in the checkpoint binding.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl OperationFrontierLedgerWitnessV1 {
    /// Sign one payload with the exact same Ed25519 identity as the bound ledger checkpoint.
    pub fn sign_ed25519(
        payload: OperationFrontierLedgerWitnessPayloadV1,
        signing_key: &SigningKey,
    ) -> Result<Self, FrontierLedgerWitnessError> {
        payload.validate()?;
        if signing_key.verifying_key().to_bytes() != payload.ledger_checkpoint.ledger_public_key {
            return Err(FrontierLedgerWitnessError::SigningKeyDoesNotMatchLedger);
        }
        let message = witness_message(&payload)?;
        let signature = signing_key.sign(&message).to_bytes();
        let value = Self {
            schema: OPERATION_FRONTIER_LEDGER_WITNESS_SCHEMA_V1.to_string(),
            payload,
            signature,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate schema, payload shape, and the Ed25519 witness signature.
    ///
    /// This does not independently authenticate the ledger checkpoint binding. Call
    /// [`Self::validate_against_authenticated_checkpoint`] when making a trust decision.
    pub fn validate(&self) -> Result<(), FrontierLedgerWitnessError> {
        if self.schema != OPERATION_FRONTIER_LEDGER_WITNESS_SCHEMA_V1 {
            return Err(FrontierLedgerWitnessError::UnsupportedWitnessSchema);
        }
        self.payload.validate()?;
        let verifying_key = VerifyingKey::from_bytes(&self.payload.ledger_checkpoint.ledger_public_key)
            .map_err(|_| FrontierLedgerWitnessError::MalformedLedgerPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&witness_message(&self.payload)?, &signature)
            .map_err(|_| FrontierLedgerWitnessError::BadWitnessSignature)
    }

    /// Require this signed witness to bind the exact independently authenticated checkpoint.
    pub fn validate_against_authenticated_checkpoint(
        &self,
        checkpoint: AuthenticatedLedgerCheckpointV1,
    ) -> Result<(), FrontierLedgerWitnessError> {
        self.validate()?;
        self.payload.ledger_checkpoint.validate_against(checkpoint)
    }

    /// Deterministic exact signed bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FrontierLedgerWitnessError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable digest of the exact signed witness used by successor witnesses.
    pub fn witness_digest(&self) -> Result<[u8; 32], FrontierLedgerWitnessError> {
        Ok(domain_digest(
            OPERATION_FRONTIER_LEDGER_WITNESS_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    /// Validate this witness as an exact successor in the same V1 witness lineage.
    pub fn validate_successor(
        &self,
        previous: &Self,
    ) -> Result<(), FrontierLedgerWitnessError> {
        previous.validate()?;
        self.validate()?;

        let expected_sequence = previous
            .payload
            .witness_sequence
            .checked_add(1)
            .ok_or(FrontierLedgerWitnessError::WitnessSequenceOverflow)?;
        if self.payload.witness_sequence != expected_sequence {
            return Err(FrontierLedgerWitnessError::WitnessSequenceMismatch);
        }
        if self.payload.previous_witness_digest != previous.witness_digest()? {
            return Err(FrontierLedgerWitnessError::PreviousWitnessDigestMismatch);
        }

        let old_anchor = &previous.payload.frontier_anchor;
        let new_anchor = &self.payload.frontier_anchor;
        if new_anchor.store_id != old_anchor.store_id {
            return Err(FrontierLedgerWitnessError::StoreIdChanged);
        }
        if new_anchor.generation != old_anchor.generation {
            return Err(FrontierLedgerWitnessError::StoreGenerationChanged);
        }
        if new_anchor.checkpoint_sequence < old_anchor.checkpoint_sequence {
            return Err(FrontierLedgerWitnessError::FrontierCheckpointRegressed);
        }
        if new_anchor.checkpoint_sequence == old_anchor.checkpoint_sequence
            && new_anchor.frontier_digest != old_anchor.frontier_digest
        {
            return Err(FrontierLedgerWitnessError::FrontierForkAtSameCheckpoint);
        }
        if new_anchor.anchored_at_unix_ms < old_anchor.anchored_at_unix_ms {
            return Err(FrontierLedgerWitnessError::FrontierAnchorTimestampRegressed);
        }

        let old_checkpoint = &previous.payload.ledger_checkpoint;
        let new_checkpoint = &self.payload.ledger_checkpoint;
        if new_checkpoint.ledger_public_key != old_checkpoint.ledger_public_key {
            return Err(FrontierLedgerWitnessError::LedgerKeyChanged);
        }
        if new_checkpoint.entry_count < old_checkpoint.entry_count {
            return Err(FrontierLedgerWitnessError::LedgerEntryCountRegressed);
        }
        if new_checkpoint.entry_count == old_checkpoint.entry_count {
            if new_checkpoint.head_hash != old_checkpoint.head_hash
                || new_checkpoint.checkpoint_fingerprint != old_checkpoint.checkpoint_fingerprint
            {
                return Err(FrontierLedgerWitnessError::LedgerForkAtSameHeight);
            }
        }
        if new_checkpoint.timestamp_unix_secs < old_checkpoint.timestamp_unix_secs {
            return Err(FrontierLedgerWitnessError::LedgerCheckpointTimestampRegressed);
        }
        if self.payload.witnessed_at_unix_ms < previous.payload.witnessed_at_unix_ms {
            return Err(FrontierLedgerWitnessError::WitnessTimestampRegressed);
        }
        Ok(())
    }
}

/// Verify a retained signed witness lineage in witness-sequence order.
pub fn verify_witness_chain(
    witnesses: &[OperationFrontierLedgerWitnessV1],
) -> Result<(), FrontierLedgerWitnessError> {
    let Some(first) = witnesses.first() else {
        return Ok(());
    };
    first.validate()?;
    for pair in witnesses.windows(2) {
        pair[1].validate_successor(&pair[0])?;
    }
    Ok(())
}

/// Final restart/rollback gate for the newest externally retained witness.
///
/// The caller supplies the independently authenticated ledger-checkpoint facts and the local
/// retained operation-frontier chain. Success proves that the witness is correctly signed by the
/// ledger authority, names the exact authenticated checkpoint, and that the local operation store
/// still contains the externally witnessed frontier in its valid retained ancestry.
pub fn verify_latest_witness_against_local(
    witness: &OperationFrontierLedgerWitnessV1,
    checkpoint: AuthenticatedLedgerCheckpointV1,
    local_frontiers: &[OperationStoreFrontierV1],
) -> Result<(), FrontierLedgerWitnessError> {
    witness.validate_against_authenticated_checkpoint(checkpoint)?;
    verify_anchor_lineage(&witness.payload.frontier_anchor, local_frontiers)?;
    Ok(())
}

/// Domain-separated witness signing message.
pub fn witness_message(
    payload: &OperationFrontierLedgerWitnessPayloadV1,
) -> Result<Vec<u8>, FrontierLedgerWitnessError> {
    let bytes = payload.canonical_bytes()?;
    let mut message = Vec::with_capacity(
        OPERATION_FRONTIER_LEDGER_WITNESS_MESSAGE_DOMAIN_V1.len() + 8 + bytes.len(),
    );
    message.extend_from_slice(OPERATION_FRONTIER_LEDGER_WITNESS_MESSAGE_DOMAIN_V1);
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(&bytes);
    Ok(message)
}

/// Witness validation failure.
#[derive(Debug, Error)]
pub enum FrontierLedgerWitnessError {
    /// Frontier/anchor contract rejected the supplied state.
    #[error("operation-store frontier rejected witness state: {0}")]
    Frontier(#[from] OperationStoreFrontierError),
    /// Bincode serialization failed.
    #[error("witness serialization failed: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    /// Checkpoint-binding schema mismatch.
    #[error("unsupported ledger checkpoint binding schema")]
    UnsupportedCheckpointBindingSchema,
    /// Witness payload schema mismatch.
    #[error("unsupported frontier-ledger witness payload schema")]
    UnsupportedPayloadSchema,
    /// Signed witness schema mismatch.
    #[error("unsupported frontier-ledger witness schema")]
    UnsupportedWitnessSchema,
    /// Checkpoint fingerprint is unset.
    #[error("ledger checkpoint fingerprint must not be zero")]
    ZeroLedgerCheckpointFingerprint,
    /// Ledger public key is unset.
    #[error("ledger public key must not be zero")]
    ZeroLedgerPublicKey,
    /// Empty ledger checkpoint unexpectedly has a head.
    #[error("empty ledger checkpoint must use a zero head hash")]
    EmptyLedgerHasHead,
    /// Non-empty ledger checkpoint is missing its head.
    #[error("non-empty ledger checkpoint must use a nonzero head hash")]
    NonEmptyLedgerMissingHead,
    /// Ledger public key is not a valid Ed25519 key.
    #[error("ledger public key is malformed")]
    MalformedLedgerPublicKey,
    /// Serialized checkpoint fingerprint differs from authenticated checkpoint facts.
    #[error("ledger checkpoint fingerprint mismatch")]
    LedgerCheckpointFingerprintMismatch,
    /// Serialized checkpoint entry count differs from authenticated checkpoint facts.
    #[error("ledger checkpoint entry count mismatch")]
    LedgerEntryCountMismatch,
    /// Serialized checkpoint head differs from authenticated checkpoint facts.
    #[error("ledger checkpoint head mismatch")]
    LedgerHeadMismatch,
    /// Serialized checkpoint key differs from authenticated checkpoint facts.
    #[error("ledger public key mismatch")]
    LedgerPublicKeyMismatch,
    /// Serialized checkpoint timestamp differs from authenticated checkpoint facts.
    #[error("ledger checkpoint timestamp mismatch")]
    LedgerCheckpointTimestampMismatch,
    /// Checkpoint seconds could not be represented in milliseconds.
    #[error("ledger checkpoint timestamp overflow")]
    LedgerCheckpointTimestampOverflow,
    /// Witness was recorded before the frontier anchor it claims to retain.
    #[error("witness timestamp predates frontier anchor")]
    WitnessPredatesFrontierAnchor,
    /// Witness was recorded before the ledger checkpoint it claims to bind.
    #[error("witness timestamp predates ledger checkpoint")]
    WitnessPredatesLedgerCheckpoint,
    /// Genesis witness unexpectedly references a predecessor.
    #[error("witness zero must not reference a previous witness")]
    GenesisWitnessHasPrevious,
    /// Non-genesis witness is missing a predecessor commitment.
    #[error("non-genesis witness requires a previous witness digest")]
    MissingPreviousWitnessDigest,
    /// Signing key does not equal the ledger checkpoint's public key.
    #[error("witness signing key does not match ledger public key")]
    SigningKeyDoesNotMatchLedger,
    /// Witness signature failed verification.
    #[error("frontier-ledger witness Ed25519 signature is invalid")]
    BadWitnessSignature,
    /// Witness sequence overflow.
    #[error("witness sequence overflow")]
    WitnessSequenceOverflow,
    /// Witness sequence is not exactly previous + 1.
    #[error("witness sequence is not the exact successor")]
    WitnessSequenceMismatch,
    /// Previous-witness digest does not bind the exact prior signed witness.
    #[error("previous witness digest mismatch")]
    PreviousWitnessDigestMismatch,
    /// Store identity changed within one V1 witness lineage.
    #[error("operation-store identity changed within witness lineage")]
    StoreIdChanged,
    /// Store generation changed without a separately governed transition.
    #[error("operation-store generation changed within witness lineage")]
    StoreGenerationChanged,
    /// Operation frontier checkpoint sequence regressed.
    #[error("operation frontier checkpoint sequence regressed")]
    FrontierCheckpointRegressed,
    /// Same frontier checkpoint sequence committed to a different digest.
    #[error("operation frontier fork detected at same checkpoint sequence")]
    FrontierForkAtSameCheckpoint,
    /// Frontier anchor timestamp regressed.
    #[error("frontier anchor timestamp regressed")]
    FrontierAnchorTimestampRegressed,
    /// Ledger public key changed within one V1 witness lineage.
    #[error("ledger public key changed within witness lineage")]
    LedgerKeyChanged,
    /// Ledger checkpoint entry count regressed.
    #[error("ledger checkpoint entry count regressed")]
    LedgerEntryCountRegressed,
    /// Same ledger checkpoint height committed to different checkpoint identity/head.
    #[error("ledger checkpoint fork detected at same entry count")]
    LedgerForkAtSameHeight,
    /// Ledger checkpoint timestamp regressed.
    #[error("ledger checkpoint timestamp regressed")]
    LedgerCheckpointTimestampRegressed,
    /// Witness wall-clock evidence regressed.
    #[error("witness timestamp regressed")]
    WitnessTimestampRegressed,
}

fn checkpoint_timestamp_ms(timestamp_unix_secs: u64) -> Result<u64, FrontierLedgerWitnessError> {
    timestamp_unix_secs
        .checked_mul(1_000)
        .ok_or(FrontierLedgerWitnessError::LedgerCheckpointTimestampOverflow)
}

fn require_nonzero32(
    value: [u8; 32],
    error: FrontierLedgerWitnessError,
) -> Result<(), FrontierLedgerWitnessError> {
    if value == [0u8; 32] {
        Err(error)
    } else {
        Ok(())
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operation_store_frontier::{
        AdmissionFrontierEntryV1, ReceiptHeadFrontierEntryV1,
    };

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn checkpoint(key: &SigningKey, entry_count: u64, marker: u8) -> AuthenticatedLedgerCheckpointV1 {
        AuthenticatedLedgerCheckpointV1 {
            checkpoint_fingerprint: [marker; 32],
            entry_count,
            head_hash: if entry_count == 0 { [0; 32] } else { [marker.wrapping_add(1); 32] },
            ledger_public_key: key.verifying_key().to_bytes(),
            timestamp_unix_secs: 10 + entry_count,
        }
    }

    fn frontier(
        sequence: u64,
        previous: [u8; 32],
        admission_count: usize,
    ) -> OperationStoreFrontierV1 {
        let admissions: Vec<_> = (0..admission_count)
            .map(|index| AdmissionFrontierEntryV1 {
                admission_sequence: index as u64,
                operation_id: [index as u8 + 1; 16],
                admission_digest: [index as u8 + 11; 32],
            })
            .collect();
        let heads: Vec<_> = admissions
            .iter()
            .map(|entry| ReceiptHeadFrontierEntryV1 {
                operation_id: entry.operation_id,
                event_index: None,
                event_digest: [0; 32],
            })
            .collect();
        OperationStoreFrontierV1::from_state(
            [0xA1; 16],
            0,
            sequence,
            [0xB2; 32],
            previous,
            20_000 + sequence,
            &admissions,
            &heads,
        )
        .unwrap()
    }

    fn witness(
        key: &SigningKey,
        frontier: &OperationStoreFrontierV1,
        checkpoint: AuthenticatedLedgerCheckpointV1,
        witness_sequence: u64,
        previous_witness_digest: [u8; 32],
    ) -> OperationFrontierLedgerWitnessV1 {
        let anchor = frontier.anchor(30_000 + frontier.checkpoint_sequence).unwrap();
        let payload = OperationFrontierLedgerWitnessPayloadV1::new(
            anchor,
            checkpoint,
            witness_sequence,
            previous_witness_digest,
            40_000 + witness_sequence,
        )
        .unwrap();
        OperationFrontierLedgerWitnessV1::sign_ed25519(payload, key).unwrap()
    }

    #[test]
    fn witness_binds_exact_authenticated_checkpoint_and_frontier_ancestry() {
        let key = signing_key(7);
        let f0 = frontier(0, [0; 32], 0);
        let f1 = frontier(1, f0.frontier_digest().unwrap(), 1);
        let cp = checkpoint(&key, 3, 0x31);
        let w = witness(&key, &f1, cp, 0, [0; 32]);

        verify_latest_witness_against_local(&w, cp, &[f0, f1]).unwrap();
    }

    #[test]
    fn restored_store_behind_external_witness_is_rejected() {
        let key = signing_key(8);
        let f0 = frontier(0, [0; 32], 0);
        let f1 = frontier(1, f0.frontier_digest().unwrap(), 1);
        let cp = checkpoint(&key, 4, 0x32);
        let w = witness(&key, &f1, cp, 0, [0; 32]);

        assert!(matches!(
            verify_latest_witness_against_local(&w, cp, &[f0]),
            Err(FrontierLedgerWitnessError::Frontier(_))
        ));
    }

    #[test]
    fn checkpoint_bytes_cannot_self_authenticate() {
        let key = signing_key(9);
        let f0 = frontier(0, [0; 32], 0);
        let cp = checkpoint(&key, 5, 0x33);
        let w = witness(&key, &f0, cp, 0, [0; 32]);
        let wrong = AuthenticatedLedgerCheckpointV1 {
            checkpoint_fingerprint: [0xEE; 32],
            ..cp
        };

        assert!(matches!(
            w.validate_against_authenticated_checkpoint(wrong),
            Err(FrontierLedgerWitnessError::LedgerCheckpointFingerprintMismatch)
        ));
    }

    #[test]
    fn wrong_signing_key_is_rejected() {
        let key = signing_key(10);
        let wrong = signing_key(11);
        let f0 = frontier(0, [0; 32], 0);
        let cp = checkpoint(&key, 6, 0x34);
        let payload = OperationFrontierLedgerWitnessPayloadV1::new(
            f0.anchor(30_000).unwrap(),
            cp,
            0,
            [0; 32],
            40_000,
        )
        .unwrap();

        assert!(matches!(
            OperationFrontierLedgerWitnessV1::sign_ed25519(payload, &wrong),
            Err(FrontierLedgerWitnessError::SigningKeyDoesNotMatchLedger)
        ));
    }

    #[test]
    fn tampering_breaks_signature() {
        let key = signing_key(12);
        let f0 = frontier(0, [0; 32], 0);
        let cp = checkpoint(&key, 7, 0x35);
        let mut w = witness(&key, &f0, cp, 0, [0; 32]);
        w.payload.frontier_anchor.frontier_digest[0] ^= 1;

        assert!(matches!(w.validate(), Err(FrontierLedgerWitnessError::BadWitnessSignature)));
    }

    #[test]
    fn successor_allows_frontier_advance_with_same_ledger_checkpoint() {
        let key = signing_key(13);
        let f0 = frontier(0, [0; 32], 0);
        let f1 = frontier(1, f0.frontier_digest().unwrap(), 1);
        let cp = checkpoint(&key, 8, 0x36);
        let w0 = witness(&key, &f0, cp, 0, [0; 32]);
        let w1 = witness(&key, &f1, cp, 1, w0.witness_digest().unwrap());

        w1.validate_successor(&w0).unwrap();
    }

    #[test]
    fn successor_allows_ledger_advance_with_same_frontier() {
        let key = signing_key(14);
        let f0 = frontier(0, [0; 32], 0);
        let cp0 = checkpoint(&key, 9, 0x37);
        let cp1 = checkpoint(&key, 10, 0x38);
        let w0 = witness(&key, &f0, cp0, 0, [0; 32]);
        let w1 = witness(&key, &f0, cp1, 1, w0.witness_digest().unwrap());

        w1.validate_successor(&w0).unwrap();
    }

    #[test]
    fn witness_chain_rejects_same_height_ledger_fork() {
        let key = signing_key(15);
        let f0 = frontier(0, [0; 32], 0);
        let cp0 = checkpoint(&key, 11, 0x39);
        let cp_fork = checkpoint(&key, 11, 0x3A);
        let w0 = witness(&key, &f0, cp0, 0, [0; 32]);
        let w1 = witness(&key, &f0, cp_fork, 1, w0.witness_digest().unwrap());

        assert!(matches!(
            w1.validate_successor(&w0),
            Err(FrontierLedgerWitnessError::LedgerForkAtSameHeight)
        ));
    }

    #[test]
    fn witness_chain_rejects_ledger_key_substitution() {
        let key0 = signing_key(16);
        let key1 = signing_key(17);
        let f0 = frontier(0, [0; 32], 0);
        let cp0 = checkpoint(&key0, 12, 0x3B);
        let cp1 = checkpoint(&key1, 13, 0x3C);
        let w0 = witness(&key0, &f0, cp0, 0, [0; 32]);
        let w1 = witness(&key1, &f0, cp1, 1, w0.witness_digest().unwrap());

        assert!(matches!(
            w1.validate_successor(&w0),
            Err(FrontierLedgerWitnessError::LedgerKeyChanged)
        ));
    }

    #[test]
    fn witness_chain_rejects_store_generation_change() {
        let key = signing_key(18);
        let f0 = frontier(0, [0; 32], 0);
        let cp0 = checkpoint(&key, 14, 0x3D);
        let w0 = witness(&key, &f0, cp0, 0, [0; 32]);

        let mut anchor = f0.anchor(30_001).unwrap();
        anchor.generation = 1;
        let payload = OperationFrontierLedgerWitnessPayloadV1::new(
            anchor,
            checkpoint(&key, 15, 0x3E),
            1,
            w0.witness_digest().unwrap(),
            40_001,
        )
        .unwrap();
        let w1 = OperationFrontierLedgerWitnessV1::sign_ed25519(payload, &key).unwrap();

        assert!(matches!(
            w1.validate_successor(&w0),
            Err(FrontierLedgerWitnessError::StoreGenerationChanged)
        ));
    }

    #[test]
    fn previous_witness_digest_prevents_branching_history() {
        let key = signing_key(19);
        let f0 = frontier(0, [0; 32], 0);
        let cp0 = checkpoint(&key, 16, 0x3F);
        let w0 = witness(&key, &f0, cp0, 0, [0; 32]);
        let mut w1 = witness(&key, &f0, cp0, 1, w0.witness_digest().unwrap());
        w1.payload.previous_witness_digest = [0xEE; 32];
        // Re-sign so this specifically tests lineage, not signature tampering.
        w1 = OperationFrontierLedgerWitnessV1::sign_ed25519(w1.payload, &key).unwrap();

        assert!(matches!(
            w1.validate_successor(&w0),
            Err(FrontierLedgerWitnessError::PreviousWitnessDigestMismatch)
        ));
    }
}
