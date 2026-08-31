// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Signed syntax and lineage contracts for operation-frontier ledger witnesses.
//!
//! This permissive crate deliberately does **not** authenticate a Xenia ledger checkpoint.
//! It can validate the witness payload, the Ed25519 signature under the public key named by the
//! payload, and successor-lineage rules. A production anti-rollback decision must additionally
//! verify the referenced real `xenia-ledger::LedgerCheckpoint`, its trusted ledger key/prefix,
//! and the operation frontier ancestry in an authority-owning adapter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use xenia_operation_store_frontier::OperationStoreFrontierAnchorV1;

/// Exact payload schema for a ledger-backed operation-frontier witness.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_PAYLOAD_SCHEMA_V1: &str =
    "xenia-operation-frontier-ledger-witness-payload-v1";
/// Exact signed witness schema.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_SCHEMA_V1: &str =
    "xenia-operation-frontier-ledger-witness-v1";
/// Exact checkpoint-binding schema.
pub const LEDGER_CHECKPOINT_BINDING_SCHEMA_V1: &str =
    "xenia-operation-frontier-ledger-checkpoint-binding-v1";
/// Domain separator for the signed witness message.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_MESSAGE_DOMAIN_V1: &[u8] =
    b"xenia-operation-frontier-ledger-witness-message-v1";
/// Domain separator for exact signed-witness commitments.
pub const OPERATION_FRONTIER_LEDGER_WITNESS_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-frontier-ledger-witness-digest-v1";

/// Serializable commitment to one ledger checkpoint.
///
/// This is evidence syntax only. These fields are not authenticated merely because this value
/// exists. The authority-owning verifier must compare them to a real, independently verified
/// Xenia ledger checkpoint.
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
    /// Ed25519 public key named as the ledger/witness authority.
    pub ledger_public_key: [u8; 32],
    /// Signed checkpoint timestamp in Unix seconds.
    pub timestamp_unix_secs: u64,
}

impl LedgerCheckpointBindingV1 {
    /// Construct locally valid checkpoint-binding syntax.
    pub fn new(
        checkpoint_fingerprint: [u8; 32],
        entry_count: u64,
        head_hash: [u8; 32],
        ledger_public_key: [u8; 32],
        timestamp_unix_secs: u64,
    ) -> Result<Self, FrontierLedgerWitnessError> {
        let value = Self {
            schema: LEDGER_CHECKPOINT_BINDING_SCHEMA_V1.to_string(),
            checkpoint_fingerprint,
            entry_count,
            head_hash,
            ledger_public_key,
            timestamp_unix_secs,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate local syntax without authenticating the referenced checkpoint.
    pub fn validate(&self) -> Result<(), FrontierLedgerWitnessError> {
        if self.schema != LEDGER_CHECKPOINT_BINDING_SCHEMA_V1 {
            return Err(FrontierLedgerWitnessError::UnsupportedCheckpointBindingSchema);
        }
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

/// Unsigned semantic payload authenticated by one witness signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationFrontierLedgerWitnessPayloadV1 {
    /// Exact payload schema.
    pub schema: String,
    /// Exact operation-store frontier anchor being witnessed.
    pub frontier_anchor: OperationStoreFrontierAnchorV1,
    /// Ledger-checkpoint evidence syntax. Production trust is external to this crate.
    pub ledger_checkpoint: LedgerCheckpointBindingV1,
    /// Monotonic sequence in this witness lineage.
    pub witness_sequence: u64,
    /// Digest of the previous exact signed witness, or all zeros for witness zero.
    pub previous_witness_digest: [u8; 32],
    /// Time the witness was created, in Unix milliseconds.
    pub witnessed_at_unix_ms: u64,
}

impl OperationFrontierLedgerWitnessPayloadV1 {
    /// Construct one locally valid witness payload.
    pub fn new(
        frontier_anchor: OperationStoreFrontierAnchorV1,
        ledger_checkpoint: LedgerCheckpointBindingV1,
        witness_sequence: u64,
        previous_witness_digest: [u8; 32],
        witnessed_at_unix_ms: u64,
    ) -> Result<Self, FrontierLedgerWitnessError> {
        let value = Self {
            schema: OPERATION_FRONTIER_LEDGER_WITNESS_PAYLOAD_SCHEMA_V1.to_string(),
            frontier_anchor,
            ledger_checkpoint,
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

    /// Deterministic payload bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FrontierLedgerWitnessError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }
}

/// Signed witness joining an operation-store frontier anchor to checkpoint evidence syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationFrontierLedgerWitnessV1 {
    /// Exact signed-witness schema.
    pub schema: String,
    /// Semantic payload authenticated by `signature`.
    pub payload: OperationFrontierLedgerWitnessPayloadV1,
    /// Ed25519 signature under the public key named by the checkpoint binding.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl OperationFrontierLedgerWitnessV1 {
    /// Sign one payload with the same Ed25519 key named by the checkpoint binding.
    ///
    /// This proves possession of that private key; it does not prove that the binding corresponds
    /// to a real Xenia ledger checkpoint. The AGPL authority adapter owns that latter decision.
    pub fn sign_ed25519(
        payload: OperationFrontierLedgerWitnessPayloadV1,
        signing_key: &SigningKey,
    ) -> Result<Self, FrontierLedgerWitnessError> {
        payload.validate()?;
        if signing_key.verifying_key().to_bytes() != payload.ledger_checkpoint.ledger_public_key {
            return Err(FrontierLedgerWitnessError::SigningKeyDoesNotMatchLedgerBinding);
        }
        let signature = signing_key.sign(&witness_message(&payload)?).to_bytes();
        let value = Self {
            schema: OPERATION_FRONTIER_LEDGER_WITNESS_SCHEMA_V1.to_string(),
            payload,
            signature,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate schema, payload shape, and signature under the key named by the payload.
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
    ///
    /// This is a structural/signed-lineage check. A production verifier must additionally prove
    /// each checkpoint binding against real ledger history and each anchor against local frontier
    /// ancestry.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), FrontierLedgerWitnessError> {
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
        if new_checkpoint.entry_count == old_checkpoint.entry_count
            && new_checkpoint.head_hash != old_checkpoint.head_hash
        {
            return Err(FrontierLedgerWitnessError::LedgerForkAtSameHeight);
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

/// Return the domain-separated Ed25519 message for a witness payload.
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

/// Errors surfaced by the non-authoritative witness syntax/lineage contract.
#[derive(Debug, Error)]
pub enum FrontierLedgerWitnessError {
    /// Frontier contract rejected an anchor.
    #[error("operation frontier rejected witness input: {0}")]
    Frontier(#[from] xenia_operation_store_frontier::OperationStoreFrontierError),
    /// Canonical serialization failed.
    #[error("witness serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
    /// Unknown checkpoint-binding schema.
    #[error("unsupported ledger checkpoint binding schema")]
    UnsupportedCheckpointBindingSchema,
    /// Unknown payload schema.
    #[error("unsupported witness payload schema")]
    UnsupportedPayloadSchema,
    /// Unknown witness schema.
    #[error("unsupported signed witness schema")]
    UnsupportedWitnessSchema,
    /// Checkpoint fingerprint was the zero sentinel.
    #[error("ledger checkpoint fingerprint must not be zero")]
    ZeroLedgerCheckpointFingerprint,
    /// Ledger public key was the zero sentinel.
    #[error("ledger public key must not be zero")]
    ZeroLedgerPublicKey,
    /// Empty ledger declared a non-zero head.
    #[error("empty ledger checkpoint must use the zero head")]
    EmptyLedgerHasHead,
    /// Non-empty ledger omitted its head.
    #[error("non-empty ledger checkpoint must have a non-zero head")]
    NonEmptyLedgerMissingHead,
    /// Ledger public key bytes were malformed.
    #[error("ledger public key is malformed")]
    MalformedLedgerPublicKey,
    /// Witness timestamp was before the operation frontier anchor timestamp.
    #[error("witness timestamp predates frontier anchor")]
    WitnessPredatesFrontierAnchor,
    /// Witness timestamp was before the ledger checkpoint timestamp.
    #[error("witness timestamp predates ledger checkpoint")]
    WitnessPredatesLedgerCheckpoint,
    /// Witness zero incorrectly named a predecessor.
    #[error("genesis witness must not name a previous witness")]
    GenesisWitnessHasPrevious,
    /// Non-genesis witness omitted its predecessor digest.
    #[error("non-genesis witness requires previous witness digest")]
    MissingPreviousWitnessDigest,
    /// Signing key does not match the ledger public key named by the payload.
    #[error("witness signing key does not match ledger checkpoint binding")]
    SigningKeyDoesNotMatchLedgerBinding,
    /// Witness signature did not verify.
    #[error("witness signature is invalid")]
    BadWitnessSignature,
    /// Witness sequence overflowed.
    #[error("witness sequence overflow")]
    WitnessSequenceOverflow,
    /// Witness sequence was not exactly previous + 1.
    #[error("witness sequence mismatch")]
    WitnessSequenceMismatch,
    /// Previous signed-witness digest was wrong.
    #[error("previous witness digest mismatch")]
    PreviousWitnessDigestMismatch,
    /// Operation-store identity changed inside a V1 lineage.
    #[error("operation-store identity changed")]
    StoreIdChanged,
    /// Operation-store generation changed without governed recovery transition.
    #[error("operation-store generation changed")]
    StoreGenerationChanged,
    /// Frontier checkpoint moved backward.
    #[error("operation frontier checkpoint regressed")]
    FrontierCheckpointRegressed,
    /// Same frontier checkpoint sequence committed to a different digest.
    #[error("operation frontier fork at same checkpoint")]
    FrontierForkAtSameCheckpoint,
    /// Frontier anchor timestamp moved backward.
    #[error("operation frontier anchor timestamp regressed")]
    FrontierAnchorTimestampRegressed,
    /// Ledger key changed inside a V1 witness lineage.
    #[error("ledger key changed")]
    LedgerKeyChanged,
    /// Ledger entry count moved backward.
    #[error("ledger entry count regressed")]
    LedgerEntryCountRegressed,
    /// Same ledger height committed to a different head.
    #[error("ledger fork at same height")]
    LedgerForkAtSameHeight,
    /// Ledger checkpoint timestamp moved backward.
    #[error("ledger checkpoint timestamp regressed")]
    LedgerCheckpointTimestampRegressed,
    /// Witness creation timestamp moved backward.
    #[error("witness timestamp regressed")]
    WitnessTimestampRegressed,
    /// Checkpoint timestamp could not be represented in milliseconds.
    #[error("ledger checkpoint timestamp overflow")]
    LedgerCheckpointTimestampOverflow,
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
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operation_store_frontier::OperationStoreFrontierV1;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn frontier(sequence: u64, previous: [u8; 32], recorded_at_ms: u64) -> OperationStoreFrontierV1 {
        OperationStoreFrontierV1::from_state(
            [7u8; 16],
            0,
            sequence,
            [8u8; 32],
            previous,
            recorded_at_ms,
            &[],
            &[],
        )
        .unwrap()
    }

    fn checkpoint_binding(
        signing_key: &SigningKey,
        fingerprint: [u8; 32],
        count: u64,
        head: [u8; 32],
        timestamp: u64,
    ) -> LedgerCheckpointBindingV1 {
        LedgerCheckpointBindingV1::new(
            fingerprint,
            count,
            head,
            signing_key.verifying_key().to_bytes(),
            timestamp,
        )
        .unwrap()
    }

    #[test]
    fn signed_witness_validates_without_claiming_checkpoint_authenticity() {
        let signing_key = key(3);
        let f0 = frontier(0, [0u8; 32], 1_000);
        let payload = OperationFrontierLedgerWitnessPayloadV1::new(
            f0.anchor(1_000).unwrap(),
            checkpoint_binding(&signing_key, [9u8; 32], 1, [10u8; 32], 1),
            0,
            [0u8; 32],
            1_000,
        )
        .unwrap();
        OperationFrontierLedgerWitnessV1::sign_ed25519(payload, &signing_key)
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn signing_key_must_match_binding_key() {
        let k1 = key(3);
        let k2 = key(4);
        let f0 = frontier(0, [0u8; 32], 1_000);
        let payload = OperationFrontierLedgerWitnessPayloadV1::new(
            f0.anchor(1_000).unwrap(),
            checkpoint_binding(&k1, [9u8; 32], 1, [10u8; 32], 1),
            0,
            [0u8; 32],
            1_000,
        )
        .unwrap();
        assert!(matches!(
            OperationFrontierLedgerWitnessV1::sign_ed25519(payload, &k2),
            Err(FrontierLedgerWitnessError::SigningKeyDoesNotMatchLedgerBinding)
        ));
    }

    #[test]
    fn same_ledger_height_same_head_may_be_recheckpointed() {
        let signing_key = key(3);
        let f0 = frontier(0, [0u8; 32], 1_000);
        let w0 = OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                f0.anchor(1_000).unwrap(),
                checkpoint_binding(&signing_key, [9u8; 32], 1, [10u8; 32], 1),
                0,
                [0u8; 32],
                1_000,
            )
            .unwrap(),
            &signing_key,
        )
        .unwrap();
        let f1 = frontier(1, f0.frontier_digest().unwrap(), 2_000);
        let w1 = OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                f1.anchor(2_000).unwrap(),
                checkpoint_binding(&signing_key, [11u8; 32], 1, [10u8; 32], 2),
                1,
                w0.witness_digest().unwrap(),
                2_000,
            )
            .unwrap(),
            &signing_key,
        )
        .unwrap();
        w1.validate_successor(&w0).unwrap();
    }

    #[test]
    fn same_ledger_height_different_head_is_fork() {
        let signing_key = key(3);
        let f0 = frontier(0, [0u8; 32], 1_000);
        let w0 = OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                f0.anchor(1_000).unwrap(),
                checkpoint_binding(&signing_key, [9u8; 32], 1, [10u8; 32], 1),
                0,
                [0u8; 32],
                1_000,
            )
            .unwrap(),
            &signing_key,
        )
        .unwrap();
        let w1 = OperationFrontierLedgerWitnessV1::sign_ed25519(
            OperationFrontierLedgerWitnessPayloadV1::new(
                f0.anchor(2_000).unwrap(),
                checkpoint_binding(&signing_key, [11u8; 32], 1, [12u8; 32], 2),
                1,
                w0.witness_digest().unwrap(),
                2_000,
            )
            .unwrap(),
            &signing_key,
        )
        .unwrap();
        assert!(matches!(
            w1.validate_successor(&w0),
            Err(FrontierLedgerWitnessError::LedgerForkAtSameHeight)
        ));
    }
}
