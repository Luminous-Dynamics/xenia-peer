// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent countersignatures over public ledger checkpoints.
//!
//! The ledger key proves checkpoint authenticity, but a compromised host that
//! still owns that key can serve different valid histories to different
//! observers. Witness countersignatures let operators retain the same
//! checkpoint through multiple independently controlled keys and require a
//! quorum before accepting a restore anchor.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{checkpoint_fingerprint, CheckpointError, LedgerCheckpoint, Verifier};

/// Stable schema label for [`CheckpointWitnessBundle`].
pub const CHECKPOINT_WITNESS_BUNDLE_SCHEMA: &str = "xenia-checkpoint-witness-bundle-v1";

/// Maximum distinct countersignatures accepted in one bundle.
pub const MAX_CHECKPOINT_WITNESSES: usize = 64;

/// One independent witness's countersignature over an exact checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointWitnessSignature {
    /// Witness Ed25519 public key.
    pub witness_public_key: [u8; 32],
    /// Unix seconds when the witness observed and signed the checkpoint.
    pub timestamp_unix_secs: u64,
    /// Ed25519 signature over [`checkpoint_witness_message`].
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// One checkpoint plus countersignatures from independent witness keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointWitnessBundle {
    /// Must equal [`CHECKPOINT_WITNESS_BUNDLE_SCHEMA`].
    pub schema: String,
    /// Exact ledger checkpoint observed by every witness.
    pub checkpoint: LedgerCheckpoint,
    /// Independent countersignatures. Duplicate keys are invalid.
    pub witnesses: Vec<CheckpointWitnessSignature>,
}

/// Domain-separated bytes signed by an independent checkpoint witness.
pub fn checkpoint_witness_message(
    checkpoint_fingerprint: &[u8; 32],
    witness_public_key: &[u8; 32],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(128);
    message.extend_from_slice(b"xenia:checkpoint-witness:v1");
    message.push(0);
    message.extend_from_slice(CHECKPOINT_WITNESS_BUNDLE_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(checkpoint_fingerprint);
    message.extend_from_slice(witness_public_key);
    message.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    message
}

impl CheckpointWitnessBundle {
    /// Begin a bundle for an internally valid ledger checkpoint.
    pub fn new(checkpoint: LedgerCheckpoint) -> Result<Self, CheckpointWitnessError> {
        Verifier::verify_checkpoint(&checkpoint)?;
        Ok(Self {
            schema: CHECKPOINT_WITNESS_BUNDLE_SCHEMA.to_string(),
            checkpoint,
            witnesses: Vec::new(),
        })
    }

    /// Add one independent witness signature.
    pub fn sign_with(
        &mut self,
        witness_signing_key: &SigningKey,
        timestamp_unix_secs: u64,
    ) -> Result<(), CheckpointWitnessError> {
        if timestamp_unix_secs < self.checkpoint.timestamp_unix_secs {
            return Err(CheckpointWitnessError::WitnessPredatesCheckpoint);
        }
        if self.witnesses.len() >= MAX_CHECKPOINT_WITNESSES {
            return Err(CheckpointWitnessError::TooManyWitnesses {
                count: self.witnesses.len() + 1,
                maximum: MAX_CHECKPOINT_WITNESSES,
            });
        }
        let witness_public_key = witness_signing_key.verifying_key().to_bytes();
        if self
            .witnesses
            .iter()
            .any(|witness| witness.witness_public_key == witness_public_key)
        {
            return Err(CheckpointWitnessError::DuplicateWitness);
        }
        let fingerprint = checkpoint_fingerprint(&self.checkpoint)?;
        let message = checkpoint_witness_message(
            &fingerprint,
            &witness_public_key,
            timestamp_unix_secs,
        );
        self.witnesses.push(CheckpointWitnessSignature {
            witness_public_key,
            timestamp_unix_secs,
            signature: witness_signing_key.sign(&message).to_bytes(),
        });
        Ok(())
    }
}

/// Why a checkpoint witness bundle or quorum was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointWitnessError {
    /// The bundle schema is unknown.
    #[error("unsupported checkpoint witness bundle schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the bundle.
        schema: String,
    },
    /// The embedded ledger checkpoint was invalid.
    #[error("witnessed ledger checkpoint is invalid: {0}")]
    Checkpoint(#[from] CheckpointError),
    /// A witness signature timestamp predates the checkpoint it claims to have
    /// observed.
    #[error("checkpoint witness timestamp predates the checkpoint")]
    WitnessPredatesCheckpoint,
    /// A witness public key was malformed.
    #[error("checkpoint witness public key is malformed")]
    BadWitnessPublicKey,
    /// A witness signature was invalid.
    #[error("checkpoint witness signature is invalid")]
    BadWitnessSignature,
    /// The same witness key appeared more than once.
    #[error("duplicate checkpoint witness key")]
    DuplicateWitness,
    /// A countersignature came from a key outside the caller's trust set.
    #[error("checkpoint witness key is not trusted")]
    UntrustedWitness,
    /// The bundle exceeded the explicit countersignature bound.
    #[error("checkpoint witness bundle has {count} signatures; maximum is {maximum}")]
    TooManyWitnesses {
        /// Observed countersignature count.
        count: usize,
        /// Maximum accepted countersignature count.
        maximum: usize,
    },
    /// A zero quorum would accept an unwitnessed checkpoint.
    #[error("checkpoint witness quorum must be greater than zero")]
    ZeroQuorum,
    /// The verified trusted witness count did not satisfy policy.
    #[error("checkpoint witness quorum not met: verified={verified}, required={required}")]
    QuorumNotMet {
        /// Number of valid distinct trusted witnesses.
        verified: usize,
        /// Required quorum.
        required: usize,
    },
}

impl Verifier {
    /// Verify every countersignature and require at least `minimum_quorum`
    /// distinct keys from `trusted_witness_keys`.
    ///
    /// Untrusted signatures are rejected rather than ignored so a bundle
    /// cannot conceal an unexpected witness set behind an otherwise adequate
    /// trusted quorum.
    pub fn verify_checkpoint_witness_quorum(
        bundle: &CheckpointWitnessBundle,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<(), CheckpointWitnessError> {
        if bundle.schema != CHECKPOINT_WITNESS_BUNDLE_SCHEMA {
            return Err(CheckpointWitnessError::UnsupportedSchema {
                schema: bundle.schema.clone(),
            });
        }
        if minimum_quorum == 0 {
            return Err(CheckpointWitnessError::ZeroQuorum);
        }
        if bundle.witnesses.len() > MAX_CHECKPOINT_WITNESSES {
            return Err(CheckpointWitnessError::TooManyWitnesses {
                count: bundle.witnesses.len(),
                maximum: MAX_CHECKPOINT_WITNESSES,
            });
        }
        Self::verify_checkpoint(&bundle.checkpoint)?;
        let trusted = trusted_witness_keys.iter().copied().collect::<BTreeSet<_>>();
        let fingerprint = checkpoint_fingerprint(&bundle.checkpoint)?;
        let mut observed = BTreeSet::new();
        for witness in &bundle.witnesses {
            if witness.timestamp_unix_secs < bundle.checkpoint.timestamp_unix_secs {
                return Err(CheckpointWitnessError::WitnessPredatesCheckpoint);
            }
            if !observed.insert(witness.witness_public_key) {
                return Err(CheckpointWitnessError::DuplicateWitness);
            }
            if !trusted.contains(&witness.witness_public_key) {
                return Err(CheckpointWitnessError::UntrustedWitness);
            }
            let key = VerifyingKey::from_bytes(&witness.witness_public_key)
                .map_err(|_| CheckpointWitnessError::BadWitnessPublicKey)?;
            let message = checkpoint_witness_message(
                &fingerprint,
                &witness.witness_public_key,
                witness.timestamp_unix_secs,
            );
            key.verify(&message, &Signature::from_bytes(&witness.signature))
                .map_err(|_| CheckpointWitnessError::BadWitnessSignature)?;
        }
        if observed.len() < minimum_quorum {
            return Err(CheckpointWitnessError::QuorumNotMet {
                verified: observed.len(),
                required: minimum_quorum,
            });
        }
        Ok(())
    }
}
