// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit succession proofs between independently signed ledger epochs.
//!
//! Xenia's live ledger entries are intentionally signed by one stable key per
//! epoch. Rotating that key therefore starts a new epoch rather than silently
//! changing the verifier key in the middle of one hash chain. A
//! [`LedgerKeyTransition`] is dual-signed by the old and new keys and commits
//! to the final checkpoint of the old epoch. Retaining the transition beside
//! the archived old epoch lets an auditor prove that the new epoch was
//! authorized by both sides of the handover.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{
    CheckpointContinuityError, CheckpointError, LedgerCheckpoint, LedgerEntry, Verifier,
    checkpoint_fingerprint,
};

/// Stable schema label for [`LedgerKeyTransition`].
pub const LEDGER_KEY_TRANSITION_SCHEMA: &str = "xenia-ledger-key-transition-v1";

/// Dual-signed authorization to begin a new ledger epoch under a new key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerKeyTransition {
    /// Must equal [`LEDGER_KEY_TRANSITION_SCHEMA`].
    pub schema: String,
    /// Final signed checkpoint of the previous ledger epoch.
    pub previous_checkpoint: LedgerCheckpoint,
    /// Ed25519 public key authorized for the successor epoch.
    pub new_ledger_public_key: [u8; 32],
    /// Unix seconds when the handover artifact was produced.
    pub timestamp_unix_secs: u64,
    /// Signature by the previous epoch key.
    #[serde(with = "BigArray")]
    pub previous_key_signature: [u8; 64],
    /// Acceptance signature by the successor epoch key.
    #[serde(with = "BigArray")]
    pub new_key_signature: [u8; 64],
}

/// Domain-separated bytes signed by both sides of a ledger-key handover.
pub fn ledger_key_transition_message(
    previous_checkpoint_fingerprint: &[u8; 32],
    new_ledger_public_key: &[u8; 32],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(128);
    message.extend_from_slice(b"xenia:ledger-key-transition:v1");
    message.push(0);
    message.extend_from_slice(LEDGER_KEY_TRANSITION_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(previous_checkpoint_fingerprint);
    message.extend_from_slice(new_ledger_public_key);
    message.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    message
}

impl LedgerKeyTransition {
    /// Create a handover accepted by both the previous and successor keys.
    ///
    /// The previous signing key must match the key embedded in
    /// `previous_checkpoint`; otherwise an unrelated key cannot manufacture a
    /// plausible-looking transition around somebody else's checkpoint.
    pub fn sign(
        previous_checkpoint: LedgerCheckpoint,
        previous_signing_key: &SigningKey,
        new_signing_key: &SigningKey,
        timestamp_unix_secs: u64,
    ) -> Result<Self, LedgerKeyTransitionError> {
        Verifier::verify_checkpoint(&previous_checkpoint)?;
        if previous_checkpoint.ledger_public_key
            != previous_signing_key.verifying_key().to_bytes()
        {
            return Err(LedgerKeyTransitionError::PreviousKeyMismatch);
        }
        let new_ledger_public_key = new_signing_key.verifying_key().to_bytes();
        let fingerprint = checkpoint_fingerprint(&previous_checkpoint)?;
        let message = ledger_key_transition_message(
            &fingerprint,
            &new_ledger_public_key,
            timestamp_unix_secs,
        );
        Ok(Self {
            schema: LEDGER_KEY_TRANSITION_SCHEMA.to_string(),
            previous_checkpoint,
            new_ledger_public_key,
            timestamp_unix_secs,
            previous_key_signature: previous_signing_key.sign(&message).to_bytes(),
            new_key_signature: new_signing_key.sign(&message).to_bytes(),
        })
    }
}

/// Why a key-transition artifact or successor epoch was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LedgerKeyTransitionError {
    /// The transition schema is unknown.
    #[error("unsupported ledger key transition schema: {schema}")]
    UnsupportedSchema {
        /// Schema label found in the artifact.
        schema: String,
    },
    /// The previous checkpoint was invalid.
    #[error("previous ledger checkpoint is invalid: {0}")]
    PreviousCheckpoint(#[from] CheckpointError),
    /// The supplied old signing key did not own the previous checkpoint.
    #[error("previous signing key does not match the checkpoint ledger key")]
    PreviousKeyMismatch,
    /// The successor public key was malformed.
    #[error("successor ledger public key is malformed")]
    BadNewPublicKey,
    /// The old-key authorization signature was invalid.
    #[error("previous ledger key did not authorize the transition")]
    BadPreviousSignature,
    /// The new-key acceptance signature was invalid.
    #[error("successor ledger key did not accept the transition")]
    BadNewSignature,
    /// A caller supplied a different retained checkpoint than the transition
    /// commits to.
    #[error("ledger key transition does not reference the retained checkpoint")]
    PreviousCheckpointMismatch,
    /// The candidate checkpoint was not signed by the authorized successor key.
    #[error("candidate checkpoint key does not match the authorized successor key")]
    SuccessorKeyMismatch,
    /// The candidate checkpoint predates the signed handover.
    #[error("candidate checkpoint timestamp predates the ledger key transition")]
    CandidatePredatesTransition,
    /// The candidate epoch did not verify as a complete ledger.
    #[error("successor ledger epoch failed verification: {0}")]
    SuccessorLedger(#[from] CheckpointContinuityError),
}

impl Verifier {
    /// Verify both signatures and the embedded previous checkpoint.
    pub fn verify_ledger_key_transition(
        transition: &LedgerKeyTransition,
    ) -> Result<(), LedgerKeyTransitionError> {
        if transition.schema != LEDGER_KEY_TRANSITION_SCHEMA {
            return Err(LedgerKeyTransitionError::UnsupportedSchema {
                schema: transition.schema.clone(),
            });
        }
        Self::verify_checkpoint(&transition.previous_checkpoint)?;
        let previous_key = VerifyingKey::from_bytes(
            &transition.previous_checkpoint.ledger_public_key,
        )
        .map_err(|_| CheckpointError::BadPublicKey)?;
        let new_key = VerifyingKey::from_bytes(&transition.new_ledger_public_key)
            .map_err(|_| LedgerKeyTransitionError::BadNewPublicKey)?;
        let fingerprint = checkpoint_fingerprint(&transition.previous_checkpoint)?;
        let message = ledger_key_transition_message(
            &fingerprint,
            &transition.new_ledger_public_key,
            transition.timestamp_unix_secs,
        );
        previous_key
            .verify(
                &message,
                &Signature::from_bytes(&transition.previous_key_signature),
            )
            .map_err(|_| LedgerKeyTransitionError::BadPreviousSignature)?;
        new_key
            .verify(
                &message,
                &Signature::from_bytes(&transition.new_key_signature),
            )
            .map_err(|_| LedgerKeyTransitionError::BadNewSignature)
    }

    /// Verify that `candidate_checkpoint` and `candidate_entries` form the
    /// complete first checkpointed state of the authorized successor epoch.
    pub fn verify_ledger_key_successor(
        retained_previous: &LedgerCheckpoint,
        transition: &LedgerKeyTransition,
        candidate_checkpoint: &LedgerCheckpoint,
        candidate_entries: &[LedgerEntry],
    ) -> Result<(), LedgerKeyTransitionError> {
        Self::verify_ledger_key_transition(transition)?;
        if &transition.previous_checkpoint != retained_previous {
            return Err(LedgerKeyTransitionError::PreviousCheckpointMismatch);
        }
        if candidate_checkpoint.ledger_public_key != transition.new_ledger_public_key {
            return Err(LedgerKeyTransitionError::SuccessorKeyMismatch);
        }
        if candidate_checkpoint.timestamp_unix_secs < transition.timestamp_unix_secs {
            return Err(LedgerKeyTransitionError::CandidatePredatesTransition);
        }
        let new_key = VerifyingKey::from_bytes(&transition.new_ledger_public_key)
            .map_err(|_| LedgerKeyTransitionError::BadNewPublicKey)?;
        Self::verify_checkpoint_prefix(candidate_checkpoint, candidate_entries, &new_key)?;
        Ok(())
    }
}
