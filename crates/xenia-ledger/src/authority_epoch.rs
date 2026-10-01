// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit, dual-signed authorization for advancing a witness authority epoch.
//! A numeric epoch is only a fencing value; selecting a larger number does not
//! establish authority. This module binds epoch advance to a verified
//! LedgerKeyTransition and requires signatures from both ledger keys.

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{checkpoint_fingerprint, LedgerKeyTransition, LedgerKeyTransitionError, Verifier};

/// Stable schema label for an explicit witness-authority epoch transition.
pub const LEDGER_AUTHORITY_EPOCH_TRANSITION_SCHEMA: &str =
    "xenia-ledger-authority-epoch-transition-v1";

/// Dual-signed authorization to advance a source/witness authority epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerAuthorityEpochTransitionV1 {
    /// Schema identifier.
    pub schema: String,
    /// Fingerprint of the verified key transition.
    pub key_transition_fingerprint: [u8; 32],
    /// Epoch authoritative before the handover.
    pub previous_epoch: u64,
    /// Epoch authorized after the handover.
    pub successor_epoch: u64,
    /// Successor ledger public key.
    pub new_ledger_public_key: [u8; 32],
    /// Handover timestamp inherited from the key transition.
    pub timestamp_unix_secs: u64,
    /// Signature by the retiring authority.
    #[serde(with = "BigArray")]
    pub previous_key_signature: [u8; 64],
    /// Acceptance signature by the successor authority.
    #[serde(with = "BigArray")]
    pub new_key_signature: [u8; 64],
}

/// Domain-separated bytes signed by both authorities for an epoch advance.
pub fn ledger_authority_epoch_transition_message(
    key_transition_fingerprint: &[u8; 32],
    previous_epoch: u64,
    successor_epoch: u64,
    new_ledger_public_key: &[u8; 32],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(128);
    message.extend_from_slice(b"xenia:ledger-authority-epoch-transition:v1");
    message.push(0);
    message.extend_from_slice(LEDGER_AUTHORITY_EPOCH_TRANSITION_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(key_transition_fingerprint);
    message.extend_from_slice(&previous_epoch.to_be_bytes());
    message.extend_from_slice(&successor_epoch.to_be_bytes());
    message.extend_from_slice(new_ledger_public_key);
    message.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    message
}

/// Stable fingerprint of the complete verified key-transition artifact.
pub fn ledger_key_transition_fingerprint(
    transition: &LedgerKeyTransition,
) -> Result<[u8; 32], LedgerKeyTransitionError> {
    Verifier::verify_ledger_key_transition(transition)?;
    let checkpoint = checkpoint_fingerprint(&transition.previous_checkpoint)?;
    let mut hasher = Hasher::new();
    hasher.update(b"xenia:ledger-key-transition-fingerprint:v1\0");
    hasher.update(transition.schema.as_bytes());
    hasher.update(&checkpoint);
    hasher.update(&transition.new_ledger_public_key);
    hasher.update(&transition.timestamp_unix_secs.to_be_bytes());
    hasher.update(&transition.previous_key_signature);
    hasher.update(&transition.new_key_signature);
    Ok(*hasher.finalize().as_bytes())
}

impl LedgerAuthorityEpochTransitionV1 {
    /// Create a dual-signed epoch advance bound to an existing key transition.
    pub fn sign(
        key_transition: &LedgerKeyTransition,
        previous_epoch: u64,
        successor_epoch: u64,
        previous_signing_key: &SigningKey,
        new_signing_key: &SigningKey,
    ) -> Result<Self, LedgerAuthorityEpochTransitionError> {
        Verifier::verify_ledger_key_transition(key_transition)?;
        if successor_epoch != previous_epoch.saturating_add(1) {
            return Err(LedgerAuthorityEpochTransitionError::NonAdjacentEpoch);
        }
        if key_transition.previous_checkpoint.ledger_public_key
            != previous_signing_key.verifying_key().to_bytes()
        {
            return Err(LedgerAuthorityEpochTransitionError::PreviousKeyMismatch);
        }
        if key_transition.new_ledger_public_key != new_signing_key.verifying_key().to_bytes() {
            return Err(LedgerAuthorityEpochTransitionError::SuccessorKeyMismatch);
        }
        let key_transition_fingerprint = ledger_key_transition_fingerprint(key_transition)?;
        let message = ledger_authority_epoch_transition_message(
            &key_transition_fingerprint,
            previous_epoch,
            successor_epoch,
            &key_transition.new_ledger_public_key,
            key_transition.timestamp_unix_secs,
        );
        Ok(Self {
            schema: LEDGER_AUTHORITY_EPOCH_TRANSITION_SCHEMA.to_string(),
            key_transition_fingerprint,
            previous_epoch,
            successor_epoch,
            new_ledger_public_key: key_transition.new_ledger_public_key,
            timestamp_unix_secs: key_transition.timestamp_unix_secs,
            previous_key_signature: previous_signing_key.sign(&message).to_bytes(),
            new_key_signature: new_signing_key.sign(&message).to_bytes(),
        })
    }

    /// Verify the transition and prove that the expected successor epoch is authorized.
    pub fn verify(
        &self,
        key_transition: &LedgerKeyTransition,
        expected_previous_epoch: u64,
        expected_successor_epoch: u64,
    ) -> Result<(), LedgerAuthorityEpochTransitionError> {
        if self.schema != LEDGER_AUTHORITY_EPOCH_TRANSITION_SCHEMA {
            return Err(LedgerAuthorityEpochTransitionError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        Verifier::verify_ledger_key_transition(key_transition)?;
        let expected_fingerprint = ledger_key_transition_fingerprint(key_transition)?;
        if self.key_transition_fingerprint != expected_fingerprint {
            return Err(LedgerAuthorityEpochTransitionError::KeyTransitionMismatch);
        }
        if self.previous_epoch != expected_previous_epoch
            || self.successor_epoch != expected_successor_epoch
        {
            return Err(LedgerAuthorityEpochTransitionError::EpochMismatch);
        }
        if self.successor_epoch != self.previous_epoch.saturating_add(1) {
            return Err(LedgerAuthorityEpochTransitionError::NonAdjacentEpoch);
        }
        if self.new_ledger_public_key != key_transition.new_ledger_public_key
            || self.timestamp_unix_secs != key_transition.timestamp_unix_secs
        {
            return Err(LedgerAuthorityEpochTransitionError::KeyTransitionMismatch);
        }
        let previous_key = VerifyingKey::from_bytes(
            &key_transition.previous_checkpoint.ledger_public_key,
        )
        .map_err(|_| LedgerAuthorityEpochTransitionError::PreviousKeyMismatch)?;
        let new_key = VerifyingKey::from_bytes(&self.new_ledger_public_key)
            .map_err(|_| LedgerAuthorityEpochTransitionError::SuccessorKeyMismatch)?;
        let message = ledger_authority_epoch_transition_message(
            &self.key_transition_fingerprint,
            self.previous_epoch,
            self.successor_epoch,
            &self.new_ledger_public_key,
            self.timestamp_unix_secs,
        );
        previous_key
            .verify(&message, &Signature::from_bytes(&self.previous_key_signature))
            .map_err(|_| LedgerAuthorityEpochTransitionError::BadPreviousSignature)?;
        new_key
            .verify(&message, &Signature::from_bytes(&self.new_key_signature))
            .map_err(|_| LedgerAuthorityEpochTransitionError::BadNewSignature)
    }
}

/// Why an authority epoch transition was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LedgerAuthorityEpochTransitionError {
    /// The schema is unknown.
    #[error("unsupported ledger authority epoch transition schema: {schema}")]
    UnsupportedSchema {
        /// Schema identifier that was not recognized.
        schema: String,
    },
    /// The underlying key transition was invalid.
    #[error("ledger key transition is invalid: {0}")]
    KeyTransition(#[from] LedgerKeyTransitionError),
    /// The supplied epoch pair is not the expected transition.
    #[error("ledger authority epoch does not match the expected transition")]
    EpochMismatch,
    /// Epoch advancement must be exactly one step.
    #[error("ledger authority epoch transition must advance exactly one epoch")]
    NonAdjacentEpoch,
    /// The retiring signing key did not own the prior checkpoint.
    #[error("retiring authority key does not match the key transition")]
    PreviousKeyMismatch,
    /// The successor signing key did not match the key transition.
    #[error("successor authority key does not match the key transition")]
    SuccessorKeyMismatch,
    /// The retained key-transition artifact differs from the signed reference.
    #[error("authority epoch transition is bound to a different key transition")]
    KeyTransitionMismatch,
    /// The retiring authority signature was invalid.
    #[error("retiring authority did not authorize the epoch transition")]
    BadPreviousSignature,
    /// The successor authority signature was invalid.
    #[error("successor authority did not accept the epoch transition")]
    BadNewSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{checkpoint_message, LedgerCheckpoint, LEDGER_CHECKPOINT_SCHEMA};

    fn checkpoint(key: &SigningKey) -> LedgerCheckpoint {
        let public = key.verifying_key().to_bytes();
        let message = checkpoint_message(0, &[0; 32], &public, 0);
        LedgerCheckpoint {
            schema: LEDGER_CHECKPOINT_SCHEMA.to_string(),
            entry_count: 0,
            head_hash: [0; 32],
            ledger_public_key: public,
            timestamp_unix_secs: 0,
            signature: key.sign(&message).to_bytes(),
        }
    }

    #[test]
    fn dual_signed_epoch_transition_requires_real_key_handover() {
        let old = SigningKey::from_bytes(&[31; 32]);
        let new = SigningKey::from_bytes(&[32; 32]);
        let transition = LedgerKeyTransition::sign(checkpoint(&old), &old, &new, 100)
            .expect("key transition");
        let epoch = LedgerAuthorityEpochTransitionV1::sign(&transition, 7, 8, &old, &new)
            .expect("epoch transition");
        epoch.verify(&transition, 7, 8).expect("valid epoch transition");
    }

    #[test]
    fn selecting_a_higher_epoch_without_matching_transition_is_rejected() {
        let old = SigningKey::from_bytes(&[33; 32]);
        let new = SigningKey::from_bytes(&[34; 32]);
        let transition = LedgerKeyTransition::sign(checkpoint(&old), &old, &new, 100)
            .expect("key transition");
        let epoch = LedgerAuthorityEpochTransitionV1::sign(&transition, 7, 8, &old, &new)
            .expect("epoch transition");
        assert!(epoch.verify(&transition, 7, 9).is_err());
        assert!(epoch.verify(&transition, 8, 9).is_err());
    }

    #[test]
    fn old_epoch_proof_cannot_authorize_a_new_key_transition() {
        let old = SigningKey::from_bytes(&[35; 32]);
        let new = SigningKey::from_bytes(&[36; 32]);
        let later = SigningKey::from_bytes(&[37; 32]);
        let first = LedgerKeyTransition::sign(checkpoint(&old), &old, &new, 100)
            .expect("first key transition");
        let first_epoch = LedgerAuthorityEpochTransitionV1::sign(&first, 7, 8, &old, &new)
            .expect("first epoch transition");
        let second = LedgerKeyTransition::sign(checkpoint(&new), &new, &later, 200)
            .expect("second key transition");
        assert!(first_epoch.verify(&second, 8, 9).is_err());
    }
}