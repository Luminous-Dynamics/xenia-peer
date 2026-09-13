// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Relying-context admission wrapper for generic state witnesses.
//!
//! Raw witness verification proves that configured keys signed an exact
//! commitment. Cross-system consumers also need to prove that the commitment is
//! for the namespace, target, epoch, and trust context they intended to admit.
//! This module makes those checks explicit before signature work.

use thiserror::Error;

use crate::{
    EvidenceSignatureBackend, MAX_STATE_NAMESPACE_BYTES, StateWitnessBundle,
    StateWitnessError, StateWitnessTrustKey, VerifiedStateWitness, Verifier,
};

/// Exact relying-system context expected for a state-witness bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWitnessExpectation {
    namespace: String,
    target_id: [u8; 32],
    epoch_id: [u8; 32],
    trust_context_digest: [u8; 32],
}

impl StateWitnessExpectation {
    /// Construct an exact expected relying context.
    pub fn new(
        namespace: impl Into<String>,
        target_id: [u8; 32],
        epoch_id: [u8; 32],
        trust_context_digest: [u8; 32],
    ) -> Result<Self, StateWitnessContextError> {
        let namespace = namespace.into();
        if namespace.is_empty() {
            return Err(StateWitnessContextError::EmptyExpectedNamespace);
        }
        if namespace.len() > MAX_STATE_NAMESPACE_BYTES {
            return Err(StateWitnessContextError::ExpectedNamespaceTooLong {
                found: namespace.len(),
                maximum: MAX_STATE_NAMESPACE_BYTES,
            });
        }
        Ok(Self {
            namespace,
            target_id,
            epoch_id,
            trust_context_digest,
        })
    }

    /// Expected namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Expected opaque target identifier.
    pub const fn target_id(&self) -> [u8; 32] {
        self.target_id
    }

    /// Expected opaque epoch identifier.
    pub const fn epoch_id(&self) -> [u8; 32] {
        self.epoch_id
    }

    /// Expected trust/policy-context digest.
    pub const fn trust_context_digest(&self) -> [u8; 32] {
        self.trust_context_digest
    }
}

fn verify_expected_context(
    bundle: &StateWitnessBundle,
    expected: &StateWitnessExpectation,
) -> Result<(), StateWitnessContextError> {
    let commitment = &bundle.commitment;
    if commitment.namespace != expected.namespace {
        return Err(StateWitnessContextError::NamespaceMismatch);
    }
    if commitment.target_id != expected.target_id {
        return Err(StateWitnessContextError::TargetMismatch);
    }
    if commitment.epoch_id != expected.epoch_id {
        return Err(StateWitnessContextError::EpochMismatch);
    }
    if commitment.trust_context_digest != expected.trust_context_digest {
        return Err(StateWitnessContextError::TrustContextMismatch);
    }
    Ok(())
}

impl Verifier {
    /// Verify exact relying context, then verify witness quorum with explicit
    /// signature backends.
    pub fn verify_state_witness_quorum_for_with_backends(
        bundle: &StateWitnessBundle,
        expected: &StateWitnessExpectation,
        trusted_witness_keys: &[StateWitnessTrustKey],
        minimum_quorum: usize,
        backends: &[&dyn EvidenceSignatureBackend],
    ) -> Result<VerifiedStateWitness, StateWitnessContextError> {
        verify_expected_context(bundle, expected)?;
        Ok(Self::verify_state_witness_quorum_with_backends(
            bundle,
            trusted_witness_keys,
            minimum_quorum,
            backends,
        )?)
    }

    /// Verify exact relying context and the current Ed25519 witness profile.
    pub fn verify_state_witness_quorum_ed25519_for(
        bundle: &StateWitnessBundle,
        expected: &StateWitnessExpectation,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<VerifiedStateWitness, StateWitnessContextError> {
        verify_expected_context(bundle, expected)?;
        Ok(Self::verify_state_witness_quorum_ed25519(
            bundle,
            trusted_witness_keys,
            minimum_quorum,
        )?)
    }
}

/// Failures while binding a witness bundle to an expected relying context.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateWitnessContextError {
    /// Expected namespace was empty.
    #[error("expected state-witness namespace must not be empty")]
    EmptyExpectedNamespace,
    /// Expected namespace exceeded the commitment profile bound.
    #[error("expected state-witness namespace has {found} bytes; maximum is {maximum}")]
    ExpectedNamespaceTooLong {
        /// Observed byte length.
        found: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// Commitment namespace did not match the caller's expected namespace.
    #[error("state-witness namespace does not match relying context")]
    NamespaceMismatch,
    /// Commitment target did not match the caller's expected target.
    #[error("state-witness target does not match relying context")]
    TargetMismatch,
    /// Commitment epoch did not match the caller's expected epoch.
    #[error("state-witness epoch does not match relying context")]
    EpochMismatch,
    /// Commitment trust/policy context did not match the caller's expectation.
    #[error("state-witness trust context does not match relying context")]
    TrustContextMismatch,
    /// Lower-level witness verification failed after context matching.
    #[error("state-witness verification failed: {0}")]
    Witness(#[from] StateWitnessError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{StateCommitment, StateWitnessBundle, ZERO_STATE_COMMITMENT};

    fn bundle() -> (StateWitnessBundle, [u8; 32]) {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let trusted = signer.verifying_key().to_bytes();
        let commitment = StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            0,
            ZERO_STATE_COMMITMENT,
            [0x40; 32],
            [0x30; 32],
            100,
        )
        .unwrap();
        let mut bundle = StateWitnessBundle::new(commitment).unwrap();
        bundle.sign_with_ed25519(&signer, 101).unwrap();
        (bundle, trusted)
    }

    fn expected() -> StateWitnessExpectation {
        StateWitnessExpectation::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            [0x30; 32],
        )
        .unwrap()
    }

    #[test]
    fn exact_context_then_quorum_verifies() {
        let (bundle, trusted) = bundle();
        let verified = Verifier::verify_state_witness_quorum_ed25519_for(
            &bundle,
            &expected(),
            &[trusted],
            1,
        )
        .unwrap();
        assert_eq!(verified.commitment().namespace, "test.namespace");
    }

    #[test]
    fn wrong_relying_context_is_rejected() {
        let (bundle, trusted) = bundle();

        let wrong_namespace = StateWitnessExpectation::new(
            "other.namespace",
            [0x10; 32],
            [0x20; 32],
            [0x30; 32],
        )
        .unwrap();
        assert_eq!(
            Verifier::verify_state_witness_quorum_ed25519_for(
                &bundle,
                &wrong_namespace,
                &[trusted],
                1,
            )
            .unwrap_err(),
            StateWitnessContextError::NamespaceMismatch
        );

        let wrong_target = StateWitnessExpectation::new(
            "test.namespace",
            [0x11; 32],
            [0x20; 32],
            [0x30; 32],
        )
        .unwrap();
        assert_eq!(
            Verifier::verify_state_witness_quorum_ed25519_for(
                &bundle,
                &wrong_target,
                &[trusted],
                1,
            )
            .unwrap_err(),
            StateWitnessContextError::TargetMismatch
        );

        let wrong_epoch = StateWitnessExpectation::new(
            "test.namespace",
            [0x10; 32],
            [0x21; 32],
            [0x30; 32],
        )
        .unwrap();
        assert_eq!(
            Verifier::verify_state_witness_quorum_ed25519_for(
                &bundle,
                &wrong_epoch,
                &[trusted],
                1,
            )
            .unwrap_err(),
            StateWitnessContextError::EpochMismatch
        );

        let wrong_trust = StateWitnessExpectation::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            [0x31; 32],
        )
        .unwrap();
        assert_eq!(
            Verifier::verify_state_witness_quorum_ed25519_for(
                &bundle,
                &wrong_trust,
                &[trusted],
                1,
            )
            .unwrap_err(),
            StateWitnessContextError::TrustContextMismatch
        );
    }
}
