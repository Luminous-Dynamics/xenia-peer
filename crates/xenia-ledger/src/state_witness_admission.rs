// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Context-bound admission evidence for generic state witnesses.
//!
//! `VerifiedStateWitness` intentionally proves only that a configured trusted-key
//! quorum signed one exact commitment. Cross-system consumers sometimes also need
//! to map the *actual keys that verified* into an independently governed signer /
//! lifecycle / failure-domain policy. This module exposes those verified keys as
//! Xenia's existing [`EvidencePublicKeyBinding`] objects without reopening an
//! unverified witness bundle as authority.
//!
//! The resulting key bindings still prove only cryptographic key identity. They do
//! **not** prove that two keys belong to different people, organizations, hardware
//! roots, clouds, or failure domains. That remains relying-system policy.

use thiserror::Error;

use crate::{
    EvidencePublicKeyBinding, EvidenceSignatureBackend, SignatureEnvelopeError,
    StateWitnessBundle, StateWitnessContextError, StateWitnessExpectation,
    StateWitnessTrustKey, VerifiedStateWitness, Verifier,
};

/// Context-bound verified state witness plus the exact cryptographic keys that
/// participated in the successful verification.
///
/// There is no public constructor. Values are produced only by the admission
/// verifier after the lower-level context and signature/quorum checks succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStateWitnessAdmission {
    verified: VerifiedStateWitness,
    witness_key_bindings: Vec<EvidencePublicKeyBinding>,
}

impl VerifiedStateWitnessAdmission {
    /// The lower-level verified state witness.
    pub fn verified_state_witness(&self) -> &VerifiedStateWitness {
        &self.verified
    }

    /// Xenia public-key bindings for every witness signature that was accepted.
    ///
    /// Each binding contains the signature suite, raw verifier key, and Xenia's
    /// stable BLAKE3-256 public-key fingerprint. The order matches the witness
    /// order in the verified bundle; callers that need a canonical set should
    /// sort by `(signature_suite, public_key_fingerprint)` or their own admitted
    /// signer identity mapping.
    pub fn verified_witness_key_bindings(&self) -> &[EvidencePublicKeyBinding] {
        &self.witness_key_bindings
    }
}

fn verified_bindings_from_bundle(
    bundle: &StateWitnessBundle,
) -> Result<Vec<EvidencePublicKeyBinding>, StateWitnessAdmissionError> {
    bundle
        .witnesses
        .iter()
        .map(|witness| {
            let suite = witness.signature.suite()?;
            Ok(EvidencePublicKeyBinding::new(
                suite,
                witness.witness_public_key.clone(),
            ))
        })
        .collect()
}

impl Verifier {
    /// Verify exact relying context and witness quorum, then expose the exact
    /// verified cryptographic key bindings for higher-level policy mapping.
    ///
    /// The key bindings are materialized only *after* the lower-level verifier
    /// has successfully validated every bundle witness, rejected duplicates and
    /// untrusted keys, selected the matching signature backend, and satisfied the
    /// configured quorum.
    pub fn verify_state_witness_admission_for_with_backends(
        bundle: &StateWitnessBundle,
        expected: &StateWitnessExpectation,
        trusted_witness_keys: &[StateWitnessTrustKey],
        minimum_quorum: usize,
        backends: &[&dyn EvidenceSignatureBackend],
    ) -> Result<VerifiedStateWitnessAdmission, StateWitnessAdmissionError> {
        let verified = Self::verify_state_witness_quorum_for_with_backends(
            bundle,
            expected,
            trusted_witness_keys,
            minimum_quorum,
            backends,
        )?;
        let witness_key_bindings = verified_bindings_from_bundle(bundle)?;
        debug_assert_eq!(
            witness_key_bindings.len(),
            verified.verified_witness_count(),
            "successful verifier must account for every bundle witness"
        );
        Ok(VerifiedStateWitnessAdmission {
            verified,
            witness_key_bindings,
        })
    }

    /// Verify the current Ed25519 state-witness profile and expose the exact
    /// verified cryptographic key bindings for higher-level policy mapping.
    pub fn verify_state_witness_admission_ed25519_for(
        bundle: &StateWitnessBundle,
        expected: &StateWitnessExpectation,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<VerifiedStateWitnessAdmission, StateWitnessAdmissionError> {
        let verified = Self::verify_state_witness_quorum_ed25519_for(
            bundle,
            expected,
            trusted_witness_keys,
            minimum_quorum,
        )?;
        let witness_key_bindings = verified_bindings_from_bundle(bundle)?;
        debug_assert_eq!(
            witness_key_bindings.len(),
            verified.verified_witness_count(),
            "successful verifier must account for every bundle witness"
        );
        Ok(VerifiedStateWitnessAdmission {
            verified,
            witness_key_bindings,
        })
    }
}

/// Errors surfaced while producing context-bound verified key evidence.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateWitnessAdmissionError {
    /// Context binding or lower-level state-witness verification failed.
    #[error("state-witness admission verification failed: {0}")]
    Context(#[from] StateWitnessContextError),
    /// A signature envelope could not be converted into a stable key binding.
    ///
    /// This should be unreachable after successful lower-level verification, but
    /// remains explicit rather than relying on a panic if the envelope schema is
    /// extended in the future.
    #[error("state-witness signature envelope is invalid: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        StateCommitment, StateWitnessBundle, ZERO_STATE_COMMITMENT,
        compute_evidence_public_key_fingerprint,
    };

    fn commitment() -> StateCommitment {
        StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            0,
            ZERO_STATE_COMMITMENT,
            [0x30; 32],
            [0x40; 32],
            100,
        )
        .expect("valid commitment")
    }

    fn expectation() -> StateWitnessExpectation {
        StateWitnessExpectation::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            [0x40; 32],
        )
        .expect("valid expectation")
    }

    #[test]
    fn admission_exposes_only_keys_from_successfully_verified_bundle() {
        let first = SigningKey::from_bytes(&[7u8; 32]);
        let second = SigningKey::from_bytes(&[8u8; 32]);
        let first_public = first.verifying_key().to_bytes();
        let second_public = second.verifying_key().to_bytes();

        let mut bundle = StateWitnessBundle::new(commitment()).expect("valid bundle");
        bundle
            .sign_with_ed25519(&first, 101)
            .expect("first witness signature");
        bundle
            .sign_with_ed25519(&second, 102)
            .expect("second witness signature");

        let admitted = Verifier::verify_state_witness_admission_ed25519_for(
            &bundle,
            &expectation(),
            &[first_public, second_public],
            2,
        )
        .expect("verified admission");

        assert_eq!(admitted.verified_state_witness().verified_witness_count(), 2);
        let bindings = admitted.verified_witness_key_bindings();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].public_key, first_public.to_vec());
        assert_eq!(
            bindings[0].public_key_fingerprint,
            compute_evidence_public_key_fingerprint(&first_public)
        );
        assert_eq!(bindings[1].public_key, second_public.to_vec());
        assert_eq!(
            bindings[1].public_key_fingerprint,
            compute_evidence_public_key_fingerprint(&second_public)
        );
    }

    #[test]
    fn failed_signature_never_produces_verified_key_evidence() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let trusted = signer.verifying_key().to_bytes();
        let mut bundle = StateWitnessBundle::new(commitment()).expect("valid bundle");
        bundle
            .sign_with_ed25519(&signer, 101)
            .expect("witness signature");
        bundle.witnesses[0].signature.signature[0] ^= 0x80;

        let error = Verifier::verify_state_witness_admission_ed25519_for(
            &bundle,
            &expectation(),
            &[trusted],
            1,
        )
        .expect_err("tampered signature must fail");
        assert!(matches!(error, StateWitnessAdmissionError::Context(_)));
    }
}
