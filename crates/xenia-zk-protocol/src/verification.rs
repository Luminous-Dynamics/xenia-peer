// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Backend-neutral verification orchestration and typestate.
//!
//! This module contains no proving backend and no signature implementation. It
//! prevents callers from conflating structural/contract validation with actual
//! cryptographic verification by exposing separate result types for each stage.

use thiserror::Error;

use crate::{
    AuthenticationSuiteId, ParameterSetId, ProofEnvelopeV3, ProofSystemId, VerifierId,
    public_inputs_digest,
    policy::{
        ContractValidatedEnvelope, EnvelopePolicy, EnvelopeValidationError, VerificationContract,
        validate_envelope_against_contract,
    },
};

/// Public values that a challenge-response verifier must bind into the proof
/// relation.
///
/// The envelope digest binds these values together, but that alone is not
/// sufficient: the backend verifier must also verify a circuit/program whose
/// public-input relation includes `challenge_nonce`. Otherwise an old proof can
/// be re-enveloped under a fresh challenge by an authenticated holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeBoundPublicInputs<'a> {
    pub challenge_nonce: &'a [u8; 32],
    pub canonical_application_inputs: &'a [u8],
}

/// Backend adapter for one exact statement verifier/program and parameter set.
///
/// Implementations should be narrow: one adapter instance identifies exactly the
/// verifier bytes/image/AIR and parameter set it knows how to execute.
pub trait ProofBackendVerifier {
    fn proof_system(&self) -> ProofSystemId;
    fn verifier_id(&self) -> VerifierId;
    fn parameter_set_id(&self) -> ParameterSetId;

    /// Verify backend-specific proof bytes against the statement's canonical
    /// application inputs **and** verifier-issued challenge. Return `false` for
    /// malformed/invalid proofs or when the verifier program does not bind the
    /// supplied challenge as public input.
    fn verify(&self, proof: &[u8], public_inputs: ChallengeBoundPublicInputs<'_>) -> bool;
}

/// Signature/authentication adapter for one exact suite and signer key.
pub trait ProofAuthenticationVerifier {
    fn suite(&self) -> AuthenticationSuiteId;
    fn signer_key_id(&self) -> [u8; 32];

    /// Verify a signature over the canonical 32-byte authentication digest.
    fn verify(&self, digest: &[u8; 32], signature: &[u8]) -> bool;
}

/// Envelope whose local contract and backend proof have both been verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofVerifiedEnvelope<'a> {
    validated: ContractValidatedEnvelope<'a>,
}

impl<'a> ProofVerifiedEnvelope<'a> {
    pub fn envelope(self) -> &'a ProofEnvelopeV3 {
        self.validated.envelope()
    }
}

/// Envelope whose local contract, backend proof, and every accepted
/// authentication entry have been cryptographically verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullyVerifiedEnvelope<'a> {
    proof_verified: ProofVerifiedEnvelope<'a>,
}

impl<'a> FullyVerifiedEnvelope<'a> {
    pub fn envelope(self) -> &'a ProofEnvelopeV3 {
        self.proof_verified.envelope()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptographicVerificationError {
    #[error("envelope failed structural or exact-contract validation: {0}")]
    Contract(EnvelopeValidationError),
    #[error("canonical public inputs do not match the envelope digest")]
    PublicInputsMismatch,
    #[error("proof backend does not match the contracted proof-system identifier")]
    BackendProofSystemMismatch,
    #[error("proof backend does not match the contracted verifier/program identifier")]
    BackendVerifierMismatch,
    #[error("proof backend does not match the contracted parameter-set identifier")]
    BackendParameterSetMismatch,
    #[error("backend rejected the proof")]
    ProofRejected,
    #[error("no authentication verifier is available for suite {suite} and signer key")]
    MissingAuthenticationVerifier { suite: u16 },
    #[error("authentication verifier identity does not match the envelope entry")]
    AuthenticationVerifierMismatch,
    #[error("authentication signature verification failed for suite {suite}")]
    AuthenticationRejected { suite: u16 },
}

impl From<EnvelopeValidationError> for CryptographicVerificationError {
    fn from(value: EnvelopeValidationError) -> Self {
        Self::Contract(value)
    }
}

/// Verify the backend proof after an envelope has passed its exact local contract.
pub fn verify_backend_proof<'a>(
    validated: ContractValidatedEnvelope<'a>,
    canonical_public_inputs: &[u8],
    backend: &dyn ProofBackendVerifier,
) -> Result<ProofVerifiedEnvelope<'a>, CryptographicVerificationError> {
    let envelope = validated.envelope();
    let digest = public_inputs_digest(
        &envelope.statement,
        &envelope.nonce,
        canonical_public_inputs,
    )
        .map_err(|_| CryptographicVerificationError::PublicInputsMismatch)?;
    if digest != envelope.public_inputs_hash {
        return Err(CryptographicVerificationError::PublicInputsMismatch);
    }
    if backend.proof_system() != envelope.proof_system {
        return Err(CryptographicVerificationError::BackendProofSystemMismatch);
    }
    if backend.verifier_id() != envelope.verifier_id {
        return Err(CryptographicVerificationError::BackendVerifierMismatch);
    }
    if backend.parameter_set_id() != envelope.parameter_set_id {
        return Err(CryptographicVerificationError::BackendParameterSetMismatch);
    }
    if !backend.verify(
        &envelope.proof,
        ChallengeBoundPublicInputs {
            challenge_nonce: &envelope.nonce,
            canonical_application_inputs: canonical_public_inputs,
        },
    ) {
        return Err(CryptographicVerificationError::ProofRejected);
    }

    Ok(ProofVerifiedEnvelope { validated })
}

/// Verify every authentication entry on a proof-verified envelope.
///
/// Exact signer trust/quorum has already been checked by the local
/// [`VerificationContract`]. This stage proves that each accepted entry is a real
/// signature under the matching verifier implementation.
pub fn verify_authentication<'a>(
    proof_verified: ProofVerifiedEnvelope<'a>,
    verifiers: &[&dyn ProofAuthenticationVerifier],
) -> Result<FullyVerifiedEnvelope<'a>, CryptographicVerificationError> {
    let envelope = proof_verified.envelope();

    for authentication in &envelope.authentication {
        let Some(verifier) = verifiers.iter().copied().find(|candidate| {
            candidate.suite() == authentication.suite
                && candidate.signer_key_id() == authentication.signer_key_id
        }) else {
            return Err(CryptographicVerificationError::MissingAuthenticationVerifier {
                suite: authentication.suite.wire_id(),
            });
        };

        if verifier.suite() != authentication.suite
            || verifier.signer_key_id() != authentication.signer_key_id
        {
            return Err(CryptographicVerificationError::AuthenticationVerifierMismatch);
        }

        let digest = envelope
            .authentication_digest(authentication.suite, &authentication.signer_key_id)
            .map_err(|_| CryptographicVerificationError::AuthenticationRejected {
                suite: authentication.suite.wire_id(),
            })?;
        if !verifier.verify(&digest, &authentication.signature) {
            return Err(CryptographicVerificationError::AuthenticationRejected {
                suite: authentication.suite.wire_id(),
            });
        }
    }

    Ok(FullyVerifiedEnvelope { proof_verified })
}

/// One-shot strict verifier: structure + exact local contract + public-input
/// binding + backend proof verification + authentication verification.
pub fn verify_envelope<'a>(
    envelope: &'a ProofEnvelopeV3,
    policy: &EnvelopePolicy,
    contract: &VerificationContract,
    now_unix_seconds: u64,
    canonical_public_inputs: &[u8],
    backend: &dyn ProofBackendVerifier,
    authentication_verifiers: &[&dyn ProofAuthenticationVerifier],
) -> Result<FullyVerifiedEnvelope<'a>, CryptographicVerificationError> {
    let validated =
        validate_envelope_against_contract(envelope, policy, contract, now_unix_seconds)?;
    let proof_verified = verify_backend_proof(validated, canonical_public_inputs, backend)?;
    verify_authentication(proof_verified, authentication_verifiers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthenticationSuiteId, ParameterSetId, ProofAuthentication, ProofSystemId, StatementId,
        VerifierId, empty_extensions_digest, public_inputs_digest,
        policy::{ProofVerificationBinding, VerificationContract},
    };

    const NOW: u64 = 1_800_000_000;
    const PUBLIC_INPUTS: &[u8] = b"canonical-access-inputs";

    struct FakeBackend {
        accept: bool,
        verifier_id: VerifierId,
    }

    impl ProofBackendVerifier for FakeBackend {
        fn proof_system(&self) -> ProofSystemId {
            ProofSystemId::MIDEN
        }

        fn verifier_id(&self) -> VerifierId {
            self.verifier_id
        }

        fn parameter_set_id(&self) -> ParameterSetId {
            ParameterSetId([0x22; 32])
        }

        fn verify(&self, proof: &[u8], public_inputs: ChallengeBoundPublicInputs<'_>) -> bool {
            self.accept
                && proof == [1, 2, 3]
                && public_inputs.challenge_nonce == &[0x33; 32]
                && public_inputs.canonical_application_inputs == PUBLIC_INPUTS
        }
    }

    struct FakeAuthenticationVerifier {
        accept: bool,
        key_id: [u8; 32],
    }

    impl ProofAuthenticationVerifier for FakeAuthenticationVerifier {
        fn suite(&self) -> AuthenticationSuiteId {
            AuthenticationSuiteId::ML_DSA_65_FIPS204
        }

        fn signer_key_id(&self) -> [u8; 32] {
            self.key_id
        }

        fn verify(&self, _digest: &[u8; 32], signature: &[u8]) -> bool {
            self.accept && signature == [0x66; 128]
        }
    }

    fn fixture() -> (ProofEnvelopeV3, VerificationContract) {
        let statement = StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1).unwrap();
        let public_inputs_hash =
            public_inputs_digest(&statement, &[0x33; 32], PUBLIC_INPUTS).unwrap();
        let mut envelope = ProofEnvelopeV3::new_unsigned(
            statement.clone(),
            ProofSystemId::MIDEN,
            VerifierId([0x11; 32]),
            ParameterSetId([0x22; 32]),
            NOW,
            [0x33; 32],
            public_inputs_hash,
            vec![1, 2, 3],
            empty_extensions_digest(),
        );
        envelope.authentication.push(ProofAuthentication {
            suite: AuthenticationSuiteId::ML_DSA_65_FIPS204,
            signer_key_id: [0x55; 32],
            signature: vec![0x66; 128],
        });
        let contract = VerificationContract::single_signer(
            ProofVerificationBinding {
                statement,
                proof_system: ProofSystemId::MIDEN,
                verifier_id: VerifierId([0x11; 32]),
                parameter_set_id: ParameterSetId([0x22; 32]),
                nonce: [0x33; 32],
                public_inputs_hash,
            },
            AuthenticationSuiteId::ML_DSA_65_FIPS204,
            [0x55; 32],
        );
        (envelope, contract)
    }

    #[test]
    fn one_shot_pipeline_returns_only_fully_verified_type() {
        let (envelope, contract) = fixture();
        let backend = FakeBackend {
            accept: true,
            verifier_id: VerifierId([0x11; 32]),
        };
        let auth = FakeAuthenticationVerifier {
            accept: true,
            key_id: [0x55; 32],
        };
        let verified = verify_envelope(
            &envelope,
            &EnvelopePolicy::default(),
            &contract,
            NOW,
            PUBLIC_INPUTS,
            &backend,
            &[&auth],
        )
        .unwrap();
        assert_eq!(verified.envelope(), &envelope);
    }

    #[test]
    fn public_input_substitution_is_rejected_before_backend_acceptance() {
        let (envelope, contract) = fixture();
        let backend = FakeBackend {
            accept: true,
            verifier_id: VerifierId([0x11; 32]),
        };
        let validated = validate_envelope_against_contract(
            &envelope,
            &EnvelopePolicy::default(),
            &contract,
            NOW,
        )
        .unwrap();
        assert_eq!(
            verify_backend_proof(validated, b"different-inputs", &backend),
            Err(CryptographicVerificationError::PublicInputsMismatch)
        );
    }

    #[test]
    fn fresh_challenge_cannot_be_re_enveloped_without_backend_binding() {
        let (mut envelope, mut contract) = fixture();
        envelope.nonce = [0x44; 32];
        envelope.public_inputs_hash =
            public_inputs_digest(&envelope.statement, &envelope.nonce, PUBLIC_INPUTS).unwrap();
        contract.proof.nonce = envelope.nonce;
        contract.proof.public_inputs_hash = envelope.public_inputs_hash;

        let backend = FakeBackend {
            accept: true,
            verifier_id: VerifierId([0x11; 32]),
        };
        let validated = validate_envelope_against_contract(
            &envelope,
            &EnvelopePolicy::default(),
            &contract,
            NOW,
        )
        .unwrap();
        assert_eq!(
            verify_backend_proof(validated, PUBLIC_INPUTS, &backend),
            Err(CryptographicVerificationError::ProofRejected)
        );
    }

    #[test]
    fn backend_cannot_self_select_a_different_verifier_program() {
        let (envelope, contract) = fixture();
        let backend = FakeBackend {
            accept: true,
            verifier_id: VerifierId([0x99; 32]),
        };
        let validated = validate_envelope_against_contract(
            &envelope,
            &EnvelopePolicy::default(),
            &contract,
            NOW,
        )
        .unwrap();
        assert_eq!(
            verify_backend_proof(validated, PUBLIC_INPUTS, &backend),
            Err(CryptographicVerificationError::BackendVerifierMismatch)
        );
    }

    #[test]
    fn proof_and_signature_rejections_remain_distinct() {
        let (envelope, contract) = fixture();
        let rejecting_backend = FakeBackend {
            accept: false,
            verifier_id: VerifierId([0x11; 32]),
        };
        let auth = FakeAuthenticationVerifier {
            accept: true,
            key_id: [0x55; 32],
        };
        assert_eq!(
            verify_envelope(
                &envelope,
                &EnvelopePolicy::default(),
                &contract,
                NOW,
                PUBLIC_INPUTS,
                &rejecting_backend,
                &[&auth],
            ),
            Err(CryptographicVerificationError::ProofRejected)
        );

        let accepting_backend = FakeBackend {
            accept: true,
            verifier_id: VerifierId([0x11; 32]),
        };
        let rejecting_auth = FakeAuthenticationVerifier {
            accept: false,
            key_id: [0x55; 32],
        };
        assert_eq!(
            verify_envelope(
                &envelope,
                &EnvelopePolicy::default(),
                &contract,
                NOW,
                PUBLIC_INPUTS,
                &accepting_backend,
                &[&rejecting_auth],
            ),
            Err(CryptographicVerificationError::AuthenticationRejected {
                suite: AuthenticationSuiteId::ML_DSA_65_FIPS204.wire_id(),
            })
        );
    }
}
