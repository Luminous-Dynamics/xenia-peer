// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic witnessed commitments for monotonic cross-system state.
//!
//! This module deliberately does not extend `ConsentEventRecord` or reinterpret
//! the consent ledger. It provides a separate, domain-separated commitment that
//! other systems can use when they need independent witnesses to retain the same
//! opaque state identity.
//!
//! A verified witness quorum proves only that the configured trusted keys signed
//! the exact commitment. It does not by itself prove administrative/failure-domain
//! independence, trusted storage, hardware monotonicity, or rollback resistance.
//! Those are deployment-policy properties outside this module.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend,
    EvidenceSignatureBackendError, SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
    Verifier,
};

/// Stable schema label for [`StateCommitment`].
pub const STATE_COMMITMENT_SCHEMA: &str = "xenia-state-commitment-v1";
/// Stable schema label for [`StateWitnessBundle`].
pub const STATE_WITNESS_BUNDLE_SCHEMA: &str = "xenia-state-witness-bundle-v1";
/// Maximum UTF-8 byte length accepted for a commitment namespace.
pub const MAX_STATE_NAMESPACE_BYTES: usize = 128;
/// Maximum witness signatures accepted in one bundle.
pub const MAX_STATE_WITNESSES: usize = 64;
/// All-zero commitment used only for a counter-zero genesis predecessor.
pub const ZERO_STATE_COMMITMENT: [u8; 32] = [0u8; 32];

/// Opaque cross-system state commitment.
///
/// Xenia does not interpret `state_digest`; the relying system defines its
/// semantics. `trust_context_digest` lets that system bind the policy/trust
/// context under which the state was produced without exposing that context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCommitment {
    /// Must equal [`STATE_COMMITMENT_SCHEMA`].
    pub schema: String,
    /// Domain-separated relying-system namespace.
    pub namespace: String,
    /// Opaque exact target identifier inside the namespace.
    pub target_id: [u8; 32],
    /// Opaque epoch identifier. Changing epochs requires higher-level recovery.
    pub epoch_id: [u8; 32],
    /// Monotonic revision inside one epoch.
    pub counter: u64,
    /// Fingerprint of the immediately preceding accepted commitment.
    /// Counter zero must use [`ZERO_STATE_COMMITMENT`].
    pub previous_commitment: [u8; 32],
    /// Opaque relying-system state digest.
    pub state_digest: [u8; 32],
    /// Opaque digest of the trust/policy context used by the relying system.
    pub trust_context_digest: [u8; 32],
    /// Unix seconds when the commitment was produced.
    pub timestamp_unix_secs: u64,
}

impl StateCommitment {
    /// Construct and validate a commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: impl Into<String>,
        target_id: [u8; 32],
        epoch_id: [u8; 32],
        counter: u64,
        previous_commitment: [u8; 32],
        state_digest: [u8; 32],
        trust_context_digest: [u8; 32],
        timestamp_unix_secs: u64,
    ) -> Result<Self, StateWitnessError> {
        let commitment = Self {
            schema: STATE_COMMITMENT_SCHEMA.to_string(),
            namespace: namespace.into(),
            target_id,
            epoch_id,
            counter,
            previous_commitment,
            state_digest,
            trust_context_digest,
            timestamp_unix_secs,
        };
        validate_state_commitment(&commitment)?;
        Ok(commitment)
    }
}

/// One algorithm-tagged witness signature over an exact [`StateCommitment`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessSignature {
    /// Raw public-key bytes for the suite declared by `signature`.
    pub witness_public_key: Vec<u8>,
    /// Unix seconds when the witness observed the commitment.
    pub timestamp_unix_secs: u64,
    /// Algorithm-tagged signature over [`state_witness_message`].
    pub signature: SignatureEnvelope,
}

/// One opaque commitment plus independent witness signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessBundle {
    /// Must equal [`STATE_WITNESS_BUNDLE_SCHEMA`].
    pub schema: String,
    /// Exact state commitment signed by every witness.
    pub commitment: StateCommitment,
    /// Witness signatures. Duplicate `(suite,key)` pairs are invalid.
    pub witnesses: Vec<StateWitnessSignature>,
}

impl StateWitnessBundle {
    /// Start an empty witness bundle for one structurally valid commitment.
    pub fn new(commitment: StateCommitment) -> Result<Self, StateWitnessError> {
        validate_state_commitment(&commitment)?;
        Ok(Self {
            schema: STATE_WITNESS_BUNDLE_SCHEMA.to_string(),
            commitment,
            witnesses: Vec::new(),
        })
    }

    /// Add one Ed25519 witness signature.
    ///
    /// This convenience helper is for the current classical Xenia profile.
    /// Verification remains algorithm-tagged and can use other registered
    /// [`EvidenceSignatureBackend`] implementations.
    pub fn sign_with_ed25519(
        &mut self,
        witness_signing_key: &SigningKey,
        timestamp_unix_secs: u64,
    ) -> Result<(), StateWitnessError> {
        validate_state_witness_bundle_shape(self)?;
        if timestamp_unix_secs < self.commitment.timestamp_unix_secs {
            return Err(StateWitnessError::WitnessPredatesCommitment);
        }
        if self.witnesses.len() >= MAX_STATE_WITNESSES {
            return Err(StateWitnessError::TooManyWitnesses {
                count: self.witnesses.len() + 1,
                maximum: MAX_STATE_WITNESSES,
            });
        }
        let public_key = witness_signing_key.verifying_key().to_bytes().to_vec();
        if self
            .witnesses
            .iter()
            .any(|witness| witness.witness_public_key == public_key)
        {
            return Err(StateWitnessError::DuplicateWitness);
        }
        let fingerprint = state_commitment_fingerprint(&self.commitment)?;
        let suite = SignatureSuite::Ed25519Rfc8032;
        let message = state_witness_message(
            &fingerprint,
            suite,
            &public_key,
            timestamp_unix_secs,
        );
        self.witnesses.push(StateWitnessSignature {
            witness_public_key: public_key,
            timestamp_unix_secs,
            signature: SignatureEnvelope::ed25519(witness_signing_key.sign(&message).to_bytes()),
        });
        Ok(())
    }
}

/// One key accepted by the caller's external witness-trust policy.
///
/// Distinct entries here are only distinct cryptographic keys. A higher layer
/// must prove signer identity, lifecycle, revocation, and failure-domain
/// independence when those properties matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWitnessTrustKey {
    /// Signature suite used by this trusted key.
    pub suite: SignatureSuite,
    /// Raw public-key bytes for `suite`.
    pub public_key: Vec<u8>,
}

/// Opaque type state returned only after witness verification succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStateWitness {
    commitment: StateCommitment,
    commitment_fingerprint: [u8; 32],
    verified_witnesses: Vec<StateWitnessTrustKey>,
}

impl VerifiedStateWitness {
    /// Exact witnessed commitment.
    pub fn commitment(&self) -> &StateCommitment {
        &self.commitment
    }

    /// Stable BLAKE3 fingerprint of the exact commitment message.
    pub const fn commitment_fingerprint(&self) -> [u8; 32] {
        self.commitment_fingerprint
    }

    /// Number of distinct trusted witness keys that verified.
    pub fn verified_witness_count(&self) -> usize {
        self.verified_witnesses.len()
    }
}

/// Return domain-separated canonical bytes for a [`StateCommitment`].
pub fn state_commitment_message(
    commitment: &StateCommitment,
) -> Result<Vec<u8>, StateWitnessError> {
    validate_state_commitment(commitment)?;
    let mut message = Vec::with_capacity(256 + commitment.namespace.len());
    push_bytes(&mut message, b"xenia:state-commitment:v1");
    push_bytes(&mut message, commitment.schema.as_bytes());
    push_bytes(&mut message, commitment.namespace.as_bytes());
    push_bytes(&mut message, &commitment.target_id);
    push_bytes(&mut message, &commitment.epoch_id);
    push_u64(&mut message, commitment.counter);
    push_bytes(&mut message, &commitment.previous_commitment);
    push_bytes(&mut message, &commitment.state_digest);
    push_bytes(&mut message, &commitment.trust_context_digest);
    push_u64(&mut message, commitment.timestamp_unix_secs);
    Ok(message)
}

/// Compute a stable BLAKE3 fingerprint for one exact commitment.
pub fn state_commitment_fingerprint(
    commitment: &StateCommitment,
) -> Result<[u8; 32], StateWitnessError> {
    Ok(*blake3::hash(&state_commitment_message(commitment)?).as_bytes())
}

/// Return the domain-separated message signed by a witness key.
pub fn state_witness_message(
    commitment_fingerprint: &[u8; 32],
    suite: SignatureSuite,
    witness_public_key: &[u8],
    timestamp_unix_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(160 + witness_public_key.len());
    push_bytes(&mut message, b"xenia:state-witness:v1");
    push_bytes(&mut message, STATE_WITNESS_BUNDLE_SCHEMA.as_bytes());
    push_bytes(&mut message, commitment_fingerprint);
    push_bytes(&mut message, suite.stable_label().as_bytes());
    push_bytes(&mut message, witness_public_key);
    push_u64(&mut message, timestamp_unix_secs);
    message
}

fn push_bytes(message: &mut Vec<u8>, bytes: &[u8]) {
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(bytes);
}

fn push_u64(message: &mut Vec<u8>, value: u64) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn validate_state_commitment(commitment: &StateCommitment) -> Result<(), StateWitnessError> {
    if commitment.schema != STATE_COMMITMENT_SCHEMA {
        return Err(StateWitnessError::UnsupportedCommitmentSchema {
            schema: commitment.schema.clone(),
        });
    }
    if commitment.namespace.is_empty() {
        return Err(StateWitnessError::EmptyNamespace);
    }
    if commitment.namespace.len() > MAX_STATE_NAMESPACE_BYTES {
        return Err(StateWitnessError::NamespaceTooLong {
            found: commitment.namespace.len(),
            maximum: MAX_STATE_NAMESPACE_BYTES,
        });
    }
    if commitment.counter == 0 {
        if commitment.previous_commitment != ZERO_STATE_COMMITMENT {
            return Err(StateWitnessError::GenesisHasPreviousCommitment);
        }
    } else if commitment.previous_commitment == ZERO_STATE_COMMITMENT {
        return Err(StateWitnessError::MissingPreviousCommitment);
    }
    Ok(())
}

fn validate_state_witness_bundle_shape(bundle: &StateWitnessBundle) -> Result<(), StateWitnessError> {
    if bundle.schema != STATE_WITNESS_BUNDLE_SCHEMA {
        return Err(StateWitnessError::UnsupportedBundleSchema {
            schema: bundle.schema.clone(),
        });
    }
    validate_state_commitment(&bundle.commitment)?;
    if bundle.witnesses.len() > MAX_STATE_WITNESSES {
        return Err(StateWitnessError::TooManyWitnesses {
            count: bundle.witnesses.len(),
            maximum: MAX_STATE_WITNESSES,
        });
    }
    Ok(())
}

impl Verifier {
    /// Verify a witness quorum using explicitly supplied signature backends.
    ///
    /// The caller supplies the trusted key set. This function intentionally
    /// does not infer key lifecycle, signer identity, or failure domains from
    /// the bundle itself.
    pub fn verify_state_witness_quorum_with_backends(
        bundle: &StateWitnessBundle,
        trusted_witness_keys: &[StateWitnessTrustKey],
        minimum_quorum: usize,
        backends: &[&dyn EvidenceSignatureBackend],
    ) -> Result<VerifiedStateWitness, StateWitnessError> {
        validate_state_witness_bundle_shape(bundle)?;
        if minimum_quorum == 0 {
            return Err(StateWitnessError::ZeroQuorum);
        }

        let trusted = trusted_witness_keys
            .iter()
            .map(|key| (key.suite.stable_label().to_string(), key.public_key.clone()))
            .collect::<BTreeSet<_>>();
        let fingerprint = state_commitment_fingerprint(&bundle.commitment)?;
        let mut observed = BTreeSet::<(String, Vec<u8>)>::new();
        let mut verified_witnesses = Vec::new();

        for witness in &bundle.witnesses {
            if witness.timestamp_unix_secs < bundle.commitment.timestamp_unix_secs {
                return Err(StateWitnessError::WitnessPredatesCommitment);
            }
            let suite = witness.signature.validate_shape()?;
            let identity = (
                suite.stable_label().to_string(),
                witness.witness_public_key.clone(),
            );
            if !observed.insert(identity.clone()) {
                return Err(StateWitnessError::DuplicateWitness);
            }
            if !trusted.contains(&identity) {
                return Err(StateWitnessError::UntrustedWitness);
            }
            let backend = backends
                .iter()
                .copied()
                .find(|backend| backend.suite() == suite)
                .ok_or(StateWitnessError::MissingSignatureBackend { suite })?;
            let message = state_witness_message(
                &fingerprint,
                suite,
                &witness.witness_public_key,
                witness.timestamp_unix_secs,
            );
            backend.verify_signature(
                &witness.witness_public_key,
                &message,
                &witness.signature.signature,
            )?;
            verified_witnesses.push(StateWitnessTrustKey {
                suite,
                public_key: witness.witness_public_key.clone(),
            });
        }

        if verified_witnesses.len() < minimum_quorum {
            return Err(StateWitnessError::QuorumNotMet {
                verified: verified_witnesses.len(),
                required: minimum_quorum,
            });
        }

        Ok(VerifiedStateWitness {
            commitment: bundle.commitment.clone(),
            commitment_fingerprint: fingerprint,
            verified_witnesses,
        })
    }

    /// Verify the current Ed25519 witness profile.
    pub fn verify_state_witness_quorum_ed25519(
        bundle: &StateWitnessBundle,
        trusted_witness_keys: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<VerifiedStateWitness, StateWitnessError> {
        let trusted = trusted_witness_keys
            .iter()
            .map(|key| StateWitnessTrustKey {
                suite: SignatureSuite::Ed25519Rfc8032,
                public_key: key.to_vec(),
            })
            .collect::<Vec<_>>();
        let backend = Ed25519EvidenceSignatureBackend;
        let backends: [&dyn EvidenceSignatureBackend; 1] = [&backend];
        Self::verify_state_witness_quorum_with_backends(
            bundle,
            &trusted,
            minimum_quorum,
            &backends,
        )
    }

    /// Verify exact adjacent monotonic continuity between two already-verified
    /// state commitments.
    ///
    /// Exact replay is accepted. A forward transition must advance by exactly
    /// one counter and bind the previous commitment fingerprint. Larger jumps
    /// require a separately verified intermediate sequence rather than an
    /// implicit skip.
    pub fn verify_state_witness_adjacent(
        previous: &VerifiedStateWitness,
        candidate: &VerifiedStateWitness,
    ) -> Result<(), StateWitnessContinuityError> {
        let previous_state = previous.commitment();
        let candidate_state = candidate.commitment();

        if candidate_state.namespace != previous_state.namespace {
            return Err(StateWitnessContinuityError::NamespaceChanged);
        }
        if candidate_state.target_id != previous_state.target_id {
            return Err(StateWitnessContinuityError::TargetChanged);
        }
        if candidate_state.epoch_id != previous_state.epoch_id {
            return Err(StateWitnessContinuityError::EpochChanged);
        }
        if candidate_state.trust_context_digest != previous_state.trust_context_digest {
            return Err(StateWitnessContinuityError::TrustContextChanged);
        }
        if candidate_state.timestamp_unix_secs < previous_state.timestamp_unix_secs {
            return Err(StateWitnessContinuityError::TimestampRegressed {
                previous: previous_state.timestamp_unix_secs,
                candidate: candidate_state.timestamp_unix_secs,
            });
        }
        if candidate_state.counter < previous_state.counter {
            return Err(StateWitnessContinuityError::CounterRegressed {
                previous: previous_state.counter,
                candidate: candidate_state.counter,
            });
        }
        if candidate_state.counter == previous_state.counter {
            if candidate.commitment_fingerprint() != previous.commitment_fingerprint() {
                return Err(StateWitnessContinuityError::ForkAtSameCounter {
                    counter: candidate_state.counter,
                });
            }
            return Ok(());
        }
        let expected = previous_state.counter.checked_add(1).ok_or(
            StateWitnessContinuityError::CounterOverflow,
        )?;
        if candidate_state.counter != expected {
            return Err(StateWitnessContinuityError::NonAdjacentCounter {
                previous: previous_state.counter,
                candidate: candidate_state.counter,
            });
        }
        if candidate_state.previous_commitment != previous.commitment_fingerprint() {
            return Err(StateWitnessContinuityError::PreviousCommitmentMismatch);
        }
        Ok(())
    }
}

/// Verification failures for state commitments and witness bundles.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateWitnessError {
    /// Commitment schema is not recognized.
    #[error("unsupported state commitment schema: {schema}")]
    UnsupportedCommitmentSchema {
        /// Found schema label.
        schema: String,
    },
    /// Witness-bundle schema is not recognized.
    #[error("unsupported state witness bundle schema: {schema}")]
    UnsupportedBundleSchema {
        /// Found schema label.
        schema: String,
    },
    /// Namespace was empty.
    #[error("state commitment namespace must not be empty")]
    EmptyNamespace,
    /// Namespace exceeded its explicit byte bound.
    #[error("state commitment namespace has {found} bytes; maximum is {maximum}")]
    NamespaceTooLong {
        /// Observed byte length.
        found: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// Counter-zero genesis carried a nonzero predecessor.
    #[error("state commitment genesis must use an all-zero previous commitment")]
    GenesisHasPreviousCommitment,
    /// Non-genesis commitment did not bind a predecessor.
    #[error("non-genesis state commitment must bind a previous commitment")]
    MissingPreviousCommitment,
    /// A witness timestamp predates the state commitment.
    #[error("state witness timestamp predates the state commitment")]
    WitnessPredatesCommitment,
    /// The same `(signature suite, public key)` appeared more than once.
    #[error("duplicate state witness key")]
    DuplicateWitness,
    /// A witness was outside the caller's trust set.
    #[error("state witness key is not trusted")]
    UntrustedWitness,
    /// Witness list exceeded the explicit processing bound.
    #[error("state witness bundle has {count} signatures; maximum is {maximum}")]
    TooManyWitnesses {
        /// Observed witness count.
        count: usize,
        /// Maximum accepted witness count.
        maximum: usize,
    },
    /// Zero witness quorum is forbidden.
    #[error("state witness quorum must be greater than zero")]
    ZeroQuorum,
    /// Trusted verified witness count was below policy.
    #[error("state witness quorum not met: verified={verified}, required={required}")]
    QuorumNotMet {
        /// Verified distinct trusted key count.
        verified: usize,
        /// Required count.
        required: usize,
    },
    /// No verifier backend was supplied for an observed signature suite.
    #[error("no state-witness signature backend supplied for {suite:?}")]
    MissingSignatureBackend {
        /// Signature suite needing verification.
        suite: SignatureSuite,
    },
    /// Signature-envelope parsing/shape failure.
    #[error("invalid state-witness signature envelope: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Cryptographic signature-backend verification failure.
    #[error("state-witness signature verification failed: {0}")]
    SignatureBackend(#[from] EvidenceSignatureBackendError),
}

/// Continuity failures between independently verified state commitments.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateWitnessContinuityError {
    /// Relying-system namespace changed.
    #[error("state-witness namespace changed")]
    NamespaceChanged,
    /// Exact target changed.
    #[error("state-witness target changed")]
    TargetChanged,
    /// Epoch changed without higher-level recovery.
    #[error("state-witness epoch changed")]
    EpochChanged,
    /// Trust/policy context changed inside one epoch.
    #[error("state-witness trust context changed")]
    TrustContextChanged,
    /// Commitment timestamp regressed.
    #[error("state-witness timestamp regressed from {previous} to {candidate}")]
    TimestampRegressed {
        /// Previous timestamp.
        previous: u64,
        /// Candidate timestamp.
        candidate: u64,
    },
    /// Monotonic counter regressed.
    #[error("state-witness counter regressed from {previous} to {candidate}")]
    CounterRegressed {
        /// Previous counter.
        previous: u64,
        /// Candidate counter.
        candidate: u64,
    },
    /// Same counter committed to different state.
    #[error("state-witness fork at counter {counter}")]
    ForkAtSameCounter {
        /// Conflicting counter.
        counter: u64,
    },
    /// Adjacent verifier was asked to accept a skipped counter.
    #[error("state-witness counter is not adjacent: previous={previous}, candidate={candidate}")]
    NonAdjacentCounter {
        /// Previous counter.
        previous: u64,
        /// Candidate counter.
        candidate: u64,
    },
    /// Counter increment overflowed.
    #[error("state-witness counter overflow")]
    CounterOverflow,
    /// Candidate did not bind the exact previous commitment.
    #[error("state-witness previous commitment mismatch")]
    PreviousCommitmentMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn genesis(state_byte: u8) -> StateCommitment {
        StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            0,
            ZERO_STATE_COMMITMENT,
            [state_byte; 32],
            [0x30; 32],
            100,
        )
        .unwrap()
    }

    fn witnessed(commitment: StateCommitment) -> VerifiedStateWitness {
        let first = key(1);
        let second = key(2);
        let trusted = [
            first.verifying_key().to_bytes(),
            second.verifying_key().to_bytes(),
        ];
        let mut bundle = StateWitnessBundle::new(commitment).unwrap();
        bundle.sign_with_ed25519(&first, 101).unwrap();
        bundle.sign_with_ed25519(&second, 102).unwrap();
        Verifier::verify_state_witness_quorum_ed25519(&bundle, &trusted, 2).unwrap()
    }

    #[test]
    fn two_witness_quorum_verifies_exact_commitment() {
        let verified = witnessed(genesis(0x40));
        assert_eq!(verified.commitment().counter, 0);
        assert_eq!(verified.verified_witness_count(), 2);
        assert_ne!(verified.commitment_fingerprint(), [0u8; 32]);
    }

    #[test]
    fn zero_quorum_and_untrusted_witness_fail_closed() {
        let signer = key(1);
        let mut bundle = StateWitnessBundle::new(genesis(0x40)).unwrap();
        bundle.sign_with_ed25519(&signer, 101).unwrap();
        let trusted = [signer.verifying_key().to_bytes()];
        assert_eq!(
            Verifier::verify_state_witness_quorum_ed25519(&bundle, &trusted, 0)
                .unwrap_err(),
            StateWitnessError::ZeroQuorum
        );
        let other = [key(9).verifying_key().to_bytes()];
        assert_eq!(
            Verifier::verify_state_witness_quorum_ed25519(&bundle, &other, 1)
                .unwrap_err(),
            StateWitnessError::UntrustedWitness
        );
    }

    #[test]
    fn duplicate_witness_cannot_inflate_quorum() {
        let signer = key(1);
        let mut bundle = StateWitnessBundle::new(genesis(0x40)).unwrap();
        bundle.sign_with_ed25519(&signer, 101).unwrap();
        bundle.witnesses.push(bundle.witnesses[0].clone());
        let trusted = [signer.verifying_key().to_bytes()];
        assert_eq!(
            Verifier::verify_state_witness_quorum_ed25519(&bundle, &trusted, 2)
                .unwrap_err(),
            StateWitnessError::DuplicateWitness
        );
    }

    #[test]
    fn tampering_commitment_after_signing_breaks_signature() {
        let signer = key(1);
        let mut bundle = StateWitnessBundle::new(genesis(0x40)).unwrap();
        bundle.sign_with_ed25519(&signer, 101).unwrap();
        bundle.commitment.state_digest = [0x41; 32];
        let trusted = [signer.verifying_key().to_bytes()];
        assert!(matches!(
            Verifier::verify_state_witness_quorum_ed25519(&bundle, &trusted, 1),
            Err(StateWitnessError::SignatureBackend(_))
        ));
    }

    #[test]
    fn exact_replay_is_idempotent() {
        let previous = witnessed(genesis(0x40));
        let candidate = witnessed(genesis(0x40));
        Verifier::verify_state_witness_adjacent(&previous, &candidate).unwrap();
    }

    #[test]
    fn adjacent_transition_binds_exact_previous_commitment() {
        let previous = witnessed(genesis(0x40));
        let next = StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            1,
            previous.commitment_fingerprint(),
            [0x41; 32],
            [0x30; 32],
            110,
        )
        .unwrap();
        let candidate = witnessed(next);
        Verifier::verify_state_witness_adjacent(&previous, &candidate).unwrap();
    }

    #[test]
    fn same_counter_different_state_is_fork() {
        let previous = witnessed(genesis(0x40));
        let candidate = witnessed(genesis(0x41));
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &candidate).unwrap_err(),
            StateWitnessContinuityError::ForkAtSameCounter { counter: 0 }
        );
    }

    #[test]
    fn rollback_skip_and_wrong_parent_fail_closed() {
        let previous = witnessed(genesis(0x40));
        let next = StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            1,
            previous.commitment_fingerprint(),
            [0x41; 32],
            [0x30; 32],
            110,
        )
        .unwrap();
        let verified_next = witnessed(next.clone());
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&verified_next, &previous).unwrap_err(),
            StateWitnessContinuityError::CounterRegressed {
                previous: 1,
                candidate: 0,
            }
        );

        let skipped = StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            2,
            verified_next.commitment_fingerprint(),
            [0x42; 32],
            [0x30; 32],
            120,
        )
        .unwrap();
        let verified_skipped = witnessed(skipped);
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &verified_skipped).unwrap_err(),
            StateWitnessContinuityError::NonAdjacentCounter {
                previous: 0,
                candidate: 2,
            }
        );

        let wrong_parent = StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            1,
            [0xAA; 32],
            [0x41; 32],
            [0x30; 32],
            110,
        )
        .unwrap();
        let verified_wrong_parent = witnessed(wrong_parent);
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &verified_wrong_parent).unwrap_err(),
            StateWitnessContinuityError::PreviousCommitmentMismatch
        );
    }

    #[test]
    fn namespace_target_epoch_trust_and_time_are_continuity_bound() {
        let previous = witnessed(genesis(0x40));
        let base = StateCommitment::new(
            "test.namespace",
            [0x10; 32],
            [0x20; 32],
            1,
            previous.commitment_fingerprint(),
            [0x41; 32],
            [0x30; 32],
            110,
        )
        .unwrap();

        let mut changed = base.clone();
        changed.namespace = "other.namespace".into();
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &witnessed(changed)).unwrap_err(),
            StateWitnessContinuityError::NamespaceChanged
        );

        let mut changed = base.clone();
        changed.target_id = [0x11; 32];
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &witnessed(changed)).unwrap_err(),
            StateWitnessContinuityError::TargetChanged
        );

        let mut changed = base.clone();
        changed.epoch_id = [0x21; 32];
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &witnessed(changed)).unwrap_err(),
            StateWitnessContinuityError::EpochChanged
        );

        let mut changed = base.clone();
        changed.trust_context_digest = [0x31; 32];
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &witnessed(changed)).unwrap_err(),
            StateWitnessContinuityError::TrustContextChanged
        );

        let mut changed = base;
        changed.timestamp_unix_secs = 99;
        assert_eq!(
            Verifier::verify_state_witness_adjacent(&previous, &witnessed(changed)).unwrap_err(),
            StateWitnessContinuityError::TimestampRegressed {
                previous: 100,
                candidate: 99,
            }
        );
    }

    #[test]
    fn genesis_and_namespace_bounds_are_enforced() {
        assert_eq!(
            StateCommitment::new(
                "",
                [0; 32],
                [0; 32],
                0,
                ZERO_STATE_COMMITMENT,
                [0; 32],
                [0; 32],
                0,
            )
            .unwrap_err(),
            StateWitnessError::EmptyNamespace
        );
        assert_eq!(
            StateCommitment::new(
                "test.namespace",
                [0; 32],
                [0; 32],
                0,
                [1; 32],
                [0; 32],
                [0; 32],
                0,
            )
            .unwrap_err(),
            StateWitnessError::GenesisHasPreviousCommitment
        );
        assert_eq!(
            StateCommitment::new(
                "test.namespace",
                [0; 32],
                [0; 32],
                1,
                ZERO_STATE_COMMITMENT,
                [0; 32],
                [0; 32],
                0,
            )
            .unwrap_err(),
            StateWitnessError::MissingPreviousCommitment
        );
    }
}
