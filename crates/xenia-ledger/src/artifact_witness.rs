// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distinct trusted-key countersignatures for generic evidence artifacts.
//!
//! A primary [`EvidenceArtifactAttestation`] authenticates exact artifact bytes and
//! semantic metadata under one key. This module optionally adds countersignatures from
//! additional trusted keys so callers can require a key quorum before accepting an
//! artifact for a policy that needs multiple authenticated observers.
//!
//! Key diversity is not social/scientific independence. A valid quorum means only that
//! multiple distinct keys in the caller's trust set countersigned the same binding and
//! primary attestor fingerprint. It does not establish truth, institutional diversity,
//! scientific replication, reputation, or execution authority.

#![deny(unsafe_code)]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{MlDsa65, MlDsa87, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey};

use crate::artifact_attestation::{
    EvidenceArtifactAttestation, EvidenceArtifactAttestationError, EvidenceArtifactBinding,
    VerifiedEvidenceArtifactAttestation,
};
use crate::binding::{EvidencePublicKeyBinding, EvidencePublicKeyBindingError};
use crate::signature::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema label for a witness bundle.
pub const EVIDENCE_ARTIFACT_WITNESS_BUNDLE_SCHEMA: &str =
    "xenia-evidence-artifact-witness-bundle-v1";
/// Stable schema label for one witness countersignature.
pub const EVIDENCE_ARTIFACT_WITNESS_SIGNATURE_SCHEMA: &str =
    "xenia-evidence-artifact-witness-signature-v1";
/// Domain separation for witness countersignatures.
pub const EVIDENCE_ARTIFACT_WITNESS_DOMAIN: &[u8] =
    b"xenia:evidence-artifact-witness:v1";
/// Explicit upper bound for serialized/verification work.
pub const MAX_EVIDENCE_ARTIFACT_WITNESSES: usize = 64;

/// One trusted-key candidate countersignature over an exact artifact binding and
/// primary attestor fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifactWitnessSignature {
    /// Stable witness-signature schema.
    pub schema: String,
    /// Self-describing verifier key. Trust in this fingerprint remains caller policy.
    pub witness_key_binding: EvidencePublicKeyBinding,
    /// Signature suite committed into the signed transcript.
    pub signature_suite: SignatureSuite,
    /// Signature over [`evidence_artifact_witness_message`].
    pub signature: SignatureEnvelope,
}

impl EvidenceArtifactWitnessSignature {
    fn from_parts(
        witness_key_binding: EvidencePublicKeyBinding,
        signature_suite: SignatureSuite,
        signature: SignatureEnvelope,
    ) -> Result<Self, EvidenceArtifactWitnessError> {
        let envelope_suite = signature.validate_shape()?;
        if envelope_suite != signature_suite {
            return Err(EvidenceArtifactWitnessError::SignatureSuiteMismatch {
                declared_suite: signature_suite,
                envelope_suite,
            });
        }
        Ok(Self {
            schema: EVIDENCE_ARTIFACT_WITNESS_SIGNATURE_SCHEMA.to_string(),
            witness_key_binding,
            signature_suite,
            signature,
        })
    }

    fn validate_shape(&self) -> Result<(), EvidenceArtifactWitnessError> {
        if self.schema != EVIDENCE_ARTIFACT_WITNESS_SIGNATURE_SCHEMA {
            return Err(EvidenceArtifactWitnessError::UnsupportedWitnessSignatureSchema {
                schema: self.schema.clone(),
            });
        }
        let envelope_suite = self.signature.validate_shape()?;
        if envelope_suite != self.signature_suite {
            return Err(EvidenceArtifactWitnessError::SignatureSuiteMismatch {
                declared_suite: self.signature_suite,
                envelope_suite,
            });
        }
        Ok(())
    }
}

/// Primary artifact attestation plus optional countersignatures from distinct keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifactWitnessBundle {
    /// Stable bundle schema.
    pub schema: String,
    /// Primary artifact attestation whose signer is being witnessed.
    pub primary_attestation: EvidenceArtifactAttestation,
    /// Public-key binding needed to verify the primary attestation.
    pub primary_key_binding: EvidencePublicKeyBinding,
    /// Additional countersignatures. Duplicate signer fingerprints are invalid.
    pub witnesses: Vec<EvidenceArtifactWitnessSignature>,
}

impl EvidenceArtifactWitnessBundle {
    /// Begin a structurally checked bundle around one primary attestation/key binding.
    /// Cryptographic verification still occurs in [`Self::verify`].
    pub fn new(
        primary_attestation: EvidenceArtifactAttestation,
        primary_key_binding: EvidencePublicKeyBinding,
    ) -> Result<Self, EvidenceArtifactWitnessError> {
        primary_attestation.validate_shape()?;
        if primary_key_binding.signature_suite != primary_attestation.signature_suite {
            return Err(EvidenceArtifactWitnessError::PrimaryKeySuiteMismatch {
                attestation_suite: primary_attestation.signature_suite,
                key_suite: primary_key_binding.signature_suite,
            });
        }
        Ok(Self {
            schema: EVIDENCE_ARTIFACT_WITNESS_BUNDLE_SCHEMA.to_string(),
            primary_attestation,
            primary_key_binding,
            witnesses: Vec::new(),
        })
    }

    /// Add an Ed25519 countersignature. The primary key cannot witness itself.
    pub fn sign_with_ed25519(
        &mut self,
        witness_signing_key: &SigningKey,
    ) -> Result<(), EvidenceArtifactWitnessError> {
        self.ensure_witness_capacity()?;
        let suite = SignatureSuite::Ed25519Rfc8032;
        self.ensure_bundle_suite(suite)?;
        let key_binding = EvidencePublicKeyBinding::new(
            suite,
            witness_signing_key.verifying_key().to_bytes().to_vec(),
        );
        self.ensure_new_witness(&key_binding.public_key_fingerprint)?;
        let message = evidence_artifact_witness_message(
            &self.primary_attestation.binding,
            &self.primary_key_binding.public_key_fingerprint,
            &key_binding.public_key_fingerprint,
            suite,
        );
        let signature = witness_signing_key.sign(&message).to_bytes();
        self.witnesses.push(EvidenceArtifactWitnessSignature::from_parts(
            key_binding,
            suite,
            SignatureEnvelope::ed25519(signature),
        )?);
        Ok(())
    }

    /// Add an ML-DSA-65 countersignature under the existing PQC feature gate.
    #[cfg(feature = "pqc-signatures")]
    pub fn sign_with_ml_dsa_65(
        &mut self,
        witness_signing_key: &MlDsaSigningKey<MlDsa65>,
    ) -> Result<(), EvidenceArtifactWitnessError> {
        self.ensure_witness_capacity()?;
        let suite = SignatureSuite::MlDsa65Fips204;
        self.ensure_bundle_suite(suite)?;
        let verifying = witness_signing_key.verifying_key().encode();
        let key_bytes: &[u8] = verifying.as_ref();
        let key_binding = EvidencePublicKeyBinding::new(suite, key_bytes.to_vec());
        self.ensure_new_witness(&key_binding.public_key_fingerprint)?;
        let message = evidence_artifact_witness_message(
            &self.primary_attestation.binding,
            &self.primary_key_binding.public_key_fingerprint,
            &key_binding.public_key_fingerprint,
            suite,
        );
        let signature = witness_signing_key.sign(&message).encode();
        let signature_bytes: &[u8] = signature.as_ref();
        self.witnesses.push(EvidenceArtifactWitnessSignature::from_parts(
            key_binding,
            suite,
            SignatureEnvelope::new(suite, signature_bytes.to_vec()),
        )?);
        Ok(())
    }

    /// Add an ML-DSA-87 countersignature under the existing PQC feature gate.
    #[cfg(feature = "pqc-signatures")]
    pub fn sign_with_ml_dsa_87(
        &mut self,
        witness_signing_key: &MlDsaSigningKey<MlDsa87>,
    ) -> Result<(), EvidenceArtifactWitnessError> {
        self.ensure_witness_capacity()?;
        let suite = SignatureSuite::MlDsa87Fips204;
        self.ensure_bundle_suite(suite)?;
        let verifying = witness_signing_key.verifying_key().encode();
        let key_bytes: &[u8] = verifying.as_ref();
        let key_binding = EvidencePublicKeyBinding::new(suite, key_bytes.to_vec());
        self.ensure_new_witness(&key_binding.public_key_fingerprint)?;
        let message = evidence_artifact_witness_message(
            &self.primary_attestation.binding,
            &self.primary_key_binding.public_key_fingerprint,
            &key_binding.public_key_fingerprint,
            suite,
        );
        let signature = witness_signing_key.sign(&message).encode();
        let signature_bytes: &[u8] = signature.as_ref();
        self.witnesses.push(EvidenceArtifactWitnessSignature::from_parts(
            key_binding,
            suite,
            SignatureEnvelope::new(suite, signature_bytes.to_vec()),
        )?);
        Ok(())
    }

    /// Verify the primary attestation, every presented witness, and a minimum quorum of
    /// distinct fingerprints from the caller's explicit trust set.
    ///
    /// V1 deliberately requires the primary and all witness signatures to use the same
    /// signature suite/backend. Mixed-suite migration can be introduced later with an
    /// explicit backend registry rather than silently selecting algorithms from input.
    ///
    /// Unexpected/untrusted witnesses fail closed instead of being ignored. The returned
    /// verified type is not deserializable, so persisted bundles must re-verify.
    pub fn verify(
        &self,
        artifact_bytes: &[u8],
        backend: &impl EvidenceSignatureBackend,
        trusted_witness_key_fingerprints: &[[u8; 32]],
        minimum_quorum: usize,
    ) -> Result<VerifiedEvidenceArtifactWitnessBundle, EvidenceArtifactWitnessError> {
        self.validate_shape()?;
        validate_trust_policy(trusted_witness_key_fingerprints, minimum_quorum)?;

        let verified_primary = self.primary_attestation.verify(
            artifact_bytes,
            &self.primary_key_binding,
            backend,
        )?;
        let primary_fingerprint = *verified_primary.signer_public_key_fingerprint();

        let trusted = trusted_witness_key_fingerprints
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();

        for witness in &self.witnesses {
            witness.validate_shape()?;
            if witness.signature_suite != self.primary_attestation.signature_suite {
                return Err(EvidenceArtifactWitnessError::MixedSignatureSuiteUnsupported {
                    primary_suite: self.primary_attestation.signature_suite,
                    witness_suite: witness.signature_suite,
                });
            }
            witness
                .witness_key_binding
                .validate_against_signature_suite_and_backend(witness.signature_suite, backend)?;

            let fingerprint = witness.witness_key_binding.public_key_fingerprint;
            if fingerprint == primary_fingerprint {
                return Err(EvidenceArtifactWitnessError::PrimaryKeyCannotWitnessItself);
            }
            if !observed.insert(fingerprint) {
                return Err(EvidenceArtifactWitnessError::DuplicateWitnessFingerprint);
            }
            if !trusted.contains(&fingerprint) {
                return Err(EvidenceArtifactWitnessError::UntrustedWitness);
            }

            let message = evidence_artifact_witness_message(
                verified_primary.binding(),
                &primary_fingerprint,
                &fingerprint,
                witness.signature_suite,
            );
            backend.verify_signature(
                &witness.witness_key_binding.public_key,
                &message,
                &witness.signature.signature,
            )?;
        }

        if observed.len() < minimum_quorum {
            return Err(EvidenceArtifactWitnessError::QuorumNotMet {
                verified: observed.len(),
                required: minimum_quorum,
            });
        }

        Ok(VerifiedEvidenceArtifactWitnessBundle {
            primary: verified_primary,
            verified_witness_key_fingerprints: observed.into_iter().collect(),
            required_quorum: minimum_quorum,
        })
    }

    fn validate_shape(&self) -> Result<(), EvidenceArtifactWitnessError> {
        if self.schema != EVIDENCE_ARTIFACT_WITNESS_BUNDLE_SCHEMA {
            return Err(EvidenceArtifactWitnessError::UnsupportedWitnessBundleSchema {
                schema: self.schema.clone(),
            });
        }
        self.primary_attestation.validate_shape()?;
        if self.primary_key_binding.signature_suite != self.primary_attestation.signature_suite {
            return Err(EvidenceArtifactWitnessError::PrimaryKeySuiteMismatch {
                attestation_suite: self.primary_attestation.signature_suite,
                key_suite: self.primary_key_binding.signature_suite,
            });
        }
        if self.witnesses.len() > MAX_EVIDENCE_ARTIFACT_WITNESSES {
            return Err(EvidenceArtifactWitnessError::TooManyWitnesses {
                count: self.witnesses.len(),
                maximum: MAX_EVIDENCE_ARTIFACT_WITNESSES,
            });
        }
        Ok(())
    }

    fn ensure_bundle_suite(&self, suite: SignatureSuite) -> Result<(), EvidenceArtifactWitnessError> {
        if self.primary_attestation.signature_suite != suite {
            return Err(EvidenceArtifactWitnessError::MixedSignatureSuiteUnsupported {
                primary_suite: self.primary_attestation.signature_suite,
                witness_suite: suite,
            });
        }
        Ok(())
    }

    fn ensure_witness_capacity(&self) -> Result<(), EvidenceArtifactWitnessError> {
        if self.witnesses.len() >= MAX_EVIDENCE_ARTIFACT_WITNESSES {
            return Err(EvidenceArtifactWitnessError::TooManyWitnesses {
                count: self.witnesses.len() + 1,
                maximum: MAX_EVIDENCE_ARTIFACT_WITNESSES,
            });
        }
        Ok(())
    }

    fn ensure_new_witness(&self, fingerprint: &[u8; 32]) -> Result<(), EvidenceArtifactWitnessError> {
        if fingerprint == &self.primary_key_binding.public_key_fingerprint {
            return Err(EvidenceArtifactWitnessError::PrimaryKeyCannotWitnessItself);
        }
        if self
            .witnesses
            .iter()
            .any(|witness| &witness.witness_key_binding.public_key_fingerprint == fingerprint)
        {
            return Err(EvidenceArtifactWitnessError::DuplicateWitnessFingerprint);
        }
        Ok(())
    }
}

/// Constructor-only result of primary + witness verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedEvidenceArtifactWitnessBundle {
    primary: VerifiedEvidenceArtifactAttestation,
    verified_witness_key_fingerprints: Vec<[u8; 32]>,
    required_quorum: usize,
}

impl VerifiedEvidenceArtifactWitnessBundle {
    /// Verified primary artifact attestation.
    pub fn primary(&self) -> &VerifiedEvidenceArtifactAttestation {
        &self.primary
    }

    /// Sorted distinct trusted witness-key fingerprints that cryptographically verified.
    pub fn verified_witness_key_fingerprints(&self) -> &[[u8; 32]] {
        &self.verified_witness_key_fingerprints
    }

    /// Quorum floor that was satisfied by this verification.
    pub fn required_quorum(&self) -> usize {
        self.required_quorum
    }
}

/// Domain-separated witness transcript.
///
/// The witness signs the exact artifact semantic binding, the primary signer fingerprint,
/// its own key fingerprint, and the selected signature suite. This makes witness signatures
/// non-transferable across primary signers, artifacts, semantic domains, or suite tags.
pub fn evidence_artifact_witness_message(
    binding: &EvidenceArtifactBinding,
    primary_attestor_fingerprint: &[u8; 32],
    witness_fingerprint: &[u8; 32],
    signature_suite: SignatureSuite,
) -> Vec<u8> {
    let mut message = Vec::new();
    push_bytes(&mut message, EVIDENCE_ARTIFACT_WITNESS_DOMAIN);
    push_bytes(
        &mut message,
        EVIDENCE_ARTIFACT_WITNESS_SIGNATURE_SCHEMA.as_bytes(),
    );
    push_bytes(&mut message, binding.schema.as_bytes());
    push_bytes(&mut message, binding.artifact_domain.as_bytes());
    push_bytes(&mut message, binding.artifact_schema.as_bytes());
    push_bytes(&mut message, binding.subject_ref.as_bytes());
    push_bytes(&mut message, binding.digest_algorithm.as_bytes());
    push_bytes(&mut message, &binding.artifact_digest);
    push_bytes(&mut message, primary_attestor_fingerprint);
    push_bytes(&mut message, witness_fingerprint);
    push_bytes(&mut message, signature_suite.stable_label().as_bytes());
    message
}

fn validate_trust_policy(
    trusted_fingerprints: &[[u8; 32]],
    minimum_quorum: usize,
) -> Result<(), EvidenceArtifactWitnessError> {
    if minimum_quorum == 0 {
        return Err(EvidenceArtifactWitnessError::ZeroQuorum);
    }
    if trusted_fingerprints.len() > MAX_EVIDENCE_ARTIFACT_WITNESSES {
        return Err(EvidenceArtifactWitnessError::TooManyTrustedWitnesses {
            count: trusted_fingerprints.len(),
            maximum: MAX_EVIDENCE_ARTIFACT_WITNESSES,
        });
    }
    let distinct = trusted_fingerprints.iter().copied().collect::<BTreeSet<_>>();
    if distinct.len() != trusted_fingerprints.len() {
        return Err(EvidenceArtifactWitnessError::DuplicateTrustedWitnessFingerprint);
    }
    if minimum_quorum > distinct.len() {
        return Err(EvidenceArtifactWitnessError::ImpossibleQuorum {
            required: minimum_quorum,
            trusted: distinct.len(),
        });
    }
    Ok(())
}

fn push_bytes(message: &mut Vec<u8>, bytes: &[u8]) {
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(bytes);
}

/// Why a witness bundle or quorum was rejected.
#[derive(Debug, Error)]
pub enum EvidenceArtifactWitnessError {
    /// Primary artifact attestation failed validation or cryptographic verification.
    #[error("primary artifact attestation failed: {0}")]
    ArtifactAttestation(#[from] EvidenceArtifactAttestationError),
    /// A key binding was malformed or incompatible with the selected backend.
    #[error("evidence public-key binding failed: {0}")]
    KeyBinding(#[from] EvidencePublicKeyBindingError),
    /// A witness signature envelope was malformed.
    #[error("signature envelope failed: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Cryptographic signature verification failed.
    #[error("signature backend failed: {0}")]
    SignatureBackend(#[from] EvidenceSignatureBackendError),
    /// Bundle schema is unknown.
    #[error("unsupported evidence artifact witness bundle schema: {schema}")]
    UnsupportedWitnessBundleSchema { schema: String },
    /// Witness-signature schema is unknown.
    #[error("unsupported evidence artifact witness signature schema: {schema}")]
    UnsupportedWitnessSignatureSchema { schema: String },
    /// Signature envelope and declared suite disagree.
    #[error("witness signature suite mismatch: declared={declared_suite:?}, envelope={envelope_suite:?}")]
    SignatureSuiteMismatch {
        declared_suite: SignatureSuite,
        envelope_suite: SignatureSuite,
    },
    /// Primary key binding and primary attestation use different signature suites.
    #[error("primary key suite mismatch: attestation={attestation_suite:?}, key={key_suite:?}")]
    PrimaryKeySuiteMismatch {
        attestation_suite: SignatureSuite,
        key_suite: SignatureSuite,
    },
    /// V1 does not silently dispatch heterogeneous signature algorithms.
    #[error("mixed witness signature suites are unsupported in v1: primary={primary_suite:?}, witness={witness_suite:?}")]
    MixedSignatureSuiteUnsupported {
        primary_suite: SignatureSuite,
        witness_suite: SignatureSuite,
    },
    /// The primary signing key cannot count as its own independent witness key.
    #[error("primary artifact attestor key cannot witness itself")]
    PrimaryKeyCannotWitnessItself,
    /// The same witness fingerprint appeared more than once.
    #[error("duplicate artifact witness key fingerprint")]
    DuplicateWitnessFingerprint,
    /// The configured trust set contained the same fingerprint more than once.
    #[error("duplicate fingerprint in trusted artifact witness set")]
    DuplicateTrustedWitnessFingerprint,
    /// A presented witness is outside the caller's explicit trust set.
    #[error("artifact witness key is not trusted")]
    UntrustedWitness,
    /// Witness bundle exceeded explicit resource bound.
    #[error("artifact witness bundle has {count} witnesses; maximum is {maximum}")]
    TooManyWitnesses { count: usize, maximum: usize },
    /// Trust policy exceeded explicit resource bound.
    #[error("artifact witness trust set has {count} keys; maximum is {maximum}")]
    TooManyTrustedWitnesses { count: usize, maximum: usize },
    /// A zero quorum would accept an unwitnessed artifact.
    #[error("artifact witness quorum must be greater than zero")]
    ZeroQuorum,
    /// Quorum cannot exceed the number of distinct trusted keys.
    #[error("artifact witness quorum is impossible: required={required}, trusted={trusted}")]
    ImpossibleQuorum { required: usize, trusted: usize },
    /// Verified witness count did not meet policy.
    #[error("artifact witness quorum not met: verified={verified}, required={required}")]
    QuorumNotMet { verified: usize, required: usize },
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::artifact_attestation::{
        EvidenceArtifactBinding, sign_evidence_artifact_binding_ed25519,
    };
    use crate::signature::Ed25519EvidenceSignatureBackend;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn primary_bundle(artifact: &[u8]) -> EvidenceArtifactWitnessBundle {
        let primary = key(1);
        let binding = EvidenceArtifactBinding::from_artifact(
            "symthaea-generativity-provenance",
            "symthaea-generativity-provenance-capsule-v1",
            "subject:alpha",
            artifact,
        )
        .unwrap();
        let attestation = sign_evidence_artifact_binding_ed25519(binding, &primary).unwrap();
        let key_binding = EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            primary.verifying_key().to_bytes().to_vec(),
        );
        EvidenceArtifactWitnessBundle::new(attestation, key_binding).unwrap()
    }

    fn fingerprint(signing_key: &SigningKey) -> [u8; 32] {
        EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            signing_key.verifying_key().to_bytes().to_vec(),
        )
        .public_key_fingerprint
    }

    #[test]
    fn two_of_three_trusted_keys_verify() {
        let artifact = b"canonical provenance capsule";
        let mut bundle = primary_bundle(artifact);
        let w1 = key(2);
        let w2 = key(3);
        let w3 = key(4);
        bundle.sign_with_ed25519(&w1).unwrap();
        bundle.sign_with_ed25519(&w2).unwrap();

        let trusted = [fingerprint(&w1), fingerprint(&w2), fingerprint(&w3)];
        let verified = bundle
            .verify(artifact, &Ed25519EvidenceSignatureBackend, &trusted, 2)
            .unwrap();
        assert_eq!(verified.required_quorum(), 2);
        assert_eq!(verified.verified_witness_key_fingerprints().len(), 2);
    }

    #[test]
    fn duplicate_witness_key_is_rejected() {
        let artifact = b"capsule";
        let mut bundle = primary_bundle(artifact);
        let witness = key(2);
        bundle.sign_with_ed25519(&witness).unwrap();
        assert!(matches!(
            bundle.sign_with_ed25519(&witness),
            Err(EvidenceArtifactWitnessError::DuplicateWitnessFingerprint)
        ));
    }

    #[test]
    fn primary_key_cannot_witness_itself() {
        let artifact = b"capsule";
        let mut bundle = primary_bundle(artifact);
        assert!(matches!(
            bundle.sign_with_ed25519(&key(1)),
            Err(EvidenceArtifactWitnessError::PrimaryKeyCannotWitnessItself)
        ));
    }

    #[test]
    fn unexpected_witness_fails_closed() {
        let artifact = b"capsule";
        let mut bundle = primary_bundle(artifact);
        let witness = key(2);
        let other = key(3);
        bundle.sign_with_ed25519(&witness).unwrap();
        let trusted = [fingerprint(&other)];
        assert!(matches!(
            bundle.verify(artifact, &Ed25519EvidenceSignatureBackend, &trusted, 1),
            Err(EvidenceArtifactWitnessError::UntrustedWitness)
        ));
    }

    #[test]
    fn copied_witness_signature_does_not_verify_for_different_primary_signer() {
        let artifact = b"capsule";
        let mut original = primary_bundle(artifact);
        let witness = key(2);
        original.sign_with_ed25519(&witness).unwrap();

        let different_primary = key(9);
        let binding = original.primary_attestation.binding.clone();
        let attestation =
            sign_evidence_artifact_binding_ed25519(binding, &different_primary).unwrap();
        let key_binding = EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            different_primary.verifying_key().to_bytes().to_vec(),
        );
        let mut transplanted = EvidenceArtifactWitnessBundle::new(attestation, key_binding).unwrap();
        transplanted.witnesses = original.witnesses.clone();
        let trusted = [fingerprint(&witness)];
        assert!(matches!(
            transplanted.verify(artifact, &Ed25519EvidenceSignatureBackend, &trusted, 1),
            Err(EvidenceArtifactWitnessError::SignatureBackend(_))
        ));
    }

    #[test]
    fn artifact_mutation_fails_before_quorum_can_launder_it() {
        let artifact = b"capsule";
        let mut bundle = primary_bundle(artifact);
        let witness = key(2);
        bundle.sign_with_ed25519(&witness).unwrap();
        let trusted = [fingerprint(&witness)];
        assert!(matches!(
            bundle.verify(b"mutated", &Ed25519EvidenceSignatureBackend, &trusted, 1),
            Err(EvidenceArtifactWitnessError::ArtifactAttestation(_))
        ));
    }

    #[test]
    fn zero_and_impossible_quorums_fail_closed() {
        let artifact = b"capsule";
        let bundle = primary_bundle(artifact);
        let witness = key(2);
        let trusted = [fingerprint(&witness)];
        assert!(matches!(
            bundle.verify(artifact, &Ed25519EvidenceSignatureBackend, &trusted, 0),
            Err(EvidenceArtifactWitnessError::ZeroQuorum)
        ));
        assert!(matches!(
            bundle.verify(artifact, &Ed25519EvidenceSignatureBackend, &trusted, 2),
            Err(EvidenceArtifactWitnessError::ImpossibleQuorum { .. })
        ));
    }
}
