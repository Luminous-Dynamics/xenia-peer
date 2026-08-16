// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Concrete authentication adapters for `xenia-zk-protocol`.
//!
//! This crate is intentionally narrow: it verifies the canonical 32-byte
//! authentication digests produced by `xenia-zk-protocol` using the exact V1
//! authentication-suite registry. It does not parse proof envelopes or choose
//! trust policy for callers.

use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    MlDsa65, Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    signature::Verifier as _,
};
use thiserror::Error;
use xenia_zk_protocol::{
    AuthenticationSuiteId, signer_key_id,
    verification::ProofAuthenticationVerifier,
};

pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;


pub const MAX_AUTHENTICATION_VERIFIERS_V1: usize = 64;

/// Bounded, ambiguity-free collection of canonical authentication verifiers.
///
/// The registry owns no authorization policy: callers still decide which signer
/// identities are trusted for a particular protocol action. Its job is narrower:
/// guarantee that an exact `(suite, signer_key_id)` lookup resolves to at most
/// one cryptographic verifier and that untrusted configuration cannot grow the
/// verifier set without bound.
pub struct AuthenticationVerifierRegistryV1 {
    verifiers: Vec<Box<dyn ProofAuthenticationVerifier>>,
}

impl AuthenticationVerifierRegistryV1 {
    pub fn try_new(
        verifiers: Vec<Box<dyn ProofAuthenticationVerifier>>,
    ) -> Result<Self, AuthenticationAdapterError> {
        if verifiers.len() > MAX_AUTHENTICATION_VERIFIERS_V1 {
            return Err(AuthenticationAdapterError::TooManyVerifiers {
                actual: verifiers.len(),
                limit: MAX_AUTHENTICATION_VERIFIERS_V1,
            });
        }
        for (index, verifier) in verifiers.iter().enumerate() {
            let identity = (verifier.suite().wire_id(), verifier.signer_key_id());
            if verifiers[..index].iter().any(|existing| {
                (existing.suite().wire_id(), existing.signer_key_id()) == identity
            }) {
                return Err(AuthenticationAdapterError::DuplicateVerifierIdentity);
            }
        }
        Ok(Self { verifiers })
    }

    pub fn len(&self) -> usize {
        self.verifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.verifiers.is_empty()
    }

    pub fn find_exact(
        &self,
        suite: AuthenticationSuiteId,
        signer_key_id: [u8; 32],
    ) -> Option<&dyn ProofAuthenticationVerifier> {
        self.verifiers
            .iter()
            .find(|verifier| {
                verifier.suite() == suite && verifier.signer_key_id() == signer_key_id
            })
            .map(|verifier| verifier.as_ref())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthenticationAdapterError {
    #[error("invalid Ed25519 public key encoding")]
    InvalidEd25519PublicKey,
    #[error("invalid ML-DSA-65 public key length: {actual} != {expected}")]
    InvalidMlDsa65PublicKeyLength { actual: usize, expected: usize },
    #[error("invalid ML-DSA-65 public key encoding")]
    InvalidMlDsa65PublicKey,
    #[error("failed to derive canonical signer key id")]
    SignerKeyId,
    #[error("too many authentication verifiers: {actual} > {limit}")]
    TooManyVerifiers { actual: usize, limit: usize },
    #[error("authentication verifier registry contains a duplicate suite/key identity")]
    DuplicateVerifierIdentity,
}

/// Concrete Ed25519 verifier for Xenia's canonical authentication digest.
pub struct Ed25519AuthenticationVerifier {
    verifying_key: VerifyingKey,
    signer_key_id: [u8; 32],
}

impl Ed25519AuthenticationVerifier {
    pub fn try_from_public_key_bytes(bytes: &[u8]) -> Result<Self, AuthenticationAdapterError> {
        let raw: [u8; ED25519_PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| AuthenticationAdapterError::InvalidEd25519PublicKey)?;
        let verifying_key = VerifyingKey::from_bytes(&raw)
            .map_err(|_| AuthenticationAdapterError::InvalidEd25519PublicKey)?;
        let signer_key_id = signer_key_id(AuthenticationSuiteId::ED25519, bytes)
            .map_err(|_| AuthenticationAdapterError::SignerKeyId)?;
        Ok(Self { verifying_key, signer_key_id })
    }
}

impl ProofAuthenticationVerifier for Ed25519AuthenticationVerifier {
    fn suite(&self) -> AuthenticationSuiteId {
        AuthenticationSuiteId::ED25519
    }

    fn signer_key_id(&self) -> [u8; 32] {
        self.signer_key_id
    }

    fn verify(&self, digest: &[u8; 32], signature: &[u8]) -> bool {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return false;
        }
        let Ok(signature) = Ed25519Signature::from_slice(signature) else {
            return false;
        };
        self.verifying_key.verify(digest, &signature).is_ok()
    }
}

/// Concrete FIPS-204 ML-DSA-65 verifier for Xenia's canonical authentication digest.
pub struct MlDsa65AuthenticationVerifier {
    verifying_key: MlDsaVerifyingKey<MlDsa65>,
    signer_key_id: [u8; 32],
}

impl MlDsa65AuthenticationVerifier {
    pub fn try_from_public_key_bytes(bytes: &[u8]) -> Result<Self, AuthenticationAdapterError> {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
            return Err(AuthenticationAdapterError::InvalidMlDsa65PublicKeyLength {
                actual: bytes.len(),
                expected: ML_DSA_65_PUBLIC_KEY_BYTES,
            });
        }
        let encoded = MlDsaEncodedVerifyingKey::<MlDsa65>::try_from(bytes)
            .map_err(|_| AuthenticationAdapterError::InvalidMlDsa65PublicKey)?;
        let verifying_key = MlDsaVerifyingKey::<MlDsa65>::decode(&encoded);
        let signer_key_id = signer_key_id(AuthenticationSuiteId::ML_DSA_65_FIPS204, bytes)
            .map_err(|_| AuthenticationAdapterError::SignerKeyId)?;
        Ok(Self { verifying_key, signer_key_id })
    }
}

impl ProofAuthenticationVerifier for MlDsa65AuthenticationVerifier {
    fn suite(&self) -> AuthenticationSuiteId {
        AuthenticationSuiteId::ML_DSA_65_FIPS204
    }

    fn signer_key_id(&self) -> [u8; 32] {
        self.signer_key_id
    }

    fn verify(&self, digest: &[u8; 32], signature: &[u8]) -> bool {
        if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return false;
        }
        let Ok(encoded) = MlDsaEncodedSignature::<MlDsa65>::try_from(signature) else {
            return false;
        };
        let Some(signature) = MlDsaSignature::<MlDsa65>::decode(&encoded) else {
            return false;
        };
        self.verifying_key.verify(digest, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn ed25519_adapter_verifies_only_exact_digest_and_signature_size() {
        let signing = SigningKey::from_bytes(&[0x42; 32]);
        let public = signing.verifying_key().to_bytes();
        let verifier = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        let digest = [0xA5; 32];
        let signature = signing.sign(&digest).to_bytes();
        assert_eq!(
            public,
            [
                0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24,
                0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c,
                0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00,
                0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12,
            ]
        );
        assert_eq!(
            signature,
            [
                0xc2, 0xe6, 0x43, 0xed, 0x74, 0xc6, 0x11, 0x2d,
                0x24, 0x73, 0x38, 0xda, 0x8f, 0x05, 0x5d, 0x0a,
                0x00, 0xa4, 0x4a, 0xc8, 0x95, 0x39, 0xde, 0x47,
                0xa9, 0xbe, 0xf9, 0x21, 0x3b, 0xd9, 0xec, 0xbf,
                0x67, 0xcd, 0x34, 0xbb, 0xba, 0x1e, 0x61, 0x4c,
                0x5d, 0x0a, 0x40, 0xb2, 0xac, 0x4d, 0xab, 0xaf,
                0xdf, 0x2d, 0x9f, 0x13, 0x77, 0xf2, 0xc8, 0xb4,
                0xcf, 0x02, 0x39, 0x44, 0x13, 0x64, 0x0f, 0x07,
            ]
        );
        assert_eq!(
            verifier.signer_key_id(),
            [
                0x0f, 0xf8, 0x5d, 0x10, 0x3c, 0xb9, 0x86, 0x5d,
                0x2a, 0x01, 0xf4, 0xca, 0x0c, 0x72, 0x91, 0xd9,
                0x97, 0x4a, 0x48, 0x70, 0x80, 0x9f, 0xd5, 0xeb,
                0x93, 0x42, 0x6b, 0x76, 0xd2, 0x10, 0xcd, 0xcf,
            ]
        );
        assert!(verifier.verify(&digest, &signature));
        let mut changed = digest;
        changed[0] ^= 1;
        assert!(!verifier.verify(&changed, &signature));
        assert!(!verifier.verify(&digest, &signature[..63]));
        assert_eq!(verifier.suite(), AuthenticationSuiteId::ED25519);
        assert_eq!(
            verifier.signer_key_id(),
            signer_key_id(AuthenticationSuiteId::ED25519, &public).unwrap()
        );
    }

    #[test]
    fn malformed_ml_dsa_public_key_length_fails_before_decode() {
        assert!(matches!(
            MlDsa65AuthenticationVerifier::try_from_public_key_bytes(&[0u8; 32]),
            Err(AuthenticationAdapterError::InvalidMlDsa65PublicKeyLength { .. })
        ));
    }


    #[test]
    fn verifier_registry_rejects_duplicate_identity_and_supports_exact_lookup() {
        let signing = SigningKey::from_bytes(&[0x24; 32]);
        let public = signing.verifying_key().to_bytes();
        let first = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        let id = first.signer_key_id();
        let registry = AuthenticationVerifierRegistryV1::try_new(vec![Box::new(first)]).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.find_exact(AuthenticationSuiteId::ED25519, id).is_some());
        assert!(registry.find_exact(AuthenticationSuiteId::ML_DSA_65_FIPS204, id).is_none());

        let a = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        let b = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        assert!(matches!(
            AuthenticationVerifierRegistryV1::try_new(vec![Box::new(a), Box::new(b)]),
            Err(AuthenticationAdapterError::DuplicateVerifierIdentity)
        ));
    }
}
