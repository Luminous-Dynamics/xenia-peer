// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Concrete cryptographic adapters for Xenia generic authenticated subjects.
//!
//! This crate proves signature validity for one exact `(suite, signer_key_id)`
//! over a caller-supplied canonical authentication digest. It deliberately does
//! not decide whether that signer is authorized for an application action.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    MlDsa65, Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    signature::Verifier as _,
};
use thiserror::Error;
use xenia_auth_protocol::{
    AuthenticationProtocolError, AuthenticationSuiteId, SubjectAuthentication,
    SubjectAuthenticationVerifier, signer_key_id,
};

pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;
pub const MAX_AUTHENTICATION_VERIFIERS_V1: usize = 64;

/// Bounded exact-identity registry of generic authentication verifiers.
///
/// Authorization remains outside this registry. Callers decide which exact
/// suite/key identities are trusted for their application subject.
pub struct AuthenticationVerifierRegistryV1 {
    verifiers: Vec<Box<dyn SubjectAuthenticationVerifier>>,
}

impl AuthenticationVerifierRegistryV1 {
    pub fn try_new(
        verifiers: Vec<Box<dyn SubjectAuthenticationVerifier>>,
    ) -> Result<Self, AuthenticationAdapterError> {
        if verifiers.len() > MAX_AUTHENTICATION_VERIFIERS_V1 {
            return Err(AuthenticationAdapterError::TooManyVerifiers {
                actual: verifiers.len(),
                limit: MAX_AUTHENTICATION_VERIFIERS_V1,
            });
        }

        for (index, verifier) in verifiers.iter().enumerate() {
            let identity = (verifier.suite().wire_id(), verifier.signer_key_id());
            if verifiers[..index]
                .iter()
                .any(|existing| (existing.suite().wire_id(), existing.signer_key_id()) == identity)
            {
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
    ) -> Option<&dyn SubjectAuthenticationVerifier> {
        self.verifiers
            .iter()
            .find(|verifier| verifier.suite() == suite && verifier.signer_key_id() == signer_key_id)
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
    #[error("failed to derive canonical signer key id: {0}")]
    SignerKeyId(AuthenticationProtocolError),
    #[error("too many authentication verifiers: {actual} > {limit}")]
    TooManyVerifiers { actual: usize, limit: usize },
    #[error("authentication verifier registry contains a duplicate suite/key identity")]
    DuplicateVerifierIdentity,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SubjectAuthenticationVerificationError {
    #[error("malformed authentication entry: {0}")]
    MalformedAuthentication(AuthenticationProtocolError),
    #[error("no verifier is registered for the exact suite/key identity")]
    ExactVerifierNotFound,
    #[error("cryptographic authentication failed")]
    SignatureInvalid,
}

/// Concrete Ed25519 verifier for a Xenia generic authentication digest.
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
            .map_err(AuthenticationAdapterError::SignerKeyId)?;
        Ok(Self {
            verifying_key,
            signer_key_id,
        })
    }
}

impl SubjectAuthenticationVerifier for Ed25519AuthenticationVerifier {
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
        self.verifying_key.verify_strict(digest, &signature).is_ok()
    }
}

/// Concrete FIPS-204 ML-DSA-65 verifier for a Xenia generic authentication digest.
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
            .map_err(AuthenticationAdapterError::SignerKeyId)?;
        Ok(Self {
            verifying_key,
            signer_key_id,
        })
    }
}

impl SubjectAuthenticationVerifier for MlDsa65AuthenticationVerifier {
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

/// Verify one detached authentication against an exact preconfigured verifier.
pub fn verify_authentication(
    registry: &AuthenticationVerifierRegistryV1,
    digest: &[u8; 32],
    authentication: &SubjectAuthentication,
) -> Result<(), SubjectAuthenticationVerificationError> {
    authentication
        .validate()
        .map_err(SubjectAuthenticationVerificationError::MalformedAuthentication)?;

    let verifier = registry
        .find_exact(authentication.suite, authentication.signer_key_id)
        .ok_or(SubjectAuthenticationVerificationError::ExactVerifierNotFound)?;

    if verifier.verify(digest, &authentication.signature) {
        Ok(())
    } else {
        Err(SubjectAuthenticationVerificationError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use xenia_auth_protocol::{AuthenticationContextId, authenticated_subject_digest};

    const GOLDEN_GENERIC_ED25519_KEY_ID: [u8; 32] = [
        0x3c, 0x0e, 0x8b, 0xd0, 0x16, 0x25, 0x3b, 0xfe, 0xd7, 0x34, 0xee, 0x6a, 0x24, 0xd4, 0xb4,
        0xa4, 0x7c, 0x2e, 0x15, 0x46, 0xbc, 0x04, 0xfa, 0x00, 0x2b, 0x43, 0x22, 0x9a, 0xd2, 0x95,
        0xe0, 0x55,
    ];
    const GOLDEN_GENERIC_ED25519_AUTH_DIGEST: [u8; 32] = [
        0xc4, 0x57, 0xf5, 0xb2, 0xea, 0xc8, 0x15, 0xa0, 0xf7, 0x6d, 0x0e, 0x04, 0x66, 0x15, 0x37,
        0xa1, 0x9c, 0x60, 0x39, 0xb5, 0x49, 0x9a, 0x56, 0xab, 0x80, 0xcb, 0xdb, 0x25, 0x74, 0x30,
        0x11, 0x4b,
    ];

    fn context() -> AuthenticationContextId {
        AuthenticationContextId::try_new("MYCELIX", "PublicElection", "VerifierReceipt", 1).unwrap()
    }

    #[test]
    fn ed25519_adapter_verifies_exact_generic_subject() {
        let signing = SigningKey::from_bytes(&[0x42; 32]);
        let public = signing.verifying_key().to_bytes();
        let verifier = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        assert_eq!(verifier.signer_key_id(), GOLDEN_GENERIC_ED25519_KEY_ID);

        let digest = authenticated_subject_digest(
            &context(),
            &[0xA5; 32],
            AuthenticationSuiteId::ED25519,
            &verifier.signer_key_id(),
        )
        .unwrap();
        assert_eq!(digest, GOLDEN_GENERIC_ED25519_AUTH_DIGEST);

        let signature = signing.sign(&digest).to_bytes().to_vec();
        let authentication = SubjectAuthentication {
            suite: AuthenticationSuiteId::ED25519,
            signer_key_id: verifier.signer_key_id(),
            signature,
        };
        let registry = AuthenticationVerifierRegistryV1::try_new(vec![Box::new(verifier)]).unwrap();
        assert_eq!(
            verify_authentication(&registry, &digest, &authentication),
            Ok(())
        );

        let changed_digest = authenticated_subject_digest(
            &context(),
            &[0xA6; 32],
            AuthenticationSuiteId::ED25519,
            &authentication.signer_key_id,
        )
        .unwrap();
        assert_eq!(
            verify_authentication(&registry, &changed_digest, &authentication),
            Err(SubjectAuthenticationVerificationError::SignatureInvalid)
        );
    }

    #[test]
    fn exact_registry_lookup_prevents_suite_or_key_relabeling() {
        let signing = SigningKey::from_bytes(&[0x24; 32]);
        let public = signing.verifying_key().to_bytes();
        let verifier = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        let id = verifier.signer_key_id();
        let registry = AuthenticationVerifierRegistryV1::try_new(vec![Box::new(verifier)]).unwrap();

        assert!(
            registry
                .find_exact(AuthenticationSuiteId::ED25519, id)
                .is_some()
        );
        assert!(
            registry
                .find_exact(AuthenticationSuiteId::ML_DSA_65_FIPS204, id)
                .is_none()
        );

        let mut wrong_id = id;
        wrong_id[0] ^= 1;
        assert!(
            registry
                .find_exact(AuthenticationSuiteId::ED25519, wrong_id)
                .is_none()
        );
    }

    #[test]
    fn duplicate_verifier_identity_is_rejected() {
        let signing = SigningKey::from_bytes(&[0x24; 32]);
        let public = signing.verifying_key().to_bytes();
        let first = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        let second = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        assert!(matches!(
            AuthenticationVerifierRegistryV1::try_new(vec![Box::new(first), Box::new(second)]),
            Err(AuthenticationAdapterError::DuplicateVerifierIdentity)
        ));
    }

    #[test]
    fn malformed_ml_dsa_public_key_length_fails_before_decode() {
        assert!(matches!(
            MlDsa65AuthenticationVerifier::try_from_public_key_bytes(&[0u8; 32]),
            Err(AuthenticationAdapterError::InvalidMlDsa65PublicKeyLength { .. })
        ));
    }

    #[test]
    fn malformed_signature_entry_fails_before_crypto() {
        let signing = SigningKey::from_bytes(&[0x33; 32]);
        let public = signing.verifying_key().to_bytes();
        let verifier = Ed25519AuthenticationVerifier::try_from_public_key_bytes(&public).unwrap();
        let authentication = SubjectAuthentication {
            suite: AuthenticationSuiteId::ED25519,
            signer_key_id: verifier.signer_key_id(),
            signature: Vec::new(),
        };
        let registry = AuthenticationVerifierRegistryV1::try_new(vec![Box::new(verifier)]).unwrap();
        assert!(matches!(
            verify_authentication(&registry, &[0xA5; 32], &authentication),
            Err(
                SubjectAuthenticationVerificationError::MalformedAuthentication(
                    AuthenticationProtocolError::EmptySignature
                )
            )
        ));
    }

    #[test]
    fn absent_exact_verifier_fails_closed() {
        let authentication = SubjectAuthentication {
            suite: AuthenticationSuiteId::ED25519,
            signer_key_id: [0x77; 32],
            signature: vec![0x88; ED25519_SIGNATURE_BYTES],
        };
        let registry = AuthenticationVerifierRegistryV1::try_new(Vec::new()).unwrap();
        assert_eq!(
            verify_authentication(&registry, &[0xA5; 32], &authentication),
            Err(SubjectAuthenticationVerificationError::ExactVerifierNotFound)
        );
    }
}
