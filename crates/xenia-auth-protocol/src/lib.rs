// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generic authenticated-subject protocol substrate for Xenia.
//!
//! This crate defines no application authorization policy and performs no
//! cryptographic verification. It freezes the language-neutral identities and
//! transcripts required to authenticate an exact 32-byte application subject.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonical authentication-suite registry shared with Xenia proof protocols.
pub const AUTHENTICATION_SUITE_REGISTRY_V1: &[u8] =
    b"XENIA:AuthenticationSuiteRegistry:v1\n1=ed25519\n2=ml-dsa-65-fips204\n";
/// SHA-256 of [`AUTHENTICATION_SUITE_REGISTRY_V1`].
pub const AUTHENTICATION_SUITE_REGISTRY_V1_SHA256: [u8; 32] = [
    0x02, 0x55, 0xc2, 0xb3, 0x07, 0x0e, 0x57, 0x9d, 0x52, 0xe4, 0x1a, 0xb6, 0xa9, 0xd7, 0x67, 0xd1,
    0x70, 0x0b, 0x61, 0xfd, 0x68, 0x78, 0x7b, 0xba, 0xe7, 0x8b, 0xd4, 0x1a, 0xa8, 0x68, 0x94, 0x5f,
];

/// Domain separator for generic signer-key identifiers.
pub const SIGNER_KEY_ID_DOMAIN: &[u8] = b"XENIA:AuthenticationSignerKeyId:v1";
/// Domain separator for suite/key-bound authentication of one application subject.
pub const AUTHENTICATED_SUBJECT_DOMAIN: &[u8] = b"XENIA:AuthenticatedSubject:v1";

pub const MAX_CONTEXT_COMPONENT_BYTES_V1: usize = 64;
pub const MAX_PUBLIC_KEY_BYTES_V1: usize = 4096;
pub const MAX_SIGNATURE_BYTES_V1: usize = 4096;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthenticationProtocolError {
    #[error("{component} cannot be empty")]
    EmptyContextComponent { component: &'static str },
    #[error("{component} exceeds {limit} bytes")]
    ContextComponentTooLong {
        component: &'static str,
        limit: usize,
    },
    #[error("{component} contains a non-canonical character")]
    InvalidContextComponent { component: &'static str },
    #[error("authentication context version must be greater than zero")]
    InvalidContextVersion,
    #[error("authentication-suite identifier 0 is reserved")]
    ReservedAuthenticationSuite,
    #[error("signer public key cannot be empty")]
    EmptySignerPublicKey,
    #[error("signer public key exceeds {limit} bytes")]
    SignerPublicKeyTooLong { limit: usize },
    #[error("subject digest cannot be all zero")]
    ZeroSubjectDigest,
    #[error("signer key id cannot be all zero")]
    ZeroSignerKeyId,
    #[error("authentication signature cannot be empty")]
    EmptySignature,
    #[error("authentication signature exceeds {limit} bytes")]
    SignatureTooLong { limit: usize },
    #[error("canonical length cannot be represented as u64")]
    LengthOverflow,
}

/// Stable authentication-suite identifier. Concrete implementations live in `xenia-auth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct AuthenticationSuiteId(u16);

impl AuthenticationSuiteId {
    pub const ED25519: Self = Self(1);
    pub const ML_DSA_65_FIPS204: Self = Self(2);

    pub const fn from_wire_id(value: u16) -> Result<Self, AuthenticationProtocolError> {
        if value == 0 {
            Err(AuthenticationProtocolError::ReservedAuthenticationSuite)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn wire_id(self) -> u16 {
        self.0
    }

    pub const fn canonical_name(self) -> Option<&'static str> {
        match self.0 {
            1 => Some("ed25519"),
            2 => Some("ml-dsa-65-fips204"),
            _ => None,
        }
    }
}

impl TryFrom<u16> for AuthenticationSuiteId {
    type Error = AuthenticationProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_wire_id(value)
    }
}

impl From<AuthenticationSuiteId> for u16 {
    fn from(value: AuthenticationSuiteId) -> Self {
        value.wire_id()
    }
}

/// Application-owned namespace for an authenticated subject.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationContextId {
    ecosystem: String,
    application: String,
    purpose: String,
    version: u32,
}

impl AuthenticationContextId {
    pub fn try_new(
        ecosystem: impl Into<String>,
        application: impl Into<String>,
        purpose: impl Into<String>,
        version: u32,
    ) -> Result<Self, AuthenticationProtocolError> {
        let value = Self {
            ecosystem: ecosystem.into(),
            application: application.into(),
            purpose: purpose.into(),
            version,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn ecosystem(&self) -> &str {
        &self.ecosystem
    }

    pub fn application(&self) -> &str {
        &self.application
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub const fn version(&self) -> u32 {
        self.version
    }

    pub fn canonical_text(&self) -> String {
        format!(
            "{}:{}:{}:v{}",
            self.ecosystem, self.application, self.purpose, self.version
        )
    }

    pub fn validate(&self) -> Result<(), AuthenticationProtocolError> {
        validate_context_component(&self.ecosystem, "ecosystem")?;
        validate_context_component(&self.application, "application")?;
        validate_context_component(&self.purpose, "purpose")?;
        if self.version == 0 {
            return Err(AuthenticationProtocolError::InvalidContextVersion);
        }
        Ok(())
    }
}

fn validate_context_component(
    value: &str,
    component: &'static str,
) -> Result<(), AuthenticationProtocolError> {
    if value.is_empty() {
        return Err(AuthenticationProtocolError::EmptyContextComponent { component });
    }
    if value.len() > MAX_CONTEXT_COMPONENT_BYTES_V1 {
        return Err(AuthenticationProtocolError::ContextComponentTooLong {
            component,
            limit: MAX_CONTEXT_COMPONENT_BYTES_V1,
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AuthenticationProtocolError::InvalidContextComponent { component });
    }
    Ok(())
}

/// One detached authentication entry for an already-canonical application subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectAuthentication {
    pub suite: AuthenticationSuiteId,
    pub signer_key_id: [u8; 32],
    pub signature: Vec<u8>,
}

impl SubjectAuthentication {
    pub fn validate(&self) -> Result<(), AuthenticationProtocolError> {
        if self.signer_key_id == [0; 32] {
            return Err(AuthenticationProtocolError::ZeroSignerKeyId);
        }
        if self.signature.is_empty() {
            return Err(AuthenticationProtocolError::EmptySignature);
        }
        if self.signature.len() > MAX_SIGNATURE_BYTES_V1 {
            return Err(AuthenticationProtocolError::SignatureTooLong {
                limit: MAX_SIGNATURE_BYTES_V1,
            });
        }
        Ok(())
    }
}

/// Cryptographic verifier interface for one exact suite/key identity.
pub trait SubjectAuthenticationVerifier {
    fn suite(&self) -> AuthenticationSuiteId;
    fn signer_key_id(&self) -> [u8; 32];
    fn verify(&self, digest: &[u8; 32], signature: &[u8]) -> bool;
}

/// Derive the generic signer-key identifier for one suite and public key.
pub fn signer_key_id(
    suite: AuthenticationSuiteId,
    public_key_bytes: &[u8],
) -> Result<[u8; 32], AuthenticationProtocolError> {
    if public_key_bytes.is_empty() {
        return Err(AuthenticationProtocolError::EmptySignerPublicKey);
    }
    if public_key_bytes.len() > MAX_PUBLIC_KEY_BYTES_V1 {
        return Err(AuthenticationProtocolError::SignerPublicKeyTooLong {
            limit: MAX_PUBLIC_KEY_BYTES_V1,
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_KEY_ID_DOMAIN);
    hasher.update(suite.wire_id().to_le_bytes());
    append_hash_len_prefixed(&mut hasher, public_key_bytes)?;
    Ok(hasher.finalize().into())
}

/// Derive the suite/key-bound authentication digest for one exact application subject.
///
/// Two different suites authenticating the same subject intentionally sign different
/// final digests because the suite and signer identity are part of the transcript.
pub fn authenticated_subject_digest(
    context: &AuthenticationContextId,
    subject_digest: &[u8; 32],
    suite: AuthenticationSuiteId,
    signer_key_id: &[u8; 32],
) -> Result<[u8; 32], AuthenticationProtocolError> {
    context.validate()?;
    if subject_digest == &[0; 32] {
        return Err(AuthenticationProtocolError::ZeroSubjectDigest);
    }
    if signer_key_id == &[0; 32] {
        return Err(AuthenticationProtocolError::ZeroSignerKeyId);
    }

    let mut hasher = Sha256::new();
    hasher.update(AUTHENTICATED_SUBJECT_DOMAIN);
    append_context_id(&mut hasher, context)?;
    hasher.update(subject_digest);
    hasher.update(suite.wire_id().to_le_bytes());
    hasher.update(signer_key_id);
    Ok(hasher.finalize().into())
}

fn append_context_id(
    hasher: &mut Sha256,
    context: &AuthenticationContextId,
) -> Result<(), AuthenticationProtocolError> {
    append_hash_len_prefixed(hasher, context.ecosystem.as_bytes())?;
    append_hash_len_prefixed(hasher, context.application.as_bytes())?;
    append_hash_len_prefixed(hasher, context.purpose.as_bytes())?;
    hasher.update(context.version.to_le_bytes());
    Ok(())
}

fn append_hash_len_prefixed(
    hasher: &mut Sha256,
    value: &[u8],
) -> Result<(), AuthenticationProtocolError> {
    let len =
        u64::try_from(value.len()).map_err(|_| AuthenticationProtocolError::LengthOverflow)?;
    hasher.update(len.to_le_bytes());
    hasher.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ED25519_PUBLIC_KEY: [u8; 32] = [
        0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab,
        0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06, 0x98, 0x81,
        0xdb, 0x12,
    ];
    const GOLDEN_ED25519_SIGNER_KEY_ID: [u8; 32] = [
        0x3c, 0x0e, 0x8b, 0xd0, 0x16, 0x25, 0x3b, 0xfe, 0xd7, 0x34, 0xee, 0x6a, 0x24, 0xd4, 0xb4,
        0xa4, 0x7c, 0x2e, 0x15, 0x46, 0xbc, 0x04, 0xfa, 0x00, 0x2b, 0x43, 0x22, 0x9a, 0xd2, 0x95,
        0xe0, 0x55,
    ];
    const GOLDEN_ED25519_AUTH_DIGEST: [u8; 32] = [
        0xc4, 0x57, 0xf5, 0xb2, 0xea, 0xc8, 0x15, 0xa0, 0xf7, 0x6d, 0x0e, 0x04, 0x66, 0x15, 0x37,
        0xa1, 0x9c, 0x60, 0x39, 0xb5, 0x49, 0x9a, 0x56, 0xab, 0x80, 0xcb, 0xdb, 0x25, 0x74, 0x30,
        0x11, 0x4b,
    ];

    fn context() -> AuthenticationContextId {
        AuthenticationContextId::try_new("MYCELIX", "PublicElection", "VerifierReceipt", 1).unwrap()
    }

    #[test]
    fn registry_and_suite_ids_are_frozen() {
        assert_eq!(AuthenticationSuiteId::ED25519.wire_id(), 1);
        assert_eq!(AuthenticationSuiteId::ML_DSA_65_FIPS204.wire_id(), 2);
        assert_eq!(
            Sha256::digest(AUTHENTICATION_SUITE_REGISTRY_V1).as_slice(),
            AUTHENTICATION_SUITE_REGISTRY_V1_SHA256
        );
    }

    #[test]
    fn context_components_are_canonical() {
        assert_eq!(
            context().canonical_text(),
            "MYCELIX:PublicElection:VerifierReceipt:v1"
        );
        assert!(AuthenticationContextId::try_new("MYCELIX", "bad:app", "Receipt", 1).is_err());
        assert!(AuthenticationContextId::try_new("MYCELIX", "App", "Receipt", 0).is_err());
    }

    #[test]
    fn signer_key_id_matches_language_neutral_vector() {
        assert_eq!(
            signer_key_id(AuthenticationSuiteId::ED25519, &SAMPLE_ED25519_PUBLIC_KEY).unwrap(),
            GOLDEN_ED25519_SIGNER_KEY_ID
        );
    }

    #[test]
    fn authenticated_subject_digest_matches_language_neutral_vector() {
        assert_eq!(
            authenticated_subject_digest(
                &context(),
                &[0xA5; 32],
                AuthenticationSuiteId::ED25519,
                &GOLDEN_ED25519_SIGNER_KEY_ID,
            )
            .unwrap(),
            GOLDEN_ED25519_AUTH_DIGEST
        );
    }

    #[test]
    fn authentication_digest_binds_context_subject_suite_and_signer() {
        let baseline = authenticated_subject_digest(
            &context(),
            &[0xA5; 32],
            AuthenticationSuiteId::ED25519,
            &GOLDEN_ED25519_SIGNER_KEY_ID,
        )
        .unwrap();

        let changed_context =
            AuthenticationContextId::try_new("MYCELIX", "PublicElection", "OtherReceipt", 1)
                .unwrap();
        assert_ne!(
            baseline,
            authenticated_subject_digest(
                &changed_context,
                &[0xA5; 32],
                AuthenticationSuiteId::ED25519,
                &GOLDEN_ED25519_SIGNER_KEY_ID,
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            authenticated_subject_digest(
                &context(),
                &[0xA6; 32],
                AuthenticationSuiteId::ED25519,
                &GOLDEN_ED25519_SIGNER_KEY_ID,
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            authenticated_subject_digest(
                &context(),
                &[0xA5; 32],
                AuthenticationSuiteId::ML_DSA_65_FIPS204,
                &GOLDEN_ED25519_SIGNER_KEY_ID,
            )
            .unwrap()
        );
        let mut other_key = GOLDEN_ED25519_SIGNER_KEY_ID;
        other_key[0] ^= 1;
        assert_ne!(
            baseline,
            authenticated_subject_digest(
                &context(),
                &[0xA5; 32],
                AuthenticationSuiteId::ED25519,
                &other_key,
            )
            .unwrap()
        );
    }

    #[test]
    fn zero_and_oversized_inputs_fail_closed() {
        assert_eq!(
            authenticated_subject_digest(
                &context(),
                &[0; 32],
                AuthenticationSuiteId::ED25519,
                &GOLDEN_ED25519_SIGNER_KEY_ID,
            ),
            Err(AuthenticationProtocolError::ZeroSubjectDigest)
        );
        assert_eq!(
            signer_key_id(AuthenticationSuiteId::ED25519, &[]),
            Err(AuthenticationProtocolError::EmptySignerPublicKey)
        );
        assert!(matches!(
            signer_key_id(
                AuthenticationSuiteId::ED25519,
                &vec![0u8; MAX_PUBLIC_KEY_BYTES_V1 + 1]
            ),
            Err(AuthenticationProtocolError::SignerPublicKeyTooLong { .. })
        ));
    }

    #[test]
    fn detached_authentication_entry_is_bounded() {
        let valid = SubjectAuthentication {
            suite: AuthenticationSuiteId::ED25519,
            signer_key_id: GOLDEN_ED25519_SIGNER_KEY_ID,
            signature: vec![0x11; 64],
        };
        assert_eq!(valid.validate(), Ok(()));

        let oversized = SubjectAuthentication {
            signature: vec![0x22; MAX_SIGNATURE_BYTES_V1 + 1],
            ..valid
        };
        assert!(matches!(
            oversized.validate(),
            Err(AuthenticationProtocolError::SignatureTooLong { .. })
        ));
    }
}
