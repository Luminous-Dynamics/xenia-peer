// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Backend-neutral zero-knowledge proof protocol substrate.
//!
//! This crate deliberately contains **no proving backend and no application
//! statement semantics**. It defines only the identities and canonical bytes
//! required to say exactly what a proof claims to be about.
//!
//! Security boundary:
//! - Xenia defines envelope/version/statement/verifier/parameter identities.
//! - A backend adapter verifies proof bytes against the exact `VerifierId`.
//! - Applications define statement semantics and public-input encodings.
//! - Signature implementations live outside this crate and sign the canonical
//!   authentication digest produced here.
//! - Legacy Mycelix v2 parsing belongs in a separate compatibility adapter. This
//!   crate never auto-detects or silently falls back to a legacy protocol.

pub mod policy;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonical Xenia proof-envelope generation.
pub const PROOF_ENVELOPE_PROTOCOL_VERSION: u32 = 3;
/// Domain separator for the canonical v3 proof body digest.
pub const PROOF_ENVELOPE_BODY_DOMAIN: &[u8] = b"XENIA:ProofEnvelope:Body:v3";
/// Domain separator for a signature/authentication digest over a v3 proof body.
pub const PROOF_ENVELOPE_AUTH_DOMAIN: &[u8] = b"XENIA:ProofEnvelope:Auth:v3";
/// Domain separator used when deriving a verifier/program identity from bytes.
pub const VERIFIER_ID_DOMAIN: &[u8] = b"XENIA:ProofVerifierId:v1";
/// Domain separator used when deriving a parameter-set identity from bytes.
pub const PARAMETER_SET_ID_DOMAIN: &[u8] = b"XENIA:ProofParameterSetId:v1";
/// Domain separator for canonical public-input digests.
pub const PUBLIC_INPUTS_DOMAIN: &[u8] = b"XENIA:ProofPublicInputs:v1";
/// Domain separator for verifier-issued challenge bindings carried in `nonce`.
pub const CHALLENGE_NONCE_DOMAIN: &[u8] = b"XENIA:ProofChallengeNonce:v1";
/// Domain separator for public-key fingerprints used as signer-key identifiers.
pub const SIGNER_KEY_ID_DOMAIN: &[u8] = b"XENIA:ProofSignerKeyId:v1";

const MAX_STATEMENT_COMPONENT_BYTES: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("{component} cannot be empty")]
    EmptyStatementComponent { component: &'static str },
    #[error("{component} exceeds {limit} bytes")]
    StatementComponentTooLong {
        component: &'static str,
        limit: usize,
    },
    #[error("{component} contains a non-canonical character")]
    InvalidStatementComponent { component: &'static str },
    #[error("statement version must be greater than zero")]
    InvalidStatementVersion,
    #[error("identifier value 0 is reserved")]
    ReservedIdentifier,
    #[error("verifier challenge entropy cannot be all zero")]
    ZeroChallengeEntropy,
    #[error("challenge audience cannot be empty")]
    EmptyChallengeAudience,
    #[error("signer public key cannot be empty")]
    EmptySignerPublicKey,
}

/// Backend-neutral statement identity.
///
/// Display form is `{ecosystem}:{application}:{purpose}:v{version}`, while the
/// signed transcript length-prefixes each text component independently.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatementId {
    ecosystem: String,
    application: String,
    purpose: String,
    version: u32,
}

impl StatementId {
    pub fn try_new(
        ecosystem: impl Into<String>,
        application: impl Into<String>,
        purpose: impl Into<String>,
        version: u32,
    ) -> Result<Self, ProtocolError> {
        let statement = Self {
            ecosystem: ecosystem.into(),
            application: application.into(),
            purpose: purpose.into(),
            version,
        };
        statement.validate()?;
        Ok(statement)
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

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_component(&self.ecosystem, "ecosystem")?;
        validate_component(&self.application, "application")?;
        validate_component(&self.purpose, "purpose")?;
        if self.version == 0 {
            return Err(ProtocolError::InvalidStatementVersion);
        }
        Ok(())
    }

    pub fn canonical_text(&self) -> String {
        format!(
            "{}:{}:{}:v{}",
            self.ecosystem, self.application, self.purpose, self.version
        )
    }
}

fn validate_component(value: &str, component: &'static str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::EmptyStatementComponent { component });
    }
    if value.len() > MAX_STATEMENT_COMPONENT_BYTES {
        return Err(ProtocolError::StatementComponentTooLong {
            component,
            limit: MAX_STATEMENT_COMPONENT_BYTES,
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ProtocolError::InvalidStatementComponent { component });
    }
    Ok(())
}

/// Stable proof-system identifier.
///
/// This identifies the proof technology, **not** the circuit/program. Exact
/// verifier identity is carried separately by [`VerifierId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofSystemId(u16);

impl ProofSystemId {
    pub const WINTERFELL: Self = Self(1);
    pub const MIDEN: Self = Self(2);
    pub const RISC0: Self = Self(3);
    pub const BINIUS: Self = Self(4);

    pub const fn from_wire_id(value: u16) -> Result<Self, ProtocolError> {
        if value == 0 {
            Err(ProtocolError::ReservedIdentifier)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn wire_id(self) -> u16 {
        self.0
    }
}

/// Stable authentication-suite identifier. Implementations live outside this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthenticationSuiteId(u16);

impl AuthenticationSuiteId {
    pub const ED25519: Self = Self(1);
    pub const ML_DSA_65_FIPS204: Self = Self(2);

    pub const fn from_wire_id(value: u16) -> Result<Self, ProtocolError> {
        if value == 0 {
            Err(ProtocolError::ReservedIdentifier)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn wire_id(self) -> u16 {
        self.0
    }
}

/// Hash of the exact verifier program/AIR/image expected for this proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifierId(pub [u8; 32]);

impl VerifierId {
    pub fn derive(proof_system: ProofSystemId, verifier_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(VERIFIER_ID_DOMAIN);
        hasher.update(proof_system.wire_id().to_le_bytes());
        append_hash_len_prefixed(&mut hasher, verifier_bytes);
        Self(hasher.finalize().into())
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

/// Hash of the exact proving/verifying parameter set expected for this proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParameterSetId(pub [u8; 32]);

impl ParameterSetId {
    pub fn derive(parameter_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PARAMETER_SET_ID_DOMAIN);
        append_hash_len_prefixed(&mut hasher, parameter_bytes);
        Self(hasher.finalize().into())
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

/// Authentication over the canonical v3 proof body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAuthentication {
    pub suite: AuthenticationSuiteId,
    /// Hash/fingerprint of the verifying key selected by the surrounding trust policy.
    pub signer_key_id: [u8; 32],
    pub signature: Vec<u8>,
}

/// Canonical v3 proof envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEnvelopeV3 {
    pub protocol_version: u32,
    pub statement: StatementId,
    pub proof_system: ProofSystemId,
    pub verifier_id: VerifierId,
    pub parameter_set_id: ParameterSetId,
    pub timestamp_unix_seconds: u64,
    /// Verifier-issued challenge binding. New protocols should derive this with
    /// [`derive_challenge_nonce`] so audience/session context is replay-bound.
    pub nonce: [u8; 32],
    /// Digest of canonical statement public inputs. New protocols should derive
    /// this with [`public_inputs_digest`].
    pub public_inputs_hash: [u8; 32],
    pub proof: Vec<u8>,
    /// Digest of typed authenticated extension claims. Use [`empty_extensions_digest`]
    /// when no extensions exist instead of inventing application fields here.
    pub extensions_digest: [u8; 32],
    pub authentication: Vec<ProofAuthentication>,
}

impl ProofEnvelopeV3 {
    /// Create a v3 envelope body with no authentication entries yet.
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        statement: StatementId,
        proof_system: ProofSystemId,
        verifier_id: VerifierId,
        parameter_set_id: ParameterSetId,
        timestamp_unix_seconds: u64,
        nonce: [u8; 32],
        public_inputs_hash: [u8; 32],
        proof: Vec<u8>,
        extensions_digest: [u8; 32],
    ) -> Self {
        Self {
            protocol_version: PROOF_ENVELOPE_PROTOCOL_VERSION,
            statement,
            proof_system,
            verifier_id,
            parameter_set_id,
            timestamp_unix_seconds,
            nonce,
            public_inputs_hash,
            proof,
            extensions_digest,
            authentication: Vec::new(),
        }
    }

    /// SHA-256 of the canonical v3 proof body transcript.
    ///
    /// Authentication entries are intentionally excluded; every signer signs the
    /// same body and gets a suite/key-specific authentication digest below.
    pub fn body_digest(&self) -> Result<[u8; 32], ProtocolError> {
        self.statement.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(PROOF_ENVELOPE_BODY_DOMAIN);
        hasher.update(self.protocol_version.to_le_bytes());
        append_statement_id(&mut hasher, &self.statement);
        hasher.update(self.proof_system.wire_id().to_le_bytes());
        hasher.update(self.verifier_id.0);
        hasher.update(self.parameter_set_id.0);
        hasher.update(self.timestamp_unix_seconds.to_le_bytes());
        hasher.update(self.nonce);
        hasher.update(self.public_inputs_hash);
        hasher.update(Sha256::digest(&self.proof));
        hasher.update(self.extensions_digest);
        Ok(hasher.finalize().into())
    }

    /// Digest that one authentication entry signs.
    ///
    /// Binding the suite and signer key identifier prevents an otherwise valid
    /// signature from being relabeled as another authentication method or signer.
    pub fn authentication_digest(
        &self,
        suite: AuthenticationSuiteId,
        signer_key_id: &[u8; 32],
    ) -> Result<[u8; 32], ProtocolError> {
        let body = self.body_digest()?;
        let mut hasher = Sha256::new();
        hasher.update(PROOF_ENVELOPE_AUTH_DOMAIN);
        hasher.update(body);
        hasher.update(suite.wire_id().to_le_bytes());
        hasher.update(signer_key_id);
        Ok(hasher.finalize().into())
    }
}

/// Canonical digest of public inputs for a statement.
///
/// The protocol does not define application serialization; callers must provide
/// the statement's canonical public-input bytes. Binding the statement identity
/// here prevents the same byte encoding from being silently reused as another
/// statement's public inputs.
pub fn public_inputs_digest(
    statement: &StatementId,
    canonical_public_inputs: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    statement.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_INPUTS_DOMAIN);
    append_statement_id(&mut hasher, statement);
    append_hash_len_prefixed(&mut hasher, canonical_public_inputs);
    Ok(hasher.finalize().into())
}

/// Derive the 32-byte verifier challenge binding carried in `ProofEnvelopeV3::nonce`.
///
/// `verifier_random` must be fresh unpredictable verifier-provided entropy.
/// `audience` identifies the relying party/service and `session_context` binds
/// any additional channel/session/purpose data chosen by that relying party.
pub fn derive_challenge_nonce(
    statement: &StatementId,
    audience: &[u8],
    session_context: &[u8],
    verifier_random: &[u8; 32],
) -> Result<[u8; 32], ProtocolError> {
    statement.validate()?;
    if audience.is_empty() {
        return Err(ProtocolError::EmptyChallengeAudience);
    }
    if verifier_random == &[0; 32] {
        return Err(ProtocolError::ZeroChallengeEntropy);
    }

    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_NONCE_DOMAIN);
    append_statement_id(&mut hasher, statement);
    append_hash_len_prefixed(&mut hasher, audience);
    append_hash_len_prefixed(&mut hasher, session_context);
    hasher.update(verifier_random);
    Ok(hasher.finalize().into())
}

/// Derive the canonical key identifier used by `ProofAuthentication`.
pub fn signer_key_id(
    suite: AuthenticationSuiteId,
    public_key_bytes: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    if public_key_bytes.is_empty() {
        return Err(ProtocolError::EmptySignerPublicKey);
    }
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_KEY_ID_DOMAIN);
    hasher.update(suite.wire_id().to_le_bytes());
    append_hash_len_prefixed(&mut hasher, public_key_bytes);
    Ok(hasher.finalize().into())
}

/// Canonical digest representing an empty set of extension claims.
pub fn empty_extensions_digest() -> [u8; 32] {
    Sha256::digest(b"XENIA:ProofEnvelope:Extensions:Empty:v1").into()
}

fn append_statement_id(hasher: &mut Sha256, statement: &StatementId) {
    append_hash_len_prefixed(hasher, statement.ecosystem.as_bytes());
    append_hash_len_prefixed(hasher, statement.application.as_bytes());
    append_hash_len_prefixed(hasher, statement.purpose.as_bytes());
    hasher.update(statement.version.to_le_bytes());
}

fn append_hash_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> ProofEnvelopeV3 {
        ProofEnvelopeV3::new_unsigned(
            StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1).unwrap(),
            ProofSystemId::MIDEN,
            VerifierId([0x11; 32]),
            ParameterSetId([0x22; 32]),
            1_800_000_000,
            [0x33; 32],
            [0x44; 32],
            vec![0x55, 0x66, 0x77],
            [0x88; 32],
        )
    }

    #[test]
    fn statement_components_are_canonical() {
        assert!(StatementId::try_new("XENIA", "Device", "Enrollment", 1).is_ok());
        assert!(StatementId::try_new("XENIA", "bad:component", "Enrollment", 1).is_err());
        assert!(StatementId::try_new("XENIA", "Device", "Enrollment", 0).is_err());
    }

    #[test]
    fn body_digest_binds_security_relevant_fields() {
        let envelope = sample_envelope();
        let baseline = envelope.body_digest().unwrap();

        let mut changed = envelope.clone();
        changed.public_inputs_hash[0] ^= 1;
        assert_ne!(baseline, changed.body_digest().unwrap());

        let mut changed = envelope.clone();
        changed.verifier_id.0[0] ^= 1;
        assert_ne!(baseline, changed.body_digest().unwrap());

        let mut changed = envelope.clone();
        changed.parameter_set_id.0[0] ^= 1;
        assert_ne!(baseline, changed.body_digest().unwrap());

        let mut changed = envelope.clone();
        changed.proof.push(0x99);
        assert_ne!(baseline, changed.body_digest().unwrap());

        let mut changed = envelope;
        changed.extensions_digest[0] ^= 1;
        assert_ne!(baseline, changed.body_digest().unwrap());
    }

    #[test]
    fn public_inputs_digest_is_statement_bound() {
        let a = StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1).unwrap();
        let b = StatementId::try_new("XENIA", "Access", "DeviceEnrollment", 1).unwrap();
        let bytes = b"canonical-public-inputs";
        assert_ne!(
            public_inputs_digest(&a, bytes).unwrap(),
            public_inputs_digest(&b, bytes).unwrap()
        );
    }

    #[test]
    fn challenge_nonce_binds_audience_session_and_statement() {
        let statement = StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1).unwrap();
        let entropy = [0xA5; 32];
        let baseline = derive_challenge_nonce(&statement, b"service-a", b"session-1", &entropy).unwrap();
        assert_ne!(
            baseline,
            derive_challenge_nonce(&statement, b"service-b", b"session-1", &entropy).unwrap()
        );
        assert_ne!(
            baseline,
            derive_challenge_nonce(&statement, b"service-a", b"session-2", &entropy).unwrap()
        );
        let other = StatementId::try_new("XENIA", "Access", "DeviceEnrollment", 1).unwrap();
        assert_ne!(
            baseline,
            derive_challenge_nonce(&other, b"service-a", b"session-1", &entropy).unwrap()
        );
        assert_eq!(
            derive_challenge_nonce(&statement, b"service-a", b"session-1", &[0; 32]),
            Err(ProtocolError::ZeroChallengeEntropy)
        );
    }

    #[test]
    fn signer_key_id_binds_suite_and_public_key() {
        let key = [0x42; 32];
        let ml = signer_key_id(AuthenticationSuiteId::ML_DSA_65_FIPS204, &key).unwrap();
        let ed = signer_key_id(AuthenticationSuiteId::ED25519, &key).unwrap();
        assert_ne!(ml, ed);
        assert_ne!(
            ml,
            signer_key_id(AuthenticationSuiteId::ML_DSA_65_FIPS204, &[0x43; 32]).unwrap()
        );
    }

    #[test]
    fn v3_golden_body_and_authentication_digests_are_stable() {
        let envelope = sample_envelope();
        let body = envelope.body_digest().unwrap();
        assert_eq!(
            hex_lower(&body),
            "7472f4d0abf4d2c22cbfe7f95d66738fa377f3fb0d1b197b43a0f79cf0756230"
        );

        let auth = envelope
            .authentication_digest(AuthenticationSuiteId::ML_DSA_65_FIPS204, &[0xA1; 32])
            .unwrap();
        assert_eq!(
            hex_lower(&auth),
            "4622614d73d684cffa98eccc087a526ec1b943349d4253a4b0b50f53f8cfec9d"
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn authentication_digest_binds_suite_and_signer() {
        let envelope = sample_envelope();
        let key_a = [0xA1; 32];
        let key_b = [0xB2; 32];
        let a = envelope
            .authentication_digest(AuthenticationSuiteId::ML_DSA_65_FIPS204, &key_a)
            .unwrap();
        let b = envelope
            .authentication_digest(AuthenticationSuiteId::ED25519, &key_a)
            .unwrap();
        let c = envelope
            .authentication_digest(AuthenticationSuiteId::ML_DSA_65_FIPS204, &key_b)
            .unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
