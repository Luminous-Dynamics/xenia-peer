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
pub mod verification;

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
/// Domain separator for legacy/static canonical public-input digests.
///
/// New challenge-response protocols should use [`public_inputs_digest`], which
/// additionally binds the verifier-issued challenge carried in the envelope.
pub const STATIC_PUBLIC_INPUTS_DOMAIN: &[u8] = b"XENIA:ProofPublicInputs:v1";
/// Domain separator for challenge-bound canonical public-input digests.
pub const PUBLIC_INPUTS_DOMAIN: &[u8] = b"XENIA:ProofPublicInputs:ChallengeBound:v1";
/// Domain separator for verifier-issued challenge bindings carried in `nonce`.
pub const CHALLENGE_NONCE_DOMAIN: &[u8] = b"XENIA:ProofChallengeNonce:v1";
/// Domain separator for public-key fingerprints used as signer-key identifiers.
pub const SIGNER_KEY_ID_DOMAIN: &[u8] = b"XENIA:ProofSignerKeyId:v1";
/// Domain separator for one typed extension value digest.
pub const EXTENSION_VALUE_DOMAIN: &[u8] = b"XENIA:ProofExtensionValue:v1";
/// Domain separator for a canonical non-empty set of extension claims.
pub const EXTENSIONS_SET_DOMAIN: &[u8] = b"XENIA:ProofEnvelope:Extensions:Set:v1";
/// Maximum number of typed extension claims accepted by the canonical helper.
pub const MAX_EXTENSION_CLAIMS: usize = 64;

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
    #[error("proof public inputs require a non-zero verifier challenge")]
    ZeroChallengeNonce,
    #[error("challenge audience cannot be empty")]
    EmptyChallengeAudience,
    #[error("signer public key cannot be empty")]
    EmptySignerPublicKey,
    #[error("extension value digest cannot be all zero")]
    ZeroExtensionValueDigest,
    #[error("duplicate extension claim type {claim_type}")]
    DuplicateExtensionClaim { claim_type: String },
    #[error("too many extension claims: {actual} > {limit}")]
    TooManyExtensionClaims { actual: usize, limit: usize },
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
#[serde(try_from = "u16", into = "u16")]
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

impl TryFrom<u16> for ProofSystemId {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_wire_id(value)
    }
}

impl From<ProofSystemId> for u16 {
    fn from(value: ProofSystemId) -> Self {
        value.wire_id()
    }
}

/// Stable authentication-suite identifier. Implementations live outside this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
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

impl TryFrom<u16> for AuthenticationSuiteId {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_wire_id(value)
    }
}

impl From<AuthenticationSuiteId> for u16 {
    fn from(value: AuthenticationSuiteId) -> Self {
        value.wire_id()
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

/// One application-defined, authenticated extension claim.
///
/// The claim type uses the same canonical namespace grammar as proof statements,
/// while the value is represented only by a domain-separated digest. Keeping the
/// raw extension encoding outside the envelope avoids turning the protocol crate
/// into an application schema registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionClaim {
    claim_type: StatementId,
    value_digest: [u8; 32],
}

impl ExtensionClaim {
    pub fn try_new(
        claim_type: StatementId,
        value_digest: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        claim_type.validate()?;
        if value_digest == [0; 32] {
            return Err(ProtocolError::ZeroExtensionValueDigest);
        }
        Ok(Self {
            claim_type,
            value_digest,
        })
    }

    pub fn claim_type(&self) -> &StatementId {
        &self.claim_type
    }

    pub const fn value_digest(&self) -> [u8; 32] {
        self.value_digest
    }
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
    /// Digest of canonical statement public inputs and the verifier challenge.
    /// New challenge-response protocols should derive this with
    /// [`public_inputs_digest`]. Statements that intentionally permit replay
    /// must opt into [`static_public_inputs_digest`] explicitly.
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

/// Canonical challenge-bound digest of public inputs for a statement.
///
/// The protocol does not define application serialization; callers must provide
/// the statement's canonical public-input bytes. Binding both statement identity
/// and the verifier-issued challenge prevents an otherwise-valid proof from being
/// re-enveloped under a fresh challenge without the backend proving the fresh
/// challenge-bound public-input relation.
pub fn public_inputs_digest(
    statement: &StatementId,
    challenge_nonce: &[u8; 32],
    canonical_public_inputs: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    statement.validate()?;
    if challenge_nonce == &[0; 32] {
        return Err(ProtocolError::ZeroChallengeNonce);
    }
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_INPUTS_DOMAIN);
    append_statement_id(&mut hasher, statement);
    hasher.update(challenge_nonce);
    append_hash_len_prefixed(&mut hasher, canonical_public_inputs);
    Ok(hasher.finalize().into())
}

/// Canonical digest for a statement whose proof is intentionally independent of
/// verifier challenge/freshness.
///
/// This helper is deliberately named `static_*` to make replay tolerance visible
/// at call sites. Do not use it for challenge-response or possession proofs.
pub fn static_public_inputs_digest(
    statement: &StatementId,
    canonical_public_inputs: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    statement.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(STATIC_PUBLIC_INPUTS_DOMAIN);
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

/// Digest the canonical bytes of one typed extension value.
///
/// Binding the claim type here prevents the same application bytes from being
/// relabeled as a different authenticated extension type.
pub fn extension_value_digest(
    claim_type: &StatementId,
    canonical_value: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    claim_type.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(EXTENSION_VALUE_DOMAIN);
    append_statement_id(&mut hasher, claim_type);
    append_hash_len_prefixed(&mut hasher, canonical_value);
    Ok(hasher.finalize().into())
}

/// Canonical digest of a set of typed extension claims.
///
/// Claims are sorted by canonical claim identity before hashing, so callers do
/// not accidentally create different envelope digests solely because map/list
/// iteration order changed. Duplicate claim types are rejected rather than
/// adopting ambiguous "first wins" or "last wins" semantics.
pub fn extensions_digest(claims: &[ExtensionClaim]) -> Result<[u8; 32], ProtocolError> {
    if claims.is_empty() {
        return Ok(empty_extensions_digest());
    }
    if claims.len() > MAX_EXTENSION_CLAIMS {
        return Err(ProtocolError::TooManyExtensionClaims {
            actual: claims.len(),
            limit: MAX_EXTENSION_CLAIMS,
        });
    }

    let mut ordered: Vec<&ExtensionClaim> = claims.iter().collect();
    ordered.sort_by(|left, right| {
        left.claim_type
            .canonical_text()
            .cmp(&right.claim_type.canonical_text())
    });

    for pair in ordered.windows(2) {
        if pair[0].claim_type == pair[1].claim_type {
            return Err(ProtocolError::DuplicateExtensionClaim {
                claim_type: pair[0].claim_type.canonical_text(),
            });
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(EXTENSIONS_SET_DOMAIN);
    hasher.update((ordered.len() as u64).to_le_bytes());
    for claim in ordered {
        append_statement_id(&mut hasher, &claim.claim_type);
        hasher.update(claim.value_digest);
    }
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
        let challenge = [0xA5; 32];
        assert_ne!(
            public_inputs_digest(&a, &challenge, bytes).unwrap(),
            public_inputs_digest(&b, &challenge, bytes).unwrap()
        );
    }

    #[test]
    fn public_inputs_digest_is_challenge_bound() {
        let statement = StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1).unwrap();
        let bytes = b"canonical-public-inputs";
        let first = public_inputs_digest(&statement, &[0xA5; 32], bytes).unwrap();
        let second = public_inputs_digest(&statement, &[0xA6; 32], bytes).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            public_inputs_digest(&statement, &[0; 32], bytes),
            Err(ProtocolError::ZeroChallengeNonce)
        );
    }

    #[test]
    fn static_public_inputs_are_an_explicit_replay_tolerant_opt_in() {
        let statement = StatementId::try_new("XENIA", "Archive", "HistoricalAttestation", 1).unwrap();
        assert_eq!(
            static_public_inputs_digest(&statement, b"canonical-public-inputs").unwrap(),
            static_public_inputs_digest(&statement, b"canonical-public-inputs").unwrap()
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
    fn extension_digest_is_typed_order_independent_and_duplicate_safe() {
        let energy = StatementId::try_new("XENIA", "Evidence", "EnergyMeasurement", 1).unwrap();
        let session = StatementId::try_new("XENIA", "Access", "SessionBinding", 1).unwrap();
        let energy_digest = extension_value_digest(&energy, b"42mJ").unwrap();
        let session_digest = extension_value_digest(&session, b"session-7").unwrap();
        assert_ne!(energy_digest, extension_value_digest(&session, b"42mJ").unwrap());

        let energy_claim = ExtensionClaim::try_new(energy.clone(), energy_digest).unwrap();
        let session_claim = ExtensionClaim::try_new(session, session_digest).unwrap();
        assert_eq!(
            extensions_digest(&[energy_claim.clone(), session_claim.clone()]).unwrap(),
            extensions_digest(&[session_claim, energy_claim.clone()]).unwrap()
        );
        assert!(matches!(
            extensions_digest(&[energy_claim.clone(), energy_claim]),
            Err(ProtocolError::DuplicateExtensionClaim { .. })
        ));
    }

    #[test]
    fn empty_extensions_helper_matches_canonical_set_helper() {
        assert_eq!(extensions_digest(&[]).unwrap(), empty_extensions_digest());
    }

    #[test]
    fn helper_derivations_have_stable_golden_vectors() {
        let statement = StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1).unwrap();
        assert_eq!(
            hex_lower(
                &public_inputs_digest(&statement, &[0xA5; 32], b"canonical-public-inputs")
                    .unwrap()
            ),
            "743950938990948d062f90b83e986d2c27f45904fe6528bf08e09e463498733d"
        );
        assert_eq!(
            hex_lower(&static_public_inputs_digest(&statement, b"canonical-public-inputs").unwrap()),
            "05828844e869d0e7c25090db611a7e8fe4a83d338da053622d21ef67afc7cc66"
        );
        assert_eq!(
            hex_lower(
                &derive_challenge_nonce(&statement, b"service-a", b"session-1", &[0xA5; 32])
                    .unwrap()
            ),
            "b9eee4287767cbf3195678982fa75984356a317390d66f8c58c3d204fe532689"
        );
        assert_eq!(
            hex_lower(
                &signer_key_id(AuthenticationSuiteId::ML_DSA_65_FIPS204, &[0x42; 32]).unwrap()
            ),
            "c58668a376948a0a6688ae3b7457b3e5ca0f4727ffdea6c56a564d2cc202ea75"
        );

        let claim_type = StatementId::try_new("XENIA", "Evidence", "EnergyMeasurement", 1).unwrap();
        let value_digest = extension_value_digest(&claim_type, b"42mJ").unwrap();
        let claim = ExtensionClaim::try_new(claim_type, value_digest).unwrap();
        assert_eq!(
            hex_lower(&extensions_digest(&[claim]).unwrap()),
            "dcb196488f9224473db5ca719a2643bf57f871937eed2e1135b5d4e152e14974"
        );
    }

    #[test]
    fn reserved_wire_identifiers_are_rejected_by_construction() {
        assert_eq!(ProofSystemId::try_from(0), Err(ProtocolError::ReservedIdentifier));
        assert_eq!(
            AuthenticationSuiteId::try_from(0),
            Err(ProtocolError::ReservedIdentifier)
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
