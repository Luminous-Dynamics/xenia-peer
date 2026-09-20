// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical evaluation-receipt attestation statements for Xenia.
//!
//! This crate defines application semantics only. It performs no cryptographic
//! signing, no key custody, no receipt verification, and no authorization.
//! The canonical 32-byte statement digest produced here is authenticated through
//! the generic `xenia-auth-protocol` substrate.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use xenia_auth_protocol::{
    AuthenticationContextId, AuthenticationProtocolError, AuthenticationSuiteId,
    authenticated_subject_digest,
};

/// Frozen language-neutral statement profile bytes.
pub const EVALUATION_RECEIPT_STATEMENT_PROFILE_V1: &[u8] =
    include_bytes!("../EVALUATION_RECEIPT_STATEMENT_PROFILE_V1.txt");
/// SHA-256 of [`EVALUATION_RECEIPT_STATEMENT_PROFILE_V1`].
pub const EVALUATION_RECEIPT_STATEMENT_PROFILE_V1_SHA256: [u8; 32] = [
    0x52, 0xa9, 0x39, 0x90, 0x21, 0x4f, 0x56, 0x62, 0xfb, 0x15, 0xde, 0xf4, 0x88, 0xcd, 0xff, 0xf7,
    0xd9, 0xe6, 0x8d, 0x35, 0x11, 0xfc, 0x1c, 0x87, 0x7e, 0xb6, 0x60, 0x37, 0x41, 0x07, 0x6a, 0x8a,
];

/// Domain separator for the canonical evaluation statement subject digest.
pub const EVALUATION_RECEIPT_STATEMENT_DOMAIN_V1: &[u8] = b"XENIA:SymEvalReceiptStatement:v1";
/// Generic authentication context ecosystem component.
pub const EVALUATION_AUTH_ECOSYSTEM_V1: &str = "XENIA";
/// Generic authentication context application component.
pub const EVALUATION_AUTH_APPLICATION_V1: &str = "SymEval";
/// Generic authentication context purpose component.
pub const EVALUATION_AUTH_PURPOSE_V1: &str = "ReceiptAttestation";
/// Generic authentication context version.
pub const EVALUATION_AUTH_CONTEXT_VERSION_V1: u32 = 1;

/// Maximum UTF-8 byte length for an experiment identifier.
pub const MAX_EXPERIMENT_ID_BYTES_V1: usize = 128;
/// Maximum UTF-8 byte length for a schema identifier.
pub const MAX_SCHEMA_ID_BYTES_V1: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvaluationStatementError {
    #[error("{field} cannot be empty")]
    EmptyText { field: &'static str },
    #[error("{field} exceeds {limit} bytes")]
    TextTooLong { field: &'static str, limit: usize },
    #[error("{field} contains a non-canonical character")]
    InvalidTextCharacter { field: &'static str },
    #[error("{field} schema version must be greater than zero")]
    ZeroSchemaVersion { field: &'static str },
    #[error("terminal sequence must be greater than zero")]
    ZeroTerminalSequence,
    #[error("{field} digest cannot be all zero")]
    ZeroDigest { field: &'static str },
    #[error("unsupported assurance profile id {0}")]
    UnsupportedAssuranceProfile(u8),
    #[error("unsupported receipt digest algorithm id {0}")]
    UnsupportedReceiptDigestAlgorithm(u8),
    #[error("canonical length cannot be represented as u64")]
    LengthOverflow,
    #[error("generic authentication protocol rejected the statement: {0}")]
    AuthenticationProtocol(AuthenticationProtocolError),
}

impl From<AuthenticationProtocolError> for EvaluationStatementError {
    fn from(value: AuthenticationProtocolError) -> Self {
        Self::AuthenticationProtocol(value)
    }
}

/// What the attestor claims to have done before authenticating the statement.
///
/// `TypedStatementSigned` authenticates only the typed fields supplied to the
/// attestor. It does **not** imply that receipt bytes were independently
/// verified. `ReceiptVerifiedAndSigned` is reserved for a future qualified
/// attestor path that locally verifies the finalized receipt before signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum EvaluationAssuranceProfileV1 {
    TypedStatementSigned,
    ReceiptVerifiedAndSigned,
}

impl EvaluationAssuranceProfileV1 {
    pub const fn wire_id(self) -> u8 {
        match self {
            Self::TypedStatementSigned => 1,
            Self::ReceiptVerifiedAndSigned => 2,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::TypedStatementSigned => "typed-statement-signed",
            Self::ReceiptVerifiedAndSigned => "receipt-verified-and-signed",
        }
    }
}

impl TryFrom<u8> for EvaluationAssuranceProfileV1 {
    type Error = EvaluationStatementError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TypedStatementSigned),
            2 => Ok(Self::ReceiptVerifiedAndSigned),
            other => Err(EvaluationStatementError::UnsupportedAssuranceProfile(other)),
        }
    }
}

impl From<EvaluationAssuranceProfileV1> for u8 {
    fn from(value: EvaluationAssuranceProfileV1) -> Self {
        value.wire_id()
    }
}

/// Algorithm used for the exact finalized receipt-container digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum ReceiptDigestAlgorithmV1 {
    Sha256,
}

impl ReceiptDigestAlgorithmV1 {
    pub const fn wire_id(self) -> u8 {
        match self {
            Self::Sha256 => 1,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
        }
    }
}

impl TryFrom<u8> for ReceiptDigestAlgorithmV1 {
    type Error = EvaluationStatementError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Sha256),
            other => Err(EvaluationStatementError::UnsupportedReceiptDigestAlgorithm(
                other,
            )),
        }
    }
}

impl From<ReceiptDigestAlgorithmV1> for u8 {
    fn from(value: ReceiptDigestAlgorithmV1) -> Self {
        value.wire_id()
    }
}

/// Untrusted input shape used to construct a validated statement.
///
/// This type is intentionally allowed to represent invalid data. Only
/// [`EvaluationReceiptStatementV1`] is the validated protocol object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReceiptStatementInputV1 {
    pub assurance_profile: EvaluationAssuranceProfileV1,
    pub experiment_id: String,
    pub receipt_container_schema_id: String,
    pub receipt_container_schema_version: u32,
    pub core_event_schema_id: String,
    pub core_event_schema_version: u32,
    pub terminal_sequence: u64,
    pub core_chain_head_digest: [u8; 32],
    pub receipt_digest_algorithm: ReceiptDigestAlgorithmV1,
    pub receipt_container_digest: [u8; 32],
    pub experiment_plan_digest: Option<[u8; 32]>,
    pub capability_manifest_digest: Option<[u8; 32]>,
    pub producer_manifest_digest: [u8; 32],
    pub scorer_subject_digest: [u8; 32],
    pub attestor_delegation_digest: [u8; 32],
}

/// Validated, canonical evaluation-receipt attestation statement.
///
/// Serde is a transport convenience only. JSON/bincode/native layout are not
/// the canonical statement bytes. [`Self::subject_digest`] defines protocol
/// identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvaluationReceiptStatementV1 {
    assurance_profile: EvaluationAssuranceProfileV1,
    experiment_id: String,
    receipt_container_schema_id: String,
    receipt_container_schema_version: u32,
    core_event_schema_id: String,
    core_event_schema_version: u32,
    terminal_sequence: u64,
    core_chain_head_digest: [u8; 32],
    receipt_digest_algorithm: ReceiptDigestAlgorithmV1,
    receipt_container_digest: [u8; 32],
    experiment_plan_digest: Option<[u8; 32]>,
    capability_manifest_digest: Option<[u8; 32]>,
    producer_manifest_digest: [u8; 32],
    scorer_subject_digest: [u8; 32],
    attestor_delegation_digest: [u8; 32],
}

impl EvaluationReceiptStatementV1 {
    /// Validate untrusted input and construct the canonical statement object.
    pub fn try_new(
        input: EvaluationReceiptStatementInputV1,
    ) -> Result<Self, EvaluationStatementError> {
        validate_text(
            &input.experiment_id,
            "experiment_id",
            MAX_EXPERIMENT_ID_BYTES_V1,
        )?;
        validate_text(
            &input.receipt_container_schema_id,
            "receipt_container_schema_id",
            MAX_SCHEMA_ID_BYTES_V1,
        )?;
        validate_text(
            &input.core_event_schema_id,
            "core_event_schema_id",
            MAX_SCHEMA_ID_BYTES_V1,
        )?;
        if input.receipt_container_schema_version == 0 {
            return Err(EvaluationStatementError::ZeroSchemaVersion {
                field: "receipt_container_schema",
            });
        }
        if input.core_event_schema_version == 0 {
            return Err(EvaluationStatementError::ZeroSchemaVersion {
                field: "core_event_schema",
            });
        }
        if input.terminal_sequence == 0 {
            return Err(EvaluationStatementError::ZeroTerminalSequence);
        }
        validate_digest(&input.core_chain_head_digest, "core_chain_head_digest")?;
        validate_digest(&input.receipt_container_digest, "receipt_container_digest")?;
        validate_optional_digest(
            input.experiment_plan_digest.as_ref(),
            "experiment_plan_digest",
        )?;
        validate_optional_digest(
            input.capability_manifest_digest.as_ref(),
            "capability_manifest_digest",
        )?;
        validate_digest(&input.producer_manifest_digest, "producer_manifest_digest")?;
        validate_digest(&input.scorer_subject_digest, "scorer_subject_digest")?;
        validate_digest(
            &input.attestor_delegation_digest,
            "attestor_delegation_digest",
        )?;

        Ok(Self {
            assurance_profile: input.assurance_profile,
            experiment_id: input.experiment_id,
            receipt_container_schema_id: input.receipt_container_schema_id,
            receipt_container_schema_version: input.receipt_container_schema_version,
            core_event_schema_id: input.core_event_schema_id,
            core_event_schema_version: input.core_event_schema_version,
            terminal_sequence: input.terminal_sequence,
            core_chain_head_digest: input.core_chain_head_digest,
            receipt_digest_algorithm: input.receipt_digest_algorithm,
            receipt_container_digest: input.receipt_container_digest,
            experiment_plan_digest: input.experiment_plan_digest,
            capability_manifest_digest: input.capability_manifest_digest,
            producer_manifest_digest: input.producer_manifest_digest,
            scorer_subject_digest: input.scorer_subject_digest,
            attestor_delegation_digest: input.attestor_delegation_digest,
        })
    }

    pub const fn assurance_profile(&self) -> EvaluationAssuranceProfileV1 {
        self.assurance_profile
    }

    pub fn experiment_id(&self) -> &str {
        &self.experiment_id
    }

    pub fn receipt_container_schema_id(&self) -> &str {
        &self.receipt_container_schema_id
    }

    pub const fn receipt_container_schema_version(&self) -> u32 {
        self.receipt_container_schema_version
    }

    pub fn core_event_schema_id(&self) -> &str {
        &self.core_event_schema_id
    }

    pub const fn core_event_schema_version(&self) -> u32 {
        self.core_event_schema_version
    }

    pub const fn terminal_sequence(&self) -> u64 {
        self.terminal_sequence
    }

    pub const fn core_chain_head_digest(&self) -> [u8; 32] {
        self.core_chain_head_digest
    }

    pub const fn receipt_digest_algorithm(&self) -> ReceiptDigestAlgorithmV1 {
        self.receipt_digest_algorithm
    }

    pub const fn receipt_container_digest(&self) -> [u8; 32] {
        self.receipt_container_digest
    }

    pub const fn experiment_plan_digest(&self) -> Option<[u8; 32]> {
        self.experiment_plan_digest
    }

    pub const fn capability_manifest_digest(&self) -> Option<[u8; 32]> {
        self.capability_manifest_digest
    }

    pub const fn producer_manifest_digest(&self) -> [u8; 32] {
        self.producer_manifest_digest
    }

    pub const fn scorer_subject_digest(&self) -> [u8; 32] {
        self.scorer_subject_digest
    }

    pub const fn attestor_delegation_digest(&self) -> [u8; 32] {
        self.attestor_delegation_digest
    }

    /// Derive the canonical 32-byte subject digest for this exact statement.
    pub fn subject_digest(&self) -> Result<[u8; 32], EvaluationStatementError> {
        let mut hasher = Sha256::new();
        hasher.update(EVALUATION_RECEIPT_STATEMENT_DOMAIN_V1);
        hasher.update([self.assurance_profile.wire_id()]);
        append_len_prefixed(&mut hasher, self.experiment_id.as_bytes())?;
        append_len_prefixed(&mut hasher, self.receipt_container_schema_id.as_bytes())?;
        hasher.update(self.receipt_container_schema_version.to_le_bytes());
        append_len_prefixed(&mut hasher, self.core_event_schema_id.as_bytes())?;
        hasher.update(self.core_event_schema_version.to_le_bytes());
        hasher.update(self.terminal_sequence.to_le_bytes());
        hasher.update(self.core_chain_head_digest);
        hasher.update([self.receipt_digest_algorithm.wire_id()]);
        hasher.update(self.receipt_container_digest);
        append_optional_digest(&mut hasher, self.experiment_plan_digest.as_ref());
        append_optional_digest(&mut hasher, self.capability_manifest_digest.as_ref());
        hasher.update(self.producer_manifest_digest);
        hasher.update(self.scorer_subject_digest);
        hasher.update(self.attestor_delegation_digest);
        Ok(hasher.finalize().into())
    }

    /// Derive the generic Xenia authentication digest for one exact suite/key.
    pub fn authentication_digest(
        &self,
        suite: AuthenticationSuiteId,
        signer_key_id: &[u8; 32],
    ) -> Result<[u8; 32], EvaluationStatementError> {
        Ok(authenticated_subject_digest(
            &evaluation_authentication_context_v1()?,
            &self.subject_digest()?,
            suite,
            signer_key_id,
        )?)
    }
}

impl<'de> Deserialize<'de> for EvaluationReceiptStatementV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = EvaluationReceiptStatementInputV1::deserialize(deserializer)?;
        Self::try_new(input).map_err(serde::de::Error::custom)
    }
}

/// Canonical generic-authentication context for evaluation receipt statements.
pub fn evaluation_authentication_context_v1()
-> Result<AuthenticationContextId, EvaluationStatementError> {
    Ok(AuthenticationContextId::try_new(
        EVALUATION_AUTH_ECOSYSTEM_V1,
        EVALUATION_AUTH_APPLICATION_V1,
        EVALUATION_AUTH_PURPOSE_V1,
        EVALUATION_AUTH_CONTEXT_VERSION_V1,
    )?)
}

fn validate_text(
    value: &str,
    field: &'static str,
    limit: usize,
) -> Result<(), EvaluationStatementError> {
    if value.is_empty() {
        return Err(EvaluationStatementError::EmptyText { field });
    }
    if value.len() > limit {
        return Err(EvaluationStatementError::TextTooLong { field, limit });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(EvaluationStatementError::InvalidTextCharacter { field });
    }
    Ok(())
}

fn validate_digest(digest: &[u8; 32], field: &'static str) -> Result<(), EvaluationStatementError> {
    if digest == &[0; 32] {
        Err(EvaluationStatementError::ZeroDigest { field })
    } else {
        Ok(())
    }
}

fn validate_optional_digest(
    digest: Option<&[u8; 32]>,
    field: &'static str,
) -> Result<(), EvaluationStatementError> {
    if let Some(digest) = digest {
        validate_digest(digest, field)?;
    }
    Ok(())
}

fn append_len_prefixed(hasher: &mut Sha256, value: &[u8]) -> Result<(), EvaluationStatementError> {
    let len = u64::try_from(value.len()).map_err(|_| EvaluationStatementError::LengthOverflow)?;
    hasher.update(len.to_le_bytes());
    hasher.update(value);
    Ok(())
}

fn append_optional_digest(hasher: &mut Sha256, digest: Option<&[u8; 32]>) {
    match digest {
        Some(digest) => {
            hasher.update([1]);
            hasher.update(digest);
        }
        None => hasher.update([0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_STATEMENT_DIGEST: [u8; 32] = [
        0x0f, 0x93, 0x2e, 0x35, 0xa7, 0x78, 0x8a, 0x95, 0x59, 0x54, 0x06, 0x83, 0x1c, 0x55, 0x1c,
        0x6b, 0x98, 0x96, 0xd2, 0x7e, 0x81, 0x43, 0x7c, 0xee, 0xbc, 0x07, 0x20, 0xcb, 0xba, 0xce,
        0xc8, 0x42,
    ];
    const GOLDEN_ED25519_AUTH_DIGEST: [u8; 32] = [
        0xc2, 0xcb, 0x01, 0x24, 0xe6, 0xd8, 0x3c, 0x96, 0xa4, 0xad, 0x1e, 0xb9, 0x0a, 0xd6, 0x23,
        0x02, 0x38, 0x66, 0x59, 0x5f, 0xd9, 0xe6, 0x99, 0x2c, 0x88, 0xfd, 0x29, 0x4d, 0xc1, 0x46,
        0x9f, 0x96,
    ];
    const GOLDEN_ML_DSA_65_AUTH_DIGEST: [u8; 32] = [
        0xe6, 0x56, 0x58, 0x31, 0x66, 0x80, 0x32, 0x6f, 0xb8, 0x7b, 0x53, 0x31, 0xa6, 0xa6, 0xc9,
        0xb9, 0x94, 0xb4, 0x9f, 0x77, 0x7b, 0x59, 0x21, 0x85, 0xa1, 0x5d, 0xff, 0x0e, 0xe8, 0xc5,
        0x8f, 0xe6,
    ];

    fn sample_input() -> EvaluationReceiptStatementInputV1 {
        EvaluationReceiptStatementInputV1 {
            assurance_profile: EvaluationAssuranceProfileV1::TypedStatementSigned,
            experiment_id: "SYM-EVAL-001C-RUN-0001".to_string(),
            receipt_container_schema_id: "sym-eval.evidence-receipt.v1".to_string(),
            receipt_container_schema_version: 1,
            core_event_schema_id: "sym-eval.evidence-event.v1".to_string(),
            core_event_schema_version: 1,
            terminal_sequence: 42,
            core_chain_head_digest: [0x11; 32],
            receipt_digest_algorithm: ReceiptDigestAlgorithmV1::Sha256,
            receipt_container_digest: [0x22; 32],
            experiment_plan_digest: Some([0x33; 32]),
            capability_manifest_digest: Some([0x44; 32]),
            producer_manifest_digest: [0x55; 32],
            scorer_subject_digest: [0x66; 32],
            attestor_delegation_digest: [0x77; 32],
        }
    }

    fn sample_statement() -> EvaluationReceiptStatementV1 {
        EvaluationReceiptStatementV1::try_new(sample_input()).unwrap()
    }

    #[test]
    fn frozen_profile_hash_matches_constant() {
        assert_eq!(
            Sha256::digest(EVALUATION_RECEIPT_STATEMENT_PROFILE_V1).as_slice(),
            EVALUATION_RECEIPT_STATEMENT_PROFILE_V1_SHA256
        );
    }

    #[test]
    fn assurance_and_digest_algorithm_ids_are_frozen() {
        assert_eq!(
            EvaluationAssuranceProfileV1::TypedStatementSigned.wire_id(),
            1
        );
        assert_eq!(
            EvaluationAssuranceProfileV1::ReceiptVerifiedAndSigned.wire_id(),
            2
        );
        assert_eq!(ReceiptDigestAlgorithmV1::Sha256.wire_id(), 1);
        assert!(EvaluationAssuranceProfileV1::try_from(0).is_err());
        assert!(ReceiptDigestAlgorithmV1::try_from(2).is_err());
    }

    #[test]
    fn authentication_context_is_frozen() {
        let context = evaluation_authentication_context_v1().unwrap();
        assert_eq!(
            context.canonical_text(),
            "XENIA:SymEval:ReceiptAttestation:v1"
        );
    }

    #[test]
    fn statement_digest_matches_language_neutral_vector() {
        assert_eq!(
            sample_statement().subject_digest().unwrap(),
            GOLDEN_STATEMENT_DIGEST
        );
    }

    #[test]
    fn generic_authentication_handoff_matches_language_neutral_vectors() {
        let statement = sample_statement();
        let signer_key_id = [0x88; 32];
        assert_eq!(
            statement
                .authentication_digest(AuthenticationSuiteId::ED25519, &signer_key_id)
                .unwrap(),
            GOLDEN_ED25519_AUTH_DIGEST
        );
        assert_eq!(
            statement
                .authentication_digest(AuthenticationSuiteId::ML_DSA_65_FIPS204, &signer_key_id,)
                .unwrap(),
            GOLDEN_ML_DSA_65_AUTH_DIGEST
        );
    }

    #[test]
    fn statement_digest_binds_every_semantic_field() {
        let baseline = sample_statement().subject_digest().unwrap();
        let mut mutations = Vec::new();

        let mut input = sample_input();
        input.assurance_profile = EvaluationAssuranceProfileV1::ReceiptVerifiedAndSigned;
        mutations.push(input);

        let mut input = sample_input();
        input.experiment_id.push('X');
        mutations.push(input);

        let mut input = sample_input();
        input.receipt_container_schema_id.push('X');
        mutations.push(input);

        let mut input = sample_input();
        input.receipt_container_schema_version = 2;
        mutations.push(input);

        let mut input = sample_input();
        input.core_event_schema_id.push('X');
        mutations.push(input);

        let mut input = sample_input();
        input.core_event_schema_version = 2;
        mutations.push(input);

        let mut input = sample_input();
        input.terminal_sequence += 1;
        mutations.push(input);

        let mut input = sample_input();
        input.core_chain_head_digest[0] ^= 1;
        mutations.push(input);

        let mut input = sample_input();
        input.receipt_container_digest[0] ^= 1;
        mutations.push(input);

        let mut input = sample_input();
        input.experiment_plan_digest = None;
        mutations.push(input);

        let mut input = sample_input();
        input.capability_manifest_digest = None;
        mutations.push(input);

        let mut input = sample_input();
        input.producer_manifest_digest[0] ^= 1;
        mutations.push(input);

        let mut input = sample_input();
        input.scorer_subject_digest[0] ^= 1;
        mutations.push(input);

        let mut input = sample_input();
        input.attestor_delegation_digest[0] ^= 1;
        mutations.push(input);

        for input in mutations {
            let digest = EvaluationReceiptStatementV1::try_new(input)
                .unwrap()
                .subject_digest()
                .unwrap();
            assert_ne!(digest, baseline);
        }
    }

    #[test]
    fn malformed_statement_input_fails_closed() {
        let mut input = sample_input();
        input.experiment_id.clear();
        assert!(matches!(
            EvaluationReceiptStatementV1::try_new(input),
            Err(EvaluationStatementError::EmptyText {
                field: "experiment_id"
            })
        ));

        let mut input = sample_input();
        input.core_event_schema_id = "bad/schema".to_string();
        assert!(matches!(
            EvaluationReceiptStatementV1::try_new(input),
            Err(EvaluationStatementError::InvalidTextCharacter {
                field: "core_event_schema_id"
            })
        ));

        let mut input = sample_input();
        input.receipt_container_schema_version = 0;
        assert!(matches!(
            EvaluationReceiptStatementV1::try_new(input),
            Err(EvaluationStatementError::ZeroSchemaVersion { .. })
        ));

        let mut input = sample_input();
        input.terminal_sequence = 0;
        assert_eq!(
            EvaluationReceiptStatementV1::try_new(input),
            Err(EvaluationStatementError::ZeroTerminalSequence)
        );

        let mut input = sample_input();
        input.receipt_container_digest = [0; 32];
        assert!(matches!(
            EvaluationReceiptStatementV1::try_new(input),
            Err(EvaluationStatementError::ZeroDigest {
                field: "receipt_container_digest"
            })
        ));

        let mut input = sample_input();
        input.experiment_plan_digest = Some([0; 32]);
        assert!(matches!(
            EvaluationReceiptStatementV1::try_new(input),
            Err(EvaluationStatementError::ZeroDigest {
                field: "experiment_plan_digest"
            })
        ));
    }

    #[test]
    fn deserialization_revalidates_invariants() {
        let valid = sample_statement();
        let mut value = serde_json::to_value(valid).unwrap();
        value["experiment_id"] = serde_json::Value::String(String::new());
        assert!(serde_json::from_value::<EvaluationReceiptStatementV1>(value).is_err());
    }

    #[test]
    fn authentication_digest_binds_suite_and_signer_identity() {
        let statement = sample_statement();
        let first_signer = [0x88; 32];
        let second_signer = [0x89; 32];
        let ed = statement
            .authentication_digest(AuthenticationSuiteId::ED25519, &first_signer)
            .unwrap();
        let ml = statement
            .authentication_digest(AuthenticationSuiteId::ML_DSA_65_FIPS204, &first_signer)
            .unwrap();
        let other_signer = statement
            .authentication_digest(AuthenticationSuiteId::ED25519, &second_signer)
            .unwrap();
        assert_ne!(ed, ml);
        assert_ne!(ed, other_signer);
    }
}
