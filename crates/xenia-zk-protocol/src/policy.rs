// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fail-closed structural and local-policy validation for proof envelopes.
//!
//! Passing this validator is **not** proof verification and is **not** signature
//! verification. It means only that the v3 envelope is structurally acceptable
//! to a caller-supplied policy before expensive cryptography is attempted.

use std::collections::HashSet;

use thiserror::Error;

use crate::{
    AuthenticationSuiteId, PROOF_ENVELOPE_PROTOCOL_VERSION, ProofEnvelopeV3, ProofSystemId,
    ProtocolError,
};

pub const DEFAULT_MAX_PROOF_BYTES: usize = 512 * 1024;
pub const DEFAULT_MAX_SIGNATURE_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_AUTHENTICATION_ENTRIES: usize = 4;

#[derive(Clone, Debug)]
pub struct EnvelopePolicy {
    pub protocol_version: u32,
    pub max_proof_bytes: usize,
    pub max_signature_bytes: usize,
    pub max_authentication_entries: usize,
    pub max_age_seconds: u64,
    pub max_future_skew_seconds: u64,
    /// Empty means every non-zero proof-system identifier is structurally allowed.
    pub allowed_proof_systems: Vec<ProofSystemId>,
    /// Every listed suite must have at least one distinct authentication entry.
    pub required_authentication_suites: Vec<AuthenticationSuiteId>,
}

impl Default for EnvelopePolicy {
    fn default() -> Self {
        Self {
            protocol_version: PROOF_ENVELOPE_PROTOCOL_VERSION,
            max_proof_bytes: DEFAULT_MAX_PROOF_BYTES,
            max_signature_bytes: DEFAULT_MAX_SIGNATURE_BYTES,
            max_authentication_entries: DEFAULT_MAX_AUTHENTICATION_ENTRIES,
            max_age_seconds: 60 * 60,
            max_future_skew_seconds: 5 * 60,
            allowed_proof_systems: Vec::new(),
            required_authentication_suites: vec![AuthenticationSuiteId::ML_DSA_65_FIPS204],
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EnvelopeValidationError {
    #[error("unsupported proof-envelope protocol version: expected {expected}, got {actual}")]
    ProtocolVersion { expected: u32, actual: u32 },
    #[error("invalid statement identifier: {0}")]
    Statement(ProtocolError),
    #[error("proof payload is empty")]
    EmptyProof,
    #[error("proof payload is too large: {actual} > {limit}")]
    ProofTooLarge { actual: usize, limit: usize },
    #[error("verifier identifier is zero")]
    ZeroVerifierId,
    #[error("parameter-set identifier is zero")]
    ZeroParameterSetId,
    #[error("nonce is zero")]
    ZeroNonce,
    #[error("public-input digest is zero")]
    ZeroPublicInputsHash,
    #[error("proof timestamp is too far in the future")]
    FutureTimestamp,
    #[error("proof timestamp is older than policy allows")]
    ExpiredTimestamp,
    #[error("proof system {0} is not allowed by local policy")]
    ProofSystemNotAllowed(u16),
    #[error("too many authentication entries: {actual} > {limit}")]
    TooManyAuthenticationEntries { actual: usize, limit: usize },
    #[error("authentication entry has a zero signer-key identifier")]
    ZeroSignerKeyId,
    #[error("authentication signature is empty")]
    EmptySignature,
    #[error("authentication signature is too large: {actual} > {limit}")]
    SignatureTooLarge { actual: usize, limit: usize },
    #[error("duplicate authentication entry for suite {suite} and signer")]
    DuplicateAuthentication { suite: u16 },
    #[error("required authentication suite {0} is missing")]
    MissingAuthenticationSuite(u16),
}

/// Validate v3 structure and local acceptance policy without verifying cryptography.
pub fn validate_envelope(
    envelope: &ProofEnvelopeV3,
    policy: &EnvelopePolicy,
    now_unix_seconds: u64,
) -> Result<(), EnvelopeValidationError> {
    if envelope.protocol_version != policy.protocol_version {
        return Err(EnvelopeValidationError::ProtocolVersion {
            expected: policy.protocol_version,
            actual: envelope.protocol_version,
        });
    }

    envelope
        .statement
        .validate()
        .map_err(EnvelopeValidationError::Statement)?;

    if envelope.proof.is_empty() {
        return Err(EnvelopeValidationError::EmptyProof);
    }
    if envelope.proof.len() > policy.max_proof_bytes {
        return Err(EnvelopeValidationError::ProofTooLarge {
            actual: envelope.proof.len(),
            limit: policy.max_proof_bytes,
        });
    }
    if envelope.verifier_id.is_zero() {
        return Err(EnvelopeValidationError::ZeroVerifierId);
    }
    if envelope.parameter_set_id.is_zero() {
        return Err(EnvelopeValidationError::ZeroParameterSetId);
    }
    if envelope.nonce == [0; 32] {
        return Err(EnvelopeValidationError::ZeroNonce);
    }
    if envelope.public_inputs_hash == [0; 32] {
        return Err(EnvelopeValidationError::ZeroPublicInputsHash);
    }

    let latest_allowed = now_unix_seconds.saturating_add(policy.max_future_skew_seconds);
    if envelope.timestamp_unix_seconds > latest_allowed {
        return Err(EnvelopeValidationError::FutureTimestamp);
    }
    let oldest_allowed = now_unix_seconds.saturating_sub(policy.max_age_seconds);
    if envelope.timestamp_unix_seconds < oldest_allowed {
        return Err(EnvelopeValidationError::ExpiredTimestamp);
    }

    if !policy.allowed_proof_systems.is_empty()
        && !policy.allowed_proof_systems.contains(&envelope.proof_system)
    {
        return Err(EnvelopeValidationError::ProofSystemNotAllowed(
            envelope.proof_system.wire_id(),
        ));
    }

    if envelope.authentication.len() > policy.max_authentication_entries {
        return Err(EnvelopeValidationError::TooManyAuthenticationEntries {
            actual: envelope.authentication.len(),
            limit: policy.max_authentication_entries,
        });
    }

    let mut seen = HashSet::new();
    for authentication in &envelope.authentication {
        if authentication.signer_key_id == [0; 32] {
            return Err(EnvelopeValidationError::ZeroSignerKeyId);
        }
        if authentication.signature.is_empty() {
            return Err(EnvelopeValidationError::EmptySignature);
        }
        if authentication.signature.len() > policy.max_signature_bytes {
            return Err(EnvelopeValidationError::SignatureTooLarge {
                actual: authentication.signature.len(),
                limit: policy.max_signature_bytes,
            });
        }

        let identity = (authentication.suite.wire_id(), authentication.signer_key_id);
        if !seen.insert(identity) {
            return Err(EnvelopeValidationError::DuplicateAuthentication {
                suite: authentication.suite.wire_id(),
            });
        }
    }

    for required in &policy.required_authentication_suites {
        if !envelope
            .authentication
            .iter()
            .any(|entry| entry.suite == *required)
        {
            return Err(EnvelopeValidationError::MissingAuthenticationSuite(
                required.wire_id(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ParameterSetId, ProofAuthentication, StatementId, VerifierId, empty_extensions_digest,
    };

    const NOW: u64 = 1_800_000_000;

    fn valid_envelope() -> ProofEnvelopeV3 {
        let mut envelope = ProofEnvelopeV3::new_unsigned(
            StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1).unwrap(),
            ProofSystemId::MIDEN,
            VerifierId([0x11; 32]),
            ParameterSetId([0x22; 32]),
            NOW,
            [0x33; 32],
            [0x44; 32],
            vec![1, 2, 3],
            empty_extensions_digest(),
        );
        envelope.authentication.push(ProofAuthentication {
            suite: AuthenticationSuiteId::ML_DSA_65_FIPS204,
            signer_key_id: [0x55; 32],
            signature: vec![0x66; 128],
        });
        envelope
    }

    #[test]
    fn valid_structure_passes() {
        validate_envelope(&valid_envelope(), &EnvelopePolicy::default(), NOW).unwrap();
    }

    #[test]
    fn version_downgrade_fails_closed() {
        let mut envelope = valid_envelope();
        envelope.protocol_version = 2;
        assert!(matches!(
            validate_envelope(&envelope, &EnvelopePolicy::default(), NOW),
            Err(EnvelopeValidationError::ProtocolVersion { .. })
        ));
    }

    #[test]
    fn required_pq_authentication_cannot_be_silently_removed() {
        let mut envelope = valid_envelope();
        envelope.authentication.clear();
        assert!(matches!(
            validate_envelope(&envelope, &EnvelopePolicy::default(), NOW),
            Err(EnvelopeValidationError::MissingAuthenticationSuite(_))
        ));
    }

    #[test]
    fn duplicate_authentication_is_rejected() {
        let mut envelope = valid_envelope();
        envelope.authentication.push(envelope.authentication[0].clone());
        assert!(matches!(
            validate_envelope(&envelope, &EnvelopePolicy::default(), NOW),
            Err(EnvelopeValidationError::DuplicateAuthentication { .. })
        ));
    }

    #[test]
    fn verifier_and_parameter_identity_are_mandatory() {
        let mut envelope = valid_envelope();
        envelope.verifier_id = VerifierId([0; 32]);
        assert_eq!(
            validate_envelope(&envelope, &EnvelopePolicy::default(), NOW),
            Err(EnvelopeValidationError::ZeroVerifierId)
        );

        let mut envelope = valid_envelope();
        envelope.parameter_set_id = ParameterSetId([0; 32]);
        assert_eq!(
            validate_envelope(&envelope, &EnvelopePolicy::default(), NOW),
            Err(EnvelopeValidationError::ZeroParameterSetId)
        );
    }
}
