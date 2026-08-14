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
    AuthenticationSuiteId, PROOF_ENVELOPE_PROTOCOL_VERSION, ParameterSetId, ProofEnvelopeV3,
    ProofSystemId, ProtocolError, StatementId, VerifierId,
};

pub const DEFAULT_MAX_PROOF_BYTES: usize = 512 * 1024;
pub const DEFAULT_MAX_SIGNATURE_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_AUTHENTICATION_ENTRIES: usize = 4;

/// Exact local verifier binding for a statement.
///
/// The envelope is untrusted input; these values come from local configuration,
/// a compiled statement registry, or another authenticated policy source. A
/// verifier must never accept the envelope's own `verifier_id` or parameter set
/// as authority for what program is allowed to prove a statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVerificationBinding {
    pub statement: StatementId,
    pub proof_system: ProofSystemId,
    pub verifier_id: VerifierId,
    pub parameter_set_id: ParameterSetId,
    /// Verifier-issued challenge/context binding expected for this proof instance.
    pub nonce: [u8; 32],
    /// Digest of the canonical public inputs expected by the relying application.
    pub public_inputs_hash: [u8; 32],
}

/// Authentication trust requirement for an accepted proof envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationRequirement {
    pub suite: AuthenticationSuiteId,
    /// Locally trusted signer-key identifiers for this suite.
    pub trusted_signer_key_ids: Vec<[u8; 32]>,
    /// Number of distinct trusted signers required for this suite.
    pub min_distinct_signers: usize,
}

/// Application acceptance contract for a single proof statement instance.
///
/// Structural validation is intentionally insufficient for authorization. This
/// contract pins the exact verifier and trust roots that the relying application
/// expects before expensive cryptographic verification is attempted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationContract {
    pub binding: ProofVerificationBinding,
    pub authentication: Vec<AuthenticationRequirement>,
}

impl VerificationContract {
    pub fn single_signer(
        binding: ProofVerificationBinding,
        suite: AuthenticationSuiteId,
        signer_key_id: [u8; 32],
    ) -> Self {
        Self {
            binding,
            authentication: vec![AuthenticationRequirement {
                suite,
                trusted_signer_key_ids: vec![signer_key_id],
                min_distinct_signers: 1,
            }],
        }
    }
}

/// Envelope that has passed both structural policy and an exact local
/// [`VerificationContract`]. This still does **not** mean the proof or signatures
/// have been cryptographically verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractValidatedEnvelope<'a> {
    envelope: &'a ProofEnvelopeV3,
}

impl<'a> ContractValidatedEnvelope<'a> {
    pub fn envelope(self) -> &'a ProofEnvelopeV3 {
        self.envelope
    }
}

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
    #[error("proof-system identifier 0 is reserved")]
    ReservedProofSystem,
    #[error("authentication-suite identifier 0 is reserved")]
    ReservedAuthenticationSuite,
    #[error("statement identifier does not match the local verification contract")]
    ContractStatementMismatch,
    #[error("proof system does not match the local verification contract")]
    ContractProofSystemMismatch,
    #[error("verifier/program identifier does not match the local verification contract")]
    ContractVerifierMismatch,
    #[error("parameter-set identifier does not match the local verification contract")]
    ContractParameterSetMismatch,
    #[error("proof challenge/nonce does not match the local verification contract")]
    ContractNonceMismatch,
    #[error("public-input digest does not match the local verification contract")]
    ContractPublicInputsMismatch,
    #[error("authentication contract contains an invalid requirement for suite {suite}")]
    InvalidAuthenticationRequirement { suite: u16 },
    #[error("authentication entry is not trusted by the local verification contract")]
    UntrustedAuthentication,
    #[error("authentication suite {suite} has {actual} trusted signers; {required} required")]
    AuthenticationQuorumNotMet {
        suite: u16,
        required: usize,
        actual: usize,
    },
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
    if envelope.proof_system.wire_id() == 0 {
        return Err(EnvelopeValidationError::ReservedProofSystem);
    }

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
        if authentication.suite.wire_id() == 0 {
            return Err(EnvelopeValidationError::ReservedAuthenticationSuite);
        }
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

/// Validate an envelope against both generic resource policy and an exact local
/// verification contract.
///
/// Passing this function still does not establish cryptographic proof validity or
/// signature validity. It establishes that the untrusted envelope names exactly the
/// statement/verifier/parameters/challenge/public inputs and trusted signer IDs the
/// relying application intended to verify.
pub fn validate_envelope_against_contract<'a>(
    envelope: &'a ProofEnvelopeV3,
    policy: &EnvelopePolicy,
    contract: &VerificationContract,
    now_unix_seconds: u64,
) -> Result<ContractValidatedEnvelope<'a>, EnvelopeValidationError> {
    validate_envelope(envelope, policy, now_unix_seconds)?;

    let expected = &contract.binding;
    if envelope.statement != expected.statement {
        return Err(EnvelopeValidationError::ContractStatementMismatch);
    }
    if envelope.proof_system != expected.proof_system {
        return Err(EnvelopeValidationError::ContractProofSystemMismatch);
    }
    if envelope.verifier_id != expected.verifier_id {
        return Err(EnvelopeValidationError::ContractVerifierMismatch);
    }
    if envelope.parameter_set_id != expected.parameter_set_id {
        return Err(EnvelopeValidationError::ContractParameterSetMismatch);
    }
    if envelope.nonce != expected.nonce {
        return Err(EnvelopeValidationError::ContractNonceMismatch);
    }
    if envelope.public_inputs_hash != expected.public_inputs_hash {
        return Err(EnvelopeValidationError::ContractPublicInputsMismatch);
    }

    let mut trusted_entries = HashSet::new();
    let mut seen_requirement_suites = HashSet::new();
    for requirement in &contract.authentication {
        if !seen_requirement_suites.insert(requirement.suite.wire_id())
            || requirement.suite.wire_id() == 0
            || requirement.min_distinct_signers == 0
            || requirement.trusted_signer_key_ids.len() < requirement.min_distinct_signers
            || requirement
                .trusted_signer_key_ids
                .iter()
                .any(|key_id| *key_id == [0; 32])
        {
            return Err(EnvelopeValidationError::InvalidAuthenticationRequirement {
                suite: requirement.suite.wire_id(),
            });
        }

        let trusted: HashSet<[u8; 32]> =
            requirement.trusted_signer_key_ids.iter().copied().collect();
        let actual: HashSet<[u8; 32]> = envelope
            .authentication
            .iter()
            .filter(|entry| entry.suite == requirement.suite && trusted.contains(&entry.signer_key_id))
            .map(|entry| entry.signer_key_id)
            .collect();
        if actual.len() < requirement.min_distinct_signers {
            return Err(EnvelopeValidationError::AuthenticationQuorumNotMet {
                suite: requirement.suite.wire_id(),
                required: requirement.min_distinct_signers,
                actual: actual.len(),
            });
        }
        for key_id in actual {
            trusted_entries.insert((requirement.suite.wire_id(), key_id));
        }
    }

    // Reject authentication material that is not named by the local contract.
    // Extra self-selected signatures must not be mistaken for additional trust.
    for entry in &envelope.authentication {
        if !trusted_entries.contains(&(entry.suite.wire_id(), entry.signer_key_id)) {
            return Err(EnvelopeValidationError::UntrustedAuthentication);
        }
    }

    Ok(ContractValidatedEnvelope { envelope })
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

    fn valid_contract() -> VerificationContract {
        VerificationContract::single_signer(
            ProofVerificationBinding {
                statement: StatementId::try_new("XENIA", "Access", "CapabilityPossession", 1)
                    .unwrap(),
                proof_system: ProofSystemId::MIDEN,
                verifier_id: VerifierId([0x11; 32]),
                parameter_set_id: ParameterSetId([0x22; 32]),
                nonce: [0x33; 32],
                public_inputs_hash: [0x44; 32],
            },
            AuthenticationSuiteId::ML_DSA_65_FIPS204,
            [0x55; 32],
        )
    }

    #[test]
    fn exact_contract_passes() {
        let envelope = valid_envelope();
        let validated = validate_envelope_against_contract(
            &envelope,
            &EnvelopePolicy::default(),
            &valid_contract(),
            NOW,
        )
        .unwrap();
        assert_eq!(validated.envelope(), &envelope);
    }

    #[test]
    fn self_selected_verifier_is_rejected() {
        let mut envelope = valid_envelope();
        envelope.verifier_id = VerifierId([0x99; 32]);
        assert_eq!(
            validate_envelope_against_contract(
                &envelope,
                &EnvelopePolicy::default(),
                &valid_contract(),
                NOW,
            ),
            Err(EnvelopeValidationError::ContractVerifierMismatch)
        );
    }

    #[test]
    fn statement_relabeling_is_rejected() {
        let mut envelope = valid_envelope();
        envelope.statement = StatementId::try_new("XENIA", "Access", "DifferentClaim", 1).unwrap();
        assert_eq!(
            validate_envelope_against_contract(
                &envelope,
                &EnvelopePolicy::default(),
                &valid_contract(),
                NOW,
            ),
            Err(EnvelopeValidationError::ContractStatementMismatch)
        );
    }

    #[test]
    fn self_selected_signer_is_rejected_even_with_required_suite() {
        let mut envelope = valid_envelope();
        envelope.authentication[0].signer_key_id = [0x99; 32];
        assert!(matches!(
            validate_envelope_against_contract(
                &envelope,
                &EnvelopePolicy::default(),
                &valid_contract(),
                NOW,
            ),
            Err(EnvelopeValidationError::AuthenticationQuorumNotMet { .. })
        ));
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
