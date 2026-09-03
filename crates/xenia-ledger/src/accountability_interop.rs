// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Provider-neutral adapter metadata for exporting Xenia accountability evidence.
//!
//! The Mycelix receipt layer should treat an attestation reference as an opaque
//! locator/claim. This module is the Xenia-side verifier that turns such a claim
//! into cryptographically checked execution evidence and then exports only stable
//! commitment metadata back to the higher layer.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    AccountabilityBindingError, AccountabilityExecutionAttestation, AccountabilityExecutionBinding,
    EvidenceCryptoManifest, EvidenceSignatureBackend, SignatureSuite,
    accountability_execution_binding_digest,
};

/// Domain separator for stable verifier-key identifiers exported to higher layers.
const ACCOUNTABILITY_VERIFIER_KEY_DOMAIN: &[u8] = b"xenia:accountability-verifier-key:v1";

/// Domain separator for the opaque operation nonce shared with a computation
/// proof provider such as Symthaea.
const ACCOUNTABILITY_OPERATION_NONCE_DOMAIN: &[u8] = b"xenia:sif-computation-operation-nonce:v1";

impl AccountabilityExecutionBinding {
    /// Derive the opaque 32-byte operation nonce that a computation proof MUST
    /// bind when it claims to belong to this authenticated Xenia execution.
    ///
    /// This closes a subtle cross-provider gap: the Mycelix receipt statement
    /// proves common semantics, while this nonce additionally ties Symthaea's
    /// computation proof to Xenia's concrete live operation/session. The nonce
    /// contains no citizen or case identifier.
    pub fn sif_computation_operation_nonce(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ACCOUNTABILITY_OPERATION_NONCE_DOMAIN);
        hasher.update(&[0]);
        hasher.update(self.operation_id.as_bytes());
        hasher.update(self.session.session_id.as_bytes());
        hasher.update(&self.receipt_digest);
        hasher.update(&self.query_digest);
        *hasher.finalize().as_bytes()
    }
}

/// Expected higher-layer commitments for one accountability execution.
///
/// `operation_id` and `session_id` are optional because some semantic receipt
/// schemas intentionally do not embed transport/session identifiers. Callers that
/// possess those identifiers SHOULD supply them; when supplied they are checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountabilityExecutionExpectation {
    /// Exact pre-attestation receipt statement that Xenia must have signed.
    pub statement_digest: [u8; 32],
    /// Authenticated Xenia requester/source identifier committed by Mycelix.
    pub requester_source_id: [u8; 32],
    /// Exact query commitment.
    pub query_digest: [u8; 32],
    /// Exact purpose/scope commitment.
    pub purpose_digest: [u8; 32],
    /// Exact policy commitment.
    pub policy_digest: [u8; 32],
    /// Minimum-necessary result commitment, if a result exists.
    pub result_digest: Option<[u8; 32]>,
    /// Optional logical operation ID from the live execution context.
    pub operation_id: Option<Uuid>,
    /// Optional authenticated session ID from the live execution context.
    pub session_id: Option<Uuid>,
}

/// Stable proof-reference metadata produced only after successful verification.
///
/// `statement_digest` is deliberately the higher-layer pre-attestation receipt
/// commitment, not Xenia's binding digest. This lets Xenia, Symthaea and external
/// witnesses all prove the same public statement while retaining distinct proof IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccountabilityExecutionRef {
    /// Stable namespaced proof scheme including the actual signature suite.
    pub scheme: String,
    /// Exact higher-layer receipt statement proved by the attestation.
    pub statement_digest: [u8; 32],
    /// Xenia-specific proof identifier (digest of the signed execution binding).
    pub proof_digest: [u8; 32],
    /// Stable digest of the actual verifier public key and signature suite.
    pub verifier_key_id: [u8; 32],
    /// Stable verifier profile suitable for an opaque higher-layer reference.
    pub verifier_profile: String,
}

/// Verify a Xenia execution attestation and require that every higher-layer
/// commitment matches the expected accountability receipt/execution context.
///
/// This is intentionally stricter than signature verification alone: a perfectly
/// valid signature over the wrong receipt, query, requester, policy, result, or
/// supplied live session/operation is rejected.
pub fn verify_accountability_execution_for_expectation(
    attestation: &AccountabilityExecutionAttestation,
    expectation: &AccountabilityExecutionExpectation,
    manifest: EvidenceCryptoManifest,
    backend: &impl EvidenceSignatureBackend,
    public_key: &[u8],
) -> Result<VerifiedAccountabilityExecutionRef, AccountabilityInteropError> {
    attestation.verify(manifest, backend, public_key)?;

    let binding = &attestation.binding;
    require_equal(
        "receipt statement",
        &binding.receipt_digest,
        &expectation.statement_digest,
    )?;
    require_equal(
        "requester source",
        &binding.requester_source_id,
        &expectation.requester_source_id,
    )?;
    require_equal("query", &binding.query_digest, &expectation.query_digest)?;
    require_equal(
        "purpose",
        &binding.purpose_digest,
        &expectation.purpose_digest,
    )?;
    require_equal("policy", &binding.policy_digest, &expectation.policy_digest)?;
    if binding.result_digest != expectation.result_digest {
        return Err(AccountabilityInteropError::CommitmentMismatch { field: "result" });
    }
    if let Some(operation_id) = expectation.operation_id
        && binding.operation_id != operation_id
    {
        return Err(AccountabilityInteropError::OperationMismatch);
    }
    if let Some(session_id) = expectation.session_id
        && binding.session.session_id != session_id
    {
        return Err(AccountabilityInteropError::SessionMismatch);
    }

    let suite = attestation
        .signature
        .suite()
        .map_err(AccountabilityBindingError::from)?;
    Ok(VerifiedAccountabilityExecutionRef {
        scheme: accountability_execution_scheme(suite),
        statement_digest: expectation.statement_digest,
        proof_digest: accountability_execution_binding_digest(binding),
        verifier_key_id: accountability_verifier_key_id(suite, public_key),
        verifier_profile: format!(
            "xenia-ledger/accountability-execution/v1/{}",
            suite.stable_label()
        ),
    })
}

/// Stable namespaced scheme identifier for a signed Xenia execution attestation.
pub fn accountability_execution_scheme(suite: SignatureSuite) -> String {
    format!(
        "xenia-ledger/accountability-execution/v1/{}",
        suite.stable_label()
    )
}

/// Stable commitment to the exact verifier key and signature suite.
pub fn accountability_verifier_key_id(suite: SignatureSuite, public_key: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACCOUNTABILITY_VERIFIER_KEY_DOMAIN);
    hasher.update(&[0]);
    hasher.update(suite.stable_label().as_bytes());
    hasher.update(&[0]);
    hasher.update(&(public_key.len() as u64).to_be_bytes());
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

fn require_equal(
    field: &'static str,
    actual: &[u8; 32],
    expected: &[u8; 32],
) -> Result<(), AccountabilityInteropError> {
    if actual != expected {
        return Err(AccountabilityInteropError::CommitmentMismatch { field });
    }
    Ok(())
}

/// Fail-closed cross-layer verification errors.
#[derive(Debug, Error)]
pub enum AccountabilityInteropError {
    /// Xenia attestation/schema/session/signature verification failed.
    #[error(transparent)]
    Binding(#[from] AccountabilityBindingError),
    /// Signed Xenia commitment did not equal the higher-layer expected commitment.
    #[error("accountability execution {field} commitment does not match expectation")]
    CommitmentMismatch {
        /// Mismatched semantic field.
        field: &'static str,
    },
    /// Live operation ID did not match the signed execution binding.
    #[error("accountability execution operation ID does not match live context")]
    OperationMismatch,
    /// Live authenticated session ID did not match the signed execution binding.
    #[error("accountability execution session ID does not match live context")]
    SessionMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ACCOUNTABILITY_COMMITMENT_ALGORITHM, ACCOUNTABILITY_EXECUTION_BINDING_SCHEMA,
        AccountabilityExecutionPhase, SessionTranscriptBinding,
    };

    fn binding(operation: u128, session: u128) -> AccountabilityExecutionBinding {
        AccountabilityExecutionBinding {
            schema: ACCOUNTABILITY_EXECUTION_BINDING_SCHEMA.to_string(),
            commitment_algorithm: ACCOUNTABILITY_COMMITMENT_ALGORITHM.to_string(),
            operation_id: Uuid::from_u128(operation),
            session: SessionTranscriptBinding::from_hash(
                Uuid::from_u128(session),
                [5u8; 32],
                SignatureSuite::Ed25519Rfc8032,
            ),
            requester_source_id: [6u8; 32],
            query_digest: [7u8; 32],
            purpose_digest: [8u8; 32],
            policy_digest: [9u8; 32],
            result_digest: Some([10u8; 32]),
            receipt_digest: [11u8; 32],
            ledger_entry_count: 1,
            ledger_head_hash: [12u8; 32],
            phase: AccountabilityExecutionPhase::PreDisclosureCommit,
        }
    }

    #[test]
    fn scheme_is_signature_suite_specific() {
        let ed = accountability_execution_scheme(SignatureSuite::Ed25519Rfc8032);
        let pq = accountability_execution_scheme(SignatureSuite::MlDsa65Fips204);
        assert_ne!(ed, pq);
        assert!(ed.contains("ed25519-rfc8032"));
        assert!(pq.contains("ml-dsa-65-fips204"));
    }

    #[test]
    fn verifier_key_id_is_domain_and_suite_bound() {
        let key = [7u8; 32];
        let ed = accountability_verifier_key_id(SignatureSuite::Ed25519Rfc8032, &key);
        let pq = accountability_verifier_key_id(SignatureSuite::MlDsa65Fips204, &key);
        assert_ne!(ed, pq);
        assert_ne!(ed, [0u8; 32]);
    }

    #[test]
    fn computation_nonce_is_bound_to_live_operation_and_session() {
        let base = binding(1, 2).sif_computation_operation_nonce();
        let different_operation = binding(3, 2).sif_computation_operation_nonce();
        let different_session = binding(1, 4).sif_computation_operation_nonce();
        assert_ne!(base, different_operation);
        assert_ne!(base, different_session);
        assert_ne!(base, [0u8; 32]);
    }
}
