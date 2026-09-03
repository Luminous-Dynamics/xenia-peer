// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Xenia ledger authority binding for bounded external agents.
//!
//! The signed object is intentionally commitment-only. Xenia authenticates the
//! delegating session and ledger frontier without receiving agent plan contents,
//! secrets, or application-specific capability fields.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_agent_authority_proto::{
    AgentCapabilityAuthorizationError, AgentCapabilityAuthorizationV1, AgentCheckpointAnchorV1,
    TranscriptSignatureSuiteV1,
};

use crate::binding::{
    EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM, EvidencePublicKeyBinding,
    EvidencePublicKeyBindingError, SESSION_TRANSCRIPT_BINDING_SCHEMA,
    SESSION_TRANSCRIPT_HASH_ALGORITHM, SessionTranscriptBinding,
    compute_evidence_public_key_fingerprint,
};
use crate::signature::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};
use crate::Chain;

/// Schema label for a Xenia signature over an external bounded-agent capability.
pub const AGENT_CAPABILITY_ATTESTATION_SCHEMA: &str = "xenia-agent-capability-attestation-v1";

/// Xenia-authenticated delegation evidence for one exact capability commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapabilityAttestationV1 {
    /// Stable attestation schema label.
    pub schema: String,
    /// The exact crypto-free authorization statement that was signed.
    pub authorization: AgentCapabilityAuthorizationV1,
    /// Fingerprint of the Xenia ledger authority key that signed this statement.
    pub ledger_public_key_fingerprint: [u8; 32],
    /// Algorithm-tagged signature over `authorization.canonical_message()`.
    pub signature: SignatureEnvelope,
}

impl Chain {
    /// Sign an already-constructed bounded-agent authorization at this chain's
    /// exact current frontier.
    ///
    /// The caller must ensure the corresponding consent/approval frontier is
    /// durably persisted before releasing this attestation for consequential
    /// execution. This method proves cryptographic binding; it does not itself
    /// provide persistence ordering.
    pub fn attest_agent_capability_authorization(
        &self,
        authorization: AgentCapabilityAuthorizationV1,
        session_binding: &SessionTranscriptBinding,
    ) -> Result<AgentCapabilityAttestationV1, AgentCapabilityAttestationError> {
        validate_session_binding(&authorization, session_binding)?;
        authorization.validate()?;
        if self.entry_count() == 0 || self.last_hash() == [0u8; 32] {
            return Err(AgentCapabilityAttestationError::PreGenesisLedger);
        }
        if authorization.ledger_entry_count != self.entry_count()
            || authorization.ledger_head_hash != self.last_hash()
        {
            return Err(AgentCapabilityAttestationError::LedgerFrontierMismatch);
        }

        let message = authorization.canonical_message()?;
        let signature = self.signing_key.sign(&message).to_bytes();
        let public_key = self.signing_key.verifying_key().to_bytes();
        Ok(AgentCapabilityAttestationV1 {
            schema: AGENT_CAPABILITY_ATTESTATION_SCHEMA.to_string(),
            authorization,
            ledger_public_key_fingerprint: compute_evidence_public_key_fingerprint(&public_key),
            signature: SignatureEnvelope::ed25519(signature),
        })
    }
}

/// Verify a Xenia agent-capability attestation and all expected application
/// bindings before the external agent treats it as authenticated authority.
#[allow(clippy::too_many_arguments)]
pub fn verify_agent_capability_attestation(
    attestation: &AgentCapabilityAttestationV1,
    session_binding: &SessionTranscriptBinding,
    public_key_binding: &EvidencePublicKeyBinding,
    signature_backend: &impl EvidenceSignatureBackend,
    now_unix_s: u64,
    expected_capability_digest: [u8; 32],
    expected_executor_workload_digest: [u8; 32],
    expected_authority_epoch: u64,
    expected_prior_checkpoint: Option<AgentCheckpointAnchorV1>,
) -> Result<(), AgentCapabilityAttestationError> {
    if attestation.schema != AGENT_CAPABILITY_ATTESTATION_SCHEMA {
        return Err(AgentCapabilityAttestationError::UnsupportedSchema);
    }
    attestation.authorization.validate()?;
    validate_session_binding(&attestation.authorization, session_binding)?;

    if now_unix_s < attestation.authorization.issued_at_unix_s {
        return Err(AgentCapabilityAttestationError::NotYetValid);
    }
    if now_unix_s > attestation.authorization.expires_at_unix_s {
        return Err(AgentCapabilityAttestationError::Expired);
    }
    if attestation.authorization.capability_digest != expected_capability_digest {
        return Err(AgentCapabilityAttestationError::CapabilityDigestMismatch);
    }
    if attestation.authorization.executor_workload_digest != expected_executor_workload_digest {
        return Err(AgentCapabilityAttestationError::ExecutorWorkloadMismatch);
    }
    if attestation.authorization.authority_epoch != expected_authority_epoch {
        return Err(AgentCapabilityAttestationError::AuthorityEpochMismatch);
    }
    if attestation.authorization.prior_checkpoint != expected_prior_checkpoint {
        return Err(AgentCapabilityAttestationError::CheckpointAnchorMismatch);
    }

    if public_key_binding.fingerprint_algorithm != EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM {
        return Err(AgentCapabilityAttestationError::PublicKeyBinding(
            EvidencePublicKeyBindingError::UnsupportedFingerprintAlgorithm {
                algorithm: public_key_binding.fingerprint_algorithm.clone(),
            },
        ));
    }
    if attestation.ledger_public_key_fingerprint != public_key_binding.public_key_fingerprint {
        return Err(AgentCapabilityAttestationError::SignerFingerprintMismatch);
    }

    let signature_suite = attestation.signature.validate_shape()?;
    public_key_binding
        .validate_against_signature_suite_and_backend(signature_suite, signature_backend)?;
    signature_backend.verify_signature(
        &public_key_binding.public_key,
        &attestation.authorization.canonical_message()?,
        &attestation.signature.signature,
    )?;
    Ok(())
}

fn validate_session_binding(
    authorization: &AgentCapabilityAuthorizationV1,
    binding: &SessionTranscriptBinding,
) -> Result<(), AgentCapabilityAttestationError> {
    if binding.schema != SESSION_TRANSCRIPT_BINDING_SCHEMA
        || binding.transcript_hash_algorithm != SESSION_TRANSCRIPT_HASH_ALGORITHM
        || binding.transcript_hash == [0u8; 32]
    {
        return Err(AgentCapabilityAttestationError::InvalidSessionBinding);
    }
    if authorization.session_id != *binding.session_id.as_bytes()
        || authorization.session_transcript_hash != binding.transcript_hash
    {
        return Err(AgentCapabilityAttestationError::SessionBindingMismatch);
    }
    let expected_suite = map_transcript_suite(binding.transcript_signature)?;
    if authorization.session_signature_suite != expected_suite {
        return Err(AgentCapabilityAttestationError::SessionSignatureSuiteMismatch);
    }
    Ok(())
}

fn map_transcript_suite(
    suite: SignatureSuite,
) -> Result<TranscriptSignatureSuiteV1, AgentCapabilityAttestationError> {
    match suite {
        SignatureSuite::Ed25519Rfc8032 => Ok(TranscriptSignatureSuiteV1::Ed25519Rfc8032),
        SignatureSuite::MlDsa65Fips204 => Ok(TranscriptSignatureSuiteV1::MlDsa65Fips204),
        SignatureSuite::MlDsa87Fips204 => Ok(TranscriptSignatureSuiteV1::MlDsa87Fips204),
        SignatureSuite::SlhDsaFips205 => {
            Err(AgentCapabilityAttestationError::UnsupportedTranscriptSignatureSuite)
        }
    }
}

/// Fail-closed validation/verification errors for agent authority attestations.
#[derive(Debug, Error)]
pub enum AgentCapabilityAttestationError {
    /// Unknown attestation schema.
    #[error("unsupported agent capability attestation schema")]
    UnsupportedSchema,
    /// The crypto-free authorization statement is malformed.
    #[error("invalid authorization statement: {0}")]
    Authorization(#[from] AgentCapabilityAuthorizationError),
    /// A pre-genesis ledger cannot authorize consequential agent actions.
    #[error("agent authority cannot be issued from a pre-genesis ledger")]
    PreGenesisLedger,
    /// Authorization did not bind the chain's exact current frontier.
    #[error("authorization ledger frontier does not match current Xenia chain")]
    LedgerFrontierMismatch,
    /// Session binding structure is malformed.
    #[error("invalid Xenia session transcript binding")]
    InvalidSessionBinding,
    /// Authorization does not bind the expected authenticated Xenia session.
    #[error("authorization session binding mismatch")]
    SessionBindingMismatch,
    /// Session transcript signature suite differs from the authorization.
    #[error("authorization session signature suite mismatch")]
    SessionSignatureSuiteMismatch,
    /// Current protocol has no precise mapping for this transcript suite.
    #[error("unsupported transcript signature suite for agent authorization v1")]
    UnsupportedTranscriptSignatureSuite,
    /// Authorization is not yet valid.
    #[error("agent capability authorization is not yet valid")]
    NotYetValid,
    /// Authorization is expired.
    #[error("agent capability authorization is expired")]
    Expired,
    /// Wrong bounded-agent capability commitment.
    #[error("capability digest mismatch")]
    CapabilityDigestMismatch,
    /// Wrong exact workload/software identity.
    #[error("executor workload digest mismatch")]
    ExecutorWorkloadMismatch,
    /// Wrong authority epoch.
    #[error("authority epoch mismatch")]
    AuthorityEpochMismatch,
    /// Wrong prior runtime anti-rollback anchor.
    #[error("prior checkpoint anchor mismatch")]
    CheckpointAnchorMismatch,
    /// Public-key metadata failed validation.
    #[error("public-key binding invalid: {0}")]
    PublicKeyBinding(#[from] EvidencePublicKeyBindingError),
    /// Attestation names a different signing key fingerprint.
    #[error("attestation signer fingerprint mismatch")]
    SignerFingerprintMismatch,
    /// Signature envelope is malformed.
    #[error("signature envelope invalid: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Cryptographic verification failed.
    #[error("signature verification failed: {0}")]
    SignatureBackend(#[from] EvidenceSignatureBackendError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConsentEventRecord, ConsentKind, Ed25519EvidenceSignatureBackend, SignatureSuite,
    };
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    fn session() -> SessionTranscriptBinding {
        SessionTranscriptBinding::from_hash(
            Uuid::from_bytes([9; 16]),
            [7; 32],
            SignatureSuite::Ed25519Rfc8032,
        )
    }

    fn seeded_chain() -> Chain {
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        chain
            .append(ConsentEventRecord {
                session_id: Uuid::from_bytes([9; 16]),
                consent_request_id: Uuid::from_bytes([4; 16]),
                kind: ConsentKind::Approval,
                source: "operator".into(),
                detail: "bounded-agent authorization".into(),
            })
            .unwrap();
        chain
    }

    fn authorization(chain: &Chain) -> AgentCapabilityAuthorizationV1 {
        AgentCapabilityAuthorizationV1 {
            schema_version: 1,
            authorization_id: [1; 16],
            session_id: [9; 16],
            session_transcript_hash: [7; 32],
            session_signature_suite: TranscriptSignatureSuiteV1::Ed25519Rfc8032,
            capability_digest: [5; 32],
            executor_workload_digest: [6; 32],
            authority_epoch: 11,
            issued_at_unix_s: 100,
            expires_at_unix_s: 160,
            nonce: [8; 16],
            ledger_entry_count: chain.entry_count(),
            ledger_head_hash: chain.last_hash(),
            prior_checkpoint: Some(AgentCheckpointAnchorV1 {
                sequence: 2,
                digest: [10; 32],
            }),
        }
    }

    #[test]
    fn exact_authorization_verifies_and_tampering_fails() {
        let chain = seeded_chain();
        let session = session();
        let authorization = authorization(&chain);
        let attestation = chain
            .attest_agent_capability_authorization(authorization.clone(), &session)
            .unwrap();
        let public_key = chain.signing_key.verifying_key().to_bytes();
        let binding = EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
        let backend = Ed25519EvidenceSignatureBackend;
        verify_agent_capability_attestation(
            &attestation,
            &session,
            &binding,
            &backend,
            120,
            authorization.capability_digest,
            authorization.executor_workload_digest,
            authorization.authority_epoch,
            authorization.prior_checkpoint,
        )
        .unwrap();

        let mut tampered = attestation.clone();
        tampered.authorization.capability_digest[0] ^= 1;
        assert!(verify_agent_capability_attestation(
            &tampered,
            &session,
            &binding,
            &backend,
            120,
            authorization.capability_digest,
            authorization.executor_workload_digest,
            authorization.authority_epoch,
            authorization.prior_checkpoint,
        )
        .is_err());
    }

    #[test]
    fn stale_frontier_cannot_be_signed() {
        let chain = seeded_chain();
        let session = session();
        let mut authorization = authorization(&chain);
        authorization.ledger_head_hash[0] ^= 1;
        assert!(matches!(
            chain.attest_agent_capability_authorization(authorization, &session),
            Err(AgentCapabilityAttestationError::LedgerFrontierMismatch)
        ));
    }
}
