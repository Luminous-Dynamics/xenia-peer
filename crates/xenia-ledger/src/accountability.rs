// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cryptographic execution bindings for reciprocal-accountability receipts.
//!
//! This module is intentionally domain-agnostic. It never receives a citizen
//! identifier, case number, query text, or disclosed record. Instead it binds
//! commitments produced by a higher policy layer (for example Mycelix) to the
//! authenticated Xenia session transcript and the current signed-ledger
//! frontier.
//!
//! The resulting attestation is designed to be created *before* protected
//! output is released. It proves that the signer committed to the query,
//! purpose, policy, result (when one exists), and accountability receipt while
//! operating inside a particular authenticated session and against a specific
//! append-only ledger frontier. Strong real-time ordering still requires the
//! attestation/receipt commitment to be durably persisted or externally
//! witnessed before disclosure; a signature alone cannot prove when a signer
//! actually emitted it.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "pqc-signatures")]
use ml_dsa::{MlDsa65, MlDsa87, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey};

use crate::binding::SessionTranscriptBinding;
use crate::chain::Chain;
use crate::entry::TranscriptBindingError;
use crate::policy::EvidenceCryptoManifest;
use crate::signature::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema label for reciprocal-accountability execution bindings.
pub const ACCOUNTABILITY_EXECUTION_BINDING_SCHEMA: &str =
    "xenia-accountability-execution-binding-v1";

/// Stable schema label for signed accountability execution attestations.
pub const ACCOUNTABILITY_EXECUTION_ATTESTATION_SCHEMA: &str =
    "xenia-accountability-execution-attestation-v1";

/// Hash algorithm used for all fixed-size commitments in this binding.
pub const ACCOUNTABILITY_COMMITMENT_ALGORITHM: &str = "blake3-256";

/// Domain separator for the signed canonical binding message.
const ACCOUNTABILITY_EXECUTION_DOMAIN: &[u8] = b"xenia:accountability-execution:v1";

/// Domain separator for the digest exported to higher layers as an attestation
/// statement commitment.
const ACCOUNTABILITY_BINDING_DIGEST_DOMAIN: &[u8] =
    b"xenia:accountability-binding-digest:v1";

/// Phase represented by an execution binding.
///
/// v1 intentionally exposes only a pre-disclosure commitment. If post-release
/// evidence is needed later, it should use a distinct variant/schema rather than
/// weakening the meaning of this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountabilityExecutionPhase {
    /// Receipt/result commitments have been formed and signed, but the caller
    /// asserts protected output has not yet been released.
    PreDisclosureCommit,
}

/// Commitment-only binding between a reciprocal-accountability receipt and an
/// authenticated Xenia execution context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilityExecutionBinding {
    /// Stable schema label.
    pub schema: String,
    /// Hash algorithm used for all fixed-size commitment fields.
    pub commitment_algorithm: String,
    /// Unique identifier for this logical lookup/action.
    pub operation_id: Uuid,
    /// Authenticated session transcript to which the execution belongs.
    pub session: SessionTranscriptBinding,
    /// Opaque 32-byte requester/operator principal fingerprint. Construction
    /// requires this to match the most recent resident signed-ledger event.
    pub requester_source_id: [u8; 32],
    /// Commitment to the canonical lookup/predicate.
    pub query_digest: [u8; 32],
    /// Commitment to the purpose/scope authorization.
    pub purpose_digest: [u8; 32],
    /// Commitment to the exact policy/version evaluated for this lookup.
    pub policy_digest: [u8; 32],
    /// Commitment to the minimum-necessary result, when a result exists.
    /// Denied/no-disclosure operations may leave this absent.
    pub result_digest: Option<[u8; 32]>,
    /// Commitment to the canonical pre-attestation accountability receipt.
    pub receipt_digest: [u8; 32],
    /// Number of authenticated ledger entries at the execution anchor.
    pub ledger_entry_count: u64,
    /// Signed ledger head at the execution anchor.
    pub ledger_head_hash: [u8; 32],
    /// Commitment phase. v1 only permits `PreDisclosureCommit`.
    pub phase: AccountabilityExecutionPhase,
}

impl AccountabilityExecutionBinding {
    /// Build a pre-disclosure binding anchored to the current Xenia ledger
    /// frontier.
    ///
    /// The most recent resident ledger event must belong to the same Xenia
    /// session and requester source ID. This prevents a caller from taking a
    /// valid session transcript or unrelated ledger frontier and claiming that
    /// it authenticated a different principal's lookup.
    #[allow(clippy::too_many_arguments)]
    pub fn at_chain_frontier(
        chain: &Chain,
        session: SessionTranscriptBinding,
        operation_id: Uuid,
        requester_source_id: [u8; 32],
        query_digest: [u8; 32],
        purpose_digest: [u8; 32],
        policy_digest: [u8; 32],
        result_digest: Option<[u8; 32]>,
        receipt_digest: [u8; 32],
    ) -> Result<Self, AccountabilityBindingError> {
        let anchor = chain
            .iter()
            .last()
            .ok_or(AccountabilityBindingError::MissingResidentAuthorizationAnchor)?;
        if anchor.event.session_id != session.session_id {
            return Err(AccountabilityBindingError::LedgerSessionMismatch {
                ledger_session_id: anchor.event.session_id,
                binding_session_id: session.session_id,
            });
        }
        if anchor.event.source_id != requester_source_id {
            return Err(AccountabilityBindingError::RequesterSourceMismatch);
        }

        let binding = Self {
            schema: ACCOUNTABILITY_EXECUTION_BINDING_SCHEMA.to_string(),
            commitment_algorithm: ACCOUNTABILITY_COMMITMENT_ALGORITHM.to_string(),
            operation_id,
            session,
            requester_source_id,
            query_digest,
            purpose_digest,
            policy_digest,
            result_digest,
            receipt_digest,
            ledger_entry_count: chain.entry_count(),
            ledger_head_hash: chain.last_hash(),
            phase: AccountabilityExecutionPhase::PreDisclosureCommit,
        };
        binding.validate_shape()?;
        Ok(binding)
    }

    /// Validate schema and commitment shape independent of a crypto manifest.
    pub fn validate_shape(&self) -> Result<(), AccountabilityBindingError> {
        if self.schema != ACCOUNTABILITY_EXECUTION_BINDING_SCHEMA {
            return Err(AccountabilityBindingError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.commitment_algorithm != ACCOUNTABILITY_COMMITMENT_ALGORITHM {
            return Err(AccountabilityBindingError::UnsupportedCommitmentAlgorithm {
                algorithm: self.commitment_algorithm.clone(),
            });
        }
        if self.operation_id.is_nil() {
            return Err(AccountabilityBindingError::NilOperationId);
        }
        require_nonzero("requester_source_id", &self.requester_source_id)?;
        require_nonzero("query_digest", &self.query_digest)?;
        require_nonzero("purpose_digest", &self.purpose_digest)?;
        require_nonzero("policy_digest", &self.policy_digest)?;
        require_nonzero("receipt_digest", &self.receipt_digest)?;
        if let Some(result_digest) = &self.result_digest {
            require_nonzero("result_digest", result_digest)?;
        }
        if self.ledger_entry_count == 0 || self.ledger_head_hash == [0u8; 32] {
            return Err(AccountabilityBindingError::EmptyLedgerAnchor);
        }
        Ok(())
    }

    /// Validate this execution binding against the evidence crypto manifest,
    /// including its nested authenticated-session transcript binding.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<(), AccountabilityBindingError> {
        self.validate_shape()?;
        self.session.validate_against_manifest(manifest)?;
        Ok(())
    }
}

/// Signed proof that an Xenia evidence authority committed to an accountability
/// binding at a particular ledger/session frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilityExecutionAttestation {
    /// Stable schema label.
    pub schema: String,
    /// Binding whose canonical message is signed.
    pub binding: AccountabilityExecutionBinding,
    /// Algorithm-tagged signature over [`accountability_execution_message`].
    pub signature: SignatureEnvelope,
}

impl AccountabilityExecutionAttestation {
    /// Validate the attestation shape and algorithm against a manifest.
    pub fn validate_against_manifest(
        &self,
        manifest: EvidenceCryptoManifest,
    ) -> Result<SignatureSuite, AccountabilityBindingError> {
        if self.schema != ACCOUNTABILITY_EXECUTION_ATTESTATION_SCHEMA {
            return Err(AccountabilityBindingError::UnsupportedAttestationSchema {
                schema: self.schema.clone(),
            });
        }
        self.binding.validate_against_manifest(manifest)?;
        let suite = self.signature.validate_shape()?;
        if suite != manifest.ledger_signature {
            return Err(AccountabilityBindingError::SignatureSuiteManifestMismatch {
                manifest_suite: manifest.ledger_signature,
                attestation_suite: suite,
            });
        }
        Ok(suite)
    }

    /// Verify the attestation cryptographically using an evidence-signature
    /// backend and the corresponding public key.
    pub fn verify(
        &self,
        manifest: EvidenceCryptoManifest,
        backend: &impl EvidenceSignatureBackend,
        public_key: &[u8],
    ) -> Result<(), AccountabilityBindingError> {
        let suite = self.validate_against_manifest(manifest)?;
        if suite != backend.suite() {
            return Err(AccountabilityBindingError::SignatureSuiteBackendMismatch {
                attestation_suite: suite,
                backend_suite: backend.suite(),
            });
        }
        backend.verify_signature(
            public_key,
            &accountability_execution_message(&self.binding),
            &self.signature.signature,
        )?;
        Ok(())
    }
}

/// Produce the canonical domain-separated bytes signed by an accountability
/// execution attestation.
///
/// This avoids a serializer dependency for the signature preimage: every field
/// is fixed-width or explicitly tagged, and the schema/domain are embedded.
pub fn accountability_execution_message(binding: &AccountabilityExecutionBinding) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + 16 + (8 * 32) + 64);
    message.extend_from_slice(ACCOUNTABILITY_EXECUTION_DOMAIN);
    message.push(0);
    message.extend_from_slice(ACCOUNTABILITY_EXECUTION_BINDING_SCHEMA.as_bytes());
    message.push(0);
    message.extend_from_slice(ACCOUNTABILITY_COMMITMENT_ALGORITHM.as_bytes());
    message.push(0);
    message.extend_from_slice(binding.operation_id.as_bytes());
    message.extend_from_slice(binding.session.session_id.as_bytes());
    message.extend_from_slice(&binding.session.transcript_hash);
    message.extend_from_slice(&binding.requester_source_id);
    message.extend_from_slice(&binding.query_digest);
    message.extend_from_slice(&binding.purpose_digest);
    message.extend_from_slice(&binding.policy_digest);
    match binding.result_digest {
        Some(digest) => {
            message.push(1);
            message.extend_from_slice(&digest);
        }
        None => message.push(0),
    }
    message.extend_from_slice(&binding.receipt_digest);
    message.extend_from_slice(&binding.ledger_entry_count.to_be_bytes());
    message.extend_from_slice(&binding.ledger_head_hash);
    message.push(match binding.phase {
        AccountabilityExecutionPhase::PreDisclosureCommit => 1,
    });
    message
}

/// Compute the statement commitment exported to Mycelix/Symthaea as an
/// `AttestationRef.statement_digest` equivalent.
pub fn accountability_execution_binding_digest(
    binding: &AccountabilityExecutionBinding,
) -> [u8; 32] {
    let message = accountability_execution_message(binding);
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACCOUNTABILITY_BINDING_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&message);
    *hasher.finalize().as_bytes()
}

/// Sign a binding with the current classical ledger authority.
pub fn sign_accountability_execution_ed25519(
    binding: AccountabilityExecutionBinding,
    signing_key: &SigningKey,
) -> AccountabilityExecutionAttestation {
    let signature = signing_key
        .sign(&accountability_execution_message(&binding))
        .to_bytes();
    AccountabilityExecutionAttestation {
        schema: ACCOUNTABILITY_EXECUTION_ATTESTATION_SCHEMA.to_string(),
        binding,
        signature: SignatureEnvelope::ed25519(signature),
    }
}

/// Sign a binding with ML-DSA-65 for a full-PQC evidence profile.
#[cfg(feature = "pqc-signatures")]
pub fn sign_accountability_execution_ml_dsa_65(
    binding: AccountabilityExecutionBinding,
    signing_key: &MlDsaSigningKey<MlDsa65>,
) -> AccountabilityExecutionAttestation {
    let signature = signing_key
        .sign(&accountability_execution_message(&binding))
        .encode();
    let signature_bytes: &[u8] = signature.as_ref();
    AccountabilityExecutionAttestation {
        schema: ACCOUNTABILITY_EXECUTION_ATTESTATION_SCHEMA.to_string(),
        binding,
        signature: SignatureEnvelope::new(
            SignatureSuite::MlDsa65Fips204,
            signature_bytes.to_vec(),
        ),
    }
}

/// Sign a binding with ML-DSA-87 for a high-sensitivity full-PQC profile.
#[cfg(feature = "pqc-signatures")]
pub fn sign_accountability_execution_ml_dsa_87(
    binding: AccountabilityExecutionBinding,
    signing_key: &MlDsaSigningKey<MlDsa87>,
) -> AccountabilityExecutionAttestation {
    let signature = signing_key
        .sign(&accountability_execution_message(&binding))
        .encode();
    let signature_bytes: &[u8] = signature.as_ref();
    AccountabilityExecutionAttestation {
        schema: ACCOUNTABILITY_EXECUTION_ATTESTATION_SCHEMA.to_string(),
        binding,
        signature: SignatureEnvelope::new(
            SignatureSuite::MlDsa87Fips204,
            signature_bytes.to_vec(),
        ),
    }
}

/// Convenience method using a chain's current Ed25519 ledger authority. This
/// deliberately does not append another consent event: the attestation is a
/// separate, commitment-only artifact that can be persisted beside the receipt
/// and ledger evidence without changing the existing ledger-entry schema.
impl Chain {
    /// Build and sign a pre-disclosure accountability binding at this chain's
    /// current authenticated frontier.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_accountability_execution(
        &self,
        session: SessionTranscriptBinding,
        operation_id: Uuid,
        requester_source_id: [u8; 32],
        query_digest: [u8; 32],
        purpose_digest: [u8; 32],
        policy_digest: [u8; 32],
        result_digest: Option<[u8; 32]>,
        receipt_digest: [u8; 32],
    ) -> Result<AccountabilityExecutionAttestation, AccountabilityBindingError> {
        let binding = AccountabilityExecutionBinding::at_chain_frontier(
            self,
            session,
            operation_id,
            requester_source_id,
            query_digest,
            purpose_digest,
            policy_digest,
            result_digest,
            receipt_digest,
        )?;
        Ok(sign_accountability_execution_ed25519(
            binding,
            &self.signing_key,
        ))
    }
}

fn require_nonzero(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), AccountabilityBindingError> {
    if *digest == [0u8; 32] {
        return Err(AccountabilityBindingError::ZeroCommitment { field });
    }
    Ok(())
}

/// Fail-closed validation/verification errors for accountability execution
/// bindings.
#[derive(Debug, Error)]
pub enum AccountabilityBindingError {
    /// Binding schema is not supported.
    #[error("unsupported accountability execution binding schema: {schema}")]
    UnsupportedSchema {
        /// Schema found in the artifact.
        schema: String,
    },
    /// Attestation schema is not supported.
    #[error("unsupported accountability execution attestation schema: {schema}")]
    UnsupportedAttestationSchema {
        /// Schema found in the artifact.
        schema: String,
    },
    /// Commitment hash algorithm is not supported.
    #[error("unsupported accountability commitment algorithm: {algorithm}")]
    UnsupportedCommitmentAlgorithm {
        /// Algorithm found in the artifact.
        algorithm: String,
    },
    /// Operation UUID was nil.
    #[error("accountability operation id must not be nil")]
    NilOperationId,
    /// A commitment used an all-zero placeholder.
    #[error("accountability commitment {field} must not be all-zero")]
    ZeroCommitment {
        /// Field containing the zero commitment.
        field: &'static str,
    },
    /// No resident signed authorization event exists to bind requester/session.
    #[error("accountability execution requires a resident signed authorization anchor")]
    MissingResidentAuthorizationAnchor,
    /// Ledger/session anchor and supplied transcript refer to different sessions.
    #[error(
        "ledger authorization session {ledger_session_id} does not match accountability binding session {binding_session_id}"
    )]
    LedgerSessionMismatch {
        /// Session UUID on the latest resident ledger event.
        ledger_session_id: Uuid,
        /// Session UUID in the supplied transcript binding.
        binding_session_id: Uuid,
    },
    /// Supplied semantic requester does not match the signed ledger principal.
    #[error("accountability requester source id does not match signed ledger authorization principal")]
    RequesterSourceMismatch,
    /// Ledger anchor is structurally empty.
    #[error("accountability execution requires a non-empty signed ledger frontier")]
    EmptyLedgerAnchor,
    /// Nested session-transcript binding failed validation.
    #[error("session transcript binding rejected accountability artifact: {0}")]
    TranscriptBinding(#[from] TranscriptBindingError),
    /// Signature envelope was malformed.
    #[error("accountability signature envelope rejected artifact: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Attestation signature suite disagreed with the evidence manifest.
    #[error(
        "manifest ledger signature {manifest_suite:?} does not match accountability attestation {attestation_suite:?}"
    )]
    SignatureSuiteManifestMismatch {
        /// Suite required by manifest.
        manifest_suite: SignatureSuite,
        /// Suite carried by attestation.
        attestation_suite: SignatureSuite,
    },
    /// Verification backend does not implement the attestation signature suite.
    #[error(
        "accountability attestation suite {attestation_suite:?} does not match verifier backend {backend_suite:?}"
    )]
    SignatureSuiteBackendMismatch {
        /// Suite carried by attestation.
        attestation_suite: SignatureSuite,
        /// Suite implemented by backend.
        backend_suite: SignatureSuite,
    },
    /// Cryptographic verification failed.
    #[error("accountability execution signature verification failed: {0}")]
    SignatureVerification(#[from] EvidenceSignatureBackendError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CURRENT_EVIDENCE_CRYPTO_MANIFEST, ConsentEventRecord, ConsentKind,
        Ed25519EvidenceSignatureBackend,
    };
    use ed25519_dalek::SigningKey;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn transcript_binding(session_id: Uuid) -> SessionTranscriptBinding {
        SessionTranscriptBinding::new(
            session_id,
            b"authenticated xenia session transcript",
            CURRENT_EVIDENCE_CRYPTO_MANIFEST.transcript_signature,
        )
    }

    fn seeded_chain(session_id: Uuid, key: SigningKey) -> Chain {
        let mut chain = Chain::new(key);
        chain
            .append(ConsentEventRecord {
                source_id: [9u8; 32],
                session_id,
                request_id: Uuid::from_u128(2),
                kind: ConsentKind::Approval,
                scope: "purpose-bound lookup authorization".into(),
            })
            .expect("seed ledger authorization");
        chain
    }

    fn attestation() -> (AccountabilityExecutionAttestation, SigningKey) {
        let key = signing_key();
        let session_id = Uuid::from_u128(1);
        let chain = seeded_chain(session_id, key.clone());
        let attestation = chain
            .attest_accountability_execution(
                transcript_binding(session_id),
                Uuid::from_u128(3),
                [9u8; 32],
                [10u8; 32],
                [11u8; 32],
                [12u8; 32],
                Some([13u8; 32]),
                [14u8; 32],
            )
            .expect("valid accountability attestation");
        (attestation, key)
    }

    #[test]
    fn execution_binding_is_session_requester_and_ledger_anchored() {
        let (attestation, _) = attestation();
        assert_eq!(attestation.binding.ledger_entry_count, 1);
        assert_ne!(attestation.binding.ledger_head_hash, [0u8; 32]);
        assert_eq!(attestation.binding.requester_source_id, [9u8; 32]);
        assert_eq!(
            attestation.binding.phase,
            AccountabilityExecutionPhase::PreDisclosureCommit
        );
    }

    #[test]
    fn attestation_verifies_under_manifest_and_ledger_key() {
        let (attestation, key) = attestation();
        attestation
            .verify(
                CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                &Ed25519EvidenceSignatureBackend,
                key.verifying_key().as_bytes(),
            )
            .expect("signature verifies");
    }

    #[test]
    fn tampered_receipt_commitment_breaks_signature() {
        let (mut attestation, key) = attestation();
        attestation.binding.receipt_digest = [99u8; 32];
        assert!(
            attestation
                .verify(
                    CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                    &Ed25519EvidenceSignatureBackend,
                    key.verifying_key().as_bytes(),
                )
                .is_err()
        );
    }

    #[test]
    fn wrong_authenticated_session_is_rejected_after_tampering() {
        let (mut attestation, key) = attestation();
        attestation.binding.session.session_id = Uuid::from_u128(99);
        assert!(
            attestation
                .verify(
                    CURRENT_EVIDENCE_CRYPTO_MANIFEST,
                    &Ed25519EvidenceSignatureBackend,
                    key.verifying_key().as_bytes(),
                )
                .is_err()
        );
    }

    #[test]
    fn construction_rejects_session_not_matching_signed_ledger_event() {
        let key = signing_key();
        let chain = seeded_chain(Uuid::from_u128(1), key);
        let result = chain.attest_accountability_execution(
            transcript_binding(Uuid::from_u128(99)),
            Uuid::from_u128(3),
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
            [12u8; 32],
            None,
            [14u8; 32],
        );
        assert!(matches!(
            result,
            Err(AccountabilityBindingError::LedgerSessionMismatch { .. })
        ));
    }

    #[test]
    fn construction_rejects_requester_not_matching_signed_ledger_event() {
        let key = signing_key();
        let session_id = Uuid::from_u128(1);
        let chain = seeded_chain(session_id, key);
        let result = chain.attest_accountability_execution(
            transcript_binding(session_id),
            Uuid::from_u128(3),
            [99u8; 32],
            [10u8; 32],
            [11u8; 32],
            [12u8; 32],
            None,
            [14u8; 32],
        );
        assert!(matches!(
            result,
            Err(AccountabilityBindingError::RequesterSourceMismatch)
        ));
    }

    #[test]
    fn pre_genesis_chain_cannot_attest_a_lookup() {
        let key = signing_key();
        let chain = Chain::new(key);
        let result = chain.attest_accountability_execution(
            transcript_binding(Uuid::from_u128(1)),
            Uuid::from_u128(3),
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
            [12u8; 32],
            None,
            [14u8; 32],
        );
        assert!(matches!(
            result,
            Err(AccountabilityBindingError::MissingResidentAuthorizationAnchor)
        ));
    }

    #[test]
    fn zero_receipt_commitment_is_fail_closed() {
        let key = signing_key();
        let session_id = Uuid::from_u128(1);
        let chain = seeded_chain(session_id, key);
        let result = chain.attest_accountability_execution(
            transcript_binding(session_id),
            Uuid::from_u128(3),
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
            [12u8; 32],
            None,
            [0u8; 32],
        );
        assert!(matches!(
            result,
            Err(AccountabilityBindingError::ZeroCommitment {
                field: "receipt_digest"
            })
        ));
    }

    #[test]
    fn binding_digest_changes_with_receipt() {
        let (attestation, _) = attestation();
        let first = accountability_execution_binding_digest(&attestation.binding);
        let mut changed = attestation.binding.clone();
        changed.receipt_digest = [15u8; 32];
        let second = accountability_execution_binding_digest(&changed);
        assert_ne!(first, second);
    }

    #[test]
    fn unknown_commitment_algorithm_is_rejected() {
        let (mut attestation, _) = attestation();
        attestation.binding.commitment_algorithm = "sha256".into();
        assert!(matches!(
            attestation.binding.validate_shape(),
            Err(AccountabilityBindingError::UnsupportedCommitmentAlgorithm { .. })
        ));
    }
}
