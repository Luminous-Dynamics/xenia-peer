// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-act / sink-bound, process-local execution handles.
//!
//! This is intentionally a *consequence-boundary primitive*, not an authority
//! token and not durable evidence. A verified agent authorization can be
//! narrowed to one exact act and one exact sink, after which the handle can be
//! consumed exactly once. The replay registry is concurrency-safe.
//!
//! Persistence and crash consistency remain outside this module: a process
//! restart loses the in-memory consumption registry, and callers must not use
//! this type as evidence that an external effect happened.

use std::collections::BTreeSet;
use std::sync::Mutex;

use blake3::Hasher;
use thiserror::Error;

use crate::{
    AgentCapabilityAttestationError, AgentCapabilityAttestationV1,
    AgentCheckpointAnchorV1, EvidencePublicKeyBinding, EvidenceSignatureBackend,
    SessionTranscriptBinding, verify_agent_capability_attestation,
};

/// Stable domain separator for exact execution-handle identities.
pub const EXECUTION_HANDLE_DOMAIN: &[u8] = b"xenia:exact-execution-handle:v1\0";

/// A process-local handle narrowed from one already-verified agent authorization.
///
/// The private seal prevents callers from fabricating a handle by struct
/// literal. The handle carries no signing key and is not itself evidence of
/// durable persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactExecutionHandleV1 {
    authorization_digest: [u8; 32],
    act_digest: [u8; 32],
    sink_digest: [u8; 32],
    expires_at_unix_s: u64,
    _seal: ExecutionHandleSeal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutionHandleSeal;

impl ExactExecutionHandleV1 {
    /// Construct an exact-act/sink handle from an attestation after all
    /// application bindings have been verified.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        attestation: &AgentCapabilityAttestationV1,
        session_binding: &SessionTranscriptBinding,
        public_key_binding: &EvidencePublicKeyBinding,
        signature_backend: &impl EvidenceSignatureBackend,
        now_unix_s: u64,
        expected_capability_digest: [u8; 32],
        expected_executor_workload_digest: [u8; 32],
        expected_authority_epoch: u64,
        expected_prior_checkpoint: Option<AgentCheckpointAnchorV1>,
        act_digest: [u8; 32],
        sink_digest: [u8; 32],
    ) -> Result<Self, ExactExecutionHandleError> {
        verify_agent_capability_attestation(
            attestation,
            session_binding,
            public_key_binding,
            signature_backend,
            now_unix_s,
            expected_capability_digest,
            expected_executor_workload_digest,
            expected_authority_epoch,
            expected_prior_checkpoint,
        )?;

        if act_digest == [0; 32] {
            return Err(ExactExecutionHandleError::ZeroActDigest);
        }
        if sink_digest == [0; 32] {
            return Err(ExactExecutionHandleError::ZeroSinkDigest);
        }

        let authorization_message = attestation.authorization.canonical_message()?;
        let authorization_digest = *blake3::hash(&authorization_message).as_bytes();

        Ok(Self {
            authorization_digest,
            act_digest,
            sink_digest,
            expires_at_unix_s: attestation.authorization.expires_at_unix_s,
            _seal: ExecutionHandleSeal,
        })
    }

    /// Stable identity committing to authorization, exact act, and exact sink.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(EXECUTION_HANDLE_DOMAIN);
        hasher.update(&self.authorization_digest);
        hasher.update(&self.act_digest);
        hasher.update(&self.sink_digest);
        hasher.update(&self.expires_at_unix_s.to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Digest of the exact act this handle authorizes.
    pub fn act_digest(&self) -> [u8; 32] {
        self.act_digest
    }

    /// Digest of the exact sink/destination this handle authorizes.
    pub fn sink_digest(&self) -> [u8; 32] {
        self.sink_digest
    }

    /// Expiration inherited from the verified authorization.
    pub fn expires_at_unix_s(&self) -> u64 {
        self.expires_at_unix_s
    }
}

/// Concurrency-safe process-local one-use registry for exact execution handles.
#[derive(Debug, Default)]
pub struct ExactExecutionConsumptionGuardV1 {
    consumed: Mutex<BTreeSet<[u8; 32]>>,
}

impl ExactExecutionConsumptionGuardV1 {
    /// Create an empty consumption registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically consume a handle exactly once.
    pub fn consume(
        &self,
        handle: &ExactExecutionHandleV1,
        now_unix_s: u64,
    ) -> Result<(), ExactExecutionConsumptionError> {
        if now_unix_s >= handle.expires_at_unix_s {
            return Err(ExactExecutionConsumptionError::Expired);
        }

        let digest = handle.digest();
        let mut consumed = self
            .consumed
            .lock()
            .map_err(|_| ExactExecutionConsumptionError::Poisoned)?;
        if !consumed.insert(digest) {
            return Err(ExactExecutionConsumptionError::AlreadyConsumed);
        }
        Ok(())
    }

    /// Number of consumed exact execution handles.
    pub fn len(&self) -> Result<usize, ExactExecutionConsumptionError> {
        self.consumed
            .lock()
            .map(|set| set.len())
            .map_err(|_| ExactExecutionConsumptionError::Poisoned)
    }

    /// Whether no exact execution handle has been consumed.
    pub fn is_empty(&self) -> Result<bool, ExactExecutionConsumptionError> {
        self.len().map(|len| len == 0)
    }
}

/// Errors issuing an exact execution handle.
#[derive(Debug, Error)]
pub enum ExactExecutionHandleError {
    /// The underlying agent authorization failed verification.
    #[error("agent authorization verification failed: {0}")]
    Authorization(#[from] AgentCapabilityAttestationError),
    /// The authorization canonical message was malformed.
    #[error("agent authorization canonicalization failed: {0}")]
    CanonicalAuthorization(#[from] crate::AgentCapabilityAuthorizationError),
    /// The exact act digest was empty.
    #[error("exact execution act digest must be nonzero")]
    ZeroActDigest,
    /// The exact sink digest was empty.
    #[error("exact execution sink digest must be nonzero")]
    ZeroSinkDigest,
}

/// Errors consuming an exact execution handle.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExactExecutionConsumptionError {
    /// The authorization's validity window has elapsed.
    #[error("exact execution handle is expired")]
    Expired,
    /// This exact handle was already consumed.
    #[error("exact execution handle has already been consumed")]
    AlreadyConsumed,
    /// The process-local registry became unusable.
    #[error("exact execution consumption registry is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentCapabilityAuthorizationV1, Chain, ConsentEventRecord, ConsentKind,
        Ed25519EvidenceSignatureBackend, SignatureSuite, TranscriptSignatureSuiteV1,
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

    fn fixture() -> (
        AgentCapabilityAttestationV1,
        SessionTranscriptBinding,
        EvidencePublicKeyBinding,
        AgentCapabilityAuthorizationV1,
    ) {
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        chain
            .append(ConsentEventRecord {
                source_id: [11; 32],
                session_id: Uuid::from_bytes([9; 16]),
                request_id: Uuid::from_bytes([4; 16]),
                kind: ConsentKind::Approval,
                scope: "bounded-agent authorization".into(),
            })
            .unwrap();

        let authorization = AgentCapabilityAuthorizationV1 {
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
        };
        let attestation = chain
            .attest_agent_capability_authorization(authorization.clone(), &session())
            .unwrap();
        let public_key =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, chain.signing_key.verifying_key().to_bytes());
        (attestation, session(), public_key, authorization)
    }

    fn issue(act: [u8; 32], sink: [u8; 32]) -> ExactExecutionHandleV1 {
        let (attestation, session, binding, authorization) = fixture();
        ExactExecutionHandleV1::issue(
            &attestation,
            &session,
            &binding,
            &Ed25519EvidenceSignatureBackend,
            120,
            authorization.capability_digest,
            authorization.executor_workload_digest,
            authorization.authority_epoch,
            authorization.prior_checkpoint,
            act,
            sink,
        )
        .unwrap()
    }

    #[test]
    fn handle_binds_exact_act_and_sink() {
        let handle = issue([0x11; 32], [0x22; 32]);
        let same = issue([0x11; 32], [0x22; 32]);
        assert_eq!(handle.digest(), same.digest());
        assert_eq!(handle.act_digest(), [0x11; 32]);
        assert_eq!(handle.sink_digest(), [0x22; 32]);
        assert_ne!(handle.digest(), issue([0x12; 32], [0x22; 32]).digest());
        assert_ne!(handle.digest(), issue([0x11; 32], [0x23; 32]).digest());
    }

    #[test]
    fn consumption_is_exactly_once_and_concurrency_safe() {
        let handle = issue([0x31; 32], [0x41; 32]);
        let guard = std::sync::Arc::new(ExactExecutionConsumptionGuardV1::new());
        let mut workers = Vec::new();
        for _ in 0..16 {
            let guard = std::sync::Arc::clone(&guard);
            let handle = handle.clone();
            workers.push(std::thread::spawn(move || guard.consume(&handle, 120).is_ok()));
        }
        let successes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
        assert_eq!(guard.len().unwrap(), 1);
    }

    #[test]
    fn expired_handle_cannot_be_consumed() {
        let handle = issue([0x51; 32], [0x61; 32]);
        let guard = ExactExecutionConsumptionGuardV1::new();
        assert_eq!(
            guard.consume(&handle, 160),
            Err(ExactExecutionConsumptionError::Expired)
        );
        assert!(guard.is_empty().unwrap());
    }

    #[test]
    fn zero_bindings_are_rejected_before_handle_creation() {
        let (attestation, session, binding, authorization) = fixture();
        let result = ExactExecutionHandleV1::issue(
            &attestation,
            &session,
            &binding,
            &Ed25519EvidenceSignatureBackend,
            120,
            authorization.capability_digest,
            authorization.executor_workload_digest,
            authorization.authority_epoch,
            authorization.prior_checkpoint,
            [0; 32],
            [0x71; 32],
        );
        assert!(matches!(result, Err(ExactExecutionHandleError::ZeroActDigest)));

        let result = ExactExecutionHandleV1::issue(
            &attestation,
            &session,
            &binding,
            &Ed25519EvidenceSignatureBackend,
            120,
            authorization.capability_digest,
            authorization.executor_workload_digest,
            authorization.authority_epoch,
            authorization.prior_checkpoint,
            [0x71; 32],
            [0; 32],
        );
        assert!(matches!(result, Err(ExactExecutionHandleError::ZeroSinkDigest)));
    }
}
