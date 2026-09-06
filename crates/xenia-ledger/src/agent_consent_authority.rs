// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Consent-bound durable agent authority.
//!
//! The lower-level `AgentCapabilityAttestationV1` proves that Xenia signed an
//! exact authorization at an exact ledger frontier. `DurableLedgerFrontierV1`
//! additionally proves that exact frontier passed a reviewed persistence
//! boundary. Neither fact, by itself, proves that the authorization's semantic
//! capability/workload intent was the object approved by the consent history.
//!
//! This module closes that gap without changing the historical
//! `ConsentEventRecord` encoding. A pre-frontier intent is committed into the
//! existing signed/hash-chained `scope` string, then a distinct stronger
//! attestation can be issued only when the complete local ledger proves:
//!
//! ```text
//! exact intent + exact presentation commitment
//!         ↓
//! matching Request
//!         ↓
//! matching Approval
//!         ↓
//! no Denial / Revocation / Violation for that request
//!         ↓
//! exact durable current ledger frontier
//!         ↓
//! DurableConsentBoundAgentCapabilityAttestationV1
//! ```
//!
//! A compacted-prefix chain fails closed in V1 because the issuer cannot inspect
//! the complete request history. The complete resident history is also verified
//! cryptographically before its consent semantics are trusted, so a permissive
//! restore callback cannot launder tampered entries into consent-bound authority.
//!
//! An already-issued attestation remains replayable cryptographic evidence. A
//! later ledger Revocation advances the frontier but cannot erase an old
//! signature; consequential downstream admission must still establish current
//! Xenia frontier/freshness before accepting the attestation.
//!
//! Evidence chronology remains separate from execution authority.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AGENT_CAPABILITY_ATTESTATION_SCHEMA, AgentCapabilityAttestationError,
    AgentCapabilityAttestationV1, AgentCapabilityAuthorizationError,
    AgentCapabilityAuthorizationV1, AgentCheckpointAnchorV1, Chain, ConsentEventRecord,
    ConsentKind, DURABLE_LEDGER_FRONTIER_SCHEMA_VERSION, DurableLedgerFrontierClaimV1,
    DurableLedgerFrontierError, DurableLedgerFrontierV1, EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM,
    EvidencePublicKeyBinding, EvidencePublicKeyBindingError, EvidenceSignatureBackend,
    EvidenceSignatureBackendError, SessionTranscriptBinding, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite, TranscriptSignatureSuiteV1, Verifier,
    verify_agent_capability_attestation,
};

/// Schema version for [`AgentCapabilityConsentIntentV1`].
pub const AGENT_CAPABILITY_CONSENT_INTENT_SCHEMA_VERSION: u16 = 1;
/// Domain separator for the pre-frontier consent intent.
pub const AGENT_CAPABILITY_CONSENT_INTENT_DOMAIN: &[u8] =
    b"xenia.agent-capability-consent-intent.v1\0";
/// Stable scope prefix written into existing consent-ledger events.
pub const AGENT_CAPABILITY_CONSENT_SCOPE_PREFIX: &str =
    "xenia.agent-capability-consent.v1:blake3:";
/// Schema version for [`DurableConsentBoundAgentCapabilityAttestationV1`].
pub const DURABLE_CONSENT_BOUND_AGENT_ATTESTATION_SCHEMA_VERSION: u16 = 1;
/// Domain separator for the stronger consent-bound attestation signature.
pub const DURABLE_CONSENT_BOUND_AGENT_ATTESTATION_DOMAIN: &[u8] =
    b"xenia.durable-consent-bound-agent-capability.v1\0";

const ZERO16: [u8; 16] = [0; 16];
const ZERO32: [u8; 32] = [0; 32];

/// Pre-frontier bounded-agent intent that can be presented and approved before
/// the approval itself advances the Xenia ledger frontier.
///
/// `consent_presentation_digest` commits the exact application-defined canonical
/// artifact shown to the human. Xenia need not retain or understand the raw
/// presentation. Integrations MUST define that presentation encoding and MUST
/// show the semantic artifact corresponding to this digest before recording an
/// Approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapabilityConsentIntentV1 {
    /// Must equal [`AGENT_CAPABILITY_CONSENT_INTENT_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// DID-bound/opaque Xenia source that requested this authorization.
    pub requester_source_id: [u8; 32],
    /// Stable authorization/request identifier. Also used as the ledger request UUID bytes.
    pub authorization_id: [u8; 16],
    /// Authenticated Xenia session UUID bytes.
    pub session_id: [u8; 16],
    /// Commitment to the authenticated session transcript.
    pub session_transcript_hash: [u8; 32],
    /// Signature suite authenticating the session transcript.
    pub session_signature_suite: TranscriptSignatureSuiteV1,
    /// Exact application capability commitment being approved.
    pub capability_digest: [u8; 32],
    /// Exact workload/software identity allowed to exercise the capability.
    pub executor_workload_digest: [u8; 32],
    /// Monotonic bounded-agent authority epoch.
    pub authority_epoch: u64,
    /// Earliest wall-clock instant named by the requested authorization.
    pub issued_at_unix_s: u64,
    /// Hard authorization expiry named by the requested authorization.
    pub expires_at_unix_s: u64,
    /// Replay/domain nonce.
    pub nonce: [u8; 16],
    /// Optional exact prior runtime checkpoint anchor.
    pub prior_checkpoint: Option<AgentCheckpointAnchorV1>,
    /// Commitment to the exact canonical user-facing consent presentation.
    pub consent_presentation_digest: [u8; 32],
}

impl AgentCapabilityConsentIntentV1 {
    /// Validate the pre-frontier intent without requiring a ledger frontier that
    /// does not exist until after Approval is durably appended.
    pub fn validate(self) -> Result<(), AgentConsentAuthorityError> {
        if self.schema_version != AGENT_CAPABILITY_CONSENT_INTENT_SCHEMA_VERSION {
            return Err(AgentConsentAuthorityError::UnsupportedIntentSchema);
        }
        if self.requester_source_id == ZERO32 {
            return Err(AgentConsentAuthorityError::ZeroRequesterSource);
        }
        if self.authorization_id == ZERO16 {
            return Err(AgentConsentAuthorityError::ZeroAuthorizationId);
        }
        if self.session_id == ZERO16 {
            return Err(AgentConsentAuthorityError::ZeroSessionId);
        }
        if self.session_transcript_hash == ZERO32 {
            return Err(AgentConsentAuthorityError::ZeroSessionTranscriptHash);
        }
        if self.capability_digest == ZERO32 {
            return Err(AgentConsentAuthorityError::ZeroCapabilityDigest);
        }
        if self.executor_workload_digest == ZERO32 {
            return Err(AgentConsentAuthorityError::ZeroExecutorWorkloadDigest);
        }
        if self.authority_epoch == 0 {
            return Err(AgentConsentAuthorityError::ZeroAuthorityEpoch);
        }
        if self.issued_at_unix_s == 0 || self.expires_at_unix_s <= self.issued_at_unix_s {
            return Err(AgentConsentAuthorityError::InvalidValidityWindow);
        }
        if self.nonce == ZERO16 {
            return Err(AgentConsentAuthorityError::ZeroNonce);
        }
        if self
            .prior_checkpoint
            .is_some_and(|checkpoint| checkpoint.digest == ZERO32)
        {
            return Err(AgentConsentAuthorityError::ZeroCheckpointDigest);
        }
        if self.consent_presentation_digest == ZERO32 {
            return Err(AgentConsentAuthorityError::ZeroPresentationDigest);
        }
        Ok(())
    }

    /// Stable hand-written message for the intent commitment.
    pub fn canonical_message(self) -> Result<Vec<u8>, AgentConsentAuthorityError> {
        self.validate()?;
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(AGENT_CAPABILITY_CONSENT_INTENT_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(&self.requester_source_id);
        out.extend_from_slice(&self.authorization_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.session_transcript_hash);
        out.push(self.session_signature_suite as u8);
        out.extend_from_slice(&self.capability_digest);
        out.extend_from_slice(&self.executor_workload_digest);
        out.extend_from_slice(&self.authority_epoch.to_be_bytes());
        out.extend_from_slice(&self.issued_at_unix_s.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix_s.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        match self.prior_checkpoint {
            None => out.push(0),
            Some(checkpoint) => {
                out.push(1);
                out.extend_from_slice(&checkpoint.sequence.to_be_bytes());
                out.extend_from_slice(&checkpoint.digest);
            }
        }
        out.extend_from_slice(&self.consent_presentation_digest);
        Ok(out)
    }

    /// BLAKE3 commitment to the complete pre-frontier consent intent.
    pub fn digest(self) -> Result<[u8; 32], AgentConsentAuthorityError> {
        Ok(*blake3::hash(&self.canonical_message()?).as_bytes())
    }

    /// Exact scope string that Request/Approval events must carry.
    pub fn consent_scope(self) -> Result<String, AgentConsentAuthorityError> {
        Ok(format!(
            "{AGENT_CAPABILITY_CONSENT_SCOPE_PREFIX}{}",
            hex32(self.digest()?)
        ))
    }

    /// UUID corresponding exactly to `authorization_id`.
    pub fn request_id(self) -> Result<Uuid, AgentConsentAuthorityError> {
        self.validate()?;
        Ok(Uuid::from_bytes(self.authorization_id))
    }

    /// UUID corresponding exactly to `session_id`.
    pub fn session_uuid(self) -> Result<Uuid, AgentConsentAuthorityError> {
        self.validate()?;
        Ok(Uuid::from_bytes(self.session_id))
    }

    /// Construct the exact Request ledger record for this intent.
    ///
    /// This helper intentionally does not construct an Approval. Approval must
    /// come from the authenticated consent interaction/state-machine boundary.
    pub fn request_record(self) -> Result<ConsentEventRecord, AgentConsentAuthorityError> {
        Ok(ConsentEventRecord {
            source_id: self.requester_source_id,
            session_id: self.session_uuid()?,
            request_id: self.request_id()?,
            kind: ConsentKind::Request,
            scope: self.consent_scope()?,
        })
    }

    /// Materialize the final signed-protocol authorization at one exact frontier.
    /// This is intentionally unavailable until the caller has a non-genesis
    /// frontier, normally the durable frontier that includes Approval.
    pub fn authorization_at_frontier(
        self,
        ledger_entry_count: u64,
        ledger_head_hash: [u8; 32],
    ) -> Result<AgentCapabilityAuthorizationV1, AgentConsentAuthorityError> {
        self.validate()?;
        let authorization = AgentCapabilityAuthorizationV1 {
            schema_version: crate::AGENT_CAPABILITY_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: self.authorization_id,
            session_id: self.session_id,
            session_transcript_hash: self.session_transcript_hash,
            session_signature_suite: self.session_signature_suite,
            capability_digest: self.capability_digest,
            executor_workload_digest: self.executor_workload_digest,
            authority_epoch: self.authority_epoch,
            issued_at_unix_s: self.issued_at_unix_s,
            expires_at_unix_s: self.expires_at_unix_s,
            nonce: self.nonce,
            ledger_entry_count,
            ledger_head_hash,
            prior_checkpoint: self.prior_checkpoint,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Reconstruct this intent from a final authorization plus the two facts not
    /// carried by the lower-level authorization protocol.
    pub fn from_authorization(
        authorization: &AgentCapabilityAuthorizationV1,
        requester_source_id: [u8; 32],
        consent_presentation_digest: [u8; 32],
    ) -> Result<Self, AgentConsentAuthorityError> {
        authorization.validate()?;
        let value = Self {
            schema_version: AGENT_CAPABILITY_CONSENT_INTENT_SCHEMA_VERSION,
            requester_source_id,
            authorization_id: authorization.authorization_id,
            session_id: authorization.session_id,
            session_transcript_hash: authorization.session_transcript_hash,
            session_signature_suite: authorization.session_signature_suite,
            capability_digest: authorization.capability_digest,
            executor_workload_digest: authorization.executor_workload_digest,
            authority_epoch: authorization.authority_epoch,
            issued_at_unix_s: authorization.issued_at_unix_s,
            expires_at_unix_s: authorization.expires_at_unix_s,
            nonce: authorization.nonce,
            prior_checkpoint: authorization.prior_checkpoint,
            consent_presentation_digest,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Privacy-minimized evidence that Xenia found the exact consent history before
/// issuing the stronger attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapabilityConsentEvidenceV1 {
    /// Source identity shared by the matching Request and Approval.
    pub requester_source_id: [u8; 32],
    /// Commitment to the exact user-facing presentation.
    pub consent_presentation_digest: [u8; 32],
    /// Commitment to the complete pre-frontier intent.
    pub consent_intent_digest: [u8; 32],
    /// Sequence of the matching Request entry.
    pub request_entry_seq: u64,
    /// Hash of the matching Request entry.
    pub request_entry_hash: [u8; 32],
    /// Sequence of the matching Approval entry.
    pub approval_entry_seq: u64,
    /// Hash of the matching Approval entry.
    pub approval_entry_hash: [u8; 32],
    /// Persistence policy under which the exact current frontier was established.
    pub persistence_policy_digest: [u8; 32],
    /// Commitment to the exact durable current ledger frontier.
    pub durable_frontier_digest: [u8; 32],
}

impl AgentCapabilityConsentEvidenceV1 {
    fn validate(
        self,
        authorization: &AgentCapabilityAuthorizationV1,
    ) -> Result<(), AgentConsentAuthorityError> {
        if self.requester_source_id == ZERO32
            || self.consent_presentation_digest == ZERO32
            || self.consent_intent_digest == ZERO32
            || self.request_entry_hash == ZERO32
            || self.approval_entry_hash == ZERO32
            || self.persistence_policy_digest == ZERO32
            || self.durable_frontier_digest == ZERO32
        {
            return Err(AgentConsentAuthorityError::MalformedConsentEvidence);
        }
        if self.approval_entry_seq <= self.request_entry_seq
            || self.approval_entry_seq >= authorization.ledger_entry_count
        {
            return Err(AgentConsentAuthorityError::MalformedConsentEvidence);
        }
        Ok(())
    }
}

/// Stronger wire evidence: the ordinary Xenia authorization attestation plus a
/// second Xenia signature proving the exact intent was found in complete consent
/// history and the resulting frontier was durable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableConsentBoundAgentCapabilityAttestationV1 {
    /// Must equal [`DURABLE_CONSENT_BOUND_AGENT_ATTESTATION_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// Existing cryptographic authorization/frontier attestation.
    pub inner: AgentCapabilityAttestationV1,
    /// Consent-history + durable-frontier commitments established by Xenia.
    pub consent: AgentCapabilityConsentEvidenceV1,
    /// Xenia signature over the stronger composition message.
    pub signature: SignatureEnvelope,
}

impl DurableConsentBoundAgentCapabilityAttestationV1 {
    /// Stable message covered by the stronger composition signature.
    pub fn canonical_message(&self) -> Result<Vec<u8>, AgentConsentAuthorityError> {
        if self.schema_version != DURABLE_CONSENT_BOUND_AGENT_ATTESTATION_SCHEMA_VERSION {
            return Err(AgentConsentAuthorityError::UnsupportedAttestationSchema);
        }
        if self.inner.schema != AGENT_CAPABILITY_ATTESTATION_SCHEMA {
            return Err(AgentConsentAuthorityError::MalformedInnerAttestation);
        }
        self.inner.authorization.validate()?;
        self.consent.validate(&self.inner.authorization)?;
        if self.inner.signature.validate_shape()? != SignatureSuite::Ed25519Rfc8032 {
            return Err(AgentConsentAuthorityError::UnsupportedSignatureSuite);
        }

        let authorization_message = self.inner.authorization.canonical_message()?;
        let authorization_digest = *blake3::hash(&authorization_message).as_bytes();
        let inner_signature: [u8; 64] = self
            .inner
            .signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AgentConsentAuthorityError::MalformedInnerAttestation)?;

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(DURABLE_CONSENT_BOUND_AGENT_ATTESTATION_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(&authorization_digest);
        out.extend_from_slice(&self.inner.ledger_public_key_fingerprint);
        out.extend_from_slice(&inner_signature);
        out.extend_from_slice(&self.consent.requester_source_id);
        out.extend_from_slice(&self.consent.consent_presentation_digest);
        out.extend_from_slice(&self.consent.consent_intent_digest);
        out.extend_from_slice(&self.consent.request_entry_seq.to_be_bytes());
        out.extend_from_slice(&self.consent.request_entry_hash);
        out.extend_from_slice(&self.consent.approval_entry_seq.to_be_bytes());
        out.extend_from_slice(&self.consent.approval_entry_hash);
        out.extend_from_slice(&self.consent.persistence_policy_digest);
        out.extend_from_slice(&self.consent.durable_frontier_digest);
        Ok(out)
    }
}

impl Chain {
    /// Issue the stronger durable + consent-bound agent authorization.
    ///
    /// The caller supplies only the pre-frontier intent. This method derives the
    /// final authorization frontier from the current chain after verifying the
    /// exact durable token, preventing caller-selected frontier substitution.
    pub fn attest_agent_capability_consent_bound_durable_v1(
        &self,
        intent: AgentCapabilityConsentIntentV1,
        session_binding: &SessionTranscriptBinding,
        durable_frontier: &DurableLedgerFrontierV1,
        expected_persistence_policy_digest: [u8; 32],
    ) -> Result<DurableConsentBoundAgentCapabilityAttestationV1, AgentConsentAuthorityError> {
        intent.validate()?;
        verify_exact_durable_frontier(
            self,
            durable_frontier,
            expected_persistence_policy_digest,
        )?;

        let history = verify_exact_consent_history(self, intent)?;
        let authorization = intent.authorization_at_frontier(self.entry_count(), self.last_hash())?;
        let inner = self
            .attest_agent_capability_authorization(authorization, session_binding)
            .map_err(AgentConsentAuthorityError::InnerAttestation)?;

        let consent = AgentCapabilityConsentEvidenceV1 {
            requester_source_id: intent.requester_source_id,
            consent_presentation_digest: intent.consent_presentation_digest,
            consent_intent_digest: intent.digest()?,
            request_entry_seq: history.request_entry_seq,
            request_entry_hash: history.request_entry_hash,
            approval_entry_seq: history.approval_entry_seq,
            approval_entry_hash: history.approval_entry_hash,
            persistence_policy_digest: expected_persistence_policy_digest,
            durable_frontier_digest: durable_frontier.digest(),
        };
        consent.validate(&inner.authorization)?;

        let mut attestation = DurableConsentBoundAgentCapabilityAttestationV1 {
            schema_version: DURABLE_CONSENT_BOUND_AGENT_ATTESTATION_SCHEMA_VERSION,
            inner,
            consent,
            signature: SignatureEnvelope::ed25519([0; 64]),
        };
        let signature = self
            .signing_key
            .sign(&attestation.canonical_message()?)
            .to_bytes();
        attestation.signature = SignatureEnvelope::ed25519(signature);
        Ok(attestation)
    }
}

/// Verify the stronger consent-bound attestation for a downstream bounded agent.
///
/// This verifies signed evidence at the attestation's named ledger frontier. It
/// does not prove that frontier is still current after issuance. Consequential
/// admission must separately establish fresh Xenia ledger currentness so a later
/// Revocation/Denial/Violation cannot be suppressed behind an older valid
/// signature.
#[allow(clippy::too_many_arguments)]
pub fn verify_durable_consent_bound_agent_capability_attestation_v1(
    attestation: &DurableConsentBoundAgentCapabilityAttestationV1,
    session_binding: &SessionTranscriptBinding,
    public_key_binding: &EvidencePublicKeyBinding,
    signature_backend: &impl EvidenceSignatureBackend,
    now_unix_s: u64,
    expected_capability_digest: [u8; 32],
    expected_executor_workload_digest: [u8; 32],
    expected_authority_epoch: u64,
    expected_prior_checkpoint: Option<AgentCheckpointAnchorV1>,
    expected_persistence_policy_digest: [u8; 32],
) -> Result<(), AgentConsentAuthorityError> {
    if attestation.schema_version != DURABLE_CONSENT_BOUND_AGENT_ATTESTATION_SCHEMA_VERSION {
        return Err(AgentConsentAuthorityError::UnsupportedAttestationSchema);
    }

    verify_agent_capability_attestation(
        &attestation.inner,
        session_binding,
        public_key_binding,
        signature_backend,
        now_unix_s,
        expected_capability_digest,
        expected_executor_workload_digest,
        expected_authority_epoch,
        expected_prior_checkpoint,
    )?;

    if expected_persistence_policy_digest == ZERO32
        || attestation.consent.persistence_policy_digest != expected_persistence_policy_digest
    {
        return Err(AgentConsentAuthorityError::PersistencePolicyMismatch);
    }
    attestation.consent.validate(&attestation.inner.authorization)?;

    let intent = AgentCapabilityConsentIntentV1::from_authorization(
        &attestation.inner.authorization,
        attestation.consent.requester_source_id,
        attestation.consent.consent_presentation_digest,
    )?;
    if intent.digest()? != attestation.consent.consent_intent_digest {
        return Err(AgentConsentAuthorityError::ConsentIntentDigestMismatch);
    }

    if public_key_binding.fingerprint_algorithm != EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM {
        return Err(AgentConsentAuthorityError::PublicKeyBinding(
            EvidencePublicKeyBindingError::UnsupportedFingerprintAlgorithm {
                algorithm: public_key_binding.fingerprint_algorithm.clone(),
            },
        ));
    }
    public_key_binding.validate_against_signature_suite_and_backend(
        SignatureSuite::Ed25519Rfc8032,
        signature_backend,
    )?;
    let ledger_public_key: [u8; 32] = public_key_binding
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| AgentConsentAuthorityError::MalformedLedgerPublicKey)?;
    let durable_claim = DurableLedgerFrontierClaimV1 {
        schema_version: DURABLE_LEDGER_FRONTIER_SCHEMA_VERSION,
        entry_count: attestation.inner.authorization.ledger_entry_count,
        head_hash: attestation.inner.authorization.ledger_head_hash,
        ledger_public_key,
        persistence_policy_digest: expected_persistence_policy_digest,
    };
    if durable_claim.digest()? != attestation.consent.durable_frontier_digest {
        return Err(AgentConsentAuthorityError::DurableFrontierDigestMismatch);
    }

    if attestation.signature.validate_shape()? != SignatureSuite::Ed25519Rfc8032 {
        return Err(AgentConsentAuthorityError::UnsupportedSignatureSuite);
    }
    signature_backend.verify_signature(
        &public_key_binding.public_key,
        &attestation.canonical_message()?,
        &attestation.signature.signature,
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct VerifiedConsentHistory {
    request_entry_seq: u64,
    request_entry_hash: [u8; 32],
    approval_entry_seq: u64,
    approval_entry_hash: [u8; 32],
}

fn verify_exact_durable_frontier(
    chain: &Chain,
    durable_frontier: &DurableLedgerFrontierV1,
    expected_persistence_policy_digest: [u8; 32],
) -> Result<(), AgentConsentAuthorityError> {
    if expected_persistence_policy_digest == ZERO32
        || durable_frontier.persistence_policy_digest() != expected_persistence_policy_digest
    {
        return Err(AgentConsentAuthorityError::PersistencePolicyMismatch);
    }
    if chain.has_uncertain_persistence() {
        return Err(AgentConsentAuthorityError::PersistenceUncertain);
    }
    if durable_frontier.entry_count() != chain.entry_count()
        || durable_frontier.head_hash() != chain.last_hash()
    {
        return Err(AgentConsentAuthorityError::DurableFrontierMismatch);
    }
    let claim = DurableLedgerFrontierClaimV1 {
        schema_version: DURABLE_LEDGER_FRONTIER_SCHEMA_VERSION,
        entry_count: chain.entry_count(),
        head_hash: chain.last_hash(),
        ledger_public_key: chain.signing_key.verifying_key().to_bytes(),
        persistence_policy_digest: expected_persistence_policy_digest,
    };
    if claim.digest()? != durable_frontier.digest() {
        return Err(AgentConsentAuthorityError::DurableFrontierMismatch);
    }
    Ok(())
}

fn verify_exact_consent_history(
    chain: &Chain,
    intent: AgentCapabilityConsentIntentV1,
) -> Result<VerifiedConsentHistory, AgentConsentAuthorityError> {
    if chain.base_checkpoint().is_some() || chain.resident_len() as u64 != chain.entry_count() {
        return Err(AgentConsentAuthorityError::CompactedConsentHistory);
    }

    let resident: Vec<_> = chain.iter().cloned().collect();
    Verifier::verify_chain(&resident, &chain.signing_key.verifying_key())
        .map_err(|_| AgentConsentAuthorityError::ConsentHistoryCryptographicVerificationFailed)?;

    let session_id = intent.session_uuid()?;
    let request_id = intent.request_id()?;
    let scope = intent.consent_scope()?;
    let mut expected_seq = 0u64;
    let mut previous_hash = ZERO32;
    let mut request = None;
    let mut approval = None;

    for entry in &resident {
        if entry.seq != expected_seq || entry.prev_hash != previous_hash || entry.entry_hash == ZERO32 {
            return Err(AgentConsentAuthorityError::MalformedConsentHistory);
        }
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or(AgentConsentAuthorityError::MalformedConsentHistory)?;
        previous_hash = entry.entry_hash;

        let event = &entry.event;
        if event.session_id != session_id || event.request_id != request_id {
            continue;
        }

        match event.kind {
            ConsentKind::Denial | ConsentKind::Revocation | ConsentKind::Violation => {
                return Err(AgentConsentAuthorityError::ConsentNegated(event.kind));
            }
            ConsentKind::AthenaTriage => {
                return Err(AgentConsentAuthorityError::UnexpectedConsentEventKind);
            }
            ConsentKind::Request => {
                if event.source_id != intent.requester_source_id || event.scope != scope {
                    return Err(AgentConsentAuthorityError::ConsentIntentConflict);
                }
                if approval.is_some() {
                    return Err(AgentConsentAuthorityError::ConsentEventOrderViolation);
                }
                request = Some((entry.seq, entry.entry_hash));
            }
            ConsentKind::Approval => {
                if event.source_id != intent.requester_source_id || event.scope != scope {
                    return Err(AgentConsentAuthorityError::ConsentIntentConflict);
                }
                if request.is_none() {
                    return Err(AgentConsentAuthorityError::ApprovalWithoutRequest);
                }
                approval = Some((entry.seq, entry.entry_hash));
            }
        }
    }

    if expected_seq != chain.entry_count() || previous_hash != chain.last_hash() {
        return Err(AgentConsentAuthorityError::MalformedConsentHistory);
    }
    let (request_entry_seq, request_entry_hash) =
        request.ok_or(AgentConsentAuthorityError::ConsentRequestMissing)?;
    let (approval_entry_seq, approval_entry_hash) =
        approval.ok_or(AgentConsentAuthorityError::ConsentApprovalMissing)?;
    if approval_entry_seq <= request_entry_seq {
        return Err(AgentConsentAuthorityError::ConsentEventOrderViolation);
    }
    Ok(VerifiedConsentHistory {
        request_entry_seq,
        request_entry_hash,
        approval_entry_seq,
        approval_entry_hash,
    })
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Fail-closed errors for durable consent-bound agent authorization.
#[derive(Debug, Error)]
pub enum AgentConsentAuthorityError {
    /// Unknown pre-frontier intent schema.
    #[error("unsupported agent capability consent-intent schema")]
    UnsupportedIntentSchema,
    /// Unknown stronger attestation schema.
    #[error("unsupported durable consent-bound agent attestation schema")]
    UnsupportedAttestationSchema,
    /// Requester/source identity is the all-zero placeholder.
    #[error("agent consent requester source must not be zero")]
    ZeroRequesterSource,
    /// Authorization/request id is zero.
    #[error("agent consent authorization id must not be zero")]
    ZeroAuthorizationId,
    /// Session id is zero.
    #[error("agent consent session id must not be zero")]
    ZeroSessionId,
    /// Session transcript commitment is zero.
    #[error("agent consent transcript hash must not be zero")]
    ZeroSessionTranscriptHash,
    /// Capability commitment is zero.
    #[error("agent consent capability digest must not be zero")]
    ZeroCapabilityDigest,
    /// Workload commitment is zero.
    #[error("agent consent workload digest must not be zero")]
    ZeroExecutorWorkloadDigest,
    /// Authority epoch is zero.
    #[error("agent consent authority epoch must not be zero")]
    ZeroAuthorityEpoch,
    /// Validity window is malformed.
    #[error("agent consent validity window is invalid")]
    InvalidValidityWindow,
    /// Replay nonce is zero.
    #[error("agent consent nonce must not be zero")]
    ZeroNonce,
    /// Runtime checkpoint commitment is zero.
    #[error("agent consent prior checkpoint digest must not be zero")]
    ZeroCheckpointDigest,
    /// User-facing presentation commitment is zero.
    #[error("agent consent presentation digest must not be zero")]
    ZeroPresentationDigest,
    /// Current chain contains a compacted/non-resident prefix that V1 cannot inspect.
    #[error("complete consent history is unavailable because the ledger is compacted")]
    CompactedConsentHistory,
    /// Complete resident history failed sequence/hash/signature verification.
    #[error("complete consent history failed cryptographic verification")]
    ConsentHistoryCryptographicVerificationFailed,
    /// Complete resident history has malformed sequence/hash-link shape.
    #[error("complete consent history has malformed sequence/hash-link structure")]
    MalformedConsentHistory,
    /// Exact consent Request was not found.
    #[error("exact agent consent request is missing")]
    ConsentRequestMissing,
    /// Exact consent Approval was not found.
    #[error("exact agent consent approval is missing")]
    ConsentApprovalMissing,
    /// Approval appeared before a matching Request.
    #[error("agent consent approval appeared without a prior matching request")]
    ApprovalWithoutRequest,
    /// Matching request identity carried conflicting source/scope data.
    #[error("agent consent request identity was reused for a conflicting intent")]
    ConsentIntentConflict,
    /// Matching consent events violate the closed-world V1 chronology.
    #[error("agent consent event ordering is invalid")]
    ConsentEventOrderViolation,
    /// A negative authority fact dominates the request permanently in V1.
    #[error("agent consent was negated by {0:?}")]
    ConsentNegated(ConsentKind),
    /// Automated triage cannot substitute for user consent on this request id.
    #[error("unexpected automated consent event shares the agent authorization request id")]
    UnexpectedConsentEventKind,
    /// Durable token was minted under a different persistence policy.
    #[error("durable consent frontier persistence policy mismatch")]
    PersistencePolicyMismatch,
    /// Consent ledger still has an ambiguous persistence outcome.
    #[error("consent ledger persistence remains unresolved")]
    PersistenceUncertain,
    /// Durable token does not match the exact current Xenia chain/key/frontier.
    #[error("durable consent frontier does not match the current Xenia chain")]
    DurableFrontierMismatch,
    /// Wire evidence fields are malformed.
    #[error("malformed agent consent evidence")]
    MalformedConsentEvidence,
    /// The inner lower-level attestation schema/signature shape is malformed.
    #[error("malformed inner agent capability attestation")]
    MalformedInnerAttestation,
    /// Recomputed pre-frontier intent differs from Xenia's signed consent evidence.
    #[error("agent consent intent digest mismatch")]
    ConsentIntentDigestMismatch,
    /// Recomputed durable frontier differs from Xenia's signed consent evidence.
    #[error("durable consent frontier digest mismatch")]
    DurableFrontierDigestMismatch,
    /// Current consent-bound V1 wrapper signs only with the ledger Ed25519 key.
    #[error("unsupported consent-bound agent signature suite")]
    UnsupportedSignatureSuite,
    /// Public key is not the current 32-byte Ed25519 ledger key shape.
    #[error("malformed consent-bound agent ledger public key")]
    MalformedLedgerPublicKey,
    /// Lower-level authorization structure failed validation.
    #[error("invalid final agent authorization: {0}")]
    Authorization(#[from] AgentCapabilityAuthorizationError),
    /// Existing lower-level attestation issuance/verification failed.
    #[error("inner agent capability attestation failed: {0}")]
    InnerAttestation(#[from] AgentCapabilityAttestationError),
    /// Durable frontier claim failed validation.
    #[error("durable frontier validation failed: {0}")]
    DurableFrontier(#[from] DurableLedgerFrontierError),
    /// Evidence public-key metadata failed validation.
    #[error("public-key binding invalid: {0}")]
    PublicKeyBinding(#[from] EvidencePublicKeyBindingError),
    /// Signature envelope was malformed.
    #[error("signature envelope invalid: {0}")]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Evidence signature backend rejected the stronger signature.
    #[error("consent-bound agent signature verification failed: {0}")]
    SignatureBackend(#[from] EvidenceSignatureBackendError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        DurableLedgerAppendOutcomeV1, Ed25519EvidenceSignatureBackend, PersistenceDisposition,
    };

    const PERSISTENCE_POLICY: [u8; 32] = [0xD1; 32];

    fn intent() -> AgentCapabilityConsentIntentV1 {
        AgentCapabilityConsentIntentV1 {
            schema_version: AGENT_CAPABILITY_CONSENT_INTENT_SCHEMA_VERSION,
            requester_source_id: [0x11; 32],
            authorization_id: [0x21; 16],
            session_id: [0x22; 16],
            session_transcript_hash: [0x33; 32],
            session_signature_suite: TranscriptSignatureSuiteV1::Ed25519Rfc8032,
            capability_digest: [0x44; 32],
            executor_workload_digest: [0x55; 32],
            authority_epoch: 9,
            issued_at_unix_s: 100,
            expires_at_unix_s: 200,
            nonce: [0x66; 16],
            prior_checkpoint: Some(AgentCheckpointAnchorV1 {
                sequence: 3,
                digest: [0x77; 32],
            }),
            consent_presentation_digest: [0x88; 32],
        }
    }

    fn session() -> SessionTranscriptBinding {
        SessionTranscriptBinding::from_hash(
            Uuid::from_bytes([0x22; 16]),
            [0x33; 32],
            SignatureSuite::Ed25519Rfc8032,
        )
    }

    fn append_durable(chain: &mut Chain, event: ConsentEventRecord) -> DurableLedgerFrontierV1 {
        match chain
            .append_transactional_outcome_durable_v1(event, PERSISTENCE_POLICY, |_, _| {
                crate::PersistenceDisposition::Persisted
            })
            .unwrap()
        {
            DurableLedgerAppendOutcomeV1::Persisted {
                durable_frontier, ..
            } => durable_frontier,
            _ => panic!("expected persisted durable append"),
        }
    }

    fn approval_for(intent: AgentCapabilityConsentIntentV1) -> ConsentEventRecord {
        let mut event = intent.request_record().unwrap();
        event.kind = ConsentKind::Approval;
        event
    }

    fn approved_chain() -> (Chain, DurableLedgerFrontierV1) {
        let intent = intent();
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        let _request_frontier = append_durable(&mut chain, intent.request_record().unwrap());
        let approval_frontier = append_durable(&mut chain, approval_for(intent));
        (chain, approval_frontier)
    }

    #[test]
    fn exact_request_approval_and_durable_frontier_issue_stronger_attestation() {
        let intent = intent();
        let (chain, durable_frontier) = approved_chain();
        let attestation = chain
            .attest_agent_capability_consent_bound_durable_v1(
                intent,
                &session(),
                &durable_frontier,
                PERSISTENCE_POLICY,
            )
            .unwrap();
        assert_eq!(attestation.inner.authorization.ledger_entry_count, 2);
        assert_eq!(attestation.consent.request_entry_seq, 0);
        assert_eq!(attestation.consent.approval_entry_seq, 1);

        let public_key = chain.signing_key.verifying_key().to_bytes();
        let public_key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);
        verify_durable_consent_bound_agent_capability_attestation_v1(
            &attestation,
            &session(),
            &public_key_binding,
            &Ed25519EvidenceSignatureBackend,
            120,
            intent.capability_digest,
            intent.executor_workload_digest,
            intent.authority_epoch,
            intent.prior_checkpoint,
            PERSISTENCE_POLICY,
        )
        .unwrap();
    }

    #[test]
    fn generic_or_mismatched_approval_cannot_authorize_exact_intent() {
        let intent = intent();
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        let _ = append_durable(&mut chain, intent.request_record().unwrap());
        let mut wrong = approval_for(intent);
        wrong.scope = "bounded-agent authorization".to_string();
        let frontier = append_durable(&mut chain, wrong);
        assert!(matches!(
            chain.attest_agent_capability_consent_bound_durable_v1(
                intent,
                &session(),
                &frontier,
                PERSISTENCE_POLICY,
            ),
            Err(AgentConsentAuthorityError::ConsentIntentConflict)
        ));
    }

    #[test]
    fn capability_substitution_under_same_durable_frontier_fails() {
        let approved = intent();
        let (chain, durable_frontier) = approved_chain();
        let mut substituted = approved;
        substituted.capability_digest[0] ^= 1;
        assert!(matches!(
            chain.attest_agent_capability_consent_bound_durable_v1(
                substituted,
                &session(),
                &durable_frontier,
                PERSISTENCE_POLICY,
            ),
            Err(AgentConsentAuthorityError::ConsentIntentConflict)
                | Err(AgentConsentAuthorityError::ConsentRequestMissing)
                | Err(AgentConsentAuthorityError::ConsentApprovalMissing)
        ));
    }

    #[test]
    fn later_revocation_dominates_prior_approval_for_new_issuance() {
        let intent = intent();
        let (mut chain, _approved_frontier) = approved_chain();
        let mut revocation = approval_for(intent);
        revocation.kind = ConsentKind::Revocation;
        revocation.scope.clear();
        let revoked_frontier = append_durable(&mut chain, revocation);
        assert!(matches!(
            chain.attest_agent_capability_consent_bound_durable_v1(
                intent,
                &session(),
                &revoked_frontier,
                PERSISTENCE_POLICY,
            ),
            Err(AgentConsentAuthorityError::ConsentNegated(
                ConsentKind::Revocation
            ))
        ));
    }

    #[test]
    fn approval_without_request_is_rejected() {
        let intent = intent();
        let mut chain = Chain::new(SigningKey::from_bytes(&[3; 32]));
        let frontier = append_durable(&mut chain, approval_for(intent));
        assert!(matches!(
            chain.attest_agent_capability_consent_bound_durable_v1(
                intent,
                &session(),
                &frontier,
                PERSISTENCE_POLICY,
            ),
            Err(AgentConsentAuthorityError::ApprovalWithoutRequest)
        ));
    }

    #[test]
    fn wrong_persistence_policy_cannot_relabel_durable_frontier() {
        let intent = intent();
        let (chain, durable_frontier) = approved_chain();
        assert!(matches!(
            chain.attest_agent_capability_consent_bound_durable_v1(
                intent,
                &session(),
                &durable_frontier,
                [0xD2; 32],
            ),
            Err(AgentConsentAuthorityError::PersistencePolicyMismatch)
        ));
    }

    #[test]
    fn tampered_consent_evidence_breaks_outer_signature_or_recomputed_commitment() {
        let intent = intent();
        let (chain, durable_frontier) = approved_chain();
        let attestation = chain
            .attest_agent_capability_consent_bound_durable_v1(
                intent,
                &session(),
                &durable_frontier,
                PERSISTENCE_POLICY,
            )
            .unwrap();
        let public_key = chain.signing_key.verifying_key().to_bytes();
        let public_key_binding =
            EvidencePublicKeyBinding::new(SignatureSuite::Ed25519Rfc8032, public_key);

        let mut tampered = attestation.clone();
        tampered.consent.approval_entry_hash[0] ^= 1;
        assert!(verify_durable_consent_bound_agent_capability_attestation_v1(
            &tampered,
            &session(),
            &public_key_binding,
            &Ed25519EvidenceSignatureBackend,
            120,
            intent.capability_digest,
            intent.executor_workload_digest,
            intent.authority_epoch,
            intent.prior_checkpoint,
            PERSISTENCE_POLICY,
        )
        .is_err());

        let mut tampered = attestation;
        tampered.consent.consent_presentation_digest[0] ^= 1;
        assert!(matches!(
            verify_durable_consent_bound_agent_capability_attestation_v1(
                &tampered,
                &session(),
                &public_key_binding,
                &Ed25519EvidenceSignatureBackend,
                120,
                intent.capability_digest,
                intent.executor_workload_digest,
                intent.authority_epoch,
                intent.prior_checkpoint,
                PERSISTENCE_POLICY,
            ),
            Err(AgentConsentAuthorityError::ConsentIntentDigestMismatch)
        ));
    }
}
