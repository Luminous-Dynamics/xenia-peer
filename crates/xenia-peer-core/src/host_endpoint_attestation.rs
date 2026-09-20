// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session-bound host endpoint attestation for downstream identity composition.
//!
//! A proof from this module is signed evidence about one exact Xenia host/session
//! tuple. It is not workload, software, device, embodiment, authorization, or
//! safety evidence.

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use xenia_handshake::{
    HANDSHAKE_POLICY_PROFILE, HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN,
    host_identity_fingerprint,
};

use crate::handshake::HandshakeOutcome;

/// Stable evidence schema for Xenia host endpoint proofs.
pub const HOST_ENDPOINT_PROOF_SCHEMA_V1: &str = "xenia-host-endpoint-proof-v1";
/// Domain separator for the canonical statement signed by both identity suites.
pub const HOST_ENDPOINT_PROOF_DOMAIN_V1: &[u8] = b"xenia.host-endpoint-proof.v1\0";

const HOST_ENDPOINT_PROOF_VERSION: u16 = 1;

/// Opaque commitment to a downstream identity-composition challenge.
///
/// Xenia deliberately does not interpret the challenge preimage. The downstream
/// relying party owns semantics such as principal, executor profile, runtime
/// incarnation, and identity requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalCompositionChallengeCommitment([u8; 32]);

impl ExternalCompositionChallengeCommitment {
    /// Construct a non-zero external composition challenge commitment.
    pub fn new(bytes: [u8; 32]) -> Result<Self, HostEndpointProofError> {
        if bytes == [0; 32] {
            return Err(HostEndpointProofError::ZeroCommitment("composition challenge"));
        }
        Ok(Self(bytes))
    }

    /// Return the exact commitment bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Endpoint role asserted by signed host endpoint evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XeniaEndpointRole {
    /// The machine-side Xenia host endpoint.
    Host,
    /// The remote viewer/controller endpoint. V1 host attestation rejects this.
    Viewer,
}

impl XeniaEndpointRole {
    const fn code(self) -> u8 {
        match self {
            Self::Host => 1,
            Self::Viewer => 2,
        }
    }
}

/// Serializable, dual-signed evidence produced by a Xenia host identity.
///
/// Loading this object from bytes never creates a verified live identity result.
/// Call [`verify_host_endpoint_proof`] with independently obtained exact session
/// expectations before using it as an EXEC-ID evidence input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XeniaHostEndpointProofV1 {
    schema: String,
    challenge_commitment: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    negotiated_context_hash: [u8; 32],
    host_identity_fingerprint: [u8; 32],
    endpoint_role: XeniaEndpointRole,
    handshake_policy_profile: String,
    ed25519_public_key: [u8; 32],
    #[serde(with = "BigArray")]
    ml_dsa_public_key: [u8; ML_DSA_65_PK_LEN],
    #[serde(with = "BigArray")]
    ed25519_signature: [u8; 64],
    #[serde(with = "BigArray")]
    ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
}

impl XeniaHostEndpointProofV1 {
    /// Stable evidence schema carried by this proof.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Exact external challenge commitment signed by the host.
    pub const fn challenge_commitment(&self) -> [u8; 32] {
        self.challenge_commitment
    }

    /// Exact canonical handshake transcript hash signed by the host.
    pub const fn handshake_transcript_hash(&self) -> [u8; 32] {
        self.handshake_transcript_hash
    }

    /// Exact negotiated Xenia session-context hash signed by the host.
    pub const fn negotiated_context_hash(&self) -> [u8; 32] {
        self.negotiated_context_hash
    }

    /// Combined Ed25519 + ML-DSA host identity fingerprint.
    pub const fn host_identity_fingerprint(&self) -> [u8; 32] {
        self.host_identity_fingerprint
    }

    /// Endpoint role included in the signed statement.
    pub const fn endpoint_role(&self) -> XeniaEndpointRole {
        self.endpoint_role
    }

    /// Exact handshake policy profile included in the signed statement.
    pub fn handshake_policy_profile(&self) -> &str {
        &self.handshake_policy_profile
    }

    /// Host Ed25519 public key carried by the proof.
    pub const fn ed25519_public_key(&self) -> [u8; 32] {
        self.ed25519_public_key
    }

    /// Host ML-DSA-65 public key carried by the proof.
    pub const fn ml_dsa_public_key(&self) -> &[u8; ML_DSA_65_PK_LEN] {
        &self.ml_dsa_public_key
    }

    /// Canonical bytes signed by both host identity algorithms.
    pub fn canonical_statement(&self) -> Result<Vec<u8>, HostEndpointProofError> {
        canonical_statement(
            &self.schema,
            self.challenge_commitment,
            self.handshake_transcript_hash,
            self.negotiated_context_hash,
            self.host_identity_fingerprint,
            self.endpoint_role,
            &self.handshake_policy_profile,
            self.ed25519_public_key,
            &self.ml_dsa_public_key,
        )
    }

    fn evidence_commitment(&self) -> Result<[u8; 32], HostEndpointProofError> {
        let statement = self.canonical_statement()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"xenia-host-endpoint-proof-evidence-v1\0");
        hasher.update(&statement);
        hasher.update(&self.ed25519_signature);
        hasher.update(&self.ml_dsa_signature);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Exact live-session values an independent verifier expects this proof to name.
///
/// These values must come from the caller's trusted/current Xenia session view,
/// not from copying fields out of the proof under verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedHostEndpointSessionV1 {
    handshake_transcript_hash: [u8; 32],
    negotiated_context_hash: [u8; 32],
    host_identity_fingerprint: [u8; 32],
}

impl ExpectedHostEndpointSessionV1 {
    /// Construct exact expected session values, rejecting placeholder digests.
    pub fn new(
        handshake_transcript_hash: [u8; 32],
        negotiated_context_hash: [u8; 32],
        host_identity_fingerprint: [u8; 32],
    ) -> Result<Self, HostEndpointProofError> {
        reject_zero("handshake transcript", handshake_transcript_hash)?;
        reject_zero("negotiated context", negotiated_context_hash)?;
        reject_zero("host identity fingerprint", host_identity_fingerprint)?;
        Ok(Self {
            handshake_transcript_hash,
            negotiated_context_hash,
            host_identity_fingerprint,
        })
    }

    /// Build expectations from an independently trusted/current handshake result.
    pub fn from_outcome(outcome: &HandshakeOutcome) -> Result<Self, HostEndpointProofError> {
        let negotiated_context_hash = outcome
            .negotiated_context_hash
            .ok_or(HostEndpointProofError::MissingNegotiatedContext)?;
        Self::new(
            outcome.transcript_hash,
            negotiated_context_hash,
            outcome.host_identity_fingerprint,
        )
    }
}

/// Opaque verifier-owned result proving one proof matched one exact expected Xenia
/// host/session tuple and both host signatures verified.
///
/// This type is deliberately neither serializable nor publicly constructible.
/// It is an identity evidence result only; it grants no Symthaea/Mycelix action
/// authority.
#[derive(Debug)]
pub struct VerifiedXeniaHostEndpointV1 {
    challenge_commitment: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    negotiated_context_hash: [u8; 32],
    host_identity_fingerprint: [u8; 32],
    evidence_commitment: [u8; 32],
}

impl VerifiedXeniaHostEndpointV1 {
    /// Exact external challenge commitment authenticated by the host.
    pub const fn challenge_commitment(&self) -> [u8; 32] {
        self.challenge_commitment
    }

    /// Exact authenticated handshake transcript hash.
    pub const fn handshake_transcript_hash(&self) -> [u8; 32] {
        self.handshake_transcript_hash
    }

    /// Exact authenticated negotiated-session-context hash.
    pub const fn negotiated_context_hash(&self) -> [u8; 32] {
        self.negotiated_context_hash
    }

    /// Exact authenticated host signing-identity fingerprint.
    pub const fn host_identity_fingerprint(&self) -> [u8; 32] {
        self.host_identity_fingerprint
    }

    /// Content commitment over the exact proof statement and both signatures.
    pub const fn evidence_commitment(&self) -> [u8; 32] {
        self.evidence_commitment
    }
}

/// Create dual-signed host endpoint evidence from one manager/outcome pair.
///
/// The function requires the signing manager identity to equal the host identity
/// fingerprint carried by the outcome and requires a negotiated session context.
/// A caller still must independently establish that the supplied `HandshakeOutcome`
/// is its trusted/current live session view; downstream verification therefore also
/// requires [`ExpectedHostEndpointSessionV1`].
pub fn attest_host_endpoint(
    manager: &HandshakeManager,
    outcome: &HandshakeOutcome,
    challenge_commitment: ExternalCompositionChallengeCommitment,
) -> Result<XeniaHostEndpointProofV1, HostEndpointProofError> {
    let negotiated_context_hash = outcome
        .negotiated_context_hash
        .ok_or(HostEndpointProofError::MissingNegotiatedContext)?;
    reject_zero("handshake transcript", outcome.transcript_hash)?;
    reject_zero("negotiated context", negotiated_context_hash)?;
    reject_zero("host identity fingerprint", outcome.host_identity_fingerprint)?;

    let manager_fingerprint = manager.identity_fingerprint();
    if manager_fingerprint != outcome.host_identity_fingerprint {
        return Err(HostEndpointProofError::ManagerOutcomeIdentityMismatch);
    }

    let ed25519_public_key = manager.identity_public_key_bytes();
    let ml_dsa_public_key = manager.ml_dsa_public_key_bytes();
    let mut proof = XeniaHostEndpointProofV1 {
        schema: HOST_ENDPOINT_PROOF_SCHEMA_V1.to_string(),
        challenge_commitment: *challenge_commitment.as_bytes(),
        handshake_transcript_hash: outcome.transcript_hash,
        negotiated_context_hash,
        host_identity_fingerprint: outcome.host_identity_fingerprint,
        endpoint_role: XeniaEndpointRole::Host,
        handshake_policy_profile: HANDSHAKE_POLICY_PROFILE.to_string(),
        ed25519_public_key,
        ml_dsa_public_key,
        ed25519_signature: [0; 64],
        ml_dsa_signature: [0; ML_DSA_65_SIG_LEN],
    };
    let statement = proof.canonical_statement()?;
    proof.ed25519_signature = manager.sign(&statement).to_bytes();
    proof.ml_dsa_signature = manager.sign_ml_dsa(&statement);
    Ok(proof)
}

/// Verify dual-signed host endpoint evidence against an exact external challenge
/// and an independently obtained expected live Xenia session tuple.
pub fn verify_host_endpoint_proof(
    proof: &XeniaHostEndpointProofV1,
    expected_challenge: ExternalCompositionChallengeCommitment,
    expected_session: ExpectedHostEndpointSessionV1,
) -> Result<VerifiedXeniaHostEndpointV1, HostEndpointProofError> {
    if proof.schema != HOST_ENDPOINT_PROOF_SCHEMA_V1 {
        return Err(HostEndpointProofError::SchemaMismatch);
    }
    if proof.challenge_commitment != *expected_challenge.as_bytes() {
        return Err(HostEndpointProofError::ChallengeMismatch);
    }
    if proof.endpoint_role != XeniaEndpointRole::Host {
        return Err(HostEndpointProofError::WrongEndpointRole);
    }
    if proof.handshake_policy_profile != HANDSHAKE_POLICY_PROFILE {
        return Err(HostEndpointProofError::PolicyProfileMismatch);
    }
    reject_zero("handshake transcript", proof.handshake_transcript_hash)?;
    reject_zero("negotiated context", proof.negotiated_context_hash)?;
    reject_zero("host identity fingerprint", proof.host_identity_fingerprint)?;

    if proof.handshake_transcript_hash != expected_session.handshake_transcript_hash {
        return Err(HostEndpointProofError::TranscriptMismatch);
    }
    if proof.negotiated_context_hash != expected_session.negotiated_context_hash {
        return Err(HostEndpointProofError::NegotiatedContextMismatch);
    }
    if proof.host_identity_fingerprint != expected_session.host_identity_fingerprint {
        return Err(HostEndpointProofError::HostIdentityMismatch);
    }

    let recomputed_fingerprint =
        host_identity_fingerprint(&proof.ed25519_public_key, &proof.ml_dsa_public_key);
    if recomputed_fingerprint != proof.host_identity_fingerprint {
        return Err(HostEndpointProofError::HostIdentityMismatch);
    }

    let statement = proof.canonical_statement()?;
    let ed25519_key = HandshakeManager::parse_peer_public_key(&proof.ed25519_public_key)
        .map_err(|_| HostEndpointProofError::InvalidEd25519PublicKey)?;
    let ed25519_signature = Signature::from_bytes(&proof.ed25519_signature);
    HandshakeManager::verify(&ed25519_key, &statement, &ed25519_signature)
        .map_err(|_| HostEndpointProofError::Ed25519SignatureInvalid)?;
    HandshakeManager::verify_ml_dsa(
        &proof.ml_dsa_public_key,
        &statement,
        &proof.ml_dsa_signature,
    )
    .map_err(|_| HostEndpointProofError::MlDsaSignatureInvalid)?;

    Ok(VerifiedXeniaHostEndpointV1 {
        challenge_commitment: proof.challenge_commitment,
        handshake_transcript_hash: proof.handshake_transcript_hash,
        negotiated_context_hash: proof.negotiated_context_hash,
        host_identity_fingerprint: proof.host_identity_fingerprint,
        evidence_commitment: proof.evidence_commitment()?,
    })
}

fn canonical_statement(
    schema: &str,
    challenge_commitment: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    negotiated_context_hash: [u8; 32],
    host_identity_fingerprint: [u8; 32],
    endpoint_role: XeniaEndpointRole,
    handshake_policy_profile: &str,
    ed25519_public_key: [u8; 32],
    ml_dsa_public_key: &[u8; ML_DSA_65_PK_LEN],
) -> Result<Vec<u8>, HostEndpointProofError> {
    if schema.len() > u16::MAX as usize || handshake_policy_profile.len() > u16::MAX as usize {
        return Err(HostEndpointProofError::CanonicalEncoding);
    }
    let mut out = Vec::with_capacity(256 + ML_DSA_65_PK_LEN);
    out.extend_from_slice(HOST_ENDPOINT_PROOF_DOMAIN_V1);
    out.extend_from_slice(&HOST_ENDPOINT_PROOF_VERSION.to_be_bytes());
    push_text(&mut out, schema)?;
    out.extend_from_slice(&challenge_commitment);
    out.extend_from_slice(&handshake_transcript_hash);
    out.extend_from_slice(&negotiated_context_hash);
    out.extend_from_slice(&host_identity_fingerprint);
    out.push(endpoint_role.code());
    push_text(&mut out, handshake_policy_profile)?;
    out.extend_from_slice(&ed25519_public_key);
    out.extend_from_slice(&(ML_DSA_65_PK_LEN as u32).to_be_bytes());
    out.extend_from_slice(ml_dsa_public_key);
    Ok(out)
}

fn push_text(out: &mut Vec<u8>, value: &str) -> Result<(), HostEndpointProofError> {
    let length = u16::try_from(value.len()).map_err(|_| HostEndpointProofError::CanonicalEncoding)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn reject_zero(field: &'static str, value: [u8; 32]) -> Result<(), HostEndpointProofError> {
    if value == [0; 32] {
        Err(HostEndpointProofError::ZeroCommitment(field))
    } else {
        Ok(())
    }
}

/// Fail-closed errors for host endpoint attestation creation and verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostEndpointProofError {
    /// A required fixed-width commitment was all-zero.
    #[error("{0} must not be all-zero")]
    ZeroCommitment(&'static str),
    /// The completed handshake did not bind a negotiated session context.
    #[error("host endpoint attestation requires a negotiated session context")]
    MissingNegotiatedContext,
    /// The signing manager identity does not equal the host identity in the outcome.
    #[error("handshake manager identity does not match handshake outcome host identity")]
    ManagerOutcomeIdentityMismatch,
    /// Evidence schema is not the exact V1 schema.
    #[error("host endpoint proof schema mismatch")]
    SchemaMismatch,
    /// The proof is bound to a different external composition challenge.
    #[error("host endpoint proof challenge mismatch")]
    ChallengeMismatch,
    /// A Viewer proof was presented where Host evidence is required.
    #[error("host endpoint proof has the wrong endpoint role")]
    WrongEndpointRole,
    /// The proof declares a different handshake security profile.
    #[error("host endpoint proof handshake policy profile mismatch")]
    PolicyProfileMismatch,
    /// The proof transcript does not equal the independently expected live transcript.
    #[error("host endpoint proof transcript does not match expected live session")]
    TranscriptMismatch,
    /// The proof negotiated context does not equal the independently expected context.
    #[error("host endpoint proof context does not match expected live session")]
    NegotiatedContextMismatch,
    /// The proof host identity does not equal or reconstruct to the expected identity.
    #[error("host endpoint proof host identity mismatch")]
    HostIdentityMismatch,
    /// The Ed25519 public key could not be parsed.
    #[error("invalid Ed25519 public key in host endpoint proof")]
    InvalidEd25519PublicKey,
    /// The Ed25519 signature failed verification.
    #[error("invalid Ed25519 signature in host endpoint proof")]
    Ed25519SignatureInvalid,
    /// The ML-DSA-65 signature failed verification.
    #[error("invalid ML-DSA-65 signature in host endpoint proof")]
    MlDsaSignatureInvalid,
    /// Canonical statement encoding failed.
    #[error("host endpoint proof canonical encoding failed")]
    CanonicalEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_handshake::SessionKeySchedule;

    fn manager(seed: u8) -> HandshakeManager {
        HandshakeManager::from_identity_seeds([seed; 32], [seed.wrapping_add(1); 32])
    }

    fn outcome(manager: &HandshakeManager) -> HandshakeOutcome {
        HandshakeOutcome {
            session_key: [0x10; 32],
            transcript_hash: [0x11; 32],
            key_schedule: SessionKeySchedule {
                aead: [0x20; 32],
                control: [0x21; 32],
                video: [0x22; 32],
                audio: [0x23; 32],
                telemetry: [0x24; 32],
                rekey: [0x25; 32],
                context: [0x26; 32],
            },
            negotiated_context_hash: Some([0x12; 32]),
            host_identity_fingerprint: manager.identity_fingerprint(),
        }
    }

    fn challenge(byte: u8) -> ExternalCompositionChallengeCommitment {
        ExternalCompositionChallengeCommitment::new([byte; 32]).unwrap()
    }

    #[test]
    fn exact_manager_outcome_challenge_round_trip_verifies() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let proof = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        let verified = verify_host_endpoint_proof(
            &proof,
            challenge(0x31),
            ExpectedHostEndpointSessionV1::from_outcome(&outcome).unwrap(),
        )
        .unwrap();

        assert_eq!(verified.challenge_commitment(), [0x31; 32]);
        assert_eq!(verified.handshake_transcript_hash(), outcome.transcript_hash);
        assert_eq!(
            verified.negotiated_context_hash(),
            outcome.negotiated_context_hash.unwrap()
        );
        assert_eq!(
            verified.host_identity_fingerprint(),
            outcome.host_identity_fingerprint
        );
        assert_ne!(verified.evidence_commitment(), [0; 32]);
    }

    #[test]
    fn wrong_composition_challenge_rejects() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let proof = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        let error = verify_host_endpoint_proof(
            &proof,
            challenge(0x32),
            ExpectedHostEndpointSessionV1::from_outcome(&outcome).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error, HostEndpointProofError::ChallengeMismatch);
    }

    #[test]
    fn proof_replay_against_different_live_session_rejects() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let proof = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        let expected = ExpectedHostEndpointSessionV1::new(
            [0x41; 32],
            outcome.negotiated_context_hash.unwrap(),
            outcome.host_identity_fingerprint,
        )
        .unwrap();
        let error = verify_host_endpoint_proof(&proof, challenge(0x31), expected).unwrap_err();
        assert_eq!(error, HostEndpointProofError::TranscriptMismatch);
    }

    #[test]
    fn swapped_negotiated_context_rejects() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let proof = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        let expected = ExpectedHostEndpointSessionV1::new(
            outcome.transcript_hash,
            [0x42; 32],
            outcome.host_identity_fingerprint,
        )
        .unwrap();
        let error = verify_host_endpoint_proof(&proof, challenge(0x31), expected).unwrap_err();
        assert_eq!(error, HostEndpointProofError::NegotiatedContextMismatch);
    }

    #[test]
    fn unrelated_manager_cannot_attest_an_outcome() {
        let manager_a = manager(1);
        let manager_b = manager(9);
        let outcome = outcome(&manager_a);
        let error = attest_host_endpoint(&manager_b, &outcome, challenge(0x31)).unwrap_err();
        assert_eq!(error, HostEndpointProofError::ManagerOutcomeIdentityMismatch);
    }

    #[test]
    fn ed25519_signature_mutation_rejects() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let mut proof = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        proof.ed25519_signature[0] ^= 1;
        let error = verify_host_endpoint_proof(
            &proof,
            challenge(0x31),
            ExpectedHostEndpointSessionV1::from_outcome(&outcome).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error, HostEndpointProofError::Ed25519SignatureInvalid);
    }

    #[test]
    fn ml_dsa_signature_mutation_rejects() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let mut proof = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        proof.ml_dsa_signature[0] ^= 1;
        let error = verify_host_endpoint_proof(
            &proof,
            challenge(0x31),
            ExpectedHostEndpointSessionV1::from_outcome(&outcome).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error, HostEndpointProofError::MlDsaSignatureInvalid);
    }

    #[test]
    fn viewer_role_and_policy_profile_substitution_reject() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let mut viewer = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        viewer.endpoint_role = XeniaEndpointRole::Viewer;
        assert_eq!(
            verify_host_endpoint_proof(
                &viewer,
                challenge(0x31),
                ExpectedHostEndpointSessionV1::from_outcome(&outcome).unwrap(),
            )
            .unwrap_err(),
            HostEndpointProofError::WrongEndpointRole
        );

        let mut policy = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        policy.handshake_policy_profile = "hybrid-pre-pqc-v1".into();
        assert_eq!(
            verify_host_endpoint_proof(
                &policy,
                challenge(0x31),
                ExpectedHostEndpointSessionV1::from_outcome(&outcome).unwrap(),
            )
            .unwrap_err(),
            HostEndpointProofError::PolicyProfileMismatch
        );
    }

    #[test]
    fn missing_context_and_zero_challenge_fail_closed() {
        assert_eq!(
            ExternalCompositionChallengeCommitment::new([0; 32]).unwrap_err(),
            HostEndpointProofError::ZeroCommitment("composition challenge")
        );

        let manager = manager(1);
        let mut outcome = outcome(&manager);
        outcome.negotiated_context_hash = None;
        assert_eq!(
            attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap_err(),
            HostEndpointProofError::MissingNegotiatedContext
        );
    }

    #[test]
    fn serialized_evidence_requires_reverification() {
        let manager = manager(1);
        let outcome = outcome(&manager);
        let proof = attest_host_endpoint(&manager, &outcome, challenge(0x31)).unwrap();
        let bytes = bincode::serialize(&proof).unwrap();
        let restored: XeniaHostEndpointProofV1 = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored, proof);
        verify_host_endpoint_proof(
            &restored,
            challenge(0x31),
            ExpectedHostEndpointSessionV1::from_outcome(&outcome).unwrap(),
        )
        .unwrap();
    }
}
