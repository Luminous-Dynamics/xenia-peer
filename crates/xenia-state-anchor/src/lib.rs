// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Generic, purpose-separated signed state anchors for cross-system continuity.
//!
//! This crate is intentionally separate from `xenia-ledger`'s consent-event schema. It reuses
//! Xenia's algorithm-tagged evidence-signature verification boundary while giving external state
//! commitments their own domain, schema, continuity rules, and retained-checkpoint shape.
//!
//! Signed anchors prove authenticated continuity of supplied artifacts. Rollback resistance still
//! requires an independent holder to retain the latest anchor/checkpoint (or a monotonic TPM/TEE /
//! witness service). A signer that can rewrite its own local files is not, by itself, a rollback
//! anchor.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_ledger::{
    EvidenceSignatureBackend, EvidenceSignatureBackendError, SignatureEnvelope,
    SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema for [`StateAnchorRecord`].
pub const STATE_ANCHOR_SCHEMA: &str = "xenia-state-anchor-v1";
/// Stable schema for privacy-reduced retained [`StateAnchorCheckpoint`] artifacts.
pub const STATE_ANCHOR_CHECKPOINT_SCHEMA: &str = "xenia-state-anchor-checkpoint-v1";
const ANCHOR_MESSAGE_DOMAIN: &[u8] = b"xenia:state-anchor:v1\0";
const CHECKPOINT_MESSAGE_DOMAIN: &[u8] = b"xenia:state-anchor-checkpoint:v1\0";
const ANCHOR_FINGERPRINT_DOMAIN: &[u8] = b"xenia:state-anchor-fingerprint:v1\0";
const TARGET_FINGERPRINT_DOMAIN: &[u8] = b"xenia:state-anchor-target:v1\0";
const MAX_NAMESPACE_BYTES: usize = 256;
const MAX_OBJECT_ID_BYTES: usize = 512;

/// Unsigned semantic payload of one external-state anchor revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAnchorRecord {
    /// Must equal [`STATE_ANCHOR_SCHEMA`].
    pub schema: String,
    /// Domain/purpose namespace, for example `symthaea.episodic-continuity`.
    pub namespace: String,
    /// Opaque relying-system object identifier.
    pub object_id: String,
    /// Strictly monotonic revision. Genesis is revision 1.
    pub revision: u64,
    /// Fingerprint of the exact signed prior anchor. `None` only at revision 1.
    pub previous_anchor_fingerprint: Option<[u8; 32]>,
    /// Opaque commitment to relying-system state.
    pub state_commitment: [u8; 32],
    /// Optional opaque commitment to policy/trust context used by the relying system.
    pub policy_commitment: Option<[u8; 32]>,
    /// Unix seconds recorded by the signer.
    pub timestamp_unix_secs: u64,
}

impl StateAnchorRecord {
    /// Validate schema, identifiers, revision shape, and non-placeholder commitments.
    pub fn validate(&self) -> Result<(), StateAnchorError> {
        if self.schema != STATE_ANCHOR_SCHEMA {
            return Err(StateAnchorError::UnsupportedSchema(self.schema.clone()));
        }
        validate_text("namespace", &self.namespace, MAX_NAMESPACE_BYTES)?;
        validate_text("object_id", &self.object_id, MAX_OBJECT_ID_BYTES)?;
        if self.revision == 0 {
            return Err(StateAnchorError::ZeroRevision);
        }
        if self.state_commitment == [0; 32] {
            return Err(StateAnchorError::ZeroCommitment("state_commitment"));
        }
        if self.policy_commitment == Some([0; 32]) {
            return Err(StateAnchorError::ZeroCommitment("policy_commitment"));
        }
        match (self.revision, self.previous_anchor_fingerprint) {
            (1, None) => {}
            (1, Some(_)) => return Err(StateAnchorError::GenesisHasPrevious),
            (_, None) => return Err(StateAnchorError::MissingPrevious),
            (_, Some([0; 32])) => {
                return Err(StateAnchorError::ZeroCommitment(
                    "previous_anchor_fingerprint",
                ));
            }
            (_, Some(_)) => {}
        }
        Ok(())
    }

    /// Build the exact domain-separated message signed by a selected suite/key.
    ///
    /// The signature suite and signer public key are covered by the signature itself. This avoids
    /// relying solely on verifier configuration to prevent algorithm/key-context substitution.
    pub fn signing_message(
        &self,
        suite: SignatureSuite,
        signer_public_key: &[u8],
    ) -> Result<Vec<u8>, StateAnchorError> {
        self.validate()?;
        validate_public_key_shape(suite, signer_public_key)?;
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(ANCHOR_MESSAGE_DOMAIN);
        push_text(&mut out, &self.schema);
        push_text(&mut out, &self.namespace);
        push_text(&mut out, &self.object_id);
        out.extend_from_slice(&self.revision.to_be_bytes());
        match self.previous_anchor_fingerprint {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                out.extend_from_slice(&value);
            }
        }
        out.extend_from_slice(&self.state_commitment);
        match self.policy_commitment {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                out.extend_from_slice(&value);
            }
        }
        out.extend_from_slice(&self.timestamp_unix_secs.to_be_bytes());
        push_text(&mut out, suite.stable_label());
        push_bytes(&mut out, signer_public_key);
        Ok(out)
    }

    /// Stable privacy-reduced fingerprint of the namespace/object pair.
    pub fn target_fingerprint(&self) -> Result<[u8; 32], StateAnchorError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(TARGET_FINGERPRINT_DOMAIN);
        hash_text(&mut hasher, &self.namespace);
        hash_text(&mut hasher, &self.object_id);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Algorithm-tagged signed state-anchor artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStateAnchor {
    /// Signed semantic state.
    pub record: StateAnchorRecord,
    /// Raw signer public-key bytes for the selected signature suite.
    pub signer_public_key: Vec<u8>,
    /// Algorithm-tagged signature over the record plus suite/key context.
    pub signature: SignatureEnvelope,
}

impl SignedStateAnchor {
    /// Validate local artifact shape only. This does not establish key trust or verify a signature.
    pub fn validate_shape(&self) -> Result<SignatureSuite, StateAnchorError> {
        self.record.validate()?;
        let suite = self.signature.validate_shape()?;
        validate_public_key_shape(suite, &self.signer_public_key)?;
        Ok(suite)
    }

    /// Fingerprint the exact signed artifact, including suite, key, and signature bytes.
    ///
    /// Security-sensitive callers should first verify the anchor against an independently trusted
    /// key. The fingerprint is an object commitment, not signature verification.
    pub fn fingerprint(&self) -> Result<[u8; 32], StateAnchorError> {
        let suite = self.validate_shape()?;
        let message = self
            .record
            .signing_message(suite, &self.signer_public_key)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(ANCHOR_FINGERPRINT_DOMAIN);
        hasher.update(&(message.len() as u64).to_be_bytes());
        hasher.update(&message);
        hash_bytes(&mut hasher, self.signature.algorithm.as_bytes());
        hash_bytes(&mut hasher, &self.signature.signature);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Signing boundary for operator-agent, HSM, TPM, or future PQC implementations.
pub trait StateAnchorSigner {
    /// Signature suite emitted by this signer.
    fn suite(&self) -> SignatureSuite;
    /// Public-key bytes corresponding to the signing key.
    fn public_key(&self) -> Vec<u8>;
    /// Sign the supplied domain-separated message.
    fn sign_state_anchor(&self, message: &[u8]) -> Result<SignatureEnvelope, String>;
}

/// Sign one validated state-anchor record.
pub fn sign_state_anchor<S: StateAnchorSigner>(
    record: StateAnchorRecord,
    signer: &S,
) -> Result<SignedStateAnchor, StateAnchorError> {
    let suite = signer.suite();
    let signer_public_key = signer.public_key();
    let message = record.signing_message(suite, &signer_public_key)?;
    let signature = signer
        .sign_state_anchor(&message)
        .map_err(StateAnchorError::Signer)?;
    let envelope_suite = signature.validate_shape()?;
    if envelope_suite != suite {
        return Err(StateAnchorError::SignerSuiteMismatch(suite, envelope_suite));
    }
    let signed = SignedStateAnchor {
        record,
        signer_public_key,
        signature,
    };
    signed.validate_shape()?;
    Ok(signed)
}

/// Verify one signed anchor against an independently trusted key and signature backend.
pub fn verify_anchor<B: EvidenceSignatureBackend>(
    anchor: &SignedStateAnchor,
    trusted_public_key: &[u8],
    backend: &B,
) -> Result<(), StateAnchorVerifyError> {
    let suite = anchor.validate_shape()?;
    if suite != backend.suite() {
        return Err(StateAnchorVerifyError::BackendSuiteMismatch(
            suite,
            backend.suite(),
        ));
    }
    if anchor.signer_public_key != trusted_public_key {
        return Err(StateAnchorVerifyError::TrustedKeyMismatch);
    }
    backend.verify_signature(
        trusted_public_key,
        &anchor.record.signing_message(suite, trusted_public_key)?,
        &anchor.signature.signature,
    )?;
    Ok(())
}

/// Verify a strict N -> N+1 transition under one pre-trusted key.
///
/// Key changes are deliberately not implicit. A future adapter should require Xenia's explicit
/// key-transition evidence before changing `trusted_public_key`.
pub fn verify_direct_successor<B: EvidenceSignatureBackend>(
    previous: &SignedStateAnchor,
    candidate: &SignedStateAnchor,
    trusted_public_key: &[u8],
    backend: &B,
) -> Result<(), StateAnchorContinuityError> {
    verify_anchor(previous, trusted_public_key, backend)?;
    verify_anchor(candidate, trusted_public_key, backend)?;
    if previous.record.namespace != candidate.record.namespace
        || previous.record.object_id != candidate.record.object_id
    {
        return Err(StateAnchorContinuityError::TargetChanged);
    }
    let expected_revision = previous
        .record
        .revision
        .checked_add(1)
        .ok_or(StateAnchorContinuityError::RevisionOverflow)?;
    if candidate.record.revision != expected_revision {
        return Err(StateAnchorContinuityError::NotDirectSuccessor(
            previous.record.revision,
            candidate.record.revision,
        ));
    }
    if candidate.record.previous_anchor_fingerprint != Some(previous.fingerprint()?) {
        return Err(StateAnchorContinuityError::PreviousFingerprintMismatch);
    }
    if candidate.record.timestamp_unix_secs < previous.record.timestamp_unix_secs {
        return Err(StateAnchorContinuityError::TimestampRegressed(
            previous.record.timestamp_unix_secs,
            candidate.record.timestamp_unix_secs,
        ));
    }
    Ok(())
}

/// Verify every direct successor in an anchor suffix.
pub fn verify_extension<B: EvidenceSignatureBackend>(
    retained: &SignedStateAnchor,
    suffix: &[SignedStateAnchor],
    trusted_public_key: &[u8],
    backend: &B,
) -> Result<(), StateAnchorContinuityError> {
    verify_anchor(retained, trusted_public_key, backend)?;
    let mut previous = retained;
    for candidate in suffix {
        verify_direct_successor(previous, candidate, trusted_public_key, backend)?;
        previous = candidate;
    }
    Ok(())
}

/// Freshness policy for signed anchors/checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateAnchorFreshnessPolicy {
    /// Maximum accepted age, or `None` for archival acceptance.
    pub max_age_secs: Option<u64>,
    /// Maximum positive clock skew accepted from the signer.
    pub max_future_skew_secs: u64,
}

impl Default for StateAnchorFreshnessPolicy {
    fn default() -> Self {
        Self {
            max_age_secs: None,
            max_future_skew_secs: 300,
        }
    }
}

/// Verify signature/key plus host-local freshness policy.
pub fn verify_anchor_freshness<B: EvidenceSignatureBackend>(
    anchor: &SignedStateAnchor,
    trusted_public_key: &[u8],
    backend: &B,
    now_unix_secs: u64,
    policy: StateAnchorFreshnessPolicy,
) -> Result<(), StateAnchorContinuityError> {
    verify_anchor(anchor, trusted_public_key, backend)?;
    if anchor.record.timestamp_unix_secs
        > now_unix_secs.saturating_add(policy.max_future_skew_secs)
    {
        return Err(StateAnchorContinuityError::AnchorFromFuture(
            anchor.record.timestamp_unix_secs,
            now_unix_secs,
            policy.max_future_skew_secs,
        ));
    }
    if let Some(maximum_age) = policy.max_age_secs {
        let age = now_unix_secs.saturating_sub(anchor.record.timestamp_unix_secs);
        if age > maximum_age {
            return Err(StateAnchorContinuityError::AnchorTooOld(age, maximum_age));
        }
    }
    Ok(())
}

/// Privacy-reduced retained checkpoint for one signed anchor.
///
/// It omits namespace/object/state commitments. `target_fingerprint` prevents replay of the
/// retained checkpoint beside a different relying-system target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAnchorCheckpoint {
    /// Must equal [`STATE_ANCHOR_CHECKPOINT_SCHEMA`].
    pub schema: String,
    /// Revision of the exact anchor retained by this checkpoint.
    pub revision: u64,
    /// Fingerprint of the exact signed anchor artifact.
    pub anchor_fingerprint: [u8; 32],
    /// Privacy-reduced fingerprint of namespace/object.
    pub target_fingerprint: [u8; 32],
    /// Signer public-key bytes.
    pub signer_public_key: Vec<u8>,
    /// Unix seconds this checkpoint was produced.
    pub timestamp_unix_secs: u64,
    /// Algorithm-tagged signature over all preceding checkpoint fields plus suite/key context.
    pub signature: SignatureEnvelope,
}

impl StateAnchorCheckpoint {
    /// Validate shape and build the exact checkpoint signing message.
    pub fn signing_message(&self) -> Result<Vec<u8>, StateAnchorError> {
        let suite = self.signature.validate_shape()?;
        checkpoint_message(
            &self.schema,
            self.revision,
            self.anchor_fingerprint,
            self.target_fingerprint,
            &self.signer_public_key,
            self.timestamp_unix_secs,
            suite,
        )
    }
}

/// Create a signed privacy-reduced checkpoint using the same verified signer identity as `anchor`.
///
/// The source anchor is cryptographically verified before the checkpoint is issued. This prevents
/// an otherwise-valid signer from accidentally countersigning the fingerprint of an invalid anchor.
pub fn sign_anchor_checkpoint<S: StateAnchorSigner, B: EvidenceSignatureBackend>(
    anchor: &SignedStateAnchor,
    signer: &S,
    backend: &B,
    timestamp_unix_secs: u64,
) -> Result<StateAnchorCheckpoint, StateAnchorError> {
    let suite = signer.suite();
    let signer_public_key = signer.public_key();
    if suite != backend.suite() {
        return Err(StateAnchorError::SignerSuiteMismatch(suite, backend.suite()));
    }
    verify_anchor(anchor, &signer_public_key, backend)
        .map_err(|_| StateAnchorError::CheckpointSourceVerificationFailed)?;

    let schema = STATE_ANCHOR_CHECKPOINT_SCHEMA.to_string();
    let anchor_fingerprint = anchor.fingerprint()?;
    let target_fingerprint = anchor.record.target_fingerprint()?;
    let message = checkpoint_message(
        &schema,
        anchor.record.revision,
        anchor_fingerprint,
        target_fingerprint,
        &signer_public_key,
        timestamp_unix_secs,
        suite,
    )?;
    let signature = signer
        .sign_state_anchor(&message)
        .map_err(StateAnchorError::Signer)?;
    let envelope_suite = signature.validate_shape()?;
    if envelope_suite != suite {
        return Err(StateAnchorError::SignerSuiteMismatch(suite, envelope_suite));
    }
    let checkpoint = StateAnchorCheckpoint {
        schema,
        revision: anchor.record.revision,
        anchor_fingerprint,
        target_fingerprint,
        signer_public_key,
        timestamp_unix_secs,
        signature,
    };
    checkpoint.signing_message()?;
    Ok(checkpoint)
}

/// Verify a retained checkpoint under an independently trusted key.
pub fn verify_anchor_checkpoint<B: EvidenceSignatureBackend>(
    checkpoint: &StateAnchorCheckpoint,
    trusted_public_key: &[u8],
    backend: &B,
) -> Result<(), StateAnchorVerifyError> {
    if checkpoint.signer_public_key != trusted_public_key {
        return Err(StateAnchorVerifyError::TrustedKeyMismatch);
    }
    let suite = checkpoint.signature.validate_shape()?;
    if suite != backend.suite() {
        return Err(StateAnchorVerifyError::BackendSuiteMismatch(
            suite,
            backend.suite(),
        ));
    }
    backend.verify_signature(
        trusted_public_key,
        &checkpoint.signing_message()?,
        &checkpoint.signature.signature,
    )?;
    Ok(())
}

/// Verify a direct candidate successor using only a retained privacy-reduced checkpoint.
pub fn verify_successor_from_checkpoint<B: EvidenceSignatureBackend>(
    retained: &StateAnchorCheckpoint,
    candidate: &SignedStateAnchor,
    trusted_public_key: &[u8],
    backend: &B,
) -> Result<(), StateAnchorContinuityError> {
    verify_anchor_checkpoint(retained, trusted_public_key, backend)?;
    verify_anchor(candidate, trusted_public_key, backend)?;
    let expected_revision = retained
        .revision
        .checked_add(1)
        .ok_or(StateAnchorContinuityError::RevisionOverflow)?;
    if candidate.record.revision != expected_revision {
        return Err(StateAnchorContinuityError::NotDirectSuccessor(
            retained.revision,
            candidate.record.revision,
        ));
    }
    if candidate.record.previous_anchor_fingerprint != Some(retained.anchor_fingerprint) {
        return Err(StateAnchorContinuityError::PreviousFingerprintMismatch);
    }
    if candidate.record.target_fingerprint()? != retained.target_fingerprint {
        return Err(StateAnchorContinuityError::TargetChanged);
    }
    if candidate.record.timestamp_unix_secs < retained.timestamp_unix_secs {
        return Err(StateAnchorContinuityError::TimestampRegressed(
            retained.timestamp_unix_secs,
            candidate.record.timestamp_unix_secs,
        ));
    }
    Ok(())
}

fn checkpoint_message(
    schema: &str,
    revision: u64,
    anchor_fingerprint: [u8; 32],
    target_fingerprint: [u8; 32],
    signer_public_key: &[u8],
    timestamp_unix_secs: u64,
    suite: SignatureSuite,
) -> Result<Vec<u8>, StateAnchorError> {
    if schema != STATE_ANCHOR_CHECKPOINT_SCHEMA {
        return Err(StateAnchorError::UnsupportedCheckpointSchema(
            schema.to_string(),
        ));
    }
    if revision == 0 {
        return Err(StateAnchorError::ZeroRevision);
    }
    if anchor_fingerprint == [0; 32] || target_fingerprint == [0; 32] {
        return Err(StateAnchorError::ZeroCommitment("checkpoint_fingerprint"));
    }
    validate_public_key_shape(suite, signer_public_key)?;
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(CHECKPOINT_MESSAGE_DOMAIN);
    push_text(&mut out, schema);
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(&anchor_fingerprint);
    out.extend_from_slice(&target_fingerprint);
    out.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    push_text(&mut out, suite.stable_label());
    push_bytes(&mut out, signer_public_key);
    Ok(out)
}

fn validate_public_key_shape(
    suite: SignatureSuite,
    public_key: &[u8],
) -> Result<(), StateAnchorError> {
    if let Some(expected) = suite.fixed_public_key_len() {
        if public_key.len() != expected {
            return Err(StateAnchorError::BadPublicKeyLength(
                expected,
                public_key.len(),
            ));
        }
    } else if public_key.is_empty() {
        return Err(StateAnchorError::BadPublicKeyLength(1, 0));
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str, max: usize) -> Result<(), StateAnchorError> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.len() > max
        || value.chars().any(char::is_control)
    {
        Err(StateAnchorError::InvalidText(field))
    } else {
        Ok(())
    }
}

fn push_text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn hash_text(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Artifact construction or local-shape error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateAnchorError {
    /// Unknown anchor schema.
    #[error("unsupported state-anchor schema: {0}")]
    UnsupportedSchema(String),
    /// Unknown checkpoint schema.
    #[error("unsupported state-anchor checkpoint schema: {0}")]
    UnsupportedCheckpointSchema(String),
    /// Invalid namespace/object text.
    #[error("invalid state-anchor text field `{0}`")]
    InvalidText(&'static str),
    /// Revision zero is not valid.
    #[error("state-anchor revision must be nonzero")]
    ZeroRevision,
    /// Commitment must not be the all-zero placeholder.
    #[error("state-anchor commitment `{0}` must not be all zero")]
    ZeroCommitment(&'static str),
    /// Genesis must not point to a predecessor.
    #[error("genesis state anchor must not contain a previous fingerprint")]
    GenesisHasPrevious,
    /// Non-genesis records must point to an exact predecessor.
    #[error("non-genesis state anchor is missing previous fingerprint")]
    MissingPrevious,
    /// Public-key length disagreed with the selected suite.
    #[error("state-anchor public-key length mismatch: expected={0}, found={1}")]
    BadPublicKeyLength(usize, usize),
    /// Signing backend failed.
    #[error("state-anchor signer failed: {0}")]
    Signer(String),
    /// Signature envelope suite disagreed with signer/backend declaration.
    #[error("state-anchor signature suite mismatch: expected={0:?}, actual={1:?}")]
    SignerSuiteMismatch(SignatureSuite, SignatureSuite),
    /// A checkpoint source anchor failed cryptographic verification under the checkpoint signer.
    #[error("state-anchor checkpoint source failed cryptographic verification")]
    CheckpointSourceVerificationFailed,
    /// Signature-envelope shape failed validation.
    #[error(transparent)]
    SignatureEnvelope(#[from] SignatureEnvelopeError),
}

/// Signature/key verification error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateAnchorVerifyError {
    /// Local artifact validation failed.
    #[error(transparent)]
    Anchor(#[from] StateAnchorError),
    /// Signature suite disagreed with the selected verifier backend.
    #[error("state-anchor envelope suite {0:?} disagrees with verifier backend {1:?}")]
    BackendSuiteMismatch(SignatureSuite, SignatureSuite),
    /// Embedded public key differed from the independently trusted key.
    #[error("state-anchor signer public key does not match trusted key")]
    TrustedKeyMismatch,
    /// Cryptographic verification failed.
    #[error(transparent)]
    Signature(#[from] EvidenceSignatureBackendError),
}

/// Continuity or freshness verification error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateAnchorContinuityError {
    /// Signature/key verification failed.
    #[error(transparent)]
    Verify(#[from] StateAnchorVerifyError),
    /// Anchor artifact shape failed while recomputing a predecessor fingerprint.
    #[error(transparent)]
    Anchor(#[from] StateAnchorError),
    /// Namespace/object changed across continuity.
    #[error("state-anchor target changed")]
    TargetChanged,
    /// Candidate was not the exact next revision.
    #[error("state-anchor is not a direct successor: previous={0}, candidate={1}")]
    NotDirectSuccessor(u64, u64),
    /// Revision increment overflowed.
    #[error("state-anchor revision overflow")]
    RevisionOverflow,
    /// Candidate did not bind the exact retained signed predecessor.
    #[error("state-anchor previous fingerprint mismatch")]
    PreviousFingerprintMismatch,
    /// Signed timestamp moved backward.
    #[error("state-anchor timestamp regressed from {0} to {1}")]
    TimestampRegressed(u64, u64),
    /// Anchor timestamp exceeded configured future skew.
    #[error("state anchor timestamp {0} exceeds now {1} plus allowed skew {2}")]
    AnchorFromFuture(u64, u64, u64),
    /// Anchor exceeded configured maximum age.
    #[error("state anchor age {0} seconds exceeds maximum accepted age {1}")]
    AnchorTooOld(u64, u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use rand_core::OsRng;
    use xenia_ledger::Ed25519EvidenceSignatureBackend;

    struct EdSigner(SigningKey);

    impl StateAnchorSigner for EdSigner {
        fn suite(&self) -> SignatureSuite {
            SignatureSuite::Ed25519Rfc8032
        }

        fn public_key(&self) -> Vec<u8> {
            self.0.verifying_key().to_bytes().to_vec()
        }

        fn sign_state_anchor(&self, message: &[u8]) -> Result<SignatureEnvelope, String> {
            Ok(SignatureEnvelope::new(
                SignatureSuite::Ed25519Rfc8032,
                self.0.sign(message).to_bytes(),
            ))
        }
    }

    fn record(
        revision: u64,
        previous: Option<[u8; 32]>,
        state: u8,
        timestamp: u64,
    ) -> StateAnchorRecord {
        StateAnchorRecord {
            schema: STATE_ANCHOR_SCHEMA.into(),
            namespace: "symthaea.episodic-continuity".into(),
            object_id: "symthaea:self:episodic-memory".into(),
            revision,
            previous_anchor_fingerprint: previous,
            state_commitment: [state; 32],
            policy_commitment: Some([0x55; 32]),
            timestamp_unix_secs: timestamp,
        }
    }

    fn genesis(signer: &EdSigner) -> SignedStateAnchor {
        sign_state_anchor(record(1, None, 1, 100), signer).unwrap()
    }

    #[test]
    fn signs_and_verifies_against_independently_trusted_key() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let anchor = genesis(&signer);
        verify_anchor(
            &anchor,
            &signer.public_key(),
            &Ed25519EvidenceSignatureBackend,
        )
        .unwrap();
    }

    #[test]
    fn signature_binds_key_and_algorithm_context() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let mut anchor = genesis(&signer);
        let other = EdSigner(SigningKey::generate(&mut OsRng));
        anchor.signer_public_key = other.public_key();
        assert!(verify_anchor(
            &anchor,
            &other.public_key(),
            &Ed25519EvidenceSignatureBackend,
        )
        .is_err());
    }

    #[test]
    fn signature_cannot_be_replayed_beside_changed_state_commitment() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let mut anchor = genesis(&signer);
        anchor.record.state_commitment = [9; 32];
        assert!(verify_anchor(
            &anchor,
            &signer.public_key(),
            &Ed25519EvidenceSignatureBackend,
        )
        .is_err());
    }

    #[test]
    fn direct_successor_binds_exact_signed_predecessor() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let first = genesis(&signer);
        let second = sign_state_anchor(
            record(2, Some(first.fingerprint().unwrap()), 2, 110),
            &signer,
        )
        .unwrap();
        verify_direct_successor(
            &first,
            &second,
            &signer.public_key(),
            &Ed25519EvidenceSignatureBackend,
        )
        .unwrap();

        let unrelated = EdSigner(SigningKey::generate(&mut OsRng));
        let forged_second = sign_state_anchor(
            record(2, Some(first.fingerprint().unwrap()), 2, 110),
            &unrelated,
        )
        .unwrap();
        assert!(matches!(
            verify_direct_successor(
                &first,
                &forged_second,
                &signer.public_key(),
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(StateAnchorContinuityError::Verify(
                StateAnchorVerifyError::TrustedKeyMismatch
            ))
        ));
    }

    #[test]
    fn same_revision_fork_is_not_a_successor() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let first = genesis(&signer);
        let fork = sign_state_anchor(record(1, None, 7, 101), &signer).unwrap();
        assert!(matches!(
            verify_direct_successor(
                &first,
                &fork,
                &signer.public_key(),
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(StateAnchorContinuityError::NotDirectSuccessor(_, _))
        ));
    }

    #[test]
    fn changed_namespace_or_object_cannot_extend_retained_anchor() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let first = genesis(&signer);
        let mut next_record = record(2, Some(first.fingerprint().unwrap()), 2, 110);
        next_record.object_id = "different-object".into();
        let second = sign_state_anchor(next_record, &signer).unwrap();
        assert!(matches!(
            verify_direct_successor(
                &first,
                &second,
                &signer.public_key(),
                &Ed25519EvidenceSignatureBackend,
            ),
            Err(StateAnchorContinuityError::TargetChanged)
        ));
    }

    #[test]
    fn privacy_reduced_checkpoint_verifies_source_and_direct_successor() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let first = genesis(&signer);
        let checkpoint = sign_anchor_checkpoint(
            &first,
            &signer,
            &Ed25519EvidenceSignatureBackend,
            105,
        )
        .unwrap();
        verify_anchor_checkpoint(
            &checkpoint,
            &signer.public_key(),
            &Ed25519EvidenceSignatureBackend,
        )
        .unwrap();
        let second = sign_state_anchor(
            record(2, Some(first.fingerprint().unwrap()), 2, 110),
            &signer,
        )
        .unwrap();
        verify_successor_from_checkpoint(
            &checkpoint,
            &second,
            &signer.public_key(),
            &Ed25519EvidenceSignatureBackend,
        )
        .unwrap();
    }

    #[test]
    fn checkpoint_refuses_invalid_source_anchor() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let mut first = genesis(&signer);
        first.record.state_commitment = [0x99; 32];
        assert!(matches!(
            sign_anchor_checkpoint(
                &first,
                &signer,
                &Ed25519EvidenceSignatureBackend,
                105,
            ),
            Err(StateAnchorError::CheckpointSourceVerificationFailed)
        ));
    }

    #[test]
    fn freshness_policy_rejects_old_and_future_anchors() {
        let signer = EdSigner(SigningKey::generate(&mut OsRng));
        let anchor = genesis(&signer);
        assert!(matches!(
            verify_anchor_freshness(
                &anchor,
                &signer.public_key(),
                &Ed25519EvidenceSignatureBackend,
                1000,
                StateAnchorFreshnessPolicy {
                    max_age_secs: Some(100),
                    max_future_skew_secs: 5,
                },
            ),
            Err(StateAnchorContinuityError::AnchorTooOld(_, _))
        ));

        let future = sign_state_anchor(record(1, None, 1, 2000), &signer).unwrap();
        assert!(matches!(
            verify_anchor_freshness(
                &future,
                &signer.public_key(),
                &Ed25519EvidenceSignatureBackend,
                1000,
                StateAnchorFreshnessPolicy {
                    max_age_secs: None,
                    max_future_skew_secs: 5,
                },
            ),
            Err(StateAnchorContinuityError::AnchorFromFuture(_, _, _))
        ));
    }
}
