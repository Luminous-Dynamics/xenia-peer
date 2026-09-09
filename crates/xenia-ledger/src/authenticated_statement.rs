// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic verifier-owned authentication for exact purpose-bound statement bytes.
//!
//! This module deliberately stops at authentication. A successful
//! [`AuthenticatedStatementV1`] proves that the exact payload bytes supplied to
//! the verifier were signed under the exact configured key binding, signature
//! suite, purpose, transaction challenge, and verifier-root epoch. It does not
//! establish application-specific truth, freshness, authorization, or permission
//! to execute an action.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::binding::EvidencePublicKeyBinding;
use crate::signature::{
    Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend, EvidenceSignatureBackendError,
    SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
};
#[cfg(feature = "pqc-signatures")]
use crate::signature::{MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend};

/// Stable schema label for generic authenticated-statement claims.
pub const AUTHENTICATED_STATEMENT_CLAIM_SCHEMA: &str = "xenia-authenticated-statement-claim-v1";
/// Stable schema label for signed generic statements.
pub const SIGNED_STATEMENT_SCHEMA: &str = "xenia-signed-statement-v1";
/// Hash used for statement/policy identities and payload identities.
pub const AUTHENTICATED_STATEMENT_HASH_ALGORITHM: &str = "blake3-256";

const POLICY_DOMAIN: &[u8] = b"xenia.authenticated-statement.policy.v1\0";
const CLAIM_DOMAIN: &[u8] = b"xenia.authenticated-statement.claim.v1\0";
const SIGNATURE_MESSAGE_DOMAIN: &[u8] = b"xenia.authenticated-statement.signature-message.v1\0";
const AUTHENTICATED_DOMAIN: &[u8] = b"xenia.authenticated-statement.verified.v1\0";

/// Content identity of one validated statement-verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StatementVerificationPolicyId([u8; 32]);

impl StatementVerificationPolicyId {
    /// Return the raw BLAKE3-256 identity bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Content identity of one signed-statement claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StatementClaimId([u8; 32]);

impl StatementClaimId {
    /// Return the raw BLAKE3-256 identity bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Verifier-owned identity of one successfully authenticated statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthenticatedStatementId([u8; 32]);

impl AuthenticatedStatementId {
    /// Return the raw BLAKE3-256 identity bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Local policy specifying exactly which verifier root may authenticate one purpose.
///
/// This value is serializable configuration, not proof. [`verify_statement`] always
/// revalidates its stored content identity and the live public-key binding before
/// producing an opaque authenticated result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementVerificationPolicyV1 {
    purpose: String,
    signature_suite: SignatureSuite,
    verifier_key_fingerprint: [u8; 32],
    verifier_root_epoch: u64,
    policy_id: StatementVerificationPolicyId,
}

impl StatementVerificationPolicyV1 {
    /// Construct a policy for one exact purpose, suite, verifier key, and root epoch.
    pub fn new(
        purpose: impl Into<String>,
        signature_suite: SignatureSuite,
        verifier_key_fingerprint: [u8; 32],
        verifier_root_epoch: u64,
    ) -> Result<Self, AuthenticatedStatementError> {
        let purpose = checked_text("purpose", purpose.into())?;
        if verifier_key_fingerprint == [0; 32] {
            return Err(AuthenticatedStatementError::ZeroVerifierKeyFingerprint);
        }
        if verifier_root_epoch == 0 {
            return Err(AuthenticatedStatementError::ZeroVerifierRootEpoch);
        }
        let policy_id = StatementVerificationPolicyId(hash_policy(
            &purpose,
            signature_suite,
            verifier_key_fingerprint,
            verifier_root_epoch,
        ));
        Ok(Self {
            purpose,
            signature_suite,
            verifier_key_fingerprint,
            verifier_root_epoch,
            policy_id,
        })
    }

    /// Stable policy identity.
    pub fn id(&self) -> StatementVerificationPolicyId {
        self.policy_id
    }

    /// Application-defined purpose/domain string.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Signature suite required by the policy.
    pub fn signature_suite(&self) -> SignatureSuite {
        self.signature_suite
    }

    /// Fingerprint of the exact verifier public key accepted by the policy.
    pub fn verifier_key_fingerprint(&self) -> [u8; 32] {
        self.verifier_key_fingerprint
    }

    /// Monotone application-managed epoch for the verifier root.
    pub fn verifier_root_epoch(&self) -> u64 {
        self.verifier_root_epoch
    }

    /// Revalidate stored fields and content identity.
    pub fn validate(&self) -> Result<(), AuthenticatedStatementError> {
        checked_text("purpose", self.purpose.clone())?;
        if self.verifier_key_fingerprint == [0; 32] {
            return Err(AuthenticatedStatementError::ZeroVerifierKeyFingerprint);
        }
        if self.verifier_root_epoch == 0 {
            return Err(AuthenticatedStatementError::ZeroVerifierRootEpoch);
        }
        let expected = StatementVerificationPolicyId(hash_policy(
            &self.purpose,
            self.signature_suite,
            self.verifier_key_fingerprint,
            self.verifier_root_epoch,
        ));
        if expected != self.policy_id {
            return Err(AuthenticatedStatementError::PolicyIdentityMismatch);
        }
        Ok(())
    }
}

/// Transportable claim describing the exact context in which payload bytes are signed.
///
/// The payload itself is supplied separately to [`statement_signature_message`] and
/// [`verify_statement`]. `payload_digest` makes claim identity stable while the
/// signature message still includes the exact payload bytes rather than merely signing
/// a caller-supplied digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementClaimV1 {
    schema: String,
    purpose: String,
    signature_suite: SignatureSuite,
    verifier_key_fingerprint: [u8; 32],
    verifier_root_epoch: u64,
    transaction_challenge: [u8; 32],
    payload_digest: [u8; 32],
    claim_id: StatementClaimId,
}

impl StatementClaimV1 {
    /// Construct a claim over the supplied exact payload bytes.
    pub fn new(
        purpose: impl Into<String>,
        signature_suite: SignatureSuite,
        verifier_key_fingerprint: [u8; 32],
        verifier_root_epoch: u64,
        transaction_challenge: [u8; 32],
        payload: &[u8],
    ) -> Result<Self, AuthenticatedStatementError> {
        let purpose = checked_text("purpose", purpose.into())?;
        if verifier_key_fingerprint == [0; 32] {
            return Err(AuthenticatedStatementError::ZeroVerifierKeyFingerprint);
        }
        if verifier_root_epoch == 0 {
            return Err(AuthenticatedStatementError::ZeroVerifierRootEpoch);
        }
        if transaction_challenge == [0; 32] {
            return Err(AuthenticatedStatementError::ZeroTransactionChallenge);
        }
        let payload_digest = *blake3::hash(payload).as_bytes();
        let claim_id = StatementClaimId(hash_claim(
            &purpose,
            signature_suite,
            verifier_key_fingerprint,
            verifier_root_epoch,
            transaction_challenge,
            payload_digest,
        ));
        Ok(Self {
            schema: AUTHENTICATED_STATEMENT_CLAIM_SCHEMA.to_string(),
            purpose,
            signature_suite,
            verifier_key_fingerprint,
            verifier_root_epoch,
            transaction_challenge,
            payload_digest,
            claim_id,
        })
    }

    /// Stable claim identity.
    pub fn id(&self) -> StatementClaimId {
        self.claim_id
    }

    /// Purpose/domain string committed by the signature.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Signature suite declared by the signed claim.
    pub fn signature_suite(&self) -> SignatureSuite {
        self.signature_suite
    }

    /// Fingerprint of the verifier key to which the claim is bound.
    pub fn verifier_key_fingerprint(&self) -> [u8; 32] {
        self.verifier_key_fingerprint
    }

    /// Verifier-root epoch committed by the claim.
    pub fn verifier_root_epoch(&self) -> u64 {
        self.verifier_root_epoch
    }

    /// Transaction challenge committed by the claim.
    pub fn transaction_challenge(&self) -> [u8; 32] {
        self.transaction_challenge
    }

    /// BLAKE3-256 digest of the exact payload bytes.
    pub fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    fn validate_against_payload(&self, payload: &[u8]) -> Result<(), AuthenticatedStatementError> {
        if self.schema != AUTHENTICATED_STATEMENT_CLAIM_SCHEMA {
            return Err(AuthenticatedStatementError::UnsupportedClaimSchema {
                schema: self.schema.clone(),
            });
        }
        checked_text("purpose", self.purpose.clone())?;
        if self.verifier_key_fingerprint == [0; 32] {
            return Err(AuthenticatedStatementError::ZeroVerifierKeyFingerprint);
        }
        if self.verifier_root_epoch == 0 {
            return Err(AuthenticatedStatementError::ZeroVerifierRootEpoch);
        }
        if self.transaction_challenge == [0; 32] {
            return Err(AuthenticatedStatementError::ZeroTransactionChallenge);
        }
        let actual_payload_digest = *blake3::hash(payload).as_bytes();
        if actual_payload_digest != self.payload_digest {
            return Err(AuthenticatedStatementError::PayloadDigestMismatch);
        }
        let expected = StatementClaimId(hash_claim(
            &self.purpose,
            self.signature_suite,
            self.verifier_key_fingerprint,
            self.verifier_root_epoch,
            self.transaction_challenge,
            self.payload_digest,
        ));
        if expected != self.claim_id {
            return Err(AuthenticatedStatementError::ClaimIdentityMismatch);
        }
        Ok(())
    }
}

/// Algorithm-tagged signature plus its exact purpose-bound claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStatementV1 {
    schema: String,
    claim: StatementClaimV1,
    signature: SignatureEnvelope,
}

impl SignedStatementV1 {
    /// Pair one claim with the signature over [`statement_signature_message`].
    pub fn new(claim: StatementClaimV1, signature: SignatureEnvelope) -> Self {
        Self {
            schema: SIGNED_STATEMENT_SCHEMA.to_string(),
            claim,
            signature,
        }
    }

    /// Borrow the signed claim.
    pub fn claim(&self) -> &StatementClaimV1 {
        &self.claim
    }

    /// Borrow the algorithm-tagged signature bytes.
    pub fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
}

/// Opaque verifier-created proof that one exact payload authenticated successfully.
///
/// This type deliberately does not implement `Serialize` or `Deserialize`; transport
/// bytes cannot manufacture a successful verification result. It is still not an
/// authorization, truth claim, freshness proof, or execution capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedStatementV1 {
    authenticated_id: AuthenticatedStatementId,
    policy_id: StatementVerificationPolicyId,
    claim_id: StatementClaimId,
    signature_suite: SignatureSuite,
    verifier_key_fingerprint: [u8; 32],
    verifier_root_epoch: u64,
    transaction_challenge: [u8; 32],
    payload_digest: [u8; 32],
}

impl AuthenticatedStatementV1 {
    /// Stable verifier-owned authentication identity.
    pub fn id(&self) -> AuthenticatedStatementId {
        self.authenticated_id
    }

    /// Exact local verification policy used to authenticate the statement.
    pub fn policy_id(&self) -> StatementVerificationPolicyId {
        self.policy_id
    }

    /// Exact signed claim that authenticated.
    pub fn claim_id(&self) -> StatementClaimId {
        self.claim_id
    }

    /// Signature suite that successfully verified.
    pub fn signature_suite(&self) -> SignatureSuite {
        self.signature_suite
    }

    /// Fingerprint of the exact verifier key used.
    pub fn verifier_key_fingerprint(&self) -> [u8; 32] {
        self.verifier_key_fingerprint
    }

    /// Verifier-root epoch accepted by the local policy and signed claim.
    pub fn verifier_root_epoch(&self) -> u64 {
        self.verifier_root_epoch
    }

    /// Exact transaction challenge authenticated by the signature.
    pub fn transaction_challenge(&self) -> [u8; 32] {
        self.transaction_challenge
    }

    /// Digest of the exact payload bytes passed to the verifier.
    pub fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }
}

/// Build the exact domain-separated bytes a signer must authenticate.
///
/// The payload bytes themselves are included after all context fields. This avoids a
/// protocol in which a remote signer signs only a caller-provided payload digest. The
/// payload digest is still carried in the claim and checked independently for stable
/// identity and audit use.
pub fn statement_signature_message(claim: &StatementClaimV1, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(SIGNATURE_MESSAGE_DOMAIN);
    put_str(&mut message, AUTHENTICATED_STATEMENT_CLAIM_SCHEMA);
    put_str(&mut message, claim.purpose());
    put_str(&mut message, claim.signature_suite().stable_label());
    message.extend_from_slice(&claim.verifier_key_fingerprint());
    message.extend_from_slice(&claim.verifier_root_epoch().to_le_bytes());
    message.extend_from_slice(&claim.transaction_challenge());
    message.extend_from_slice(&claim.payload_digest());
    message.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    message.extend_from_slice(payload);
    message
}

/// Verify one signed statement using only Xenia's built-in signature backends.
///
/// Callers do not supply an [`EvidenceSignatureBackend`] implementation. This is
/// deliberate: the trait remains useful for Xenia's artifact-verification internals,
/// but accepting an arbitrary external implementation here would let a caller provide
/// an "always succeeds" verifier and manufacture [`AuthenticatedStatementV1`].
///
/// With default features, Ed25519 is supported. ML-DSA-65/87 become available only
/// when the existing `pqc-signatures` feature compiles those built-in backends.
pub fn verify_statement(
    policy: &StatementVerificationPolicyV1,
    key_binding: &EvidencePublicKeyBinding,
    expected_transaction_challenge: [u8; 32],
    payload: &[u8],
    signed: &SignedStatementV1,
) -> Result<AuthenticatedStatementV1, AuthenticatedStatementError> {
    match policy.signature_suite() {
        SignatureSuite::Ed25519Rfc8032 => verify_statement_with_backend(
            policy,
            key_binding,
            &Ed25519EvidenceSignatureBackend,
            expected_transaction_challenge,
            payload,
            signed,
        ),
        #[cfg(feature = "pqc-signatures")]
        SignatureSuite::MlDsa65Fips204 => verify_statement_with_backend(
            policy,
            key_binding,
            &MlDsa65EvidenceSignatureBackend,
            expected_transaction_challenge,
            payload,
            signed,
        ),
        #[cfg(feature = "pqc-signatures")]
        SignatureSuite::MlDsa87Fips204 => verify_statement_with_backend(
            policy,
            key_binding,
            &MlDsa87EvidenceSignatureBackend,
            expected_transaction_challenge,
            payload,
            signed,
        ),
        #[cfg(not(feature = "pqc-signatures"))]
        SignatureSuite::MlDsa65Fips204 | SignatureSuite::MlDsa87Fips204 => {
            Err(AuthenticatedStatementError::BuiltInSignatureSuiteUnavailable {
                suite: policy.signature_suite(),
            })
        }
        SignatureSuite::SlhDsaFips205 => {
            Err(AuthenticatedStatementError::BuiltInSignatureSuiteUnavailable {
                suite: policy.signature_suite(),
            })
        }
    }
}

fn verify_statement_with_backend(
    policy: &StatementVerificationPolicyV1,
    key_binding: &EvidencePublicKeyBinding,
    backend: &impl EvidenceSignatureBackend,
    expected_transaction_challenge: [u8; 32],
    payload: &[u8],
    signed: &SignedStatementV1,
) -> Result<AuthenticatedStatementV1, AuthenticatedStatementError> {
    policy.validate()?;
    if expected_transaction_challenge == [0; 32] {
        return Err(AuthenticatedStatementError::ZeroTransactionChallenge);
    }
    if signed.schema != SIGNED_STATEMENT_SCHEMA {
        return Err(AuthenticatedStatementError::UnsupportedSignedStatementSchema {
            schema: signed.schema.clone(),
        });
    }
    signed.claim.validate_against_payload(payload)?;

    key_binding
        .validate_against_signature_suite_and_backend(policy.signature_suite(), backend)
        .map_err(AuthenticatedStatementError::PublicKeyBinding)?;

    if key_binding.public_key_fingerprint != policy.verifier_key_fingerprint() {
        return Err(AuthenticatedStatementError::VerifierKeyFingerprintMismatch);
    }
    if signed.claim.purpose() != policy.purpose() {
        return Err(AuthenticatedStatementError::PurposeMismatch);
    }
    if signed.claim.signature_suite() != policy.signature_suite() {
        return Err(AuthenticatedStatementError::SignatureSuiteMismatch);
    }
    if signed.claim.verifier_key_fingerprint() != policy.verifier_key_fingerprint() {
        return Err(AuthenticatedStatementError::VerifierKeyFingerprintMismatch);
    }
    if signed.claim.verifier_root_epoch() != policy.verifier_root_epoch() {
        return Err(AuthenticatedStatementError::VerifierRootEpochMismatch);
    }
    if signed.claim.transaction_challenge() != expected_transaction_challenge {
        return Err(AuthenticatedStatementError::TransactionChallengeMismatch);
    }

    let envelope_suite = signed
        .signature
        .validate_shape()
        .map_err(AuthenticatedStatementError::SignatureEnvelope)?;
    if envelope_suite != policy.signature_suite() {
        return Err(AuthenticatedStatementError::SignatureSuiteMismatch);
    }

    let message = statement_signature_message(&signed.claim, payload);
    backend
        .verify_signature(
            &key_binding.public_key,
            &message,
            &signed.signature.signature,
        )
        .map_err(AuthenticatedStatementError::SignatureVerification)?;

    let signature_digest = *blake3::hash(&signed.signature.signature).as_bytes();
    let authenticated_id = AuthenticatedStatementId(hash_authenticated(
        policy.id(),
        signed.claim.id(),
        key_binding.public_key_fingerprint,
        signature_digest,
    ));

    Ok(AuthenticatedStatementV1 {
        authenticated_id,
        policy_id: policy.id(),
        claim_id: signed.claim.id(),
        signature_suite: policy.signature_suite(),
        verifier_key_fingerprint: policy.verifier_key_fingerprint(),
        verifier_root_epoch: policy.verifier_root_epoch(),
        transaction_challenge: signed.claim.transaction_challenge(),
        payload_digest: signed.claim.payload_digest(),
    })
}

/// Failures while constructing or verifying a generic authenticated statement.
#[derive(Debug, Error)]
pub enum AuthenticatedStatementError {
    /// A bounded text field was blank.
    #[error("{field} must not be blank")]
    BlankText { field: &'static str },
    /// A bounded text field exceeded the v1 limit.
    #[error("{field} exceeds 1024 bytes")]
    TextTooLong { field: &'static str },
    /// A bounded text field contained control characters.
    #[error("{field} contains control characters")]
    ControlCharacters { field: &'static str },
    /// Verifier public-key fingerprints must be explicit and non-zero.
    #[error("verifier key fingerprint must be non-zero")]
    ZeroVerifierKeyFingerprint,
    /// Verifier root epochs are monotone non-zero policy inputs.
    #[error("verifier root epoch must be non-zero")]
    ZeroVerifierRootEpoch,
    /// Transaction challenges are required to prevent cross-transaction replay.
    #[error("transaction challenge must be non-zero")]
    ZeroTransactionChallenge,
    /// Stored policy identity did not match its canonical fields.
    #[error("statement verification policy identity mismatch")]
    PolicyIdentityMismatch,
    /// The signed claim used an unsupported schema.
    #[error("unsupported authenticated-statement claim schema: {schema}")]
    UnsupportedClaimSchema { schema: String },
    /// The outer signed-statement wrapper used an unsupported schema.
    #[error("unsupported signed-statement schema: {schema}")]
    UnsupportedSignedStatementSchema { schema: String },
    /// Exact supplied payload bytes did not match the signed claim digest.
    #[error("payload digest does not match signed statement claim")]
    PayloadDigestMismatch,
    /// Stored claim identity did not match its canonical fields.
    #[error("signed statement claim identity mismatch")]
    ClaimIdentityMismatch,
    /// The requested suite has no Xenia-owned built-in statement verifier in this build.
    #[error("built-in authenticated-statement verifier unavailable for {suite:?}")]
    BuiltInSignatureSuiteUnavailable { suite: SignatureSuite },
    /// Current public-key binding did not satisfy the required suite/key shape.
    #[error("evidence public-key binding rejected: {0}")]
    PublicKeyBinding(#[source] crate::binding::EvidencePublicKeyBindingError),
    /// Current verifier key did not match the exact policy/claim fingerprint.
    #[error("verifier key fingerprint mismatch")]
    VerifierKeyFingerprintMismatch,
    /// Claim purpose differed from the local policy.
    #[error("signed statement purpose differs from verification policy")]
    PurposeMismatch,
    /// Signature suite differed across policy, claim, envelope, key, or backend.
    #[error("signed statement signature suite mismatch")]
    SignatureSuiteMismatch,
    /// Signed root epoch differed from the currently accepted local epoch.
    #[error("signed verifier-root epoch differs from verification policy")]
    VerifierRootEpochMismatch,
    /// Signed challenge differed from this verification transaction.
    #[error("signed statement transaction challenge mismatch")]
    TransactionChallengeMismatch,
    /// Algorithm-tagged signature envelope was malformed.
    #[error("signature envelope rejected: {0}")]
    SignatureEnvelope(#[source] SignatureEnvelopeError),
    /// Cryptographic signature verification failed.
    #[error("statement signature verification failed: {0}")]
    SignatureVerification(#[source] EvidenceSignatureBackendError),
}

fn checked_text(field: &'static str, value: String) -> Result<String, AuthenticatedStatementError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AuthenticatedStatementError::BlankText { field });
    }
    if trimmed.len() > 1024 {
        return Err(AuthenticatedStatementError::TextTooLong { field });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AuthenticatedStatementError::ControlCharacters { field });
    }
    Ok(trimmed.to_string())
}

fn hash_policy(
    purpose: &str,
    suite: SignatureSuite,
    verifier_key_fingerprint: [u8; 32],
    verifier_root_epoch: u64,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    put_str(&mut bytes, purpose);
    put_str(&mut bytes, suite.stable_label());
    bytes.extend_from_slice(&verifier_key_fingerprint);
    bytes.extend_from_slice(&verifier_root_epoch.to_le_bytes());
    domain_hash(POLICY_DOMAIN, &bytes)
}

fn hash_claim(
    purpose: &str,
    suite: SignatureSuite,
    verifier_key_fingerprint: [u8; 32],
    verifier_root_epoch: u64,
    transaction_challenge: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    put_str(&mut bytes, purpose);
    put_str(&mut bytes, suite.stable_label());
    bytes.extend_from_slice(&verifier_key_fingerprint);
    bytes.extend_from_slice(&verifier_root_epoch.to_le_bytes());
    bytes.extend_from_slice(&transaction_challenge);
    bytes.extend_from_slice(&payload_digest);
    domain_hash(CLAIM_DOMAIN, &bytes)
}

fn hash_authenticated(
    policy_id: StatementVerificationPolicyId,
    claim_id: StatementClaimId,
    verifier_key_fingerprint: [u8; 32],
    signature_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(policy_id.as_bytes());
    bytes.extend_from_slice(claim_id.as_bytes());
    bytes.extend_from_slice(&verifier_key_fingerprint);
    bytes.extend_from_slice(&signature_digest);
    domain_hash(AUTHENTICATED_DOMAIN, &bytes)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn put_str(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::{EvidencePublicKeyBinding, compute_evidence_public_key_fingerprint};

    fn fixture() -> (
        SigningKey,
        EvidencePublicKeyBinding,
        StatementVerificationPolicyV1,
        [u8; 32],
        Vec<u8>,
    ) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let binding = EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            verifying_key.to_vec(),
        );
        let policy = StatementVerificationPolicyV1::new(
            "org.luminous.fixture.verification.v1",
            SignatureSuite::Ed25519Rfc8032,
            compute_evidence_public_key_fingerprint(&verifying_key),
            4,
        )
        .unwrap();
        (signing_key, binding, policy, [9; 32], b"exact payload bytes".to_vec())
    }

    fn signed_fixture(
        signing_key: &SigningKey,
        policy: &StatementVerificationPolicyV1,
        challenge: [u8; 32],
        payload: &[u8],
    ) -> SignedStatementV1 {
        let claim = StatementClaimV1::new(
            policy.purpose(),
            policy.signature_suite(),
            policy.verifier_key_fingerprint(),
            policy.verifier_root_epoch(),
            challenge,
            payload,
        )
        .unwrap();
        let message = statement_signature_message(&claim, payload);
        let signature = signing_key.sign(&message).to_bytes();
        SignedStatementV1::new(claim, SignatureEnvelope::ed25519(signature))
    }

    #[test]
    fn exact_statement_authenticates() {
        let (signing_key, binding, policy, challenge, payload) = fixture();
        let signed = signed_fixture(&signing_key, &policy, challenge, &payload);
        let authenticated = verify_statement(&policy, &binding, challenge, &payload, &signed).unwrap();
        assert_eq!(authenticated.policy_id(), policy.id());
        assert_eq!(authenticated.claim_id(), signed.claim().id());
        assert_eq!(authenticated.payload_digest(), *blake3::hash(&payload).as_bytes());
        assert_eq!(authenticated.verifier_root_epoch(), 4);
    }

    #[test]
    fn changed_payload_fails_before_signature_acceptance() {
        let (signing_key, binding, policy, challenge, payload) = fixture();
        let signed = signed_fixture(&signing_key, &policy, challenge, &payload);
        let err = verify_statement(&policy, &binding, challenge, b"different payload", &signed)
            .unwrap_err();
        assert!(matches!(err, AuthenticatedStatementError::PayloadDigestMismatch));
    }

    #[test]
    fn cross_challenge_replay_fails_closed() {
        let (signing_key, binding, policy, challenge, payload) = fixture();
        let signed = signed_fixture(&signing_key, &policy, challenge, &payload);
        let err = verify_statement(&policy, &binding, [10; 32], &payload, &signed).unwrap_err();
        assert!(matches!(
            err,
            AuthenticatedStatementError::TransactionChallengeMismatch
        ));
    }

    #[test]
    fn root_epoch_rotation_invalidates_old_statement() {
        let (signing_key, binding, policy, challenge, payload) = fixture();
        let signed = signed_fixture(&signing_key, &policy, challenge, &payload);
        let rotated = StatementVerificationPolicyV1::new(
            policy.purpose(),
            policy.signature_suite(),
            policy.verifier_key_fingerprint(),
            5,
        )
        .unwrap();
        let err = verify_statement(&rotated, &binding, challenge, &payload, &signed).unwrap_err();
        assert!(matches!(
            err,
            AuthenticatedStatementError::VerifierRootEpochMismatch
        ));
    }

    #[test]
    fn wrong_key_binding_fails_closed() {
        let (signing_key, _binding, policy, challenge, payload) = fixture();
        let signed = signed_fixture(&signing_key, &policy, challenge, &payload);
        let other_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let other_binding = EvidencePublicKeyBinding::new(
            SignatureSuite::Ed25519Rfc8032,
            other_key.to_vec(),
        );
        let err = verify_statement(&policy, &other_binding, challenge, &payload, &signed)
            .unwrap_err();
        assert!(matches!(
            err,
            AuthenticatedStatementError::VerifierKeyFingerprintMismatch
        ));
    }

    #[test]
    fn purpose_replay_fails_closed() {
        let (signing_key, binding, policy, challenge, payload) = fixture();
        let signed = signed_fixture(&signing_key, &policy, challenge, &payload);
        let other_policy = StatementVerificationPolicyV1::new(
            "org.luminous.other-purpose.v1",
            policy.signature_suite(),
            policy.verifier_key_fingerprint(),
            policy.verifier_root_epoch(),
        )
        .unwrap();
        let err = verify_statement(&other_policy, &binding, challenge, &payload, &signed)
            .unwrap_err();
        assert!(matches!(err, AuthenticatedStatementError::PurposeMismatch));
    }

    #[test]
    fn unavailable_suite_cannot_mint_authenticated_statement() {
        let (_, binding, _, challenge, payload) = fixture();
        let policy = StatementVerificationPolicyV1::new(
            "org.luminous.fixture.verification.v1",
            SignatureSuite::SlhDsaFips205,
            binding.public_key_fingerprint,
            4,
        )
        .unwrap();
        let claim = StatementClaimV1::new(
            policy.purpose(),
            policy.signature_suite(),
            policy.verifier_key_fingerprint(),
            policy.verifier_root_epoch(),
            challenge,
            &payload,
        )
        .unwrap();
        let signed = SignedStatementV1::new(
            claim,
            SignatureEnvelope::new(SignatureSuite::SlhDsaFips205, vec![1, 2, 3]),
        );
        let err = verify_statement(&policy, &binding, challenge, &payload, &signed).unwrap_err();
        assert!(matches!(
            err,
            AuthenticatedStatementError::BuiltInSignatureSuiteUnavailable {
                suite: SignatureSuite::SlhDsaFips205
            }
        ));
    }
}
