// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable SIF release-credential verification.
//!
//! This is the runtime trust bridge between a Mycelix
//! `PreDisclosureVerifiedBundle` and Xenia's disclosure permit. Xenia does not trust
//! a caller-provided bundle digest. It first verifies a canonical credential under a
//! local threshold of configured release-authority keys/trust domains, then binds the
//! credential to the exact cryptographically verified Xenia execution proof.
//!
//! The wire shape intentionally mirrors `mycelix-accountability-credential` but this
//! crate has no source dependency on Mycelix. Interoperability is defined by the
//! canonical v1 protocol, not Rust type identity.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::accountability::{
    AccountabilityBindingError, AccountabilityExecutionAttestation,
    accountability_execution_binding_digest,
};
use crate::accountability_interop::accountability_verifier_key_id;
use crate::binding::SessionTranscriptBinding;
use crate::policy::EvidenceCryptoManifest;
use crate::signature::{
    EvidenceSignatureBackend, SignatureEnvelopeError, SignatureSuite,
};

/// Stable schema shared with `mycelix-accountability-credential`.
pub const SIF_RELEASE_CREDENTIAL_SCHEMA: &str = "sif-release-credential-v1";
/// Canonical byte profile shared with Mycelix.
pub const SIF_RELEASE_CREDENTIAL_CODEC: &str = "sif-release-credential-canonical-v1";
/// Signature suite supported by the v1 bridge credential.
pub const SIF_RELEASE_CREDENTIAL_ED25519: &str = "ed25519-rfc8032";

const RELEASE_CREDENTIAL_DOMAIN: &[u8] = b"sif:release-credential:statement:v1";
const RELEASE_AUTHORITY_KEY_DOMAIN: &[u8] = b"sif:release-credential:authority-key:v1";

/// Commitment-only release statement issued by Mycelix.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SifReleaseCredentialStatement {
    /// Stable schema label.
    pub schema: String,
    /// Unique release-lineage authorization identifier.
    pub credential_id: [u8; 32],
    /// Frozen semantic receipt statement.
    pub receipt_statement_digest: [u8; 32],
    /// Exact provider-proof bundle witnessed before disclosure.
    pub pre_witness_bundle_digest: [u8; 32],
    /// Final archival evidence bundle including resolved witness evidence.
    pub finalized_evidence_bundle_digest: [u8; 32],
    /// Exact semantic accountability-policy commitment.
    pub accountability_policy_digest: [u8; 32],
    /// Exact non-witness trust-policy commitment.
    pub non_witness_trust_policy_digest: [u8; 32],
    /// Exact external-witness policy commitment.
    pub witness_policy_digest: [u8; 32],
    /// Selected trust-qualified Xenia execution-proof identifier.
    pub execution_proof_digest: [u8; 32],
    /// Resolved Xenia execution verifier/key identity.
    pub execution_verifier_id: [u8; 32],
    /// Locally meaningful administration domain for that execution verifier.
    pub execution_trust_domain_id: [u8; 32],
    /// Minimum-necessary result commitment, when present.
    pub result_digest: Option<[u8; 32]>,
}

/// One release-authority signature carried by the credential.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SifReleaseCredentialSignature {
    /// Stable algorithm label.
    pub algorithm: String,
    /// Domain-separated identifier for the signer public key.
    pub signer_key_id: [u8; 32],
    /// Raw signature bytes. v1 Ed25519 requires 64 bytes.
    pub signature: Vec<u8>,
}

/// Portable signed release credential.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SifReleaseCredential {
    /// Canonical commitment-only statement.
    pub statement: SifReleaseCredentialStatement,
    /// Independent authority signatures over the same statement.
    pub signatures: Vec<SifReleaseCredentialSignature>,
}

/// Locally configured release-authority root.
///
/// Trust-domain identity comes from Xenia configuration, not from credential input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedReleaseAuthority {
    /// Raw Ed25519 public key.
    pub public_key: [u8; 32],
    /// Independently administered trust domain for threshold policy.
    pub trust_domain_id: [u8; 32],
}

impl TrustedReleaseAuthority {
    /// Stable key ID used in portable credential signatures.
    pub fn key_id(&self) -> [u8; 32] {
        release_authority_key_id(&self.public_key)
    }
}

/// Threshold policy applied by Xenia before a credential becomes release authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseCredentialTrustPolicy {
    /// Minimum number of distinct trusted authority keys with valid signatures.
    pub min_valid_signatures: u8,
    /// Minimum number of distinct locally configured administrative trust domains.
    pub min_distinct_trust_domains: u8,
}

/// Credential that passed Xenia's local release-authority threshold policy.
///
/// Fields are private so downstream code cannot manufacture this boundary from a
/// raw digest or deserialized credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReleaseCredential {
    statement: SifReleaseCredentialStatement,
    signer_key_ids: Vec<[u8; 32]>,
    signer_trust_domains: Vec<[u8; 32]>,
}

impl VerifiedReleaseCredential {
    /// Verified release-lineage authorization identifier.
    pub const fn credential_id(&self) -> [u8; 32] {
        self.statement.credential_id
    }

    /// Final witnessed Mycelix bundle committed by the credential.
    pub const fn finalized_evidence_bundle_digest(&self) -> [u8; 32] {
        self.statement.finalized_evidence_bundle_digest
    }

    /// Frozen semantic receipt statement.
    pub const fn receipt_statement_digest(&self) -> [u8; 32] {
        self.statement.receipt_statement_digest
    }

    /// Distinct release-authority key roots that actually verified.
    pub fn signer_key_ids(&self) -> &[[u8; 32]] {
        &self.signer_key_ids
    }

    /// Locally configured administrative domains represented by those signatures.
    pub fn signer_trust_domains(&self) -> &[[u8; 32]] {
        &self.signer_trust_domains
    }
}

/// Release credential additionally bound to one exact authenticated Xenia execution.
///
/// This is the only credential form the disclosure-permit layer should consume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionBoundReleaseCredential {
    credential_id: [u8; 32],
    finalized_evidence_bundle_digest: [u8; 32],
    operation_id: Uuid,
    session: SessionTranscriptBinding,
    requester_source_id: [u8; 32],
    receipt_digest: [u8; 32],
    execution_binding_digest: [u8; 32],
    result_digest: Option<[u8; 32]>,
    ledger_entry_count: u64,
    ledger_head_hash: [u8; 32],
}

impl ExecutionBoundReleaseCredential {
    pub(crate) const fn credential_id(&self) -> [u8; 32] {
        self.credential_id
    }

    pub(crate) const fn finalized_evidence_bundle_digest(&self) -> [u8; 32] {
        self.finalized_evidence_bundle_digest
    }

    pub(crate) const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(crate) fn session(&self) -> &SessionTranscriptBinding {
        &self.session
    }

    pub(crate) const fn requester_source_id(&self) -> [u8; 32] {
        self.requester_source_id
    }

    pub(crate) const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    pub(crate) const fn execution_binding_digest(&self) -> [u8; 32] {
        self.execution_binding_digest
    }

    pub(crate) const fn result_digest(&self) -> Option<[u8; 32]> {
        self.result_digest
    }

    pub(crate) const fn ledger_entry_count(&self) -> u64 {
        self.ledger_entry_count
    }

    pub(crate) const fn ledger_head_hash(&self) -> [u8; 32] {
        self.ledger_head_hash
    }
}

/// Fail-closed release-credential verification failures.
#[derive(Debug, Error)]
pub enum ReleaseCredentialError {
    /// Statement schema is unsupported.
    #[error("unsupported SIF release credential schema: {schema}")]
    UnsupportedSchema { schema: String },
    /// Required commitment used an all-zero placeholder.
    #[error("SIF release credential commitment {field} must not be all-zero")]
    ZeroCommitment { field: &'static str },
    /// Signature threshold must be non-zero and feasible.
    #[error("invalid SIF release credential trust threshold")]
    InvalidTrustThreshold,
    /// Trusted authority configuration repeats a key root.
    #[error("trusted SIF release authority key appears more than once")]
    DuplicateTrustedAuthority,
    /// Trusted authority carries an invalid all-zero trust-domain ID.
    #[error("trusted SIF release authority has an all-zero trust-domain ID")]
    ZeroTrustedAuthorityDomain,
    /// Credential repeats a signer key.
    #[error("SIF release credential repeats a signer key")]
    DuplicateCredentialSignature,
    /// Credential signature algorithm is unsupported.
    #[error("unsupported SIF release credential signature algorithm")]
    UnsupportedSignatureAlgorithm,
    /// Credential signature references an authority not trusted by this deployment.
    #[error("SIF release credential signer is not a trusted release authority")]
    UntrustedReleaseAuthority,
    /// Credential signature length is not Ed25519's 64 bytes.
    #[error("invalid SIF release credential Ed25519 signature length")]
    InvalidSignatureLength,
    /// Trusted Ed25519 public key could not be parsed.
    #[error("invalid trusted SIF release authority public key")]
    InvalidAuthorityPublicKey,
    /// Mathematically invalid authority signature.
    #[error("invalid SIF release credential signature")]
    InvalidAuthoritySignature,
    /// Not enough trusted signatures verified.
    #[error("insufficient trusted SIF release credential signatures")]
    InsufficientTrustedSignatures,
    /// Not enough independently administered trust domains verified.
    #[error("insufficient distinct SIF release credential trust domains")]
    InsufficientTrustedDomains,
    /// Xenia execution proof itself failed verification.
    #[error(transparent)]
    ExecutionBinding(#[from] AccountabilityBindingError),
    /// Execution signature envelope could not be interpreted.
    #[error(transparent)]
    ExecutionSignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Credential and execution bind different semantic receipts.
    #[error("SIF release credential receipt does not match Xenia execution")]
    ReceiptMismatch,
    /// Credential names a different Xenia execution proof.
    #[error("SIF release credential execution proof does not match Xenia execution")]
    ExecutionProofMismatch,
    /// Credential and Xenia disagree about the execution verifier/key root.
    #[error("SIF release credential execution verifier identity mismatch")]
    ExecutionVerifierMismatch,
    /// Credential and local Xenia configuration disagree about execution administration.
    #[error("SIF release credential execution trust-domain mismatch")]
    ExecutionTrustDomainMismatch,
    /// Credential and execution bind different minimum-necessary results.
    #[error("SIF release credential result does not match Xenia execution")]
    ResultMismatch,
}

/// Verify the credential under local release-authority roots and threshold policy.
pub fn verify_release_credential(
    credential: &SifReleaseCredential,
    authorities: &[TrustedReleaseAuthority],
    policy: ReleaseCredentialTrustPolicy,
) -> Result<VerifiedReleaseCredential, ReleaseCredentialError> {
    validate_statement(&credential.statement)?;
    if policy.min_valid_signatures == 0
        || policy.min_distinct_trust_domains == 0
        || policy.min_distinct_trust_domains > policy.min_valid_signatures
    {
        return Err(ReleaseCredentialError::InvalidTrustThreshold);
    }

    let mut trusted = BTreeMap::new();
    for authority in authorities {
        if authority.trust_domain_id == [0u8; 32] {
            return Err(ReleaseCredentialError::ZeroTrustedAuthorityDomain);
        }
        if trusted.insert(authority.key_id(), *authority).is_some() {
            return Err(ReleaseCredentialError::DuplicateTrustedAuthority);
        }
    }

    let message = release_credential_message(&credential.statement);
    let mut seen_signers = BTreeSet::new();
    let mut verified_signers = Vec::new();
    let mut verified_domains = BTreeSet::new();

    for signature in &credential.signatures {
        if signature.algorithm != SIF_RELEASE_CREDENTIAL_ED25519 {
            return Err(ReleaseCredentialError::UnsupportedSignatureAlgorithm);
        }
        if !seen_signers.insert(signature.signer_key_id) {
            return Err(ReleaseCredentialError::DuplicateCredentialSignature);
        }
        let authority = trusted
            .get(&signature.signer_key_id)
            .ok_or(ReleaseCredentialError::UntrustedReleaseAuthority)?;
        let signature_bytes: [u8; 64] = signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ReleaseCredentialError::InvalidSignatureLength)?;
        let verifying_key = VerifyingKey::from_bytes(&authority.public_key)
            .map_err(|_| ReleaseCredentialError::InvalidAuthorityPublicKey)?;
        verifying_key
            .verify(&message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| ReleaseCredentialError::InvalidAuthoritySignature)?;
        verified_signers.push(signature.signer_key_id);
        verified_domains.insert(authority.trust_domain_id);
    }

    if verified_signers.len() < usize::from(policy.min_valid_signatures) {
        return Err(ReleaseCredentialError::InsufficientTrustedSignatures);
    }
    if verified_domains.len() < usize::from(policy.min_distinct_trust_domains) {
        return Err(ReleaseCredentialError::InsufficientTrustedDomains);
    }

    Ok(VerifiedReleaseCredential {
        statement: credential.statement.clone(),
        signer_key_ids: verified_signers,
        signer_trust_domains: verified_domains.into_iter().collect(),
    })
}

/// Verify that a trusted release credential names this exact Xenia execution.
///
/// `local_execution_trust_domain_id` comes from local Xenia policy/configuration;
/// the credential cannot self-assert its way into a trusted administrative domain.
pub fn bind_release_credential_to_execution(
    credential: &VerifiedReleaseCredential,
    execution: &AccountabilityExecutionAttestation,
    manifest: EvidenceCryptoManifest,
    execution_backend: &impl EvidenceSignatureBackend,
    execution_public_key: &[u8],
    local_execution_trust_domain_id: [u8; 32],
) -> Result<ExecutionBoundReleaseCredential, ReleaseCredentialError> {
    if local_execution_trust_domain_id == [0u8; 32] {
        return Err(ReleaseCredentialError::ExecutionTrustDomainMismatch);
    }
    execution.verify(manifest, execution_backend, execution_public_key)?;
    let binding = &execution.binding;
    let statement = &credential.statement;

    if statement.receipt_statement_digest != binding.receipt_digest {
        return Err(ReleaseCredentialError::ReceiptMismatch);
    }
    let execution_binding_digest = accountability_execution_binding_digest(binding);
    if statement.execution_proof_digest != execution_binding_digest {
        return Err(ReleaseCredentialError::ExecutionProofMismatch);
    }
    let suite = execution.signature.suite()?;
    let verifier_id = accountability_verifier_key_id(suite, execution_public_key);
    if statement.execution_verifier_id != verifier_id {
        return Err(ReleaseCredentialError::ExecutionVerifierMismatch);
    }
    if statement.execution_trust_domain_id != local_execution_trust_domain_id {
        return Err(ReleaseCredentialError::ExecutionTrustDomainMismatch);
    }
    if statement.result_digest != binding.result_digest {
        return Err(ReleaseCredentialError::ResultMismatch);
    }

    Ok(ExecutionBoundReleaseCredential {
        credential_id: statement.credential_id,
        finalized_evidence_bundle_digest: statement.finalized_evidence_bundle_digest,
        operation_id: binding.operation_id,
        session: binding.session.clone(),
        requester_source_id: binding.requester_source_id,
        receipt_digest: binding.receipt_digest,
        execution_binding_digest,
        result_digest: binding.result_digest,
        ledger_entry_count: binding.ledger_entry_count,
        ledger_head_hash: binding.ledger_head_hash,
    })
}

/// Exact canonical bytes signed by Mycelix release authorities.
pub fn release_credential_message(statement: &SifReleaseCredentialStatement) -> Vec<u8> {
    let mut out = Vec::with_capacity(420);
    out.extend_from_slice(RELEASE_CREDENTIAL_DOMAIN);
    out.push(0);
    out.extend_from_slice(SIF_RELEASE_CREDENTIAL_SCHEMA.as_bytes());
    out.push(0);
    out.extend_from_slice(SIF_RELEASE_CREDENTIAL_CODEC.as_bytes());
    out.push(0);
    push_digest(&mut out, statement.credential_id);
    push_digest(&mut out, statement.receipt_statement_digest);
    push_digest(&mut out, statement.pre_witness_bundle_digest);
    push_digest(&mut out, statement.finalized_evidence_bundle_digest);
    push_digest(&mut out, statement.accountability_policy_digest);
    push_digest(&mut out, statement.non_witness_trust_policy_digest);
    push_digest(&mut out, statement.witness_policy_digest);
    push_digest(&mut out, statement.execution_proof_digest);
    push_digest(&mut out, statement.execution_verifier_id);
    push_digest(&mut out, statement.execution_trust_domain_id);
    match statement.result_digest {
        Some(result) => {
            out.push(1);
            push_digest(&mut out, result);
        }
        None => out.push(0),
    }
    out
}

/// Stable release-authority key ID shared with Mycelix.
pub fn release_authority_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_AUTHORITY_KEY_DOMAIN);
    hasher.update(&[0]);
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

fn validate_statement(statement: &SifReleaseCredentialStatement) -> Result<(), ReleaseCredentialError> {
    if statement.schema != SIF_RELEASE_CREDENTIAL_SCHEMA {
        return Err(ReleaseCredentialError::UnsupportedSchema {
            schema: statement.schema.clone(),
        });
    }
    require_nonzero("credential_id", &statement.credential_id)?;
    require_nonzero("receipt_statement_digest", &statement.receipt_statement_digest)?;
    require_nonzero("pre_witness_bundle_digest", &statement.pre_witness_bundle_digest)?;
    require_nonzero(
        "finalized_evidence_bundle_digest",
        &statement.finalized_evidence_bundle_digest,
    )?;
    require_nonzero(
        "accountability_policy_digest",
        &statement.accountability_policy_digest,
    )?;
    require_nonzero(
        "non_witness_trust_policy_digest",
        &statement.non_witness_trust_policy_digest,
    )?;
    require_nonzero("witness_policy_digest", &statement.witness_policy_digest)?;
    require_nonzero("execution_proof_digest", &statement.execution_proof_digest)?;
    require_nonzero("execution_verifier_id", &statement.execution_verifier_id)?;
    require_nonzero(
        "execution_trust_domain_id",
        &statement.execution_trust_domain_id,
    )?;
    if let Some(result) = &statement.result_digest {
        require_nonzero("result_digest", result)?;
    }
    Ok(())
}

fn push_digest(out: &mut Vec<u8>, digest: [u8; 32]) {
    out.extend_from_slice(&digest);
}

fn require_nonzero(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), ReleaseCredentialError> {
    if *digest == [0u8; 32] {
        return Err(ReleaseCredentialError::ZeroCommitment { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn statement() -> SifReleaseCredentialStatement {
        SifReleaseCredentialStatement {
            schema: SIF_RELEASE_CREDENTIAL_SCHEMA.into(),
            credential_id: [1u8; 32],
            receipt_statement_digest: [2u8; 32],
            pre_witness_bundle_digest: [3u8; 32],
            finalized_evidence_bundle_digest: [4u8; 32],
            accountability_policy_digest: [5u8; 32],
            non_witness_trust_policy_digest: [6u8; 32],
            witness_policy_digest: [7u8; 32],
            execution_proof_digest: [8u8; 32],
            execution_verifier_id: [9u8; 32],
            execution_trust_domain_id: [10u8; 32],
            result_digest: Some([11u8; 32]),
        }
    }

    fn sign(statement: &SifReleaseCredentialStatement, key: &SigningKey) -> SifReleaseCredentialSignature {
        SifReleaseCredentialSignature {
            algorithm: SIF_RELEASE_CREDENTIAL_ED25519.into(),
            signer_key_id: release_authority_key_id(&key.verifying_key().to_bytes()),
            signature: key.sign(&release_credential_message(statement)).to_bytes().to_vec(),
        }
    }

    #[test]
    fn threshold_requires_independent_local_domains() {
        let statement = statement();
        let key_a = SigningKey::from_bytes(&[41u8; 32]);
        let key_b = SigningKey::from_bytes(&[42u8; 32]);
        let credential = SifReleaseCredential {
            statement: statement.clone(),
            signatures: vec![sign(&statement, &key_a), sign(&statement, &key_b)],
        };
        let same_domain = [90u8; 32];
        let authorities = [
            TrustedReleaseAuthority {
                public_key: key_a.verifying_key().to_bytes(),
                trust_domain_id: same_domain,
            },
            TrustedReleaseAuthority {
                public_key: key_b.verifying_key().to_bytes(),
                trust_domain_id: same_domain,
            },
        ];
        assert!(matches!(
            verify_release_credential(
                &credential,
                &authorities,
                ReleaseCredentialTrustPolicy {
                    min_valid_signatures: 2,
                    min_distinct_trust_domains: 2,
                },
            ),
            Err(ReleaseCredentialError::InsufficientTrustedDomains)
        ));
    }

    #[test]
    fn two_independent_release_authorities_verify() {
        let statement = statement();
        let key_a = SigningKey::from_bytes(&[41u8; 32]);
        let key_b = SigningKey::from_bytes(&[42u8; 32]);
        let credential = SifReleaseCredential {
            statement: statement.clone(),
            signatures: vec![sign(&statement, &key_a), sign(&statement, &key_b)],
        };
        let authorities = [
            TrustedReleaseAuthority {
                public_key: key_a.verifying_key().to_bytes(),
                trust_domain_id: [91u8; 32],
            },
            TrustedReleaseAuthority {
                public_key: key_b.verifying_key().to_bytes(),
                trust_domain_id: [92u8; 32],
            },
        ];
        let verified = verify_release_credential(
            &credential,
            &authorities,
            ReleaseCredentialTrustPolicy {
                min_valid_signatures: 2,
                min_distinct_trust_domains: 2,
            },
        )
        .unwrap();
        assert_eq!(verified.credential_id(), [1u8; 32]);
        assert_eq!(verified.signer_key_ids().len(), 2);
        assert_eq!(verified.signer_trust_domains().len(), 2);
    }

    #[test]
    fn tampered_statement_rejects_existing_signature() {
        let mut statement = statement();
        let key = SigningKey::from_bytes(&[41u8; 32]);
        let signature = sign(&statement, &key);
        statement.finalized_evidence_bundle_digest = [99u8; 32];
        let credential = SifReleaseCredential {
            statement,
            signatures: vec![signature],
        };
        let authorities = [TrustedReleaseAuthority {
            public_key: key.verifying_key().to_bytes(),
            trust_domain_id: [91u8; 32],
        }];
        assert!(matches!(
            verify_release_credential(
                &credential,
                &authorities,
                ReleaseCredentialTrustPolicy {
                    min_valid_signatures: 1,
                    min_distinct_trust_domains: 1,
                },
            ),
            Err(ReleaseCredentialError::InvalidAuthoritySignature)
        ));
    }
}
