// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent Xenia verifier for Mycelix SIF release credential v2.
//!
//! V2 is additive: the complete canonical v1 release statement remains embedded as
//! historical authority evidence, while a non-zero required SIF protected-transfer
//! profile is bound into a new credential ID and authority-signature domain. Xenia
//! intentionally has no source dependency on Mycelix; interoperability is the exact
//! canonical byte contract reproduced here.

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
use crate::release_credential::{
    ReleaseCredentialTrustPolicy, SIF_RELEASE_CREDENTIAL_ED25519, SIF_RELEASE_CREDENTIAL_SCHEMA,
    SifReleaseCredentialSignature, SifReleaseCredentialStatement, TrustedReleaseAuthority,
    release_authority_key_id, release_credential_message,
};
use crate::signature::{EvidenceSignatureBackend, SignatureEnvelopeError};

/// Exact schema published by `mycelix-accountability-credential-v2`.
pub const SIF_RELEASE_CREDENTIAL_V2_SCHEMA: &str = "sif-release-credential-v2";
/// Exact canonical byte profile published by Mycelix credential v2.
pub const SIF_RELEASE_CREDENTIAL_V2_CODEC: &str = "sif-release-credential-canonical-v2";

const RELEASE_CREDENTIAL_V2_MESSAGE_DOMAIN: &[u8] = b"sif:release-credential:statement:v2";
const RELEASE_CREDENTIAL_V2_ID_DOMAIN: &[u8] = b"sif:release-credential:id:v2";

/// Canonical commitment-only profile-bound authorization statement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SifReleaseCredentialStatementV2 {
    /// Exact v2 schema label.
    pub schema: String,
    /// Identity derived from the complete canonical v1 statement and required profile.
    pub credential_id: [u8; 32],
    /// Complete historical v1 release-credential statement.
    pub v1: SifReleaseCredentialStatement,
    /// Exact SIF protected-transfer profile required by upstream authorization.
    pub required_sif_profile_digest: [u8; 32],
}

impl SifReleaseCredentialStatementV2 {
    /// Validate outer schema, nested v1 statement, non-zero profile and derived ID.
    pub fn validate(&self) -> Result<(), ReleaseCredentialV2Error> {
        if self.schema != SIF_RELEASE_CREDENTIAL_V2_SCHEMA {
            return Err(ReleaseCredentialV2Error::UnsupportedSchema);
        }
        validate_nested_v1_statement(&self.v1)?;
        require_nonzero_profile(&self.required_sif_profile_digest)?;
        let expected = profile_bound_credential_id(&self.v1, self.required_sif_profile_digest);
        if self.credential_id != expected {
            return Err(ReleaseCredentialV2Error::CredentialIdMismatch);
        }
        Ok(())
    }
}

/// Portable multi-authority profile-bound credential.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SifReleaseCredentialV2 {
    /// Canonical v2 statement.
    pub statement: SifReleaseCredentialStatementV2,
    /// Independent authority signatures over the exact v2 signing message.
    pub signatures: Vec<SifReleaseCredentialSignature>,
}

/// Credential that passed Xenia's local release-authority threshold policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProfileBoundReleaseCredential {
    statement: SifReleaseCredentialStatementV2,
    signer_key_ids: Vec<[u8; 32]>,
    signer_trust_domains: Vec<[u8; 32]>,
}

impl VerifiedProfileBoundReleaseCredential {
    /// Exact v2 release-lineage credential identifier.
    pub const fn credential_id(&self) -> [u8; 32] {
        self.statement.credential_id
    }

    /// Profile that upstream Mycelix authorization requires Xenia to negotiate.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.statement.required_sif_profile_digest
    }

    /// Complete nested historical v1 authority statement.
    pub fn v1_statement(&self) -> &SifReleaseCredentialStatement {
        &self.statement.v1
    }

    /// Distinct release-authority key roots that actually verified.
    pub fn signer_key_ids(&self) -> &[[u8; 32]] {
        &self.signer_key_ids
    }

    /// Locally configured administrative domains represented by verified signatures.
    pub fn signer_trust_domains(&self) -> &[[u8; 32]] {
        &self.signer_trust_domains
    }
}

/// V2 authorization additionally bound to one exact authenticated Xenia execution.
///
/// This capability retains the required SIF profile so downstream disclosure code
/// never has to recover or infer it from an untrusted caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileBoundExecutionReleaseCredential {
    credential_id: [u8; 32],
    finalized_evidence_bundle_digest: [u8; 32],
    required_sif_profile_digest: [u8; 32],
    operation_id: Uuid,
    session: SessionTranscriptBinding,
    requester_source_id: [u8; 32],
    receipt_digest: [u8; 32],
    execution_binding_digest: [u8; 32],
    result_digest: Option<[u8; 32]>,
    ledger_entry_count: u64,
    ledger_head_hash: [u8; 32],
}

impl ProfileBoundExecutionReleaseCredential {
    pub(crate) const fn credential_id(&self) -> [u8; 32] {
        self.credential_id
    }

    pub(crate) const fn finalized_evidence_bundle_digest(&self) -> [u8; 32] {
        self.finalized_evidence_bundle_digest
    }

    /// Exact upstream-authorized SIF profile.
    pub const fn required_sif_profile_digest(&self) -> [u8; 32] {
        self.required_sif_profile_digest
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

/// Fail-closed v2 credential/interoperability failures.
#[derive(Debug, Error)]
pub enum ReleaseCredentialV2Error {
    /// Outer credential schema is not exact v2.
    #[error("unsupported profile-bound release credential schema")]
    UnsupportedSchema,
    /// Nested historical statement is not exact v1.
    #[error("profile-bound release credential does not contain an exact v1 statement")]
    NestedV1SchemaMismatch,
    /// Nested historical statement contains an all-zero required commitment.
    #[error("nested v1 release credential commitment {field} must not be all-zero")]
    NestedV1ZeroCommitment { field: &'static str },
    /// High-assurance release authorization requires an explicit profile.
    #[error("required SIF profile digest must not be all-zero")]
    ZeroRequiredSifProfile,
    /// Stored v2 credential identity does not match v1 statement + profile.
    #[error("profile-bound release credential ID mismatch")]
    CredentialIdMismatch,
    /// Signature threshold is zero, inconsistent or impossible for configured roots.
    #[error("invalid profile-bound release credential trust threshold")]
    InvalidTrustThreshold,
    /// Trusted authority configuration repeats a key root.
    #[error("trusted profile-bound release authority key appears more than once")]
    DuplicateTrustedAuthority,
    /// Trusted authority carries an invalid all-zero trust-domain identifier.
    #[error("trusted profile-bound release authority has an all-zero trust-domain ID")]
    ZeroTrustedAuthorityDomain,
    /// Credential repeats a signer key.
    #[error("profile-bound release credential repeats a signer key")]
    DuplicateCredentialSignature,
    /// Credential signature algorithm is not the v2 Ed25519 baseline.
    #[error("unsupported profile-bound release credential signature algorithm")]
    UnsupportedSignatureAlgorithm,
    /// Credential signature references a release authority not trusted locally.
    #[error("profile-bound release credential signer is not a trusted authority")]
    UntrustedReleaseAuthority,
    /// Signature length is not Ed25519's 64 bytes.
    #[error("invalid profile-bound release credential Ed25519 signature length")]
    InvalidSignatureLength,
    /// Trusted Ed25519 public key could not be parsed.
    #[error("invalid trusted profile-bound release authority public key")]
    InvalidAuthorityPublicKey,
    /// Authority signature failed verification.
    #[error("invalid profile-bound release credential signature")]
    InvalidAuthoritySignature,
    /// Not enough trusted signatures verified.
    #[error("insufficient trusted profile-bound release credential signatures")]
    InsufficientTrustedSignatures,
    /// Not enough independently administered trust domains verified.
    #[error("insufficient distinct profile-bound release credential trust domains")]
    InsufficientTrustedDomains,
    /// Xenia execution proof itself failed verification.
    #[error(transparent)]
    ExecutionBinding(#[from] AccountabilityBindingError),
    /// Execution signature envelope could not be interpreted.
    #[error(transparent)]
    ExecutionSignatureEnvelope(#[from] SignatureEnvelopeError),
    /// Credential and execution bind different semantic receipts.
    #[error("profile-bound release credential receipt does not match Xenia execution")]
    ReceiptMismatch,
    /// Credential and execution were evaluated under different accountability policies.
    #[error("profile-bound release credential policy does not match Xenia execution")]
    PolicyMismatch,
    /// Credential names a different Xenia execution proof.
    #[error("profile-bound release credential execution proof does not match Xenia execution")]
    ExecutionProofMismatch,
    /// Credential and Xenia disagree about the execution verifier/key root.
    #[error("profile-bound release credential execution verifier identity mismatch")]
    ExecutionVerifierMismatch,
    /// Credential and local Xenia configuration disagree about execution administration.
    #[error("profile-bound release credential execution trust-domain mismatch")]
    ExecutionTrustDomainMismatch,
    /// Credential and execution bind different minimum-necessary results.
    #[error("profile-bound release credential result does not match Xenia execution")]
    ResultMismatch,
}

/// Derive the v2 credential ID exactly as Mycelix PR #76 specifies it.
pub fn profile_bound_credential_id(
    v1: &SifReleaseCredentialStatement,
    required_sif_profile_digest: [u8; 32],
) -> [u8; 32] {
    let v1_message = release_credential_message(v1);
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_CREDENTIAL_V2_ID_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&(v1_message.len() as u64).to_be_bytes());
    hasher.update(&v1_message);
    hasher.update(&required_sif_profile_digest);
    *hasher.finalize().as_bytes()
}

/// Exact language-neutral v2 bytes signed by Mycelix release authorities.
pub fn release_credential_v2_message(
    statement: &SifReleaseCredentialStatementV2,
) -> Result<Vec<u8>, ReleaseCredentialV2Error> {
    statement.validate()?;
    let v1_message = release_credential_message(&statement.v1);
    let mut out = Vec::with_capacity(v1_message.len() + 160);
    out.extend_from_slice(RELEASE_CREDENTIAL_V2_MESSAGE_DOMAIN);
    out.push(0);
    out.extend_from_slice(SIF_RELEASE_CREDENTIAL_V2_SCHEMA.as_bytes());
    out.push(0);
    out.extend_from_slice(SIF_RELEASE_CREDENTIAL_V2_CODEC.as_bytes());
    out.push(0);
    out.extend_from_slice(&statement.credential_id);
    out.extend_from_slice(&(v1_message.len() as u64).to_be_bytes());
    out.extend_from_slice(&v1_message);
    out.extend_from_slice(&statement.required_sif_profile_digest);
    Ok(out)
}

/// Verify a profile-bound credential under local authority roots and threshold policy.
pub fn verify_release_credential_v2(
    credential: &SifReleaseCredentialV2,
    authorities: &[TrustedReleaseAuthority],
    policy: ReleaseCredentialTrustPolicy,
) -> Result<VerifiedProfileBoundReleaseCredential, ReleaseCredentialV2Error> {
    credential.statement.validate()?;
    if policy.min_valid_signatures == 0
        || policy.min_distinct_trust_domains == 0
        || policy.min_distinct_trust_domains > policy.min_valid_signatures
        || usize::from(policy.min_valid_signatures) > authorities.len()
    {
        return Err(ReleaseCredentialV2Error::InvalidTrustThreshold);
    }

    let mut trusted = BTreeMap::new();
    for authority in authorities {
        if authority.trust_domain_id == [0u8; 32] {
            return Err(ReleaseCredentialV2Error::ZeroTrustedAuthorityDomain);
        }
        if trusted.insert(authority.key_id(), *authority).is_some() {
            return Err(ReleaseCredentialV2Error::DuplicateTrustedAuthority);
        }
    }

    let message = release_credential_v2_message(&credential.statement)?;
    let mut seen_signers = BTreeSet::new();
    let mut verified_signers = Vec::new();
    let mut verified_domains = BTreeSet::new();

    for signature in &credential.signatures {
        if signature.algorithm != SIF_RELEASE_CREDENTIAL_ED25519 {
            return Err(ReleaseCredentialV2Error::UnsupportedSignatureAlgorithm);
        }
        if !seen_signers.insert(signature.signer_key_id) {
            return Err(ReleaseCredentialV2Error::DuplicateCredentialSignature);
        }
        let authority = trusted
            .get(&signature.signer_key_id)
            .ok_or(ReleaseCredentialV2Error::UntrustedReleaseAuthority)?;
        let signature_bytes: [u8; 64] = signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ReleaseCredentialV2Error::InvalidSignatureLength)?;
        let verifying_key = VerifyingKey::from_bytes(&authority.public_key)
            .map_err(|_| ReleaseCredentialV2Error::InvalidAuthorityPublicKey)?;
        verifying_key
            .verify(&message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| ReleaseCredentialV2Error::InvalidAuthoritySignature)?;
        verified_signers.push(signature.signer_key_id);
        verified_domains.insert(authority.trust_domain_id);
    }

    if verified_signers.len() < usize::from(policy.min_valid_signatures) {
        return Err(ReleaseCredentialV2Error::InsufficientTrustedSignatures);
    }
    if verified_domains.len() < usize::from(policy.min_distinct_trust_domains) {
        return Err(ReleaseCredentialV2Error::InsufficientTrustedDomains);
    }

    Ok(VerifiedProfileBoundReleaseCredential {
        statement: credential.statement.clone(),
        signer_key_ids: verified_signers,
        signer_trust_domains: verified_domains.into_iter().collect(),
    })
}

/// Bind a trusted v2 credential to the exact cryptographically verified Xenia execution.
pub fn bind_release_credential_v2_to_execution(
    credential: &VerifiedProfileBoundReleaseCredential,
    execution: &AccountabilityExecutionAttestation,
    manifest: EvidenceCryptoManifest,
    execution_backend: &impl EvidenceSignatureBackend,
    execution_public_key: &[u8],
    local_execution_trust_domain_id: [u8; 32],
) -> Result<ProfileBoundExecutionReleaseCredential, ReleaseCredentialV2Error> {
    if local_execution_trust_domain_id == [0u8; 32] {
        return Err(ReleaseCredentialV2Error::ExecutionTrustDomainMismatch);
    }
    execution.verify(manifest, execution_backend, execution_public_key)?;
    let binding = &execution.binding;
    let statement = &credential.statement.v1;

    if statement.receipt_statement_digest != binding.receipt_digest {
        return Err(ReleaseCredentialV2Error::ReceiptMismatch);
    }
    if statement.accountability_policy_digest != binding.policy_digest {
        return Err(ReleaseCredentialV2Error::PolicyMismatch);
    }
    let execution_binding_digest = accountability_execution_binding_digest(binding);
    if statement.execution_proof_digest != execution_binding_digest {
        return Err(ReleaseCredentialV2Error::ExecutionProofMismatch);
    }
    let suite = execution.signature.suite()?;
    let verifier_id = accountability_verifier_key_id(suite, execution_public_key);
    if statement.execution_verifier_id != verifier_id {
        return Err(ReleaseCredentialV2Error::ExecutionVerifierMismatch);
    }
    if statement.execution_trust_domain_id != local_execution_trust_domain_id {
        return Err(ReleaseCredentialV2Error::ExecutionTrustDomainMismatch);
    }
    if statement.result_digest != binding.result_digest {
        return Err(ReleaseCredentialV2Error::ResultMismatch);
    }

    Ok(ProfileBoundExecutionReleaseCredential {
        credential_id: credential.statement.credential_id,
        finalized_evidence_bundle_digest: statement.finalized_evidence_bundle_digest,
        required_sif_profile_digest: credential.statement.required_sif_profile_digest,
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

fn validate_nested_v1_statement(
    statement: &SifReleaseCredentialStatement,
) -> Result<(), ReleaseCredentialV2Error> {
    if statement.schema != SIF_RELEASE_CREDENTIAL_SCHEMA {
        return Err(ReleaseCredentialV2Error::NestedV1SchemaMismatch);
    }
    for (field, digest) in [
        ("credential_id", statement.credential_id),
        ("receipt_statement_digest", statement.receipt_statement_digest),
        ("pre_witness_bundle_digest", statement.pre_witness_bundle_digest),
        (
            "finalized_evidence_bundle_digest",
            statement.finalized_evidence_bundle_digest,
        ),
        (
            "accountability_policy_digest",
            statement.accountability_policy_digest,
        ),
        (
            "non_witness_trust_policy_digest",
            statement.non_witness_trust_policy_digest,
        ),
        ("witness_policy_digest", statement.witness_policy_digest),
        ("execution_proof_digest", statement.execution_proof_digest),
        ("execution_verifier_id", statement.execution_verifier_id),
        (
            "execution_trust_domain_id",
            statement.execution_trust_domain_id,
        ),
    ] {
        if digest == [0u8; 32] {
            return Err(ReleaseCredentialV2Error::NestedV1ZeroCommitment { field });
        }
    }
    if statement.result_digest == Some([0u8; 32]) {
        return Err(ReleaseCredentialV2Error::NestedV1ZeroCommitment {
            field: "result_digest",
        });
    }
    Ok(())
}

fn require_nonzero_profile(profile: &[u8; 32]) -> Result<(), ReleaseCredentialV2Error> {
    if *profile == [0u8; 32] {
        return Err(ReleaseCredentialV2Error::ZeroRequiredSifProfile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn v1_statement() -> SifReleaseCredentialStatement {
        SifReleaseCredentialStatement {
            schema: SIF_RELEASE_CREDENTIAL_SCHEMA.to_string(),
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

    fn statement(profile: [u8; 32]) -> SifReleaseCredentialStatementV2 {
        let v1 = v1_statement();
        SifReleaseCredentialStatementV2 {
            schema: SIF_RELEASE_CREDENTIAL_V2_SCHEMA.to_string(),
            credential_id: profile_bound_credential_id(&v1, profile),
            v1,
            required_sif_profile_digest: profile,
        }
    }

    fn v2_signature(
        statement: &SifReleaseCredentialStatementV2,
        key: &SigningKey,
    ) -> SifReleaseCredentialSignature {
        SifReleaseCredentialSignature {
            algorithm: SIF_RELEASE_CREDENTIAL_ED25519.to_string(),
            signer_key_id: release_authority_key_id(&key.verifying_key().to_bytes()),
            signature: key
                .sign(&release_credential_v2_message(statement).unwrap())
                .to_bytes()
                .to_vec(),
        }
    }

    #[test]
    fn mycelix_v2_semantics_profile_changes_id_and_message() {
        let p1 = statement([20u8; 32]);
        let p2 = statement([21u8; 32]);
        assert_ne!(p1.credential_id, p2.credential_id);
        assert_ne!(
            release_credential_v2_message(&p1).unwrap(),
            release_credential_v2_message(&p2).unwrap()
        );
    }

    #[test]
    fn zero_profile_fails_closed() {
        let statement = statement([0u8; 32]);
        assert!(matches!(
            statement.validate(),
            Err(ReleaseCredentialV2Error::ZeroRequiredSifProfile)
        ));
    }

    #[test]
    fn authority_signature_is_bound_to_exact_profile() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let p1 = statement([20u8; 32]);
        let p2 = statement([21u8; 32]);
        let credential = SifReleaseCredentialV2 {
            statement: p1.clone(),
            signatures: vec![v2_signature(&p1, &key)],
        };
        let authorities = [TrustedReleaseAuthority {
            public_key: key.verifying_key().to_bytes(),
            trust_domain_id: [90u8; 32],
        }];
        let policy = ReleaseCredentialTrustPolicy {
            min_valid_signatures: 1,
            min_distinct_trust_domains: 1,
        };
        verify_release_credential_v2(&credential, &authorities, policy).unwrap();

        let migrated = SifReleaseCredentialV2 {
            statement: p2,
            signatures: credential.signatures,
        };
        assert!(matches!(
            verify_release_credential_v2(&migrated, &authorities, policy),
            Err(ReleaseCredentialV2Error::InvalidAuthoritySignature)
        ));
    }

    #[test]
    fn valid_v1_signature_cannot_satisfy_v2() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let statement = statement([20u8; 32]);
        let signature = SifReleaseCredentialSignature {
            algorithm: SIF_RELEASE_CREDENTIAL_ED25519.to_string(),
            signer_key_id: release_authority_key_id(&key.verifying_key().to_bytes()),
            signature: key
                .sign(&release_credential_message(&statement.v1))
                .to_bytes()
                .to_vec(),
        };
        let credential = SifReleaseCredentialV2 {
            statement,
            signatures: vec![signature],
        };
        let authorities = [TrustedReleaseAuthority {
            public_key: key.verifying_key().to_bytes(),
            trust_domain_id: [90u8; 32],
        }];
        let policy = ReleaseCredentialTrustPolicy {
            min_valid_signatures: 1,
            min_distinct_trust_domains: 1,
        };
        assert!(matches!(
            verify_release_credential_v2(&credential, &authorities, policy),
            Err(ReleaseCredentialV2Error::InvalidAuthoritySignature)
        ));
    }

    #[test]
    fn tampered_derived_id_fails_before_signature_verification() {
        let mut statement = statement([20u8; 32]);
        statement.credential_id = [99u8; 32];
        assert!(matches!(
            statement.validate(),
            Err(ReleaseCredentialV2Error::CredentialIdMismatch)
        ));
    }
}
