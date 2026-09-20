// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Current-enrollment and authority binding for verified Symthaea receipt attestations.
//!
//! XENIA-SYM-001B proves only that both signatures are valid over the exact
//! receipt-bound transcript. This crate adds the next independent theorem:
//! the exact Ed25519 + ML-DSA-65 pair belongs to one supplied authoritative
//! enrollment snapshot that is current, active, and explicitly scoped for
//! Symthaea verification-receipt attestation.
//!
//! It does not claim the underlying Symthaea verifier conclusion is true, does
//! not perform Symthaea/Mycelix evidence admission, and does not qualify claims.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use xenia_handshake::ML_DSA_65_PK_LEN;
use xenia_symthaea_attestation_contract::{ReceiptDigestV1, SHA256_LEN};
use xenia_symthaea_attestation_verifier::VerifiedSymthaeaAttestationSignaturesV1;

/// Provider namespace accepted by this Xenia-owned authority adapter.
pub const XENIA_SYMTHAEA_PROVIDER_NAMESPACE_V1: &str = "luminous-dynamics/xenia";
/// Domain separator for the exact enrolled signing-key lineage.
pub const SYMTHAEA_KEY_LINEAGE_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-attestation/key-lineage/v1\0";
/// Stable authority-scope spelling for Symthaea receipt attestation.
pub const SYMTHAEA_RECEIPT_ATTESTATION_SCOPE_V1: &str =
    "attest:symthaea-verification-receipt:v1";
/// Defensive bound for supplied logical identity strings.
pub const MAX_AUTHORITY_IDENTIFIER_BYTES: usize = 4 * 1024;

/// Current lifecycle state of one authoritative enrollment snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentStatusV1 {
    /// The enrollment may participate in authority decisions subject to time and scope.
    Active,
    /// The enrollment has been explicitly revoked.
    Revoked,
}

/// Explicit authority scopes carried by an enrollment snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymthaeaAuthorityScopeV1 {
    /// Authority to attest to Symthaea verification-receipt transcripts.
    VerificationReceiptAttestationV1,
}

impl SymthaeaAuthorityScopeV1 {
    /// Stable scope identifier suitable for portable downstream receipts/grants.
    pub const fn id(self) -> &'static str {
        match self {
            Self::VerificationReceiptAttestationV1 => SYMTHAEA_RECEIPT_ATTESTATION_SCOPE_V1,
        }
    }
}

/// Authoritative current enrollment input supplied by Xenia policy/state.
///
/// This crate does not itself own the enrollment database. A future daemon
/// adapter must construct this value from the real current Xenia enrollment and
/// policy state rather than caller-controlled request contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledSymthaeaAttestationIdentityV1 {
    /// Stable enrollment record identifier for audit correlation.
    pub enrollment_id: String,
    /// Stable logical Xenia signer identity.
    pub signer_id: String,
    /// Exact currently enrolled Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Exact currently enrolled ML-DSA-65 public key.
    pub ml_dsa_65_pubkey: Vec<u8>,
    /// Enrollment lifecycle state.
    pub status: EnrollmentStatusV1,
    /// Explicit scopes granted by the authoritative policy snapshot.
    pub authority_scopes: Vec<SymthaeaAuthorityScopeV1>,
    /// Start of this enrollment/policy snapshot's validity interval.
    pub issued_unix_s: u64,
    /// Optional inclusive end of the validity interval.
    pub valid_until_unix_s: Option<u64>,
}

impl EnrolledSymthaeaAttestationIdentityV1 {
    /// Structural validity only; this does not establish that the snapshot came
    /// from the real daemon/policy store.
    pub fn validate_structure(&self) -> bool {
        bounded_nonempty(&self.enrollment_id)
            && bounded_nonempty(&self.signer_id)
            && self.ml_dsa_65_pubkey.len() == ML_DSA_65_PK_LEN
            && !self.authority_scopes.is_empty()
            && unique_scopes(&self.authority_scopes)
            && self
                .valid_until_unix_s
                .is_none_or(|deadline| deadline >= self.issued_unix_s)
    }

    /// Whether the supplied evaluation time falls inside the inclusive interval.
    pub fn is_current_at(&self, now_unix_s: u64) -> bool {
        self.issued_unix_s <= now_unix_s
            && self
                .valid_until_unix_s
                .is_none_or(|deadline| now_unix_s <= deadline)
    }

    /// Whether this enrollment explicitly contains `scope`.
    pub fn grants(&self, scope: SymthaeaAuthorityScopeV1) -> bool {
        self.authority_scopes.contains(&scope)
    }
}

/// Positive current-enrollment + authority result for one exact verified
/// Symthaea receipt attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedSymthaeaReceiptAttestationV1 {
    enrollment_id: String,
    signer_id: String,
    key_lineage_commitment: String,
    receipt_id: [u8; 16],
    payload_digest: ReceiptDigestV1,
    authority_scope: SymthaeaAuthorityScopeV1,
    authorized_at_unix_s: u64,
    valid_until_unix_s: Option<u64>,
}

impl AuthorizedSymthaeaReceiptAttestationV1 {
    /// Authoritative enrollment record used for the decision.
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }

    /// Stable logical signer identity.
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// Deterministic commitment to the exact jointly enrolled hybrid key pair.
    pub fn key_lineage_commitment(&self) -> &str {
        &self.key_lineage_commitment
    }

    /// Exact Symthaea receipt identity covered by the attestation.
    pub const fn receipt_id(&self) -> [u8; 16] {
        self.receipt_id
    }

    /// Exact canonical receipt digest authenticated by the signatures.
    pub fn payload_digest(&self) -> &ReceiptDigestV1 {
        &self.payload_digest
    }

    /// Exact authority scope that was established.
    pub const fn authority_scope(&self) -> SymthaeaAuthorityScopeV1 {
        self.authority_scope
    }

    /// Time at which this authority decision was evaluated.
    pub const fn authorized_at_unix_s(&self) -> u64 {
        self.authorized_at_unix_s
    }

    /// Inclusive expiry inherited from the authoritative enrollment snapshot.
    pub const fn valid_until_unix_s(&self) -> Option<u64> {
        self.valid_until_unix_s
    }
}

/// Bind already-verified hybrid signatures to one exact current enrollment and
/// explicit authority scope.
pub fn authorize_symthaea_receipt_attestation_v1(
    verified: VerifiedSymthaeaAttestationSignaturesV1,
    enrollment: &EnrolledSymthaeaAttestationIdentityV1,
    required_scope: SymthaeaAuthorityScopeV1,
    now_unix_s: u64,
) -> Result<AuthorizedSymthaeaReceiptAttestationV1, SymthaeaAttestationAuthorityError> {
    if !enrollment.validate_structure() {
        return Err(SymthaeaAttestationAuthorityError::InvalidEnrollment);
    }
    if enrollment.status != EnrollmentStatusV1::Active {
        return Err(SymthaeaAttestationAuthorityError::EnrollmentRevoked);
    }
    if now_unix_s < enrollment.issued_unix_s {
        return Err(SymthaeaAttestationAuthorityError::EnrollmentNotYetValid);
    }
    if enrollment
        .valid_until_unix_s
        .is_some_and(|deadline| now_unix_s > deadline)
    {
        return Err(SymthaeaAttestationAuthorityError::EnrollmentExpired);
    }
    if !enrollment.grants(required_scope) {
        return Err(SymthaeaAttestationAuthorityError::AuthorityScopeMissing);
    }

    let signed = verified.signed();
    if signed.ed25519_pubkey != enrollment.ed25519_pubkey
        || signed.ml_dsa_65_pubkey.as_slice() != enrollment.ml_dsa_65_pubkey.as_slice()
    {
        return Err(SymthaeaAttestationAuthorityError::EnrollmentKeyPairMismatch);
    }

    let attestation = &signed.attestation;
    if attestation.provider_namespace != XENIA_SYMTHAEA_PROVIDER_NAMESPACE_V1 {
        return Err(SymthaeaAttestationAuthorityError::ProviderNamespaceMismatch);
    }
    if attestation.signer_id != enrollment.signer_id {
        return Err(SymthaeaAttestationAuthorityError::SignerIdentityMismatch);
    }

    let derived_lineage = symthaea_key_lineage_commitment_v1(
        &enrollment.ed25519_pubkey,
        &enrollment.ml_dsa_65_pubkey,
    )?;
    if attestation.key_lineage_commitment != derived_lineage {
        return Err(SymthaeaAttestationAuthorityError::KeyLineageMismatch);
    }

    Ok(AuthorizedSymthaeaReceiptAttestationV1 {
        enrollment_id: enrollment.enrollment_id.clone(),
        signer_id: enrollment.signer_id.clone(),
        key_lineage_commitment: derived_lineage,
        receipt_id: attestation.receipt_id,
        payload_digest: attestation.payload_digest.clone(),
        authority_scope: required_scope,
        authorized_at_unix_s: now_unix_s,
        valid_until_unix_s: enrollment.valid_until_unix_s,
    })
}

/// Deterministic SHA-256 commitment to one exact jointly enrolled Ed25519 +
/// ML-DSA-65 key pair.
pub fn symthaea_key_lineage_commitment_v1(
    ed25519_pubkey: &[u8; 32],
    ml_dsa_65_pubkey: &[u8],
) -> Result<String, SymthaeaAttestationAuthorityError> {
    if ml_dsa_65_pubkey.len() != ML_DSA_65_PK_LEN {
        return Err(SymthaeaAttestationAuthorityError::MalformedEnrollmentKey);
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(SYMTHAEA_KEY_LINEAGE_DOMAIN_V1);
    push_bytes(&mut transcript, ed25519_pubkey)?;
    push_bytes(&mut transcript, ml_dsa_65_pubkey)?;
    let digest: [u8; SHA256_LEN] = Sha256::digest(transcript).into();
    Ok(format!("sha256:{}", hex(&digest)))
}

fn bounded_nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_AUTHORITY_IDENTIFIER_BYTES
}

fn unique_scopes(scopes: &[SymthaeaAuthorityScopeV1]) -> bool {
    scopes
        .iter()
        .enumerate()
        .all(|(index, scope)| !scopes[..index].contains(scope))
}

fn push_bytes(
    out: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), SymthaeaAttestationAuthorityError> {
    let len = u32::try_from(value.len())
        .map_err(|_| SymthaeaAttestationAuthorityError::CanonicalFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Enrollment/authority-binding failures.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SymthaeaAttestationAuthorityError {
    /// Authoritative enrollment snapshot is structurally malformed.
    #[error("invalid Symthaea attestation enrollment snapshot")]
    InvalidEnrollment,
    /// Enrollment is explicitly revoked.
    #[error("Symthaea attestation enrollment is revoked")]
    EnrollmentRevoked,
    /// Enrollment's validity interval has not begun.
    #[error("Symthaea attestation enrollment is not yet valid")]
    EnrollmentNotYetValid,
    /// Enrollment's validity interval has expired.
    #[error("Symthaea attestation enrollment has expired")]
    EnrollmentExpired,
    /// Required Symthaea attestation scope is absent.
    #[error("Symthaea attestation authority scope is missing")]
    AuthorityScopeMissing,
    /// Verified signatures do not use the exact jointly enrolled key pair.
    #[error("verified Symthaea attestation key pair does not match enrollment")]
    EnrollmentKeyPairMismatch,
    /// Attestation names a provider other than this Xenia adapter.
    #[error("Symthaea attestation provider namespace mismatch")]
    ProviderNamespaceMismatch,
    /// Attestation signer id differs from the authoritative enrollment identity.
    #[error("Symthaea attestation signer identity mismatch")]
    SignerIdentityMismatch,
    /// Attestation key-lineage commitment is not derived from the exact enrolled pair.
    #[error("Symthaea attestation key-lineage commitment mismatch")]
    KeyLineageMismatch,
    /// Enrollment contains malformed ML-DSA-65 key material.
    #[error("malformed enrolled ML-DSA-65 public key")]
    MalformedEnrollmentKey,
    /// Canonical lineage field cannot be length encoded.
    #[error("canonical Symthaea key-lineage field is too large")]
    CanonicalFieldTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_handshake::HandshakeManager;
    use xenia_symthaea_attestation_contract::{
        ED25519_SIGNATURE_LEN, HybridSignatureBundleV1, ML_DSA_65_SIGNATURE_LEN,
        SymthaeaReceiptAttestationV1, XeniaHybridSuiteV1,
    };
    use xenia_symthaea_attestation_verifier::{
        SignedSymthaeaReceiptAttestationV1, verify_symthaea_attestation_signatures_v1,
    };

    const RECEIPT_BYTES: &[u8] = b"canonical-symthaea-receipt-fixture-v1";

    fn unsigned_attestation(lineage: String) -> SymthaeaReceiptAttestationV1 {
        SymthaeaReceiptAttestationV1::new(
            RECEIPT_BYTES,
            1,
            [0x11; 16],
            XENIA_SYMTHAEA_PROVIDER_NAMESPACE_V1,
            "operator:alice",
            lineage,
            XeniaHybridSuiteV1::Ed25519MlDsa65V1,
            HybridSignatureBundleV1 {
                ed25519: [0; ED25519_SIGNATURE_LEN],
                ml_dsa_65: vec![0; ML_DSA_65_SIGNATURE_LEN],
            },
        )
        .unwrap()
    }

    fn signed_with(
        ed_signer: &HandshakeManager,
        pq_signer: &HandshakeManager,
        lineage_keys: (&[u8; 32], &[u8]),
    ) -> SignedSymthaeaReceiptAttestationV1 {
        let lineage = symthaea_key_lineage_commitment_v1(lineage_keys.0, lineage_keys.1).unwrap();
        let mut attestation = unsigned_attestation(lineage);
        let transcript = attestation.canonical_signing_transcript().unwrap();
        attestation.signatures.ed25519 = ed_signer.sign(&transcript).to_bytes();
        attestation.signatures.ml_dsa_65 = pq_signer.sign_ml_dsa(&transcript).to_vec();
        SignedSymthaeaReceiptAttestationV1 {
            attestation,
            ed25519_pubkey: ed_signer.identity_public_key_bytes(),
            ml_dsa_65_pubkey: pq_signer.ml_dsa_public_key_bytes().to_vec(),
        }
    }

    fn enrollment(signer: &HandshakeManager) -> EnrolledSymthaeaAttestationIdentityV1 {
        EnrolledSymthaeaAttestationIdentityV1 {
            enrollment_id: "enrollment:alice:v1".into(),
            signer_id: "operator:alice".into(),
            ed25519_pubkey: signer.identity_public_key_bytes(),
            ml_dsa_65_pubkey: signer.ml_dsa_public_key_bytes().to_vec(),
            status: EnrollmentStatusV1::Active,
            authority_scopes: vec![SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1],
            issued_unix_s: 100,
            valid_until_unix_s: Some(200),
        }
    }

    fn verified_for(signer: &HandshakeManager) -> VerifiedSymthaeaAttestationSignaturesV1 {
        let ed = signer.identity_public_key_bytes();
        let ml = signer.ml_dsa_public_key_bytes();
        let signed = signed_with(signer, signer, (&ed, &ml));
        verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, signed).unwrap()
    }

    #[test]
    fn exact_current_enrollment_and_scope_authorize() {
        let signer = HandshakeManager::from_identity_seeds([0x11; 32], [0x12; 32]);
        let expected_lineage = symthaea_key_lineage_commitment_v1(
            &signer.identity_public_key_bytes(),
            &signer.ml_dsa_public_key_bytes(),
        )
        .unwrap();
        let authorized = authorize_symthaea_receipt_attestation_v1(
            verified_for(&signer),
            &enrollment(&signer),
            SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
            150,
        )
        .unwrap();

        assert_eq!(authorized.signer_id(), "operator:alice");
        assert_eq!(authorized.key_lineage_commitment(), expected_lineage);
        assert_eq!(
            authorized.authority_scope().id(),
            SYMTHAEA_RECEIPT_ATTESTATION_SCOPE_V1
        );
    }

    #[test]
    fn mixed_individually_valid_pair_is_rejected_by_joint_enrollment() {
        let classical = HandshakeManager::from_identity_seeds([0x21; 32], [0x22; 32]);
        let pq = HandshakeManager::from_identity_seeds([0x23; 32], [0x24; 32]);
        let enrolled = enrollment(&classical);
        let ed = classical.identity_public_key_bytes();
        let ml = pq.ml_dsa_public_key_bytes();
        let signed = signed_with(&classical, &pq, (&ed, &ml));
        let verified = verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, signed).unwrap();

        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified,
                &enrolled,
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                150,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::EnrollmentKeyPairMismatch
        );
    }

    #[test]
    fn key_rotation_rejects_old_verified_pair() {
        let old = HandshakeManager::from_identity_seeds([0x31; 32], [0x32; 32]);
        let replacement = HandshakeManager::from_identity_seeds([0x33; 32], [0x34; 32]);
        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified_for(&old),
                &enrollment(&replacement),
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                150,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::EnrollmentKeyPairMismatch
        );
    }

    #[test]
    fn revoked_or_out_of_window_enrollment_fails_closed() {
        let signer = HandshakeManager::from_identity_seeds([0x41; 32], [0x42; 32]);
        let mut revoked = enrollment(&signer);
        revoked.status = EnrollmentStatusV1::Revoked;
        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified_for(&signer),
                &revoked,
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                150,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::EnrollmentRevoked
        );

        let current = enrollment(&signer);
        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified_for(&signer),
                &current,
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                99,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::EnrollmentNotYetValid
        );
        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified_for(&signer),
                &current,
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                201,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::EnrollmentExpired
        );
    }

    #[test]
    fn missing_scope_fails_closed() {
        let signer = HandshakeManager::from_identity_seeds([0x51; 32], [0x52; 32]);
        let mut enrolled = enrollment(&signer);
        enrolled.authority_scopes.clear();
        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified_for(&signer),
                &enrolled,
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                150,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::InvalidEnrollment
        );
    }

    #[test]
    fn provider_or_lineage_substitution_fails_closed() {
        let signer = HandshakeManager::from_identity_seeds([0x61; 32], [0x62; 32]);
        let ed = signer.identity_public_key_bytes();
        let ml = signer.ml_dsa_public_key_bytes();

        let mut wrong_provider = signed_with(&signer, &signer, (&ed, &ml));
        wrong_provider.attestation.provider_namespace = "other-provider".into();
        // Re-sign the modified transcript so this is a cryptographically valid
        // but policy-invalid provider substitution.
        let transcript = wrong_provider.attestation.canonical_signing_transcript().unwrap();
        wrong_provider.attestation.signatures.ed25519 = signer.sign(&transcript).to_bytes();
        wrong_provider.attestation.signatures.ml_dsa_65 = signer.sign_ml_dsa(&transcript).to_vec();
        let verified = verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, wrong_provider).unwrap();
        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified,
                &enrollment(&signer),
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                150,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::ProviderNamespaceMismatch
        );

        let mut wrong_lineage = signed_with(&signer, &signer, (&ed, &ml));
        wrong_lineage.attestation.key_lineage_commitment = "sha256:wrong".into();
        let transcript = wrong_lineage.attestation.canonical_signing_transcript().unwrap();
        wrong_lineage.attestation.signatures.ed25519 = signer.sign(&transcript).to_bytes();
        wrong_lineage.attestation.signatures.ml_dsa_65 = signer.sign_ml_dsa(&transcript).to_vec();
        let verified = verify_symthaea_attestation_signatures_v1(RECEIPT_BYTES, wrong_lineage).unwrap();
        assert_eq!(
            authorize_symthaea_receipt_attestation_v1(
                verified,
                &enrollment(&signer),
                SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                150,
            )
            .unwrap_err(),
            SymthaeaAttestationAuthorityError::KeyLineageMismatch
        );
    }
}
