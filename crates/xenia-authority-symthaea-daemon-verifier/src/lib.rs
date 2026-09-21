// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-cryptography verification of portable Xenia daemon authorization
//! receipts for Symthaea.
//!
//! This tranche authenticates a D1 receipt through Xenia's existing host →
//! delegated HTTP-auth trust chain. It requires an independently supplied host
//! fingerprint; a self-consistent attacker-generated host/certificate/receipt
//! chain is therefore insufficient.
//!
//! It still does not establish live daemon policy freshness after receipt
//! issuance, Symthaea evidence admission, claim qualification, or action
//! authorization.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use thiserror::Error;
use xenia_handshake::{
    HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, host_identity_fingerprint,
};
use xenia_operator_proto::{DaemonIdentityCertificate, daemon_delegation_transcript};
use xenia_symthaea_authorization_receipt::SignedXeniaSymthaeaAuthorizationReceiptV1;
use xenia_symthaea_daemon_certificate_commitment::{
    CanonicalDaemonIdentityCertificateV1, daemon_certificate_commitment_sha256_v1,
};

/// Caller-held expectations that bind a daemon response to one local request
/// and one independently trusted Xenia host identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedSymthaeaAuthorizationV1 {
    /// Independently pinned/trusted Xenia daemon host fingerprint.
    pub daemon_host_fingerprint: [u8; 32],
    /// Exact Symthaea verification-receipt UUID requested by the caller.
    pub symthaea_receipt_id: [u8; 16],
    /// Exact SHA-256 of the canonical Symthaea verification-receipt bytes.
    pub symthaea_receipt_digest_sha256: [u8; 32],
    /// Exact caller nonce used for this authorization request.
    pub request_nonce: [u8; 32],
    /// Expected verifier/runtime artifact commitment.
    pub verifier_artifact_commitment_sha256: [u8; 32],
    /// Minimum locally accepted authority-state epoch; prevents rollback below
    /// a state already observed by this verifier.
    pub minimum_authority_state_epoch: u64,
    /// Evaluation time used for the receipt validity window.
    pub now_unix_s: u64,
}

/// Positive result proving that one exact portable receipt was authenticated by
/// HTTP-auth keys delegated by the independently trusted Xenia host identity.
///
/// Fields are private so callers cannot construct this positive theorem from
/// parsed receipt fields alone.
#[derive(Clone, Debug)]
pub struct VerifiedXeniaSymthaeaAuthorizationReceiptV1 {
    signed: SignedXeniaSymthaeaAuthorizationReceiptV1,
    daemon_certificate_commitment_sha256: [u8; 32],
    daemon_host_fingerprint: [u8; 32],
}

impl VerifiedXeniaSymthaeaAuthorizationReceiptV1 {
    /// Exact signed portable receipt whose trust chain verified.
    pub fn signed(&self) -> &SignedXeniaSymthaeaAuthorizationReceiptV1 {
        &self.signed
    }

    /// Canonical commitment to the exact delegation certificate used.
    pub const fn daemon_certificate_commitment_sha256(&self) -> [u8; 32] {
        self.daemon_certificate_commitment_sha256
    }

    /// Independently pinned host fingerprint that authenticated the chain.
    pub const fn daemon_host_fingerprint(&self) -> [u8; 32] {
        self.daemon_host_fingerprint
    }
}

/// Verify one portable Xenia→Symthaea authorization receipt against the
/// existing host-identity delegation model plus caller-held request bindings.
pub fn verify_xenia_symthaea_authorization_receipt_v1(
    signed: SignedXeniaSymthaeaAuthorizationReceiptV1,
    daemon_certificate: &DaemonIdentityCertificate,
    expected: &ExpectedSymthaeaAuthorizationV1,
) -> Result<VerifiedXeniaSymthaeaAuthorizationReceiptV1, DaemonAuthorizationVerifierError> {
    if !signed.validate_structure() {
        return Err(DaemonAuthorizationVerifierError::MalformedReceipt);
    }
    if !signed.receipt.is_current_at(expected.now_unix_s) {
        return Err(DaemonAuthorizationVerifierError::ReceiptNotCurrent);
    }
    if signed.receipt.symthaea_receipt_id != expected.symthaea_receipt_id
        || signed.receipt.symthaea_receipt_digest_sha256
            != expected.symthaea_receipt_digest_sha256
        || signed.receipt.request_nonce != expected.request_nonce
        || signed.receipt.verifier_artifact_commitment_sha256
            != expected.verifier_artifact_commitment_sha256
    {
        return Err(DaemonAuthorizationVerifierError::RequestBindingMismatch);
    }
    if signed.receipt.authority_state_epoch < expected.minimum_authority_state_epoch {
        return Err(DaemonAuthorizationVerifierError::AuthorityEpochRollback);
    }

    let canonical_certificate = CanonicalDaemonIdentityCertificateV1::from_dto(daemon_certificate)
        .ok_or(DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    let certificate_commitment = daemon_certificate_commitment_sha256_v1(daemon_certificate)
        .ok_or(DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    if signed
        .receipt
        .daemon_delegation_certificate_digest_sha256
        != certificate_commitment
    {
        return Err(DaemonAuthorizationVerifierError::CertificateCommitmentMismatch);
    }

    let host_ed25519_pubkey: [u8; 32] = canonical_certificate
        .host_ed25519_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    let host_ml_dsa_pubkey: [u8; ML_DSA_65_PK_LEN] = canonical_certificate
        .host_ml_dsa_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    let http_auth_ed25519_pubkey: [u8; 32] = canonical_certificate
        .http_auth_ed25519_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    let http_auth_ml_dsa_pubkey: [u8; ML_DSA_65_PK_LEN] = canonical_certificate
        .http_auth_ml_dsa_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    let host_ed_signature: [u8; 64] = canonical_certificate
        .host_ed_signature
        .as_slice()
        .try_into()
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    let host_ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN] = canonical_certificate
        .host_ml_dsa_signature
        .as_slice()
        .try_into()
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;

    let delegation_transcript =
        daemon_delegation_transcript(&http_auth_ed25519_pubkey, &http_auth_ml_dsa_pubkey);
    let host_ed_vk = HandshakeManager::parse_peer_public_key(&host_ed25519_pubkey)
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    HandshakeManager::verify(
        &host_ed_vk,
        &delegation_transcript,
        &Signature::from_bytes(&host_ed_signature),
    )
    .map_err(|_| DaemonAuthorizationVerifierError::DaemonDelegationEd25519Invalid)?;
    HandshakeManager::verify_ml_dsa(
        &host_ml_dsa_pubkey,
        &delegation_transcript,
        &host_ml_dsa_signature,
    )
    .map_err(|_| DaemonAuthorizationVerifierError::DaemonDelegationMlDsaInvalid)?;

    let computed_host_fingerprint =
        host_identity_fingerprint(&host_ed25519_pubkey, &host_ml_dsa_pubkey);
    if computed_host_fingerprint != expected.daemon_host_fingerprint
        || signed.receipt.daemon_host_fingerprint != expected.daemon_host_fingerprint
    {
        return Err(DaemonAuthorizationVerifierError::HostTrustMismatch);
    }

    let receipt_transcript = signed
        .receipt
        .canonical_signing_transcript()
        .ok_or(DaemonAuthorizationVerifierError::MalformedReceipt)?;
    let http_ed_vk = HandshakeManager::parse_peer_public_key(&http_auth_ed25519_pubkey)
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedDaemonCertificate)?;
    HandshakeManager::verify(
        &http_ed_vk,
        &receipt_transcript,
        &Signature::from_bytes(&signed.signatures.ed25519),
    )
    .map_err(|_| DaemonAuthorizationVerifierError::ReceiptEd25519Invalid)?;

    let receipt_ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN] = signed
        .signatures
        .ml_dsa_65
        .as_slice()
        .try_into()
        .map_err(|_| DaemonAuthorizationVerifierError::MalformedReceipt)?;
    HandshakeManager::verify_ml_dsa(
        &http_auth_ml_dsa_pubkey,
        &receipt_transcript,
        &receipt_ml_dsa_signature,
    )
    .map_err(|_| DaemonAuthorizationVerifierError::ReceiptMlDsaInvalid)?;

    Ok(VerifiedXeniaSymthaeaAuthorizationReceiptV1 {
        signed,
        daemon_certificate_commitment_sha256: certificate_commitment,
        daemon_host_fingerprint: computed_host_fingerprint,
    })
}

/// Fail-closed verification errors for the portable daemon authorization chain.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DaemonAuthorizationVerifierError {
    /// Portable receipt or hybrid bundle is structurally invalid.
    #[error("malformed Xenia Symthaea authorization receipt")]
    MalformedReceipt,
    /// Receipt is future-dated or expired at the caller's evaluation time.
    #[error("Xenia Symthaea authorization receipt is not current")]
    ReceiptNotCurrent,
    /// Receipt does not match the caller's exact request/subject/artifact binding.
    #[error("Xenia Symthaea authorization receipt request binding mismatch")]
    RequestBindingMismatch,
    /// Receipt advertises an authority epoch older than one already trusted locally.
    #[error("Xenia Symthaea authorization authority-state epoch rollback")]
    AuthorityEpochRollback,
    /// Daemon delegation certificate is malformed.
    #[error("malformed Xenia daemon delegation certificate")]
    MalformedDaemonCertificate,
    /// Receipt names a certificate commitment different from the supplied certificate.
    #[error("Xenia daemon delegation certificate commitment mismatch")]
    CertificateCommitmentMismatch,
    /// Host Ed25519 delegation signature failed.
    #[error("Xenia daemon Ed25519 delegation signature invalid")]
    DaemonDelegationEd25519Invalid,
    /// Host ML-DSA-65 delegation signature failed.
    #[error("Xenia daemon ML-DSA-65 delegation signature invalid")]
    DaemonDelegationMlDsaInvalid,
    /// Computed/presented host identity does not match the independently trusted pin.
    #[error("Xenia daemon host identity does not match trusted fingerprint")]
    HostTrustMismatch,
    /// Portable receipt Ed25519 signature failed against delegated HTTP-auth key.
    #[error("Xenia Symthaea authorization receipt Ed25519 signature invalid")]
    ReceiptEd25519Invalid,
    /// Portable receipt ML-DSA-65 signature failed against delegated HTTP-auth key.
    #[error("Xenia Symthaea authorization receipt ML-DSA-65 signature invalid")]
    ReceiptMlDsaInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_operator_proto::OperatorRole;
    use xenia_symthaea_attestation_contract::{
        HybridSignatureBundleV1, XeniaHybridSuiteV1,
    };
    use xenia_symthaea_authorization_receipt::XeniaSymthaeaAuthorizationReceiptV1;

    const RECEIPT_ID: [u8; 16] = [0x11; 16];
    const RECEIPT_DIGEST: [u8; 32] = [0x12; 32];
    const REQUEST_NONCE: [u8; 32] = [0x22; 32];
    const VERIFIER_ARTIFACT: [u8; 32] = [0x77; 32];

    struct Fixture {
        signed: SignedXeniaSymthaeaAuthorizationReceiptV1,
        certificate: DaemonIdentityCertificate,
        expected: ExpectedSymthaeaAuthorizationV1,
    }

    fn fixture() -> Fixture {
        let host = HandshakeManager::from_identity_seeds([0x01; 32], [0x02; 32]);
        let http = HandshakeManager::from_identity_seeds([0x03; 32], [0x04; 32]);

        let host_ed = host.identity_public_key_bytes();
        let host_ml = host.ml_dsa_public_key_bytes();
        let http_ed = http.identity_public_key_bytes();
        let http_ml = http.ml_dsa_public_key_bytes();
        let delegation = daemon_delegation_transcript(&http_ed, &http_ml);
        let certificate = DaemonIdentityCertificate {
            host_ed25519_pubkey: hex(&host_ed),
            host_ml_dsa_pubkey: hex(&host_ml),
            http_auth_ed25519_pubkey: hex(&http_ed),
            http_auth_ml_dsa_pubkey: hex(&http_ml),
            host_ed_signature: hex(&host.sign(&delegation).to_bytes()),
            host_ml_dsa_signature: hex(&host.sign_ml_dsa(&delegation)),
        };
        let certificate_commitment =
            daemon_certificate_commitment_sha256_v1(&certificate).unwrap();
        let host_fingerprint = host_identity_fingerprint(&host_ed, &host_ml);

        let receipt = XeniaSymthaeaAuthorizationReceiptV1::new(
            RECEIPT_ID,
            RECEIPT_DIGEST,
            REQUEST_NONCE,
            "operator:alice",
            OperatorRole::Admin,
            "sha256:operator-lineage",
            [0x33; 32],
            [0x44; 32],
            7,
            1000,
            1200,
            host_fingerprint,
            certificate_commitment,
            VERIFIER_ARTIFACT,
        )
        .unwrap();
        let receipt_transcript = receipt.canonical_signing_transcript().unwrap();
        let signed = SignedXeniaSymthaeaAuthorizationReceiptV1 {
            receipt,
            suite: XeniaHybridSuiteV1::Ed25519MlDsa65V1,
            signatures: HybridSignatureBundleV1 {
                ed25519: http.sign(&receipt_transcript).to_bytes(),
                ml_dsa_65: http.sign_ml_dsa(&receipt_transcript).to_vec(),
            },
        };
        let expected = ExpectedSymthaeaAuthorizationV1 {
            daemon_host_fingerprint: host_fingerprint,
            symthaea_receipt_id: RECEIPT_ID,
            symthaea_receipt_digest_sha256: RECEIPT_DIGEST,
            request_nonce: REQUEST_NONCE,
            verifier_artifact_commitment_sha256: VERIFIER_ARTIFACT,
            minimum_authority_state_epoch: 7,
            now_unix_s: 1100,
        };
        Fixture {
            signed,
            certificate,
            expected,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn exact_delegated_daemon_chain_verifies() {
        let f = fixture();
        let verified = verify_xenia_symthaea_authorization_receipt_v1(
            f.signed,
            &f.certificate,
            &f.expected,
        )
        .unwrap();
        assert_eq!(verified.daemon_host_fingerprint(), f.expected.daemon_host_fingerprint);
        assert_eq!(
            verified.signed().receipt.symthaea_receipt_id,
            f.expected.symthaea_receipt_id
        );
    }

    #[test]
    fn self_consistent_but_untrusted_host_is_rejected() {
        let mut f = fixture();
        f.expected.daemon_host_fingerprint[0] ^= 1;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                f.signed,
                &f.certificate,
                &f.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::HostTrustMismatch
        );
    }

    #[test]
    fn wrong_certificate_commitment_is_rejected() {
        let mut f = fixture();
        f.signed
            .receipt
            .daemon_delegation_certificate_digest_sha256[0] ^= 1;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                f.signed,
                &f.certificate,
                &f.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::CertificateCommitmentMismatch
        );
    }

    #[test]
    fn corrupted_certificate_and_receipt_signatures_fail_closed() {
        let mut cert_bad = fixture();
        cert_bad.certificate.host_ed_signature.replace_range(0..2, "00");
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                cert_bad.signed,
                &cert_bad.certificate,
                &cert_bad.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::CertificateCommitmentMismatch,
            "certificate mutation first invalidates the receipt-bound certificate commitment"
        );

        let mut ed_bad = fixture();
        ed_bad.signed.signatures.ed25519[0] ^= 1;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                ed_bad.signed,
                &ed_bad.certificate,
                &ed_bad.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::ReceiptEd25519Invalid
        );

        let mut pq_bad = fixture();
        pq_bad.signed.signatures.ml_dsa_65[0] ^= 1;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                pq_bad.signed,
                &pq_bad.certificate,
                &pq_bad.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::ReceiptMlDsaInvalid
        );
    }

    #[test]
    fn request_binding_and_epoch_rollback_fail_closed() {
        let mut wrong_nonce = fixture();
        wrong_nonce.expected.request_nonce[0] ^= 1;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                wrong_nonce.signed,
                &wrong_nonce.certificate,
                &wrong_nonce.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::RequestBindingMismatch
        );

        let mut rollback = fixture();
        rollback.expected.minimum_authority_state_epoch = 8;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                rollback.signed,
                &rollback.certificate,
                &rollback.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::AuthorityEpochRollback
        );
    }

    #[test]
    fn future_and_expired_receipts_fail_closed() {
        let mut future = fixture();
        future.expected.now_unix_s = 999;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                future.signed,
                &future.certificate,
                &future.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::ReceiptNotCurrent
        );

        let mut expired = fixture();
        expired.expected.now_unix_s = 1201;
        assert_eq!(
            verify_xenia_symthaea_authorization_receipt_v1(
                expired.signed,
                &expired.certificate,
                &expired.expected,
            )
            .unwrap_err(),
            DaemonAuthorizationVerifierError::ReceiptNotCurrent
        );
    }
}
