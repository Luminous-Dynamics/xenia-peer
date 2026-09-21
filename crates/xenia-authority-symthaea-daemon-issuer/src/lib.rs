// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Delegated daemon-issuer authentication for portable Xenia→Symthaea
//! authorization receipts.
//!
//! XENIA-SYM-001D2 proves that one exact Ed25519 + ML-DSA-65 pair verified the
//! portable receipt. This tranche proves that the same pair is jointly
//! delegated by Xenia's existing host-signed [`DaemonIdentityCertificate`]
//! and that the derived host identity matches both the receipt's signed host
//! fingerprint and an independently expected/pinned fingerprint.
//!
//! This remains issuer authentication only. It does not admit Symthaea
//! evidence, qualify a claim, or authorize any runtime action.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use thiserror::Error;
use xenia_handshake::{
    HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, host_identity_fingerprint,
};
use xenia_operator_proto::{DaemonIdentityCertificate, daemon_delegation_transcript};
use xenia_symthaea_daemon_authority_crypto::{
    VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1,
    XeniaSymthaeaDaemonVerifyingKeysV1,
};

/// Positive result proving that D2's exact verifying pair is jointly delegated
/// by the expected Xenia daemon host identity.
#[derive(Debug)]
pub struct AuthenticatedXeniaSymthaeaDaemonIssuerV1 {
    verified_signatures: VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1,
    host_fingerprint: [u8; 32],
}

impl AuthenticatedXeniaSymthaeaDaemonIssuerV1 {
    /// D2 result whose exact verifying pair was authenticated by this tranche.
    pub fn verified_signatures(&self) -> &VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1 {
        &self.verified_signatures
    }

    /// Host fingerprint independently derived from the host public keys in the
    /// verified daemon identity certificate.
    pub fn host_fingerprint(&self) -> &[u8; 32] {
        &self.host_fingerprint
    }
}

#[derive(Debug)]
struct VerifiedDaemonDelegationV1 {
    delegated_keys: XeniaSymthaeaDaemonVerifyingKeysV1,
    host_fingerprint: [u8; 32],
}

/// Authenticate D2's exact verifying pair as the delegated HTTP-auth identity
/// of one expected Xenia daemon host.
///
/// `expected_host_fingerprint` must come from an independently trusted caller
/// view (for example a pin/TOFU store or an authenticated session binding). It
/// is not learned from the receipt or certificate itself.
pub fn authenticate_xenia_symthaea_daemon_issuer_v1(
    verified: VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1,
    certificate: &DaemonIdentityCertificate,
    expected_host_fingerprint: [u8; 32],
) -> Result<AuthenticatedXeniaSymthaeaDaemonIssuerV1, XeniaSymthaeaDaemonIssuerError> {
    let delegation = verify_daemon_delegation_certificate(certificate)?;

    if verified.verifying_keys() != &delegation.delegated_keys {
        return Err(XeniaSymthaeaDaemonIssuerError::DelegatedPairMismatch);
    }

    if verified.receipt().decision.daemon_host_fingerprint != delegation.host_fingerprint {
        return Err(XeniaSymthaeaDaemonIssuerError::ReceiptHostFingerprintMismatch);
    }

    if expected_host_fingerprint != delegation.host_fingerprint {
        return Err(XeniaSymthaeaDaemonIssuerError::ExpectedHostFingerprintMismatch);
    }

    Ok(AuthenticatedXeniaSymthaeaDaemonIssuerV1 {
        verified_signatures: verified,
        host_fingerprint: delegation.host_fingerprint,
    })
}

fn verify_daemon_delegation_certificate(
    certificate: &DaemonIdentityCertificate,
) -> Result<VerifiedDaemonDelegationV1, XeniaSymthaeaDaemonIssuerError> {
    let host_ed25519 = decode_fixed_hex::<32>(&certificate.host_ed25519_pubkey)?;
    let host_ml_dsa_65 =
        decode_fixed_hex::<ML_DSA_65_PK_LEN>(&certificate.host_ml_dsa_pubkey)?;
    let delegated_ed25519 = decode_fixed_hex::<32>(&certificate.http_auth_ed25519_pubkey)?;
    let delegated_ml_dsa_65 =
        decode_fixed_hex::<ML_DSA_65_PK_LEN>(&certificate.http_auth_ml_dsa_pubkey)?;
    let host_ed_signature = decode_fixed_hex::<64>(&certificate.host_ed_signature)?;
    let host_ml_dsa_signature =
        decode_fixed_hex::<ML_DSA_65_SIG_LEN>(&certificate.host_ml_dsa_signature)?;

    let host_ed_key = HandshakeManager::parse_peer_public_key(&host_ed25519)
        .map_err(|_| XeniaSymthaeaDaemonIssuerError::MalformedCertificate)?;
    let transcript = daemon_delegation_transcript(&delegated_ed25519, &delegated_ml_dsa_65);

    HandshakeManager::verify(
        &host_ed_key,
        &transcript,
        &Signature::from_bytes(&host_ed_signature),
    )
    .map_err(|_| XeniaSymthaeaDaemonIssuerError::HostEd25519DelegationInvalid)?;

    HandshakeManager::verify_ml_dsa(&host_ml_dsa_65, &transcript, &host_ml_dsa_signature)
        .map_err(|_| XeniaSymthaeaDaemonIssuerError::HostMlDsaDelegationInvalid)?;

    Ok(VerifiedDaemonDelegationV1 {
        delegated_keys: XeniaSymthaeaDaemonVerifyingKeysV1 {
            ed25519: delegated_ed25519,
            ml_dsa_65: delegated_ml_dsa_65,
        },
        host_fingerprint: host_identity_fingerprint(&host_ed25519, &host_ml_dsa_65),
    })
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], XeniaSymthaeaDaemonIssuerError> {
    let decoded = hex::decode(value.trim())
        .map_err(|_| XeniaSymthaeaDaemonIssuerError::MalformedCertificate)?;
    decoded
        .try_into()
        .map_err(|_| XeniaSymthaeaDaemonIssuerError::MalformedCertificate)
}

/// Issuer-authentication failures for XENIA-SYM-001D3.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum XeniaSymthaeaDaemonIssuerError {
    /// Certificate fields are malformed or contain an invalid Ed25519 key.
    #[error("malformed Xenia daemon identity certificate")]
    MalformedCertificate,
    /// Host Ed25519 delegation signature does not authenticate the delegated pair.
    #[error("Xenia daemon host Ed25519 delegation signature is invalid")]
    HostEd25519DelegationInvalid,
    /// Host ML-DSA-65 delegation signature does not authenticate the delegated pair.
    #[error("Xenia daemon host ML-DSA-65 delegation signature is invalid")]
    HostMlDsaDelegationInvalid,
    /// The exact pair that established D2 is not the pair delegated by the certificate.
    #[error("D2 verifying pair does not match the daemon certificate delegated pair")]
    DelegatedPairMismatch,
    /// D1 signed a daemon host fingerprint different from the verified certificate host.
    #[error("D1 daemon host fingerprint does not match the verified daemon certificate")]
    ReceiptHostFingerprintMismatch,
    /// Verified certificate host is not the independently expected/pinned daemon.
    #[error("verified daemon certificate does not match the expected host fingerprint")]
    ExpectedHostFingerprintMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use xenia_handshake::MlDsaIdentity;
    use xenia_symthaea_attestation_contract::{
        DigestAlgorithmV1, HybridSignatureBundleV1, ReceiptDigestV1, XeniaHybridSuiteV1,
    };
    use xenia_symthaea_daemon_authority_crypto::verify_xenia_symthaea_daemon_authorization_signatures_v1;
    use xenia_symthaea_daemon_authority_receipt::{
        PortableSymthaeaAuthorityScopeV1, SignedXeniaSymthaeaDaemonAuthorizationReceiptV1,
        XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1,
        XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1, XeniaSymthaeaDaemonAuthorizationDecisionV1,
    };

    fn decision(host_fingerprint: [u8; 32]) -> XeniaSymthaeaDaemonAuthorizationDecisionV1 {
        XeniaSymthaeaDaemonAuthorizationDecisionV1 {
            schema_version: XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1,
            decision_nonce: [0xA1; 32],
            receipt_id: [0x11; 16],
            receipt_digest: ReceiptDigestV1 {
                algorithm: DigestAlgorithmV1::Sha256,
                bytes: [0x22; 32],
            },
            enrollment_id: "enrollment:alice:v1".into(),
            signer_id: "operator:alice".into(),
            key_lineage_commitment: "sha256:lineage".into(),
            authority_scope: PortableSymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
            rbac_policy_version: XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1,
            daemon_host_fingerprint: host_fingerprint,
            issued_unix_s: 100,
            valid_until_unix_s: 200,
            suite: XeniaHybridSuiteV1::Ed25519MlDsa65V1,
        }
    }

    fn http_identity(ed_seed: u8, ml_seed: u8) -> (SigningKey, MlDsaIdentity) {
        (
            SigningKey::from_bytes(&[ed_seed; 32]),
            MlDsaIdentity::from_seed([ml_seed; 32]),
        )
    }

    fn sign_fixture(
        decision: XeniaSymthaeaDaemonAuthorizationDecisionV1,
        http_ed: &SigningKey,
        http_ml: &MlDsaIdentity,
    ) -> SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
        let transcript = decision.canonical_signing_transcript().unwrap();
        SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
            decision,
            signatures: HybridSignatureBundleV1 {
                ed25519: http_ed.sign(&transcript).to_bytes(),
                ml_dsa_65: http_ml.sign(&transcript).to_vec(),
            },
        }
    }

    fn certificate_for(
        host: &HandshakeManager,
        http_ed: &SigningKey,
        http_ml: &MlDsaIdentity,
    ) -> DaemonIdentityCertificate {
        let delegated_ed = http_ed.verifying_key().to_bytes();
        let delegated_ml = http_ml.public_key_bytes();
        let transcript = daemon_delegation_transcript(&delegated_ed, &delegated_ml);
        DaemonIdentityCertificate {
            host_ed25519_pubkey: hex::encode(host.identity_public_key_bytes()),
            host_ml_dsa_pubkey: hex::encode(host.ml_dsa_public_key_bytes()),
            http_auth_ed25519_pubkey: hex::encode(delegated_ed),
            http_auth_ml_dsa_pubkey: hex::encode(delegated_ml),
            host_ed_signature: hex::encode(host.sign(&transcript).to_bytes()),
            host_ml_dsa_signature: hex::encode(host.sign_ml_dsa(&transcript)),
        }
    }

    fn d2_verified(
        host_fingerprint: [u8; 32],
        http_ed: &SigningKey,
        http_ml: &MlDsaIdentity,
    ) -> VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1 {
        let signed = sign_fixture(decision(host_fingerprint), http_ed, http_ml);
        let keys = XeniaSymthaeaDaemonVerifyingKeysV1 {
            ed25519: http_ed.verifying_key().to_bytes(),
            ml_dsa_65: http_ml.public_key_bytes(),
        };
        verify_xenia_symthaea_daemon_authorization_signatures_v1(signed, &keys, 150).unwrap()
    }

    #[test]
    fn genuine_delegated_pair_and_expected_host_authenticate() {
        let host = HandshakeManager::new();
        let (http_ed, http_ml) = http_identity(0x11, 0x21);
        let certificate = certificate_for(&host, &http_ed, &http_ml);
        let expected = host.identity_fingerprint();
        let verified = d2_verified(expected, &http_ed, &http_ml);

        let authenticated =
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, expected).unwrap();
        assert_eq!(authenticated.host_fingerprint(), &expected);
    }

    #[test]
    fn mixed_d2_pair_is_rejected_by_joint_delegation_binding() {
        let host = HandshakeManager::new();
        let (http_ed_a, http_ml_a) = http_identity(0x12, 0x22);
        let (_, http_ml_b) = http_identity(0x13, 0x23);
        let certificate = certificate_for(&host, &http_ed_a, &http_ml_a);
        let expected = host.identity_fingerprint();
        let verified = d2_verified(expected, &http_ed_a, &http_ml_b);

        assert_eq!(
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, expected)
                .unwrap_err(),
            XeniaSymthaeaDaemonIssuerError::DelegatedPairMismatch
        );
    }

    #[test]
    fn tampered_delegated_key_breaks_host_delegation_signature() {
        let host = HandshakeManager::new();
        let (http_ed, http_ml) = http_identity(0x14, 0x24);
        let mut certificate = certificate_for(&host, &http_ed, &http_ml);
        let (other_ed, _) = http_identity(0x15, 0x25);
        certificate.http_auth_ed25519_pubkey = hex::encode(other_ed.verifying_key().to_bytes());
        let expected = host.identity_fingerprint();
        let verified = d2_verified(expected, &http_ed, &http_ml);

        assert_eq!(
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, expected)
                .unwrap_err(),
            XeniaSymthaeaDaemonIssuerError::HostEd25519DelegationInvalid
        );
    }

    #[test]
    fn corrupt_host_ed25519_delegation_signature_fails_closed() {
        let host = HandshakeManager::new();
        let (http_ed, http_ml) = http_identity(0x16, 0x26);
        let mut certificate = certificate_for(&host, &http_ed, &http_ml);
        let mut signature = hex::decode(&certificate.host_ed_signature).unwrap();
        signature[0] ^= 1;
        certificate.host_ed_signature = hex::encode(signature);
        let expected = host.identity_fingerprint();
        let verified = d2_verified(expected, &http_ed, &http_ml);

        assert_eq!(
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, expected)
                .unwrap_err(),
            XeniaSymthaeaDaemonIssuerError::HostEd25519DelegationInvalid
        );
    }

    #[test]
    fn corrupt_host_ml_dsa_delegation_signature_fails_closed() {
        let host = HandshakeManager::new();
        let (http_ed, http_ml) = http_identity(0x17, 0x27);
        let mut certificate = certificate_for(&host, &http_ed, &http_ml);
        let mut signature = hex::decode(&certificate.host_ml_dsa_signature).unwrap();
        signature[0] ^= 1;
        certificate.host_ml_dsa_signature = hex::encode(signature);
        let expected = host.identity_fingerprint();
        let verified = d2_verified(expected, &http_ed, &http_ml);

        assert_eq!(
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, expected)
                .unwrap_err(),
            XeniaSymthaeaDaemonIssuerError::HostMlDsaDelegationInvalid
        );
    }

    #[test]
    fn receipt_signed_host_fingerprint_must_match_certificate_host() {
        let host = HandshakeManager::new();
        let (http_ed, http_ml) = http_identity(0x18, 0x28);
        let certificate = certificate_for(&host, &http_ed, &http_ml);
        let expected = host.identity_fingerprint();
        let verified = d2_verified([0x44; 32], &http_ed, &http_ml);

        assert_eq!(
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, expected)
                .unwrap_err(),
            XeniaSymthaeaDaemonIssuerError::ReceiptHostFingerprintMismatch
        );
    }

    #[test]
    fn independently_expected_host_must_match_verified_certificate() {
        let host = HandshakeManager::new();
        let (http_ed, http_ml) = http_identity(0x19, 0x29);
        let certificate = certificate_for(&host, &http_ed, &http_ml);
        let actual = host.identity_fingerprint();
        let verified = d2_verified(actual, &http_ed, &http_ml);

        assert_eq!(
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, [0x55; 32])
                .unwrap_err(),
            XeniaSymthaeaDaemonIssuerError::ExpectedHostFingerprintMismatch
        );
    }

    #[test]
    fn malformed_certificate_field_fails_before_positive_state() {
        let host = HandshakeManager::new();
        let (http_ed, http_ml) = http_identity(0x1A, 0x2A);
        let mut certificate = certificate_for(&host, &http_ed, &http_ml);
        certificate.host_ed25519_pubkey = "not-hex".into();
        let expected = host.identity_fingerprint();
        let verified = d2_verified(expected, &http_ed, &http_ml);

        assert_eq!(
            authenticate_xenia_symthaea_daemon_issuer_v1(verified, &certificate, expected)
                .unwrap_err(),
            XeniaSymthaeaDaemonIssuerError::MalformedCertificate
        );
    }
}
