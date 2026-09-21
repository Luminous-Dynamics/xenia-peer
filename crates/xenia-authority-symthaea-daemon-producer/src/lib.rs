// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Producer-gated daemon signing for portable Xenia→Symthaea authority receipts.
//!
//! The public signing API accepts only XENIA-SYM-001C's private-construction
//! [`AuthorizedSymthaeaReceiptAttestationV1`]. It does not accept an arbitrary
//! deserialized D1 decision. The portable decision fields that describe
//! Symthaea authority are therefore derived from the upstream positive type;
//! callers can supply only issuance material owned by the daemon boundary:
//! a fresh decision nonce, the daemon host fingerprint, and the daemon's
//! delegated HTTP-auth signing identities.
//!
//! This establishes a producer API theorem only. D3 still authenticates the
//! portable receipt's daemon issuer for consumers, and later work must bind
//! 001C to Xenia's live runtime policy/revocation state and durable single-use
//! decision admission.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signer as _, SigningKey};
use thiserror::Error;
use xenia_handshake::MlDsaIdentity;
use xenia_symthaea_attestation_authority::{
    AuthorizedSymthaeaReceiptAttestationV1, SymthaeaAuthorityScopeV1,
};
use xenia_symthaea_attestation_contract::{HybridSignatureBundleV1, XeniaHybridSuiteV1};
use xenia_symthaea_daemon_authority_receipt::{
    MAX_DAEMON_AUTHORIZATION_RECEIPT_TTL_SECS_V1, PortableSymthaeaAuthorityScopeV1,
    SignedXeniaSymthaeaDaemonAuthorizationReceiptV1,
    XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1, XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1,
    XeniaSymthaeaDaemonAuthorizationDecisionV1,
};

/// Build and hybrid-sign one portable daemon authorization receipt from an
/// already-authorized Symthaea receipt-attestation authority result.
///
/// All portable authority fields are derived from `authorized`; they are not
/// caller-selectable. `decision_nonce` and `daemon_host_fingerprint` must be
/// nonzero because the D1 byte contract rejects zero sentinel values.
pub fn sign_authorized_xenia_symthaea_daemon_receipt_v1(
    authorized: AuthorizedSymthaeaReceiptAttestationV1,
    decision_nonce: [u8; 32],
    daemon_host_fingerprint: [u8; 32],
    ed25519_signing_key: &SigningKey,
    ml_dsa_65_signing_identity: &MlDsaIdentity,
) -> Result<SignedXeniaSymthaeaDaemonAuthorizationReceiptV1, XeniaSymthaeaDaemonProducerError> {
    let issued_unix_s = authorized.authorized_at_unix_s();
    let ttl_deadline = issued_unix_s.saturating_add(MAX_DAEMON_AUTHORIZATION_RECEIPT_TTL_SECS_V1);
    let valid_until_unix_s = authorized
        .valid_until_unix_s()
        .map_or(ttl_deadline, |deadline| deadline.min(ttl_deadline));

    let authority_scope = match authorized.authority_scope() {
        SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1 => {
            PortableSymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1
        }
    };

    let decision = XeniaSymthaeaDaemonAuthorizationDecisionV1 {
        schema_version: XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1,
        decision_nonce,
        receipt_id: authorized.receipt_id(),
        receipt_digest: authorized.payload_digest().clone(),
        enrollment_id: authorized.enrollment_id().to_string(),
        signer_id: authorized.signer_id().to_string(),
        key_lineage_commitment: authorized.key_lineage_commitment().to_string(),
        authority_scope,
        rbac_policy_version: XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1,
        daemon_host_fingerprint,
        issued_unix_s,
        valid_until_unix_s,
        suite: XeniaHybridSuiteV1::Ed25519MlDsa65V1,
    };

    let transcript = decision
        .canonical_signing_transcript()
        .ok_or(XeniaSymthaeaDaemonProducerError::InvalidIssuanceMaterial)?;

    Ok(SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
        decision,
        signatures: HybridSignatureBundleV1 {
            ed25519: ed25519_signing_key.sign(&transcript).to_bytes(),
            ml_dsa_65: ml_dsa_65_signing_identity.sign(&transcript).to_vec(),
        },
    })
}

/// Producer-gated portable daemon receipt failures.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum XeniaSymthaeaDaemonProducerError {
    /// Daemon-owned issuance material produced an invalid D1 decision, such as
    /// a zero decision nonce or zero daemon host fingerprint.
    #[error("invalid Xenia Symthaea daemon receipt issuance material")]
    InvalidIssuanceMaterial,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN};
    use xenia_symthaea_attestation_authority::{
        EnrolledSymthaeaAttestationIdentityV1, EnrollmentStatusV1,
        XENIA_SYMTHAEA_PROVIDER_NAMESPACE_V1, authorize_symthaea_receipt_attestation_v1,
        symthaea_key_lineage_commitment_v1,
    };
    use xenia_symthaea_attestation_contract::{
        ED25519_SIGNATURE_LEN, HybridSignatureBundleV1 as AttestationSignatures,
        ML_DSA_65_SIGNATURE_LEN, SymthaeaReceiptAttestationV1,
    };
    use xenia_symthaea_attestation_verifier::{
        SignedSymthaeaReceiptAttestationV1, verify_symthaea_attestation_signatures_v1,
    };
    use xenia_symthaea_daemon_authority_crypto::{
        XeniaSymthaeaDaemonVerifyingKeysV1,
        verify_xenia_symthaea_daemon_authorization_signatures_v1,
    };

    const RECEIPT_BYTES: &[u8] = b"canonical-symthaea-receipt-fixture-v1";

    fn authorized(
        signer: &HandshakeManager,
        now: u64,
        enrollment_deadline: Option<u64>,
    ) -> AuthorizedSymthaeaReceiptAttestationV1 {
        let ed = signer.identity_public_key_bytes();
        let ml = signer.ml_dsa_public_key_bytes();
        let lineage = symthaea_key_lineage_commitment_v1(&ed, &ml).unwrap();
        let mut attestation = SymthaeaReceiptAttestationV1::new(
            RECEIPT_BYTES,
            1,
            [0x11; 16],
            XENIA_SYMTHAEA_PROVIDER_NAMESPACE_V1,
            "operator:alice",
            lineage,
            XeniaHybridSuiteV1::Ed25519MlDsa65V1,
            AttestationSignatures {
                ed25519: [0; ED25519_SIGNATURE_LEN],
                ml_dsa_65: vec![0; ML_DSA_65_SIGNATURE_LEN],
            },
        )
        .unwrap();
        let transcript = attestation.canonical_signing_transcript().unwrap();
        attestation.signatures.ed25519 = signer.sign(&transcript).to_bytes();
        attestation.signatures.ml_dsa_65 = signer.sign_ml_dsa(&transcript).to_vec();

        let verified = verify_symthaea_attestation_signatures_v1(
            RECEIPT_BYTES,
            SignedSymthaeaReceiptAttestationV1 {
                attestation,
                ed25519_pubkey: ed,
                ml_dsa_65_pubkey: ml.to_vec(),
            },
        )
        .unwrap();

        authorize_symthaea_receipt_attestation_v1(
            verified,
            &EnrolledSymthaeaAttestationIdentityV1 {
                enrollment_id: "enrollment:alice:v1".into(),
                signer_id: "operator:alice".into(),
                ed25519_pubkey: ed,
                ml_dsa_65_pubkey: ml.to_vec(),
                status: EnrollmentStatusV1::Active,
                authority_scopes: vec![
                    SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
                ],
                issued_unix_s: 100,
                valid_until_unix_s: enrollment_deadline,
            },
            SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
            now,
        )
        .unwrap()
    }

    fn daemon_identity() -> (SigningKey, MlDsaIdentity, XeniaSymthaeaDaemonVerifyingKeysV1) {
        let ed = SigningKey::from_bytes(&[0xD1; 32]);
        let ml = MlDsaIdentity::from_seed([0xD2; 32]);
        let keys = XeniaSymthaeaDaemonVerifyingKeysV1 {
            ed25519: ed.verifying_key().to_bytes(),
            ml_dsa_65: ml.public_key_bytes(),
        };
        assert_eq!(keys.ml_dsa_65.len(), ML_DSA_65_PK_LEN);
        (ed, ml, keys)
    }

    #[test]
    fn upstream_authority_fields_are_derived_and_hybrid_signatures_verify() {
        let signer = HandshakeManager::from_identity_seeds([0x11; 32], [0x12; 32]);
        let authorized = authorized(&signer, 150, Some(900));
        let expected_receipt_id = authorized.receipt_id();
        let expected_digest = authorized.payload_digest().clone();
        let expected_enrollment = authorized.enrollment_id().to_string();
        let expected_signer = authorized.signer_id().to_string();
        let expected_lineage = authorized.key_lineage_commitment().to_string();
        let (daemon_ed, daemon_ml, keys) = daemon_identity();

        let signed = sign_authorized_xenia_symthaea_daemon_receipt_v1(
            authorized,
            [0xA1; 32],
            [0xB1; 32],
            &daemon_ed,
            &daemon_ml,
        )
        .unwrap();

        assert_eq!(signed.decision.receipt_id, expected_receipt_id);
        assert_eq!(signed.decision.receipt_digest, expected_digest);
        assert_eq!(signed.decision.enrollment_id, expected_enrollment);
        assert_eq!(signed.decision.signer_id, expected_signer);
        assert_eq!(signed.decision.key_lineage_commitment, expected_lineage);
        assert_eq!(
            signed.decision.authority_scope,
            PortableSymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1
        );
        assert_eq!(signed.decision.issued_unix_s, 150);
        assert_eq!(signed.decision.valid_until_unix_s, 450);

        let verified =
            verify_xenia_symthaea_daemon_authorization_signatures_v1(signed, &keys, 150).unwrap();
        assert_eq!(verified.verifying_keys(), &keys);
    }

    #[test]
    fn earlier_enrollment_deadline_tightens_portable_expiry() {
        let signer = HandshakeManager::from_identity_seeds([0x21; 32], [0x22; 32]);
        let authorized = authorized(&signer, 150, Some(200));
        let (daemon_ed, daemon_ml, _) = daemon_identity();
        let signed = sign_authorized_xenia_symthaea_daemon_receipt_v1(
            authorized,
            [0xA2; 32],
            [0xB2; 32],
            &daemon_ed,
            &daemon_ml,
        )
        .unwrap();
        assert_eq!(signed.decision.valid_until_unix_s, 200);
    }

    #[test]
    fn no_enrollment_deadline_is_still_capped_by_d1_ttl() {
        let signer = HandshakeManager::from_identity_seeds([0x31; 32], [0x32; 32]);
        let authorized = authorized(&signer, 150, None);
        let (daemon_ed, daemon_ml, _) = daemon_identity();
        let signed = sign_authorized_xenia_symthaea_daemon_receipt_v1(
            authorized,
            [0xA3; 32],
            [0xB3; 32],
            &daemon_ed,
            &daemon_ml,
        )
        .unwrap();
        assert_eq!(signed.decision.valid_until_unix_s, 450);
    }

    #[test]
    fn zero_nonce_or_zero_host_fingerprint_is_refused() {
        let signer = HandshakeManager::from_identity_seeds([0x41; 32], [0x42; 32]);
        let (daemon_ed, daemon_ml, _) = daemon_identity();
        assert_eq!(
            sign_authorized_xenia_symthaea_daemon_receipt_v1(
                authorized(&signer, 150, None),
                [0; 32],
                [0xB4; 32],
                &daemon_ed,
                &daemon_ml,
            )
            .unwrap_err(),
            XeniaSymthaeaDaemonProducerError::InvalidIssuanceMaterial
        );
        assert_eq!(
            sign_authorized_xenia_symthaea_daemon_receipt_v1(
                authorized(&signer, 150, None),
                [0xA4; 32],
                [0; 32],
                &daemon_ed,
                &daemon_ml,
            )
            .unwrap_err(),
            XeniaSymthaeaDaemonProducerError::InvalidIssuanceMaterial
        );
    }
}
