// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real hybrid verification for portable Xenia→Symthaea daemon authorization
//! receipts.
//!
//! This tranche proves only that Ed25519 and ML-DSA-65 signatures both verify
//! over the exact same short-lived D1 canonical transcript. It deliberately
//! does not prove that the presented key pair is jointly delegated by the
//! expected daemon host identity.
//!
//! Production signing is intentionally not exposed here. D2 is a verifier;
//! the producer-gated signing path belongs to XENIA-SYM-001D4, where signing
//! requires the private-construction upstream authority result rather than an
//! arbitrary receipt-shaped decision.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
#[cfg(test)]
use ed25519_dalek::{Signer as _, SigningKey};
use thiserror::Error;
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, MlDsaIdentity};
use xenia_symthaea_attestation_contract::ML_DSA_65_SIGNATURE_LEN;
#[cfg(test)]
use xenia_symthaea_attestation_contract::HybridSignatureBundleV1;
use xenia_symthaea_daemon_authority_receipt::SignedXeniaSymthaeaDaemonAuthorizationReceiptV1;
#[cfg(test)]
use xenia_symthaea_daemon_authority_receipt::XeniaSymthaeaDaemonAuthorizationDecisionV1;

/// Exact public-key pair presented for D2 cryptographic verification.
///
/// Possession of this pair does not itself prove that the keys are jointly
/// delegated by the expected daemon host identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XeniaSymthaeaDaemonVerifyingKeysV1 {
    /// Presented Ed25519 HTTP-auth verifying key.
    pub ed25519: [u8; 32],
    /// Presented ML-DSA-65 HTTP-auth verifying key.
    pub ml_dsa_65: [u8; ML_DSA_65_PK_LEN],
}

/// Positive result proving only that both daemon-key signatures verified over
/// one exact, currently valid D1 decision transcript.
///
/// The exact verifying pair is retained as part of the positive result. A
/// downstream issuer/delegation verifier must be able to prove that the pair
/// which actually established D2's cryptographic fact is the same pair named
/// by the daemon's host-signed delegation certificate. Forgetting the pair at
/// this boundary would force downstream code either to trust caller-supplied
/// replacement keys or to repeat cryptographic verification.
#[derive(Debug, Clone)]
pub struct VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1 {
    receipt: SignedXeniaSymthaeaDaemonAuthorizationReceiptV1,
    transcript: Vec<u8>,
    verifying_keys: XeniaSymthaeaDaemonVerifyingKeysV1,
}

impl VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1 {
    /// Original signed portable receipt whose two signatures verified.
    pub fn receipt(&self) -> &SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
        &self.receipt
    }

    /// Exact D1 transcript authenticated by both signatures.
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    /// Exact Ed25519 + ML-DSA-65 public-key pair that established this D2
    /// verification result.
    ///
    /// This is cryptographic provenance only. It does not mean the pair is
    /// trusted, jointly delegated, current, or authorized for any application
    /// action.
    pub fn verifying_keys(&self) -> &XeniaSymthaeaDaemonVerifyingKeysV1 {
        &self.verifying_keys
    }
}

#[cfg(test)]
fn sign_test_decision(
    decision: XeniaSymthaeaDaemonAuthorizationDecisionV1,
    ed25519_signing_key: &SigningKey,
    ml_dsa_65_signing_identity: &MlDsaIdentity,
) -> Result<SignedXeniaSymthaeaDaemonAuthorizationReceiptV1, XeniaSymthaeaDaemonCryptoError> {
    ensure_contract_constants()?;
    let transcript = decision
        .canonical_signing_transcript()
        .ok_or(XeniaSymthaeaDaemonCryptoError::InvalidDecision)?;

    let ed25519 = ed25519_signing_key.sign(&transcript).to_bytes();
    let ml_dsa_65 = ml_dsa_65_signing_identity.sign(&transcript).to_vec();

    Ok(SignedXeniaSymthaeaDaemonAuthorizationReceiptV1 {
        decision,
        signatures: HybridSignatureBundleV1 {
            ed25519,
            ml_dsa_65,
        },
    })
}

/// Verify both signatures over the exact D1 canonical transcript and enforce
/// the D1 validity interval at `now_unix_s`.
///
/// Success still does **not** establish that the two presented keys belong to
/// one trusted Xenia daemon. The delegation-chain verifier must establish that
/// separately before the receipt can become authenticated daemon authority.
pub fn verify_xenia_symthaea_daemon_authorization_signatures_v1(
    signed: SignedXeniaSymthaeaDaemonAuthorizationReceiptV1,
    keys: &XeniaSymthaeaDaemonVerifyingKeysV1,
    now_unix_s: u64,
) -> Result<VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1, XeniaSymthaeaDaemonCryptoError> {
    ensure_contract_constants()?;
    if !signed.validate_structure() {
        return Err(XeniaSymthaeaDaemonCryptoError::MalformedReceipt);
    }
    if signed.decision.is_not_yet_valid_at(now_unix_s) {
        return Err(XeniaSymthaeaDaemonCryptoError::ReceiptNotYetValid);
    }
    if signed.decision.is_expired_at(now_unix_s) {
        return Err(XeniaSymthaeaDaemonCryptoError::ReceiptExpired);
    }

    let transcript = signed
        .canonical_signing_transcript()
        .ok_or(XeniaSymthaeaDaemonCryptoError::MalformedReceipt)?;

    let ed_vk = HandshakeManager::parse_peer_public_key(&keys.ed25519)
        .map_err(|_| XeniaSymthaeaDaemonCryptoError::MalformedKey)?;
    let ed_signature = Signature::from_bytes(&signed.signatures.ed25519);
    HandshakeManager::verify(&ed_vk, &transcript, &ed_signature)
        .map_err(|_| XeniaSymthaeaDaemonCryptoError::Ed25519VerifyFailed)?;

    let ml_signature: [u8; ML_DSA_65_SIG_LEN] = signed
        .signatures
        .ml_dsa_65
        .as_slice()
        .try_into()
        .map_err(|_| XeniaSymthaeaDaemonCryptoError::MalformedReceipt)?;
    MlDsaIdentity::verify(&keys.ml_dsa_65, &transcript, &ml_signature)
        .map_err(|_| XeniaSymthaeaDaemonCryptoError::MlDsaVerifyFailed)?;

    Ok(VerifiedXeniaSymthaeaDaemonAuthorizationSignaturesV1 {
        receipt: signed,
        transcript,
        verifying_keys: keys.clone(),
    })
}

fn ensure_contract_constants() -> Result<(), XeniaSymthaeaDaemonCryptoError> {
    if ML_DSA_65_SIGNATURE_LEN != ML_DSA_65_SIG_LEN {
        return Err(XeniaSymthaeaDaemonCryptoError::ContractConstantMismatch);
    }
    Ok(())
}

/// Real-crypto verification failures for D1 receipts.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum XeniaSymthaeaDaemonCryptoError {
    /// Portable contract and Xenia disagree about fixed ML-DSA-65 sizes.
    #[error("portable daemon receipt contract and Xenia ML-DSA-65 constants disagree")]
    ContractConstantMismatch,
    /// Test/construction decision failed D1 structural validation.
    #[error("invalid Xenia Symthaea daemon authorization decision")]
    InvalidDecision,
    /// Signed receipt is structurally malformed.
    #[error("malformed Xenia Symthaea daemon authorization receipt")]
    MalformedReceipt,
    /// Evaluation time precedes the signed decision's issuance time.
    #[error("Xenia Symthaea daemon authorization receipt is not yet valid")]
    ReceiptNotYetValid,
    /// Evaluation time is after the signed decision's mandatory expiry.
    #[error("Xenia Symthaea daemon authorization receipt has expired")]
    ReceiptExpired,
    /// Presented Ed25519 verifying key is malformed.
    #[error("malformed Xenia daemon Ed25519 verifying key")]
    MalformedKey,
    /// Ed25519 verification failed.
    #[error("Xenia daemon authorization Ed25519 verification failed")]
    Ed25519VerifyFailed,
    /// ML-DSA-65 verification failed.
    #[error("Xenia daemon authorization ML-DSA-65 verification failed")]
    MlDsaVerifyFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_symthaea_attestation_contract::{DigestAlgorithmV1, ReceiptDigestV1, XeniaHybridSuiteV1};
    use xenia_symthaea_daemon_authority_receipt::{
        PortableSymthaeaAuthorityScopeV1, XENIA_SYMTHAEA_DAEMON_RECEIPT_SCHEMA_VERSION_V1,
        XENIA_SYMTHAEA_RBAC_POLICY_VERSION_V1,
    };

    fn decision() -> XeniaSymthaeaDaemonAuthorizationDecisionV1 {
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
            daemon_host_fingerprint: [0x33; 32],
            issued_unix_s: 100,
            valid_until_unix_s: 200,
            suite: XeniaHybridSuiteV1::Ed25519MlDsa65V1,
        }
    }

    fn identities(
        ed_seed: u8,
        ml_seed: u8,
    ) -> (SigningKey, MlDsaIdentity, XeniaSymthaeaDaemonVerifyingKeysV1) {
        let ed = SigningKey::from_bytes(&[ed_seed; 32]);
        let ml = MlDsaIdentity::from_seed([ml_seed; 32]);
        let keys = XeniaSymthaeaDaemonVerifyingKeysV1 {
            ed25519: ed.verifying_key().to_bytes(),
            ml_dsa_65: ml.public_key_bytes(),
        };
        (ed, ml, keys)
    }

    #[test]
    fn exact_hybrid_daemon_signatures_verify_and_preserve_verifying_pair() {
        let (ed, ml, keys) = identities(0x10, 0x20);
        let signed = sign_test_decision(decision(), &ed, &ml).unwrap();
        let verified = verify_xenia_symthaea_daemon_authorization_signatures_v1(signed, &keys, 150)
            .unwrap();
        assert_eq!(
            verified.transcript(),
            verified.receipt().decision.canonical_signing_transcript().unwrap()
        );
        assert_eq!(verified.verifying_keys(), &keys);
    }

    #[test]
    fn invalid_decision_is_refused_before_test_signing() {
        let (ed, ml, _) = identities(0x11, 0x21);
        let mut value = decision();
        value.decision_nonce = [0; 32];
        assert_eq!(
            sign_test_decision(value, &ed, &ml).unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::InvalidDecision
        );
    }

    #[test]
    fn tampered_decision_breaks_signature_verification() {
        let (ed, ml, keys) = identities(0x12, 0x22);
        let mut signed = sign_test_decision(decision(), &ed, &ml).unwrap();
        signed.decision.signer_id = "operator:bob".into();
        assert_eq!(
            verify_xenia_symthaea_daemon_authorization_signatures_v1(signed, &keys, 150)
                .unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::Ed25519VerifyFailed
        );
    }

    #[test]
    fn either_corrupted_signature_fails_hybrid_verification() {
        let (ed, ml, keys) = identities(0x13, 0x23);

        let mut bad_ed = sign_test_decision(decision(), &ed, &ml).unwrap();
        bad_ed.signatures.ed25519[0] ^= 1;
        assert_eq!(
            verify_xenia_symthaea_daemon_authorization_signatures_v1(bad_ed, &keys, 150)
                .unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::Ed25519VerifyFailed
        );

        let mut bad_ml = sign_test_decision(decision(), &ed, &ml).unwrap();
        bad_ml.signatures.ml_dsa_65[0] ^= 1;
        assert_eq!(
            verify_xenia_symthaea_daemon_authorization_signatures_v1(bad_ml, &keys, 150)
                .unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::MlDsaVerifyFailed
        );
    }

    #[test]
    fn wrong_verifying_key_fails_closed() {
        let (ed, ml, _) = identities(0x14, 0x24);
        let signed = sign_test_decision(decision(), &ed, &ml).unwrap();

        let (_, _, wrong_ed_keys) = identities(0x15, 0x24);
        assert_eq!(
            verify_xenia_symthaea_daemon_authorization_signatures_v1(
                signed.clone(),
                &wrong_ed_keys,
                150,
            )
            .unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::Ed25519VerifyFailed
        );

        let (_, _, wrong_ml_keys) = identities(0x14, 0x25);
        assert_eq!(
            verify_xenia_symthaea_daemon_authorization_signatures_v1(
                signed,
                &wrong_ml_keys,
                150,
            )
            .unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::MlDsaVerifyFailed
        );
    }

    #[test]
    fn future_or_expired_receipts_fail_before_positive_crypto_state() {
        let (ed, ml, keys) = identities(0x16, 0x26);
        let signed = sign_test_decision(decision(), &ed, &ml).unwrap();
        assert_eq!(
            verify_xenia_symthaea_daemon_authorization_signatures_v1(
                signed.clone(),
                &keys,
                99,
            )
            .unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::ReceiptNotYetValid
        );
        assert_eq!(
            verify_xenia_symthaea_daemon_authorization_signatures_v1(signed, &keys, 201)
                .unwrap_err(),
            XeniaSymthaeaDaemonCryptoError::ReceiptExpired
        );
    }

    #[test]
    fn mixed_individually_valid_pair_is_crypto_valid_but_not_daemon_identity_proof() {
        let (ed_a, _, _) = identities(0x17, 0x27);
        let (_, ml_b, _) = identities(0x18, 0x28);
        let signed = sign_test_decision(decision(), &ed_a, &ml_b).unwrap();
        let keys = XeniaSymthaeaDaemonVerifyingKeysV1 {
            ed25519: ed_a.verifying_key().to_bytes(),
            ml_dsa_65: ml_b.public_key_bytes(),
        };

        let verified = verify_xenia_symthaea_daemon_authorization_signatures_v1(signed, &keys, 150)
            .unwrap();
        assert_eq!(verified.verifying_keys(), &keys);
    }
}
