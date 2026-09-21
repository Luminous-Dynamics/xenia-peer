// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact per-action operator approval for Xenia→Symthaea authorization-receipt issuance.
//!
//! A valid daemon session token proves that an enrolled operator authenticated
//! recently. It does **not** prove that the operator approved every later
//! authority-bearing action performed with that bearer token. This crate freezes
//! and verifies a second, domain-separated hybrid signature over the exact
//! Symthaea authorization request.
//!
//! The transcript binds the authenticated token nonce, operator identity,
//! receipt identity/digest, request nonce, typed authority scope, and requested
//! receipt TTL. Both Ed25519 and ML-DSA-65 must verify against the exact enrolled
//! operator pair supplied by the live daemon.
//!
//! This crate deliberately does not verify the daemon session token, look up
//! enrollment, check live revocation/RBAC, or issue the final D1 receipt. Those
//! are separate theorems in the live daemon adapter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, MlDsaIdentity};
use xenia_symthaea_attestation_authority::SymthaeaAuthorityScopeV1;
use xenia_symthaea_attestation_contract::HybridSignatureBundleV1;
use xenia_symthaea_authorization_receipt::{MAX_AUTHORIZATION_TTL_SECS_V1, SHA256_LEN};

/// Domain separator for the exact operator-approved issuance action.
pub const SYMTHAEA_AUTHORIZATION_ACTION_DOMAIN_V1: &[u8] =
    b"xenia-symthaea-operator-authorization-action-v1\0";
/// Defensive bound for the stable operator id.
pub const MAX_OPERATOR_ID_BYTES: usize = 4 * 1024;

/// Exact authority-bearing action the operator approves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymthaeaAuthorizationActionV1 {
    /// Stable operator identity from the daemon token.
    pub operator_id: String,
    /// Nonce of the exact daemon-issued session token authorizing this action.
    pub token_nonce: [u8; 16],
    /// Exact typed authority scope being requested.
    pub authority_scope: SymthaeaAuthorityScopeV1,
    /// Exact Symthaea verification-receipt UUID.
    pub symthaea_receipt_id: [u8; 16],
    /// SHA-256 of the exact canonical Symthaea verification-receipt bytes.
    pub symthaea_receipt_digest_sha256: [u8; SHA256_LEN],
    /// Caller-generated nonce binding the returned D1 receipt to this request.
    pub request_nonce: [u8; 32],
    /// Exact offline validity requested for the positive D1 receipt.
    pub requested_ttl_secs: u64,
}

impl SymthaeaAuthorizationActionV1 {
    /// Structural validity only. This does not establish that a daemon token or
    /// either operator signature is valid.
    pub fn validate_structure(&self) -> bool {
        !self.operator_id.trim().is_empty()
            && self.operator_id.len() <= MAX_OPERATOR_ID_BYTES
            && self.authority_scope
                == SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1
            && self.symthaea_receipt_id != [0; 16]
            && nonzero32(&self.symthaea_receipt_digest_sha256)
            && nonzero32(&self.request_nonce)
            && self.requested_ttl_secs > 0
            && self.requested_ttl_secs <= MAX_AUTHORIZATION_TTL_SECS_V1
    }

    /// Exact domain-separated bytes both operator signatures must cover.
    pub fn canonical_signing_transcript(&self) -> Option<Vec<u8>> {
        if !self.validate_structure() {
            return None;
        }
        let mut out = Vec::new();
        out.extend_from_slice(SYMTHAEA_AUTHORIZATION_ACTION_DOMAIN_V1);
        push_field(&mut out, "operator_id", self.operator_id.as_bytes());
        push_field(&mut out, "token_nonce", &self.token_nonce);
        push_field(
            &mut out,
            "authority_scope",
            self.authority_scope.id().as_bytes(),
        );
        push_field(&mut out, "symthaea_receipt_id", &self.symthaea_receipt_id);
        push_field(
            &mut out,
            "symthaea_receipt_digest_sha256",
            &self.symthaea_receipt_digest_sha256,
        );
        push_field(&mut out, "request_nonce", &self.request_nonce);
        push_field(
            &mut out,
            "requested_ttl_secs",
            &self.requested_ttl_secs.to_be_bytes(),
        );
        Some(out)
    }

    /// SHA-256 of the exact action-signing transcript.
    pub fn transcript_sha256(&self) -> Option<[u8; SHA256_LEN]> {
        self.canonical_signing_transcript()
            .map(|bytes| Sha256::digest(bytes).into())
    }
}

/// Operator action plus both required hybrid signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSymthaeaAuthorizationActionV1 {
    /// Exact action being approved.
    pub action: SymthaeaAuthorizationActionV1,
    /// Ed25519 + ML-DSA-65 signatures over the identical canonical transcript.
    pub signatures: HybridSignatureBundleV1,
}

impl SignedSymthaeaAuthorizationActionV1 {
    /// Structural validity only; no crypto or token verification occurs here.
    pub fn validate_structure(&self) -> bool {
        self.action.validate_structure() && self.signatures.validate_structure()
    }
}

/// Positive proof that both operator signatures verified over the exact action
/// and that its operator/token nonce matched the daemon-verified session token.
///
/// Fields are private so callers cannot construct this positive state by
/// deserializing or populating a boolean.
#[derive(Clone, Debug)]
pub struct VerifiedSymthaeaAuthorizationActionV1 {
    signed: SignedSymthaeaAuthorizationActionV1,
}

impl VerifiedSymthaeaAuthorizationActionV1 {
    /// Exact operator-approved action whose signatures verified.
    pub fn action(&self) -> &SymthaeaAuthorizationActionV1 {
        &self.signed.action
    }

    /// Exact signed action for audit/evidence export.
    pub fn signed(&self) -> &SignedSymthaeaAuthorizationActionV1 {
        &self.signed
    }
}

/// Verification failures for the exact per-action operator approval boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SymthaeaAuthorizationActionError {
    /// Action/signature shape was malformed.
    #[error("invalid Symthaea authorization action structure")]
    InvalidStructure,
    /// Action operator did not match the already-verified daemon token identity.
    #[error("Symthaea authorization action operator does not match session token")]
    OperatorMismatch,
    /// Action token nonce did not match the already-verified daemon token.
    #[error("Symthaea authorization action token nonce does not match session token")]
    TokenNonceMismatch,
    /// Enrolled ML-DSA-65 public key had the wrong size.
    #[error("malformed enrolled ML-DSA-65 key")]
    MalformedMlDsaKey,
    /// Ed25519 action signature failed.
    #[error("Ed25519 Symthaea authorization action signature failed")]
    Ed25519VerifyFailed,
    /// ML-DSA-65 action signature failed.
    #[error("ML-DSA-65 Symthaea authorization action signature failed")]
    MlDsaVerifyFailed,
}

/// Verify exact per-action hybrid approval against the already-enrolled operator
/// key pair and the identity/token nonce established by the daemon's session
/// token verifier.
pub fn verify_symthaea_authorization_action_v1(
    signed: SignedSymthaeaAuthorizationActionV1,
    expected_operator_id: &str,
    expected_token_nonce: &[u8; 16],
    enrolled_ed25519_pubkey: &[u8; 32],
    enrolled_ml_dsa_65_pubkey: &[u8],
) -> Result<VerifiedSymthaeaAuthorizationActionV1, SymthaeaAuthorizationActionError> {
    if !signed.validate_structure() {
        return Err(SymthaeaAuthorizationActionError::InvalidStructure);
    }
    if signed.action.operator_id != expected_operator_id {
        return Err(SymthaeaAuthorizationActionError::OperatorMismatch);
    }
    if signed.action.token_nonce != *expected_token_nonce {
        return Err(SymthaeaAuthorizationActionError::TokenNonceMismatch);
    }

    let ml_public_key: [u8; ML_DSA_65_PK_LEN] = enrolled_ml_dsa_65_pubkey
        .try_into()
        .map_err(|_| SymthaeaAuthorizationActionError::MalformedMlDsaKey)?;
    let transcript = signed
        .action
        .canonical_signing_transcript()
        .ok_or(SymthaeaAuthorizationActionError::InvalidStructure)?;

    let ed_public_key = HandshakeManager::parse_peer_public_key(enrolled_ed25519_pubkey)
        .map_err(|_| SymthaeaAuthorizationActionError::Ed25519VerifyFailed)?;
    let ed_signature = Signature::from_bytes(&signed.signatures.ed25519);
    HandshakeManager::verify(&ed_public_key, &transcript, &ed_signature)
        .map_err(|_| SymthaeaAuthorizationActionError::Ed25519VerifyFailed)?;

    let ml_signature: [u8; ML_DSA_65_SIG_LEN] = signed
        .signatures
        .ml_dsa_65
        .as_slice()
        .try_into()
        .map_err(|_| SymthaeaAuthorizationActionError::InvalidStructure)?;
    MlDsaIdentity::verify(&ml_public_key, &transcript, &ml_signature)
        .map_err(|_| SymthaeaAuthorizationActionError::MlDsaVerifyFailed)?;

    Ok(VerifiedSymthaeaAuthorizationActionV1 { signed })
}

fn nonzero32(value: &[u8; SHA256_LEN]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn push_field(out: &mut Vec<u8>, label: &str, value: &[u8]) {
    let label_len = u16::try_from(label.len()).expect("static label length fits u16");
    let value_len = u32::try_from(value.len()).expect("validated value length fits u32");
    out.extend_from_slice(&label_len.to_be_bytes());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_handshake::HandshakeManager;

    fn action() -> SymthaeaAuthorizationActionV1 {
        SymthaeaAuthorizationActionV1 {
            operator_id: "alice".into(),
            token_nonce: [0x11; 16],
            authority_scope: SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
            symthaea_receipt_id: [0x22; 16],
            symthaea_receipt_digest_sha256: [0x33; SHA256_LEN],
            request_nonce: [0x44; 32],
            requested_ttl_secs: 120,
        }
    }

    fn signed_with(manager: &HandshakeManager) -> SignedSymthaeaAuthorizationActionV1 {
        let action = action();
        let transcript = action.canonical_signing_transcript().unwrap();
        SignedSymthaeaAuthorizationActionV1 {
            action,
            signatures: HybridSignatureBundleV1 {
                ed25519: manager.sign(&transcript).to_bytes(),
                ml_dsa_65: manager.sign_ml_dsa(&transcript).to_vec(),
            },
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn frozen_action_transcript_hash_is_stable() {
        assert_eq!(
            hex(&action().transcript_sha256().unwrap()),
            "96893440205f91a69e112030bc33097a9b438187fb981b3189e8c89140a819bd"
        );
    }

    #[test]
    fn both_signatures_and_exact_token_binding_are_required() {
        let operator = HandshakeManager::new();
        let verified = verify_symthaea_authorization_action_v1(
            signed_with(&operator),
            "alice",
            &[0x11; 16],
            &operator.identity_public_key_bytes(),
            &operator.ml_dsa_public_key_bytes(),
        )
        .unwrap();
        assert_eq!(verified.action(), &action());
    }

    #[test]
    fn wrong_operator_or_token_nonce_is_rejected_before_crypto_authority() {
        let operator = HandshakeManager::new();
        assert_eq!(
            verify_symthaea_authorization_action_v1(
                signed_with(&operator),
                "mallory",
                &[0x11; 16],
                &operator.identity_public_key_bytes(),
                &operator.ml_dsa_public_key_bytes(),
            )
            .unwrap_err(),
            SymthaeaAuthorizationActionError::OperatorMismatch
        );
        assert_eq!(
            verify_symthaea_authorization_action_v1(
                signed_with(&operator),
                "alice",
                &[0x99; 16],
                &operator.identity_public_key_bytes(),
                &operator.ml_dsa_public_key_bytes(),
            )
            .unwrap_err(),
            SymthaeaAuthorizationActionError::TokenNonceMismatch
        );
    }

    #[test]
    fn tampering_receipt_digest_ttl_or_request_nonce_breaks_signatures() {
        let operator = HandshakeManager::new();
        let mut digest = signed_with(&operator);
        digest.action.symthaea_receipt_digest_sha256[0] ^= 1;
        assert!(matches!(
            verify_symthaea_authorization_action_v1(
                digest,
                "alice",
                &[0x11; 16],
                &operator.identity_public_key_bytes(),
                &operator.ml_dsa_public_key_bytes(),
            ),
            Err(SymthaeaAuthorizationActionError::Ed25519VerifyFailed)
                | Err(SymthaeaAuthorizationActionError::MlDsaVerifyFailed)
        ));

        let mut ttl = signed_with(&operator);
        ttl.action.requested_ttl_secs = 121;
        assert!(verify_symthaea_authorization_action_v1(
            ttl,
            "alice",
            &[0x11; 16],
            &operator.identity_public_key_bytes(),
            &operator.ml_dsa_public_key_bytes(),
        )
        .is_err());

        let mut nonce = signed_with(&operator);
        nonce.action.request_nonce[0] ^= 1;
        assert!(verify_symthaea_authorization_action_v1(
            nonce,
            "alice",
            &[0x11; 16],
            &operator.identity_public_key_bytes(),
            &operator.ml_dsa_public_key_bytes(),
        )
        .is_err());
    }

    #[test]
    fn mixed_operator_key_pair_is_rejected() {
        let genuine = HandshakeManager::new();
        let foreign = HandshakeManager::new();
        let signed = signed_with(&genuine);
        assert!(matches!(
            verify_symthaea_authorization_action_v1(
                signed,
                "alice",
                &[0x11; 16],
                &genuine.identity_public_key_bytes(),
                &foreign.ml_dsa_public_key_bytes(),
            ),
            Err(SymthaeaAuthorizationActionError::MlDsaVerifyFailed)
        ));
    }

    #[test]
    fn ttl_outside_d1_policy_is_structurally_invalid() {
        let mut zero = action();
        zero.requested_ttl_secs = 0;
        assert!(!zero.validate_structure());
        let mut long = action();
        long.requested_ttl_secs = MAX_AUTHORIZATION_TTL_SECS_V1 + 1;
        assert!(!long.validate_structure());
    }
}
