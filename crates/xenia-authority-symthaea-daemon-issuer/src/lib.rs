// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core issuer for Xenia daemon authorization receipts consumed by Symthaea.
//!
//! This crate deliberately starts **after** request authentication. Its request
//! value is structural input, not proof that an operator authorized anything.
//! The live daemon adapter must populate it only from an already-authenticated,
//! exact operator action and then obtain a coherent authority snapshot under the
//! D3A1 live guard before calling [`issue_symthaea_authorization_receipt_v1`].
//!
//! The issuer itself prevents caller mixing of generation, policy and enrollment
//! state by deriving those fields exclusively from one
//! `StableAuthoritySnapshot<CoherentSymthaeaAuthoritySnapshotV1>`. It derives
//! key lineage from the exact snapshot keys, uses the snapshot's trusted daemon
//! host fingerprint, constructs the frozen D1 transcript, and signs those exact
//! bytes with both delegated HTTP-auth algorithms.
//!
//! A successfully issued receipt still does **not** mean the Symthaea verifier
//! result is true, that Symthaea admitted the evidence, or that an assurance
//! claim is qualified.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signer as _, SigningKey};
use thiserror::Error;
use xenia_handshake::MlDsaIdentity;
use xenia_symthaea_attestation_authority::{
    SymthaeaAuthorityScopeV1, symthaea_key_lineage_commitment_v1,
};
use xenia_symthaea_attestation_contract::{HybridSignatureBundleV1, XeniaHybridSuiteV1};
use xenia_symthaea_authority_generation::{SHA256_LEN, StableAuthoritySnapshot};
use xenia_symthaea_authorization_receipt::{
    MAX_AUTHORIZATION_TTL_SECS_V1, SignedXeniaSymthaeaAuthorizationReceiptV1,
    XeniaSymthaeaAuthorizationReceiptV1,
};
use xenia_symthaea_live_authority_snapshot::CoherentSymthaeaAuthoritySnapshotV1;

/// Defensive bound for the stable operator identity carried by an issuer request.
pub const MAX_REQUEST_OPERATOR_ID_BYTES: usize = 4 * 1024;

/// Structural request material passed into the issuer after the live daemon has
/// independently authenticated the operator action.
///
/// Construction/validation of this value is **not authentication**. In the live
/// endpoint, `operator_id` must come from the authenticated Xenia token/action,
/// never from an unauthenticated request body field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonSymthaeaAuthorizationRequestV1 {
    /// Operator identity attributed by the authenticated daemon request layer.
    pub operator_id: String,
    /// Exact typed authority scope requested.
    pub authority_scope: SymthaeaAuthorityScopeV1,
    /// Exact Symthaea verification-receipt UUID.
    pub symthaea_receipt_id: [u8; 16],
    /// SHA-256 of the exact canonical Symthaea verification-receipt bytes.
    pub symthaea_receipt_digest_sha256: [u8; SHA256_LEN],
    /// Caller/request nonce binding the returned decision to one request.
    pub request_nonce: [u8; 32],
}

impl DaemonSymthaeaAuthorizationRequestV1 {
    /// Structural validity only. This does not prove the operator authenticated
    /// or authorized this request.
    pub fn validate_structure(&self) -> bool {
        !self.operator_id.trim().is_empty()
            && self.operator_id.len() <= MAX_REQUEST_OPERATOR_ID_BYTES
            && self.authority_scope
                == SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1
            && self.symthaea_receipt_id != [0; 16]
            && nonzero32(&self.symthaea_receipt_digest_sha256)
            && nonzero32(&self.request_nonce)
    }
}

/// Fail-closed issuer errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DaemonAuthorizationIssuerError {
    /// Structural request was malformed.
    #[error("invalid Symthaea authorization request structure")]
    InvalidRequest,
    /// Authenticated request identity did not match the coherent authority snapshot.
    #[error("authenticated request operator does not match coherent authority snapshot")]
    OperatorMismatch,
    /// Requested typed scope did not match the scope established by the coherent snapshot.
    #[error("requested authority scope does not match coherent authority snapshot")]
    AuthorityScopeMismatch,
    /// Snapshot policy commitment did not match its durable generation commitment.
    #[error("coherent authority snapshot commitment does not match durable generation")]
    SnapshotCommitmentMismatch,
    /// Requested positive-receipt TTL was zero or exceeded the frozen v1 maximum.
    #[error("authorization receipt TTL is outside the permitted v1 range")]
    InvalidTtl,
    /// Receipt expiry overflowed `u64`.
    #[error("authorization receipt expiry overflow")]
    TimeOverflow,
    /// Exact hybrid key-lineage commitment could not be derived from snapshot keys.
    #[error("unable to derive exact operator hybrid key lineage")]
    KeyLineage,
    /// D1 receipt construction rejected one of the issuer-derived inputs.
    #[error("D1 authorization receipt construction failed")]
    ReceiptConstruction,
    /// Frozen D1 canonical signing transcript could not be produced.
    #[error("D1 authorization receipt transcript construction failed")]
    TranscriptConstruction,
    /// Resulting hybrid-signed receipt failed its own structural invariant.
    #[error("issued hybrid authorization receipt failed structural validation")]
    SignedReceiptInvalid,
}

/// Issue one D1 portable authorization receipt from a coherent committed live
/// authority snapshot and sign its exact frozen transcript with the daemon's
/// delegated Ed25519 + ML-DSA-65 HTTP-auth identities.
///
/// `authorized_at_unix_s`, daemon certificate commitment, and verifier artifact
/// commitment must come from daemon-owned state. They are intentionally not
/// fields in the structural request.
#[allow(clippy::too_many_arguments)]
pub fn issue_symthaea_authorization_receipt_v1(
    request: &DaemonSymthaeaAuthorizationRequestV1,
    snapshot: &StableAuthoritySnapshot<CoherentSymthaeaAuthoritySnapshotV1>,
    authorized_at_unix_s: u64,
    ttl_secs: u64,
    daemon_delegation_certificate_digest_sha256: [u8; SHA256_LEN],
    verifier_artifact_commitment_sha256: [u8; SHA256_LEN],
    daemon_ed25519: &SigningKey,
    daemon_ml_dsa_65: &MlDsaIdentity,
) -> Result<SignedXeniaSymthaeaAuthorizationReceiptV1, DaemonAuthorizationIssuerError> {
    if !request.validate_structure() {
        return Err(DaemonAuthorizationIssuerError::InvalidRequest);
    }
    if ttl_secs == 0 || ttl_secs > MAX_AUTHORIZATION_TTL_SECS_V1 {
        return Err(DaemonAuthorizationIssuerError::InvalidTtl);
    }

    let version = snapshot.version();
    let authority = snapshot.value();
    let operator = authority.operator();

    if request.operator_id != operator.operator_id {
        return Err(DaemonAuthorizationIssuerError::OperatorMismatch);
    }
    if request.authority_scope != authority.authority_scope() {
        return Err(DaemonAuthorizationIssuerError::AuthorityScopeMismatch);
    }
    if authority.effective_policy_commitment_sha256() != version.state_commitment_sha256 {
        return Err(DaemonAuthorizationIssuerError::SnapshotCommitmentMismatch);
    }

    let operator_key_lineage_commitment = symthaea_key_lineage_commitment_v1(
        &operator.ed25519_pubkey,
        &operator.ml_dsa_65_pubkey,
    )
    .map_err(|_| DaemonAuthorizationIssuerError::KeyLineage)?;

    let expires_at_unix_s = authorized_at_unix_s
        .checked_add(ttl_secs)
        .ok_or(DaemonAuthorizationIssuerError::TimeOverflow)?;

    let receipt = XeniaSymthaeaAuthorizationReceiptV1::new(
        request.symthaea_receipt_id,
        request.symthaea_receipt_digest_sha256,
        request.request_nonce,
        operator.operator_id.clone(),
        operator.role,
        operator_key_lineage_commitment,
        authority.enrollment_commitment_sha256(),
        authority.effective_policy_commitment_sha256(),
        version.generation,
        authorized_at_unix_s,
        expires_at_unix_s,
        version.daemon_host_fingerprint,
        daemon_delegation_certificate_digest_sha256,
        verifier_artifact_commitment_sha256,
    )
    .ok_or(DaemonAuthorizationIssuerError::ReceiptConstruction)?;

    let transcript = receipt
        .canonical_signing_transcript()
        .ok_or(DaemonAuthorizationIssuerError::TranscriptConstruction)?;
    let signatures = HybridSignatureBundleV1 {
        ed25519: daemon_ed25519.sign(&transcript).to_bytes(),
        ml_dsa_65: daemon_ml_dsa_65.sign(&transcript).to_vec(),
    };
    let signed = SignedXeniaSymthaeaAuthorizationReceiptV1 {
        receipt,
        suite: XeniaHybridSuiteV1::Ed25519MlDsa65V1,
        signatures,
    };
    if !signed.validate_structure() {
        return Err(DaemonAuthorizationIssuerError::SignedReceiptInvalid);
    }
    Ok(signed)
}

fn nonzero32(value: &[u8; SHA256_LEN]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier as _};
    use std::path::PathBuf;
    use xenia_handshake::{ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};
    use xenia_operator_proto::OperatorRole;
    use xenia_symthaea_authority_state_commitment::SymthaeaEnrollmentCommitmentInputV1;
    use xenia_symthaea_live_authority_guard::LiveAuthorityGuard;
    use xenia_symthaea_live_authority_snapshot::{
        AuthoritySnapshotMaterialV1, read_coherent_symthaea_authority_snapshot_v1,
    };

    const HOST: [u8; SHA256_LEN] = [0x11; SHA256_LEN];
    const CERT: [u8; SHA256_LEN] = [0x77; SHA256_LEN];
    const VERIFIER: [u8; SHA256_LEN] = [0x88; SHA256_LEN];

    fn material() -> AuthoritySnapshotMaterialV1 {
        AuthoritySnapshotMaterialV1 {
            enrollments: vec![SymthaeaEnrollmentCommitmentInputV1 {
                operator_id: "alice".into(),
                ed25519_pubkey: [0x21; 32],
                ml_dsa_65_pubkey: vec![0x31; ML_DSA_65_PK_LEN],
                role: OperatorRole::Admin,
            }],
            revoked_operator_ids: vec![],
        }
    }

    fn ledger_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("authority-generation.bin")
    }

    fn snapshot(
        dir: &tempfile::TempDir,
    ) -> StableAuthoritySnapshot<CoherentSymthaeaAuthoritySnapshotV1> {
        let source = material();
        let commitment = source.effective_policy_commitment_sha256().unwrap();
        let guard = LiveAuthorityGuard::bootstrap_new(ledger_path(dir), HOST, commitment).unwrap();
        read_coherent_symthaea_authority_snapshot_v1(&guard, "alice", || {
            Ok::<_, &'static str>(source)
        })
        .unwrap()
    }

    fn request() -> DaemonSymthaeaAuthorizationRequestV1 {
        DaemonSymthaeaAuthorizationRequestV1 {
            operator_id: "alice".into(),
            authority_scope: SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
            symthaea_receipt_id: [0x41; 16],
            symthaea_receipt_digest_sha256: [0x42; SHA256_LEN],
            request_nonce: [0x43; 32],
        }
    }

    fn daemon_keys() -> (SigningKey, MlDsaIdentity) {
        (
            SigningKey::from_bytes(&[0xA1; 32]),
            MlDsaIdentity::from_seed([0xA2; 32]),
        )
    }

    #[test]
    fn issuer_derives_authority_fields_and_both_signatures_verify() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = snapshot(&dir);
        let (ed, ml) = daemon_keys();
        let signed = issue_symthaea_authorization_receipt_v1(
            &request(),
            &snapshot,
            1_000,
            120,
            CERT,
            VERIFIER,
            &ed,
            &ml,
        )
        .unwrap();

        assert_eq!(signed.receipt.operator_id, "alice");
        assert_eq!(signed.receipt.operator_role, OperatorRole::Admin);
        assert_eq!(signed.receipt.authority_state_epoch, snapshot.version().generation);
        assert_eq!(signed.receipt.daemon_host_fingerprint, HOST);
        assert_eq!(
            signed.receipt.policy_commitment_sha256,
            snapshot.version().state_commitment_sha256
        );
        assert_eq!(signed.receipt.authorized_at_unix_s, 1_000);
        assert_eq!(signed.receipt.expires_at_unix_s, 1_120);

        let transcript = signed.receipt.canonical_signing_transcript().unwrap();
        let ed_signature = Signature::from_bytes(&signed.signatures.ed25519);
        assert!(ed.verifying_key().verify(&transcript, &ed_signature).is_ok());
        let ml_signature: [u8; ML_DSA_65_SIG_LEN] = signed
            .signatures
            .ml_dsa_65
            .clone()
            .try_into()
            .unwrap();
        assert!(
            MlDsaIdentity::verify(&ml.public_key_bytes(), &transcript, &ml_signature).is_ok()
        );
    }

    #[test]
    fn request_operator_must_match_coherent_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = snapshot(&dir);
        let (ed, ml) = daemon_keys();
        let mut wrong = request();
        wrong.operator_id = "mallory".into();
        assert_eq!(
            issue_symthaea_authorization_receipt_v1(
                &wrong, &snapshot, 1_000, 120, CERT, VERIFIER, &ed, &ml
            )
            .unwrap_err(),
            DaemonAuthorizationIssuerError::OperatorMismatch
        );
    }

    #[test]
    fn zero_and_overlong_ttl_fail_closed_instead_of_clamping() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = snapshot(&dir);
        let (ed, ml) = daemon_keys();
        for ttl in [0, MAX_AUTHORIZATION_TTL_SECS_V1 + 1] {
            assert_eq!(
                issue_symthaea_authorization_receipt_v1(
                    &request(), &snapshot, 1_000, ttl, CERT, VERIFIER, &ed, &ml
                )
                .unwrap_err(),
                DaemonAuthorizationIssuerError::InvalidTtl
            );
        }
    }

    #[test]
    fn time_overflow_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = snapshot(&dir);
        let (ed, ml) = daemon_keys();
        assert_eq!(
            issue_symthaea_authorization_receipt_v1(
                &request(),
                &snapshot,
                u64::MAX,
                1,
                CERT,
                VERIFIER,
                &ed,
                &ml,
            )
            .unwrap_err(),
            DaemonAuthorizationIssuerError::TimeOverflow
        );
    }

    #[test]
    fn structurally_invalid_request_is_not_signed() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = snapshot(&dir);
        let (ed, ml) = daemon_keys();
        let mut invalid = request();
        invalid.request_nonce = [0; 32];
        assert_eq!(
            issue_symthaea_authorization_receipt_v1(
                &invalid, &snapshot, 1_000, 120, CERT, VERIFIER, &ed, &ml
            )
            .unwrap_err(),
            DaemonAuthorizationIssuerError::InvalidRequest
        );
    }
}
