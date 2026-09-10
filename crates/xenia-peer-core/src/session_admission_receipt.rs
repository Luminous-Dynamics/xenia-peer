// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Signed provider receipt proving that one exact portable machine-session evidence record was
//! actually admitted by Xenia.
//!
//! `VerifiedMachineSessionEvidenceV1` intentionally remains portable/deserializable. Its shape
//! alone is not authentication. This companion receipt lets delayed/historical consumers prove
//! that the exact session id, principal, transcript binding, negotiated context, authority epoch,
//! admission time and expiry were attested by an independently trusted machine-authority key.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::VerifiedMachineSessionEvidenceV1;

/// Exact schema version for signed session-admission receipts.
pub const MACHINE_SESSION_ADMISSION_RECEIPT_SCHEMA_V1: u8 = 1;
/// Stable prefix for an opaque provider-admission binding exported to downstream audit layers.
pub const MACHINE_SESSION_ADMISSION_BINDING_PREFIX_V1: &str =
    "xenia-machine-session-admission-v1:blake3-256:";

const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"xenia-machine-session-evidence-receipt-v1\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"xenia-machine-session-admission-receipt-v1\0";
const AUTHORITY_SIGNER_DOMAIN: &[u8] = b"xenia-machine-authority-signer-v1\0";
const ADMISSION_BINDING_DOMAIN: &[u8] = b"xenia-machine-session-admission-binding-v1\0";

/// Explicit signature suite for a session-admission receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineSessionAdmissionSignatureV1 {
    /// Ed25519 signature over the receipt's domain-separated signing digest.
    Ed25519(Vec<u8>),
}

/// Portable provider signature over one exact `VerifiedMachineSessionEvidenceV1`.
///
/// Deserializing this value does not establish trust. Call
/// [`verify_machine_session_admission_receipt`] with an independently trusted provider key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMachineSessionAdmissionReceiptV1 {
    schema_version: u8,
    evidence_digest: [u8; 32],
    signature: MachineSessionAdmissionSignatureV1,
}

impl SignedMachineSessionAdmissionReceiptV1 {
    /// Exact v1 schema number.
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    /// Domain-separated digest of every portable session-evidence field covered by this receipt.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    fn signing_digest(&self) -> Result<[u8; 32], MachineSessionAdmissionReceiptError> {
        if self.schema_version != MACHINE_SESSION_ADMISSION_RECEIPT_SCHEMA_V1 {
            return Err(MachineSessionAdmissionReceiptError::InvalidSchema);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECEIPT_SIGNATURE_DOMAIN);
        hasher.update(&[self.schema_version]);
        hasher.update(&self.evidence_digest);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Non-serializable proof that a trusted provider key signed one exact machine-session admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMachineSessionAdmissionV1 {
    evidence: VerifiedMachineSessionEvidenceV1,
    evidence_digest: [u8; 32],
    authority_signer_fingerprint: [u8; 32],
    admission_binding: String,
}

impl VerifiedMachineSessionAdmissionV1 {
    /// Exact portable session evidence whose provider admission was verified.
    pub fn evidence(&self) -> &VerifiedMachineSessionEvidenceV1 {
        &self.evidence
    }

    /// Stable digest committed by the provider's receipt signature.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    /// Domain-separated fingerprint of the Ed25519 authority key that verified this receipt.
    pub const fn authority_signer_fingerprint(&self) -> [u8; 32] {
        self.authority_signer_fingerprint
    }

    /// Opaque binding to the exact evidence digest and authority signer used for admission proof.
    pub fn admission_binding(&self) -> &str {
        &self.admission_binding
    }
}

/// Failure while issuing or verifying a signed machine-session admission receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MachineSessionAdmissionReceiptError {
    /// Receipt schema was not exactly v1.
    #[error("unsupported machine-session admission receipt schema")]
    InvalidSchema,
    /// Portable session evidence failed its canonical v1 shape validation.
    #[error("machine-session evidence is malformed")]
    InvalidSessionEvidence,
    /// Receipt digest did not match the supplied portable session evidence.
    #[error("machine-session admission receipt does not match supplied evidence")]
    EvidenceDigestMismatch,
    /// Signature bytes were malformed or did not verify under the trusted authority key.
    #[error("machine-session admission receipt signature is invalid")]
    InvalidSignature,
}

/// Issue a provider-owned admission receipt for one exact portable session-evidence record.
///
/// The signing key is authority-provider state and must not be distributed with the receipt.
pub fn sign_machine_session_admission_receipt(
    evidence: &VerifiedMachineSessionEvidenceV1,
    signing_key: &SigningKey,
) -> Result<SignedMachineSessionAdmissionReceiptV1, MachineSessionAdmissionReceiptError> {
    evidence
        .validate_shape()
        .map_err(|_| MachineSessionAdmissionReceiptError::InvalidSessionEvidence)?;
    let evidence_digest = machine_session_evidence_receipt_digest(evidence)?;
    let mut receipt = SignedMachineSessionAdmissionReceiptV1 {
        schema_version: MACHINE_SESSION_ADMISSION_RECEIPT_SCHEMA_V1,
        evidence_digest,
        signature: MachineSessionAdmissionSignatureV1::Ed25519(Vec::new()),
    };
    let signing_digest = receipt.signing_digest()?;
    receipt.signature = MachineSessionAdmissionSignatureV1::Ed25519(
        signing_key.sign(&signing_digest).to_bytes().to_vec(),
    );
    Ok(receipt)
}

/// Verify a portable admission receipt and cross into non-serializable provider-qualified state.
pub fn verify_machine_session_admission_receipt(
    evidence: &VerifiedMachineSessionEvidenceV1,
    receipt: &SignedMachineSessionAdmissionReceiptV1,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedMachineSessionAdmissionV1, MachineSessionAdmissionReceiptError> {
    evidence
        .validate_shape()
        .map_err(|_| MachineSessionAdmissionReceiptError::InvalidSessionEvidence)?;
    let expected_digest = machine_session_evidence_receipt_digest(evidence)?;
    if receipt.evidence_digest != expected_digest {
        return Err(MachineSessionAdmissionReceiptError::EvidenceDigestMismatch);
    }
    let signature = match &receipt.signature {
        MachineSessionAdmissionSignatureV1::Ed25519(bytes) => {
            let array: [u8; 64] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| MachineSessionAdmissionReceiptError::InvalidSignature)?;
            Signature::from_bytes(&array)
        }
    };
    verifying_key
        .verify(&receipt.signing_digest()?, &signature)
        .map_err(|_| MachineSessionAdmissionReceiptError::InvalidSignature)?;

    let authority_signer_fingerprint = authority_signer_fingerprint(verifying_key);
    let admission_binding = machine_session_admission_binding(
        &expected_digest,
        &authority_signer_fingerprint,
    );
    Ok(VerifiedMachineSessionAdmissionV1 {
        evidence: evidence.clone(),
        evidence_digest: expected_digest,
        authority_signer_fingerprint,
        admission_binding,
    })
}

/// Domain-separated identity of an authority signer used to prevent unrelated verified artifacts
/// from being composed merely because both signatures are individually valid.
pub(crate) fn authority_signer_fingerprint(verifying_key: &VerifyingKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTHORITY_SIGNER_DOMAIN);
    hasher.update(verifying_key.as_bytes());
    *hasher.finalize().as_bytes()
}

fn machine_session_admission_binding(
    evidence_digest: &[u8; 32],
    authority_signer_fingerprint: &[u8; 32],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ADMISSION_BINDING_DOMAIN);
    hasher.update(evidence_digest);
    hasher.update(authority_signer_fingerprint);
    format!(
        "{MACHINE_SESSION_ADMISSION_BINDING_PREFIX_V1}{}",
        hex_lower(hasher.finalize().as_bytes())
    )
}

fn machine_session_evidence_receipt_digest(
    evidence: &VerifiedMachineSessionEvidenceV1,
) -> Result<[u8; 32], MachineSessionAdmissionReceiptError> {
    evidence
        .validate_shape()
        .map_err(|_| MachineSessionAdmissionReceiptError::InvalidSessionEvidence)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(EVIDENCE_DIGEST_DOMAIN);
    hash_bytes(&mut hasher, evidence.schema().as_bytes());
    hash_bytes(&mut hasher, evidence.session_id().as_bytes());
    hash_bytes(&mut hasher, evidence.peer_identity_binding().as_bytes());
    hasher.update(&evidence.authenticated_at_ms().to_le_bytes());
    hasher.update(&evidence.expires_at_ms().to_le_bytes());
    hasher.update(&evidence.authority_epoch().to_le_bytes());
    hash_bytes(&mut hasher, evidence.evidence_binding().as_bytes());
    match evidence.negotiated_context_binding() {
        Some(binding) => {
            hasher.update(&[1]);
            hash_bytes(&mut hasher, binding.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MachineAuthorityPolicyV1, MachineAuthorityRecordV1, VerifiedSessionEvidenceError,
    };
    use xenia_handshake::{HandshakeOutcome, VerifiedPeerIdentity, derive_session_key_schedule};

    fn outcome() -> HandshakeOutcome {
        let transcript_hash = [0x22; 32];
        HandshakeOutcome {
            session_key: [0x11; 32],
            transcript_hash,
            key_schedule: derive_session_key_schedule(&[0x11; 32], &transcript_hash),
            negotiated_context_hash: Some([0x33; 32]),
            host_identity_fingerprint: [0x44; 32],
        }
    }

    fn peer() -> VerifiedPeerIdentity {
        VerifiedPeerIdentity {
            ed25519_pk: [0x55; 32],
            ml_dsa_pk: vec![0x56; xenia_handshake::ML_DSA_65_PK_LEN],
        }
    }

    fn evidence() -> Result<VerifiedMachineSessionEvidenceV1, VerifiedSessionEvidenceError> {
        let peer = peer();
        let outcome = outcome();
        let policy = MachineAuthorityPolicyV1::new(
            [MachineAuthorityRecordV1 {
                peer_identity_fingerprint: peer.signing_identity_fingerprint(),
                authority_epoch: 9,
                valid_from_ms: 50,
                valid_until_ms: 1_000,
                revoked: false,
            }],
            100,
        )
        .unwrap();
        let admission = policy
            .admit_verified_session(&peer, &outcome, 100, true)
            .unwrap();
        VerifiedMachineSessionEvidenceV1::from_verified_handshake(
            &outcome,
            &peer,
            "session-1",
            &admission,
        )
    }

    #[test]
    fn exact_signed_admission_round_trips_to_nonserializable_verified_state() {
        let evidence = evidence().unwrap();
        let authority = SigningKey::from_bytes(&[0x42; 32]);
        let receipt = sign_machine_session_admission_receipt(&evidence, &authority).unwrap();
        let verified = verify_machine_session_admission_receipt(
            &evidence,
            &receipt,
            &authority.verifying_key(),
        )
        .unwrap();
        assert_eq!(verified.evidence(), &evidence);
        assert_eq!(verified.evidence_digest(), receipt.evidence_digest());
        assert_eq!(
            verified.authority_signer_fingerprint(),
            authority_signer_fingerprint(&authority.verifying_key())
        );
        assert!(verified
            .admission_binding()
            .starts_with(MACHINE_SESSION_ADMISSION_BINDING_PREFIX_V1));
    }

    #[test]
    fn wrong_key_or_malformed_signature_fails_closed() {
        let evidence = evidence().unwrap();
        let authority = SigningKey::from_bytes(&[0x42; 32]);
        let other = SigningKey::from_bytes(&[0x43; 32]);
        let receipt = sign_machine_session_admission_receipt(&evidence, &authority).unwrap();
        assert_eq!(
            verify_machine_session_admission_receipt(&evidence, &receipt, &other.verifying_key()),
            Err(MachineSessionAdmissionReceiptError::InvalidSignature)
        );

        let mut malformed = receipt;
        let MachineSessionAdmissionSignatureV1::Ed25519(bytes) = &mut malformed.signature;
        bytes.truncate(63);
        assert_eq!(
            verify_machine_session_admission_receipt(
                &evidence,
                &malformed,
                &authority.verifying_key(),
            ),
            Err(MachineSessionAdmissionReceiptError::InvalidSignature)
        );
    }
}
