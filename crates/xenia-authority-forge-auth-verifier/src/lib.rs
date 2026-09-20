// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Forge-bound Xenia hybrid-authentication verifier engine.
//!
//! This crate owns the cryptographic sequencing for FORGE-005B2B without
//! importing daemon HTTP/session/RBAC state. A caller provides only two narrow
//! authority surfaces: one-time challenge consumption and exact enrolled-key
//! lookup. The engine consumes the challenge first, reconstructs the frozen
//! Forge-bound transcript, verifies both Ed25519 and ML-DSA-65 signatures,
//! requires both keys to resolve to one current enrollment, and only then mints
//! the portable receipt frozen by `xenia-forge-auth-receipt`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::Signature;
use thiserror::Error;
use xenia_forge_auth_receipt::{
    Digest, ReceiptError, XeniaHybridSuite, XeniaVerificationReceiptV1, challenge_commitment,
    forge_auth_signing_transcript, key_lineage_commitment, operator_id_commitment,
};
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

const CRYPTO_EVIDENCE_DOMAIN_V1: &[u8] = b"xenia-forge-auth/crypto-evidence/v1\0";
const CHALLENGE_EVIDENCE_DOMAIN_V1: &[u8] = b"xenia-forge-auth/challenge-consumption/v1\0";
const VERIFIER_STATE_DOMAIN_V1: &[u8] = b"xenia-forge-auth/verifier-state/v1\0";

/// Successful one-time challenge consumption returned by the authoritative
/// challenge store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeConsumption {
    expires_at_unix_secs: u64,
}

impl ChallengeConsumption {
    /// Construct evidence for a challenge known to have been atomically
    /// removed from the authoritative outstanding-challenge set.
    pub const fn new(expires_at_unix_secs: u64) -> Self {
        Self {
            expires_at_unix_secs,
        }
    }

    /// Original challenge expiry.
    pub const fn expires_at_unix_secs(&self) -> u64 {
        self.expires_at_unix_secs
    }
}

/// Authoritative one-time challenge store required by the verifier engine.
pub trait ChallengeAuthority {
    /// Atomically remove `challenge` if it is outstanding and unexpired at
    /// `now`; return its original expiry on success.
    fn consume(
        &mut self,
        challenge: &[u8; 32],
        now: u64,
    ) -> Option<ChallengeConsumption>;
}

/// Current enrolled Xenia operator snapshot.
///
/// Stable logical identity is separated from current key material so key
/// replacement changes the Forge lineage while preserving `operator_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledForgeOperator {
    operator_id: String,
    ed25519_pubkey: [u8; 32],
    ml_dsa_65_pubkey: Vec<u8>,
    ml_dsa_87_pubkey: Option<Vec<u8>>,
}

impl EnrolledForgeOperator {
    /// Construct a current enrollment snapshot.
    pub fn new(
        operator_id: String,
        ed25519_pubkey: [u8; 32],
        ml_dsa_65_pubkey: Vec<u8>,
        ml_dsa_87_pubkey: Option<Vec<u8>>,
    ) -> Self {
        Self {
            operator_id,
            ed25519_pubkey,
            ml_dsa_65_pubkey,
            ml_dsa_87_pubkey,
        }
    }

    /// Stable logical Xenia operator id.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Current Ed25519 public key.
    pub const fn ed25519_pubkey(&self) -> &[u8; 32] {
        &self.ed25519_pubkey
    }

    /// Current ML-DSA-65 public key.
    pub fn ml_dsa_65_pubkey(&self) -> &[u8] {
        &self.ml_dsa_65_pubkey
    }

    /// Optional current ML-DSA-87 public key participating in key-lineage
    /// identity even though v1 Forge authentication verifies ML-DSA-65.
    pub fn ml_dsa_87_pubkey(&self) -> Option<&[u8]> {
        self.ml_dsa_87_pubkey.as_deref()
    }
}

/// Authoritative current enrollment lookup.
pub trait EnrollmentAuthority {
    /// Return the current operator only if the exact Ed25519 + ML-DSA-65 pair
    /// belongs to the same enrollment record.
    fn lookup_verified(
        &self,
        ed25519_pubkey: &[u8; 32],
        ml_dsa_65_pubkey: &[u8],
    ) -> Option<EnrolledForgeOperator>;
}

/// Signed Forge-bound Xenia authentication response.
pub struct ForgeAuthenticationResponse {
    /// SHA-256 of the exact Mycelix Forge `PrincipalAuthenticationRequest`.
    pub forge_request_sha256: [u8; 32],
    /// Verifier-issued one-time challenge.
    pub challenge: [u8; 32],
    /// Presented Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Presented ML-DSA-65 public key.
    pub ml_dsa_65_pubkey: Vec<u8>,
    /// Ed25519 signature over the frozen Forge-bound transcript.
    pub ed25519_signature: [u8; 64],
    /// ML-DSA-65 signature over the identical transcript.
    pub ml_dsa_65_signature: [u8; ML_DSA_65_SIG_LEN],
}

/// Positive verifier result. This is authentication evidence only; it carries
/// no Xenia role and grants no Forge capability by itself.
#[derive(Clone, Debug)]
pub struct VerifiedForgeAuthentication {
    operator_id: String,
    receipt: XeniaVerificationReceiptV1,
}

impl VerifiedForgeAuthentication {
    /// Stable logical operator id resolved from authoritative enrollment.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Portable Forge/Xenia verification receipt.
    pub fn receipt(&self) -> &XeniaVerificationReceiptV1 {
        &self.receipt
    }

    /// Consume the result and return the portable receipt.
    pub fn into_receipt(self) -> XeniaVerificationReceiptV1 {
        self.receipt
    }
}

/// Forge-bound verifier failures. Every variant is a denial.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ForgeAuthVerifyError {
    /// Challenge was unknown, already consumed, or expired.
    #[error("unknown, used, or expired Forge authentication challenge")]
    UnknownOrExpiredChallenge,
    /// ML-DSA-65 public key had the wrong byte length.
    #[error("malformed ML-DSA-65 public key")]
    MalformedMlDsaKey,
    /// Ed25519 public key encoding was invalid.
    #[error("malformed Ed25519 public key")]
    MalformedEd25519Key,
    /// Ed25519 signature failed over the exact Forge-bound transcript.
    #[error("Ed25519 Forge-bound signature verification failed")]
    Ed25519VerifyFailed,
    /// ML-DSA-65 signature failed over the exact same transcript.
    #[error("ML-DSA-65 Forge-bound signature verification failed")]
    MlDsaVerifyFailed,
    /// Both signatures verified but the exact key pair is not currently
    /// enrolled to one logical operator.
    #[error("verified hybrid key pair is not currently enrolled")]
    NotEnrolled,
    /// Enrollment authority returned a snapshot inconsistent with the exact
    /// pair used for verification.
    #[error("enrollment snapshot does not match verified key pair")]
    EnrollmentSnapshotMismatch,
    /// Portable receipt/transcript canonicalization failed.
    #[error("Forge receipt contract failure")]
    ReceiptContract,
}

/// Consume a one-time challenge, verify both signatures over the exact
/// Forge-bound transcript, resolve the current enrolled key pair, and mint a
/// portable receipt.
///
/// Challenge consumption deliberately happens before public-key parsing or
/// signature verification, matching Xenia's existing fail-closed replay
/// discipline: a failed signature attempt cannot retry the same nonce.
pub fn verify_and_issue_receipt<C, E>(
    challenges: &mut C,
    enrollments: &E,
    now: u64,
    response: &ForgeAuthenticationResponse,
) -> Result<VerifiedForgeAuthentication, ForgeAuthVerifyError>
where
    C: ChallengeAuthority,
    E: EnrollmentAuthority,
{
    let consumption = challenges
        .consume(&response.challenge, now)
        .ok_or(ForgeAuthVerifyError::UnknownOrExpiredChallenge)?;

    if response.ml_dsa_65_pubkey.len() != ML_DSA_65_PK_LEN {
        return Err(ForgeAuthVerifyError::MalformedMlDsaKey);
    }

    let transcript = forge_auth_signing_transcript(
        &response.forge_request_sha256,
        &response.challenge,
        &response.ed25519_pubkey,
        &response.ml_dsa_65_pubkey,
    )
    .map_err(|_| ForgeAuthVerifyError::ReceiptContract)?;

    let ed_vk = HandshakeManager::parse_peer_public_key(&response.ed25519_pubkey)
        .map_err(|_| ForgeAuthVerifyError::MalformedEd25519Key)?;
    let ed_sig = Signature::from_bytes(&response.ed25519_signature);
    HandshakeManager::verify(&ed_vk, &transcript, &ed_sig)
        .map_err(|_| ForgeAuthVerifyError::Ed25519VerifyFailed)?;

    let ml_pk: [u8; ML_DSA_65_PK_LEN] = response
        .ml_dsa_65_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ForgeAuthVerifyError::MalformedMlDsaKey)?;
    HandshakeManager::verify_ml_dsa(&ml_pk, &transcript, &response.ml_dsa_65_signature)
        .map_err(|_| ForgeAuthVerifyError::MlDsaVerifyFailed)?;

    let enrolled = enrollments
        .lookup_verified(&response.ed25519_pubkey, &response.ml_dsa_65_pubkey)
        .ok_or(ForgeAuthVerifyError::NotEnrolled)?;

    if enrolled.ed25519_pubkey() != &response.ed25519_pubkey
        || enrolled.ml_dsa_65_pubkey() != response.ml_dsa_65_pubkey.as_slice()
    {
        return Err(ForgeAuthVerifyError::EnrollmentSnapshotMismatch);
    }

    let operator_commitment = operator_id_commitment(enrolled.operator_id())
        .map_err(|_| ForgeAuthVerifyError::ReceiptContract)?;
    let lineage_commitment = key_lineage_commitment(
        enrolled.ed25519_pubkey(),
        enrolled.ml_dsa_65_pubkey(),
        enrolled.ml_dsa_87_pubkey(),
    )
    .map_err(|_| ForgeAuthVerifyError::ReceiptContract)?;

    let request_commitment = Digest::sha256(response.forge_request_sha256);
    let challenge_digest = challenge_commitment(&response.challenge);
    let crypto_evidence = cryptographic_evidence_commitment(
        &transcript,
        &response.ed25519_signature,
        &response.ml_dsa_65_signature,
    )?;
    let challenge_evidence = challenge_consumption_commitment(
        &response.challenge,
        consumption.expires_at_unix_secs(),
        now,
    );
    let verifier_state = verifier_state_commitment(
        &operator_commitment,
        &lineage_commitment,
        &request_commitment,
    );

    let receipt = XeniaVerificationReceiptV1::new(
        request_commitment,
        operator_commitment,
        lineage_commitment,
        challenge_digest,
        XeniaHybridSuite::Ed25519MlDsa65V1,
        crypto_evidence,
        challenge_evidence,
        verifier_state,
        now,
    );

    Ok(VerifiedForgeAuthentication {
        operator_id: enrolled.operator_id().to_owned(),
        receipt,
    })
}

fn cryptographic_evidence_commitment(
    transcript: &[u8],
    ed25519_signature: &[u8; 64],
    ml_dsa_65_signature: &[u8; ML_DSA_65_SIG_LEN],
) -> Result<Digest, ForgeAuthVerifyError> {
    let mut out = Vec::new();
    out.extend_from_slice(CRYPTO_EVIDENCE_DOMAIN_V1);
    push_bytes(&mut out, transcript)?;
    push_bytes(&mut out, ed25519_signature)?;
    push_bytes(&mut out, ml_dsa_65_signature)?;
    Ok(Digest::of_bytes(&out))
}

fn challenge_consumption_commitment(
    challenge: &[u8; 32],
    expires_at_unix_secs: u64,
    consumed_at_unix_secs: u64,
) -> Digest {
    let mut out = Vec::new();
    out.extend_from_slice(CHALLENGE_EVIDENCE_DOMAIN_V1);
    out.extend_from_slice(challenge);
    out.extend_from_slice(&expires_at_unix_secs.to_be_bytes());
    out.extend_from_slice(&consumed_at_unix_secs.to_be_bytes());
    Digest::of_bytes(&out)
}

fn verifier_state_commitment(
    operator_id: &Digest,
    key_lineage: &Digest,
    request_commitment: &Digest,
) -> Digest {
    let mut out = Vec::new();
    out.extend_from_slice(VERIFIER_STATE_DOMAIN_V1);
    push_digest_bytes(&mut out, operator_id);
    push_digest_bytes(&mut out, key_lineage);
    push_digest_bytes(&mut out, request_commitment);
    Digest::of_bytes(&out)
}

fn push_digest_bytes(out: &mut Vec<u8>, digest: &Digest) {
    out.extend_from_slice(digest.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ForgeAuthVerifyError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ForgeAuthVerifyError::ReceiptContract)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

impl From<ReceiptError> for ForgeAuthVerifyError {
    fn from(_: ReceiptError) -> Self {
        Self::ReceiptContract
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChallengeFixture {
        challenge: [u8; 32],
        expires_at: u64,
        consumed: bool,
    }

    impl ChallengeAuthority for ChallengeFixture {
        fn consume(
            &mut self,
            challenge: &[u8; 32],
            now: u64,
        ) -> Option<ChallengeConsumption> {
            if self.consumed || challenge != &self.challenge || now > self.expires_at {
                return None;
            }
            self.consumed = true;
            Some(ChallengeConsumption::new(self.expires_at))
        }
    }

    #[derive(Clone)]
    struct EnrollmentFixture {
        operator: EnrolledForgeOperator,
    }

    impl EnrollmentAuthority for EnrollmentFixture {
        fn lookup_verified(
            &self,
            ed25519_pubkey: &[u8; 32],
            ml_dsa_65_pubkey: &[u8],
        ) -> Option<EnrolledForgeOperator> {
            (self.operator.ed25519_pubkey() == ed25519_pubkey
                && self.operator.ml_dsa_65_pubkey() == ml_dsa_65_pubkey)
                .then(|| self.operator.clone())
        }
    }

    fn fixture(
        operator_id: &str,
        request: [u8; 32],
        challenge: [u8; 32],
    ) -> (
        HandshakeManager,
        ChallengeFixture,
        EnrollmentFixture,
        ForgeAuthenticationResponse,
    ) {
        let manager = HandshakeManager::from_identity_seeds([0x11; 32], [0x22; 32]);
        let ed = manager.identity_public_key_bytes();
        let ml = manager.ml_dsa_public_key_bytes();
        let transcript = forge_auth_signing_transcript(&request, &challenge, &ed, &ml).unwrap();
        let ed_sig = manager.sign(&transcript).to_bytes();
        let ml_sig = manager.sign_ml_dsa(&transcript);
        let response = ForgeAuthenticationResponse {
            forge_request_sha256: request,
            challenge,
            ed25519_pubkey: ed,
            ml_dsa_65_pubkey: ml.to_vec(),
            ed25519_signature: ed_sig,
            ml_dsa_65_signature: ml_sig,
        };
        let challenges = ChallengeFixture {
            challenge,
            expires_at: 200,
            consumed: false,
        };
        let enrollments = EnrollmentFixture {
            operator: EnrolledForgeOperator::new(
                operator_id.to_owned(),
                ed,
                ml.to_vec(),
                None,
            ),
        };
        (manager, challenges, enrollments, response)
    }

    #[test]
    fn exact_subject_mints_receipt_and_consumes_challenge() {
        let (_, mut challenges, enrollments, response) =
            fixture("operator:alice", [0x33; 32], [0x44; 32]);
        let verified =
            verify_and_issue_receipt(&mut challenges, &enrollments, 150, &response).unwrap();
        assert_eq!(verified.operator_id(), "operator:alice");
        assert_eq!(
            verified.receipt().request_commitment().as_bytes(),
            &[0x33; 32]
        );
        assert!(challenges.consumed);
    }

    #[test]
    fn replayed_challenge_is_denied() {
        let (_, mut challenges, enrollments, response) =
            fixture("operator:alice", [0x33; 32], [0x44; 32]);
        verify_and_issue_receipt(&mut challenges, &enrollments, 150, &response).unwrap();
        assert_eq!(
            verify_and_issue_receipt(&mut challenges, &enrollments, 151, &response).unwrap_err(),
            ForgeAuthVerifyError::UnknownOrExpiredChallenge
        );
    }

    #[test]
    fn request_substitution_invalidates_signature_after_consumption() {
        let (_, mut challenges, enrollments, mut response) =
            fixture("operator:alice", [0x33; 32], [0x44; 32]);
        response.forge_request_sha256[0] ^= 1;
        assert_eq!(
            verify_and_issue_receipt(&mut challenges, &enrollments, 150, &response).unwrap_err(),
            ForgeAuthVerifyError::Ed25519VerifyFailed
        );
        assert!(challenges.consumed);
    }

    #[test]
    fn mismatched_enrollment_is_denied() {
        let (_, mut challenges, mut enrollments, response) =
            fixture("operator:alice", [0x33; 32], [0x44; 32]);
        enrollments.operator.ml_dsa_65_pubkey[0] ^= 1;
        assert_eq!(
            verify_and_issue_receipt(&mut challenges, &enrollments, 150, &response).unwrap_err(),
            ForgeAuthVerifyError::NotEnrolled
        );
    }

    #[test]
    fn key_rotation_changes_lineage_but_not_operator_identity() {
        let (_, mut challenges_a, enrollments_a, response_a) =
            fixture("operator:alice", [0x33; 32], [0x44; 32]);
        let a = verify_and_issue_receipt(&mut challenges_a, &enrollments_a, 150, &response_a)
            .unwrap()
            .into_receipt();

        let (_, mut challenges_b, enrollments_b, response_b) =
            fixture("operator:alice", [0x33; 32], [0x45; 32]);
        let b = verify_and_issue_receipt(&mut challenges_b, &enrollments_b, 150, &response_b)
            .unwrap()
            .into_receipt();

        assert_eq!(a.operator_id_commitment(), b.operator_id_commitment());
        assert_eq!(a.key_lineage_commitment(), b.key_lineage_commitment());

        let rotated = HandshakeManager::from_identity_seeds([0x12; 32], [0x23; 32]);
        let rotated_ed = rotated.identity_public_key_bytes();
        let rotated_ml = rotated.ml_dsa_public_key_bytes();
        let rotated_challenge = [0x46; 32];
        let transcript = forge_auth_signing_transcript(
            &[0x33; 32],
            &rotated_challenge,
            &rotated_ed,
            &rotated_ml,
        )
        .unwrap();
        let response = ForgeAuthenticationResponse {
            forge_request_sha256: [0x33; 32],
            challenge: rotated_challenge,
            ed25519_pubkey: rotated_ed,
            ml_dsa_65_pubkey: rotated_ml.to_vec(),
            ed25519_signature: rotated.sign(&transcript).to_bytes(),
            ml_dsa_65_signature: rotated.sign_ml_dsa(&transcript),
        };
        let mut challenges = ChallengeFixture {
            challenge: rotated_challenge,
            expires_at: 200,
            consumed: false,
        };
        let enrollments = EnrollmentFixture {
            operator: EnrolledForgeOperator::new(
                "operator:alice".to_owned(),
                rotated_ed,
                rotated_ml.to_vec(),
                None,
            ),
        };
        let c = verify_and_issue_receipt(&mut challenges, &enrollments, 150, &response)
            .unwrap()
            .into_receipt();
        assert_eq!(a.operator_id_commitment(), c.operator_id_commitment());
        assert_ne!(a.key_lineage_commitment(), c.key_lineage_commitment());
    }
}
