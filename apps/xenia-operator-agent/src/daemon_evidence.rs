// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cryptographic verification of daemon-signed evidence
//! (`docs/security/SIGNER_DELEGATION_DESIGN.md`).
//!
//! Complements `host_trust`: that module decides whether a *fingerprint*
//! (once known) is trusted; this module establishes that the fingerprint,
//! and the other daemon-signed evidence a `/v1/sign/*` request carries, is
//! genuine in the first place -- rather than something the caller simply
//! asserted. An earlier revision of the `/v1/sign/*` protocol (schema
//! version 1) let the caller name a `daemon_fingerprint_hex` directly; a
//! compromised browser could label any request with an already-trusted
//! fingerprint regardless of what it was actually asking to be signed.
//! Schema version 2 replaces that with evidence the agent verifies itself:
//!
//! - [`verify_daemon_certificate`]: the daemon's host identity vouching for
//!   its separate HTTP-auth signing key. The agent verifies both
//!   signatures and computes the fingerprint itself
//!   (`xenia_handshake::host_identity_fingerprint`) -- it never trusts a
//!   caller-supplied fingerprint.
//! - [`verify_challenge_attestation`]: the host identity's signatures over
//!   a *specific* `/auth/challenge` nonce, proving that exact nonce really
//!   came from the attested daemon.
//! - [`verify_token`]: an operator session token's daemon signature,
//!   verified against the certificate's (now-verified) delegated
//!   HTTP-auth key -- so a relayed `token_nonce` can be trusted before
//!   it's bound into a consent-action/revoke transcript.

use ed25519_dalek::Signature;
use xenia_handshake::{
    host_identity_fingerprint, HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN,
};
use xenia_operator_agent_proto::{DaemonIdentityCertificate, SignedTokenDto};
use xenia_operator_proto::{
    challenge_host_attestation_transcript, daemon_delegation_transcript,
    operator_token_canonical_bytes,
};

/// Why verifying a piece of daemon-signed evidence failed.
#[derive(Debug)]
pub enum EvidenceError {
    /// A hex field was the wrong length, not valid hex, or otherwise
    /// didn't match its expected shape -- a caller-facing input problem,
    /// not a trust decision.
    Malformed(String),
    /// A cryptographic signature did not verify. This is a trust failure:
    /// either the evidence was forged, or (for a certificate/attestation)
    /// doesn't actually vouch for what the caller claims it does.
    SignatureInvalid(String),
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceError::Malformed(m) => write!(f, "malformed daemon evidence: {m}"),
            EvidenceError::SignatureInvalid(m) => write!(f, "invalid daemon evidence: {m}"),
        }
    }
}

impl std::error::Error for EvidenceError {}

impl EvidenceError {
    /// Convert to the typed error shape `/v1/sign/*` endpoints return.
    /// Malformed input is `BadRequest`; a signature that doesn't verify is
    /// `HostNotTrusted` -- the same code [`crate::host_trust::HostTrustError`]
    /// uses for an unpinned/changed fingerprint, since both mean "this
    /// agent will not vouch for this daemon."
    pub fn to_agent_error(&self) -> xenia_operator_agent_proto::AgentErrorResponse {
        use xenia_operator_agent_proto::AgentErrorCode;
        let code = match self {
            EvidenceError::Malformed(_) => AgentErrorCode::BadRequest,
            EvidenceError::SignatureInvalid(_) => AgentErrorCode::HostNotTrusted,
        };
        xenia_operator_agent_proto::AgentErrorResponse {
            code,
            message: self.to_string(),
        }
    }
}

/// A [`DaemonIdentityCertificate`] whose signatures have been verified --
/// the raw key material and fingerprint a caller can now safely act on.
#[derive(Debug)]
pub struct VerifiedDaemonIdentity {
    /// The daemon's host identity Ed25519 public key.
    pub host_ed25519_pubkey: [u8; 32],
    /// The daemon's host identity ML-DSA-65 public key.
    pub host_ml_dsa_pubkey: [u8; ML_DSA_65_PK_LEN],
    /// The daemon's separate HTTP-auth signing key, now known to be
    /// genuinely delegated-to by the host identity above.
    pub http_auth_ed25519_pubkey: [u8; 32],
    /// `xenia_handshake::host_identity_fingerprint(host_ed25519_pubkey,
    /// host_ml_dsa_pubkey)` -- computed here, not accepted from the
    /// caller.
    pub fingerprint: [u8; 32],
}

/// Verify a [`DaemonIdentityCertificate`]: decode its hex fields, verify
/// both the Ed25519 and ML-DSA-65 signatures over
/// `daemon_delegation_transcript(http_auth_ed25519_pubkey)` against the
/// certificate's own presented host keys, and compute the fingerprint.
pub fn verify_daemon_certificate(
    cert: &DaemonIdentityCertificate,
) -> Result<VerifiedDaemonIdentity, EvidenceError> {
    let host_ed25519_pubkey =
        decode_fixed_hex::<32>(&cert.host_ed25519_pubkey).ok_or_else(|| {
            EvidenceError::Malformed("host_ed25519_pubkey must be 64 hex characters".to_string())
        })?;
    let host_ml_dsa_pubkey = decode_fixed_hex::<ML_DSA_65_PK_LEN>(&cert.host_ml_dsa_pubkey)
        .ok_or_else(|| {
            EvidenceError::Malformed(format!(
                "host_ml_dsa_pubkey must be {} hex bytes",
                ML_DSA_65_PK_LEN
            ))
        })?;
    let http_auth_ed25519_pubkey = decode_fixed_hex::<32>(&cert.http_auth_ed25519_pubkey)
        .ok_or_else(|| {
            EvidenceError::Malformed(
                "http_auth_ed25519_pubkey must be 64 hex characters".to_string(),
            )
        })?;
    let host_ed_signature = decode_fixed_hex::<64>(&cert.host_ed_signature).ok_or_else(|| {
        EvidenceError::Malformed("host_ed_signature must be 128 hex characters".to_string())
    })?;
    let host_ml_dsa_signature = decode_fixed_hex::<ML_DSA_65_SIG_LEN>(&cert.host_ml_dsa_signature)
        .ok_or_else(|| {
            EvidenceError::Malformed(format!(
                "host_ml_dsa_signature must be {} hex bytes",
                ML_DSA_65_SIG_LEN
            ))
        })?;

    let host_ed_pk =
        HandshakeManager::parse_peer_public_key(&host_ed25519_pubkey).map_err(|_| {
            EvidenceError::Malformed("host_ed25519_pubkey is not a valid point".to_string())
        })?;
    let transcript = daemon_delegation_transcript(&http_auth_ed25519_pubkey);

    HandshakeManager::verify(
        &host_ed_pk,
        &transcript,
        &Signature::from_bytes(&host_ed_signature),
    )
    .map_err(|_| {
        EvidenceError::SignatureInvalid(
            "daemon certificate Ed25519 delegation signature does not verify".to_string(),
        )
    })?;
    HandshakeManager::verify_ml_dsa(&host_ml_dsa_pubkey, &transcript, &host_ml_dsa_signature)
        .map_err(|_| {
            EvidenceError::SignatureInvalid(
                "daemon certificate ML-DSA delegation signature does not verify".to_string(),
            )
        })?;

    let fingerprint = host_identity_fingerprint(&host_ed25519_pubkey, &host_ml_dsa_pubkey);

    Ok(VerifiedDaemonIdentity {
        host_ed25519_pubkey,
        host_ml_dsa_pubkey,
        http_auth_ed25519_pubkey,
        fingerprint,
    })
}

/// Verify that `nonce` was really attested by `identity`'s host identity --
/// closes the gap where a compromised browser could otherwise ask the
/// agent to sign an attacker-chosen nonce under an otherwise-legitimate,
/// already-trusted daemon certificate.
pub fn verify_challenge_attestation(
    identity: &VerifiedDaemonIdentity,
    nonce: &[u8; 32],
    host_ed_attestation_hex: &str,
    host_ml_dsa_attestation_hex: &str,
) -> Result<(), EvidenceError> {
    let host_ed_pk = HandshakeManager::parse_peer_public_key(&identity.host_ed25519_pubkey)
        .map_err(|_| {
            EvidenceError::Malformed("host_ed25519_pubkey is not a valid point".to_string())
        })?;
    let transcript = challenge_host_attestation_transcript(nonce);

    let ed_sig = decode_fixed_hex::<64>(host_ed_attestation_hex).ok_or_else(|| {
        EvidenceError::Malformed("host_ed_attestation_hex must be 128 hex characters".to_string())
    })?;
    HandshakeManager::verify(&host_ed_pk, &transcript, &Signature::from_bytes(&ed_sig)).map_err(
        |_| {
            EvidenceError::SignatureInvalid(
                "challenge host attestation Ed25519 signature does not verify".to_string(),
            )
        },
    )?;

    let ml_sig =
        decode_fixed_hex::<ML_DSA_65_SIG_LEN>(host_ml_dsa_attestation_hex).ok_or_else(|| {
            EvidenceError::Malformed(format!(
                "host_ml_dsa_attestation_hex must be {} hex bytes",
                ML_DSA_65_SIG_LEN
            ))
        })?;
    HandshakeManager::verify_ml_dsa(&identity.host_ml_dsa_pubkey, &transcript, &ml_sig).map_err(
        |_| {
            EvidenceError::SignatureInvalid(
                "challenge host attestation ML-DSA signature does not verify".to_string(),
            )
        },
    )?;

    Ok(())
}

/// Verify a [`SignedTokenDto`]'s signature against `identity`'s
/// (now-verified) delegated HTTP-auth key, reconstructing the exact bytes
/// the daemon's own signature covers
/// (`xenia_operator_proto::operator_token_canonical_bytes`). Returns the
/// token's nonce -- only once verified is it safe to bind into a
/// consent-action/revoke transcript.
pub fn verify_token(
    identity: &VerifiedDaemonIdentity,
    token: &SignedTokenDto,
) -> Result<[u8; 16], EvidenceError> {
    let token_nonce = decode_fixed_hex::<16>(&token.token_nonce_hex).ok_or_else(|| {
        EvidenceError::Malformed("token_nonce_hex must be 32 hex characters".to_string())
    })?;
    let signature = decode_fixed_hex::<64>(&token.signature_hex).ok_or_else(|| {
        EvidenceError::Malformed("signature_hex must be 128 hex characters".to_string())
    })?;

    let canonical = operator_token_canonical_bytes(
        &token.operator_id,
        token.role,
        token.issued_at,
        token.expires_at,
        &token_nonce,
    );
    let http_auth_pk = HandshakeManager::parse_peer_public_key(&identity.http_auth_ed25519_pubkey)
        .map_err(|_| {
            EvidenceError::Malformed("http_auth_ed25519_pubkey is not a valid point".to_string())
        })?;
    HandshakeManager::verify(
        &http_auth_pk,
        &canonical,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| {
        EvidenceError::SignatureInvalid(
            "operator token signature does not verify against the certificate's delegated key"
                .to_string(),
        )
    })?;

    Ok(token_nonce)
}

/// Decode exactly `N` bytes of hex, rejecting anything shorter, longer, or
/// malformed rather than silently truncating/padding. `pub(crate)` so
/// `main.rs` can reuse it instead of keeping a second copy.
pub(crate) fn decode_fixed_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}

/// Decode a variable-length hex string, for fields with no fixed size
/// (handshake message bytes -- `bincode`-encoded, so their length varies
/// by suite/content). `pub(crate)` for the same reason as
/// [`decode_fixed_hex`].
pub(crate) fn decode_hex_vec(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn daemon_and_http_auth() -> (HandshakeManager, ed25519_dalek::SigningKey) {
        (
            HandshakeManager::new(),
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()),
        )
    }

    fn certificate_for(
        host: &HandshakeManager,
        http_auth: &ed25519_dalek::SigningKey,
    ) -> DaemonIdentityCertificate {
        let http_auth_pk = http_auth.verifying_key().to_bytes();
        let transcript = daemon_delegation_transcript(&http_auth_pk);
        DaemonIdentityCertificate {
            host_ed25519_pubkey: hex::encode(host.identity_public_key_bytes()),
            host_ml_dsa_pubkey: hex::encode(host.ml_dsa_public_key_bytes()),
            http_auth_ed25519_pubkey: hex::encode(http_auth_pk),
            host_ed_signature: hex::encode(host.sign(&transcript).to_bytes()),
            host_ml_dsa_signature: hex::encode(host.sign_ml_dsa(&transcript)),
        }
    }

    #[test]
    fn verify_daemon_certificate_accepts_a_genuine_certificate_and_computes_the_fingerprint() {
        let (host, http_auth) = daemon_and_http_auth();
        let cert = certificate_for(&host, &http_auth);
        let verified = verify_daemon_certificate(&cert).unwrap();
        assert_eq!(verified.fingerprint, host.identity_fingerprint());
        assert_eq!(
            verified.http_auth_ed25519_pubkey,
            http_auth.verifying_key().to_bytes()
        );
    }

    #[test]
    fn verify_daemon_certificate_rejects_a_tampered_delegated_key() {
        let (host, http_auth) = daemon_and_http_auth();
        let mut cert = certificate_for(&host, &http_auth);
        // The certificate now claims to delegate to a *different* key than
        // the one the signature was actually computed over.
        let other = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        cert.http_auth_ed25519_pubkey = hex::encode(other.verifying_key().to_bytes());
        let err = verify_daemon_certificate(&cert).unwrap_err();
        assert!(matches!(err, EvidenceError::SignatureInvalid(_)));
    }

    #[test]
    fn verify_daemon_certificate_rejects_a_forged_signature_from_an_untrusted_host() {
        let (host, http_auth) = daemon_and_http_auth();
        let mut cert = certificate_for(&host, &http_auth);
        // An attacker's own host identity signs the same transcript, but
        // the certificate still claims the *real* host's public keys --
        // the signature must not verify against them.
        let attacker_host = HandshakeManager::new();
        let transcript = daemon_delegation_transcript(&http_auth.verifying_key().to_bytes());
        cert.host_ed_signature = hex::encode(attacker_host.sign(&transcript).to_bytes());
        let err = verify_daemon_certificate(&cert).unwrap_err();
        assert!(matches!(err, EvidenceError::SignatureInvalid(_)));
    }

    #[test]
    fn verify_daemon_certificate_rejects_malformed_hex() {
        let (host, http_auth) = daemon_and_http_auth();
        let mut cert = certificate_for(&host, &http_auth);
        cert.host_ed25519_pubkey = "not-hex".to_string();
        let err = verify_daemon_certificate(&cert).unwrap_err();
        assert!(matches!(err, EvidenceError::Malformed(_)));
    }

    #[test]
    fn verify_challenge_attestation_accepts_a_genuine_attestation_bound_to_the_exact_nonce() {
        let (host, http_auth) = daemon_and_http_auth();
        let cert = certificate_for(&host, &http_auth);
        let identity = verify_daemon_certificate(&cert).unwrap();

        let nonce = [7u8; 32];
        let transcript = challenge_host_attestation_transcript(&nonce);
        let ed_sig = hex::encode(host.sign(&transcript).to_bytes());
        let ml_sig = hex::encode(host.sign_ml_dsa(&transcript));

        assert!(verify_challenge_attestation(&identity, &nonce, &ed_sig, &ml_sig).is_ok());

        // The same attestation does not verify against a different nonce.
        let other_nonce = [8u8; 32];
        assert!(matches!(
            verify_challenge_attestation(&identity, &other_nonce, &ed_sig, &ml_sig),
            Err(EvidenceError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn verify_token_accepts_a_genuine_token_and_returns_its_nonce() {
        let (host, http_auth) = daemon_and_http_auth();
        let cert = certificate_for(&host, &http_auth);
        let identity = verify_daemon_certificate(&cert).unwrap();

        let token_nonce = [9u8; 16];
        let canonical = operator_token_canonical_bytes(
            "alice",
            xenia_operator_proto::OperatorRole::Admin,
            1000,
            2000,
            &token_nonce,
        );
        let token = SignedTokenDto {
            operator_id: "alice".to_string(),
            role: xenia_operator_proto::OperatorRole::Admin,
            issued_at: 1000,
            expires_at: 2000,
            token_nonce_hex: hex::encode(token_nonce),
            signature_hex: hex::encode(http_auth.sign(&canonical).to_bytes()),
        };

        let verified_nonce = verify_token(&identity, &token).unwrap();
        assert_eq!(verified_nonce, token_nonce);
    }

    #[test]
    fn verify_token_rejects_a_token_signed_by_the_wrong_key() {
        let (host, http_auth) = daemon_and_http_auth();
        let cert = certificate_for(&host, &http_auth);
        let identity = verify_daemon_certificate(&cert).unwrap();

        let token_nonce = [9u8; 16];
        let canonical = operator_token_canonical_bytes(
            "alice",
            xenia_operator_proto::OperatorRole::Admin,
            1000,
            2000,
            &token_nonce,
        );
        // Signed by a key that isn't the certificate's delegated HTTP-auth
        // key -- e.g. a compromised browser inventing its own token.
        let attacker = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let token = SignedTokenDto {
            operator_id: "alice".to_string(),
            role: xenia_operator_proto::OperatorRole::Admin,
            issued_at: 1000,
            expires_at: 2000,
            token_nonce_hex: hex::encode(token_nonce),
            signature_hex: hex::encode(attacker.sign(&canonical).to_bytes()),
        };

        let err = verify_token(&identity, &token).unwrap_err();
        assert!(matches!(err, EvidenceError::SignatureInvalid(_)));
    }

    #[test]
    fn verify_token_rejects_a_tampered_field() {
        let (host, http_auth) = daemon_and_http_auth();
        let cert = certificate_for(&host, &http_auth);
        let identity = verify_daemon_certificate(&cert).unwrap();

        let token_nonce = [9u8; 16];
        let canonical = operator_token_canonical_bytes(
            "alice",
            xenia_operator_proto::OperatorRole::Admin,
            1000,
            2000,
            &token_nonce,
        );
        let mut token = SignedTokenDto {
            operator_id: "alice".to_string(),
            role: xenia_operator_proto::OperatorRole::Admin,
            issued_at: 1000,
            expires_at: 2000,
            token_nonce_hex: hex::encode(token_nonce),
            signature_hex: hex::encode(http_auth.sign(&canonical).to_bytes()),
        };
        // Escalate the role after signing: the signature no longer covers
        // this field's new value.
        token.role = xenia_operator_proto::OperatorRole::Viewer;
        let err = verify_token(&identity, &token).unwrap_err();
        assert!(matches!(err, EvidenceError::SignatureInvalid(_)));
    }
}
