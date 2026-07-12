// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator challenge/response authentication + role-scoped session tokens.
//!
//! Phase 2 of `docs/security/OPERATOR_RBAC_PLAN.md`. The daemon proves an
//! operator controls an enrolled key (proof of possession), then issues a
//! short-lived token bound to the operator's role:
//!
//! 1. daemon issues a random `Challenge` nonce (short TTL, one-time).
//! 2. operator signs the domain-separated transcript
//!    (`nonce || ed_pubkey || ml_dsa_pubkey`) with **both** Ed25519 and
//!    ML-DSA-65 -- no classical-only fallback, matching the handshake.
//! 3. daemon verifies both signatures, consumes the challenge, looks the key
//!    up in the [`OperatorPolicy`], and mints a daemon-signed
//!    [`OperatorToken`] carrying the operator id + role + expiry.
//!
//! The pure crypto/time logic here takes `now` as a parameter so it is
//! deterministically testable; the daemon wrapper supplies wall-clock time.
//! The HTTP surface and enforcement on privileged actions are Phase 3.

// Wired by Phase 3 (auth HTTP endpoint + action enforcement).
#![allow(dead_code)]

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

use crate::operator::{OperatorPolicy, OperatorRole};

// The challenge/consent transcripts and the consent-action model come from the
// shared `xenia-operator-proto` crate so the console signs exactly the bytes
// the daemon verifies. Re-exported at `crate::operator_auth::*` so existing
// call sites (main.rs, operator_http, the smoke test) stay unchanged.
pub(crate) use xenia_operator_proto::{
    challenge_transcript, consent_action_transcript, revoke_operator_transcript, ConsentAction,
    OperatorAction,
};

// The session token is minted and verified only by the daemon, so its domain
// tag stays here rather than in the shared crate.
const TOKEN_DOMAIN: &[u8] = b"xenia-operator-token-v1";

/// Default lifetime of an issued challenge (seconds). Short: a challenge is
/// consumed within one round trip.
pub(crate) const CHALLENGE_TTL_SECS: u64 = 60;
/// Default lifetime of an issued session token (seconds).
pub(crate) const TOKEN_TTL_SECS: u64 = 15 * 60;

/// Default auth-attempt rate limit: attempts allowed per window, and window
/// length. Bounds brute-force / flood attempts against the auth surface.
pub(crate) const AUTH_RATE_MAX: u32 = 30;
pub(crate) const AUTH_RATE_WINDOW_SECS: u64 = 60;

/// A fixed-window rate limiter. `allow(now)` returns whether an attempt is
/// permitted, consuming one slot; the window resets when it elapses. Pure and
/// time-injectable for testing.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    window_secs: u64,
    max: u32,
    window_start: u64,
    count: u32,
}

impl RateLimiter {
    pub(crate) fn new(max: u32, window_secs: u64) -> Self {
        Self {
            window_secs,
            max,
            window_start: 0,
            count: 0,
        }
    }

    /// Record an attempt; return whether it is within the limit. Once the
    /// window elapses the counter resets.
    pub(crate) fn allow(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.window_start) >= self.window_secs {
            self.window_start = now;
            self.count = 0;
        }
        if self.count < self.max {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

/// Outstanding challenges awaiting a response: nonce -> expiry (unix secs).
/// A challenge is single-use -- [`Self::consume`] removes it.
#[derive(Debug, Default)]
pub(crate) struct ChallengeStore {
    outstanding: HashMap<[u8; 32], u64>,
}

impl ChallengeStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record an issued challenge with `now + ttl_secs` expiry.
    pub(crate) fn issue(&mut self, nonce: [u8; 32], now: u64, ttl_secs: u64) {
        self.outstanding.insert(nonce, now.saturating_add(ttl_secs));
    }

    /// Consume a challenge: it must be outstanding and unexpired. Returns
    /// true and removes it (single-use); false if unknown or expired (an
    /// expired one is also removed).
    pub(crate) fn consume(&mut self, nonce: &[u8; 32], now: u64) -> bool {
        match self.outstanding.remove(nonce) {
            Some(expires_at) => now <= expires_at,
            None => false,
        }
    }

    /// Drop every expired challenge.
    pub(crate) fn gc(&mut self, now: u64) {
        self.outstanding
            .retain(|_, &mut expires_at| now <= expires_at);
    }

    pub(crate) fn len(&self) -> usize {
        self.outstanding.len()
    }
}

/// A signed response to an operator auth challenge.
pub(crate) struct ChallengeResponse {
    pub(crate) nonce: [u8; 32],
    pub(crate) ed_pubkey: [u8; 32],
    pub(crate) ml_dsa_pubkey: Vec<u8>,
    pub(crate) ed_signature: [u8; 64],
    pub(crate) ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
}

/// Why an operator authentication attempt failed. All are denials; kept
/// distinct for audit and messaging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthError {
    /// The challenge is unknown, already used, or expired.
    UnknownOrExpiredChallenge,
    /// The ML-DSA public key was the wrong length.
    MalformedKey,
    /// The Ed25519 signature did not verify.
    Ed25519VerifyFailed,
    /// The ML-DSA signature did not verify.
    MlDsaVerifyFailed,
    /// Both signatures verified, but the key is not enrolled.
    NotEnrolled,
    /// A token failed to verify (bad signature or expired).
    InvalidToken,
    /// The token is valid but its role does not permit the requested action.
    RoleNotPermitted,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthError::UnknownOrExpiredChallenge => "unknown, used, or expired challenge",
            AuthError::MalformedKey => "malformed operator public key",
            AuthError::Ed25519VerifyFailed => "Ed25519 signature verification failed",
            AuthError::MlDsaVerifyFailed => "ML-DSA signature verification failed",
            AuthError::NotEnrolled => "operator key is not enrolled",
            AuthError::InvalidToken => "invalid or expired operator token",
            AuthError::RoleNotPermitted => "operator role does not permit this action",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AuthError {}

/// Verify a challenge response and, on success, return the authenticated
/// operator's id + role. Consumes the challenge (single-use) *before* any
/// signature check so a replayed nonce can't be retried. Requires BOTH
/// signatures to verify and the key to be enrolled -- fail-closed at every
/// step.
pub(crate) fn verify_challenge_response(
    policy: &OperatorPolicy,
    challenges: &mut ChallengeStore,
    now: u64,
    response: &ChallengeResponse,
) -> Result<AuthenticatedOperator, AuthError> {
    if !challenges.consume(&response.nonce, now) {
        return Err(AuthError::UnknownOrExpiredChallenge);
    }
    if response.ml_dsa_pubkey.len() != ML_DSA_65_PK_LEN {
        return Err(AuthError::MalformedKey);
    }
    let transcript = challenge_transcript(
        &response.nonce,
        &response.ed_pubkey,
        &response.ml_dsa_pubkey,
    );

    let ed_vk: VerifyingKey = HandshakeManager::parse_peer_public_key(&response.ed_pubkey)
        .map_err(|_| AuthError::MalformedKey)?;
    let ed_sig = Signature::from_bytes(&response.ed_signature);
    HandshakeManager::verify(&ed_vk, &transcript, &ed_sig)
        .map_err(|_| AuthError::Ed25519VerifyFailed)?;

    let ml_pk: [u8; ML_DSA_65_PK_LEN] = response
        .ml_dsa_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::MalformedKey)?;
    HandshakeManager::verify_ml_dsa(&ml_pk, &transcript, &response.ml_dsa_signature)
        .map_err(|_| AuthError::MlDsaVerifyFailed)?;

    // Both signatures verified: the caller controls this key *pair*. Is that
    // exact pair enrolled? `lookup_verified` (not plain `lookup`) is required
    // here -- otherwise an attacker holding only the enrolled Ed25519 secret
    // could pair it with a self-generated ML-DSA keypair and still pass,
    // silently downgrading hybrid auth to classical-only.
    match policy.lookup_verified(&response.ed_pubkey, &response.ml_dsa_pubkey) {
        Some(op) => Ok(AuthenticatedOperator {
            operator_id: op.operator_id.clone(),
            role: op.role,
        }),
        None => Err(AuthError::NotEnrolled),
    }
}

/// A successfully-authenticated operator (proof-of-possession + enrolled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedOperator {
    pub(crate) operator_id: String,
    pub(crate) role: OperatorRole,
}

/// A role-scoped session token the daemon mints after authentication. The
/// daemon signs it with its own key; every privileged action re-presents it,
/// and the daemon re-verifies it (Phase 3) rather than trusting the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorToken {
    pub(crate) operator_id: String,
    pub(crate) role: OperatorRole,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) token_nonce: [u8; 16],
}

impl OperatorToken {
    fn canonical_bytes(&self) -> Vec<u8> {
        let id = self.operator_id.as_bytes();
        let mut b = Vec::with_capacity(TOKEN_DOMAIN.len() + 8 + id.len() + 1 + 8 + 8 + 16);
        b.extend_from_slice(TOKEN_DOMAIN);
        b.extend_from_slice(&(id.len() as u64).to_le_bytes());
        b.extend_from_slice(id);
        b.push(role_tag(self.role));
        b.extend_from_slice(&self.issued_at.to_le_bytes());
        b.extend_from_slice(&self.expires_at.to_le_bytes());
        b.extend_from_slice(&self.token_nonce);
        b
    }
}

/// A token plus the daemon's signature over its canonical bytes.
#[derive(Debug, Clone)]
pub(crate) struct SignedOperatorToken {
    pub(crate) token: OperatorToken,
    pub(crate) signature: [u8; 64],
}

/// Mint a signed token for an authenticated operator.
pub(crate) fn issue_token(
    daemon_key: &SigningKey,
    operator: &AuthenticatedOperator,
    now: u64,
    ttl_secs: u64,
    token_nonce: [u8; 16],
) -> SignedOperatorToken {
    let token = OperatorToken {
        operator_id: operator.operator_id.clone(),
        role: operator.role,
        issued_at: now,
        expires_at: now.saturating_add(ttl_secs),
        token_nonce,
    };
    let signature = daemon_key.sign(&token.canonical_bytes()).to_bytes();
    SignedOperatorToken { token, signature }
}

/// Verify a token was signed by `daemon_pubkey` and has not expired. Returns
/// the token (operator id + role) for the authorization check.
pub(crate) fn verify_token(
    daemon_pubkey: &VerifyingKey,
    now: u64,
    signed: &SignedOperatorToken,
) -> Result<OperatorToken, AuthError> {
    let sig = Signature::from_bytes(&signed.signature);
    HandshakeManager::verify(daemon_pubkey, &signed.token.canonical_bytes(), &sig)
        .map_err(|_| AuthError::InvalidToken)?;
    if now > signed.token.expires_at {
        return Err(AuthError::InvalidToken);
    }
    Ok(signed.token.clone())
}

fn role_tag(role: OperatorRole) -> u8 {
    match role {
        OperatorRole::Viewer => 0,
        OperatorRole::Approver => 1,
        OperatorRole::Operator => 2,
        OperatorRole::Admin => 3,
    }
}

/// An operator's authenticated request to perform a consent action: their
/// session token plus a per-action signature (over the action + session +
/// token nonce) proving they, not just a token bearer, authorized it.
pub(crate) struct AuthenticatedConsentAction {
    pub(crate) token: SignedOperatorToken,
    pub(crate) action: ConsentAction,
    pub(crate) action_signature: [u8; 64],
}

/// A consent action authorized to a specific operator, ready to apply + audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedConsentAction {
    pub(crate) action: ConsentAction,
    pub(crate) operator_id: String,
    pub(crate) role: OperatorRole,
    /// The operator's enrolled Ed25519 public key, for stable audit
    /// attribution (used as the ledger entry's `source_id`).
    pub(crate) ed25519_pubkey: [u8; 32],
}

/// Authorize a consent action, fail-closed at every step:
/// 1. the token is daemon-signed and unexpired;
/// 2. the token's role permits the action;
/// 3. the operator is *still* enrolled (a de-enrolled operator's token is
///    dead even if unexpired);
/// 4. the per-action signature verifies against that operator's enrolled
///    Ed25519 key over this exact action + session + token nonce.
pub(crate) fn authorize_consent_action(
    policy: &OperatorPolicy,
    daemon_pubkey: &VerifyingKey,
    now: u64,
    session_id: &[u8; 16],
    request: &AuthenticatedConsentAction,
) -> Result<AuthorizedConsentAction, AuthError> {
    let token = verify_token(daemon_pubkey, now, &request.token)?;

    if !crate::operator::role_permits(token.role, request.action.required_permission()) {
        return Err(AuthError::RoleNotPermitted);
    }

    let operator = policy
        .lookup_by_id(&token.operator_id)
        .ok_or(AuthError::NotEnrolled)?;

    let transcript = consent_action_transcript(request.action, session_id, &token.token_nonce);
    let ed_vk = HandshakeManager::parse_peer_public_key(&operator.ed25519_pubkey)
        .map_err(|_| AuthError::MalformedKey)?;
    let sig = Signature::from_bytes(&request.action_signature);
    HandshakeManager::verify(&ed_vk, &transcript, &sig)
        .map_err(|_| AuthError::Ed25519VerifyFailed)?;

    Ok(AuthorizedConsentAction {
        action: request.action,
        operator_id: token.operator_id,
        role: token.role,
        ed25519_pubkey: operator.ed25519_pubkey,
    })
}

/// An admin's authenticated request to revoke another operator: their session
/// token plus a signature over (revoke domain + target id + token nonce),
/// proving the *admin* (not just a token bearer) authorized this exact
/// revocation.
pub(crate) struct AuthenticatedRevocation {
    pub(crate) token: SignedOperatorToken,
    pub(crate) target_operator_id: String,
    pub(crate) action_signature: [u8; 64],
}

/// A revocation authorized to a specific admin operator, ready to apply + audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedRevocation {
    /// The operator being revoked.
    pub(crate) target_operator_id: String,
    /// The admin who authorized the revocation (for audit attribution).
    pub(crate) operator_id: String,
    /// The authorizing admin's enrolled Ed25519 key.
    pub(crate) ed25519_pubkey: [u8; 32],
}

/// Authorize an operator-revocation request, fail-closed at every step — the
/// same discipline as [`authorize_consent_action`]:
/// 1. the token is daemon-signed and unexpired;
/// 2. the token's role is `Admin` (via the `EnrollOperator` permission, which is
///    "enroll or revoke an operator");
/// 3. the authorizing admin is *still* enrolled;
/// 4. the per-action signature verifies against that admin's enrolled Ed25519
///    key over this exact target id + token nonce.
///
/// Note this authorizes *who may revoke*; it does not itself validate that
/// `target_operator_id` is currently enrolled — revoking an unknown/already-gone
/// id is a harmless no-op the caller may still want recorded.
pub(crate) fn authorize_operator_revocation(
    policy: &OperatorPolicy,
    daemon_pubkey: &VerifyingKey,
    now: u64,
    request: &AuthenticatedRevocation,
) -> Result<AuthorizedRevocation, AuthError> {
    let token = verify_token(daemon_pubkey, now, &request.token)?;

    // "Enroll or revoke an operator" is Admin-only.
    if !crate::operator::role_permits(token.role, OperatorAction::EnrollOperator) {
        return Err(AuthError::RoleNotPermitted);
    }

    let operator = policy
        .lookup_by_id(&token.operator_id)
        .ok_or(AuthError::NotEnrolled)?;

    let transcript = revoke_operator_transcript(&request.target_operator_id, &token.token_nonce);
    let ed_vk = HandshakeManager::parse_peer_public_key(&operator.ed25519_pubkey)
        .map_err(|_| AuthError::MalformedKey)?;
    let sig = Signature::from_bytes(&request.action_signature);
    HandshakeManager::verify(&ed_vk, &transcript, &sig)
        .map_err(|_| AuthError::Ed25519VerifyFailed)?;

    Ok(AuthorizedRevocation {
        target_operator_id: request.target_operator_id.clone(),
        operator_id: token.operator_id,
        ed25519_pubkey: operator.ed25519_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::EnrolledOperator;

    /// Build a one-operator policy from a HandshakeManager's public identity.
    fn policy_with(mgr: &HandshakeManager, role: OperatorRole) -> OperatorPolicy {
        OperatorPolicy::from_operators(vec![EnrolledOperator {
            operator_id: "op".to_string(),
            ed25519_pubkey: mgr.identity_public_key_bytes(),
            ml_dsa_pubkey: mgr.ml_dsa_public_key_bytes().to_vec(),
            role,
        }])
        .unwrap()
    }

    fn signed_response(mgr: &HandshakeManager, nonce: [u8; 32]) -> ChallengeResponse {
        let ed_pubkey = mgr.identity_public_key_bytes();
        let ml_dsa_pubkey = mgr.ml_dsa_public_key_bytes().to_vec();
        let transcript = challenge_transcript(&nonce, &ed_pubkey, &ml_dsa_pubkey);
        ChallengeResponse {
            nonce,
            ed_pubkey,
            ml_dsa_pubkey,
            ed_signature: mgr.sign(&transcript).to_bytes(),
            ml_dsa_signature: mgr.sign_ml_dsa(&transcript),
        }
    }

    #[test]
    fn rate_limiter_bounds_attempts_per_window_and_resets() {
        let mut rl = RateLimiter::new(3, 60);
        // 3 allowed in the first window.
        assert!(rl.allow(1000));
        assert!(rl.allow(1001));
        assert!(rl.allow(1030));
        // 4th within the same window is refused.
        assert!(!rl.allow(1031));
        assert!(!rl.allow(1059));
        // Next window resets the count.
        assert!(rl.allow(1060));
        assert!(rl.allow(1061));
    }

    #[test]
    fn full_auth_round_trip_succeeds_and_is_single_use() {
        let op = HandshakeManager::new();
        let policy = policy_with(&op, OperatorRole::Approver);
        let mut challenges = ChallengeStore::new();
        let nonce = [3u8; 32];
        challenges.issue(nonce, 1000, CHALLENGE_TTL_SECS);

        let response = signed_response(&op, nonce);
        let authed = verify_challenge_response(&policy, &mut challenges, 1010, &response).unwrap();
        assert_eq!(authed.operator_id, "op");
        assert_eq!(authed.role, OperatorRole::Approver);

        // The challenge is consumed: replaying the same response fails.
        assert_eq!(
            verify_challenge_response(&policy, &mut challenges, 1010, &response),
            Err(AuthError::UnknownOrExpiredChallenge)
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let op = HandshakeManager::new();
        let policy = policy_with(&op, OperatorRole::Admin);
        let mut challenges = ChallengeStore::new();
        let nonce = [4u8; 32];
        challenges.issue(nonce, 1000, CHALLENGE_TTL_SECS);
        let response = signed_response(&op, nonce);
        // now is past expiry.
        assert_eq!(
            verify_challenge_response(
                &policy,
                &mut challenges,
                1000 + CHALLENGE_TTL_SECS + 1,
                &response
            ),
            Err(AuthError::UnknownOrExpiredChallenge)
        );
    }

    #[test]
    fn unenrolled_key_is_rejected_after_valid_signatures() {
        let op = HandshakeManager::new();
        let other = HandshakeManager::new();
        // Policy enrolls `other`, not `op`.
        let policy = policy_with(&other, OperatorRole::Admin);
        let mut challenges = ChallengeStore::new();
        let nonce = [5u8; 32];
        challenges.issue(nonce, 1000, CHALLENGE_TTL_SECS);
        let response = signed_response(&op, nonce);
        assert_eq!(
            verify_challenge_response(&policy, &mut challenges, 1010, &response),
            Err(AuthError::NotEnrolled)
        );
    }

    #[test]
    fn enrolled_ed25519_key_with_a_foreign_ml_dsa_key_is_rejected() {
        // The scenario the hybrid suite exists to defend against: an attacker
        // who somehow controls the *enrolled* Ed25519 secret (e.g. Ed25519 is
        // broken by a quantum adversary, or the classical key leaked) but
        // does not control the enrolled ML-DSA key. They sign the transcript
        // with the real Ed25519 key and their own freshly-generated ML-DSA
        // keypair; both signatures verify individually, but the presented
        // ML-DSA key does not match the enrollment record and must be
        // refused -- otherwise the ML-DSA signature buys no security at all.
        let op = HandshakeManager::new();
        let policy = policy_with(&op, OperatorRole::Admin);
        let mut challenges = ChallengeStore::new();
        let nonce = [11u8; 32];
        challenges.issue(nonce, 1000, CHALLENGE_TTL_SECS);

        let attacker_ml_dsa = HandshakeManager::new();
        let ed_pubkey = op.identity_public_key_bytes();
        let ml_dsa_pubkey = attacker_ml_dsa.ml_dsa_public_key_bytes().to_vec();
        let transcript = challenge_transcript(&nonce, &ed_pubkey, &ml_dsa_pubkey);
        let response = ChallengeResponse {
            nonce,
            ed_pubkey,
            ml_dsa_pubkey,
            ed_signature: op.sign(&transcript).to_bytes(),
            ml_dsa_signature: attacker_ml_dsa.sign_ml_dsa(&transcript),
        };

        assert_eq!(
            verify_challenge_response(&policy, &mut challenges, 1010, &response),
            Err(AuthError::NotEnrolled)
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let op = HandshakeManager::new();
        let policy = policy_with(&op, OperatorRole::Admin);
        let mut challenges = ChallengeStore::new();
        let nonce = [6u8; 32];
        challenges.issue(nonce, 1000, CHALLENGE_TTL_SECS);
        let mut response = signed_response(&op, nonce);
        response.ed_signature[0] ^= 0x01;
        assert_eq!(
            verify_challenge_response(&policy, &mut challenges, 1010, &response),
            Err(AuthError::Ed25519VerifyFailed)
        );
    }

    #[test]
    fn token_round_trip_and_expiry() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let daemon_pk = daemon.verifying_key();
        let operator = AuthenticatedOperator {
            operator_id: "op".to_string(),
            role: OperatorRole::Operator,
        };
        let signed = issue_token(&daemon, &operator, 2000, TOKEN_TTL_SECS, [1u8; 16]);

        // Valid within TTL.
        let token = verify_token(&daemon_pk, 2100, &signed).unwrap();
        assert_eq!(token.operator_id, "op");
        assert_eq!(token.role, OperatorRole::Operator);

        // Expired.
        assert_eq!(
            verify_token(&daemon_pk, 2000 + TOKEN_TTL_SECS + 1, &signed),
            Err(AuthError::InvalidToken)
        );

        // Wrong daemon key.
        let attacker = SigningKey::generate(&mut rand::thread_rng());
        assert_eq!(
            verify_token(&attacker.verifying_key(), 2100, &signed),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn tampered_token_fields_fail_verification() {
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let daemon_pk = daemon.verifying_key();
        let operator = AuthenticatedOperator {
            operator_id: "op".to_string(),
            role: OperatorRole::Viewer,
        };
        let mut signed = issue_token(&daemon, &operator, 2000, TOKEN_TTL_SECS, [1u8; 16]);
        // Escalate the role in the token body: signature no longer matches.
        signed.token.role = OperatorRole::Admin;
        assert_eq!(
            verify_token(&daemon_pk, 2100, &signed),
            Err(AuthError::InvalidToken)
        );
    }

    /// Build an authenticated consent action: a token for `op` at `role`,
    /// plus `op`'s Ed25519 signature over the action + session + token nonce.
    fn authed_action(
        op: &HandshakeManager,
        daemon: &SigningKey,
        role: OperatorRole,
        session_id: &[u8; 16],
        action: ConsentAction,
        now: u64,
    ) -> AuthenticatedConsentAction {
        let authed = AuthenticatedOperator {
            operator_id: "op".to_string(),
            role,
        };
        let signed = issue_token(daemon, &authed, now, TOKEN_TTL_SECS, [5u8; 16]);
        let transcript = consent_action_transcript(action, session_id, &signed.token.token_nonce);
        let action_signature = op.sign(&transcript).to_bytes();
        AuthenticatedConsentAction {
            token: signed,
            action,
            action_signature,
        }
    }

    /// Build a signed operator-revocation request: `op` (role `role`) authorizes
    /// revoking `target`.
    fn authed_revocation(
        op: &HandshakeManager,
        daemon: &SigningKey,
        role: OperatorRole,
        target: &str,
        now: u64,
    ) -> AuthenticatedRevocation {
        let authed = AuthenticatedOperator {
            operator_id: "op".to_string(),
            role,
        };
        let signed = issue_token(daemon, &authed, now, TOKEN_TTL_SECS, [9u8; 16]);
        let transcript = revoke_operator_transcript(target, &signed.token.token_nonce);
        let action_signature = op.sign(&transcript).to_bytes();
        AuthenticatedRevocation {
            token: signed,
            target_operator_id: target.to_string(),
            action_signature,
        }
    }

    #[test]
    fn revocation_authorized_for_admin() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let policy = policy_with(&op, OperatorRole::Admin);
        let req = authed_revocation(&op, &daemon, OperatorRole::Admin, "mallory", 3000);
        let authorized =
            authorize_operator_revocation(&policy, &daemon.verifying_key(), 3010, &req).unwrap();
        assert_eq!(authorized.target_operator_id, "mallory");
        assert_eq!(authorized.operator_id, "op");
    }

    #[test]
    fn revocation_denied_for_non_admin() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        // Approver is below Admin; even an honestly-issued Approver token can't
        // revoke an operator.
        let policy = policy_with(&op, OperatorRole::Approver);
        let req = authed_revocation(&op, &daemon, OperatorRole::Approver, "mallory", 3000);
        assert_eq!(
            authorize_operator_revocation(&policy, &daemon.verifying_key(), 3010, &req),
            Err(AuthError::RoleNotPermitted)
        );
    }

    #[test]
    fn revocation_signature_bound_to_target() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let policy = policy_with(&op, OperatorRole::Admin);
        // Signature is over "mallory"; swap the target to "alice" → the per-action
        // signature no longer verifies (can't be replayed for a different target).
        let mut req = authed_revocation(&op, &daemon, OperatorRole::Admin, "mallory", 3000);
        req.target_operator_id = "alice".to_string();
        assert_eq!(
            authorize_operator_revocation(&policy, &daemon.verifying_key(), 3010, &req),
            Err(AuthError::Ed25519VerifyFailed)
        );
    }

    #[test]
    fn revocation_rejected_for_expired_token() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let policy = policy_with(&op, OperatorRole::Admin);
        let req = authed_revocation(&op, &daemon, OperatorRole::Admin, "mallory", 3000);
        // now is past the token's expiry.
        assert_eq!(
            authorize_operator_revocation(
                &policy,
                &daemon.verifying_key(),
                3000 + TOKEN_TTL_SECS + 1,
                &req
            ),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn consent_action_authorized_for_permitted_role() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let policy = policy_with(&op, OperatorRole::Approver);
        let session = [7u8; 16];
        let req = authed_action(
            &op,
            &daemon,
            OperatorRole::Approver,
            &session,
            ConsentAction::Approve,
            3000,
        );
        let authorized =
            authorize_consent_action(&policy, &daemon.verifying_key(), 3010, &session, &req)
                .unwrap();
        assert_eq!(authorized.action, ConsentAction::Approve);
        assert_eq!(authorized.operator_id, "op");
        assert_eq!(authorized.role, OperatorRole::Approver);
    }

    #[test]
    fn consent_action_denied_for_insufficient_role() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let policy = policy_with(&op, OperatorRole::Viewer);
        let session = [7u8; 16];
        // A Viewer-role token can't approve. (The token is honestly issued at
        // Viewer -- a forged Approver token would fail token verification.)
        let req = authed_action(
            &op,
            &daemon,
            OperatorRole::Viewer,
            &session,
            ConsentAction::Approve,
            3000,
        );
        assert_eq!(
            authorize_consent_action(&policy, &daemon.verifying_key(), 3010, &session, &req),
            Err(AuthError::RoleNotPermitted)
        );
    }

    #[test]
    fn consent_action_signature_bound_to_session() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        let policy = policy_with(&op, OperatorRole::Admin);
        // Signed for one session, presented against another: the per-action
        // signature no longer verifies (replay across sessions is refused).
        let req = authed_action(
            &op,
            &daemon,
            OperatorRole::Admin,
            &[1u8; 16],
            ConsentAction::Revoke,
            3000,
        );
        assert_eq!(
            authorize_consent_action(&policy, &daemon.verifying_key(), 3010, &[2u8; 16], &req),
            Err(AuthError::Ed25519VerifyFailed)
        );
    }

    #[test]
    fn consent_action_rejected_after_operator_de_enrolled() {
        let op = HandshakeManager::new();
        let daemon = SigningKey::generate(&mut rand::thread_rng());
        // Empty policy: the operator was de-enrolled after the token was issued.
        let policy = OperatorPolicy::default();
        let session = [7u8; 16];
        let req = authed_action(
            &op,
            &daemon,
            OperatorRole::Admin,
            &session,
            ConsentAction::Revoke,
            3000,
        );
        assert_eq!(
            authorize_consent_action(&policy, &daemon.verifying_key(), 3010, &session, &req),
            Err(AuthError::NotEnrolled)
        );
    }
}
