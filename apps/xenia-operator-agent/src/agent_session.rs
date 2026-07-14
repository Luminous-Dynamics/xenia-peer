// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Short-lived agent sessions (item 4 of
//! `docs/security/POST_DELEGATION_HARDENING_PLAN.md`), replacing the raw
//! pairing token as the credential presented on every request after the
//! first.
//!
//! **The problem this closes**: the pairing token used to be a permanent,
//! unbounded bearer secret -- generated once, persisted to disk, and sent
//! as `X-Agent-Token` on literally every request forever. The console
//! mirrored that by persisting it in `localStorage` indefinitely. A
//! one-time read of `localStorage` (XSS, a malicious extension, a
//! compromised same-origin dependency) therefore yielded indefinite
//! ability to command the agent -- there was no time bound at all.
//!
//! **The fix**: the pairing token becomes bootstrap-only, accepted solely
//! on `POST /v1/pair`. Every other route requires a short-lived
//! [`xenia_operator_agent_proto::AgentSessionToken`] instead, presented as
//! `X-Agent-Session`. `POST /v1/session/refresh` mints a fresh one given a
//! still-valid one, so an actively-used console never has to re-present
//! the raw pairing token; an idle console (closed past the TTL) does. See
//! [`AgentSessionToken`]'s own doc comment for why there's no per-session
//! revocation (only the blunt instrument of regenerating the pairing-token
//! file, same as the old model already required).
//!
//! Session tokens are verified statelessly: a keyed BLAKE3 hash
//! ([`blake3::keyed_hash`]) over the token's fields, keyed by a value
//! *derived* from the raw pairing token via [`blake3::derive_key`] --
//! never the pairing token's raw bytes directly, so the same 32 bytes are
//! never used in two different cryptographic roles (compared as a bearer
//! secret on `/v1/pair`, and separately keying every session's MAC).
//! Deriving from the (file-persisted) pairing token rather than a
//! per-process random key also means sessions minted before an agent
//! restart stay valid after one -- restarting the agent shouldn't force
//! every open console tab to re-pair.

use xenia_operator_agent_proto::{AgentSessionToken, agent_session_mac_message};

/// Default session lifetime: long enough to cover a normal working session
/// without needing to re-pair, short enough to meaningfully bound exposure
/// if a session token leaks (browser disk forensics, a misconfigured log,
/// a stolen laptop that's been asleep) -- unlike the pairing token it's
/// derived from, which had no expiry at all. An actively-used console
/// renews via `/v1/session/refresh` well before this and never notices.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 60 * 60;

/// blake3 key-derivation context for [`session_mac_key`]. Domain-separates
/// the *MAC key itself* from the pairing token's other cryptographic role
/// (a directly-compared bearer secret on `/v1/pair`) -- see the module doc
/// comment. Distinct from
/// [`xenia_operator_agent_proto::AGENT_SESSION_MAC_DOMAIN`], which
/// domain-separates the *MAC message*, not the key.
const SESSION_MAC_KDF_CONTEXT: &str = "xenia-operator-agent 2026-07 session-mac-key";

/// Derive the session-MAC key from the raw, file-persisted pairing token.
/// Deterministic and meant to be computed once at startup and cached
/// (`AgentState::session_mac_key`), not recomputed per request.
pub fn session_mac_key(pairing_token: &str) -> [u8; 32] {
    blake3::derive_key(SESSION_MAC_KDF_CONTEXT, pairing_token.as_bytes())
}

/// Mint a fresh session token, MAC'd under `mac_key`, expiring
/// `ttl_secs` after `now`.
pub fn mint(mac_key: &[u8; 32], now: u64, ttl_secs: u64) -> AgentSessionToken {
    let session_id: [u8; 16] = rand::random();
    let expires_at = now.saturating_add(ttl_secs);
    let mac = blake3::keyed_hash(
        mac_key,
        &agent_session_mac_message(&session_id, now, expires_at),
    );
    AgentSessionToken {
        session_id_hex: hex::encode(session_id),
        issued_at: now,
        expires_at,
        mac_hex: hex::encode(mac.as_bytes()),
    }
}

/// Why a presented session token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Missing, or not the `session_id.issued_at.expires_at.mac` shape, or
    /// a field that doesn't decode to the expected byte length.
    Malformed,
    /// Well-formed, but the MAC doesn't verify -- forged, or MAC'd under a
    /// different pairing token (e.g. after the token file was
    /// regenerated).
    BadMac,
    /// MAC verified, but `now > expires_at`.
    Expired,
}

impl SessionError {
    /// A caller-facing message. Deliberately generic for [`Self::BadMac`]
    /// (doesn't distinguish "forged" from "stale key" -- both look
    /// identical to a caller and neither should be narrated to one).
    pub fn message(self) -> &'static str {
        match self {
            SessionError::Malformed => "missing or malformed X-Agent-Session",
            SessionError::BadMac => "invalid X-Agent-Session",
            SessionError::Expired => "X-Agent-Session has expired, please re-pair",
        }
    }
}

/// Verify a presented `X-Agent-Session` header value: well-formed, MAC
/// checks out under `mac_key`, not expired. MAC is checked before expiry
/// (mirrors `xenia-peer`'s own `operator_auth::verify_token` order), so a
/// caller can't use expiry-vs-MAC-failure differences to learn anything
/// about how close a forged token is to being valid.
pub fn verify(
    mac_key: &[u8; 32],
    now: u64,
    presented: &str,
) -> Result<AgentSessionToken, SessionError> {
    let token = AgentSessionToken::from_header_value(presented).ok_or(SessionError::Malformed)?;
    let session_id: [u8; 16] = crate::daemon_evidence::decode_fixed_hex(&token.session_id_hex)
        .ok_or(SessionError::Malformed)?;
    let presented_mac: [u8; 32] =
        crate::daemon_evidence::decode_fixed_hex(&token.mac_hex).ok_or(SessionError::Malformed)?;

    let expected = blake3::keyed_hash(
        mac_key,
        &agent_session_mac_message(&session_id, token.issued_at, token.expires_at),
    );
    if !crate::constant_time_eq(expected.as_bytes(), &presented_mac) {
        return Err(SessionError::BadMac);
    }
    if now > token.expires_at {
        return Err(SessionError::Expired);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_pairing_tokens_derive_different_mac_keys() {
        let a = session_mac_key("token-a");
        let b = session_mac_key("token-b");
        assert_ne!(a, b);
        // Deterministic: the same pairing token always derives the same
        // key (sessions minted before an agent restart must stay valid
        // after one, since the pairing token file is what persists).
        assert_eq!(a, session_mac_key("token-a"));
    }

    #[test]
    fn mac_key_is_never_the_raw_pairing_token_bytes() {
        let token = "a".repeat(64);
        let key = session_mac_key(&token);
        assert_ne!(key.to_vec(), token.as_bytes()[..32].to_vec());
    }

    #[test]
    fn mint_then_verify_round_trips() {
        let key = session_mac_key("secret");
        let minted = mint(&key, 1000, 3600);
        assert_eq!(minted.issued_at, 1000);
        assert_eq!(minted.expires_at, 4600);

        let header = minted.to_header_value();
        let verified = verify(&key, 1000, &header).expect("freshly minted session verifies");
        assert_eq!(verified, minted);
    }

    #[test]
    fn verify_rejects_a_missing_or_malformed_header() {
        let key = session_mac_key("secret");
        assert_eq!(verify(&key, 1000, "").unwrap_err(), SessionError::Malformed);
        assert_eq!(
            verify(&key, 1000, "not.enough.parts").unwrap_err(),
            SessionError::Malformed
        );
        assert_eq!(
            verify(&key, 1000, "zz.1000.4600.aa").unwrap_err(),
            SessionError::Malformed,
            "session_id_hex must decode to exactly 16 bytes"
        );
    }

    #[test]
    fn verify_rejects_a_session_minted_under_a_different_pairing_token() {
        let key_a = session_mac_key("token-a");
        let key_b = session_mac_key("token-b");
        let minted = mint(&key_a, 1000, 3600);
        assert_eq!(
            verify(&key_b, 1000, &minted.to_header_value()).unwrap_err(),
            SessionError::BadMac,
            "a session MAC'd under a rotated/different pairing token must not verify"
        );
    }

    #[test]
    fn verify_rejects_any_tampered_field() {
        let key = session_mac_key("secret");
        let minted = mint(&key, 1000, 3600);

        let mut tampered = minted.clone();
        tampered.session_id_hex = "ff".repeat(16);
        assert_eq!(
            verify(&key, 1000, &tampered.to_header_value()).unwrap_err(),
            SessionError::BadMac
        );

        let mut tampered = minted.clone();
        tampered.issued_at -= 1;
        assert_eq!(
            verify(&key, 1000, &tampered.to_header_value()).unwrap_err(),
            SessionError::BadMac
        );

        let mut tampered = minted.clone();
        tampered.expires_at += 1_000_000;
        assert_eq!(
            verify(&key, 1000, &tampered.to_header_value()).unwrap_err(),
            SessionError::BadMac,
            "extending expires_at must be caught by the MAC, not silently accepted"
        );
    }

    #[test]
    fn verify_rejects_an_expired_but_otherwise_valid_session() {
        let key = session_mac_key("secret");
        let minted = mint(&key, 1000, 3600);
        assert_eq!(
            verify(&key, 4601, &minted.to_header_value()).unwrap_err(),
            SessionError::Expired
        );
        // The boundary itself is still valid.
        assert!(verify(&key, 4600, &minted.to_header_value()).is_ok());
    }
}
