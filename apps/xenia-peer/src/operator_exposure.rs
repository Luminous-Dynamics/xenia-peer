// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed guard for exposing the operator surface beyond loopback
//! (`OPERATOR_RBAC_PLAN.md` Phase 6 — remote operators).
//!
//! The operator surface is the admin port (`/auth/*` + the consent-prompt
//! `/ws`) and the raw consent port. Binding it to loopback is unchanged and
//! always allowed. Binding it to a network address is only safe when every
//! consent decision must be a cryptographically-authenticated,
//! role-authorized operator action — otherwise any host on the network could
//! connect to the consent port and send `Approve`. So a non-loopback bind
//! *requires* `--require-operator-auth`; we refuse to start otherwise.
//!
//! This guards **integrity** (forgery), which is enforceable in-process.
//! **Confidentiality** (a passive observer reading prompts/tokens) is a
//! transport concern: terminate TLS in front (reverse proxy / `wss`). The
//! app-layer signatures already bind every action to its session + token, so
//! an observer can't forge or usefully replay one.

/// Whether `bind` is a loopback-only address (safe to expose without operator
/// auth). Hostnames other than `localhost` are treated as **non**-loopback
/// (fail-safe: we can't resolve them here, so we assume the worst).
pub(crate) fn is_loopback_bind(bind: &str) -> bool {
    if bind.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // Accept a bracketed IPv6 literal (`[::1]`) as well as bare forms.
    let host = bind.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Refuse to expose the operator surface beyond loopback without operator
/// auth. Returns the operator-facing error message to abort startup with.
pub(crate) fn validate_operator_exposure(
    bind: &str,
    require_operator_auth: bool,
) -> Result<(), String> {
    if !is_loopback_bind(bind) && !require_operator_auth {
        return Err(format!(
            "refusing to bind the operator surface to non-loopback address {bind:?} without \
             --require-operator-auth: an exposed consent port with no operator auth lets any host \
             on the network approve sessions. Re-run with --require-operator-auth (and \
             --operators-file), or bind to 127.0.0.1."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_addresses_are_recognized() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("127.0.0.5")); // whole 127/8 is loopback
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("[::1]"));
        assert!(is_loopback_bind("localhost"));
        assert!(is_loopback_bind("LocalHost"));
    }

    #[test]
    fn network_addresses_and_hostnames_are_not_loopback() {
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("192.168.1.10"));
        assert!(!is_loopback_bind("10.0.0.1"));
        assert!(!is_loopback_bind("::"));
        // A hostname we can't resolve here is treated as non-loopback.
        assert!(!is_loopback_bind("ops.example.org"));
    }

    #[test]
    fn loopback_bind_is_always_allowed() {
        assert!(validate_operator_exposure("127.0.0.1", false).is_ok());
        assert!(validate_operator_exposure("127.0.0.1", true).is_ok());
        assert!(validate_operator_exposure("localhost", false).is_ok());
    }

    #[test]
    fn non_loopback_bind_requires_operator_auth() {
        // Exposed without auth -> refused.
        assert!(validate_operator_exposure("0.0.0.0", false).is_err());
        assert!(validate_operator_exposure("192.168.1.10", false).is_err());
        // Exposed *with* auth -> allowed.
        assert!(validate_operator_exposure("0.0.0.0", true).is_ok());
    }
}
