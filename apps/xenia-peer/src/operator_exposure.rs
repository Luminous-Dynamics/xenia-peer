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

/// Whether a full `host:port` listen address is loopback-only.
///
/// [`is_loopback_bind`] takes a bare host (the operator surface's
/// `--operator-bind`), but the session listener's `--listen` carries a port
/// too, so it needs its own entry point rather than being passed a string
/// that would never parse as an `IpAddr`. Same fail-safe posture: anything
/// we cannot positively identify as loopback is treated as exposed.
pub(crate) fn is_loopback_listen_addr(addr: &str) -> bool {
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        return sock.ip().is_loopback();
    }
    // Not a bare socket address (e.g. `localhost:8080`, or a bracketed IPv6
    // literal we should still split). Strip the port and reuse the host check.
    let host = match addr.rfind(':') {
        // Only treat the last `:` as a port separator when it isn't part of
        // an unbracketed IPv6 literal (which has several).
        Some(idx) if addr.starts_with('[') || addr.matches(':').count() == 1 => &addr[..idx],
        _ => addr,
    };
    is_loopback_bind(host)
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
    fn listen_addresses_with_ports_are_classified() {
        // The session listener's default, and its exposed counterparts.
        assert!(is_loopback_listen_addr("127.0.0.1:8080"));
        assert!(is_loopback_listen_addr("[::1]:8080"));
        assert!(is_loopback_listen_addr("localhost:8080"));
        assert!(!is_loopback_listen_addr("0.0.0.0:8080"));
        assert!(!is_loopback_listen_addr("192.168.1.10:8080"));
        assert!(!is_loopback_listen_addr("[::]:8080"));
        // Bare hosts still work, so the two helpers can't disagree.
        assert!(is_loopback_listen_addr("127.0.0.1"));
        assert!(!is_loopback_listen_addr("0.0.0.0"));
        // An unbracketed IPv6 literal must not be mistaken for host:port and
        // silently truncated into something that parses as loopback.
        assert!(!is_loopback_listen_addr("2001:db8::1"));
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
