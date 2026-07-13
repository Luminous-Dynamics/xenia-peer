// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native host-trust policy (`docs/security/SIGNER_DELEGATION_DESIGN.md`).
//!
//! Typed signing requests stop the agent from being tricked into signing
//! bytes it doesn't understand, but not from being tricked into faithfully
//! authenticating to the *wrong* daemon -- a compromised browser can submit
//! a perfectly well-formed request naming an attacker-controlled host, and
//! the agent would sign it correctly. This module is the fix: the agent
//! pins a daemon's identity fingerprint per `(host_alias, suite)` in its
//! own file (not anything the browser can see or influence), and requires
//! a **native** confirmation -- shown from fields *this process* parsed,
//! never browser-supplied text -- on first use of a host or when a
//! fingerprint changes. Browser-side TOFU pinning (`sovereign-admin`'s
//! `host_pin.rs`, from the hardening pass) stays as defense in depth, but
//! is no longer the authoritative check once the agent performs the
//! signing/handshake itself.
//!
//! Wired into `POST /v1/sign/challenge` (step 2), `POST
//! /v1/sign/consent-action` (step 3), and `POST /v1/sign/revoke` (step 4,
//! via [`HostTrustStore::confirm_action`] -- the first endpoint that
//! actually exercises the mandatory-confirmation path for an *action*,
//! not just a host identity) of the recommended PR sequence;
//! `/v1/handshake/*` lands in a later PR and calls into this module too.
//!
//! ## Confirmation UI (v1 scope)
//!
//! The only confirmation surface implemented here is a blocking prompt on
//! this process's own stdin/stdout. There is no GUI or desktop-notification
//! confirmation yet -- a real UX gap for a long-running headless agent, but
//! out of scope for this foundational step (see the design doc). When no
//! interactive terminal is available, a privileged confirmation fails
//! closed **unless** the operator explicitly opted in via
//! `allow_noninteractive_privileged` -- there is no silent fallback to
//! "trust it anyway" or "let the browser decide instead."
//!
//! [`confirm`] is a *blocking* call. A future caller wiring this into an
//! async axum handler should run it via `tokio::task::spawn_blocking`
//! rather than await it directly on the runtime's worker threads.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::secure_file;

/// Why a host-trust check refused to proceed.
#[derive(Debug)]
pub enum HostTrustError {
    /// A previously-pinned fingerprint doesn't match the one just
    /// presented, and rotating the pin wasn't confirmed.
    FingerprintChanged {
        host_alias: String,
        pinned_hex: String,
        presented_hex: String,
    },
    /// First use of this host, and trusting it wasn't confirmed.
    NotConfirmed { host_alias: String },
    /// A confirmation was required but no interactive terminal was
    /// available and noninteractive privileged confirmation isn't enabled.
    ConfirmationUnavailable { reason: String },
    /// The pin-store file couldn't be read, parsed, or written.
    Storage(String),
}

impl std::fmt::Display for HostTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostTrustError::FingerprintChanged {
                host_alias,
                pinned_hex,
                presented_hex,
            } => write!(
                f,
                "host '{host_alias}' presented a different identity fingerprint \
                 (pinned {pinned_hex}, presented {presented_hex}) and the change was not confirmed"
            ),
            HostTrustError::NotConfirmed { host_alias } => {
                write!(
                    f,
                    "trusting host '{host_alias}' for the first time was not confirmed"
                )
            }
            HostTrustError::ConfirmationUnavailable { reason } => {
                write!(f, "confirmation required but unavailable: {reason}")
            }
            HostTrustError::Storage(e) => write!(f, "host-trust pin store error: {e}"),
        }
    }
}

impl std::error::Error for HostTrustError {}

impl HostTrustError {
    /// Convert to the typed error shape the future `/v1/sign/*` /
    /// `/v1/handshake/*` endpoints return (`xenia_operator_agent_proto`),
    /// so the console gets an accurate, stable error code instead of a
    /// bare HTTP status.
    pub fn to_agent_error(&self) -> xenia_operator_agent_proto::AgentErrorResponse {
        use xenia_operator_agent_proto::AgentErrorCode;
        let code = match self {
            HostTrustError::FingerprintChanged { .. } | HostTrustError::NotConfirmed { .. } => {
                AgentErrorCode::HostNotTrusted
            }
            HostTrustError::ConfirmationUnavailable { .. } => AgentErrorCode::ConfirmationRequired,
            HostTrustError::Storage(_) => AgentErrorCode::Internal,
        };
        xenia_operator_agent_proto::AgentErrorResponse {
            code,
            message: self.to_string(),
        }
    }
}

/// What happened when a fingerprint was checked against the pin store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// Already pinned and matched -- no change made.
    Matched,
    /// Not previously pinned; confirmed and now pinned.
    TrustedOnFirstUse,
    /// A different fingerprint was previously pinned; confirmed and the
    /// pin was rotated.
    Rotated,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PinFile {
    /// key: `"{host_alias}:{suite}"` -> fingerprint, hex.
    pins: HashMap<String, String>,
}

/// The native host-trust pin store: one process-local file, one entry per
/// `(host_alias, suite)`.
pub struct HostTrustStore {
    path: PathBuf,
    pins: HashMap<String, [u8; 32]>,
    /// Whether a privileged (mandatory-confirmation) check may proceed
    /// without an interactive confirmation if no terminal is available.
    /// Off by default -- must be explicitly enabled by the operator
    /// (`--allow-noninteractive-privileged-confirmation`); silently
    /// defaulting this on would reopen exactly the oracle problem native
    /// confirmation exists to close.
    allow_noninteractive_privileged: bool,
}

impl HostTrustStore {
    /// Load the pin store from `path` (created empty if it doesn't exist
    /// yet -- unlike the identity/token files, there's no fixed content to
    /// generate; pins accrue over time as hosts are trusted).
    pub fn load(
        path: PathBuf,
        allow_noninteractive_privileged: bool,
    ) -> Result<Self, HostTrustError> {
        let pins = match secure_file::read_secure_file_if_exists(&path)
            .map_err(|e| HostTrustError::Storage(e.to_string()))?
        {
            None => HashMap::new(),
            Some(bytes) => {
                let file: PinFile = serde_json::from_slice(&bytes)
                    .map_err(|e| HostTrustError::Storage(format!("malformed pin store: {e}")))?;
                file.pins
                    .into_iter()
                    .filter_map(|(k, v)| {
                        let bytes = hex::decode(&v).ok()?;
                        let arr: [u8; 32] = bytes.try_into().ok()?;
                        Some((k, arr))
                    })
                    .collect()
            }
        };
        Ok(Self {
            path,
            pins,
            allow_noninteractive_privileged,
        })
    }

    fn key(host_alias: &str, suite: &str) -> String {
        format!("{host_alias}:{suite}")
    }

    /// Look up the pinned fingerprint for `(host_alias, suite)`, if any --
    /// read-only, no confirmation, no mutation. Useful for a caller
    /// deciding whether it even needs to go through [`Self::check`]'s
    /// confirmation path (e.g. to skip prompting for an action that's
    /// low-risk *and* already-pinned, per the confirmation policy's
    /// no-confirmation-required list).
    ///
    /// Not called from any endpoint yet -- `/v1/sign/challenge` always
    /// goes through [`Self::check`], which subsumes this. A later step may
    /// use it to short-circuit an already-trusted, no-confirmation-needed
    /// action before touching the blocking `check` path at all.
    #[allow(dead_code)]
    pub fn lookup(&self, host_alias: &str, suite: &str) -> Option<[u8; 32]> {
        self.pins.get(&Self::key(host_alias, suite)).copied()
    }

    /// Check `fingerprint` for `(host_alias, suite)` against the pin
    /// store. Already-pinned-and-matching succeeds with no confirmation.
    /// Otherwise (first use, or a changed fingerprint) blocks on a native
    /// terminal confirmation showing exactly `host_alias`, `suite`, and
    /// the fingerprint(s) involved -- generated from these parameters, not
    /// from anything the caller supplies as free text.
    pub fn check(
        &mut self,
        host_alias: &str,
        suite: &str,
        fingerprint: [u8; 32],
    ) -> Result<PinOutcome, HostTrustError> {
        let key = Self::key(host_alias, suite);
        match self.pins.get(&key).copied() {
            Some(pinned) if pinned == fingerprint => Ok(PinOutcome::Matched),
            Some(pinned) => {
                let confirmed = confirm(
                    self.allow_noninteractive_privileged,
                    "Daemon identity changed",
                    &[
                        ("host", host_alias.to_string()),
                        ("suite", suite.to_string()),
                        ("previously pinned fingerprint", hex::encode(pinned)),
                        ("newly presented fingerprint", hex::encode(fingerprint)),
                        (
                            "meaning",
                            "either the daemon's key was legitimately rotated, or this is an \
                             impersonation attempt"
                                .to_string(),
                        ),
                    ],
                )?;
                if !confirmed {
                    return Err(HostTrustError::FingerprintChanged {
                        host_alias: host_alias.to_string(),
                        pinned_hex: hex::encode(pinned),
                        presented_hex: hex::encode(fingerprint),
                    });
                }
                self.set_pin(&key, fingerprint)?;
                Ok(PinOutcome::Rotated)
            }
            None => {
                let confirmed = confirm(
                    self.allow_noninteractive_privileged,
                    "Trust this host for the first time?",
                    &[
                        ("host", host_alias.to_string()),
                        ("suite", suite.to_string()),
                        ("fingerprint", hex::encode(fingerprint)),
                    ],
                )?;
                if !confirmed {
                    return Err(HostTrustError::NotConfirmed {
                        host_alias: host_alias.to_string(),
                    });
                }
                self.set_pin(&key, fingerprint)?;
                Ok(PinOutcome::TrustedOnFirstUse)
            }
        }
    }

    /// Explicitly forget a pin (the operator's path for a legitimate
    /// rotation without going through the interactive confirmation flow --
    /// e.g. from a future admin CLI subcommand). Not called from any
    /// endpoint yet.
    #[allow(dead_code)]
    pub fn forget(&mut self, host_alias: &str, suite: &str) -> Result<(), HostTrustError> {
        let key = Self::key(host_alias, suite);
        self.pins.remove(&key);
        self.persist()
    }

    /// Block on a native confirmation for an *action*-specific
    /// mandatory-confirmation case (e.g. operator revocation), as opposed
    /// to [`Self::check`]'s *host-identity* confirmation. Reuses the same
    /// `allow_noninteractive_privileged` policy and prompt mechanism, so
    /// there's exactly one confirmation UI/policy in the whole agent
    /// rather than a second one growing alongside it.
    pub fn confirm_action(
        &self,
        title: &str,
        fields: &[(&str, String)],
    ) -> Result<bool, HostTrustError> {
        confirm(self.allow_noninteractive_privileged, title, fields)
    }

    fn set_pin(&mut self, key: &str, fingerprint: [u8; 32]) -> Result<(), HostTrustError> {
        self.pins.insert(key.to_string(), fingerprint);
        self.persist()
    }

    fn persist(&self) -> Result<(), HostTrustError> {
        let file = PinFile {
            pins: self
                .pins
                .iter()
                .map(|(k, v)| (k.clone(), hex::encode(v)))
                .collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|e| HostTrustError::Storage(e.to_string()))?;
        secure_file::secure_overwrite(&self.path, &bytes)
            .map_err(|e| HostTrustError::Storage(e.to_string()))
    }
}

/// Block on a native terminal confirmation, showing `title` and `fields`
/// (already-formatted key/value pairs -- callers build these from typed
/// data they parsed themselves, never from raw browser input). Returns
/// `Ok(true)` only if the operator explicitly typed "yes". Fails with
/// [`HostTrustError::ConfirmationUnavailable`] if there's no interactive
/// terminal and `allow_noninteractive_privileged` is `false`; if it's
/// `true`, a noninteractive environment is treated as an explicit,
/// pre-authorized "yes" (the operator opted into this at agent startup,
/// not per-request).
///
/// Exposed at crate visibility (not just this module's) so the future
/// action-confirmation paths (revoke, enrollment, ...) can reuse the same
/// prompt mechanism instead of growing a second one.
pub(crate) fn confirm(
    allow_noninteractive_privileged: bool,
    title: &str,
    fields: &[(&str, String)],
) -> Result<bool, HostTrustError> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return if allow_noninteractive_privileged {
            tracing::warn!(
                title,
                "no interactive terminal available; proceeding because \
                 --allow-noninteractive-privileged-confirmation is set"
            );
            Ok(true)
        } else {
            Err(HostTrustError::ConfirmationUnavailable {
                reason: "no interactive terminal available".to_string(),
            })
        };
    }

    println!();
    println!("=== xenia-operator-agent: confirmation required ===");
    println!("{title}");
    for (k, v) in fields {
        println!("  {k}: {v}");
    }
    print!("Type 'yes' to confirm, anything else to refuse: ");
    use std::io::Write;
    std::io::stdout()
        .flush()
        .map_err(|e| HostTrustError::Storage(e.to_string()))?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| HostTrustError::Storage(e.to_string()))?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-agent-host-trust-test-{label}-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("pins.json")
    }

    // These exercise the pin-storage logic with `allow_noninteractive_privileged:
    // true`, which -- in a non-interactive `cargo test` environment -- makes
    // `confirm()` return `Ok(true)` immediately without touching stdin, so
    // `check()`'s confirmation branches are exercised deterministically.
    // Genuine interactive confirmation (a real terminal, an operator typing
    // "yes"/anything else) is not covered by unit tests; it's a thin,
    // deliberately simple wrapper around stdin/stdout with no logic beyond
    // the string comparison covered by nothing-fancy manual testing.

    #[test]
    fn first_use_is_trusted_on_first_use_and_persisted() {
        let path = temp_path("first-use");
        let fp = [7u8; 32];
        {
            let mut store = HostTrustStore::load(path.clone(), true).unwrap();
            assert_eq!(store.lookup("daemon-a", "standard"), None);
            let outcome = store.check("daemon-a", "standard", fp).unwrap();
            assert_eq!(outcome, PinOutcome::TrustedOnFirstUse);
        }
        // Reload from disk: the pin survives.
        let store2 = HostTrustStore::load(path.clone(), true).unwrap();
        assert_eq!(store2.lookup("daemon-a", "standard"), Some(fp));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn matching_fingerprint_is_matched_with_no_change() {
        let path = temp_path("matching");
        let fp = [3u8; 32];
        let mut store = HostTrustStore::load(path.clone(), true).unwrap();
        store.check("daemon-b", "highsec", fp).unwrap();
        let outcome = store.check("daemon-b", "highsec", fp).unwrap();
        assert_eq!(outcome, PinOutcome::Matched);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn changed_fingerprint_is_rotated_when_confirmed() {
        let path = temp_path("rotate");
        let mut store = HostTrustStore::load(path.clone(), true).unwrap();
        store.check("daemon-c", "standard", [1u8; 32]).unwrap();
        let outcome = store.check("daemon-c", "standard", [2u8; 32]).unwrap();
        assert_eq!(outcome, PinOutcome::Rotated);
        assert_eq!(store.lookup("daemon-c", "standard"), Some([2u8; 32]));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn confirmation_unavailable_when_noninteractive_and_not_opted_in() {
        let path = temp_path("no-confirm");
        let mut store = HostTrustStore::load(path.clone(), false).unwrap();
        let err = store.check("daemon-d", "standard", [9u8; 32]).unwrap_err();
        assert!(matches!(
            err,
            HostTrustError::ConfirmationUnavailable { .. }
        ));
        // Nothing was pinned.
        assert_eq!(store.lookup("daemon-d", "standard"), None);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn forget_removes_a_pin() {
        let path = temp_path("forget");
        let mut store = HostTrustStore::load(path.clone(), true).unwrap();
        store.check("daemon-e", "standard", [5u8; 32]).unwrap();
        assert!(store.lookup("daemon-e", "standard").is_some());
        store.forget("daemon-e", "standard").unwrap();
        assert_eq!(store.lookup("daemon-e", "standard"), None);
        // Persisted: reload confirms.
        let store2 = HostTrustStore::load(path.clone(), true).unwrap();
        assert_eq!(store2.lookup("daemon-e", "standard"), None);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn standard_and_highsec_suites_are_independent_pins() {
        let path = temp_path("suites");
        let mut store = HostTrustStore::load(path.clone(), true).unwrap();
        store.check("daemon-f", "standard", [1u8; 32]).unwrap();
        store.check("daemon-f", "highsec", [2u8; 32]).unwrap();
        assert_eq!(store.lookup("daemon-f", "standard"), Some([1u8; 32]));
        assert_eq!(store.lookup("daemon-f", "highsec"), Some([2u8; 32]));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn errors_convert_to_the_typed_agent_error_shape() {
        use xenia_operator_agent_proto::AgentErrorCode;

        let not_confirmed = HostTrustError::NotConfirmed {
            host_alias: "daemon-g".to_string(),
        };
        assert_eq!(
            not_confirmed.to_agent_error().code,
            AgentErrorCode::HostNotTrusted
        );

        let changed = HostTrustError::FingerprintChanged {
            host_alias: "daemon-g".to_string(),
            pinned_hex: "aa".repeat(32),
            presented_hex: "bb".repeat(32),
        };
        assert_eq!(
            changed.to_agent_error().code,
            AgentErrorCode::HostNotTrusted
        );

        let unavailable = HostTrustError::ConfirmationUnavailable {
            reason: "no tty".to_string(),
        };
        assert_eq!(
            unavailable.to_agent_error().code,
            AgentErrorCode::ConfirmationRequired
        );
    }

    #[test]
    fn confirm_action_respects_the_store_s_noninteractive_policy() {
        let allowed_path = temp_path("confirm-action-allowed");
        let allowed = HostTrustStore::load(allowed_path.clone(), true).unwrap();
        assert!(allowed
            .confirm_action("Revoke?", &[("target", "op-1".to_string())])
            .unwrap());
        std::fs::remove_dir_all(allowed_path.parent().unwrap()).ok();

        let blocked_path = temp_path("confirm-action-blocked");
        let blocked = HostTrustStore::load(blocked_path.clone(), false).unwrap();
        let err = blocked
            .confirm_action("Revoke?", &[("target", "op-1".to_string())])
            .unwrap_err();
        assert!(matches!(
            err,
            HostTrustError::ConfirmationUnavailable { .. }
        ));
        std::fs::remove_dir_all(blocked_path.parent().unwrap()).ok();
    }
}
