// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trust-on-first-use (TOFU) pinning of the daemon's sealed-channel host
//! identity fingerprint.
//!
//! Both handshake suites' `finish()` return a
//! `schedule.host_identity_fingerprint` -- a BLAKE3 hash of the host's
//! signing identity -- specifically so a client can detect an active MITM
//! that substituted its own keys in `HostHello`. Until this module, nothing
//! in the console ever read that field: the handshake proved the peer we
//! finished talking to controls *some* signing identity, but never that it's
//! the *same* identity the operator has connected to before.
//!
//! The model: the first time the console completes a handshake against a
//! given `(sealed_ws_url, suite)`, it trusts and pins the fingerprint it
//! sees (TOFU). Every later connection to that same endpoint+suite must
//! present the identical fingerprint, or the connection is refused *before*
//! any consent payload is sent -- a changed fingerprint means either the
//! daemon's identity key was legitimately rotated (operator action required:
//! [`forget`]) or a MITM is presenting a different key.

use web_sys::Storage;

const STORAGE_PREFIX: &str = "xenia-admin.host-fingerprint";

/// Outcome of a successful pin check -- both are "proceed", but
/// [`PinOutcome::FirstConnection`] is worth surfacing to the operator since
/// it's the one point where an active MITM present from the very first
/// connection would go undetected (TOFU's inherent limitation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// No fingerprint was pinned for this endpoint+suite yet; this one is
    /// now trusted and stored.
    FirstConnection,
    /// The presented fingerprint matches the previously-pinned one.
    Matched,
}

/// The channel must be refused: the presented fingerprint does not match
/// what was previously pinned for this endpoint+suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinMismatch {
    pub expected: [u8; 32],
    pub presented: [u8; 32],
}

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host identity fingerprint changed: expected {}, got {} -- refusing the channel \
             (legitimate key rotation requires the operator to explicitly forget the old pin)",
            hex::encode(self.expected),
            hex::encode(self.presented)
        )
    }
}

/// The storage key for a given sealed-channel endpoint + suite. Exposed so
/// callers (e.g. a "forget this host" UI action) can address the same pin
/// without duplicating the format.
pub fn storage_key(sealed_ws_url: &str, suite: &str) -> String {
    format!("{STORAGE_PREFIX}.{suite}.{sealed_ws_url}")
}

/// Check `fingerprint` (from a just-completed handshake) against the pin
/// stored under `key`. On first use, pins and returns
/// [`PinOutcome::FirstConnection`]. On a match, returns
/// [`PinOutcome::Matched`]. On a mismatch, pins nothing and returns
/// [`PinMismatch`] -- the caller must refuse the channel (not send any
/// payload over it) rather than proceed.
pub fn verify_or_pin(key: &str, fingerprint: [u8; 32]) -> Result<PinOutcome, PinMismatch> {
    match load_pin(key) {
        None => {
            store_pin(key, fingerprint);
            Ok(PinOutcome::FirstConnection)
        }
        Some(expected) if expected == fingerprint => Ok(PinOutcome::Matched),
        Some(expected) => Err(PinMismatch {
            expected,
            presented: fingerprint,
        }),
    }
}

/// Clear a pinned fingerprint so the next connection re-pins via TOFU --
/// the operator's explicit path for a legitimate daemon identity rotation.
pub fn forget(key: &str) {
    if let Some(storage) = local_storage() {
        let _ = storage.remove_item(key);
    }
}

fn load_pin(key: &str) -> Option<[u8; 32]> {
    let hex_str = local_storage()?.get_item(key).ok().flatten()?;
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

fn store_pin(key: &str, fingerprint: [u8; 32]) {
    if let Some(storage) = local_storage() {
        let _ = storage.set_item(key, &hex::encode(fingerprint));
    }
}

fn local_storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the pure decode/encode + comparison logic without a
    // `window()` (unavailable outside wasm32); the storage round-trip itself
    // is covered by `wasm-bindgen-test` in the browser test suite, not here.

    #[test]
    fn mismatch_display_is_human_readable_and_names_both_fingerprints() {
        let mismatch = PinMismatch {
            expected: [0xAA; 32],
            presented: [0xBB; 32],
        };
        let msg = mismatch.to_string();
        assert!(msg.contains(&hex::encode([0xAAu8; 32])));
        assert!(msg.contains(&hex::encode([0xBBu8; 32])));
        assert!(msg.contains("refusing"));
    }

    #[test]
    fn storage_key_is_scoped_by_both_endpoint_and_suite() {
        let standard = storage_key("ws://127.0.0.1:8083", "standard");
        let highsec = storage_key("ws://127.0.0.1:8083", "highsec");
        let other_host = storage_key("ws://127.0.0.1:9000", "standard");
        assert_ne!(standard, highsec);
        assert_ne!(standard, other_host);
    }
}
