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
//! present the identical fingerprint, or the connection is refused -- the
//! console sends the handshake's own `ViewerResponse` regardless (that's
//! how a handshake works), but never seals or sends any consent payload --
//! a changed fingerprint means either the daemon's identity key was
//! legitimately rotated (operator action required: [`forget`]) or a MITM is
//! presenting a different key.
//!
//! ## Fail-closed storage
//!
//! `localStorage` can be unavailable (private browsing, a restrictive
//! browser policy), fail on write (quota), or hold a corrupted value (a
//! prior partial write, manual tampering). A naive implementation that
//! treats "couldn't read a pin" the same as "no pin exists yet" would
//! silently degrade real persistent pinning into TOFU-on-every-connection --
//! passing the same first-connection review process yourself, quietly,
//! every single time, on affected browsers. [`verify_or_pin`] instead
//! distinguishes a genuine absent pin ([`PinError`]'s absence) from a
//! storage failure ([`PinError`]'s presence) and fails closed on the
//! latter -- see [`PinCheckError::Storage`].
//!
//! The storage access itself lives behind the [`PinStore`] trait so the
//! decision logic in [`verify_or_pin`]/[`forget`] is unit-testable natively
//! (an in-memory mock `PinStore`) without needing a real `window()` or a
//! browser test harness -- see this module's tests for the exact scenarios
//! (mismatch, corrupt pin, write failure, forget) exercised this way. The
//! `web_sys::Storage`-backed implementation is thin, untested glue for
//! exactly that reason -- the same boundary `config.rs`'s `local_storage()`
//! wrapper draws.

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

/// A storage-layer failure. Distinguished from "no pin exists yet" so a
/// caller can fail closed instead of silently re-trusting on every
/// connection -- see the module doc comment's "Fail-closed storage" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// The underlying storage (e.g. `localStorage`) could not be reached at
    /// all -- private browsing, a restrictive browser policy, or no
    /// `window()`.
    StorageUnavailable,
    /// A stored pin exists but isn't valid 32-byte hex -- a prior partial
    /// write or manual tampering. Never treated as "no pin."
    CorruptPin,
    /// Storage was reachable but the write failed (e.g. quota exceeded).
    WriteFailed,
    /// Storage was reachable but removing the pin failed.
    RemoveFailed,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PinError::StorageUnavailable => "host-fingerprint storage is unavailable",
            PinError::CorruptPin => "stored host fingerprint is corrupt",
            PinError::WriteFailed => "failed to persist the host fingerprint pin",
            PinError::RemoveFailed => "failed to remove the host fingerprint pin",
        };
        f.write_str(s)
    }
}

/// Why [`verify_or_pin`] refused to let the caller proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheckError {
    /// The storage layer itself failed -- fail closed rather than treat this
    /// as "no pin yet."
    Storage(PinError),
    /// The presented fingerprint doesn't match the pinned one.
    Mismatch(PinMismatch),
}

impl std::fmt::Display for PinCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinCheckError::Storage(e) => write!(f, "{e} -- refusing the channel"),
            PinCheckError::Mismatch(m) => write!(f, "{m}"),
        }
    }
}

/// A minimal key-value store abstraction over pin storage, so the decision
/// logic in [`verify_or_pin`]/[`forget`] can be tested with an in-memory
/// mock instead of needing a real browser `window()`. Implemented for
/// production by [`LocalStoragePinStore`].
trait PinStore {
    /// The stored hex string for `key`, or `None` if nothing is stored.
    /// `Err` means storage itself failed (not "no value").
    fn get(&self, key: &str) -> Result<Option<String>, PinError>;
    /// Store `value` (hex) under `key`.
    fn set(&mut self, key: &str, value: &str) -> Result<(), PinError>;
    /// Remove whatever is stored under `key`, if anything.
    fn remove(&mut self, key: &str) -> Result<(), PinError>;
}

/// The storage key for a given sealed-channel endpoint + suite. Exposed so
/// callers (e.g. a "forget this host" UI action) can address the same pin
/// without duplicating the format.
pub fn storage_key(sealed_ws_url: &str, suite: &str) -> String {
    format!("{STORAGE_PREFIX}.{suite}.{sealed_ws_url}")
}

/// Check `fingerprint` (from a just-completed handshake) against the pin
/// stored under `key` in `localStorage`. On first use, pins and returns
/// [`PinOutcome::FirstConnection`]. On a match, returns
/// [`PinOutcome::Matched`]. On a mismatch or any storage failure, pins
/// nothing (on mismatch) or leaves the existing pin untouched (on storage
/// failure) and returns an error -- the caller must refuse the channel (not
/// send any payload over it) rather than proceed.
pub fn verify_or_pin(key: &str, fingerprint: [u8; 32]) -> Result<PinOutcome, PinCheckError> {
    verify_or_pin_with(&mut LocalStoragePinStore, key, fingerprint)
}

/// Clear a pinned fingerprint so the next connection re-pins via TOFU --
/// the operator's explicit path for a legitimate daemon identity rotation.
pub fn forget(key: &str) -> Result<(), PinError> {
    forget_with(&mut LocalStoragePinStore, key)
}

/// The actual decision logic, generic over the storage backend so it's
/// testable without a browser. See [`verify_or_pin`] for the public API.
fn verify_or_pin_with(
    store: &mut impl PinStore,
    key: &str,
    fingerprint: [u8; 32],
) -> Result<PinOutcome, PinCheckError> {
    match store.get(key).map_err(PinCheckError::Storage)? {
        None => {
            store
                .set(key, &hex::encode(fingerprint))
                .map_err(PinCheckError::Storage)?;
            Ok(PinOutcome::FirstConnection)
        }
        Some(hex_str) => {
            let bytes =
                hex::decode(&hex_str).map_err(|_| PinCheckError::Storage(PinError::CorruptPin))?;
            let expected: [u8; 32] = bytes
                .try_into()
                .map_err(|_| PinCheckError::Storage(PinError::CorruptPin))?;
            if expected == fingerprint {
                Ok(PinOutcome::Matched)
            } else {
                Err(PinCheckError::Mismatch(PinMismatch {
                    expected,
                    presented: fingerprint,
                }))
            }
        }
    }
}

fn forget_with(store: &mut impl PinStore, key: &str) -> Result<(), PinError> {
    store.remove(key)
}

/// Production [`PinStore`]: `web_sys::window().local_storage()`.
struct LocalStoragePinStore;

impl PinStore for LocalStoragePinStore {
    fn get(&self, key: &str) -> Result<Option<String>, PinError> {
        local_storage()?
            .get_item(key)
            .map_err(|_| PinError::StorageUnavailable)
    }

    fn set(&mut self, key: &str, value: &str) -> Result<(), PinError> {
        local_storage()?
            .set_item(key, value)
            .map_err(|_| PinError::WriteFailed)
    }

    fn remove(&mut self, key: &str) -> Result<(), PinError> {
        local_storage()?
            .remove_item(key)
            .map_err(|_| PinError::RemoveFailed)
    }
}

fn local_storage() -> Result<web_sys::Storage, PinError> {
    web_sys::window()
        .ok_or(PinError::StorageUnavailable)?
        .local_storage()
        .map_err(|_| PinError::StorageUnavailable)?
        .ok_or(PinError::StorageUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory `PinStore` for testing the decision logic without a real
    /// `window()`. Can be told to fail on the next `set`/`remove` call, or to
    /// hold a pre-corrupted value, to exercise the fail-closed paths.
    #[derive(Default)]
    struct MockStore {
        values: HashMap<String, String>,
        fail_next_set: bool,
        fail_next_remove: bool,
        fail_get: bool,
    }

    impl PinStore for MockStore {
        fn get(&self, key: &str) -> Result<Option<String>, PinError> {
            if self.fail_get {
                return Err(PinError::StorageUnavailable);
            }
            Ok(self.values.get(key).cloned())
        }

        fn set(&mut self, key: &str, value: &str) -> Result<(), PinError> {
            if self.fail_next_set {
                return Err(PinError::WriteFailed);
            }
            self.values.insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn remove(&mut self, key: &str) -> Result<(), PinError> {
            if self.fail_next_remove {
                return Err(PinError::RemoveFailed);
            }
            self.values.remove(key);
            Ok(())
        }
    }

    const KEY: &str = "test-key";
    const FP_A: [u8; 32] = [0xAA; 32];
    const FP_B: [u8; 32] = [0xBB; 32];

    #[test]
    fn first_connection_persists_the_pin() {
        let mut store = MockStore::default();
        assert_eq!(
            verify_or_pin_with(&mut store, KEY, FP_A),
            Ok(PinOutcome::FirstConnection)
        );
        assert_eq!(store.values.get(KEY), Some(&hex::encode(FP_A)));
    }

    #[test]
    fn second_matching_connection_succeeds() {
        let mut store = MockStore::default();
        verify_or_pin_with(&mut store, KEY, FP_A).unwrap();
        assert_eq!(
            verify_or_pin_with(&mut store, KEY, FP_A),
            Ok(PinOutcome::Matched)
        );
    }

    #[test]
    fn mismatch_refuses_and_preserves_the_old_pin() {
        let mut store = MockStore::default();
        verify_or_pin_with(&mut store, KEY, FP_A).unwrap();
        let result = verify_or_pin_with(&mut store, KEY, FP_B);
        assert_eq!(
            result,
            Err(PinCheckError::Mismatch(PinMismatch {
                expected: FP_A,
                presented: FP_B
            }))
        );
        // The old pin is untouched -- a mismatch never overwrites.
        assert_eq!(store.values.get(KEY), Some(&hex::encode(FP_A)));
    }

    #[test]
    fn malformed_stored_pin_refuses_fail_closed() {
        let mut store = MockStore::default();
        store
            .values
            .insert(KEY.to_string(), "not-valid-hex".to_string());
        assert_eq!(
            verify_or_pin_with(&mut store, KEY, FP_A),
            Err(PinCheckError::Storage(PinError::CorruptPin))
        );
    }

    #[test]
    fn wrong_length_stored_pin_refuses_fail_closed() {
        let mut store = MockStore::default();
        // Valid hex, wrong length (16 bytes, not 32).
        store.values.insert(KEY.to_string(), hex::encode([0u8; 16]));
        assert_eq!(
            verify_or_pin_with(&mut store, KEY, FP_A),
            Err(PinCheckError::Storage(PinError::CorruptPin))
        );
    }

    #[test]
    fn read_failure_refuses_fail_closed_rather_than_re_pinning() {
        let mut store = MockStore {
            fail_get: true,
            ..Default::default()
        };
        // If a read failure were treated as "no pin," this would silently
        // succeed as FirstConnection every time -- exactly the bug being
        // fixed.
        assert_eq!(
            verify_or_pin_with(&mut store, KEY, FP_A),
            Err(PinCheckError::Storage(PinError::StorageUnavailable))
        );
    }

    #[test]
    fn write_failure_on_first_connection_refuses_fail_closed() {
        let mut store = MockStore {
            fail_next_set: true,
            ..Default::default()
        };
        assert_eq!(
            verify_or_pin_with(&mut store, KEY, FP_A),
            Err(PinCheckError::Storage(PinError::WriteFailed))
        );
        // Nothing was actually pinned.
        assert!(store.values.is_empty());
    }

    #[test]
    fn forget_actually_removes_the_pin() {
        let mut store = MockStore::default();
        verify_or_pin_with(&mut store, KEY, FP_A).unwrap();
        assert!(store.values.contains_key(KEY));
        forget_with(&mut store, KEY).unwrap();
        assert!(!store.values.contains_key(KEY));
        // A subsequent connection is treated as first-use again.
        assert_eq!(
            verify_or_pin_with(&mut store, KEY, FP_B),
            Ok(PinOutcome::FirstConnection)
        );
    }

    #[test]
    fn forget_failure_is_reported_not_silently_swallowed() {
        let mut store = MockStore {
            fail_next_remove: true,
            ..Default::default()
        };
        assert_eq!(forget_with(&mut store, KEY), Err(PinError::RemoveFailed));
    }

    #[test]
    fn standard_and_highsec_suite_pins_are_independent() {
        let mut store = MockStore::default();
        let standard_key = storage_key("ws://127.0.0.1:8083", "standard");
        let highsec_key = storage_key("ws://127.0.0.1:8083", "highsec");
        verify_or_pin_with(&mut store, &standard_key, FP_A).unwrap();
        // A different suite's pin doesn't exist yet even though the
        // endpoint is identical -- also FirstConnection, not a mismatch.
        assert_eq!(
            verify_or_pin_with(&mut store, &highsec_key, FP_B),
            Ok(PinOutcome::FirstConnection)
        );
        // And the two pins really did land under different keys.
        assert_eq!(store.values.get(&standard_key), Some(&hex::encode(FP_A)));
        assert_eq!(store.values.get(&highsec_key), Some(&hex::encode(FP_B)));
    }

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
