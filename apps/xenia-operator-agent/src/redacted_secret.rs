// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A secret value that zeroizes its backing memory on drop *and* never
//! reveals its contents through `{:?}`.
//!
//! `Zeroizing<T>` (used elsewhere in this crate for the Ed25519/ML-DSA
//! identity seeds) only guarantees the first half -- its `Debug` impl still
//! forwards to `T`'s, so a stray `tracing::debug!(?state, ...)`, a derived
//! `Debug` on a containing struct, or a panic message that happens to
//! include the value would still print it in full. [`RedactedSecret`] wraps
//! `Zeroizing` and overrides `Debug` to print a fixed placeholder instead.
//!
//! Reading the real value requires the explicit [`RedactedSecret::expose_secret`]
//! call (deliberately not `Deref`) so every genuine use is grep-able and
//! nothing reaches for the raw bytes/string by accident via autoderef.

use zeroize::{Zeroize, Zeroizing};

pub(crate) struct RedactedSecret<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> RedactedSecret<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The real value. Every call site is a deliberate, auditable exception
    /// to the redaction below -- name it explicitly rather than routing
    /// through `Deref`.
    pub(crate) fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> std::fmt::Debug for RedactedSecret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactedSecret(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_secret() {
        let secret = RedactedSecret::new(String::from("super-secret-pairing-token"));
        let printed = format!("{secret:?}");
        assert!(!printed.contains("super-secret-pairing-token"));
        assert_eq!(printed, "RedactedSecret(..)");
    }

    #[test]
    fn expose_secret_returns_the_real_value() {
        let secret = RedactedSecret::new([7u8; 32]);
        assert_eq!(secret.expose_secret(), &[7u8; 32]);
    }
}
