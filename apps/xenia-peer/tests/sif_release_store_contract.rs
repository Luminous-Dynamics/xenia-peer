// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

// Compile the release-store module as an isolated app contract before the daemon
// CLI/runtime wiring lands. This avoids leaving a security-critical persistence
// module as unchecked dead source while keeping the runtime integration in its own
// reviewable stack.
#[path = "../src/sif_release_store.rs"]
mod sif_release_store;

#[test]
fn release_store_contract_is_linked_into_tests() {
    // The module's own tests exercise genesis loading, lock exclusivity and
    // malformed-store fail-closed behavior. This marker makes the integration
    // contract explicit in `cargo test -p xenia-peer --test sif_release_store_contract`.
    assert!(true);
}
