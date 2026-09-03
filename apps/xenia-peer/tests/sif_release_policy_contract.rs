// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

// Compile the authenticated SIF release-authority policy as an isolated app
// contract before live daemon CLI/runtime wiring lands. The module's inline
// tests exercise root authentication, epoch anti-rollback, validity windows,
// threshold feasibility, canonical authority ordering, and key-role separation.
#[path = "../src/sif_release_policy.rs"]
mod sif_release_policy;

#[test]
fn sif_release_authority_policy_contract_is_linked() {
    assert!(true);
}
