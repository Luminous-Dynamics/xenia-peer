// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

// Compile the SIF authority adapter against the real daemon-local M1 ledger and
// runtime modules before live transport wiring lands. This makes the security
// boundary CI-visible without exposing the private M1 Chain through a new API.
#[path = "../src/m1_ledger.rs"]
mod m1_ledger;
#[path = "../src/m1_runtime.rs"]
mod m1_runtime;
#[path = "../src/sif_m1_authority.rs"]
mod sif_m1_authority;

#[test]
fn sif_m1_authority_contract_is_linked() {
    // The adapter's inline tests exercise missing-key refusal, current-Approval
    // enforcement, key mismatch refusal, and transcript/principal binding.
    assert!(true);
}
