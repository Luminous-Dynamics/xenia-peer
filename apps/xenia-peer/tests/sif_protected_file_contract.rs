// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

// Compile the protected-file boundary against the real daemon-local M1 authority
// and durable SIF store before any network sender is added.
#[path = "../src/m1_ledger.rs"]
mod m1_ledger;
#[path = "../src/m1_runtime.rs"]
mod m1_runtime;
#[path = "../src/sif_m1_authority.rs"]
mod sif_m1_authority;
#[path = "../src/sif_release_store.rs"]
mod sif_release_store;
#[path = "../src/sif_protected_file.rs"]
mod sif_protected_file;

#[test]
fn sif_protected_file_precommit_contract_is_linked() {
    assert!(true);
}
