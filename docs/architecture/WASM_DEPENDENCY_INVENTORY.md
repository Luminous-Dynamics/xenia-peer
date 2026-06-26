# WASM Dependency Inventory

Status: post-RC1 planning inventory.

This document records the dependency classes that currently block simple wasm32-unknown-unknown checks for selected Xenia crates.

## Context

The PQC/WASM feasibility work found that the first WASM blockers are randomness-related, not screen capture, input injection, filesystem, or native transport assumptions.

Observed blocker classes:

- getrandom 0.2.17
- getrandom 0.4.2
- uuid 1.23.1

## Inventory commands

Because multiple getrandom versions are present, use version-qualified Cargo package names.

Suggested commands:

    cargo tree -p xenia-handshake --target wasm32-unknown-unknown -i getrandom@0.2.17
    cargo tree -p xenia-handshake --target wasm32-unknown-unknown -i getrandom@0.4.2

    cargo tree -p xenia-ledger --target wasm32-unknown-unknown -i uuid@1.23.1
    cargo tree -p xenia-ledger --target wasm32-unknown-unknown -i getrandom@0.2.17
    cargo tree -p xenia-ledger --target wasm32-unknown-unknown -i getrandom@0.4.2

    cargo tree -p xenia-peer-core --target wasm32-unknown-unknown -i getrandom@0.2.17
    cargo tree -p xenia-peer-core --target wasm32-unknown-unknown -i getrandom@0.4.2

## Known observed results

### xenia-handshake

Observed wasm32 check failure:

- failed in getrandom 0.2
- blocker class: browser/WASM randomness feature not configured

Interpretation:

Handshake WASM feasibility depends first on explicit randomness policy and feature boundaries.

### xenia-ledger

Observed wasm32 check failure:

- failed in uuid
- uuid requires an explicit randomness source on wasm32-unknown-unknown

Interpretation:

Ledger WASM feasibility may be improved by avoiding random UUID generation in protocol-critical paths, isolating random constructors, or adding target-specific feature configuration after policy review.

### xenia-peer-core

Observed wasm32 check failure:

- failed in getrandom 0.4
- blocker class: browser/WASM randomness feature not configured

Interpretation:

Peer-core likely mixes protocol-level types and runtime dependencies. It may need a protocol/runtime split before broad WASM compatibility is realistic.

## Recommended next technical target

Do not try to make all crates compile to WASM at once.

Candidate first target:

1. xenia-ledger, if random UUID generation can be isolated.
2. xenia-handshake, if browser-safe cryptographic randomness can be configured explicitly.
3. xenia-peer-core only after protocol/runtime boundaries are clearer.

## Decision

WASM compatibility work should proceed through dependency inventory and target-specific randomness policy before enabling Cargo features.
