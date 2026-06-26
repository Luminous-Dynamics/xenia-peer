# WASM Randomness Policy

Status: post-RC1 policy note.

This document records the first WASM compatibility blocker found during PQC/WASM feasibility checks: browser-safe randomness configuration.

## Context

The PQC/WASM feasibility note found that Xenia's first wasm32-unknown-unknown blockers are not screen capture, input injection, filesystem access, or native transport dependencies. The first blockers are randomness configuration issues in dependencies used by protocol-adjacent crates.

Observed exploratory checks:

- `xenia-handshake` failed in `getrandom` 0.2 on wasm32-unknown-unknown.
- `xenia-ledger` failed in `uuid` because no WASM randomness source was configured.
- `xenia-peer-core` failed in `getrandom` 0.4 on wasm32-unknown-unknown.

## Policy

Xenia must not silently enable browser randomness or cryptographic features without an explicit policy.

Any WASM-compatible cryptographic or session crate must answer:

1. What randomness source is used on native targets?
2. What randomness source is used in browser/WASM targets?
3. Is the randomness source suitable for cryptographic material?
4. Is the randomness source available in non-browser WASM runtimes?
5. Does enabling a feature change behavior for native builds?
6. Does the crate need random generation at runtime, or can random-bearing constructors be isolated?

## Target split

Xenia should treat these as distinct targets:

- native server/client runtime
- browser WASM runtime
- non-browser WASM runtime
- test-only deterministic runtime

A feature that is correct for browser WASM may not be correct for non-browser WASM.

## Current blocker classes

### getrandom 0.2

Observed failure class:

- wasm32-unknown-unknown is not supported by default
- dependency requests explicit web support

Policy response:

- do not blindly enable JS randomness globally
- identify which crate path requires getrandom 0.2
- prefer crate-local target-specific feature decisions

### getrandom 0.4

Observed failure class:

- wasm32-unknown-unknown is not supported by default
- dependency requests explicit wasm_js support

Policy response:

- identify whether the dependency is protocol-critical
- document whether browser WASM is the intended target
- avoid making non-browser WASM claims until tested

### uuid

Observed failure class:

- uuid random generation requires an explicit randomness source on wasm32-unknown-unknown

Policy response:

- avoid random UUID generation in protocol types where deterministic IDs are acceptable
- isolate random ID generation behind constructors
- document feature selection before enabling uuid WASM randomness

## Dependency inventory note

The lockfile currently contains multiple randomness-related dependency versions, including:

- `getrandom` 0.2.17
- `getrandom` 0.4.2
- `uuid` 1.23.1

Because multiple `getrandom` versions are present, dependency inventory commands must use version-qualified package names such as:

    cargo tree -i getrandom@0.2.17
    cargo tree -i getrandom@0.4.2

Initial inventory confirmed that `uuid` 1.23.1 is used by `xenia-ledger`.

## Recommended implementation path

The next implementation PR should not try to make every crate compile to WASM at once.

Recommended order:

1. Inventory dependency paths for `getrandom` 0.2, `getrandom` 0.4, and `uuid`.
2. Identify whether `xenia-handshake` can support browser WASM safely.
3. Identify whether `xenia-ledger` can avoid runtime random UUID generation.
4. Decide whether `xenia-peer-core` should split protocol types from runtime dependencies.
5. Add one targeted WASM cargo check only after a crate compiles cleanly.
6. Keep native builds unchanged unless explicitly justified.

## Non-goals

This policy does not:

- claim current WASM compatibility
- enable Cargo features
- change cryptographic behavior
- define a complete browser client
- replace the existing xenia-wire web viewer
- publish crates to crates.io

## Decision

The first WASM blocker is randomness policy, not proof that Xenia's protocol crates are inherently native-only.

Xenia should make browser randomness explicit, target-specific, documented, and tested before advertising WASM compatibility.
