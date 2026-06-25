# Binary Serialization Migration

Status: Required before RC1.

## Context

Xenia currently uses `bincode` 1.3.3 in several internal and test-facing serialization paths.
Cargo-deny reports `RUSTSEC-2025-0141`, marking bincode as unmaintained.

This is temporarily allowed during M0 normalization so the workspace can reach a clean baseline.

## Rule

Do not expand bincode usage.

Before RC1, migrate runtime serialization to one of:

- postcard
- bitcode
- wincode
- a dedicated Xenia wire codec

## Acceptance Criteria

- `cargo deny check advisories bans licenses sources` passes without ignoring `RUSTSEC-2025-0141`.
- Xenia wire/session compatibility tests still pass.
- Ledger/event serialization has explicit compatibility vectors.
