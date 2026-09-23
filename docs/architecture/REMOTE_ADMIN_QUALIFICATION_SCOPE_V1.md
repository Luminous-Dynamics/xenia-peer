# Privileged Operation Parent Qualification Scope v1

The remote-admin adapter line depends on exact subject `75fe52b1bafb72fc07ee0db80ee5f62ce82566e9` only as a current qualification target, not as an assumed PASS.

A disposable qualifier should check out that exact subject and execute read-only gates:

- pinned Rust 1.96.0;
- `cargo fmt --all --check`;
- `cargo metadata --format-version 1`;
- strict Cargo-boundary inventory;
- tests for `xenia-exec-proto`;
- tests for `xenia-operation-proto`;
- tests for `xenia-peer-core`;
- focused package checks without privileged runtime effects.

No qualifier job may push repairs into the product subject. Any failure must produce a fresh repair subject rather than mutating the evidence target in place.
