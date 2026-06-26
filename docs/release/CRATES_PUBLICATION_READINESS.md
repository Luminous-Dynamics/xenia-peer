# Crates.io Publication Readiness

Status: deferred.

Xenia Peer v0.0.0 RC1 is a GitHub/source release candidate, not a crates.io publication candidate.

## Current decision

Do not publish Xenia crates to crates.io for RC1.

## Evidence

Cargo metadata shows every workspace crate and app is intentionally private via `publish = false`.

The following crates package and verify successfully as local crate archives:

- `xenia-handshake`
- `xenia-ledger`
- `xenia-video`
- `xenia-inject`

The following crates are not crates.io-ready yet:

- `xenia-peer-core`: depends on local path crate `xenia-handshake` without a crates.io version requirement
- `xenia-transport-quic`: depends on local path crate `xenia-peer-core` without a crates.io version requirement
- `xenia-transport-ws`: depends on local path crate `xenia-peer-core` without a crates.io version requirement
- `xenia-capture`: depends on git dependency `scap` without a crates.io version requirement

`cargo publish --dry-run` correctly refuses publication while `publish = false` is set.

## Future crates.io readiness requirements

Before any crates.io publication, Xenia should have an explicit public API milestone that decides:

- Which crates are public API versus internal implementation details
- Public crate version, likely not `0.0.0-m0`
- Version requirements for all inter-crate dependencies
- Replacement or publication strategy for git dependencies
- Complete crate metadata: description, license, repository, readme, keywords, and categories
- Package archive hygiene checks
- `cargo publish --dry-run` passing for each selected public crate

## Conclusion

Crates.io publication is intentionally deferred. RC1 remains valid as a GitHub/source release candidate.
