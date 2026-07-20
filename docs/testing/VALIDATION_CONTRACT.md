# Validation Contract

Xenia distinguishes a full merge-gate validation from a static diagnostic pass.

## Full validation

```text
scripts/xenia-validate.sh .
```

Full validation requires `cargo` and `rustc`, verifies they satisfy the workspace
MSRV, and runs metadata, formatting, compilation, test-build, supply-chain, and
source-policy checks. Missing Rust is a failure, not a skipped green result.

## Static diagnostic validation

```text
scripts/xenia-static-validate.sh .
```

Static validation is useful in restricted review environments. Its success
message explicitly says that Rust compilation and tests were not run. It is not
a merge or release gate. Each repository check has a hard wall-clock bound,
configured with `XENIA_VALIDATION_CHECK_TIMEOUT_SECS` (default: 300 seconds).

Static and full validation are read-only with respect to Python bytecode: syntax
checks run in one process and `PYTHONDONTWRITEBYTECODE=1` prevents imported
helpers from leaving ignored cache state in the checkout.

Advisory dashboard generation is intentionally outside the default gate because
it reruns several checks. Request it explicitly when collecting evidence:

```text
scripts/xenia-static-validate.sh --with-reports .
```

## Toolchain and feature contracts

- `rust-toolchain.toml` pins the exact Rust release and required components.
- `scripts/check-rust-toolchain-contract.py` keeps Cargo, rustup, and CI pins in sync.
- `xenia.features.toml` inventories every non-default Cargo feature.
- `scripts/check-feature-matrix.py` requires CI evidence or an explicit manual/scaffold rationale.
- `scripts/check-validation-contract-negative.sh` mutates each toolchain/feature contract and proves the guards fail closed.
- `scripts/check-validation-runtime-negative.sh` proves syntax failures, timeout cleanup, report opt-in, and read-only validation behavior.

The Nix validation shell may provide a newer compiler, but it must still satisfy
the declared MSRV at runtime. CI jobs that use rustup use the exact pinned release.
