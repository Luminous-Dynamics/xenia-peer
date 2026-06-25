# Xenia Validation Matrix

Xenia should treat validation as layers. Each layer answers a different question
and should fail early before expensive checks run.

| Layer | Command | Purpose | Required before merge? |
|---|---|---|---|
| Workspace hygiene | `scripts/xenia-hygiene-audit.sh .` | Detect build artifacts, nested VCS state, tarballs, absolute paths, local runtime state. | Yes |
| Cargo boundaries | `scripts/check-cargo-boundaries.py .` | Detect absolute path deps, app-to-crate inversion, wire depending on product crates. | Yes after normalization |
| Shell syntax | `find scripts -name '*.sh' -print0 | xargs -0 bash -n` | Catch broken project automation. | Yes |
| Metadata | `cargo metadata --format-version 1 --no-deps` | Prove workspace path dependencies resolve. | Yes |
| Formatting | `cargo fmt --all -- --check` | Keep code stable for diffs and agents. | Yes |
| Static Rust check | `cargo check --workspace --all-targets` | Catch type/feature breakage. | Yes |
| Test build | `cargo test --workspace --all-targets --no-run` | Prove tests compile without requiring devices. | Yes |
| Unit/integration tests | `cargo test --workspace` or `cargo nextest run` | Prove behavior. | Required for release candidates |
| Transport conformance | `cargo test -p xenia-transport-ws -p xenia-transport-quic` | Keep WS and QUIC behavior aligned. | Required for release candidates |
| Protocol vectors | `cd xenia-wire && cargo test --all-features` | Ensure sealed envelope compatibility. | Yes for wire changes |
| Supply chain | `cargo deny check advisories bans licenses sources` | Catch yanked/vulnerable/disallowed deps/licenses. | Advisory until dependency graph is normalized; required before public release |
| Archive validation | `scripts/check-source-archive.sh <archive.tar.gz>` | Prove source exports are clean. | Required before publishing archives |
| Nix reproducibility | `nix flake check` | Prove Nix shell/checks stay usable. | Required when flake changes |

## Recommended local sequence

```bash
scripts/xenia-validate.sh .
scripts/export-source-archive.sh . /tmp/xenia-source.tar.gz
scripts/check-source-archive.sh /tmp/xenia-source.tar.gz
```

When Nix is available:

```bash
nix develop .#ci -c bash scripts/xenia-validate.sh .
nix flake check --show-trace
```

## Device-dependent tests

Screen capture, input injection, and H.264 tests may require host capabilities.
Keep a device-independent default test path that works in CI, then gate hardware
or desktop integration tests behind explicit features or environment variables.

## v5 policy and risk gates

| Check | Command | Merge gate | RC gate | Purpose |
| --- | --- | --- | --- | --- |
| Project policy | `scripts/check-xenia-policy.py .` | required | required | Keeps safety posture and component roles machine-readable. |
| Runtime risk report | `scripts/check-runtime-risk-patterns.py .` | advisory | reviewed | Counts `unwrap`, `expect`, `panic`, `todo`, and `unimplemented` in runtime source. |
| Strict runtime risk | `scripts/check-runtime-risk-patterns.py . --strict` | optional | required or exception-tracked | Blocks release candidates with unresolved runtime panic/unwrap debt. |
| Agent handoff | `scripts/xenia-agent-handoff-report.sh . /tmp/xenia-agent-handoff.md` | advisory | required for external review | Prevents future agents from relying on stale conversational state. |
