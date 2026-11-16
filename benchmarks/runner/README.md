# Xenia Benchmark Runner

A local-first Rust tool for preparing reproducible Xenia benchmark runs and checking their evidence packets.

This is deliberately **not yet a capture/transport measurement adapter**. It does not launch Xenia, inject network impairments, read screen pixels, or claim performance results. The first increment establishes a stable profile validator, host/source capture, evidence packet and fail-closed result checker. Actual capture-to-display and input-to-photon adapters are separate work and must emit measured samples plus raw artifacts.

## Build and test

From the repository root:

```sh
cargo test -p xenia-bench-runner
cargo clippy -p xenia-bench-runner --all-targets -- -D warnings
cargo run -p xenia-bench-runner -- validate-profile benchmarks/xenia-benchmark-profile-v0.1.json
```

## Prepare a local run packet

```sh
cargo run -p xenia-bench-runner -- prepare-run \
  --profile benchmarks/xenia-benchmark-profile-v0.1.json \
  --profile-id lan_interactive \
  --repo . \
  --out artifacts/xenia-bench/lan-interactive-run.json
```

Preparation records the profile SHA-256, exact Git commit and dirty state, OS/kernel, CPU, available NVIDIA GPU metadata and Rust toolchain where discoverable, selected network/media profile, and required measurements.

The resulting packet is `BLOCKED` with `measurement_adapter.state=NOT_CONFIGURED`. Preparation never fabricates metrics or claims that a test ran.

## Validate a completed packet

After a real measurement adapter has populated `measurements`, `sample_count`, raw `artifacts`, `measurement_adapter`, and the result state:

```sh
cargo run -p xenia-bench-runner -- check-run artifacts/xenia-bench/lan-interactive-run.json
```

A claimed `PASS` is rejected unless all required metrics exist, the working tree was clean at capture time, an adapter is marked executed, at least one raw artifact is bound, the sample count is adequate, and the profile-specific thresholds pass. The checker recomputes thresholds instead of trusting a caller-supplied threshold table.

## Result vocabulary

- `PASS`: the selected performance profile's defined thresholds passed for the recorded run.
- `FAIL`: a measured threshold or invariant failed.
- `BLOCKED`: no valid measurement was completed or a required dependency/evidence item is absent.
- `ENVIRONMENT_FAILURE`: the test environment invalidated the run.

These states qualify **only the named benchmark profile**. They do not qualify cryptographic security, consent correctness, platform support, or a Xenia release.

The checker validates consistency, not truth or authorship. Raw artifact digests and measurements are self-reported until a separate signed provenance/independent-verification layer is implemented. Never use this tool's output alone as a security or release attestation.

## Safety

The tool is read-only with respect to network configuration. It does not run `tc netem`, modify firewall rules, elevate privileges, access screen contents, capture keystrokes, or alter the Xenia process. Network shaping and real-device execution require a separately reviewed adapter with explicit user invocation.
