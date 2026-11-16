# Xenia Benchmark Evidence Tool

The local-first Rust benchmark evidence CLI is a second binary target in the existing `xenia-peer` package: `apps/xenia-peer/src/bin/xenia-bench.rs`.

It intentionally reuses the daemon package's existing `serde_json` dependency and does not add a workspace package or introduce a new lockfile dependency. This preserves `cargo --locked` discipline.

## Build and test

From the repository root:

```sh
cargo test --locked -p xenia-peer --bin xenia-bench
cargo clippy --locked -p xenia-peer --bin xenia-bench --all-targets -- -D warnings
cargo run --locked -p xenia-peer --bin xenia-bench -- validate-profile benchmarks/xenia-benchmark-profile-v0.1.json
```

## Prepare a local run packet

```sh
cargo run --locked -p xenia-peer --bin xenia-bench -- prepare-run \
  --profile benchmarks/xenia-benchmark-profile-v0.1.json \
  --profile-id lan_interactive \
  --repo . \
  --out artifacts/xenia-bench/lan-interactive-run.json
```

The tool records the profile SHA-256, exact Git commit and dirty state, OS/kernel, CPU, discoverable NVIDIA GPU metadata and Rust toolchain, selected network/media profile, and the required measurement keys.

The resulting packet is deliberately `BLOCKED` with `measurement_adapter.state=NOT_CONFIGURED`. This first increment does not yet measure capture-to-display or input-to-photon. It never fabricates metrics.

## Validate a completed packet

After a real adapter has populated measurements, sample count, raw artifact paths/digests, adapter identity and result state:

```sh
cargo run --locked -p xenia-peer --bin xenia-bench -- check-run artifacts/xenia-bench/lan-interactive-run.json
```

A claimed `PASS` is rejected unless all required measurements exist, the source was clean at capture time, an identified adapter is marked executed, raw evidence is bound, at least 100 samples exist, and the profile-specific thresholds pass. Thresholds are recomputed by the tool rather than accepted from the run packet. For PASS, the tool also resolves each artifact relative to the run packet directory, rejects path escapes, reads the file and recomputes SHA-256. A digest-shaped string is not accepted in place of the actual bytes.

The checker validates packet consistency and on-disk artifact integrity only. It does not independently attest the truth or authorship of measurements, instrument calibration or artifacts. A claimed input-to-photon result also needs physical instrument evidence; see the measurement methodology. Without an attached photodiode or high-speed-camera trace and calibration record, the checker refuses PASS for profiles that require input-to-photon.

## Physical input-to-photon evidence

Profiles requiring input-to-photon measurement must include a calibrated photodiode record (timer resolution <=1 microsecond) or a high-speed-camera record (>=1,000 frames/s), >=300 valid trials, verified event-ID association, a physical trace digest and a calibration artifact digest. The method and sensor position must be recorded. A software presentation callback is not physical input-to-photon evidence.

See [Measurement Methodology](../../docs/benchmarks/MEASUREMENT_METHODOLOGY.md).

## Result vocabulary

- `PASS`: the selected performance profile's defined thresholds passed.
- `FAIL`: a measured threshold or invariant failed.
- `BLOCKED`: no valid measurement was completed or required evidence is absent.
- `ENVIRONMENT_FAILURE`: the test environment invalidated the run.

These states qualify only the named performance profile, never cryptographic security, consent correctness, platform support or a Xenia release.

The tool does not modify networking, firewall configuration, privileges, screen contents or input state. Network shaping and real-device execution require a separately reviewed adapter with explicit operator invocation.
