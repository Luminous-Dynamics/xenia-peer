# Physical input-to-photon trace format

**Schema:** `xenia-i2p-trace/v1`  
**Calibration schema:** `xenia-i2p-calibration/v1`  
**Status:** implemented importer; no physical Xenia result is implied by this document or by synthetic unit fixtures.

The importer is the first measurement-adapter increment for [#457](https://github.com/Luminous-Dynamics/xenia-peer/issues/457). It ingests a trace captured by an external HID-trigger / photodiode rig or a synchronized high-speed-camera rig. It does not generate physical measurements, drive hardware, authenticate an instrument vendor, or qualify a whole performance profile.

## Measurement boundary

Input-to-photon is the duration between:

1. an externally observed HID trigger edge, and
2. the corresponding visual marker's optical transition at the display sensor.

The trigger counter and sensor counter must belong to one declared instrument timebase. The importer never subtracts host and client wall clocks. `measurement_unix_ms` is used only to check the calibration's validity interval; duration comes only from counter ticks and `counter_frequency_hz`.

This path measures the input-to-observed-pixel chain on the tested rig. It does not by itself measure every internal pipeline stage, cross-machine one-way network delay, or human-perceived quality.

## Trace JSON

The complete trace is hashed as raw file bytes (SHA-256). Do not parse and reserialize a trace before recording its digest. The importer stores a verbatim copy of the trace and calibration file in the run directory under digest-derived names.

Required top-level fields:

| Field | Meaning |
|---|---|
| `schema_version` | Exact value `xenia-i2p-trace/v1` |
| `run_id`, `profile_id` | Must equal the target run packet |
| `condition_id` | Stable workload/condition identifier, e.g. `lan-static-ui-1080p60` |
| `measurement_unix_ms` | Time used only to check calibration validity |
| `instrument` | Instrument ID, firmware version, tool version, method |
| `timebase` | Shared counter source, ticks per second, uncertainty bound |
| `sensor` | Position and method-specific timing/measurement constraints |
| `display` | Resolution, refresh rate, VRR and HDR state |
| `calibration_sha256` | SHA-256 of the exact calibration JSON artifact bytes |
| `triggers` | Ordered external HID trigger records |
| `transitions` | Ordered corresponding sensor transition records |

Each trigger record contains `event_id`, monotonically increasing `sequence`, `trigger_tick`, and `expected_marker_id`. Each transition record contains the matching `event_id`, `sequence`, `sensor_tick`, `observed_marker_id`, `valid`, and (when invalid) a non-empty `rejection_reason`.

Arrays are deliberately separate: the importer requires equal lengths and a one-to-one, same-order join. Duplicate IDs, sequence or marker replay, missing partners, mismatched IDs/markers, out-of-order counter ticks, and negative durations reject the import. Invalid-but-well-formed trials remain accounted for by rejection reason; they are not silently repaired or included in percentiles.

### Illustrative trace excerpt

This abbreviated example describes the field names only. Two trials are intentionally insufficient for import; a pilot requires at least 300 valid trials.

```json
{
  "schema_version": "xenia-i2p-trace/v1",
  "run_id": "lan_interactive-1794834543000-0123456789ab",
  "profile_id": "lan_interactive",
  "condition_id": "lan-static-ui-1080p60",
  "measurement_unix_ms": 1794834543000,
  "instrument": {
    "id": "lab-photodiode-01",
    "firmware_version": "2.4.1",
    "tool_version": "xenia-hid-photodiode-bridge/0.1",
    "method": "photodiode"
  },
  "timebase": {
    "clock_source": "mcu-timer-1",
    "counter_frequency_hz": 100000000,
    "uncertainty_ns": 250
  },
  "sensor": {
    "position": "centre",
    "clock_resolution_ns": 10,
    "bandwidth_hz": 20000
  },
  "display": {
    "width_px": 1920,
    "height_px": 1080,
    "refresh_rate_hz": 60.0,
    "vrr_enabled": false,
    "hdr_enabled": false
  },
  "calibration_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "triggers": [
    {
      "event_id": "evt-000001",
      "sequence": 1,
      "trigger_tick": 1000000,
      "expected_marker_id": "marker-000001"
    },
    {
      "event_id": "evt-000002",
      "sequence": 2,
      "trigger_tick": 2000000,
      "expected_marker_id": "marker-000002"
    }
  ],
  "transitions": [
    {
      "event_id": "evt-000001",
      "sequence": 1,
      "sensor_tick": 6100000,
      "observed_marker_id": "marker-000001",
      "valid": true,
      "rejection_reason": null
    },
    {
      "event_id": "evt-000002",
      "sequence": 2,
      "sensor_tick": 7100000,
      "observed_marker_id": "marker-000002",
      "valid": true,
      "rejection_reason": null
    }
  ]
}
```

## Calibration artifact JSON

The calibration file is separately hashed as raw bytes. Its required fields are:

- `schema_version = "xenia-i2p-calibration/v1"`;
- `instrument_id` and `method`, which must match the trace;
- non-empty `calibration_id`;
- `valid_from_unix_ms` and `valid_until_unix_ms`, inclusive;
- `uncertainty_ns`, a non-negative integer bound.

The trace's `measurement_unix_ms` must fall inside the calibration interval. The trace's `calibration_sha256` must match the supplied calibration file's actual bytes.

Example:

```json
{
  "schema_version": "xenia-i2p-calibration/v1",
  "instrument_id": "lab-photodiode-01",
  "method": "photodiode",
  "calibration_id": "cal-lab-2026-11-14-01",
  "valid_from_unix_ms": 1794614400000,
  "valid_until_unix_ms": 1795219200000,
  "uncertainty_ns": 150
}
```

This is a calibration metadata contract, not a digital certificate format. The importer checks file integrity, declared identity/method and validity interval; it does not establish the calibration issuer's authority or the physical instrument's authenticity. Lab procedures must retain the signed calibration certificate and chain of custody separately where applicable.

## Instrument requirements

**Photodiode**
- `sensor.clock_resolution_ns` must be positive and no worse than 1,000 ns.
- `sensor.bandwidth_hz` must be at least 10,000 Hz.
- The sensor position must be `top`, `centre`, or `bottom`.

**High-speed camera**
- `sensor.frame_rate_fps` must be at least 1,000.
- Exposure, rolling/global shutter, display refresh, and frame-time uncertainty should be recorded in the lab's accompanying metadata. The v1 summary retains the declared frame rate, position and clock uncertainty.

Both methods require a positive `counter_frequency_hz`, non-empty `clock_source`, and a declared uncertainty bound. Counter values are unsigned integer ticks; the importer converts `sensor_tick - trigger_tick` to integer nanoseconds using the declared frequency before percentile calculation.

## CLI import

The input run packet must already be a valid `BLOCKED` packet prepared by `xenia-bench prepare-run`. The output must be a new filename in the same run directory:

```sh
cargo run --locked -p xenia-peer --bin xenia-bench -- import-i2p \
  --run artifacts/xenia-bench/lan-interactive-run.json \
  --trace lab/lan-static-ui-1080p60.trace.json \
  --calibration lab/photodiode-calibration.json \
  --out artifacts/xenia-bench/lan-interactive-run-with-i2p.json

cargo run --locked -p xenia-peer --bin xenia-bench -- check-run \
  artifacts/xenia-bench/lan-interactive-run-with-i2p.json
```

Import behavior:

1. Validate the existing run packet, its embedded profile binding, and its current artifacts.
2. Hash the raw trace and calibration files, parse the exact supported schemas, and validate run/profile identity.
3. Require one-to-one event and marker joins, strictly increasing sequences and counters, and non-negative durations.
4. Validate calibration identity, method and time interval.
5. Require at least 300 valid trials. Invalid trials are reported separately with reason counts; 1,000 valid trials are preferred for stronger tail estimates.
6. Compute nearest-rank p50/p95/p99/max. Compute a deterministic 95% bootstrap percentile interval for p95 using 2,000 resamples. The seed is derived from the raw trace digest, so rechecking identical bytes is reproducible.
7. Copy raw trace and calibration bytes verbatim to digest-named artifacts beside the new packet, record the derived summary and artifact digests, and keep `result_state = BLOCKED`.
8. When `check-run` is later called, re-open both artifacts, recompute the statistics, and reject a summary that differs from the raw evidence.

The input trace, calibration and source run packet are never overwritten. An existing output packet is never overwritten. A failure to validate prevents creation of the output packet. Digest-named sidecar artifacts may remain if a later output-file creation fails; they are immutable, unreferenced files and cannot qualify a run.

## Statistical interpretation

Percentiles use nearest-rank selection: rank `ceil(p × n)`. The p95 interval is a nonparametric percentile bootstrap over the valid trial latencies, with a fixed number of resamples and a digest-derived seed. This gives deterministic uncertainty reporting; it is not a substitute for adequate independent trials, randomized trial order, instrument uncertainty analysis, or a pre-registered statistical plan. Strongly correlated or thermally/time-varying trials should be identified and analyzed in separate blocks rather than treated as independent samples.

The run packet records raw p50/p95/p99/max in nanoseconds and milliseconds, the p95 95% interval, sample/rejection counts, instrument/calibration identity, clock source/frequency, and a conservative sum of declared clock and calibration uncertainty bounds.

## Result-state boundary

An imported I2P trace is one partial measurement. It does not set the overall `measurement_adapter` to executed, fill the unrelated profile metrics, or elevate the run to `PASS`. The run remains `BLOCKED` until all canonical profile measurements, a complete measurement adapter, raw artifacts, and threshold checks are provided and revalidated. A synthetic unit fixture is explicitly labelled as test data and never produces a releasable result.
