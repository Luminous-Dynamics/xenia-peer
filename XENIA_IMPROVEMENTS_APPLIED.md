# Xenia Improvements Applied

This patch is intentionally low-risk. It does not delete any source. It adds
workspace hygiene guardrails, updates stale protocol/security wording, and
hardens the daemon around spawned-server failures.

## Added

- `WORKSPACE_BOUNDARIES.md`
- `docs/runbooks/ARCHIVE_HYGIENE.md`
- `docs/security/PRE_PRODUCTION_GATES.md`
- `scripts/xenia-hygiene-audit.sh`
- root `.gitignore`

## Updated

- `xenia-wire/README.md`
  - Install/version text now matches `0.2.0-alpha.3`.
  - Pre-alpha banner no longer says the wire crate owns the placeholder
    handshake path; it now points responsibility at product handshake layers.
- `xenia-wire/SECURITY.md`
  - Status now reflects `0.2.0-alpha.x` and acknowledges that spec/test vectors
    exist but still need independent review.
- `xenia-wire/Cargo.toml`
  - Package excludes now explicitly block archive/build bundles.
- `.gitignore` files
  - Added archive/build/editor ignores.
- `scripts/xenia-hygiene-audit.sh`
  - Fails on active tarballs/build output/nested git repos/absolute local workspace paths.
  - Reports pre-alpha/TODO markers as review warnings, not hard failures.
- `xenia-peer/src/main.rs`
  - Added configurable `--consent-port`.
  - Replaced `unwrap()` in spawned admin/consent server paths with logged errors.
  - Falls back to `TestCapture` if `ScapCapture::new()` fails after availability
    detection.

## Not changed

- No dependencies were upgraded.
- No crate layout was moved automatically.
- No historical artifacts were deleted.

## Second-pass additions

- `docs/architecture/CRATE_OWNERSHIP.md`
  - Declares crate/app ownership and allowed dependency direction.
- `docs/security/THREAT_MODEL.md`
  - Defines assets, trust boundaries, adversaries, and production blockers.
- `docs/release/RELEASE_GATES.md`
  - Turns readiness into auditable gates with evidence requirements.
- `docs/runbooks/PORTABILITY_AUDIT.md`
  - Adds checks for machine-local paths and non-portable dependencies.
- `scripts/archive-active-artifacts.sh`
  - Dry-run-first artifact archival; preserves tarballs/scripts under `_archive`.
- `scripts/export-source-archive.sh`
  - Produces source-only tarballs that exclude `.git`, `target`, `dist`, prior archives, and editor debris.
- `scripts/xenia-validate.sh`
  - Combines hygiene, shell syntax, metadata, format, check, and test-build validation where workspaces exist.
- `.github/workflows/xenia-validate.yml`
  - CI entrypoint for hygiene and `xenia-wire` validation.
- `deny.toml`
  - Starter cargo-deny policy for advisory dependency/license review.

## v4 add-on: normalization and release preflight

- Added `docs/architecture/WORKSPACE_NORMALIZATION_PLAN.md` to turn the cleanup into a staged, non-destructive migration.
- Added `docs/testing/VALIDATION_MATRIX.md` so each validation layer has a clear purpose and merge/release status.
- Added `docs/security/CONSENT_AND_ABUSE_CASES.md` to keep consent, revocation, and remote-control abuse cases visible while Xenia is pre-production.
- Added `docs/release/SOURCE_ARCHIVE_POLICY.md` for source-only archive expectations.
- Added `scripts/check-cargo-boundaries.py` to detect absolute path dependencies, wire/product dependency inversions, and app/library boundary violations using only Python stdlib.
- Added `scripts/check-source-archive.sh` to validate generated `.tar.gz` files before sharing or publishing.
- Added `scripts/xenia-preflight-report.sh` to generate a single markdown diagnostic report from the current tree.
- Updated `scripts/xenia-validate.sh` and GitHub Actions to include the new boundary checks.
- Updated `scripts/export-source-archive.sh` to post-validate archives when `check-source-archive.sh` is present.

## Evidence bundle verification gate

- Added `Verifier::verify_evidence_bundle(...)` to bind an evidence crypto
  manifest to the exported ledger entry signature envelopes.
- Added `EvidenceBundleVerifyError::LedgerSignatureSuiteMismatch` so artifacts
  cannot attach a stronger manifest to a weaker Ed25519 export.
- Added docs and a validation script for the evidence bundle contract.

## Evidence transcript binding hardening

- Added `SessionTranscriptBinding` and `compute_session_transcript_hash` to `xenia-ledger`.
- Added `Verifier::verify_transcript_bound_evidence_bundle(...)` so a valid exported ledger cannot be trusted beside the wrong session transcript.
- Added a transcript-bound evidence contract doc and validation script.


## Transport/session V20: SAF streaming staging and bounded file memory

- Replaced the current Android picker path's `InputStream.readBytes()` whole-file allocation with a reusable 64 KiB chunk loop into native app-private staging.
- Native staging incrementally hashes BLAKE3, enforces the 100 MiB mobile cap for known and unknown provider lengths, and consumes the existing bounded command permit before expensive work.
- Preserved the existing authenticated file-transfer wire protocol: `Offer(size, hash)` remains precomputed before peer acceptance; staged bytes are read with Tokio in 64 KiB chunks only after `Accept`.
- Added a fixed five-minute non-extending staging lease, partial-file cleanup on expiry/cancel/session teardown, and explicit staging `IO_ERROR` status `8`.
- Added `FileTransferAdmissionSnapshotV2` with `active_streaming` and `active_stream_bytes` while retaining V19's V1 ABI.
- Added V20 language-neutral vector, source contract, reduced resource model, and accumulated-runner integration.

## Transport/session V19: deterministic reservation races and diagnostic fidelity

- Switched mobile file-reservation deadlines to `tokio::time::Instant` and extracted the async expiry worker around `sleep_until`, enabling deterministic paused-time tests rather than wall-clock sleeps.
- Added Tokio `test-util` merge tests for claim-at-29.999s, survival past the original admission deadline, copy-lease expiry returning command capacity, and non-extending repeat claims.
- Added a JNI/Kotlin exact-result path for all stable file-admission statuses (`0..7`) while retaining the historical Boolean `sendFile` wrapper.
- Added a point-in-time local file-admission snapshot (`active_reserved`, `active_copying`, `available_command_slots`, `command_capacity`) through Rust/C/JNI/Kotlin.
- Added the V19 source contract/model/vector to the accumulated transport/session contract runner.

## Transport/session V18: runtime evidence and reservation-race hardening

- Added a two-stage file-transfer reservation lifecycle (`Reserved` -> `Copying`) with a 30 s admission TTL and bounded 60 s copy lease.
- Expiry tasks re-read the live deadline so a near-expiry claim cannot be removed by the original timer; repeated claims do not extend the lease.
- JNI claims capacity before Java byte-array materialization and commit still rechecks the token/length.
- Removed the duplicate Android file-event `name_len` header store and pinned the 32-byte layout in a V18 compatibility vector.
- Exposed desktop audio ingress pressure in the native GUI and emit a host video-pressure summary on normal teardown.
- Added `scripts/run_transport_session_contracts.sh` and wired the accumulated V10-V18 source/model contracts into the flake CI job before the existing Rust tests.
