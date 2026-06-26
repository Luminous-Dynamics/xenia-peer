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
