# v9 Secure Defaults and Dashboard Pass

v9 adds a release-readiness layer focused on abuse resistance and visibility.

## Added

- `xenia.safety.toml`
- `.github/CODEOWNERS`
- `scripts/check-secure-defaults.py`
- `scripts/check-codeowners.py`
- `scripts/generate-release-dashboard.py`
- `docs/security/SECURE_BY_DEFAULT_BASELINE.md`
- `docs/security/CONSENT_STATE_MACHINE.md`
- `docs/testing/SECURE_DEFAULTS_TEST_PLAN.md`
- `docs/release/RELEASE_DASHBOARD.md`
- `docs/agents/SECURITY_REVIEW_PROMPT.md`

## Purpose

Xenia should not accidentally become a powerful unattended remote-control stack
while still in pre-production. The new safety manifest and scanner make the
pre-production stance explicit and checkable.
