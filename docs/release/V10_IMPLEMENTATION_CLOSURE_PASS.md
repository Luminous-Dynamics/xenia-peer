# v10 Implementation Closure Pass

v10 is the handoff from meta-hardening to executable work.

## Added

- `xenia.tasks.toml`
- `scripts/generate-fix-tickets.py`
- `scripts/scaffold-consent-tests.py`
- `scripts/check-consent-coverage.py`
- `scripts/ci-collect-artifacts.sh`
- `.github/workflows/xenia-artifacts.yml`
- `docs/implementation/FIRST_REAL_BRANCH_PLAN.md`
- `docs/implementation/CONSENT_TEST_IMPLEMENTATION_PLAN.md`
- `docs/ci/ARTIFACT_OUTPUTS.md`

## Purpose

The project has enough guardrails. The next improvement should be an actual
normalization branch with evidence, fix tickets, and CI artifacts.

v10 makes that branch easier by giving future agents and maintainers:

- a machine-readable task queue;
- generated Markdown/JSON fix tickets;
- a consent-test scaffold;
- a CI artifact collector;
- a concrete first-branch plan.

## Recommended next action

```bash
scripts/generate-fix-tickets.py . --markdown _archive/fix-tickets.md --json _archive/fix-tickets.json
scripts/ci-collect-artifacts.sh . _archive/ci-artifacts
```

Then start `xenia/normalization-v0.2-execution` and execute the normalization
runbook.
