# CI Artifact Outputs

CI should not only say pass/fail. For a pre-production remote capture/control
stack, failed checks should leave useful evidence.

Use:

```bash
scripts/ci-collect-artifacts.sh . _archive/ci-artifacts
```

Expected outputs:

- `release-dashboard.md`
- `release-dashboard.json`
- `fix-tickets.md`
- `fix-tickets.json`
- `agent-handoff.md`
- `metrics.json`
- `consent-coverage.json`
- `logs/*.log`
- `logs/*.exit`

A failed validation log is useful. Do not hide it. Review it and convert concrete
failures into fix tickets.
