# PQC evidence boundary check

`scripts/check-pqc-evidence-boundary.sh .` is the operator-facing gate for the
current Xenia PQC evidence posture. It intentionally validates the boundary
without claiming that runtime authentication has moved beyond classical signatures today.

The command runs the claim guards, evidence crypto profile checks, manifest
fixtures, signature-envelope agility checks, transcript-bound evidence checks,
PQC signature backend boundary checks, full-PQC runtime refusal checks, and the
PQ signature vector harness.

## Why this exists

Xenia currently has a hybrid posture: ML-KEM key establishment is allowed by the
manifest profile, while evidence and transcript signatures remain classical
unless a reviewed PQ signature backend is explicitly wired in. The boundary
check keeps that posture machine-checkable.

The check also runs a negative manifest-guard self-test. That self-test copies
the fixture registry into a temporary sandbox and proves the manifest checker
fails closed when:

- an unregistered manifest fixture is added; or
- a required manifest fixture is removed.

This turns the fixture registry into an explicit review surface instead of a
folder that can drift silently.

## Recommended local validation

```bash
scripts/check-pqc-evidence-boundary.sh .
scripts/xenia-validate.sh .
```

If either command fails, prefer tightening wording, manifests, or test fixtures
over weakening the boundary labels.
