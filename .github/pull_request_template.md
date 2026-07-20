## What changed?

Describe the user-visible or architecture-visible change.

## Xenia safety checklist

- [ ] I did not delete historical material; anything superseded was archived.
- [ ] I did not add `target/`, `dist/`, tarballs, local secrets, or nested `.git`.
- [ ] I did not introduce absolute `<workspace-root>` paths.
- [ ] I preserved the `xenia-wire` protocol/product boundary.
- [ ] I considered consent, revocation, and abuse cases for this change.

## Validation

Paste the relevant output or attach a preflight report:

```text
scripts/check-pqc-evidence-boundary.sh .
scripts/xenia-validate.sh .        # full; Rust toolchain required
scripts/xenia-static-validate.sh . # diagnostic fallback; not a merge gate
scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-report.md
```

## Release impact

- [ ] No release impact.
- [ ] Requires docs update.
- [ ] Requires test-vector update.
- [ ] Requires threat-model / consent review.
- [ ] Requires source-archive validation.
