# Xenia Release Train

Xenia should not jump from prototype to release by vibes. The release train is a
small, explicit path from stabilization to normalization to RC1.

## Current state

`xenia.release.toml` is the machine-readable source of truth.

Current expected stage:

```text
pre-production -> stabilization-v0.1 -> normalization-v0.2 -> rc1
```

RC1 is not a production-security claim. It is the first point where the project
should have a clean source archive, reviewed privilege boundaries, reviewed
consent behavior, and reproducible validation output.

## Required command

```bash
scripts/check-release-readiness.py .
```

During an explicit RC review only:

```bash
scripts/check-release-readiness.py . --rc1
```

## Release discipline

Before any release-candidate branch:

1. Generate a handoff report.
2. Generate a preflight report.
3. Run the release-readiness check.
4. Produce a clean source archive.
5. Validate that archive independently.
6. Review consent, revocation, audit, unsafe/FFI, and runtime-risk findings.

If a blocker is real, keep it in `xenia.release.toml` instead of hiding it in
chat history.
