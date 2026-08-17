# Cargo-vet workflow

Xenia treats `cargo vet --locked` as a supply-chain provenance gate. Normal
validation and CI are non-interactive: committed audits, exemptions, and locked
imports are reused until the dependency graph changes.

## Normal development and CI

Run:

```bash
scripts/xenia-vet-delta.sh check
```

This is equivalent to `cargo vet --locked`. If it passes, no human action is
required.

## A dependency version is unvetted

Do not add an exemption just to make the gate green. Review only the missing
version delta:

```bash
scripts/xenia-vet-delta.sh review <crate> <old> <new>
```

The helper invokes the local, locked cargo-vet diff so imported audit feeds are
not refreshed as part of the review. Read the criterion shown by cargo-vet and
inspect the security-relevant changes, especially unsafe code and powerful or
ambient capabilities.

If the delta satisfies the criterion, certify it explicitly without opening an
editor:

```bash
scripts/xenia-vet-delta.sh certify <crate> <old> <new> \
  --reviewed \
  --notes "Reviewed <security-relevant surfaces and any discretion>."
```

Use `--criteria` when the required criterion is not `safe-to-deploy`, and
`--who` when the cargo-vet identity should be overridden for this audit.
Certification requires both `--reviewed` and non-empty notes; the helper will
not infer or auto-accept the human security judgment.

After recording the audit, the helper reruns `cargo vet --locked` and shows the
`supply-chain/audits.toml` diff when Git is available. Review that diff and
commit the audit metadata with the dependency change.

## Why review and certification are separate

The purpose of cargo-vet is to record an accountable human security judgment,
not merely to silence a dependency gate. Keeping `review` and `certify` as
separate explicit operations makes routine use editor-free while preserving the
important human decision.
