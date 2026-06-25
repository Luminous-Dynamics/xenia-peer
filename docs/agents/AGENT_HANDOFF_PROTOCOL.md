# Xenia Agent Handoff Protocol

Xenia is a remote-control and infrastructure-observation stack. Treat every
agent pass as safety-critical even while the project is pre-production.

## First action for every agent

Run or generate a handoff report before editing:

```bash
scripts/xenia-agent-handoff-report.sh . /tmp/xenia-agent-handoff.md
```

Read the report before making claims about project health.

## Non-destructive rule

Do not delete active files during cleanup. Archive instead:

```bash
scripts/archive-active-artifacts.sh .          # dry run
scripts/archive-active-artifacts.sh . --apply  # after review
```

Use `_archive/YYYY-MM-DD-*` for historical bundles, build output, generated
artifacts, and superseded migration scripts.

## Boundary rule

Keep the layers separate:

1. `xenia-wire` defines protocol truth and test vectors.
2. Runtime libraries implement capture, transport, handshake, ledger, video, and
   input primitives.
3. Apps wire libraries into daemon/viewer/admin behavior.

Never make `xenia-wire` depend on product crates. Never make a library depend on
an app.

## Security posture rule

Until an explicit release-cut review says otherwise, Xenia is pre-production:

- remote control defaults to disabled;
- capture and input require consent;
- revocation fails closed;
- privileged sessions require auditability;
- development keys, local paths, and build output must not appear in release
  archives.

## Required validation before handoff

```bash
scripts/xenia-validate.sh .
scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-report.md
```

If validation fails, report the failure honestly and include the relevant block
from the preflight report. Do not claim release readiness from partial checks.
