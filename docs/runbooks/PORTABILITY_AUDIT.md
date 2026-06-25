# Portability Audit Runbook

Run this before handing the project to another machine, agent, CI runner, or
public repository.

## Checks

```bash
scripts/xenia-hygiene-audit.sh .
scripts/xenia-validate.sh .
rg -n '<workspace-root>|<home>/|<sandbox-data>|tristan\.stoltz@|evolvingresonantcocreationism\.com' . \
  -g '!_archive/**' -g '!target/**' -g '!dist/**' -g '!*.lock'
```

Personal author metadata in package manifests may be intentional. Absolute local
paths in dependencies, scripts, docs, or generated bundles are not portable and
must be replaced with workspace-relative paths, feature gates, or documented
overrides.

## Common fixes

- Replace absolute path dependencies with workspace-relative paths.
- Move machine-local scripts under `_archive/YYYY-MM-DD-*` if they were one-off
  migration helpers.
- Move release bundles out of active source paths.
- Regenerate source archives with `scripts/export-source-archive.sh`.
