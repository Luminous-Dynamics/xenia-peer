# Release Dashboard

The release dashboard is the human-readable artifact for answering:

```text
What is still blocking Xenia from the next release stage?
```

Generate it with:

```bash
scripts/generate-release-dashboard.py . \
  --markdown _archive/release-dashboard.md \
  --json _archive/release-dashboard.json
```

The dashboard intentionally continues after failed checks. A dashboard that shows
failures is still valuable evidence; it prevents hidden release debt.

## Required before RC1

- dashboard generated from the active branch;
- hard blockers reviewed;
- secure-default scan reviewed in strict mode;
- runtime-risk and unsafe-surface findings reviewed or exceptioned;
- source archive generated and checked;
- normalization evidence exists if the branch includes layout moves.
