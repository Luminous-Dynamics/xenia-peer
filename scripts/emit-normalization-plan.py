#!/usr/bin/env python3
"""Emit a reviewable Xenia workspace-normalization plan.

Default output is Markdown. `--format shell` emits commands for human review;
it does not execute them. Prefer copying commands into a branch after generating
a snapshot with scripts/create-normalization-snapshot.py.
"""
from __future__ import annotations

import argparse
import shlex
import tomllib
from pathlib import Path


def load(root: Path) -> dict:
    return tomllib.loads((root / "xenia.normalization.toml").read_text(encoding="utf-8"))


def q(value: str) -> str:
    return shlex.quote(value)


def markdown(root: Path, manifest: dict) -> str:
    lines: list[str] = []
    norm = manifest.get("normalization", {})
    lines.append("# Xenia Workspace Normalization Plan")
    lines.append("")
    lines.append(f"Root: `{root}`")
    lines.append(f"Status: `{norm.get('status', 'unknown')}`")
    lines.append(f"Layout: `{norm.get('layout_mode_before', 'unknown')}` -> `{norm.get('layout_mode_after', 'unknown')}`")
    lines.append("")
    lines.append("## Preflight")
    lines.append("")
    lines.append("Run these before moving anything:")
    lines.append("")
    lines.append("```bash")
    lines.append("scripts/check-normalization-plan.py .")
    lines.append("scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json")
    lines.append("scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-before-normalization.md")
    lines.append("```")
    lines.append("")
    lines.append("## Archive rules")
    lines.append("")
    for rule in manifest.get("archive_rule", []):
        lines.append(f"- **{rule['id']}**: `{rule['pattern']}` -> `{rule['destination']}`")
        lines.append(f"  - {rule.get('reason', 'No reason provided.')}")
    lines.append("")
    lines.append("## Planned moves")
    lines.append("")
    lines.append("| ID | Kind | Source | Target | Present |")
    lines.append("| --- | --- | --- | --- | --- |")
    for move in manifest.get("move", []):
        source = move["source"]
        target = move["target"]
        present = "yes" if (root / source).exists() else "no"
        lines.append(f"| `{move['id']}` | `{move['kind']}` | `{source}` | `{target}` | {present} |")
    lines.append("")
    lines.append("## Postflight")
    lines.append("")
    lines.append("```bash")
    lines.append("scripts/xenia-validate.sh .")
    lines.append("scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-after-normalization.md")
    lines.append("scripts/export-source-archive.sh . /tmp/xenia-source-after-normalization.tar.gz")
    lines.append("scripts/check-source-archive.sh /tmp/xenia-source-after-normalization.tar.gz")
    lines.append("```")
    return "\n".join(lines) + "\n"


def shell(root: Path, manifest: dict) -> str:
    lines: list[str] = []
    lines.append("#!/usr/bin/env bash")
    lines.append("set -euo pipefail")
    lines.append("# Review before running. Generated commands are intentionally conservative.")
    lines.append("scripts/check-normalization-plan.py .")
    lines.append("scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json")
    lines.append("mkdir -p _archive/normalization-v0.2")
    lines.append("")
    lines.append("# Archive active artifacts first. Use the existing dry-run-first script when available.")
    lines.append("if [[ -x scripts/archive-active-artifacts.sh ]]; then")
    lines.append("  scripts/archive-active-artifacts.sh . --apply")
    lines.append("else")
    lines.append("  echo 'WARN: scripts/archive-active-artifacts.sh not found; archive artifacts manually' >&2")
    lines.append("fi")
    lines.append("")
    lines.append("# Move app surfaces out of crates/. Prefer git mv to preserve history.")
    for move in manifest.get("move", []):
        source = move["source"]
        target = move["target"]
        parent = str(Path(target).parent)
        lines.append(f"mkdir -p {q(parent)}")
        lines.append(f"if [[ -e {q(source)} && ! -e {q(target)} ]]; then")
        lines.append(f"  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then")
        lines.append(f"    git mv {q(source)} {q(target)}")
        lines.append("  else")
        lines.append(f"    mv {q(source)} {q(target)}")
        lines.append("  fi")
        lines.append("else")
        lines.append(f"  echo 'SKIP: {source} -> {target}'")
        lines.append("fi")
        lines.append("")
    lines.append("scripts/xenia-validate.sh .")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--format", choices={"markdown", "shell"}, default="markdown")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    manifest = load(root)
    if args.format == "shell":
        print(shell(root, manifest), end="")
    else:
        print(markdown(root, manifest), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
