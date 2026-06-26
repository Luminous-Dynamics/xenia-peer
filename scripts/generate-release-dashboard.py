#!/usr/bin/env python3
"""Generate a sanitized Xenia release/readiness dashboard.

The dashboard is intended to be committed as release evidence, so it must not
record machine-local absolute paths, temporary filenames, user names, or other
workspace-specific details. Keep the raw checks useful, but normalize the paths
that vary between developer machines and CI runners.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any


CHECKS = [
    ("hygiene", ["bash", "scripts/xenia-hygiene-audit.sh", "."]),
    ("policy", [sys.executable, "scripts/check-xenia-policy.py", "."]),
    ("safety", [sys.executable, "scripts/check-secure-defaults.py", ".", "--max-lines", "80"]),
    ("codeowners", [sys.executable, "scripts/check-codeowners.py", "."]),
    ("release-readiness", [sys.executable, "scripts/check-release-readiness.py", "."]),
    ("normalization-plan", [sys.executable, "scripts/check-normalization-plan.py", "."]),
    ("post-normalization", [sys.executable, "scripts/check-post-normalization.py", "."]),
    ("cargo-boundaries", [sys.executable, "scripts/check-cargo-boundaries.py", "."]),
    ("runtime-risk", [sys.executable, "scripts/check-runtime-risk-patterns.py", ".", "--max-lines", "80"]),
    ("unsafe-surfaces", [sys.executable, "scripts/check-unsafe-surfaces.py", ".", "--max-lines", "80"]),
]

ROOT_PLACEHOLDER = "<repo-root>"
TEMP_PLACEHOLDER = "<temp-artifact>"


def load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def git_value(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except Exception:  # noqa: BLE001 - dashboard should be best-effort evidence
        return "unknown"
    value = proc.stdout.strip()
    return value if proc.returncode == 0 and value else "unknown"


def sanitize_text(text: str, root: Path) -> str:
    """Remove machine-local values from committed dashboard evidence."""
    sanitized = text.replace(str(root), ROOT_PLACEHOLDER)
    sanitized = sanitized.replace(str(root.resolve()), ROOT_PLACEHOLDER)

    # Archive/check helpers use temporary files. Keep the evidence meaningful
    # while removing host-specific temporary paths.
    sanitized = re.sub(r"/tmp/xenia[-A-Za-z0-9_.:/]+", TEMP_PLACEHOLDER, sanitized)
    sanitized = re.sub(r"/var/folders/[-A-Za-z0-9_./]+", TEMP_PLACEHOLDER, sanitized)
    sanitized = re.sub(r"[A-Z]:\\\\[^\s`\"']+", TEMP_PLACEHOLDER, sanitized)
    return sanitized


def run_check(root: Path, name: str, command: list[str]) -> dict[str, Any]:
    # For Python/bash script commands, skip missing scripts instead of failing
    # the dashboard generator.
    if len(command) > 1 and command[1].startswith("scripts/") and not (root / command[1]).exists():
        return {"name": name, "status": "missing", "exit_code": None, "output": "script not found"}
    try:
        proc = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        status = "pass" if proc.returncode == 0 else "fail"
        output = sanitize_text(proc.stdout[-12000:], root)
        return {"name": name, "status": status, "exit_code": proc.returncode, "output": output}
    except Exception as exc:  # noqa: BLE001 - dashboard should keep going
        return {"name": name, "status": "error", "exit_code": None, "output": sanitize_text(str(exc), root)}


def source_context(root: Path, release: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    layout = policy.get("layout", {})
    train = release.get("release_train", {})
    return {
        "root": ROOT_PLACEHOLDER,
        "git_branch": git_value(root, "branch", "--show-current"),
        "git_head": git_value(root, "rev-parse", "--short=12", "HEAD"),
        "layout_mode": layout.get("mode", "unknown"),
        "current_milestone": train.get("current_milestone", "unknown"),
        "release_status": train.get("status", "unknown"),
        "generated_from_normalized_layout": layout.get("mode") == "normalized",
    }


def render_markdown(
    source: dict[str, Any],
    results: list[dict[str, Any]],
    release: dict[str, Any],
    safety: dict[str, Any],
) -> str:
    train = release.get("release_train", {})
    blockers = release.get("blockers", {})
    safety_defaults = safety.get("secure_defaults", {})
    lines: list[str] = []
    lines.append("# Xenia Release Dashboard")
    lines.append("")
    lines.append(f"Root: `{source['root']}`")
    lines.append(f"Generated from branch: `{source['git_branch']}`")
    lines.append(f"Generated from HEAD: `{source['git_head']}`")
    lines.append(f"Layout mode: `{source['layout_mode']}`")
    lines.append(f"Generated from normalized layout: `{source['generated_from_normalized_layout']}`")
    lines.append(f"Current milestone: `{train.get('current_milestone', 'unknown')}`")
    lines.append(f"Status: `{train.get('status', 'unknown')}`")
    lines.append("")
    lines.append("## Gate summary")
    lines.append("")
    lines.append("| Check | Status | Exit |")
    lines.append("| --- | --- | --- |")
    for result in results:
        lines.append(f"| {result['name']} | {result['status']} | {result['exit_code']} |")
    lines.append("")
    lines.append("## Secure-default summary")
    lines.append("")
    for key in sorted(safety_defaults):
        lines.append(f"- `{key}`: `{safety_defaults[key]}`")
    lines.append("")
    lines.append("## Hard blockers")
    lines.append("")
    hard = blockers.get("hard", [])
    if hard:
        for item in hard:
            lines.append(f"- {item}")
    else:
        lines.append("- None recorded")
    lines.append("")
    lines.append("## Soft blockers")
    lines.append("")
    soft = blockers.get("soft", [])
    if soft:
        for item in soft:
            lines.append(f"- {item}")
    else:
        lines.append("- None recorded")
    lines.append("")
    lines.append("## Check output")
    for result in results:
        lines.append("")
        lines.append(f"### {result['name']}")
        lines.append("")
        lines.append("```text")
        lines.append(result.get("output", "").strip())
        lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--markdown", default="")
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    release = load_toml(root / "xenia.release.toml")
    policy = load_toml(root / "xenia.policy.toml")
    safety = load_toml(root / "xenia.safety.toml")
    results = [run_check(root, name, command) for name, command in CHECKS]
    source = source_context(root, release, policy)
    dashboard = {
        "source": source,
        "root": ROOT_PLACEHOLDER,
        "release_train": release.get("release_train", {}),
        "hard_blockers": release.get("blockers", {}).get("hard", []),
        "soft_blockers": release.get("blockers", {}).get("soft", []),
        "checks": results,
    }
    markdown = render_markdown(source, results, release, safety)
    if args.markdown:
        Path(args.markdown).write_text(markdown, encoding="utf-8")
        print(f"wrote markdown dashboard: {args.markdown}")
    else:
        print(markdown)
    if args.json:
        Path(args.json).write_text(json.dumps(dashboard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote json dashboard: {args.json}")
    # Dashboard generation succeeds even when checks fail; the dashboard is evidence.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
