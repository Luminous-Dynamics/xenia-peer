#!/usr/bin/env python3
"""Generate sanitized RC1 evidence for the normalization executor dry-run gate.

This script proves that apply-normalization-execution.py can be invoked in
non-mutating dry-run mode against the current normalized tree, using the reviewed
normalization execution plan as input. It writes committed evidence without local
absolute paths or temporary artifact locations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

DEFAULT_JSON = "docs/release/evidence/normalization-v0.2-dry-run-current.json"
DEFAULT_MARKDOWN = "docs/release/evidence/NORMALIZATION_V0_2_DRY_RUN_EVIDENCE.md"
PLAN_CANDIDATES = [
    "_archive/normalization-v0.2/execution-plan.sanitized.json",
    "_archive/normalization-v0.2/execution-plan.json",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def choose_plan(root: Path) -> Path:
    for rel in PLAN_CANDIDATES:
        path = root / rel
        if path.exists():
            return path
    fail("no reviewed normalization execution plan found")


def rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def sanitize_text(value: str, root: Path, temp_dir: Path) -> str:
    root_abs = str(root.resolve())
    temp_abs = str(temp_dir.resolve())
    value = value.replace(temp_abs, "<temp-artifact>")
    value = value.replace(root_abs, "<repo-root>")
    # The executor prints the ledger path; keep that stable and non-local.
    value = value.replace("<temp-artifact>/dry-run-ledger.json", "<temp-ledger>")
    return value


def sanitize_value(value: Any, root: Path, temp_dir: Path) -> Any:
    if isinstance(value, str):
        return sanitize_text(value, root, temp_dir)
    if isinstance(value, list):
        return [sanitize_value(item, root, temp_dir) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_value(item, root, temp_dir) for key, item in value.items()}
    return value


def write_markdown(path: Path, evidence: dict[str, Any]) -> None:
    dry_run = evidence["dry_run_result"]
    validation = evidence["validation"]
    lines = [
        "# Normalization v0.2 Dry-Run Evidence",
        "",
        "This evidence closes the RC1 soft blocker:",
        "",
        '"> normalization executor should be dry-run once on the production tree before apply"',
        "",
        "## Scope",
        "",
        "The normalization executor was invoked in dry-run mode against the current normalized Xenia production tree using the reviewed normalization execution plan.",
        "",
        "No filesystem apply mode was used.",
        "",
        "## Result",
        "",
        f"- mode: `{dry_run.get('mode')}`",
        f"- applied actions: `{dry_run.get('applied')}`",
        f"- blocked actions: `{dry_run.get('blocked')}`",
        f"- dry-run actions: `{dry_run.get('dry_run')}`",
        f"- working tree unchanged by dry-run: `{str(validation['working_tree_unchanged_by_dry_run']).lower()}`",
        f"- no apply rollback emitted: `{str(validation['no_apply_rollback_emitted']).lower()}`",
        "",
        "## Reviewed inputs",
        "",
        f"- plan: `{evidence['reviewed_plan']['path']}`",
        f"- plan sha256: `{evidence['reviewed_plan']['sha256']}`",
        f"- executor: `{evidence['executor']['path']}`",
        f"- executor sha256: `{evidence['executor']['sha256']}`",
        "",
        "## Evidence artifact",
        "",
        f"Machine-readable evidence is committed at `{DEFAULT_JSON}`.",
        "",
        "## Release posture",
        "",
        "This evidence does not promote Xenia to RC status. The release train remains `pre-rc`.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate normalization dry-run release evidence.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--json", default=DEFAULT_JSON)
    parser.add_argument("--markdown", default=DEFAULT_MARKDOWN)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not (root / "xenia.release.toml").exists():
        fail("xenia.release.toml not found at root")

    executor = root / "scripts" / "apply-normalization-execution.py"
    if not executor.exists():
        fail("scripts/apply-normalization-execution.py not found")

    plan = choose_plan(root)

    status_before = run(["git", "status", "--short"], root).stdout

    with tempfile.TemporaryDirectory(prefix="xenia-normalization-dry-run-") as tmp:
        temp_dir = Path(tmp)
        ledger = temp_dir / "dry-run-ledger.json"
        command = [
            sys.executable,
            str(executor),
            str(root),
            "--plan",
            str(plan),
            "--ledger",
            str(ledger),
        ]
        completed = run(command, root)
        if not ledger.exists():
            fail("dry-run ledger was not written")

        status_after = run(["git", "status", "--short"], root).stdout

        try:
            dry_run_result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            fail("dry-run command did not produce JSON stdout")

        with ledger.open("r", encoding="utf-8") as f:
            ledger_data = json.load(f)

        evidence: dict[str, Any] = {
            "schema": "xenia.normalization.dry-run-evidence.v1",
            "scope": "rc1-soft-blocker-burn-down",
            "soft_blocker_closed": "normalization executor should be dry-run once on the production tree before apply",
            "reviewed_plan": {
                "path": rel(root, plan),
                "sha256": sha256_file(plan),
            },
            "executor": {
                "path": rel(root, executor),
                "sha256": sha256_file(executor),
            },
            "command": sanitize_value(command, root, temp_dir),
            "stdout": sanitize_text(completed.stdout, root, temp_dir),
            "dry_run_result": sanitize_value(dry_run_result, root, temp_dir),
            "ledger": sanitize_value(ledger_data, root, temp_dir),
            "git_status_before": status_before,
            "git_status_after": status_after,
            "validation": {
                "executor_mode_is_dry_run": ledger_data.get("mode") == "dry-run",
                "applied_count_is_zero": ledger_data.get("applied_count") == 0,
                "blocked_count_is_zero": ledger_data.get("blocked_count") == 0,
                "working_tree_unchanged_by_dry_run": status_before == status_after,
                "no_apply_rollback_emitted": ledger_data.get("rollback") is None,
            },
        }

    validation = evidence["validation"]
    if not all(validation.values()):
        print(json.dumps(evidence, indent=2, sort_keys=True), file=sys.stderr)
        fail("normalization dry-run evidence validation failed")

    json_path = root / args.json
    markdown_path = root / args.markdown
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(markdown_path, evidence)

    print(f"wrote manifest: {rel(root, json_path)}")
    print(f"wrote markdown: {rel(root, markdown_path)}")
    print(f"dry_run_actions: {evidence['dry_run_result']['dry_run']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
