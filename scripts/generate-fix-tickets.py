#!/usr/bin/env python3
"""Generate human-readable fix tickets from Xenia manifests and scanner outputs.

The script is dependency-free and intentionally conservative. It does not modify
source files. It reads xenia.tasks.toml when Python 3.11+ tomllib is available,
then emits Markdown/JSON tickets that can be pasted into GitHub issues or used as
an agent handoff queue.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


DEFAULT_TICKETS = [
    {
        "id": "XN-BOOTSTRAP",
        "title": "Apply v10 implementation-closure patch",
        "kind": "process",
        "priority": "P0",
        "status": "ready",
        "blocking_rc1": False,
        "summary": "Apply the v10 pass and generate fix tickets from the active workspace.",
        "commands": ["scripts/generate-fix-tickets.py . --markdown _archive/fix-tickets.md --json _archive/fix-tickets.json"],
        "acceptance": ["Fix-ticket output exists and is reviewed before the next branch starts."],
    }
]


def run_optional(root: Path, cmd: list[str]) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        return {"command": cmd, "returncode": proc.returncode, "output": proc.stdout[-8000:]}
    except FileNotFoundError:
        return {"command": cmd, "returncode": 127, "output": f"missing executable: {cmd[0]}"}
    except subprocess.TimeoutExpired as exc:
        return {"command": cmd, "returncode": 124, "output": (exc.stdout or "")[-8000:]}


def load_tasks(root: Path) -> list[dict[str, Any]]:
    path = root / "xenia.tasks.toml"
    if not path.exists():
        return DEFAULT_TICKETS
    if tomllib is None:
        return DEFAULT_TICKETS
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    tasks = data.get("task", [])
    if not isinstance(tasks, list):
        raise SystemExit("xenia.tasks.toml: expected [[task]] array")
    out: list[dict[str, Any]] = []
    for task in tasks:
        if not isinstance(task, dict):
            raise SystemExit("xenia.tasks.toml: each task must be a table")
        for key in ("id", "title", "kind", "priority", "status", "summary"):
            if not isinstance(task.get(key), str) or not task[key].strip():
                raise SystemExit(f"xenia.tasks.toml: task missing string field {key!r}")
        out.append(task)
    return out


def collect_context(root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    candidates = [
        ["scripts/check-release-readiness.py", "."],
        ["scripts/check-secure-defaults.py", "."],
        ["scripts/check-normalization-plan.py", "."],
        ["scripts/check-codeowners.py", "."],
    ]
    for cmd in candidates:
        if (root / cmd[0]).exists():
            checks.append(run_optional(root, cmd))
    return {"checks": checks}


def render_markdown(tickets: list[dict[str, Any]], context: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Xenia Fix Tickets")
    lines.append("")
    lines.append("Generated from `xenia.tasks.toml` plus advisory validation context.")
    lines.append("")
    rc_blockers = [t for t in tickets if bool(t.get("blocking_rc1"))]
    lines.append(f"- Total tickets: {len(tickets)}")
    lines.append(f"- RC1 blockers: {len(rc_blockers)}")
    lines.append("")
    for ticket in tickets:
        lines.append(f"## {ticket['id']}: {ticket['title']}")
        lines.append("")
        lines.append(f"- Kind: `{ticket['kind']}`")
        lines.append(f"- Priority: `{ticket['priority']}`")
        lines.append(f"- Status: `{ticket['status']}`")
        lines.append(f"- Blocks RC1: `{str(bool(ticket.get('blocking_rc1'))).lower()}`")
        lines.append("")
        lines.append(str(ticket.get("summary", "")))
        lines.append("")
        commands = ticket.get("commands", [])
        if commands:
            lines.append("### Suggested commands")
            lines.append("")
            lines.append("```bash")
            lines.extend(str(c) for c in commands)
            lines.append("```")
            lines.append("")
        acceptance = ticket.get("acceptance", [])
        if acceptance:
            lines.append("### Acceptance")
            lines.append("")
            for item in acceptance:
                lines.append(f"- [ ] {item}")
            lines.append("")
    checks = context.get("checks", [])
    if checks:
        lines.append("## Advisory validation context")
        lines.append("")
        for check in checks:
            command = " ".join(check.get("command", []))
            lines.append(f"### `{command}`")
            lines.append("")
            lines.append(f"Return code: `{check.get('returncode')}`")
            output = str(check.get("output", "")).strip()
            if output:
                lines.append("")
                lines.append("```text")
                lines.append(output[-3000:])
                lines.append("```")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia repository root")
    parser.add_argument("--markdown", help="write Markdown tickets to this path")
    parser.add_argument("--json", help="write JSON tickets to this path")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    tickets = load_tasks(root)
    context = collect_context(root)
    payload = {"tickets": tickets, "context": context}
    markdown = render_markdown(tickets, context)

    if args.markdown:
        out = root / args.markdown if not os.path.isabs(args.markdown) else Path(args.markdown)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
    else:
        print(markdown, end="")

    if args.json:
        out = root / args.json if not os.path.isabs(args.json) else Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
