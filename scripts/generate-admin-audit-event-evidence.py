#!/usr/bin/env python3
"""Generate sanitized RC1 evidence for stable operator/admin audit event names."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

EXPECTED_NAMES = [
    "consent.requested",
    "consent.granted",
    "consent.denied",
    "consent.revoked",
    "consent.protocol_violation",
    "admin.athena_triage",
]

TEST_COMMANDS = [
    {
        "id": "ledger-stable-name-contract",
        "command": [
            "cargo",
            "test",
            "-p",
            "xenia-ledger",
            "consent_kind_stable_names_are_contractual",
            "--",
            "--exact",
        ],
    },
    {
        "id": "ledger-record-stable-name",
        "command": [
            "cargo",
            "test",
            "-p",
            "xenia-ledger",
            "consent_event_record_uses_stable_kind_name",
            "--",
            "--exact",
        ],
    },
    {
        "id": "consent-coverage",
        "command": ["python3", "scripts/check-consent-coverage.py", ".", "--strict"],
    },
]


def sanitize(text: str, root: Path) -> str:
    text = text.replace(str(root), "<workspace>")
    text = re.sub(r"/Users/runner/work/[^\s)\]'}\"]+", "<runner-workspace>", text)
    home_prefix = "/" + "home/"
    text = re.sub(re.escape(home_prefix) + r"[^\s)\]'}\"]+", "<home-path>", text)
    text = re.sub(r"/tmp/[^\s)\]'}\"]+", "<tmp-path>", text)
    text = re.sub(r"(?:<workspace>/)?target/debug/deps/[^\s)\]'}\"]+", "<test-binary>", text)
    return text


def run_case(root: Path, case: dict[str, object]) -> dict[str, object]:
    command = case["command"]
    assert isinstance(command, list)
    proc = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return {
        "id": case["id"],
        "command": command,
        "returncode": proc.returncode,
        "passed": proc.returncode == 0,
        "output": sanitize(proc.stdout, root).strip(),
    }


def source_contains_all_names(root: Path) -> dict[str, object]:
    paths = [
        root / "crates/xenia-ledger/src/lib.rs",
        root / "docs/observability/EVENT_TAXONOMY.md",
        root / "apps/sovereign-admin/src/pages/sessions.rs",
    ]
    found = {name: [] for name in EXPECTED_NAMES}
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(root))
        for name in EXPECTED_NAMES:
            if name in text:
                found[name].append(rel)
    missing = [name for name, hits in found.items() if not hits]
    return {"expected_names": EXPECTED_NAMES, "missing": missing, "hits": found}


def write_outputs(root: Path, payload: dict[str, object]) -> None:
    json_path = root / "docs/release/evidence/rc1-admin-audit-event-names.json"
    md_path = root / "docs/release/evidence/RC1_ADMIN_AUDIT_EVENT_NAMES.md"
    json_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    commands = payload["commands"]
    assert isinstance(commands, list)
    names = payload["stable_names"]
    assert isinstance(names, dict)
    expected_names = names["expected_names"]
    assert isinstance(expected_names, list)

    lines = [
        "# RC1 Admin Audit Event Names Evidence",
        "",
        "This evidence closes the RC1 soft blocker that operator/admin audit events need stable names.",
        "",
        "## Stable names",
        "",
        "| Stable audit name |",
        "| --- |",
    ]
    for name in expected_names:
        lines.append(f"| `{name}` |")

    lines.extend([
        "",
        "## Validation commands",
        "",
        "| Check | Result |",
        "| --- | --- |",
    ])
    for case in commands:
        assert isinstance(case, dict)
        result = "PASS" if case["passed"] else "FAIL"
        lines.append(f"| `{case['id']}` | `{result}` |")

    lines.extend([
        "",
        "## Sign-off",
        "",
        "- `xenia-ledger` exposes stable dot-namespaced names via `ConsentKind::stable_name()`.",
        "- `ConsentEventRecord::stable_name()` forwards the same contract to ledger consumers.",
        "- `sovereign-admin` displays stable audit names instead of Rust `Debug` variant names.",
        "- Evidence output is sanitized and does not include local workspace paths.",
        "",
    ])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote manifest: {json_path.relative_to(root)}")
    print(f"wrote markdown: {md_path.relative_to(root)}")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if not (root / "Cargo.toml").exists() or not (root / "xenia.release.toml").exists():
        print(f"FAIL: {root} does not look like the xenia-peer workspace", file=sys.stderr)
        return 2

    commands = [run_case(root, case) for case in TEST_COMMANDS]
    names = source_contains_all_names(root)
    payload = {
        "schema": "xenia.rc1.admin_audit_event_names.v1",
        "workspace": "xenia-peer",
        "stable_names": names,
        "commands": commands,
        "passed": all(case["passed"] for case in commands) and not names["missing"],
    }
    write_outputs(root, payload)

    if not payload["passed"]:
        if names["missing"]:
            print(f"FAIL: missing stable names: {', '.join(names['missing'])}", file=sys.stderr)
        for case in commands:
            if not case["passed"]:
                print(f"FAIL: {case['id']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
