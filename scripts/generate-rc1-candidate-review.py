#!/usr/bin/env python3
"""Generate sanitized RC1 candidate-review evidence for Xenia."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


MARKDOWN_PATH = Path("docs/release/evidence/RC1_CANDIDATE_REVIEW.md")
JSON_PATH = Path("docs/release/evidence/rc1-candidate-review.json")

REQUIRED_EVIDENCE = [
    (
        "normalization review",
        Path("docs/release/evidence/NORMALIZATION_V0_2_EVIDENCE_REVIEW.md"),
        "normalization manifest, execution plan, ledger, and current after-snapshot were reviewed",
    ),
    (
        "release dashboard",
        Path("docs/release/evidence/RC1_RELEASE_DASHBOARD.md"),
        "RC1 dashboard evidence was generated from the normalized branch",
    ),
    (
        "source archive checksums",
        Path("docs/release/evidence/RC1_SOURCE_ARCHIVE_CHECKSUMS.md"),
        "source archive generation has deterministic checksum evidence",
    ),
    (
        "normalization dry-run",
        Path("docs/release/evidence/NORMALIZATION_V0_2_DRY_RUN_EVIDENCE.md"),
        "normalization executor dry-run evidence exists for the current normalized tree",
    ),
    (
        "transport fault injection",
        Path("docs/release/evidence/RC1_TRANSPORT_FAULT_INJECTION.md"),
        "transport fault-injection coverage was expanded and recorded",
    ),
    (
        "admin audit event names",
        Path("docs/release/evidence/RC1_ADMIN_AUDIT_EVENT_NAMES.md"),
        "operator/admin audit event names have a stable dot-namespaced contract",
    ),
]


def sanitize(text: str) -> str:
    """Remove machine-local path fragments from command output."""
    sanitized = text
    for label in ("home", "srv", "tmp", "mnt", "Users"):
        prefix = "/" + label + "/"
        sanitized = re.sub(
            re.escape(prefix) + r"[^\s\"'\)\]\}]+",
            f"<{label.lower()}-path>",
            sanitized,
        )
    return sanitized.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_check(root: Path, name: str, command: list[str]) -> dict:
    proc = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    # Keep candidate-review evidence deterministic. The full command output is
    # intentionally not embedded because validator/tool output can contain
    # environment-dependent ordering, warnings, or transient formatting. The
    # review records the command, exit code, and pass/fail status; detailed logs
    # remain in CI/local terminal output.
    return {
        "name": name,
        "command": [sanitize(part) for part in command],
        "exit_code": proc.returncode,
        "status": "pass" if proc.returncode == 0 else "fail",
    }


def load_manifest(root: Path) -> dict:
    manifest_path = root / "xenia.release.toml"
    if tomllib is not None:
        return tomllib.loads(manifest_path.read_text())

    # Minimal fallback for older Python runtimes. It is intentionally narrow:
    # enough to preserve release status and blocker counts in generated evidence.
    text = manifest_path.read_text()
    status = re.search(r'^status\s*=\s*"([^"]+)"', text, re.M)
    hard = re.search(r"hard\s*=\s*\[(.*?)\]", text, re.S)
    soft = re.search(r"soft\s*=\s*\[(.*?)\]", text, re.S)
    return {
        "release_train": {"status": status.group(1) if status else "unknown"},
        "blockers": {
            "hard": [] if hard and not hard.group(1).strip() else ["unparsed"],
            "soft": [] if soft and not soft.group(1).strip() else ["unparsed"],
        },
    }


def git_value(root: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return sanitize(proc.stdout).strip() if proc.returncode == 0 else "unknown"


def collect(root: Path) -> dict:
    manifest = load_manifest(root)
    release_train = manifest.get("release_train", {})
    blockers = manifest.get("blockers", {})

    checks = [
        run_check(root, "xenia-validate", ["bash", "scripts/xenia-validate.sh", "."]),
        run_check(
            root,
            "release-readiness",
            ["python3", "scripts/check-release-readiness.py", "."],
        ),
        run_check(
            root,
            "release-readiness-rc1",
            ["python3", "scripts/check-release-readiness.py", ".", "--rc1"],
        ),
    ]

    evidence = []
    for name, rel_path, purpose in REQUIRED_EVIDENCE:
        path = root / rel_path
        item = {
            "name": name,
            "path": rel_path.as_posix(),
            "purpose": purpose,
            "present": path.exists(),
        }
        if path.exists():
            item["size_bytes"] = path.stat().st_size
            item["sha256"] = sha256_file(path)
        evidence.append(item)

    hard = blockers.get("hard", []) or []
    soft = blockers.get("soft", []) or []
    all_checks_pass = all(check["exit_code"] == 0 for check in checks)
    all_evidence_present = all(item["present"] for item in evidence)

    ready = (
        release_train.get("status") == "pre-rc"
        and len(hard) == 0
        and len(soft) == 0
        and all_checks_pass
        and all_evidence_present
    )

    return {
        "schema": "xenia.rc1_candidate_review.v1",
        "generated_by": "scripts/generate-rc1-candidate-review.py",
        "review_scope": {
            "workspace": "current checkout",
            "git_identity_recorded": False,
            "reason": "Branch names and commit SHAs change across squash merges; RC1 evidence is structural.",
        },
        "release_train": {
            "status": release_train.get("status", "unknown"),
            "current_milestone": release_train.get("current_milestone", "unknown"),
            "next_candidate": release_train.get("next_candidate", "unknown"),
        },
        "blockers": {
            "hard_count": len(hard),
            "soft_count": len(soft),
            "hard": hard,
            "soft": soft,
        },
        "checks": checks,
        "evidence": evidence,
        "decision": {
            "rc1_candidate_review_ready": ready,
            "promotion_performed": False,
            "promotion_policy": "Promotion must be a separate explicit PR after this review passes.",
        },
    }


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def render_markdown(data: dict) -> str:
    release = data["release_train"]
    blockers = data["blockers"]
    decision = data["decision"]

    lines = [
        "# RC1 Candidate Review Evidence",
        "",
        "Status: generated for explicit RC1 candidate review.",
        "",
        "This evidence confirms that Xenia has exited blocker burn-down while still",
        "remaining in `pre-rc` status. It does not promote the release train.",
        "",
        "## Release train",
        "",
        f"- Current milestone: `{release['current_milestone']}`",
        f"- Next candidate: `{release['next_candidate']}`",
        f"- Release status: `{release['status']}`",
        f"- Hard blockers: `{blockers['hard_count']}`",
        f"- Soft blockers: `{blockers['soft_count']}`",
        "",
        "## Validation checks",
        "",
        "| Check | Status | Exit code |",
        "| --- | --- | ---: |",
    ]
    for check in data["checks"]:
        lines.append(f"| `{check['name']}` | `{check['status']}` | `{check['exit_code']}` |")

    lines.extend(
        [
            "",
            "## Required evidence set",
            "",
            "| Evidence | Present | Path |",
            "| --- | --- | --- |",
        ]
    )
    for item in data["evidence"]:
        present = "yes" if item["present"] else "no"
        lines.append(f"| {item['name']} | `{present}` | `{item['path']}` |")

    lines.extend(
        [
            "",
            "## Decision",
            "",
            f"- RC1 candidate review ready: `{decision['rc1_candidate_review_ready']}`",
            f"- Promotion performed: `{decision['promotion_performed']}`",
            f"- Promotion policy: {decision['promotion_policy']}",
            "",
            "## Next step",
            "",
            "If this review PR passes CI and is merged, open a separate promotion PR.",
            "That promotion PR should be intentionally small and should change only the",
            "release-train status/evidence needed to mark RC1.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="xenia-peer workspace root")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if committed candidate-review evidence is stale",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not (root / "xenia.release.toml").exists():
        print("ERROR: workspace root must contain xenia.release.toml", file=sys.stderr)
        return 2

    data = collect(root)
    markdown = render_markdown(data)
    json_text = render_json(data)

    markdown_path = root / MARKDOWN_PATH
    json_path = root / JSON_PATH

    if args.check:
        stale = False
        if not markdown_path.exists() or markdown_path.read_text() != markdown:
            print(f"stale evidence: {MARKDOWN_PATH}", file=sys.stderr)
            stale = True
        if not json_path.exists() or json_path.read_text() != json_text:
            print(f"stale evidence: {JSON_PATH}", file=sys.stderr)
            stale = True
        if stale:
            print("rerun: python3 scripts/generate-rc1-candidate-review.py .", file=sys.stderr)
            return 1
        print("RC1 candidate-review evidence is current")
        return 0

    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(markdown)
    json_path.write_text(json_text)
    print(f"wrote markdown: {MARKDOWN_PATH}")
    print(f"wrote manifest: {JSON_PATH}")
    return 0 if data["decision"]["rc1_candidate_review_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
