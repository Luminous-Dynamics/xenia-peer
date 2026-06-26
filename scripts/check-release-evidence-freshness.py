#!/usr/bin/env python3
"""
Check release evidence inventory and hygiene.

RC1 evidence is historical evidence for the tagged RC1 release snapshot.
This checker intentionally does not regenerate historical RC1 evidence against
later post-RC1 commits, because that would rewrite release evidence after the tag.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


REQUIRED_EVIDENCE = [
    "docs/release/evidence/RC1_SOURCE_ARCHIVE_CHECKSUMS.md",
    "docs/release/evidence/rc1-source-archive-checksums.json",
    "docs/release/evidence/RC1_RELEASE_DASHBOARD.md",
    "docs/release/evidence/rc1-release-dashboard.json",
    "docs/release/evidence/NORMALIZATION_V0_2_DRY_RUN_EVIDENCE.md",
    "docs/release/evidence/normalization-v0.2-dry-run-current.json",
    "docs/release/evidence/RC1_TRANSPORT_FAULT_INJECTION.md",
    "docs/release/evidence/rc1-transport-fault-injection.json",
    "docs/release/evidence/RC1_ADMIN_AUDIT_EVENT_NAMES.md",
    "docs/release/evidence/rc1-admin-audit-event-names.json",
    "docs/release/evidence/RC1_CANDIDATE_REVIEW.md",
    "docs/release/evidence/rc1-candidate-review.json",
]

LOCAL_PATH_MARKERS = [
    "/" + "srv/",
    "/" + "home/",
    "/" + "mnt/",
    "/" + "tmp/",
]

LEAK_PATTERNS = [
    *(re.compile(re.escape(marker)) for marker in LOCAL_PATH_MARKERS),
    re.compile(r"tristan", re.IGNORECASE),
    re.compile(r"evolvingresonant", re.IGNORECASE),
    re.compile(r"\.git/"),
    re.compile(r"target/"),
]


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)


def check_required_files(root: Path) -> int:
    missing = [path for path in REQUIRED_EVIDENCE if not (root / path).is_file()]
    if missing:
        print("missing release evidence files:", file=sys.stderr)
        for path in missing:
            print(f"  {path}", file=sys.stderr)
        return 1

    print("release evidence inventory: ok")
    return 0


def check_leaks(root: Path) -> int:
    failed = False

    for rel in REQUIRED_EVIDENCE:
        path = root / rel
        text = path.read_text(errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            for pattern in LEAK_PATTERNS:
                if pattern.search(line):
                    print(f"leak-like evidence content: {rel}:{line_no}: {line}", file=sys.stderr)
                    failed = True

    if failed:
        return 1

    print("release evidence leak scan: ok")
    return 0


def check_readiness(root: Path) -> int:
    commands = [
        ["python3", "scripts/check-release-readiness.py", ".", "--rc1"],
    ]

    for cmd in commands:
        proc = run(cmd, root)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            print(f"command failed: {' '.join(cmd)}", file=sys.stderr)
            return 1

    print("release readiness gates: ok")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    failed = False
    failed |= bool(check_required_files(root))
    failed |= bool(check_leaks(root))
    failed |= bool(check_readiness(root))

    if failed:
        return 1

    print("release evidence freshness check completed")
    print("note: RC1 evidence is historical; this checker does not rewrite it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
