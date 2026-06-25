#!/usr/bin/env python3
"""Validate that Xenia has a minimal CODEOWNERS map."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

REQUIRED_PATTERNS = [
    "*",
    "/xenia-wire/",
    "/xenia-peer/crates/xenia-peer-core/",
    "/xenia-peer/crates/xenia-handshake/",
    "/xenia-peer/crates/xenia-ledger/",
    "/xenia-peer/apps/",
    "/docs/security/",
    "/scripts/",
    "/xenia.policy.toml",
    "/xenia.safety.toml",
    "/xenia.release.toml",
    "/xenia.normalization.toml",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    path = root / ".github" / "CODEOWNERS"
    if not path.exists():
        fail(".github/CODEOWNERS is missing")
    text = path.read_text(encoding="utf-8")
    missing = [pattern for pattern in REQUIRED_PATTERNS if pattern not in text]
    if missing:
        for pattern in missing:
            print(f"MISSING: {pattern}")
        fail("CODEOWNERS does not cover required Xenia paths")
    if "@luminous-dynamics/xenia-maintainers" in text:
        print("WARN: CODEOWNERS still uses placeholder team @luminous-dynamics/xenia-maintainers")
    print("CODEOWNERS check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
