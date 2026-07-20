#!/usr/bin/env python3
"""Validate all repository shell scripts in one bounded orchestration process."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PER_FILE_TIMEOUT_SECS = 10


def shell_sources(root: Path) -> list[Path]:
    scripts = root / "scripts"
    if not scripts.is_dir():
        return []
    return sorted(path for path in scripts.rglob("*.sh") if path.is_file())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    sources = shell_sources(root)
    failures: list[str] = []
    for path in sources:
        relative = path.relative_to(root)
        try:
            result = subprocess.run(
                ["bash", "-n", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=PER_FILE_TIMEOUT_SECS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{relative}: syntax check exceeded {PER_FILE_TIMEOUT_SECS}s")
            continue
        except OSError as exc:
            print(f"shell syntax runner could not execute bash: {exc}", file=sys.stderr)
            return 2
        if result.returncode != 0:
            detail = result.stdout.strip() or f"bash exited {result.returncode}"
            failures.append(f"{relative}: {detail}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"shell syntax failed for {len(failures)} of {len(sources)} file(s)", file=sys.stderr)
        return 1

    print(f"shell syntax: {len(sources)} file(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
