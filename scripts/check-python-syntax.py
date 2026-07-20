#!/usr/bin/env python3
"""Compile every repository Python source without creating bytecode caches.

The validator previously spawned one interpreter per file with ``py_compile``.
Besides being needlessly slow on cold or sandboxed filesystems, that wrote
ignored ``__pycache__`` state into the source tree.  This checker keeps the
syntax pass in one process and uses the built-in compiler directly, so it is
read-only and deterministic.
"""
from __future__ import annotations

import argparse
import sys
import tokenize
from pathlib import Path


def python_sources(root: Path) -> list[Path]:
    scripts = root / "scripts"
    if not scripts.is_dir():
        return []
    return sorted(
        path
        for path in scripts.rglob("*.py")
        if "__pycache__" not in path.parts and path.is_file()
    )


def check_file(path: Path, root: Path) -> str | None:
    try:
        with tokenize.open(path) as source_file:
            source = source_file.read()
        compile(source, str(path.relative_to(root)), "exec", dont_inherit=True)
    except (OSError, SyntaxError, UnicodeError) as exc:
        return f"{path.relative_to(root)}: {exc}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    sources = python_sources(root)
    if not sources:
        print("python syntax: no scripts found")
        return 0

    failures = [failure for path in sources if (failure := check_file(path, root))]
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"python syntax failed for {len(failures)} of {len(sources)} file(s)", file=sys.stderr)
        return 1

    print(f"python syntax: {len(sources)} file(s) passed without bytecode output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
