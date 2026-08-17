#!/usr/bin/env python3
"""Shared repository-aware scan scope helpers for Xenia validation scripts.

The security scanners need two properties at once:

* include tracked files and ordinary untracked work-in-progress, so a new source
  file cannot evade review merely because it has not been staged yet;
* exclude ignored local machinery such as agent worktrees and runtime state,
  which otherwise duplicates the tree and destroys scanner signal-to-noise.

When Git metadata is unavailable (for example in an exported source archive),
helpers fall back to a normal recursive filesystem walk with the same explicit
skip-part policy.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
from typing import Iterable


_CFG_TEST_ONLY_RE = re.compile(r"^\s*#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*$")


def iter_repo_files(
    root: Path,
    *,
    suffixes: set[str],
    skip_parts: set[str],
) -> list[Path]:
    """Return candidate files with Git-aware ignored-file handling.

    In a Git checkout, ``git ls-files --cached --others --exclude-standard`` is
    the intended source of truth: committed files plus untracked, non-ignored
    work. In a source archive or other Git-less tree, recurse normally.
    """

    root = root.resolve()
    rel_paths: list[Path] | None = None

    if (root / ".git").exists() and shutil.which("git"):
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if proc.returncode == 0:
            rel_paths = [
                Path(raw.decode("utf-8", errors="surrogateescape"))
                for raw in proc.stdout.split(b"\0")
                if raw
            ]

    if rel_paths is None:
        rel_paths = [path.relative_to(root) for path in root.rglob("*") if path.is_file()]

    result: list[Path] = []
    for rel in rel_paths:
        if set(rel.parts) & skip_parts:
            continue
        path = root / rel
        if not path.is_file():
            continue
        if path.suffix not in suffixes:
            continue
        result.append(path)
    return sorted(set(result))


def _item_end(lines: list[str], start: int) -> int:
    """Best-effort end index for the item beginning at ``start``.

    This is deliberately a tiny structural scanner rather than a Rust parser.
    It only runs after an exact ``#[cfg(test)]`` attribute and therefore needs
    to distinguish a semicolon-terminated item from a brace-delimited item.
    Braces inside ordinary format/JSON strings are overwhelmingly balanced; if
    this conservative heuristic is ever ambiguous, the scanner should count a
    few test lines as runtime rather than hide runtime source.
    """

    depth = 0
    saw_open = False
    for index in range(start, len(lines)):
        line = lines[index]
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        opens = line.count("{")
        closes = line.count("}")
        if opens:
            saw_open = True
        if saw_open:
            depth += opens - closes
            if depth <= 0:
                return index
        elif ";" in line:
            return index

    # Malformed/truncated source: mark only the starting line test-only rather
    # than hiding the remainder of the file.
    return start


def cfg_test_only_lines(lines: list[str]) -> set[int]:
    """Return 1-based line numbers belonging to exact ``#[cfg(test)]`` items.

    Importantly, ``#[cfg(any(feature = \"foo\", test))]`` is *not* test-only:
    that item can compile in production when ``foo`` is enabled. The previous
    runtime-risk scanner treated the first attribute containing the word
    ``test`` as a cutoff for the entire rest of the file, which could hide real
    runtime ``unwrap``/``expect`` calls in large ``main.rs`` files.
    """

    masked: set[int] = set()
    index = 0
    while index < len(lines):
        if not _CFG_TEST_ONLY_RE.match(lines[index]):
            index += 1
            continue

        attr_start = index
        item_start = index + 1
        # Additional attributes/comments/blank lines belong to the same item.
        while item_start < len(lines):
            stripped = lines[item_start].strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#["):
                item_start += 1
                continue
            break

        if item_start >= len(lines):
            masked.add(attr_start + 1)
            break

        end = _item_end(lines, item_start)
        # If structural detection looks suspiciously large, fail conservative:
        # only mask through the first semicolon/brace item that was identified,
        # never an open-ended tail of the source file.
        for line_no in range(attr_start + 1, end + 2):
            masked.add(line_no)
        index = end + 1

    return masked
