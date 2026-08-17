#!/usr/bin/env python3
"""Report risky Rust patterns in non-archive Xenia source.

This is a triage tool, not a Rust linter. By default it reports findings and
returns success so it can be used during stabilization without blocking every
existing test helper. Use --strict to fail on runtime-source findings.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from xenia_scan_scope import cfg_test_only_lines, iter_repo_files

TEST_PARTS = {"tests", "benches", "examples"}
PATTERNS = {
    "panic": re.compile(r"\bpanic!\s*\("),
    "todo": re.compile(r"\btodo!\s*\("),
    "unimplemented": re.compile(r"\bunimplemented!\s*\("),
    "unwrap": re.compile(r"\.unwrap\s*\("),
    "expect": re.compile(r"\.expect\s*\("),
}


@dataclass(frozen=True)
class Finding:
    rel_path: Path
    line_no: int
    kind: str
    line: str
    runtime_source: bool


def is_test_or_example(path: Path) -> bool:
    if set(path.parts) & TEST_PARTS or path.name.endswith("_test.rs"):
        return True
    # `tests.rs` is a module file loaded via `#[cfg(test)] mod tests;` in its
    # parent -- e.g. crates/xenia-ledger/src/tests.rs, split out of lib.rs on
    # 2026-07-19. Its own content has no in-file `#[cfg(test)]` marker (that
    # attribute lives on the `mod` declaration one file up), so the
    # first_cfg_test_line() heuristic below can't see it; the filename must
    # be recognized directly.
    if path.name == "tests.rs":
        return True
    # Smoke-test harnesses (manual, run-against-a-live-daemon binaries/
    # modules, not `#[cfg(test)]`-gated unit tests) live directly under
    # `src/` or `src/bin/`, not under any TEST_PARTS directory.
    if path.name.endswith("_smoke.rs"):
        return True
    if "bin" in path.parts and "smoke" in path.name:
        return True
    return False


def iter_rust_files(root: Path):
    for path in iter_repo_files(root, suffixes={".rs"}):
        yield path, path.relative_to(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia root")
    parser.add_argument("--strict", action="store_true", help="fail if runtime-source findings are present")
    parser.add_argument(
        "--max-lines",
        type=int,
        default=200,
        help="maximum finding lines to print before truncating output",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    findings: list[Finding] = []

    for path, rel in iter_rust_files(root):
        runtime_source = "src" in rel.parts and not is_test_or_example(rel)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        test_only_lines = cfg_test_only_lines(lines)
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            line_runtime_source = runtime_source and line_no not in test_only_lines
            for kind, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(Finding(rel, line_no, kind, stripped, line_runtime_source))

    counts: dict[tuple[str, bool], int] = {}
    for finding in findings:
        counts[(finding.kind, finding.runtime_source)] = counts.get((finding.kind, finding.runtime_source), 0) + 1

    print("== Runtime risk pattern summary ==")
    if not findings:
        print("clean")
        return 0

    for kind in sorted(PATTERNS):
        runtime_count = counts.get((kind, True), 0)
        test_count = counts.get((kind, False), 0)
        print(f"{kind:16} runtime={runtime_count:4} tests/examples={test_count:4}")

    print("\n== Findings ==")
    printed = 0
    for finding in findings:
        if printed >= args.max_lines:
            remaining = len(findings) - printed
            print(f"... truncated {remaining} additional finding(s)")
            break
        scope = "runtime" if finding.runtime_source else "test/example"
        print(f"{finding.rel_path}:{finding.line_no}: {finding.kind} [{scope}] {finding.line}")
        printed += 1

    runtime_findings = [finding for finding in findings if finding.runtime_source]
    if runtime_findings:
        print(
            "\nWARN: runtime-source risk patterns found. Replace with explicit error handling before release candidates.",
            file=sys.stderr,
        )
    if args.strict and runtime_findings:
        print("FAIL: --strict enabled and runtime-source risk patterns were found", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
