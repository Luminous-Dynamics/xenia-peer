#!/usr/bin/env python3
"""Report unsafe/FFI surfaces in Xenia Rust code.

This does not prove unsafety. It creates a small review queue for code that can
cross memory, OS, capture, input, or FFI privilege boundaries.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from xenia_scan_scope import cfg_test_only_lines, iter_repo_files

SKIP_PARTS = {
    ".git",
    ".claude",
    "_archive",
    "target",
    "dist",
    "pkg",
    "node_modules",
    "xenia-peer-state",
    "xenia-operator-agent-state",
}
TEST_PARTS = {"tests", "benches", "examples"}
PATTERNS = {
    "unsafe_block_or_fn": re.compile(r"\bunsafe\b"),
    "extern_block_or_fn": re.compile(r"\bextern\s+(?:\"[A-Za-z0-9_+-]+\"\s*)?(?:fn|\{)"),
    "static_mut": re.compile(r"\bstatic\s+mut\b"),
    "raw_pointer": re.compile(r"\*(?:const|mut)\s+[A-Za-z_:][A-Za-z0-9_:<>]*"),
    "ffi_repr": re.compile(r"#\[repr\((?:C|transparent)\)\]"),
}

@dataclass(frozen=True)
class Finding:
    rel_path: Path
    line_no: int
    kind: str
    line: str
    runtime_source: bool


def is_test_or_example(path: Path) -> bool:
    return bool(set(path.parts) & TEST_PARTS) or path.name.endswith("_test.rs")


def iter_rust_files(root: Path):
    for path in iter_repo_files(root, suffixes={".rs"}, skip_parts=SKIP_PARTS):
        yield path, path.relative_to(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia root")
    parser.add_argument("--strict", action="store_true", help="fail if runtime unsafe/FFI findings are present")
    parser.add_argument("--max-lines", type=int, default=200, help="maximum finding lines to print")
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
            if not stripped or stripped.startswith("//"):
                continue
            for kind, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rel,
                            line_no,
                            kind,
                            stripped,
                            runtime_source and line_no not in test_only_lines,
                        )
                    )

    counts: dict[tuple[str, bool], int] = {}
    for finding in findings:
        counts[(finding.kind, finding.runtime_source)] = counts.get((finding.kind, finding.runtime_source), 0) + 1

    print("== Unsafe / FFI surface summary ==")
    if not findings:
        print("clean")
        return 0

    for kind in sorted(PATTERNS):
        runtime_count = counts.get((kind, True), 0)
        test_count = counts.get((kind, False), 0)
        print(f"{kind:20} runtime={runtime_count:4} tests/examples={test_count:4}")

    print("\n== Findings ==")
    printed = 0
    for finding in findings:
        if printed >= args.max_lines:
            print(f"... truncated {len(findings) - printed} additional finding(s)")
            break
        scope = "runtime" if finding.runtime_source else "test/example"
        print(f"{finding.rel_path}:{finding.line_no}: {finding.kind} [{scope}] {finding.line}")
        printed += 1

    runtime_findings = [f for f in findings if f.runtime_source]
    if runtime_findings:
        print("\nWARN: runtime unsafe/FFI surfaces require review before RC1.", file=sys.stderr)
    if args.strict and runtime_findings:
        print("FAIL: --strict enabled and runtime unsafe/FFI findings were found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
