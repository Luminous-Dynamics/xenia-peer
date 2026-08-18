#!/usr/bin/env python3
"""Report and govern unsafe/FFI surfaces in Xenia Rust code.

Without a baseline this is the historical raw review report.

`--strict` preserves its original meaning: fail if *any* runtime unsafe/FFI
finding exists.

`--baseline FILE --strict-baseline` instead verifies that the runtime surface
matches an explicitly reviewed per-file/per-kind contract exactly. This is the
mode used by normal repository validation: legitimate OS/FFI boundaries remain
possible, but additions, removals, category changes, and new files require an
explicit baseline review.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
import sys
import tomllib

from xenia_scan_scope import cfg_test_only_lines, iter_repo_files


TEST_PARTS = {"tests", "benches", "examples"}

PATTERNS = {
    "unsafe_block_or_fn": re.compile(r"\bunsafe\b"),
    "extern_block_or_fn": re.compile(
        r'\bextern\s+(?:"[A-Za-z0-9_+-]+"\s*)?(?:fn|\{)'
    ),
    "static_mut": re.compile(r"\bstatic\s+mut\b"),
    "raw_pointer": re.compile(
        r"\*(?:const|mut)\s+[A-Za-z_:][A-Za-z0-9_:<>]*"
    ),
    "ffi_repr": re.compile(r"#\[repr\((?:C|transparent)\)\]"),
}

REQUIRED_REVIEW_FIELDS = (
    "owner",
    "rationale",
    "invariant",
    "evidence",
)


@dataclass(frozen=True)
class Finding:
    rel_path: Path
    line_no: int
    kind: str
    line: str
    runtime_source: bool


def is_test_or_example(path: Path) -> bool:
    return (
        bool(set(path.parts) & TEST_PARTS)
        or path.name.endswith("_test.rs")
    )


def iter_rust_files(root: Path):
    for path in iter_repo_files(root, suffixes={".rs"}):
        yield path, path.relative_to(root)


def load_baseline(
    path: Path,
) -> tuple[dict[tuple[Path, str], int], set[Path]]:
    with path.open("rb") as handle:
        document = tomllib.load(handle)

    if document.get("schema") != "xenia-unsafe-baseline-v1":
        raise ValueError(
            "baseline schema must be xenia-unsafe-baseline-v1"
        )

    surfaces = document.get("surface")
    if not isinstance(surfaces, list) or not surfaces:
        raise ValueError(
            "baseline must contain at least one [[surface]] entry"
        )

    expected: dict[tuple[Path, str], int] = {}
    reviewed_paths: set[Path] = set()

    for index, surface in enumerate(surfaces, start=1):
        if not isinstance(surface, dict):
            raise ValueError(
                f"surface #{index} must be a TOML table"
            )

        raw_path = surface.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError(
                f"surface #{index} requires non-empty path"
            )

        rel = Path(raw_path)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(
                f"surface #{index} path must be repository-relative: "
                f"{raw_path!r}"
            )

        if rel in reviewed_paths:
            raise ValueError(
                f"duplicate baseline surface path: {rel}"
            )
        reviewed_paths.add(rel)

        for field in REQUIRED_REVIEW_FIELDS:
            value = surface.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{rel}: reviewed surface requires non-empty "
                    f"{field}"
                )

        raw_counts = surface.get("counts")
        if not isinstance(raw_counts, dict):
            raise ValueError(
                f"{rel}: reviewed surface requires counts table"
            )

        unknown = sorted(
            set(raw_counts) - set(PATTERNS)
        )
        if unknown:
            raise ValueError(
                f"{rel}: unknown unsafe categories: {unknown}"
            )

        for kind in PATTERNS:
            value = raw_counts.get(kind, 0)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(
                    f"{rel}: {kind} count must be a non-negative "
                    "integer"
                )
            expected[(rel, kind)] = value

    return expected, reviewed_paths


def baseline_drift(
    expected: dict[tuple[Path, str], int],
    findings: list[Finding],
) -> tuple[
    Counter[tuple[Path, str]],
    list[tuple[Path, str, int, int]],
]:
    actual: Counter[tuple[Path, str]] = Counter(
        (finding.rel_path, finding.kind)
        for finding in findings
        if finding.runtime_source
    )

    keys = set(expected) | set(actual)

    drift = [
        (
            path,
            kind,
            expected.get((path, kind), 0),
            actual.get((path, kind), 0),
        )
        for path, kind in sorted(
            keys,
            key=lambda key: (str(key[0]), key[1]),
        )
        if expected.get((path, kind), 0)
        != actual.get((path, kind), 0)
    ]

    return actual, drift


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Xenia root",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "fail if any runtime unsafe/FFI finding exists "
            "(raw zero-unsafe audit)"
        ),
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help=(
            "reviewed unsafe baseline TOML; relative paths are "
            "resolved beneath root"
        ),
    )
    parser.add_argument(
        "--strict-baseline",
        action="store_true",
        help=(
            "fail if runtime unsafe/FFI counts differ from the "
            "reviewed baseline"
        ),
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=200,
        help="maximum finding lines to print",
    )
    args = parser.parse_args()

    if args.strict_baseline and args.baseline is None:
        parser.error(
            "--strict-baseline requires --baseline"
        )

    root = Path(args.root).resolve()
    findings: list[Finding] = []

    for path, rel in iter_rust_files(root):
        runtime_source = (
            "src" in rel.parts
            and not is_test_or_example(rel)
        )

        try:
            lines = path.read_text(
                encoding="utf-8"
            ).splitlines()
        except UnicodeDecodeError:
            continue

        test_only_lines = cfg_test_only_lines(lines)

        for line_no, line in enumerate(
            lines,
            start=1,
        ):
            stripped = line.strip()

            if (
                not stripped
                or stripped.startswith("//")
            ):
                continue

            for kind, pattern in PATTERNS.items():
                if not pattern.search(line):
                    continue

                findings.append(
                    Finding(
                        rel,
                        line_no,
                        kind,
                        stripped,
                        (
                            runtime_source
                            and line_no
                            not in test_only_lines
                        ),
                    )
                )

    counts: Counter[tuple[str, bool]] = Counter(
        (
            finding.kind,
            finding.runtime_source,
        )
        for finding in findings
    )

    print("== Unsafe / FFI surface summary ==")

    if not findings:
        print("clean")
    else:
        for kind in sorted(PATTERNS):
            runtime_count = counts.get(
                (kind, True),
                0,
            )
            test_count = counts.get(
                (kind, False),
                0,
            )
            print(
                f"{kind:20} "
                f"runtime={runtime_count:4} "
                f"tests/examples={test_count:4}"
            )

        print("\n== Findings ==")

        printed = 0

        for finding in findings:
            if printed >= args.max_lines:
                print(
                    "... truncated "
                    f"{len(findings) - printed} "
                    "additional finding(s)"
                )
                break

            scope = (
                "runtime"
                if finding.runtime_source
                else "test/example"
            )

            print(
                f"{finding.rel_path}:"
                f"{finding.line_no}: "
                f"{finding.kind} "
                f"[{scope}] "
                f"{finding.line}"
            )
            printed += 1

    runtime_findings = [
        finding
        for finding in findings
        if finding.runtime_source
    ]

    drift: list[
        tuple[Path, str, int, int]
    ] = []

    if args.baseline is not None:
        baseline_path = args.baseline

        if not baseline_path.is_absolute():
            baseline_path = root / baseline_path

        try:
            expected, reviewed_paths = load_baseline(
                baseline_path
            )
        except (
            OSError,
            tomllib.TOMLDecodeError,
            ValueError,
        ) as exc:
            print(
                f"FAIL: invalid unsafe baseline: {exc}",
                file=sys.stderr,
            )
            return 2

        actual, drift = baseline_drift(
            expected,
            findings,
        )

        print("\n== Reviewed unsafe baseline ==")

        runtime_total = sum(actual.values())
        actual_paths = {
            path
            for path, _kind in actual
            if sum(
                actual.get((path, kind), 0)
                for kind in PATTERNS
            )
            > 0
        }

        print(
            f"reviewed files={len(reviewed_paths)} "
            f"runtime findings={runtime_total}"
        )

        if drift:
            for (
                path,
                kind,
                expected_count,
                actual_count,
            ) in drift:
                if actual_count > expected_count:
                    status = "growth"
                else:
                    status = "stale-baseline"

                print(
                    "BASELINE-DRIFT: "
                    f"{status}: "
                    f"{path}: {kind}: "
                    f"expected={expected_count} "
                    f"actual={actual_count}"
                )
        else:
            print(
                "unsafe baseline matched exactly"
            )

        unreviewed_paths = (
            actual_paths - reviewed_paths
        )
        if unreviewed_paths:
            # This should already be represented by count
            # drift, but keep it explicit for operator UX.
            for path in sorted(
                unreviewed_paths,
                key=str,
            ):
                print(
                    "BASELINE-DRIFT: "
                    f"unreviewed runtime file: {path}"
                )

    if args.baseline is None and runtime_findings:
        print(
            "\nWARN: runtime unsafe/FFI surfaces "
            "require review before RC1.",
            file=sys.stderr,
        )

    if args.baseline is not None and drift:
        print(
            "\nWARN: reviewed unsafe/FFI baseline "
            "does not match runtime source.",
            file=sys.stderr,
        )

    if args.strict and runtime_findings:
        print(
            "FAIL: --strict enabled and runtime "
            "unsafe/FFI findings were found",
            file=sys.stderr,
        )
        return 1

    if args.strict_baseline and drift:
        print(
            "FAIL: --strict-baseline enabled and "
            "reviewed unsafe/FFI surface drifted",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
