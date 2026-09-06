#!/usr/bin/env python3
"""Check Xenia secure-default invariants and low-noise risky literals.

This scanner is deliberately conservative. It does not prove Xenia is secure;
it catches the easiest mistakes that can productize a remote-control/capture
stack unsafely:

- privileged behavior enabled by default;
- consent bypass/fail-open strings;
- public bind addresses in source/config without explicit review;
- plaintext local URLs in source/config that should be reviewed before RC.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import fnmatch
import sys
import tomllib
from typing import Any

from xenia_scan_scope import (
    cfg_test_only_lines,
    iter_repo_files,
    rust_file_is_test_only,
)


@dataclass(frozen=True)
class Finding:
    severity: str
    path: str
    line: int
    pattern: str
    text: str


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "xenia.safety.toml"
    if not path.exists():
        fail("xenia.safety.toml is missing")
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        fail(f"xenia.safety.toml is invalid TOML: {exc}")


def require_bool(section: dict[str, Any], key: str, expected: bool) -> None:
    actual = section.get(key)
    if actual is not expected:
        fail(f"secure default {key} must be {expected!r}, found {actual!r}")


def validate_manifest(data: dict[str, Any]) -> None:
    manifest = data.get("manifest", {})
    if manifest.get("manifest_version") != 1:
        fail("xenia.safety.toml manifest_version must be 1")
    if manifest.get("stage") != "pre-production":
        fail("xenia.safety.toml stage must remain pre-production until an explicit release review")

    defaults = data.get("secure_defaults", {})
    require_bool(defaults, "remote_control_enabled_by_default", False)
    require_bool(defaults, "capture_enabled_by_default", False)
    require_bool(defaults, "injection_enabled_by_default", False)
    require_bool(defaults, "unattended_access_allowed", False)
    require_bool(defaults, "consent_required_for_privileged_sessions", True)
    require_bool(defaults, "consent_revocation_fail_closed", True)
    require_bool(defaults, "ledger_required_for_privileged_sessions", True)
    require_bool(defaults, "public_bind_requires_explicit_flag", True)
    require_bool(defaults, "plaintext_credentials_allowed", False)
    require_bool(defaults, "silent_session_start_allowed", False)
    if defaults.get("default_bind_address") not in {"127.0.0.1", "localhost", "::1"}:
        fail("default_bind_address must be loopback during pre-production")


def should_exclude(path: Path, rel: str, exclude_dirs: set[str], exclude_files: set[str]) -> bool:
    parts = set(path.parts)
    if parts.intersection(exclude_dirs):
        return True
    return rel in exclude_files


def is_allowed_public_bind(rel: str, allowed: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pattern) for pattern in allowed)


def is_reviewed_warning(rel: str, pattern: str, line: str, reviewed: list[dict[str, Any]]) -> bool:
    """Return true when a warning literal is intentionally reviewed.

    Reviewed warnings are for policy text, local-loopback development defaults,
    and test/example transport literals. They must remain precise: path, pattern,
    text match, and reason are all required so a broad file exclusion cannot hide
    new secure-default debt.
    """
    for entry in reviewed:
        path_pattern = entry.get("path")
        reviewed_pattern = entry.get("pattern")
        text_contains = entry.get("text_contains")
        reason = entry.get("reason")

        if not path_pattern or not reviewed_pattern or not text_contains or not reason:
            continue
        if not fnmatch.fnmatch(rel, path_pattern):
            continue
        if reviewed_pattern != pattern:
            continue
        if text_contains not in line:
            continue
        return True
    return False


def iter_files(root: Path, data: dict[str, Any]) -> list[Path]:
    scanner = data.get("scanner", {})
    source_exts = set(scanner.get("source_extensions", []))
    doc_exts = set(scanner.get("doc_extensions", []))
    exclude_dirs = set(scanner.get("exclude_dirs", []))
    exclude_files = set(scanner.get("exclude_files", []))
    paths: list[Path] = []
    for path in iter_repo_files(
        root,
        suffixes=source_exts | doc_exts,
        skip_parts=exclude_dirs,
    ):
        rel = path.relative_to(root).as_posix()
        if should_exclude(path.relative_to(root), rel, exclude_dirs, exclude_files):
            continue
        paths.append(path)
    return paths


def scan(root: Path, data: dict[str, Any]) -> list[Finding]:
    scanner = data.get("scanner", {})
    source_exts = set(scanner.get("source_extensions", []))
    doc_exts = set(scanner.get("doc_extensions", []))
    hard_patterns = data.get("review_required_patterns", {}).get("hard", [])
    warning_patterns = data.get("review_required_patterns", {}).get("warning", [])
    public_binds = set(data.get("network", {}).get("public_binds_requiring_review", []))
    allowed_public_bind_files = data.get("network", {}).get("allowed_public_bind_files", [])
    reviewed_warnings = data.get("reviewed_warnings", {}).get("entries", [])

    findings: list[Finding] = []
    for path in iter_files(root, data):
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            findings.append(Finding("warning", rel, 0, "unreadable", str(exc)))
            continue
        is_doc = path.suffix in doc_exts and path.suffix not in source_exts
        if path.suffix == ".rs" and rust_file_is_test_only(lines):
            continue
        test_only_lines = (
            cfg_test_only_lines(lines)
            if path.suffix == ".rs"
            else set()
        )
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            if idx in test_only_lines:
                continue
            for pattern in hard_patterns:
                if pattern in line:
                    severity = "warning" if is_doc else "hard"
                    if severity == "warning" and is_reviewed_warning(rel, pattern, line, reviewed_warnings):
                        continue
                    findings.append(Finding(severity, rel, idx, pattern, stripped[:180]))
            for pattern in warning_patterns:
                if pattern in line:
                    severity = "warning"
                    if pattern in public_binds and not is_doc and not is_allowed_public_bind(rel, allowed_public_bind_files):
                        severity = "hard"
                    if severity == "warning" and is_reviewed_warning(rel, pattern, line, reviewed_warnings):
                        continue
                    findings.append(Finding(severity, rel, idx, pattern, stripped[:180]))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.add_argument("--max-lines", type=int, default=200)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    data = load_manifest(root)
    validate_manifest(data)
    findings = scan(root, data)
    hard = [f for f in findings if f.severity == "hard"]
    warnings = [f for f in findings if f.severity == "warning"]

    print(f"secure-default scan: hard={len(hard)} warning={len(warnings)}")
    shown = 0
    for finding in findings:
        if shown >= args.max_lines:
            print(f"... truncated after {args.max_lines} findings")
            break
        print(f"{finding.severity.upper()}: {finding.path}:{finding.line}: {finding.pattern} :: {finding.text}")
        shown += 1

    if hard:
        fail("secure-default hard findings require review")
    if args.strict and warnings:
        fail("secure-default warnings require review in strict mode")
    print("secure-default check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
