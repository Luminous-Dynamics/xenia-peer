#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from xenia_scan_scope import DEFAULT_SCAN_SKIP_PARTS


# These names are findings when they occur in the canonical checkout, so they
# must not themselves be treated as containers to skip. Other shared scanner
# exclusions (.claude, _archive, runtime state, etc.) are noncanonical
# containers whose contents must not contaminate normalization checks.
GENERATED_DIR_NAMES = {"target", "dist", "build", "node_modules"}
NONCANONICAL_CONTAINER_PARTS = (
    set(DEFAULT_SCAN_SKIP_PARTS) - GENERATED_DIR_NAMES
)


def is_beneath_noncanonical_container(path: Path) -> bool:
    return bool(
        set(path.parts[:-1]) & NONCANONICAL_CONTAINER_PARTS
    )


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

    failures = 0
    warnings = 0

    # Root .git is expected for a normal checkout.
    # Nested .git directories are not expected and should be archived.
    for path in root.rglob(".git"):
        path = path.resolve()
        if path == root / ".git":
            continue
        if is_beneath_noncanonical_container(
            path.relative_to(root)
        ):
            continue
        print(f"FAIL: nested Git metadata remains outside archive: {path.relative_to(root)}")
        failures += 1

    # Generated build output should not remain in active paths.
    generated_dirs = [
        root / "target",
        root / "dist",
        root / "build",
        root / "node_modules",
    ]

    for path in generated_dirs:
        if path.exists():
            print(f"FAIL: active generated/archive artifact remains outside archive: {path.relative_to(root)}")
            failures += 1

    # Also catch generated outputs under active apps/crates, but ignore _archive.
    for name in ("target", "dist", "build", "node_modules"):
        for path in root.rglob(name):
            if not path.is_dir():
                continue
            rel = path.relative_to(root)
            if is_beneath_noncanonical_container(rel):
                continue
            if path in generated_dirs:
                continue
            print(f"FAIL: active generated/archive artifact remains outside archive: {rel}")
            failures += 1

    expected_apps = [
        root / "apps" / "xenia-peer",
        root / "apps" / "xenia-viewer",
        root / "apps" / "sovereign-admin",
    ]

    for path in expected_apps:
        if path.exists():
            print(f"OK: normalized app path exists: {path.relative_to(root)}")
        else:
            print(f"WARN: normalized app path missing: {path.relative_to(root)}")
            warnings += 1

    print(f"post-normalization check completed: failures={failures} warnings={warnings}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
