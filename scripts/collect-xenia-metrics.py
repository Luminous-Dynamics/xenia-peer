#!/usr/bin/env python3
"""Collect lightweight Xenia repository metrics as JSON.

Metrics are intentionally simple and dependency-free so they can be attached to
preflight reports and compared across stabilization passes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SKIP_PARTS = {".git", "_archive", "target", "dist", "pkg", "node_modules", "__pycache__"}
EXT_TO_KIND = {
    ".rs": "rust_files",
    ".toml": "toml_files",
    ".md": "markdown_files",
    ".sh": "shell_scripts",
    ".py": "python_scripts",
}


def skip(path: Path) -> bool:
    return bool(set(path.parts) & SKIP_PARTS)


def count_lines(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except UnicodeDecodeError:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    metrics: dict[str, object] = {
        "root": str(root),
        "counts": {
            "rust_files": 0,
            "toml_files": 0,
            "markdown_files": 0,
            "shell_scripts": 0,
            "python_scripts": 0,
            "cargo_manifests": 0,
            "total_tracked_text_lines": 0,
        },
        "components": [],
    }
    counts = metrics["counts"]  # type: ignore[assignment]

    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if skip(rel) or not path.is_file():
            continue
        kind = EXT_TO_KIND.get(path.suffix)
        if kind:
            counts[kind] += 1  # type: ignore[index]
            counts["total_tracked_text_lines"] += count_lines(path)  # type: ignore[index]
        if path.name == "Cargo.toml":
            counts["cargo_manifests"] += 1  # type: ignore[index]
            metrics["components"].append(str(rel.parent))  # type: ignore[index]

    metrics["components"] = sorted(metrics["components"])  # type: ignore[index]
    print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
