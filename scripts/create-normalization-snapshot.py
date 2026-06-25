#!/usr/bin/env python3
"""Create a JSON snapshot before or after Xenia workspace normalization.

The snapshot is intentionally small and portable: it records planned move paths,
whether they exist, file counts, byte counts, and SHA-256 hashes for Cargo.toml
and package metadata files under each planned path. It does not store file data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

METADATA_FILES = {"Cargo.toml", "package.json", "Trunk.toml", "flake.nix", "README.md"}
SKIP_DIRS = {".git", "target", "dist", "node_modules", "__pycache__"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(path: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        base = Path(dirpath)
        for filename in filenames:
            yield base / filename


def summarize_path(root: Path, rel: str) -> dict:
    path = root / rel
    summary: dict = {"path": rel, "exists": path.exists(), "kind": "missing"}
    if not path.exists():
        return summary
    if path.is_file():
        summary.update({
            "kind": "file",
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
        return summary
    files = list(iter_files(path))
    summary.update({
        "kind": "directory",
        "file_count": len(files),
        "bytes": sum(f.stat().st_size for f in files if f.is_file()),
        "metadata": {},
    })
    metadata: dict[str, str] = {}
    for file_path in files:
        if file_path.name in METADATA_FILES:
            metadata[str(file_path.relative_to(root))] = sha256_file(file_path)
    summary["metadata"] = metadata
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("out", nargs="?", default="_archive/normalization-v0.2/normalization-snapshot.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest = tomllib.loads((root / "xenia.normalization.toml").read_text(encoding="utf-8"))
    paths: list[str] = []
    for move in manifest.get("move", []):
        paths.extend([move["source"], move["target"]])
    for component in manifest.get("component", []):
        paths.append(component["canonical_path"])
    paths = sorted(set(paths))

    snapshot = {
        "schema": "xenia.normalization.snapshot.v1",
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "root": str(root),
        "manifest_version": manifest.get("normalization", {}).get("manifest_version"),
        "paths": [summarize_path(root, rel) for rel in paths],
    }

    out = Path(args.out)
    if not out.is_absolute():
        out = root / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
