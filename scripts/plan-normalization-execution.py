#!/usr/bin/env python3
"""Generate a deterministic execution plan for Xenia workspace normalization.

The plan is evidence, not execution. It records what would be archived/moved and
which Cargo workspace-member rewrites are expected. Use apply-normalization-execution.py
for an explicit dry-run/apply step.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import sys
import tomllib
from typing import Any

SKIP_DIR_NAMES = {".git", "target", "dist", "node_modules", "__pycache__"}
TEXT_CARGO = "Cargo.toml"


def rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / "xenia.normalization.toml"
    if not manifest_path.exists():
        fail("xenia.normalization.toml not found")
    with manifest_path.open("rb") as f:
        return tomllib.load(f)


def stable_hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_sha256(path: Path, limit_bytes: int) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > limit_bytes:
        return None
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def path_fingerprint(root: Path, path: Path, limit_bytes: int) -> dict[str, Any]:
    """Return deterministic-ish metadata without hashing huge build outputs."""
    exists = path.exists()
    info: dict[str, Any] = {"path": rel(root, path), "exists": exists}
    if not exists:
        return info
    if path.is_file():
        stat = path.stat()
        info.update(
            {
                "type": "file",
                "bytes": stat.st_size,
                "sha256": file_sha256(path, limit_bytes),
                "sha256_omitted_reason": "larger-than-limit" if stat.st_size > limit_bytes else None,
            }
        )
        return info
    if path.is_dir():
        files = 0
        dirs = 0
        total_bytes = 0
        sample: list[str] = []
        for current, dirnames, filenames in os.walk(path):
            current_path = Path(current)
            # Do not descend further into heavy/generated directories when the root itself is not that dir.
            if current_path != path:
                dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIR_NAMES]
            else:
                dirnames[:] = sorted(dirnames)
            dirs += len(dirnames)
            for filename in sorted(filenames):
                f = current_path / filename
                try:
                    total_bytes += f.stat().st_size
                except OSError:
                    pass
                files += 1
                if len(sample) < 20:
                    sample.append(rel(root, f))
        basis = json.dumps({"path": rel(root, path), "files": files, "dirs": dirs, "bytes": total_bytes, "sample": sample}, sort_keys=True)
        info.update({"type": "dir", "files": files, "dirs": dirs, "bytes": total_bytes, "sample": sample, "metadata_sha256": stable_hash_text(basis)})
        return info
    info["type"] = "other"
    return info


def is_under(path: Path, ancestor: Path) -> bool:
    try:
        path.resolve().relative_to(ancestor.resolve())
        return True
    except ValueError:
        return False


def find_archive_candidates(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    archive_root = root / manifest.get("normalization", {}).get("archive_root", "_archive")
    rules = manifest.get("archive_rule", [])
    actions: list[dict[str, Any]] = []
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        if is_under(current_path, archive_root):
            dirnames[:] = []
            continue
        # Visit dirs in deterministic order. Do not skip target/dist/.git because those are candidates.
        dirnames[:] = sorted(dirnames)
        filenames = sorted(filenames)
        entries = [(current_path / d, True) for d in dirnames] + [(current_path / f, False) for f in filenames]
        for entry, is_dir in entries:
            name = entry.name
            for rule in rules:
                pattern = str(rule.get("pattern", ""))
                if not pattern:
                    continue
                matched = name == pattern if is_dir else fnmatch.fnmatch(name, pattern)
                if matched:
                    destination_root = root / str(rule.get("destination"))
                    destination = destination_root / rel(root, entry)
                    actions.append(
                        {
                            "action": "archive",
                            "rule_id": rule.get("id"),
                            "reason": rule.get("reason"),
                            "source": rel(root, entry),
                            "target": rel(root, destination),
                            "source_kind": "dir" if is_dir else "file",
                            "exists": entry.exists(),
                        }
                    )
                    break
    actions.sort(key=lambda a: (a["action"], a["source"]))
    return actions


def planned_moves(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for move in manifest.get("move", []):
        source = root / str(move.get("source"))
        target = root / str(move.get("target"))
        actions.append(
            {
                "action": "move",
                "id": move.get("id"),
                "kind": move.get("kind"),
                "reason": move.get("reason"),
                "source": rel(root, source),
                "target": rel(root, target),
                "source_exists": source.exists(),
                "target_exists": target.exists(),
            }
        )
    actions.sort(key=lambda a: str(a.get("id", "")))
    return actions


def cargo_rewrite_actions(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    workspace = manifest.get("normalization", {}).get("workspace", "xenia-peer")
    cargo_path = root / workspace / TEXT_CARGO
    actions: list[dict[str, Any]] = []
    for move in manifest.get("move", []):
        source = str(move.get("source"))
        target = str(move.get("target"))
        source_member = source.removeprefix(f"{workspace}/")
        target_member = target.removeprefix(f"{workspace}/")
        actions.append(
            {
                "action": "rewrite_cargo_member",
                "cargo_toml": rel(root, cargo_path),
                "from": source_member,
                "to": target_member,
                "cargo_toml_exists": cargo_path.exists(),
            }
        )
    actions.sort(key=lambda a: a["from"])
    return actions


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a deterministic Xenia normalization execution plan.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--output", "-o", default="-", help="JSON output path, or '-' for stdout")
    parser.add_argument("--hash-limit-bytes", type=int, default=2_000_000, help="maximum file size to hash for evidence")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest = load_manifest(root)
    manifest_path = root / "xenia.normalization.toml"

    actions = []
    actions.extend(find_archive_candidates(root, manifest))
    actions.extend(planned_moves(root, manifest))
    actions.extend(cargo_rewrite_actions(root, manifest))

    evidence_paths: list[Path] = [manifest_path]
    for action in actions:
        if action["action"] in {"archive", "move"}:
            evidence_paths.append(root / action["source"])
    evidence = [path_fingerprint(root, p, args.hash_limit_bytes) for p in sorted(set(evidence_paths), key=lambda p: rel(root, p) if p.exists() else p.as_posix())]

    plan = {
        "schema": "xenia.normalization.execution-plan.v1",
        "root": str(root),
        "manifest": "xenia.normalization.toml",
        "manifest_sha256": file_sha256(manifest_path, args.hash_limit_bytes),
        "mode": "plan-only",
        "action_count": len(actions),
        "actions": actions,
        "evidence": evidence,
        "notes": [
            "This plan does not execute filesystem changes.",
            "Review archive and move actions before using apply-normalization-execution.py --apply.",
            "Generated target paths must not already exist unless a previous partial normalization is being reviewed.",
        ],
    }

    output = json.dumps(plan, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(output, end="")
    else:
        Path(args.output).write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
