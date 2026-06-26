#!/usr/bin/env python3
from __future__ import annotations

import sys
import tomllib
from pathlib import Path


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_under(path: str, prefix: str) -> bool:
    p = Path(path)
    return p == Path(prefix) or prefix in p.parts[:1] or str(p).startswith(prefix.rstrip("/") + "/")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    manifest = root / "xenia.normalization.toml"

    failures = 0
    warnings = 0

    if not manifest.exists():
        print(f"FAIL: missing normalization manifest: {manifest.relative_to(root)}")
        return 1

    data = tomllib.loads(manifest.read_text())

    moves = as_list(data.get("move")) + as_list(data.get("moves"))
    components = as_list(data.get("component")) + as_list(data.get("components"))
    archive_rules = as_list(data.get("archive_rule")) + as_list(data.get("archive_rules"))

    print("xenia normalization plan check")
    print(f"root: {root}")
    print(f"moves: {len(moves)}")
    print(f"archive_rules: {len(archive_rules)}")
    print(f"components: {len(components)}")

    for idx, move in enumerate(moves, start=1):
        if not isinstance(move, dict):
            continue

        move_id = move.get("id", f"move-{idx}")
        kind = move.get("kind", "")
        source = move.get("source", "")
        target = move.get("target", "")

        if kind == "app":
            if not is_under(target, "apps"):
                print(f"FAIL: move[{idx}] {move_id}: app target must be under apps: {target}")
                failures += 1

        source_path = root / source
        target_path = root / target

        if source and target:
            if source_path.exists() and not target_path.exists():
                print(f"OK: move[{idx}] {move_id}: pending move {source} -> {target}")
            elif not source_path.exists() and target_path.exists():
                print(f"OK: move[{idx}] {move_id}: already applied {target}")
            elif source_path.exists() and target_path.exists():
                print(f"WARN: move[{idx}] {move_id}: source and target both exist; review duplicate layout: {source} and {target}")
                warnings += 1
            else:
                print(f"FAIL: move[{idx}] {move_id}: neither source nor target exists: {source} -> {target}")
                failures += 1

    for idx, component in enumerate(components, start=1):
        if not isinstance(component, dict):
            continue

        name = component.get("id") or component.get("name") or f"component-{idx}"
        kind = component.get("kind", "")
        canonical = component.get("canonical_path", "")

        if not canonical:
            print(f"WARN: component[{idx}] {name}: no canonical_path declared")
            warnings += 1
            continue

        if kind in {"library", "lib", "crate"}:
            if not is_under(canonical, "crates"):
                print(f"FAIL: component[{idx}] {name}: library canonical_path must be under crates: {canonical}")
                failures += 1
        elif kind == "app":
            if not is_under(canonical, "apps"):
                print(f"FAIL: component[{idx}] {name}: app canonical_path must be under apps: {canonical}")
                failures += 1

        if not (root / canonical).exists():
            if component.get("external") is True:
                print(f"OK: component[{idx}] {name}: external component not present in this checkout: {canonical}")
            else:
                print(f"WARN: component[{idx}] {name}: canonical_path not present yet: {canonical}")
                warnings += 1

    if failures:
        return 1

    print(f"normalization plan check passed: warnings={warnings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
