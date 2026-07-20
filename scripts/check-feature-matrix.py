#!/usr/bin/env python3
"""Ensure every declared Cargo feature has explicit CI or exception evidence."""

from __future__ import annotations

import pathlib
import sys
import tomllib


VALID_STATUSES = {"ci", "manual", "scaffold"}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    matrix_path = root / "xenia.features.toml"
    try:
        matrix = tomllib.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read feature matrix: {exc}")
        return 1

    failures: list[str] = []
    if matrix.get("schema") != 1:
        failures.append("xenia.features.toml schema must be 1")

    declared: set[tuple[str, str]] = set()
    for base in (root / "apps", root / "crates"):
        for manifest in sorted(base.glob("*/Cargo.toml")):
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            package = str(data["package"]["name"])
            for feature in data.get("features", {}):
                if feature != "default":
                    declared.add((package, str(feature)))

    registered: dict[tuple[str, str], dict] = {}
    for entry in matrix.get("feature", []):
        key = (str(entry.get("package", "")), str(entry.get("name", "")))
        if key in registered:
            failures.append(f"duplicate feature-matrix entry: {key[0]}:{key[1]}")
            continue
        registered[key] = entry
        status = entry.get("status")
        if status not in VALID_STATUSES:
            failures.append(f"{key[0]}:{key[1]} has invalid status {status!r}")
            continue
        if status == "ci":
            evidence = entry.get("evidence", [])
            if not evidence:
                failures.append(f"{key[0]}:{key[1]} is marked ci without evidence")
            for item in evidence:
                if "::" not in item:
                    failures.append(f"invalid evidence reference for {key[0]}:{key[1]}: {item!r}")
                    continue
                relative, needle = item.split("::", 1)
                path = root / relative
                if not path.is_file():
                    failures.append(f"feature evidence file is missing: {relative}")
                else:
                    haystack = " ".join(path.read_text(encoding="utf-8").split())
                    normalized_needle = " ".join(needle.split())
                    if normalized_needle not in haystack:
                        failures.append(
                            f"feature evidence missing for {key[0]}:{key[1]}: "
                            f"{relative} lacks {needle!r}"
                        )
        elif not str(entry.get("rationale", "")).strip():
            failures.append(f"{key[0]}:{key[1]} status {status} requires a rationale")

    for package, feature in sorted(declared - registered.keys()):
        failures.append(f"declared Cargo feature is unregistered: {package}:{feature}")
    for package, feature in sorted(registered.keys() - declared):
        failures.append(f"feature matrix contains stale entry: {package}:{feature}")

    if failures:
        for message in failures:
            fail(message)
        return 1

    counts = {status: 0 for status in VALID_STATUSES}
    for entry in registered.values():
        counts[str(entry["status"])] += 1
    print(
        "feature matrix: PASS "
        f"({len(declared)} features; {counts['ci']} CI, {counts['manual']} manual, "
        f"{counts['scaffold']} scaffold)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
