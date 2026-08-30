#!/usr/bin/env python3
"""Check Xenia Cargo path dependencies for workspace-boundary violations.

This script intentionally uses only the Python standard library. It is safe to
run before Rust/Nix tooling is available.
"""
from __future__ import annotations

import argparse
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from xenia_scan_scope import iter_repo_files

WIRE_CRATE = "xenia-wire"
WIRE_SUPPORT_CRATES = {"xenia-wire-fuzz"}
TOOL_CRATES = {"xenia-peer-fuzz"}
APP_CRATES = {
    "sovereign-admin",
    "xenia-launcher-linux",
    "xenia-launcher-macos",
    "xenia-launcher-windows",
    "xenia-operator-agent",
    "xenia-peer",
    "xenia-viewer",
    "xenia-viewer-web",
}
LIBRARY_CRATES = {
    "xenia-peer-core",
    "xenia-secure-file",
    "xenia-capture",
    "xenia-capture-scrcpy",
    "xenia-exec-proto",
    "xenia-video",
    "xenia-handshake",
    "xenia-ledger",
    "xenia-mobile-ffi",
    "xenia-operation-proto",
    "xenia-operation-receipt-proto",
    "xenia-operator-agent-proto",
    "xenia-operator-proto",
    "xenia-transport-ws",
    "xenia-transport-quic",
    "xenia-inject",
    "xenia-launcher-core",
    "xenia-launcher-shell",
    "xenia-zk-protocol",
    "xenia-zk-codec",
    "xenia-zk-auth",
    "xenia-zk-legacy-mycelix",
}
KNOWN_XENIA_CRATES = {
    WIRE_CRATE,
    *WIRE_SUPPORT_CRATES,
    *TOOL_CRATES,
    *APP_CRATES,
    *LIBRARY_CRATES,
}


@dataclass(frozen=True)
class CargoPackage:
    name: str
    manifest: Path
    rel_manifest: Path
    data: dict


def iter_manifest_paths(root: Path) -> Iterable[Path]:
    for manifest in iter_repo_files(root, suffixes={".toml"}):
        if manifest.name == "Cargo.toml":
            yield manifest


def load_package(root: Path, manifest: Path) -> CargoPackage | None:
    try:
        with manifest.open("rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        print(f"FAIL: invalid TOML: {manifest.relative_to(root)}: {exc}", file=sys.stderr)
        return CargoPackage("<invalid>", manifest, manifest.relative_to(root), {})

    package = data.get("package")
    if not isinstance(package, dict):
        return None
    name = package.get("name")
    if not isinstance(name, str):
        print(f"FAIL: package without string name: {manifest.relative_to(root)}", file=sys.stderr)
        return CargoPackage("<unknown>", manifest, manifest.relative_to(root), data)
    return CargoPackage(name, manifest, manifest.relative_to(root), data)


def dependency_tables(data: dict) -> Iterable[tuple[str, dict]]:
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            yield key, value

    target = data.get("target")
    if isinstance(target, dict):
        for target_name, target_data in target.items():
            if not isinstance(target_data, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target_data.get(key)
                if isinstance(value, dict):
                    yield f"target.{target_name}.{key}", value


def package_path(root: Path, package: CargoPackage, dep_spec: object) -> Path | None:
    if not isinstance(dep_spec, dict):
        return None
    dep_path = dep_spec.get("path")
    if not isinstance(dep_path, str):
        return None
    expanded = os.path.expanduser(dep_path)
    if os.path.isabs(expanded):
        return Path(expanded)
    return (package.manifest.parent / expanded).resolve()


def is_within(path: Path, maybe_parent: Path) -> bool:
    try:
        path.relative_to(maybe_parent)
        return True
    except ValueError:
        return False


def classify(package: CargoPackage) -> str:
    if package.name == WIRE_CRATE:
        return "wire"
    if package.name in WIRE_SUPPORT_CRATES:
        return "wire-support"
    if package.name in TOOL_CRATES:
        return "tool"
    if package.name in APP_CRATES:
        return "app"
    if package.name in LIBRARY_CRATES:
        return "library"
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="workspace root to check")
    parser.add_argument(
        "--strict-unknown",
        action="store_true",
        help="fail on unknown Xenia-ish package names instead of warning",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"FAIL: root is not a directory: {root}", file=sys.stderr)
        return 2

    packages: list[CargoPackage] = []
    failures: list[str] = []
    warnings: list[str] = []

    for manifest in sorted(iter_manifest_paths(root)):
        pkg = load_package(root, manifest)
        if pkg is None:
            continue
        if pkg.name in {"<invalid>", "<unknown>"}:
            failures.append(f"invalid package manifest: {pkg.rel_manifest}")
        packages.append(pkg)

    by_name = {pkg.name: pkg for pkg in packages}

    for pkg in packages:
        pkg_kind = classify(pkg)
        if pkg.name.startswith("xenia") or pkg.name == "sovereign-admin":
            if pkg.name not in KNOWN_XENIA_CRATES:
                msg = f"unknown Xenia package '{pkg.name}' at {pkg.rel_manifest}; update boundary map if intentional"
                (failures if args.strict_unknown else warnings).append(msg)

        for table_name, table in dependency_tables(pkg.data):
            for dep_name, dep_spec in table.items():
                dep_path = package_path(root, pkg, dep_spec)
                if dep_path is None:
                    continue

                spec_path = dep_spec.get("path") if isinstance(dep_spec, dict) else None
                if isinstance(spec_path, str) and os.path.isabs(os.path.expanduser(spec_path)):
                    failures.append(
                        f"{pkg.name} {table_name}.{dep_name} uses absolute path '{spec_path}' in {pkg.rel_manifest}"
                    )

                if not is_within(dep_path, root):
                    failures.append(
                        f"{pkg.name} {table_name}.{dep_name} points outside workspace: {spec_path!r} in {pkg.rel_manifest}"
                    )

                dep_pkg = by_name.get(dep_name)
                dep_kind = classify(dep_pkg) if dep_pkg else ("wire" if dep_name == WIRE_CRATE else "unknown")

                if pkg.name == WIRE_CRATE and dep_name in KNOWN_XENIA_CRATES - {WIRE_CRATE}:
                    failures.append(
                        f"xenia-wire must not depend on product/runtime crate {dep_name} ({pkg.rel_manifest})"
                    )

                if pkg_kind == "library" and dep_name in APP_CRATES:
                    failures.append(
                        f"library crate {pkg.name} must not depend on app crate {dep_name} ({pkg.rel_manifest})"
                    )

                if pkg_kind == "app" and dep_kind == "app" and dep_name != pkg.name:
                    warnings.append(
                        f"app crate {pkg.name} depends on app crate {dep_name}; verify this is intentional ({pkg.rel_manifest})"
                    )

    print("== Cargo boundary packages ==")
    if packages:
        for pkg in sorted(packages, key=lambda p: str(p.rel_manifest)):
            print(f"{pkg.name:24} {classify(pkg):8} {pkg.rel_manifest}")
    else:
        print("no Cargo packages found")

    if warnings:
        print("\n== Warnings ==")
        for warning in warnings:
            print(f"WARN: {warning}")

    if failures:
        print("\n== Failures ==", file=sys.stderr)
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print("\nCargo boundary check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
