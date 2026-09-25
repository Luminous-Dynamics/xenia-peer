#!/usr/bin/env python3
"""Validate Xenia's exact local crypto-provider identity manifest.

This is an identity/provenance checker, not a cryptographic-security checker.
It uses only the Python standard library.
"""

from __future__ import annotations

import copy
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

SCHEMA = "xenia-crypto-provider-assurance-v1"
ASSURANCE_SCOPE = "identity-only"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MANIFEST_PATH = Path("docs/crypto/provider_assurance_v1.json")
LOCK_PATH = Path("Cargo.lock")


class AssuranceError(ValueError):
    pass


def fail(message: str) -> None:
    raise AssuranceError(message)


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def normalize_dep(spec: Any) -> dict[str, Any]:
    if isinstance(spec, str):
        return {"version": spec}
    if not isinstance(spec, dict):
        fail(f"unsupported dependency specification: {spec!r}")
    return dict(spec)


def compare_dep(actual_raw: Any, expected: dict[str, Any], subject: str) -> None:
    actual = normalize_dep(actual_raw)
    if actual.get("version") != expected.get("version"):
        fail(
            f"{subject}: version requirement drift: expected {expected.get('version')!r}, "
            f"found {actual.get('version')!r}"
        )

    expected_features = sorted(expected.get("features", []))
    actual_features = sorted(actual.get("features", []))
    if actual_features != expected_features:
        fail(
            f"{subject}: feature drift: expected {expected_features!r}, "
            f"found {actual_features!r}"
        )

    if "default_features" in expected:
        actual_default = actual.get("default-features", True)
        if actual_default is not expected["default_features"]:
            fail(
                f"{subject}: default-features drift: expected "
                f"{expected['default_features']!r}, found {actual_default!r}"
            )

    if "optional" in expected:
        actual_optional = actual.get("optional", False)
        if actual_optional is not expected["optional"]:
            fail(
                f"{subject}: optional drift: expected {expected['optional']!r}, "
                f"found {actual_optional!r}"
            )


def validate_manifest(root: Path, manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != SCHEMA:
        fail(f"manifest: unsupported schema {manifest.get('schema')!r}")
    if manifest.get("assurance_scope") != ASSURANCE_SCOPE:
        fail(
            "manifest: 001A assurance_scope must be exactly 'identity-only'; "
            f"found {manifest.get('assurance_scope')!r}"
        )

    external = manifest.get("external_assurance")
    if not isinstance(external, dict):
        fail("manifest: missing external_assurance object")
    if external.get("status") != "not-bound-in-001a":
        fail("manifest: external assurance must remain unbound in 001A")
    if external.get("successor") != "XEN-CRYPTO-FV-001B":
        fail("manifest: external assurance successor must be XEN-CRYPTO-FV-001B")

    lock_meta = manifest.get("lockfile")
    if not isinstance(lock_meta, dict):
        fail("manifest: missing lockfile metadata")
    if lock_meta.get("path") != str(LOCK_PATH):
        fail("manifest: lockfile path drift")
    if lock_meta.get("format_version") != 4:
        fail("manifest: Cargo.lock format_version must be 4")
    if lock_meta.get("registry_source") != REGISTRY_SOURCE:
        fail("manifest: registry source drift")

    lock = read_toml(root / LOCK_PATH)
    if lock.get("version") != 4:
        fail(f"Cargo.lock: expected format version 4, found {lock.get('version')!r}")
    packages = lock.get("package")
    if not isinstance(packages, list):
        fail("Cargo.lock: package list missing")

    providers = manifest.get("providers")
    if not isinstance(providers, list) or not providers:
        fail("manifest: providers must be a non-empty list")

    seen_identity: set[tuple[str, str]] = set()
    seen_names: set[str] = set()
    for provider in providers:
        if not isinstance(provider, dict):
            fail("manifest: provider entry must be an object")
        name = provider.get("name")
        version = provider.get("version")
        checksum = provider.get("checksum")
        source = provider.get("source")
        roles = provider.get("roles")
        if not all(isinstance(value, str) and value for value in [name, version, checksum, source]):
            fail(f"manifest: incomplete provider identity: {provider!r}")
        if not isinstance(roles, list) or not roles or not all(isinstance(role, str) and role for role in roles):
            fail(f"manifest: provider {name} must have non-empty roles")

        identity = (name, version)
        if identity in seen_identity:
            fail(f"manifest: duplicate provider identity {name} {version}")
        seen_identity.add(identity)
        if name in seen_names:
            # Multiple versions of a crate can exist in Cargo.lock, but this assurance
            # manifest intentionally selects exactly one security-relevant identity per name.
            fail(f"manifest: ambiguous duplicate provider name {name}")
        seen_names.add(name)

        matches = [
            package
            for package in packages
            if package.get("name") == name and package.get("version") == version
        ]
        if len(matches) != 1:
            fail(
                f"Cargo.lock: expected exactly one {name} {version} package, "
                f"found {len(matches)}"
            )
        package = matches[0]
        if package.get("source") != source:
            fail(
                f"Cargo.lock: {name} {version} source drift: expected {source!r}, "
                f"found {package.get('source')!r}"
            )
        if package.get("checksum") != checksum:
            fail(
                f"Cargo.lock: {name} {version} checksum drift: expected {checksum}, "
                f"found {package.get('checksum')}"
            )

        if name == "xenia-wire":
            expected_deps = provider.get("required_crypto_dependencies")
            if not isinstance(expected_deps, list) or not expected_deps:
                fail("manifest: xenia-wire required_crypto_dependencies missing")
            actual_deps = package.get("dependencies", [])
            missing = sorted(set(expected_deps) - set(actual_deps))
            if missing:
                fail(f"Cargo.lock: xenia-wire missing expected crypto dependencies: {missing}")

    direct_requirements = manifest.get("direct_requirements")
    if not isinstance(direct_requirements, list) or not direct_requirements:
        fail("manifest: direct_requirements missing")

    for requirement in direct_requirements:
        path = requirement.get("path")
        if not isinstance(path, str) or not path:
            fail("manifest: direct requirement path missing")
        cargo = read_toml(root / path)

        expected_deps = requirement.get("dependencies")
        if expected_deps is not None:
            actual_deps = cargo.get("dependencies")
            if not isinstance(actual_deps, dict):
                fail(f"{path}: dependencies table missing")
            for name, expected in expected_deps.items():
                if name not in actual_deps:
                    fail(f"{path}: required dependency {name!r} missing")
                compare_dep(actual_deps[name], expected, f"{path}:{name}")

        expected_features = requirement.get("features")
        if expected_features is not None:
            actual_features = cargo.get("features")
            if not isinstance(actual_features, dict):
                fail(f"{path}: features table missing")
            for name, expected in expected_features.items():
                if actual_features.get(name) != expected:
                    fail(
                        f"{path}: feature {name!r} drift: expected {expected!r}, "
                        f"found {actual_features.get(name)!r}"
                    )

        expected_workspace = requirement.get("workspace_dependencies")
        if expected_workspace is not None:
            workspace = cargo.get("workspace")
            if not isinstance(workspace, dict):
                fail(f"{path}: workspace table missing")
            actual_workspace = workspace.get("dependencies")
            if not isinstance(actual_workspace, dict):
                fail(f"{path}: workspace.dependencies table missing")
            for name, expected in expected_workspace.items():
                if name not in actual_workspace:
                    fail(f"{path}: workspace dependency {name!r} missing")
                compare_dep(actual_workspace[name], expected, f"{path}:workspace:{name}")


def run_negative_controls(root: Path, baseline: dict[str, Any]) -> None:
    def must_reject(name: str, mutant: dict[str, Any]) -> None:
        try:
            validate_manifest(root, mutant)
        except AssuranceError as exc:
            print(f"negative control rejected: {name}: {exc}")
        else:
            fail(f"negative control unexpectedly accepted: {name}")

    ml_kem = copy.deepcopy(baseline)
    next(p for p in ml_kem["providers"] if p["name"] == "ml-kem")["checksum"] = "0" * 64
    must_reject("ml-kem-checksum-substitution", ml_kem)

    ml_dsa = copy.deepcopy(baseline)
    next(p for p in ml_dsa["providers"] if p["name"] == "ml-dsa")["version"] = "0.1.0"
    must_reject("ml-dsa-version-substitution", ml_dsa)

    wire = copy.deepcopy(baseline)
    next(p for p in wire["providers"] if p["name"] == "xenia-wire")["checksum"] = "f" * 64
    must_reject("xenia-wire-checksum-substitution", wire)

    overclaim = copy.deepcopy(baseline)
    overclaim["assurance_scope"] = "formally-verified"
    must_reject("assurance-scope-overclaim", overclaim)


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    try:
        manifest = json.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))
        validate_manifest(root, manifest)
        run_negative_controls(root, manifest)
    except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError, KeyError, AssuranceError) as exc:
        print(f"crypto provider assurance check failed: {exc}", file=sys.stderr)
        return 1

    print("crypto provider assurance identity check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
