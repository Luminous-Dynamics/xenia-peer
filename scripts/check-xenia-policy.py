#!/usr/bin/env python3
"""Validate the Xenia project policy manifest.

The policy manifest is deliberately small. It gives agents and CI one place to
check whether a tree is still pre-production, what safety posture is expected,
and which components are protocol/library/app boundaries.
"""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

REQUIRED_PROJECT_KEYS = {"name", "stage", "policy_version", "archive_root"}
REQUIRED_RELEASE_TRUE = {
    "source_archives_must_be_clean",
    "build_outputs_forbidden",
    "nested_git_forbidden",
    "absolute_workspace_paths_forbidden",
    "cargo_boundary_check_required",
    "runtime_risk_report_required",
    "consent_abuse_review_required",
    "threat_model_review_required",
}
REQUIRED_SECURITY_TRUE = {
    "consent_required_for_input",
    "consent_required_for_capture",
    "revocation_must_fail_closed",
    "ledger_required_for_privileged_sessions",
    "operator_auth_required",
    "pre_shared_dev_keys_forbidden_in_release",
}
VALID_COMPONENT_KINDS = {"protocol", "library", "app"}
REQUIRED_COMPONENTS = {
    "xenia-wire",
    "xenia-peer-core",
    "xenia-capture",
    "xenia-video",
    "xenia-handshake",
    "xenia-ledger",
    "xenia-transport-ws",
    "xenia-transport-quic",
    "xenia-inject",
    "xenia-peer",
    "xenia-viewer",
    "xenia-viewer-web",
    "sovereign-admin",
}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia root")
    parser.add_argument(
        "--allow-release-stage",
        action="store_true",
        help="allow project.stage other than pre-production; intended only for explicit release-cut reviews",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    policy_path = root / "xenia.policy.toml"
    errors: list[str] = []
    warnings: list[str] = []

    if not policy_path.is_file():
        print("FAIL: missing xenia.policy.toml", file=sys.stderr)
        return 1

    try:
        with policy_path.open("rb") as f:
            policy = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        print(f"FAIL: invalid xenia.policy.toml: {exc}", file=sys.stderr)
        return 1

    project = policy.get("project")
    if not isinstance(project, dict):
        fail(errors, "missing [project] table")
    else:
        missing = REQUIRED_PROJECT_KEYS - set(project)
        if missing:
            fail(errors, f"[project] missing keys: {', '.join(sorted(missing))}")
        if project.get("name") != "xenia":
            fail(errors, "[project].name must be 'xenia'")
        if not isinstance(project.get("policy_version"), int):
            fail(errors, "[project].policy_version must be an integer")
        if project.get("stage") != "pre-production" and not args.allow_release_stage:
            fail(errors, "[project].stage must remain 'pre-production' until an explicit release-cut review")

    layout = policy.get("layout")
    if not isinstance(layout, dict):
        fail(errors, "missing [layout] table")
    else:
        if layout.get("mode") not in {"transitional", "normalized"}:
            fail(errors, "[layout].mode must be 'transitional' or 'normalized'")
        for key in ("wire_roots", "peer_workspace_roots", "library_roots", "app_roots"):
            value = layout.get(key)
            if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
                fail(errors, f"[layout].{key} must be a non-empty string list")

    release = policy.get("release")
    if not isinstance(release, dict):
        fail(errors, "missing [release] table")
    else:
        for key in sorted(REQUIRED_RELEASE_TRUE):
            if release.get(key) is not True:
                fail(errors, f"[release].{key} must be true")

    security = policy.get("security")
    if not isinstance(security, dict):
        fail(errors, "missing [security] table")
    else:
        if security.get("remote_control_default") != "disabled":
            fail(errors, "[security].remote_control_default must be 'disabled' before release")
        for key in sorted(REQUIRED_SECURITY_TRUE):
            if security.get(key) is not True:
                fail(errors, f"[security].{key} must be true")

    components = policy.get("component")
    if not isinstance(components, list) or not components:
        fail(errors, "missing [[component]] entries")
        components = []

    seen: set[str] = set()
    for idx, component in enumerate(components, start=1):
        if not isinstance(component, dict):
            fail(errors, f"component #{idx} is not a table")
            continue
        name = component.get("name")
        kind = component.get("kind")
        if not isinstance(name, str) or not name:
            fail(errors, f"component #{idx} missing string name")
            continue
        if name in seen:
            fail(errors, f"duplicate component entry: {name}")
        seen.add(name)
        if kind not in VALID_COMPONENT_KINDS:
            fail(errors, f"component {name} has invalid kind: {kind!r}")
        if not isinstance(component.get("release_role"), str) or not component.get("release_role"):
            fail(errors, f"component {name} missing release_role")
        if kind in {"protocol", "library"} and component.get("may_depend_on_apps") is not False:
            fail(errors, f"component {name} must declare may_depend_on_apps = false")
        if kind == "protocol" and component.get("may_depend_on_product") is not False:
            fail(errors, f"protocol component {name} must declare may_depend_on_product = false")
        if kind == "app" and component.get("requires_consent_review") is not True:
            fail(errors, f"app component {name} must declare requires_consent_review = true")

    missing_components = REQUIRED_COMPONENTS - seen
    if missing_components:
        fail(errors, f"missing component entries: {', '.join(sorted(missing_components))}")

    print("== Xenia policy manifest ==")
    print(f"policy: {policy_path.relative_to(root)}")
    if isinstance(project, dict):
        print(f"stage: {project.get('stage')}")
        print(f"policy_version: {project.get('policy_version')}")
    print(f"components: {len(seen)}")

    if warnings:
        print("\n== Warnings ==")
        for warning in warnings:
            print(f"WARN: {warning}")

    if errors:
        print("\n== Failures ==", file=sys.stderr)
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("\nXenia policy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
