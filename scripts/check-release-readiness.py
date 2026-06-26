#!/usr/bin/env python3
"""Validate Xenia release-train readiness manifests.

This is intentionally stricter about release process than about prototype code.
Normal mode verifies that the release train is coherent. `--rc1` additionally
fails while hard blockers remain or required RC docs are missing.
"""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

REQUIRED_GATE_TRUE = {
    "hygiene_required",
    "policy_required",
    "cargo_boundaries_required",
    "source_archive_required",
    "runtime_risk_report_required",
    "unsafe_surface_report_required",
    "consent_abuse_review_required",
    "threat_model_review_required",
    "fault_injection_plan_required",
    "observability_event_taxonomy_required",
}

REQUIRED_RC_DOCS = [
    "docs/release/RC1_CANDIDATE_CHECKLIST.md",
    "docs/security/THREAT_MODEL.md",
    "docs/security/CONSENT_AND_ABUSE_CASES.md",
    "docs/security/PRIVILEGE_BOUNDARIES.md",
    "docs/testing/FAULT_INJECTION_PLAN.md",
    "docs/observability/EVENT_TAXONOMY.md",
]


def load_toml(path: Path) -> dict:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"missing {path.name}") from None
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"invalid {path.name}: {exc}") from None


def as_non_empty_str_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia root")
    parser.add_argument("--rc1", action="store_true", help="enforce RC1-candidate blocking conditions")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    errors: list[str] = []
    warnings: list[str] = []

    try:
        policy = load_toml(root / "xenia.policy.toml")
        release = load_toml(root / "xenia.release.toml")
    except RuntimeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    project = policy.get("project", {})
    layout = policy.get("layout", {})
    train = release.get("release_train", {})
    gates = release.get("gates", {})
    blockers = release.get("blockers", {})
    milestones = release.get("milestone", [])

    if project.get("stage") != "pre-production":
        errors.append("xenia.policy.toml [project].stage must remain pre-production before explicit release-cut review")
    if train.get("manifest_version") != 1:
        errors.append("xenia.release.toml [release_train].manifest_version must be 1")
    if train.get("status") not in {"pre-rc", "rc", "released"}:
        errors.append("xenia.release.toml [release_train].status must be pre-rc, rc, or released")
    if not isinstance(train.get("current_milestone"), str) or not train.get("current_milestone"):
        errors.append("missing [release_train].current_milestone")
    if not isinstance(train.get("next_candidate"), str) or not train.get("next_candidate"):
        errors.append("missing [release_train].next_candidate")

    for gate in sorted(REQUIRED_GATE_TRUE):
        if gates.get(gate) is not True:
            errors.append(f"[gates].{gate} must be true")

    if not isinstance(milestones, list) or not milestones:
        errors.append("missing [[milestone]] entries")
        milestone_names: set[str] = set()
    else:
        milestone_names = set()
        for idx, milestone in enumerate(milestones, start=1):
            if not isinstance(milestone, dict):
                errors.append(f"milestone #{idx} is not a table")
                continue
            name = milestone.get("name")
            if not isinstance(name, str) or not name:
                errors.append(f"milestone #{idx} missing name")
                continue
            if name in milestone_names:
                errors.append(f"duplicate milestone: {name}")
            milestone_names.add(name)
            if milestone.get("kind") not in {"completed", "current", "planned", "candidate", "released"}:
                errors.append(f"milestone {name} has invalid kind")
            if not isinstance(milestone.get("summary"), str) or not milestone.get("summary"):
                errors.append(f"milestone {name} missing summary")
            if not as_non_empty_str_list(milestone.get("entry_criteria")):
                errors.append(f"milestone {name} missing non-empty entry_criteria")
            if not as_non_empty_str_list(milestone.get("exit_criteria")):
                errors.append(f"milestone {name} missing non-empty exit_criteria")

    current = train.get("current_milestone")
    next_candidate = train.get("next_candidate")
    if isinstance(current, str) and current not in milestone_names:
        errors.append(f"current milestone {current!r} is not listed in [[milestone]]")
    if isinstance(next_candidate, str) and next_candidate not in milestone_names:
        errors.append(f"next candidate {next_candidate!r} is not listed in [[milestone]]")

    hard_blockers = blockers.get("hard", [])
    soft_blockers = blockers.get("soft", [])
    if hard_blockers and not as_non_empty_str_list(hard_blockers):
        errors.append("[blockers].hard must be a string list")
    if soft_blockers and not as_non_empty_str_list(soft_blockers):
        errors.append("[blockers].soft must be a string list")

    if layout.get("mode") != "normalized":
        warnings.append("layout is not normalized yet; this is expected before normalization-v0.2")

    if args.rc1:
        if hard_blockers:
            errors.append("RC1 mode is blocked while [blockers].hard is non-empty")
        if layout.get("mode") != "normalized":
            errors.append("RC1 mode requires xenia.policy.toml [layout].mode = 'normalized'")
        for doc in REQUIRED_RC_DOCS:
            if not (root / doc).is_file():
                errors.append(f"RC1 required doc missing: {doc}")

    print("== Xenia release readiness ==")
    print(f"policy_stage: {project.get('stage')}")
    print(f"layout_mode: {layout.get('mode')}")
    print(f"release_status: {train.get('status')}")
    print(f"current_milestone: {current}")
    print(f"next_candidate: {next_candidate}")
    print(f"hard_blockers: {len(hard_blockers) if isinstance(hard_blockers, list) else 'invalid'}")
    print(f"soft_blockers: {len(soft_blockers) if isinstance(soft_blockers, list) else 'invalid'}")

    if warnings:
        print("\n== Warnings ==")
        for warning in warnings:
            print(f"WARN: {warning}")
    if errors:
        print("\n== Failures ==", file=sys.stderr)
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("\nRelease readiness manifest check passed.")
    if not args.rc1:
        print("Note: run with --rc1 only during an explicit release-candidate review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
