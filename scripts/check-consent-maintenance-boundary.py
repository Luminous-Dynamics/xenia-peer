#!/usr/bin/env python3
"""Guard the consent-maintenance orchestration boundary.

This is intentionally a source-architecture check rather than a semantic Rust
parser.  Its job is to catch the specific regressions that previously made the
one-shot maintenance surface unsafe and difficult to review:

* an operation flag that is not represented by the typed selector;
* key loading before ambiguous-operation rejection;
* reintroduction of ad-hoc operation counters;
* reintroduction of local path-normalization helpers in ``main.rs``; and
* unpacking verified retention evidence back into unchecked path lookups.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"failed to read {path}: {exc}") from exc


def extract_variants(source: str) -> list[str]:
    match = re.search(
        r"pub\(crate\) enum OneShotOperation\s*\{(?P<body>.*?)^\}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise ValueError("OneShotOperation enum not found")
    return re.findall(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*,\s*$", match.group("body"), re.MULTILINE)


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    app = root / "apps/xenia-peer/src"
    main_path = app / "main.rs"
    maintenance_path = app / "consent_maintenance.rs"
    paths_path = app / "consent_artifact_paths.rs"

    failures: list[str] = []
    for path in (main_path, maintenance_path, paths_path):
        if not path.is_file():
            failures.append(f"required source module is missing: {path.relative_to(root)}")
    if failures:
        for message in failures:
            fail(message)
        return 1

    main_source = read(main_path)
    maintenance_source = read(maintenance_path)
    path_source = read(paths_path)

    for declaration in ("mod consent_maintenance;", "mod consent_artifact_paths;"):
        if declaration not in main_source:
            failures.append(f"main.rs must declare {declaration}")

    try:
        variants = extract_variants(maintenance_source)
    except ValueError as exc:
        failures.append(str(exc))
        variants = []

    if not variants:
        failures.append("OneShotOperation must contain at least one operation")
    if len(variants) != len(set(variants)):
        failures.append("OneShotOperation contains duplicate variant names")

    selector_start = maintenance_source.find("pub(crate) fn selected_one_shot_operations")
    selector_end = maintenance_source.find("pub(crate) fn validate_one_shot_selection")
    if selector_start < 0 or selector_end <= selector_start:
        failures.append("typed one-shot selector functions are missing or reordered")
        selector_source = ""
    else:
        selector_source = maintenance_source[selector_start:selector_end]

    impl_start = maintenance_source.find("impl OneShotOperation")
    impl_end = maintenance_source.find("fn push_if", impl_start)
    if impl_start < 0 or impl_end <= impl_start:
        failures.append("OneShotOperation family/flag implementation is missing")
        impl_source = ""
    else:
        impl_source = maintenance_source[impl_start:impl_end]

    for variant in variants:
        selected_count = selector_source.count(f"OneShotOperation::{variant}")
        if selected_count != 1:
            failures.append(
                f"OneShotOperation::{variant} must appear exactly once in the selector; found {selected_count}"
            )
        mapping_count = impl_source.count(f"Self::{variant}")
        if mapping_count != 2:
            failures.append(
                f"OneShotOperation::{variant} must have exactly one family and one flag mapping; found {mapping_count} mappings"
            )

    args_match = re.search(r"struct Args\s*\{(?P<body>.*?)^\}", main_source, re.MULTILINE | re.DOTALL)
    if args_match is None:
        failures.append("Args struct not found")
        operation_fields: set[str] = set()
    else:
        all_fields = set(
            re.findall(
                r"^\s{4}([a-z][a-z0-9_]*)\s*:\s*",
                args_match.group("body"),
                re.MULTILINE,
            )
        )
        operation_prefixes = (
            "sign_",
            "recover_",
            "verify_",
            "audit_",
            "export_",
            "quarantine_",
            "execute_",
            "activate_",
            "advance_",
        )
        operation_fields = {
            field
            for field in all_fields
            if field == "m1_runtime_smoke" or field.startswith(operation_prefixes)
        }

    selector_fields = set(re.findall(r"args\.([a-z][a-z0-9_]*)", selector_source))
    missing_fields = sorted(operation_fields - selector_fields)
    unexpected_fields = sorted(selector_fields - operation_fields)
    if missing_fields:
        failures.append(
            "operation-like Args fields missing from typed selector: " + ", ".join(missing_fields)
        )
    if unexpected_fields:
        failures.append(
            "typed selector references non-operation Args fields: " + ", ".join(unexpected_fields)
        )
    if operation_fields and len(operation_fields) != len(variants):
        failures.append(
            "operation Args field count does not match OneShotOperation variant count: "
            f"{len(operation_fields)} fields vs {len(variants)} variants"
        )
    for field in sorted(operation_fields):
        expected_flag = "--" + field.replace("_", "-")
        count = impl_source.count(f'"{expected_flag}"')
        if count != 1:
            failures.append(
                f"operation field {field} must have exactly one canonical flag mapping {expected_flag}; found {count}"
            )

    if "select exactly one one-shot operation per invocation" not in maintenance_source:
        failures.append("typed selector must fail closed on ambiguous invocations")
    if "rejects_cross_family_operations_before_dispatch" not in maintenance_source:
        failures.append("cross-family ambiguity regression test is missing")

    main_marker = "async fn main()"
    main_start = main_source.find(main_marker)
    if main_start < 0:
        failures.append("async main entry point not found")
        main_body = main_source
    else:
        main_body = main_source[main_start:]

    validation_pos = main_body.find("consent_maintenance::validate_one_shot_selection(&args)?")
    if validation_pos < 0:
        failures.append("main must validate the typed one-shot selection")
    key_positions = [
        pos
        for needle in ("load_existing_signing_key(", "load_or_create_signing_key(")
        if (pos := main_body.find(needle)) >= 0
    ]
    if validation_pos >= 0 and key_positions and validation_pos > min(key_positions):
        failures.append("ambiguous-operation validation must happen before any signing key is loaded")

    forbidden_main_patterns = {
        "operation_count": "ad-hoc operation counters must not return to main.rs",
        'expect("verified retention context requires': (
            "verified retention evidence must not be unpacked into unchecked Args lookups"
        ),
        "fn normalized_output_path(": "path normalization belongs in consent_artifact_paths.rs",
        "fn ensure_output_disjoint_from_inputs(": (
            "path-disjointness implementation belongs in consent_artifact_paths.rs"
        ),
    }
    for needle, message in forbidden_main_patterns.items():
        if needle in main_source:
            failures.append(message)

    required_context_fragments = (
        "struct VerifiedRetentionContext",
        "fn verified_retention_context(",
        "fn protect_output(",
        "consent_artifact_paths::ensure_output_disjoint_from_inputs(",
    )
    for fragment in required_context_fragments:
        if fragment not in main_source:
            failures.append(f"verified retention context boundary is missing: {fragment}")

    required_path_fragments = (
        "struct ProtectedPathSet",
        "std::fs::canonicalize",
        "normalized_output.starts_with(root)",
        "rejects_symlink_alias_of_protected_input",
    )
    for fragment in required_path_fragments:
        if fragment not in path_source:
            failures.append(f"canonical path guard is missing: {fragment}")

    if failures:
        for message in failures:
            fail(message)
        return 1

    print(
        "consent maintenance boundary: PASS "
        f"({len(variants)} typed one-shot operations; key loading follows ambiguity rejection)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
