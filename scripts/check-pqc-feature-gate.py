#!/usr/bin/env python3
"""Validate the Xenia ledger PQC signature feature gate.

This check is intentionally static so it can run in lightweight release-review
contexts before a Rust toolchain is available. It complements, but does not
replace, `cargo test -p xenia-ledger --features pqc-signatures`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_LEDGER_FEATURE_TEST_COMMAND = (
    "cargo test -p xenia-ledger --features pqc-signatures --lib --no-fail-fast"
)
REQUIRED_PEER_FEATURE_TEST_COMMAND = (
    "cargo test -p xenia-peer --features pqc-signatures --no-fail-fast"
)


class CheckFailure(Exception):
    pass


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise CheckFailure(f"missing required PQC feature-gate file: {path}") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def require_regex(text: str, pattern: str, message: str) -> None:
    require(re.search(pattern, text, flags=re.MULTILINE) is not None, message)


def require_cfg_gated(source: str, declaration: str) -> None:
    """Require `declaration` to be immediately feature-gated.

    Rust attributes for these declarations should stay adjacent to the item so a
    later refactor cannot accidentally compile ML-DSA code into the default
    verifier surface. This intentionally uses direct substring matching instead
    of regex backtracking so the lightweight guard remains cheap in CI.
    """
    required = f'#[cfg(feature = "pqc-signatures")]\n{declaration}'
    require(required in source, f"missing pqc-signatures cfg gate for: {declaration}")


def require_cfg_gated_test(source: str, test_name: str) -> None:
    required = f'#[cfg(feature = "pqc-signatures")]\n    #[test]\n    fn {test_name}('
    require(
        required in source,
        f"feature test must stay cfg-gated and present: {test_name}",
    )


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(".")
    cargo_toml = read(root / "crates/xenia-ledger/Cargo.toml")
    ledger_src = read(root / "crates/xenia-ledger/src/lib.rs")
    peer_cargo_toml = read(root / "apps/xenia-peer/Cargo.toml")
    peer_main_src = read(root / "apps/xenia-peer/src/main.rs")
    ci_yml = read(root / ".github/workflows/xenia-validate.yml")

    require_regex(
        cargo_toml,
        r'^ml-dsa\s*=\s*\{[^\n}]*optional\s*=\s*true[^\n}]*\}',
        "ml-dsa must remain an optional dependency",
    )
    require_regex(
        cargo_toml,
        r'^default\s*=\s*\[\s*\]',
        "default features must remain empty; pqc-signatures must be opt-in",
    )
    require(
        'pqc-signatures = ["dep:ml-dsa"]' in cargo_toml,
        'pqc-signatures must explicitly enable only dep:ml-dsa',
    )
    require(
        'default = ["pqc-signatures"]' not in cargo_toml,
        'pqc-signatures must not be enabled by default',
    )

    require_cfg_gated(ledger_src, "pub struct MlDsa65EvidenceSignatureBackend;")
    require_cfg_gated(
        ledger_src,
        "impl EvidenceSignatureBackend for MlDsa65EvidenceSignatureBackend {",
    )
    require_cfg_gated(ledger_src, "pub struct MlDsa87EvidenceSignatureBackend;")
    require_cfg_gated(
        ledger_src,
        "impl EvidenceSignatureBackend for MlDsa87EvidenceSignatureBackend {",
    )
    require_cfg_gated(ledger_src, "fn verify_ml_dsa<P: MlDsaParams>(")
    require_cfg_gated(ledger_src, "pub const PQC_SIGNATURE_BACKEND_STATUS: &str =")

    for test_name in (
        "ml_dsa_65_backend_verifies_real_signature_bytes",
        "ml_dsa_65_backend_rejects_tampered_signature",
        "full_pqc_evidence_bundle_can_verify_with_ml_dsa_backend",
    ):
        require_cfg_gated_test(ledger_src, test_name)

    require(
        'pqc-signatures = ["xenia-ledger/pqc-signatures"]' in peer_cargo_toml,
        'xenia-peer pqc-signatures feature must propagate to xenia-ledger/pqc-signatures',
    )
    require(
        'EvidenceVerifierSuite' in peer_main_src
        and 'evidence_signature_suite' in peer_main_src
        and 'verify_evidence_bundle_with_selected_suite' in peer_main_src,
        'xenia-peer must expose an explicit evidence verifier suite selector',
    )
    require_regex(
        peer_main_src,
        r'require_evidence_profile:\s*Option<\s*EvidenceProfileRequirement\s*>',
        'xenia-peer verifier must expose exact profile requirement CLI field',
    )
    require_regex(
        peer_main_src,
        r'fn\s+preflight_evidence_verifier_selection\s*\(',
        'xenia-peer verifier must preflight manifest profile/suite before verification',
    )
    require_regex(
        peer_main_src,
        r'validate_required_profile_suite\(required_profile,\s*suite\)\?',
        'xenia-peer verifier must reject incompatible required profile / suite pairs before verification',
    )
    require_regex(
        peer_main_src,
        r'if\s+manifest\.downgrade_policy\s*!=\s*expected_downgrade_policy',
        'xenia-peer verifier must preflight downgrade_policy against required profile',
    )
    require_regex(
        peer_main_src,
        r'if\s+manifest\.transcript_signature\s*!=\s*selected_label',
        'xenia-peer verifier must bind transcript_signature to the requested verifier suite',
    )
    require_regex(
        peer_main_src,
        r'if\s+manifest\.ledger_signature\s*!=\s*selected_label',
        'xenia-peer verifier must bind ledger_signature to the requested verifier suite',
    )
    require(
        'MlDsa65EvidenceSignatureBackend' in peer_main_src
        and 'MlDsa87EvidenceSignatureBackend' in peer_main_src,
        'xenia-peer must wire ML-DSA evidence verifier backends behind its feature gate',
    )
    require_regex(
        peer_main_src,
        r'#\[cfg\(feature = "pqc-signatures"\)\]\s*use xenia_ledger::\{MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend\};',
        'xenia-peer ML-DSA backend imports must stay cfg-gated',
    )

    require(
        REQUIRED_LEDGER_FEATURE_TEST_COMMAND in ci_yml,
        "CI must compile/test the xenia-ledger pqc-signatures feature",
    )
    require(
        REQUIRED_PEER_FEATURE_TEST_COMMAND in ci_yml,
        "CI must compile/test the xenia-peer pqc-signatures verifier feature",
    )

    print("PQC feature gate check passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except CheckFailure as exc:
        print(f"PQC feature gate check failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
