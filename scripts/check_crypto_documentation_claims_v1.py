#!/usr/bin/env python3
"""Guard authoritative crypto documentation against the scoped current-surface registry.

This checker is deliberately dependency-free. It does not infer cryptographic
security; it only prevents known current-state claims from drifting away from
`current_crypto_surface_v1.json`.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

REGISTRY = Path("docs/crypto/current_crypto_surface_v1.json")
CANONICAL = Path("docs/crypto/CANONICAL_HANDSHAKE_TRANSCRIPT.md")
MIGRATION = Path("docs/crypto/FULL_PQC_MIGRATION_PLAN.md")
HANDSHAKE_CARGO = Path("crates/xenia-handshake/Cargo.toml")


class ClaimError(ValueError):
    pass


def require(text: str, needle: str, subject: str) -> None:
    if needle not in text:
        raise ClaimError(f"{subject}: missing required current-state token: {needle!r}")


def forbid(text: str, needle: str, subject: str) -> None:
    if needle in text:
        raise ClaimError(f"{subject}: stale/forbidden current-state wording present: {needle!r}")


def validate_claims(root: Path, *, texts: dict[str, str] | None = None) -> None:
    registry = json.loads((root / REGISTRY).read_text(encoding="utf-8"))
    if registry.get("schema") != "xenia-current-crypto-surface-v1":
        raise ClaimError("registry: unexpected schema")

    native = registry["native_handshake"]
    ledger = registry["ledger_evidence_default"]
    aggregate = registry["aggregate"]
    auth = native["transcript_authentication"]

    if auth["mode"] != "all-of":
        raise ClaimError("registry: native transcript authentication must remain all-of")
    if auth["suites"] != ["ed25519-rfc8032", "ml-dsa-65-fips204"]:
        raise ClaimError("registry: native transcript authentication suite set drifted")
    if aggregate["full_pqc"] is not False:
        raise ClaimError("registry: aggregate full_pqc must remain false for this subject")

    if texts is None:
        texts = {
            "canonical": (root / CANONICAL).read_text(encoding="utf-8"),
            "migration": (root / MIGRATION).read_text(encoding="utf-8"),
            "cargo": (root / HANDSHAKE_CARGO).read_text(encoding="utf-8"),
        }

    canonical = texts["canonical"]
    migration = texts["migration"]
    cargo = texts["cargo"]

    require(canonical, native["profile"], "canonical transcript doc")
    require(canonical, auth["combined_label"], "canonical transcript doc")
    require(canonical, "Ed25519 valid\nAND\nML-DSA-65 valid", "canonical transcript doc")
    require(canonical, "host and viewer ML-DSA-65 public keys", "canonical transcript doc")
    require(canonical, ledger["policy_profile"], "canonical transcript evidence-boundary section")
    require(canonical, "full-PQC remains false", "canonical transcript doc")
    forbid(
        canonical,
        "transcript_signature = ed25519-rfc8032` for the current hybrid/pre-PQC build",
        "canonical transcript doc",
    )
    forbid(
        canonical,
        "current transcript\nsignature suite remains `ed25519-rfc8032`",
        "canonical transcript doc",
    )

    require(migration, native["profile"], "migration plan")
    require(migration, "mandatory Ed25519 AND ML-DSA-65 transcript authentication", "migration plan")
    require(migration, "WASM-capable viewer-side handshake implementation", "migration plan")
    require(migration, "stable `Chain::append` path remains Ed25519 by default", "migration plan")
    require(migration, ledger["policy_profile"], "migration plan")
    require(migration, "aggregate `full_pqc` remains false", "migration plan")
    forbid(migration, "native handshake done, browser not started", "migration plan")
    forbid(migration, "that work has not started", "migration plan")
    forbid(
        migration,
        "uses ML-KEM-768 for key establishment and Ed25519 for identity/transcript\nauthentication",
        "migration plan",
    )

    require(cargo, "ML-KEM-768", "xenia-handshake Cargo description")
    require(cargo, "Ed25519 + ML-DSA-65", "xenia-handshake Cargo description")
    require(cargo, native["profile"], "xenia-handshake Cargo description")
    require(cargo, "Full-PQC remains a separately gated future profile", "xenia-handshake Cargo description")
    forbid(cargo, "classical Ed25519 transcript authentication", "xenia-handshake Cargo description")


def run_negative_controls(root: Path) -> None:
    baseline = {
        "canonical": (root / CANONICAL).read_text(encoding="utf-8"),
        "migration": (root / MIGRATION).read_text(encoding="utf-8"),
        "cargo": (root / HANDSHAKE_CARGO).read_text(encoding="utf-8"),
    }

    mutants: list[tuple[str, dict[str, str]]] = []

    weakened = copy.deepcopy(baseline)
    weakened["canonical"] = weakened["canonical"].replace(
        "ed25519-rfc8032+ml-dsa-65-fips204", "ed25519-rfc8032"
    )
    mutants.append(("weaken-canonical-transcript-suite", weakened))

    browser_stale = copy.deepcopy(baseline)
    browser_stale["migration"] += "\nStatus: native handshake done, browser not started.\n"
    mutants.append(("reintroduce-browser-not-started", browser_stale))

    cargo_stale = copy.deepcopy(baseline)
    cargo_stale["cargo"] = cargo_stale["cargo"].replace(
        "mandatory Ed25519 + ML-DSA-65 transcript authentication",
        "classical Ed25519 transcript authentication",
    )
    mutants.append(("weaken-package-description", cargo_stale))

    for name, mutant in mutants:
        try:
            validate_claims(root, texts=mutant)
        except ClaimError as exc:
            print(f"negative control rejected: {name}: {exc}")
        else:
            raise ClaimError(f"negative control unexpectedly accepted: {name}")


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    try:
        validate_claims(root)
        run_negative_controls(root)
    except (OSError, KeyError, json.JSONDecodeError, ClaimError) as exc:
        print(f"crypto documentation claim guard failed: {exc}", file=sys.stderr)
        return 1
    print("crypto documentation claim guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
