#!/usr/bin/env python3
"""Validate the frozen mlkem-native test-oracle identity and claim ceiling."""

from __future__ import annotations

import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
MANIFEST_PATH = ROOT / "docs/crypto/mlkem_oracle_pin_v1.json"

EXPECTED = {
    "schema": "xenia-mlkem-oracle-pin-v1",
    "assurance_scope": "oracle-identity-and-boundary-only",
    "repository": "pq-code-package/mlkem-native",
    "tag": "v2.0.0",
    "commit": "d1b2fe782888bdb761a50336012923180be7f502",
    "parameter_set": "ML-KEM-768",
    "role": "test-only-independent-oracle",
    "api": ["keypair_derand", "enc_derand", "dec", "check_pk"],
    "error": "MLK_ERR_INVALID_PK",
    "dimensions": {
        "public_key_bytes": 1184,
        "ciphertext_bytes": 1088,
        "shared_secret_bytes": 32,
        "keygen_randomness_bytes": 64,
        "encapsulation_randomness_bytes": 32,
    },
}

FORBIDDEN_SCOPE_TOKENS = {
    "protocol-secure",
    "xenia-formally-verified",
    "production-qualified",
    "provider-equivalent",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def validate(data: dict, *, check_cargo: bool = True) -> None:
    if data.get("schema") != EXPECTED["schema"]:
        fail("oracle manifest schema drift")
    if data.get("assurance_scope") != EXPECTED["assurance_scope"]:
        fail("oracle assurance scope escalation/drift")

    oracle = data.get("oracle", {})
    for key in ("repository", "tag", "commit", "parameter_set", "role"):
        if oracle.get(key) != EXPECTED[key]:
            fail(f"oracle {key} drift")
    if oracle.get("production_dependency") is not False:
        fail("oracle must remain test-only, not a production dependency")

    if data.get("dimensions") != EXPECTED["dimensions"]:
        fail("ML-KEM-768 dimension drift")
    if data.get("required_public_api") != EXPECTED["api"]:
        fail("deterministic/public oracle API drift")
    if data.get("required_error_identity") != EXPECTED["error"]:
        fail("invalid-public-key error identity drift")

    boundary = data.get("documented_assurance_boundary", {})
    expected_portable = {"cbmc-memory-safety", "cbmc-type-safety"}
    expected_asm = {
        "hol-light-functional-correctness",
        "hol-light-memory-safety",
        "hol-light-secret-independent-timing",
    }
    if set(boundary.get("portable_c", [])) != expected_portable:
        fail("portable-C assurance boundary drift")
    if set(boundary.get("x86_64_aarch64_assembly", [])) != expected_asm:
        fail("assembly assurance boundary drift")

    exclusions = set(boundary.get("explicit_exclusions", []))
    required_exclusions = {
        "power-side-channels",
        "electromagnetic-side-channels",
        "speculative-microarchitectural-side-channels",
        "fault-injection",
        "xenia-protocol-security",
        "xenia-provider-equivalence",
        "xenia-production-authorization",
    }
    if not required_exclusions.issubset(exclusions):
        fail("oracle assurance exclusions weakened")

    serialized = json.dumps(data, sort_keys=True).lower()
    for token in FORBIDDEN_SCOPE_TOKENS:
        if token in serialized:
            fail(f"forbidden escalated claim token present: {token}")

    if check_cargo:
        offenders = []
        for cargo in ROOT.rglob("Cargo.toml"):
            # Ignore generated/build directories if any are present in a developer checkout.
            if any(part in {"target", ".git"} for part in cargo.parts):
                continue
            text = cargo.read_text(encoding="utf-8").lower()
            if "mlkem-native" in text or "mlkem_native" in text:
                offenders.append(str(cargo.relative_to(ROOT)))
        if offenders:
            fail("mlkem-native appeared in production Cargo manifests: " + ", ".join(offenders))


def negative_controls(data: dict) -> None:
    mutant = copy.deepcopy(data)
    mutant["oracle"]["commit"] = "0" * 40
    expect_reject(mutant, "commit substitution")

    mutant = copy.deepcopy(data)
    mutant["oracle"]["parameter_set"] = "ML-KEM-1024"
    expect_reject(mutant, "parameter-set substitution")

    mutant = copy.deepcopy(data)
    mutant["required_public_api"].remove("enc_derand")
    expect_reject(mutant, "deterministic API removal")

    mutant = copy.deepcopy(data)
    mutant["oracle"]["production_dependency"] = True
    expect_reject(mutant, "production promotion")

    mutant = copy.deepcopy(data)
    mutant["assurance_scope"] = "protocol-secure"
    expect_reject(mutant, "claim escalation")


def expect_reject(mutant: dict, name: str) -> None:
    try:
        validate(mutant, check_cargo=False)
    except AssertionError:
        return
    fail(f"negative control unexpectedly accepted: {name}")


def main() -> int:
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    validate(data)
    negative_controls(data)
    print("mlkem oracle pin v1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
