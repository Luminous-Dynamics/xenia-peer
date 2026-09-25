#!/usr/bin/env python3
"""Validate Xenia's scoped current cryptographic-surface census.

Dependency-free by design. This is a source/profile drift gate, not a
cryptographic verifier.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

REGISTRY_REL = Path("docs/crypto/current_crypto_surface_v1.json")
HANDSHAKE_REL = Path("crates/xenia-handshake/src/lib.rs")
LEDGER_POLICY_REL = Path("crates/xenia-ledger/src/policy.rs")
LEDGER_SIGNATURE_REL = Path("crates/xenia-ledger/src/signature.rs")
LEDGER_CARGO_REL = Path("crates/xenia-ledger/Cargo.toml")

EXPECTED_SCHEMA = "xenia-current-crypto-surface-v1"
EXPECTED_HANDSHAKE = {
    "profile": "hybrid-pq-transcript-v1",
    "kem": "ml-kem-768-fips203",
    "combined_signature": "ed25519-rfc8032+ml-dsa-65-fips204",
    "suites": ["ed25519-rfc8032", "ml-dsa-65-fips204"],
    "kdf": "hkdf-sha256",
    "transcript_schema": "xenia-handshake-transcript-v1",
    "transcript_hash": "blake3-256",
}
EXPECTED_LEDGER_PROFILE = "hybrid-pre-pqc-v1"
EXPECTED_LEDGER_SIGNATURE = "ed25519-rfc8032"
EXPECTED_AGGREGATE_STATUS = "mixed-migration-v1"


class ContractError(ValueError):
    """A semantic mismatch in the current-crypto-surface contract."""


def fail(message: str) -> None:
    raise ContractError(message)


def read_text(root: Path, rel: Path) -> str:
    path = root / rel
    if not path.is_file():
        fail(f"missing required source: {rel}")
    return path.read_text(encoding="utf-8")


def rust_str_const(source: str, name: str) -> str:
    pattern = rf"(?:pub\s+)?const\s+{re.escape(name)}\s*:\s*&str\s*=\s*\"([^\"]+)\"\s*;"
    match = re.search(pattern, source)
    if not match:
        fail(f"could not find Rust &str constant {name}")
    return match.group(1)


def require_fragment(source: str, fragment: str, subject: str) -> None:
    if fragment not in source:
        fail(f"{subject}: required source fragment absent: {fragment!r}")


def extract_source_state(root: Path) -> dict:
    handshake = read_text(root, HANDSHAKE_REL)
    ledger_policy = read_text(root, LEDGER_POLICY_REL)
    ledger_signature = read_text(root, LEDGER_SIGNATURE_REL)
    ledger_cargo = read_text(root, LEDGER_CARGO_REL)

    handshake_state = {
        "profile": rust_str_const(handshake, "HANDSHAKE_POLICY_PROFILE"),
        "kem": rust_str_const(handshake, "KEM_SUITE_LABEL"),
        "combined_signature": rust_str_const(handshake, "TRANSCRIPT_SIGNATURE_SUITE_LABEL"),
        "classical_signature": rust_str_const(
            handshake, "CLASSICAL_TRANSCRIPT_SIGNATURE_SUITE_LABEL"
        ),
        "pq_signature": rust_str_const(handshake, "PQ_TRANSCRIPT_SIGNATURE_SUITE_LABEL"),
        "kdf": rust_str_const(handshake, "KDF_SUITE_LABEL"),
        "transcript_schema": rust_str_const(handshake, "HANDSHAKE_TRANSCRIPT_SCHEMA"),
        "transcript_hash": rust_str_const(
            handshake, "HANDSHAKE_TRANSCRIPT_HASH_ALGORITHM"
        ),
    }
    require_fragment(
        handshake,
        "transcript_signature_post_quantum: true",
        str(HANDSHAKE_REL),
    )
    require_fragment(
        handshake,
        'Self::HybridPqTranscriptV1 => "hybrid-pq-transcript-v1"',
        str(HANDSHAKE_REL),
    )

    require_fragment(
        ledger_policy,
        'policy_profile: "hybrid-pre-pqc-v1"',
        str(LEDGER_POLICY_REL),
    )
    require_fragment(
        ledger_policy,
        "profile: CryptoPolicyProfile::HybridPrePqcV1",
        str(LEDGER_POLICY_REL),
    )
    require_fragment(
        ledger_policy,
        "transcript_signature: SignatureSuite::Ed25519Rfc8032",
        str(LEDGER_POLICY_REL),
    )
    require_fragment(
        ledger_signature,
        "CURRENT_LEDGER_SIGNATURE_SUITE: SignatureSuite = SignatureSuite::Ed25519Rfc8032",
        str(LEDGER_SIGNATURE_REL),
    )
    require_fragment(
        ledger_cargo,
        'ml-dsa = { version = "0.1.1", optional = true',
        str(LEDGER_CARGO_REL),
    )
    require_fragment(
        ledger_cargo,
        'pqc-signatures = ["dep:ml-dsa"]',
        str(LEDGER_CARGO_REL),
    )

    return {
        "handshake": handshake_state,
        "ledger_profile": EXPECTED_LEDGER_PROFILE,
        "ledger_signature": EXPECTED_LEDGER_SIGNATURE,
        "optional_pq_feature": "pqc-signatures",
    }


def validate_registry(data: dict, source_state: dict) -> None:
    if data.get("schema") != EXPECTED_SCHEMA:
        fail(f"unsupported registry schema: {data.get('schema')!r}")
    if data.get("subject_scope") != "source-declared-current-state":
        fail("registry subject_scope must remain source-declared-current-state")

    native = data.get("native_handshake")
    if not isinstance(native, dict):
        fail("native_handshake must be an object")
    if native.get("repository") != "Luminous-Dynamics/xenia-peer":
        fail("native_handshake repository drift")
    if native.get("source") != str(HANDSHAKE_REL):
        fail("native_handshake source drift")

    auth = native.get("transcript_authentication")
    if not isinstance(auth, dict):
        fail("native transcript_authentication must be an object")
    if auth.get("mode") != "all-of":
        fail("current native handshake authentication must remain all-of")

    actual_hs = source_state["handshake"]
    comparisons = {
        "profile": (native.get("profile"), actual_hs["profile"]),
        "kem": (native.get("kem"), actual_hs["kem"]),
        "combined transcript signature": (
            auth.get("combined_label"),
            actual_hs["combined_signature"],
        ),
        "kdf": (native.get("kdf"), actual_hs["kdf"]),
        "transcript schema": (
            native.get("transcript_schema"),
            actual_hs["transcript_schema"],
        ),
        "transcript hash": (
            native.get("transcript_hash"),
            actual_hs["transcript_hash"],
        ),
    }
    for label, (declared, actual) in comparisons.items():
        if declared != actual:
            fail(f"native handshake {label} drift: registry={declared!r} source={actual!r}")

    expected_suites = [actual_hs["classical_signature"], actual_hs["pq_signature"]]
    if auth.get("suites") != expected_suites:
        fail(
            "native handshake suite census drift: "
            f"registry={auth.get('suites')!r} source={expected_suites!r}"
        )
    if native.get("full_pqc") is not False:
        fail("native handshake must not be classified full_pqc under current subject")

    wasm = data.get("wasm_viewer_handshake")
    if not isinstance(wasm, dict):
        fail("wasm_viewer_handshake must be an object")
    if wasm.get("repository") != "Luminous-Dynamics/xenia-wire":
        fail("WASM viewer repository identity drift")
    if wasm.get("relationship") != "external-cross-repo-conformance-required":
        fail("WASM viewer must remain explicitly external-cross-repo")
    if wasm.get("locally_proven") is not False:
        fail("external xenia-wire handshake must not be labeled locally_proven")
    if wasm.get("expected_profile") != native.get("profile"):
        fail("WASM expected handshake profile must match native profile expectation")
    wasm_auth = wasm.get("expected_transcript_authentication", {})
    if wasm_auth.get("mode") != "all-of" or wasm_auth.get("suites") != expected_suites:
        fail("WASM expected transcript-authentication contract drift")

    ledger = data.get("ledger_evidence_default")
    if not isinstance(ledger, dict):
        fail("ledger_evidence_default must be an object")
    if ledger.get("policy_profile") != source_state["ledger_profile"]:
        fail("ledger/evidence policy profile drift")
    if ledger.get("default_evidence_transcript_signature") != EXPECTED_LEDGER_SIGNATURE:
        fail("default evidence transcript-signature artifact drift")
    if ledger.get("default_ledger_signature") != source_state["ledger_signature"]:
        fail("default ledger signature drift")
    if ledger.get("hash_chain") != "blake3-256":
        fail("default ledger hash-chain drift")
    if ledger.get("full_pqc") is not False:
        fail("default ledger/evidence path must not be classified full_pqc")

    optional = ledger.get("optional_pq_backend")
    if not isinstance(optional, dict):
        fail("optional_pq_backend must be an object")
    if optional.get("feature") != source_state["optional_pq_feature"]:
        fail("optional PQ backend feature drift")
    if optional.get("provider") != "ml-dsa":
        fail("optional PQ backend provider drift")
    if optional.get("changes_default_append_path") is not False:
        fail("optional PQ backend must not claim to change the default append path")

    if native.get("profile") == ledger.get("policy_profile"):
        fail("handshake and ledger/evidence profiles were collapsed into one profile")

    aggregate = data.get("aggregate")
    if not isinstance(aggregate, dict):
        fail("aggregate must be an object")
    if aggregate.get("status") != EXPECTED_AGGREGATE_STATUS:
        fail("aggregate status drift")
    if aggregate.get("full_pqc") is not False:
        fail("aggregate full_pqc must remain false under current source subject")

    required_non_equivalences = {
        "handshake profile != ledger/evidence profile",
        "hybrid PQ transcript authentication != full-PQC authority",
        "optional PQ evidence backend != PQ default ledger append",
        "external cross-repository implementation claim != local source proof",
        "source/profile consistency != cryptographic security theorem",
    }
    actual_non_equivalences = set(data.get("non_equivalences", []))
    missing = sorted(required_non_equivalences - actual_non_equivalences)
    if missing:
        fail(f"missing required non-equivalences: {missing}")


def expect_mutant_rejected(name: str, data: dict, source_state: dict) -> None:
    try:
        validate_registry(data, source_state)
    except ContractError as exc:
        print(f"expected mutant rejected [{name}]: {exc}")
        return
    fail(f"negative control unexpectedly accepted: {name}")


def run_negative_controls(canonical: dict, source_state: dict) -> None:
    mutant = copy.deepcopy(canonical)
    mutant["native_handshake"]["transcript_authentication"]["combined_label"] = (
        "ed25519-rfc8032"
    )
    expect_mutant_rejected("weaken-handshake-suite", mutant, source_state)

    mutant = copy.deepcopy(canonical)
    mutant["ledger_evidence_default"]["default_ledger_signature"] = "ml-dsa-65-fips204"
    expect_mutant_rejected("relabel-default-ledger-pq", mutant, source_state)

    mutant = copy.deepcopy(canonical)
    mutant["ledger_evidence_default"]["policy_profile"] = mutant["native_handshake"]["profile"]
    expect_mutant_rejected("collapse-surface-profiles", mutant, source_state)

    mutant = copy.deepcopy(canonical)
    mutant["aggregate"]["full_pqc"] = True
    expect_mutant_rejected("premature-full-pqc", mutant, source_state)


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(".").resolve()
    registry_path = root / REGISTRY_REL
    if not registry_path.is_file():
        print(f"missing registry: {REGISTRY_REL}", file=sys.stderr)
        return 1

    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        source_state = extract_source_state(root)
        validate_registry(registry, source_state)
        print("current crypto surface canonical contract: PASS")
        run_negative_controls(registry, source_state)
        print("current crypto surface negative controls: PASS")
    except (ContractError, json.JSONDecodeError) as exc:
        print(f"current crypto surface validation failed: {exc}", file=sys.stderr)
        return 1

    print("current crypto surface v1 validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
