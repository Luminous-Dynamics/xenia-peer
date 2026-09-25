#!/usr/bin/env python3
"""Validate the XEN-CRYPTO-FV-000 architecture contract.

Architecture gate only: this script does not execute cryptographic proofs.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/crypto/FORMAL_CRYPTO_VERIFICATION_ARCHITECTURE_V1.md"
REGISTRY = ROOT / "docs/crypto/formal_crypto_evidence_planes_v1.json"

EXPECTED_PLANES = {
    "P1": "PrimitiveProviderAssurance",
    "P2": "ProtocolSymbolicSecurity",
    "P3": "EncodingTranscriptRefinement",
    "P4": "StateMachineDeductiveProof",
    "P5": "CompiledSideChannelRuntimeBoundary",
}

REQUIRED_NON_EQUIVALENCES = {
    "primitive proof != protocol proof",
    "protocol proof != transcript/serialization proof",
    "transcript refinement != primitive security proof",
    "functional correctness != constant time",
    "source secret independence != compiler-preserved constant time",
    "cross-implementation conformance != primitive correctness",
    "symbolic theorem != concrete runtime refinement",
    "hybrid PQ transcript authentication != full-PQC system",
    "verified dependency != verified application",
    "formal verification != runtime authorization",
}

REQUIRED_TRACKERS = {
    "architecture": 395,
    "provider_inventory": 396,
    "transcript_refinement": 397,
    "protocol_tamarin": 398,
    "native_wasm_conformance": 399,
    "side_channel": 400,
    "profile_drift": 401,
}


def fail(message: str) -> None:
    raise SystemExit(f"formal-crypto-architecture-v1: FAIL: {message}")


def main() -> None:
    if not DOC.is_file():
        fail(f"missing {DOC.relative_to(ROOT)}")
    if not REGISTRY.is_file():
        fail(f"missing {REGISTRY.relative_to(ROOT)}")

    doc = DOC.read_text(encoding="utf-8")
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))

    if data.get("schema") != "xenia-formal-crypto-evidence-planes-v1":
        fail("unexpected registry schema")
    if data.get("status") != "architecture-only":
        fail("registry status must remain architecture-only in XEN-CRYPTO-FV-000")

    planes = data.get("planes")
    if not isinstance(planes, list):
        fail("planes must be a list")
    observed = {entry.get("id"): entry.get("name") for entry in planes}
    if observed != EXPECTED_PLANES:
        fail(f"plane census mismatch: {observed!r}")

    for entry in planes:
        for field in ("id", "name", "subjects", "requires", "nonclaims"):
            if field not in entry:
                fail(f"plane {entry.get('id')} missing {field}")
        if not entry["subjects"] or not entry["requires"] or not entry["nonclaims"]:
            fail(f"plane {entry['id']} has an empty contract field")

    non_eq = set(data.get("required_non_equivalences", []))
    missing_non_eq = REQUIRED_NON_EQUIVALENCES - non_eq
    if missing_non_eq:
        fail(f"missing non-equivalences: {sorted(missing_non_eq)!r}")

    trackers = data.get("initial_trackers")
    if trackers != REQUIRED_TRACKERS:
        fail(f"tracker map drift: {trackers!r}")

    required_doc_tokens = [
        "primitive proof",
        "protocol proof",
        "Tamarin",
        "Aeneas->Lean",
        "hax/F*",
        "Verus",
        "Kani",
        "TOFU",
        "first-contact",
        "forward-secrecy",
        "native/WASM",
        "bincode-v1",
        "mlkem-native",
        "libcrux",
        "HACL*/EverCrypt",
        "hybrid PQ transcript auth != full-PQC system",
        "verified dependency != verified application",
    ]
    missing_tokens = [token for token in required_doc_tokens if token not in doc]
    if missing_tokens:
        fail(f"architecture document missing tokens: {missing_tokens!r}")

    forbidden_promotion_phrases = [
        "Xenia is formally verified",
        "the Xenia cryptography is formally verified",
        "the compiled binary is verified",
        "full-PQC system is verified",
    ]
    bad = [phrase for phrase in forbidden_promotion_phrases if phrase in doc]
    if bad:
        fail(f"claim-promotion phrase present: {bad!r}")

    print("formal-crypto-architecture-v1: PASS")
    print(f"planes={len(planes)} non_equivalences={len(non_eq)} trackers={len(trackers)}")


if __name__ == "__main__":
    main()
