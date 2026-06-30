#!/usr/bin/env python3
"""Validate Xenia evidence crypto manifest fixtures.

This checker deliberately has no third-party dependencies. It enforces the
policy labels that make `full-pqc-v1` claims machine-checkable instead of relying on
human prose.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCHEMA = "xenia-evidence-crypto-manifest-v1"
REQUIRED_KEYS = {
    "schema",
    "profile",
    "kem",
    "transcript_signature",
    "ledger_signature",
    "hash_chain",
    "kdf",
    "aead",
    "downgrade_policy",
}

PQ_SIGNATURES = {
    "ml-dsa-65-fips204",
    "ml-dsa-87-fips204",
    "slh-dsa-fips205",
}
CLASSICAL_SIGNATURES = {"ed25519-rfc8032"}
ALL_SIGNATURES = PQ_SIGNATURES | CLASSICAL_SIGNATURES


def fail(message: str) -> None:
    raise ValueError(message)


def validate_manifest(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_KEYS - data.keys())
    extra = sorted(data.keys() - REQUIRED_KEYS)
    if missing:
        fail(f"{path}: missing keys: {', '.join(missing)}")
    if extra:
        fail(f"{path}: unexpected keys: {', '.join(extra)}")

    if data["schema"] != SCHEMA:
        fail(f"{path}: unsupported schema {data['schema']!r}")
    if not data["kem"].startswith("ml-kem-"):
        fail(f"{path}: kem must be ML-KEM for Xenia evidence")
    if data["transcript_signature"] not in ALL_SIGNATURES:
        fail(f"{path}: unknown transcript_signature {data['transcript_signature']!r}")
    if data["ledger_signature"] not in ALL_SIGNATURES:
        fail(f"{path}: unknown ledger_signature {data['ledger_signature']!r}")

    profile = data["profile"]
    downgrade_policy = data["downgrade_policy"]

    if profile == "hybrid-pre-pqc-v1":
        if downgrade_policy != "explicit-classical-signature-allowance":
            fail(f"{path}: hybrid-pre-pqc-v1 requires explicit classical allowance")
        return

    if profile == "full-pqc-v1":
        if downgrade_policy != "reject-classical-signatures":
            fail(f"{path}: full-pqc-v1 requires reject-classical-signatures")
        if data["transcript_signature"] not in PQ_SIGNATURES:
            fail(f"{path}: full-pqc-v1 rejects classical transcript signatures")
        if data["ledger_signature"] not in PQ_SIGNATURES:
            fail(f"{path}: full-pqc-v1 rejects classical ledger signatures")
        return

    fail(f"{path}: unsupported profile {profile!r}")


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    fixture_dir = root / "docs" / "crypto" / "fixtures"
    if not fixture_dir.is_dir():
        print(f"missing manifest fixture dir: {fixture_dir}", file=sys.stderr)
        return 1

    failures: list[str] = []
    manifests = sorted(fixture_dir.glob("*.manifest.json"))
    if not manifests:
        print(f"no manifest fixtures found in {fixture_dir}", file=sys.stderr)
        return 1

    for manifest in manifests:
        expect_invalid = ".invalid-" in manifest.name
        try:
            validate_manifest(manifest)
        except Exception as exc:  # noqa: BLE001 - dependency-free CLI checker.
            if expect_invalid:
                print(f"expected invalid manifest rejected: {manifest.name}: {exc}")
            else:
                failures.append(str(exc))
        else:
            if expect_invalid:
                failures.append(f"{manifest}: expected invalid manifest was accepted")
            else:
                print(f"manifest valid: {manifest.name}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print("evidence manifest check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
