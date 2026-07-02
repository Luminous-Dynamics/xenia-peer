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
ALLOWED_KEMS = {"ml-kem-768-fips203"}
ALLOWED_HASH_CHAINS = {"blake3-256"}
ALLOWED_KDFS = {"hkdf-sha256"}
ALLOWED_AEADS = {"chacha20-poly1305"}

REQUIRED_VALID_FIXTURES = {
    "hybrid-pre-pqc-v1.manifest.json",
    "full-pqc-v1.valid.manifest.json",
}
REQUIRED_INVALID_FIXTURES = {
    "full-pqc-v1.invalid-classical-allowance.manifest.json",
    "full-pqc-v1.invalid-ed25519.manifest.json",
    "full-pqc-v1.invalid-unknown-kem.manifest.json",
    "full-pqc-v1.invalid-unknown-signature.manifest.json",
    "hybrid-pre-pqc-v1.invalid-pq-ledger.manifest.json",
    "hybrid-pre-pqc-v1.invalid-pq-transcript.manifest.json",
    "hybrid-pre-pqc-v1.invalid-reject-classical.manifest.json",
    "hybrid-pre-pqc-v1.invalid-unknown-profile.manifest.json",
}
EXPECTED_FIXTURES = REQUIRED_VALID_FIXTURES | REQUIRED_INVALID_FIXTURES


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
    if data["kem"] not in ALLOWED_KEMS:
        fail(f"{path}: unsupported kem {data['kem']!r}")
    if data["hash_chain"] not in ALLOWED_HASH_CHAINS:
        fail(f"{path}: unsupported hash_chain {data['hash_chain']!r}")
    if data["kdf"] not in ALLOWED_KDFS:
        fail(f"{path}: unsupported kdf {data['kdf']!r}")
    if data["aead"] not in ALLOWED_AEADS:
        fail(f"{path}: unsupported aead {data['aead']!r}")
    if data["transcript_signature"] not in ALL_SIGNATURES:
        fail(f"{path}: unknown transcript_signature {data['transcript_signature']!r}")
    if data["ledger_signature"] not in ALL_SIGNATURES:
        fail(f"{path}: unknown ledger_signature {data['ledger_signature']!r}")

    profile = data["profile"]
    downgrade_policy = data["downgrade_policy"]

    if profile == "hybrid-pre-pqc-v1":
        if downgrade_policy != "explicit-classical-signature-allowance":
            fail(f"{path}: hybrid-pre-pqc-v1 requires explicit classical allowance")
        if data["transcript_signature"] not in CLASSICAL_SIGNATURES:
            fail(f"{path}: hybrid-pre-pqc-v1 requires classical transcript signatures")
        if data["ledger_signature"] not in CLASSICAL_SIGNATURES:
            fail(f"{path}: hybrid-pre-pqc-v1 requires classical ledger signatures")
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

    fixture_names = {manifest.name for manifest in manifests}
    missing_valid = sorted(REQUIRED_VALID_FIXTURES - fixture_names)
    missing_invalid = sorted(REQUIRED_INVALID_FIXTURES - fixture_names)
    unexpected = sorted(fixture_names - EXPECTED_FIXTURES)
    if missing_valid or missing_invalid or unexpected:
        if missing_valid:
            print(
                f"missing required valid manifest fixtures: {', '.join(missing_valid)}",
                file=sys.stderr,
            )
        if missing_invalid:
            print(
                f"missing required invalid manifest fixtures: {', '.join(missing_invalid)}",
                file=sys.stderr,
            )
        if unexpected:
            print(
                f"unexpected unregistered manifest fixtures: {', '.join(unexpected)}",
                file=sys.stderr,
            )
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
