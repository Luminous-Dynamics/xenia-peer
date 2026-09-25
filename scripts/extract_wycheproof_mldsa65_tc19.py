#!/usr/bin/env python3
"""Authenticate and extract one pinned Wycheproof ML-DSA-65 regression case.

The upstream corpus is fetched only by the dedicated evidence workflow. This
script proves its Git blob identity locally, locates exactly one configured test
case, validates its metadata/lengths, and emits raw bytes plus a receipt.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any


class FixtureError(ValueError):
    pass


def fail(message: str) -> None:
    raise FixtureError(message)


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324 - Git object identity, not security.


def decode_hex(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        fail(f"{field}: expected hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        fail(f"{field}: invalid hex: {exc}")


def validate_case(contract: dict[str, Any], raw: bytes, corpus: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema") != "xenia-wycheproof-mldsa65-regression-v1":
        fail("contract: unsupported schema")

    upstream = contract.get("upstream")
    case = contract.get("case")
    boundary = contract.get("xenia_boundary")
    if not isinstance(upstream, dict) or not isinstance(case, dict) or not isinstance(boundary, dict):
        fail("contract: missing upstream/case/xenia_boundary objects")

    observed_blob = git_blob_sha(raw)
    if observed_blob != upstream.get("git_blob"):
        fail(
            f"upstream corpus Git blob mismatch: expected {upstream.get('git_blob')}, "
            f"found {observed_blob}"
        )

    if corpus.get("algorithm") != case.get("algorithm"):
        fail(
            f"algorithm mismatch: expected {case.get('algorithm')!r}, "
            f"found {corpus.get('algorithm')!r}"
        )

    tc_id = case.get("tc_id")
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for group in corpus.get("testGroups", []):
        if not isinstance(group, dict):
            continue
        for test in group.get("tests", []):
            if isinstance(test, dict) and test.get("tcId") == tc_id:
                matches.append((group, test))

    if len(matches) != 1:
        fail(f"expected exactly one tcId {tc_id}, found {len(matches)}")

    group, test = matches[0]
    if group.get("type") != case.get("type"):
        fail(f"test-group type mismatch: expected {case.get('type')!r}, found {group.get('type')!r}")
    if test.get("comment") != case.get("comment"):
        fail(f"comment mismatch: expected {case.get('comment')!r}, found {test.get('comment')!r}")
    if test.get("result") != case.get("expected_result"):
        fail(
            f"result mismatch: expected {case.get('expected_result')!r}, "
            f"found {test.get('result')!r}"
        )

    flags = test.get("flags")
    if not isinstance(flags, list):
        fail("test flags missing")
    missing_flags = sorted(set(case.get("required_flags", [])) - set(flags))
    if missing_flags:
        fail(f"missing required flags: {missing_flags}")

    if test.get("msg") != case.get("message_hex"):
        fail("message mismatch")

    public_key = decode_hex(group.get("publicKey"), "publicKey")
    message = decode_hex(test.get("msg"), "msg")
    signature = decode_hex(test.get("sig"), "sig")

    expected_lengths = {
        "public_key": case.get("public_key_bytes"),
        "message": case.get("message_bytes"),
        "signature": case.get("signature_bytes"),
    }
    observed_lengths = {
        "public_key": len(public_key),
        "message": len(message),
        "signature": len(signature),
    }
    for name, expected in expected_lengths.items():
        if observed_lengths[name] != expected:
            fail(f"{name} length mismatch: expected {expected}, found {observed_lengths[name]}")

    provider = boundary.get("provider_identity")
    if not isinstance(provider, dict):
        fail("contract: provider identity missing")
    if provider != {
        "name": "ml-dsa",
        "version": "0.1.1",
        "checksum": "add6b9d92e496f16f4526d68ff29da1483aba4b119baeab8bed3b9e3544a6f3d",
    }:
        fail("contract: C2 provider identity drifted from the frozen 001A subject")

    return {
        "public_key": public_key,
        "message": message,
        "signature": signature,
        "receipt": {
            "schema": "xenia-wycheproof-mldsa65-extraction-receipt-v1",
            "upstream_git_blob": observed_blob,
            "tc_id": tc_id,
            "comment": test["comment"],
            "expected_result": test["result"],
            "flags": flags,
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "public_key_bytes": len(public_key),
            "message_bytes": len(message),
            "signature_bytes": len(signature),
            "provider_identity": provider,
        },
    }


def write_outputs(extracted: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "public_key.bin").write_bytes(extracted["public_key"])
    (output_dir / "message.bin").write_bytes(extracted["message"])
    (output_dir / "signature.bin").write_bytes(extracted["signature"])
    (output_dir / "receipt.json").write_text(
        json.dumps(extracted["receipt"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_negative_controls(contract: dict[str, Any], raw: bytes, corpus: dict[str, Any]) -> None:
    def must_reject(name: str, mutated_contract: dict[str, Any], mutated_corpus: dict[str, Any] | None = None) -> None:
        try:
            validate_case(mutated_contract, raw, corpus if mutated_corpus is None else mutated_corpus)
        except FixtureError as exc:
            print(f"negative control rejected: {name}: {exc}")
        else:
            fail(f"negative control unexpectedly accepted: {name}")

    wrong_blob = copy.deepcopy(contract)
    wrong_blob["upstream"]["git_blob"] = "0" * 40
    must_reject("wrong-upstream-git-blob", wrong_blob)

    wrong_id = copy.deepcopy(contract)
    wrong_id["case"]["tc_id"] = 999999
    must_reject("wrong-tc-id", wrong_id)

    wrong_result = copy.deepcopy(contract)
    wrong_result["case"]["expected_result"] = "valid"
    must_reject("inverted-expected-result", wrong_result)

    missing_flag = copy.deepcopy(contract)
    missing_flag["case"]["required_flags"] = ["DefinitelyNotPresent"]
    must_reject("missing-required-flag", missing_flag)

    wrong_message = copy.deepcopy(contract)
    wrong_message["case"]["message_hex"] = "00" * int(contract["case"]["message_bytes"])
    must_reject("message-substitution", wrong_message)

    duplicate = copy.deepcopy(corpus)
    target = None
    owner = None
    for group in duplicate.get("testGroups", []):
        for test in group.get("tests", []):
            if test.get("tcId") == contract["case"]["tc_id"]:
                target = copy.deepcopy(test)
                owner = group
                break
        if target is not None:
            break
    if target is None or owner is None:
        fail("negative-control setup: tcId not found")
    owner["tests"].append(target)
    must_reject("duplicate-tc-id", contract, duplicate)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    try:
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        raw = args.corpus.read_bytes()
        corpus = json.loads(raw)
        extracted = validate_case(contract, raw, corpus)
        run_negative_controls(contract, raw, corpus)
        write_outputs(extracted, args.output_dir)
    except (OSError, json.JSONDecodeError, FixtureError) as exc:
        print(f"Wycheproof ML-DSA-65 fixture extraction failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(extracted["receipt"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main())
