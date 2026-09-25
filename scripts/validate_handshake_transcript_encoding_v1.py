#!/usr/bin/env python3
"""Fail-closed census validator for HandshakeTranscriptV1 canonical encoding."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
MANIFEST = ROOT / "docs/crypto/handshake_transcript_encoding_v1.json"
LOCK = ROOT / "Cargo.lock"
SOURCE = ROOT / "crates/xenia-handshake/src/lib.rs"
DOC = ROOT / "docs/crypto/HANDSHAKE_TRANSCRIPT_ENCODING_V1.md"


def fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")


def load_json(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def package(lock, name: str):
    matches = [p for p in lock.get("package", []) if p.get("name") == name]
    if len(matches) != 1:
        fail(f"expected exactly one {name} package, found {len(matches)}")
    return matches[0]


def assert_package(actual, expected, name: str) -> None:
    for key in ("version", "checksum"):
        if actual.get(key) != expected.get(key):
            fail(f"{name} {key} drift: {actual.get(key)!r} != {expected.get(key)!r}")
    if "source" in expected and actual.get("source") != expected.get("source"):
        fail(f"{name} source drift")


def extract_struct_fields(source: str):
    marker = "pub struct HandshakeTranscriptV1 {"
    start = source.find(marker)
    if start < 0:
        fail("HandshakeTranscriptV1 struct missing")
    body_start = start + len(marker)
    depth = 1
    i = body_start
    while i < len(source) and depth:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
    if depth:
        fail("unterminated HandshakeTranscriptV1 struct")
    body = source[body_start : i - 1]
    fields = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("pub "):
            continue
        m = re.fullmatch(r"pub ([A-Za-z0-9_]+): (.+),", line)
        if not m:
            fail(f"unparsed public field line: {line}")
        fields.append([m.group(1), m.group(2)])
    return fields


def require_source_contract(source: str, manifest) -> None:
    required = [
        f'pub const HANDSHAKE_TRANSCRIPT_SCHEMA: &str = "{manifest["subject"]["transcript_schema"]}";',
        f'pub const HANDSHAKE_TRANSCRIPT_HASH_ALGORITHM: &str = "{manifest["subject"]["hash_algorithm"]}";',
        "pub fn canonical_session_transcript_bytes(transcript: &HandshakeTranscriptV1) -> Result<Vec<u8>>",
        "Ok(bincode::serialize(transcript)?)",
        "pub fn compute_session_transcript_hash(transcript: &HandshakeTranscriptV1) -> Result<[u8; 32]>",
        "compute_session_transcript_hash_from_bytes(&bytes)",
        "*blake3::hash(canonical_bytes).as_bytes()",
    ]
    for needle in required:
        if needle not in source:
            fail(f"source contract drift: missing {needle!r}")


def run_negative_controls(manifest, lock, source: str) -> None:
    bad = json.loads(json.dumps(manifest))
    bad["serializer"]["bincode"]["version"] = "9.9.9"
    try:
        assert_package(package(lock, "bincode"), bad["serializer"]["bincode"], "bincode")
    except SystemExit:
        pass
    else:
        fail("negative control failed: bincode version mutation accepted")

    bad_fields = list(manifest["field_order"])
    bad_fields[0], bad_fields[1] = bad_fields[1], bad_fields[0]
    if extract_struct_fields(source) == bad_fields:
        fail("negative control failed: reordered field census accepted")

    bad_claims = set(manifest["claim_ceiling"])
    bad_claims.add("universal-bincode-refinement")
    forbidden = set(manifest["not_claimed"])
    if not (bad_claims & forbidden):
        fail("negative control failed: claim escalation detector broken")


def main() -> None:
    manifest = load_json(MANIFEST)
    lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    source = SOURCE.read_text(encoding="utf-8")

    if manifest.get("schema") != "xenia-handshake-transcript-encoding-census-v1":
        fail("manifest schema drift")
    if manifest["subject"].get("serialization_call") != "bincode::serialize(transcript)":
        fail("serialization-call identity drift")

    assert_package(package(lock, "bincode"), manifest["serializer"]["bincode"], "bincode")
    assert_package(package(lock, "serde"), manifest["serializer"]["serde"], "serde")
    assert_package(package(lock, "serde_core"), manifest["serializer"]["serde_core"], "serde_core")
    assert_package(package(lock, "serde_derive"), manifest["serializer"]["serde_derive"], "serde_derive")

    actual_fields = extract_struct_fields(source)
    if actual_fields != manifest["field_order"]:
        fail(f"HandshakeTranscriptV1 field-order/type drift:\nactual={actual_fields!r}\nexpected={manifest['field_order']!r}")

    require_source_contract(source, manifest)

    claimed = set(manifest["claim_ceiling"])
    forbidden = set(manifest["not_claimed"])
    if claimed & forbidden:
        fail(f"claim ceiling overlaps exclusions: {sorted(claimed & forbidden)}")
    required_exclusions = {
        "universal-bincode-refinement",
        "blake3-collision-resistance-proof",
        "signature-security-proof",
        "handshake-authentication-theorem",
        "native-wasm-byte-equivalence",
        "compiled-code-proof",
    }
    if not required_exclusions.issubset(forbidden):
        fail("required claim exclusions missing")

    run_negative_controls(manifest, lock, source)

    print("PASS: handshake transcript encoding census v1")
    for p in (LOCK, SOURCE, MANIFEST, DOC):
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f"sha256 {digest}  {p.relative_to(ROOT)}")
    print("field_count", len(actual_fields))
    print("bincode", package(lock, "bincode")["version"])
    print("serde", package(lock, "serde")["version"])


if __name__ == "__main__":
    main()
