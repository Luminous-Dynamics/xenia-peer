#!/usr/bin/env python3
"""Static boundary guard for the backend-neutral xenia-zk-protocol crate."""

from __future__ import annotations

import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
crate = root / "crates" / "xenia-zk-protocol"
failures: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


manifest_path = crate / "Cargo.toml"
source_path = crate / "src" / "lib.rs"
policy_path = crate / "src" / "policy.rs"

require(manifest_path.is_file(), "xenia-zk-protocol/Cargo.toml missing")
require(source_path.is_file(), "xenia-zk-protocol/src/lib.rs missing")
require(policy_path.is_file(), "xenia-zk-protocol/src/policy.rs missing")

if manifest_path.is_file():
    with manifest_path.open("rb") as handle:
        manifest = tomllib.load(handle)
    deps = set(manifest.get("dependencies", {}))
    forbidden_deps = {
        "winterfell",
        "winter-math",
        "winter-crypto",
        "miden-vm",
        "miden-core",
        "risc0-zkvm",
        "pqcrypto-dilithium",
        "ml-dsa",
        "ed25519-dalek",
        "hdk",
        "hdi",
        "holochain",
    }
    require(
        not (deps & forbidden_deps),
        f"protocol crate owns implementation/domain dependencies: {sorted(deps & forbidden_deps)}",
    )

if source_path.is_file():
    source = source_path.read_text(encoding="utf-8")
    for fragment in (
        'PROOF_ENVELOPE_PROTOCOL_VERSION: u32 = 3',
        'b"XENIA:ProofEnvelope:Body:v3"',
        "pub struct StatementId",
        "pub struct VerifierId",
        "pub struct ParameterSetId",
        "pub struct ProofEnvelopeV3",
        "public_inputs_hash",
        "extensions_digest",
        "authentication_digest",
    ):
        require(fragment in source, f"V3 protocol invariant missing: {fragment}")

    # The generic protocol core must not absorb legacy/domain ownership.
    for forbidden in (
        "MYCELIX:AuthenticatedProof",
        "ZTML:",
        "Holochain",
        "ConsciousnessProof",
        "JurisdictionProof",
        "SupplyProof",
    ):
        require(forbidden not in source, f"domain/legacy semantic leaked into protocol core: {forbidden}")

if policy_path.is_file():
    policy = policy_path.read_text(encoding="utf-8")
    for fragment in (
        "envelope.protocol_version != policy.protocol_version",
        "envelope.verifier_id.is_zero()",
        "envelope.parameter_set_id.is_zero()",
        "envelope.nonce == [0; 32]",
        "envelope.public_inputs_hash == [0; 32]",
        "required_authentication_suites",
        "DuplicateAuthentication",
    ):
        require(fragment in policy, f"fail-closed policy invariant missing: {fragment}")

if failures:
    print("ZK protocol boundary check FAILED", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("ZK protocol boundary check passed")
