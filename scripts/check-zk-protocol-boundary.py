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


def reject_duplicate_test_attributes(path: pathlib.Path) -> None:
    if not path.is_file():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    previous_test = False
    for lineno, line in enumerate(lines, 1):
        is_test = line.strip() == "#[test]"
        if is_test and previous_test:
            failures.append(f"{path.relative_to(root)}:{lineno}: duplicate adjacent #[test] attributes")
        previous_test = is_test


def require_test(source: str, name: str) -> None:
    import re
    pattern = re.compile(rf"(?m)^\s*#\[test\]\s*\n\s*fn\s+{re.escape(name)}\s*\(")
    require(bool(pattern.search(source)), f"protocol regression test is not executable: {name}")


manifest_path = crate / "Cargo.toml"
source_path = crate / "src" / "lib.rs"
policy_path = crate / "src" / "policy.rs"
verification_path = crate / "src" / "verification.rs"

require(manifest_path.is_file(), "xenia-zk-protocol/Cargo.toml missing")
require(source_path.is_file(), "xenia-zk-protocol/src/lib.rs missing")
require(policy_path.is_file(), "xenia-zk-protocol/src/policy.rs missing")
require(verification_path.is_file(), "xenia-zk-protocol/src/verification.rs missing")

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
        "pub struct ExtensionClaim",
        "pub fn extension_value_digest",
        "pub fn extensions_digest",
        "authentication_digest",
    ):
        require(fragment in source, f"V3 protocol invariant missing: {fragment}")

    # The generic protocol core must not absorb legacy/domain ownership.
    require_test(source, "v3_golden_body_and_authentication_digests_are_stable")
    require_test(source, "authentication_digest_binds_suite_and_signer")
    require_test(source, "public_inputs_digest_is_challenge_bound")
    require_test(source, "extension_digest_is_typed_order_independent_and_duplicate_safe")

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
        "pub struct VerificationContract",
        "ContractVerifierMismatch",
        "ContractParameterSetMismatch",
        "ContractNonceMismatch",
        "ContractPublicInputsMismatch",
        "ContractExtensionsMismatch",
        "expected.extensions_digest",
        "DEFAULT_MAX_PUBLIC_INPUT_BYTES",
        "ZeroExtensionsDigest",
        "AuthenticationQuorumNotMet",
        "validate_envelope_against_contract",
    ):
        require(fragment in policy, f"fail-closed policy invariant missing: {fragment}")
    require_test(policy, "zero_extensions_digest_is_rejected_as_noncanonical")


if verification_path.is_file():
    verification = verification_path.read_text(encoding="utf-8")
    for fragment in (
        "pub trait ProofBackendVerifier",
        "pub struct ChallengeBoundPublicInputs",
        "pub trait ProofAuthenticationVerifier",
        "pub struct ProofVerifiedEnvelope",
        "pub struct FullyVerifiedEnvelope",
        "public_inputs_digest",
        "BackendVerifierMismatch",
        "AuthenticationRejected",
        "pub fn verify_envelope",
        "challenge_nonce: &envelope.nonce",
    ):
        require(fragment in verification, f"verification typestate invariant missing: {fragment}")
    require_test(verification, "fresh_challenge_cannot_be_re_enveloped_without_backend_binding")
    require_test(verification, "oversized_public_inputs_are_rejected_before_backend_work")
    require("contract.proof." not in verification, "stale VerificationContract field access reintroduced")

workspace_manifest = root / "Cargo.toml"
if workspace_manifest.is_file():
    with workspace_manifest.open("rb") as handle:
        workspace = tomllib.load(handle).get("workspace", {})
    members = set(workspace.get("members", []))
    defaults = set(workspace.get("default-members", []))
    require("crates/xenia-zk-legacy-mycelix" in members, "legacy Mycelix adapter must be an explicit workspace member")
    require("crates/xenia-zk-legacy-mycelix" not in defaults, "legacy Mycelix adapter must remain opt-in, not a default member")

legacy_manifest = root / "crates" / "xenia-zk-legacy-mycelix" / "Cargo.toml"
if legacy_manifest.is_file():
    with legacy_manifest.open("rb") as handle:
        legacy = tomllib.load(handle)
    require("xenia-zk-protocol" not in legacy.get("dependencies", {}), "legacy adapter must not create a V3 dependency cycle")

for rust_source in crate.rglob("*.rs"):
    reject_duplicate_test_attributes(rust_source)

if failures:
    print("ZK protocol boundary check FAILED", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("ZK protocol boundary check passed")
