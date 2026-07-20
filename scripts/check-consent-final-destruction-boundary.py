#!/usr/bin/env python3
"""Static guard for the authorization-only final-destruction boundary."""

from __future__ import annotations

import pathlib
import sys


def require(text: str, needle: str, failures: list[str]) -> None:
    if needle not in text:
        failures.append(f"missing required invariant: {needle}")


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    protocol_path = root / "apps/xenia-peer/src/consent_final_destruction.rs"
    main_path = root / "apps/xenia-peer/src/main.rs"
    if not protocol_path.is_file() or not main_path.is_file():
        print("final-destruction boundary files are missing", file=sys.stderr)
        return 1

    protocol = protocol_path.read_text(encoding="utf-8")
    main_rs = main_path.read_text(encoding="utf-8")
    failures: list[str] = []

    # Filesystem mutation primitives are forbidden in the authorization-only
    # protocol module.  main.rs legitimately contains the earlier, separately
    # authorized quarantine-purge executor, so only reject a final-destruction
    # executor surface there rather than scanning unrelated lifecycle code.
    for forbidden in (
        "remove_file(",
        "remove_dir(",
        "remove_dir_all(",
        "unlink(",
    ):
        if forbidden in protocol:
            failures.append(f"forbidden deletion primitive in protocol: {forbidden}")

    for forbidden in (
        "execute_consent_final_destruction",
        "execute-consent-final-destruction",
    ):
        if forbidden in protocol or forbidden in main_rs:
            failures.append(f"forbidden final-destruction executor present: {forbidden}")

    require(protocol, "certificate.verify_authority_signature(public_key)?", failures)
    require(protocol, "verify_protected_inventory_files(certificate)?", failures)
    require(protocol, "candidates: certificate.protected_artifacts.clone()", failures)
    require(protocol, "protected_inventory_digest(&self.candidates)?", failures)
    require(protocol, "RetentionStillActive", failures)
    require(protocol, "custody_bundle.verify_quorum", failures)
    require(protocol, "approvals.verify_quorum", failures)
    require(protocol, "MAX_FINAL_DESTRUCTION_PLAN_LIFETIME_SECS", failures)
    require(main_rs, "verified_retention_context(&args, &ledger_public_key)?", failures)
    require(main_rs, "plan.verify(", failures)
    require(main_rs, "ensure_output_disjoint_from_inputs", failures)
    require(main_rs, "no artifact was removed", failures)
    require(main_rs, "this artifact authorizes no implicit cleanup implementation", failures)

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("final-destruction boundary: authorization-only invariants present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
