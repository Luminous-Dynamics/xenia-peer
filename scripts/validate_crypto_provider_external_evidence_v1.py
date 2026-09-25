#!/usr/bin/env python3
"""Validate a dated Xenia crypto-provider external evidence snapshot.

This checker is intentionally offline. It validates conservative structure and
exact binding to the local provider identity manifest; it does not re-fetch or
independently endorse mutable external sources.
"""

from __future__ import annotations

import copy
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

IDENTITY_PATH = Path("docs/crypto/provider_assurance_v1.json")
EVIDENCE_PATH = Path("docs/crypto/provider_external_evidence_v1.json")
IDENTITY_SCHEMA = "xenia-crypto-provider-assurance-v1"
EVIDENCE_SCHEMA = "xenia-crypto-provider-external-evidence-v1"
EVIDENCE_SCOPE = "dated-external-evidence-only"

ALLOWED_CLASSES = {
    "standard",
    "errata",
    "audit",
    "test-vector",
    "advisory",
    "formal-proof",
    "constant-time",
    "oracle-candidate",
}
ALLOWED_APPLICABILITY = {
    "algorithm-standard",
    "exact-version",
    "version-range",
    "provider-family",
    "reference-only",
    "oracle-candidate",
    "oracle-candidate-history",
}
FORBIDDEN_DISPOSITIONS = {
    "safe",
    "secure",
    "formally-verified-production",
    "production-approved",
    "protocol-secure",
    "fully-audited",
}


class EvidenceError(ValueError):
    pass


def fail(message: str) -> None:
    raise EvidenceError(message)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        fail(f"{path}: top-level JSON value must be an object")
    return data


def provider_identity_map(identity: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    providers = identity.get("providers")
    if not isinstance(providers, list):
        fail("identity manifest: providers missing")
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for provider in providers:
        if not isinstance(provider, dict):
            fail("identity manifest: provider entry must be an object")
        key = (provider.get("name"), provider.get("version"), provider.get("checksum"))
        if not all(isinstance(part, str) and part for part in key):
            fail("identity manifest: incomplete provider identity")
        if key in result:
            fail(f"identity manifest: duplicate provider identity {key!r}")
        result[key] = provider
    return result


def valid_https_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def validate_snapshot(identity: dict[str, Any], evidence: dict[str, Any]) -> None:
    if identity.get("schema") != IDENTITY_SCHEMA:
        fail(f"identity manifest: expected schema {IDENTITY_SCHEMA!r}")
    if identity.get("assurance_scope") != "identity-only":
        fail("identity manifest: 001B requires the 001A identity-only root")

    if evidence.get("schema") != EVIDENCE_SCHEMA:
        fail(f"external evidence: unsupported schema {evidence.get('schema')!r}")
    if evidence.get("assurance_scope") != EVIDENCE_SCOPE:
        fail(
            f"external evidence: assurance_scope must be {EVIDENCE_SCOPE!r}, "
            f"found {evidence.get('assurance_scope')!r}"
        )
    if evidence.get("identity_manifest") != str(IDENTITY_PATH):
        fail("external evidence: identity_manifest path drift")
    if evidence.get("identity_schema") != IDENTITY_SCHEMA:
        fail("external evidence: identity_schema drift")

    observed_at = evidence.get("observed_at")
    if not isinstance(observed_at, str):
        fail("external evidence: observed_at missing")
    try:
        date.fromisoformat(observed_at)
    except ValueError as exc:
        fail(f"external evidence: invalid observed_at {observed_at!r}: {exc}")

    refresh = evidence.get("refresh_policy")
    if not isinstance(refresh, dict):
        fail("external evidence: refresh_policy missing")
    if refresh.get("live_network_in_ci") is not False:
        fail("external evidence: reproducible CI must not enable live-network source checking")
    review_days = refresh.get("review_after_days")
    if not isinstance(review_days, int) or review_days <= 0:
        fail("external evidence: review_after_days must be a positive integer")

    known_identities = provider_identity_map(identity)
    records = evidence.get("records")
    if not isinstance(records, list) or not records:
        fail("external evidence: records must be a non-empty list")

    seen_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            fail("external evidence: record must be an object")
        record_id = record.get("id")
        if not isinstance(record_id, str) or not record_id:
            fail("external evidence: record id missing")
        if record_id in seen_ids:
            fail(f"external evidence: duplicate record id {record_id!r}")
        seen_ids.add(record_id)

        evidence_class = record.get("evidence_class")
        if evidence_class not in ALLOWED_CLASSES:
            fail(f"{record_id}: unsupported evidence_class {evidence_class!r}")
        applicability = record.get("applicability")
        if applicability not in ALLOWED_APPLICABILITY:
            fail(f"{record_id}: unsupported applicability {applicability!r}")
        if not valid_https_url(record.get("source_url")):
            fail(f"{record_id}: source_url must be an https URL")
        for field in ("observed_claim", "disposition", "claim_ceiling"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                fail(f"{record_id}: {field} must be a non-empty string")

        disposition = record["disposition"].strip().lower()
        if disposition in FORBIDDEN_DISPOSITIONS:
            fail(f"{record_id}: overstrong disposition {disposition!r}")
        if record.get("production_selected") is True:
            fail(f"{record_id}: external evidence snapshot may not select a production provider")

        provider_ref = record.get("provider_ref")
        if provider_ref is not None:
            if not isinstance(provider_ref, dict):
                fail(f"{record_id}: provider_ref must be null or an object")
            key = (
                provider_ref.get("name"),
                provider_ref.get("version"),
                provider_ref.get("checksum"),
            )
            if not all(isinstance(part, str) and part for part in key):
                fail(f"{record_id}: provider_ref is incomplete")
            if key not in known_identities:
                fail(f"{record_id}: provider_ref does not match an exact 001A identity: {key!r}")

        assessment = record.get("published_affected_range_assessment")
        if assessment is not None:
            if evidence_class != "advisory":
                fail(f"{record_id}: affected-range assessment is only valid for advisories")
            if assessment != "locked-version-outside-published-affected-range":
                fail(f"{record_id}: overstrong/unknown advisory range assessment {assessment!r}")
            if disposition != "range-only-non-applicability":
                fail(f"{record_id}: range assessment must use range-only-non-applicability")

        if applicability.startswith("oracle-candidate"):
            if provider_ref is not None:
                fail(f"{record_id}: oracle candidate/history must not masquerade as the locked provider")

    followups = evidence.get("required_followups")
    if not isinstance(followups, list) or not followups:
        fail("external evidence: required_followups missing")
    non_equivalences = evidence.get("non_equivalences")
    if not isinstance(non_equivalences, list) or len(non_equivalences) < 4:
        fail("external evidence: non_equivalences must retain the claim ceiling")


def run_negative_controls(identity: dict[str, Any], baseline: dict[str, Any]) -> None:
    def must_reject(name: str, mutant: dict[str, Any]) -> None:
        try:
            validate_snapshot(identity, mutant)
        except EvidenceError as exc:
            print(f"negative control rejected: {name}: {exc}")
        else:
            fail(f"negative control unexpectedly accepted: {name}")

    bad_ref = copy.deepcopy(baseline)
    target = next(r for r in bad_ref["records"] if r.get("provider_ref"))
    target["provider_ref"]["version"] = "99.99.99"
    must_reject("provider-identity-substitution", bad_ref)

    overclaim = copy.deepcopy(baseline)
    advisory = next(r for r in overclaim["records"] if r["evidence_class"] == "advisory")
    advisory["disposition"] = "safe"
    must_reject("advisory-safe-overclaim", overclaim)

    production = copy.deepcopy(baseline)
    oracle = next(r for r in production["records"] if r["applicability"] == "oracle-candidate")
    oracle["production_selected"] = True
    must_reject("oracle-production-promotion", production)

    network = copy.deepcopy(baseline)
    network["refresh_policy"]["live_network_in_ci"] = True
    must_reject("live-network-in-reproducible-ci", network)

    scope = copy.deepcopy(baseline)
    scope["assurance_scope"] = "protocol-secure"
    must_reject("assurance-scope-escalation", scope)


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    try:
        identity = load_json(root / IDENTITY_PATH)
        evidence = load_json(root / EVIDENCE_PATH)
        validate_snapshot(identity, evidence)
        run_negative_controls(identity, evidence)
    except (OSError, json.JSONDecodeError, EvidenceError) as exc:
        print(f"crypto external evidence check failed: {exc}", file=sys.stderr)
        return 1

    print("crypto external evidence snapshot check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
