#!/usr/bin/env python3
"""Fail-closed text verifier for ADR-037's inert live-GCS workflow contract.

The contract is intentionally not active GitHub Actions YAML yet. This verifier treats exact
security-sensitive snippets as API: weakening a trigger, action pin, environment boundary, source
ref gate, identity comparison, or irreversible-lock condition requires an explicit verifier/ADR
change instead of silently passing ordinary YAML review.
"""

from pathlib import Path
import re
import sys

CONTRACT = Path(".github/workflow-contracts/operation-authority-retention-gcs-live-manual-v1.yml")
ACTIVE = Path(".github/workflows/operation-authority-retention-gcs-live-manual-v1.yml")

CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"
AUTH_SHA = "7c6bc770dae815cd3e89ee6cdf493a5fab2cc093"
RUST_SHA = "4360b52568e2003a75bf9bc1d59f33a8e3fc893c"

ENVIRONMENTS = {
    "xenia-gcs-qual-admin-reversible",
    "xenia-gcs-qual-runtime",
    "xenia-gcs-qual-admin-lock",
    "xenia-gcs-qual-admin-cleanup",
}

BINARIES = {
    "xenia_gcs_admin_provision_v1",
    "xenia_gcs_runtime_permissions_v1",
    "xenia_gcs_admin_lock_v1",
    "xenia_gcs_admin_teardown_v1",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(text: str, needle: str, description: str) -> None:
    if needle not in text:
        fail(f"missing {description}: {needle!r}")


def require_count(text: str, needle: str, count: int, description: str) -> None:
    observed = text.count(needle)
    if observed != count:
        fail(f"{description}: expected {count}, observed {observed}: {needle!r}")


def main() -> None:
    if not CONTRACT.is_file():
        fail("inert workflow contract is missing")
    if ACTIVE.exists():
        fail("live workflow is active; activation requires a separate reviewed tranche")

    text = CONTRACT.read_text()

    # Trigger contract: manual only. Reject the common activation paths anywhere in this inert file.
    require(text, "  workflow_dispatch:\n", "workflow_dispatch trigger")
    for forbidden in ("  push:\n", "  pull_request:\n", "  schedule:\n", "  repository_dispatch:\n"):
        if forbidden in text:
            fail(f"forbidden automatic/external trigger present: {forbidden.strip()}")

    # Explicit single-phase interface and no generic orchestration binary.
    for phase in ("provision", "runtime", "lock", "teardown"):
        require(text, f"          - {phase}\n", f"phase option {phase}")
    if "run_everything" in text or "run-all" in text:
        fail("generic all-phases execution path is forbidden")

    # Full SHA pins. No floating major tags are allowed for any action.
    require_count(text, f"actions/checkout@{CHECKOUT_SHA}", 4, "checkout full-SHA pin count")
    require_count(text, f"google-github-actions/auth@{AUTH_SHA}", 4, "Google auth full-SHA pin count")
    require_count(text, f"dtolnay/rust-toolchain@{RUST_SHA}", 4, "Rust action full-SHA pin count")
    if re.search(r"uses:\s*[^\n]+@v\d+(?:\s|$)", text):
        fail("floating major-version action reference is forbidden")

    # No long-lived cloud keys or GitHub secrets in the workflow contract.
    for forbidden in (
        "credentials_json",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "${{ secrets.",
        "service_account_key",
        "private_key",
    ):
        if forbidden in text:
            fail(f"static/secret credential surface forbidden in WIF contract: {forbidden}")

    # Job-scoped OIDC only; each cloud phase has its own protected environment.
    require_count(text, "      id-token: write\n", 4, "job-scoped OIDC permission count")
    observed_envs = set(re.findall(r"^    environment: ([A-Za-z0-9_-]+)$", text, re.MULTILINE))
    if observed_envs != ENVIRONMENTS:
        fail(f"protected environment set mismatch: {sorted(observed_envs)}")
    require_count(text, "workload_identity_provider: ${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}", 4, "WIF provider binding")
    require_count(text, "service_account: ${{ vars.GCP_SERVICE_ACCOUNT }}", 4, "service-account impersonation binding")

    # Main-only and exact reviewed-source binding in all jobs.
    require_count(text, "github.ref == 'refs/heads/main'", 4, "main-branch execution gate")
    require_count(text, 'test "${{ github.sha }}" = "${{ inputs.expected_sha }}"', 4, "expected SHA gate")

    # The environment-selected Google service account must equal the exact ADR-035 configured member.
    require_count(text, 'test "serviceAccount:${{ vars.GCP_SERVICE_ACCOUNT }}" = "${{ inputs.admin_member }}"', 3, "admin credential/member binding")
    require_count(text, 'test "serviceAccount:${{ vars.GCP_SERVICE_ACCOUNT }}" = "${{ inputs.runtime_member }}"', 1, "runtime credential/member binding")

    # Lock cannot run in reversible mode or without an explicit lock acknowledgement.
    require(
        text,
        "inputs.phase == 'lock' && inputs.mode == 'irreversible-bucket-lock'",
        "irreversible lock job condition",
    )
    require(text, 'test -n "${{ inputs.irreversible_lock_ack }}"', "non-empty lock acknowledgement gate")

    # Every destructive binary appears exactly once; there is no hidden second invocation.
    for binary in BINARIES:
        require_count(text, f"--bin {binary}", 1, f"single invocation of {binary}")
    require_count(text, "cargo run --locked", 4, "manual binary invocation count")
    if "continue-on-error" in text:
        fail("continue-on-error is forbidden in qualification workflow")

    # Provider identity inputs are environment-scoped variables, never dispatch-controlled strings.
    for value in ("vars.GCP_WORKLOAD_IDENTITY_PROVIDER", "vars.GCP_SERVICE_ACCOUNT"):
        require(text, value, f"environment-scoped {value}")

    print("PASS: ADR-037 inert live-GCS workflow contract")


if __name__ == "__main__":
    main()
