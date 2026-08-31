#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).parent
SOURCE = ROOT / "src" / "lib.rs"

# Once the qualified end-state has been auto-committed and rustfmt has normalized the source,
# do not run textual migration scripts again. Qualification must be repeatable on the committed
# source, not dependent on the exact pre-rustfmt layout used by the first migration pass.
FINAL_MARKERS = (
    "pub const QUALIFIED_SQLITE_VERSION_V2",
    "fn run_sqlite_engine_recovery(",
    "fn qualified_sqlite_source_profile_is_exact",
    "grant_authority_bytes BLOB NOT NULL",
    "authenticated_issuance: AuthenticatedIssuanceContextV2",
    "fn verify_frontier_semantics(&self)",
    "fn corrupted_store_cannot_claim_clean_close",
    "admitted_at < grant.issued_at_unix_ms",
    'qualification_crash_point("admission", "C9")',
    'qualification_crash_point("effect-armed", "C9")',
    "pub fn qualification_effect_armed_proof_digest",
)

source = SOURCE.read_text()
if all(marker in source for marker in FINAL_MARKERS):
    print("sqlite-v2-qualification-hardening: already applied")
    raise SystemExit(0)

SCRIPTS = (
    "repair_injector_idempotency.py",
    "repair_pre_pr.py",
    "inject_engine_recovery.py",
    "inject_hardening_tests.py",
    "inject_engine_recovery_tests.py",
    "inject_frontier_semantics.py",
    "inject_clean_close_integrity.py",
    "inject_temporal_epoch_integrity.py",
    "inject_crash_qualification.py",
)

for script in SCRIPTS:
    path = ROOT / script
    subprocess.run([sys.executable, str(path)], check=True)

source = SOURCE.read_text()
missing = [marker for marker in FINAL_MARKERS if marker not in source]
if missing:
    raise SystemExit(f"sqlite-v2 hardening incomplete; missing markers: {missing}")

print("sqlite-v2-qualification-hardening: OK")
