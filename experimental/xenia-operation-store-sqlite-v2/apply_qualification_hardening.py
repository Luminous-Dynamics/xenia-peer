#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).parent
SCRIPTS = (
    "repair_injector_idempotency.py",
    "repair_pre_pr.py",
    "inject_hardening_tests.py",
    "inject_frontier_semantics.py",
    "inject_clean_close_integrity.py",
)

for script in SCRIPTS:
    path = ROOT / script
    subprocess.run([sys.executable, str(path)], check=True)

print("sqlite-v2-qualification-hardening: OK")
