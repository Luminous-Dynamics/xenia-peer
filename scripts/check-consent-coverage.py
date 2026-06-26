#!/usr/bin/env python3
"""Advisory scan for consent/session lifecycle coverage in Xenia source files."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

EVENTS = [
    "consent.requested",
    "consent.presented",
    "consent.granted",
    "consent.denied",
    "session.active_started",
    "session.revocation_requested",
    "session.revoked",
    "session.expired",
    "session.fault_closed",
]
STATES = [
    "Idle",
    "Requested",
    "Presented",
    "Granted",
    "Active",
    "Revoking",
    "Revoked",
    "Denied",
    "Expired",
    "FaultClosed",
]
SKIP_PARTS = {".git", "target", "dist", "_archive", "node_modules"}


def iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        if path.suffix.lower() not in {".rs", ".md", ".toml"}:
            continue
        yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--strict", action="store_true", help="fail if required event/state names are missing from source/docs")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    hits = {"events": {event: [] for event in EVENTS}, "states": {state: [] for state in STATES}}
    for path in iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for event in EVENTS:
            if event in text:
                hits["events"][event].append(rel)
        for state in STATES:
            if re.search(rf"\b{re.escape(state)}\b", text):
                hits["states"][state].append(rel)

    missing_events = [event for event, paths in hits["events"].items() if not paths]
    missing_states = [state for state, paths in hits["states"].items() if not paths]
    payload = {"missing_events": missing_events, "missing_states": missing_states, "hits": hits}

    if args.json_path:
        out = root / args.json_path if not os.path.isabs(args.json_path) else Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("Consent coverage scan")
    print(f"  missing events: {len(missing_events)}")
    print(f"  missing states: {len(missing_states)}")
    if missing_events:
        print("  events:")
        for event in missing_events:
            print(f"    - {event}")
    if missing_states:
        print("  states:")
        for state in missing_states:
            print(f"    - {state}")

    if args.strict and (missing_events or missing_states):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
