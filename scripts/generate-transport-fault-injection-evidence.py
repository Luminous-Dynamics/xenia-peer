#!/usr/bin/env python3
"""Generate sanitized RC1 evidence for transport fault-injection tests."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

CASES = [
    {
        "id": "tcp-truncated-envelope",
        "crate": "xenia-transport-ws",
        "test": "tcp_detects_truncated_envelope_as_unexpected_eof",
        "fault": "TCP peer closes before the advertised envelope length is satisfied.",
        "expected": "receiver returns TransportError::UnexpectedEof without session decode",
    },
    {
        "id": "tcp-oversize-prefix",
        "crate": "xenia-transport-ws",
        "test": "tcp_rejects_oversize_receive_before_allocation",
        "fault": "TCP peer advertises an envelope larger than MAX_ENVELOPE_BYTES.",
        "expected": "receiver returns TransportError::EnvelopeTooLarge before payload allocation",
    },
    {
        "id": "websocket-oversize-binary",
        "crate": "xenia-transport-ws",
        "test": "websocket_rejects_oversize_send_without_poisoning_connection",
        "fault": "WebSocket side attempts to send a binary envelope larger than MAX_ENVELOPE_BYTES.",
        "expected": "local send is rejected and the connection remains usable for a sentinel envelope",
    },
    {
        "id": "websocket-text-frame",
        "crate": "xenia-transport-ws",
        "test": "websocket_rejects_text_protocol_fault",
        "fault": "WebSocket peer sends text instead of sealed binary envelope bytes.",
        "expected": "receiver fails closed with TransportError::UnexpectedEof-compatible protocol error",
    },
    {
        "id": "quic-oversize-send",
        "crate": "xenia-transport-quic",
        "test": "quic_rejects_oversize_send_without_poisoning_connection",
        "fault": "QUIC side attempts to send an envelope larger than MAX_ENVELOPE_BYTES.",
        "expected": "local send is rejected and the stream remains usable for a sentinel envelope",
    },
]


def sanitize(text: str, root: Path) -> str:
    root_s = str(root.resolve())
    text = text.replace(root_s, "<repo-root>")
    text = text.replace(str(root), "<repo-root>")
    home = os.environ.get("HOME")
    if home:
        text = text.replace(home, "<home>")
    text = re.sub(r"/srv/[^\s)\]'}\"]+", "<srv-path>", text)
    home_prefix = "/" + "home/"
    text = re.sub(re.escape(home_prefix) + r"[^\s)\]'}\"]+", "<home-path>", text)
    text = re.sub(r"/tmp/[^\s)\]'}\"]+", "<tmp-path>", text)
    text = re.sub(r"/mnt/[^\s)\]'}\"]+", "<mnt-path>", text)
    text = re.sub(r"target/(debug|release)/[^\s)\]'}\"]*", "target/<profile>/<path>", text)
    return text.strip()


def run_case(root: Path, case: dict[str, str]) -> dict[str, Any]:
    command = [
        "cargo",
        "test",
        "-p",
        case["crate"],
        "--test",
        "transport_conformance",
        case["test"],
        "--",
        "--exact",
    ]
    proc = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = sanitize(proc.stdout, root)
    return {
        **case,
        "command": command,
        "exit_code": proc.returncode,
        "passed": proc.returncode == 0,
        "output": output,
    }


def write_outputs(root: Path, manifest: dict[str, Any]) -> None:
    evidence_dir = root / "docs" / "release" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    json_path = evidence_dir / "rc1-transport-fault-injection.json"
    md_path = evidence_dir / "RC1_TRANSPORT_FAULT_INJECTION.md"

    json_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    lines = [
        "# RC1 Transport Fault-Injection Evidence",
        "",
        "This evidence was generated from the normalized Xenia source tree.",
        "It proves the current transport conformance suite covers the minimum",
        "RC1 malformed-transport cases without relying on local machine paths,",
        "runtime state, or device-dependent infrastructure.",
        "",
        f"- generated_at_utc: `{manifest['generated_at_utc']}`",
        f"- all_cases_passed: `{str(manifest['all_cases_passed']).lower()}`",
        f"- cases: `{len(manifest['cases'])}`",
        "",
        "## Covered cases",
        "",
        "| Case | Crate | Test | Result |",
        "| --- | --- | --- | --- |",
    ]
    for case in manifest["cases"]:
        result = "PASS" if case["passed"] else "FAIL"
        lines.append(f"| `{case['id']}` | `{case['crate']}` | `{case['test']}` | `{result}` |")
    lines += [
        "",
        "## RC1 conclusion",
        "",
        "The transport fault-injection soft blocker is satisfied only when every",
        "listed case passes and `xenia.release.toml` removes only the matching",
        "soft blocker. Xenia remains `pre-rc`; this evidence does not promote the",
        "release train by itself.",
        "",
    ]
    md_path.write_text("\n".join(lines))
    print(f"wrote manifest: {json_path.relative_to(root)}")
    print(f"wrote markdown: {md_path.relative_to(root)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia peer repository root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not (root / "Cargo.toml").is_file():
        print(f"FAIL: {root} does not look like the xenia-peer workspace", file=sys.stderr)
        return 2

    cases = [run_case(root, case) for case in CASES]
    manifest = {
        "schema": "xenia.rc1.transport_fault_injection.v1",
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "release_status": "pre-rc",
        "evidence_scope": "transport fault-injection soft blocker",
        "all_cases_passed": all(case["passed"] for case in cases),
        "cases": cases,
    }
    write_outputs(root, manifest)

    if not manifest["all_cases_passed"]:
        for case in cases:
            if not case["passed"]:
                print(f"FAIL: {case['id']} ({case['test']})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
