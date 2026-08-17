#!/usr/bin/env python3
"""Contract tests for scripts/xenia-vet-delta.sh."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "xenia-vet-delta.sh"


class XeniaVetDeltaTests(unittest.TestCase):
    def run_helper(self, *args: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "supply-chain").mkdir()
            (root / "supply-chain" / "config.toml").write_text("[cargo-vet]\nversion = \"0.10\"\n")

            fake_bin = root / "bin"
            fake_bin.mkdir()
            log = root / "cargo.log"
            cargo = fake_bin / "cargo"
            cargo.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf '%s\\n' \"$*\" >> \"$XENIA_TEST_CARGO_LOG\"\n"
            )
            cargo.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            env["XENIA_TEST_CARGO_LOG"] = str(log)

            proc = subprocess.run(
                [str(SCRIPT), *args],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            calls = log.read_text().splitlines() if log.exists() else []
            return proc, calls

    def test_review_uses_locked_local_diff_only(self) -> None:
        proc, calls = self.run_helper("review", "webbrowser", "1.2.1", "1.2.2")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            calls,
            ["vet diff --locked --mode=local webbrowser 1.2.1 1.2.2"],
        )
        self.assertIn("certify it explicitly without an editor", proc.stdout)

    def test_certify_refuses_without_review_attestation(self) -> None:
        proc, calls = self.run_helper(
            "certify",
            "webbrowser",
            "1.2.1",
            "1.2.2",
            "--notes",
            "reviewed",
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn("requires --reviewed", proc.stderr)

    def test_certify_refuses_without_notes(self) -> None:
        proc, calls = self.run_helper(
            "certify",
            "webbrowser",
            "1.2.1",
            "1.2.2",
            "--reviewed",
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn("requires non-empty --notes", proc.stderr)

    def test_certify_records_delta_then_runs_locked_gate(self) -> None:
        proc, calls = self.run_helper(
            "certify",
            "webbrowser",
            "1.2.1",
            "1.2.2",
            "--reviewed",
            "--criteria",
            "safe-to-deploy",
            "--who",
            "tester <tester@example.invalid>",
            "--notes",
            "reviewed security delta",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            calls,
            [
                "vet certify --locked webbrowser 1.2.1 1.2.2 --criteria safe-to-deploy --notes reviewed security delta --who tester <tester@example.invalid>",
                "vet --locked",
            ],
        )

    def test_check_is_noninteractive_locked_gate(self) -> None:
        proc, calls = self.run_helper("check")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(calls, ["vet --locked"])


if __name__ == "__main__":
    unittest.main()
