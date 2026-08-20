from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "xenia-vet-delta.sh"


class XeniaVetDeltaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

        self.tmp = Path(self.tempdir.name)
        self.bin_dir = self.tmp / "bin"
        self.bin_dir.mkdir()
        self.cargo_log = self.tmp / "cargo.log"

        cargo = self.bin_dir / "cargo"
        cargo.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -eu

                {
                  first=1
                  for arg in "$@"; do
                    if [ "$first" -eq 0 ]; then
                      printf '\t'
                    fi
                    printf '%s' "$arg"
                    first=0
                  done
                  printf '\n'
                } >> "$CARGO_LOG"

                if [ "${1:-}" = "vet" ] && [ "${2:-}" = "certify" ]; then
                  accept_all=0
                  for arg in "$@"; do
                    if [ "$arg" = "--accept-all" ]; then
                      accept_all=1
                    fi
                  done
                  if [ "$accept_all" -ne 1 ]; then
                    echo "fake cargo: certify would prompt without --accept-all" >&2
                    exit 97
                  fi
                fi

                exit 0
                """
            )
        )
        cargo.chmod(0o755)

        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.bin_dir}:{self.env['PATH']}"
        self.env["CARGO_LOG"] = str(self.cargo_log)

    def run_helper(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def cargo_calls(self) -> list[list[str]]:
        if not self.cargo_log.exists():
            return []
        return [line.split("\t") for line in self.cargo_log.read_text().splitlines()]

    def test_certify_requires_reviewed_before_running_cargo(self) -> None:
        result = self.run_helper(
            "certify",
            "demo-crate",
            "1.0.0",
            "1.0.1",
            "--notes",
            "Reviewed the delta.",
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("requires --reviewed", result.stderr)
        self.assertEqual(self.cargo_calls(), [])

    def test_certify_requires_nonempty_notes_before_running_cargo(self) -> None:
        result = self.run_helper(
            "certify",
            "demo-crate",
            "1.0.0",
            "1.0.1",
            "--reviewed",
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("requires non-empty --notes", result.stderr)
        self.assertEqual(self.cargo_calls(), [])

    def test_certify_passes_accept_all_only_after_review_attestation(self) -> None:
        result = self.run_helper(
            "certify",
            "demo-crate",
            "1.0.0",
            "1.0.1",
            "--reviewed",
            "--criteria",
            "safe-to-deploy",
            "--notes",
            "Reviewed parser and I/O changes.",
            "--who",
            "Example Reviewer",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        calls = self.cargo_calls()
        self.assertEqual(len(calls), 2, calls)

        certify = calls[0]
        self.assertEqual(certify[:6], [
            "vet",
            "certify",
            "--locked",
            "demo-crate",
            "1.0.0",
            "1.0.1",
        ])
        self.assertIn("--accept-all", certify)
        self.assertIn("--criteria", certify)
        self.assertIn("safe-to-deploy", certify)
        self.assertIn("--notes", certify)
        self.assertIn("Reviewed parser and I/O changes.", certify)
        self.assertIn("--who", certify)
        self.assertIn("Example Reviewer", certify)

        self.assertEqual(calls[1], ["vet", "--locked"])

    def test_review_remains_separate_and_does_not_certify(self) -> None:
        result = self.run_helper(
            "review",
            "demo-crate",
            "1.0.0",
            "1.0.1",
            "--criteria",
            "safe-to-deploy",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        calls = self.cargo_calls()
        self.assertEqual(calls, [[
            "vet",
            "diff",
            "--locked",
            "--mode=local",
            "demo-crate",
            "1.0.0",
            "1.0.1",
        ]])
        self.assertNotIn("--accept-all", calls[0])


if __name__ == "__main__":
    unittest.main()
