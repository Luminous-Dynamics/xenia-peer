from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-runtime-risk-patterns.py"


def run_scan(
    source: str,
    *,
    filename: str = "adversarial_tests.rs",
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / filename).write_text(source, encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(root),
                "--strict",
                "--max-lines",
                "50",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


class RuntimeRiskScopeTests(unittest.TestCase):
    def test_exact_file_cfg_test_reclassifies_split_module(self) -> None:
        result = run_scan(
            "#![cfg(test)]\nfn adversarial() { value.unwrap(); }\n"
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=combined)
        self.assertIn("unwrap           runtime=   0 tests/examples=   1", result.stdout)
        self.assertIn("unwrap [test/example]", result.stdout)

    def test_tests_like_filename_without_proof_remains_runtime(self) -> None:
        result = run_scan(
            "fn adversarial() { value.unwrap(); }\n",
            filename="operator_adversarial_tests.rs",
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, msg=combined)
        self.assertIn("unwrap           runtime=   1 tests/examples=   0", result.stdout)
        self.assertIn("unwrap [runtime]", result.stdout)
        self.assertIn("FAIL: --strict enabled", result.stderr)

    def test_broad_file_cfg_remains_runtime_visible(self) -> None:
        result = run_scan(
            '#![cfg(any(feature = "capture", test))]\n'
            "fn maybe_runtime() { value.expect(\"runtime\"); }\n"
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, msg=combined)
        self.assertIn("expect           runtime=   1 tests/examples=   0", result.stdout)
        self.assertIn("expect [runtime]", result.stdout)

    def test_comment_claim_cannot_hide_runtime_finding(self) -> None:
        result = run_scan(
            "// #![cfg(test)]\nfn runtime() { panic!(\"still runtime\"); }\n"
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, msg=combined)
        self.assertIn("panic            runtime=   1 tests/examples=   0", result.stdout)
        self.assertIn("panic [runtime]", result.stdout)


if __name__ == "__main__":
    unittest.main()
