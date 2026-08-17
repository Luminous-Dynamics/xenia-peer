import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


class XeniaValidateOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        scripts = self.root / "scripts"
        scripts.mkdir()

        source = Path(__file__).resolve().parents[1] / "xenia-validate.sh"
        shutil.copy2(source, scripts / "xenia-validate.sh")

        # Keep this fixture independent of whether the host running the test
        # has Rust installed. The fixture contains no Cargo.toml, so the stub
        # is only needed to let the validator reach its final summary.
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        cargo = fake_bin / "cargo"
        cargo.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        cargo.chmod(0o755)
        self.fake_bin = fake_bin

    def tearDown(self):
        self.tmp.cleanup()

    def write_hygiene(self, *, exit_code=0):
        script = self.root / "scripts" / "xenia-hygiene-audit.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "for i in $(seq 1 250); do\n"
            "  echo VALIDATOR_NOISE_MARKER-$i\n"
            "done\n"
            f"exit {exit_code}\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

    def run_validator(self, evidence_name, *, verbose=False):
        evidence = self.root / evidence_name
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env["XENIA_VALIDATION_DIR"] = str(evidence)
        env["XENIA_VERBOSE"] = "1" if verbose else "0"
        result = subprocess.run(
            ["bash", "scripts/xenia-validate.sh", "."],
            cwd=self.root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return result, evidence

    def test_default_mode_keeps_success_noise_in_evidence_logs(self):
        self.write_hygiene()
        result, evidence = self.run_validator("evidence-default")

        self.assertEqual(result.returncode, 0, result.stderr)
        combined = result.stdout + result.stderr
        self.assertNotIn("VALIDATOR_NOISE_MARKER-250", combined)
        self.assertIn("RESULT: PASS", result.stdout)
        self.assertIn(f"Evidence: {evidence}", result.stdout)

        logs = sorted(evidence.glob("*.log"))
        self.assertTrue(logs)
        self.assertTrue(
            any("VALIDATOR_NOISE_MARKER-250" in log.read_text() for log in logs)
        )
        summary_path = evidence / "summary.tsv"
        summary = summary_path.read_text(encoding="utf-8")
        self.assertIn("PASS", summary)
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(summary_path.stat().st_mode), 0o600)
        self.assertTrue(all(stat.S_IMODE(log.stat().st_mode) == 0o600 for log in logs))

    def test_verbose_mode_streams_success_output_and_keeps_evidence(self):
        self.write_hygiene()
        result, evidence = self.run_validator("evidence-verbose", verbose=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VALIDATOR_NOISE_MARKER-250", result.stdout + result.stderr)
        self.assertTrue((evidence / "summary.tsv").is_file())
        self.assertTrue(list(evidence.glob("*.log")))

    def test_hard_failure_prints_head_and_tail_and_returns_nonzero(self):
        self.write_hygiene(exit_code=7)
        result, evidence = self.run_validator("evidence-failure")

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FAIL: command failed (7): scripts/xenia-hygiene-audit.sh .",
            result.stderr,
        )
        self.assertIn("first 20 log lines", result.stderr)
        self.assertIn("VALIDATOR_NOISE_MARKER-1", result.stderr)
        self.assertIn("last 20 log lines", result.stderr)
        self.assertIn("VALIDATOR_NOISE_MARKER-250", result.stderr)
        self.assertNotIn("VALIDATOR_NOISE_MARKER-125", result.stderr)
        self.assertIn("xenia validation failed with 1 failure(s)", result.stderr)
        self.assertIn("RESULT: FAIL", result.stderr)
        self.assertIn(f"Evidence: {evidence}", result.stderr)
        summary = (evidence / "summary.tsv").read_text(encoding="utf-8")
        self.assertIn("FAIL\tscripts/xenia-hygiene-audit.sh .", summary)

    def test_successful_warning_lines_are_surfaced_without_full_log_dump(self):
        script = self.root / "scripts" / "xenia-hygiene-audit.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'WARN xenia_fixture: deliberate safety warning'\n"
            "for i in $(seq 1 250); do echo QUIET_AFTER_WARNING-$i; done\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

        result, evidence = self.run_validator("evidence-warning")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("deliberate safety warning", result.stderr)
        self.assertNotIn("QUIET_AFTER_WARNING-250", result.stdout + result.stderr)
        summary = (evidence / "summary.tsv").read_text(encoding="utf-8")
        self.assertIn("emitted warning lines", summary)


if __name__ == "__main__":
    unittest.main()
