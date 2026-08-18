from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-secure-defaults.py"
MANIFEST = REPO_ROOT / "xenia.safety.toml"


def run_scan(source: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        shutil.copyfile(
            MANIFEST,
            root / "xenia.safety.toml",
        )

        (root / "src").mkdir()
        (root / "src" / "main.rs").write_text(
            source,
            encoding="utf-8",
        )

        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(root),
                "--max-lines",
                "50",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


class SecureDefaultScopeTests(unittest.TestCase):
    def test_cfg_test_literals_do_not_enter_runtime_review_queue(self) -> None:
        loopback = "http" + "://localhost:8134"
        bypass = "skip_" + "consent"
        source = r"""
fn runtime_path() {}

#[cfg(test)]
mod tests {
    const LOOPBACK: &str = "__LOOPBACK__";
    const BYPASS_FIXTURE: &str = "__BYPASS__";
}
"""
        source = source.replace("__LOOPBACK__", loopback)
        source = source.replace("__BYPASS__", bypass)
        result = run_scan(source)

        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=combined)
        self.assertIn(
            "secure-default scan: hard=0 warning=0",
            result.stdout,
        )
        self.assertNotIn("LOOPBACK", combined)
        self.assertNotIn("BYPASS_FIXTURE", combined)

    def test_runtime_plaintext_literal_remains_visible(self) -> None:
        endpoint = "http" + "://127.0.0.1:9999"
        source = r"""
const RUNTIME_ENDPOINT: &str = "__ENDPOINT__";
"""
        result = run_scan(
            source.replace("__ENDPOINT__", endpoint)
        )

        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=combined)
        self.assertIn(
            "secure-default scan: hard=0 warning=1",
            result.stdout,
        )
        self.assertIn("RUNTIME_ENDPOINT", combined)


if __name__ == "__main__":
    unittest.main()
