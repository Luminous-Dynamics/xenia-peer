from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "check-cargo-boundaries.py"
)


class CargoBoundaryScopeTests(unittest.TestCase):
    def test_ignored_agent_worktree_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            subprocess.run(
                ["git", "init", "-q", str(root)],
                check=True,
            )

            (root / ".gitignore").write_text(
                ".claude/\n",
                encoding="utf-8",
            )

            canonical = root / "crates" / "xenia-peer-core"
            canonical.mkdir(parents=True)
            (canonical / "Cargo.toml").write_text(
                """[package]
name = "xenia-peer-core"
version = "0.0.0"
edition = "2024"
""",
                encoding="utf-8",
            )

            ignored = (
                root
                / ".claude"
                / "worktrees"
                / "copy"
                / "crates"
                / "ignored"
            )
            ignored.mkdir(parents=True)
            (ignored / "Cargo.toml").write_text(
                """[package]
name = "xenia-ignored-worktree-copy"
version = "0.0.0"
edition = "2024"
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            combined = result.stdout + result.stderr

            self.assertEqual(
                result.returncode,
                0,
                msg=combined,
            )
            self.assertIn("xenia-peer-core", result.stdout)
            self.assertNotIn("xenia-ignored-worktree-copy", combined)
            self.assertNotIn(".claude/worktrees", combined)


if __name__ == "__main__":
    unittest.main()
