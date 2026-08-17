from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "check-post-normalization.py"
)


def create_expected_apps(root: Path) -> None:
    for name in ("xenia-peer", "xenia-viewer", "sovereign-admin"):
        (root / "apps" / name).mkdir(parents=True, exist_ok=True)


def run_check(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(root)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class PostNormalizationScopeTests(unittest.TestCase):
    def test_ignored_agent_worktree_git_metadata_is_not_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_expected_apps(root)

            nested = (
                root
                / ".claude"
                / "worktrees"
                / "agent-copy"
                / ".git"
            )
            nested.parent.mkdir(parents=True)
            nested.write_text(
                "gitdir: /tmp/example\n",
                encoding="utf-8",
            )

            generated = (
                root
                / ".claude"
                / "worktrees"
                / "agent-copy"
                / "apps"
                / "example"
                / "dist"
            )
            generated.mkdir(parents=True)

            result = run_check(root)
            combined = result.stdout + result.stderr

            self.assertEqual(result.returncode, 0, msg=combined)
            self.assertNotIn(".claude/worktrees", combined)
            self.assertIn("failures=0", result.stdout)

    def test_canonical_nested_git_metadata_still_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_expected_apps(root)

            nested = root / "crates" / "unexpected" / ".git"
            nested.parent.mkdir(parents=True)
            nested.mkdir()

            result = run_check(root)
            combined = result.stdout + result.stderr

            self.assertEqual(result.returncode, 1, msg=combined)
            self.assertIn(
                "nested Git metadata remains outside archive",
                combined,
            )

    def test_canonical_generated_output_still_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_expected_apps(root)

            (root / "apps" / "sovereign-admin" / "dist").mkdir()

            result = run_check(root)
            combined = result.stdout + result.stderr

            self.assertEqual(result.returncode, 1, msg=combined)
            self.assertIn(
                "active generated/archive artifact remains outside archive",
                combined,
            )


if __name__ == "__main__":
    unittest.main()
