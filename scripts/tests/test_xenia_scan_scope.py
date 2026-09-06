from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from xenia_scan_scope import (
    cfg_test_only_lines,
    iter_repo_files,
    rust_file_is_test_only,
)


class ScanScopeTests(unittest.TestCase):
    def test_git_scope_includes_untracked_work_but_not_ignored_agent_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text(".claude/\nxenia-peer-state/\n")
            (root / "src").mkdir()
            (root / "src" / "tracked.rs").write_text("fn tracked() {}\n")
            subprocess.run(
                ["git", "-C", str(root), "add", ".gitignore", "src/tracked.rs"],
                check=True,
            )
            (root / "src" / "untracked.rs").write_text("fn untracked() {}\n")
            ignored = root / ".claude" / "worktrees" / "copy" / "src"
            ignored.mkdir(parents=True)
            (ignored / "duplicate.rs").write_text("fn duplicate() { panic!() }\n")
            state = root / "xenia-peer-state"
            state.mkdir()
            (state / "generated.rs").write_text("fn generated() { panic!() }\n")

            paths = {
                path.relative_to(root).as_posix()
                for path in iter_repo_files(
                    root,
                    suffixes={".rs"},
                )
            }
            self.assertEqual(paths, {"src/tracked.rs", "src/untracked.rs"})

    def test_filesystem_fallback_uses_same_skip_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "main.rs").write_text("fn main() {}\n")
            ignored = root / ".claude" / "worktrees"
            ignored.mkdir(parents=True)
            (ignored / "copy.rs").write_text("panic!()\n")

            paths = {
                path.relative_to(root).as_posix()
                for path in iter_repo_files(
                    root,
                    suffixes={".rs"},
                )
            }
            self.assertEqual(paths, {"src/main.rs"})

    def test_cfg_test_mask_does_not_hide_runtime_tail(self) -> None:
        lines = [
            "#[cfg(test)]",
            "use crate::test_support::Fixture;",
            "fn runtime_before() { value.unwrap(); }",
            '#[cfg(any(feature = "capture", test))]',
            "use crate::capture::Frame;",
            "fn runtime_middle() { value.expect(\"runtime\"); }",
            "#[cfg(test)]",
            "mod tests {",
            "    #[test]",
            "    fn smoke() { value.unwrap(); }",
            "}",
            "fn runtime_after() { value.unwrap(); }",
        ]

        masked = cfg_test_only_lines(lines)
        self.assertTrue({1, 2}.issubset(masked))
        self.assertTrue({7, 8, 9, 10, 11}.issubset(masked))
        self.assertNotIn(3, masked)
        self.assertNotIn(4, masked)
        self.assertNotIn(5, masked)
        self.assertNotIn(6, masked)
        self.assertNotIn(12, masked)

    def test_exact_file_level_cfg_test_is_authoritative(self) -> None:
        lines = [
            "\ufeff//! Adversarial test module.",
            "#![allow(dead_code)]",
            "#! [ cfg ( test ) ]",
            "fn adversarial_fixture() { value.unwrap(); }",
        ]
        self.assertTrue(rust_file_is_test_only(lines))

    def test_broader_file_cfg_remains_production_visible(self) -> None:
        lines = [
            '#![cfg(any(feature = "capture", test))]',
            "fn maybe_runtime() { value.unwrap(); }",
        ]
        self.assertFalse(rust_file_is_test_only(lines))

    def test_late_file_cfg_cannot_reclassify_runtime_prefix(self) -> None:
        lines = [
            "fn runtime_before() { value.unwrap(); }",
            "#![cfg(test)]",
            "fn tests_after() { value.unwrap(); }",
        ]
        self.assertFalse(rust_file_is_test_only(lines))

    def test_comment_string_and_block_comment_do_not_prove_test_scope(self) -> None:
        self.assertFalse(
            rust_file_is_test_only(
                [
                    "// #![cfg(test)]",
                    'const CLAIM: &str = "#![cfg(test)]";',
                ]
            )
        )
        self.assertFalse(
            rust_file_is_test_only(
                [
                    "/* #![cfg(test)] */",
                    "fn runtime() { value.unwrap(); }",
                ]
            )
        )


if __name__ == "__main__":
    unittest.main()
