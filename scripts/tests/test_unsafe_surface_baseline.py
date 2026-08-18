from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-unsafe-surfaces.py"


def init_repo() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)

    subprocess.run(
        ["git", "init", "-q"],
        cwd=root,
        check=True,
    )

    (root / "src").mkdir()

    return tmp, root


def write_source(root: Path, count: int) -> None:
    lines = [
        "pub fn boundary() {",
    ]

    for index in range(count):
        lines.append(
            f"    unsafe {{ ffi_call_{index}(); }}"
        )

    lines.append("}")

    (root / "src" / "lib.rs").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def write_baseline(root: Path, count: int) -> Path:
    baseline = root / "xenia.unsafe.toml"
    baseline.write_text(
        f'''schema = "xenia-unsafe-baseline-v1"

[[surface]]
path = "src/lib.rs"
owner = "test"
rationale = "test native boundary"
invariant = "test invariant"
evidence = "test evidence"
counts = {{ unsafe_block_or_fn = {count} }}
''',
        encoding="utf-8",
    )
    return baseline


def run_scan(
    root: Path,
    *extra: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(root),
            *extra,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class UnsafeSurfaceBaselineTests(unittest.TestCase):
    def test_exact_reviewed_baseline_passes(self) -> None:
        tmp, root = init_repo()
        try:
            write_source(root, 1)
            baseline = write_baseline(root, 1)

            result = run_scan(
                root,
                "--baseline",
                str(baseline),
                "--strict-baseline",
            )

            combined = (
                result.stdout + result.stderr
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=combined,
            )
            self.assertIn(
                "unsafe baseline matched exactly",
                result.stdout,
            )
        finally:
            tmp.cleanup()

    def test_unreviewed_growth_fails(self) -> None:
        tmp, root = init_repo()
        try:
            write_source(root, 2)
            baseline = write_baseline(root, 1)

            result = run_scan(
                root,
                "--baseline",
                str(baseline),
                "--strict-baseline",
            )

            combined = (
                result.stdout + result.stderr
            )

            self.assertEqual(
                result.returncode,
                1,
                msg=combined,
            )
            self.assertIn(
                "growth:",
                result.stdout,
            )
            self.assertIn(
                "expected=1 actual=2",
                result.stdout,
            )
        finally:
            tmp.cleanup()

    def test_reduction_requires_baseline_update(self) -> None:
        tmp, root = init_repo()
        try:
            write_source(root, 1)
            baseline = write_baseline(root, 2)

            result = run_scan(
                root,
                "--baseline",
                str(baseline),
                "--strict-baseline",
            )

            combined = (
                result.stdout + result.stderr
            )

            self.assertEqual(
                result.returncode,
                1,
                msg=combined,
            )
            self.assertIn(
                "stale-baseline:",
                result.stdout,
            )
            self.assertIn(
                "expected=2 actual=1",
                result.stdout,
            )
        finally:
            tmp.cleanup()

    def test_raw_strict_keeps_zero_unsafe_semantics(self) -> None:
        tmp, root = init_repo()
        try:
            write_source(root, 1)

            result = run_scan(
                root,
                "--strict",
            )

            combined = (
                result.stdout + result.stderr
            )

            self.assertEqual(
                result.returncode,
                1,
                msg=combined,
            )
            self.assertIn(
                "--strict enabled",
                result.stderr,
            )
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
