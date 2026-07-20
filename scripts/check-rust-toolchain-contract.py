#!/usr/bin/env python3
"""Verify Xenia's declared and executable Rust toolchain contract."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass


REQUIRED_COMPONENTS = {"rustfmt", "clippy"}
REQUIRED_TARGETS = {"wasm32-unknown-unknown"}
TOOLCHAIN_ACTION_RE = re.compile(r"dtolnay/rust-toolchain@([^\s#]+)")
VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass(frozen=True, order=True)
class RustVersion:
    major: int
    minor: int
    patch: int = 0

    @classmethod
    def parse(cls, value: str, *, label: str) -> "RustVersion":
        match = VERSION_RE.match(value.strip())
        if match is None:
            raise ValueError(f"{label} is not a numeric Rust release: {value!r}")
        return cls(*(int(part or 0) for part in match.groups()))


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


def read_toml(path: pathlib.Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def command_version(command: str) -> RustVersion:
    try:
        result = subprocess.run(
            [command, "--version"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"cannot execute {command} --version: {exc}") from exc
    fields = result.stdout.strip().split()
    if len(fields) < 2:
        raise ValueError(f"unexpected {command} --version output: {result.stdout!r}")
    return RustVersion.parse(fields[1], label=command)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--runtime",
        action="store_true",
        help="also require installed rustc/cargo versions at or above the MSRV",
    )
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    failures: list[str] = []

    try:
        cargo = read_toml(root / "Cargo.toml")
        msrv_text = str(cargo["workspace"]["package"]["rust-version"])
        msrv = RustVersion.parse(msrv_text, label="workspace.package.rust-version")
    except (KeyError, ValueError) as exc:
        fail(str(exc))
        return 1

    try:
        toolchain = read_toml(root / "rust-toolchain.toml")["toolchain"]
        channel_text = str(toolchain["channel"])
        channel = RustVersion.parse(channel_text, label="rust-toolchain channel")
        components = {str(value) for value in toolchain.get("components", [])}
        targets = {str(value) for value in toolchain.get("targets", [])}
    except (KeyError, ValueError) as exc:
        fail(str(exc))
        return 1

    if channel_text in {"stable", "beta", "nightly"} or channel_text.count(".") != 2:
        failures.append("rust-toolchain.toml must pin an exact x.y.z release")
    if channel < msrv:
        failures.append(
            f"pinned toolchain {channel_text} is older than workspace MSRV {msrv_text}"
        )
    missing_components = sorted(REQUIRED_COMPONENTS - components)
    if missing_components:
        failures.append("missing Rust components: " + ", ".join(missing_components))
    missing_targets = sorted(REQUIRED_TARGETS - targets)
    if missing_targets:
        failures.append("missing Rust targets: " + ", ".join(missing_targets))

    workflow_refs: list[tuple[pathlib.Path, str]] = []
    workflow_root = root / ".github" / "workflows"
    for path in sorted(workflow_root.glob("*.yml")) + sorted(workflow_root.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        workflow_refs.extend((path, match.group(1)) for match in TOOLCHAIN_ACTION_RE.finditer(text))
    if not workflow_refs:
        failures.append("no dtolnay/rust-toolchain actions were found in CI workflows")
    for path, reference in workflow_refs:
        if reference != channel_text:
            failures.append(
                f"{path.relative_to(root)} uses dtolnay/rust-toolchain@{reference}; expected @{channel_text}"
            )

    if args.runtime:
        for command in ("rustc", "cargo"):
            try:
                installed = command_version(command)
            except ValueError as exc:
                failures.append(str(exc))
                continue
            if installed < msrv:
                failures.append(
                    f"installed {command} {installed.major}.{installed.minor}.{installed.patch} "
                    f"is older than MSRV {msrv_text}"
                )

    if failures:
        for message in failures:
            fail(message)
        return 1

    mode = "declarations + runtime" if args.runtime else "declarations"
    print(
        f"Rust toolchain contract: PASS ({mode}; MSRV {msrv_text}; pinned {channel_text}; "
        f"{len(workflow_refs)} CI action reference(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
