#!/usr/bin/env python3
"""Run one validation command with a hard wall-clock bound.

The command inherits stdout and stderr so CI logs remain live.  On POSIX the
child receives its own process group; timeout cleanup therefore terminates the
entire check rather than leaving grandchildren running in the background.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

TIMEOUT_EXIT = 124
TERMINATE_GRACE_SECS = 2.0


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=TERMINATE_GRACE_SECS)
        return
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass

    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        return
    process.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-secs", type=float, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    if args.timeout_secs <= 0:
        parser.error("--timeout-secs must be greater than zero")

    started = time.monotonic()
    try:
        process = subprocess.Popen(command, start_new_session=(os.name == "posix"))
    except OSError as exc:
        print(f"validation command could not start: {exc}", file=sys.stderr)
        return 127

    try:
        return process.wait(timeout=args.timeout_secs)
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        print(
            f"validation command timed out after {elapsed:.1f}s "
            f"(limit {args.timeout_secs:.1f}s): {' '.join(command)}",
            file=sys.stderr,
        )
        terminate_process_tree(process)
        return TIMEOUT_EXIT
    except KeyboardInterrupt:
        terminate_process_tree(process)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
