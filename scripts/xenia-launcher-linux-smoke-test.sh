#!/usr/bin/env bash
# Real end-to-end smoke test for the xenia-launcher-linux .deb: install it
# via apt into a container that has NOTHING but the package's own declared
# Depends: (no -dev headers, no build tooling), then actually run the
# binary under a virtual display + D-Bus session and confirm it stays
# alive.
#
# This exists because the CI job that BUILDS the .deb already has
# libappindicator3-dev etc. installed to link against -- running a smoke
# test in that same job would not have caught a real bug found by hand
# 2026-07-31: tray-icon's Linux backend dlopen()s libappindicator at
# runtime rather than linking it, so `dpkg-shlibdeps`-based `$auto`
# dependency detection can't see it, and without the library actually
# installed the app doesn't just lose its tray icon -- it panics and the
# whole process dies. A clean container is the only way to test what a
# real end user's machine (which only has what apt says it needs) sees.
#
# Usage (from repo root, inside a fresh ubuntu:24.04-or-similar container):
#   scripts/xenia-launcher-linux-smoke-test.sh /path/to/xenia-launcher.deb
#
# Exits non-zero (and prints the launcher's log) if the binary exits
# within the startup window -- that's the real failure signal, not just
# "the command errored."

set -euo pipefail

DEB="${1:?usage: $0 <path-to-deb>}"
STARTUP_WINDOW_SECS="${STARTUP_WINDOW_SECS:-5}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Install ONLY what the package declares (plus apt's own dependency
# resolution) -- this is the whole point of running in a fresh container.
apt-get install -y -qq "$DEB"
# Test-only infrastructure, not a runtime dependency of the app itself.
apt-get install -y -qq xvfb dbus-x11 procps

Xvfb :98 -screen 0 1024x768x24 >/tmp/xvfb.log 2>&1 &
XVFB_PID=$!
sleep 1

DISPLAY=:98 dbus-run-session -- xenia-launcher > /tmp/launcher.log 2>&1 &
sleep "$STARTUP_WINDOW_SECS"

PID=$(pgrep -f '(^|/)xenia-launcher$' || true)
if [[ -z "$PID" ]]; then
  echo "FAIL: xenia-launcher was not still running after ${STARTUP_WINDOW_SECS}s"
  echo "--- launcher log ---"
  cat /tmp/launcher.log
  kill "$XVFB_PID" 2>/dev/null || true
  exit 1
fi

echo "OK: xenia-launcher still running after ${STARTUP_WINDOW_SECS}s (pid $PID)"
echo "--- launcher log ---"
cat /tmp/launcher.log

kill "$PID" 2>/dev/null || true
kill "$XVFB_PID" 2>/dev/null || true
