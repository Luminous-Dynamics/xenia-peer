#!/usr/bin/env bash
set -euo pipefail

exec "$(dirname "$0")/xenia-validate.sh" --static-only "$@"
