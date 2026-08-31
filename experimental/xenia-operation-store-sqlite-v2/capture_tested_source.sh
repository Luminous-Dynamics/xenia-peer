#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
EVIDENCE="${1:-$ROOT/qualification-evidence}"
SNAPSHOT="$EVIDENCE/tested-source"
mkdir -p "$SNAPSHOT/src/bin" "$SNAPSHOT/hardening"

cp Cargo.toml "$SNAPSHOT/Cargo.toml"
cp src/lib.rs "$SNAPSHOT/src/lib.rs"
cp src/bin/store_lock_probe.rs "$SNAPSHOT/src/bin/store_lock_probe.rs"
cp src/bin/store_crash_probe.rs "$SNAPSHOT/src/bin/store_crash_probe.rs"
cp src/bin/sqlite_profile_probe.rs "$SNAPSHOT/src/bin/sqlite_profile_probe.rs"
cp run_destructive_qualification.sh "$SNAPSHOT/run_destructive_qualification.sh"
cp verify_production_crash_surface.sh "$SNAPSHOT/verify_production_crash_surface.sh"
cp verify_qualification_artifact.sh "$SNAPSHOT/verify_qualification_artifact.sh"
cp capture_tested_source.sh "$SNAPSHOT/capture_tested_source.sh"
cp QUALIFICATION_EVIDENCE.md "$SNAPSHOT/QUALIFICATION_EVIDENCE.md"
cp apply_qualification_hardening.py "$SNAPSHOT/hardening/apply_qualification_hardening.py"
for script in repair_*.py inject_*.py; do
  [[ -f "$script" ]] || continue
  cp "$script" "$SNAPSHOT/hardening/$script"
done

if git diff --quiet -- Cargo.toml src/lib.rs src/bin run_destructive_qualification.sh \
  verify_production_crash_surface.sh verify_qualification_artifact.sh capture_tested_source.sh \
  QUALIFICATION_EVIDENCE.md apply_qualification_hardening.py repair_*.py inject_*.py; then
  dirty=0
else
  dirty=1
fi

{
  echo 'SOURCE_STATE_SCHEMA=xenia-sqlite-v2-tested-source-v1'
  echo "GITHUB_SHA=${GITHUB_SHA:-unknown}"
  echo "TRACKED_SOURCE_DIRTY=${dirty}"
  echo "LIB_RS_SHA256=$(sha256sum src/lib.rs | awk '{print $1}')"
  echo "CARGO_TOML_SHA256=$(sha256sum Cargo.toml | awk '{print $1}')"
  echo "STORE_CRASH_PROBE_SHA256=$(sha256sum src/bin/store_crash_probe.rs | awk '{print $1}')"
  echo "DESTRUCTIVE_RUNNER_SHA256=$(sha256sum run_destructive_qualification.sh | awk '{print $1}')"
  echo "ARTIFACT_VERIFIER_SHA256=$(sha256sum verify_qualification_artifact.sh | awk '{print $1}')"
  echo "SOURCE_CAPTURE_SHA256=$(sha256sum capture_tested_source.sh | awk '{print $1}')"
} > "$EVIDENCE/source-state.txt"

git diff -- \
  Cargo.toml src/lib.rs src/bin run_destructive_qualification.sh \
  verify_production_crash_surface.sh verify_qualification_artifact.sh capture_tested_source.sh \
  QUALIFICATION_EVIDENCE.md apply_qualification_hardening.py repair_*.py inject_*.py \
  > "$EVIDENCE/tested-source.patch"

(
  cd "$SNAPSHOT"
  find . -type f -print0 | sort -z | xargs -0 sha256sum > SOURCE.sha256
)

cat "$EVIDENCE/source-state.txt"
