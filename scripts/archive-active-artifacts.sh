#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/archive-active-artifacts.sh [ROOT] [--apply]

Moves active tarballs and migration scratch scripts into _archive/YYYY-MM-DD-*
without deleting them. By default this is a dry run. Pass --apply to move files.

The script intentionally reports target/dist directories but does not move or
remove build output, because those directories are rebuildable and can be huge.
USAGE
}

root="."
apply=0
for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    -h|--help) usage; exit 0 ;;
    *) root="$arg" ;;
  esac
done

cd "$root"
stamp="$(date +%F)-xenia-migration-artifacts"
archive_dir="_archive/${stamp}"

echo "Archive directory: ${archive_dir}"
if [[ "$apply" -eq 0 ]]; then
  echo "Mode: dry-run. Re-run with --apply to move files."
else
  mkdir -p "${archive_dir}/tarballs" "${archive_dir}/scratch-scripts" "${archive_dir}/notes"
fi

move_or_print() {
  local src="$1"
  local dst_dir="$2"
  if [[ "$apply" -eq 1 ]]; then
    mkdir -p "$dst_dir"
    mv -- "$src" "$dst_dir/"
    echo "moved: $src -> $dst_dir/"
  else
    echo "would move: $src -> $dst_dir/"
  fi
}

while IFS= read -r -d '' file; do
  move_or_print "$file" "${archive_dir}/tarballs"
done < <(find . \
  -path './_archive' -prune -o \
  -type f \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zip' \) -print0)

while IFS= read -r -d '' file; do
  move_or_print "$file" "${archive_dir}/scratch-scripts"
done < <(find . \
  -path './_archive' -prune -o \
  -type f \( -name 'fix_*.py' -o -name '*_final*.py' -o -name '*migration*.py' \) -print0)

if [[ "$apply" -eq 1 ]]; then
  cat > "${archive_dir}/README.md" <<README
# ${stamp}

Archived migration artifacts from active Xenia paths. Files were moved to
preserve history while keeping the source workspace clean.
README
fi

echo
echo "Build output directories still present:"
find . -path './_archive' -prune -o -type d \( -name target -o -name dist -o -name pkg \) -print | sort || true
