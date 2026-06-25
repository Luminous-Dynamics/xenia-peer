# Archive Hygiene Runbook

Use this runbook whenever imports, exports, or agent migrations leave tarballs,
build outputs, or scratch scripts inside active Xenia paths.

## Goals

- Preserve every historical artifact.
- Remove archive/build debris from active crate and app directories.
- Keep `xenia-wire` small enough for protocol review and crates.io packaging.
- Keep `xenia-peer` clear enough for `cargo metadata`, CI, and release scripts.

## Safe cleanup commands

Run from the Xenia root:

```bash
stamp="$(date +%F)-xenia-migration-artifacts"
mkdir -p "_archive/${stamp}/tarballs" "_archive/${stamp}/scratch-scripts" "_archive/${stamp}/notes"

find . \
  -path './_archive' -prune -o \
  -type f \( -name '*.tar.gz' -o -name '*.tgz' \) -print \
  -exec mv {} "_archive/${stamp}/tarballs/" \;

find . \
  -path './_archive' -prune -o \
  -type f \( -name 'fix_*.py' -o -name '*_final*.py' \) -print \
  -exec mv {} "_archive/${stamp}/scratch-scripts/" \;

cat > "_archive/${stamp}/README.md" <<README
# ${stamp}

Archived migration artifacts from active Xenia paths. These files were moved to
preserve history while keeping the Cargo workspace clean.
README
```

## Build output cleanup

`target/` and `dist/` should not be archived by default because they are
rebuildable output. If a build artifact is needed for forensic reasons, move it
to `_archive/.../build-output/`; otherwise remove it after confirming no source
files live inside it.

```bash
find . \
  -path './_archive' -prune -o \
  -type d \( -name target -o -name dist \) -print
```

## Verification

```bash
scripts/xenia-hygiene-audit.sh .
cargo metadata --format-version 1 --no-deps
cargo check --workspace
cargo test --workspace --no-run
```

If any command fails, keep the archive intact and fix the active workspace.
