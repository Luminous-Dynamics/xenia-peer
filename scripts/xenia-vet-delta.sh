#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/xenia-vet-delta.sh review <crate> <from-version> <to-version> [--criteria <name>]
  scripts/xenia-vet-delta.sh certify <crate> <from-version> <to-version> --reviewed --notes <text> [--criteria <name>] [--who <identity>]
  scripts/xenia-vet-delta.sh check

Review is deliberately separate from certification. The helper never opens an
editor and never auto-certifies a dependency delta.

Examples:
  scripts/xenia-vet-delta.sh review webbrowser 1.2.1 1.2.2

  scripts/xenia-vet-delta.sh certify webbrowser 1.2.1 1.2.2 \
    --reviewed \
    --notes "Reviewed Unix BROWSER tokenization and macOS NSWorkspace migration."
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

ensure_repo() {
  [[ -f supply-chain/config.toml ]] \
    || fail "run from the xenia-peer repository root (supply-chain/config.toml not found)"
}

run_check() {
  echo "+ cargo vet --locked"
  cargo vet --locked
}

[[ $# -ge 1 ]] || {
  usage >&2
  exit 2
}

need_cmd cargo
ensure_repo

command_name="$1"
shift

case "$command_name" in
  check)
    [[ $# -eq 0 ]] || fail "check does not accept additional arguments"
    run_check
    ;;

  review|certify)
    [[ $# -ge 3 ]] || {
      usage >&2
      exit 2
    }

    crate="$1"
    from_version="$2"
    to_version="$3"
    shift 3

    criteria="safe-to-deploy"
    who=""
    notes=""
    reviewed=0

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --criteria)
          [[ $# -ge 2 ]] || fail "--criteria requires a value"
          criteria="$2"
          shift 2
          ;;
        --who)
          [[ $# -ge 2 ]] || fail "--who requires a value"
          who="$2"
          shift 2
          ;;
        --notes)
          [[ $# -ge 2 ]] || fail "--notes requires a value"
          notes="$2"
          shift 2
          ;;
        --reviewed)
          reviewed=1
          shift
          ;;
        -h|--help)
          usage
          exit 0
          ;;
        *)
          fail "unknown argument: $1"
          ;;
      esac
    done

    if [[ "$command_name" == "review" ]]; then
      [[ "$reviewed" -eq 0 ]] || fail "--reviewed is only valid with certify"
      [[ -z "$notes" ]] || fail "--notes is only valid with certify"
      [[ -z "$who" ]] || fail "--who is only valid with certify"

      echo "+ cargo vet diff --locked --mode=local $crate $from_version $to_version"
      cargo vet diff --locked --mode=local "$crate" "$from_version" "$to_version"

      cat <<EOF_NEXT

Review complete. If the delta satisfies '$criteria', certify it explicitly without an editor:

  scripts/xenia-vet-delta.sh certify '$crate' '$from_version' '$to_version' \\
    --reviewed \\
    --criteria '$criteria' \\
    --notes '<what you reviewed and any relevant discretion>'
EOF_NEXT
      exit 0
    fi

    [[ "$reviewed" -eq 1 ]] \
      || fail "certification requires --reviewed to explicitly attest that you inspected the delta"
    [[ -n "$notes" ]] \
      || fail "certification requires non-empty --notes; record the security-relevant surfaces you reviewed"

    args=(
      vet certify --locked
      "$crate" "$from_version" "$to_version"
      --criteria "$criteria"
      --notes "$notes"
    )
    if [[ -n "$who" ]]; then
      args+=(--who "$who")
    fi

    printf '+ cargo'
    printf ' %q' "${args[@]}"
    printf '\n'
    cargo "${args[@]}"

    echo
    run_check

    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      echo
      echo "Audit metadata diff:"
      git diff -- supply-chain/audits.toml
    fi
    ;;

  -h|--help|help)
    usage
    ;;

  *)
    usage >&2
    fail "unknown command: $command_name"
    ;;
esac
