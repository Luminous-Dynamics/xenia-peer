# SQLite V2 Qualification Evidence

This directory defines the retained evidence produced by `run_destructive_qualification.sh` for ADR-019/020/021.

The evidence bundle is not itself an authorization token and does not make a store healthy. It records the environment and observed crash/recovery outcomes used to qualify one exact implementation/dependency lineage.

## Required bundle

A completed run contains at least:

- `environment.txt` — GitHub/run identity when available, Rust/Cargo versions, kernel/OS, and filesystem/mount information;
- `Cargo.lock` and `Cargo.lock.sha256` — exact dependency solution;
- `rusqlite-tree.txt` and `libsqlite3-sys-tree.txt` — resolved wrapper/native dependency lineage;
- `sqlite-source.txt` — runtime `sqlite_version()` and `sqlite_source_id()`;
- `writer-ownership.txt` — competing-writer refusal and stale-lifecycle recovery result;
- `c0-c10.tsv` — 22 deterministic crash outcomes: admission C0-C10 plus `EffectArmed` C0-C10;
- `commit-races.tsv` — repeated SIGKILL races across the COMMIT window;
- `summary.txt` — matrix cardinality and outcome counts;
- `result.txt` — `PASS` or `FAIL` plus script exit code;
- `logs/` — per-case child/inspection logs;
- `EVIDENCE.sha256` — SHA-256 manifest over every other retained file.

The GitHub workflow uploads the bundle with `if: always()`, so a failed qualification should still preserve the evidence generated before the failure.

## Deterministic C0-C10 interpretation

For both transaction classes:

- C0-C8 must recover to the exact previous committed state (`OUTCOME=absent`);
- C9-C10 must recover to the exact new committed state (`OUTCOME=committed`);
- every recovered lifecycle must remain `HEALTH=RecoveryRequired`;
- committed cases must reconstruct the relevant persistence-proof digest from durable facts;
- no partial row/frontier/link state is accepted.

`c0-c10.tsv` must contain exactly 22 data rows.

## COMMIT-race interpretation

The COMMIT-window harness releases a child from a pre-COMMIT barrier and races `SIGKILL` at multiple small delays. Each timing is repeated.

For a race case, either of these is valid after ADR-021 pager recovery:

1. `OUTCOME=absent` with the exact previous frontier/state; or
2. `OUTCOME=committed` with the exact complete transaction/frontier/proof facts.

A race does not need to produce both outcomes on every machine. The security invariant is atomic canonicalization, not outcome diversity.

The current profile records 80 race rows: 8 delays × 5 repetitions × 2 transaction classes.

`child_alive_at_kill` records whether the process still appeared live when the kill was attempted; `child_exit_status` records the subsequent wait status. A child that exits with an unexpected non-zero status before the kill attempt is a qualification failure rather than being masked by the recovered database state.

## SQLite source boundary

ADR-021 qualifies rollback-journal recovery only against the pinned runtime identity recorded in `sqlite-source.txt`.

The current exact profile is:

```text
SQLITE_VERSION=3.53.4
SQLITE_SOURCE_ID=2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc
```

A different SQLite source ID is a new evidence lineage and requires the destructive qualification to be rerun.

## Verification

After downloading/extracting an artifact:

```sh
cd <artifact-directory>
sha256sum -c EVIDENCE.sha256
grep -Fx 'QUALIFICATION_RESULT=PASS' result.txt
[ "$(($(wc -l < c0-c10.tsv) - 1))" -eq 22 ]
[ "$(($(wc -l < commit-races.tsv) - 1))" -eq 80 ]
grep -Fx 'SQLITE_VERSION=3.53.4' sqlite-source.txt
grep -Fx 'SQLITE_SOURCE_ID=2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc' sqlite-source.txt
```

The evidence establishes only the named local SQLite/profile crash properties in the recorded environment. It does not prove resistance to whole-store rollback without an external frontier anchor, authenticate persisted grant issuance by itself, authorize recovery, or authorize any privileged external effect.
