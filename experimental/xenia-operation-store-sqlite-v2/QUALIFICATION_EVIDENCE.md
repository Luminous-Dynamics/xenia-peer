# SQLite V2 Qualification Evidence

This directory defines the retained evidence produced for ADR-019/020/021.

The evidence bundle is not itself an authorization token and does not make a store healthy. It records the exact tested source, dependency/runtime identity, environment, and observed crash/recovery outcomes for one implementation lineage.

## Required bundle

A completed run contains at least:

- `environment.txt` — GitHub/run identity when available, Rust/Cargo versions, kernel/OS, and filesystem/mount information;
- `Cargo.lock` and `Cargo.lock.sha256` — exact dependency solution;
- `rusqlite-tree.txt` and `libsqlite3-sys-tree.txt` — resolved wrapper/native dependency lineage;
- `sqlite-source.txt` — runtime `sqlite_version()` and `sqlite_source_id()`;
- `writer-ownership.txt` — competing-writer refusal and stale-lifecycle recovery result;
- `c0-c10.tsv` — 22 deterministic crash outcomes: admission C0-C10 plus `EffectArmed` C0-C10;
- `commit-races.tsv` — 80 repeated SIGKILL races across the COMMIT window;
- `production-crash-surface.txt` — proof that the crash target requires the test feature and optimized production binaries do not contain the crash-control environment-variable names;
- `source-state.txt` — exact tested-source hashes and whether tracked source differed from the triggering Git commit;
- `tested-source/` — snapshot of the exact store source, probes, manifests, qualification scripts, and hardening transforms used by the run;
- `tested-source/SOURCE.sha256` — checksum manifest for that source snapshot;
- `tested-source.patch` — tracked diff between the triggering commit and the tested working tree;
- `summary.txt` — matrix cardinality and outcome counts;
- `result.txt` — destructive qualification `PASS` or `FAIL` plus script exit code;
- `logs/` and production-build logs — per-case/negative-test evidence;
- `verify_qualification_artifact.sh` — self-contained semantic verifier for the bundle;
- `EVIDENCE.sha256` — SHA-256 manifest over every other retained file.

The GitHub workflow uploads the bundle with `if: always()`, so a failed qualification should still preserve the evidence generated before the failure.

## Source binding and two-pass qualification

The workflow may apply deterministic hardening and `rustfmt` before tests. On the first successful qualification, those tested bytes may therefore differ from the branch commit that triggered the run.

`source-state.txt` records:

```text
TRACKED_SOURCE_DIRTY=1
```

for that case, and `tested-source.patch` records the exact difference. Such an artifact may justify the workflow's deterministic repair commit, but it is **not final promotion evidence**.

The repair commit triggers a new run. A promotion candidate requires a subsequent successful artifact with:

```text
TRACKED_SOURCE_DIRTY=0
```

meaning the exact tested tracked source was already committed at the triggering Git SHA. The artifact verifier reports this distinction as either:

```text
PROMOTION_SOURCE_STATE=dirty-first-pass-only
```

or:

```text
PROMOTION_SOURCE_STATE=clean-second-pass-candidate
```

A clean second pass is still not sufficient by itself to enable privileged effects; the remaining ADR-019 promotion gates, including external anti-rollback/governed-recovery composition, continue to apply.

## Deterministic C0-C10 interpretation

For both transaction classes:

- C0-C8 must recover to the exact previous committed state (`expected=absent`, `OUTCOME=absent`);
- C9-C10 must recover to the exact new committed state (`expected=present`, `OUTCOME=committed`);
- every recovered lifecycle must remain `HEALTH=RecoveryRequired`;
- committed cases must reconstruct the relevant persistence-proof digest from durable facts;
- no partial row/frontier/link state is accepted.

`c0-c10.tsv` must contain exactly 22 data rows and exactly one row for every transaction-class/C-point pair.

## COMMIT-race interpretation

The COMMIT-window harness releases a child from a pre-COMMIT barrier and races `SIGKILL` at multiple small delays. Each timing is repeated five times for both admission and `EffectArmed`.

For a race case, either of these is valid after ADR-021 pager recovery:

1. `OUTCOME=absent` with the exact previous frontier/state; or
2. `OUTCOME=committed` with the exact complete transaction/frontier/proof facts.

A race does not need to produce both outcomes on every machine. The security invariant is atomic canonicalization, not outcome diversity.

The current profile records 80 race rows: 8 delays × 5 repetitions × 2 transaction classes.

`child_alive_at_kill` records whether the process still appeared live when the kill was attempted; `child_exit_status` records the subsequent wait status. At least one race must attempt `SIGKILL` while the child still appears live. A child that exits with an unexpected non-zero status before the kill attempt is a qualification failure rather than being masked by the recovered database state.

## Production crash-surface boundary

`crash-injection` defaults off and the crash probe target declares it as a required feature.

The retained negative test requires both:

1. an explicit no-feature build of `store_crash_probe` fails with a Cargo diagnostic naming the exact target and `crash-injection` feature; and
2. optimized ordinary binaries do not contain `XENIA_SQLITE_V2_CRASH_AT` or `XENIA_SQLITE_V2_COMMIT_WINDOW`.

An unrelated compiler failure is not accepted as feature-gate evidence.

## SQLite source boundary

ADR-021 qualifies rollback-journal recovery only against the pinned runtime identity recorded in `sqlite-source.txt`.

The current exact profile is:

```text
SQLITE_VERSION=3.53.4
SQLITE_SOURCE_ID=2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc
```

A different SQLite source ID is a new evidence lineage and requires the destructive qualification to be rerun.

## Verification

After downloading/extracting an artifact, the preferred verification is:

```sh
bash ./verify_qualification_artifact.sh .
```

The verifier checks the complete artifact hash manifest, the nested tested-source manifest, exact SQLite source identity, writer recovery, production crash-surface proof, deterministic matrix cardinality/semantics, race cardinality/semantics, and proof presence for committed outcomes. It also reports whether the tested source is clean second-pass or dirty first-pass evidence.

The evidence establishes only the named local SQLite/profile crash properties in the recorded environment. It does not prove resistance to whole-store rollback without an external frontier anchor, authenticate persisted grant issuance by itself, authorize recovery, or authorize any privileged external effect.
