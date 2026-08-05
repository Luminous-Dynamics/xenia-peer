# Consent-Ledger Compaction & Compacted-Boot Runbook

How to compact a growing `xenia-peer` consent ledger and cut a daemon over
to boot from the compacted state instead of the full genesis-to-now
history. Covers the CLI pipeline wired across three PRs
(daemon-startup persister-mode switch #131, continuity checks + guards
#132, startup-path test coverage #133) on top of the consent-ledger
maintenance operations from an earlier phase (#126-130).

Every command below is a real, tested CLI invocation of the `xenia-peer`
binary itself -- nothing here requires writing code or touching internals.

## Why compact

`--consent-ledger-path` is an append-only, fully-verified-on-every-boot
audit log: every consent grant/deny/revoke since the daemon's first run.
`load_verified` re-verifies the whole entry chain from genesis on every
startup. As the ledger grows, that verification -- and the file itself --
grows without bound.

Compaction lets a daemon boot instead from `--consent-ledger-compacted-state`:
a small signed **checkpoint** authenticating everything before a chosen
cutover point (verified once, as a single signature, never entry-by-entry
again) plus a **resident suffix** of the entries since that cutover. The
original entries aren't deleted or re-verified less rigorously -- they're
moved into an independently verifiable **cold archive** that the daemon no
longer needs to touch at boot.

## Non-destructive by design -- read this before doing anything else

**Every operation in this runbook, through activation, is non-destructive.**
Building an archive segment, a compaction bundle, a compacted snapshot, and
activating it all read the live `--consent-ledger-path` file; none of them
write to it, truncate it, or delete anything. The daemon's own one-shot
output for the compaction-bundle step says so explicitly
(`no live ledger entries were deleted`), and the same is true of every
other step here.

This means the entire pipeline is safe to run against a live production
ledger, repeatedly, while deciding whether to actually cut over -- and
**rollback from compacted-boot mode is just "boot with `--consent-ledger-path`
again."** The original ledger file is untouched and still fully valid.

Physically deleting/quarantining the superseded on-disk bytes is a
*separate*, much more heavily gated ceremony (retirement -> purge ->
retention certification -> custody attestation -> final-destruction
readiness) that this runbook does not cover -- see
[Relationship to the retirement/purge ceremony](#relationship-to-the-retirementpurge-ceremony)
below. Nothing in this runbook's pipeline requires it, and nothing in this
runbook's pipeline performs it.

## Known limitation: this is a one-time cutover, not a recurring operation (yet)

Read this before planning a maintenance cadence around this feature.

Once a daemon is running in compacted-boot mode, every new consent decision
extends the **resident suffix** stored inside the active-state file
(`ConsentCompactedActiveStateV1::advance_from_chain` stores the chain's
full resident entry list on every append -- confirmed by reading the
implementation, not assumed). That resident suffix has no upper bound and
no automatic re-compaction.

There is currently no CLI path to re-compact an already-activated compacted
state: the four export operations that build compaction artifacts
(`--export-consent-ledger-archive-segment`,
`--export-consent-ledger-compaction-bundle`,
`--verify-consent-ledger-compaction-bundle`,
`--export-consent-ledger-compacted-snapshot`) all require
`--consent-ledger-path` (a plain, complete chain) and are explicitly
**rejected** when the daemon is booted from `--consent-ledger-compacted-state`
(Phase B guard, `main.rs`). The two on-disk formats aren't
interchangeable, so an active-state file can't be fed back in as
`--consent-ledger-path` either.

**Practical consequence:** treat this feature today as a one-time reduction
of a large historical ledger down to a bounded starting point, not as a
maintenance operation you run on a schedule. If the resident suffix grows
large enough to matter again, the only current option is to stop the
daemon, boot briefly from the *original* `--consent-ledger-path` (still
intact, per the non-destructive guarantee above -- though note it does not
include any decisions appended while running in compacted mode, since
those went to the active-state file, not back to the plain ledger), and
decide from there. Recurring compaction is a real gap, not a documented
workflow -- if you need it, that's new work, not a missing flag.

## Prerequisites

- The daemon's `--operator-key-path` (default `xenia-peer-state/operator.key`).
  Every artifact below is signed under this key; compacting under one key
  and booting under another will fail closed at verification time (by
  design -- see [Continuity anchors](#continuity-anchors-recommended-hardening)).
- The live `--consent-ledger-path` you're compacting (default
  `xenia-peer-state/consent.ledger`).
- The daemon **stopped**, or at minimum no consent decisions in flight,
  for the duration of this pipeline -- every step below reads a point-in-time
  snapshot of the ledger; a decision appended mid-pipeline won't be
  reflected in that run's checkpoint and will need a fresh pass.

Set once at the top of a real session:

```bash
KEY=xenia-peer-state/operator.key
LEDGER=xenia-peer-state/consent.ledger
WORK=xenia-peer-state/compaction-$(date +%F)
mkdir -p "$WORK"
```

## Step 1 -- Sign a cutover checkpoint

Everything before this checkpoint becomes the compacted prefix.

```bash
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-path "$LEDGER" \
  --advance-consent-ledger-checkpoint "$WORK/checkpoint.json"
```

Prints the entry count and head hash the checkpoint now covers. Keep this
file -- you'll want an independently retained copy of it (see
[Continuity anchors](#continuity-anchors-recommended-hardening)).

## Step 2 -- Export the cold archive segment

The detailed, independently-verifiable record of everything up to the
checkpoint. This is what gets archived; nothing is removed from `$LEDGER`.

```bash
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-path "$LEDGER" \
  --export-consent-ledger-archive-segment "$WORK/archive-segment.json" \
  --consent-ledger-archive-base-checkpoint "$WORK/checkpoint.json"
```

If you're compacting for the first time, the base checkpoint covers 0
entries (genesis) and this segment covers everything since. If you've
compacted before via the plain path, pass whichever earlier checkpoint you
want this segment to start from.

## Step 3 -- Build the compaction preflight bundle

Bundles the archive segment(s) with a recovery summary (replay-action IDs,
completed session IDs) needed to reconstruct state correctly on restore.
Repeat `--consent-ledger-compaction-archive-segment` once per segment if
you have more than one (chronological order from genesis).

```bash
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-path "$LEDGER" \
  --export-consent-ledger-compaction-bundle "$WORK/compaction-bundle.json" \
  --consent-ledger-compaction-archive-segment "$WORK/archive-segment.json"
```

## Step 4 -- Verify the bundle (recommended, not optional in spirit)

A read-only proof check against the live ledger before you trust this
bundle for anything downstream. Costs nothing to run.

```bash
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-path "$LEDGER" \
  --verify-consent-ledger-compaction-bundle "$WORK/compaction-bundle.json"
```

## Step 5 -- Export the compacted snapshot

The unactivated compacted-state artifact -- still doesn't touch `$LEDGER`.

```bash
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-path "$LEDGER" \
  --export-consent-ledger-compacted-snapshot "$WORK/compacted-snapshot.json" \
  --consent-ledger-compaction-bundle-input "$WORK/compaction-bundle.json"
```

## Step 6 -- Activate

**This is the only step that creates the file you'll actually boot from.**
It's still non-destructive of `$LEDGER` (see the guarantee above), but it
is the point where you're producing something meant to be used, not just
inspected.

```bash
xenia-peer \
  --operator-key-path "$KEY" \
  --activate-consent-ledger-compacted-state "$WORK/active-state.json" \
  --consent-ledger-activation-snapshot "$WORK/compacted-snapshot.json" \
  --consent-ledger-activation-archive-segment "$WORK/archive-segment.json"
```

Repeat `--consent-ledger-activation-archive-segment` for every segment
represented by the snapshot, same order as Step 3.

At this point `$WORK/active-state.json` is a complete, independently
verifiable substitute for booting from `$LEDGER` -- but the daemon is still
running in plain mode. Nothing has changed operationally yet.

## Step 7 -- Cut the daemon over

Stop the daemon (if not already stopped for this pipeline) and restart it
pointed at the activated state instead of the plain path:

```bash
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-compacted-state "$WORK/active-state.json" \
  # ... your normal --listen / --operator-bind / etc. flags
```

You should see `compacted consent ledger loaded and verified` in the
startup log (stdout -- `init_tracing` writes there, not stderr; see
`apps/xenia-peer/tests/startup_persister_mode.rs` for the confirmed
behavior), followed by the normal `xenia-peer daemon listening` line, with
no change to any other flag or listener.

## Rollback

Stop the daemon and restart it with `--consent-ledger-path "$LEDGER"`
instead of `--consent-ledger-compacted-state`. The original file was never
touched. The only thing you lose is any consent decisions that were made
*while running in compacted mode* -- those were appended to
`active-state.json`, not back into `$LEDGER` -- so decide the cutover
window with that in mind, and don't delete `active-state.json` after a
rollback until you've confirmed you don't need those decisions.

## Continuity anchors (recommended hardening)

Once you're running in compacted mode, two independent mechanisms guard
against the active-state file itself being rolled back, replaced, or
substituted -- both wired in #132 and worth using for anything beyond a
throwaway test:

**A retained pin**, stored somewhere other than next to the daemon
(a separate host, a secrets manager, wherever your threat model requires):

```bash
# Create/advance the pin -- overwrites an existing pin only if the current
# active state proves append-only extension from it.
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-compacted-state "$WORK/active-state.json" \
  --advance-consent-ledger-compacted-state-pin /secure/location/compacted-state.pin

# Enforce it at every boot:
xenia-peer \
  --operator-key-path "$KEY" \
  --consent-ledger-compacted-state "$WORK/active-state.json" \
  --trusted-consent-ledger-compacted-state-pin /secure/location/compacted-state.pin \
  # ... your normal flags
```

**A retained checkpoint or witness bundle**, for the plain-boot path
(`--consent-ledger-path`) instead -- `--trusted-consent-ledger-checkpoint`,
optionally combined with `--trusted-consent-ledger-key-transition` for a
signed key-succession event, or `--trusted-consent-ledger-witness-bundle` +
`--trusted-consent-ledger-witness-key-hex` (repeatable) +
`--trusted-consent-ledger-witness-quorum` for independent-witness quorum
verification instead of a single retained copy. `--trusted-consent-ledger-checkpoint-max-age-secs`
adds a freshness SLA on top of either.

Both real, cryptographically rejects a mismatch -- confirmed by hand
against the compiled binary during #132's review: booting under a
checkpoint/pin signed under a *different* key fails closed with a specific
disclosed error before any listener opens, not a silent fallback.

## Guards -- what you cannot combine with compacted-boot mode

Enforced in `main.rs`, confirmed by direct invocation, not just read from
source:

- `--trusted-consent-ledger-key-transition` is rejected when booted from
  `--consent-ledger-compacted-state` (key-transition anchoring isn't
  supported for compacted mode yet -- use the pin mechanism above instead,
  or retain the complete successor epoch and use the plain path).
- The four export/verify operations from Steps 2-5 above
  (`--export-consent-ledger-archive-segment`,
  `--export-consent-ledger-compaction-bundle`,
  `--verify-consent-ledger-compaction-bundle`,
  `--export-consent-ledger-compacted-snapshot`) all require a complete,
  genesis-based ledger and are rejected against a compacted-state boot --
  this is the same fact as the "one-time cutover" limitation above, stated
  as an enforced guard rather than an absence of tooling.

## Relationship to the retirement/purge ceremony

Compaction (this runbook) moves old entries into a cold archive the daemon
no longer verifies at boot -- it never deletes anything. Actually removing
superseded on-disk bytes is a separate, far more heavily gated ceremony:
retirement planning -> quarantine -> purge planning -> purge execution ->
retention certification -> witnessed retention renewal -> custody
attestation -> final-destruction *readiness* (never actual deletion --
`consent_final_destruction.rs`'s own module doc comment states this
explicitly, and it was adversarially verified in #129). That ceremony now
has its own runbook:
[`CONSENT_LEDGER_RETIREMENT_PURGE_RUNBOOK.md`](CONSENT_LEDGER_RETIREMENT_PURGE_RUNBOOK.md).
It is out of scope here; nothing in this document requires it, and
completing this runbook's Steps 1-7 does not start it.

## Quick reference

| Goal | Flag |
|---|---|
| Sign a cutover checkpoint | `--advance-consent-ledger-checkpoint` |
| Export cold archive segment | `--export-consent-ledger-archive-segment` (+ `--consent-ledger-archive-base-checkpoint`) |
| Build compaction bundle | `--export-consent-ledger-compaction-bundle` (+ `--consent-ledger-compaction-archive-segment`, repeatable) |
| Verify compaction bundle | `--verify-consent-ledger-compaction-bundle` |
| Export compacted snapshot | `--export-consent-ledger-compacted-snapshot` (+ `--consent-ledger-compaction-bundle-input`) |
| Activate compacted state | `--activate-consent-ledger-compacted-state` (+ `--consent-ledger-activation-snapshot`, `--consent-ledger-activation-archive-segment` repeatable) |
| Boot from compacted state | `--consent-ledger-compacted-state` |
| Retain a compacted-state pin | `--advance-consent-ledger-compacted-state-pin` / `--trusted-consent-ledger-compacted-state-pin` |
| Retain a plain-ledger checkpoint | `--advance-consent-ledger-checkpoint` / `--trusted-consent-ledger-checkpoint` |
| Witnessed checkpoint quorum | `--trusted-consent-ledger-witness-bundle` + `--trusted-consent-ledger-witness-key-hex` + `--trusted-consent-ledger-witness-quorum` |

Full flag documentation: `xenia-peer --help`.
