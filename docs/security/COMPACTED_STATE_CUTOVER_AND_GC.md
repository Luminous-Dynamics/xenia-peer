# Compacted consent state: cutover, retained pins, and GC readiness

Xenia's compacted consent-ledger mode separates three responsibilities that
must not be conflated:

1. **Cutover correctness** — the activated compacted state preserves the exact
   signed head of the complete ledger that produced the snapshot.
2. **Rollback detection** — an independently retained pin proves that a later
   active state equals or append-only extends a previously observed compacted
   generation.
3. **Garbage-collection readiness** — a signed certificate proves that the
   cold archive, recovery summary, cutover receipt, active state, and retained
   pin all agree.

None of these artifacts deletes data. They are prerequisites for a future,
separately reviewed garbage-collection implementation.

## Active-state schema migration

This hardening advances the active-state envelope schema to
`xenia-consent-compacted-active-state-v2`. Earlier v1 envelopes do not contain
a signed cutover receipt or generation metadata and are refused rather than
implicitly upgraded. Recreate the active state from the previously verified
compacted snapshot and cold archive, then create an independently retained pin.

## Signed cutover receipt

`ConsentCompactedCutoverReceiptV1` is embedded in the active-state envelope. It
commits to:

- the ledger signing-key epoch;
- the compacted snapshot digest;
- the archive-sequence and recovery-summary digests;
- the source complete-ledger checkpoint;
- the activated checkpoint; and
- the activation timestamp.

The source and activated checkpoints must have the same key, entry count, and
head hash. Cross-key compaction remains refused. Ledger-key rotation must create
a new explicit epoch rather than being hidden inside compaction.

## Retained compacted-state pins

Create or advance a pin only after the compacted state is active:

```sh
xenia-peer \
  --operator-key-path /secure/operator.key \
  --consent-ledger-compacted-state /var/lib/xenia/consent.active.json \
  --advance-consent-ledger-compacted-state-pin /offline/xenia/consent.active.pin.json
```

When the pin file already exists, Xenia verifies that the current state
append-only extends it before replacing it atomically. Keep the pin outside the
state directory and outside the same backup/rollback domain as the active state.

Normal startup can require the retained pin:

```sh
xenia-peer \
  --operator-key-path /secure/operator.key \
  --consent-ledger-compacted-state /var/lib/xenia/consent.active.json \
  --trusted-consent-ledger-compacted-state-pin /offline/xenia/consent.active.pin.json
```

The pin binds both the signed ledger checkpoint and the immutable cutover
identity. A state from another compaction cutover or signing-key epoch is
refused even when its JSON shape is otherwise valid.

## GC-readiness certificate

After independently retaining the active-state pin and verifying every cold
archive segment, export a non-destructive readiness certificate:

```sh
xenia-peer \
  --operator-key-path /secure/operator.key \
  --consent-ledger-compacted-state /var/lib/xenia/consent.active.json \
  --trusted-consent-ledger-compacted-state-pin /offline/xenia/consent.active.pin.json \
  --consent-ledger-gc-archive-segment /archive/xenia/0001.json \
  --consent-ledger-gc-archive-segment /archive/xenia/0002.json \
  --export-consent-ledger-compaction-gc-certificate /offline/xenia/gc-ready.json
```

Verify the certificate against the same independently retained inputs:

```sh
xenia-peer \
  --operator-key-path /secure/operator.key \
  --consent-ledger-compacted-state /var/lib/xenia/consent.active.json \
  --trusted-consent-ledger-compacted-state-pin /offline/xenia/consent.active.pin.json \
  --consent-ledger-gc-archive-segment /archive/xenia/0001.json \
  --consent-ledger-gc-archive-segment /archive/xenia/0002.json \
  --verify-consent-ledger-compaction-gc-certificate /offline/xenia/gc-ready.json
```

The certificate binds the exact active-state digest. Any later authorization
append makes the certificate stale by design; regenerate it before a future GC
operation.

## Non-claims

This mechanism does not:

- delete the complete ledger;
- delete cold archive segments;
- make archive storage optional;
- permit cross-key-epoch compaction;
- protect an active state and pin stored in the same rollback domain; or
- authorize an unattended cleanup job.

A future destructive GC path must additionally use an explicit deletion plan,
verify every target path and digest immediately before unlinking, preserve a
rollback package, and commit an auditable completion record after directory
synchronization.
