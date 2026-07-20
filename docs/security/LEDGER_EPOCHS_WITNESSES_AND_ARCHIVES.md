# Ledger epochs, checkpoint witnesses, and archive segments

Xenia's consent ledger uses one Ed25519 signing key for every entry in a ledger
epoch. The signer is not allowed to change silently inside a hash chain. This
document defines the explicit continuity artifacts used when operators rotate
that key, retain checkpoint observations through independent witnesses, or move
bounded evidence segments to colder storage.

## Ledger-key succession

`xenia_ledger::LedgerKeyTransition` is a dual-signed handover artifact. It
commits to the exact final checkpoint of the old epoch and the public key of the
new epoch. The old key authorizes the handover and the new key signs acceptance.

A valid transition proves authorization to begin a fresh ledger epoch. It does
not pretend that the new epoch is another entry in the old hash chain. Keep all
three artifacts together:

1. The archived old ledger epoch.
2. Its final retained checkpoint.
3. The dual-signed transition to the successor key.

At restore, pass the old checkpoint and transition beside the new epoch:

```bash
xenia-peer \
  --operator-key-path /restore/new-epoch/operator.key \
  --consent-ledger-path /restore/new-epoch/consent.ledger \
  --trusted-consent-ledger-checkpoint /retention/old-final-checkpoint.json \
  --trusted-consent-ledger-key-transition /retention/old-to-new-transition.json
```

The daemon verifies both handover signatures, the exact old checkpoint, the
successor key, and the complete new ledger epoch. The transition artifact is
created through the `LedgerKeyTransition::sign` library API so both private keys
can remain in an offline rotation ceremony rather than being loaded into the
running daemon.

## Independent checkpoint witnesses

The ledger signature proves that the ledger authority produced a checkpoint.
It does not prevent a compromised authority that still owns the key from
showing different valid histories to different observers.

`CheckpointWitnessBundle` binds independent Ed25519 countersignatures to one
exact checkpoint. A restore can require a quorum of distinct configured witness
keys:

```bash
xenia-peer \
  --trusted-consent-ledger-witness-bundle /retention/checkpoint-witnesses.json \
  --trusted-consent-ledger-witness-key-hex "$SITE_A_KEY" \
  --trusted-consent-ledger-witness-key-hex "$SITE_B_KEY" \
  --trusted-consent-ledger-witness-quorum 2 \
  ...
```

Every signature in the bundle must come from the configured trust set. Duplicate
keys, untrusted keys, malformed signatures, or a quorum shortfall fail closed.
Witness keys should be controlled by genuinely separate systems or operators;
placing several keys on the same host creates only nominal diversity.

## Retention freshness

Signature and prefix checks can accept an authentic but indefinitely old
retention anchor. Deployments can turn retention freshness into a startup SLA:

```bash
xenia-peer \
  --trusted-consent-ledger-checkpoint /retention/checkpoint.json \
  --trusted-consent-ledger-checkpoint-max-age-secs 86400 \
  --trusted-consent-ledger-checkpoint-max-future-skew-secs 300 \
  ...
```

The age limit applies to direct retained checkpoints and witnessed checkpoints.
A key-transition restore checks the newly loaded successor epoch and the signed
handover ordering; the old epoch's final checkpoint is historical by design.

## Bounded archive segments

`LedgerArchiveSegment` contains:

- A signed base checkpoint.
- Every signed entry after that checkpoint.
- A signed terminal checkpoint.
- A BLAKE3 commitment to the exact checkpoints, entry hashes, and signatures.

One segment is capped at 4,096 entries. Export it with:

```bash
xenia-peer \
  --operator-key-path /srv/xenia-peer-state/operator.key \
  --consent-ledger-path /srv/xenia-peer-state/consent.ledger \
  --consent-ledger-archive-base-checkpoint /retention/base.json \
  --export-consent-ledger-archive-segment /archive/segment-0001.json
```

The export is written with owner-only permissions and atomic replacement. It
does **not** truncate the live ledger. An archive segment by itself is not a
recovery index; use the compaction preflight below to derive and authenticate
that state. Reaching the live ledger's hard persistence limit must continue to
fail closed rather than discarding history.

`Verifier::verify_ledger_archive_segment` verifies one segment;
`Verifier::verify_ledger_archive_sequence` verifies that ordered segments share
identical boundary checkpoints. `ledger_archive_sequence_digest` adds one
bounded commitment over the exact ordered sequence.

## Compaction preflight bundles

Xenia can now produce a **non-destructive** compaction preflight bundle. The
bundle embeds the complete verified archive sequence plus two derived artifacts:

- `ConsentRecoverySummaryV1`, containing every archived signed decision action ID
  needed for replay refusal, every completed session, approval provenance, and
  the exact archived boundary.
- `LedgerCompactionManifest`, signed by the ledger key and binding the archive
  sequence digest and recovery-summary digest to both the archived checkpoint
  and the current full live-ledger checkpoint.

The recovery builder refuses a sequence unless it begins at genesis and every
consent ceremony in the archived prefix is terminal. A pending request or an
approved-but-not-terminated session remains a hard stop because pruning it would
remove live authorization state.

Create a preflight bundle from archive segments supplied in chronological order:

```bash
xenia-peer \
  --operator-key-path /srv/xenia-peer-state/operator.key \
  --consent-ledger-path /srv/xenia-peer-state/consent.ledger \
  --consent-ledger-compaction-archive-segment /archive/segment-0001.json \
  --consent-ledger-compaction-archive-segment /archive/segment-0002.json \
  --export-consent-ledger-compaction-bundle /retention/compaction-preflight.json
```

Verify it later against the same complete live ledger:

```bash
xenia-peer \
  --operator-key-path /srv/xenia-peer-state/operator.key \
  --consent-ledger-path /srv/xenia-peer-state/consent.ledger \
  --verify-consent-ledger-compaction-bundle /retention/compaction-preflight.json
```

Both commands are one-shot and read-only with respect to the live ledger. The
export uses owner-only atomic replacement. Verification recomputes the archive
sequence, replay index, session summaries, signed manifest, archived prefix, and
current full-ledger checkpoint. It also rejects any live-suffix reuse of an
archived decision action ID or terminal session ID.

This is intentionally a pruning **precondition**, not pruning itself. The
ledger library now has an appendable checkpoint-anchored suffix frontier, but
safe live truncation still requires a versioned durable suffix store and startup
integration that loads the authenticated replay index before accepting any new
action. Until those pieces exist, the daemon must retain the full live ledger
and continue to fail closed at its hard storage bounds.

## Non-claims

These artifacts improve evidence continuity, but they do not provide:

- Byzantine consensus among witnesses.
- Transparency-log gossip or global fork detection.
- Automatic safe deletion of live ledger entries.
- Recovery of an old private signing key.
- Protection when all witness keys and retained artifacts are compromised
  together.

## Compacted restore snapshots

After a compaction preflight bundle verifies against the complete live ledger,
Xenia can derive a smaller, still non-destructive restore snapshot. The snapshot
contains:

- the authenticated `ConsentRecoverySummaryV1` replay and terminal-session
  indexes;
- the ledger-signed `LedgerCompactionManifest`;
- only the signed live suffix after the archived checkpoint; and
- a BLAKE3 envelope commitment over those exact artifacts.

Export the snapshot while the complete live ledger is still available:

```bash
xenia-peer \
  --operator-key-path /srv/xenia-peer-state/operator.key \
  --consent-ledger-path /srv/xenia-peer-state/consent.ledger \
  --consent-ledger-compaction-bundle-input /retention/compaction-preflight.json \
  --export-consent-ledger-compacted-snapshot /retention/compacted-restore.json
```

Verify and materialize its restore frontier using the independently retained
archive sequence:

```bash
xenia-peer \
  --operator-key-path /srv/xenia-peer-state/operator.key \
  --verify-consent-ledger-compacted-snapshot /retention/compacted-restore.json \
  --consent-ledger-compacted-snapshot-archive-segment /archive/segment-0001.json \
  --consent-ledger-compacted-snapshot-archive-segment /archive/segment-0002.json
```

Verification reconstructs an appendable checkpoint-anchored `Chain`, checks its
absolute sequence frontier, and materializes the archived action-ID and terminal
session indexes that a future activation path must consult before accepting any
operator action. The signing key must match the ledger identity committed by the
snapshot.

The operation remains deliberately non-destructive. It does not replace the
configured live ledger, delete archived entries, or enable daemon startup from a
compacted file. Safe activation still requires a versioned durable suffix store
that atomically preserves the recovery summary and loads its replay/session
indexes before any HTTP or consent transport begins serving.
