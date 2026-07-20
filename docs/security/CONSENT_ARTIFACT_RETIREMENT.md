# Reversible consent-artifact retirement

Compacted-state activation and a GC-readiness certificate prove that Xenia can
recover without treating a superseded complete ledger, preflight bundle, or
compacted snapshot as active state. They do **not** authorize deleting a file.

Xenia therefore treats artifact retirement as a separate, explicit ceremony:

```text
verified compacted state + retained pin + cold archive + GC certificate
                              ↓
              short-lived ledger-signed exact plan
                              ↓
              independent retention-key quorum
                              ↓
              rehash immediately before each move
                              ↓
       owner-only same-filesystem quarantine transaction
                              ↓
              signed receipt or crash-safe rollback
```

No operation in this workflow unlinks an artifact.

## Candidate allowlist

A retirement plan can represent only:

- a superseded complete consent ledger;
- a superseded compaction-preflight bundle; or
- a superseded compacted snapshot.

Active compacted state, retained pins, cold archive segments, ledger keys,
GC-readiness certificates, plans, approvals, journals, and receipts are absent
from the role enum and cannot be valid candidates.

Every candidate is committed by:

- role;
- canonical absolute UTF-8 path;
- byte length; and
- BLAKE3 digest.

A plan also commits to the active-state digest, retained-pin fingerprint,
GC-certificate fingerprint, ledger-key epoch, canonical quarantine root,
issuance time, and expiry. Plans contain at most 32 candidates and are valid
for at most 24 hours.

## 1. Export a signed plan

First create an existing, owner-controlled quarantine root. It should be on the
same filesystem as every candidate because quarantine uses atomic rename and
will fail rather than copy across filesystems.

```sh
install -d -m 0700 /var/lib/xenia/quarantine

xenia-peer \
  --operator-key-path /secure/consent-ledger.key \
  --consent-ledger-compacted-state /var/lib/xenia/consent.active.json \
  --trusted-consent-ledger-compacted-state-pin /offline/xenia/consent.active.pin.json \
  --consent-retirement-gc-certificate /offline/xenia/gc-ready.json \
  --consent-ledger-gc-archive-segment /archive/xenia/0001.json \
  --consent-retirement-quarantine-root /var/lib/xenia/quarantine \
  --consent-retirement-complete-ledger-candidate /var/lib/xenia/consent.ledger.old \
  --export-consent-retirement-plan /offline/xenia/retirement-plan.json
```

Plan export verifies the active compacted state, retained pin, complete cold
archive sequence, and GC certificate before signing. The output cannot alias a
candidate, protected prerequisite, signing key, or quarantine path.

## 2. Collect independent approvals

Approval does not require or access the ledger private key. Each retention
witness needs only:

- the exact signed plan;
- the ledger public key; and
- its own existing Ed25519 witness key.

```sh
xenia-peer \
  --sign-consent-retirement-plan \
  --consent-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY_HEX" \
  --consent-retirement-witness-key /secure/retention-witness-1.key \
  --consent-retirement-approval-bundle /offline/xenia/retirement-approvals.json
```

Repeat with independently controlled keys. Duplicate keys, malformed
signatures, substituted plans, and approval timestamps outside the signed plan
window are refused. The ledger signing key cannot count as a witness.

## 3. Move exact bytes into quarantine

Quarantine requires the current verified prerequisites, the ledger private key,
and the configured independent witness quorum:

```sh
xenia-peer \
  --operator-key-path /secure/consent-ledger.key \
  --consent-ledger-compacted-state /var/lib/xenia/consent.active.json \
  --trusted-consent-ledger-compacted-state-pin /offline/xenia/consent.active.pin.json \
  --consent-retirement-gc-certificate /offline/xenia/gc-ready.json \
  --consent-ledger-gc-archive-segment /archive/xenia/0001.json \
  --consent-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_1_PUBLIC_KEY_HEX" \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_2_PUBLIC_KEY_HEX" \
  --trusted-consent-retirement-witness-quorum 2 \
  --quarantine-consent-retirement
```

Before each rename, Xenia reopens and rehashes the candidate. It writes an
owner-only journal before the first mutation and after every move, synchronizes
both source and quarantine directories, rehashes the quarantined files, emits a
ledger-signed receipt, and only then marks the transaction committed.

A multi-file move is not a filesystem-wide transaction. If an operation fails,
Xenia reconciles the actual original and quarantine paths and rolls back every
completed rename. Ambiguous states—both copies present, neither copy present,
or changed bytes—fail closed for operator review.

Concurrent writers must be quiesced. Rehashing narrows substitution risk, but
portable Rust filesystem APIs do not provide one atomic transaction spanning
multiple paths and directories.

## 4. Recover an interrupted transaction

Recovery needs the signed plan, approval quorum, ledger public key, and exact
journal path. It does not need the ledger private key.

```sh
xenia-peer \
  --recover-consent-retirement-journal /var/lib/xenia/quarantine/<plan-id>/journal.json \
  --consent-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY_HEX" \
  --consent-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_1_PUBLIC_KEY_HEX" \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_2_PUBLIC_KEY_HEX" \
  --trusted-consent-retirement-witness-quorum 2
```

Recovery behavior is deterministic:

- a valid signed receipt finalizes the committed transaction;
- an unreceipted prepared or moving transaction is rolled back;
- a stale `Pending` journal entry is reconciled against the real paths and
  hashes, so a crash after rename but before journal update cannot strand the
  artifact silently;
- a committed journal without its receipt is refused; and
- a rolled-back journal is accepted only when its filesystem placement agrees
  with the recorded state.

## 5. Verify retained quarantine

```sh
xenia-peer \
  --verify-consent-retirement-receipt /var/lib/xenia/quarantine/<plan-id>/receipt.json \
  --consent-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY_HEX" \
  --consent-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_1_PUBLIC_KEY_HEX" \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_2_PUBLIC_KEY_HEX" \
  --trusted-consent-retirement-witness-quorum 2
```

Verification checks the authority signature, independent quorum, deterministic
transaction paths, signed receipt, absence of the original paths, and every
quarantined file's exact length and digest.

## Resource and trust boundaries

- Maximum candidates per plan: 32.
- Maximum candidate size: 256 MiB.
- Maximum approvals per bundle: 64.
- Maximum plan lifetime: 24 hours.
- Maximum plan, approval, journal, or receipt JSON: 1 MiB.
- Quarantine uses rename, not copy; cross-filesystem candidates fail closed.
- Witness approval, recovery, and receipt verification use only the ledger
  public key.
- The ledger authority and retention witnesses are separate trust roles.

## Non-claims

This workflow does not:

- permanently delete or unlink an artifact;
- make cold archives, retained pins, or signing keys disposable;
- make a same-host witness independent merely because it uses another key;
- provide an atomic transaction across multiple filesystems;
- protect against an attacker who controls the ledger key and the required
  witness quorum; or
- authorize an unattended cleanup timer.

Permanent purge, if ever added, should be a separate ceremony with a new
short-lived signed plan, immediate digest verification, a minimum quarantine
retention period, externally retained receipts, explicit operator action, and a
crash-audited completion record.
