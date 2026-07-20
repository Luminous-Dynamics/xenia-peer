# Consent-artifact purge with retained rollback packages

Reversible retirement moves exact superseded artifacts into quarantine. Purge
is a separate and more dangerous ceremony: it removes the quarantine copies
only after Xenia has created, synchronized, signed, and retained a complete
rollback package under a disjoint private root.

```text
signed quarantine receipt old enough for policy
                    ↓
       short-lived ledger-signed purge plan
                    ↓
   distinct independent purge-witness quorum
                    ↓
 copy + fsync every byte into rollback package
                    ↓
 persist crash journal before the first unlink
                    ↓
 rehash source and rollback copy immediately
                    ↓
       unlink exact quarantine file + fsync
                    ↓
 ledger-signed purge receipt or restore from backup
```

The rollback package is not automatically removed. This workflow reduces the
quarantine footprint while retaining exact recovery bytes and an audit trail.
It is not final destruction.

## Security invariants

A purge plan commits to:

- the ledger-key epoch;
- the exact retirement plan, retirement approval bundle, and quarantine receipt;
- the quarantine transaction directory;
- every candidate role, quarantine path, byte length, and BLAKE3 digest;
- the canonical rollback root and deterministic rollback path for every file;
- the signed quarantine completion time;
- the minimum quarantine age;
- issuance, expiry, and a unique purge ID.

The protocol minimum quarantine age is 24 hours. The CLI default is seven days.
A purge plan cannot be issued before that age has elapsed and is valid for at
most one hour.

Purge witness keys must be distinct from both the ledger key and all keys that
approved the earlier retirement ceremony. This prevents one nominal witness
role from approving both movement into quarantine and removal from quarantine.

## 1. Prepare rollback storage

Use an owner-only directory that is outside the quarantine tree. A separately
administered volume or mounted backup target is strongly preferred.

```sh
install -d -m 0700 /rollback/xenia-consent
```

Xenia proves path separation, permissions, exact bytes, and signatures. It does
not claim that two directories on the same host are independent failure domains.

## 2. Export a signed purge plan

```sh
xenia-peer \
  --operator-key-path /secure/consent-ledger.key \
  --consent-purge-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-purge-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --consent-purge-quarantine-receipt /var/lib/xenia/quarantine/<retirement-id>/receipt.json \
  --consent-purge-rollback-root /rollback/xenia-consent \
  --consent-purge-min-quarantine-age-secs 604800 \
  --export-consent-purge-plan /offline/xenia/purge-plan.json
```

Export re-verifies the ledger signatures and every quarantined file. It refuses
an early receipt, overlapping rollback/quarantine roots, excessive plan window,
or output path that aliases a key, prerequisite, quarantine path, or rollback
path.

## 3. Collect a separate purge quorum

Each purge witness needs the exact plan, the original retirement evidence, the
ledger public key, and its own existing Ed25519 key.

```sh
xenia-peer \
  --sign-consent-purge-plan \
  --consent-purge-plan-input /offline/xenia/purge-plan.json \
  --consent-purge-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-purge-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --consent-purge-quarantine-receipt /var/lib/xenia/quarantine/<retirement-id>/receipt.json \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY_HEX" \
  --consent-purge-witness-key /secure/purge-witness-1.key \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json
```

Repeat with independently controlled purge keys. Duplicate, untrusted, stale,
retirement-witness, and ledger keys are refused.

## 4. Execute the purge

```sh
xenia-peer \
  --execute-consent-purge \
  --operator-key-path /secure/consent-ledger.key \
  --consent-purge-plan-input /offline/xenia/purge-plan.json \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-purge-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --consent-purge-quarantine-receipt /var/lib/xenia/quarantine/<retirement-id>/receipt.json \
  --trusted-consent-purge-witness-key-hex "$PURGE_WITNESS_1_HEX" \
  --trusted-consent-purge-witness-key-hex "$PURGE_WITNESS_2_HEX" \
  --trusted-consent-purge-witness-quorum 2
```

Before the first unlink, Xenia:

1. creates a unique owner-only temporary package directory;
2. copies and rehashes every candidate;
3. synchronizes every rollback file;
4. signs and persists the rollback-package manifest;
5. writes the recovery journal inside the package;
6. atomically renames the complete package into its final location; and
7. synchronizes the rollback root.

Only then does it rehash both copies, unlink one quarantine file at a time,
synchronize the quarantine directory, and persist the journal transition.
The final ledger-signed receipt is written before the journal is marked
committed. Operators must quiesce concurrent writers: portable Rust filesystem
APIs do not provide one atomic verify-and-unlink primitive across arbitrary
paths, so Xenia narrows but does not eliminate the final pathname race.

## 5. Recover an interrupted purge

```sh
xenia-peer \
  --recover-consent-purge-journal /rollback/xenia-consent/<purge-id>/journal.json \
  --consent-purge-plan-input /offline/xenia/purge-plan.json \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-purge-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --consent-purge-quarantine-receipt /var/lib/xenia/quarantine/<retirement-id>/receipt.json \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY_HEX" \
  --trusted-consent-purge-witness-key-hex "$PURGE_WITNESS_1_HEX" \
  --trusted-consent-purge-witness-key-hex "$PURGE_WITNESS_2_HEX" \
  --trusted-consent-purge-witness-quorum 2
```

Recovery requires no ledger private key. A valid signed purge receipt finalizes
the transaction. Without one, every missing quarantine file is recreated from
the exact retained rollback copy and synchronized before the journal becomes
`rolled_back`. A committed journal without its receipt fails closed.

## 6. Verify the retained result

```sh
xenia-peer \
  --verify-consent-purge-receipt /rollback/xenia-consent/<purge-id>/purge-receipt.json \
  --consent-purge-plan-input /offline/xenia/purge-plan.json \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-retirement-plan-input /offline/xenia/retirement-plan.json \
  --consent-purge-retirement-approval-bundle /offline/xenia/retirement-approvals.json \
  --consent-purge-quarantine-receipt /var/lib/xenia/quarantine/<retirement-id>/receipt.json \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY_HEX" \
  --trusted-consent-purge-witness-key-hex "$PURGE_WITNESS_1_HEX" \
  --trusted-consent-purge-witness-key-hex "$PURGE_WITNESS_2_HEX" \
  --trusted-consent-purge-witness-quorum 2
```

Verification checks the authority signature, purge quorum, rollback-package
signature, receipt signature, absence of every quarantine source, and exact
length and digest of every rollback copy.

## Resource boundaries

- Maximum candidates: 32.
- Maximum candidate size: 256 MiB.
- Maximum purge approvals: 64.
- Minimum quarantine age: 24 hours.
- Maximum purge-plan lifetime: one hour.
- Maximum plan, approval, package, journal, or receipt JSON: 1 MiB.
- Rollback package creation is complete before any quarantine unlink.

## Non-claims

This workflow does not:

- remove the retained rollback package;
- destroy cold archives, pins, certificates, signing keys, or active state;
- prove two local paths are separate physical failure domains;
- provide one atomic transaction across all files or an atomic verify-and-unlink primitive;
- make one organization independent merely because it owns multiple keys;
- run automatically on a timer; or
- provide cryptographic erasure of storage media.

Retiring the rollback package itself would require another independently
reviewed ceremony with a longer retention policy and externally retained proof.
