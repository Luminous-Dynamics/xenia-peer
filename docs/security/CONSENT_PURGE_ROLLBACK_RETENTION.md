# Purge rollback-package retention anchors

A successful consent-artifact purge deliberately leaves a complete rollback
package. That package is recovery evidence, not disposable scratch space.
Series XVII makes its retention obligation explicit and independently
observable before any final-destruction design is considered.

## Evidence chain

```text
signed purge plan and quorum
        ↓
signed rollback package and purge receipt
        ↓
ledger-signed retention certificate
        ↓
independent retention-witness quorum
        ↓
ledger-signed externally retained anchor
```

The certificate commits to every rollback artifact plus
`rollback-package.json`, `journal.json`, and `purge-receipt.json`, including
canonical path, byte length, and BLAKE3 digest. The protocol minimum retention
period is 24 hours; the deployment default is 30 days.

Retention-witness keys must be distinct from the ledger key and from keys that
approved the purge. Organizational independence still depends on separate
control and storage; distinct key bytes alone do not prove that independence.

## Export a certificate

```sh
xenia-peer \
  --export-consent-purge-retention-certificate /offline/xenia/retention.json \
  --consent-purge-plan-input /offline/xenia/purge-plan.json \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-receipt-input /rollback/xenia/<purge-id>/purge-receipt.json \
  --consent-purge-retention-secs 2592000
```

The certificate output must be outside the rollback-package directory and must
not alias the ledger private key or prerequisite evidence.

## Collect independent observations

```sh
xenia-peer \
  --sign-consent-purge-retention-certificate \
  --consent-purge-retention-certificate-input /offline/xenia/retention.json \
  --consent-purge-retention-witness-key /secure/retention-witness-1.key \
  --consent-purge-retention-witness-bundle /offline/xenia/retention-witnesses.json \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY"
```

Each witness replays the signed purge-plan, approval, rollback-package, and
purge-receipt identity chain, then rehashes the complete protected inventory
before signing the certificate fingerprint.

## Export and verify an anchor

```sh
xenia-peer \
  --export-consent-purge-retention-anchor /external/xenia/retention-anchor.json \
  --consent-purge-retention-certificate-input /offline/xenia/retention.json \
  --consent-purge-retention-witness-bundle /offline/xenia/retention-witnesses.json \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --trusted-consent-purge-retention-witness-key-hex "$WITNESS_1" \
  --trusted-consent-purge-retention-witness-key-hex "$WITNESS_2" \
  --trusted-consent-purge-retention-witness-quorum 2
```

Verification uses the same inputs with
`--verify-consent-purge-retention-anchor FILE` and the ledger public key. It
rehashes every protected file and refuses stale, substituted, untrusted, or
insufficient witness evidence. Repeat
`--consent-purge-retention-candidate-check PATH` to prove proposed cleanup
paths do not alias the package, any protected child, or a parent directory that
would recursively contain the package.

Store the anchor outside the rollback package and outside the host state backup
set. Otherwise a rollback can replace the package and its local anchor together.

## Non-claims

This workflow does not:

- permanently destroy rollback bytes;
- make a local witness a remote witness;
- prove physical failure-domain separation;
- renew retention after the signed deadline;
- authorize any implicit directory cleanup;
- allow a later cleanup plan to select a protected file by alias or parent path.

Permanent destruction remains a separate future ceremony.
