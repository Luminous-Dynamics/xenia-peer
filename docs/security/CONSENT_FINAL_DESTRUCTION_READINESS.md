# Final-destruction readiness for purge rollback evidence

Series XVIII separates **authorization readiness** from irreversible deletion.
Xenia can now prove that one exact rollback-package inventory has completed its
retention obligation, remains covered by independently signed custody
assertions, and has received a distinct final-destruction approval quorum.
It still contains no final-destruction executor.

## Evidence chain

```text
signed purge rollback package and receipt
        ↓
retention certificate + independent witness anchor
        ↓
zero or more monotonic retention renewals
        ↓
independent custody-attestation quorum
        ↓
short-lived ledger-signed final-destruction plan
        ↓
distinct final-destruction approval quorum
        ↓
ledger-signed readiness artifact
```

A renewal must be signed before the currently effective deadline. It cannot
revive an expired obligation, replace the protected inventory, cross a ledger
key epoch, or extend retention beyond ten years from purge completion. The
versioned renewal-chain file is itself continuity evidence and should be retained
outside the rollback package's failure domain; Xenia verifies the supplied chain
but cannot infer that an operator supplied the newest externally retained copy.

Custody classes (`offline-media`, `remote-vault`, and `hardware-protected`) are
custodian assertions. Xenia verifies signatures, configured trust, distinct
replica identifiers, opaque locator digests, and availability deadlines. It
does not independently prove hardware properties, geography, organizational
independence, or continued possession.

## Renew retention

```sh
xenia-peer \
  --export-consent-purge-retention-renewal /offline/xenia/renewals.json \
  --operator-key-path /secure/consent-ledger.key \
  --consent-purge-retention-certificate-input /offline/xenia/retention.json \
  --consent-purge-retention-anchor-input /external/xenia/retention-anchor.json \
  --consent-purge-retention-renewal-chain /offline/xenia/renewals.json \
  --consent-purge-retention-witness-bundle /offline/xenia/retention-witnesses.json \
  --trusted-consent-purge-retention-witness-key-hex "$RETENTION_WITNESS_1" \
  --trusted-consent-purge-retention-witness-quorum 1 \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-retention-renewal-secs 2592000
```

Omit `--consent-purge-retention-renewal-chain` for the first renewal. The
output remains a versioned chain, not an unversioned list of signatures.

## Add an independent custody assertion

```sh
xenia-peer \
  --sign-consent-purge-custody \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY" \
  --consent-purge-retention-certificate-input /offline/xenia/retention.json \
  --consent-purge-retention-anchor-input /external/xenia/retention-anchor.json \
  --consent-purge-retention-renewal-chain /offline/xenia/renewals.json \
  --consent-purge-retention-witness-bundle /offline/xenia/retention-witnesses.json \
  --trusted-consent-purge-retention-witness-key-hex "$RETENTION_WITNESS_1" \
  --trusted-consent-purge-retention-witness-quorum 1 \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-custody-key /secure/custodian-1.key \
  --consent-purge-custody-class remote-vault \
  --consent-purge-custody-locator 'vault://independent-site/object-42' \
  --consent-purge-custody-replica-id-hex 00112233445566778899aabbccddeeff \
  --consent-purge-custody-available-secs 7776000 \
  --consent-purge-custody-bundle /offline/xenia/custody.json
```

Custody keys must be distinct from the ledger key and from the purge and
retention-witness keys supplied to the operation.

## Export a readiness plan

After the effective retention deadline has elapsed:

```sh
xenia-peer \
  --export-consent-final-destruction-plan /offline/xenia/destruction-plan.json \
  --operator-key-path /secure/consent-ledger.key \
  --consent-purge-retention-certificate-input /offline/xenia/retention.json \
  --consent-purge-retention-anchor-input /external/xenia/retention-anchor.json \
  --consent-purge-retention-renewal-chain /offline/xenia/renewals.json \
  --consent-purge-retention-witness-bundle /offline/xenia/retention-witnesses.json \
  --trusted-consent-purge-retention-witness-key-hex "$RETENTION_WITNESS_1" \
  --trusted-consent-purge-retention-witness-quorum 1 \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-custody-bundle /offline/xenia/custody.json \
  --trusted-consent-purge-custody-key-hex "$CUSTODIAN_1" \
  --trusted-consent-purge-custody-quorum 1
```

The plan always selects the complete protected inventory. There is no CLI for
selecting a subset, parent directory, wildcard, or newly discovered file. The
plan is valid for at most one hour.

## Collect a distinct destruction quorum

```sh
xenia-peer \
  --sign-consent-final-destruction-plan \
  --consent-retirement-ledger-public-key-hex "$LEDGER_PUBLIC_KEY" \
  --consent-final-destruction-plan-input /offline/xenia/destruction-plan.json \
  --consent-final-destruction-witness-key /secure/destruction-witness-1.key \
  --consent-final-destruction-approval-bundle /offline/xenia/destruction-approvals.json \
  --consent-purge-retention-certificate-input /offline/xenia/retention.json \
  --consent-purge-retention-anchor-input /external/xenia/retention-anchor.json \
  --consent-purge-retention-renewal-chain /offline/xenia/renewals.json \
  --consent-purge-retention-witness-bundle /offline/xenia/retention-witnesses.json \
  --trusted-consent-purge-retention-witness-key-hex "$RETENTION_WITNESS_1" \
  --trusted-consent-purge-retention-witness-quorum 1 \
  --consent-purge-approval-bundle /offline/xenia/purge-approvals.json \
  --consent-purge-custody-bundle /offline/xenia/custody.json \
  --trusted-consent-purge-custody-key-hex "$CUSTODIAN_1" \
  --trusted-consent-purge-custody-quorum 1
```

Each witness independently replays the complete retention, protected-inventory,
and custody chain before signing. Final-destruction witness keys must be
distinct from ledger, purge, retention, and custody keys.

## Export and verify readiness

Export joins the exact plan, custody bundle, and distinct approval quorum into
one ledger-signed artifact. Verification replays the retention anchor and
renewal chain, rehashes every protected file, and validates both quorums.

```sh
xenia-peer \
  --export-consent-final-destruction-readiness /external/xenia/destruction-ready.json \
  --operator-key-path /secure/consent-ledger.key \
  --consent-final-destruction-plan-input /offline/xenia/destruction-plan.json \
  --consent-final-destruction-approval-bundle /offline/xenia/destruction-approvals.json \
  --consent-purge-custody-bundle /offline/xenia/custody.json \
  --trusted-consent-purge-custody-key-hex "$CUSTODIAN_1" \
  --trusted-consent-purge-custody-quorum 1 \
  --trusted-consent-final-destruction-witness-key-hex "$DESTRUCTION_WITNESS_1" \
  --trusted-consent-final-destruction-witness-quorum 1 \
  <the same retention-context arguments shown above>
```

Use `--verify-consent-final-destruction-readiness FILE` with the same public
inputs and `--consent-retirement-ledger-public-key-hex` for later independent
verification.

## Non-claims

This workflow does not:

- delete or overwrite a protected artifact;
- prove that a custody class is truthful;
- prove geographic or organizational independence;
- permit an implicit recursive cleanup;
- permit subset selection;
- revive an expired retention obligation;
- prove that the supplied renewal-chain file is the newest copy retained by an
  external operator;
- authorize a future executor after the one-hour plan expires.

A future irreversible executor must remain a separate patch and ceremony. It
should require immediate descriptor-relative revalidation, a crash-audited
journal, externally retained completion evidence, and an explicit policy for
whether independently retained replicas are themselves in scope.
