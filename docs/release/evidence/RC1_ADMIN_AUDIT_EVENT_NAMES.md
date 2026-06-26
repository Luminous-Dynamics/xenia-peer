# RC1 Admin Audit Event Names Evidence

This evidence closes the RC1 soft blocker that operator/admin audit events need stable names.

## Stable names

| Stable audit name |
| --- |
| `consent.requested` |
| `consent.granted` |
| `consent.denied` |
| `consent.revoked` |
| `consent.protocol_violation` |
| `admin.athena_triage` |

## Validation commands

| Check | Result |
| --- | --- |
| `ledger-stable-name-contract` | `PASS` |
| `ledger-record-stable-name` | `PASS` |
| `consent-coverage` | `PASS` |

## Sign-off

- `xenia-ledger` exposes stable dot-namespaced names via `ConsentKind::stable_name()`.
- `ConsentEventRecord::stable_name()` forwards the same contract to ledger consumers.
- `sovereign-admin` displays stable audit names instead of Rust `Debug` variant names.
- Evidence output is sanitized and does not include local workspace paths.
