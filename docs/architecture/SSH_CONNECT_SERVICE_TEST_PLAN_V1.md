# SSH ConnectService Adapter Qualification Plan v1

Status: pre-implementation qualification contract

The first compatibility adapter must prove service access without widening Xenia authority.

## Required positive cases

- exact grant + exact session + exact target + accepted SSH host key -> one bounded service path;
- explicit bridge close produces terminal metadata receipt;
- revoke/expiry closes the path;
- reconnect requires fresh valid authority unless the exact parent contract explicitly permits another use slot.

## Required negative cases

- wrong target digest;
- wrong port/service profile;
- wrong SSH host key;
- no host-key policy;
- wrong/stale Xenia session;
- wrong subject;
- stale authority epoch;
- expired grant;
- already-consumed use slot;
- request digest mismatch;
- `ConnectService` used as `Execute`;
- generic local/remote/dynamic forwarding;
- SSH-agent forwarding when not separately authorized;
- credential disclosure attempt;
- revoke racing bridge open;
- crash/ambiguous open followed by blind retry;
- adapter shutdown leaving a listener/tunnel behind.

## Evidence

Receipts may commit endpoint/host-key evidence, authority/use IDs, open/close/revoke timestamps and terminal state. SSH plaintext, commands, keystrokes, terminal output and credentials are excluded by default.

## Parent qualification

No adapter PASS is valid unless it binds the exact qualified parent authority/durability composition selected by #216. Historical parent results do not transfer to a restacked adapter.
