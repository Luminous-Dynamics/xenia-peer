# M1 effect-commit reference model v0.1

**Owner:** Xenia #504  
**Stacked on:** Xenia draft PR #509 (M1 action/direction crosswalk)  
**Status:** deterministic reference model; not runtime-integrated or production-qualified

## Research question

Can each M1 protected operation be identified exactly, admitted at one local effect-owner linearization point, and reconciled without duplicate dispatch or optimistic retry when revocation, crash, or an unknown external outcome intervenes?

This module is a deterministic state-machine reference for that contract. It deliberately does not create a second policy engine, authority service, durable event store or provider adapter.

## Exact operation identity

`M1EffectIntentV1` binds:

- stable operation/idempotency ID;
- exact Xenia session ID and session/rekey epoch;
- one of the eight M1 permission lanes and its fixed direction;
- resource commitment and operation/payload commitment;
- consent scope commitment;
- purpose, audience and policy/profile commitments;
- optional Mycelix delegation commitment and authority epoch.

The fingerprint uses BLAKE3 with the domain separator `xenia.m1.effect-intent.v1`. Every field above (including optional-field presence) is bound. The operation ID is the idempotency key; changing any other bound field under that ID is a conflict.

The digest is a commitment over owner-supplied values. This module does not decide whether a resource identity, payload canonicalizer, consent record, policy, delegation signature, authority epoch or currentness frontier is authentic. That evidence must come from the owning subsystem.

## State transitions

```text
new operation
    |
    v
Prepared -- revoke wins --> Rejected
    |
    | final effect-owner linearization point wins
    v
CommitLinearized
    |             |               |
    | success     | positive      | timeout/crash/ambiguous
    v             | no-effect     v
Committed         v             Unknown
              ConfirmedNoEffect    |
                                   | owner-qualified reconciliation
                                   +--> Committed
                                   +--> ConfirmedNoEffect
```

### Ordering law

- If `revoke()` obtains the serialized gate before `linearize_commit()`, the operation is rejected and no commit receipt is issued.
- If `linearize_commit()` obtains the same serialized gate first, it issues a sequence-bound receipt. A subsequent revoke does not rewrite or erase that already-linearized operation.
- A later owner result may resolve it as `Committed`, `ConfirmedNoEffect`, `Partial` or `Unknown`.
- On restart, a commit-linearized operation without a terminal result becomes `Unknown`. It is never reissued automatically.
- An Unknown operation ID/fingerprint remains occupied. Repeating the same request returns the existing state; changing the fingerprint is an idempotency conflict. Only owner-qualified reconciliation may close Unknown.
- Revocation is idempotent. It invalidates operations that are only Prepared but preserves already-linearized history.
- Sequence exhaustion still closes admission first. It may leave the revocation sequence unavailable, but it cannot keep the gate open.

## Concurrency contract

The model is an ordinary Rust state machine mutated through `&mut self`. A runtime implementation must protect the same instance with one owner-local serialization primitive and use that same primitive for both `linearize_commit` and `revoke`. The mutex race test demonstrates the two possible serial orders; it does not establish that the current Xenia daemon uses this gate.

The linearization point is the local effect-owner's final, serialized admission of the exact operation. For each actual effect, the owner must define whether that point is:
- before a synchronous OS call (input injection or clipboard application);
- before local filesystem publication (incoming file finish/link);
- before an outbound transport send is handed to the transport;
- or another provider-specific boundary.

An outbound send's local return does not prove remote receipt, rendering or playback. The provider/receiver's acknowledgement and independent observation remain separate evidence stages.

## Tests in this increment

The module includes deterministic checks for:
- revoke-before-commit and commit-before-revoke order;
- a concurrent Mutex history with one serializable winner;
- duplicate exact ID/fingerprint and changed-fingerprint conflict; duplicate
  preparation returns the same handle only while the original is still
  Prepared;
- one-shot commit admission;
- timeout/unknown retry blocking and reconciliation;
- restart conversion of unfinished linearized work to Unknown and rejection
  of prepared-but-not-linearized work;
- binding of session, epoch, lane, direction, resource, operation, consent, purpose, audience, policy and optional delegation/authority fields;
- missing IDs/commitments, wrong session/epoch, direction mismatch and lane denial;
- idempotent revocation preserving committed history;
- fail-closed revocation when sequence bookkeeping is exhausted.

These tests validate this reference model's state-transition contract. They are not a race test of OS syscalls, QUIC/TCP sends, conductor state, durable crash recovery, or provider reconciliation.

## Required runtime integration before a stronger claim

1. Give every real M1 effect a stable operation ID and exact immutable intent fingerprint.
2. Make the final effect owner call the gate immediately at the actual effect boundary.
3. Serialize that final gate and local revoke through the same owner lock/transaction; the current shared AtomicBool latch is a preflight fence, not this transaction.
4. Persist admission/commit receipts before allowing non-replay-safe external dispatch, or prove an equivalent atomic coupling.
5. Record Attempted, Committed, ConfirmedNoEffect and Unknown distinctly, with a lane-specific evidence ceiling.
6. Reconcile Unknown by operation ID and exact fingerprint before any retry.
7. Exercise every lane through network partitions, concurrent revoke, cancellation, process restart, reconnect/rekey, and alternate-route negative controls.
8. Compose verified ROS-005 delegation/currentness and recipient consent at that same boundary; do not let this local model stand in for Mycelix authority.

## Claim ceiling

This increment is **reference-model only**. It does not serialize the existing daemon's OS/network effects, does not persist its model state, does not issue a cryptographically authenticated receipt, does not verify Mycelix ROS-005, and does not prove Holochain 0.7.1 qualification, complete route mediation, distributed linearizability, provider idempotency, remote observation or SOTA superiority.

The next proof obligation is to implement the same contract at the actual Xenia effect owners and independently replay the concurrency/fault histories in Mycelix #6193 and IPB-FINALITY #6136.


## Partial outcomes

The reference model treats a partially applied operation as a terminal, distinct
state. It is neither success nor confirmed-no-effect, and cannot be retried as
a new effect under the same operation ID. An Unknown operation may be reconciled
to Partial only by owner-qualified evidence. Domain-specific compensation or
completion is a separate operation and must not rewrite the original partial
effect as though it never happened.

Two tests cover direct Partial completion and Unknown-to-Partial reconciliation;
both prove the operation remains consumed and cannot obtain a second commit
receipt.
