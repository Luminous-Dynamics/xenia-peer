# Generic State Witness v1

Status: reference security contract for `xenia-ledger`.

## Purpose

`xenia-ledger` already provides signed consent chains, public ledger checkpoints,
checkpoint continuity verification, and independent checkpoint witnesses. Some
Luminous systems also need a small public commitment that is **not** a consent
record and whose payload remains opaque to Xenia.

Generic State Witness v1 provides that evidence shape without changing the
meaning of `ConsentEventRecord` or `LedgerCheckpoint`.

The primitive proves only that configured trusted cryptographic keys signed the
same exact state commitment and that two already-verified commitments satisfy
an adjacent continuity relation.

It does not grant authority in the relying system.

## State commitment

The domain-separated commitment binds:

- schema label;
- relying-system namespace;
- exact opaque target ID;
- exact opaque epoch ID;
- monotonic counter;
- exact previous-commitment fingerprint;
- opaque state digest;
- opaque trust/policy-context digest;
- timestamp.

Xenia does not interpret the state digest, target, epoch, or trust-context
digest.

Counter zero is genesis and must use an all-zero previous commitment. A
non-genesis commitment must bind a nonzero predecessor.

## Witness signatures

Witnesses sign a domain-separated message containing:

- the exact commitment fingerprint;
- signature-suite identity;
- exact witness public key bytes;
- witness observation timestamp.

The exported signature uses Xenia's existing `SignatureEnvelope`. Verification
uses explicit `EvidenceSignatureBackend` implementations, preserving the same
algorithm-agility boundary used by other Xenia evidence.

`sign_with_ed25519` is only a convenience helper for the current classical
profile; it does not redefine the generic verification contract.

## Verified type state

`VerifiedStateWitness` is not serialized authority. Its fields are private and
it is returned only by a successful verifier call.

A verifier requires:

1. valid commitment and bundle structure;
2. nonzero configured quorum;
3. bounded witness count;
4. no duplicate `(suite, public key)` witness;
5. every included witness key is in the caller-supplied trust set;
6. an explicit verification backend for each observed suite;
7. valid signature over the exact witness message;
8. at least the configured number of distinct trusted keys.

## Key quorum is not failure-domain quorum

The core verifier counts distinct trusted cryptographic keys. It deliberately
does **not** infer:

- human/operator identity;
- organizational independence;
- hardware independence;
- network or cloud failure domains;
- key lifecycle or revocation state;
- trust-root freshness.

A deployment that needs those properties must verify them in a higher-level
trust policy before treating the returned witness result as sufficient.

Two keys controlled by one administrator are still two keys, not two independent
failure domains.

## Adjacent continuity

`verify_state_witness_adjacent(previous, candidate)` accepts only already-
verified type-state values.

Within one continuity epoch it requires:

- exact namespace equality;
- exact target equality;
- exact epoch equality;
- exact trust-context equality;
- non-regressing timestamp;
- non-regressing counter.

Exact replay of the same commitment is idempotent.

At the same counter, a different commitment fingerprint is a fork.

A forward transition must advance by exactly one counter and must bind
`previous.commitment_fingerprint()` as its predecessor. Larger jumps require a
separately verified intermediate sequence; the adjacent verifier does not infer
missing history.

An epoch change is not ordinary continuity. It requires a higher-level recovery
or re-enrollment process.

## Non-claims

This primitive does not by itself provide:

- persistent storage;
- compare-and-swap storage;
- hardware-backed monotonic counters;
- external witness retention;
- trusted wall-clock time;
- signer lifecycle or revocation policy;
- failure-domain independence;
- authority in the relying system;
- proof that a higher counter is durably retained anywhere.

Rollback resistance therefore requires an independent holder/provider to retain
and compare witnessed commitments. A caller that accepts whichever signed bundle
is currently presented has authenticity evidence, not rollback resistance.

## Relationship to checkpoint witnesses

`CheckpointWitnessBundle` remains the specialized witness mechanism for Xenia
consent-ledger checkpoints. Generic State Witness v1 is purpose-separated and
does not reinterpret consent entries or ledger checkpoints.

The two mechanisms intentionally share the same architectural pattern:

signed exact commitment -> trusted witness quorum -> retained continuity check.

## First cross-system consumer

Symthaea's Replicator Safety Kernel can consume a separately admitted witness
result as one external continuity predicate for its registry anti-rollback
state. Symthaea remains responsible for:

- defining the tracker state digest;
- checking exact local-state equality;
- trusted-time requirements;
- failure-domain policy;
- recovery/epoch transitions;
- all replication-authority semantics.

Xenia witnessing must never become a replication grant or override a local
quarantine/revocation decision.
