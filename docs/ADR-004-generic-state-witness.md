# ADR-004: Generic witnessed state commitments for cross-system continuity

**Status**: proposed
**Date**: 2026-09-13
**Deciders**: tstoltz
**Related**: issues #330 and #332; `xenia-ledger` checkpoint/witness continuity.

## Context

`xenia-ledger` already has strong continuity primitives for its consent ledger:

- signed append-only entries;
- signed public checkpoints;
- same-height fork and rollback detection;
- exact checkpoint-prefix/extension verification;
- independent checkpoint witness signatures and key quorum.

Other Luminous systems need the same evidence pattern for state that is not a
consent/session record. Encoding arbitrary external state inside
`ConsentEventRecord` would weaken the semantic boundary of the consent ledger and
make downstream verification ambiguous.

At the same time, inventing an unrelated signature format would duplicate
Xenia's existing `SignatureEnvelope` and `EvidenceSignatureBackend` machinery.

## Decision

### 1. Keep generic state commitments outside the consent event schema

Add a purpose-separated `StateCommitment` and `StateWitnessBundle` in
`xenia-ledger`. Do not add generic variants to `ConsentKind` or
`ConsentEventRecord`.

The generic payload is opaque to Xenia and binds only stable continuity facts:
namespace, target, epoch, counter, predecessor fingerprint, state digest,
trust-context digest, and timestamp.

### 2. Reuse Xenia's algorithm-tagged evidence signature boundary

Witness signatures use `SignatureEnvelope`. Verification is performed through
explicit `EvidenceSignatureBackend` implementations. Ed25519 receives a
convenience signing/verification path for the current profile, while the wire
shape does not require another schema break to accept approved future backends.

### 3. Successful verification produces opaque type state

`VerifiedStateWitness` has no public constructor and is not a serialized trust
bit. It is returned only after exact bundle validation, trusted-key membership,
signature verification, duplicate rejection, and nonzero quorum satisfaction.

### 4. Adjacent continuity is exact and fail closed

Within one epoch, continuity requires identical namespace, target, and
trust-context digest, non-regressing timestamp/counter, and either:

- exact replay of the same commitment; or
- exactly `counter + 1` with `previous_commitment` equal to the exact prior
  commitment fingerprint.

A different commitment at the same counter is a fork. Counter skips require a
separately verified intermediate sequence. Epoch changes are higher-level
recovery/re-enrollment events, not ordinary continuity.

### 5. Cryptographic key quorum is not administrative independence

The core verifier counts distinct trusted `(suite, public key)` values only.
It does not claim that those keys belong to different people, organizations,
hardware roots, networks, or failure domains.

Any relying system that needs independence must verify signer identity,
lifecycle, revocation, trust-snapshot freshness, and failure-domain metadata in
a higher-level policy before relying on the witness result.

### 6. Witnessing is evidence, not authority

A `VerifiedStateWitness` proves evidence authenticity under the caller's trust
set. It does not grant privileges in the relying system and does not override
that system's local negative state.

For the Replicator Safety Kernel, Xenia may provide one externally witnessed
continuity predicate; Symthaea remains responsible for its complete tracker
state digest, policy, trusted time, recovery, quarantine/revocation, and all
replication-authority decisions.

## Consequences

Positive:

- cross-system continuity can reuse Xenia's existing evidence/signature stack;
- consent-ledger semantics stay narrow;
- algorithm agility is preserved;
- stale writers and same-height forks become explicit continuity failures;
- consumers can retain witness bundles without disclosing application state.

Tradeoffs:

- callers must provide and govern their trusted witness key sets;
- failure-domain independence remains a separate trust-policy layer;
- persistence/CAS/remote retention are not supplied by this crate;
- timestamps remain evidence fields, not trusted time by themselves;
- a signed bundle presented without independently retained prior state does not
  establish rollback resistance.

## Validation target

The first implementation tranche must cover at least:

- two-key quorum success;
- zero/insufficient quorum denial;
- duplicate and untrusted witness denial;
- state tamper invalidates signatures;
- exact replay;
- adjacent predecessor binding;
- same-counter fork;
- rollback and skipped-counter denial;
- namespace/target/epoch/trust-context/time continuity checks;
- genesis/predecessor structural checks.

Production consumers remain responsible for independent retention and trust
policy beyond raw key membership.
