# ADR-005: Expose verified state-witness key bindings

**Status**: proposed
**Date**: 2026-09-13

## Context

The generic state-witness verifier can prove that a configured trusted-key quorum signed one exact commitment. Its opaque `VerifiedStateWitness` intentionally exposes only the verified commitment, its fingerprint, and a witness count.

A relying system such as RSK must additionally map the *actual keys that verified* into a separately authenticated signer/lifecycle/revocation/failure-domain policy. A count alone cannot establish that mapping, and reopening raw bundle metadata after verification would weaken the type-state boundary.

Xenia already has `EvidencePublicKeyBinding`, which binds a signature suite to raw public-key bytes and their BLAKE3-256 fingerprint.

## Decision

Add `VerifiedStateWitnessAdmission`, produced only after the existing context-bound state-witness verifier succeeds.

It contains:

- the existing `VerifiedStateWitness` result; and
- cloned `EvidencePublicKeyBinding` records for every witness key whose signature was accepted by that successful verification.

The admission verifier does not add another cryptographic verification path. It calls the existing verifier first and materializes key bindings only after success.

## Security boundary

The exported bindings establish cryptographic key identity only. They do not establish signer identity, ownership, lifecycle, revocation, administrative separation, or failure-domain independence.

Higher-level consumers must authenticate those mappings independently.

In particular:

```text
verified key quorum != verified signer quorum != verified failure-domain quorum
```

Multiple keys may belong to one signer, and multiple signers may share one failure domain.

## Consequences

Cross-system adapters no longer need to reinterpret unverified witness records merely to learn which keys participated in a successful quorum.

The new type remains evidence-only. It does not provide persistence, monotonic hardware, trusted time, recovery authority, or authority in any relying system.
