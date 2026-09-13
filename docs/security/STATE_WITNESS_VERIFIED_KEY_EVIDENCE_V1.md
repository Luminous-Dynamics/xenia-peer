# State-Witness Verified Key Evidence v1

**Status:** reference security boundary; not a production admission claim

## Purpose

The generic state-witness verifier introduced by #335 proves that configured trusted cryptographic keys signed one exact state commitment. Some relying systems also need to map the keys that actually verified into an independently governed identity, lifecycle, revocation, and failure-domain policy.

A numeric witness count is insufficient for that second step.

`VerifiedStateWitnessAdmission` therefore pairs the already verified state witness with `EvidencePublicKeyBinding` records derived from the exact bundle witnesses **only after** context, trust-set membership, signature verification, duplicate rejection, and quorum checks have succeeded.

## Returned key identity

Each binding carries:

- signature suite;
- raw verifier public-key bytes;
- fingerprint algorithm `blake3-256`;
- BLAKE3-256 fingerprint of the raw public key.

This reuses Xenia's existing evidence-key binding convention rather than creating a state-witness-specific fingerprint scheme.

## Type-state rule

```text
unverified bundle
    -> exact relying-context check
    -> trusted-key membership
    -> signature verification of every witness
    -> duplicate rejection
    -> configured key quorum
    -> VerifiedStateWitness
    -> VerifiedStateWitnessAdmission + exact verified key bindings
```

There is no public constructor for `VerifiedStateWitnessAdmission`.

If lower-level verification fails, no verified key-evidence value is produced.

## Non-claims

A valid `EvidencePublicKeyBinding` proves the identity of a cryptographic verifier key under the selected signature suite. It does **not** prove:

- who controls the key;
- that two keys have different human or organizational owners;
- that multiple keys reside in different hardware roots;
- that multiple keys occupy different clouds, networks, jurisdictions, or administrative domains;
- signer lifecycle or revocation status;
- failure-domain independence;
- trusted time;
- persistent retention or rollback resistance;
- authority in a relying system.

Those facts require a separately authenticated trust policy/snapshot.

## RSK composition

An RSK adapter may use the verified key bindings as cryptographic inputs to its own trust-context verifier. The intended mapping is conceptually:

```text
Xenia verified key fingerprint
    + separately authenticated trust snapshot
    -> RSK key identity
    -> signer identity
    -> role/lifecycle
    -> failure domain
```

RSK must count key quorum, signer-identity quorum, and failure-domain quorum separately. Multiple keys controlled by one signer do not create multiple signer identities, and multiple signers in one failure domain do not create multiple failure domains.

## Mutation safety

The admission object owns cloned key bindings produced after verification. It does not expose a mutable reference to the original witness bundle and does not require callers to reinterpret unverified signature records after the fact.

## Production status

This interface improves evidence composition only. It does not by itself establish a production-qualified external monotonic provider or any replication authority.
