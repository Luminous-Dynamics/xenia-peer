# Xenia durable ledger frontier witness V0.1

## Purpose

Close the most important persistence-ordering gap left explicit by bounded-agent authority PR #232.

Before this profile, a `Chain` could be at the correct in-memory frontier and sign an agent-capability authorization without a type-level proof that a reviewed persistence boundary had durably established that frontier.

V0.1 adds a process-local opaque witness:

```text
DurableLedgerFrontierV1
```

and durable-only higher-level issuance methods.

## Core invariant

```text
exact in-memory frontier
        +
reviewed persistence policy
        +
authoritative durable-storage success
        ↓
DurableLedgerFrontierV1
        ↓
exact-current recheck
        ↓
higher-level issuance
```

No token is produced for:

- a plain `Chain::append`;
- `ProvenNotPersisted`;
- `OutcomeUnknown`;
- a rejected restored-frontier verification;
- an unresolved #287 persistence latch.

## Opaque token

`DurableLedgerFrontierV1` has:

- no public constructor;
- no serde implementation;
- no public raw-claim field;
- no public `Clone` implementation.

It binds:

- schema version;
- exact total ledger entry count;
- exact ledger head hash;
- exact ledger public key;
- exact persistence-policy digest.

The token exposes only selected accessors and a privacy-minimized domain-separated digest.

This is primarily an accidental-bypass prevention boundary. Code with arbitrary unsafe memory corruption or a malicious persistence adapter remains outside this source-only claim.

## Persistence policy

Every token binds a nonzero `persistence_policy_digest`.

That digest should commit the concrete reviewed persistence/restore semantics, for example:

- storage implementation/version;
- atomic commit protocol;
- durability/fsync policy;
- path/database identity;
- crash-recovery policy;
- restore verification procedure.

Higher-level durable issuance requires the integration's exact expected policy digest again. A token from a different persistence profile cannot be silently reused.

## Outcome-aware append

`Chain::append_transactional_outcome_durable_v1` wraps #287's outcome-aware append.

The persistence callback receives both the chain and the exact `DurableLedgerFrontierClaimV1` it is being asked to establish.

The callback contract remains closed-world:

```text
Persisted
ProvenNotPersisted
OutcomeUnknown
```

Only `Persisted` mints a token.

`OutcomeUnknown` preserves #287's candidate/latch and returns no token. A later `reconcile_pending_persistence_durable_v1` can mint the token only if reconciliation establishes the exact candidate as durable.

## Restored chains

`verify_restored_durable_frontier_v1` provides the restart path.

Its reviewed callback now receives **both**:

```text
&Chain
+
&DurableLedgerFrontierClaimV1
```

before any token can be minted.

That shape lets one production restore boundary establish two separate facts without conflating them:

```text
exact frontier is durably recoverable
        +
restored chain/checkpoint state is cryptographically valid
        ↓
callback returns success
        ↓
DurableLedgerFrontierV1 may be minted
```

**Durable presence is still not the same claim as cryptographic ledger validity.** The API merely ensures the reviewed restore verifier has direct access to both pieces of evidence before it can approve minting.

A restore integration should perform the appropriate Xenia integrity verification inside that callback:

- complete chains: `Verifier::verify_chain` under the trusted ledger public key;
- compacted chains: the retained checkpoint + suffix must satisfy the appropriate checkpoint-extension/restore verification.

The source test exercises the complete-chain path by running `Verifier::verify_chain` inside the callback before the token is returned.

The opaque token itself remains a durability witness. It does not later pretend to prove which cryptographic restore procedure ran; that procedure belongs to the reviewed persistence-policy implementation and evidence set.

## Staleness

Every durable-only issuance method rechecks the token against the exact current `Chain`.

If the chain advances after token creation:

```text
old token frontier != current chain frontier
        ↓
ChainFrontierMismatch
```

If #287 enters an ambiguous state after token creation:

```text
has_uncertain_persistence() == true
        ↓
PersistenceUncertain
```

Thus possessing a once-valid token is not permission to sign at a later frontier.

## Durable-only agent authority

`attest_agent_capability_authorization_durable_v1` requires:

1. exact durable token;
2. exact expected persistence-policy digest;
3. token == current Xenia chain frontier;
4. no unresolved #287 outcome;
5. all existing #232 authorization/session/frontier checks.

This closes the accidental path:

```text
in-memory authorization frontier
        ↓
attestation escapes
```

for integrations that use the durable-only API.

The legacy #232 signer remains available for compatibility and retains its original persistence non-claim. Production consequential-agent integration should use the durable-only method.

## Durable-only witness anchor and observation

The same token is required by:

- `append_witness_frontier_anchor_durable_v1`;
- `observe_witness_frontier_durable_v1`.

This makes the two durability domains explicit and separate:

```text
DurableLedgerFrontierV1
    proves reviewed consent-ledger persistence boundary

WitnessFrontierAnchorStore::compare_and_swap
    proves reviewed witness-anchor-store persistence boundary
```

Neither is inferred from the other.

## Cross-repository interoperability vector

The branch also freezes one exact Xenia↔Symthaea witness-frontier V1 vector from Ed25519 seed `[7;32]`.

It pins the exact:

- ledger public key;
- derived Xenia source ID;
- witness-frontier statement digest;
- Symthaea anchor operation ID;
- Xenia anchor signature;
- Xenia anchor fingerprint;
- Xenia observation signature;
- Xenia observation fingerprint.

Symthaea #465 independently mirrors the same constants and protocol. The values were derived independently from the hand-written byte contract rather than generated by either Rust implementation under test.

This makes field order, widths, endianness, domain separators and signature-envelope fingerprint semantics a permanent cross-repository regression boundary.

## Trust boundary

The token is only as strong as the adapter that mints it.

A callback that falsely reports `Persisted`, or a restore callback that falsely reports cryptographic integrity, can falsely mint a token. That is why the production adapter, its exact implementation identity, restore-integrity procedure and crash qualification belong in the persistence-policy digest/evidence set.

The type prevents accidental bypass; it does not turn an untrusted storage implementation into a trusted one.

## Tests authored

Source tests cover:

- confirmed append mints a token;
- token enables durable-only #232 agent authority issuance;
- chain advance invalidates an older token;
- `OutcomeUnknown` mints no token and leaves #287 latched;
- later reconciliation-to-Persisted mints the exact token;
- restored frontier rejection mints no token;
- successful restored frontier verification receives both the restored chain and exact claim;
- complete-chain cryptographic verification runs inside the restore callback before a token is minted;
- frozen Xenia↔Symthaea witness-frontier wire/signature/fingerprint compatibility.

## Non-claims

V0.1 does not yet provide:

- the concrete production persistence adapter;
- filesystem/database crash qualification;
- TPM/remote anti-rollback for the consent ledger;
- proof that arbitrary callers cannot lie from inside the trusted persistence adapter;
- trusted time;
- PQ issuance.

The next production step is to make one concrete durable store implement the reviewed verification contract and fault-inject every cut between write, flush, acknowledgement, restart and reconciliation.
