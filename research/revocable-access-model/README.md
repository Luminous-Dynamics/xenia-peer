# xenia-access-model

A deterministic Rust reference model for composable, revocable delegated authority across Mycelix and Xenia.

## Models

- Exact-resource, exact-domain grants with explicit rights and purpose.
- Proposal-only versus execution-authorized grants.
- Parent lineage and strict attenuation of rights, purpose, mode, validity, epoch, and delegation depth.
- Local revocation and authority-epoch invalidation.
- Three-valued results: `Allowed`, `Denied`, and `Indeterminate`.
- Distinct composition operators: independent grants (OR) and required bundles (AND).

## Does not establish

This is a policy-semantics oracle, not a production authorization service. It does not verify signatures or content-address commitments, authenticate identities, communicate with Holochain, prove DHT convergence, distribute revocation, or enforce OS-level effects. Callers must authenticate source records, verify each delegation ID commits to every field, provide complete/current authority state, and enforce decisions at every lane and effect-commit boundary. `Indeterminate` must never be treated as permission.

Resource matching is exact equality. Wildcards, path-prefix semantics, URI normalization, and cross-domain translation are excluded pending a separately versioned canonicalization contract.

## Run

```sh
cargo test --manifest-path research/revocable-access-model/Cargo.toml
```

The crate has no third-party dependencies and is an isolated workspace so it can be tested independently of Xenia's platform-specific workspace members.
