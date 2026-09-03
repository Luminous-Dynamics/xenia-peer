# SIF Release Credential Verification Contract

Status: draft v0.1 interoperability and enforcement profile.

This document defines the Xenia-side trust boundary for accepting a Mycelix SIF release credential and turning it into a disclosure permit.

## Required order

A protected disclosure path MUST follow this order:

1. Verify every attached SIF release-credential signature under locally configured release-authority keys.
2. Enforce the local minimum signature and distinct administrative trust-domain thresholds.
3. Cryptographically verify the selected Xenia accountability execution attestation.
4. Require credential/execution equality for receipt statement, accountability policy, execution proof digest, execution verifier identity, execution administrative trust domain, and minimum-necessary result commitment.
5. Require the exact consent-ledger Approval that anchored execution to remain the latest matching consent event for the authenticated session/requester.
6. Prepare a signed Xenia disclosure permit that binds the credential ID and finalized witnessed evidence bundle.
7. Transactionally persist the signed release-journal Commit entry.
8. Only then expose `CommittedDisclosurePermit` to protected-output code.
9. Record exactly one terminal `Completed`, `Aborted`, or non-zero `Partial` outcome.

No caller-provided raw evidence-bundle digest is sufficient release authority.

## Credential trust

Credential signatures are claims until Xenia resolves `signer_key_id` against local trust configuration. Unknown signers fail closed. Duplicate signer keys do not count twice. Trust-domain identity is supplied by local Xenia configuration, never by credential input.

The v1 credential signature profile is Ed25519/RFC 8032. This does not imply that Ed25519 is the final high-assurance release profile; a future full-PQC release-authority profile requires an explicitly versioned protocol update.

## Execution binding

A valid release credential is still insufficient until it is bound to the exact Xenia execution. Xenia independently verifies the execution signature and checks:

- `receipt_statement_digest == execution.receipt_digest`
- `accountability_policy_digest == execution.policy_digest`
- `execution_proof_digest == accountability_execution_binding_digest(execution)`
- `execution_verifier_id == locally derived verifier-key ID`
- `execution_trust_domain_id == locally configured execution trust domain`
- `result_digest == execution.result_digest`

The resulting `ExecutionBoundReleaseCredential` is the only input accepted by permit preparation.

## Consent continuity

Authorization is not represented by "some later Approval exists". The exact signed Approval entry that anchored execution must still be the latest consent event for the same authenticated session/requester when the permit is prepared and when its release-journal Commit is durably persisted.

Any later matching Request, Approval, Denial, Revocation, Violation, or other consent event invalidates the old execution for release and requires a fresh execution/evidence/credential lineage.

## Release lineage

One `credential_id` authorizes at most one initial release lineage. `Aborted` and `Partial` outcomes may have one explicit retry child with a fresh release ID. `Completed` and unresolved releases cannot be retried, and a retry parent cannot have two children.

This prevents one valid accountability credential from becoming an unlimited reusable disclosure capability.

## Crash semantics

- Persistence failure of the Commit entry returns no `CommittedDisclosurePermit`.
- Crash after durable Commit but before output/outcome leaves an unresolved release. It is not automatically replayable.
- Partial output records the known number of emitted protected bytes and requires a fresh explicit retry.
- Rehydrated release state is accepted only after offline hash-chain, signature, lifecycle, and lineage verification.

## Non-equivocation boundary

The release journal is signed and hash-chained, which makes forks detectable once heads are compared. It does not by itself prevent a malicious signing/storage authority from maintaining two valid histories. High-assurance deployment therefore additionally requires atomic compare-and-swap persistence and/or independent release-head witnessing.

## Runtime integration requirement

This protocol does not justify the statement "all Xenia disclosures are SIF-gated" until each protected output adapter requires `CommittedDisclosurePermit` (or a deliberately versioned lease/stream derivative) by value and bypass tests demonstrate that the ungated path is unavailable.
