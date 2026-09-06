# Agent Consent-Bound Authority V1

## Status

Authored draft stacked on Xenia PR #295 exact head `2f7dffa719109fea0f09fd90db8b8e2a77aae979`.

No Rustfmt, test, Clippy, or qualification claim exists until the exact-head `Agent Consent-Bound Authority` workflow executes successfully.

## Problem

The existing bounded-agent authority stack deliberately separated two claims:

1. `AgentCapabilityAttestationV1` proves Xenia signed an exact commitment-only authorization at an exact ledger frontier.
2. `DurableLedgerFrontierV1` proves that exact frontier passed a reviewed durable-storage verification boundary.

Those are necessary, but they do not prove that the **specific capability/workload authorization** was the semantic object approved by the consent history.

A generic approval entry and an arbitrary authorization could otherwise share the same authenticated session and durable frontier while remaining unrelated at the semantic commitment layer.

V1 closes that gap without changing the historical `ConsentEventRecord` or ledger hash encoding.

## Core invariant

```text
canonical user-facing consent presentation
        ↓ BLAKE3 commitment
AgentCapabilityConsentIntentV1
        ↓ domain-separated commitment
exact existing ConsentEventRecord scope
        ↓
matching Request
        ↓
matching Approval
        ↓
no Denial / Revocation / Violation
for the same session + authorization/request id
        ↓
exact durable current Xenia ledger frontier
        ↓
final AgentCapabilityAuthorizationV1
is derived from that frontier, not supplied by caller
        ↓
legacy inner Xenia authorization signature
        +
second Xenia consent-bound composition signature
        ↓
DurableConsentBoundAgentCapabilityAttestationV1
```

The stronger attestation is evidence chronology. It does not create Symthaea capabilities, budgets, reservations, retries, or execution authority.

## Pre-frontier intent

Consent must exist before the final ledger frontier can include that consent, so V1 introduces a pre-frontier object rather than trying to approve a circular final authorization.

`AgentCapabilityConsentIntentV1` commits:

- requester/source identity;
- authorization/request id;
- authenticated session id;
- session transcript hash and signature suite;
- exact capability digest;
- exact executor/workload digest;
- authority epoch;
- requested issuance and expiry window;
- nonce;
- optional prior agent-runtime checkpoint;
- digest of the exact canonical user-facing consent presentation.

It intentionally excludes only the final Xenia ledger entry count/head.

The authorization id is also the UUID bytes used as the consent-ledger `request_id`.

## Presentation binding

`consent_presentation_digest` exists because an opaque capability digest alone is not evidence that the human saw the corresponding semantic proposal.

The application/integration must define a canonical presentation artifact, show the semantic contents to the human, and bind its BLAKE3 digest into the intent before recording Approval.

Xenia V1 stores only that commitment, not raw plan contents, application payload, secrets, or the rendered presentation.

This tranche does **not** prove the UI actually displayed the artifact. That remains a separate authenticated-consent-interaction boundary. It prevents the ledger and later authority attestation from being detached from the presentation commitment that the UI claims to have used.

## Compatibility-preserving ledger scope

Historical `ConsentEventRecord` remains unchanged. Its existing `scope: String` is already covered by the signed/hash-chained entry preimage.

The exact V1 scope is:

```text
xenia.agent-capability-consent.v1:blake3:<64 lowercase hex digits>
```

where the digest is the domain-separated canonical `AgentCapabilityConsentIntentV1` commitment.

Changing the consent event struct or old bincode entry preimage is deliberately avoided.

## Closed-world consent chronology

For the exact session id + request id, V1 requires:

- at least one exact matching `Request`;
- an exact matching `Approval` after a matching Request;
- matching Request/Approval source id and scope;
- no conflicting source/scope reuse;
- no `AthenaTriage` substitution;
- no `Denial`, `Revocation`, or `Violation` anywhere in that request history.

Negative facts dominate regardless of their scope/source fields once they name the same session/request identity. Re-consent after revocation therefore requires a new authorization/request id rather than resurrecting the old request.

Repeated identical Requests before Approval and repeated identical Approvals after Request are tolerated for retry/idempotency; the signed evidence records the last matching Request and Approval seen. A Request appearing after Approval fails closed.

## Complete-history requirement

V1 does not attempt to infer consent from a compacted prefix.

If `Chain::base_checkpoint()` exists, or the complete resident sequence is unavailable, consent-bound issuance returns `CompactedConsentHistory`.

A signed checkpoint proves ledger chronology/integrity under its verification contract; it does not by itself prove the exact consent intent existed in the non-resident prefix.

A later V2 may accept an independently verified inclusion/absence proof for the exact request history, but must not weaken this V1 fail-closed rule.

## Durable frontier ordering

The final authorization is **not supplied by the caller** to the stronger issuance API.

The API first verifies:

1. expected persistence-policy digest;
2. no unresolved persistence outcome;
3. durable token entry count/head equals the exact current chain;
4. durable token commitment also binds the current Xenia ledger public key;
5. complete exact consent history.

Only then does it derive `AgentCapabilityAuthorizationV1` from the pre-frontier intent plus the exact current ledger count/head and enter the lower-level signer.

This prevents frontier substitution between consent and signing.

## Stronger wire evidence

`DurableConsentBoundAgentCapabilityAttestationV1` contains:

- the existing lower-level `AgentCapabilityAttestationV1`;
- requester/source id;
- presentation digest;
- consent-intent digest;
- exact Request sequence/hash;
- exact Approval sequence/hash;
- persistence-policy digest;
- durable-frontier digest;
- a second Xenia Ed25519 signature over the complete composition.

The second signature binds the exact inner authorization signature as well as the consent/durability evidence, so those pieces cannot be recombined across otherwise valid attestations.

## Downstream verification

The public verifier first performs the existing lower-level authorization verification, including:

- session binding;
- validity window;
- expected capability/workload/authority epoch/checkpoint;
- key fingerprint and signature.

It then independently recomputes:

- the pre-frontier intent digest from the final authorization + requester + presentation digest;
- the durable-frontier digest from final ledger count/head + trusted Xenia ledger key + expected persistence policy;
- the outer consent-bound signature.

The downstream verifier does not receive the complete ledger and therefore does not independently replay the Request/Approval history in V1. The outer Xenia signature is the attestation that Xenia performed that complete-history check. A future transparency/inclusion-proof profile can make that history proof independently replayable without exposing raw application payloads.

## Deliberate compatibility boundary

`AgentCapabilityAttestationV1` remains available as a low-level cryptographic/frontier primitive because existing interop vectors and integrations depend on it.

It must not be described as consent-bound.

Production integrations that require evidence of exact semantic consent should require `DurableConsentBoundAgentCapabilityAttestationV1` (or a later stronger profile), not merely the lower-level attestation.

## Tests authored

The source/unit and public integration tests cover:

- exact Request + Approval + durable frontier -> stronger attestation;
- public downstream verification of the stronger attestation;
- generic/mismatched Approval scope rejection;
- capability substitution under the same durable frontier rejection;
- later Revocation dominating prior Approval;
- Approval without prior Request rejection;
- persistence-policy substitution rejection;
- tampered consent evidence rejection;
- compacted-prefix history rejection even when a durable restored frontier token exists.

## Qualification evidence

The dedicated workflow retains exact:

- Git HEAD/tree;
- Rust/Cargo versions;
- `Cargo.lock` hash;
- consent-bound protocol/issuer/verifier source hash;
- public-path test hash;
- inherited low-level agent authority/protocol source hashes;
- inherited durable-frontier source hash;
- consent event schema hash;
- ledger hash-encoding source hash.

The workflow runs:

```text
cargo fmt --check --package xenia-ledger
cargo test --locked -p xenia-ledger
cargo clippy --locked -p xenia-ledger --all-targets -- -D warnings
```

No pass is claimed until those commands execute successfully at the exact PR head.

## Remaining boundaries

This tranche deliberately does not yet prove:

- that the UI actually rendered the presentation whose digest it supplied;
- that the human understood the presented semantics;
- trusted wall-clock integrity for issuance/expiry;
- independently replayable consent inclusion proofs for compacted ledgers;
- PQ signatures for the stronger outer attestation;
- production durable-store crash qualification beyond #295's existing boundary;
- downstream Symthaea admission of this stronger type.

The next cross-repository step, after Xenia compiler evidence, should be to mirror this protocol independently in Symthaea and require the stronger consent-bound attestation for consequential Xenia-authorized execution profiles.
