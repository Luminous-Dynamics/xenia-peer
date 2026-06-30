# Xenia Transcript-Bound Evidence

Status: pre-production hardening contract.

This note extends evidence-bundle verification with a session transcript binding.
The goal is to prevent a valid ledger chain from being replayed beside the wrong
handshake or session transcript.

## Problem

After evidence bundle verification, Xenia can prove that:

- the manifest satisfies its declared crypto policy;
- exported ledger entries use the ledger signature suite the manifest declares;
- the exported chain verifies structurally and cryptographically under the
  supplied key.

That is necessary, but not sufficient. A valid ledger export still needs to be
bound to the exact session transcript it claims to describe.

Without this binding, a misleading artifact could pair:

- a valid consent ledger from session A; and
- a different handshake/session transcript from session B.

That artifact must be rejected before an auditor trusts the consent claim.

## Binding shape

The ledger crate now defines `SessionTranscriptBinding` with:

- `schema = xenia-session-transcript-binding-v1`
- `session_id`
- `transcript_hash_algorithm = blake3-256`
- `transcript_hash`
- `transcript_signature`

The hash is computed by `compute_session_transcript_hash(...)` over canonical
handshake/session transcript bytes. `xenia-handshake` now defines the canonical
`HandshakeTranscriptV1` serializer, and `xenia-peer-core` returns the resulting
transcript hash from the real host/viewer handshake path.

## Verifier rule

Use:

```rust
Verifier::verify_transcript_bound_evidence_bundle(
    manifest,
    &session_transcript_binding,
    entries,
    public_key,
)
```

The verifier performs these gates:

1. Validate the transcript binding schema, hash algorithm, non-placeholder hash,
   and `transcript_signature` against the evidence manifest.
2. Reject empty transcript-bound bundles.
3. Confirm every exported ledger entry carries the same `session_id` as the
   transcript binding.
4. Run normal evidence-bundle verification.

## What this proves

Transcript-bound verification proves that a verified ledger bundle is tied to a
specific session UUID and transcript hash label. It prevents simple evidence
replay where the ledger is valid but attached to the wrong transcript.

It does not prove that the canonical transcript serializer is complete, that the
UI honestly displayed the session, that wall-clock timestamps are externally
truthful, or that PQ transcript signatures are valid before an ML-DSA/SLH-DSA
backend lands.

## Runtime binding

The daemon should use `perform_host_handshake_with_transcript(...)`, bind the
returned `transcript_hash` into `M1RuntimeSession`, and then export the manifest,
`SessionTranscriptBinding`, and ledger entries together. This keeps the evidence
binding anchored to the actual handshake artifacts instead of caller-invented
placeholder bytes.
