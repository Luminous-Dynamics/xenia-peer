# Xenia Evidence Bundle Verification

Status: pre-production hardening contract.

This note binds together the evidence crypto manifest and exported ledger entries.
It exists so a reviewer can reject a misleading artifact before trusting any
higher-level consent claim.

## Problem

After signature-envelope agility, exported ledger entries can carry an explicit
signature suite label. The evidence manifest also declares a ledger signature
suite. Those two surfaces must agree.

Without a bundle-level check, an artifact could attach a stronger manifest to a
weaker chain, for example:

- manifest says `ledger_signature = ml-dsa-65-fips204`
- entry envelopes still say `algorithm = ed25519-rfc8032`

That artifact must be rejected even if the Ed25519 chain is internally valid.

## Verifier rule

Use `Verifier::verify_evidence_bundle(manifest, entries, public_key)` for
long-lived evidence artifacts.

The verifier performs three gates in order:

1. Validate the manifest against its declared crypto policy.
2. Confirm every entry signature envelope matches `manifest.ledger_signature`.
3. Verify sequence order, hash links, entry hashes, and supported signatures.

Today, `hybrid-pre-pqc-v1` with `ed25519-rfc8032` ledger signatures can pass.
A `full-pqc-v1` manifest can pass policy only with PQ transcript and ledger
signature labels, but exported-chain verification will still reject ML-DSA/SLH-DSA
signatures until a real verification backend lands.

## What this proves

Bundle verification proves that the manifest does not overstate the ledger
signature suite carried by the exported entries, and that the current supported
chain verifier accepted the entries under the supplied public key.

It does not prove wall-clock timestamp truth, user-interface honesty, private-key
protection, or PQ signature validity before the ML-DSA/SLH-DSA backend lands.

## Transcript-bound bundle verifier

For evidence artifacts that include a canonical handshake/session transcript hash,
prefer `Verifier::verify_transcript_bound_evidence_bundle(...)`. That verifier
first validates `SessionTranscriptBinding`, rejects empty bundles, confirms every
entry belongs to the bound `session_id`, and then runs normal bundle
verification. See `docs/crypto/TRANSCRIPT_BOUND_EVIDENCE.md`.
