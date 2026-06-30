# Signature Envelope Agility

Status: post-RC1 implementation bridge.

Xenia's current consent ledger stores Ed25519 signatures in the legacy M1 entry
shape as a fixed 64-byte field. That is acceptable for `hybrid-pre-pqc-v1`, but
it is not sufficient for `full-pqc-v1` because ML-DSA and SLH-DSA signatures are
not 64-byte Ed25519 signatures.

This document defines the next compatibility seam: exported evidence should use
an algorithm-tagged signature envelope even while the internal append path remains
Ed25519-only.

## Export shape

A ledger entry exported for long-lived evidence should carry:

```json
{
  "signature": {
    "algorithm": "ed25519-rfc8032",
    "signature": [0, 1, 2]
  }
}
```

The `algorithm` field must use the stable labels from
`EVIDENCE_CRYPTO_PROFILE.md`:

- `ed25519-rfc8032`
- `ml-dsa-65-fips204`
- `ml-dsa-87-fips204`
- `slh-dsa-fips205`

The byte array is raw signature material for that algorithm. Higher-level bundle
formats may encode the byte array as JSON bytes, base64, or CBOR bytes, but the
algorithm label must stay stable.

## Current verifier behavior

The current verifier accepts only Ed25519 envelopes because the ML-DSA/SLH-DSA
verification backend has not landed yet.

It must reject:

- unknown signature labels;
- malformed Ed25519 signature lengths;
- ML-DSA/SLH-DSA envelopes when the current Ed25519-only verifier is used.

That rejection is intentional. It lets the export schema carry future PQ
signatures without silently claiming to verify them today.

## Migration sequence

1. Export all ledger evidence through `LedgerEntryExport` and
   `SignatureEnvelope`.
2. Keep `LedgerEntry` as the M1 compatibility shape until storage migration is
   explicit.
3. Add an ML-DSA verifier backend behind a named feature such as
   `pqc-signatures`.
4. Add `Verifier::verify_exported_chain_with_signature_keys(...)` that accepts
   typed PQ verifying keys rather than an Ed25519-only key.
5. Flip `full-pqc-v1` artifacts to reject Ed25519 and require ML-DSA/SLH-DSA
   signature envelopes.

## Non-goals

This is not a fake PQC implementation. Do not add placeholder verification that
accepts ML-DSA bytes without checking them against a real FIPS 204-compatible
backend and test vectors.
