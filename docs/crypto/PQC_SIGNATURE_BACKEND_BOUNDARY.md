# PQC Signature Backend Boundary

Xenia's evidence format is now signature-agile. The legacy verifier still
accepts only Ed25519 evidence signatures, while the `pqc-signatures` feature
wires a real ML-DSA verification backend for explicit verifier entry points.
This is an implementation boundary, not a production PQC claim by itself.

The boundary introduces `EvidenceSignatureBackend`, the current
`Ed25519EvidenceSignatureBackend`, and feature-gated
`MlDsa65EvidenceSignatureBackend` / `MlDsa87EvidenceSignatureBackend` types.
ML-DSA acceptance must remain tied to explicit manifests, backend suite matching,
real FIPS-compatible vectors, negative tests, and downgrade tests.

Rules for this lane:

1. Feature-gating a PQ signature backend must never make unsupported PQ envelopes
   verify successfully.
2. `full-pqc-v1` must continue rejecting classical signatures unless a real PQ
   transcript and ledger signature path is present.
3. PQ backend enablement must update evidence fixtures, verifier tests, and the
   release threat model in the same change.

## Real-backend gate

The first real PQ signature backend is ML-DSA verification behind the
`pqc-signatures` feature in `xenia-ledger`. It is not enabled by default and does
not change the legacy `Verifier::verify_exported_chain(...)` path: that path
continues to reject PQ envelopes. Full-PQC evidence verification must use
`Verifier::verify_evidence_bundle_with_backend(...)` or
`Verifier::verify_transcript_bound_evidence_bundle_with_backend(...)` with a
backend whose suite exactly matches the manifest and every entry envelope. The
`xenia-peer` operator CLI may expose those backends only through the explicit
`--evidence-signature-suite` selector and only when built with
`xenia-peer/pqc-signatures`.

Before enabling this feature in a release lane, run local Rust validation with
`cargo test --locked -p xenia-ledger --features pqc-signatures --lib --no-fail-fast` and
record dependency review for the ML-DSA crate.
