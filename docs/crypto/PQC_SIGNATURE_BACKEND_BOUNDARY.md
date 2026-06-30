# PQC Signature Backend Boundary

Xenia's evidence format is now signature-agile, but the current verifier still
accepts only Ed25519 evidence signatures. The `pqc-signatures` feature is an
implementation boundary, not a production PQC claim.

The boundary introduces `EvidenceSignatureBackend` and the current
`Ed25519EvidenceSignatureBackend`. ML-DSA/SLH-DSA backends must not be accepted
until they have real FIPS-compatible vectors, negative tests, and downgrade tests.

Rules for this lane:

1. Feature-gating a PQ signature backend must never make unsupported PQ envelopes
   verify successfully.
2. `full-pqc-v1` must continue rejecting classical signatures unless a real PQ
   transcript and ledger signature path is present.
3. PQ backend enablement must update evidence fixtures, verifier tests, and the
   release threat model in the same change.
