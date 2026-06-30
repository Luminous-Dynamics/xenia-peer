# Full-PQC Runtime Refusal Gate

Xenia's current runtime evidence export profile is `hybrid-pre-pqc-v1`:
ML-KEM key establishment with classical Ed25519 transcript and ledger signatures.

The runtime must refuse `full-pqc-v1` exports until the actual transcript and
ledger signature surfaces are post-quantum. This prevents demos, smoke tests, or
operator scripts from producing artifacts that claim full PQC while carrying
Ed25519 authority signatures.

The smoke exporter accepts a requested profile, but `full-pqc-v1` returns a hard
`FullPqcRuntimeUnavailable` error while the current manifest reports
`ed25519-rfc8032` for transcript or ledger signatures.
