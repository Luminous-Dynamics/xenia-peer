# M1 Evidence Bundle Export

Xenia's M1 runtime can export a verifier-consumable evidence bundle after the
session has a canonical handshake transcript hash bound to it.

The export writes four JSON files:

- `evidence_manifest.json` — stable-label crypto profile for the artifact.
- `ledger_entries.json` — signature-envelope ledger entries.
- `session_transcript_binding.json` — session UUID plus canonical transcript hash.
- `verification_report.json` — report emitted only after local verification passes.

The exported manifest uses stable labels such as `hybrid-pre-pqc-v1`,
`ml-kem-768-fips203`, and `ed25519-rfc8032`; it must not rely on Rust enum debug
or serde variant names as long-lived evidence labels.

Smoke example:

```bash
cargo run -p xenia-peer --features preprod-fixtures -- \
  --m1-runtime-smoke \
  --m1-runtime-smoke-evidence-dir /tmp/xenia-m1-evidence
```

The next production lane should make the live daemon write the same bundle at
session end, using the real canonical handshake transcript hash emitted by
`xenia-handshake`.
