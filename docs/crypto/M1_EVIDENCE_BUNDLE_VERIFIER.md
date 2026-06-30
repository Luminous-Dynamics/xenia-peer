# M1 Evidence Bundle Verifier

`xenia-peer` can verify a transcript-bound M1 evidence bundle without trusting the
bundle's own `verification_report.json`.

```bash
cargo run -p xenia-peer -- \
  --verify-evidence-bundle /tmp/xenia-m1-evidence \
  --evidence-public-key-hex <ed25519-verifying-key-hex>
```

The verifier reads:

- `evidence_manifest.json`
- `ledger_entries.json`
- `session_transcript_binding.json`

Then it reconstructs the typed manifest from stable labels and calls
`xenia-ledger::Verifier::verify_transcript_bound_evidence_bundle` with the
operator public key supplied out-of-band.

The verifier intentionally does **not** trust `verification_report.json`; that
file is an informational report from the exporter, not an authority root.
