# PQC evidence verification report audit

`verification_report.json` is useful only if it still describes the exact bundle
artifacts that were verified. Xenia therefore exposes a report-audit path that
recomputes the BLAKE3-256 artifact digests for:

- `evidence_manifest.json`
- `ledger_entries.json`
- `session_transcript_binding.json`

and compares them with the stored `xenia-evidence-artifact-digests-v1` section.
The audit also recomputes `artifact_set_blake3`, so an operator gets one compact
handle for the exact current artifact set.

Run the audit with:

```bash
xenia-peer --audit-evidence-report ./evidence-bundle
```

A successful audit means the stored report still matches the current artifact
bytes. It does **not** replace signature verification. Operators should still run
`--verify-evidence-bundle` with the intended `--evidence-signature-suite` and,
when needed, `--require-evidence-profile` before trusting the evidence.

The aggregate release boundary includes this guard through:

```bash
scripts/check-pqc-evidence-boundary.sh .
```

or directly:

```bash
scripts/check-pqc-evidence-report-audit.sh .
scripts/check-pqc-evidence-report-audit-negative.sh .
```
