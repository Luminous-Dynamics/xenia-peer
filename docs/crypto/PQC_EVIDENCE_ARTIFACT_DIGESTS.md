# PQC Evidence Artifact Digests

Xenia's PQC verifier surface now emits a deterministic artifact digest section in
`verification_report.json` after the evidence manifest, ledger export, and
session transcript binding have been verified.

The digest section uses schema `xenia-evidence-artifact-digests-v1` and
`BLAKE3-256` labels. It records the exact bytes verified for:

- `evidence_manifest.json`
- `ledger_entries.json`
- `session_transcript_binding.json`

It also records `artifact_set_blake3`, a deterministic digest over the ordered
file-name/digest pairs. This gives operators and reviewers a compact handle for
the full verified evidence bundle without depending on a local filesystem path.

## Boundary

These digests are an auditability layer. They does not replace signature verification, manifest policy checks, transcript binding, downgrade resistance,
or the explicit verifier suite selection.

A valid report means:

1. the verifier accepted the evidence bundle through the selected signature
   backend;
2. the manifest/profile/suite preflight checks passed;
3. the report names the exact artifact bytes that were verified at that time.

A valid report does **not** mean the bundle remains valid after later edits. A
post-verification audit should recompute the three BLAKE3-256 file digests and
compare them to `artifact_set_blake3` before relying on a stored report.

## Operator check

Run the aggregate boundary check:

```bash
scripts/check-pqc-evidence-boundary.sh .
```

Or run the artifact-digest guard directly:

```bash
scripts/check-pqc-evidence-artifact-digests.sh .
```
