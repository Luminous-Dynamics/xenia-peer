# Sealed PQC evidence verification report audit

A sealed `full-pqc-v1` evidence bundle is accepted only after the verifier
recomputes trust from the seven sealed artifacts and the operator's trusted key
fingerprints. A stored `verification_report.json` is therefore an audit aid, not
an authority root.

When requested with `--write-sealed-evidence-report`, the sealed verifier writes
a deterministic report using schema
`xenia-sealed-evidence-verification-report-v1`. The report records:

- the verified profile and signature suites;
- the verified session ID and ledger-entry count;
- the trusted transcript and ledger key fingerprints accepted by policy;
- when `--sealed-evidence-trust-policy` is used, a
  `xenia-sealed-evidence-trust-policy-receipt-v1` section containing the
  policy path, policy BLAKE3 digest, `policy_id`, `operator_id`, and optional
  signed policy-root receipt fields such as `policy_signature_blake3` and
  `policy_root_key_fingerprint_hex`;
- when `--sealed-evidence-policy-roots` is used, the policy-root registry path,
  registry BLAKE3 digest, authorized `policy_root_id`, root validity window, and
  optional `supersedes_root_id`;
- the `xenia-sealed-evidence-artifact-digests-v1` digest section; and
- the seven-file sealed artifact-set digest.

The report does **not** replace signature verification or trust-anchor checking.
It is useful only if it still matches the current bytes of:

- `evidence_manifest.json`
- `session_transcript_binding.json`
- `session_transcript_signature.json`
- `transcript_public_key_binding.json`
- `ledger_public_key_binding.json`
- `ledger_entries.json`
- `evidence_bundle_seal.json`

## Operator flow

Verify and write the sealed report:

```bash
xenia-peer \
  --verify-sealed-evidence-bundle ./full-pqc-evidence \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --sealed-evidence-trust-policy ./trusted_keys.json \
  --write-sealed-evidence-report
```

When a trust policy is used, the report records which local policy authorized
the fingerprints at verification time. If the policy was authenticated through
`--sealed-evidence-trust-policy-signature`, the report also records the detached
signature digest and policy-root key fingerprint. If a policy-root registry was
used, the report also records `policy_roots_blake3` and the authorized
`policy_root_id`. The `policy_blake3`, `policy_signature_blake3`, and
`policy_roots_blake3` fields let CI or an auditor detect that a stored report was
produced under different policy material than the one currently expected by
operator policy. Manual
fingerprint verification remains supported, but it does not populate the
`trust_policy` receipt section. When present, the receipt records the policy
path, BLAKE3 digest, optional `policy_id`, optional `operator_id`, optional
`policy_epoch`, and optional validity window that authorized the verification
run.

Later, audit that the stored report still describes the current artifact bytes:

```bash
xenia-peer --audit-sealed-evidence-report ./full-pqc-evidence
```

A successful audit means the stored report's artifact digests still match the
current sealed bundle. It does **not** mean the signatures or trust anchors have
been re-verified; rerun `--verify-sealed-evidence-bundle` before relying on the
bundle for a fresh trust decision.

The aggregate release boundary includes this guard through:

```bash
scripts/check-pqc-evidence-boundary.sh .
```

or directly:

```bash
scripts/check-sealed-pqc-evidence-report-audit.sh .
scripts/check-sealed-pqc-evidence-report-audit-negative.sh .
```
