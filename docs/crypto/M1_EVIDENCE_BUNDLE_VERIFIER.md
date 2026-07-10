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

## Full-PQC sealed evidence

`full-pqc-v1` evidence must use the sealed verifier path, not the older unsigned
transcript-bound verifier. A sealed full-PQC bundle is expected to carry:

- `evidence_manifest.json`
- `session_transcript_binding.json`
- `session_transcript_signature.json`
- `transcript_public_key_binding.json`
- `ledger_public_key_binding.json`
- `ledger_entries.json`
- `evidence_bundle_seal.json`

The crate-level verifier is
`Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(...)`.
It verifies the signed transcript, both key bindings, the ledger chain, and the
bundle seal over key fingerprints plus ledger-chain anchors.

The public-key binding files are not self-authenticating identity claims. A
production CLI or admin console still needs an out-of-band trust anchor, such as
an enrolled operator public-key fingerprint, before treating a sealed bundle as
operator-authorized evidence.


### CLI verifier with trust anchors

The operator-facing sealed verifier requires explicit trusted fingerprints. The
public keys inside `transcript_public_key_binding.json` and
`ledger_public_key_binding.json` are verified, but their identity is accepted
only when their BLAKE3 fingerprints match policy supplied out of band.

```bash
cargo run -p xenia-peer --features pqc-signatures -- \
  --verify-sealed-evidence-bundle /tmp/xenia-full-pqc-evidence \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --trusted-transcript-key-fingerprint-hex <32-byte-blake3-hex> \
  --trusted-ledger-key-fingerprint-hex <32-byte-blake3-hex>
```

For repeatable CI/operator verification, use an enrolled trust policy instead of
manual fingerprints:

```bash
cargo run -p xenia-peer --features pqc-signatures -- \
  --verify-sealed-evidence-bundle /tmp/xenia-full-pqc-evidence \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --sealed-evidence-trust-policy ./trusted_keys.json \
  --minimum-sealed-evidence-policy-epoch 7
```

The trust policy must use schema `xenia-sealed-evidence-trust-policy-v1`, require
`full-pqc-v1`, and declare the same ML-DSA suite selected by the verifier. A
stale policy for `ml-dsa-65-fips204` must not authorize an `ml-dsa-87-fips204`
verification run. For higher-assurance CI, authenticate the policy with
`--sealed-evidence-trust-policy-signature` and authorize the signing root through
either `--trusted-sealed-evidence-policy-root-fingerprint-hex` or an enrolled
`--sealed-evidence-policy-roots ./policy_roots.json` registry.

The sealed verifier refuses classical signature suites. It is intended for
`full-pqc-v1` bundles only and prints a recomputed sealed artifact-set digest
when verification succeeds. Add `--write-sealed-evidence-report` to persist a
`verification_report.json` audit handle after successful verification. Later,
run `--audit-sealed-evidence-report <bundle-dir>` to recompute the seven sealed
artifact digests and confirm the stored report still describes the current
bundle bytes. When verification used `--sealed-evidence-trust-policy`, the
report also records a `xenia-sealed-evidence-trust-policy-receipt-v1` section
with `policy_blake3`, `policy_id`, `operator_id`, optional `policy_epoch`,
optional validity window, optional `policy_root_key_fingerprint_hex`, and, when
a policy-root registry was used, `policy_roots_blake3`, `policy_root_id`, and
root validity metadata, so the operator can prove which enrolled policy and
policy-root authorized the trust anchors at report-write time. The audit does **not**
replace a fresh signature and trust-anchor verification run.

Trust-policy verification also fails closed when an enrolled policy is not yet
valid, expired, revoked by `revoked_policy_ids`, declares a zero
`policy_epoch`, or falls below `--minimum-sealed-evidence-policy-epoch`.
Policy-root registry verification additionally fails closed when the signing root
is not enrolled, expired, premature, revoked by `revoked_root_ids`, or does not
match `--required-sealed-evidence-policy-root-id`.
