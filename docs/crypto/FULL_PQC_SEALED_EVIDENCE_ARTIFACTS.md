# Full-PQC Sealed Evidence Artifacts

Status: pre-production hardening contract.

This document defines the verifier-facing file layout for a `full-pqc-v1`
Xenia evidence bundle. The goal is to prevent a future runtime or admin console
from treating individually valid ML-DSA signatures as a complete authority chain
unless the bundle is sealed, transcript-bound, and keyed by explicit verifier
bindings.

## Required file set

A sealed full-PQC evidence directory must contain these JSON artifacts:

- `evidence_manifest.json`
- `session_transcript_binding.json`
- `session_transcript_signature.json`
- `transcript_public_key_binding.json`
- `ledger_public_key_binding.json`
- `ledger_entries.json`
- `evidence_bundle_seal.json`

`verification_report.json` may also be present after an operator explicitly runs
`--write-sealed-evidence-report`, but it is not an authority root. Verifiers must
recompute trust from the seven artifacts above.

## Authority chain

A verifier for `full-pqc-v1` must perform these checks in order:

1. Parse `evidence_manifest.json` and require `profile = full-pqc-v1`.
2. Require `downgrade_policy = reject-classical-signatures`.
3. Require post-quantum transcript and ledger signature suites.
4. Validate `session_transcript_binding.json` against the manifest.
5. Verify `session_transcript_signature.json` over the domain-separated
   transcript-signature message.
6. Validate both public-key bindings, including suite and BLAKE3 fingerprint.
7. Verify every exported ledger entry signature and hash-chain link.
8. Verify `evidence_bundle_seal.json` over the bundle context, key
   fingerprints, ledger count, and ledger endpoint hashes.

The crate-level verifier path for this is:

```rust
Verifier::verify_sealed_signed_transcript_bound_evidence_bundle_with_key_bindings(...)
```

A `full-pqc-v1` bundle must not be accepted by the older unsigned
transcript-bound verifier. That older verifier remains valid for the current
`hybrid-pre-pqc-v1` runtime export only.

## Trust anchor rule

The bundle can prove internal consistency, but not operator identity by itself.
A production verifier still needs an out-of-band trust anchor, such as an
operator-approved public-key fingerprint, device enrollment record, local admin
policy, or hardware-backed key registry.

Do not treat the public-key binding files as self-authenticating identity claims.
They are the signed bundle's verifier keys and fingerprints; the operator trust
decision must come from outside the bundle.

For repeatable operator and CI workflows, prefer an enrolled trust policy file:

```bash
xenia-peer \
  --verify-sealed-evidence-bundle <bundle-dir> \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --sealed-evidence-trust-policy ./trusted_keys.json
```

The policy must use `xenia-sealed-evidence-trust-policy-v1`, require
`full-pqc-v1`, declare the same signature suite selected by the verifier, and
carry both 32-byte BLAKE3 key fingerprints.

## File purpose

| File | Purpose |
|---|---|
| `evidence_manifest.json` | Declares the crypto profile, signature suites, KEM, hash, KDF, AEAD, and downgrade policy. |
| `session_transcript_binding.json` | Binds the evidence to one session UUID and canonical transcript hash. |
| `session_transcript_signature.json` | Signs the transcript binding with the manifest transcript signature suite. |
| `transcript_public_key_binding.json` | Carries the transcript verifier key and BLAKE3 fingerprint. |
| `ledger_public_key_binding.json` | Carries the ledger verifier key and BLAKE3 fingerprint. |
| `ledger_entries.json` | Carries exported consent-ledger entries and signature envelopes. |
| `evidence_bundle_seal.json` | Signs the bundle context, key fingerprints, ledger count, first entry hash, and last entry hash. |

## Operator-facing verification

The CLI verifier for this layout is intentionally trust-anchor driven:

```bash
xenia-peer \
  --verify-sealed-evidence-bundle <bundle-dir> \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --trusted-transcript-key-fingerprint-hex <32-byte-blake3-hex> \
  --trusted-ledger-key-fingerprint-hex <32-byte-blake3-hex>
```

For enrolled-policy verification, replace the two manual fingerprint flags with
`--sealed-evidence-trust-policy ./trusted_keys.json`. Do not pass both forms in
the same invocation. For stricter operator workflows, add
`--sealed-evidence-trust-policy-signature ./trusted_keys.signature.json` plus
either `--trusted-sealed-evidence-policy-root-fingerprint-hex <32-byte-blake3-hex>`
or `--sealed-evidence-policy-roots ./policy_roots.json`. Add
`--required-sealed-evidence-policy-root-id <root-id>` when a CI lane expects one
exact enrolled root. Add `--require-signed-sealed-evidence-trust-policy` so the
verifier rejects an unsigned or tampered policy file.

The verifier must reject `ed25519-rfc8032` for sealed full-PQC evidence. It must
also reject a bundle whose embedded key-binding fingerprints do not match the
trusted fingerprints supplied by operator policy, or whose signed policy was
authorized by a policy-root registry entry that is missing, stale, revoked, or
not the required root id.

Successful verification should report the session ID, signature suites, both
trusted fingerprints, ledger-entry count, and a recomputed seven-file artifact
set digest. Operators that need an archival audit handle can add
`--write-sealed-evidence-report` and later run `--audit-sealed-evidence-report`
to confirm that `verification_report.json` still matches the current seven
sealed artifacts.

## Acceptance rule

A PR that claims to emit or verify `full-pqc-v1` evidence must either:

1. produce and verify all seven required files above; or
2. explicitly refuse `full-pqc-v1` at runtime and document the refusal.

Partial support is acceptable only behind a pre-production fixture or library
unit test name that does not imply production export readiness.
