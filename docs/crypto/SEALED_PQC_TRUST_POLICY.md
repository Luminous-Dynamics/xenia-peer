# Sealed PQC trust policy

Status: pre-production operator-policy contract.

A sealed `full-pqc-v1` evidence bundle proves that its artifacts, signatures,
key bindings, and bundle seal are internally consistent. It does not prove that
those keys are authorized for an operator. Authorization comes from an enrolled
trust policy outside the bundle.

## Policy file

`xenia-peer --verify-sealed-evidence-bundle` may read trusted fingerprints from
a JSON policy file instead of requiring fingerprints on the command line:

```bash
xenia-peer \
  --verify-sealed-evidence-bundle ./full-pqc-evidence \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --sealed-evidence-trust-policy ./trusted_keys.json \
  --minimum-sealed-evidence-policy-epoch 7
```

The policy schema is:

```json
{
  "schema": "xenia-sealed-evidence-trust-policy-v1",
  "profile": "full-pqc-v1",
  "signature_suite": "ml-dsa-65-fips204",
  "trusted_transcript_key_fingerprint_hex": "<32-byte-blake3-hex>",
  "trusted_ledger_key_fingerprint_hex": "<32-byte-blake3-hex>",
  "policy_id": "optional operator policy identifier",
  "operator_id": "optional local operator identifier",
  "policy_epoch": 1,
  "valid_from": "optional RFC3339 timestamp",
  "valid_until": "optional RFC3339 timestamp",
  "revoked_policy_ids": ["optional revoked policy ids"]
}
```

The policy is deliberately small. It enrolls trusted verifier-key fingerprints;
it does not embed private keys, runtime secrets, cloud tenancy claims, or a
self-authenticating identity assertion. Optional `policy_epoch`, `valid_from`,
`valid_until`, and `revoked_policy_ids` fields let operators fail closed on
stale, premature, expired, or explicitly revoked policy material. Operators can
raise `--minimum-sealed-evidence-policy-epoch` in CI to prevent an older
policy file from authorizing new sealed evidence. A stale or revoked policy must not authorize a sealed evidence bundle. When
`--write-sealed-evidence-report` is also used, the report records a
`xenia-sealed-evidence-trust-policy-receipt-v1` section with the policy path,
policy BLAKE3 digest, `policy_id`, `operator_id`, policy epoch, validity window,
and optional policy-root signature receipt fields such as `policy_signature_blake3`
and `policy_root_key_fingerprint_hex` that authorized the verification run.

## Optional signed policy root

For higher-assurance operator workflows, the trust policy may be authenticated by
a detached policy-root signature:

```bash
xenia-peer \
  --verify-sealed-evidence-bundle ./full-pqc-evidence \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --sealed-evidence-trust-policy ./trusted_keys.json \
  --sealed-evidence-trust-policy-signature ./trusted_keys.signature.json \
  --trusted-sealed-evidence-policy-root-fingerprint-hex <32-byte-blake3-hex> \
  --require-signed-sealed-evidence-trust-policy
```

The detached signature schema is:

```json
{
  "schema": "xenia-sealed-evidence-trust-policy-signature-v1",
  "policy_schema": "xenia-sealed-evidence-trust-policy-v1",
  "profile": "full-pqc-v1",
  "signature_suite": "ml-dsa-65-fips204",
  "policy_blake3": "<blake3 of trusted_keys.json>",
  "root_public_key_binding": {
    "schema": "xenia-evidence-public-key-binding-v1",
    "signature_suite": "ml-dsa-65-fips204",
    "public_key": [0],
    "fingerprint_algorithm": "blake3-256",
    "public_key_fingerprint": [0]
  },
  "signature": {
    "algorithm": "ml-dsa-65-fips204",
    "signature": [0]
  }
}
```

The signature covers a domain-separated message containing the policy schema,
profile, signature suite, and BLAKE3 digest of the policy file bytes. The policy
root key is still a local trust anchor: the verifier only accepts the detached
signature when the root public-key binding fingerprint matches
`--trusted-sealed-evidence-policy-root-fingerprint-hex`.

## Optional policy-root registry

Operators can avoid manually pasting the policy-root fingerprint by enrolling
policy roots in a local registry:

```bash
xenia-peer \
  --verify-sealed-evidence-bundle ./full-pqc-evidence \
  --sealed-evidence-signature-suite ml-dsa-65-fips204 \
  --sealed-evidence-trust-policy ./trusted_keys.json \
  --sealed-evidence-trust-policy-signature ./trusted_keys.signature.json \
  --sealed-evidence-policy-roots ./policy_roots.json \
  --required-sealed-evidence-policy-root-id root-2026-q3 \
  --require-signed-sealed-evidence-trust-policy
```

The registry schema is:

```json
{
  "schema": "xenia-sealed-evidence-policy-roots-v1",
  "profile": "full-pqc-v1",
  "signature_suite": "ml-dsa-65-fips204",
  "roots": [
    {
      "root_id": "root-2026-q3",
      "root_key_fingerprint_hex": "<32-byte-blake3-hex>",
      "operator_id": "optional operator or environment id",
      "valid_from": "optional RFC3339 timestamp",
      "valid_until": "optional RFC3339 timestamp",
      "supersedes_root_id": "optional previous root id"
    }
  ],
  "revoked_root_ids": ["optional revoked root ids"]
}
```

When `--sealed-evidence-policy-roots` is used, the verifier reads the detached
policy signature, extracts the root public-key binding fingerprint, and accepts
that signature only if the fingerprint maps to an enrolled, current, non-revoked
root in `policy_roots.json`. `--required-sealed-evidence-policy-root-id` is an
optional extra guard for CI and release workflows that expect one exact root.

Verification reports produced through a policy-root registry record the registry
path, registry BLAKE3 digest, authorized `policy_root_id`, root validity window,
and optional `supersedes_root_id` alongside the existing policy-signature receipt.

## Fail-closed rules

The verifier must reject a trust policy when:

- `schema` is not `xenia-sealed-evidence-trust-policy-v1`;
- `profile` is not `full-pqc-v1`;
- `signature_suite` does not match `--sealed-evidence-signature-suite`;
- `policy_epoch`, when present, is zero;
- `--minimum-sealed-evidence-policy-epoch` is set and `policy_epoch` is missing
  or below the required minimum;
- `valid_from` or `valid_until`, when present, is not RFC3339;
- the current verifier time is before `valid_from`;
- the current verifier time is at or after `valid_until`;
- `valid_from` is not before `valid_until`;
- `policy_id` appears in `revoked_policy_ids`;
- either fingerprint is not exactly 32 bytes of hex; or
- the bundle's public-key-binding fingerprint does not match the enrolled
  fingerprint.

The verifier must reject a signed policy path when:

- `--require-signed-sealed-evidence-trust-policy` is set and no detached policy
  signature is supplied;
- `--sealed-evidence-trust-policy-signature` is supplied without either
  `--trusted-sealed-evidence-policy-root-fingerprint-hex` or
  `--sealed-evidence-policy-roots`;
- both `--trusted-sealed-evidence-policy-root-fingerprint-hex` and
  `--sealed-evidence-policy-roots` are supplied in one verification run;
- `--required-sealed-evidence-policy-root-id` is supplied without
  `--sealed-evidence-policy-roots`;
- the detached signature schema is not
  `xenia-sealed-evidence-trust-policy-signature-v1`;
- the signature's `policy_blake3` does not match the current policy file bytes;
- the signature suite or envelope algorithm does not match the selected ML-DSA
  verifier suite;
- the root public-key binding fingerprint does not match the trusted local
  policy-root fingerprint;
- the policy-root signature verification fails;
- the policy-root registry schema, profile, or signature suite does not match the
  selected sealed verifier suite;
- the policy-root registry is empty, contains duplicate root IDs, contains an
  invalid root fingerprint, or contains a root that supersedes itself;
- the signing root fingerprint is not enrolled in `policy_roots.json`;
- the enrolled root is outside its validity window;
- the enrolled root ID appears in `revoked_root_ids`; or
- `--required-sealed-evidence-policy-root-id` does not match the enrolled root.

Do not combine `--sealed-evidence-trust-policy` with the manual
`--trusted-transcript-key-fingerprint-hex` or
`--trusted-ledger-key-fingerprint-hex` flags. One verification run should have
one clear source of operator trust anchors.

## Boundary

A successful trust-policy verification means:

1. the seven sealed artifacts are cryptographically consistent;
2. the bundle is `full-pqc-v1` and downgrade-resistant;
3. the transcript, ledger, and bundle-seal signatures verify under ML-DSA; and
4. the verifier keys match fingerprints enrolled by operator policy.

A successful signed trust-policy verification additionally means:

5. the operator policy file bytes matched the detached policy signature; and
6. the detached policy signature verified under a local trusted policy-root key.

When a policy-root registry is used, it additionally means:

7. the signing root fingerprint was enrolled, current, and not revoked in the
   local policy-root registry selected for the verification run.

It still does not mean the policy root was distributed securely. Production
systems should protect `trusted_keys.json`, `policy_roots.json`, and any manual
policy-root fingerprint with the same care as other local security policy, such
as a NixOS-managed file, hardware-backed registry, or admin-approved enrollment
record. The verification report's policy digest, policy-root fingerprint,
policy-root registry digest, policy epoch, and validity windows are audit receipts
only; they do not prove the policy was distributed securely or that the operator
selected the correct policy for the environment.
