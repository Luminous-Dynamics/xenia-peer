# Evidence Crypto Manifest

Status: post-RC1 enforcement contract.

`EVIDENCE_CRYPTO_PROFILE.md` defines the labels. This document defines the
export artifact that carries those labels and the policy rule that decides
whether the artifact is acceptable.

A verifier should be able to reject a session transcript or consent-ledger export
before trusting any human claim about it. The manifest exists for that early
reject path.

## Manifest shape

Every exported evidence bundle should include a JSON object with these fields:

```json
{
  "schema": "xenia-evidence-crypto-manifest-v1",
  "profile": "hybrid-pre-pqc-v1",
  "kem": "ml-kem-768-fips203",
  "transcript_signature": "ed25519-rfc8032",
  "ledger_signature": "ed25519-rfc8032",
  "hash_chain": "blake3-256",
  "kdf": "hkdf-sha256",
  "aead": "chacha20-poly1305",
  "downgrade_policy": "explicit-classical-signature-allowance"
}
```


## Entry signature envelope

The manifest declares which signature suites are acceptable for the bundle. The
ledger entries themselves should carry their actual signature bytes through the
algorithm-tagged export shape defined in `SIGNATURE_ENVELOPE_AGILITY.md`.

That split is deliberate:

- the manifest says what policy the artifact claims;
- each entry envelope says which algorithm produced that entry signature;
- the verifier rejects an entry whose envelope does not satisfy the manifest and
  the verifier backend currently in use.

## Enforcement rule

`hybrid-pre-pqc-v1` is allowed only when classical signature use is explicit:

- `kem` must be an ML-KEM label.
- `transcript_signature` may be `ed25519-rfc8032`.
- `ledger_signature` may be `ed25519-rfc8032`.
- `downgrade_policy` must be `explicit-classical-signature-allowance`.

`full-pqc-v1` is stricter:

- `kem` must be an ML-KEM label.
- `transcript_signature` must be a PQ signature label such as `ml-dsa-65-fips204`.
- `ledger_signature` must be a PQ signature label such as `ml-dsa-65-fips204`.
- `downgrade_policy` must be `reject-classical-signatures`.
- `ed25519-rfc8032` must fail on any authority-bearing signature surface.

## Fixture contract

The fixtures in `docs/crypto/fixtures/` are part of the release evidence
contract:

- `hybrid-pre-pqc-v1.manifest.json` must validate.
- `full-pqc-v1.valid.manifest.json` must validate.
- `full-pqc-v1.invalid-ed25519.manifest.json` must fail validation.

Run:

```bash
python3 scripts/check-evidence-manifests.py .
```

Do not change labels, downgrade semantics, or fixture expectations without
updating the Rust-side policy validator in `xenia-ledger` in the same PR.
