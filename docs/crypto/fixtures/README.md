# Evidence crypto manifest fixtures

This directory is the machine-checkable policy matrix for Xenia evidence crypto
profiles. `scripts/check-evidence-manifests.py` validates each manifest and pins
the expected fixture set so profile coverage cannot drift silently.

## Canonical labels

- Schema: `xenia-evidence-crypto-manifest-v1`
- Hybrid profile: `hybrid-pre-pqc-v1`
- Future PQ profile: `full-pqc-v1`
- KEM: `ml-kem-768-fips203`
- Classical signature: `ed25519-rfc8032`
- PQ signature labels reserved for real backends: `ml-dsa-65-fips204`,
  `ml-dsa-87-fips204`, `slh-dsa-fips205`
- Hash chain: `blake3-256`
- KDF: `hkdf-sha256`
- AEAD: `chacha20-poly1305`
- Classical allowance: `explicit-classical-signature-allowance`
- Classical rejection: `reject-classical-signatures`

## Fixture contract

- `hybrid-pre-pqc-v1.manifest.json` must validate.
- `full-pqc-v1.valid.manifest.json` must validate as a policy fixture, while
  runtime export remains refused until a reviewed PQ signature backend lands.
- Files containing `.invalid-` in the filename must be rejected by the checker.
- New manifest fixtures must be registered in `check-evidence-manifests.py`; an
  unregistered fixture is treated as drift, not silently accepted.
