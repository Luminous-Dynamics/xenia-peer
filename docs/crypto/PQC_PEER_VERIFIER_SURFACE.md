# PQC Peer Verifier Surface

`xenia-peer` keeps PQ evidence verification explicit. The default build and the
legacy verifier path remain Ed25519-only. Building with `xenia-peer/pqc-signatures`
propagates the feature to `xenia-ledger/pqc-signatures` and exposes explicit
ML-DSA verification backends for imported transcript-bound evidence bundles.

This does not enable PQ runtime export and does not relabel the daemon as fully
post-quantum. It only allows an operator to verify evidence whose manifest and
entry signature envelopes already declare the selected suite.

## Operator flags

Default hybrid verifier:

```bash
xenia-peer \
  --verify-evidence-bundle ./bundle \
  --evidence-public-key-hex "$ED25519_PUBLIC_KEY_HEX" \
  --evidence-signature-suite ed25519-rfc8032 \
  --require-evidence-profile hybrid-pre-pqc-v1
```

Explicit ML-DSA verifier, available only when built with `pqc-signatures`:

```bash
cargo run -p xenia-peer --features pqc-signatures -- \
  --verify-evidence-bundle ./bundle \
  --evidence-public-key-hex "$ML_DSA_65_PUBLIC_KEY_HEX" \
  --evidence-signature-suite ml-dsa-65-fips204 \
  --require-evidence-profile full-pqc-v1
```

`ml-dsa-87-fips204` follows the same pattern with an ML-DSA-87 public key.

## downgrade-resistant preflight

The verifier now performs a manifest preflight before accepting a bundle:

- `--require-evidence-profile full-pqc-v1` refuses before accepting a weaker
  `hybrid-pre-pqc-v1` bundle.
- `--require-evidence-profile hybrid-pre-pqc-v1` refuses a differently labelled
  evidence profile.
- the requested profile and verifier suite must be compatible:
  `hybrid-pre-pqc-v1` requires `ed25519-rfc8032`, while `full-pqc-v1` requires
  an explicitly post-quantum verifier suite.
- the manifest `downgrade_policy` must match the required profile:
  `explicit-classical-signature-allowance` for hybrid, and
  `reject-classical-signatures` for full-PQC verification.
- both manifest signature surfaces, `transcript_signature` and
  `ledger_signature`, must match the requested verifier suite. For example, an
  operator request for `ml-dsa-65-fips204` cannot accidentally verify an
  Ed25519-only bundle or a split-suite bundle whose transcript is labelled with
  a different signature suite.

The deeper `xenia-ledger` verifier still enforces manifest policy, transcript
binding, ledger-entry suite matching, and backend-suite matching. The peer
preflight is an operator-facing downgrade and suite-binding guard with clearer
refusal messages.

## Guard script

```bash
scripts/check-pqc-verifier-downgrade-resistance.sh .
```

The aggregate release-review boundary includes this script through:

```bash
scripts/check-pqc-evidence-boundary.sh .
```
