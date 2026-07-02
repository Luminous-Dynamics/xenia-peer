# PQC Signature Feature Gate

Xenia's ledger keeps the real ML-DSA evidence verifier behind the Rust feature
`pqc-signatures`.

This gate exists because the dependency is real cryptographic code, but the
release posture still needs explicit review, fixture pinning, and operator
approval before PQ evidence signatures are accepted in production policy.

## Required invariants

- `ml-dsa` remains an optional dependency of `xenia-ledger`.
- `pqc-signatures` explicitly enables `dep:ml-dsa`.
- Default features remain empty.
- ML-DSA backend symbols remain protected by `#[cfg(feature = "pqc-signatures")]`.
- CI compiles and tests `xenia-ledger` with `--features pqc-signatures`.
- CI also compiles and tests `xenia-peer` with `--features pqc-signatures` so
  the operator verifier surface cannot drift away from the ledger feature graph.
- The default verifier path remains Ed25519-only; PQ evidence verification must
  use an explicit backend entry point or the explicit `--evidence-signature-suite` selector.
- `xenia-peer` verifier preflight keeps required evidence profiles, downgrade
  policies, `transcript_signature`, and `ledger_signature` bound to the selected
  verifier suite before invoking deeper bundle verification.

## Operator checks

Run the aggregate evidence boundary check:

```bash
scripts/check-pqc-evidence-boundary.sh .
```

For just this gate:

```bash
python3 scripts/check-pqc-feature-gate.py .
scripts/check-pqc-peer-verifier-surface.sh .
scripts/check-pqc-feature-gate-negative.sh .
```

The negative check mutates temporary fixtures and proves the gate fails when the
optional dependency, feature link, default-feature posture, cfg gate, CI test, or
peer verifier preflight is weakened.
