# Xenia Pre-Production Gates

Xenia is a remote-session and operator-control stack. Treat every production
claim as blocked until these gates pass.

## Gate 0 — Workspace integrity

- No `target/`, `dist/`, tarballs, or migration scripts in active source paths.
- `cargo metadata --format-version 1 --no-deps` succeeds from the product workspace.
- `xenia-wire` builds independently.
- `nix flake check --show-trace` passes from the product workspace when a flake is present.

## Gate 1 — Consent and identity

- Consent ceremony is explicit, logged, revocable, and bound to the session fingerprint.
- Operator identity keys are stored in an explicit state directory with restricted permissions.
- The consent ledger can be exported and independently verified.

## Gate 2 — Transport correctness

- TCP, WebSocket, and QUIC transports share the same envelope-boundary conformance tests.
- Oversized-envelope rejection is tested for every transport.
- QUIC upgrade fallback behavior is deterministic and observable.

## Gate 3 — Capture and input safety

- Capture backend selection is visible to the user/operator.
- Input injection is disabled by default until consent and policy gates are satisfied.
- Platform-specific permissions are documented for Linux, macOS, and Windows.

## Gate 4 — Cryptographic review

- `xenia-wire` spec, replay-window behavior, nonce layout, and consent signing receive independent review.
- Test vectors are cross-validated by at least one independent implementation.
- Fuzz targets run in CI or scheduled CI.

## Gate 5 — Operational auditability

- Ledger entries are hash-chained and signed.
- Admin actions, policy changes, consent changes, and emergency bypasses produce durable audit records.
- Logs avoid leaking frame contents, secrets, consent private data, or session keys.


## Gate 6 — Reproducible developer environment

- The default Nix shell includes all native headers required for capture, video, and viewer development.
- The CI Nix shell excludes interactive-only tools and can run `scripts/xenia-validate.sh .` without manual package installation.
- Any new system dependency is added to `flake.nix` and documented in `docs/nix/DEV_SHELL.md`.
