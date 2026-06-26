# Xenia Release Gates

Use these gates to avoid ambiguous “almost ready” states. A release can be tagged
only when every gate in its lane has an owner, evidence, and a passing command or
review artifact.

## Evidence format

Each gate should produce one of:

- passing command output committed or attached to the release notes;
- a signed review note under `docs/release/evidence/`;
- a test, fuzz, or conformance artifact checked into the appropriate crate.

## Gate table

| Gate | Scope | Required evidence |
|---|---|---|
| W0 — Protocol integrity | `xenia-wire` | `cargo test --all-features`, test-vector validation, fuzz smoke, spec/version alignment. |
| W1 — Independent review readiness | `xenia-wire` | Frozen draft spec, threat model, known limitations, no production claims. |
| P0 — Workspace hygiene | Xenia root/product workspace | hygiene audit passes; no active tarballs/build output/nested git; no absolute local paths. |
| P0.5 — Nix reproducibility | Product workspace | `nix flake check --show-trace` and `nix develop .#ci -c scripts/xenia-validate.sh .` pass on Linux. |
| P1 — Workspace metadata | Product workspace | `cargo metadata --format-version 1 --no-deps` succeeds. |
| P2 — Default build | Product workspace | `cargo check --workspace --all-targets` succeeds with default features. |
| P3 — Feature build matrix | Product workspace | Feature checks for `scap`, `h264`, `hdc`, `ws`, `quic` as applicable. |
| S0 — Handshake gate | `xenia-handshake`, peer/viewer | No fixture/session-key path reachable in production feature set. |
| S1 — Consent gate | daemon/viewer/admin/ledger | Frames/input are blocked before approval and after revocation in integration tests. |
| S2 — Ledger gate | `xenia-ledger`, admin | Import/export verification test, tamper detection, public-key binding. |
| T0 — Transport conformance | WS/QUIC/TCP | Same sealed-envelope conformance suite runs for every transport. |
| C0 — Capture safety | `xenia-capture`, daemon | Explicit platform permission story; fallback behavior tested; no silent privileged capture. |
| I0 — Injection safety | `xenia-inject`, viewer/daemon | Injection backends require explicit feature and consent/session state. |
| A0 — Admin API | daemon/admin | Auth/authz story, CORS/CSRF posture, audit log, no unauthenticated mutation endpoints. |
| R0 — Source export | release packaging | `scripts/export-source-archive.sh` used; archive excludes `.git`, `target`, `dist`, tarballs. |
| R1 — Supply-chain policy | Workspace | `cargo deny check advisories bans licenses sources` passes or has documented exceptions. |

## Version language

- `alpha`: architecture and invariants are being shaped; no production use.
- `beta`: no known placeholder security paths; external testing welcome.
- `1.0`: protocol reviewed, production claims narrowly worded, release gates repeatable.
