# Next Session Plan (drafted 2026-07-27)

Status: planning, not started. Written at end of a session that closed out
network-reliability testing and fuzz-CI wiring; this picks the next slice.

## What this session shipped (for context, not yet reflected in ROADMAP.md)

- **Tier 0 network-chaos smoke test** (`scripts/xenia-network-chaos-smoke.sh`,
  wired into `xenia-validate.yml`'s `network-chaos` job, every push/PR):
  real daemon + viewer session over network namespaces + `tc netem`,
  verifying byte-exact frames survive packet loss/latency/reordering.
- **Tier 1 network-vm test** (`flake.nix`'s `checks.network-vm`, wired into
  `xenia-validate.yml`'s `network-vm` job, weekly + manual dispatch): two
  genuinely separate NixOS VMs, proving a real cross-machine session and
  that the daemon's host-identity keypair survives a hard VM reboot rather
  than silently regenerating. New `packages.xenia-peer`/`packages.xenia-viewer`
  flake outputs exist to support this.
- **Fuzz targets now actually execute in CI** (`xenia-wire/.github/workflows/ci.yml`):
  previously existed as source only, never invoked. `fuzz-smoke` runs every
  push/PR (20s/target), `fuzz-deep` runs weekly (5m/target), both sharing a
  persistent corpus cache so the weekly run builds on prior discoveries
  instead of re-exploring from an empty corpus every time.
- **Corrected `xenia-transport-quic`'s doc comment**: it claimed "NAT
  traversal" but binds with iroh's `presets::Minimal` (crypto provider only,
  no relay/DNS/STUN) — matches `docs/roadmap/M1_VERTICAL_SLICE_PLAN.md`'s
  explicit M1 non-goal, but the doc comment overclaimed. Fixed to state
  plainly what works today (direct/LAN-reachable only) and what real
  traversal would need (`presets::N0` or a self-hosted relay).

**Housekeeping owed**: none of the above is reflected in `ROADMAP.md` yet
(that file says "updated by humans, not by commits" — flagging for whoever
picks this up, not doing it unasked).

## Recommended next priorities

Ranked by: real disclosed gap > bigger/riskier item, grounded against
actual code, not invented.

### 1. Rate limiting on `xenia-operator-agent`'s HTTP endpoints

`ROADMAP.md`'s "Known open threads" flags this as "flagged repeatedly,
never done." Confirmed still true: `apps/xenia-peer/src/operator_http.rs`
has a real `RateLimiter` guarding the daemon's `/auth/*` endpoints
(`operator_http.rs:66,92-93,114,245`, plus a dedicated
`verify_is_rate_limited` test at line 897) — but grepping
`apps/xenia-operator-agent/src/` for `rate_limit`/`tower`/`governor` finds
nothing. The agent's `/v1/sign/*` endpoints (the ones that actually hold
signing key material) have zero rate limiting today.

Candidate approach: port the daemon's existing `RateLimiter` type (or the
pattern) into the agent, reusing its window/max-attempts shape rather than
inventing a new one. Add a test mirroring `verify_is_rate_limited`.

### 2. Log-scrubbing of key material

Also in "Known open threads." `docs/security/POST_DELEGATION_HARDENING_PLAN.md`
mentions this gap three times (lines ~165-167, ~327, ~561) but always as
"deferred, not silently dropped" — never actually built. Needs: an audit of
what actually gets logged via `tracing::*!` macros across the daemon and
agent (particularly around handshake/signing paths), and either a redaction
layer or explicit review that nothing sensitive is emitted. Read the three
POST_DELEGATION_HARDENING_PLAN.md mentions first — they may already scope
this more precisely than "grep for tracing calls."

### 3. `POST_RC1_HARDENING_PLAN.md` Track 4 (Security and protocol hardening) — 3 remaining items

Track 4's "Expand transport fault-injection coverage" and "Add malformed
envelope fuzz or property tests where practical" are now substantially
addressed by this session's Tier 0/1 + fuzz-CI work. Three items remain
unaddressed:
- Add compatibility tests for stable admin/operator audit event names
  (there's a `stable_name()` pattern already in
  `apps/xenia-operator-agent/src/audit_log.rs` — a test asserting these
  strings never silently change would close this cheaply).
- Review consent ledger verification surfaces.
- Add negative tests for tampered or reordered ledger events (the
  versioned envelope format landed this session's predecessor work,
  `audit_ledger_store.rs` — a natural place to add tamper-detection tests
  now that the format is fixed).

### 4. Unify file-permission code between daemon and agent

`apps/xenia-peer/src/main.rs:1258`'s own comment references
`apps/xenia-operator-agent/src/secure_file.rs`'s pattern, but the daemon
hand-rolls the same `0o600`/`0o700` `set_permissions` logic independently
in at least four places (`main.rs`, `consent_server.rs`,
`audit_ledger_store.rs`, `operator.rs`) instead of sharing `secure_file.rs`
(or an equivalent shared crate). Low-risk, mechanical, but real
duplicated-logic-drift risk if one path gets fixed for a security issue and
the others don't.

## Bigger items, flagged but not recommended first

- **Tier 2** (manual real-hardware testing) — explicitly the heaviest,
  least-automatable tier of the network-reliability plan; needs a human
  with real hardware, not something to start blind.
- **B2's GNOME-Wayland capture blocker** (`ROADMAP.md`'s B2 row) — already
  root-caused three rounds deep to a virglrenderer/Mesa native-context
  vendor-selection mismatch specific to one NixOS-VM/QEMU combination;
  next step is either a host reboot (unverified whether it clears the
  issue) or a real GNOME-Wayland operator, not more test-VM config
  guessing.
- **Independent `xenia-wire` protocol review** — `ROADMAP.md` flags this as
  waiting on the wire format stabilizing past draft-03; check current
  draft status before starting.

## Not recommended

- Real NAT traversal / relay infrastructure for the QUIC transport — this
  session confirmed it's a deliberate M1 non-goal, not a gap. Revisit only
  if the project's milestone scope changes.
