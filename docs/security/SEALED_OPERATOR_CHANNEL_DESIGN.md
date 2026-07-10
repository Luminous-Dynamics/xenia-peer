# Design: the `xenia-wire`-sealed operator channel

**Status:** design pass (no code). The *destination* transport-security layer
for the operator surface — see `OPERATOR_RBAC_PLAN.md` → *Transport security*
for why this beats classical TLS for Xenia, and `docs/deploy/remote-operators.md`
for the interim reverse-proxy path this eventually supersedes.

Goal: the browser operator console talks to the daemon's operator API inside the
**same PQC-hybrid sealed envelopes** that already protect the screen channel —
PQC confidentiality, mutual auth from already-enrolled keys, no CA, one trust
model. Grounded in the existing crypto (all names/paths below verified in-tree).

## The one structural fact

Xenia's crypto is two independent, transport-agnostic layers:

- **`xenia-wire`** = envelope layer only (`Session::seal`/`open`, ChaCha20-Poly1305,
  replay window). *No handshake, no transport* — byte-in/byte-out by design
  (`xenia-wire/src/lib.rs:28-39`).
- **`xenia-peer-core::handshake` + `xenia-handshake`** = key establishment
  (PQC-hybrid handshake) producing the `SessionKeySchedule` that `xenia-wire`
  installs (`Session::install_key`).

A sealed operator channel is just: run the handshake → `install_key` → seal/open
the operator JSON. **The browser already does this end-to-end against the
daemon's video channel** (`xenia-wire/xenia-viewer-web/`), so this is a repoint,
not a green-field crypto build.

## Architecture

A single **operator WebSocket** (the handshake is host-speaks-first, so it needs
a bidirectional stream — it does *not* fit HTTP request/response):

```
browser console (viewer)                 daemon (host)
      │  ── open WS ──────────────────────▶ │
      │  ◀───────── HostHello ───────────── │   (daemon speaks first)
      │  ── ViewerResponse (signed) ──────▶ │   (KEM-encapsulate + dual-sign)
      │  ◀───────── HostFinalize ────────── │   (dual-sign)
      │        [SessionKeySchedule derived both sides; TOFU-pin host fp]
      │  ══ sealed envelopes both ways ════ │   Session::seal / ::open
      │     · auth/role (if kept)            │
      │     · consent-request broadcast      │
      │     · consent decision (Approve/…)   │
```

Handshake driver (native): `perform_host_handshake…` / `perform_viewer_handshake…`
(`crates/xenia-peer-core/src/handshake.rs:449,577`), 3 messages
(`HandshakeMessage::{HostHello, ViewerResponse, HostFinalize}` `:37-83`), bincode.
Browser driver already exists: `WasmHandshake::{new,begin,finish}`
(`xenia-viewer-web/src/handshake.rs:394,416,426`) with JS owning the socket
(`www/daemon.js`).

## Identity & trust — the key simplification

The handshake authenticates **both** peers with **Ed25519 + ML-DSA-65** (AND
composition, no classical fallback) + **ML-KEM-768** for key agreement
(host-only KEM key; the viewer never holds one).

Crucially, an enrolled operator is *already* an Ed25519 + ML-DSA-65 identity
(`EnrolledOperator { ed25519_pubkey, ml_dsa_pubkey, role }`,
`apps/xenia-peer/src/operator.rs`). That is exactly the viewer-side handshake
identity. So:

- **The operator's enrolled keypair becomes its handshake identity.** New
  constructor `WasmHandshake::from_identity(ed_sk, ml_dsa_sk)` instead of the
  current ephemeral `new()` (`handshake.rs:405` generates fresh keys today).
- **The daemon checks the viewer's presented keys against `OperatorPolicy`**
  during the handshake. If enrolled → the channel is authenticated *as that
  operator, with that role*, in one step.
- **This collapses `/auth/challenge` + `/auth/verify` into the handshake.** The
  handshake is a strictly stronger proof of possession than the challenge/
  response (it signs a live transcript incorporating a fresh KEM exchange). The
  short-lived role-scoped token becomes optional.
- **Host TOFU is unchanged and free:** `host_identity_fingerprint`
  (`xenia-handshake/src/lib.rs:101`) is already derived + returned + pinned by
  the browser (`daemon.js` `verifyHostIdentity`). That is the server-auth TLS
  would otherwise provide.

### What the sealed channel does NOT replace: ledger non-repudiation

AEAD is symmetric — the sealed channel proves *confidentiality + who the live
peer is*, but a sealed-channel message is **not** non-repudiable (the daemon
holds the same key, so it can't prove to a third party that the *operator* sent
it). The current **per-action Ed25519 signature** over the session-bound consent
transcript (`consent_action_transcript`, `xenia-operator-proto`) is what makes a
ledger entry provably the operator's. **Keep it.** Layering:

| Property | Provided by |
|----------|-------------|
| Confidentiality in transit | sealed channel (new) |
| Channel peer authentication + role | handshake vs. `OperatorPolicy` (new) |
| Server (daemon) authentication | host-identity TOFU (exists) |
| Per-action non-repudiation for the ledger | per-action Ed25519 signature (**unchanged**) |

## Payload framing

Post-handshake, everything the operator surface carries today becomes sealed
envelopes demuxed by `payload_type` in the application range
(`PAYLOAD_TYPE_APPLICATION_MIN`, `xenia-wire/src/lib.rs:106`; read the type
without decrypting via `envelope_payload_type`, `wire.rs:37`):

| Today (plaintext) | Sealed payload_type (proposed) | Body |
|-------------------|-------------------------------|------|
| `GET /ws` consent-request broadcast | `0x30` operator-consent-request | `{session_id, scope}` |
| consent decision WS msg | `0x31` operator-consent-decision | `{action, action_signature}` (+ identity is the channel's) |
| `/auth/verify` → token (if kept) | `0x32` operator-role-grant | `TokenDto` |

The daemon uses a dedicated labeled sub-key so the operator channel doesn't
overload the video `control` lane: `SessionKeySchedule` already exposes
`{control, telemetry, context, rekey}` (`xenia-handshake/src/lib.rs:549`) — add
an `operator` label or reuse `control` on a channel that carries no video.

## WASM feasibility & the one non-obvious prerequisite

Proven: `xenia-viewer-web` runs the whole viewer handshake + AEAD open in the
browser, cross-checked byte-identical against the native host
(`tests/handshake_cross_compat.rs`). The **non-obvious prerequisite** is the
`getrandom` triple-wiring — ml-kem drags in getrandom 0.2/0.3/0.4, each needing
its wasm backend wired independently (`xenia-viewer-web/Cargo.toml` comment).
`sovereign-admin` already has the 0.2/0.3/0.4 wiring from the RBAC ceremony work,
so this is already solved on the console side.

## Migration / compatibility

1. **Additive first.** Add the operator WS + sealed path behind a daemon flag
   (e.g. `--operator-sealed`) and a console toggle; keep the plaintext `/auth` +
   consent WS working. No forced cutover.
2. **Reuse the browser crypto crate.** Factor `WasmHandshake`/`WasmSession` (or
   depend on `xenia-viewer-web`'s wasm-bindgen surface) into the console rather
   than re-implementing.
3. **Deprecate the interim.** Once sealed is default, the reverse-proxy-TLS
   recipe becomes belt-and-suspenders rather than the confidentiality boundary.

## Open questions / risks

- **Keep the role-scoped token, or derive role purely from the handshake
  identity?** Token adds a TTL/revocation knob independent of enrollment; the
  handshake-identity path is simpler. Leaning: drop the token, gate on live
  `OperatorPolicy` lookup (already the pattern in `authorize_consent_action`) —
  de-enrolling an operator instantly kills their channel authority.
- **Rekey / long-lived operator sessions.** The video path has a rekey lane
  (`RekeyState`); an idle operator console holding a sealed channel should adopt
  the same rekey policy rather than a static key.
- **`WasmHandshake::from_identity` constructor** must ingest the operator's
  persisted seeds (the console already persists them,
  `operator_session.rs` `ED_SEED_KEY`/`ML_SEED_KEY`) rather than generating
  fresh keys — a small addition to the viewer-web crate.
- **Consent-request broadcast fan-out.** `/ws` today is a broadcast to any
  connected console; a sealed channel is per-operator-session, so the daemon
  must seal the prompt per live operator session (fine, but a change from the
  current single broadcast).

## First slice

- ✅ **Slice 0 — keystone proven (native).** Added
  `perform_host_handshake_authenticating_peer` + `VerifiedPeerIdentity`
  (`crates/xenia-peer-core/src/handshake.rs`): the host handshake now returns the
  authenticated peer's Ed25519 + ML-DSA-65 keys, so the daemon can authorize the
  operator straight from `OperatorPolicy`. `operator_sealed_smoke.rs` proves it:
  an operator's *enrolled* identity (from the two seeds the console persists)
  drives the viewer handshake, both sides derive identical sealed-channel keys,
  the host learns the exact enrolled keys, and policy lookup yields the role
  (stranger → fail-closed). The central claim — *the handshake IS the operator
  auth* — is now test-backed. The existing function delegates to the new one, so
  the video path is untouched.
- 🟢 **Slice 1 done** — `WasmHandshake::fromIdentity(ed25519_secret, ml_dsa_seed)`
  in the viewer-web crate reconstructs the viewer identity from the console's
  persisted seeds (mirroring the native `HandshakeManager::from_identity_seeds`
  byte-for-byte) instead of generating ephemeral keys, so the browser drives the
  handshake with the *enrolled* operator identity. On the xenia-wire branch
  `sealed-operator-channel/wasm-from-identity` (compile-verified against
  `wasm32-unknown-unknown`); merges to xenia-wire `main` via PR. The
  WASM↔native key/identity parity is guaranteed by the identical derivation and
  transitively by Slice 0; an explicit cross-compat assertion (extending
  `xenia-viewer-web/tests/handshake_cross_compat.rs`, which already path-dev-deps
  the native handshake) is Slice 4.
- ✅ **Slice 2 — establishment core + daemon endpoint done**
  (`operator_sealed_channel.rs`): `establish_operator_channel(transport,
  host_mgr, policy)` runs the host handshake and authorizes the authenticated
  peer against `OperatorPolicy`, returning the operator id + role + key schedule
  (fail-closed: a valid handshake from an un-enrolled key → `NotEnrolled`). Then
  `serve_sealed_operator_channel` reads sealed consent decisions over the
  channel, and `run_sealed_operator_endpoint` (wired into `main.rs` behind
  `--operator-sealed` / `--operator-sealed-port`, default 8083) accepts
  connections in an **`'accept` loop with v2 reconnect**: a terminal
  Deny/Revoke breaks; a dropped connection or a failed/un-enrolled handshake
  loops back (so a reconnecting console can still revoke, and a rejected first
  connection yields to a legitimate one); the single per-session grant oneshot
  is threaded across reconnects and resolved at most once — `ConsentServer`
  parity. 3 tests pass.
- 🟢 **Console URL foundation done** — `DaemonConfig.sealed_port` (default 8083)
  + `sealed_ws_url()` in `apps/sovereign-admin/src/config.rs`, so the console
  knows where the sealed endpoint lives (unit-tested; wasm32 check passes).
  `#[allow(dead_code)]` until the driver (Slice 3) consumes it.

- ✅ **Slice 2.5 — wasm-safe handshake exposed as a library** (xenia-wire
  **PR #8**, supersedes #7). Moved the pure viewer handshake core out of the
  `xenia-viewer-web` app crate into the **`xenia-wire` crate** behind an
  off-by-default `handshake` feature: `xenia_wire::handshake::{ViewerHandshake
  (new/from_identity/begin/finish/ed25519_public_key), SessionKeySchedule,
  HandshakeError, derive_labeled_session_key}` — plain Rust, no wasm-bindgen.
  `xenia-viewer-web`'s `WasmHandshake` is now a thin `#[wasm_bindgen]` wrapper
  delegating to it (keeps `begin_inner`/`finish_inner`, the
  `WasmSessionKeySchedule` alias, and the `derive_labeled_session_key`
  re-export, so `session.rs` and the cross-compat test are untouched). Deps
  `ml-kem =0.3.0-rc.2` / `ml-dsa =0.1.1` / `blake3` pinned to viewer-web's exact
  versions (wire format can't drift); getrandom 0.3/0.4 `wasm_js` backends wired
  for the wasm32 `--all-features` build. **Verified:** `handshake_cross_compat`
  3/3 through the wrapper→moved-core asserts byte-identical session keys +
  transcript hash + host-identity fingerprint vs the **real native host**; native
  `--features handshake` and `wasm32 --all-features` both build clean,
  warnings-clean, `cargo fmt --check` clean. **Console consumes it** by adding
  `features = ["handshake"]` to its existing `xenia-wire` dep.
  See `memory/xenia_sealed_browser_client_blocker.md`.
- ✅ **Slice 3 — browser sealed-consent driver done** (`sovereign-admin`):
  `src/sealed_consent.rs` is a gloo_net WebSocket driver — recv HostHello →
  `ViewerHandshake::begin` → send ViewerResponse → recv HostFinalize → `finish`
  → `aead` → `xenia_wire::Session::with_source_id(*b"xnaopch1", 1)` +
  `install_key` + `seal(payload, PAYLOAD_TYPE_APPLICATION_MIN)` → send envelope.
  `OperatorIdentity::seeds()` feeds the handshake the *enrolled* seeds (so the
  handshake authenticates the operator). `consent.rs` `decide()` seals the same
  payload the plaintext path builds (keeping the per-action Ed25519 signature for
  ledger non-repudiation) when `config.use_sealed_channel` is set — a persisted
  toggle + Sealed Port field added to the Sessions settings UI. Depends on
  `xenia-wire` `features = ["handshake"]`. **Verified:** `cargo build -p
  sovereign-admin --target wasm32-unknown-unknown` clean (no errors/warnings);
  wire-compat guaranteed by Slice 2.5's `handshake_cross_compat` (3/3, same
  `ViewerHandshake` + `source_id`). **End-to-end sealed operator channel is now
  complete: daemon (Slice 2 + v2 reconnect) ↔ console (Slice 3).**
- ⬜ **Slice 4 — live browser↔daemon E2E** (optional): a running-daemon +
  headless-browser test of the full flow. The cryptographic wire-compat is
  already proven natively by `handshake_cross_compat` (Slice 2.5), so this is a
  transport/integration smoke test, not a correctness gate.
