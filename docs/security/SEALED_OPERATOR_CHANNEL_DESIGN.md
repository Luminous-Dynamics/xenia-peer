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
- ⬜ **Slice 1** — `WasmHandshake::from_identity(ed_seed, ml_seed)` in the
  viewer-web crate (currently generates ephemeral keys), so the browser drives
  the handshake with the console's persisted operator identity.
- ⬜ **Slice 2** — daemon `--operator-sealed` WebSocket: run
  `perform_host_handshake_authenticating_peer`, reject if the peer isn't in
  `OperatorPolicy`, then serve `/auth`/consent as sealed envelopes.
- ⬜ **Slice 3** — move the consent decision path onto sealed `0x31` envelopes
  (smallest, highest-value surface — Approve/Revoke), keeping the per-action
  Ed25519 signature for ledger non-repudiation.
- ⬜ **Slice 4** — cross-compat test (mirror `handshake_cross_compat.rs`)
  asserting the WASM console and daemon derive identical operator-channel keys.
