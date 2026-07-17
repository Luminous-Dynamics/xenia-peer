# Post-delegation production hardening

**Milestone: `post-delegation-production-hardening-v0.1`.** Signer delegation
(`SIGNER_DELEGATION_DESIGN.md`, all 7 steps) is complete: the browser never
holds the operator's raw signing seeds, not even transiently. This doc is the
next phase -- closing authority-boundary gaps and proving the whole product
end-to-end, rather than adding more features. Recorded 2026-07-13 from a
detailed external review; kept as a living checklist, not a one-shot plan.

**The strategic point, stated plainly:** stop measuring progress primarily by
test count. The next real proof is: *a fresh machine can install Xenia,
enroll an operator, trust a daemon, authorize a session, exchange real
traffic, revoke it, restart everything, and reproduce the entire result
through mandatory CI -- with no durable browser-held authority.* Reaching
that moves Xenia from an unusually sophisticated security prototype toward a
credible pre-production system.

## Recommended PR order

1. **Transactional native pin storage with failure injection.** ✅ done
2. **Stable endpoint/daemon scope for native host pins.** ✅ done
3. **Remove the legacy HMAC ledger/admin path.** ✅ done
4. **Replace the persistent pairing token with short-lived agent sessions.** ✅ done
5. **Resolve the hybrid-versus-classical HTTP authorization profile.** ✅ done
6. **Add the full headless-browser vertical slice.** ✅ done
7. **Zeroization, serialization migration, and fuzzing.** Mostly done (bincode migration deliberately deferred)
8. **Packaging, recovery, and independent audit.** Partly done (agent audit logging, health endpoints, and operator-key recovery are done; systemd packaging, token/session auto-rotation, and backup remain deferred)
9. **Durable, verified consent-ledger persistence.** ✅ done

## 1. Transactional native pin storage

`host_trust.rs`'s `set_pin()` mutated the in-memory map *before*
persistence, then returned an error if persistence failed -- but the new pin
stayed trusted in memory regardless. A retry in the same process could
return `Matched` for a pin that was never durably stored. `forget()` had the
symmetric bug (removed the in-memory pin before knowing persistence
succeeded). Fix, mirroring the discipline `sovereign-admin`'s browser-side
`host_pin.rs` already follows: construct a candidate map, persist the
candidate successfully, only then replace the live in-memory map.

`HostTrustStore::load()` also used `filter_map` on stored pin values --
invalid hex or wrong-length entries were silently discarded. A
security-state file must fail closed on *any* malformed entry, not partially
load.

Introduce a `PinStorage` trait (mirrors `host_pin.rs`'s `PinStore`) so the
transactional logic is unit-testable against injected faults:
malformed individual pin, read failure, first-pin write failure, rotation
write failure, forget write failure, and reload-after-every-successful-op.

## 2. Stable host scope for pins

Production code did `let host_alias = hex::encode(fingerprint);` then stored
under `{host_alias}:{suite}`. Since the alias *is* the fingerprint, a changed
fingerprint produces an entirely new key -- `FingerprintChanged` is
effectively unreachable through the real agent endpoints; a rotated/spoofed
identity looks like another first-use host, not "the known daemon changed
identity." The cryptographic gate still requires confirmation either way, so
this isn't an automatic bypass -- but the native agent can't tell the
operator "the daemon at this known endpoint changed from A to B."

Fix: scope `/v1/handshake/begin` and Track A requests by something stable
(normalized daemon endpoint; operator-assigned alias; a stable daemon
instance ID from the signed certificate) + suite. The fingerprint stays the
verified identity value; the scope is the slot identity continuity is
checked against. First-use confirmation should show endpoint, daemon ID,
suite, and fingerprint together.

**Done.** Added `daemon_endpoint: String` to `SignRequestCommon` and
`HandshakeRequestCommon` (`xenia-operator-agent-proto`, schema version bumped
2 -> 3) -- the caller's own belief about which daemon it's talking to (the
console's configured endpoint / sealed-channel WS URL), used *only* as the
pin-store scope key, never as identity evidence; the agent normalizes it
(`normalize_daemon_endpoint`: trim + lowercase) before using it, never
trusting the caller's own normalization. `enforce_host_trust` (Track A) and
`handshake_begin`/`handshake_finish` (Track B) now scope
`check_host_trust_fingerprint` by this normalized endpoint instead of
`hex::encode(fingerprint)`. Track B's pending-handshake state
(`handshake_state.rs`) carries `daemon_endpoint` from `/begin` through to
`/finish` (`HandshakeState::take` now returns a `TakenHandshake { suite,
daemon_endpoint }`) since the fingerprint only becomes known at `finish`
time. `host_trust.rs`'s confirmation prompts now label the field "daemon
endpoint" (was "host"); `sign_revoke`'s own action-confirmation prompt also
shows it alongside the fingerprint and suite. New test
(`sign_challenge_detects_a_rotated_fingerprint_at_the_same_daemon_endpoint`)
proves the actual fix: two different daemon identities presenting at the
same `daemon_endpoint` land as one rotated pin-store entry, not two
unrelated first-use entries -- the exact scenario that was unreachable
before. An operator-assigned custom alias (configurable in the browser UI)
remains a possible future enhancement, not implemented here -- the
normalized endpoint alone already closes the reachability gap.

## 3. Remove the legacy browser HMAC admin-secret path

The console still has an older, separate control path alongside the
operator-RBAC one: `AgentConfig`/`DaemonConfig` store a long-lived agent
token and an "Admin Secret (HMAC Hex)" in `localStorage`; `sessions.rs` sends
the secret as `X-Admin-HMAC`; `apps/xenia-peer/src/api/mod.rs` appears
orphaned (not mounted by the current daemon router). The raw operator
identity is gone from the browser, but obsolete authority concepts --
possibly a dead ledger flow -- are still live surface. Consolidate:

- Delete the browser-stored HMAC admin secret.
- Serve ledger/audit access through the current operator RBAC model.
- Decide: is the signed ledger publicly readable and independently
  verifiable, or token-authorized? Avoid a parallel static-secret system.
- Remove or formally revive `api/mod.rs` rather than leave it orphaned.
- Make the sealed authenticated control path canonical.

**Done.** Landed the model an external review recommended: **private contents,
public commitments, portable proofs.**

- Confirmed `apps/xenia-peer/src/api/mod.rs` was genuinely dead, not just
  legacy: no `mod api;` declaration anywhere in the crate, and its
  `create_router(state: Arc<AppState>)` referenced an `AppState` type that
  doesn't exist anywhere in `xenia-peer`. It had never compiled as part of
  the crate. Deleted outright (nothing to migrate).
- Deleted `DaemonConfig::hmac_secret` (browser `localStorage`), the "Admin
  Secret (HMAC Hex)" UI field, `X-Admin-HMAC`, and the whole dead
  `RealLedger`/`fetch_identity`/`fetch_ledger` browser flow that called
  `GET /identity`/`GET /ledger` -- routes that had only ever existed in the
  orphaned `api/mod.rs`, so that flow 404'd against every real daemon that
  ever ran it.
- **New `xenia_ledger::LedgerCheckpoint`** (crate addition, not
  daemon-specific): `schema`, `entry_count`, `head_hash`
  (`Chain::last_hash()`), `ledger_public_key`, `timestamp_unix_secs`,
  Ed25519 `signature` over a domain-separated message of the other fields.
  Deliberately carries zero event contents (no session/request IDs, no
  scope strings) -- see its doc comment for the "third party retains
  checkpoints, later detects rewriting/truncation without ever seeing
  ledger contents" argument. `Chain::sign_checkpoint(timestamp)` produces
  one from the ledger's own signing key (the same key that signs every
  entry -- no new key introduced); `Verifier::verify_checkpoint` checks it.
  9 new tests incl. a `serde_json` round-trip asserting the JSON text never
  contains a known scope string, and tampered entry_count/head_hash/schema/
  wrong-key all rejected.
- **`GET /v1/audit/checkpoint`** (new route, `operator_http.rs`): public,
  no authentication, signs and returns the live `shared_ledger`'s
  checkpoint fresh on every call.
- **`GET /v1/audit/ledger`** (new route): the full in-memory entry export
  plus a checkpoint over the same state, gated by a new
  `operator_auth::authorize_ledger_read` (token must verify, unexpired,
  role must permit `OperatorAction::ReadAudit`, operator still enrolled).
  That action/role pairing **already existed** in `xenia-operator-proto`
  (`Viewer`'s doc comment literally says "see... the audit ledger") --
  nothing new to add there. Deliberately has **no separate per-request
  Ed25519 signature** the way consent-action/revoke do: those exist to
  bind a *mutating, non-repudiable* decision to a specific human; a read
  has nothing beyond what the bearer token's own role/expiry already
  gates. Token travels in an `X-Operator-Token` header (JSON, same shape
  `POST /auth/verify` already returns) since `GET` request bodies are
  awkward across HTTP clients. 7 new tests: public/no-auth for the
  checkpoint, missing/malformed/expired/tampered/unenrolled token all
  refused (403/401/400 as appropriate), and a real round trip proving the
  export's entry count and checkpoint agree.
- Browser: `OperatorSession` gained `token_json_string()` (the private
  `token_json` field stayed private; this is a scoped accessor, not a
  visibility widening) so `pages/sessions.rs`'s new `LedgerAudit` component
  can build the header. `LedgerAudit` always shows the public checkpoint;
  once the operator has an active RBAC session (reactively -- signing in
  or out re-triggers the fetch) it also fetches and locally verifies the
  full export via the existing `VerifiableLedger` display component.
- **Redaction** (the "don't mutate history, produce a separately signed
  disclosure bundle" half of the reviewed design) is **not implemented** --
  there is no redaction *policy* or bounded-bundle-with-omission-manifest
  concept anywhere yet for this to hook into. Recorded as explicitly
  deferred, not silently dropped: a real redaction feature needs its own
  design pass (what may be withheld, under what policy, how the omission
  is proven) rather than a speculative stub here.
- Not done (also out of scope for this PR, noted for whoever picks up
  ledger work next): `consent.ledger` is still never written back to disk
  after `Chain::append` (only read once at startup) -- appends are
  in-memory-only and lost on daemon restart, so `GET /v1/audit/*` only
  ever reflects the current process's uptime. `M1RuntimeSession` also
  holds a second, entirely independent `Chain` under a different signing
  key (`--m1-consent-key-path`) that `/v1/audit/*` does not see at all.
  Both are real, pre-existing gaps this PR did not create and did not fix.

## 4. Replace the static pairing token

The agent's pairing token is materially less dangerous than the signing
keys, but it's still a durable capability that can invoke signing and
handshaking. Today it's printed on every agent startup, persisted in a file,
persisted by the browser in `localStorage`, and accepted indefinitely until
manually replaced. Replace with pairing + session:

1. Agent creates a one-use pairing code.
2. Native confirmation approves the browser Origin.
3. Browser receives a short-lived, Origin-bound session capability.
4. Capability lives in memory or `sessionStorage`, never durable
   `localStorage`.
5. Agent supports session listing and revocation.
6. Restart invalidates active browser sessions unless explicitly restored.
7. The bootstrap secret isn't printed into service logs on every launch.

Add rate limits to agent endpoints against accidental loops and
same-origin abuse.

**Done**, but with real, deliberate divergences from the numbered sketch
above -- recorded here rather than silently reinterpreted.

- Landed the core exchange: the raw pairing token (`X-Agent-Token`,
  file-persisted, printed once at agent startup) now authenticates exactly
  one route, `POST /v1/pair`. Every other agent route (`/identity`,
  `/v1/sign/*`, `/v1/handshake/*`, `/v1/session/refresh`) requires a
  short-lived `AgentSessionToken` (`X-Agent-Session`) instead --
  1-hour default TTL (`--session-ttl-secs`), stateless keyed-BLAKE3 MAC
  (`blake3::derive_key` off the pairing token, then `blake3::keyed_hash`;
  new shared shapes in `xenia-operator-agent-proto`, verification logic in
  the agent's new `agent_session` module). `POST /v1/session/refresh`
  (itself session-gated, not token-gated) lets an actively-used console
  renew indefinitely without ever re-presenting the raw token; the browser
  (`sovereign-admin`'s `agent_client::ensure_fresh_session`) renews
  automatically once a session is within 5 minutes of expiry, falling back
  to the still-valid current session if a renewal attempt fails.
- **Not a one-use pairing code (item 1), no native-confirmation-of-Origin
  step (item 2).** Pairing is still "paste the persisted token, get a
  session" -- the token itself is reusable and durable on disk exactly as
  before, and `/v1/pair` grants a session to *any* request presenting it
  from an allowed Origin, with no additional native terminal confirmation
  step the way `host_trust`'s TOFU/rotation checks have. This is a smaller
  change than the original sketch: it bounds the *time* a leaked
  credential works for, but doesn't add a fresh out-of-band approval to
  each pairing event.
- **Session lives in `localStorage`, not `sessionStorage` (item 4).**
  Deliberate: an unbounded credential in durable storage was the actual
  problem: now that the stored value expires on its own, persisting it
  across tab closes/restarts (so the operator isn't forced to re-pair on
  every page load) was judged worth more than the extra tightening
  `sessionStorage` would add. Revisit if that tradeoff turns out wrong in
  practice.
- **Sessions intentionally survive an agent restart (item 6 not done, and
  not planned as specified).** The MAC key is derived deterministically
  from the persisted pairing-token file, not a fresh per-process secret,
  specifically so restarting the agent doesn't silently log out every open
  console tab. The tradeoff: there is **no way to revoke a single
  outstanding session** before its natural expiry -- verification is
  stateless (no session table). The only revocation lever is regenerating
  the pairing-token file, which invalidates every outstanding session at
  once. That blunt instrument already existed for the old static token
  (delete the file to force a new one); this change adds a time bound on
  top of it without regressing what was already there. Per-session
  listing/revocation (item 5) would require the agent to hold live state
  and was scoped out rather than half-built.
- **Item 7 (bootstrap secret not printed into logs) and rate limiting: not
  done.** The agent still prints the raw pairing token to stdout on every
  launch (unchanged from before this item) and neither `/v1/pair` nor
  `/v1/session/refresh` carry any new rate limiting. Both are real,
  reasonable follow-ups, not done here.

## 5. Decide what "PQC authorization" means

The `/auth/challenge` proof is hybrid Ed25519 + ML-DSA. But daemon session
tokens are signed by a delegated Ed25519-only HTTP key; consent-action and
operator-revocation signatures are Ed25519-only too. `OPERATOR_SECURITY_MODEL.md`
documents this, but `SIGNER_DELEGATION_DESIGN.md` still generally claims
Track A "signs with both required algorithms" -- true for the challenge,
not for consent-action/revoke. Pick one explicit posture:

- **Full hybrid HTTP authorization**: add ML-DSA signatures to daemon
  tokens and privileged operator actions, AND-verified.
- **Sealed-channel security boundary** (preferred for ordinary consent
  traffic, since the handshake already authenticates the full hybrid
  operator identity): require the hybrid sealed channel for privileged
  actions (enrollment, revocation, role changes, key rotation) and clearly
  classify HTTP token authorization as a compatibility/classical path.

Whichever is chosen, fix the design doc's inaccurate blanket claim.

**Done.** User chose **full hybrid HTTP authorization** over the sealed-channel
alternative (that alternative would have meant building a wholly new
sealed-channel message type for operator revocation -- the only currently-live
privileged action; enrollment/role-changes/key-rotation have no live HTTP
endpoint at all, only static config files -- for a narrower fix than closing
the gap everywhere at once).

- **New `xenia_handshake::MlDsaIdentity`**: a standalone ML-DSA-65 signing
  identity with no Ed25519 half, for roles that already have an
  independently-used Ed25519 key `HandshakeManager`'s always-hybrid design
  can't just replace. Concretely: `apps/xenia-peer`'s `operator_key_path`
  key is *also* `xenia_ledger::Chain`'s signing key -- hybridizing it in
  place would have meant hybridizing the ledger's signature scheme too,
  well outside this item's scope. The daemon now loads a *second*, new key
  (`--http-auth-ml-dsa-key-path`, a bare 32-byte seed, default
  `operator-http-ml-dsa.key`) purely for this role.
- **`DaemonIdentityCertificate`** (`xenia-operator-proto`) gained
  `http_auth_ml_dsa_pubkey`; `daemon_delegation_transcript` now covers both
  HTTP-auth pubkeys, so the host identity's delegation signature vouches
  for the *pair*, not just the Ed25519 half.
- **Daemon session tokens** (`OperatorToken`/`SignedOperatorToken`,
  `TokenDto`): `issue_token`/`verify_token` now produce/require both an
  Ed25519 and an ML-DSA-65 signature over the identical canonical bytes,
  AND-verified. `POST /auth/verify`'s response, and every internal
  `verify_token`/`authorize_*` call site (consent-action, ledger-read,
  operator-revocation) thread the daemon's ML-DSA pubkey through.
- **Consent-action / operator-revocation per-action signatures**: the
  operator agent already held the operator's ML-DSA seed in memory for the
  challenge step; it just wasn't asked to sign consent-action/revoke
  transcripts with it. Now it signs both algorithms for
  `/v1/sign/consent-action` and `/v1/sign/revoke`, and the daemon
  AND-verifies against the operator's already-enrolled ML-DSA pubkey
  (`EnrolledOperator.ml_dsa_pubkey` -- no new enrollment data needed).
  `AuthenticatedConsentAction`/`AuthenticatedRevocation` and their wire DTOs
  gained `ml_dsa_action_signature`(`_hex`).
- **Agent verification** (`daemon_evidence.rs`): `verify_daemon_certificate`
  now AND-verifies the delegation signature against both HTTP-auth pubkeys;
  `verify_token` AND-verifies both signatures on a relayed
  `SignedTokenDto` before trusting its `token_nonce`.
- **Browser**: `OperatorSession` carries and relays the daemon's ML-DSA
  token signature (`ml_dsa_signature_hex`) verbatim (same pattern as the
  Ed25519 one); `build_consent_request`/`build_revoke_request` now embed
  both signatures the agent returns in the JSON sent to the daemon.
- Fixed the design docs: `SIGNER_DELEGATION_DESIGN.md`'s step 1 no longer
  describes the (now-removed, see item 4) raw pairing token as the agent's
  local-caller credential; `OPERATOR_SECURITY_MODEL.md` no longer says
  "per-action Ed25519 signature" or "signed by the daemon's key" without
  qualification -- both now correctly say hybrid, AND-verified, both
  algorithms required.
- Verified: `cargo test` green across `xenia-handshake` (2 new
  `MlDsaIdentity` tests), `xenia-operator-proto`, `xenia-operator-agent-proto`,
  `xenia-peer` (117 tests, incl. the full `operator_rbac_smoke` integration
  test updated to sign both algorithms), `xenia-operator-agent` (89 tests,
  incl. new wrong-ML-DSA-key rejection tests mirroring the existing
  wrong-Ed25519-key ones); clippy clean on every touched native crate and on
  `sovereign-admin`'s wasm32 target.
- Not done (real, deliberate scope limits, not oversights): no rate limiting
  or log-scrubbing of the new ML-DSA key material (same gap item 4 already
  flagged for the pairing token); the ledger's own signing key
  (`operator_key_path`) stays classical-only Ed25519, unrelated to this
  item's HTTP-authorization scope; enrollment/role-change/key-rotation still
  have no live HTTP surface at all (config-file-only), so "full hybrid" here
  covers every privileged action that actually exists today, not a
  hypothetical future one.

## 6. The real browser-driven vertical slice

Not another unit-test expansion -- one mandatory test that launches the
actual system: daemon, operator agent, compiled console, headless browser,
test capture/input backend. It must prove:

1. Agent pairs with the console.
2. Public identity is enrolled through the actual JSON path.
3. Operator authenticates.
4. First host trust requires native approval.
5. Hybrid sealed handshake completes.
6. Consent is approved.
7. Frames flow only afterward.
8. Input is blocked before consent and allowed afterward.
9. Rekey succeeds.
10. Revocation terminates authority immediately.
11. Changed daemon identity is refused.
12. Daemon and agent restart recover the intended state.
13. No browser storage contains operator keys, HMAC secrets, or durable
    signing capabilities.

Playwright, installed reproducibly through Nix (not whatever happens to be
on a workstation).

**Done.**

- New `devShells.e2e` / `apps.e2e` in `flake.nix`: `playwright-driver.browsers`
  (pre-fetched, `autoPatchelfHook`-patched Chromium -- avoids needing a
  `buildFHSEnv` wrapper) + `python3Packages.playwright` + `pexpect`, the
  latter required because `xenia-operator-agent`'s native confirmation
  prompt (`host_trust::confirm()`) checks `is_terminal()` on stdin/stdout
  and fails closed on a plain piped subprocess -- the agent has to be
  spawned attached to a real pseudo-terminal.
- New `scripts/xenia-e2e-vertical-slice.sh` (build orchestrator: the three
  real binaries + `trunk build` for the console) and
  `scripts/e2e/vertical_slice.py` (the actual driver -- one sequential,
  causally-ordered scenario across seven stages, not 13 independent
  tests, since the steps depend on each other). Real processes throughout:
  `xenia-peer`, `xenia-operator-agent` (under pexpect), `xenia-viewer`,
  and the Trunk-built `sovereign-admin` console driven by a real headless
  Chromium via Playwright. All 13 numbered properties above are exercised
  and asserted on, most via log-grep against the real daemon/agent/viewer
  output (matching `scripts/xenia-audio-e2e-smoke.sh`'s established
  convention) plus DOM assertions and a `localStorage` dump for property
  13. New `--send-synthetic-input` / `--send-synthetic-input-after-frames`
  flags on `xenia-viewer` make property 8 (input gating) testable
  headlessly -- real captured input requires a real GUI window
  (`--gui` + a compositor), so these send one real
  `xenia_inject::InputEvent` through the exact same seal + send path the
  GUI capture path uses, timed relative to frame receipt (before vs.
  after consent) the same way `--play-audio synthetic` already supplies
  audio without a real microphone.
- New `e2e:` job in `.github/workflows/xenia-validate.yml`, landed in this
  same change (not deferred) -- runs the full vertical slice under
  `nix develop .#e2e` on every PR, with an `actions/cache` for the cargo
  registry/target dir (a from-scratch compile is otherwise the long pole:
  the pinned nixpkgs rustc differs from most workstations' ambient
  toolchain, so this is genuinely a cold build the first time any given
  cache key is seen) and a failure-diagnostics artifact upload.
- **Real, previously-undiscovered bugs found and fixed** -- this is the
  first time this console had ever actually been driven by a real
  browser against a real daemon; every one of these had compiled clean
  and passed every existing unit/integration test, because none of them
  exercise an actual `fetch()`/`WebSocket` from an actual browser origin:
  - **The daemon's admin HTTP router had no CORS handling at all.** The
    console is always cross-origin from the daemon's admin port by
    construction (fixed Trunk dev-serve port vs. an operator-configured
    admin port), so every `fetch()` to `/auth/*` or `/v1/audit/*` failed
    with a generic `TypeError: Failed to fetch` and no clearer signal.
    `xenia-operator-agent` already had a working Origin-allowlist + CORS
    pattern (`auth_and_cors_middleware`); added the daemon-side
    equivalent (`operator_http::cors_middleware`) plus a new
    `--allowed-origin` flag (same defaults as the agent's).
  - **`ConsentModal`'s WebSocket connection opened once at component
    mount and never reconnected.** The console fully supports changing
    the daemon endpoint and clicking "Save & Reconnect" -- every other
    part of the UI honors it -- but the consent-broadcast listener stayed
    silently pointed at whatever endpoint was configured on first page
    load, forever. Wrapped the connection logic in an `Effect::new`
    tracking `config.endpoint`.
  - **`identity_state` got permanently stuck on `Loading` after any
    operator or DID sign-out, with no way back short of a full page
    reload.** Both sign-out handlers reset it to `Loading` "to force a
    refresh," but the effect that fetches it only depends on
    `agent_config.agent_url`/`agent_config.agent_session`, not on
    `identity_state` itself -- nothing ever re-triggered the fetch.
    Removed both resets; the agent's already-fetched identity/enrollment
    info doesn't actually go stale on sign-out, so nothing needed to be
    dropped in the first place.
  - **Daemon defaults to `--transport auto` (a QUIC-advertisement
    discovery/probe exchange before falling back to TCP); a viewer
    started with `--transport tcp` skips that and speaks the raw
    handshake immediately.** The daemon then misreads those bytes as a
    discovery probe, producing a real bincode deserialization error on
    the viewer side and a `BrokenPipe` on the daemon side once the viewer
    had already exited. `scripts/xenia-audio-e2e-smoke.sh` already avoids
    this by passing `--transport` explicitly on both sides; the new e2e
    harness now does too.
  - Two Track-A/Track-B host-trust confirmation prompts this test
    surfaced that weren't previously obvious from reading the design
    docs alone: `/v1/sign/revoke` runs its own *separate*,
    action-specific native confirmation (`confirm_action`) on top of
    (not instead of) the ordinary host-identity check, and every
    `enforce_host_trust` call is scoped by the caller's exact
    `daemon_endpoint` string -- so Track A (HTTP admin port) and Track B
    (sealed WS port) pin independently, and any daemon restart onto a
    new port is a genuine first-use for whichever track's endpoint
    changed, confirmation prompt and all.
- Not done: property 9 ("rekey succeeds") is proven via the *viewer
  session's* frame-encryption epoch rekey (the same mechanism
  `xenia-audio-e2e-smoke.sh` already validates), not the *operator
  channel's* own forward-secrecy rekey
  (`--operator-rekey-interval-secs`). The latter has no browser-reachable
  path yet: `sovereign-admin`'s sealed-channel driver
  (`sealed_consent.rs`) is a one-shot connect/decide/close and never
  calls the already-real, already-tested
  `handle_operator_rekey_envelope` -- a genuine gap for a future
  persistent-console mode, explicitly out of scope here.

## 7. Protocol and operational hardening (after the vertical slice)

- `Zeroize`/`Drop` for `ViewerHandshake`/`ViewerHandshakeHighSec` so pending
  ML-DSA/KEM material doesn't rely on allocator reuse.
- Migrate off unmaintained `bincode` 1.3.3.
- Fuzz every externally-parsed handshake, envelope, evidence, and agent
  request type.
- Agent state in a dedicated `0700` directory.
- Descriptor-relative/no-follow filesystem access + parent-directory checks.

**Mostly done** -- 4 of the 5 bullets above. Landed across two `xenia-wire`
PRs plus one `xenia-peer` PR, deliberately *not* including the bincode
migration (see below).

- **Zeroize** (`xenia-wire` PR #15): `PendingState` (`handshake.rs`) and
  `ViewerPendingState`/`HostPendingState` (`handshake_highsec.rs`) held the
  handshake's raw derived `root_key` -- the actual shared secret feeding
  `SessionKeySchedule::derive` -- as a plain `[u8; 32]` with no
  `Drop`/`Zeroize` at all. Added `#[derive(Zeroize, ZeroizeOnDrop)]` to all
  three (`host_verifying_key`/`kem_dk` skipped: the former is a public key
  and `ed25519_dalek::VerifyingKey` doesn't implement `Zeroize` anyway; the
  latter, `ml_kem::DecapsulationKey`, already has its own zeroizing `Drop`
  via this crate's existing `ml-kem` "zeroize" feature, which still fires
  automatically as a normal field drop even when skipped from the derive).
  Separately, `ml-dsa`'s own "zeroize" feature was never enabled in this
  crate's `Cargo.toml`, so `MlDsaSigningKey<MlDsa65>`'s `Drop` impl -- which
  exists unconditionally but only actually calls `.zeroize()` on the seed
  when that feature is on -- was silently a no-op; one-line fix.
  `ViewerHandshake`/`ViewerHandshakeHighSec` themselves needed no new `Drop`
  impl once these two were closed. **Deliberately not touched**:
  `SessionKeySchedule` derives `Copy` (identically on this crate's and the
  native `xenia-handshake` mirror's side), and `Copy`+`Drop` cannot coexist
  in Rust -- retrofitting it would mean dropping `Copy` on both
  independently-mirrored copies, a real API-compat question for its own
  future item, not bundled in here.
- **Agent state hardening** (`xenia-peer` PR, `secure_file.rs`): two real
  gaps closed. No dedicated state directory -- every `--xxx-path` flag
  defaulted to a bare CWD-relative filename, and `create_dir_all` left
  parent directories at whatever the ambient umask gave (typically `0755`,
  world-listable); defaults now point inside a new
  `xenia-operator-agent-state/` directory, created and re-verified `0700`
  on every access. TOCTOU between the symlink/ownership check and the
  actual open, and no check on the parent directory itself (only the final
  file) -- `check_existing_file_is_safe` called `symlink_metadata`, then a
  *separate* `fs::read` that could follow a symlink swapped in between the
  two calls. Rewrote the module around rustix's safe (no `unsafe` code, per
  this workspace's `deny(unsafe_code)` lint) `openat`/`fstat`/`renameat`:
  the parent directory is opened `O_NOFOLLOW` and `fstat`-verified once,
  and every file open thereafter is descriptor-relative to that verified
  directory and also `O_NOFOLLOW` -- closing the race (the safety check and
  the open are now the same syscall) and rejecting an attacker-controlled
  parent directory, not just an attacker-swapped leaf file. Public API
  unchanged; non-unix fallback keeps the old simpler behavior (this
  hardening is POSIX-permission-bit specific). 94 tests pass (9 new).
- **Fuzzing** (`xenia-wire` PR #16 + new `xenia-peer` `fuzz/`): `xenia-wire`
  already had a real cargo-fuzz harness, but none of its 5 targets exercised
  the `handshake`/`operator-rekey` features. Added `fuzz_handshake_begin`,
  `fuzz_handshake_highsec_begin` (`ViewerHandshake`/`ViewerHandshakeHighSec`
  `::begin()` -- the real network-facing entry point for a `HostHello`
  envelope, reached before any authentication), and `fuzz_operator_rekey`
  (`OperatorRekeyMessage::decode()`). `xenia-peer` had *zero* fuzz
  infrastructure; bootstrapped a new `fuzz/` (same shape, not a member of
  the root workspace since it uses an explicit `members` list rather than a
  glob) with `fuzz_agent_request` (the union of `/v1/*` request DTOs via
  `serde_json`) and `fuzz_evidence_verify` (JSON-decodes a
  `DaemonIdentityCertificate`, then reruns `daemon_evidence::verify_daemon_certificate`'s
  hex-decode + dual-signature-verify + fingerprint steps using the same
  public library primitives -- **not** a direct call to that function
  itself, which lives in a binary-only crate with no library target and so
  isn't reachable from an external fuzz crate; a real, disclosed gap, not
  silently worked around). `cargo-fuzz` itself isn't installed in the
  environment this was developed in, so verification used a direct
  `cargo +nightly build --bins` + standalone run rather than the full
  `cargo fuzz run` wrapper -- all 5 new targets ran clean across millions
  of executions combined, no crashes, though without sanitizer-coverage
  instrumentation this is a random-input smoke test, not a true
  coverage-guided campaign.
- **Not done, deliberately**: migrating off bincode 1.3.3. Research
  surfaced that this is *not* an active vulnerability -- `xenia-wire`'s own
  CI already ignores RUSTSEC-2025-0141 with an explicit comment that it's
  an unmaintained-crate flag, not an exploit, and that migration is
  "tracked as a v1.0-blocker decision, not a CI-blocking vulnerability"
  because `SPEC.md` §12.3 normatively specifies bincode v1's exact encoding
  as the canonical wire format, and a third-party Node.js
  conformance-verification suite (`test-vectors/conformance/`) would also
  need its decoder updated to match any new format, on top of ~39 call
  sites in `xenia-wire` alone, the native `xenia-peer-core`/`xenia-handshake`
  mirrors, 12 test-vector files, and a formal draft-04 spec bump. A
  deliberate, already-documented deferral, not an oversight -- left for its
  own future item.
- Also not done: rate limiting on agent endpoints (flagged since item 4);
  log-scrubbing of key material; the daemon (`xenia-peer`) has its own,
  separately-authored, scattered `0600`-file-permission code with the same
  class of filesystem exposure this item closed on the agent side, noted
  as a real, undone follow-up rather than silently expanded scope.

## 8. Packaging, recovery, audit

- systemd user-service packaging, health reporting, token/session rotation,
  backup, operator-key recovery procedures.
- Audit-log agent trust decisions, privileged confirmations, pairing,
  session revocation, and identity rotation -- without logging secrets.
- Commission independent review of `xenia-wire` once wire formats stop
  changing.

**Partly done.** Research (a forked-agent survey, verified against the live
repo) found this item bundles genuinely independent sub-projects at very
different levels of readiness -- see the scope notes below for what's done
vs. explicitly deferred.

- **Agent-side audit logging.** New `apps/xenia-operator-agent/src/audit_log.rs`:
  a hash-chained, Ed25519-signed audit trail for this agent's own trust
  decisions. `xenia_ledger::Chain` (the daemon's consent ledger, item 9)
  can't be reused directly -- its `LedgerEntry.event` is hard-typed to
  `ConsentEventRecord` (`session_id`, `request_id`, `ConsentKind`, `scope`),
  which doesn't fit "host X's identity changed" or "pairing token consumed"
  without distorting a consent-specific shape. Mirrors `Chain`'s proven
  pattern instead (`append_transactional` persist-then-commit, `verify_chain`
  sequence/hash-link/signature checks, `sign_checkpoint`) over a new
  `AgentAuditEvent` type. Persists via `secure_file.rs`'s existing hardened,
  descriptor-relative, `O_NOFOLLOW` access (item 7) -- no new
  filesystem-safety code needed. Wired at 5 real event sites that previously
  produced nothing but an ephemeral `tracing` call: host-trust first-use/
  rotation (`host_trust::PinOutcome::Rotated` extended to carry the old
  fingerprint -- a real gap closed in passing, since the audit event
  otherwise couldn't show what changed), pairing, session refresh, and
  revocation. Each append fails closed (refuses the action if persistence
  fails), matching item 9's consent-ledger discipline. New `GET /v1/audit`
  route, gated by the same session-token middleware every other `/v1/*`
  route already uses. Closes the clearest gap against
  `PRE_PRODUCTION_GATES.md` **Gate 5** ("admin actions... produce durable
  audit records") -- consent was already covered, admin/policy actions on
  the agent side were not.
- **Health-check endpoints.** New `GET /v1/health` on the agent and
  `GET /health` on the daemon -- neither existed before. Both
  unauthenticated (a liveness probe has no session and shouldn't need one):
  the agent's sits in its own router, merged in without
  `auth_and_cors_middleware`'s layer, rather than a path special-case
  inside that function. Minimal response shape (status, uptime, a public
  fingerprint/entry-count) -- no secret material.
- **Not done, deliberately deferred**: systemd packaging (zero prior art
  anywhere in the repo), token/session automatic rotation (only passive TTL
  expiry + manual refresh exists today), backup tooling/procedures, and
  operator-key recovery (currently genuinely catastrophic if an operator
  loses their identity key file -- no self-service re-enroll path exists;
  recovery today means the daemon operator manually editing the static
  `--operators-file` and restarting). Key recovery in particular is the
  riskiest of these to design well -- a careless self-service re-enroll
  flow becomes new attack surface -- and is left for its own dedicated item
  rather than rushed.
- **Not done, confirmed not ripe**: "commission independent review of
  `xenia-wire`." Checked against the project's own stated criterion --
  `xenia-wire` is `0.2.0-alpha.8`, `SPEC.md`'s own header says "Pre-alpha --
  the format is subject to breaking change in subsequent drafts," and the
  current draft-03 was itself a breaking change over draft-02r2. This also
  isn't a codeable task -- it's commissioning a human reviewer once the
  format stabilizes, not engineering work.

## 9. Durable, verified consent-ledger persistence

Not one of the original 8 items -- discovered as a real, disclosed gap while
reviewing an external (OpenAI-authored) audit-hardening patch series against
this codebase, and independently confirmed by reading the actual code: item
3's `shared_ledger` was **never written to disk at all** (every append lived
only in the in-process `Arc<Mutex<Chain>>`, lost on restart), and the one
place a persisted ledger *was* read back, if a `consent.ledger` file
happened to already exist, was **never verified**
(`xenia_ledger::Chain::from_entries`'s own doc comment says as much). A
tampered or corrupted on-disk file would have been silently trusted and
served as genuine signed history over `/v1/audit/*`.

**Done.**

- New `xenia_ledger::Chain::append_transactional`: appends an entry, then
  calls a caller-supplied `persist` closure with the resulting full entry
  list; on a `persist` failure the entry is rolled back before returning,
  so a caller never observes a successful append that wasn't durably
  committed.
- New `apps/xenia-peer/src/audit_ledger_store.rs`: `load_verified` (decode
  + `Verifier::verify_chain` before trusting -- fails closed, refuses
  startup on a corrupt/tampered file) and `persist_entries_atomic` (temp
  file → `fsync` data → `rename` → `fsync` the containing directory --
  skipping that last directory fsync is the most common way "atomic" file
  replacement still isn't actually crash-safe).
- New `--consent-ledger-path` flag (default `consent.ledger`, unchanged
  from the old hardcoded value).
- `consent_server::apply_consent_decision` now durably persists an
  authenticated decision's audit entry (via `block_in_place`, since the
  daemon's `#[tokio::main]` is multi-threaded) before the decision takes
  effect. If persistence fails, the decision is **refused** -- the grant
  is left unresolved (observed as a closed channel) -- rather than
  silently applying a privileged action with no durable record of who
  authorized it. Threaded through both `ConsentServer` (plaintext) and
  `SealedConsentDeps` (sealed channel), which share this code path.
- Not done: the separate `M1RuntimeSession` ledger (keyed by
  `--m1-consent-key-path`) already has its own persistence path and was
  out of scope here. No log-scrubbing or rotation of the ledger file
  itself (item 8's territory).

## See also

- `SIGNER_DELEGATION_DESIGN.md` -- the completed prerequisite this builds on.
- `OPERATOR_SECURITY_MODEL.md` -- current threat coverage table (§8) and
  known-limits list (§9).
- `PRE_PRODUCTION_GATES.md` -- the broader gate checklist this milestone
  feeds into (mainly Gates 1, 4, 5).
