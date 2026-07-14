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
4. **Replace the persistent pairing token with short-lived agent sessions.**
5. **Resolve the hybrid-versus-classical HTTP authorization profile.**
6. **Add the full headless-browser vertical slice.**
7. **Zeroization, serialization migration, and fuzzing.**
8. **Packaging, recovery, and independent audit.**

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

## 7. Protocol and operational hardening (after the vertical slice)

- `Zeroize`/`Drop` for `ViewerHandshake`/`ViewerHandshakeHighSec` so pending
  ML-DSA/KEM material doesn't rely on allocator reuse.
- Migrate off unmaintained `bincode` 1.3.3.
- Fuzz every externally-parsed handshake, envelope, evidence, and agent
  request type.
- Agent state in a dedicated `0700` directory.
- Descriptor-relative/no-follow filesystem access + parent-directory checks.

## 8. Packaging, recovery, audit

- systemd user-service packaging, health reporting, token/session rotation,
  backup, operator-key recovery procedures.
- Audit-log agent trust decisions, privileged confirmations, pairing,
  session revocation, and identity rotation -- without logging secrets.
- Commission independent review of `xenia-wire` once wire formats stop
  changing.

## See also

- `SIGNER_DELEGATION_DESIGN.md` -- the completed prerequisite this builds on.
- `OPERATOR_SECURITY_MODEL.md` -- current threat coverage table (§8) and
  known-limits list (§9).
- `PRE_PRODUCTION_GATES.md` -- the broader gate checklist this milestone
  feeds into (mainly Gates 1, 4, 5).
