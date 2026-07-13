# Design: agent-side signing delegation (retiring `GET /seeds`)

**Status: all seven steps of the PR sequence below have landed.** (PRs
#69-72 for steps 2-4, #73/#74 for the 4.5a/4.5b confused-deputy fix, #75 for
step 5, #76 + a following PR for step 6's agent-side and browser-side
halves, and a final PR for step 7.) `GET /seeds` is deleted, along with the
browser's `fetch_seeds` and `OperatorIdentity` types. The raw operator seeds
never reach the browser process at all anymore, not even transiently: the
`/auth/*` ceremony and the sealed-channel handshake both ask the agent to
sign/handshake, and the one remaining identity-shaped need in the
browser -- the Sessions-page enrollment display -- is served by the agent's
pre-existing `GET /identity`, which returns only public keys, a fingerprint,
and a paste-ready enrollment record. Follow-up to `apps/xenia-operator-agent`
(PR #65) and its hardening pass (PR #66) -- see
`OPERATOR_SECURITY_MODEL.md` §9 for the gap this closed: the agent moved the
operator's Ed25519/ML-DSA seeds out of browser `localStorage`, but the
console used to fetch them into memory and sign locally with them, for both
the `/auth/*` ceremony and the sealed-channel handshake. This doc planned
having the agent sign directly, so raw key material never reaches the
browser process at all, not even transiently -- now built.

## The one structural fact that reshapes this plan

Earlier scoping (end of the hardening session) assumed this needed an
**async signing-callback abstraction inside `xenia-wire`'s published
`ViewerHandshake`/`ViewerHandshakeHighSec` API** — those types currently own
raw `SigningKey`/`MlDsaSigningKey` fields and call `.sign()` synchronously
inside `begin()`/`finish()`, so delegating the *sign step* to a remote HTTP
call seemed to require redesigning that API surface (a bigger, riskier
change to a published crate, correctly deferred rather than rushed).

That assumption turns out to be avoidable. `apps/xenia-operator-agent`
already depends on `xenia-handshake` and `xenia-wire` **natively** — the
same crates the daemon itself links. There's no wasm boundary between the
agent and these crates the way there is between the *browser* and them.
So instead of teaching `ViewerHandshake` to delegate one signature at a
time to a remote signer, **the agent can just run the entire viewer-side
handshake itself**, unmodified, exactly the way it already runs today
inside the browser's wasm build — and hand the browser back only the
*derived, ephemeral, single-purpose session key*, never the long-term
identity. No `xenia-wire` API changes, no published-crate redesign.

## The second structural fact: typed transcripts are not enough

Having the agent build transcripts itself from typed fields (rather than
signing arbitrary caller-supplied bytes) closes the **blind signing
oracle** gap — a compromised browser can no longer trick the agent into
signing a message it doesn't understand. But typed transcripts alone do
**not** close a second, equally real gap: a compromised browser can submit
a perfectly well-formed, honestly-typed request that targets the *wrong
daemon*. The agent would understand exactly what it's signing and sign it
correctly — for an attacker-controlled host.

The same applies to Track B: after `finish`, the agent has learned the
*authenticated* host fingerprint from the completed handshake. If it
releases the session key before checking that fingerprint against a trust
policy, it has faithfully proven the operator's identity to whoever the
browser happened to be talking to.

**The agent must therefore be the authoritative enforcer of host trust, not
just a signer of well-shaped messages.** Concretely:

- Known pinned host → proceed automatically.
- First use of a host → require a *native* confirmation showing the
  fingerprint and the endpoint's label (not browser-supplied descriptive
  text — see *Confirmation policy* below).
- Changed fingerprint → refuse by default; require an explicit native
  key-rotation operation to accept it.
- Browser-side TOFU pinning (`host_pin.rs`, from the hardening pass)
  remains as defense in depth, but is no longer the *authoritative* check
  once the agent performs the handshake itself — the agent's own pin
  store is.

The agent stays a pure cryptographic participant for this: it does not
need to connect to the daemon itself to enforce authenticated host
identity, since it learns the fingerprint from the handshake bytes the
browser relays to it either way.

This reframes Track B's contract. It is not:

> The agent returns the session key after completing the handshake.

It is:

> The agent releases the completed viewer message and ephemeral session
> material only after the authenticated host identity satisfies the
> agent's native trust policy.

That sentence is the one this whole design pass exists to make true, and
every endpoint shape below is written to enforce it.

## Two independent signing contexts (recap, from the hardening pass)

| Context | Shape | Where the signature is used |
|---|---|---|
| `/auth/*` HTTP ceremony (`challenge_transcript`, `consent_action_transcript`, `revoke_operator_transcript`) | Stateless: one request, one structured input, one signature | `POST /auth/verify`, consent-decision bodies, `POST /operator/revoke` |
| Sealed-channel handshake (`ViewerHandshake`/`ViewerHandshakeHighSec`) | Stateful: a 3-message protocol; the viewer's signature transcript embeds bytes the daemon supplies mid-handshake (`hello_bytes`, `kem_ct`, host nonce) | The channel's own key establishment |

These get two different delegation shapes below — Track A doesn't need any
pending state in the agent; Track B does.

## Confirmation policy (risk-based, not per-signature)

Confirming every signature would make the agent unusable; confirming none
of them reduces it to "trust Origin + token," which is the status quo this
whole effort is trying to improve on. Split by risk:

**No per-request confirmation required:**
- a routine `/auth` challenge;
- an ordinary consent approve/deny through an already-unlocked agent
  session against an already-pinned host;
- a sealed-channel reconnection to an already-pinned host.

**Mandatory native confirmation:**
- first trust of a daemon fingerprint (TOFU moment);
- a changed daemon identity, or any pin-replacement operation;
- operator enrollment;
- operator revocation;
- role or capability elevation;
- recovery-key or trust-root changes;
- any unusually durable or unusually broad consent grant.

The confirmation screen is generated **from the agent's own parsed typed
fields** — never from browser-supplied descriptive text, which a
compromised browser could word however it likes. The agent shows what it
actually parsed and is about to sign.

**Headless / noninteractive operation:** privileged actions (the mandatory
list above) fail closed with no native UI available, unless an explicit
administrative policy has been configured to permit noninteractive signing
for that specific class of action. There is no silent fallback to
"confirm in the browser instead" — that would just reintroduce the
oracle problem the native confirmation exists to close.

## Track A: stateless `/auth` signing (small, low-risk, do first)

Versioned, explicitly typed endpoints:

```
POST /v1/sign/challenge
POST /v1/sign/consent-action
POST /v1/sign/revoke
POST /v1/sign/enroll-operator     (later)
```

**Revision (PR "4.5b"):** the first implementation of this section gave
every request a bare `daemon_fingerprint_hex` field the *caller* named
directly. Building Step 5 (the browser wiring below) surfaced that this is
unverifiable: the agent had no way to check the fingerprint actually
corresponded to anything, so a compromised browser could label any
request with an already-trusted fingerprint regardless of what it was
actually asking to be signed — undermining the confirmation policy above,
since "already pinned → skip confirmation" then meant nothing. Fixed by
replacing the bare fingerprint with daemon-signed *evidence* the agent
verifies itself and computes the fingerprint from — see
`xenia_operator_proto::DaemonIdentityCertificate`'s doc comment and
`apps/xenia-operator-agent/src/daemon_evidence.rs` for the full design.
The summary: the daemon's *host identity* (the same one the sealed channel
already uses, and the one thing `host_pin.rs`/`host_trust.rs` already know
how to pin) signs a delegation certificate vouching for its separate
HTTP-auth signing key, plus a per-nonce attestation on `/auth/challenge`
and — implicitly, via that delegation — the session tokens it issues. The
browser now *relays* this evidence; it never tells the agent which daemon
to trust.

Every request carries:
- schema version;
- the target daemon's host-identity delegation certificate
  (`daemon_certificate`, fetched by the caller from that daemon's
  `GET /auth/daemon-identity` and relayed verbatim — the agent verifies
  both of its signatures and computes the fingerprint itself before
  checking it against trust policy, never trusting a caller-named
  fingerprint);
- the operator identity/key fingerprint the caller believes it's acting
  as;
- a protocol-specific request id;
- a nonce;
- action-specific typed fields (exactly the fields
  `challenge_transcript`/`consent_action_transcript`/
  `revoke_operator_transcript` need — nothing else — plus, per action, the
  daemon-signed evidence that binds those fields to a real daemon: a host
  attestation over the nonce for `/v1/sign/challenge`, or the full signed
  session token, verified against the certificate's delegated key, for
  `/v1/sign/consent-action`/`/v1/sign/revoke`);
- freshness/expiry information where the underlying protocol has it.

Agent processing, in order:
1. Authenticate the local caller (Origin + `X-Agent-Token`, unchanged from
   the hardening pass).
2. Validate Origin and request size.
3. Parse the exact typed request (reject anything that doesn't match one
   of the known shapes — no partial/duck-typed acceptance).
4. Verify `daemon_certificate`'s own signatures, compute the fingerprint
   from it, and check *that* fingerprint against native trust policy.
5. Verify the action's daemon-signed evidence (challenge attestation or
   session token) against the now-trusted certificate.
6. Enforce freshness and field limits.
7. Construct the canonical transcript itself, through
   `xenia_operator_proto`'s existing `challenge_transcript`/
   `consent_action_transcript`/`revoke_operator_transcript` functions.
8. Apply the confirmation policy above.
9. Sign with both required algorithms (Ed25519 + ML-DSA — no
   classical-only fallback, matching the rest of this project's hybrid
   posture).
10. Return a typed signature envelope.

**There is no endpoint that accepts:** arbitrary bytes, arbitrary
transcript strings, caller-supplied domain separators, or a
caller-supplied hash without the typed fields it's supposed to be a hash
of. If a future action needs a new shape, it gets a new typed endpoint,
not a generic one.

`operator_session.rs`'s `authenticate()`, `build_consent_request()`,
`build_revoke_request()` become thin wrappers over these three endpoints.
`OperatorIdentity` no longer needs `ed_seed`/`ml_seed` for any of them.

**Residual risk, stated plainly:** an XSS bug active *during an
authenticated operator session*, against an *already-trusted, already-
confirmed* host, can still trigger a no-confirmation-required action (an
ordinary Approve/Deny) the operator never actually clicked. This is not a
regression — that same XSS bug can already do this today via the browser's
own local signing code — but it's also not eliminated by Track A alone.
Closing it fully would mean confirming every signature, which the
confirmation-policy section above deliberately rejects as unworkable UX.
The floor this design settles on: forgery is bounded to low-risk actions
against hosts the operator has already, at some point, explicitly trusted.

## Track B: agent-driven sealed-channel handshake (the bigger piece)

```
POST /v1/handshake/begin
  in:  { suite, intended_host_alias_or_pin_scope, client_protocol_metadata }
  out: { handshake_id, viewer_response_bytes, expires_at, suite_metadata }

POST /v1/handshake/finish
  in:  { handshake_id, host_finalize_bytes }
  out: { viewer_final_bytes?, aead_key, rekey_root, transcript_hash,
         authenticated_host_fingerprint, suite_metadata }
```

Sequence:

```
browser                          agent                          daemon
  │  ── open WS ────────────────────────────────────────────────▶ │
  │  ◀──────────────────────────────────────── HostHello ──────── │
  │  ── POST /v1/handshake/begin(HostHello) ──▶ │                  │
  │                                    ViewerHandshake::begin()    │
  │  ◀── viewer_response_bytes, handshake_id ── │                  │
  │  ── ViewerResponse ──────────────────────────────────────────▶ │
  │  ◀──────────────────────────────────── HostFinalize ────────── │
  │  ── POST /v1/handshake/finish(id, HostFinalize) ──▶ │           │
  │                       ViewerHandshake::finish()                │
  │                       -> authenticated host fingerprint         │
  │                       -> native trust-policy check (§ above)    │
  │                       -> only on pass: consume + zeroize state, │
  │                          return session material                │
  │  ◀── aead_key, rekey_root, transcript_hash, host fingerprint ── │
  │  [installs aead_key into its own Session; seals/opens envelopes locally --
  │   this part needs no long-term identity material at all]
```

Agent processing for `/v1/handshake/finish`:
1. Resolve the pending state for `handshake_id`.
2. Complete the `xenia-wire` state machine (`ViewerHandshake::finish` /
   `ViewerHandshakeHighSec::finish`), which yields the authenticated host
   identity fingerprint as a side effect of the signature verification
   already inside that call.
3. Enforce native pinning + confirmation policy against that fingerprint
   (§ above) — **this is the gate; nothing below happens until it passes.**
4. Consume and zeroize the pending state either way (pass or fail) so a
   `handshake_id` is single-use regardless of outcome.
5. On pass: return the final viewer bytes (if the suite needs the browser
   to relay anything further), the ephemeral AEAD key, rekey root,
   transcript hash, and the authenticated fingerprint. On fail: return a
   refusal; **no session material is returned.**

The browser receives no long-term identity material at any point in this
flow.

**Landed.** `send_sealed_consent`/`send_sealed_consent_highsec` in
`sealed_consent.rs` are restructured around this: instead of driving
`ViewerHandshake` locally against `id.seeds()`, they relay
`HostHello`/`HostFinalize` bytes through the agent (via a shared
`drive_agent_handshake` helper, since both suites now differ only in the
`suite` string) and install whatever session material comes back.
`OperatorIdentity::seeds()` — the one remaining caller of the raw seeds —
is deleted; `OperatorIdentity` no longer retains `ed_seed`/`ml_seed` as
struct fields at all (see the "Once both tracks land" note above for the
one raw-seed call site that's still left, for display only).

### Pending-handshake state

- Lifetime: **30 seconds**, measured against monotonic time (not
  wall-clock, which can be adjusted).
- Concurrency caps: **8** pending handshakes per authenticated agent
  session, **32** process-wide.
- Handshake id: at least **128 random bits**.
- Each pending entry is bound to: the authenticated agent session, the
  allowed Origin it was opened from, the requested suite, the intended
  host alias/pin scope, and its creation time — `/finish` must be called
  with the same binding it was opened under.
- State is removed and zeroized on **every** exit path: success, a failed
  `finish` (a bad/forged `HostFinalize` consumes the attempt — no retrying
  attacker-controlled responses against the same pending state), explicit
  cancellation, expiry, or agent shutdown.
- **Response-loss resilience, deferred to a later iteration**: the first
  implementation requires a fresh handshake after any uncertain failure
  (e.g. the browser's HTTP request to `/finish` succeeded but the response
  was lost). A later version could add a short (~5s) completed-result
  cache keyed by agent session + exact request digest, making `finish`
  idempotent for retries without accepting different inputs under the same
  `handshake_id` — not needed for the initial PR.

**Concurrency shape note:** the pending-state map must support more than
one in-flight handshake (multiple browser tabs, a reconnect racing a still-
live attempt) — mirror the multi-peer `HashMap<handshake_id, ..>` shape
already proven in `xenia-handshake`'s `pending_kem`/`pending_decap` maps,
not `HostHandshakeHighSec`'s single-slot `Option<PendingState>` (that type
only ever drives one handshake at a time by construction, correct for a
daemon serving one connection at a time in its accept loop, wrong for an
agent that may have several browser-side attempts open at once).

## Agent network behavior

**The agent never originates the connection to the daemon.** It stays
responsible for: identity custody, transcript construction, signatures,
handshake state, authenticated host verification, host-pin policy, and
returning ephemeral session material. Networking, reconnection, proxying,
and WebSocket framing all stay in the browser. This keeps the agent a
narrow, auditable cryptographic component rather than a second network
client with its own reachability requirements.

## Once both tracks land (done)

- **`GET /seeds` is deleted**, along with the agent's `SeedsResponse`/
  `get_seeds` and the browser's `fetch_seeds`. It was always meant as the
  interim step (see its own former doc comment) -- retired once nothing
  called it, and only once both tracks had fully migrated.
- **`OperatorIdentity` is deleted entirely**, not just emptied of seed
  fields. It turned out there was no need for a thin "call the agent for X"
  handle type in `operator_session.rs` at all: the Sessions-page enrollment
  display now just stores the two `String`s it actually shows
  (`fingerprint_hex`, `enrollment_record_json`) directly in
  `app::OperatorIdentityState::Ready`, fetched in one call via
  `agent_client::fetch_identity_info` from the agent's **pre-existing**
  `GET /identity` route -- that route (public keys + fingerprint + a
  paste-ready enrollment record, built server-side from
  `xenia_operator_proto::OperatorEnrollmentRecord`) had already been added
  during an earlier hardening pass and just wasn't being called from the
  browser yet.
- The zeroize-on-drop work from the hardening pass is moot for the browser
  side now (there's nothing left there to zeroize) but stays exactly as
  valuable on the agent side, where the seeds permanently live.
- `OPERATOR_SECURITY_MODEL.md` §9's "not yet closed" bullet is now closed;
  the residual risk collapses to Track A's stated no-confirmation-action
  window, which is the honest floor for a browser-hosted operator console
  regardless of where keys live (the browser is still where decisions are
  displayed and clicked).

## Recommended PR sequence

1. Shared typed signing request/response types **and** the native
   host-trust interface (can reuse the existing `PinStore` concepts from
   the hardening pass as its starting shape) — the foundation both tracks
   build on.
2. `POST /v1/sign/challenge`.
3. `POST /v1/sign/consent-action`.
4. `POST /v1/sign/revoke`, with the native confirmation policy wired in
   (this is the first endpoint that actually exercises the mandatory-
   confirmation path).
4.5. **Inserted after steps 1-4 shipped:** daemon-signed evidence
   (`DaemonIdentityCertificate`, challenge host attestations, signed
   session tokens) replacing the bare caller-named `daemon_fingerprint_hex`
   those steps originally used — see the revision note under Track A
   above. Landed as two PRs: "4.5a" (daemon + shared-proto evidence,
   additive/backward-compatible) then "4.5b" (agent verifies it,
   supersedes steps 2-4's trust model). Step 5 below was blocked on this
   landing first, since it would otherwise have wired the browser up to
   the same unverifiable-fingerprint gap.
5. Remove those three signing uses from browser-held `OperatorIdentity`.
6. Track B, as its own separately reviewed PR (landed as two: agent-side
   `/v1/handshake/*`, then the browser wiring).
7. **Done.** Delete `GET /seeds` and `OperatorIdentity` now that both tracks
   are fully migrated and nothing calls them; the Sessions-page display
   moves to the agent's already-existing `GET /identity`.

## What does *not* change

- `xenia-wire`'s public API (`ViewerHandshake`, `ViewerHandshakeHighSec`,
  `SessionKeySchedule`, `HostHandshakeHighSec`) — zero changes.
- The daemon side of the sealed channel (`operator_sealed_channel.rs`,
  `establish_operator_channel`, host-side identity/enrollment) — entirely
  unaffected; it never knew or cared whether the viewer role ran in a
  browser or an agent process.
- The Origin/token authentication model on the agent — reused as-is for
  every new endpoint, as the first of several checks each request passes
  through (Origin/token authenticates the *local caller*; the trust-policy
  check described above separately authenticates the *destination host* —
  two different questions, both now answered natively).
