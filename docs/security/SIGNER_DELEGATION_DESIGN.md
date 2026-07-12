# Design: agent-side signing delegation (retiring `GET /seeds`)

**Status:** design pass (no code). Follow-up to `apps/xenia-operator-agent`
(PR #65) and its hardening pass (PR #66) — see
`OPERATOR_SECURITY_MODEL.md` §9 for the gap this closes: the agent moved the
operator's Ed25519/ML-DSA seeds out of browser `localStorage`, but the
console still fetches them into memory and signs locally with them, for
both the `/auth/*` ceremony and the sealed-channel handshake. This doc plans
having the agent sign directly, so raw key material never reaches the
browser process at all, not even transiently.

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
identity.

This means: **no `xenia-wire` API changes, no published-crate redesign, no
migration-compatibility problem.** The existing `ViewerHandshake::begin`/
`::finish` and `ViewerHandshakeHighSec::begin`/`::finish` are reused
as-is, just called from a different process.

## Two independent signing contexts (recap, from the hardening pass)

| Context | Shape | Where the signature is used |
|---|---|---|
| `/auth/*` HTTP ceremony (`challenge_transcript`, `consent_action_transcript`, `revoke_operator_transcript`) | Stateless: one request, one structured input, one signature | `POST /auth/verify`, consent-decision bodies, `POST /operator/revoke` |
| Sealed-channel handshake (`ViewerHandshake`/`ViewerHandshakeHighSec`) | Stateful: a 3-message protocol; the viewer's signature transcript embeds bytes the daemon supplies mid-handshake (`hello_bytes`, `kem_ct`, host nonce) | The channel's own key establishment |

These get two different delegation shapes below -- Track A doesn't need any
new state in the agent; Track B does.

## Track A: stateless `/auth` signing (small, low-risk, do first)

Three new agent endpoints, each taking **structured, typed fields** and
building the transcript itself via the already-shared, crypto-free
`xenia_operator_proto` crate (`challenge_transcript`/
`consent_action_transcript`/`revoke_operator_transcript`) -- never a "sign
these arbitrary bytes I'm handing you" endpoint. That distinction is the
whole point: if the agent signed opaque caller-supplied bytes, an XSS bug
in the console could use the agent as a blind signing oracle even without
ever extracting the key. Reconstructing the transcript from typed fields on
the agent side means the agent only ever produces a signature over a
message *shaped like* one of these three well-known ceremonies.

```
POST /sign/challenge          { nonce_hex }
                            -> { ed_pubkey_hex, ml_dsa_pubkey_hex,
                                 ed_signature_hex, ml_dsa_signature_hex }

POST /sign/consent-action     { action, session_id_hex, token_nonce_hex }
                            -> { ed_signature_hex }

POST /sign/revoke             { target_operator_id, token_nonce_hex }
                            -> { ed_signature_hex }
```

Same auth model as today's endpoints (Origin allowlist + `X-Agent-Token`,
both already hardened). `operator_session.rs`'s `authenticate()`,
`build_consent_request()`, `build_revoke_request()` become thin wrappers
that call these instead of signing locally -- `OperatorIdentity` no longer
needs `ed_seed`/`ml_seed` for these three call sites at all.

**Residual risk, stated plainly:** an XSS bug active *during an
authenticated operator session* can still call these endpoints and forge a
decision the operator never made -- Track A closes *persistent key
exfiltration*, not *in-session forgery*. This is not a regression: today,
that same XSS bug can already call the browser's own local signing code to
the same effect. The blast radius doesn't grow; it just stops extending
past the current page session. (A per-signature local confirmation step --
e.g. a desktop notification the operator must click -- would close the
in-session gap too, at the cost of UX friction on every decision; see
*Open questions* below.)

## Track B: agent-driven sealed-channel handshake (the bigger piece)

The agent takes over running `ViewerHandshake`/`ViewerHandshakeHighSec`
end to end. The browser becomes a relay for the raw handshake bytes (which
travel over the WebSocket it already owns to the daemon) plus the final
consumer of a derived session key it never needs the long-term identity
for.

```
POST /handshake/begin   { suite: "standard"|"highsec", host_hello_hex }
                      -> { handshake_id, viewer_response_hex }

POST /handshake/finish  { handshake_id, host_finalize_hex }
                      -> { aead_key_hex, rekey_root_hex, transcript_hash_hex }
```

Sequence:

```
browser                          agent                          daemon
  │  ── open WS ────────────────────────────────────────────────▶ │
  │  ◀──────────────────────────────────────── HostHello ──────── │
  │  ── POST /handshake/begin(HostHello) ──▶ │                     │
  │                                    ViewerHandshake::begin()    │
  │  ◀── viewer_response, handshake_id ───── │                     │
  │  ── ViewerResponse ──────────────────────────────────────────▶ │
  │  ◀──────────────────────────────────── HostFinalize ────────── │
  │  ── POST /handshake/finish(id, HostFinalize) ──▶ │              │
  │                                    ViewerHandshake::finish()   │
  │  ◀── aead_key, rekey_root, transcript_hash ── │                │
  │  [installs aead_key into its own Session; seals/opens envelopes locally --
  │   this part needs no long-term identity material at all]
```

Once a handshake completes (or the browser never calls `/finish`), the
agent's pending state for that `handshake_id` should be dropped -- keyed
exactly like `xenia-handshake`'s own `pending_kem`/`pending_decap` maps
(same pattern proven in the ephemeral-KEM work), with a short expiry (e.g.
30s) so an abandoned handshake (tab closed mid-flow, network drop) doesn't
leak agent memory indefinitely.

`send_sealed_consent`/`send_sealed_consent_highsec` in `sealed_consent.rs`
get restructured around this: instead of driving `ViewerHandshake` locally
against `id.seeds()`, they relay `HostHello`/`HostFinalize` bytes through
the agent and install whatever `SessionKeySchedule` fields come back.
`OperatorIdentity::seeds()` -- the one remaining caller of the raw
seeds -- goes away entirely once this lands.

**Concurrency note:** the agent's pending-handshake map must support more
than one in-flight handshake (e.g. two browser tabs, or a reconnect racing
a still-live attempt) -- mirror the multi-peer `HashMap<handshake_id, ..>`
shape already used elsewhere in this codebase rather than the single-slot
`Option<PendingState>` `HostHandshakeHighSec` itself uses (that type only
ever drives *one* handshake at a time by construction, which was fine for
a daemon serving one connection at a time in its accept loop, but isn't
the right shape for an agent serving a browser that might have several
attempts in flight).

## Once both tracks land

- `GET /seeds` is deleted. It was always meant as the interim step (see its
  own doc comment) -- retire it once nothing calls it.
- `OperatorIdentity` stops holding `ed_seed`/`ml_seed` at all; it becomes a
  thin handle around "call the agent for X," carrying only public
  information (pubkeys, fingerprint) fetched from the unchanged
  `GET /identity`.
- The zeroize-on-drop work from the hardening pass becomes moot for the
  browser side (nothing left to zeroize) but stays exactly as valuable on
  the agent side, where the seeds permanently live.
- `OPERATOR_SECURITY_MODEL.md` §9's "not yet closed" bullet becomes closed;
  the residual risk collapses to Track A's stated in-session-forgery
  window, which is the honest floor for a browser-hosted operator console
  regardless of where keys live (the browser is still where decisions are
  displayed and clicked).

## Open questions (decide before Phase 1)

1. **Per-signature local confirmation for Track A?** Trusting Origin+token
   (today's model) for `/sign/*` keeps UX identical to today but leaves the
   in-session-forgery window open for every action, not just
   high-privilege ones. A middle ground: require confirmation only for
   `Revoke`/`EnrollOperator`-class actions, not `Approve`/`Deny`. Needs a
   product decision, not just an engineering one.
2. **Does the agent need network reach to the daemon for anything beyond
   proxying bytes the browser already relays?** Track B's design keeps the
   agent purely a crypto participant (it never opens its own connection to
   the daemon) -- worth confirming that's the right invariant to hold
   rather than having the agent originate the WebSocket itself, which
   would change the trust/network model (agent would need daemon
   reachability, not just the browser).
3. **Handshake-id lifetime and cap.** 30s expiry is a starting guess;
   should also cap total concurrent pending handshakes per agent process
   (denial-of-service via a script that spams `/handshake/begin` and never
   finishes) -- mirrors the existing rate-limiting instinct already applied
   elsewhere in this codebase (`operator_auth::RateLimiter`).
4. **Track A and Track B rollout order.** Track A is smaller, lower-risk,
   and independently valuable (ships before Track B is done); Track B is
   the one that actually lets `GET /seeds` be deleted. Recommend shipping
   Track A first as its own PR, Track B as a second, separately reviewed
   PR -- consistent with how the rest of this hardening effort was staged.

## What does *not* change

- `xenia-wire`'s public API (`ViewerHandshake`, `ViewerHandshakeHighSec`,
  `SessionKeySchedule`, `HostHandshakeHighSec`) -- zero changes. This is
  the corrected scoping from the earlier (wrong) assumption.
- The daemon side of the sealed channel (`operator_sealed_channel.rs`,
  `establish_operator_channel`, host-side identity/enrollment) -- entirely
  unaffected; it never knew or cared whether the viewer role ran in a
  browser or an agent process.
- The Origin/token authentication model on the agent -- reused as-is for
  the new endpoints.
