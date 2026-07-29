# Xenia Security Invariants

**Status:** Partial. This document captures three invariants proposed in
`docs/roadmap/XENIA_EXPANSION_PLAN_REVIEW_2026-07-29.md` (a review of a
separately-drafted "Xenia Improvement and Expansion Plan" whose own
8-invariant catalogue), plus one new invariant this document adds. **The
original plan's invariants 1-8 are deliberately not reproduced here** --
that source document was never committed to this repository (searched git
history, open PRs, and open issues; not found anywhere durable), so its
exact wording isn't available to quote or paraphrase accurately. Rather
than reconstruct it from memory and risk misattributing text, this
document only asserts what is independently grounded in this repo's actual
code and tests. Whoever holds the original plan should either commit it
or fold its invariants 1-8 into this file with real citations, the same
standard applied to 9-12 below.

Each invariant below is stated, then mapped to where it's enforced in
code and which test(s) currently guard it -- per invariant 10's own
requirement, a claim here that isn't backed by a real test/file:line is a
gap to close, not a fact to assert.

---

## Invariant 9 — Availability of the authorization path is itself a security property

> An unauthenticated party must not be able to prevent an authorized
> operator from obtaining a session. Every pre-authentication read
> carries a deadline; a peer that stalls or fails is dropped in favour
> of the next; pre-auth resource commitment stays proportionate to the
> handshake being attempted; and rate limits are partitioned by source,
> so the limiter cannot itself become the denial-of-service mechanism.

**Enforcement**: `apps/xenia-peer/src/main.rs` -- handshake deadline via
`tokio::time::timeout`; `accept_transport()` loop survives a stalled/failed
peer rather than hanging permanently (closes the finding this invariant
was written in response to: a single idle socket used to deny every
subsequent session).

**Tests**: `network-chaos` and `stalled-peer` CI jobs in
`.github/workflows/xenia-validate.yml` exercise this against a real
netns/tc-netem chaos harness and a deliberately-stalled peer,
respectively -- not just unit tests, since this is fundamentally a
liveness property under adversarial network conditions.

Note the interaction with a revocation-availability tradeoff elsewhere in
the M1 lifecycle: revocation deliberately overrides availability (a
revoked session must not keep flowing just because dropping it would be
"unavailable" to that viewer) -- that is a scoped, intentional exception
to this invariant, not a violation of it.

---

## Invariant 10 — A verification signal must not claim more than it exercised

> A passing check must be traceable to the artifact it claims to verify.
> Verification that silently substitutes a cached, stale, mocked, or
> fallback path fails closed and loudly, rather than reporting success.
> Any check whose scope is narrower than its name must say so.

**Why this belongs in the constitution, not just the CI backlog**: it's
the same defect class as invariant 6 (product evidence) one level up
(process evidence), and it has independently recurred at least three
times in this project's own history:

1. CI green on `main` that was actually a warm-cache artifact -- the
   identical workflow run went `success` -> `failure` on an unchanged
   commit when the cache was cold.
2. A `cargo check` reporting "passing" in ~1s when it had in fact
   resolved the *pinned* git checkout of an edited dependency, not the
   edited clone -- it verified nothing about the change under test.
3. (Recorded in project memory, not this repo) an empirical experiment
   runner that silently fell back to a simulated backend when the real
   one was absent, and printed plausible-looking results instead of
   aborting.

**Enforcement in this repo**: none yet, beyond discipline applied
case-by-case in individual sessions (e.g. this document's own author
verified the Windows `xenia-inject` backend by actually executing its
test binary under Wine rather than trusting a cross-compile `cargo
check` alone, and explicitly flagged the macOS backend's weaker
verification tier -- `cargo check --target x86_64-apple-darwin` only,
no SDK available to build/run for real -- rather than presenting both as
equally proven). There is no automated guard yet that would catch a
future instance of pattern (1) or (2) above.

**Concrete, cheap starting points** (not yet implemented): a cold-cache
CI job (no `actions/cache` restore) run periodically to catch pattern
(1); a check that an edited path-dependency's compile duration is
implausible against a known baseline (a near-instant "recompile" after a
real source edit is the tell for pattern (2), the same signal that
caught it originally).

---

## Invariant 11 — One fact, one source of truth

> Where two artifacts must agree -- advertised vs. handled capabilities,
> declared vs. enforced permissions, a dependency pinned in two build
> systems, documentation vs. the thing it documents -- one must be
> derived from the other, or a check must assert their equality. Two
> hand-maintained lists of the same fact will drift, and the drift will
> be silent.

**Enforcement + a fourth real instance, found and fixed the same day
this document was written**: `crates/xenia-inject/src/lib.rs`'s
`evdev_button_code()` is now the single canonical Linux evdev
button-code mapping, called by both the `uinput` backend
(`lib.rs::uinput_button_code`) and the `xdg-portal` backend
(`xdg_portal.rs::evdev_button`), which previously each had their own
hand-written version. They disagreed: `xdg_portal::evdev_button`'s
formula-based implementation (`BTN_MIDDLE + n - 1`) mapped button id 3
to `BTN_EXTRA` (0x114) instead of `BTN_SIDE` (0x113), silently
disagreeing with `uinput`'s explicit match for the identical button id.
Two backends meant different things by "aux button 3" since whichever
was written second -- structurally the same failure mode as the three
instances the review that proposed this invariant already documented
(advertised-vs-handled capture formats, Cargo pin vs. Nix
`outputHashes`, README claims vs. branch content), just in a fourth
subsystem. Found by writing a test for the formula, not by inspection.

**Test**: `crates/xenia-inject/src/xdg_portal.rs`'s
`evdev_button_aux_buttons_saturate_at_extra` and
`crates/xenia-inject/src/lib.rs`'s
`uinput_button_code_matches_xdg_portal_convention` -- though per this
invariant's own point, the *real* guard is structural (both call the
same function now, so they can't drift again), not the tests, which
mainly document the agreed behavior.

---

## Invariant 12 — A consent grant authorizes exactly the tiers it names, never a superset (new, this document)

> If the operator's consent prompt describes N independently-scoped
> capabilities, there must be N independently-checked permission gates
> enforcing them -- never M < N gates where multiple described
> capabilities silently ride on one shared check. A capability described
> to the operator but not separately gated is a capability the operator
> did not actually consent to in isolation, regardless of what the
> prompt text says.

**Why this is its own invariant, not a restatement of 11**: invariant 11
is about two *independently-maintained descriptions of the same fact*
drifting apart. This is about a description and its *enforcement*
drifting apart in a specific, security-relevant direction -- the prompt
promises more granularity than the code actually checks. It is a
special case worth naming on its own because the failure mode is a
*silent over-grant*, not a crash or a mismatch two engineers would
notice from a stack trace.

**The gap this closes**: `crates/xenia-peer-core/src/m1_session.rs`'s
`M1Permission`/`M1PermissionSet` previously had six tiers (`StreamFrame`,
`InjectInput`, `ReadHostClipboard`, `WriteHostClipboard`,
`SendFileToViewer`, `ReceiveFileFromViewer`). `apps/xenia-peer/src/
main.rs`'s `m1_consent_scope()` correctly *described* two more
capabilities to the operator at consent time -- telemetry (up to
`TelemetryLevel::System`: hostname and OS version) and audio (up to
`AudioMode::Capture`: real host microphone) -- but neither had a
matching `M1Permission` variant. Both actually rode on
`M1Permission::StreamFrame` alone (`main.rs` called
`m1_runtime.allow_frame_flow()` before sending either a telemetry or an
audio frame). A viewer whose only granted tier was "view the screen"
was, by construction, also receiving whatever telemetry and audio the
daemon operator had configured on the command line -- with no way for
the *consent-granting* operator to authorize screen viewing without
those two, since no separate tier existed to grant or withhold.

**Fix**: added `M1Permission::StreamTelemetry` / `StreamAudio` and
matching `M1PermissionSet` fields, `M1SessionMachine::stream_telemetry()`
/ `stream_audio()` (each independently gated via the existing
`require_active(permission)` mechanism, following the exact shape every
other tier already uses), and `M1RuntimeService::allow_telemetry_flow()`
/ `allow_audio_flow()`. `main.rs`'s `configured_permission_set()` now
derives `stream_telemetry`/`stream_audio` from the same
`--telemetry-level`/`--audio` flags `m1_consent_scope()` already reads
to build the operator-facing description -- so the description and the
grant are now sourced from the same two flags (also satisfies invariant
11 for this specific pair), rather than the description being freeform
text and the grant being a separate, incomplete boolean set.

**Tests**: `crates/xenia-peer-core/src/m1_session.rs`'s
`stream_frame_grant_does_not_authorize_telemetry_or_audio` (the exact
regression this invariant exists to prevent: a screen-view-only grant no
longer implicitly authorizes either) and
`telemetry_and_audio_grant_does_not_authorize_stream_frame` (the
converse -- these three tiers are independent, not a hierarchy where one
implies another).

**What this does not close**: whether `m1_consent_scope()`'s *text*
accurately and legibly communicates the real capability envelope to a
human operator is a human-factors question, not a code-enforceable one
-- flagged by the same expansion-plan review (its own §7 discussion) as
requiring real user validation, not a code review. This invariant only
guarantees the enforcement now matches whatever the description
*claims*; it says nothing about whether the description itself is good.

---

## Open items

- Invariants 1-8 from the original plan: not reproduced here, source
  text unavailable. Recover or re-draft with real citations before
  treating this document as the complete constitution.
- Invariant 10: no automated guard yet, only case-by-case discipline.
  The cold-cache CI job and compile-duration-sanity-check starting
  points above are unimplemented.
- Invariant 12 exposed a general pattern worth auditing for elsewhere:
  any place a `*_consent_scope`-style description function and a
  `configured_permission_set`-style grant function both exist should be
  checked for the same drift. This document only checked M1; it did not
  audit whether an analogous split exists in, e.g., the operator-agent's
  own consent/audit surface.
