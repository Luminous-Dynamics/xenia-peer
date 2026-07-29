# Review + amendments: Xenia Improvement and Expansion Plan

**Status:** Review of the proposed expansion plan, with four amendments and a
scoping recommendation.
**Companion to:** `XENIA_COMPREHENSIVE_REVIEW_2026-07-28.md` (the audit whose
findings this review draws on).

---

## Verdict

**The plan is sound and its sequencing is right.** In particular the closing
strategic rule —

> Do not generalize code merely because two systems look similar. Generalize
> only the security invariants that two working applications have
> independently proven they share.

— is the correct discipline, and the recommendation to begin with the security
constitution, capability matrix, and adversarial state machine is the right
opening move. Nothing below disputes the shape of the plan.

What follows is (1) four amendments, each grounded in something the 2026-07-28
audit and the work that followed it actually established, not in taste; (2) a
correction of two premises that are less greenfield than the plan assumes; and
(3) an honest note on scale.

---

## Amendment 1 — The invariant catalogue is missing availability

**The plan's eight invariants are all authority-and-integrity invariants.**
Availability appears exactly once, in invariant 5 ("Revocation overrides
availability"), where it is deliberately *traded away*. That trade is correct
for revocation. But nothing in the catalogue protects availability anywhere
else, and the catalogue is explicitly the thing every later phase is checked
against.

**This is the precise blind spot the audit already found once.** Before
2026-07-28 `docs/security/` contained **zero** occurrences of "denial of
service", "availability", or "timeout" across all 14 files, and availability
was not listed as an accepted non-goal either — it had simply never been asked
about. The consequence (F1) was that a single idle TCP socket permanently
denied every session: `accept_transport`'s listener was a local that dropped
after the first accept, and the handshake had no deadline. Cost to the
attacker: one open socket.

For a remote-*support* tool this is not a lesser property. An operator locked
out during an incident has lost the thing the product exists to provide.

### Proposed invariant 9

> **9. Availability of the authorization path is itself a security property.**
>
> An unauthenticated party must not be able to prevent an authorized operator
> from obtaining a session. Every pre-authentication read carries a deadline;
> a peer that stalls or fails is dropped in favour of the next; pre-auth
> resource commitment stays proportionate to the handshake being attempted;
> and rate limits are partitioned by source, so the limiter cannot itself
> become the denial-of-service mechanism.

`THREAT_MODEL.md` gained an Availability section on 2026-07-28 stating exactly
this. The amendment is to **promote it into the constitution**, so it is
checked with the same rigour as the authority invariants rather than living in
a separate document that the invariant catalogue does not reference.

Note this interacts with invariant 5 and the plan should say so: revocation
overriding availability is a *deliberate, scoped* exception, not a general
licence to fail closed in ways an unauthenticated party can trigger.

---

## Amendment 2 — Add an invariant for the project's own verification signals

Invariant 6 is the best idea in the plan:

> Evidence cannot claim more than enforcement proved.

It is stated for *product* evidence. **The same failure mode has now bitten the
project's own development evidence three times, and the entire assurance
programme in Part VI rests on signals that demonstrably can lie.**

Three instances, all from this audit arc:

| False green | What it appeared to prove | What it actually proved |
|---|---|---|
| CI green on `main` | the repo builds | jobs restored a warm `~/.cargo/git` cache; a cold-cache job failed in 6s. **Proven** by re-running an *unchanged* workflow: run `30361403270`, commit `ec7ce79`, `success` at 12:59 → `failure` at 20:23 |
| `cargo check` "passing" in 1.34s | the edited dependency compiles | cargo used the *pinned* checkout, not the edited clone. It compiled nothing under test |
| An empirical runner completing | the experiment ran | (recorded in project memory) the LLM backend was absent, every prompt silently fell back to simulation, and the runner printed plausible numbers instead of aborting |

These are the same defect class as invariant 6, one level up: **a signal that
asserts more than it verified.**

### Proposed invariant 10

> **10. A verification signal must not claim more than it exercised.**
>
> A passing check must be traceable to the artifact it claims to verify.
> Verification that silently substitutes a cached, stale, mocked, or
> fallback path fails closed and loudly, rather than reporting success. Any
> check whose scope is narrower than its name must say so.

Concretely, for this repo: a cold-cache build job; a check that a compile
actually rebuilt the dependency under test (an implausible duration against a
known baseline is the tell); and the fail-closed-on-backend-fallback rule
already recorded in project memory.

**Why this belongs in the constitution rather than the CI backlog:** Part VI
proposes fuzzing, property testing, fault injection, and cross-version
compatibility testing. Every one of those is a signal. If signals can silently
degrade to "passed because it didn't run", the assurance programme produces
confidence without evidence — which is the exact thing the plan exists to
prevent in the product.

---

## Amendment 3 — Add an invariant against split sources of truth

A single defect class recurred **three times in one day**, in three unrelated
subsystems:

1. **Advertised vs. decodable formats.** scap's Linux engine advertised
   `RGB, RGBA, RGBx, BGRx` to PipeWire while its callback handled
   `RGB, RGBx, xBGR, BGRx`. `RGBA` was offered but undecodable; `xBGR` was
   decodable but never offered. Two hand-maintained lists, silently disagreeing
   in both directions, for ~12 months. (Pre-existing upstream; fixed downstream
   in `68ab39b` by making the advertisement *derive from* the dispatch list,
   with a test proving the guard fires.)
2. **Cargo pin vs. Nix hash.** `Cargo.toml`'s `rev` and `flake.nix`'s two
   `outputHashes` entries independently describe the same dependency. A rev
   bump invalidates the hashes, and only the `nix` job notices — after the
   fact. **This recurred within minutes**, when a concurrent session bumped the
   rev and left the hashes stale.
3. **README claims vs. branch content.** After publication, scap's `main` was
   upstream-identical while the fixes lived only on a branch — so the repo's
   own README described fixes that a fresh clone did not contain.

In every case the fix was the same shape: **make one of the two the derived
one.**

### Proposed invariant 11

> **11. One fact, one source of truth.**
>
> Where two artifacts must agree — advertised vs. handled capabilities,
> declared vs. enforced permissions, a dependency pinned in two build systems,
> documentation vs. the thing it documents — one must be derived from the
> other, or a check must assert their equality. Two hand-maintained lists of
> the same fact will drift, and the drift will be silent.

This is directly load-bearing for the plan's own §3 and §12: a capability
matrix that is *documented* in one place and *enforced* in another is precisely
this pattern at the centre of the security model.

---

## Amendment 4 — Insert a Phase 0 before the assurance programme

Part VI (§18) proposes a substantial adversarial assurance programme. It
presumes CI that means something. **Today it does not, in a specific and
measurable way:**

- **No CI job enables `scap-backend`.** Zero occurrences across every
  workflow; the flake explicitly notes it "isn't enabled here" and pins an
  outputHash only so the git dependency *resolves*. Xenia's **primary** capture
  backend per ADR-0001 therefore has **no compile coverage on any platform**.
- The consequences are not hypothetical. The Linux engine break was found by
  hand; the Windows break (`Frame::timespan()` → `timestamp()`, fixed
  2026-07-29 in `0ff8e89c`) was found by hand while cross-compiling, and its
  own commit message notes that path "had apparently never been compiled
  before."

### Proposed Phase 0 (before §18, and arguably before §2)

1. A `scap-backend` compile job, so the primary capture backend is mechanically
   built.
2. At least one **cold-cache** job, so warm-cache masking cannot recur.
3. A dual-pin guard asserting `flake.nix`'s `outputHashes` match the rev locked
   in `Cargo.lock` (amendment 3, applied).

This is small — days, not months — and everything in Parts I and VI inherits
its trustworthiness from it.

---

## Corrections to two premises

Both are cases where the plan is more of an *extension* of existing work than
it assumes, which is good news for sequencing.

### §3's capability matrix is a migration, not a greenfield design

Xenia already has a real, direction-split capability model —
`M1Permission` / `M1PermissionSet` in `crates/xenia-peer-core/src/m1_session.rs`
— with **6 capabilities**:

`StreamFrame`, `InjectInput`, `ReadHostClipboard`, `WriteHostClipboard`,
`SendFileToViewer`, `ReceiveFileFromViewer`

The existing design already embodies the plan's philosophy, with the reasoning
written down in the source: clipboard and file transfer are split *by
direction* specifically so that "a grant scoped to 'receive files' must not
silently also permit sending host files."

So §3 should be framed as extending 6 → ~17, not designing from nothing. That
matters for estimation and for preserving the existing rationale.

**One real gap found while checking this, which strengthens §3's priority.**
`m1_consent_scope()` describes telemetry level (up to `system`: hostname and OS
version) and audio mode (up to real host microphone capture) to the operator in
the consent prompt — but there is **no `M1Permission` variant for either**.
Both ride `allow_frame_flow()`, i.e. the `StreamFrame` permission. A viewer
authorized to see the screen is therefore, by construction, also authorized to
receive whatever telemetry and audio the host was configured to emit, with no
capability boundary between them.

This is exactly the plan's own success criterion — *"consent accurately
communicates the real capability envelope"* — failing today, and it is a
concrete first target for §3 rather than a hypothetical.

### §4's state machine is an extension of 7 existing states

`M1SessionState` already has `Idle`, `Offered`, `Active`, `Denied`, `Revoked`,
`Ended`, `Failed`. The plan proposes 14. Again: extension, not greenfield, and
the existing transitions have test coverage worth preserving rather than
replacing.

---

## On scale, honestly

The plan is roughly 20 sections spanning constitution, capability model, state
machine, revocation, identity recovery, consent UX, evidence model, privacy,
formal authority grants, standards alignment, a second reference application,
framework extraction, a published specification, an assurance programme, and
operational maturity.

That is **years of work at the current staffing**, on a codebase that is
honestly self-described as pre-alpha with no users. Presenting it as a single
plan risks the failure mode it warns against — expanding before the base is
proven.

**Recommended actual next scope**, in order, all of which fit inside Part I:

1. **Phase 0** (amendment 4) — days. Everything downstream depends on it.
2. **`XENIA_SECURITY_INVARIANTS.md`** with the 8 proposed invariants plus
   amendments 1–3 (11 total), each mapped to enforcement location and tests.
   This is the artifact most likely to expose whether existing features share
   one coherent authority model — which is the plan's own stated reason for
   doing it first, and I agree.
3. **Capability matrix**, starting from the existing 6 and closing the
   telemetry/audio gap above.
4. **State machine hardening**, extending the existing 7 states, with the
   property tests §4 lists.

Stop there and re-evaluate. `BoundedAuthorityGrant`, Xenia Agent, framework
extraction, and the specification should not begin until 1–4 are done, exactly
as the plan's own strategic rule implies.

### One item that cannot be closed by code review

**§7's consent redesign is a human-factors problem.** Whether a consent dialog
"accurately communicates the real capability envelope" cannot be established by
reading the code or by an agent — it requires real users, including users who
are not the author. The plan should mark it as requiring human validation, in
the same way this project already treats the singing-voice work's listening
check as the one decisive step an agent cannot perform. Otherwise it will get
marked done on the strength of a code review, which is precisely how consent
dark patterns survive.

---

## Summary of proposed changes

| # | Change | Grounded in |
|---|---|---|
| A1 | Add invariant 9: availability of the authorization path | F1 — one idle socket denied all service; threat model had zero availability coverage |
| A2 | Add invariant 10: a verification signal must not claim more than it exercised | three false greens, incl. an unchanged CI run going success → failure |
| A3 | Add invariant 11: one fact, one source of truth | three drift instances in one day, one recurring within minutes |
| A4 | Insert Phase 0 before the assurance programme | `scap-backend` has no CI compile coverage on any platform |
| C1 | Reframe §3 as 6 → ~17 migration; fix the telemetry/audio enforcement gap first | `M1Permission` already exists and is direction-split |
| C2 | Reframe §4 as extending 7 existing states | `M1SessionState` already exists with tests |
| C3 | Scope the immediate work to Phase 0 + invariants + capabilities + state machine | plan is years at current staffing |
| C4 | Mark §7 as requiring human validation | consent quality is not code-reviewable |

Everything else in the plan I would adopt as written.
