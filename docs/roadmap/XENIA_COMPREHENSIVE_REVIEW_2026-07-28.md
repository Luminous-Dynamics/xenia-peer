# Xenia comprehensive review + improvement plan (2026-07-28)

Independent audit of `xenia-peer` at `ec7ce79` (main). Written by reading and
verifying the code directly rather than accepting the existing docs' claims —
where a claim was checked, this file says so; where it wasn't, it says that too.

**Headline:** this is the healthiest codebase in the Luminous-Dynamics
constellation by a wide margin. Engineering discipline is genuinely high and
the docs are unusually honest. The gaps that remain are **not** correctness or
code-quality gaps — they are a single missing *dimension* in the threat model
(**availability**), and a handful of consequences that follow from it.

Scope note: this pass audited `xenia-peer`. `xenia-wire` (the separate protocol
repo) was checked only for version/drift consistency, not reviewed as a
protocol. That remains open — see §5.

---

## 1. What the audit verified (not taken on faith)

| Property | Measured | Comparison |
|---|---|---|
| `todo!()` / `unimplemented!()` | **0** | symthaea: widespread |
| `#[ignore]` tests | **0** | symthaea: ~2,000 |
| `// placeholder` files | **0** | symtropy: 57 |
| `TODO`/`FIXME`/`HACK` comments | **2** — both in `sovereign-admin`, both labelled scaffold with a named milestone | — |
| Tests | **595**, sensibly distributed across 17 crates | — |
| CI on `main` | **5 workflows, all green** (checked live, 2026-07-28) | symtropy: red since 2026-06-21 |
| `unwrap()`/`expect()` outside test modules | concentrated in test/smoke binaries; **~2 in real library code** | — |
| `unsafe` | 6 files, every block carrying a real `SAFETY:` rationale; workspace-wide `unsafe_code = "deny"`, FFI crates opting out explicitly and documenting why | — |
| Dependency provenance | `xenia-wire` local source **matches** published `0.2.0-alpha.9`; the only drift is a dev-only `bench-internals` feature | mycelix-bridge-common: drifted |

Supply chain has both `cargo-deny` and `cargo-vet` configured with an explicit
license allowlist. Only one non-crates.io dependency exists.

### Security design that holds up under inspection

These were checked against the code, not the design docs:

- **Hybrid signatures are AND-composed with no classical fallback.** Both
  Ed25519 *and* ML-DSA-65 must verify, at the handshake, at operator auth, and
  at token verification.
- **Hybrid downgrade is explicitly blocked.** `verify_challenge_response` uses
  `policy.lookup_verified` (the *pair*), not a bare Ed25519 lookup. The code
  comment names the exact attack this prevents — an attacker holding only the
  enrolled Ed25519 secret pairing it with a self-generated ML-DSA key.
- **Challenges are consumed before signature verification**, so a replayed
  nonce cannot be retried. Single-use, TTL-bounded, GC'd.
- **Revocation is enforced on every privileged path**, not just at token
  issuance — verified all 5 production call sites (token issuance, revoke,
  replace-key, audit endpoints, sealed channel) plus the consent action in
  `main.rs`. A stateless 15-minute token does *not* outlive its operator's
  revocation. This was my leading hypothesis for a finding and it is **refuted**.
- **Constant-time comparison** for pairing tokens and session MACs, with a
  DudeCT statistical constant-time benchmark upstream in `xenia-wire`.
- **`unsafe impl Send for HevcDecoder` is sound** — it is `Send`, not `Sync`,
  and the ownership-transfer-only justification matches the single-owner usage.

The README's own framing ("don't read *working, exercised end-to-end* as
*audited* or *production-ready*") is accurate and should be preserved.

---

## 2. Findings

Ordered by severity. Every finding was verified against code, not inferred.

### F1 — Pre-authentication denial of service: one idle socket bricks the daemon (High, latent-remote) — **FIXED 2026-07-28, verified**

> **Status: fixed and verified by experiment**, in the same change that added
> `THREAT_MODEL.md` §Availability. See "Verified fix" at the end of this
> finding. The description below is retained as the record of the defect.
>
> **One correction to the original write-up, found by actually running it.**
> This finding first said a stalled peer leaves the daemon "occupied". The
> real behaviour is worse: in `accept_transport`, the `TcpListener` is a
> *local* that drops when the function returns, so the listening socket is
> **closed after the first accept**. A second client does not queue behind
> the stalled one — it gets `ECONNREFUSED` (observed directly; see below).
> The daemon serves exactly one connection *attempt* per process lifetime.
>
> That also means a *benign* premature disconnect was enough to end the
> daemon's usable life, not just a malicious one — which independently
> corroborates the note in `scripts/xenia-network-chaos-smoke.sh`'s comments
> about "a TCP-connect probe that crashed the single-session daemon."

**The daemon accepts exactly one connection, ever, and the handshake has no timeout.**

Verified chain:
1. `accept_transport()` is called once (`main.rs:1979`), in linear flow — **not**
   inside a loop. The three `loop`s in the daemon are all downstream (background
   task, recv loop, send loop).
2. Every transport path accepts a single connection: `listener.accept()`,
   `QuicTransport::accept_one`, `WsTransport::bind_and_accept_one`.
3. `perform_host_handshake_with_transcript_and_context()` (`main.rs:2002`) is
   awaited with **no timeout**.
4. It bottoms out in `read_envelope()` (`transport.rs:108`) → `read_exact()`
   with **no read deadline**. It blocks forever.

So: connect, send nothing, never disconnect. The 250 ms WS-probe peek times out
and classifies the socket as TCP; the daemon sends its advertisement, waits 3 s
for a QUIC upgrade, falls through to TCP, and then blocks permanently awaiting
the viewer's handshake response. No legitimate viewer can ever be served. The
daemon does not recover; it must be killed.

Cost to the attacker: one idle TCP socket.

**Severity is currently bounded by `--listen` defaulting to `127.0.0.1:8080`**
(local attacker only). It is rated High-latent rather than High because the
entire purpose of the product is remote support — operators *will* bind
non-loopback, and at that moment this becomes a remote, unauthenticated,
trivially-exploitable permanent DoS.

Related asymmetry, same root: `operator_exposure::is_loopback_bind` guards
`--operator-bind` with an explicit non-loopback warning (`main.rs:1598`), but
is **never applied to `args.listen`**. The session port has no equivalent guard.

**Verified fix.** A/B'd with a single binary, using
`--handshake-timeout-secs 86400` to reproduce the pre-fix daemon exactly
(effectively no deadline) against the shipped default:

| Arm | Stalled peer attached | Real viewer result |
|---|---|---|
| Deadline 86400 s (= pre-fix) | yes | **denied** — `ECONNREFUSED`, daemon stuck in "Starting host-side handshake" |
| Deadline 5 s (= fixed) | yes, *still attached* | **8/8 frames verified**, session completed |

The fix is two things, and the regression test asserts both because either
alone is insufficient: a deadline (`--handshake-timeout-secs`, default 30) and
an accept-retry loop. A deadline *without* the retry would only convert a
silent hang into an exit — still a denial of service an attacker triggers at
will. Guarded by `scripts/xenia-stalled-peer-smoke.sh`, wired into
`xenia-validate.yml` as the `stalled-peer` job on every push/PR. It asserts a
real viewer completes a real verified session *while the stalled peer is still
connected*, rather than merely grepping for a timeout log line.

### F2 — The threat model has no availability dimension at all (Medium — root cause of F1)

`grep -i 'denial of service\|dos\|availability\|slowloris\|timeout'` across all
14 files in `docs/security/` returns **zero matches**.

This is not an accepted risk. `THREAT_MODEL.md`'s "Non-goals for pre-alpha"
lists three items (compromised host OS, legal sufficiency of consent records,
internet-scale identity resolution) — availability is not among them. It is
simply absent from the model.

The confidentiality and integrity story is thorough and genuinely well-reasoned.
Availability was never asked about, so nothing in the codebase answers for it.
F1, F3 and F6 are all downstream of this single gap. **Fix F2 and the others
become findable by the project's own process rather than by an external pass.**

### F3 — Operator auth rate limiter is a single global budget (Medium)

`operator_http.rs:66` holds one process-wide `Mutex<RateLimiter>`, checked at
`:245` for `POST /auth/verify`, at `AUTH_RATE_MAX = 30` per 60 s.

Two consequences:
- **Lockout DoS.** The budget is shared across all operators. Any party who can
  reach the operator port can burn 30 attempts and lock out every legitimate
  operator for the remainder of the window — including during an incident, which
  is exactly when operator access matters. There is no per-source or
  per-operator-key partition, and no separate budget for
  authenticated-successful vs. failed attempts.
- **Fixed-window burst.** The window resets wholesale, so ~2× `max` is
  admissible across a window boundary. Minor next to the lockout.

The same pattern was ported verbatim into `xenia-operator-agent` (PR #100), so
the fix should be made in both. Note the agent binds loopback and has exactly
one legitimate caller, so it is far less exposed — the daemon is the real
concern.

### F4 — The largest attacker-controlled parsing surface is unfuzzed (Medium)

`fuzz/fuzz_targets/` contains two targets: `fuzz_agent_request` and
`fuzz_evidence_verify`. Neither covers the wire path.

`xenia-peer-core` performs ~15 `bincode::deserialize` calls on
network-controlled bytes across `frame.rs`, `session.rs`, `handshake.rs` and
`advertisement.rs` — including `handshake.rs:717`, which parses a **pre-
authentication** `HostHello`. None of it is fuzzed here. (`xenia-wire` fuzzes
its own handshake/rekey; the *application* framing layer is the gap.)

This compounds with `deny.toml`'s ignore of **RUSTSEC-2025-0141** for
`bincode 1.3.3`, whose own stated reason is "migrate to postcard, bitcode,
wincode, or a stable Xenia wire codec **before RC1**." That deadline is a real
commitment recorded in the repo, and the untrusted-input decoder it applies to
is the least-tested surface in the project.

Mitigating: `MAX_ENVELOPE_BYTES` (16 MiB) bounds every read across all three
transports, and serde's cautious `Vec` allocation blunts the classic
length-prefix amplification. The exposure is real but not unbounded.

### F5 — `scap` is a **private** git dependency: the public repo cannot be built by the public, and CI's green history was a cache artifact (**High** — upgraded 2026-07-28)

> **This finding was originally filed as Low-Medium ("pinned to a branch, not a
> rev"). That was the small version of the problem.** The real issue was found
> only when a new CI job with a *cold* cargo cache tried to fetch the
> dependency for the first time. Recorded here as an upgrade rather than a
> rewrite, because the mis-severity is itself the lesson: the audit was run on
> a machine that *had* credentials, so an anonymous-access failure was
> invisible to it.

`gh api repos/Luminous-Dynamics/scap` reports **`"private": true`**.
`crates/xenia-capture/Cargo.toml` depends on it over git. Cargo must resolve
git sources during dependency resolution **even when the feature is off**
(`scap` is `optional = true`, and the jobs that fail do not enable it), so:

```
Updating git repository `https://github.com/Luminous-Dynamics/scap`
error: failed to get `scap` as a dependency of package `xenia-capture`
  failed to authenticate when downloading repository
```

**Consequence 1 — the README's quick start is not executable by the public.**
`git clone && cargo test --workspace` fails for anyone without access to that
private fork. For a public, AGPL/Apache-licensed repo inviting third-party
clients, that is a correctness problem in the contribution story, not just CI
hygiene.

**Consequence 2 — CI green was partly an artifact of warm caches.** Jobs that
restore a `~/.cargo/git` cache never re-clone, so they pass; a job with a fresh
cache key fails in seconds. Proven directly rather than inferred: **the exact
same `main` workflow run (`30361403270`, commit `ec7ce79`) that concluded
`success` at 12:59 was re-run unchanged at 20:23 and concluded `failure`**, with
the identical `scap` authentication error. No code changed between the two.
Every currently-green job is therefore one cache eviction (7 days idle, or the
10 GB cap) away from the same failure.

**Fix options**, in the order this review recommends them:

1. **Make the fork public.** It is a fork of an MIT/Apache upstream, and it
   exists to carry the unbounded-`mpsc`-channel memory-leak fix that
   `ROADMAP.md`'s B2 follow-up already describes pushing to it. Nothing about
   it appears to warrant privacy; the roadmap text reads as though it were
   already a normal public fork. Restores public buildability and fixes all
   five failing jobs.
2. **Vendor the patch** — drop the fork and carry the `sync_channel(2)` fix as
   a local patch over upstream `scap`. Removes the private dependency
   altogether, at the cost of maintaining the patch.
3. **Give CI a deploy key/PAT** — fixes CI only. The public still cannot build
   the repo, so the README stays wrong. Not recommended alone.

The original branch-vs-rev point still stands and should be fixed alongside
whichever option is taken: pin `rev =` so the lockfile's guarantee is
structural rather than incidental.

### F5b — the original finding: pinned to a git *branch*, not a revision (Low-Medium)

`crates/xenia-capture/Cargo.toml:34`:
```toml
scap = { git = "https://github.com/Luminous-Dynamics/scap", branch = "fix/linux-engine-two-level-frame-enum", optional = true }
```
`Cargo.lock` currently pins `58b6a62d`, so today's builds are reproducible — but
any `cargo update` silently moves to whatever the branch tip is then, with no
review. It is the project's own fork, which lowers but does not eliminate the
risk (it is also the one dependency carrying a locally-authored patch, per the
B2 memory-leak fix). `deny.toml` already allowlists the URL; pinning `rev =`
costs nothing and makes the lockfile's guarantee structural rather than
incidental.

### F6 — Eager allocation from an attacker-controlled length prefix (Low)

`transport.rs:120`: `let mut buf = vec![0u8; len as usize];` allocates the full
declared length *before* reading the body, so 4 attacker-chosen bytes buy a
16 MiB allocation. Bounded by `MAX_ENVELOPE_BYTES` and unamplifiable given
single-session accept — so genuinely Low today. Worth noting that 16 MiB is a
very generous ceiling for a handshake message whose real contents are a few KB
(ML-DSA-65 pk = 1,952 B, ML-KEM-768 pk = 1,184 B); a per-phase cap would cost
little.

### F7 — The privileged input-injection crate is the least-tested (Low)

`xenia-inject` writes synthetic input into the operator's host via raw `uinput`
ioctls (`unsafe`), and has **5 tests** — tied for the lowest in the workspace.
The blast radius (typing into a real desktop session) is inverted relative to
its coverage. `ROADMAP.md` is candid that a full live round trip was
deliberately never run because it would move the operator's real cursor; that
was the right call, and it is precisely why more *offline* coverage of the
encoding/denormalization logic is worth having.

### F8 — A 6.9 GB VM image sits untracked and un-ignored in the working tree (Housekeeping, but sharp)

`xenia-test-vm-gnome.qcow2` (6.9 GB) is untracked and **not** matched by
`.gitignore` — confirmed via `git check-ignore`. It appears in every
`git status`.

`CLAUDE.md` documents repeated real incidents of `git add -A` sweeping
unintended files across 16 concurrent sessions in this monorepo. This file is
one such command away from a catastrophic commit. Cost to fix: one `.gitignore`
line.

---

## 3. Improvement plan

Sequenced so each phase closes the *cause* of the next, not just its symptoms.

### Phase 1 — Availability, as a first-class property (closes F1, F2, F3, F6)

The ordering matters: write the model first, then the code follows from it.

1. **Add an availability section to `THREAT_MODEL.md`.** Name the adversary
   (unauthenticated party who can reach a listening port), the asset (operator's
   ability to obtain a session when they need one), and decide explicitly what
   is in scope for pre-alpha vs. deliberately deferred. If pre-alpha genuinely
   accepts single-session DoS, that belongs in "Non-goals" *in writing* — which
   is a legitimate outcome of this phase, not a failure of it.
2. **Add a handshake deadline.** Wrap `perform_host_handshake_*` in
   `tokio::time::timeout`, and add an idle-read deadline in `read_envelope`.
   A stalled peer must be dropped, not waited on forever.
3. **Re-accept after a failed or timed-out handshake.** Turn the single
   `accept_transport()` into a loop that serves one session at a time but
   *survives* a peer that never completes one. This is the actual fix for F1;
   the timeout alone only converts a permanent hang into a recoverable one.
4. **Apply `is_loopback_bind` to `--listen`,** matching the warning already in
   place for `--operator-bind`.
5. **Partition the rate limiter** by source (and/or per enrolled operator key),
   so a flood cannot lock out a legitimate operator. Consider a sliding window.
   Apply to both daemon and agent.
6. **Tighten the pre-auth envelope cap** to a handshake-phase-specific ceiling
   well under 16 MiB.

Acceptance: a regression test that opens a socket, sends nothing, and asserts a
*second* client still completes a full session. That test is the deliverable —
it encodes the property, not just the patch.

### Phase 2 — Fuzz the wire path, then honour the RC1 codec commitment (closes F4)

7. **Add fuzz targets for `xenia-peer-core`'s decode surface** — at minimum
   `RawFrame`/`RawInput`/`RawCapabilities`, `advertisement`, and the pre-auth
   `HandshakeMessage`. Wire them into the existing fuzz CI that already runs for
   `xenia-wire`, with a persisted corpus (that repo already solved corpus
   persistence — reuse the approach).
8. **Then** decide `bincode` 1.3.3's fate against the RC1 deadline the repo set
   itself. Fuzzing first is deliberate: it gives a differential oracle for the
   migration rather than a blind swap of the format that carries every frame.

### Phase 3 — Coverage where blast radius is highest (closes F7)

9. Raise `xenia-inject` coverage on the pure logic that does not need a
   compositor: keycode mapping, `[0,1]` denormalization boundaries, touch/abs
   axis encoding, and rejection of out-of-range input. No live-desktop test
   required — that constraint is real and should stay respected.

### Phase 0 — Unblock the build (closes F5) — **now the highest priority**

0. **Resolve the private `scap` dependency** (see F5 for the three options;
   making the fork public is recommended). This outranks everything else in
   this plan: until it is fixed, the public cannot build the repo at all, five
   CI jobs fail, and every currently-green job is one cache eviction from
   failing. It also blocks any PR from going green on its own merits.

### Phase 4 — Hygiene (closes F5b, F8)

10. `.gitignore` the qcow2 (or move test VM images out of the tree entirely).
    **Do this first — it is one line and removes a live hazard.**
11. Pin `scap` by `rev =` alongside the branch (F5b), whichever F5 option is taken.
12. Consider a small `xenia-viewer-android` test lane; it is the one workspace
    member with no automated coverage at all, and it was just verified by hand
    on real hardware — a good moment to capture that as a regression.

### Deliberately *not* recommended

- **Re-verifying the docs.** ROADMAP/README accuracy was spot-checked and holds
  up. Effort is better spent on §3 than on another documentation pass.
- **Chasing the GNOME-Wayland capture blocker.** Three rounds of VM debugging
  correctly concluded it is an environmental virglrenderer/Mesa mismatch, not a
  code defect. It needs a real GNOME operator, not more config guesses.
- **Broad refactoring.** There is no structural debt here worth paying down.

---

## 4. Suggested order

`F8` (one line) → **Phase 0** (F5 — nothing else can go green until it lands) →
**Phase 1** (the real work, now done) → Phase 2 → Phases 3–4.

Phase 1 is the only phase that changes the project's security posture rather
than its coverage. Everything else is worth doing and none of it is urgent.

---

## 5. Verification debt (stated explicitly)

- **No `cargo test` / `cargo clippy` was run for this review.** Host load was
  56+ on 12 cores with 16 concurrent sessions; a workspace build would have been
  antisocial and slow. Test/CI health is asserted from the **live GitHub Actions
  status on `main` (all 5 workflows green, 2026-07-28)**, not from a local run.
- **F1 was verified by code reading, not by running the attack.** The call chain
  (single accept → no timeout → `read_exact` with no deadline) was traced
  explicitly at every step and each link confirmed at file:line, but no live
  daemon was stalled to demonstrate it. Doing so is cheap and is the natural
  first step of Phase 1 step 2.
- **`xenia-wire` was not reviewed as a protocol** — only checked for version
  drift against its published `0.2.0-alpha.9`. An independent protocol review
  remains open, and `ROADMAP.md` already flags it as waiting on the wire format
  stabilising past draft-03.
- **Findings are from targeted hypothesis-driven probing, not exhaustive
  coverage.** Three hypotheses were tested and *refuted* (revocation latency,
  unbounded allocation, secret-comparison timing leaks); the eight above
  survived. A different set of hypotheses would likely surface different
  findings.
