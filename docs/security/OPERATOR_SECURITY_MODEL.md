# Operator Security Model

The consolidated reference for how the Xenia daemon secures its **operator
surface** — the privileged control plane an operator uses to authenticate,
approve/deny/revoke consent, and administer other operators. It ties together
the pieces that landed across `OPERATOR_RBAC_PLAN.md` (auth + roles),
`SEALED_OPERATOR_CHANNEL_DESIGN.md` (the sealed channel), and the revocation +
observability work, and states the threat model: what is defended, and what is
explicitly out of scope.

> Companion docs: `OPERATOR_RBAC_PLAN.md` (phased plan + rationale),
> `SEALED_OPERATOR_CHANNEL_DESIGN.md` (the sealed channel slices),
> `PRIVILEGE_BOUNDARIES.md`, `CONSENT_STATE_MACHINE.md`,
> `LEDGER_VERIFICATION_BOUNDARY.md`.

---

## 1. Assets and adversaries

**Assets.** (1) The host's screen/input/session — remote control of a machine.
(2) The consent decision — who may start/approve a session. (3) The audit
ledger — a tamper-evident record of who did what. (4) Operator identities and
their roles.

**Adversaries.** (A) A network attacker on the operator port (typically
internet-adjacent behind a reverse proxy) — can connect, replay, tamper, probe.
(B) A revoked or de-enrolled operator whose key or token may still be valid-looking.
(C) A lower-privilege operator attempting a higher-privilege action. (D) A holder
of a captured token or signature attempting replay.

Out of scope: a compromised daemon host (root on the box); a compromised enrolled
operator's live browser during a valid session; coercion of a legitimate admin.

---

## 2. Identity and enrollment

An operator identity is an **Ed25519 + ML-DSA-65 (FIPS 204) keypair**, derived
from two persisted 32-byte seeds so it is stable across reloads
(`HandshakeManager::from_identity_seeds`; browser side in
`sovereign-admin/src/operator_session.rs`, native in `crates/xenia-handshake`).

Enrollment is **allow-listed and out-of-band**: an admin adds a record
(`operator_id`, `ed25519_pubkey`, `ml_dsa_pubkey`, `role`) to the daemon's
`--operators-file` (`OperatorPolicy`, `apps/xenia-peer/src/operator.rs`). An
unenrolled key authenticates nothing — the policy is the root of trust, and an
empty/unset policy denies all (`OperatorPolicy::default()`).

The keys are bound together by a BLAKE3 **identity fingerprint** over
`ed25519_pk || ml_dsa_pk`, byte-identical on the browser and native sides, so an
admin can eyeball one value when enrolling.

---

## 3. Authentication ceremony (`/auth/*`)

Two additive admin-port routes (`operator_http.rs`), backed by a
deterministically-testable pure core (`operator_auth.rs`):

1. `POST /auth/challenge` → a random, single-use, short-TTL nonce
   (`ChallengeStore`, consumed exactly once, GC'd on expiry).
2. Operator signs the domain-separated `challenge_transcript(nonce, ed_pk,
   ml_pk)` with **both** keys (Ed25519 **and** ML-DSA-65 — AND composition, no
   classical-only fallback).
3. `POST /auth/verify` → the daemon verifies both signatures, consumes the
   challenge, confirms enrollment, and mints a **daemon-signed, role-scoped
   token** (`OperatorToken`: operator_id, role, issued_at, expires_at,
   token_nonce). The token is signed by the daemon's key; the operator cannot
   forge one, and cannot upgrade its own role (the role is copied from the
   policy at mint time).

Fail-closed at every step; auth failures return `401` with only a stable Display
string (no which-step disclosure). The verify route is **rate-limited**
(`RateLimiter`, `AUTH_RATE_MAX`/window) before any expensive signature check, to
bound brute-force/flood.

**Transcript sharing.** All signed transcripts (`challenge_transcript`,
`consent_action_transcript`, `revoke_operator_transcript`) live in the shared
`xenia-operator-proto` crate, so the browser console signs **exactly** the bytes
the daemon verifies — no drift is possible. Each is domain-separated and
length-prefixes its variable fields.

---

## 4. Roles and authorization

`OperatorRole` (Viewer < Approver < Operator < Admin) and `OperatorAction` with a
`min_role()` mapping (`xenia-operator-proto`). Notable gates:

| Action | Min role |
|--------|----------|
| ViewInventory / ReadAudit | Viewer |
| Approve / Deny / Revoke **consent** | Approver |
| InitiateSession | Operator |
| ChangePolicy / **EnrollOperator** (enroll *or revoke* an operator) / RotateKeys | Admin |

Authorization checks the **token's own role**, not the policy's current role for
that id and not any client UI — an honestly-issued lower-role token cannot
perform a higher-role action, and a forged higher-role token fails token
signature verification. Every privileged action additionally carries a
**per-action Ed25519 signature** over a transcript bound to the exact
action/target + the token's `token_nonce`, so a captured signature cannot be
replayed for a different action, session, target, or token
(`authorize_consent_action`, `authorize_operator_revocation`).

---

## 5. Two ways to reach consent: plaintext vs. sealed

The daemon runs **exactly one** consent surface (mutually exclusive):

- **Plaintext consent server** (`consent_server.rs`, default): a WebSocket on
  `--consent-port`. Without `--require-operator-auth` it accepts legacy bare
  `Approve`/`Deny`/`Revoke`; with it, each decision must be a signed,
  role-authorized, token-bearing action.
- **Sealed operator channel** (`operator_sealed_channel.rs`, `--operator-sealed`):
  the consent path wrapped in `xenia-wire` ChaCha20-Poly1305 envelopes over a
  **PQC-hybrid handshake** (ML-KEM-768 + Ed25519 + ML-DSA-65 + HKDF-SHA-256).
  The handshake **is** the operator proof-of-possession: a successful handshake
  from an enrolled key means "this confidential channel belongs to operator X,
  role R". Adds confidentiality + channel authentication on top of the existing
  per-action signatures and ledger attribution.

Enabling `--operator-sealed` **closes the plaintext port** (`main.rs`: sealed
XOR plaintext) — there is no downgrade path where an attacker routes around the
sealed channel to an equally-authoritative plaintext port.

Both surfaces decode through the same `decode_consent_decision` choke point, so
authorization, revocation, per-action non-repudiation, and ledger attribution
are identical regardless of transport.

---

## 6. Revocation — a revoked operator is refused everywhere, live

A compromised operator must be disabled **without a daemon restart** (which would
drop every live session). Revocation is by `operator_id`
(`OperatorRevocations`, `operator_revocations.rs`): a shared, hot-reloadable set
consulted fail-closed on every privileged path.

- **Set it** three ways: (1) add the id to `--revoked-operators-file` and send
  `SIGHUP` (atomic reload, existing sessions untouched); (2) the authenticated
  admin `POST /operator/revoke` endpoint (Admin token + signature over
  `revoke_operator_transcript`); (3) the console's role-gated "Revoke Operator"
  form, which builds and signs that same request.
- **Enforced everywhere**: on the sealed channel it is checked right after the
  handshake authenticates the peer (`OperatorChannelError::Revoked`); on the
  consent-authorization path `decode_consent_decision` refuses a revoked
  operator's still-valid, unexpired, correctly-signed token — so a revoked
  operator is denied on the sealed handshake, the admin endpoint, **and** the
  plaintext consent path, in both modes.
- **Fail-closed**: a poisoned lock reports revoked; a failed revocation-file load
  is fatal (the daemon won't run a privileged surface without the list it was
  told to enforce).

Note (current scope): the `/auth/verify` route can still *mint* a token for a
revoked operator, but that token authorizes nothing (every consumption path
re-checks revocation). Refusing token issuance up front is a hardening follow-up.

---

## 7. Audit and observability

- **Non-repudiable audit**: an authenticated consent decision is attributed in
  the tamper-evident hash-chain ledger (`operator_consent_audit_event`, source_id
  = the operator's enrolled key). `LEDGER_VERIFICATION_BOUNDARY.md` states what
  the chain does and does not prove.
- **Attack-signal telemetry** on the sealed endpoint (`operator_channel_metrics.rs`):
  lifetime counters for connections, handshake failures, **not-enrolled
  rejections**, **revoked rejections**, established channels, and terminal
  decisions. Each rejection emits a structured `tracing::warn!` with a running
  total + peer address, so a log pipeline (journald → SIEM) can alert on a spike
  in probing without scraping a metrics port. A session-summary line is logged
  when the endpoint closes.

---

## 8. What is defended, at a glance

| Threat | Defense |
|--------|---------|
| Unenrolled key connects | Allow-listed `OperatorPolicy`; fail-closed lookup |
| Forged/upgraded token | Daemon-signed token; role copied at mint; signature-verified |
| Replay of a captured action signature | Per-action transcript bound to action/target + token_nonce |
| Replay of a challenge | Single-use, short-TTL, consumed before signature check |
| Lower role attempts higher action | `role.permits(min_role)` on the token's own role |
| Classical-crypto break | Hybrid PQC: **both** Ed25519 and ML-DSA-65 must verify |
| Passive eavesdropping of consent | Sealed channel: ChaCha20-Poly1305 over an ML-KEM handshake |
| Downgrade to plaintext | `--operator-sealed` closes the plaintext port (XOR) |
| Compromised operator key | Live revocation (SIGHUP / endpoint / console), enforced on every path, no restart |
| Brute-force / flood on auth | Rate-limited `/auth/verify` |
| Recon / probing | Not-enrolled + handshake-failure counters + alertable warn logs |
| Tamper with the audit record | Append-only BLAKE3 hash chain, independently verifiable |

## 9. Known limits / follow-ups

- No forward secrecy on the operator channel yet (one AEAD key per session;
  `SessionKeySchedule.rekey` machinery exists but is unwired).
- Operator channel PQC is fixed at ML-DSA-65 / ML-KEM-768; a higher-security
  ML-DSA-87 / ML-KEM-1024 mode is scoped but not built.
- `/auth/verify` still mints tokens for revoked operators (harmless — see §6).
- `bincode` 1.3.3 is used for wire (handshake + envelopes) with a tracked RUSTSEC
  exception; a postcard/wincode migration is pre-RC1 debt.
- End-to-end verification is native (`handshake_cross_compat`, the sealed-channel
  and revoke integration tests); a true headless-browser smoke test is blocked on
  webdriver tooling.
