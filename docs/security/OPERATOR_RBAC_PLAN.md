# Operator Authentication & RBAC — Design Plan

Status: planning. This is the design for closing review finding #17 (no
server-side operator auth/RBAC in the operator console). It is not yet
implemented.

## The one-sentence problem

For a privileged-access / remote-support product, **the security boundary
must be a cryptographically-authenticated operator identity with a role,
enforced by the daemon and recorded in the ledger** — but today the entire
boundary is `127.0.0.1` binding, and every "auth" construct above that is
client-side scaffold.

## Current state (verified)

The real boundaries today are: loopback-only binds (`127.0.0.1:8081` admin,
`127.0.0.1:8082` consent), the M1 consent state machine, the signed
hash-chained ledger, and `0600` key files. Everything identity-shaped is
scaffold:

- **Console auth** is `AuthState { did: Option<String> }` in `localStorage`,
  self-described "no cryptographic verification yet." `is_authenticated()` is
  `did.is_some()`.
- **DID login** (`login.rs`) resolves a DID against a Holochain `did_registry`
  but only proves the DID *exists* — no proof the operator *controls* it
  (no challenge-response).
- **The daemon's `/ws` and consent port have no auth at all.** Any local
  process that connects to `127.0.0.1:8082` and writes `"Approve"` grants the
  session. The `"Approve"`/`"Deny"`/`"Revoke"` frames carry no operator
  identity or signature.
- **Orphaned `api/mod.rs`** contains an `X-Admin-HMAC` + `/challenge`+`/verify`
  route sketch that is never compiled in (not declared as a module,
  placeholder bodies). It's vestigial, but the `/challenge`+`/verify` shape is
  the right intent.
- **Consent transport is single-shot**: the daemon `accept()`s exactly one
  connection on the consent port. The browser `ConsentModal` opens a *fresh*
  socket per button click, so a `Revoke` after an `Approve` never reaches the
  daemon (the daemon-side revocation mechanism is correct; the transport is
  the gap).

## Design principles

1. **The daemon is the enforcement point, not the browser.** The console is a
   convenient signer + UI. Every privileged action is verified server-side
   against operator identity + role, fail-closed. A raw socket with no valid
   operator signature is refused — the loopback bind stops being the boundary.
2. **Reuse existing primitives; add no JWT/OAuth stack.** Operator identity =
   Ed25519 + ML-DSA keys (same hybrid the host identity and handshake already
   use). Audit = the existing `xenia-ledger` hash-chain. This keeps the trust
   model uniform and post-quantum from day one.
3. **Every privileged action is authenticated, authorized, and audited.**
   Authenticated (operator proves key control), authorized (role permits the
   action, least-privilege, fail-closed), audited (a signed ledger entry
   attributes the action to the operator + role). The ledger becomes a real
   operator audit trail — the core artifact a PAM product sells.
4. **Least-privilege tiers, mirroring the consent per-tier model.** The daemon
   already has `M1PermissionSet` (per-tier consent grants). Operator RBAC
   reuses that shape: a role is a set of permitted operator actions.
5. **Self-contained by default; DID-registry as an optional richer backend.**
   A self-hostable sovereign product should not *require* an external
   Holochain conductor to authenticate operators. The MVP is a local
   enrolled-operators policy file (pubkeys + roles, `0600`), mirroring the
   `--known-hosts` / host-identity pattern already shipped. The Holochain
   `did_registry` becomes an optional identity source-of-record for
   deployments that want org-wide operator management.

## Target architecture

```
 operator (browser console or CLI)
   │  1. GET /auth/challenge  → daemon returns a fresh nonce
   │  2. sign(nonce ‖ operator_pubkey ‖ context) with Ed25519 + ML-DSA
   │  3. POST /auth/verify {pubkey, ed_sig, mldsa_sig}
   ▼
 daemon
   ├─ verify both signatures over the nonce (proof of possession)
   ├─ look up pubkey in the operator policy → role (or reject: not enrolled)
   ├─ issue a short-lived session token (signed, role-scoped, expiring)
   └─ append `operator.authenticated {operator_id, role}` to the ledger
       │
 every privileged action (Approve/Deny/Revoke/policy-change) then carries:
   token + a per-action signature over (action ‖ session_id ‖ nonce)
   ▼
 daemon: verify token not expired → check role permits action (fail-closed)
         → perform → append `operator.<action> {operator_id, role, target}`
         to the ledger
```

## Roles (initial proposal — to confirm)

| Role | Can | Cannot |
|---|---|---|
| **Viewer** | see device/session inventory, read the audit ledger | approve, inject, change policy |
| **Approver** | Viewer + Approve/Deny/Revoke a consent ceremony | change policy, enroll operators |
| **Operator** | Approver + initiate sessions, file/clipboard where the session's consent tier allows | enroll operators, change trust policy |
| **Admin** | Operator + enroll/revoke operators, change trust policy, rotate keys | (root of trust) |

This maps cleanly onto the existing per-tier consent model: an Approver
authorizes a ceremony; the *session's* `M1PermissionSet` still bounds what the
viewer can then do. Two independent gates (operator-role AND session-consent),
both fail-closed.

## Implementation phases

**Phase 0 — Threat model + decisions (doc only).** Write the operator threat
model (local low-priv process, stolen operator key, replay, privilege
escalation, remote operator). Lock the decisions listed below. No code.

**Phase 1 — Operator enrollment + identity (`xenia-peer-core` or a new
`operator` module).** An `operators.toml`-style policy file: for each operator,
an Ed25519 + ML-DSA public key and a role. `0600`, loaded at startup. A pure,
unit-testable `authorize(action, role) -> bool` (mirrors `evaluate_offer`).
This is the self-contained MVP identity source.

**Phase 2 — Challenge/response auth endpoint (resurrect `api/mod.rs`
properly).** Real `/auth/challenge` (daemon-issued nonce, short TTL, one-time)
+ `/auth/verify` (verify Ed25519 **and** ML-DSA over the nonce, no
classical-only fallback — matching the handshake). On success, issue a
signed, role-scoped, expiring session token. Wire as a real axum module
(delete the orphaned sketch). Unit-test the verify + token logic.

**Phase 3 — Enforce on privileged actions.** Replace the plain-text,
single-shot, unauthenticated consent socket with an authenticated control
channel: every Approve/Deny/Revoke carries the token + a per-action signature;
the daemon verifies token+role before honoring, fail-closed. This also fixes
the single-`accept()` / socket-per-click transport bug so browser-console
revocation works end to end.

**Phase 4 — Operator-action audit in the ledger.** Add operator-action event
kinds to `xenia-ledger` (extend `ConsentKind`, or a parallel `OperatorAction`
kind — the `source_id` slot is already documented as "DID-bound operator
identifier"). Every authenticated privileged action appends a signed entry
attributing it to the operator + role. Negative tests for tampered/reordered
operator events.

**Phase 5 — Console integration.** Replace `AuthState`'s bare `Option<String>`
with the real flow: challenge → sign (the browser already has
`ed25519-dalek`; add ML-DSA) → token with expiry + role. Gate pages on the
*role*, not just "authenticated." Add the MFA step the login TODO already
names (TOTP/WebAuthn) as a second factor before signing.

**Phase 6 — Hardening & remote operators (later).** Rate-limit auth attempts
and privileged actions. Only after the above holds, allow operator access
beyond loopback (the enforcement no longer depends on the bind). Session
recording integrity for full PAM audit.

## Decisions needed before Phase 1

1. **Operator identity source for the MVP:** local enrolled-operators policy
   file (recommended — self-contained, no conductor dependency, matches the
   host-identity/known-hosts pattern) vs. require the Holochain `did_registry`
   (richer org management, but a hard external dependency). Can support both,
   but which is the *default* / MVP?
2. **Role set:** confirm/adjust the Viewer/Approver/Operator/Admin table above.
3. **Token vs. per-action signing:** session token with expiry (less friction)
   *plus* a per-action signature (stronger audit), or one or the other? (Recommend
   both: token gates the session, per-action signature makes each ledger entry
   independently attributable.)
4. **Remote operators now or later:** MVP loopback-only-but-authenticated
   (auth is real, exposure stays local) vs. design the remote path in from the
   start. (Recommend loopback-first — get enforcement right before widening
   exposure.)
5. **MFA in the MVP or Phase 5+:** the login TODO cites NIS2 Art. 21(j). Is a
   second factor required for the first cut, or is single-factor key-proof
   acceptable for MVP?

## What makes this genuinely better (not just "add a login")

- **The boundary moves from network location to cryptographic identity** —
  the thing that distinguishes a real PAM product from "a screen-share app on
  localhost."
- **Post-quantum operator auth from day one** (ML-DSA co-signature), matching
  Xenia's handshake posture — most PAM products are classical-only.
- **The audit trail is the product.** Because every privileged action is a
  signed, hash-chained, role-attributed ledger entry with a PQ export path,
  "who approved/revoked/changed-what, when, under what role" is
  tamper-evident and third-party-verifiable offline — which is exactly the
  compliance artifact (NIS2, SOC2, etc.) buyers need.
- **Two independent fail-closed gates** (operator-role AND session-consent),
  reusing the per-tier `M1PermissionSet` pattern already shipped — defense in
  depth, not a single approval.
- **No new trust infrastructure** — it composes the Ed25519/ML-DSA identities
  and the signed ledger the system already has, so there's one trust model to
  reason about, not a bolted-on JWT/OAuth layer.
