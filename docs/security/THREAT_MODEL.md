# Xenia Threat Model

Xenia is a remote-session stack. Until the pre-production gates pass, treat it
as a research and prototype system, not a production remote-access tool.

## Assets

- Operator identity and signing keys.
- Session keys and handshake transcript binding.
- Consent decisions, consent revocations, and the append-only ledger.
- Captured video/audio/telemetry frames.
- Input events sent from viewer to host.
- Admin policy and governance decisions.

## Trust boundaries

```text
viewer UI <-> transport <-> peer daemon <-> capture/input backends <-> host OS
                         \
                          -> admin API / sovereign-admin / ledger
```

`xenia-wire` protects sealed payloads once a session key exists. It does not by
itself solve endpoint trust, user intent, OS-level compromise, browser compromise,
or social engineering.

## Primary adversaries

| Adversary | Goal | Required controls |
|---|---|---|
| Passive network observer | Read screen/input data. | AEAD, key rotation, no plaintext fallback, no debug dumps. |
| Active network attacker | Replay, reorder, or inject sealed envelopes. | Nonce discipline, epoch handling, replay window, transcript-bound handshake. |
| Malicious viewer | Obtain access without meaningful consent or continue after revocation. | Consent ceremony, revocation enforcement, ledger evidence, bounded session lifetime. |
| Malicious host/daemon | Misrepresent what happened in a session. | Append-only signed ledger, external verification, admin audit export. |
| Local low-privilege process | Steal operator keys, consent ledger, or captured frames. | Restricted file modes, key storage plan, no world-readable session files. |
| Compromised admin browser | Abuse policy/admin surface. | Least-privilege admin API, CSRF/CORS posture, short-lived auth tokens, audit logging. |
| Confused deputy | Trick a user into approving the wrong session. | Human-readable session fingerprint, device identity, purpose string, fresh nonce. |
| Dependency compromise | Backdoor capture, codec, crypto, transport, or WASM build. | Lockfile review, cargo-deny/cargo-audit, minimal features, reproducible builds. |
| Unauthenticated peer denying service | Prevent the operator from obtaining a session when they need one. | Bounded handshake deadline, recovery from a stalled peer, bounded pre-auth allocation, partitioned rate limits. |

## Availability

Added 2026-07-28. Until then this model had no availability dimension at all —
confidentiality and integrity were covered thoroughly, availability was never
asked about, and so nothing in the codebase answered for it. That gap was the
common cause behind several concrete defects (see
`docs/roadmap/XENIA_COMPREHENSIVE_REVIEW_2026-07-28.md`, findings F1/F3/F6).

**The asset is the operator's ability to obtain a session when they need one.**
For a remote-*support* tool this is not a lesser property than confidentiality:
an operator locked out during an incident has lost the thing the product exists
to provide.

**In scope for pre-alpha.** The adversary is any unauthenticated party who can
reach a listening port, and the standing requirements are:

- **No unauthenticated peer may occupy a session slot indefinitely.** Every
  pre-authentication read carries a deadline, and a peer that stalls or fails
  the handshake is dropped in favour of the next one. A daemon that dies, hangs,
  or must be restarted by hand in response to one idle socket is a defect.
- **Pre-authentication resource commitment stays proportionate.** An
  unauthenticated peer must not be able to make the daemon allocate far more
  than the handshake it claims to be performing actually requires.
- **A flood must not lock out a legitimate operator.** Rate limits protect
  against brute force, so they must be partitioned by source rather than shared
  as one global budget — otherwise the limiter becomes the denial-of-service
  mechanism instead of the defence against it.

**Explicitly still out of scope for pre-alpha** (deferred, not solved):
network-layer volumetric flooding, resource exhaustion by an *authenticated*
operator, and multi-session concurrency — the daemon deliberately serves one
session at a time, which is a product decision, not an availability defect, so
long as it recovers from peers that never complete a session.

## Non-goals for pre-alpha

- Protection against a fully compromised host OS.
- Guaranteeing legal/compliance sufficiency of consent records.
- Internet-scale identity resolution without the Mycelix identity layer.
- Fully hardened unattended remote administration.

## Minimum production blockers

1. No placeholder handshake path in production builds.
2. Consent approval and revocation must gate frame/input flow in runtime code, not
   just docs or UI.
3. Operator keys must have explicit storage/rotation rules.
4. Admin API must have authentication, authorization, and audit logging.
5. Capture/injection backends must be feature-gated and documented per platform.
6. Independent protocol/security review must be completed before any production
   wording appears in README or marketing material.
