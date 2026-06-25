# Xenia Consent and Abuse Cases

Xenia is a remote-session stack. That means safety is not a UI polish feature;
it is a core security property. This document lists abuse cases that must remain
visible while the project is still pre-production.

## Non-negotiable defaults

1. No unattended control by default.
2. Consent must be visible, revocable, and logged.
3. Input injection must be disabled unless the active session authorizes it.
4. View-only mode should be the safest default.
5. WebSocket transport must be treated as development/browser-friendly unless
   wrapped by authenticated transport/session policy.
6. Local operator/session secrets must never be committed.
7. Ledger/audit records must not become a consent substitute; they are evidence,
   not permission.

## Abuse cases to design against

| Abuse case | Required defense |
|---|---|
| Silent remote observation | Host-visible session indicator; explicit grant before capture leaves device. |
| Consent fatigue | Short, human-readable request scope; deny by default; revocation always nearby. |
| Stale approval reuse | Session-bound consent IDs with expiration and replay protection. |
| Input escalation | Separate permission for view, pointer, keyboard, clipboard, file transfer, admin actions. |
| Web UI token leakage | Local-only default bind, no tokens in committed files, short-lived tokens. |
| Malicious relay or transport downgrade | End-to-end sealed frames, transport identity checks, downgrade logging. |
| Coerced support session | Prominent stop control and post-session ledger visible to host. |
| Agent/CI artifact leakage | Hygiene audit blocks `.env`, `operator.key`, ledgers, build output, and archive debris. |
| Supply-chain compromise | `cargo-deny`, pinned Nix shell, release gates, and source-only exports. |

## Permission tiers

| Tier | Meaning | Default |
|---|---|---|
| View | Remote party may receive frames/audio/telemetry. | Off |
| Point | Remote party may send pointer movement/clicks. | Off |
| Type | Remote party may send keyboard input. | Off |
| Clipboard | Remote party may read/write clipboard. | Off |
| File | Remote party may transfer files. | Off |
| Admin | Remote party may perform elevated/admin actions. | Off and time-limited |

Do not collapse these tiers into a single broad approval. A support workflow may
ask for multiple tiers, but the host should understand each one.

## Pre-production claim boundary

Until the gates in `docs/security/PRE_PRODUCTION_GATES.md` are complete, Xenia
should be described as a research/prototype remote-session stack, not as a safe
replacement for enterprise EDR, MDM, RMM, or privileged-access tooling.
