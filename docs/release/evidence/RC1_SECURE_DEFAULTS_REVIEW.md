# RC1 Secure-Defaults Warning Review

This note reviews the secure-default scanner warnings for the RC1 stabilization
stack.

## Decision

The scanner is allowed to suppress warning-only literals when they match a
precise reviewed entry in `xenia.safety.toml`.

Hard findings are not suppressible by this review.

## Reviewed warning classes

- Loopback-only development URLs in `sovereign-admin`.
- Explicit WebSocket transport selection in viewer/transport documentation.
- Loopback WebSocket literals in transport tests.
- Security policy documents that intentionally name forbidden patterns such as
  public bind addresses and consent-bypass phrases.

## Non-goals

This review does not approve:

- public default binds;
- plaintext credentials;
- silent session start;
- consent bypass;
- unattended access;
- fail-open revocation behavior.

Those remain hard or review-required release concerns.
