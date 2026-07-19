# Daemon-attested consent offers

Status: implemented by the consent architecture hardening series.

## Purpose

Consent must authorize the capabilities the daemon will actually unlock, not a
browser-written description of them. The browser remains a transport and
presentation surface; it is not an authority for session identity, scope, or
lifetime.

The canonical flow is:

```text
daemon configuration
  -> ConsentScopeV1
  -> ConsentOfferV1(session, scope, issued_at, approval_expires_at)
  -> host Ed25519 + ML-DSA-65 attestation
  -> browser relay
  -> native-agent verification + risk policy + operator signature
  -> daemon verification against its own stored offer digest
```

## Canonical scope

`ConsentScopeV1` explicitly records every capability represented by the current
M1 grant:

- display streaming;
- telemetry level;
- audio mode;
- remote input injection;
- clipboard direction;
- file-transfer direction.

Its canonical bytes use stable numeric tags and a domain separator. Serde
variant names, whitespace, localization, and human-facing wording are not part
of the signed encoding. Display and audit text are generated from the typed
scope rather than parsed back into authority.

## Offer attestation

`ConsentOfferV1` commits to:

- a 128-bit session identifier;
- the digest of the complete canonical scope;
- issuance time;
- approval-window expiry.

The daemon's pinned host identity signs the offer with both Ed25519 and
ML-DSA-65. `AttestedConsentOfferV1` carries the offer and both signatures. The
native agent verifies the daemon identity certificate and both offer signatures
before it considers signing an operator action.

The browser may relay or display the envelope, but changing any field causes
agent verification to fail. Replaying an old genuine offer to the agent is also
insufficient: the daemon verifies the operator signature against the digest of
its own current session offer.

## Operator action binding

The operator signs:

```text
CONSENT_ACTION_DOMAIN
|| action_tag
|| token_nonce
|| offer_digest
```

The token nonce binds the decision to the current daemon-issued operator token.
The offer digest transitively binds session, full scope, and approval lifetime.
Both operator Ed25519 and ML-DSA-65 signatures are required and AND-verified.

## Time semantics

Expiry closes only the window for a new `Approve`. It does not disable `Revoke`
for a grant that is already live. The agent accepts a small bounded clock skew
between daemon and operator workstations, but malformed intervals and offers
issued too far in the future fail closed.

## Native confirmation policy

A routine short-lived screen-stream approval may be signed without an extra
per-action prompt after the host has already passed native TOFU/pinning. A
separate native confirmation is required before approving any scope containing:

- remote input injection;
- clipboard access in either direction;
- file transfer in either direction;
- host-device audio capture;
- system-identity telemetry.

Deny and revoke remain fail-safe operations and do not require the broad-grant
prompt.

## Security boundary and non-claims

This protocol proves that the operator signature commits to the daemon-authored
offer and that the agent classified the same typed scope. It does not prove the
browser rendered a particular sentence or that a routine approval click came
from a human rather than active browser compromise.

A compromised browser in an already-authenticated agent session can still ask
the agent to perform a no-extra-confirmation action against an already-pinned
host. It cannot silently broaden the offer, substitute another session, extend
the approval lifetime, or bypass native confirmation for a scope the agent
classifies as broad.

## Compatibility rule

Changes to canonical scope fields or tags require a new scope domain/version.
Changes to offer canonical bytes require a new offer domain/version. Changes to
the action transcript require a new action domain/version. Breaking agent API
shape changes require a `xenia-operator-agent-proto::SCHEMA_VERSION` bump.
