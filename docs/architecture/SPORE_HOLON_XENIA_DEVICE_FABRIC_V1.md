# Spore / Holon / Hearth / Xenia Device Fabric — V1 Boundary

Status: proposed

## Decision

Cross-device Spore must reuse the existing Luminous Dynamics concepts instead of
creating a second device/social identity stack.

The V1 ownership model is:

```text
Spore
  portable personal runtime / experience projection
        |
        v
Holon
  persistent identity of one computing embodiment
        |
        +------ Mycelix Hearth
        |       durable household / kinship / autonomy / visibility context
        |
        v
Xenia
  authenticated transport + session-generation + consent/capability authority
```

### Spore

Spore owns experience semantics: Worlds, semantic surfaces, projection state,
portable user/runtime state, and host adapters such as Plasma/COSMIC/mobile.

Spore may *request* a remote function. It must not infer remote authority from
device discovery or from its own local policy state.

### Holon

A Holon is the persistent identity of a computing embodiment, independent of
one motherboard/disk. That identity already belongs to the higher-level
Nixward/Spore identity layer.

Xenia must not mint a parallel Holon identifier. Xenia contracts may bind an
opaque cryptographic commitment to a Holon identity.

### Hearth

Mycelix Hearth owns durable household/social semantics: membership, roles,
autonomy, visibility, care, presence, rhythms, and other relationship state.

Hearth membership is not a Xenia device capability and MUST NOT be broadcast as
ordinary device discovery metadata.

A later policy integration may provide Xenia a narrowly scoped,
privacy-preserving policy decision/commitment derived from Hearth. Xenia should
not replicate the Hearth graph or accept a caller-authored "same hearth"
boolean as authority.

### Xenia

Xenia owns the security boundary between Holons:

- authenticated peer/session establishment;
- exact handshake/session generation;
- transport binding;
- consent and revocation;
- replay protection;
- scoped application capabilities;
- deadline/expiry enforcement;
- authenticated evidence for consequential remote actions.

A device capability advertisement answers only:

> What functions could this Holon potentially expose?

It does **not** answer:

> May this peer use them?

That second question requires a later authenticated, consent-bound Xenia
authority object.

## V1 capability-discovery contract

`xenia-peer-core::device_capabilities::DeviceCapabilityAdvertisementV1`
contains:

- schema version;
- opaque 32-byte Holon identity commitment;
- coarse device class;
- descriptive capability-profile epoch;
- canonical set of potential device functions.

The advertisement has a hand-written domain-separated BLAKE3 commitment so
later request/authority profiles can bind the exact discovery subject without
depending on serde/bincode encoding.

The contract intentionally carries no:

- Hearth membership or relationship data;
- owner identity;
- consent state;
- authentication claim;
- network endpoint;
- session key;
- authorization token;
- trusted time;
- application payload.

## Intended evolution

The next contract should introduce a non-authoritative request intent:

```text
exact advertisement digest
+ exact requested subset
+ request id
+ workload/application commitment
+ canonical purpose/presentation commitment
+ requested lifetime
```

That request still grants nothing.

Only after the current Xenia authenticated-generation and durable-consent
lineages are qualified should a later integration consume the request and mint
an opaque session-bound grant:

```text
Holon capability advertisement
        +
Spore request intent
        +
authenticated Xenia session generation
        +
exact transport profile
        +
consent / Hearth-derived policy evidence where applicable
        +
deadline
        ↓
AuthenticatedDeviceCapabilityGrant
```

The grant must be unusable outside the exact authenticated generation that
created it.

## Why this boundary

This keeps four different facts separate:

1. **Identity** — which Holon is this?
2. **Relationship/policy context** — what durable Hearth/social rules apply?
3. **Discovery** — what can this device potentially do?
4. **Authority** — what may this exact authenticated peer do right now?

Collapsing any of these into a single "trusted device" boolean would recreate
ambient authority and make cross-device Spore substantially harder to audit.
