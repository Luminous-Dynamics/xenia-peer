# Xenia authenticated capability negotiation — handshake V2 design

Status: **design candidate / not normative / not implemented**

Tracking: `xenia-peer#148`, `xenia-wire#21`

## Why the current shape is insufficient

The existing handshake can bind an opaque `negotiated_context_hash` into `HostHello`, the hybrid Ed25519 + ML-DSA transcript, and the session key schedule. That is useful only when the caller has already derived the hash correctly.

For capability negotiation this is the wrong phase boundary: when the host sends `HostHello`, the viewer has not yet supplied its offer. A final mutually selected capability set therefore cannot honestly be known yet.

A strict authority profile must not treat any of the following as negotiation evidence:

- `supports_causal_authority: bool`;
- a caller-provided 32-byte context hash;
- a selected set that was not derived from both authenticated offers;
- a capability checked only after the handshake;
- presence of a non-`None` context hash;
- a valid authority-capable handshake from a different session lineage.

## Reuse the existing trust plane, do not create a second one

`xenia-peer-core` already has `NegotiatedSessionContextV4`, which commits transport semantics, pre-session policy, post-handshake availability semantics, crypto/profile schemas, and the selected `RawCapabilities` frame.

Capability negotiation should compose with V4 rather than replace it.

Candidate composition:

```text
base_session_context_hash = NegotiatedSessionContextV4.context_hash()

negotiation_binding_hash = SHA-256(
    "xenia.capability-negotiation-binding.v1\0" ||
    host_offer_hash ||
    viewer_offer_hash ||
    selected_protocol_context_hash
)

session_context_v5_hash = BLAKE3-256(
    "xenia-negotiated-session-context-v5\0" ||
    base_session_context_hash ||
    negotiation_binding_hash
)
```

V5 therefore inherits every V4 commitment while adding the exact authenticated protocol-capability exchange.

The final V5 hash, not the raw selected-set hash, is the session context used by strict authority evidence.

## Canonical offers

`xenia-negotiation` defines the candidate canonical representation.

Each peer offers at most 64 exact capability names. Each name carries 1..=16 exact version byte strings in preference order.

Bounds:

- capability name: 1..=128 bytes;
- version: 1..=32 bytes;
- duplicate capability names: reject;
- duplicate versions inside one offer entry: reject.

Capability-name order is canonicalized lexicographically. Version order is deliberately preserved because it is authenticated preference.

Offer domain:

```text
xenia.capability-offer.v1\0
```

Selection is deterministic and role-explicit:

```text
for each host capability name also offered by viewer:
    select the first host-preferred exact version also offered by viewer
```

No common version means that capability is not selected. Strict policies then require their exact selected versions explicitly.

For causal authority:

```text
name    = xenia.causal-authority
version = draft-04
```

Both peers must offer that exact pair and deterministic selection must choose it.

## Backward-compatible wire ceremony

Do not modify the fields or bincode variant indices of the existing `HostHello`, `ViewerResponse`, or `HostFinalize` variants.

Append new V2 variants for strict negotiated sessions.

Candidate semantic shape:

```text
HostHelloV2
  host identity keys
  host KEM key
  host nonce
  base V4 session-context hash
  canonical host capability-offer bytes

ViewerResponseV2
  viewer identity keys
  KEM ciphertext
  viewer nonce
  canonical viewer capability-offer bytes
  recomputed V5 session-context hash
  Ed25519 signature
  ML-DSA-65 signature

HostFinalizeV2
  recomputed V5 session-context hash
  Ed25519 signature
  ML-DSA-65 signature
```

The exact final Rust types may differ, but these commitments are mandatory.

## Ceremony

### 1. Host prepares its side

The host:

1. constructs the exact V4 session context from live transport/pre-session/availability profiles and `RawCapabilities`;
2. computes the V4 hash;
3. constructs and validates its canonical capability offer;
4. sends `HostHelloV2` containing the V4 hash and canonical host offer.

No final mutual negotiation claim exists yet.

### 2. Viewer validates and selects

The viewer:

1. decodes the host offer under the bounded canonical parser;
2. rejects malformed, duplicate, oversized, or non-canonical offers;
3. combines it with its own canonical offer;
4. deterministically selects mutual exact versions;
5. applies local strict policy (for example, require `xenia.causal-authority/draft-04`);
6. computes `negotiation_binding_hash`;
7. computes `session_context_v5_hash` from the host-supplied V4 hash plus the negotiation binding;
8. signs `ViewerResponseV2`, which commits its own offer and the resulting V5 hash.

A strict viewer that cannot negotiate the required profile must fail **before** it signs a response.

### 3. Host independently recomputes

The host:

1. verifies both viewer signatures;
2. decodes and validates the viewer offer;
3. independently derives deterministic selection from the two offers;
4. applies host strict policy;
5. independently recomputes negotiation binding and V5 hash;
6. rejects any mismatch with the viewer's signed V5 hash;
7. signs `HostFinalizeV2` over the final transcript.

The host must never trust a selected set or V5 hash merely because the viewer supplied it.

### 4. Viewer finalizes

The viewer verifies both host signatures and requires the host-finalized V5 hash to equal its independently derived value.

Only then may the API yield an authenticated negotiation proof.

## Typed result boundary

The strict API should return a value conceptually equivalent to:

```text
AuthenticatedNegotiatedHandshake
  handshake transcript hash
  V4 base session-context hash
  V5 final session-context hash
  host offer hash
  viewer offer hash
  selected protocol context hash
  negotiation binding hash
  selected capabilities
  host identity fingerprint
  session key schedule
```

The constructor must not be public. Safe Rust callers should only obtain this value after the full V2 finalize verification succeeds.

A causal-authority-specific proof can then be a checked narrowing operation:

```text
AuthenticatedNegotiatedHandshake
        |
        | require exact xenia.causal-authority/draft-04
        v
AuthenticatedCausalAuthorityHandshake
```

This is stronger than producing an authority token directly from a naked context hash.

## Legacy API posture

The existing raw-hash handshake path remains for compatibility but must be documented as low-level/legacy and insufficient by itself for strict capability claims.

No existing wire bytes are reinterpreted as V2 negotiation.

Old peers that do not understand the appended V2 message variants fail closed rather than silently negotiating draft-04.

## Rekey lineage

Authenticated capability state belongs to the cryptographic session lineage, not to an application object forever.

The authority-capable state may survive a rekey only when the new epoch is derived and authenticated through Xenia's existing transcript-bound rekey chain.

Required invariant:

```text
initial V2 authenticated handshake
        -> derived authenticated rekey epoch
        -> derived authenticated rekey epoch
        -> ...
```

An arbitrary replacement key, imported unrelated session, reset without lineage evidence, or context mismatch invalidates the authenticated authority state.

The exported lineage evidence should include at least:

- base handshake transcript hash;
- V5 session-context hash;
- current key epoch;
- previous epoch hash;
- current epoch hash.

## Adversarial gates

Before promotion, exercise at least:

- host offers draft-04, viewer does not -> strict refusal;
- viewer offers draft-04, host does not -> strict refusal;
- one side offers draft-03 + draft-04 and the other only draft-03 -> deterministic draft-03 selection, strict authority refusal;
- duplicate capability name -> reject;
- duplicate offered version -> reject;
- reordered capability names -> same offer hash;
- reordered version preference -> different offer hash and potentially different selection;
- host-offer mutation -> signature/binding failure;
- viewer-offer mutation -> signature/binding failure;
- selected-context substitution -> recomputation failure;
- V4 base-context substitution -> V5 mismatch;
- V5 substitution -> signature failure;
- cross-session authority proof reuse -> reject;
- arbitrary `install_key` after authority handshake -> authority lineage invalid;
- authenticated rekey -> authority lineage preserved;
- old V1 handshake -> still works for non-strict sessions and never claims draft-04 negotiation.

## Promotion order

1. Canonical offer/selection/binding primitive green in native Rust + independent Node.
2. Equivalent independent implementation green in xenia-wire.
3. Add V2 message variants without changing legacy variants.
4. Cross-test native host <-> xenia-wire strict viewer.
5. Add typed authenticated outcome.
6. Add V5 session-context composition.
7. Bind V5 into ledger/evidence exports.
8. Demonstrate rekey lineage and arbitrary-key invalidation.
9. Demonstrate Sovereign Ops durable reserve/consume/recovery against the authenticated proof.
10. Only then promote draft-04 in normative specifications.
