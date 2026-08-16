# xenia-zk-protocol

Backend-neutral protocol substrate for proof envelopes.

This crate intentionally does **not** contain a prover, verifier implementation,
application statement, Holochain adapter, or signature implementation. Its job is
to make cryptographic confusion difficult by assigning explicit identities to:

- the statement being proven;
- the proof system;
- the exact verifier program/AIR/image;
- the parameter set;
- the challenge-bound public-input digest;
- the verifier challenge and timestamp;
- authenticated extension claims; and
- each authentication suite + signer key.

## V3 rule

New proofs use `XENIA:ProofEnvelope:Body:v3`. Legacy Mycelix v2 envelopes retain
their historical transcript bytes in a separate compatibility adapter. V3 never
auto-detects or falls back to v2.

For challenge-response statements, the canonical public-input digest binds the
verifier challenge and backend adapters receive that challenge as an explicit
public input. A backend whose circuit/program does not constrain the challenge
is not suitable for V3 verification. V3 intentionally provides no challenge-free
public-input digest helper; noninteractive use cases still bind an explicit
context nonce into the verified relation.

Application-specific metadata uses typed `ExtensionClaim`s. Xenia hashes claim
values with their canonical claim identity, sorts the claim set before hashing,
and rejects duplicate claim types. Applications therefore do not need to invent
their own ordering/delimiter convention for the envelope's `extensions_digest`.


## Authentication-suite registry

`AuthenticationSuiteId` now has a frozen V1 registry contract:

- `1 = ed25519`
- `2 = ml-dsa-65-fips204`

The canonical registry bytes and their SHA-256 fingerprint are exported by the
crate. Downstream credential protocols can pin that fingerprint without taking a
build-time dependency on Xenia. Changing an existing wire ID or canonical name is
a protocol-version event; extension IDs remain possible as non-zero values but do
not acquire a canonical name unless the registry is explicitly revised.

## Ownership rule

> Xenia proves and verifies. Applications define what is worth proving.

A circuit is not eligible for a future `xenia-zk-primitives` crate merely because
it is mathematically generic. It must have adversarial soundness tests showing
that verifier constraints enforce the advertised statement for a malicious
prover.
## Pre-deserialization resource boundary

Untrusted serialized proof envelopes should be passed through
`bound_envelope_frame_before_deserialization()` **before** a Serde/JSON/bincode/CBOR
decoder is invoked. The default raw-frame ceiling is 1 MiB and is separately
configurable from the decoded proof, signature, and public-input ceilings. This
prevents a decoder from allocating an attacker-selected oversized `Vec` before the
ordinary `EnvelopePolicy` checks get a chance to run. Format-specific decoding stays
application-owned; the protocol crate only supplies the bounded-frame typestate.

### Preferred decode integration

For untrusted bytes, prefer `decode_bounded_envelope_with(...)` over manually
calling the raw bound helper followed by a parser. The decoder closure is not
invoked until the frame has passed the configured raw-size ceiling, and it
receives a `BoundedEnvelopeFrame` rather than the original slice. This does not
make a format parser safe against all algorithmic-complexity attacks, but it
makes the required size-check-before-deserialization ordering explicit and
unit-testable without coupling this crate to JSON, CBOR, bincode, or another
specific codec.
