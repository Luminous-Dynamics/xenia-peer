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
is not suitable for a freshness-sensitive statement. Replay-tolerant statements
must opt into the explicitly named `static_public_inputs_digest` helper instead.

Application-specific metadata uses typed `ExtensionClaim`s. Xenia hashes claim
values with their canonical claim identity, sorts the claim set before hashing,
and rejects duplicate claim types. Applications therefore do not need to invent
their own ordering/delimiter convention for the envelope's `extensions_digest`.

## Ownership rule

> Xenia proves and verifies. Applications define what is worth proving.

A circuit is not eligible for a future `xenia-zk-primitives` crate merely because
it is mathematically generic. It must have adversarial soundness tests showing
that verifier constraints enforce the advertised statement for a malicious
prover.
