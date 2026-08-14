# xenia-zk-protocol

Backend-neutral protocol substrate for proof envelopes.

This crate intentionally does **not** contain a prover, verifier implementation,
application statement, Holochain adapter, or signature implementation. Its job is
to make cryptographic confusion difficult by assigning explicit identities to:

- the statement being proven;
- the proof system;
- the exact verifier program/AIR/image;
- the parameter set;
- the public-input digest;
- the nonce and timestamp;
- authenticated extension claims; and
- each authentication suite + signer key.

## V3 rule

New proofs use `XENIA:ProofEnvelope:Body:v3`. Legacy Mycelix v2 envelopes retain
their historical transcript bytes in a separate compatibility adapter. V3 never
auto-detects or falls back to v2.

## Ownership rule

> Xenia proves and verifies. Applications define what is worth proving.

A circuit is not eligible for a future `xenia-zk-primitives` crate merely because
it is mathematically generic. It must have adversarial soundness tests showing
that verifier constraints enforce the advertised statement for a malicious
prover.
