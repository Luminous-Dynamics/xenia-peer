# Xenia ZK Envelope Codec V1

## Scope

`xenia-zk-protocol` remains backend-neutral and wire-format-neutral. Concrete parsing of untrusted proof-envelope bytes lives in the separate `xenia-zk-codec` crate.

This separation is intentional: protocol identity, signed transcript semantics, verification policy, concrete serialization, and cryptographic backend implementation are distinct assurance boundaries.

## Required decode ordering

Every untrusted envelope follows this order:

1. raw frame byte ceiling;
2. concrete decoder;
3. protocol structural/policy validation;
4. exact local verification contract;
5. backend proof verification;
6. authentication verification.

The concrete decoder must never receive an unbounded frame.

## JSON transport

JSON is a transport representation only. The exact JSON bytes are **not** signed. Signatures authenticate the canonical digest defined by `xenia-zk-protocol`.

Protocol structs reject unknown JSON fields, and duplicate struct fields are rejected by Serde. This avoids ambiguous application interpretations such as one implementation ignoring a security-relevant extension another implementation consumes.

The bounded JSON decoder first applies `EnvelopePolicy::max_encoded_envelope_bytes` and only then calls `serde_json`.

## Canonical binary format

Binary codec V1 begins with:

`XZKENV01`

All integers are little-endian. Text statement components are `u8 length || UTF-8 bytes`; proof/signature blobs are `u32 length || bytes`; authentication count is `u16`.

The decoder checks each declared length against both:

- the caller's local resource policy; and
- bytes remaining in the already-bounded frame.

These checks occur before `Vec` allocation. Authentication count is also checked against the minimum bytes needed to encode that many records before `Vec::with_capacity` is called.

Trailing bytes are rejected. Therefore a successfully decoded binary envelope has exactly one byte representation under this codec version.

## Non-goals

Codec V1 does not establish proof soundness, signature validity, credential validity, revocation freshness, or zero-knowledge privacy. It only makes the byte-to-envelope transition explicit, bounded, and canonical for the binary representation.

JSON remains noncanonical transport syntax and must never be used directly as a signing transcript.

## No-toolchain evidence

`scripts/model_check_zk_binary_codec_v1.py` independently implements the framing rules and rejects every strict truncation of its canonical fixture, trailing data, oversized proof declarations, and oversized signature declarations.

`scripts/check-zk-codec-boundary.py` enforces source-level boundary invariants.

`scripts/check-rust-function-params.py` catches duplicate simple named Rust parameters on review runners that cannot execute `cargo check`. It is an additional typo guard, **not** a Rust compiler substitute.
