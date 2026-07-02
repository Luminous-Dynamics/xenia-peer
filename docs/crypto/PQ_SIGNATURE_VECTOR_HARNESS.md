# PQ Signature Vector Harness

This document defines the contract for Xenia's post-quantum signature verification runway.

## Purpose

The harness exists to prove that a future PQ signature backend verifies known-answer vectors before `full-pqc-v1` can be enabled.

## Current state

A real ML-DSA verifier backend is available behind the non-default
`pqc-signatures` feature for explicit evidence-verifier entry points. Production
acceptance still requires pinned external known-answer vectors and dependency
review.

Current default evidence signatures remain:

- transcript signature: Ed25519
- ledger signature: Ed25519
- evidence profile: `hybrid-pre-pqc-v1`

`full-pqc-v1` must remain refused by default. A full-PQC evidence bundle may only be accepted through an explicit PQ backend path whose suite matches the manifest and every entry envelope.

## Required future vector fields

Each vector fixture must identify:

- signature suite
- public key encoding
- public key bytes
- message bytes or message encoding
- signature bytes
- expected verification result

## Accepted future suites

- `ml-dsa-65-fips204`
- `ml-dsa-87-fips204`
- `slh-dsa-fips205`

## Refusal rule

A backend must not be accepted unless it verifies known-answer pass vectors and rejects known-answer fail vectors.

Mocked or unconditional-success verification is forbidden.
