# PQ Signature Vector Harness

This document defines the contract for Xenia's post-quantum signature verification runway.

## Purpose

The harness exists to prove that a future PQ signature backend verifies known-answer vectors before `full-pqc-v1` can be enabled.

## Current state

No production PQ signature backend is enabled yet.

Current evidence signatures remain:

- transcript signature: Ed25519
- ledger signature: Ed25519
- evidence profile: `hybrid-pre-pqc-v1`

`full-pqc-v1` must remain refused until PQ signature vectors pass through a real backend.

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
