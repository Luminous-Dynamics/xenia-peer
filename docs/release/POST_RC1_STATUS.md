# Xenia Post-RC1 Status

Status: post-RC1 status note.

This document records the state of xenia-peer after RC1 release hardening, post-RC1 strategy planning, and the first targeted WASM compatibility implementation.

## Current release posture

Xenia remains pre-production.

Current release status:

- policy stage: pre-production
- layout mode: normalized
- release status: rc
- current milestone: normalization-v0.2
- next candidate: rc1
- hard blockers: 0
- soft blockers: 0

RC1 review, release readiness, validation, source archive hygiene, and CI gates are passing.

## Recent merged work

Recent post-RC1 work includes:

- #17: RC1 release notes
- #18: crates publication readiness documentation
- #19: post-RC1 hardening plan
- #20: release evidence freshness checker
- #22: RC1 review CI gate
- #23: PQC and WASM feasibility note
- #24: RustDesk positioning comparison restore
- #25: WASM randomness policy
- #26: post-RC1 strategy bundle
- #27: xenia-ledger wasm32 target check
- #28: deterministic ledger test fixture repair

## What is now true

The repository now has:

- validated RC1 release evidence
- RC1 review automation
- source archive export/check coverage
- release-readiness checks
- validation hygiene checks
- RustDesk positioning restored
- PQC/WASM feasibility documented
- WASM randomness policy documented
- integration taxonomy documented
- community thesis documented
- M1 vertical slice plan documented
- xenia-ledger compiling for wasm32-unknown-unknown
- CI protection for the ledger WASM check
- repaired deterministic ledger fixtures across native CI

## First protected WASM-compatible crate

xenia-ledger is now the first protocol-adjacent crate protected by a targeted WASM check.

The ledger WASM work deliberately avoided globally enabling browser randomness. Instead, the ledger crate was adjusted so core examples and tests do not require runtime random UUID or signing-key generation.

This supports the project policy that WASM compatibility should be explicit, target-specific, and protected by CI before claims are made.

## Remaining WASM targets

The following remain future work:

- xenia-handshake
- xenia-peer-core
- browser-facing session integration
- non-browser WASM runtime policy
- full web viewer integration with real transport/session authority

Current evidence suggests the next WASM blockers are still randomness and protocol/runtime boundary issues, not proof that the protocol design is inherently native-only.

## Product posture

Xenia should not currently claim to be a RustDesk replacement or production remote desktop system.

The honest current posture is:

- use RustDesk or another mature tool for immediate remote access
- use Xenia to develop accountable, auditable, consentful remote presence
- do not make production claims before end-to-end demos and benchmarks
- do not make security claims without threat models and evidence

## Recommended next technical milestone

The next major implementation target should be M1: one trusted local session works end-to-end.

M1 should demonstrate:

1. host starts a local session
2. viewer connects
3. explicit consent is required
4. frames flow after consent
5. limited input is accepted only after consent
6. audit/ledger events are recorded
7. revocation/end session works
8. evidence can be shown afterward

## Suggested next branches

Recommended next branch:

- xenia/m1-session-state-machine-v0.1

Possible later branches:

- xenia/handshake-wasm-inventory-v0.1
- xenia/peer-core-runtime-split-v0.1
- xenia/m1-local-demo-script-v0.1

## Decision

RC1 stabilization is complete enough to stop doing tiny release-hygiene PRs.

Next work should prioritize the M1 vertical slice unless a regression or release blocker appears.
