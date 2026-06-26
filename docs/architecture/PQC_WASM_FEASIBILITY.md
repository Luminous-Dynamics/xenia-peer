# PQC and WASM Feasibility

Status: post-RC1 feasibility note.

Xenia should not compete with mature remote desktop tools by claiming product parity. Its potential differentiation is accountable remote presence: consent/audit authority, secure-default session control, PQC or hybrid-PQC handshakes, and WASM-capable protocol components.

This document defines the feasibility questions that must be answered before Xenia makes strong PQC or WASM claims.

## Goals

- Determine which Xenia crates can compile to wasm32-unknown-unknown.
- Determine whether protocol-only components can remain browser/WASM compatible.
- Identify native-only dependencies early.
- Clarify the difference between classical encryption, PQC, and hybrid-PQC.
- Avoid overclaiming until compile checks and tests exist.

## Non-goals

This document does not:

- claim that Xenia is product-ready
- replace RustDesk operationally
- define a complete browser client
- publish crates to crates.io
- change RC1 release status
- require protocol rewrites

## Existing WASM baseline

The separate `xenia-wire` repository already contains a `xenia-viewer-web` crate. That crate is the existing web/WASM baseline for Xenia's wire protocol work.

The feasibility question is therefore not "can Xenia do WASM at all?" The better question is:

- which `xenia-peer` crates can compile to WASM?
- which `xenia-wire` web-viewer pieces should be referenced, ported, or integrated?
- which runtime capabilities must remain native-only?
- how should browser-safe randomness be configured for cryptographic/session code?

## Candidate WASM-compatible crates

Initial candidates in this checkout:

- xenia-handshake
- xenia-ledger
- xenia-peer-core protocol-only portions, if separable

External baseline:

- xenia-wire
- xenia-viewer-web

Native-only or likely-native components:

- capture backends
- input injection backends
- native viewer rendering
- QUIC/WebSocket transports with OS/network assumptions
- admin UI runtime details, depending on framework target support

## PQC feasibility questions

Xenia should answer:

1. Does the current handshake crate use PQC, classical crypto, or hybrid crypto?
2. Can the handshake compile for WASM without native/system dependencies?
3. Is randomness browser-safe under WASM?
4. Are key formats stable and serializable across native and WASM builds?
5. Can session establishment be hybridized without breaking current protocol boundaries?
6. Can the project document harvest-now-decrypt-later threat assumptions?

## WASM feasibility questions

Xenia should answer:

1. Which protocol crates compile with wasm32-unknown-unknown?
2. Which existing xenia-wire / xenia-viewer-web functionality should be referenced, ported, or integrated?
3. Which dependencies fail and why?
4. Are failures caused by randomness, time, networking, filesystem, threading, or native crypto?
5. Can protocol types be split from native runtime backends?
6. Can the existing loopback web viewer evolve into a real transport-backed browser viewer?
7. Is a browser client feasible without weakening consent/audit guarantees?

## Suggested local checks

Install the target:

    rustup target add wasm32-unknown-unknown

Run exploratory checks:

    cargo check -p xenia-handshake --target wasm32-unknown-unknown
    cargo check -p xenia-ledger --target wasm32-unknown-unknown
    cargo check -p xenia-peer-core --target wasm32-unknown-unknown

Failures should be recorded as evidence, not hidden. A failed WASM compile is useful if it identifies the native boundary clearly.

## Observed exploratory results

Local exploratory checks against wasm32-unknown-unknown found useful blockers.

### xenia-handshake

Command:

    cargo check -p xenia-handshake --target wasm32-unknown-unknown

Observed result:

- failed in getrandom 0.2
- error says wasm unknown targets are not supported by default
- suggested fix class: enable the getrandom `js` feature where appropriate

Interpretation:

The first observed blocker is browser/WASM randomness configuration, not proof that the handshake protocol is WASM-incompatible.

### xenia-ledger

Command:

    cargo check -p xenia-ledger --target wasm32-unknown-unknown

Observed result:

- failed in uuid
- error says uuid on wasm32-unknown-unknown requires a randomness source
- suggested fix class: enable one of uuid's wasm randomness features such as `js`, `rng-getrandom`, or `rng-rand`, depending on the selected dependency policy

Interpretation:

The first observed blocker is UUID/randomness configuration. Ledger types may still be WASM-feasible if randomness-dependent construction is isolated or configured correctly.

### xenia-peer-core

Command:

    cargo check -p xenia-peer-core --target wasm32-unknown-unknown

Observed result:

- failed in getrandom 0.4
- error says wasm32-unknown-unknown is not supported by default
- suggested fix class: enable the getrandom `wasm_js` crate feature where appropriate

Interpretation:

The first observed blocker is again randomness configuration. This suggests the next implementation PR should focus on a WASM randomness policy and protocol/runtime crate boundaries.

## Initial feasibility conclusion

The first WASM blockers are randomness-feature configuration issues:

- getrandom 0.2 wants explicit web support
- uuid wants an explicit randomness source
- getrandom 0.4 wants explicit wasm_js support

This is encouraging. The initial failures do not show an unavoidable native-only dependency such as screen capture, input injection, filesystem state, or OS networking in the protocol candidates. They show that Xenia needs an explicit browser randomness policy before claiming WASM compatibility.

## Acceptance criteria for a future implementation PR

A future implementation PR should provide:

- a WASM compatibility matrix
- exact cargo check target results
- documented failures and blockers
- at least one CI check for a protocol-only crate, if feasible
- no product-readiness claims

## Decision

Xenia should pursue PQC/WASM only as a disciplined feasibility track. RustDesk remains the operational baseline. Xenia's opportunity is not merely remote desktop; it is accountable, auditable, future-secure remote presence.
