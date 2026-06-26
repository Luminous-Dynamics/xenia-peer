# Xenia vs RustDesk

Status: positioning note.

RustDesk is the recommended operational remote desktop tool today. Xenia is pre-production and should not claim product parity.

## RustDesk strengths

RustDesk is a mature open-source remote desktop product with:

- working native clients
- web/browser-facing support
- self-hosting support
- relay/rendezvous infrastructure
- existing users and operational documentation
- practical production experience

## Xenia current status

Xenia is a pre-production secure remote-presence project. It has strong release discipline, archive hygiene, validation gates, historical evidence handling, source archive checks, and RC1 review tooling.

It does not yet compete with RustDesk as a usable daily remote desktop product.

## Xenia should not compete as

- RustDesk but ours
- remote desktop in Rust
- another screen-sharing app

That framing is too weak.

## Xenia should compete as

An accountable remote-presence protocol for high-trust environments.

The differentiators should be:

- PQC or hybrid-PQC session establishment
- WASM-capable protocol components
- consent-ledger-backed session authority
- auditable admin/operator actions
- fail-closed privilege handling
- source archive hygiene and release evidence
- explicit security policy gates

## Operational recommendation

Use RustDesk for immediate remote access.

Continue Xenia where it advances secure remote presence, auditability, consent, PQC readiness, WASM portability, and verifiable release discipline.

## Decision

RustDesk is the current practical baseline.

Xenia must earn product claims through benchmarks, threat modeling, protocol tests, and end-to-end usability.
