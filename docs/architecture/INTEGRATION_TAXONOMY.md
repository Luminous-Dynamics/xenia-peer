# Integration Taxonomy

Status: post-RC1 strategy note.

Xenia should learn from existing remote desktop systems without becoming a wrapper around them.

## Principle

Xenia should integrate with ecosystems at the edges, while keeping its trust model independent at the core.

Core Xenia should remain centered on:

- accountable remote presence
- consent-ledger-backed session authority
- auditable operator/admin actions
- secure-default session control
- source archive hygiene and release evidence
- PQC/WASM readiness where technically justified

## Tier 0: Benchmark only

These tools should be used for comparison, not integration.

- Parsec
- AnyDesk
- TeamViewer
- Chrome Remote Desktop

Use them to understand:

- latency expectations
- onboarding simplicity
- enterprise admin expectations
- session/support flows
- user experience polish

Do not make them core dependencies.

## Tier 1: Architectural reference

These projects are useful architectural references.

- RustDesk
- Apache Guacamole

Use RustDesk as the operational open-source baseline.

Use Guacamole as a reference for browser gateway architecture and legacy protocol bridging.

## Tier 2: Technical benchmark harness

These projects are valuable technical benchmarks.

- Sunshine
- Moonlight

Use them to understand:

- low-latency streaming expectations
- hardware encode paths
- local-network performance baselines
- input latency expectations

Do not embed them into Xenia core.

## Tier 3: Optional future adapters

Possible future adapters:

- RustDesk configuration or session-log importer
- Guacamole legacy RDP/VNC/SSH bridge
- Sunshine/Moonlight latency benchmark harness

Adapters must not weaken Xenia's consent, audit, or fail-closed authority model.

## Tier 4: Core Xenia

Core Xenia should remain independent:

- Xenia protocol
- Xenia consent ledger
- Xenia admin/audit model
- Xenia handshake/session model
- Xenia source/release evidence
- Xenia secure-default policy gates

## Non-goals

Xenia should not become:

- RustDesk but with a different name
- a proprietary remote desktop launcher
- a generic wrapper around existing tools
- a ledger bolted onto an opaque remote-control system

## Decision

Use mature systems as references and benchmarks. Keep Xenia's trust model independent.
