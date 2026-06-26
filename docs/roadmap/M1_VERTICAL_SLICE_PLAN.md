# M1 Vertical Slice Plan

Status: post-RC1 roadmap note.

RC1 established release discipline. M1 should establish a minimal usable trust-preserving session.

## M1 goal

One trusted local session works end-to-end.

The goal is not industry-leading performance. The goal is a narrow, honest, demonstrable session that preserves Xenia's core trust model.

## M1 user story

A host starts a local Xenia session.

A viewer connects.

The session requires explicit consent.

The connection produces audit/ledger evidence.

The viewer receives frames.

The viewer can send limited input only after consent.

The session can end cleanly.

## M1 non-goals

M1 does not need:

- public internet NAT traversal
- production-grade relay infrastructure
- mobile clients
- enterprise admin
- high-FPS gaming performance
- crates.io publication
- final browser client parity
- full RustDesk replacement claims

## Candidate technical scope

M1 should include:

- local host process
- local viewer process or web viewer bridge
- explicit consent gate
- frame path using current simplest viable capture/source
- sealed frame envelope path
- limited input path
- ledger/audit event path
- session end/revocation path
- basic troubleshooting output

## Trust requirements

M1 should preserve:

- no silent session start
- no default remote control
- fail-closed consent revocation
- auditable session state
- clear operator/user distinction
- local-only defaults unless explicitly changed

## Benchmark expectations

M1 should measure, not overclaim:

- capture/source frame rate
- encode/decode path timing if applicable
- transport latency
- viewer render latency
- input round trip
- session setup time

## Demo success criteria

A successful M1 demo should show:

1. Start host.
2. Start viewer.
3. Request session.
4. Approve consent.
5. View frames.
6. Send limited input.
7. Record audit/ledger events.
8. Revoke/end session.
9. Show evidence.

## Recommended implementation sequence

1. Define M1 session state machine.
2. Connect consent events to session authority.
3. Choose local frame source.
4. Wire frame envelope to viewer.
5. Add limited input path.
6. Add session end/revocation path.
7. Add audit summary command.
8. Add demo script.

## Decision

M1 should prove Xenia's core thesis in the smallest possible loop: remote presence with consent, audit, and fail-closed authority.
