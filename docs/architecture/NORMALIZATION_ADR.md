# ADR: Xenia Workspace Normalization

Status: proposed for `normalization-v0.2`

## Context

The current Xenia tree has the right architectural pieces, but some runnable
products and generated/migration artifacts live inside active crate paths. That
makes it harder for contributors and agents to know what is source, what is a
binary/app surface, and what is historical debris.

Xenia is also a sensitive class of software. It handles capture, viewing,
transport, administration, and eventually input authority. Layout ambiguity is a
security and operations risk because it hides ownership boundaries.

## Decision

Adopt this canonical shape:

```text
xenia/
  xenia-wire/                  # protocol crate/repo boundary
  xenia-peer/                  # product workspace
    crates/                    # reusable libraries only
    apps/                      # runnable products / UIs / control planes
    docs/
    scripts/
```

The intended dependency direction is:

```text
apps -> crates -> xenia-wire
```

`xenia-wire` remains protocol-only. It must not absorb product policy, capture
backends, admin UI, or peer-specific authority logic.

## Consequences

Positive:

- Build and release tooling can reason about apps and libraries separately.
- Source archives can exclude generated output more reliably.
- Agent handoffs become less fragile.
- Security review can map authority to app/control-plane surfaces.

Tradeoffs:

- Cargo workspace paths may need updates.
- Some scripts and docs may need path rewrites.
- Existing local workflows may need one-time migration.

## Non-goals

- Do not delete history.
- Do not claim production readiness.
- Do not merge `xenia-wire` into product policy.
- Do not move crates automatically without a snapshot and review.

## Evidence required before marking applied

1. `scripts/check-normalization-plan.py .` passes.
2. A before snapshot exists under `_archive/normalization-v0.2/`.
3. Active build artifacts and tarballs are archived.
4. Apps have moved to `xenia-peer/apps/`.
5. Libraries remain under `xenia-peer/crates/`.
6. `scripts/xenia-validate.sh .` passes or produces documented exceptions.
7. A source archive passes `scripts/check-source-archive.sh`.
