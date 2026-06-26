# Xenia Peer v0.0.0 RC1 Release Notes

Xenia Peer v0.0.0 RC1 is the first release-candidate checkpoint for the normalized Xenia Peer workspace.

This release candidate confirms that the repository has completed the RC1 readiness burn-down:

- Release train promoted from `pre-rc` to `rc`
- Current milestone: `normalization-v0.2`
- Next candidate: `rc1`
- Hard blockers: `0`
- Soft blockers: `0`
- Source archive validation passes
- RC1 candidate review passes
- CI passes across Linux, macOS, Windows, MSRV, docs, clippy, formatting, h264 feature tests, and artifact collection

## What changed in the RC1 burn-down

RC1 readiness was reached through a sequence of focused evidence and stabilization PRs:

- Added source archive checksum evidence
- Normalized release dashboard evidence generation
- Added normalization dry-run evidence
- Expanded transport fault-injection coverage
- Stabilized admin/operator audit event names
- Added deterministic RC1 candidate-review evidence
- Promoted the release train to `rc`

## Release artifact posture

The source archive validation confirms:

- No disallowed paths
- No nested archives
- No runtime secret or state files
- No absolute local workspace references in source/config
- Archive inventory smoke check passes

## Tag

`xenia-peer-v0.0.0-rc1`

## Status

This is a release candidate, not a final production release.
