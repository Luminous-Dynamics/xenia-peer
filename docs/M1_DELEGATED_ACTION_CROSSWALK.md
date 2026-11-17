# M1 delegated-action crosswalk

Status: implementation-level vocabulary and set-algebra contract. This is not a
Mycelix runtime integration, a signed delegation verifier, or a production
authorization qualification.

## Why this exists

Xenia M1 already has eight independently controlled permission tiers. The
crosswalk gives each tier a stable action identifier and an explicit direction
so a Mycelix ROS-005 / AuthZEN adapter cannot collapse distinct privacy and
control effects into one broad `remoteAccess` permission.

The Rust source of truth is
`xenia_peer_core::M1Permission::{ALL, action_id, direction}`. Keep these
identifiers stable once external adapters or receipts depend on them. Any
renaming or semantic change requires an explicit schema/version migration.

## Canonical mapping

| M1 permission | Delegated action ID | Direction | Effect meaning |
|---|---|---|---|
| `StreamFrame` | `xenia.screen.view` | Host → viewer | Disclose screen frames |
| `StreamTelemetry` | `xenia.host.telemetry` | Host → viewer | Disclose host telemetry and configured system identity |
| `StreamAudio` | `xenia.audio.capture` | Host → viewer | Disclose audio, including captured microphone input when enabled |
| `InjectInput` | `xenia.input.inject` | Viewer → host | Apply viewer-originated keyboard/pointer input |
| `ReadHostClipboard` | `xenia.clipboard.read` | Host → viewer | Disclose host clipboard contents |
| `WriteHostClipboard` | `xenia.clipboard.write` | Viewer → host | Apply viewer-originated clipboard contents |
| `SendFileToViewer` | `xenia.file.send` | Host → viewer | Read host file bytes and disclose them to viewer |
| `ReceiveFileFromViewer` | `xenia.file.receive` | Viewer → host | Accept and persist viewer-supplied file bytes |

No M1 lane implies another. In particular, screen viewing does not imply
telemetry, audio, input, clipboard or file access. Clipboard and file transfer
are directionally independent. Host administration, process execution, reboot,
configuration changes and other host-local privileged actions are deliberately
not included in this eight-lane set.

## Composition rules

- Recipient consent and Mycelix semantic delegation are both required.
- The child's action set must be a subset of the parent's; widening is rejected,
  not silently repaired by intersection.
- When two independent authority scopes are both required for the same action,
  their allowed action sets compose by intersection, never union.
- Preserve the separate grant identities and parent lineage even after
  computing the effective action set. A set intersection is not a revocation
  index and must not erase source provenance.
- A missing, stale, expired, revoked, mismatched or unverified authority result
  is not a permit. The future adapter must represent unknown as HOLD /
  INDETERMINATE.
- A Mycelix permit is still not an effect commit. The local M1 owner must check
  the relevant lane at admission/preflight and at the actual effect boundary.

The core methods `M1PermissionSet::is_subset_of`,
`M1PermissionSet::intersection` and `M1PermissionSet::is_empty` implement
only this finite eight-bit set algebra. They do not evaluate purpose, resource,
audience, validity, authority epoch, parent liveness, budgets, signatures,
frontier currentness or host effect outcomes.

## Existing effect checkpoints to preserve

The current file-transfer path already checks M1 consent:
- before accepting an incoming offer;
- before each received chunk;
- before publishing a completed incoming file;
- before each outgoing chunk.

Delegated authority must be composed into those same boundaries, not only
checked once at session setup. The completed-file publication is a separate
commit boundary: a transfer that was admitted earlier must not publish after a
later revocation has been observed.

The frame, telemetry, audio, input and clipboard paths need the same
operation-specific review. A generic "session active" preflight is only a cheap
resource-work check; it is not a lane permit.

## Verification added in this increment

- Stable ID and direction mapping for all eight lanes.
- Uniqueness check for all eight action identifiers.
- Exhaustive 256 × 256 child/parent permission-set comparisons (65,536 pairs).
- Every computed intersection is verified to be a subset of each input.
- No change to the existing M1 consent or effect behavior is claimed.

## Explicit claim ceiling

This crosswalk is a typed adapter contract only. No Mycelix authority client,
ROS-005 signature/lineage verifier, freshness watermark, revocation stream,
session-capability issuance, or runtime enforcement switch-over is added here.
No Holochain 0.7.1 qualification or security superiority is claimed.
