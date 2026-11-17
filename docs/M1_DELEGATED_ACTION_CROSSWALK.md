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
- A child delegation must be a proper subset of its parent's action set when
  the profile requires strict attenuation. The core distinguishes
  `is_subset_of` (non-widening) from `is_strict_subset_of` (at least one lane
  removed); equal-scope child delegations are not strict attenuation.
- When two independent authority scopes are both required for the same action,
  their effective action sets compose by intersection.
- When separate grants are independent alternatives, their effective action
  set may be the union of their lanes. The core exposes this separately as
  `union_independent_grants`; it must never be used for parent/child
  attenuation or required bundles.
- Preserve the separate grant identities and parent lineage after computing
  an effective action set. Neither intersection nor union is a revocation
  index and must not erase source provenance.
- A missing, stale, expired, revoked, mismatched or unverified authority result
  is not a permit. The future adapter must represent unknown as HOLD /
  INDETERMINATE.
- A Mycelix permit is still not an effect commit. The local M1 owner must check
  the relevant lane at admission/preflight and at the actual effect boundary.

The core methods `M1PermissionSet::is_subset_of`,
`M1PermissionSet::is_strict_subset_of`,
`M1PermissionSet::intersection`,
`M1PermissionSet::union_independent_grants` and
`M1PermissionSet::is_empty` implement only this finite eight-bit set algebra. They do not evaluate purpose, resource,
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

The outbound runtime now performs exact-lane preflight before screen capture,
telemetry polling, audio reads, host clipboard reads, the initial outbound file
open/hash, and every outbound file-chunk read. The inbound input path checks
the input lane before decoding the event. The outbound file-transfer path then
checks again after sealing each chunk and immediately before network send; it
also rechecks before sending the terminal completion signal. The final lane
checks remain at the send/apply boundary. A denial skips that lane rather than aborting the
whole daemon session. Clipboard disclosure is checked against
`ReadHostClipboard` at its final send boundary; it must not accidentally
require `StreamFrame` as well.

This is a two-stage minimization pattern: reject unauthorized access before
touching a sensitive source, then re-check at the protected effect boundary.
The preflight is not a reservation or a linearizable commit token. A later
Mycelix adapter must add current authority and revocation checks at both stages,
and the effect-commit work in #504 must define races after the final check.

## Verification added in this increment

- Stable ID and direction mapping for all eight lanes.
- Uniqueness check for all eight action identifiers.
- Exhaustive 256 × 256 child/parent permission-set comparisons (65,536 pairs).
- Every computed intersection is verified to be a subset of each input.
- Strict-subset semantics are checked independently from non-widening subset
  semantics; independent-grant union semantics are checked separately.
- Lane preflight is verified to check only the requested permission and to
  create no ledger events.
- Lane-specific denial skips sensitive source work while final effect gates
  remain intact.
- Clipboard send is gated by clipboard-read authority, not screen-frame access.
- Initial outbound file open/hash is preceded by a side-effect-free
  `SendFileToViewer` preflight; chunks are checked before source consumption
  and again at the sealed-envelope send boundary; completion is rechecked.

## Explicit claim ceiling

This increment adds typed adapter vocabulary and local M1 lane preflight
hardening. It does not add a Mycelix authority client,
ROS-005 signature/lineage verifier, freshness watermark, revocation stream,
session-capability issuance, or runtime enforcement switch-over is added here.
No Holochain 0.7.1 qualification or security superiority is claimed.
