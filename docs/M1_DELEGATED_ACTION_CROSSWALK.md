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

The route inventory pins each reviewed source file as `path@Git-blob-SHA1`.
The conformance test recomputes Git's blob identity from the exact `include_str!`
bytes compiled into the test and rejects a stale pin. Source-order checks are
scoped to the exact daemon loop or file-transfer match arm. This establishes
source correspondence for the listed files; it does not prove the completeness
of alternate OS, plugin, helper-binary or future feature routes.

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

## Local operator revocation observation

The consent server's shared operator-revocation flag is now bound into the
M1 runtime before that runtime is shared with the sender, input and file
transfer tasks. Once an authenticated operator `Revoke` is accepted and its
audit append has succeeded, the consent server stores the shared atomic latch.
Every M1 source-work preflight and every final lane admission method checks
that latch and rejects with `OperatorRevocationObserved`, even before the
main session loop appends the canonical M1 `Revocation` event.

This closes the local gap in which sibling tasks could still see the M1
state-machine state as `Active` after the operator revoke flag had already
been set. The main session loop remains the owner of the durable M1 revoke
transition; the latch is an immediate fail-closed admission signal, not a
replacement ledger.

Regression coverage sets the latch while the M1 state machine remains
`Active`, verifies all six source preflights and all eight final lane methods
deny without appending operation evidence, then verifies the owning runtime
can still append the canonical revocation transition.

Claim ceiling: this only orders local admission checks after local operator
revocation observation. It does not make an OS call or asynchronous network
send atomic with revocation after a final gate has already passed. The
in-flight/commit race remains owned by #504, and distributed revocation
propagation remains under Mycelix #6236.

## Existing effect checkpoints to preserve

The current file-transfer path now uses two distinct checks for incoming offers: a side-effect-free receive-lane preflight before local reservation/staging, followed by sealing the `Accept` response and then an audited lane recheck immediately before sending that exact envelope. If that final gate detects revocation, the staged transfer is removed and a separately sealed `Reject` is sent. The path also checks the lane before each incoming chunk append and again before final verification/publication.

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


## Mycelix ROS-005 adapter contract (source review 2026-11-18)

The current candidate implementation is Mycelix [PR #3679](https://github.com/Luminous-Dynamics/mycelix/pull/3679), exact head `ce5ad5b903d4ecf2a3c89e7b85273e7bf195875f`. It is open and unmerged. Its dedicated workflow passed the touched-file formatter and all 470 `mycelix-core-types` tests; the package-wide Clippy stage failed with 88 library and 137 test diagnostics, mainly in existing WisdomEngine code/tests. It is therefore a candidate semantic API, not a Clippy-green or production-qualified dependency. Holochain 0.7.1 qualification remains separately incomplete under Mycelix #5719.

The exposed semantic types are `Delegation`, `DelegationContext`, `ExecutionRequest`, `ExecutionDecision`, `ActionScope`, `ResourceScope`, `DelegationMode`, `PrincipalRef`, and `AuthorityEpoch`. A future adapter can construct an exact `ActionScope::named(M1Permission::action_id())` and a canonical `ResourceScope::named(...)`, then call `Delegation::authorize(request, context)` with the authenticated principal/delegate and complete addressable parent-chain records.

Important adapter constraints:

- `DelegationContext::from_slice` rejects duplicate IDs; `authorize` validates the content-bound identity of the target and each retrieved parent. The adapter must retrieve and authenticate the actual parent records from the authority owner. A caller-supplied `parent_active` boolean is not part of the hardened API.
- The content-bound ID commits to immutable delegation fields. The mutable status/event state still has to be authenticated and resolved through the owner-native currentness boundary; a locally reconstructed struct or a signed ID alone is not proof of current status.
- Missing parent records, revoked ancestors, altered content, stale epochs, scope errors and chain errors are non-permits. Missing/incomplete authority evidence remains HOLD/INDETERMINATE in Xenia; a valid negative semantic decision is DENIED.
- Mycelix `ActionScope` and `ResourceScope` currently use exact `Named` equality. That fits the eight exact M1 action IDs, but does not provide hierarchical resource containment or multi-action set algebra. A host-wide resource name must not be assumed to authorize every file, destination or sub-resource. Use exact resource identities at the effect boundary; resource-hierarchy attenuation requires a versioned upstream extension.
- The current strict child-attenuation test can narrow mode or validity interval (later start / earlier expiry). It cannot yet narrow an action set, resource set, purpose, audience, data class, direction, rate, bytes or operation count. Xenia must not synthesize those absent dimensions by concatenating opaque strings into an action name.
- `ExecutionRequest` binds principal, delegate, action, resource, proposal/execute mode, `requested_at` and authority epoch. It does not bind explicit purpose, audience, data class, direction, Xenia session fingerprint, exact operation digest, schema/profile version or consumable budget. Xenia must conjunct ROS-005 with ROS-004 `Consent::authorize`, authenticated session/rekey state, M1 lane/direction and the final effect-owner gate.
- `PrincipalRef` is backed by `ParticipantRef` namespace and identifier. The bridge needs an owner-approved deterministic mapping from authenticated Xenia identities into this type; a display name, username or session label is not an identity proof.
- Both ROS-005 and ROS-004 expose time values as `i64`, but the reviewed public types do not document the epoch or unit. Their pure evaluators intentionally accept explicit time rather than read a wall clock. Do not pass Xenia milliseconds or accept caller-selected/backdated time until Mycelix standardizes the unit and the runtime adapter obtains the value from a trusted time source.
- `authority_epoch` is also supplied in `ExecutionRequest`; it must be populated from authenticated owner/frontier evidence, not copied from untrusted request input. The context is a deterministic validation dependency, not proof that the snapshot is complete, current, signed or globally replicated.
- The crate-root `PrincipalRef` export ambiguity is resolved on PR #3679 by explicit exports `ConsentPrincipalRef` and `DelegationPrincipalRef`; module-qualified names remain available.
- `ExecutionDecision::AuthorizedExecution` is semantic authority only. It is not a Holochain zome-call credential, Xenia session capability, host effect commit, transport acknowledgement or evidence that the viewer observed anything.

The adapter sequence is therefore: pin and qualify the exact Mycelix API; agree identity, resource canonicalization, timestamp units and epoch provenance; retrieve/authenticate current delegation and ROS-004 consent plus complete parent context/frontier; compose ROS-005 AND ROS-004 AND Xenia M1; then qualify every local effect boundary, revocation race and operation receipt. Until those owner contracts and runtime controls exist, this PR remains a typed crosswalk plus local M1 hardening, not a Mycelix runtime integration.

## Machine-readable route census

The current source-reviewed lane-to-effect route map is recorded in
`docs/security/M1_ROUTE_INVENTORY_V0_1.toml`. It binds the eight M1 actions to
their source APIs, preflight points, final gates, local effect owners and
maximum supported evidence claims. The manifest records the exact source-file Git blob SHAs
used for the review and has a source-drift test.

Its completeness is deliberately `INDETERMINATE`: direct OS APIs, helper
binaries, plugins, background tasks, alternate transports, all platform/feature
combinations, reconnect/rekey paths and other alternate entry points have not
yet been independently enumerated and negatively tested. Xenia #512 owns the
remaining route inventory and bypass corpus; Mycelix #6213 owns the independent
route-mediation evaluation. The JSON inventory and TOML inventory are separate
machine-readable projections; changes to one must be reconciled with the other
in the same review. The manifest is a bounded source census, not a
complete-mediation certification.


## Mycelix ROS-005 Typed Scope Profile v1 crosswalk (draft, 2026-11-19)

Mycelix [PR #6325](https://github.com/Luminous-Dynamics/mycelix/pull/6325) introduces the separately versioned `TypedDelegationScopeV1` under Mycelix #6302. The PR is open/draft and stacked on the unmerged parent-chain/content-binding PR #3679. The new type is not yet wired into the base `Delegation` API, Holochain validation or any execution path. This section is an adapter mapping proposal, not a claim that Xenia consumes the profile.

| Typed ROS-005 v1 field | Xenia M1 mapping | Required local/owner constraint |
|---|---|---|
| `actions` | One or more exact values from the eight `M1Permission::action_id()` IDs | Preserve exact equality; unknown action IDs are unsupported/denied |
| `resources` | Exact canonical host identity plus the exact object/resource identity for the selected lane | Resource IDs are opaque. Never infer file/path/host hierarchy from string prefixes; use the exact destination or selected object identity |
| `audiences` | Exact authenticated viewer/relying-party identity | Keep audience separate from principal/delegate identity and from display names |
| `directions` | `HostToViewer` → `OwnerToDelegate`; `ViewerToHost` → `DelegateToOwner` | No M1 data lane uses `OwnerLocal`; do not treat it as an alias for either network direction |
| `consent` | Prefer one owner-issued, content-bound ROS-004 `ConsentId` reference; if independent purpose/data-class projections remain required, consume only an owner-generated typed commitment object | Mycelix open [ROS-007 PR #3692](https://github.com/Luminous-Dynamics/mycelix/pull/3692) proposes `Consent::canonical_bytes()`, `state_canonical_bytes()`, `ConsentId::derive_content_bound()` and `validate_identity()`. The immutable projection binds relationship, grantor, audience, purpose, disclosure mode/data classes/fields, grant/expiry times and authority epoch; mutable lifecycle remains separate. Exact head `38d0af4f4c86ed1ace883919395593333521e31a`; no workflow was reported for that exact head at last check. This supplies a promising whole-consent identity, but not the three separate canonical digests required by `ConsentBindingV1` (`consent_profile_digest`, `purpose_digest`, `data_class_digest`). PR #6325's constructor only checks caller-supplied values are nonzero. Xenia has recommended that ROS-005 simplify to one exact `ConsentId` plus authenticated record retrieval, `validate_identity()` and owner-native `Consent::authorize()`; alternatively ROS-004 must expose a versioned owner-generated projection object with known-answer vectors. Until one is implemented and qualified, the 3-slot mapping remains UNSUPPORTED. Never synthesize independent hashes in Xenia or treat arbitrary nonzero digests/a `ConsentId` alone as a consent decision. |
| `operation` | `AnyWithinProfile` only for an explicitly bounded session/lane profile; `ExactDigest` where a single immutable operation can be canonically identified | Exact digest must bind the full operation and schema/profile. Do not reuse a friendly request ID or session ID as the operation digest |
| `budgets.max_duration_ms` | Maximum delegated session/lane lease horizon | Milliseconds are a duration, not an absolute timestamp. Shorten to the tighter local session/consent horizon |
| `budgets.max_operations` | Maximum admitted operations under the delegation | Static upper bound only; durable shared consumption remains a separate required owner protocol |
| `budgets.max_bytes` | Maximum disclosure or transfer volume for the bound scope | Define whether bytes count read, admitted, dispatched or committed; do not charge or reset at a child boundary without shared accounting |
| `budgets.max_concurrent` | Maximum concurrent operations/streams | Static bound only; admission/lease ownership must prevent sibling sessions from multiplying the parent's capacity |
| `budgets.max_targets` | Maximum distinct host/object targets | Target identity must be canonical and exact |
| `budgets.rate_limit` | Per-operation/stream admission rate | The v1 definition is a rolling-window limit. A static scope is not a rate meter; enforcement must use a durable or otherwise qualified shared consumption boundary |

### Profile composition and non-claims

1. The typed profile's `is_no_wider_than` and `is_strictly_attenuated_by` compare only the new v1 typed dimensions. They do not prove delegation authenticity, parent record retrieval, current status, authority epoch currentness, consent validity, budget consumption, or effect permission.
2. PR #6325 keeps base ROS-005 v1/v2 exact-name semantics unchanged and is not wired into `Delegation`. Xenia must not construct a typed scope and then assume the existing ROS-005 `authorize` call enforced it.
3. Parent-chain validation remains owned by Mycelix #3677/#3680 and open PR #3679. The typed-scope comparison must eventually be replayed against the exact addressable parent records, not a caller-supplied containment boolean.
4. ROS-004 owns consent semantics and validity. Open Mycelix [PR #3692](https://github.com/Luminous-Dynamics/mycelix/pull/3692), exact head `38d0af4f4c86ed1ace883919395593333521e31a`, proposes a domain-separated whole-consent canonical identity, `validate_identity()` and a separate lifecycle projection. The candidate's canonical bytes bind purpose and disclosure scope/data classes as part of one immutable consent record; they do not expose separate projection digests for the three `ConsentBindingV1` fields. No workflow was reported for this exact head at the last check. Prefer one owner-issued `ConsentId` plus authenticated record retrieval, identity validation and `Consent::authorize()`; alternatively ROS-004 must expose a versioned, owner-generated three-part commitment with known-answer vectors. A commitment/ID is not a consent decision.
5. The base ROS-005 `i64` grant/request/revocation time and authority epoch still need owner-standardized units/epoch and authenticated source evidence. The typed profile's `max_duration_ms` and rolling `window_ms` do not resolve that absolute-time ambiguity.
6. The typed profile contains no explicit Xenia session fingerprint or rekey epoch. Xenia must continue to bind session/rekey identity locally and must reject stale queued work after rekey/reconnect until a future versioned owner contract defines a stronger mapping.
7. Static budget limits do not reserve or consume capacity. Mycelix #6302/#507 must define durable, concurrent sibling consumption and crash recovery before these ceilings can be described as enforced cumulative limits.
8. Mycelix #4903/#6236 still own currentness under delayed DHT visibility and trajectory-wide revocation propagation. Holochain 0.7.1 qualification remains under #5719 and is incomplete.

**Integration gate:** Xenia may implement a typed adapter only after the Mycelix typed profile is merged, its canonical and containment tests are independently qualified, it is connected to the base ROS-005/parent-chain API, and the currentness/time/identity contracts are explicit. Until then the typed-scope dimension is `UNSUPPORTED` for live enforcement and must remain `HOLD/INDETERMINATE`, not a locally reconstructed permit.
