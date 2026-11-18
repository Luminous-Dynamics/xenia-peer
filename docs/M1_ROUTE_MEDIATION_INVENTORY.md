# M1 source-grounded route mediation inventory

**Status:** bounded source inventory for the M1 daemon; not a complete-mediation proof.
**Tracking:** [Xenia #518](https://github.com/Luminous-Dynamics/xenia-peer/issues/518), [Mycelix #6213](https://github.com/Luminous-Dynamics/mycelix/issues/6213), [Mycelix #6236](https://github.com/Luminous-Dynamics/mycelix/issues/6236).
**Related runtime increment:** [Xenia PR #509](https://github.com/Luminous-Dynamics/xenia-peer/pull/509).

## 1. Purpose and claim ceiling

This document records the effect-capable paths visible in the current M1 daemon source and separates the data plane from the operator/consent control plane. It is a review aid and a seed for an executable route registry and bypass corpus.

It does **not** prove:
- that every possible host API, background task, build feature, platform backend, connector or ambient credential has been enumerated;
- that every source route is unreachable by any path outside the listed M1 gate;
- that a local permission check is atomic with a later OS or network effect;
- that Xenia consumes Mycelix ROS-005 or authenticated Mycelix authority-frontier evidence;
- that Holochain 0.7.1, global revocation, or end-to-end security has been qualified.

An incomplete or unverified route inventory is **INDETERMINATE/HOLD**, not PASS.

## 2. Data-plane lane map

The eight stable action identifiers and directions are defined by `M1Permission::{ALL, action_id, direction}` in `crates/xenia-peer-core/src/m1_session.rs`. The gate methods live in `apps/xenia-peer/src/m1_runtime.rs`; daemon ingress/egress is primarily in `apps/xenia-peer/src/main.rs` and file transfer in `apps/xenia-peer/src/file_transfer.rs`.

| Lane / action ID | Direction | Source path and preflight | Final local gate and protected transition | Current evidence limit |
|---|---|---|---|---|
| `StreamFrame` / `xenia.screen.view` | Host → viewer | Main send loop calls `preflight_frame_flow` before `capture.capture` | `allow_frame_flow` before each encoded frame packet is sent | A successful send is not proof that the viewer rendered/displayed the frame |
| `StreamTelemetry` / `xenia.host.telemetry` | Host → viewer | `preflight_telemetry_flow` before `telemetry.poll_samples` | `allow_telemetry_flow` before the telemetry envelope send | Poll and send are local observations; no downstream receipt is inferred |
| `StreamAudio` / `xenia.audio.capture` | Host → viewer | `preflight_audio_flow` before `audio.next_raw_audio` | `allow_audio_flow` before the audio envelope send | Send is not proof of remote playback |
| `ReadHostClipboard` / `xenia.clipboard.read` | Host → viewer | `preflight_host_clipboard_read_flow` before `read_host_clipboard_text` | `allow_host_clipboard_read_flow` before the clipboard envelope send | No clipboard payload is included in audit metadata; send is not proof of viewer receipt |
| `WriteHostClipboard` / `xenia.clipboard.write` | Viewer → host | Inbound clipboard envelope is opened; bidirectional clipboard mode is required | `allow_host_clipboard_write_flow` before `apply_clipboard_content` | OS API success is not proof another process read the clipboard |
| `InjectInput` / `xenia.input.inject` | Viewer → host | Inbound input envelope is opened; `preflight_input_flow` precedes payload decoding | `allow_input_flow` before `SessionInputInjector::process_events` | Injector success is not proof the target application acted on the input |
| `SendFileToViewer` / `xenia.file.send` | Host → viewer | CLI offer: `preflight_file_send_flow` before source open/hash. Each transfer chunk: preflight before `source.next_chunk` | `allow_file_send_flow` before offer send, each chunk send, and completion send | Local transport send is not receiver verification or proof of remote file persistence |
| `ReceiveFileFromViewer` / `xenia.file.receive` | Viewer → host | Incoming offer is evaluated for name/size/concurrency before consent gate; the gate runs before reservation/staging | `allow_file_receive_flow` on offer acceptance, every chunk and before `stager.finish` / final publication | Staging/chunk acceptance differs from verified final publication; receiver-side verification is still not independent physical observation |

### Two-stage control pattern

PR #509 adds or uses a non-auditing, exact-lane preflight to avoid touching a protected source when that lane is already denied. The existing audited lane method remains immediately before the local send/apply/publish boundary.

This is source-work minimization plus a final local check. It is **not** a reservation, lease, one-shot token, linearization point or distributed revocation barrier. A revocation can race after the final local check and before a subsequent asynchronous OS/network effect. Xenia #504 and Mycelix #6193 own that consistency problem.

## 3. Control plane — separate from the eight data lanes

These routes can establish, alter, revoke or audit the human/operator authorization context. They must not be represented as ordinary viewer data permissions.

### Consent decision socket

- Implementation: `apps/xenia-peer/src/consent_server.rs`.
- Entry point: `ConsentServer::run`; shared semantics: `apply_consent_decision`.
- Actions: initial Approve/Deny and subsequent Revoke.
- When operator authentication is disabled, the legacy consent socket accepts the plaintext strings `Approve`, `Deny` and `Revoke`. When required, actions are authenticated/role-authorized and bound to the daemon's session ID and scope digest.
- An authenticated operator audit entry is durably persisted before the decision takes effect; persistence failure refuses the decision.
- Main selects the plaintext consent server or sealed operator channel; they are not both started for the same session in this branch.

### Sealed operator channel

- Implementation: `apps/xenia-peer/src/operator_sealed_channel.rs`.
- Authenticates the operator handshake and role before processing consent actions.
- Supports optional channel rekey; rekey and consent control are control-plane key/session state, not data-lane permission.
- Live operator revocation is checked in the relevant action path.

### Admin HTTP/WebSocket surface

- Router composition: `apps/xenia-peer/src/main.rs` plus `apps/xenia-peer/src/operator_http.rs`.
- Routes enumerated in the current router:
  - `/auth/challenge`
  - `/auth/daemon-identity`
  - `/auth/verify`
  - `/v1/audit/checkpoint`
  - `/v1/audit/ledger`
  - `/operator/revoke`
  - `/operator/replace-key`
  - `/health`
  - `/ws` (admin/governance console WebSocket)
- This list is a source snapshot, not a complete route-policy proof. Each handler's authentication, role, CSRF/CORS, audit and mutation semantics need independent route-specific review. CORS is not authentication.

### Session and transport entry points

- Main data-session transport selection includes TCP, WebSocket and QUIC; `auto` selects among supported transports.
- Consent/operator binding and the data-session listener are distinct sockets/surfaces.
- Reconnect, handshake, session rekey and lane key state must be included in any complete route inventory; this document does not claim those lifecycles preserve or invalidate Mycelix semantic authority because that integration is not present yet.

## 4. File-transfer checkpoints

The receiver/sender dispatcher is `file_transfer::handle_envelope` in `apps/xenia-peer/src/file_transfer.rs`.

Incoming:
1. An Offer is checked for safe name, size ceiling and concurrent-transfer capacity.
2. M1 receive permission is checked before reserving capacity and creating private staging.
3. Every Chunk is checked before the stager writes it.
4. Complete is checked before final stager verification/publication.
5. The receiver returns Verified with its local delivery result.

Outgoing:
1. Initial source open/hash is gated before file access.
2. After Accept, every source chunk is preceded by a lane preflight.
3. A sealed chunk is checked again through `allow_file_send_flow` immediately before network send.
4. Completion is checked again before its send.
5. Receiver verification is a separate message and must not be conflated with sender transport success.

## 5. Known bypass and negative-control requirements

The following are test obligations, not assertions that a bypass currently exists:

- Call the platform input injector without an active `InjectInput` grant.
- Apply clipboard content without `WriteHostClipboard`.
- Read host clipboard data without `ReadHostClipboard`.
- Read audio or telemetry sources without the matching grant.
- Capture screen data without `StreamFrame`.
- Open/read a file or send an offer/chunk/completion without `SendFileToViewer`.
- Stage/write/publish an incoming file without `ReceiveFileFromViewer`.
- Attempt cross-lane confusion (e.g., screen permission used for clipboard, file-send for file-receive).
- Attempt to replay an Approve action across a different session ID or scope digest.
- Attempt unauthenticated operator mutation when operator authentication is required.
- Revoke an operator while an operator channel is live; test rekey/reconnect and stale-session behavior.
- Inject an alternate transport or direct host API path that bypasses the declared M1 runtime.

For each, record the exact effect owner, expected deny/hold result, actual result, and independent observation. A missing route inventory or unavailable effect observation cannot be scored as a pass.

## 6. Integration into LISE

Use this source map as an Xenia-specific producer input to:
- Mycelix #6213: complete mediation and alternate-path bypass;
- Mycelix #6236: per-session/per-route revocation observation and stale-capability exposure;
- Mycelix #6136: exact operation and effectuation correspondence;
- Mycelix #6140: operation evidence provenance and independence;
- Mycelix #6193: one-shot consumption and concurrency/failure histories.

Xenia owns the local route implementation and lane gate. Mycelix LISE owns its generic benchmark oracle, route completeness methodology and cross-system revocation qualification. Do not create a second route graph authority or revocation service here.

## 7. Next implementation steps

1. Convert this table into a machine-readable route registry with exact source symbol references and explicit owner boundaries.
2. Add a CI source-map checker that rejects stale/missing symbols and requires every declared host-effect entry to declare a gate.
3. Add test-only effect sinks for input, clipboard, file publication and media send so bypass attempts are observable without touching a real host.
4. Add route-graph negative controls and positive controls for all eight lanes.
5. Bind route/session receipts to authenticated Mycelix authority currentness only after the ROS-005 content-binding, parent-chain and delayed-DHT currentness contracts are implemented and exposed by their owning Mycelix APIs.
6. Independently qualify the control-plane routes and every enabled build/platform/transport profile.

The machine-readable registry and CI check are not implemented by this document. Documentation alone is not route-completeness evidence.
