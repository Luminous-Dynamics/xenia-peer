# Xenia Remote Administration Broker v1

Status: architecture/convergence contract; no production-readiness claim

## Purpose

Xenia should be the canonical remote-access and session-security broker for Luminous Edge and small-business administration, but the repository already contains substantially more remote-authority work than a new product layer should recreate.

This document therefore freezes a **convergence architecture**: reuse the live support-session permission model plus the existing draft privileged-operation stack, then add only protocol/adaptor-specific integration for SSH, RDP, OOB recovery, and Nixward request handoff.

## Core authority theorem

```text
Xenia session authorization
    !=
Xenia privileged-operation authorization
    !=
Nixward mutation authorization
```

Xenia owns remote-session security and concrete session-bound access authority. Nixward remains independently authoritative for managed system/network realization on Luminous Edge.

A valid Xenia operator session must never become a generic root/admin bypass around Nixward.

## Authority ownership matrix

| Concern | Canonical owner | Remote-admin rule |
|---|---|---|
| display/input/audio/clipboard/file support powers | current M1 permission model | reuse; no new capability enum |
| command vs interactive terminal authority | #173 execution sidecar | default-off; never inherited from historical broad M1 consent |
| execution advertisement / authenticated session binding | #174 + negotiated-context line | reuse/version; no parallel handshake metadata |
| concrete privileged service/resource authority | #175 `CapabilityGrantV1` / `CapabilityUseV1` | reuse for SSH/RDP/OOB/Nixward-request adapters |
| exact one-shot native execution semantics | #172 `xenia-exec-proto` | direct structured invocation; no implicit shell |
| admission/use-slot persistence and receipts | #178 onward | must precede consequential adapter effects |
| authority epoch/global revoke/recovery | #190 onward | adapters consume current authority; they do not invent recovery semantics |
| effect-start/revocation linearization | #201 | required before real privileged side effects |
| causal/negotiated transport authority | xenia-wire authority line | consume typed verified state; no generic bearer-token replacement |
| Luminous Edge system/network mutation | Nixward | Xenia may transport/request; Nixward independently authorizes |

## Existing live support-session authority — reuse as-is

Current `xenia-peer-core` already has a direction-separated `M1PermissionSet` for ordinary support-session powers:

- display/frame streaming;
- telemetry streaming;
- audio streaming;
- input injection;
- host clipboard read;
- host clipboard write;
- host -> viewer file transfer;
- viewer -> host file transfer.

These permissions are enforced at use sites and are cleared on revoke/end/failure. View-only remains a first-class session.

The clipboard and file protocols, lane-separated sealed transport, file hashes, transfer staging, ledger/evidence, secure-file work, and platform capture/input abstractions are existing providers. Remote admin must not define parallel versions.

## Existing draft execution/operation authority — canonical direction

### #172 — native execution contract / SSH boundary

`xenia-exec-proto` already defines the intended one-shot native execution semantics:

- structured executable + argv; no shell-command-string field;
- exact invocation allowlists rather than arbitrary args;
- explicit cwd/environment commitments;
- bounded output/runtime/concurrency;
- deny-by-default;
- V1 refuses stdin, PTY, elevation and forwarding;
- SSH is an interoperability edge, not the Xenia authority root.

### #173 — execution authority sidecar

Execution intentionally does **not** extend historical `M1PermissionSet` because broad legacy grants such as `M1PermissionSet::all()` must not gain process execution through a library upgrade.

It defines a separate default-off authority surface:

- `ExecuteCommand`;
- `OpenInteractiveTerminal`.

Command execution and terminal authority remain independent.

### #174 — authenticated capability binding

`RawCapabilitiesV2` / `NegotiatedSessionContextV5` bind the exact advertised execution-policy digest into the authenticated negotiated-session context, with a fail-closed legacy-decoder boundary.

This is the correct direction for capability advertisement. Remote admin should not add a second capability advertisement format.

### #175 — privileged operation grants

`xenia-operation-proto::CapabilityGrantV1` is the canonical candidate for privileged remote-operation authorization.

It already binds:

- authenticated session;
- authenticated subject;
- exact resource/action rules;
- optional exact request/parameter commitment;
- policy commitment;
- approval commitment;
- purpose commitment;
- bounded validity window;
- finite use budget;
- live reevaluation before every use.

`ResourceKindV1` already includes resource namespaces suitable for `tcp-service`, `redfish`, `nix-store`, and Xenia hosts. `OperationClassV1` already includes `Observe`, `Mutate`, `Execute`, `ConnectService`, `UseCredential`, and `Recover`.

The grant is session-bound authority, not a portable bearer credential.

### #178 onward — effect safety and recovery

The privileged-operation line already goes beyond authorization into durable effect safety:

- #178 durable admission / at-most-once local use-slot reservation;
- #180 receipt-store and anti-rollback contract;
- #181 authenticated store-frontier lineage;
- #184 executable reference store model;
- #185 conservative SQLite admission-store experiment;
- #187 component-wise Unix path-trust primitive;
- #189 Linux authority-root deployment profile;
- #190 authority epochs / global revocation;
- #191 governed recovery ceremony;
- #195 epoch-bound authority chain;
- #197 consolidated recovery-safe authority v2 candidate;
- #199 store-authenticated persistence proofs;
- #201 invocation-start vs revocation linearization fence.

These drafts are not all qualified/merged, but they are the existing semantic lineage. Remote administration must converge on them instead of starting another PAM/JIT authority stack.

## Existing xenia-wire authority — do not duplicate

The wire repository already has draft request-bound causal authority, negotiated capability/context evidence, owned negotiated-authority typestates, rekey lineage, and exact-action commitments.

Remote administration consumes those results when they mature; it must not create a parallel generic bearer-token or tunnel-authority protocol.

## No new `RemoteSessionIntentV1`

The earlier draft of this document proposed a generic `RemoteSessionIntentV1` plus another `RemoteCapability` enum. That would duplicate existing authority concepts and is withdrawn.

Remote administration instead composes three existing layers:

```text
ordinary support content/UI powers
    -> M1PermissionSet

command / interactive terminal powers
    -> M1ExecutionPermissionSet (#173)

privileged adapters / services / recovery / credentials
    -> CapabilityGrantV1 + exact CapabilityUseV1 (#175 lineage)
```

Human-readable support purpose and consent scope still matter, but enforcement authority comes from the existing canonical typed contracts.

## Access modes

### 1. Native Xenia support

Use the existing M1 permission model for display/input/audio/clipboard/file capabilities. No new remote-admin capability enum is required.

For native one-shot command or interactive terminal, consume the separate execution sidecar and the privileged-operation durability gates before any runtime effect is enabled.

### 2. SSH compatibility adapter

SSH remains an interoperability edge.

Target shape:

```text
live authenticated Xenia session
  + CapabilityGrantV1
      resource = exact tcp-service / SSH endpoint
      class = ConnectService
      exact request commitment
  -> ephemeral SSH bridge
  -> SSH performs endpoint/user authentication
```

Properties:

- no public persistent port 22 is required by the product;
- exact endpoint/host-key policy is separately validated;
- `ConnectService` does not imply shell/native-exec authority;
- credential use, if provided later, requires a separate `UseCredential` rule and never implies credential disclosure;
- generic port forwarding is not inherited from SSH merely because the bridge is authorized;
- revoke/expiry tears down the bridge.

### 3. RDP compatibility adapter

RDP uses the same `ConnectService` authority shape rather than inventing `TunnelRdp` as a generic Xenia power.

Windows/RDP remains responsible for endpoint/user authentication and RDP security semantics.

Separate adapter policy gates must cover:

- exact target/service;
- clipboard redirection;
- drive redirection;
- printer/device redirection;
- audio;
- smart-card/credential behavior;
- session lifetime and teardown.

Restricted Admin and Remote Credential Guard are separate qualification profiles. Tunnel existence does not prove either one.

### 4. Out-of-band recovery adapters

Redfish, IPMI, AMT/vPro, KVM-over-IP, serial console and smart-PDU operations should map onto existing privileged-operation resource/action classes.

Examples:

```text
Observe        -> read chassis/health state
ConnectService -> bounded console/KVM access
Recover        -> approved reset/recovery operation
UseCredential  -> bounded credential use without disclosure
Mutate         -> exact OOB configuration change where separately admitted
```

Redfish already appears in the #175 resource model; do not create a second recovery grant system.

## Adapter contract

Every new compatibility adapter must be deliberately boring. It receives already-validated authority and narrows it into one protocol operation; it does not define policy.

Minimum adapter inputs should be conceptually equivalent to:

```text
verified live session/context
+ exact CapabilityUse / current authority chain
+ exact adapter request digest
+ endpoint identity/configuration
+ current revoke/expiry/epoch state
```

Every adapter must declare:

- the exact irreversible/start boundary;
- whether the operation is replayable, idempotent, transaction-recoverable, or non-replayable;
- what positive evidence can prove `NotStarted`, `Started`, `Completed`, `FailedKnown`, or `OutcomeUnknown`;
- what is payload/content and therefore excluded from ordinary receipts;
- what credential material it needs, if any, and whether it can use it without disclosure;
- what teardown means when Xenia authority is revoked mid-operation.

An adapter may not weaken the parent authority contract merely because its underlying protocol is broad.

## Luminous Edge / Nixward boundary

For an Edge appliance:

```text
operator
  -> Xenia authentication / host evidence / session consent
  -> exact Xenia grant/use permits submission of one request
  -> typed Nixward request
  -> Nixward independently validates current subject/state/authority
  -> Nixward realizes or rejects
  -> Nixward terminal receipt
  -> Xenia displays/binds receipt reference
```

The Xenia grant authorizes **request delivery/use of the administrative channel**. It does not convert into Nixward authority by reinterpretation.

A direct unrestricted root shell is not the normal Edge administration path. If an emergency recovery shell is ever supported, it is a separately governed break-glass profile and cannot silently preserve normal production assurance.

## Unattended support

Do not implement unattended support as a permanent session or evergreen bearer credential.

Preferred shape:

```text
explicit device enrollment
  + policy identifying eligible operators/actions/time bounds
  -> fresh authenticated Xenia session
  -> fresh short-lived grant derived under that policy
  -> normal live reevaluation / revoke / receipt path
```

The enrollment authorizes issuance conditions; it is not itself an active remote-control session.

## Break-glass

Break-glass is also an **issuance/recovery policy**, not a separate bypass authority model.

It should require stronger approval/evidence, a very short validity window, explicit reason/purpose commitment, visible state, and post-event receipt/review. On a Nixward-managed Edge device, break-glass that bypasses normal realization must downgrade/void the relevant production assurance until requalification.

## Content retention

Default durable evidence should contain authority/session metadata and operation receipts, not support-session content.

Default-off content retention:

- screen recording;
- audio recording;
- clipboard content logging;
- keystroke logging;
- transferred-file plaintext duplication beyond the file-transfer/storage contract;
- terminal/stdout content unless an explicit evidence profile requires it.

Content recording is a separate visible, retention-bounded policy and must not be inferred from session authorization.

## Revised implementation sequence

Do not start with a new generic session-intent crate.

1. Reconcile and qualify the existing #172 -> #175 authority stack against current main.
2. Converge #178 -> #201 into the smallest current privileged-effect lineage required before a real adapter can act.
3. Preserve existing M1 permissions for screen/input/audio/clipboard/file.
4. Land the first adapter as an exact `ConnectService` proof — SSH is preferred because it tests service tunneling without needing a new desktop protocol implementation.
5. Add RDP as another `ConnectService` adapter with redirection policy and Windows-specific qualification.
6. Add Redfish/OOB recovery adapters using the existing resource/action classes.
7. Add Xenia -> Nixward request handoff, with Nixward independently authorizing every managed Edge mutation.
8. Only then define unattended and break-glass issuance profiles on top of the same authority stack.

## Required negative tests

- historical broad M1 consent cannot gain execute/terminal/service-connect authority;
- view-only cannot inject input or transfer files;
- `ConnectService` cannot become `Execute`;
- SSH service grant cannot open an arbitrary target/port;
- RDP grant cannot silently enable clipboard/drive/device redirection;
- `UseCredential` never permits credential disclosure;
- expired/revoked session invalidates adapter use;
- stale authority epoch invalidates outstanding privileged grants;
- crash/ambiguous external effect does not trigger blind retry;
- Xenia-authorized request rejected by Nixward does not execute anyway;
- direct shell mutation of a managed Edge cannot be represented as a successful Nixward receipt;
- break-glass use invalidates normal assurance until explicit requalification where applicable.

## Qualification boundary

Many of the execution/operation components above are open draft stacks rather than merged production authority. Their existence is implementation/review input, not a production-readiness claim.

In particular, the current #175 exact head has not earned a complete green qualification result. Remote-admin integration must not promote those draft semantics merely by depending on them.

## Non-goals

- reimplement RDP;
- replace SSH endpoint authentication;
- create a second generic Xenia grant/capability system;
- merge support-session permissions and privileged-effect authority into one broad role;
- make Xenia an alternate Nixward execution engine;
- provide invisible/permanent unattended access;
- claim adapter or Windows credential-security behavior before platform qualification.

Related: #172, #173, #174, #175, #178, #201, #216, #392 and xenia-wire causal/negotiated-authority work.
