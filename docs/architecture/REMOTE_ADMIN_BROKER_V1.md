# Xenia Remote Administration Broker v1

Status: architecture/convergence contract; no production-readiness claim

## Purpose

Xenia should be the canonical remote-access and session-security broker for Luminous Edge and small-business administration, but the repository already contains substantially more remote-authority work than a new product layer should recreate.

This document therefore freezes a **convergence architecture**: reuse the live support-session permission model plus the existing draft privileged-operation stack, then add only protocol/adaptor-specific integration for SSH, RDP, OOB recovery, and Nixward request handoff.

The broader authority-stack ordering and consolidation work belongs to existing authority-convergence PR #216. This remote-admin tranche consumes that convergence; it does not create another consolidation roadmap.

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
| protected file transfer/disclosure | existing file-transfer + SIF/secure-file lines | reuse; do not build a remote-admin uploader |
| command vs interactive terminal authority | #173 execution sidecar | default-off; never inherited from historical broad M1 consent |
| execution advertisement / authenticated session binding | #174 + negotiated-context line | reuse/version; no parallel handshake metadata |
| concrete privileged service/resource authority | #175 `CapabilityGrantV1` / `CapabilityUseV1` | reuse for SSH/RDP/OOB/Nixward-request adapters |
| exact one-shot native execution semantics | #172 `xenia-exec-proto` | direct structured invocation; no implicit shell |
| admission/use-slot persistence and receipts | #178 onward | must precede consequential adapter effects |
| authority epoch/global revoke/recovery | #190 onward | adapters consume current authority; they do not invent recovery semantics |
| effect-start/revocation linearization | #201 | required before real privileged side effects |
| cross-cutting authority convergence | #216 | remote admin follows this ordering rather than defining another stack |
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

The clipboard and file protocols, lane-separated sealed transport, file hashes, transfer staging, ledger/evidence, secure-file work, and the later SIF protected-file authority/disclosure line are existing providers. Remote admin must not define parallel versions.

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

## No new generic remote-admin authority schema

The earlier draft proposed a generic `RemoteSessionIntentV1` plus another `RemoteCapability` enum. That would duplicate existing authority concepts and is withdrawn.

Remote administration instead composes three existing layers:

```text
ordinary support content/UI powers
    -> M1PermissionSet

command / interactive terminal powers
    -> M1ExecutionPermissionSet (#173)

privileged adapters / services / recovery / credentials
    -> CapabilityGrantV1 + exact CapabilityUseV1 (#175 lineage)
```

## Access modes

### Native Xenia support

Reuse M1 plus existing capture/input/video/clipboard/file/ledger providers. For one-shot command or interactive terminal, consume the execution sidecar and the eventual qualified privileged-effect path.

### SSH compatibility adapter

SSH remains an interoperability edge. Use an exact `ConnectService` grant to one authenticated SSH endpoint. `ConnectService` does not imply native `Execute`, arbitrary port forwarding, or credential disclosure. Revoke/expiry tears down the bridge.

### RDP compatibility adapter

Use the same `ConnectService` family. Windows/RDP retains endpoint and user authentication. Clipboard, drives, devices/printers, audio and credential/smart-card redirection are separately policy-gated. Restricted Admin and Remote Credential Guard require separate qualification.

### OOB recovery adapters

Map Redfish/BMC, AMT/vPro, KVM-over-IP, serial and smart-power operations onto existing `Observe`, `ConnectService`, `Recover`, `UseCredential` and exact `Mutate` classes rather than defining another recovery grant system.

## Adapter contract

Adapters receive already-validated authority and narrow it to one protocol operation. They do not define policy.

Every adapter must identify its exact start/irreversible boundary, replay/idempotency class, outcome evidence, content-vs-receipt boundary, credential requirements, and revoke-time teardown semantics.

## Luminous Edge / Nixward handoff

```text
operator
  -> Xenia authentication / host evidence / session consent
  -> exact Xenia grant/use permits submission of one administrative request
  -> Nixward independently validates current subject/state/authority
  -> Nixward realizes or rejects
  -> Nixward terminal receipt
  -> Xenia displays/binds receipt reference
```

The Xenia grant authorizes request delivery/use of the channel. It does not become Nixward authority by reinterpretation.

## Unattended and break-glass

Unattended support is an explicit enrollment/issuance policy producing fresh short-lived sessions/grants; it is not permanent access.

Break-glass is an exceptional issuance/recovery policy over the same authority system. If it bypasses normal Nixward realization on a managed Edge device, affected production assurance must be downgraded until requalification.

## Content retention

Default durable evidence records authority/session metadata and terminal operation receipts, not screen/audio/clipboard/keystroke/terminal content. Protected file transfer reuses the existing file/SIF/secure-file line.

## Revised implementation sequence

1. Let #216 own cross-cutting authority convergence and current-base ordering.
2. Reconcile/qualify the minimum #172/#173/#174/#175 surface required for remote adapters.
3. Consume the minimum durable-effect/recovery chain selected by #216 before consequential adapter effects.
4. Implement SSH as the first exact `ConnectService` adapter.
5. Implement RDP as another adapter with Windows-specific redirection/security qualification.
6. Add Redfish/OOB adapters.
7. Add Xenia -> Nixward exact-request handoff.
8. Add unattended/break-glass issuance profiles only after the same authority stack is working.

## Qualification boundary

The execution/operation components referenced here are largely open draft stacks, not merged production authority. The current #175 head has workflow runs that are not an all-green qualification result. Remote admin must not promote those semantics merely by referencing them.

Related: #172, #173, #174, #175, #178, #201, #216 and #392.
