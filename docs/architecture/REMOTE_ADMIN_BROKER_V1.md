# Xenia Remote Administration Broker v1

Status: architecture contract; no production-readiness claim

## Purpose

Xenia already implements the core primitives of a secure remote-session stack: screen capture, input injection, video transport, PQC-sealed transport, host trust, operator RBAC, consent, and revocation. The next product boundary is to make those primitives the canonical privileged remote-access broker for Luminous Edge and small-business administration without turning Xenia into an unrestricted remote-command bypass.

## Core theorem

```text
remote session authorized
    !=
remote mutation authorized
```

Xenia owns remote session security. A downstream authority such as Nixward owns managed system/network mutation admission.

## Existing substrate to reuse

- `xenia-capture`: display/audio/input/telemetry ingestion boundary;
- `xenia-inject`: platform input injection;
- `xenia-video`: video codec/render pipeline;
- `xenia-transport-quic` / `xenia-transport-ws`: transports;
- `xenia-handshake` + xenia-wire: sealed cryptographic session;
- `xenia-operator-proto`: canonical RBAC/action/signing transcripts;
- `xenia-operator-agent-proto`: native operator-agent signing delegation and host-trust-aware request shapes;
- `xenia-ledger`: consent/audit evidence;
- `xenia-secure-file`: future file-transfer provider once its product path is separately qualified.

Do not fork these primitives into a parallel `xenia-rdp` remote-control stack.

## Access modes

### 1. Native Xenia support session

Strongest Xenia-native path. Capabilities are independently scoped:

- display view;
- keyboard/pointer/touch control;
- clipboard read;
- clipboard write;
- file upload;
- file download;
- audio;
- shell/PTY;
- typed downstream administrative request.

View-only is a first-class session. No capability implies another.

### 2. SSH compatibility bridge

Xenia authorizes an ephemeral exact-target bridge. SSH still authenticates the endpoint and user.

Do not store SSH passwords in Xenia. Prefer exact host-key binding plus short-lived certificates or hardware-backed credentials where practical.

### 3. RDP compatibility bridge

Use when Windows RDP semantics are operationally valuable.

- never make public TCP/3389 the product default;
- exact target is bound into the Xenia session intent;
- bridge lifetime is bounded by the Xenia session;
- Windows/RDP performs its own authentication;
- Xenia does not inject stored Windows passwords;
- clipboard, drive, printer, audio, smart-card and device redirection are separate capabilities;
- Restricted Admin and Remote Credential Guard require separate qualification and must not be inferred from tunnel existence;
- prefer Native Xenia for helpdesk control when minimizing credential delegation is the primary requirement.

### 4. Out-of-band rescue bridge

Potential providers:

- Redfish/BMC;
- IPMI where unavoidable;
- Intel AMT/vPro;
- KVM-over-IP/PiKVM-class devices;
- serial console;
- smart PDU/power controller.

OOB provider authentication remains independently enforced. Power/reset is a destructive capability and must be separately authorized.

## Typed session scope

A future schema should replace coarse scope strings with a canonical structure before signature:

```rust
pub struct RemoteSessionIntentV1 {
    pub target_device_digest: [u8; 32],
    pub target_endpoint_digest: [u8; 32],
    pub requested_capabilities: BTreeSet<RemoteCapability>,
    pub local_consent_policy: LocalConsentPolicy,
    pub unattended_policy_digest: Option<[u8; 32]>,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub reason_digest: [u8; 32],
}
```

Candidate capabilities:

```rust
pub enum RemoteCapability {
    ViewDisplay,
    InjectInput,
    ClipboardRead,
    ClipboardWrite,
    FileUpload,
    FileDownload,
    AudioReceive,
    AudioTransmit,
    Shell,
    TunnelSsh,
    TunnelRdp,
    RequestManagedChange,
    PowerCycle,
}
```

The exact serialized intent digest should be included in the operator approval transcript. A human-readable description may accompany it but is never the signed authority by itself.

## Session lifecycle

```text
target discovery
  -> host identity verification / pin policy
  -> operator authentication
  -> exact typed intent
  -> local or enrolled unattended consent policy
  -> operator approval signature
  -> sealed channel
  -> least-capability grant
  -> live revoke remains active
  -> session close
  -> terminal session receipt
```

## Managed-device boundary

For Luminous Edge:

```text
Xenia
  authenticate + attest + transport + remote UX
             |
             v
      typed Nixward request
             |
             v
Nixward independently validates authority/current state
             |
             v
       realization/rollback
             |
             v
       terminal receipt
```

An unrestricted root shell on a managed Edge device is not equivalent to an authorized Nixward change and should not be the normal administration path.

Emergency recovery can exist as a separately enrolled break-glass policy with stronger confirmation, short expiry and mandatory receipt.

## Unattended access

Unattended support is an explicit policy object, not implicit background control. It should bind allowed operators, device identity, capabilities, maximum duration, time windows where relevant, indicator/notice policy, expiry, revocation and recording policy.

## Content retention

Default receipt evidence should cover session metadata, authorization scope, host/operator identities, times, revocation and terminal state. Screen/audio/clipboard content is not persisted by default. Any content recording mode is separate, visible and retention-bounded.

## Qualification before product claims

- Native Xenia session across supported OS targets;
- session-capability denial tests;
- revoke during active input/file/tunnel activity;
- target identity rotation/spoof tests;
- SSH bridge host-auth tests;
- RDP Restricted Admin qualification;
- RDP Remote Credential Guard qualification only where Microsoft prerequisites are met;
- clipboard/drive redirection negative tests;
- OOB power/reset destructive-capability tests;
- Nixward-bypass negative tests on Luminous Edge.

## Non-goals for this tranche

- reimplement the RDP protocol;
- replace SSH authentication;
- claim Windows credential-security behavior without qualification;
- enable invisible/unbounded unattended access;
- make Xenia an alternate Nixward execution engine.

Related: #392.
