# Xenia SSH ConnectService Adapter v1

Status: adapter contract only; blocked on qualified parent authority

## Purpose

Define the first remote-administration compatibility adapter without adding a new generic authority model.

The adapter consumes an already-valid Xenia privileged-operation authority for one exact SSH service and provides an ephemeral transport path. SSH remains responsible for SSH host/user authentication.

## Parent authority

The adapter must consume the canonical authority lineage selected/qualified by #216, with #175 `CapabilityGrantV1` / `CapabilityUseV1` as the current semantic model for exact service access.

Conceptually:

```text
verified Xenia session/context
+ exact current authority
+ CapabilityUse for:
    resource = exact tcp-service / SSH endpoint
    class = ConnectService
    request commitment = exact adapter request
+ current epoch/revoke/expiry state
-> bounded SSH bridge
```

The adapter may not mint, widen, refresh or reinterpret authority.

## Exact request

The eventual request must bind at least:

- exact target/service identity commitment;
- exact port/service profile;
- expected SSH host-key policy commitment;
- requested bridge lifetime bounded by parent grant/session;
- direction/topology of the bridge;
- forwarding mode (V1: one target service only);
- credential-use mode, if any, as a separate authority/evidence commitment;
- operation id / exact request digest required by the parent operation stack.

Raw credentials are not part of the request commitment.

## V1 restrictions

V1 intentionally does not provide:

- generic SOCKS proxying;
- arbitrary local/remote/dynamic port forwarding;
- VPN semantics;
- SSH-agent forwarding by default;
- arbitrary credential disclosure;
- a Xenia-owned shell;
- native process execution;
- unattended permanent tunnels;
- public port-22 exposure as a product requirement.

`ConnectService` is not `Execute`.

## Host authentication

Xenia target identity and SSH host identity are separate evidence domains.

A valid Xenia target/session does not prove an SSH host key. The adapter must separately enforce the configured SSH host-key policy and bind the resulting evidence to the adapter receipt.

TOFU may exist only as an explicit profile; managed environments should prefer pinned or organizationally governed SSH host identity.

## Credential boundary

If credential brokering is added later:

```text
UseCredential
!=
DiscloseCredential
```

Credential use needs separate exact authority. The service bridge itself never authorizes reading/exporting a private key or password.

## Lifecycle

```text
validate current parent authority
  -> reserve/admit exact operation under parent durability rules
  -> verify exact SSH endpoint policy
  -> arm bridge effect under parent operation rules
  -> open one bounded service path
  -> live revoke/expiry/epoch checks remain authoritative
  -> close bridge
  -> terminal receipt
```

The exact `EffectArmed` / invocation-start semantics must follow the qualified parent operation store/fence, not be reimplemented here.

## Receipts

Default receipt metadata may include:

- operation/grant/use commitments;
- target service identity commitment;
- SSH host-key evidence commitment;
- open/close/revoke times;
- byte-count buckets if privacy policy permits;
- terminal state.

Do not record SSH plaintext, commands, terminal output, keystrokes or credentials by default.

## Required negative tests

- grant for target A cannot reach target B;
- grant for port/profile A cannot open another service;
- `ConnectService` grant cannot invoke native execution;
- no host-key evidence -> no bridge;
- host-key mismatch -> no bridge;
- revoked/expired/stale-epoch authority tears down or refuses bridge according to the qualified parent contract;
- a failed/ambiguous open cannot cause blind duplicate side effects;
- generic forwarding requests are rejected;
- credential disclosure is impossible through the bridge API;
- bridge shutdown leaves no persistent listener/tunnel.

## Luminous Edge

For managed Edge appliances, SSH is a compatibility/diagnostic access path. A shell command that mutates system/network state does not become a valid Nixward realization receipt merely because the SSH bridge was authorized.

Normal product configuration continues through Nixward's typed authority path.
