# ADR-004: Native execution is a Xenia capability; SSH is an interoperability edge

**Status:** proposed
**Date:** 2026-08-28
**Deciders:** Luminous Dynamics / Xenia maintainers
**Related:** `docs/architecture/OSI_SECURITY_PLANE.md`, `docs/security/AUTHENTICATED_SESSION_SURFACE.md`, `docs/security/CONSENT_AND_ABUSE_CASES.md`, `crates/xenia-peer-core/src/m1_session.rs`

## Context

Xenia already has authenticated, transcript-bound sessions; immutable negotiated
capabilities; operation-specific M1 consent; revocation; operator RBAC; and a
consent/evidence ledger. Remote administration needs command execution and,
eventually, an interactive terminal, but adding an SSH server as the primary
implementation would put a second trust and authorization model beside Xenia's
existing one.

SSH remains important because it is the installed interoperability surface for
servers, appliances, development environments, and automation. The architectural
question is therefore not whether Xenia should interoperate with SSH, but which
system owns authority.

## Decision

### 1. Xenia owns native execution semantics

The primary remote-execution surface is a Xenia application capability carried
inside an authenticated Xenia session. The first implementation is structured,
one-shot execution. Interactive PTY/terminal access is a later and separately
authorized capability.

The protocol must represent an executable and argument vector separately. V1
must not contain a shell command string and the host runtime must not implement
one-shot execution with `sh -c`, `cmd /C`, PowerShell string interpolation, or
an equivalent implicit shell.

### 2. SSH is an adapter, never the Xenia authority root

A future `xenia-ssh-bridge` may invoke a mature SSH implementation to reach
legacy hosts or expose carefully-scoped compatibility behavior. Successful SSH
authentication does not create a Xenia capability and must not widen an already
negotiated Xenia capability surface.

The bridge defaults to no agent forwarding, no X11 forwarding, no port
forwarding, no local-command hooks, and no PTY unless the corresponding Xenia
capability was explicitly granted.

### 3. One-shot execution and interactive terminal are distinct privileges

At minimum, M1 authorization distinguishes:

- `ExecuteCommand`: structured one-shot process execution;
- `OpenInteractiveTerminal`: PTY allocation and interactive stdin/output.

Neither implies elevation, credential delegation, tunneling, forwarding, or
background persistence. Those require separate future capabilities if ever
implemented.

### 4. Capability availability is committed before privileged payloads

Execution availability and its policy digest must become part of Xenia's
authenticated session surface before an execution request can be processed.
A duplicate capabilities frame is not a renegotiation mechanism. Enabling or
widening execution after the capability surface was authenticated requires a
fresh handshake and consent flow.

### 5. Consent binds the human-visible scope to an execution policy digest

Execution is disabled by default. When enabled, the offered consent scope must
identify the execution class and commit to a deterministic policy digest. The
policy describes, at minimum:

- allowed executable identities/paths;
- allowed working-directory roots;
- allowed environment keys;
- runtime and output ceilings;
- maximum concurrent processes;
- execution identity policy;
- whether stdin, PTY, elevation, or forwarding are allowed.

The existing operator `scope_digest` binding remains the outer human-approval
commitment. The execution policy digest is part of that scope rather than a
replacement for consent.

### 6. Authorization evidence precedes process creation

The runtime sequence for a privileged execution is:

1. authenticate the session surface;
2. verify M1 permission and the execution-policy match;
3. validate the request against finite protocol/runtime limits;
4. durably record authorization evidence;
5. only then create the process.

If required authorization evidence cannot be durably committed, the process is
not created.

Stdout/stderr contents are not ledgered by default. Evidence should record the
request/policy digest, executable identity, timing, exit/termination status,
byte counts, truncation, and operator/session attribution without turning
command output into a secret-retention mechanism.

### 7. Resource semantics are finite and fail closed

The execution protocol and runtime have explicit limits for request size,
argument/environment cardinality, output chunk size, total output, runtime,
and concurrent processes. Unknown protocol revisions, malformed requests,
wrong-direction payloads, replayed envelopes, unsupported features, and policy
mismatches are rejected before process creation.

Cancellation, consent revocation, transport/session failure, and normal session
teardown must not leave an authorized process running beyond the lifetime its
policy permits. The interactive-terminal tranche must additionally guarantee
PTY and process-tree teardown.

### 8. Initial wire placement uses the control security domain

Low-volume one-shot execution control messages may initially use the existing
control cryptographic lane with distinct host-origin and viewer-origin payload
types, following the file-transfer nonce-domain precedent.

Interactive terminal traffic is expected to justify a dedicated terminal key
and, eventually, a separately authenticated transport profile/QUIC stream. That
change must be explicit; it must not silently alter the current lane count or
transport profile.

## Initial implementation sequence

1. **Contract:** add `xenia-exec-proto`, canonical policy/request/message types,
   validation limits, deterministic policy digests, and vectors/tests. No I/O or
   process spawning.
2. **Authority:** add M1 execution permissions and authenticated execution
   advertisement/policy commitment, with viewer/daemon compatibility updates.
3. **One-shot runtime:** direct argv process creation, bounded output/runtime,
   cancellation/revocation teardown, and audit-before-effect.
4. **Interactive terminal:** PTY lifecycle, resize/signal/stdin semantics,
   dedicated lane/key as justified, and terminal UI/CLI.
5. **SSH bridge:** hardened interoperability adapter using a mature SSH
   implementation; Xenia remains the authority root.

## Consequences

### Accepted

- Xenia gains a remote-administration path that composes with its existing
  consent, evidence, transcript, and capability model instead of bypassing it.
- The first useful execution feature is smaller and more auditable than a full
  terminal or SSH server.
- Existing SSH infrastructure remains reachable later without making SSH's
  authentication or forwarding defaults authoritative inside Xenia.
- A future terminal can evolve its own lane and flow-control policy without
  prematurely changing the current transport/session contract.

### Explicitly out of scope for the contract tranche

- spawning a real process;
- PTY allocation;
- shell command strings;
- privilege elevation;
- SSH client/server implementation;
- agent/X11/TCP forwarding;
- unattended access policy;
- background/detached process persistence.
