# Remote Admin Existing Work Index v1

Status: navigation aid; evidence/qualification status remains owned by each referenced PR

This index exists to prevent remote-administration work from recreating capabilities that Xenia already has in live main or open authority branches.

## Live/current support-session substrate

- M1 direction-separated support permissions: frame, telemetry, audio, input, clipboard read/write, file send/receive.
- scoped consent + revoke/end/failure clearing.
- sealed lane transport for input/clipboard/file.
- clipboard protocol and file Offer/Accept/Reject/Chunk/Complete/Verified semantics.
- operator RBAC, signed consent scope, host trust and operator-agent delegation.
- protected file/SIF/secure-file research line.

## Draft privileged-operation lineage

- #172 native exec contract + SSH boundary.
- #173 default-off command/interactive-terminal authority sidecar.
- #174 authenticated capability/policy-digest binding.
- #175 session-bound finite-use privileged-operation grants.
- #178 durable admission/receipt boundary.
- #180 receipt store + anti-rollback.
- #181 authenticated frontier.
- #184 reference operation-store model.
- #185 SQLite admission-store experiment.
- #187 Unix path trust.
- #189 Linux authority-root deployment profile.
- #190 authority epochs/global revocation.
- #191 governed recovery.
- #195 epoch-bound authority wrappers.
- #197 consolidated recovery-safe authority v2 candidate.
- #199 store-authenticated persistence proofs.
- #201 invocation-start/revocation fence.
- #216 cross-cutting authority convergence roadmap.

## xenia-wire supporting authority work

The wire repo already carries draft request-bound causal authority, negotiated capability/context evidence, owned negotiated-authority typestates and rekey/authority lineage. Remote-admin adapters consume the qualified result rather than introducing a generic tunnel token.

## Remote-admin gaps that remain real

- exact SSH `ConnectService` runtime adapter;
- exact RDP `ConnectService` runtime adapter and Windows qualification;
- OOB adapters (Redfish/AMT/KVM/serial/power);
- Xenia -> Nixward exact-request handoff;
- unattended-support issuance profile;
- break-glass issuance/recovery profile;
- cross-platform product qualification and operator UX.

## Rule

Before creating a new remote-admin crate or protocol type, search this index and the referenced authority line. New generic authority requires an explicit architecture review demonstrating that the existing canonical abstraction cannot express the requirement.
