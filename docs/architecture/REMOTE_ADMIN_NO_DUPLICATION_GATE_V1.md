# Remote Admin No-Duplication Gate v1

Before any remote-admin PR adds a crate, protocol message, permission, grant, receipt store, transport or credential abstraction, the PR must identify the canonical existing provider and explain why extension/adaptation is insufficient.

Default canonical providers:

- support-session permissions -> current M1 model;
- capture/input/video -> existing Xenia media/platform crates;
- clipboard/file transfer -> existing clipboard/file/SIF lines;
- command/terminal authority -> #173 lineage;
- exact native exec -> #172 lineage;
- privileged resource/service grants -> #175 lineage;
- durable effect admission/receipts/recovery -> #178..#201 / #216 convergence;
- causal/negotiated transport authority -> xenia-wire authority line;
- managed Edge system/network mutation -> Nixward.

A protocol adapter may define protocol-specific request/response and evidence types. It may not define a new protocol-independent authority plane merely for convenience.
