# ADR-033: Exact GCS authority-retention readback

Status: **Experimental / draft qualification**

## Context

ADR-028 requires authoritative exact-object readback and complete namespace enumeration before ambiguous external durability can be resolved or a retained lineage can be recovered. ADR-030 selects a GCS profile, ADR-031 freezes fail-closed Google SDK error classification, and ADR-032 freezes the single-shot no-retry mutation.

Read/list operations do not mutate authority evidence, but their outputs can become recovery evidence. Returning a successful prefix of a failed object stream or a successful first page of a failed listing would therefore manufacture authority from incomplete provider state.

## Decision

Add `xenia-operation-authority-retention-gcs-readback-transport` as the V1 provider primitive for exact object reads and complete namespace enumeration.

### Exact object read

For a requested ADR-028 locator the transport MUST:

1. validate the frozen ADR-030 provider profile;
2. derive the exact bucket resource and deterministic object name from that profile and locator;
3. classify initial/final Google errors only through ADR-031;
4. accept object bytes only after the complete `ReadObjectResponse` stream reaches a clean end;
5. discard every accumulated byte if any stream chunk fails;
6. reject negative provider size metadata;
7. reject metadata declaring an object larger than ADR-032's 1 MiB writer bound;
8. independently enforce the same 1 MiB bound while streaming even when metadata/size hints claim a smaller value;
9. reject an empty retained object;
10. return `Found(exact_bytes)` only after clean EOF.

A failed stream never returns a partial `Found` result.

### Complete namespace enumeration

For one namespace digest the transport MUST:

1. derive the exact ADR-030 namespace object prefix;
2. list only the qualified bucket and exact prefix;
3. explicitly request `versions = false` even though ADR-030 also requires Object Versioning disabled;
4. consume Google's public item paginator until it terminates normally;
5. discard all accumulated sequence identities if any page/item fails;
6. verify every returned object's bucket equals the exact qualified bucket;
7. require every object name to round-trip through the exact ADR-030 grammar: `<namespace-prefix><20 ASCII decimal digits>.bin`;
8. reject duplicate retention-sequence identities;
9. canonicalize provider item order into ascending retention sequence;
10. return `Complete(sequences)` only after clean paginator exhaustion.

The provider's item order is not an authority assumption. ADR-028 remains responsible for requiring the resulting canonical sequence to be exactly contiguous `0..N` before reconstructing a retained lineage.

### Retry boundary

Reads and listings are non-mutating. A concrete Google client MAY use its qualified retry/resume machinery for these operations. The security rule is on the final result: only a fully completed stream/list may become `Found` or `Complete`. Final timeout, deserialization, exhausted retry, transient/server, future or otherwise ambiguous failures remain `Unknown` through ADR-031.

### Public Google mock qualification

Google Storage 1.18.0 provides:

- mockable data-plane `Storage<S>::from_stub(...)`;
- public `ReadObjectResponse::from_source(...)` for injecting stream behavior;
- public high-level `StorageControl::from_stub(...)` with its object-list paginator.

Qualification therefore uses Google's real public read/list builders. Tests MUST include:

- clean exact read;
- valid prefix followed by injected stream error -> no partial bytes, `Unknown`;
- provider metadata claiming a tiny object while stream exceeds 1 MiB -> fail closed;
- reversed provider list order -> canonical ascending result;
- successful first page followed by failed second page -> never `Complete`;
- duplicate sequence identities -> rejected;
- malformed-width and foreign-prefix names -> rejected.

## Authority boundary

This transport is a provider primitive, not an authority API. A caller-provided namespace digest is not self-authenticating.

Production recovery must first pass ADR-029's independently authenticated namespace gate and prove ADR-030 is the exact retention-policy profile committed by that namespace. The future async composition bridge will then use ADR-032/033 beneath ADR-028's canonical object/durability state machine.

## Qualification boundary

The first ADR-033 lane is credential-free and network-free. It proves exact Google SDK type/request/paginator composition and the fail-closed read/list semantics using Google's public mock surfaces.

It does **not** yet qualify:

- a real GCS project/bucket/service account;
- Bucket Lock or IAM behavior on the wire;
- real provider retry timing;
- real read-after-write/list consistency;
- the ADR-029 namespace trust source;
- recovery-state clearing or SQLite mutation;
- authority application, effect arming or external effects;
- process execution, shell, PTY or SSH.
