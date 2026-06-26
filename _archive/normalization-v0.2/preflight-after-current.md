# Xenia Preflight Report

Generated: 2026-06-26T06:43:45Z
Root: /srv/luminous-dynamics/xenia/xenia-peer

This report is intentionally diagnostic. A command appearing here does not mean
it passed; inspect each block.

## Git status

```text
?? _archive/normalization-v0.2/preflight-after-current.md
?? _archive/normalization-v0.2/snapshot-after-current.json
```

## Top-level layout

```text
./crates
./crates/xenia-peer-core
./crates/xenia-video
./crates/xenia-capture
./crates/xenia-transport-ws
./crates/xenia-inject
./crates/xenia-handshake
./crates/xenia-ledger
./crates/xenia-transport-quic
./docs
./docs/agents
./docs/architecture
./docs/ci
./docs/implementation
./docs/nix
./docs/observability
./docs/release
./docs/runbooks
./docs/security
./docs/testing
./apps
./apps/sovereign-admin
./apps/xenia-peer
./apps/xenia-viewer
./_archive
./_archive/normalization-v0.2
./scripts
./scripts/__pycache__
```

## Hygiene audit

```text

== archive bundles in active paths ==
clean

== build output directories in active paths ==
clean

== migration scratch scripts in active paths ==
clean

== nested git repositories in active paths ==
clean

== absolute local workspace references in source/config ==
clean

== absolute local workspace references in docs ==
clean

== review markers for humans ==
./ROADMAP.md:100:| ~~T2.1~~ | ~~`src/swarm/rdp_input.rs`~~ | ~~354~~ | ✅ shipped as `xenia-inject` (`23a49a9`). X11 backend dropped. Wayland + uinput are scaffold stubs; real plumbing lands with matching xenia-capture backend. |
./XENIA_IMPROVEMENTS_APPLIED.md:19:  - Pre-alpha banner no longer says the wire crate owns the placeholder
./XENIA_IMPROVEMENTS_APPLIED.md:30:  - Reports pre-alpha/TODO markers as review warnings, not hard failures.
./scripts/xenia-hygiene-audit.sh:118:    'DO NOT USE IN PRODUCTION|placeholder|stub|TODO|FIXME' .
./scripts/check-codeowners.py:45:        print("WARN: CODEOWNERS still uses placeholder team @luminous-dynamics/xenia-maintainers")
./docs/security/THREAT_MODEL.md:49:1. No placeholder handshake path in production builds.
./docs/implementation/NORMALIZATION_FOLLOWUPS.md:7:- Replace CODEOWNERS placeholder with the real maintainer/team.
./apps/xenia-viewer/Cargo.toml:8:description = "Native viewer for Xenia sessions. Connects to an xenia-peer daemon, decodes sealed frames, renders. Pre-alpha stub — M4 adds the egui GUI."
./apps/xenia-peer/Cargo.toml:8:description = "Headless daemon that shares a screen over the Xenia wire. Hosts sessions; delegates capture/encode to xenia-peer-core. Pre-alpha stub — M1 adds real Wayland capture + H.264."
./docs/ADR-001-m0-architecture.md:34:| `xenia-peer` | binary (daemon) | AGPL-3.0-or-later | M0 stub |
./docs/ADR-001-m0-architecture.md:35:| `xenia-viewer` | binary (CLI now, GUI at M4) | AGPL-3.0-or-later | M0 stub |
./docs/release/RELEASE_GATES.md:39:- `beta`: no known placeholder security paths; external testing welcome.
./apps/sovereign-admin/README.md:14:- **Policy:** stub page listing planned controls.
./apps/sovereign-admin/README.md:96:        └── policy.rs   planned-controls stub
./apps/sovereign-admin/src/pages/devices.rs:8:// TODO (year-2):
./apps/sovereign-admin/src/pages/sessions.rs:335:                placeholder=r#"{"public_key_hex":"...","entries":[...]}"#
./apps/sovereign-admin/src/pages/policy.rs:4:// Policy page. Scaffold stub — the admin console's CRUD surface for
./apps/sovereign-admin/src/pages/login.rs:16:// TODO (W1 tail-end):
./apps/sovereign-admin/src/pages/login.rs:166:                    placeholder="did:mycelix:… or did:key:…"
./apps/sovereign-admin/src/pages/login.rs:205:            LoginStatus::Idle => view! { <span class="status-placeholder"></span> }.into_any(),

== local runtime secret/state files ==
clean

== cargo metadata smoke check ==
cargo metadata: ok

Xenia hygiene audit passed.
```

## CODEOWNERS check

```text
CODEOWNERS check passed
```

## Secure-default scan

```text
secure-default scan: hard=0 warning=0
secure-default check passed
```

## Release dashboard

```text
# Xenia Release Dashboard

Root: `/srv/luminous-dynamics/xenia/xenia-peer`
Current milestone: `normalization-v0.2`
Status: `pre-rc`

## Gate summary

| Check | Status | Exit |
| --- | --- | --- |
| hygiene | pass | 0 |
| policy | pass | 0 |
| safety | pass | 0 |
| codeowners | pass | 0 |
| release-readiness | pass | 0 |
| normalization-plan | pass | 0 |
| post-normalization | pass | 0 |
| cargo-boundaries | pass | 0 |
| runtime-risk | pass | 0 |
| unsafe-surfaces | pass | 0 |

## Secure-default summary

- `capture_enabled_by_default`: `False`
- `consent_required_for_privileged_sessions`: `True`
- `consent_revocation_fail_closed`: `True`
- `default_bind_address`: `127.0.0.1`
- `injection_enabled_by_default`: `False`
- `ledger_required_for_privileged_sessions`: `True`
- `plaintext_credentials_allowed`: `False`
- `public_bind_requires_explicit_flag`: `True`
- `remote_control_enabled_by_default`: `False`
- `silent_session_start_allowed`: `False`
- `unattended_access_allowed`: `False`

## Hard blockers

- normalization manifest, execution plan, ledger, and before/after snapshots need review

## Soft blockers

- source archives need reproducible checksum manifest
- normalization executor should be dry-run once on the production tree before apply
- release dashboard should be generated from the normalized branch
- transport fault-injection tests need expansion
- operator/admin audit events need stable names

## Check output

### hygiene

```text
== archive bundles in active paths ==
clean

== build output directories in active paths ==
clean

== migration scratch scripts in active paths ==
clean

== nested git repositories in active paths ==
clean

== absolute local workspace references in source/config ==
clean

== absolute local workspace references in docs ==
clean

== review markers for humans ==
./ROADMAP.md:100:| ~~T2.1~~ | ~~`src/swarm/rdp_input.rs`~~ | ~~354~~ | ✅ shipped as `xenia-inject` (`23a49a9`). X11 backend dropped. Wayland + uinput are scaffold stubs; real plumbing lands with matching xenia-capture backend. |
./XENIA_IMPROVEMENTS_APPLIED.md:19:  - Pre-alpha banner no longer says the wire crate owns the placeholder
./XENIA_IMPROVEMENTS_APPLIED.md:30:  - Reports pre-alpha/TODO markers as review warnings, not hard failures.
./scripts/check-codeowners.py:45:        print("WARN: CODEOWNERS still uses placeholder team @luminous-dynamics/xenia-maintainers")
./scripts/xenia-hygiene-audit.sh:118:    'DO NOT USE IN PRODUCTION|placeholder|stub|TODO|FIXME' .
./apps/xenia-viewer/Cargo.toml:8:description = "Native viewer for Xenia sessions. Connects to an xenia-peer daemon, decodes sealed frames, renders. Pre-alpha stub — M4 adds the egui GUI."
./apps/xenia-peer/Cargo.toml:8:description = "Headless daemon that shares a screen over the Xenia wire. Hosts sessions; delegates capture/encode to xenia-peer-core. Pre-alpha stub — M1 adds real Wayland capture + H.264."
./docs/security/THREAT_MODEL.md:49:1. No placeholder handshake path in production builds.
./docs/ADR-001-m0-architecture.md:34:| `xenia-peer` | binary (daemon) | AGPL-3.0-or-later | M0 stub |
./docs/ADR-001-m0-architecture.md:35:| `xenia-viewer` | binary (CLI now, GUI at M4) | AGPL-3.0-or-later | M0 stub |
./apps/sovereign-admin/README.md:14:- **Policy:** stub page listing planned controls.
./apps/sovereign-admin/README.md:96:        └── policy.rs   planned-controls stub
./docs/implementation/NORMALIZATION_FOLLOWUPS.md:7:- Replace CODEOWNERS placeholder with the real maintainer/team.
./docs/release/RELEASE_GATES.md:39:- `beta`: no known placeholder security paths; external testing welcome.
./apps/sovereign-admin/src/pages/devices.rs:8:// TODO (year-2):
./apps/sovereign-admin/src/pages/policy.rs:4:// Policy page. Scaffold stub — the admin console's CRUD surface for
./apps/sovereign-admin/src/pages/login.rs:16:// TODO (W1 tail-end):
./apps/sovereign-admin/src/pages/login.rs:166:                    placeholder="did:mycelix:… or did:key:…"
./apps/sovereign-admin/src/pages/login.rs:205:            LoginStatus::Idle => view! { <span class="status-placeholder"></span> }.into_any(),
./apps/sovereign-admin/src/pages/sessions.rs:335:                placeholder=r#"{"public_key_hex":"...","entries":[...]}"#

== local runtime secret/state files ==
clean

== cargo metadata smoke check ==
cargo metadata: ok

Xenia hygiene audit passed.
```

### policy

```text
== Xenia policy manifest ==
policy: xenia.policy.toml
stage: pre-production
policy_version: 1
components: 13

Xenia policy check passed.
```

### safety

```text
secure-default scan: hard=0 warning=0
secure-default check passed
```

### codeowners

```text
CODEOWNERS check passed
```

### release-readiness

```text
== Xenia release readiness ==
policy_stage: pre-production
layout_mode: normalized
release_status: pre-rc
current_milestone: normalization-v0.2
next_candidate: rc1
hard_blockers: 1
soft_blockers: 5

Release readiness manifest check passed.
Note: run with --rc1 only during an explicit release-candidate review.
```

### normalization-plan

```text
xenia normalization plan check
root: /srv/luminous-dynamics/xenia/xenia-peer
moves: 3
archive_rules: 5
components: 9
OK: move[1] app-peer-daemon: already applied apps/xenia-peer
OK: move[2] app-native-viewer: already applied apps/xenia-viewer
OK: move[3] app-sovereign-admin: already applied apps/sovereign-admin
OK: component[1] xenia-wire: external component not present in this checkout: xenia-wire
normalization plan check passed: warnings=0
```

### post-normalization

```text
OK: normalized app path exists: apps/xenia-peer
OK: normalized app path exists: apps/xenia-viewer
OK: normalized app path exists: apps/sovereign-admin
post-normalization check completed: failures=0 warnings=0
```

### cargo-boundaries

```text
== Cargo boundary packages ==
sovereign-admin          app      apps/sovereign-admin/Cargo.toml
xenia-peer               app      apps/xenia-peer/Cargo.toml
xenia-viewer             app      apps/xenia-viewer/Cargo.toml
xenia-capture            library  crates/xenia-capture/Cargo.toml
xenia-handshake          library  crates/xenia-handshake/Cargo.toml
xenia-inject             library  crates/xenia-inject/Cargo.toml
xenia-ledger             library  crates/xenia-ledger/Cargo.toml
xenia-peer-core          library  crates/xenia-peer-core/Cargo.toml
xenia-transport-quic     library  crates/xenia-transport-quic/Cargo.toml
xenia-transport-ws       library  crates/xenia-transport-ws/Cargo.toml
xenia-video              library  crates/xenia-video/Cargo.toml

Cargo boundary check passed.
```

### runtime-risk

```text
== Runtime risk pattern summary ==
expect           runtime=   0 tests/examples=  32
panic            runtime=   0 tests/examples=   5
todo             runtime=   0 tests/examples=   0
unimplemented    runtime=   0 tests/examples=   0
unwrap           runtime=   0 tests/examples= 196

== Findings ==
crates/xenia-transport-quic/tests/transport_conformance.rs:20: unwrap [test/example] .unwrap()
crates/xenia-transport-quic/tests/transport_conformance.rs:30: unwrap [test/example] tokio::spawn(async move { QuicTransport::accept_one(&endpoint).await.unwrap() })
crates/xenia-transport-quic/tests/transport_conformance.rs:35: unwrap [test/example] .unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:36: unwrap [test/example] let server = server.await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:62: unwrap [test/example] client.send_envelope(envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:65: unwrap [test/example] let received = server.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:70: unwrap [test/example] server.send_envelope(envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:73: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:92: unwrap [test/example] client.send_envelope(&sentinel).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:93: unwrap [test/example] assert_eq!(server.recv_envelope().await.unwrap(), sentinel);
crates/xenia-transport-quic/tests/transport_conformance.rs:118: unwrap [test/example] .seal_frame(&telemetry.clone().into_frame().unwrap())
crates/xenia-transport-quic/tests/transport_conformance.rs:119: unwrap [test/example] .unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:120: unwrap [test/example] server.send_envelope(&envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:121: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:122: unwrap [test/example] let opened = viewer.open_frame(&received).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:124: unwrap [test/example] assert_eq!(RawTelemetry::from_frame(&opened).unwrap(), telemetry);
crates/xenia-transport-quic/tests/transport_conformance.rs:140: unwrap [test/example] let frame = audio.clone().into_frame(frame_id).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:141: unwrap [test/example] let envelope = host.seal_frame(&frame).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:142: unwrap [test/example] server.send_envelope(&envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:143: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:144: unwrap [test/example] let opened = viewer.open_frame(&received).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:146: unwrap [test/example] assert_eq!(RawAudio::from_frame(&opened).unwrap(), audio);
crates/xenia-ledger/src/lib.rs:366: unwrap [test/example] Verifier::verify_chain(chain.iter().cloned().collect::<Vec<_>>().as_slice(), &pk).unwrap();
crates/xenia-ledger/src/lib.rs:373: unwrap [test/example] let entry = chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:391: unwrap [test/example] chain.append(sample_event(kind)).unwrap();
crates/xenia-ledger/src/lib.rs:407: unwrap [test/example] Verifier::verify_chain(&entries, &pk).unwrap();
crates/xenia-ledger/src/lib.rs:415: unwrap [test/example] chain.append(sample_event(ConsentKind::Approval)).unwrap();
crates/xenia-ledger/src/lib.rs:422: panic [test/example] other => panic!("expected EntryHashMismatch, got {other:?}"),
crates/xenia-ledger/src/lib.rs:431: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:444: unwrap [test/example] .unwrap();
crates/xenia-ledger/src/lib.rs:451: panic [test/example] other => panic!("expected BadSignature, got {other:?}"),
crates/xenia-ledger/src/lib.rs:460: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:461: unwrap [test/example] chain.append(sample_event(ConsentKind::Approval)).unwrap();
crates/xenia-ledger/src/lib.rs:476: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:482: panic [test/example] other => panic!("expected BadSignature, got {other:?}"),
crates/xenia-ledger/src/lib.rs:493: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:494: unwrap [test/example] chain.append(sample_event(ConsentKind::Approval)).unwrap();
crates/xenia-ledger/src/lib.rs:499: unwrap [test/example] chain.append(sample_event(ConsentKind::Revocation)).unwrap();
crates/xenia-ledger/src/lib.rs:503: unwrap [test/example] Verifier::verify_chain(&entries, &pk).unwrap();
crates/xenia-ledger/src/lib.rs:511: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:523: unwrap [test/example] .unwrap();
crates/xenia-ledger/src/lib.rs:528: panic [test/example] other => panic!("expected BadGenesis, got {other:?}"),
crates/xenia-handshake/src/lib.rs:412: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:414: unwrap [test/example] let ct = initiator.encapsulate_for_peer("responder", &nonce).unwrap();
crates/xenia-handshake/src/lib.rs:419: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:421: unwrap [test/example] let initiator_key = initiator.session_key("responder").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:433: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:434: unwrap [test/example] me.encapsulate_for_peer("A", &nonce).unwrap();
crates/xenia-handshake/src/lib.rs:437: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:438: unwrap [test/example] me.encapsulate_for_peer("B", &nonce).unwrap();
crates/xenia-handshake/src/lib.rs:440: unwrap [test/example] let a = me.session_key("A").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:441: unwrap [test/example] let b = me.session_key("B").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:453: unwrap [test/example] init1.receive_kem_public_key("R", &rpk).unwrap();
crates/xenia-handshake/src/lib.rs:454: unwrap [test/example] init1.encapsulate_for_peer("R", &[0x01u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:456: unwrap [test/example] init2.receive_kem_public_key("R", &rpk).unwrap();
crates/xenia-handshake/src/lib.rs:457: unwrap [test/example] init2.encapsulate_for_peer("R", &[0x02u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:459: unwrap [test/example] let k1 = init1.session_key("R").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:460: unwrap [test/example] let k2 = init2.session_key("R").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:527: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:528: unwrap [test/example] me.encapsulate_for_peer("P", &[0u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:541: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:542: unwrap [test/example] init.encapsulate_for_peer("R", &[0u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:543: unwrap [test/example] assert_eq!(init.session_key("R").unwrap().bytes().len(), 32);
crates/xenia-handshake/src/lib.rs:573: unwrap [test/example] let bytes = bincode::serialize(&exchange).unwrap();
crates/xenia-handshake/src/lib.rs:574: unwrap [test/example] let decoded: KemExchange = bincode::deserialize(&bytes).unwrap();
crates/xenia-inject/src/lib.rs:483: unwrap [test/example] log.inject_pointer(0.5, 0.25, 0, true).unwrap();
crates/xenia-inject/src/lib.rs:492: panic [test/example] other => panic!("wrong variant: {other:?}"),
crates/xenia-inject/src/lib.rs:499: unwrap [test/example] log.inject_pointer(-0.5, 2.0, 0, true).unwrap();
crates/xenia-inject/src/lib.rs:500: unwrap [test/example] log.inject_pointer(1.5, -0.1, 0, true).unwrap();
crates/xenia-inject/src/lib.rs:545: unwrap [test/example] log.process_events(&events).unwrap();
crates/xenia-inject/src/lib.rs:582: unwrap [test/example] let bytes = bincode::serialize(original).unwrap();
crates/xenia-inject/src/lib.rs:583: unwrap [test/example] let decoded: InputEvent = bincode::deserialize(&bytes).unwrap();
crates/xenia-transport-ws/src/lib.rs:219: unwrap [test/example] let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
crates/xenia-transport-ws/src/lib.rs:220: unwrap [test/example] let local = listener.local_addr().unwrap();
crates/xenia-transport-ws/src/lib.rs:221: unwrap [test/example] port_tx.send(local.to_string()).unwrap();
crates/xenia-transport-ws/src/lib.rs:223: unwrap [test/example] let (stream, _peer) = listener.accept().await.unwrap();
crates/xenia-transport-ws/src/lib.rs:225: unwrap [test/example] let ws = accept_async(stream).await.unwrap();
crates/xenia-transport-ws/src/lib.rs:229: unwrap [test/example] let env = t.recv_envelope().await.unwrap();
crates/xenia-transport-ws/src/lib.rs:231: unwrap [test/example] t.send_envelope(&env).await.unwrap();
crates/xenia-transport-ws/src/lib.rs:235: unwrap [test/example] let addr = port_rx.await.unwrap();
... truncated 153 additional finding(s)
```

### unsafe-surfaces

```text
== Unsafe / FFI surface summary ==
clean
```

```

## Policy manifest check

```text
== Xenia policy manifest ==
policy: xenia.policy.toml
stage: pre-production
policy_version: 1
components: 13

Xenia policy check passed.
```

## Release readiness check

```text
== Xenia release readiness ==
policy_stage: pre-production
layout_mode: normalized
release_status: pre-rc
current_milestone: normalization-v0.2
next_candidate: rc1
hard_blockers: 1
soft_blockers: 5

Release readiness manifest check passed.
Note: run with --rc1 only during an explicit release-candidate review.
```

## Normalization manifest check

```text
xenia normalization plan check
root: /srv/luminous-dynamics/xenia/xenia-peer
moves: 3
archive_rules: 5
components: 9
OK: move[1] app-peer-daemon: already applied apps/xenia-peer
OK: move[2] app-native-viewer: already applied apps/xenia-viewer
OK: move[3] app-sovereign-admin: already applied apps/sovereign-admin
OK: component[1] xenia-wire: external component not present in this checkout: xenia-wire
normalization plan check passed: warnings=0
```

## Normalization move plan

```text
# Xenia Workspace Normalization Plan

Root: `/srv/luminous-dynamics/xenia/xenia-peer`
Status: `planning`
Layout: `transitional` -> `normalized`

## Preflight

Run these before moving anything:

```bash
scripts/check-normalization-plan.py .
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json
scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-before-normalization.md
```

## Archive rules

- **active-tarballs**: `*.tar.gz` -> `_archive/normalization-v0.2/tarballs`
  - Tarballs inside crates/apps confuse source-of-truth and export hygiene.
- **active-tgz**: `*.tgz` -> `_archive/normalization-v0.2/tarballs`
  - Compressed artifacts should never be active workspace inputs.
- **build-output-target**: `target` -> `_archive/normalization-v0.2/build-output`
  - Build output is reproducible and should not be committed or exported.
- **frontend-dist**: `dist` -> `_archive/normalization-v0.2/build-output`
  - Generated UI output belongs in release artifacts, not source archives.
- **nested-git**: `.git` -> `_archive/normalization-v0.2/nested-git-metadata`
  - Nested Git metadata makes exports non-reproducible and leaks history/state.

## Planned moves

| ID | Kind | Source | Target | Present |
| --- | --- | --- | --- | --- |
| `app-peer-daemon` | `app` | `crates/xenia-peer` | `apps/xenia-peer` | no |
| `app-native-viewer` | `app` | `crates/xenia-viewer` | `apps/xenia-viewer` | no |
| `app-sovereign-admin` | `app` | `crates/sovereign-admin` | `apps/sovereign-admin` | no |

## Postflight

```bash
scripts/xenia-validate.sh .
scripts/xenia-preflight-report.sh . /tmp/xenia-preflight-after-normalization.md
scripts/export-source-archive.sh . /tmp/xenia-source-after-normalization.tar.gz
scripts/check-source-archive.sh /tmp/xenia-source-after-normalization.tar.gz
```
```

## Normalization execution plan

```text
{
  "action_count": 7,
  "actions": [
    {
      "action": "archive",
      "exists": true,
      "reason": "Nested Git metadata makes exports non-reproducible and leaks history/state.",
      "rule_id": "nested-git",
      "source": ".git",
      "source_kind": "dir",
      "target": "_archive/normalization-v0.2/nested-git-metadata/.git"
    },
    {
      "action": "move",
      "id": "app-native-viewer",
      "kind": "app",
      "reason": "The native viewer is a runnable UI product surface.",
      "source": "crates/xenia-viewer",
      "source_exists": false,
      "target": "apps/xenia-viewer",
      "target_exists": true
    },
    {
      "action": "move",
      "id": "app-peer-daemon",
      "kind": "app",
      "reason": "The peer daemon is a runnable product surface, not a reusable library crate.",
      "source": "crates/xenia-peer",
      "source_exists": false,
      "target": "apps/xenia-peer",
      "target_exists": true
    },
    {
      "action": "move",
      "id": "app-sovereign-admin",
      "kind": "app",
      "reason": "The sovereign admin surface is an app/control-plane UI.",
      "source": "crates/sovereign-admin",
      "source_exists": false,
      "target": "apps/sovereign-admin",
      "target_exists": true
    },
    {
      "action": "rewrite_cargo_member",
      "cargo_toml": "xenia-peer/Cargo.toml",
      "cargo_toml_exists": false,
      "from": "crates/sovereign-admin",
      "to": "apps/sovereign-admin"
    },
    {
      "action": "rewrite_cargo_member",
      "cargo_toml": "xenia-peer/Cargo.toml",
      "cargo_toml_exists": false,
      "from": "crates/xenia-peer",
      "to": "apps/xenia-peer"
    },
    {
      "action": "rewrite_cargo_member",
      "cargo_toml": "xenia-peer/Cargo.toml",
      "cargo_toml_exists": false,
      "from": "crates/xenia-viewer",
      "to": "apps/xenia-viewer"
    }
  ],
  "evidence": [
    {
      "bytes": 1555382,
      "dirs": 256,
      "exists": true,
      "files": 732,
      "metadata_sha256": "a972306b893f7b761035d82e1ca3387201fa4eb2ec3f67ed9d64226f2bed00a5",
      "path": ".git",
      "sample": [
        ".git/COMMIT_EDITMSG",
        ".git/FETCH_HEAD",
        ".git/HEAD",
        ".git/ORIG_HEAD",
        ".git/config",
        ".git/description",
        ".git/index",
        ".git/packed-refs",
        ".git/hooks/applypatch-msg.sample",
        ".git/hooks/commit-msg.sample",
        ".git/hooks/fsmonitor-watchman.sample",
        ".git/hooks/post-update.sample",
        ".git/hooks/pre-applypatch.sample",
        ".git/hooks/pre-commit.sample",
        ".git/hooks/pre-merge-commit.sample",
        ".git/hooks/pre-push.sample",
        ".git/hooks/pre-rebase.sample",
        ".git/hooks/pre-receive.sample",
        ".git/hooks/prepare-commit-msg.sample",
        ".git/hooks/push-to-checkout.sample"
      ],
      "type": "dir"
    },
    {
      "exists": false,
      "path": "crates/sovereign-admin"
    },
    {
      "exists": false,
      "path": "crates/xenia-peer"
    },
    {
      "exists": false,
      "path": "crates/xenia-viewer"
    },
    {
      "bytes": 5150,
      "exists": true,
      "path": "xenia.normalization.toml",
      "sha256": "35578c27571250e77b06f6640d0f79dbba39a27071cf7252061688e966d9d179",
      "sha256_omitted_reason": null,
      "type": "file"
    }
  ],
  "manifest": "xenia.normalization.toml",
  "manifest_sha256": "35578c27571250e77b06f6640d0f79dbba39a27071cf7252061688e966d9d179",
  "mode": "plan-only",
  "notes": [
    "This plan does not execute filesystem changes.",
    "Review archive and move actions before using apply-normalization-execution.py --apply.",
    "Generated target paths must not already exist unless a previous partial normalization is being reviewed."
  ],
  "root": "/srv/luminous-dynamics/xenia/xenia-peer",
  "schema": "xenia.normalization.execution-plan.v1"
}
```

## Post-normalization acceptance check

```text
OK: normalized app path exists: apps/xenia-peer
OK: normalized app path exists: apps/xenia-viewer
OK: normalized app path exists: apps/sovereign-admin
post-normalization check completed: failures=0 warnings=0
```

## Cargo boundary check

```text
== Cargo boundary packages ==
sovereign-admin          app      apps/sovereign-admin/Cargo.toml
xenia-peer               app      apps/xenia-peer/Cargo.toml
xenia-viewer             app      apps/xenia-viewer/Cargo.toml
xenia-capture            library  crates/xenia-capture/Cargo.toml
xenia-handshake          library  crates/xenia-handshake/Cargo.toml
xenia-inject             library  crates/xenia-inject/Cargo.toml
xenia-ledger             library  crates/xenia-ledger/Cargo.toml
xenia-peer-core          library  crates/xenia-peer-core/Cargo.toml
xenia-transport-quic     library  crates/xenia-transport-quic/Cargo.toml
xenia-transport-ws       library  crates/xenia-transport-ws/Cargo.toml
xenia-video              library  crates/xenia-video/Cargo.toml

Cargo boundary check passed.
```

## Runtime risk pattern report

```text
== Runtime risk pattern summary ==
expect           runtime=   0 tests/examples=  32
panic            runtime=   0 tests/examples=   5
todo             runtime=   0 tests/examples=   0
unimplemented    runtime=   0 tests/examples=   0
unwrap           runtime=   0 tests/examples= 196

== Findings ==
crates/xenia-transport-quic/tests/transport_conformance.rs:20: unwrap [test/example] .unwrap()
crates/xenia-transport-quic/tests/transport_conformance.rs:30: unwrap [test/example] tokio::spawn(async move { QuicTransport::accept_one(&endpoint).await.unwrap() })
crates/xenia-transport-quic/tests/transport_conformance.rs:35: unwrap [test/example] .unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:36: unwrap [test/example] let server = server.await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:62: unwrap [test/example] client.send_envelope(envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:65: unwrap [test/example] let received = server.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:70: unwrap [test/example] server.send_envelope(envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:73: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:92: unwrap [test/example] client.send_envelope(&sentinel).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:93: unwrap [test/example] assert_eq!(server.recv_envelope().await.unwrap(), sentinel);
crates/xenia-transport-quic/tests/transport_conformance.rs:118: unwrap [test/example] .seal_frame(&telemetry.clone().into_frame().unwrap())
crates/xenia-transport-quic/tests/transport_conformance.rs:119: unwrap [test/example] .unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:120: unwrap [test/example] server.send_envelope(&envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:121: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:122: unwrap [test/example] let opened = viewer.open_frame(&received).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:124: unwrap [test/example] assert_eq!(RawTelemetry::from_frame(&opened).unwrap(), telemetry);
crates/xenia-transport-quic/tests/transport_conformance.rs:140: unwrap [test/example] let frame = audio.clone().into_frame(frame_id).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:141: unwrap [test/example] let envelope = host.seal_frame(&frame).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:142: unwrap [test/example] server.send_envelope(&envelope).await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:143: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:144: unwrap [test/example] let opened = viewer.open_frame(&received).unwrap();
crates/xenia-transport-quic/tests/transport_conformance.rs:146: unwrap [test/example] assert_eq!(RawAudio::from_frame(&opened).unwrap(), audio);
crates/xenia-ledger/src/lib.rs:366: unwrap [test/example] Verifier::verify_chain(chain.iter().cloned().collect::<Vec<_>>().as_slice(), &pk).unwrap();
crates/xenia-ledger/src/lib.rs:373: unwrap [test/example] let entry = chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:391: unwrap [test/example] chain.append(sample_event(kind)).unwrap();
crates/xenia-ledger/src/lib.rs:407: unwrap [test/example] Verifier::verify_chain(&entries, &pk).unwrap();
crates/xenia-ledger/src/lib.rs:415: unwrap [test/example] chain.append(sample_event(ConsentKind::Approval)).unwrap();
crates/xenia-ledger/src/lib.rs:422: panic [test/example] other => panic!("expected EntryHashMismatch, got {other:?}"),
crates/xenia-ledger/src/lib.rs:431: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:444: unwrap [test/example] .unwrap();
crates/xenia-ledger/src/lib.rs:451: panic [test/example] other => panic!("expected BadSignature, got {other:?}"),
crates/xenia-ledger/src/lib.rs:460: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:461: unwrap [test/example] chain.append(sample_event(ConsentKind::Approval)).unwrap();
crates/xenia-ledger/src/lib.rs:476: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:482: panic [test/example] other => panic!("expected BadSignature, got {other:?}"),
crates/xenia-ledger/src/lib.rs:493: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:494: unwrap [test/example] chain.append(sample_event(ConsentKind::Approval)).unwrap();
crates/xenia-ledger/src/lib.rs:499: unwrap [test/example] chain.append(sample_event(ConsentKind::Revocation)).unwrap();
crates/xenia-ledger/src/lib.rs:503: unwrap [test/example] Verifier::verify_chain(&entries, &pk).unwrap();
crates/xenia-ledger/src/lib.rs:511: unwrap [test/example] chain.append(sample_event(ConsentKind::Request)).unwrap();
crates/xenia-ledger/src/lib.rs:523: unwrap [test/example] .unwrap();
crates/xenia-ledger/src/lib.rs:528: panic [test/example] other => panic!("expected BadGenesis, got {other:?}"),
crates/xenia-handshake/src/lib.rs:412: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:414: unwrap [test/example] let ct = initiator.encapsulate_for_peer("responder", &nonce).unwrap();
crates/xenia-handshake/src/lib.rs:419: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:421: unwrap [test/example] let initiator_key = initiator.session_key("responder").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:433: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:434: unwrap [test/example] me.encapsulate_for_peer("A", &nonce).unwrap();
crates/xenia-handshake/src/lib.rs:437: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:438: unwrap [test/example] me.encapsulate_for_peer("B", &nonce).unwrap();
crates/xenia-handshake/src/lib.rs:440: unwrap [test/example] let a = me.session_key("A").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:441: unwrap [test/example] let b = me.session_key("B").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:453: unwrap [test/example] init1.receive_kem_public_key("R", &rpk).unwrap();
crates/xenia-handshake/src/lib.rs:454: unwrap [test/example] init1.encapsulate_for_peer("R", &[0x01u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:456: unwrap [test/example] init2.receive_kem_public_key("R", &rpk).unwrap();
crates/xenia-handshake/src/lib.rs:457: unwrap [test/example] init2.encapsulate_for_peer("R", &[0x02u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:459: unwrap [test/example] let k1 = init1.session_key("R").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:460: unwrap [test/example] let k2 = init2.session_key("R").unwrap().bytes();
crates/xenia-handshake/src/lib.rs:527: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:528: unwrap [test/example] me.encapsulate_for_peer("P", &[0u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:541: unwrap [test/example] .unwrap();
crates/xenia-handshake/src/lib.rs:542: unwrap [test/example] init.encapsulate_for_peer("R", &[0u8; 32]).unwrap();
crates/xenia-handshake/src/lib.rs:543: unwrap [test/example] assert_eq!(init.session_key("R").unwrap().bytes().len(), 32);
crates/xenia-handshake/src/lib.rs:573: unwrap [test/example] let bytes = bincode::serialize(&exchange).unwrap();
crates/xenia-handshake/src/lib.rs:574: unwrap [test/example] let decoded: KemExchange = bincode::deserialize(&bytes).unwrap();
crates/xenia-inject/src/lib.rs:483: unwrap [test/example] log.inject_pointer(0.5, 0.25, 0, true).unwrap();
crates/xenia-inject/src/lib.rs:492: panic [test/example] other => panic!("wrong variant: {other:?}"),
crates/xenia-inject/src/lib.rs:499: unwrap [test/example] log.inject_pointer(-0.5, 2.0, 0, true).unwrap();
crates/xenia-inject/src/lib.rs:500: unwrap [test/example] log.inject_pointer(1.5, -0.1, 0, true).unwrap();
crates/xenia-inject/src/lib.rs:545: unwrap [test/example] log.process_events(&events).unwrap();
crates/xenia-inject/src/lib.rs:582: unwrap [test/example] let bytes = bincode::serialize(original).unwrap();
crates/xenia-inject/src/lib.rs:583: unwrap [test/example] let decoded: InputEvent = bincode::deserialize(&bytes).unwrap();
crates/xenia-transport-ws/src/lib.rs:219: unwrap [test/example] let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
crates/xenia-transport-ws/src/lib.rs:220: unwrap [test/example] let local = listener.local_addr().unwrap();
crates/xenia-transport-ws/src/lib.rs:221: unwrap [test/example] port_tx.send(local.to_string()).unwrap();
crates/xenia-transport-ws/src/lib.rs:223: unwrap [test/example] let (stream, _peer) = listener.accept().await.unwrap();
crates/xenia-transport-ws/src/lib.rs:225: unwrap [test/example] let ws = accept_async(stream).await.unwrap();
crates/xenia-transport-ws/src/lib.rs:229: unwrap [test/example] let env = t.recv_envelope().await.unwrap();
crates/xenia-transport-ws/src/lib.rs:231: unwrap [test/example] t.send_envelope(&env).await.unwrap();
crates/xenia-transport-ws/src/lib.rs:235: unwrap [test/example] let addr = port_rx.await.unwrap();
crates/xenia-transport-ws/src/lib.rs:236: unwrap [test/example] let mut client = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
crates/xenia-transport-ws/src/lib.rs:239: unwrap [test/example] client.send_envelope(&payload).await.unwrap();
crates/xenia-transport-ws/src/lib.rs:240: unwrap [test/example] let echoed = client.recv_envelope().await.unwrap();
crates/xenia-transport-ws/src/lib.rs:243: unwrap [test/example] server.await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:18: unwrap [test/example] let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:19: unwrap [test/example] let addr = listener.local_addr().unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:22: unwrap [test/example] let (stream, _) = listener.accept().await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:27: unwrap [test/example] let client = TcpTransport::connect(&addr.to_string()).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:28: unwrap [test/example] let server = server.await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:33: unwrap [test/example] let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:34: unwrap [test/example] let addr = listener.local_addr().unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:37: unwrap [test/example] let (stream, _) = listener.accept().await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:39: unwrap [test/example] let ws = accept_async(stream).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:43: unwrap [test/example] let client = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:44: unwrap [test/example] let server = server.await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:69: unwrap [test/example] client.send_envelope(envelope).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:72: unwrap [test/example] let received = server.recv_envelope().await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:77: unwrap [test/example] server.send_envelope(envelope).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:80: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:99: unwrap [test/example] client.send_envelope(&sentinel).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:100: unwrap [test/example] assert_eq!(server.recv_envelope().await.unwrap(), sentinel);
crates/xenia-transport-ws/tests/transport_conformance.rs:125: unwrap [test/example] .seal_frame(&telemetry.clone().into_frame().unwrap())
crates/xenia-transport-ws/tests/transport_conformance.rs:126: unwrap [test/example] .unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:127: unwrap [test/example] server.send_envelope(&envelope).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:128: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:129: unwrap [test/example] let opened = viewer.open_frame(&received).unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:131: unwrap [test/example] assert_eq!(RawTelemetry::from_frame(&opened).unwrap(), telemetry);
crates/xenia-transport-ws/tests/transport_conformance.rs:147: unwrap [test/example] let frame = audio.clone().into_frame(frame_id).unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:148: unwrap [test/example] let envelope = host.seal_frame(&frame).unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:149: unwrap [test/example] server.send_envelope(&envelope).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:150: unwrap [test/example] let received = client.recv_envelope().await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:151: unwrap [test/example] let opened = viewer.open_frame(&received).unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:153: unwrap [test/example] assert_eq!(RawAudio::from_frame(&opened).unwrap(), audio);
crates/xenia-transport-ws/tests/transport_conformance.rs:208: unwrap [test/example] let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:209: unwrap [test/example] let addr = listener.local_addr().unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:213: unwrap [test/example] let (mut stream, _) = listener.accept().await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:214: unwrap [test/example] ready_tx.send(()).unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:218: unwrap [test/example] .unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:221: unwrap [test/example] let mut client = TcpTransport::connect(&addr.to_string()).await.unwrap();
crates/xenia-transport-ws/tests/transport_conformance.rs:222: unwrap [test/example] ready_rx.await.unwrap();
... truncated 113 additional finding(s)
```

## Unsafe/FFI surface report

```text
== Unsafe / FFI surface summary ==
clean
```

## Repository metrics

```text
{
  "components": [
    ".",
    "apps/sovereign-admin",
    "apps/xenia-peer",
    "apps/xenia-viewer",
    "crates/xenia-capture",
    "crates/xenia-handshake",
    "crates/xenia-inject",
    "crates/xenia-ledger",
    "crates/xenia-peer-core",
    "crates/xenia-transport-quic",
    "crates/xenia-transport-ws",
    "crates/xenia-video"
  ],
  "counts": {
    "cargo_manifests": 12,
    "markdown_files": 51,
    "python_scripts": 18,
    "rust_files": 41,
    "shell_scripts": 9,
    "toml_files": 19,
    "total_tracked_text_lines": 18714
  },
  "root": "/srv/luminous-dynamics/xenia/xenia-peer"
}
```

## Cargo metadata

```text
{"packages":[{"name":"xenia-peer-core","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core#0.0.0-m0","license":"Apache-2.0 OR MIT","license_file":null,"description":"Core session + transport primitives for xenia-peer. M0 — pre-alpha, no real capture/encode yet.","source":null,"dependencies":[{"name":"bincode","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"ed25519-dalek","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^2","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"rand","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.0","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"serde-big-array","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.5","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^2.0","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tokio","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["full"],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"xenia-handshake","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-handshake"},{"name":"xenia-wire","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.2.0-alpha.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["consent"],"target":null,"registry":null},{"name":"tokio","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":"dev","rename":null,"optional":false,"uses_default_features":true,"features":["full"],"target":null,"registry":null},{"name":"tracing-subscriber","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":"dev","rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_peer_core","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},{"kind":["test"],"crate_types":["bin"],"name":"loopback","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core/tests/loopback.rs","edition":"2024","doc":false,"doctest":false,"test":true},{"kind":["test"],"crate_types":["bin"],"name":"telemetry","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core/tests/telemetry.rs","edition":"2024","doc":false,"doctest":false,"test":true}],"features":{},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":null,"documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-handshake","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-handshake#0.0.0-m0","license":"Apache-2.0 OR MIT","license_file":null,"description":"Post-quantum hybrid handshake (Ed25519 + ML-KEM-768 + HKDF-SHA-256) for the Xenia remote-session stack. Fresh implementation against RustCrypto primitives; API-aligned with Symthaea's pqc_handshake but self-contained.","source":null,"dependencies":[{"name":"ed25519-dalek","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^2","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["std","rand_core"],"target":null,"registry":null},{"name":"hkdf","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.12","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"ml-kem","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3.0-rc.2","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["zeroize","getrandom"],"target":null,"registry":null},{"name":"rand","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"sha2","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.10","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"zeroize","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"bincode","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.3","kind":"dev","rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_handshake","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-handshake/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true}],"features":{},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-handshake/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-peer","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-peer#0.0.0-m0","license":"AGPL-3.0-or-later","license_file":null,"description":"Headless daemon that shares a screen over the Xenia wire. Hosts sessions; delegates capture/encode to xenia-peer-core. Pre-alpha stub — M1 adds real Wayland capture + H.264.","source":null,"dependencies":[{"name":"axum","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["ws"],"target":null,"registry":null},{"name":"bincode","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"clap","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^4","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"ed25519-dalek","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^2","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["rand_core"],"target":null,"registry":null},{"name":"futures","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"hex","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.4","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"rand","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"reqwest","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.13","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["json"],"target":null,"registry":null},{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"serde_json","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tokio","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["macros","rt-multi-thread","net","io-util","sync","time"],"target":null,"registry":null},{"name":"tokio-tungstenite","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.24","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tokio-util","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.7","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing-subscriber","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["env-filter"],"target":null,"registry":null},{"name":"uuid","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["v4","serde"],"target":null,"registry":null},{"name":"xenia-capture","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture"},{"name":"xenia-handshake","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-handshake"},{"name":"xenia-ledger","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-ledger"},{"name":"xenia-peer-core","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core"},{"name":"xenia-transport-quic","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic"},{"name":"xenia-transport-ws","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws"},{"name":"xenia-video","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-video"},{"name":"xenia-wire","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.2.0-alpha.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["consent","reference-frame"],"target":null,"registry":null}],"targets":[{"kind":["bin"],"crate_types":["bin"],"name":"xenia-peer","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-peer/src/main.rs","edition":"2024","doc":true,"doctest":false,"test":true}],"features":{"h264":["xenia-video/h264"],"hdc":["xenia-video/hdc"],"scap":["xenia-capture/scap-backend"]},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-peer/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-capture","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture#0.0.0-m0","license":"Apache-2.0 OR MIT","license_file":null,"description":"Screen-capture abstraction for the Xenia remote-session stack. Cross-platform via scap (Windows WGC, macOS ScreenCaptureKit, Linux PipeWire/xdg-desktop-portal). Wayland-only on Linux by design (see xenia-peer ADR-001).","source":null,"dependencies":[{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.0","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"sysinfo","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.30","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"scap","source":"git+https://github.com/Luminous-Dynamics/scap?branch=fix/linux-engine-two-level-frame-enum","req":"*","kind":null,"rename":null,"optional":true,"uses_default_features":true,"features":[],"target":"cfg(any(target_os = \"linux\", target_os = \"macos\", target_os = \"windows\"))","registry":null}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_capture","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},{"kind":["example"],"crate_types":["bin"],"name":"capture_bench","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture/examples/capture_bench.rs","edition":"2024","required-features":["scap-backend"],"doc":false,"doctest":false,"test":false}],"features":{"default":[],"scap-backend":["dep:scap"],"wayland-portal":[],"wayland-wlroots":[]},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-ledger","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-ledger#0.0.0-m0","license":"AGPL-3.0-or-later","license_file":null,"description":"Append-only, hash-chained, Ed25519-signed consent ledger for the Xenia remote-session stack. The third-party-verifiable cryptographic moat of the Mycelix Sovereign suite.","source":null,"dependencies":[{"name":"bincode","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"blake3","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.5","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"ed25519-dalek","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^2","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["std","rand_core","serde"],"target":null,"registry":null},{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.0","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"serde-big-array","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.5","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^2.0","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"uuid","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["v4","serde"],"target":null,"registry":null},{"name":"rand","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":"dev","rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"rand_core","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.6","kind":"dev","rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_ledger","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-ledger/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true}],"features":{},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-ledger/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":"README.md","repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-transport-quic","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic#0.0.0-m0","license":"Apache-2.0 OR MIT","license_file":null,"description":"Iroh QUIC transport for the Xenia remote-session stack. Sealed envelopes over a long-lived bidirectional QUIC stream.","source":null,"dependencies":[{"name":"bs58","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.5","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"iroh","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.0.0","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["tls-ring"],"target":null,"registry":null},{"name":"serde_json","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.0","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"xenia-peer-core","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core"},{"name":"tokio","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":"dev","rename":null,"optional":false,"uses_default_features":true,"features":["macros","rt-multi-thread","net","io-util","sync","time"],"target":null,"registry":null}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_transport_quic","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},{"kind":["test"],"crate_types":["bin"],"name":"transport_conformance","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic/tests/transport_conformance.rs","edition":"2024","doc":false,"doctest":false,"test":true}],"features":{},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-transport-ws","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws#0.0.0-m0","license":"Apache-2.0 OR MIT","license_file":null,"description":"WebSocket transport for the Xenia remote-session stack. Sealed envelopes over binary WebSocket messages — browser-compatible + CGN-friendly fallback for environments where raw UDP (Iroh QUIC) can't punch.","source":null,"dependencies":[{"name":"futures-util","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tokio","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["macros","rt-multi-thread","net","io-util","sync","time"],"target":null,"registry":null},{"name":"tokio-tungstenite","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.24","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"xenia-peer-core","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core"}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_transport_ws","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},{"kind":["test"],"crate_types":["bin"],"name":"transport_conformance","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws/tests/transport_conformance.rs","edition":"2024","doc":false,"doctest":false,"test":true}],"features":{},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-video","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-video#0.0.0-m0","license":"Apache-2.0 OR MIT","license_file":null,"description":"Video-codec abstraction + backends for the Xenia remote-session stack. Passthrough (default, no-deps) + H.264 via ffmpeg-next (feature-gated, requires libav headers).","source":null,"dependencies":[{"name":"bincode","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.3","kind":null,"rename":null,"optional":true,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"blake3","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":true,"uses_default_features":false,"features":[],"target":null,"registry":null},{"name":"ffmpeg-next","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^7","kind":null,"rename":null,"optional":true,"uses_default_features":false,"features":["codec","format","software-scaling"],"target":null,"registry":null},{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":true,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_video","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-video/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true}],"features":{"default":[],"h264":["dep:ffmpeg-next"],"hdc":["dep:blake3","dep:serde","dep:bincode"]},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-video/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-viewer","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-viewer#0.0.0-m0","license":"AGPL-3.0-or-later","license_file":null,"description":"Native viewer for Xenia sessions. Connects to an xenia-peer daemon, decodes sealed frames, renders. Pre-alpha stub — M4 adds the egui GUI.","source":null,"dependencies":[{"name":"clap","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^4","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"eframe","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.29","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["default_fonts","glow","wayland","x11"],"target":null,"registry":null},{"name":"egui","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.29","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tokio","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["macros","rt-multi-thread","net","io-util","sync","time"],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing-subscriber","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["env-filter"],"target":null,"registry":null},{"name":"xenia-capture","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture"},{"name":"xenia-peer-core","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core"},{"name":"xenia-transport-quic","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic"},{"name":"xenia-transport-ws","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws"},{"name":"xenia-video","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-video"},{"name":"xenia-wire","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.2.0-alpha.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["consent","reference-frame"],"target":null,"registry":null}],"targets":[{"kind":["bin"],"crate_types":["bin"],"name":"xenia-viewer","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-viewer/src/main.rs","edition":"2024","doc":true,"doctest":false,"test":true}],"features":{"h264":["xenia-video/h264"],"hdc":["xenia-video/hdc"]},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-viewer/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"xenia-inject","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-inject#0.0.0-m0","license":"Apache-2.0 OR MIT","license_file":null,"description":"Input-injection abstraction for the Xenia remote-session stack. Pointer / keyboard / touch events via platform backends. Ported from Symthaea's rdp_input.rs.","source":null,"dependencies":[{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"thiserror","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"tracing","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"bincode","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.3","kind":"dev","rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null}],"targets":[{"kind":["lib"],"crate_types":["lib"],"name":"xenia_inject","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-inject/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true}],"features":{"default":[],"uinput":[],"wayland-virtual":[]},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-inject/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":null,"repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"},{"name":"sovereign-admin","version":"0.0.0-m0","id":"path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/sovereign-admin#0.0.0-m0","license":"AGPL-3.0-or-later","license_file":null,"description":"Leptos CSR admin console for the Xenia remote-session stack — the operator surface of the Mycelix Sovereign suite.","source":null,"dependencies":[{"name":"bincode","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"console_error_panic_hook","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"ed25519-dalek","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^2","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["std","rand_core"],"target":null,"registry":null},{"name":"futures-util","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["std"],"target":null,"registry":null},{"name":"getrandom","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.2","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["js"],"target":null,"registry":null},{"name":"gloo-net","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.6","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"js-sys","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"leptos","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["csr"],"target":null,"registry":null},{"name":"leptos_meta","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"leptos_router","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.8","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"mycelix-leptos-client","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.1","kind":null,"rename":null,"optional":false,"uses_default_features":false,"features":["browser"],"target":null,"registry":null},{"name":"rand_core","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.6","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["getrandom"],"target":null,"registry":null},{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1.0","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["derive"],"target":null,"registry":null},{"name":"serde_json","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"uuid","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^1","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["v4","serde","js"],"target":null,"registry":null},{"name":"wasm-bindgen","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.2","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null},{"name":"web-sys","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["console","Storage","Window","Location"],"target":null,"registry":null},{"name":"xenia-ledger","source":null,"req":"*","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null,"path":"/srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-ledger"},{"name":"getrandom","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.3","kind":null,"rename":null,"optional":false,"uses_default_features":true,"features":["wasm_js"],"target":"cfg(target_arch = \"wasm32\")","registry":null}],"targets":[{"kind":["bin"],"crate_types":["bin"],"name":"sovereign-admin","src_path":"/srv/luminous-dynamics/xenia/xenia-peer/apps/sovereign-admin/src/main.rs","edition":"2024","doc":true,"doctest":false,"test":true}],"features":{},"manifest_path":"/srv/luminous-dynamics/xenia/xenia-peer/apps/sovereign-admin/Cargo.toml","metadata":null,"publish":[],"authors":["Tristan Stoltz <<maintainer-email>>"],"categories":[],"keywords":[],"readme":"README.md","repository":"https://github.com/Luminous-Dynamics/xenia-peer","homepage":"https://github.com/Luminous-Dynamics/xenia-peer","documentation":null,"edition":"2024","links":null,"default_run":null,"rust_version":"1.94"}],"workspace_members":["path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-handshake#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-peer#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-ledger#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-video#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-viewer#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-inject#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/sovereign-admin#0.0.0-m0"],"workspace_default_members":["path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-peer-core#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-peer#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/apps/xenia-viewer#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-capture#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-video#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-ws#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-transport-quic#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-inject#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-handshake#0.0.0-m0","path+file:///srv/luminous-dynamics/xenia/xenia-peer/crates/xenia-ledger#0.0.0-m0"],"resolve":null,"target_directory":"/tmp/xenia-peer-target","build_directory":"/tmp/xenia-peer-target","version":1,"workspace_root":"/srv/luminous-dynamics/xenia/xenia-peer","metadata":null}
```

## Nix flake metadata

```text
[1mResolved URL:[0m  git+file:///srv/luminous-dynamics/xenia/xenia-peer
[1mLocked URL:[0m    git+file:///srv/luminous-dynamics/xenia/xenia-peer?ref=refs/heads/xenia/rc1-normalization-evidence-review-v0.1&rev=058849a3639e6e3bb102383a7863f438fee4fd75
[1mDescription:[0m   xenia-peer — peer-to-peer, consciousness-first remote-session stack. Wayland + H.264 dev shell.
[1mPath:[0m          /nix/store/3yzajmf74g7ggg8f08waz95la7a40d6i-source
[1mRevision:[0m      058849a3639e6e3bb102383a7863f438fee4fd75
[1mRevisions:[0m     19
[1mLast modified:[0m 2026-06-26 08:16:10
[1mFingerprint:[0m   bd5a37c09cc707efe575ea9afc0e96100b3abbc851b370d089eadba4de53e699
[1mInputs:[0m
├───[1mflake-utils[0m: github:numtide/flake-utils/11707dc2f618dd54ca8739b309ec4fc024de578b?narHash=sha256-l0KFg5HjrsfsO/JpG%2Br7fRrqm12kzFHyUHqHCVpMMbI%3D (2024-11-13 21:27:16)
│   └───[1msystems[0m: github:nix-systems/default/da67096a3b9bf56a91d16901293e51ba5b49a27e?narHash=sha256-Vy1rq5AaRuLzOxct8nz4T6wlgyUR7zLU309k9mBC768%3D (2023-04-09 08:27:08)
└───[1mnixpkgs[0m: github:NixOS/nixpkgs/4bd9165a9165d7b5e33ae57f3eecbcb28fb231c9?narHash=sha256-l/iNYDZ4bGOAFQY2q8y5OAfBBtrDAaPuRQqWaFHVRXM%3D (2026-04-14 12:31:25)
```
