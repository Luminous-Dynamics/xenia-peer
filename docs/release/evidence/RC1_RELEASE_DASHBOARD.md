# Xenia Release Dashboard

Root: `<repo-root>`
Generated from branch: `xenia/rc1-dashboard-normalized-branch-v0.1`
Generated from HEAD: `ffca6296372a`
Layout mode: `normalized`
Generated from normalized layout: `True`
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

- None recorded

## Soft blockers

- normalization executor should be dry-run once on the production tree before apply
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
./apps/sovereign-admin/src/pages/sessions.rs:335:                placeholder=r#"{"public_key_hex":"...","entries":[...]}"#
./apps/sovereign-admin/src/pages/policy.rs:4:// Policy page. Scaffold stub — the admin console's CRUD surface for
./apps/sovereign-admin/src/pages/login.rs:16:// TODO (W1 tail-end):
./apps/sovereign-admin/src/pages/login.rs:166:                    placeholder="did:mycelix:… or did:key:…"
./apps/sovereign-admin/src/pages/login.rs:205:            LoginStatus::Idle => view! { <span class="status-placeholder"></span> }.into_any(),
./apps/sovereign-admin/src/pages/devices.rs:8:// TODO (year-2):
./docs/ADR-001-m0-architecture.md:34:| `xenia-peer` | binary (daemon) | AGPL-3.0-or-later | M0 stub |
./docs/ADR-001-m0-architecture.md:35:| `xenia-viewer` | binary (CLI now, GUI at M4) | AGPL-3.0-or-later | M0 stub |
./apps/sovereign-admin/README.md:14:- **Policy:** stub page listing planned controls.
./apps/sovereign-admin/README.md:96:        └── policy.rs   planned-controls stub
./docs/implementation/NORMALIZATION_FOLLOWUPS.md:7:- Replace CODEOWNERS placeholder with the real maintainer/team.
./docs/release/RELEASE_GATES.md:39:- `beta`: no known placeholder security paths; external testing welcome.

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
hard_blockers: 0
soft_blockers: 3

Release readiness manifest check passed.
Note: run with --rc1 only during an explicit release-candidate review.
```

### normalization-plan

```text
xenia normalization plan check
root: <repo-root>
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
