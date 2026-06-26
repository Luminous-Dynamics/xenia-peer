# Xenia Fix Tickets

Generated from `xenia.tasks.toml` plus advisory validation context.

- Total tickets: 5
- RC1 blockers: 4

## XN-001: Run normalization execution on real workspace

- Kind: `normalization`
- Priority: `P0`
- Status: `ready`
- Blocks RC1: `true`

Apply the reviewed normalization plan on a dedicated branch, archive active build artifacts, move apps out of crates, and produce before/after evidence.

### Suggested commands

```bash
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-before.json
scripts/plan-normalization-execution.py . --output _archive/normalization-v0.2/execution-plan.json
scripts/apply-normalization-execution.py . --apply --plan _archive/normalization-v0.2/execution-plan.json --ledger _archive/normalization-v0.2/execution-ledger.json --rollback _archive/normalization-v0.2/rollback.sh
scripts/create-normalization-snapshot.py . _archive/normalization-v0.2/snapshot-after.json
scripts/check-post-normalization.py .
```

### Acceptance

- [ ] No active target/dist/tarball/nested .git artifacts outside _archive.
- [ ] Runnable apps are under xenia-peer/apps.
- [ ] Reusable libraries remain under xenia-peer/crates.
- [ ] Rollback script and ledger are committed or archived with the branch evidence.

## XN-002: Repair Cargo and Nix after app moves

- Kind: `build`
- Priority: `P0`
- Status: `blocked-on-XN-001`
- Blocks RC1: `true`

Update workspace members, package paths, app references, and flake checks after the apps/ move.

### Suggested commands

```bash
cargo metadata --format-version 1 --no-deps
cargo check --workspace
nix flake check
```

### Acceptance

- [ ] cargo metadata succeeds from xenia-peer.
- [ ] cargo check --workspace succeeds or remaining failures are documented as code-level issues, not path-layout issues.
- [ ] nix flake check reaches project checks on supported Linux targets.

## XN-003: Implement consent-state invariant tests

- Kind: `security-test`
- Priority: `P0`
- Status: `ready`
- Blocks RC1: `true`

Add tests proving privileged sessions cannot become Active without Presented and Granted states and stop on revoke/fault/expiry.

### Suggested commands

```bash
scripts/scaffold-consent-tests.py . --stdout
cargo test consent_state --workspace
```

### Acceptance

- [ ] Active requires Presented then Granted.
- [ ] Revoked, Denied, Expired, and FaultClosed stop privileged flow.
- [ ] Reconnect does not silently restore Active.
- [ ] Ledger/audit events exist for session lifecycle transitions.

## XN-004: Convert runtime risk findings into issues

- Kind: `hardening`
- Priority: `P1`
- Status: `ready`
- Blocks RC1: `true`

Turn unwrap/expect/unsafe findings into auditable fix tickets or explicit exceptions before RC1.

### Suggested commands

```bash
scripts/check-runtime-risk-patterns.py . --json _archive/runtime-risk.json
scripts/check-unsafe-surfaces.py . --json _archive/unsafe-surfaces.json
scripts/generate-fix-tickets.py . --markdown _archive/fix-tickets.md --json _archive/fix-tickets.json
```

### Acceptance

- [ ] All runtime-risk findings are fixed, downgraded with rationale, or tracked in the ticket output.
- [ ] All unsafe/FFI surfaces are justified or removed.
- [ ] Strict runtime/unsafe scans are clean or have approved exceptions.

## XN-005: Publish CI artifacts for every validation run

- Kind: `ci`
- Priority: `P1`
- Status: `ready`
- Blocks RC1: `false`

Make validation outputs downloadable from CI so failed checks produce useful evidence.

### Suggested commands

```bash
scripts/ci-collect-artifacts.sh . _archive/ci-artifacts
```

### Acceptance

- [ ] Release dashboard markdown and JSON are generated.
- [ ] Metrics JSON is generated.
- [ ] Handoff report is generated.
- [ ] Validation logs are captured even when checks fail.

## Advisory validation context

### `scripts/check-release-readiness.py .`

Return code: `0`

```text
== Xenia release readiness ==
policy_stage: pre-production
layout_mode: transitional
release_status: pre-rc
current_milestone: stabilization-v0.1
next_candidate: rc1
hard_blockers: 4
soft_blockers: 7

== Warnings ==
WARN: layout is not normalized yet; this is expected before normalization-v0.2

Release readiness manifest check passed.
Note: run with --rc1 only during an explicit release-candidate review.
```

### `scripts/check-secure-defaults.py .`

Return code: `0`

```text
 to QUIC automatically when available. `ws://...` still selects
WARNING: ROADMAP.md:36: ws:// :: | WebSocket (binary frames) | `xenia-transport-ws` | ✅ daemon/viewer baseline; conformance-tested; selected by `auto` for `ws://...` |
WARNING: docs/security/SECURE_BY_DEFAULT_BASELINE.md:36: 0.0.0.0 :: Binding to all interfaces, including `0.0.0.0`, `::`, or `[::]`, requires a
WARNING: docs/security/SECURE_BY_DEFAULT_BASELINE.md:36: [::] :: Binding to all interfaces, including `0.0.0.0`, `::`, or `[::]`, requires a
WARNING: docs/security/SECURE_BY_DEFAULT_BASELINE.md:47: disable_consent :: Any diff containing phrases such as `skip_consent`, `disable_consent`,
WARNING: docs/security/SECURE_BY_DEFAULT_BASELINE.md:47: skip_consent :: Any diff containing phrases such as `skip_consent`, `disable_consent`,
WARNING: docs/security/SECURE_BY_DEFAULT_BASELINE.md:48: fail_open :: `bypass_consent`, or `fail_open` is a security review item, even if the code is
WARNING: docs/security/SECURE_BY_DEFAULT_BASELINE.md:48: bypass_consent :: `bypass_consent`, or `fail_open` is a security review item, even if the code is
WARNING: crates/sovereign-admin/README.md:53: http:// :: 2. **Open `http://localhost:8134/login`.** Paste any DID-shaped string (e.g. `did:mycelix:z6MkFoo123Bar456Baz789Quux012LoremIpsum`). Click **Sign in**. You land on `/devices` with 
WARNING: crates/sovereign-admin/index.html:15: ws:// :: CLAUDE.md — ws://localhost:8888, app_id=mycelix-unified,
WARNING: crates/sovereign-admin/src/config.rs:22: http:// :: load_from_storage(ENDPOINT_KEY).unwrap_or_else(|| "http://127.0.0.1:8134".into()),
WARNING: crates/sovereign-admin/src/pages/login.rs:46: ws:// :: None => "ws://localhost:8888",
WARNING: crates/sovereign-admin/src/pages/monitor.rs:29: http:// :: let binding = endpoint.replace("http://", "");
WARNING: crates/sovereign-admin/src/pages/monitor.rs:31: ws:// :: let ws_url = format!("ws://{}:8430/v1/thoughts", host);
WARNING: crates/sovereign-admin/src/pages/consent.rs:14: ws:// :: let ws = WebSocket::open("ws://127.0.0.1:8081/ws").expect("Failed to connect to WS");
WARNING: crates/sovereign-admin/src/pages/consent.rs:35: ws:// :: if let Ok(ws) = WebSocket::open("ws://127.0.0.1:8082") {
WARNING: crates/sovereign-admin/src/pages/consent.rs:44: ws:// :: if let Ok(ws) = WebSocket::open("ws://127.0.0.1:8082") {
WARNING: crates/xenia-transport-ws/src/lib.rs:236: ws:// :: let mut client = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
WARNING: crates/xenia-transport-ws/tests/transport_conformance.rs:43: ws:// :: let client = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
WARNING: crates/xenia-viewer/src/main.rs:615: ws:// :: } else if connect.starts_with("ws://") || connect.starts_with("wss://") {
WARNING: crates/xenia-viewer/src/main.rs:653: ws:// :: let url = if connect.starts_with("ws://") || connect.starts_with("wss://") {
WARNING: crates/xenia-viewer/src/main.rs:656: ws:// :: format!("ws://{connect}")
secure-default check passed
```

### `scripts/check-normalization-plan.py .`

Return code: `0`

```text
WARN: move[1] app-peer-daemon: source not present in this checkout yet: xenia-peer/crates/xenia-peer
WARN: move[2] app-native-viewer: source not present in this checkout yet: xenia-peer/crates/xenia-viewer
WARN: move[3] app-web-viewer: source not present in this checkout yet: xenia-peer/crates/xenia-viewer-web
WARN: move[4] app-sovereign-admin: source not present in this checkout yet: xenia-peer/crates/sovereign-admin
xenia normalization plan check
root: /srv/luminous-dynamics/xenia/xenia-peer
moves: 4
archive_rules: 5
components: 9
normalization manifest is coherent
```

### `scripts/check-codeowners.py .`

Return code: `0`

```text
WARN: CODEOWNERS still uses placeholder team @luminous-dynamics/xenia-maintainers
CODEOWNERS check passed
```
