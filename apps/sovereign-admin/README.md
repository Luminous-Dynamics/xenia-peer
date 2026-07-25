# xenia-admin

Leptos CSR admin console for the Xenia remote-session stack — the operator surface of the Mycelix Sovereign suite.

## Status

**Real DID login + a native signer-delegation security arc; Devices/Policy are still scaffold.** Seven routes (`/`, `/login`, `/devices`, `/sessions`, `/governance`, `/monitor`, `/policy`), `AuthState` persisted via `localStorage`. The console now delegates all signing to a local `xenia-operator-agent` process — the browser never generates or holds the operator's Ed25519/ML-DSA seeds, only ephemeral session material. See `docs/security/SIGNER_DELEGATION_DESIGN.md` and `docs/security/POST_DELEGATION_HARDENING_PLAN.md` for the full arc (host-trust pinning, scope-bound consent signatures, durable audit-ledger persistence). The Sessions page still embeds the original `xenia-ledger` demo (client-generated keypair + synthetic consent chain, per-entry tamper buttons) plus a real import/verify flow for uploaded ledger exports.

Status by page:

- **Login:** real — calls `did_registry::resolve_did` on a live Holochain conductor via `mycelix-leptos-client` (a pure-Rust WASM client; not the originally-planned `mycelix-bridge-common` shim). Shape-check is only client-side pre-validation before the real zome call. Still no MFA challenge step.
- **Devices:** static mock rows. Real device enrollment (Holon / `symthaea-phone-embodiment`) is year-2, per `MYCELIX_SOVEREIGN_PLAN.md` §7.
- **Sessions:** the ledger demo itself is client-generated/synthetic; the import+verify flow for real exported chains is real and shipped. The consent modal (approve/deny/revoke) is real, role-gated, and sends signed, token-bearing decisions.
- **Governance / Monitor:** newer pages (proposal voting, live Athena thought-stream) added after the signer-delegation arc — not yet independently reviewed for this doc; treat as unverified until checked.
- **Policy:** stub page listing planned controls.

## Build + run

```sh
cd apps/sovereign-admin

# Dev: reload on change, serves on localhost:8134
~/.cargo/bin/trunk serve

# Release: builds to dist/, ~592 KB wasm-opt'd
~/.cargo/bin/trunk build --release
```

The host's `nix develop` is **not** required for the admin console (pure Rust + WASM, no C libraries). The scap / dbus / pipewire shell applies to `xenia-capture` only.

### If trunk is missing

```sh
cargo install --locked trunk
```

(Already installed at `~/.cargo/bin/trunk` on the dev host.)

### Port assignment

`8134` per `.claude/rules/PORTS.md` and the top-level `CLAUDE.md`. In production this serves behind a Cloudflare Tunnel at `admin.sovereign.mycelix.net`.

## E2E walkthrough (~3 minutes)

This is the canonical "show a CISO what the product does" sequence. Every step happens in the browser; no backend, no network traffic.

1. **Start the dev server:**
   ```sh
   cd <xenia-root>-peer/apps/sovereign-admin
   ~/.cargo/bin/trunk serve
   ```
   Wait for `applying new distribution` / `✅ success` (first run ~40s release compile, subsequent runs <2s incremental).

2. **Open `http://localhost:8134/login`.** Paste any DID-shaped string (e.g. `did:mycelix:z6MkFoo123Bar456Baz789Quux012LoremIpsum`). Click **Sign in**. You land on `/devices` with a mock inventory of three hosts.

3. **Navigate to `/sessions`.** The page generates a fresh Ed25519 key pair + a 5-entry consent chain (Request → Approval → Request broader → Approval → Revocation) right in your browser. The top-of-page badge reads **✓ Chain verified** and shows the operator public key in full.

4. **Open DevTools → Network.** Reload `/sessions`. Observe: zero network requests after the initial WASM load. Every hash and every signature was computed client-side by `ed25519-dalek` + `blake3`.

5. **The 30-second NIS2 Art. 21(f) pitch.** Click **Tamper** on any row (easy target: seq 1, Approval). Watch the badge flip to **✗ Verify failed** with a specific error like `entry_hash mismatch at seq 1 — tampering detected`. Click **Tamper** again on the same row to restore the kind — and verify flips back to ✓. This is the "admin cannot rewrite the audit log" property of `xenia-ledger` made visible, in a demo anyone can touch.

6. **The round-trip: export + import.** Scroll down; click **Show JSON export**. You see a portable self-contained attestation (public key + entries). Copy it. Scroll to **Verify a chain from JSON** below, paste, click **Verify** — it passes. Now modify a byte in the pasted JSON (change `"kind":"Approval"` to `"kind":"Denial"`) and verify again — it fails with a specific `VerifyError`. Proves the Verifier works on arbitrary input, not just chains we generated.

7. **Sign out via the top-right button.** `localStorage` is cleared; subsequent visits redirect to `/login`.

## What's worth showing a CISO vs what's scaffold

**Show:**

- The ledger demo (step 5). This is the commercial moat of the suite rendered as 15 seconds of clickable UX. Blake3 + Ed25519 running in the browser against the same crate (`xenia-ledger`) that will sit in the production server.
- The absence of network traffic during verification. An auditor needs zero trust in our infrastructure to verify a chain — only the operator's public key.
- The permissive/AGPL split: this crate is AGPL; the underlying `xenia-wire` / `xenia-peer-core` / `xenia-handshake` / `xenia-capture` are Apache/MIT. Customers can build compatible clients; they just need their own ledger.

**Don't oversell:**

- The Devices and Policy pages are scaffolds. Say so.
- The Login page does not actually verify the DID. Say so.
- The ledger demo uses a throwaway key pair generated on page load, not a real operator key. Say so.

## Architecture

```
apps/sovereign-admin/
├── Cargo.toml           AGPL-3.0-or-later, Leptos 0.8 CSR; path deps on xenia-ledger,
│                         xenia-operator-proto, xenia-handshake, xenia-operator-agent-proto
├── Trunk.toml           dev server on localhost:8134
├── index.html           Trunk entry, links main.css + the rust bin
├── styles/main.css      Dark-theme scaffold — will be replaced with real design-system
└── src/
    ├── main.rs              mount_to_body
    ├── app.rs               Router + top nav + AuthStatus (7 routes)
    ├── auth.rs              AuthState signal + localStorage rehydration
    ├── config.rs            DaemonConfig — single source of truth for daemon URLs
    ├── context.rs           Leptos context plumbing (AuthState, DaemonConfig)
    ├── agent_client.rs      browser client for the local xenia-operator-agent —
    │                         the console no longer generates/holds operator seeds
    ├── host_pin.rs          TOFU pinning of the daemon's sealed-channel host fingerprint
    ├── operator_session.rs  browser half of the operator-RBAC ceremony (Step 5,
    │                         SIGNER_DELEGATION_DESIGN.md)
    ├── sealed_consent.rs    browser half of the PQC-sealed operator channel
    │                         (--operator-sealed mode)
    └── pages/
        ├── mod.rs       re-exports
        ├── login.rs     *** real: resolve_did zome call via mycelix-leptos-client ***
        ├── devices.rs   mocked device inventory (year-2, MYCELIX_SOVEREIGN_PLAN.md §7)
        ├── sessions.rs  *** live xenia-ledger demo + real import/verify flow ***
        ├── consent.rs   live approve/deny/revoke modal, role-gated, signed decisions
        ├── governance.rs governance-proposal voting page (not independently reviewed)
        ├── monitor.rs   live Athena thought-stream page (not independently reviewed)
        └── policy.rs    planned-controls stub
```

A tenth file, `src/pages/verify.rs`, exists but is not wired into `pages/mod.rs`/routing — its own view reads "Verification module under reconstruction."

## W1 follow-up checklist

- [x] Replace `LoginPage` DID-shape validation with a real `resolve_did` zome call — shipped via `mycelix-leptos-client` (a pure-Rust WASM Holochain client), not the originally-planned `mycelix-bridge-common` shim.
- [ ] Add WebAuthn / TOTP MFA challenge step on login.
- [x] Replace `SessionsPage` synthetic chain with an import+verify flow: operator uploads a persisted ledger file (JSON) — shipped, portable `ExportedChain` shape carries the public key alongside entries, single round-trip round-tripped.
- [ ] Wire `DevicesPage` to `xenia-peer-core`'s session registry once that lands.
- [ ] Policy CRUD (tier thresholds, session TTL, MFA enforcement) with every mutation producing a `ConsentKind::`-tagged ledger entry so policy drift is itself auditable.
- [x] Signer delegation: browser no longer generates/holds the operator's Ed25519/ML-DSA seeds — delegated to a native `xenia-operator-agent` process. See `docs/security/SIGNER_DELEGATION_DESIGN.md` and `docs/security/POST_DELEGATION_HARDENING_PLAN.md` for the full arc (host-trust pinning, scope-bound consent signatures, durable ledger persistence).
- [ ] Independently review the newer `governance.rs`/`monitor.rs` pages against their backing daemon endpoints (not covered by the signer-delegation review this checklist entry references).

## License

AGPL-3.0-or-later (application layer). See [../../LICENSE-AGPL-3.0](../../LICENSE-AGPL-3.0).
