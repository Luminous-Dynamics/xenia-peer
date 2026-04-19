# xenia-admin

Leptos CSR admin console for the Xenia remote-session stack — the operator surface of the Mycelix Sovereign suite.

## Status

**Scaffold + live ledger demo.** Four routes (`/login`, `/devices`, `/sessions`, `/policy`), `AuthState` persisted via `localStorage`. The Sessions page embeds a live `xenia-ledger` demo that generates an Ed25519 keypair + synthetic consent chain in the browser and exposes per-entry tamper buttons.

Real integrations pending (W1 follow-ups):

- **Login:** DID string-shape validation only. Real `mycelix-identity::resolve_did` via `mycelix-bridge-common` is next.
- **Devices:** static mock rows. Real device enrollment (Holon / `symthaea-phone-embodiment`) is year-2.
- **Sessions data:** synthetic chain only. Wiring to `xenia-peer-core`'s session registry is W1 tail-end.
- **Policy:** stub page listing planned controls.

## Build + run

```sh
cd crates/xenia-admin

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
   cd /srv/luminous-dynamics/xenia-peer/crates/xenia-admin
   ~/.cargo/bin/trunk serve
   ```
   Wait for `applying new distribution` / `✅ success` (first run ~40s release compile, subsequent runs <2s incremental).

2. **Open `http://localhost:8134/login`.** Paste any DID-shaped string (e.g. `did:mycelix:z6MkFoo123Bar456Baz789Quux012LoremIpsum`). Click **Sign in**. You land on `/devices` with a mock inventory of three hosts.

3. **Navigate to `/sessions`.** The page generates a fresh Ed25519 key pair + a 5-entry consent chain (Request → Approval → Request broader → Approval → Revocation) right in your browser. The top-of-page badge reads **✓ Chain verified** and shows the operator public key in full.

4. **Open DevTools → Network.** Reload `/sessions`. Observe: zero network requests after the initial WASM load. Every hash and every signature was computed client-side by `ed25519-dalek` + `blake3`.

5. **The 30-second NIS2 Art. 21(f) pitch.** Click **Tamper** on any row (easy target: seq 1, Approval). Watch the badge flip to **✗ Verify failed** with a specific error like `entry_hash mismatch at seq 1 — tampering detected`. Click **Tamper** again on the same row to restore the kind — and verify flips back to ✓. This is the "admin cannot rewrite the audit log" property of `xenia-ledger` made visible, in a demo anyone can touch.

6. **Sign out via the top-right button.** `localStorage` is cleared; subsequent visits redirect to `/login`.

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
crates/xenia-admin/
├── Cargo.toml          AGPL-3.0-or-later, Leptos 0.8 CSR, xenia-ledger path dep
├── Trunk.toml          dev server on localhost:8134
├── index.html          Trunk entry, links main.css + the rust bin
├── styles/main.css     Dark-theme scaffold — will be replaced with real design-system
└── src/
    ├── main.rs         mount_to_body
    ├── app.rs          Router + top nav + AuthStatus
    ├── auth.rs         AuthState signal + localStorage rehydration
    └── pages/
        ├── mod.rs      re-exports
        ├── login.rs    DID-shape sign-in form (no crypto yet)
        ├── devices.rs  mocked device inventory
        ├── sessions.rs *** live xenia-ledger demo ***
        └── policy.rs   planned-controls stub
```

## W1 follow-up checklist

- [ ] Replace `LoginPage` DID-shape validation with real `resolve_did` zome call via a browser-friendly shim over `mycelix-bridge-common`. Might require publishing a small `mycelix-leptos-client` port to crates.io, since xenia-peer is not inside the monorepo.
- [ ] Add WebAuthn / TOTP MFA challenge step on login.
- [ ] Replace `SessionsPage` synthetic chain with an import+verify flow: operator uploads a persisted ledger file (JSON / bincode) + pastes a public key, we verify it and render the same badges.
- [ ] Wire `DevicesPage` to `xenia-peer-core`'s session registry once that lands.
- [ ] Policy CRUD (tier thresholds, session TTL, MFA enforcement) with every mutation producing a `ConsentKind::`-tagged ledger entry so policy drift is itself auditable.

## License

AGPL-3.0-or-later (application layer). See [../../LICENSE-AGPL-3.0](../../LICENSE-AGPL-3.0).
