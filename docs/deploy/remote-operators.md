# Deploying remote operators (confidentiality via reverse-proxy TLS)

The **interim** transport-security layer for exposing the operator surface
beyond loopback (see `docs/security/OPERATOR_RBAC_PLAN.md` → *Transport
security* for why this is interim and what the destination is).

For running the daemon and its signing agent as persistent, restart-on-failure
background services in the first place (before worrying about exposing them
beyond loopback), see `docs/deploy/systemd-user-service.md`.

## What you're securing, and what's already secure

The operator surface is three endpoints on two daemon ports:

| Endpoint | Daemon port (default) | Purpose |
|----------|-----------------------|---------|
| `POST /auth/challenge`, `/auth/verify` (HTTP) | `--admin-port` (8081) | the auth ceremony |
| `/ws` (WebSocket) | `--admin-port` (8081) | consent-prompt broadcast to the console |
| consent decisions (WebSocket) | `--consent-port` (8082) | signed Approve/Deny/Revoke |

**Integrity is already enforced** by operator RBAC: every consent decision is a
signed, role-authorized, session-bound action, so forgery/replay is impossible
regardless of transport. This recipe adds **confidentiality** (a passive
observer must not read tokens, consent prompts, or enrollment records).

## Recommended: daemon on loopback, proxy terminates TLS

Do **not** use the daemon's non-loopback `--operator-bind` for this pattern.
Keep the daemon bound to loopback (the default) and let a public reverse proxy
terminate TLS and forward to it. The `--operator-bind` network mode is for
trusted-LAN/dev only — it's cleartext (forgery-safe, but not confidential), and
Phase 6a refuses it without `--require-operator-auth`.

```sh
# Daemon: loopback bind (default), auth required, operators enrolled.
xenia-peer --require-operator-auth --operators-file operators.json \
  --admin-port 8081 --consent-port 8082 \
  --m1-consent-key-path ./m1-consent.key
```

### The two-port wrinkle

The console derives its URLs from one host: `admin_ws_url()` is
`wss://<endpoint-host>/ws` and `consent_ws_url()` is
`wss://<endpoint-host>:<consent_port>`. So the proxy must expose **both** the
admin surface and the consent surface on the **same hostname, different TLS
ports**.

### Caddy (auto-TLS, simplest)

```caddyfile
# Admin surface: /auth/* + /ws  (Caddy handles the WebSocket upgrade for /ws).
ops.example.org {
    reverse_proxy 127.0.0.1:8081
}

# Consent surface: a second TLS port on the SAME host.
ops.example.org:8443 {
    reverse_proxy 127.0.0.1:8082
}
```

Then in the console's Sessions config:
- **Daemon Endpoint:** `https://ops.example.org`
  (→ `/auth/*` over HTTPS, and `admin_ws_url()` → `wss://ops.example.org/ws`)
- **Consent Port:** `8443`
  (→ `consent_ws_url()` → `wss://ops.example.org:8443`)

### nginx (manual certs)

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

# Admin surface (443): /auth/* + /ws
server {
    listen 443 ssl;
    server_name ops.example.org;
    ssl_certificate     /etc/ssl/ops.crt;
    ssl_certificate_key /etc/ssl/ops.key;
    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;       # WebSocket upgrade for /ws
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
    }
}

# Consent surface (8443): raw WebSocket
server {
    listen 8443 ssl;
    server_name ops.example.org;
    ssl_certificate     /etc/ssl/ops.crt;
    ssl_certificate_key /etc/ssl/ops.key;
    location / {
        proxy_pass http://127.0.0.1:8082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
    }
}
```

## Gotchas

- **Both `/ws` and the consent port are WebSockets** — the proxy MUST forward
  the `Upgrade`/`Connection` headers (Caddy does this automatically; nginx needs
  the `map` + `proxy_set_header` lines above).
- **Serve the console over the same origin scheme.** A console served over
  `https://` cannot open `ws://` (mixed content) — it must be `wss://`, which is
  exactly what `DaemonConfig` derives once the endpoint is `https://`.
- **This is server-authenticated TLS**, i.e. the browser trusts the proxy's
  cert. It protects confidentiality in transit; it does **not** replace operator
  RBAC (that's the integrity layer) or the host-identity TOFU the console does
  for the screen channel.
- **Interim, not destination.** The coherent long-term answer is to seal the
  operator channel with `xenia-wire`'s own PQC-hybrid envelopes (no CA, one
  trust model) — see the plan's *Transport security* section.
