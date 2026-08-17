# Running Xenia as systemd user services

How to install `xenia-peer` (the daemon) and `xenia-operator-agent` (the
native signing agent the browser console delegates to) as
`systemctl --user` services -- so both survive logout/reboot and restart
on failure, without a system-level install or root.

See `docs/deploy/remote-operators.md` for exposing the daemon beyond
loopback (TLS reverse-proxying), and `docs/deploy/backup-and-restore.md`
for backing up the state directories this doc establishes the layout of;
this doc only covers running the two binaries themselves.

## Why two services

- **`xenia-peer`** is the daemon: the actual remote-session host. It
  needs `--operators-file` to authenticate anyone at all -- an unset
  policy denies every operator (fail closed), so a fresh install with no
  enrollment file is intentionally inert on the admin surface.
- **`xenia-operator-agent`** is the native counterpart to the
  `sovereign-admin` browser console: it holds the operator's real signing
  keys (the browser never does, not even transiently) and answers
  `/v1/sign/*` requests the console relays to it. The console cannot
  authenticate to *any* daemon without this agent running.

They're independent processes -- the agent doesn't need the daemon
running to start, and vice versa -- but the console's signing-delegation
flow needs both up.

## Install the binaries

`cargo install --path ... --locked` is the primary, always-available
install path (works on any machine with a Rust toolchain, no Nix
required):

```sh
cargo install --path apps/xenia-peer --locked
cargo install --path apps/xenia-operator-agent --locked
```

This puts `xenia-peer`/`xenia-operator-agent` in `~/.cargo/bin`, which
must be on `PATH` for the unit files below (`ExecStart=` relies on `PATH`
rather than a hardcoded path, so it works the same way regardless of how
you installed the binaries).

A Nix derivation for the daemon is also available as `nix build
.#xenia-peer`. `Cargo.lock` is tracked and pinned by the flake. The normal
package deliberately **does not** compile the `preprod-fixtures` feature;
the separately named `.#xenia-peer-preprod` output exists only for scripted
VM tests that need the pre-production auto-consent fixture. Do not deploy
that test package as the normal daemon.

`xenia-operator-agent` does not yet have a dedicated flake package, so the
`cargo install --locked` path above remains the documented installation path
for the agent.

## Install the unit files

```sh
mkdir -p ~/.config/systemd/user
cp packaging/systemd/xenia-peer.service packaging/systemd/xenia-operator-agent.service \
  ~/.config/systemd/user/
systemctl --user daemon-reload
```

Both units use `StateDirectory=`/`WorkingDirectory=` to run from
`~/.local/state/<name>/`, matching each binary's own default state-path
convention (`xenia-peer-state/`, `xenia-operator-agent-state/` --
relative subdirectories of the working directory, so they nest one level
inside the systemd-managed state dir; harmless, and it keeps a
manually-run binary and the systemd-managed instance behaviorally
identical). Neither unit hardcodes application flags beyond that.

## Configure the daemon: enroll operators

`xenia-peer.service`'s `ExecStart=xenia-peer` ships with no
`--operators-file` -- add one via a drop-in rather than editing the
installed unit file directly, so a future `cp` of an updated unit file
doesn't silently drop your configuration:

```sh
systemctl --user edit xenia-peer.service
```

```ini
[Service]
ExecStart=
ExecStart=xenia-peer --operators-file %S/xenia-peer/operators.json
```

(The empty `ExecStart=` first clears the unit's own default -- systemd
appends to `ExecStart=` by default rather than replacing it.) See
`docs/security/OPERATOR_RBAC_PLAN.md` for the enrollment-file format and
`docs/deploy/remote-operators.md` for exposing this beyond loopback.

## Start, verify, stop

```sh
systemctl --user enable --now xenia-peer.service xenia-operator-agent.service

# Both expose an unauthenticated liveness probe:
curl -s http://127.0.0.1:8081/health   # xenia-peer (admin port)
curl -s http://127.0.0.1:8180/v1/health # xenia-operator-agent

journalctl --user -u xenia-peer -u xenia-operator-agent -f

systemctl --user stop xenia-peer.service xenia-operator-agent.service
systemctl --user disable xenia-peer.service xenia-operator-agent.service
```

## What the hardening does and doesn't cover

Both units set `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome=read-only`, and scope `ReadWritePaths` to just their own
state directory -- verified against the real binaries (both start
cleanly, create their state directories with correct permissions, and
serve `/health` under this exact profile). This is process-level
sandboxing, not a substitute for `--require-operator-auth` (item 5 of
`docs/security/POST_DELEGATION_HARDENING_PLAN.md`) or transport
confidentiality (`remote-operators.md`) -- both still apply if you expose
either service beyond loopback.

Not covered here: token/session automatic rotation (only passive TTL
expiry + manual refresh exists today) and backup tooling for the state
directories -- both still-open items in
`docs/security/POST_DELEGATION_HARDENING_PLAN.md` item 8.
