# Backing up and restoring xenia-peer / xenia-operator-agent state

`scripts/xenia-backup.sh` and `scripts/xenia-restore.sh` back up and restore
the state directories systemd packaging established as the standard layout
(see `docs/deploy/systemd-user-service.md`).

## Why this is worth doing even though operator-key recovery exists

`docs/security/POST_DELEGATION_HARDENING_PLAN.md` item 8 already shipped a
live, no-restart operator-key-recovery flow (a locked-out operator gets
re-enrolled under a fresh identity by a different, still-enrolled Admin).
Backup is a separate, complementary concern:

- Recovery is a real **ceremony** -- a different admin has to confirm a
  key-replacement transcript. A backup avoids needing it at all.
- **The daemon's own host identity**
  (`xenia-peer-state/host-identity.key`) has **no recovery flow**. Losing
  it changes the daemon's fingerprint, silently breaking every operator's
  trust-on-first-use pin. This is the single highest-value thing to back
  up.
- **`xenia-operator-agent-state/operator-agent-host-trust.json`** (the
  agent's pinned-daemon TOFU store) also has no recovery flow -- losing it
  means re-doing first-use trust confirmation for every daemon the
  operator has ever paired with.

## What gets backed up

| File | Directory | Sensitive? |
|---|---|---|
| `operator.key`, `consent-ledger.key`, `host-identity.key`, `operator-http-ml-dsa.key` | `xenia-peer-state/` | Yes -- raw private key material |
| `consent.ledger` | `xenia-peer-state/` | Contents are signed, not secret, but the file existing at all reveals session history |
| `operator-agent-identity.key`, `operator-agent-token.key` | `xenia-operator-agent-state/` | Yes -- raw private key material |
| `operator-agent-host-trust.json`, `audit.log` | `xenia-operator-agent-state/` | No secret material, but privacy-relevant (which daemons this operator has used) |

`--operators-file`/`--revoked-operators-file` are **not** auto-included --
they live outside either state directory by design (no default path) and
aren't secret (public keys + roles), but pass them explicitly with
`--operators-file`/`--revoked-operators-file` if you want them in the same
archive.

## Usage

```sh
# Back up both systemd-standard state directories (auto-detected).
# WITHOUT encryption -- the archive is plaintext, encrypt it yourself
# before it leaves this host.
scripts/xenia-backup.sh --out ~/backups

# The same, encrypted to an age recipient (recommended):
scripts/xenia-backup.sh --out ~/backups --encrypt-to age1...

# Or passphrase-encrypted (age prompts interactively):
scripts/xenia-backup.sh --out ~/backups --passphrase

# Restore into a fresh directory:
scripts/xenia-restore.sh ~/backups/xenia-backup-<timestamp>.tar.gz.age \
  ~/restored --decrypt-with ~/my-age-identity.txt
```

`--state-dir` (repeatable) overrides auto-detection, for a manually-run,
CWD-relative layout instead of the systemd one. See each script's `--help`
for the full flag list.

## Restoring

`xenia-restore.sh` refuses to overwrite an already-populated
`xenia-peer-state/`/`xenia-operator-agent-state/` under the target
directory unless you pass `--force` -- restoring on top of live state is
almost never what you want. After a successful restore, point
`xenia-peer`/`xenia-operator-agent`'s `--*-path` flags at the restored
directory (or run with it as the working directory, matching the
binaries' own relative defaults).

### What a bad restore looks like

The restore script does **not** independently verify the restored files --
it deliberately doesn't reimplement Ed25519/hash-chain verification in
bash (that would be exactly the kind of parallel-implementation risk this
project avoids elsewhere). What actually happens on a bad restore differs
by file type:

- **`consent.ledger` and `audit.log` are real hash chains with per-entry
  signatures.** Bit-level tampering, broken links, malformed persistence
  envelopes, and signatures under the wrong key are caught when
  `xenia-peer`/`xenia-operator-agent` loads them. The daemon's live ledger now
  also uses a versioned, size-bounded envelope whose entry count and head must
  agree with the decoded signed chain. A *complete older valid prefix* is a
  different threat: the chain alone cannot distinguish it from the historical
  state that genuinely existed at that point. Detect rollback by retaining
  signed checkpoints from `/v1/audit/checkpoint` outside the restored state
  directory and comparing key, count, and head continuity. See
  `docs/security/RUNTIME_AUTHORIZATION_CONTINUITY.md` for the exact boundary.
- **The raw key files (`*.key`) have no such structure.** Any byte string
  of the right length parses as a "valid" key -- a bit-flipped or
  otherwise corrupted key file is silently accepted at load time as a
  *different, valid-looking* key, not rejected. The mismatch surfaces
  one step later: the daemon/agent starts fine, but authentication then
  fails against whatever the *original* key was enrolled/pinned as
  (verified directly: a deliberately corrupted `operator-agent-identity.key`
  did not stop the agent from starting). Treat a working backup+restore
  round trip (content matches the source, verified with `sha256sum`) as
  the actual integrity check for key files, not "did the process start."

## Scheduling regular backups (systemd user timer)

Mirrors the packaging pattern from `docs/deploy/systemd-user-service.md`:

```sh
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/xenia-backup.service <<'EOF'
[Unit]
Description=Back up xenia-peer/xenia-operator-agent state

[Service]
Type=oneshot
ExecStart=/path/to/xenia-peer/scripts/xenia-backup.sh --out %h/backups/xenia --encrypt-to age1YOUR_RECIPIENT_HERE
EOF

cat > ~/.config/systemd/user/xenia-backup.timer <<'EOF'
[Unit]
Description=Daily xenia state backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now xenia-backup.timer
```

Replace `age1YOUR_RECIPIENT_HERE` with a real recipient (`age-keygen` to
generate one) -- **never schedule unencrypted backups to a location you
don't fully control.**


## Rollback-resistant consent-ledger restore

A consent ledger can be internally valid and still be an older, fully signed
snapshot. Keep a signed checkpoint outside the daemon state directory or backup
set and require it during restore:

```bash
xenia-peer \
  --consent-ledger-path /restore/xenia-peer-state/consent.ledger \
  --operator-key-path /restore/xenia-peer-state/operator.key \
  --trusted-consent-ledger-checkpoint /independent-retention/xenia-checkpoint.json \
  ...
```

The daemon verifies the checkpoint signature, ledger key, complete ledger
chain, and exact prefix head. A restored ledger shorter than the retained
checkpoint, or one that forks before that height, is refused.

Advance the independently stored pin only after the current ledger has been
verified:

```bash
xenia-peer \
  --consent-ledger-path /srv/xenia-peer-state/consent.ledger \
  --operator-key-path /srv/xenia-peer-state/operator.key \
  --advance-consent-ledger-checkpoint /independent-retention/xenia-checkpoint.json
```

An existing pin is replaced atomically only when the current ledger contains it
as an exact prefix. Do not store the checkpoint beside the state it is intended
to protect; rolling both back together defeats the anchor.

For frequent remote auditing, an authenticated operator can request
`GET /v1/audit/witness?after_entry_count=N`. The response includes every signed
entry after height `N` and a current signed checkpoint, allowing an auditor to
prove extension with `Verifier::verify_checkpoint_extension` without fetching
the complete ledger. Responses are capped at 4,096 entries; an auditor that
falls further behind must fetch the full authenticated ledger.

### Freshness, witnesses, and signer rotation

A retained checkpoint can also be required to satisfy a host-local freshness
SLA with `--trusted-consent-ledger-checkpoint-max-age-secs`. Use
`--trusted-consent-ledger-checkpoint-max-future-skew-secs` to bound future
clock skew.

For higher-assurance retention, supply a `CheckpointWitnessBundle`, repeat
`--trusted-consent-ledger-witness-key-hex` for each independently controlled
trusted witness, and set `--trusted-consent-ledger-witness-quorum`.

When the consent-ledger signer is intentionally rotated, start a fresh ledger
epoch and retain a dual-signed `LedgerKeyTransition` beside the old epoch's
final checkpoint. Restore the successor with
`--trusted-consent-ledger-key-transition`; never accept an unexplained ledger
key change.

Bounded verifiable archive segments can be exported with
`--export-consent-ledger-archive-segment` and
`--consent-ledger-archive-base-checkpoint`. Export does not delete live history.
See `docs/security/LEDGER_EPOCHS_WITNESSES_AND_ARCHIVES.md` for the exact
continuity and non-claim boundaries.
