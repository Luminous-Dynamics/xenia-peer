# Consent-Ledger Retirement, Purge & Final-Destruction Runbook

How to actually remove superseded consent-ledger artifacts (a plain ledger
file, a compaction bundle, a compacted snapshot) from disk, once compaction
(see
[`CONSENT_LEDGER_COMPACTION_RUNBOOK.md`](CONSENT_LEDGER_COMPACTION_RUNBOOK.md))
has moved a daemon off them. This is a real, adversarially-verified ceremony
(ported and reviewed in PRs #127-129) with a much larger and more
consequential flag surface than compaction -- it involves an operation that
genuinely deletes bytes -- so this runbook exists to make that ceremony
actually usable rather than something only discoverable by reading five
source files.

Every command below is a real CLI invocation, verified against the compiled
binary through quarantine (see [Verification](#verification-note) for
exactly how far live verification reaches and why).

## The ceremony, in order

1. **GC readiness certificate** -- proves it would be safe to eventually
   garbage-collect the cold archive from a compaction cutover.
2. **Retirement plan** -- names exact superseded bytes to move into
   quarantine. No file is touched yet.
3. **Retirement approval** -- an independent witness signs the plan.
4. **Quarantine** -- the *only* step so far with a real filesystem side
   effect: moves the named file(s) into a quarantine directory.
5. **Purge plan** -- names the quarantined copy for deletion. Requires the
   quarantine receipt to be at least 24 real hours old. No file is deleted
   yet.
6. **Purge approval** -- a second, independent witness signs the plan.
7. **Purge execution** -- the step that actually deletes bytes. Makes an
   independently-verified rollback copy first (see
   [What purge actually does](#what-purge-actually-does-and-does-not-do)).
8. **Retention certificate + witness + anchor** -- a ledger-signed
   obligation to keep the rollback package for a fixed period (protocol
   minimum 24h, operational default 30 days), witnessed and anchored.
9. **Custody attestation** -- an independent custodian asserts it holds a
   copy of the rollback package.
10. **Final-destruction plan, approval, and readiness** -- authorization
    *only*. See [What final destruction actually does](#what-final-destruction-actually-does-and-does-not-do)
    -- nothing here deletes the rollback package or anything else.

Every step after the first requires the artifacts from the step(s) before
it, and most require a genuinely distinct signing key from every other
step's key (ledger, retirement witness, purge witness, retention witness,
custodian, destruction witness) -- the CLI enforces this with real key-
separation checks, not just documentation (`ensure_purge_witness_separation`,
`ensure_custody_key_separation`, `ensure_final_destruction_key_separation`,
and equivalents), confirmed by reading each check, not assumed from naming.

## What purge actually does (and does not do)

**Purge deletes the *quarantined copy*, not the original.** By the time
purge runs, retirement's quarantine step has already moved the original out
of its live path (step 4). Purge's own execution
(`consent_purge::execute_consent_purge`) makes and verifies an independent
rollback copy *before* deleting the quarantined file -- confirmed by
reading the implementation, not assumed from the name. So after a
successful purge: the original live path is empty (freed since
quarantine), the quarantined copy is gone, and exactly one independently-
verified rollback copy survives under `--consent-purge-rollback-root`,
covered by the retention/custody/final-destruction steps that follow.

This is the one genuinely destructive operation in this whole runbook.
Everything before it (GC certificate, retirement plan, retirement approval,
quarantine, purge plan, purge approval) only moves or copies bytes, or
signs paperwork about bytes -- confirmed for real for the first four
below, see [Verification](#verification-note).

## What final destruction actually does (and does not do)

**Nothing.** `consent_final_destruction.rs`'s own module doc comment
states this explicitly, it was confirmed by a static call-graph audit
during the #129 adversarial review (no code path from
`ConsentFinalDestructionReadinessV1` to any filesystem removal call
anywhere in the crate), and the CLI's own output for
`--export-consent-final-destruction-readiness` says so too:
`this artifact authorizes no implicit cleanup implementation`. Reaching a
verified readiness certificate is the end of the ceremony -- it is a
signed statement that every prerequisite (retention obligation honored,
independent custody attested, witnessed quorum satisfied) has been met,
not a trigger for anything. If an operator wants to actually delete the
retained rollback package after reaching readiness, that is a manual,
out-of-band decision this tool deliberately does not automate.

## Prerequisites

You need a completed compaction cutover first -- an activated compacted
state and its retained pin (see the compaction runbook). Retirement's
own evidence-loading step (`load_consent_retirement_evidence`) requires
both, plus a GC readiness certificate you'll produce in Step 0 below.

```bash
KEY=xenia-peer-state/operator.key
STATE=xenia-peer-state/compaction/active-state.json
PIN=xenia-peer-state/compaction/state.pin
ARCHIVE=xenia-peer-state/compaction/archive-segment.json
WORK=xenia-peer-state/retirement
mkdir -p "$WORK"
```

**Every witness/custodian key in this ceremony must be generated
independently and must already exist -- the CLI will not silently
generate one for you** (unlike `--operator-key-path`, which auto-creates
on first use). Confirmed for real: `--sign-consent-retirement-plan`
against a nonexistent witness-key path fails with
`required signing key does not exist`, not a fresh key. Generate real
ones with a tool independent of the daemon, e.g.:

```bash
openssl genpkey -algorithm ed25519 -out /tmp/witness.pem
# Extract the raw 32-byte seed the daemon's --*-witness-key flags expect:
openssl pkey -in /tmp/witness.pem -noout -text \
  | sed -n '/^priv:/,/^pub:/p' | sed '1d;$d' | tr -d ' :\n' | xxd -r -p \
  > "$WORK/retirement-witness.key"
chmod 600 "$WORK/retirement-witness.key"
```

**There is no CLI flag to print your own operator key's public hex.**
Every "independent" verification/approval operation
(`--consent-retirement-ledger-public-key-hex` and equivalents) needs it,
and deriving it requires real Ed25519 math, not just reading the key
file. `openssl` can do it from the raw 32-byte seed via a fixed PKCS8
prefix:

```bash
SEED_HEX=$(xxd -p -c 64 "$KEY")
printf '302e020100300506032b657004220420%s' "$SEED_HEX" | xxd -r -p > /tmp/op-key.der
LEDGER_PUBKEY_HEX=$(openssl pkey -in /tmp/op-key.der -inform DER -noout -text \
  | sed -n '/^pub:/,$p' | tail -n +2 | tr -d ' :\n')
rm -f /tmp/op-key.der
```
Confirmed for real: the hex this derives matches exactly what the
`--sign-consent-retirement-plan` operation reports back as `witness
public key` for a key produced by the same derivation. Note this is a
real, if minor, tooling gap -- worth a follow-up if this ceremony sees
real use.

**Quarantine and rollback roots must be owner-only directories.** Confirmed
for real: `mkdir` defaults (0755) are rejected with
`InsecureQuarantineRootPermissions`.

```bash
mkdir -p "$WORK/quarantine" "$WORK/rollback"
chmod 700 "$WORK/quarantine" "$WORK/rollback"
```

## Step 0 -- GC readiness certificate

Prerequisite evidence for retirement planning, proving the compacted state
genuinely covers (via its archive) everything it claims to.

```bash
xenia-peer --operator-key-path "$KEY" \
  --consent-ledger-compacted-state "$STATE" \
  --trusted-consent-ledger-compacted-state-pin "$PIN" \
  --export-consent-ledger-compaction-gc-certificate "$WORK/gc-certificate.json" \
  --consent-ledger-gc-archive-segment "$ARCHIVE"
```

## Step 1 -- Retirement plan

Names the exact superseded file(s) to retire. Repeat
`--consent-retirement-complete-ledger-candidate` (or the
`-compaction-bundle-candidate` / `-compacted-snapshot-candidate` variants
for those artifact kinds) once per file. **The candidate cannot be any file
this ceremony's own evidence depends on** -- the active state, pin, GC
certificate, archive segment(s), or the operator key itself are all
protected paths; confirmed by reading `load_consent_retirement_evidence`'s
`protected_paths` construction.

```bash
xenia-peer --operator-key-path "$KEY" \
  --consent-ledger-compacted-state "$STATE" \
  --trusted-consent-ledger-compacted-state-pin "$PIN" \
  --consent-retirement-gc-certificate "$WORK/gc-certificate.json" \
  --consent-ledger-gc-archive-segment "$ARCHIVE" \
  --export-consent-retirement-plan "$WORK/retirement-plan.json" \
  --consent-retirement-quarantine-root "$WORK/quarantine" \
  --consent-retirement-complete-ledger-candidate /path/to/superseded-consent.ledger
```

Prints `no artifact was moved or deleted` -- still true at this point.

## Step 2 -- Retirement approval (independent witness)

Run this with a key and machine genuinely separate from the one holding
`--operator-key-path`, if your threat model calls for it -- the operation
itself never touches the ledger private key, only the plan's public
verification key:

```bash
xenia-peer --consent-retirement-ledger-public-key-hex "$LEDGER_PUBKEY_HEX" \
  --sign-consent-retirement-plan \
  --consent-retirement-plan-input "$WORK/retirement-plan.json" \
  --consent-retirement-approval-bundle "$WORK/retirement-approval.json" \
  --consent-retirement-witness-key "$WORK/retirement-witness.key"
```

Prints the witness's own public key and `the ledger private key was not
accessed` -- confirms this ran as a real independent-witness operation,
not a proxy for the ledger key.

## Step 3 -- Quarantine (first real filesystem change)

```bash
WITNESS_PUBKEY_HEX=$(openssl pkey -in /tmp/witness.pem -noout -text \
  | sed -n '/^pub:/,$p' | tail -n +2 | tr -d ' :\n')

xenia-peer --operator-key-path "$KEY" \
  --consent-ledger-compacted-state "$STATE" \
  --trusted-consent-ledger-compacted-state-pin "$PIN" \
  --consent-retirement-gc-certificate "$WORK/gc-certificate.json" \
  --consent-ledger-gc-archive-segment "$ARCHIVE" \
  --quarantine-consent-retirement \
  --consent-retirement-plan-input "$WORK/retirement-plan.json" \
  --consent-retirement-approval-bundle "$WORK/retirement-approval.json" \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_PUBKEY_HEX" \
  --trusted-consent-retirement-witness-quorum 1
```

**Confirmed for real: trusting a key that never actually signed the
approval is rejected outright** (`Error: UntrustedApprovalKey`), and the
candidate file is left untouched at its original path when that happens --
verified by running exactly this command with a well-formed but wrong
64-hex-character key before running it with the real one. Only the correct
trusted key moves the file: from its original path into
`$WORK/quarantine/<plan-id>/00-<hash>-<filename>`, alongside a
`receipt.json` and `journal.json`.

An independent party holding only the ledger's public key (not the private
key) can verify a quarantine receipt afterward:

```bash
xenia-peer --consent-retirement-ledger-public-key-hex "$LEDGER_PUBKEY_HEX" \
  --verify-consent-retirement-receipt "$WORK/quarantine/<plan-id>/receipt.json" \
  --consent-retirement-plan-input "$WORK/retirement-plan.json" \
  --consent-retirement-approval-bundle "$WORK/retirement-approval.json" \
  --trusted-consent-retirement-witness-key-hex "$WITNESS_PUBKEY_HEX" \
  --trusted-consent-retirement-witness-quorum 1
```

## Step 4 -- Purge plan (requires 24 real hours to have passed)

**This is a genuine, unbypassable 24-hour wait, not a configurable
default.** `--consent-purge-min-quarantine-age-secs` is not a bypass
knob -- confirmed for real by trying to set it to one hour:
`Error: InvalidMinimumAge { minimum: 86400, maximum: 31536000 }`. The CLI
enforces `[24h, 365d]` as the *allowed range for the parameter itself*,
and separately checks the quarantine receipt's actual age against
whatever value you pass. Confirmed for real by attempting a purge plan
immediately after quarantine with the flag correctly set to `86400`:
`Error: QuarantineAgeNotMet`. There is no CLI-level override, no
`--force`, and no way to backdate a receipt -- the daemon always calls the
real wall clock (`unix_now_secs()`) here, with no injectable override.
Plan your maintenance window accordingly.

```bash
xenia-peer --operator-key-path "$KEY" \
  --export-consent-purge-plan "$WORK/purge-plan.json" \
  --consent-purge-retirement-plan-input "$WORK/retirement-plan.json" \
  --consent-purge-retirement-approval-bundle "$WORK/retirement-approval.json" \
  --consent-purge-quarantine-receipt "$WORK/quarantine/<plan-id>/receipt.json" \
  --consent-purge-rollback-root "$WORK/rollback" \
  --consent-purge-min-quarantine-age-secs 86400
```

## Step 5 -- Purge approval (a second, independent witness)

Must be a genuinely different key from the retirement witness --
`--sign-consent-purge-plan` enforces this
(`ensure_purge_witness_separation`), rejecting a reused key rather than
silently accepting it.

```bash
xenia-peer --consent-retirement-ledger-public-key-hex "$LEDGER_PUBKEY_HEX" \
  --sign-consent-purge-plan \
  --consent-purge-plan-input "$WORK/purge-plan.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --consent-purge-witness-key "$WORK/purge-witness.key" \
  --consent-purge-retirement-plan-input "$WORK/retirement-plan.json" \
  --consent-purge-retirement-approval-bundle "$WORK/retirement-approval.json" \
  --consent-purge-quarantine-receipt "$WORK/quarantine/<plan-id>/receipt.json"
```

## Step 6 -- Execute the purge (the destructive step)

```bash
PURGE_WITNESS_PUBKEY_HEX=<derive from purge-witness.key the same way as Step 3>

xenia-peer --operator-key-path "$KEY" \
  --execute-consent-purge \
  --consent-purge-plan-input "$WORK/purge-plan.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --consent-purge-retirement-plan-input "$WORK/retirement-plan.json" \
  --consent-purge-retirement-approval-bundle "$WORK/retirement-approval.json" \
  --consent-purge-quarantine-receipt "$WORK/quarantine/<plan-id>/receipt.json" \
  --trusted-consent-purge-witness-key-hex "$PURGE_WITNESS_PUBKEY_HEX" \
  --trusted-consent-purge-witness-quorum 1
```

Deletes the quarantined copy; keeps a verified rollback copy under
`--consent-purge-rollback-root`. See
[What purge actually does](#what-purge-actually-does-and-does-not-do).

An independent party can verify a purge receipt (rollback package intact,
quarantine file genuinely gone) with `--verify-consent-purge-receipt`.
An interrupted purge (process killed mid-transaction) can be resumed or
rolled back with `--recover-consent-purge-journal`.

## Step 7 -- Retention certificate, witness, and anchor

Obligates keeping the rollback package for a fixed window
(`--consent-purge-retention-secs`, protocol minimum 24h, operational
default 30 days).

```bash
xenia-peer --operator-key-path "$KEY" \
  --export-consent-purge-retention-certificate "$WORK/retention-certificate.json" \
  --consent-purge-plan-input "$WORK/purge-plan.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --consent-purge-receipt-input "$WORK/purge-receipt.json" \
  --consent-purge-retention-secs 2592000   # 30 days

# Add an independent witness (distinct key again -- enforced):
xenia-peer --consent-retirement-ledger-public-key-hex "$LEDGER_PUBKEY_HEX" \
  --sign-consent-purge-retention-certificate \
  --consent-purge-retention-certificate-input "$WORK/retention-certificate.json" \
  --consent-purge-retention-witness-key "$WORK/retention-witness.key" \
  --consent-purge-retention-witness-bundle "$WORK/retention-witnesses.json" \
  --consent-purge-plan-input "$WORK/purge-plan.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --consent-purge-receipt-input "$WORK/purge-receipt.json"

# Anchor it (the immutable base every later renewal/custody/final-
# destruction operation verifies against):
xenia-peer --operator-key-path "$KEY" \
  --export-consent-purge-retention-anchor "$WORK/retention-anchor.json" \
  --consent-purge-retention-certificate-input "$WORK/retention-certificate.json" \
  --consent-purge-retention-witness-bundle "$WORK/retention-witnesses.json" \
  --consent-purge-plan-input "$WORK/purge-plan.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --consent-purge-receipt-input "$WORK/purge-receipt.json" \
  --trusted-consent-purge-retention-witness-key-hex "$RETENTION_WITNESS_PUBKEY_HEX" \
  --trusted-consent-purge-retention-witness-quorum 1
```

A retention obligation can be extended before it expires with
`--export-consent-purge-retention-renewal` (chained via
`--consent-purge-retention-renewal-chain`), and independently checked
against real files on disk with `--verify-consent-purge-retention-anchor`.

## Step 8 -- Custody attestation

An independent custodian (their own key, distinct from every prior key --
enforced) asserts it holds a copy of the rollback package. `--consent-purge-custody-class`
is `offline-media`, `remote-vault`, or `hardware-protected` -- an
assertion by the custodian, not something the daemon verifies with
hardware attestation (the CLI's own help text says so).

```bash
xenia-peer --consent-retirement-ledger-public-key-hex "$LEDGER_PUBKEY_HEX" \
  --sign-consent-purge-custody \
  --consent-purge-retention-certificate-input "$WORK/retention-certificate.json" \
  --consent-purge-retention-anchor-input "$WORK/retention-anchor.json" \
  --consent-purge-retention-witness-bundle "$WORK/retention-witnesses.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --consent-purge-custody-key "$WORK/custody.key" \
  --consent-purge-custody-bundle "$WORK/custody-bundle.json" \
  --consent-purge-custody-class remote-vault \
  --consent-purge-custody-locator "vault://independent-custodian/rollback-package" \
  --consent-purge-custody-replica-id-hex 00112233445566778899aabbccddeeff \
  --consent-purge-custody-available-secs 5184000   # 60 days
```

## Step 9 -- Final-destruction plan, approval, and readiness

Read
[What final destruction actually does](#what-final-destruction-actually-does-and-does-not-do)
first -- this produces a signed statement, nothing more.

```bash
xenia-peer --operator-key-path "$KEY" \
  --export-consent-final-destruction-plan "$WORK/destruction-plan.json" \
  --consent-purge-retention-certificate-input "$WORK/retention-certificate.json" \
  --consent-purge-retention-anchor-input "$WORK/retention-anchor.json" \
  --consent-purge-retention-witness-bundle "$WORK/retention-witnesses.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --consent-purge-custody-bundle "$WORK/custody-bundle.json" \
  --trusted-consent-purge-custody-key-hex "$CUSTODY_PUBKEY_HEX" \
  --trusted-consent-purge-custody-quorum 1

# A distinct final-destruction witness (enforced):
xenia-peer --consent-retirement-ledger-public-key-hex "$LEDGER_PUBKEY_HEX" \
  --sign-consent-final-destruction-plan \
  --consent-final-destruction-plan-input "$WORK/destruction-plan.json" \
  --consent-final-destruction-approval-bundle "$WORK/destruction-approval.json" \
  --consent-final-destruction-witness-key "$WORK/destruction-witness.key" \
  --consent-purge-retention-certificate-input "$WORK/retention-certificate.json" \
  --consent-purge-retention-anchor-input "$WORK/retention-anchor.json" \
  --consent-purge-retention-witness-bundle "$WORK/retention-witnesses.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json"

xenia-peer --operator-key-path "$KEY" \
  --export-consent-final-destruction-readiness "$WORK/destruction-readiness.json" \
  --consent-final-destruction-plan-input "$WORK/destruction-plan.json" \
  --consent-final-destruction-approval-bundle "$WORK/destruction-approval.json" \
  --consent-purge-custody-bundle "$WORK/custody-bundle.json" \
  --consent-purge-retention-certificate-input "$WORK/retention-certificate.json" \
  --consent-purge-retention-anchor-input "$WORK/retention-anchor.json" \
  --consent-purge-retention-witness-bundle "$WORK/retention-witnesses.json" \
  --consent-purge-approval-bundle "$WORK/purge-approval.json" \
  --trusted-consent-purge-custody-key-hex "$CUSTODY_PUBKEY_HEX" \
  --trusted-consent-purge-custody-quorum 1 \
  --trusted-consent-final-destruction-witness-key-hex "$DESTRUCTION_WITNESS_PUBKEY_HEX" \
  --trusted-consent-final-destruction-witness-quorum 1
```

Prints `this artifact authorizes no implicit cleanup implementation`.
`--verify-consent-final-destruction-readiness` lets an independent party
check a retained readiness artifact later using only public keys.

## Recovery from an interrupted transaction

Both quarantine and purge are transactional with a journal; if the process
is killed mid-operation, `--recover-consent-retirement-journal <FILE>` /
`--recover-consent-purge-journal <FILE>` finalize a receipted transaction
or roll it back to its pre-transaction state, never leave it half-done.
Neither was exercised live in this runbook's verification pass --
verified in-process by the `full_consent_ledger_maintenance_ceremony_end_to_end`
test's sibling recovery tests in `consent_retirement.rs`/`consent_purge.rs`.

## Verification note

**Verified live against the compiled binary, through quarantine**: the GC
certificate, retirement plan, retirement approval (including deriving an
operator's own public key hex with `openssl`, since no CLI flag prints
it), the quarantine-root permission requirement, the untrusted-witness-key
rejection (`UntrustedApprovalKey`, candidate file provably left in place),
the correct-key quarantine (candidate file provably moved), and independent
receipt verification. Then, immediately after: the unbypassable 24-hour
purge floor, confirmed two ways -- attempting the flag itself below 24h
(`InvalidMinimumAge`) and attempting a purge plan against a real
just-quarantined receipt (`QuarantineAgeNotMet`).

**Not re-run live in this pass**: purge execution through final-destruction
readiness, because doing so for real requires the genuine 24-hour wait
this runbook just proved is unbypassable -- not something a documentation
pass can fake or skip past. Those steps' exact flag names, argument
combinations, and JSON I/O shapes were extracted by direct reading of each
CLI dispatch block in `main.rs` (not inferred from `--help` text alone),
cross-checked against `--help`'s own flag descriptions, and the ceremony's
*logical* correctness (does purge really make a rollback copy before
deleting, does final destruction really delete nothing, does each witness
separation check really reject a reused key) is the same ceremony
independently adversarially verified end-to-end, in-process, by
`full_consent_ledger_maintenance_ceremony_end_to_end` in
`consent_ceremony_end_to_end_tests.rs` (Phase 3, PR #129) -- that test
drives every one of these steps for real via the same `pub(crate)`
functions the CLI dispatch calls, with a synthetic-but-internally-
consistent timeline satisfying the real 24-hour floor. If this ceremony
sees real production use, re-verifying Steps 4-9 live (accepting the real
wait, or from a second session picking up where this one left off) is the
natural next hardening pass.

## Quick reference

| Step | Primary flag |
|---|---|
| GC readiness certificate | `--export-consent-ledger-compaction-gc-certificate` |
| Retirement plan | `--export-consent-retirement-plan` |
| Retirement approval | `--sign-consent-retirement-plan` |
| Quarantine | `--quarantine-consent-retirement` |
| Verify quarantine receipt | `--verify-consent-retirement-receipt` |
| Recover interrupted quarantine | `--recover-consent-retirement-journal` |
| Purge plan | `--export-consent-purge-plan` (24h floor, real) |
| Purge approval | `--sign-consent-purge-plan` |
| Execute purge | `--execute-consent-purge` |
| Verify purge receipt | `--verify-consent-purge-receipt` |
| Recover interrupted purge | `--recover-consent-purge-journal` |
| Retention certificate | `--export-consent-purge-retention-certificate` |
| Retention witness | `--sign-consent-purge-retention-certificate` |
| Retention anchor | `--export-consent-purge-retention-anchor` |
| Verify retention anchor | `--verify-consent-purge-retention-anchor` |
| Retention renewal | `--export-consent-purge-retention-renewal` |
| Custody attestation | `--sign-consent-purge-custody` |
| Final-destruction plan | `--export-consent-final-destruction-plan` |
| Final-destruction approval | `--sign-consent-final-destruction-plan` |
| Final-destruction readiness | `--export-consent-final-destruction-readiness` |
| Verify readiness (no deletion happens) | `--verify-consent-final-destruction-readiness` |

Full flag documentation: `xenia-peer --help`.
