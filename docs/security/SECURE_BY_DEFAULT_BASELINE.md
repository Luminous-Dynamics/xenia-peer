# Xenia Secure-by-Default Baseline

Xenia is a capture, transport, viewing, and possible control stack. That puts it
close to abuse-prone remote-administration territory. The baseline rule is:

> A demo may be incomplete, but it must not be silently powerful.

## Required defaults

Until an explicit release-cut review changes the policy:

- remote control is disabled by default;
- capture is disabled by default;
- injection is disabled by default;
- unattended access is not supported as a default mode;
- privileged sessions require visible consent;
- revocation fails closed;
- privileged sessions require ledger/audit events;
- public bind addresses require an explicit operator flag and review;
- plaintext credentials are not allowed;
- silent session start is not allowed.

These defaults are encoded in `xenia.safety.toml` and checked by
`scripts/check-secure-defaults.py`.

## Public bind rule

Loopback is the only acceptable pre-production default:

```text
127.0.0.1
localhost
::1
```

Binding to all interfaces, including `0.0.0.0`, `::`, or `[::]`, requires a
review note explaining:

1. which binary owns the bind;
2. which CLI/config flag enabled it;
3. whether authentication happens before any privileged action;
4. whether consent and revocation are visible to the controlled side;
5. which ledger events are emitted.

## Consent bypass rule

Any diff containing phrases such as `skip_consent`, `disable_consent`,
`bypass_consent`, or `fail_open` is a security review item, even if the code is
inside a demo or test harness.

## RC implication

Before RC1, run:

```bash
scripts/check-secure-defaults.py . --strict
scripts/generate-release-dashboard.py . \
  --markdown _archive/release-dashboard.md \
  --json _archive/release-dashboard.json
```

Strict mode does not prove security; it forces all warnings to be consciously
reviewed before release-candidate work.
