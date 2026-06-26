# Xenia Runtime Risk Register

This register tracks code patterns that are acceptable during prototyping but
must be reduced before a release candidate.

## Why this matters

Xenia touches screen capture, input injection, transports, consent state, and
operator administration. A panic or unchecked assumption in the wrong layer can
become a denial-of-service, stuck-control, missing-revocation, or audit-gap
failure.

## Current automated scan

Run:

```bash
scripts/check-runtime-risk-patterns.py .
```

For release-candidate work:

```bash
scripts/check-runtime-risk-patterns.py . --strict
```

## Pattern policy

| Pattern | Prototype status | Release-candidate expectation |
| --- | --- | --- |
| `unwrap()` | tolerated in tests/examples, discouraged in runtime source | replace with typed errors or explicit fallback |
| `expect()` | tolerated only with invariant comment or test context | replace or justify with impossible-condition proof |
| `panic!()` | acceptable in tests only | no runtime panics for recoverable conditions |
| `todo!()` / `unimplemented!()` | allowed only behind non-default experimental paths | absent from release builds |

## Preferred replacements

- Return `Result<T, XeniaError>` from library boundaries.
- Log and fail closed in daemon/app tasks.
- Treat consent/authorization uncertainty as denial.
- Convert decoding, transport, and capture failures into typed telemetry events.
- Keep tests expressive, but do not allow test ergonomics to hide runtime debt.
