# xenia-path-trust

Standalone pre-integration contract for Xenia's Unix component-wise directory trust rule.

It is intentionally small:

- descriptor-relative component walking;
- `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` on every traversed component;
- `..` rejection;
- descriptor-relative creation of missing components;
- exact-current-uid ownership of the final private directory;
- final `0700` tightening;
- no root ownership exemption;
- the verified directory descriptor is retained for subsequent descriptor-relative work.

The critical non-goal is equally important: validating a path here and then reopening that path through another path-based API does not inherit the descriptor guarantee. See `docs/ADR-011-component-wise-path-trust.md`.

This crate is deliberately an independent workspace while the contract is being qualified. Before production promotion, retain its exact `Cargo.lock` and integrate it under the repository's normal workspace evidence boundary.
