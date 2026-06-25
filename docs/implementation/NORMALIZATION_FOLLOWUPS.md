# Xenia Normalization Follow-ups

Status: after normalization-v0.2 checkpoint.

## Before RC1

- Replace CODEOWNERS placeholder with the real maintainer/team.
- Move `sovereign-admin` profile settings from app Cargo.toml to workspace Cargo.toml.
- Review secure-default warnings for local `http://` and `ws://` endpoints.
- Replace runtime `unwrap` / `expect` in app/runtime paths with explicit error handling.
- Review and document `unsafe impl Send for CachedScaler`.
- Resolve or explicitly document cargo-deny duplicate dependency warnings.
- Remove temporary bincode advisory exception by migrating serialization.
- Decide whether `xenia-wire` remains an external sibling or becomes a formal workspace boundary.
- Run `check-release-readiness.py --rc1` only after the above are closed.

## Not blockers for normalization-v0.2

- Placeholder UI pages in sovereign-admin.
- Pre-alpha descriptions.
- Test/example `unwrap`.
- cargo-deny duplicate warnings from GUI/network dependency stacks.
