# RC1 Source Archive Checksum Evidence

Status: generated for RC1 soft-blocker review.

This evidence verifies that Xenia source archive generation is deterministic,
source-only, and paired with a checksum manifest. It does not promote Xenia
to RC1 and does not close unrelated soft blockers.

## Archive identity

- Archive name: `xenia-peer-source.tar.gz`
- Archive SHA-256: `f3097498dfa7d5a87a1bb2c20ab7d2a61f58f5ddabe94d022fb661f962702391`
- Inventory SHA-256: `9a2e451df7a639eb44123a1c39bc91f6e52eb3f8f7004a0e60bfd4a0366d0f6e`
- Entries: `226`
- Files: `175`
- Reproducible rebuild: `True`

## Checks

- `export-source-archive`: `pass` / exit `0`
- `export-source-archive-rebuild`: `pass` / exit `0`
- `check-source-archive`: `pass` / exit `0`

## Non-goals

- Does not commit generated tarballs.
- Does not remove runtime-risk, fault-injection, observability, or dashboard soft blockers.
- Does not change `release_train.status`.
