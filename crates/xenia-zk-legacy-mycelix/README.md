# xenia-zk-legacy-mycelix

Explicit compatibility helpers for historical Mycelix authenticated-proof V2.

This crate is intentionally **not** a dependency of `xenia-zk-protocol`, and no
Xenia V3 verifier should call it as a fallback. Applications that retain a
legacy-proof acceptance window must select this adapter explicitly and apply a
separate legacy signature/key policy.

The exact V2 signing domain and golden digest are frozen here so source migration
does not become an accidental cryptographic protocol migration.
