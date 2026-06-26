# Xenia RC1 Candidate Checklist

This checklist is not a promise that Xenia is ready for users. It defines the
minimum bar before cutting a release-candidate branch.

## Tree hygiene

- [ ] `scripts/xenia-hygiene-audit.sh .` passes.
- [ ] No `target/`, `dist/`, `pkg/`, `node_modules/`, tarballs, or nested `.git`
      directories exist in active source paths.
- [ ] Historical material is archived under `_archive/YYYY-MM-DD-*`.
- [ ] `scripts/check-source-archive.sh` passes on the generated source archive.

## Boundary and policy

- [ ] `scripts/check-xenia-policy.py .` passes.
- [ ] `scripts/check-cargo-boundaries.py .` passes.
- [ ] `xenia-wire` remains product-independent.
- [ ] Apps do not leak back into library crates.
- [ ] The workspace is either explicitly `transitional` or fully `normalized` in
      `xenia.policy.toml`.

## Security and abuse review

- [ ] `docs/security/THREAT_MODEL.md` reviewed for the release diff.
- [ ] `docs/security/CONSENT_AND_ABUSE_CASES.md` reviewed for the release diff.
- [ ] Capture and input are disabled unless consent is established.
- [ ] Revocation fails closed and is covered by tests.
- [ ] Operator/admin surfaces require authentication before privileged actions.
- [ ] Development keys and local-only trust assumptions are absent from release
      artifacts.

## Runtime quality

- [ ] `scripts/check-runtime-risk-patterns.py .` reviewed.
- [ ] `scripts/check-runtime-risk-patterns.py . --strict` either passes or has a
      tracked exception list approved for RC1.
- [ ] Spawned tasks log errors and terminate safely rather than panicking.
- [ ] Transport disconnects, malformed frames, replay attempts, and stale consent
      responses are tested.

## Build validation

- [ ] `scripts/xenia-validate.sh .` passes.
- [ ] `scripts/nix-xenia-check.sh .` passes on a Nix-capable host.
- [ ] `cargo test --workspace --all-targets` passes for each workspace root.
- [ ] Web/admin artifacts are rebuilt from source and not checked in as release
      source truth.
