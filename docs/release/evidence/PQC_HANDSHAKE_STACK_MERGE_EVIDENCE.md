# PQC + Handshake Stack Merge Evidence

Date: 2026-07-02

## Merged PRs

- PR #43: PQ signature vector harness contract
- PR #44: Handshake transcript context and rekey epochs
- PR #45: PQC evidence verification boundary

## Post-merge validation

After merging the stack bottom-up into `main`, the repository was updated with:

```sh
git switch main
git pull --ff-only
CARGO_TARGET_DIR=/tmp/xenia-peer-target-final scripts/xenia-validate.sh
Observed result:

hygiene audit passed
shell syntax checks passed
Python script compilation checks passed
policy manifest check passed
CODEOWNERS check passed
secure-default scan reported no hard failures
PQC claim checks passed
PQC negative guards passed
evidence manifest checks passed
transcript-bound evidence checks passed
real PQC signature backend check passed
full-PQC runtime refusal gate passed
PQ signature vector harness contract passed
release readiness manifest passed with hard_blockers=0 and soft_blockers=0
cargo validation completed
cargo-deny completed with warnings only
Intentional warning follow-up

The secure-default scanner previously reported one warning for loopback-only websocket usage in scripts/xenia-audio-e2e-smoke.sh.

That endpoint is local smoke-test traffic only. It is not a production network default, and it is now recorded as a narrowly reviewed warning in xenia.policy.toml.
