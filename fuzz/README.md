# Fuzzing xenia-peer

Coverage-guided fuzz harness on top of `cargo-fuzz` + `libfuzzer-sys`,
mirroring `xenia-wire`'s own `fuzz/` (same crate shape, same conventions).
Requires nightly Rust.

## Setup (once)

```console
$ rustup toolchain install nightly
$ cargo install cargo-fuzz
```

## Run a target

```console
$ cargo +nightly fuzz run fuzz_agent_request     -- -max_total_time=300
$ cargo +nightly fuzz run fuzz_evidence_verify   -- -max_total_time=300
```

`-max_total_time=300` runs the target for 5 minutes and exits. Drop the flag
for an open-ended run -- cargo-fuzz persists corpus + crash artifacts under
`fuzz/corpus/<target>/` and `fuzz/artifacts/<target>/`.

## Targets

| Target | What it exercises |
|--------|-------------------|
| `fuzz_agent_request` | `serde_json::from_slice` over every `xenia-operator-agent` `/v1/*` request DTO (`SignChallengeRequest`, `SignConsentActionRequest`, `SignRevokeRequest`, `HandshakeBeginRequest`, `HandshakeFinishRequest`) -- what axum's `Json<T>` extractor deserializes from an untrusted HTTP body. |
| `fuzz_evidence_verify` | JSON-decodes a `DaemonIdentityCertificate`, then -- on success -- runs the same hex-decode + dual-signature-verify + fingerprint steps `xenia-operator-agent`'s `daemon_evidence::verify_daemon_certificate` performs, using the same public library primitives (that function itself lives in a binary-only crate and isn't directly reachable -- see the target's own doc comment). |

## Reporting findings

If a target produces a crash, `fuzz/artifacts/<target>/crash-*` is the
reproducer. Please follow this repo's security disclosure policy -- do not
open a public issue with the reproducer.
