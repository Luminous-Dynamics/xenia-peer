# Full-PQC Migration Plan

Status: post-RC1 hardening plan.

Xenia can move to a full post-quantum posture, but it should do so as a staged
migration rather than by relabeling the current stack. Today, `xenia-handshake`
uses ML-KEM-768 for key establishment and Ed25519 for identity/transcript
authentication. `xenia-ledger` uses Ed25519 signatures over BLAKE3 hash-chain
entries. That is a strong hybrid/pre-PQC foundation, but it is not full-PQC.

## Claim boundary

Use these terms consistently:

| Term | Meaning in Xenia | Safe claim |
|---|---|---|
| Classical | RSA/ECC signatures or key exchange only. | Avoid for new privileged-access surfaces. |
| PQ key establishment | Session secrecy comes from ML-KEM-derived key material. | Safe for passive harvest-now-decrypt-later mitigation when transcript binding is correct. |
| Hybrid PQ/T | PQ and traditional algorithms are both present. | Safe current direction for compatibility and migration. |
| Full-PQC | Key establishment and authentication/signatures are post-quantum. | Future target, not current status. |

Do not claim "entirely PQC", "full-PQC", or "PQC at every layer" until all
signature-bearing surfaces below have PQ verification paths and downgrade tests.

## Required algorithm baseline

- **Key establishment:** ML-KEM-768 baseline; ML-KEM-1024 option for high-sensitivity profiles.
- **Online signatures:** ML-DSA-65 baseline; ML-DSA-87 option for high-sensitivity profiles.
- **Offline/root signatures:** SLH-DSA as an optional conservative root or release-signing profile where signature size/performance is acceptable.
- **Symmetric sealing:** Continue ChaCha20-Poly1305 or move to AES-256-GCM where platform acceleration/certification requires it. Symmetric crypto is not "PQC" in the same sense, but 256-bit symmetric security is the conservative quantum-era target.
- **Hashing:** Keep BLAKE3 for internal hash-chain performance only if the threat model accepts a non-FIPS hash. Use SHA-384/SHA-512/Shake-based transcript hashes for compliance profiles if required.

## Migration stages

### Stage 0 — honest hybrid status

Goal: prevent accidental overclaiming.

- Document that ML-KEM protects session key establishment, while Ed25519 still authenticates peers and signs consent/ledger records.
- Add checks that block marketing/compliance phrases such as "entirely PQC" outside migration documents.
- Keep current Ed25519 formats stable while adding version fields for future signature agility.

### Stage 1 — signature agility types

Goal: make signatures versioned before adding new crypto crates.

- Replace fixed `signature: [u8; 64]` fields in ledger/export formats with a tagged signature envelope.
- Add algorithm identifiers such as `ed25519-v1`, `ml-dsa-65-v1`, `ml-dsa-87-v1`, `slh-dsa-sha2-128s-v1`.
- Keep Ed25519 verification as the default compatibility mode.
- Add test vectors for unknown algorithms, wrong algorithm labels, and mixed-chain rejection.

### Stage 2 — PQ transcript authentication

Goal: prevent quantum-era active impersonation.

- Add ML-DSA verification over the handshake transcript.
- Bind both peers' ML-KEM public keys, nonces, consent request ID, wire session fingerprint, and chosen transport into the signed transcript.
- Add downgrade resistance: if a peer advertises full-PQC support, a classical-only transcript must fail unless explicitly permitted by policy.

**Status (2026-07-02): native handshake done, browser not started.** `xenia-handshake`'s
`HandshakeManager` and the live `xenia-peer-core` driver
(`perform_host_handshake_with_transcript_and_context`/
`perform_viewer_handshake_with_transcript`) now dual-sign every handshake:
`HostHello`/`ViewerResponse`/`HostFinalize` carry ML-DSA-65 public keys and
signatures alongside Ed25519, both signature transcripts bind the new
fields, and verification requires both algorithms (AND composition, no
classical-only fallback) — see ROADMAP.md row B4. This covers native
`xenia-peer`/`xenia-viewer` only. `xenia-viewer-web`'s `WasmHandshake`
still speaks the Ed25519-only transcript and will not interoperate with a
dual-signing native peer until it is updated to match — that work has not
started. Downgrade-resistance policy (classical-only transcript rejection
when a peer advertises full-PQC support) is also not yet implemented; today
both algorithms are simply always required.

### Stage 3 — PQ ledger signatures

Goal: make consent evidence quantum-resistant.

- Add `xenia-ledger` support for ML-DSA-signed entries.
- Keep verifier support for historical Ed25519 chains.
- Require new chains to declare a chain signature policy at genesis: `classical`, `hybrid`, or `full-pqc`.
- Add migration evidence: one Ed25519 historical chain, one hybrid chain, one full-PQC chain, and tamper tests for each.

### Stage 4 — PQ identity and admin policy

Goal: remove Ed25519 as an authority root for full-PQC deployments.

- Add PQ DID key material and key-rotation ceremonies.
- Require admin policy, mitigation rules, release artifacts, and operator enrollment records to verify under PQ signatures.
- Keep bridge records that map historical Ed25519 identities to PQ identities with dual-signed migration events.

### Stage 5 — full-PQC profile gate

Goal: make `--crypto-profile full-pqc` meaningful.

The profile should require:

- ML-KEM session establishment;
- ML-DSA or SLH-DSA transcript authentication;
- ML-DSA or SLH-DSA consent/ledger signatures;
- PQ-signed policy bundles;
- no silent fallback to Ed25519;
- evidence export that states the negotiated algorithms.

## Acceptance tests

A full-PQC PR is not done until these fail/pass conditions exist:

1. A full-PQC peer refuses a classical-only signature chain.
2. A full-PQC peer refuses a downgraded handshake after advertising PQ support.
3. A verifier reports the algorithm used for every ledger entry.
4. A tampered ML-DSA ledger entry fails with the same severity as a bad Ed25519 entry.
5. A historical Ed25519 chain remains verifiable but is labeled `classical-signature`.
6. A session evidence export includes KEM, signature, hash, AEAD, and transcript labels.

## Product wording

Safe now:

> Xenia is building toward a full-PQC remote-session profile. The current
> pre-alpha stack uses ML-KEM-based key establishment with classical Ed25519
> authentication/signatures, plus an explicit migration path to ML-DSA/SLH-DSA.

Safe after Stage 5 only:

> Xenia supports a full-PQC profile with post-quantum key establishment,
> transcript authentication, consent-ledger signatures, and policy signatures.


## Next implementation bridge: signature envelopes

The first code-level bridge toward full-PQC ledger verification is
`SignatureEnvelope` in `xenia-ledger`. It keeps the M1 append path compatible
with fixed-size Ed25519 entries, while exported evidence uses a tagged shape:

```text
algorithm = ed25519-rfc8032 | ml-dsa-65-fips204 | ml-dsa-87-fips204 | slh-dsa-fips205
signature = raw signature bytes
```

Do not add an ML-DSA dependency until the verifier can be paired with FIPS
204-compatible test vectors and downgrade tests. Until then, the exported shape
may carry PQ signature labels, but the current verifier must reject them as
unsupported rather than pretending to verify them.
