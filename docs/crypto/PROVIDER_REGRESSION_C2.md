# Xenia Crypto Provider Regression v1 — C2

Status: provenance-pinned ML-DSA-65 advisory regression contract.

## Subject

C2 replays one exact public Wycheproof invalid-signature case through the production Xenia verifier boundary:

```text
pinned C2SP/Wycheproof corpus
        ↓
local Git-blob identity check
        ↓
exact tcId 19 extraction
        ↓
raw public key / message / signature bytes
        ↓
HandshakeManager::verify_ml_dsa
        ↓
REJECT required
```

The runner also generates and verifies a fresh Xenia ML-DSA-65 signature first. Therefore the evidence distinguishes “provider/verifier cannot verify anything” from “provider/verifier specifically rejects the adversarial vector.”

## Immutable upstream provenance

The checked-in provenance contract pins:

- `C2SP/wycheproof` commit `3fa63dd0344abb611f1fb1d77e119938603ea230`;
- root tree `a774df247e34ac2c414a55913f58d70ca37af29f`;
- `testvectors_v1` tree `8486adbdb050483c5a450d650466f0123c488976`;
- `testvectors_v1/mldsa_65_verify_test.json` Git blob `049f74be9785af926623e56530ab3aa9384179e8`;
- Wycheproof license blob `7a4a3ea2424c09fbe48d455aed1eaa94d9124835` (Apache-2.0).

The corpus itself is not manually copied into this repository. The dedicated evidence job fetches the immutable raw URL at the pinned commit and computes the Git blob object identity locally before parsing any test data.

## Exact regression case

The extractor requires exactly one case with:

```text
algorithm = ML-DSA-65
type      = MlDsaVerify
tcId      = 19
comment   = signature with a repeated hint
message   = 01 00...00 (32 bytes)
result    = invalid
flag      = InvalidHintsEncoding
```

It takes the public key from the owning test group and requires exact FIPS-204 sizes expected by Xenia:

- public key: 1952 bytes;
- signature: 3309 bytes;
- message: 32 bytes.

The extraction receipt records SHA-256 digests of all three extracted artifacts in addition to the upstream Git blob identity.

## Provider binding

C2 remains bound to the 001A production subject:

```text
ml-dsa
0.1.1
add6b9d92e496f16f4526d68ff29da1483aba4b119baeab8bed3b9e3544a6f3d
```

The upstream vector is not treated as a provider or implementation. It is adversarial test evidence.

## Network boundary

Ordinary Xenia builds and `cargo test` remain network-independent.

Only the dedicated C2 evidence workflow fetches the immutable upstream file. The workflow does not trust the transport or URL contents by themselves: the extractor recomputes the Git blob identity and refuses a mismatch before extracting bytes.

This is different from the 001B mutable external-evidence snapshot, whose CI deliberately performs no live refresh. C2 fetches an immutable content-addressed qualification input.

## Negative controls

The extractor must reject in-memory mutations for:

1. wrong upstream Git blob identity;
2. wrong tcId;
3. expected result changed to `valid`;
4. missing expected `InvalidHintsEncoding` flag;
5. substituted message;
6. duplicate tcId 19.

The Rust runner must additionally fail if:

- its Xenia-generated positive control does not verify; or
- tcId 19 verifies successfully.

## Advisory relationship

The provenance contract records `GHSA-5x2r-hc65-25f9` as context for why this vector class matters. Advisory metadata and vector provenance are separate evidence objects: the security invariant tested here is the exact invalid-vector rejection, not a broad claim inferred from an advisory version range.

## Claim ceiling

A C2 PASS establishes only that the exact locked Xenia ML-DSA verifier rejects this exact pinned repeated-hint vector on the recorded build target while accepting its positive control.

It does not establish complete FIPS 204 conformance, absence of all encoding defects, constant-time behavior, ML-DSA primitive security, hybrid-signature composition security, or Xenia handshake/protocol security.
