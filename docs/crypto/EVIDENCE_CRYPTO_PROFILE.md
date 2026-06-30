# Evidence Crypto Profile

Status: post-RC1 hardening contract.

This document defines the minimum crypto metadata that every Xenia evidence
artifact must carry. It is deliberately stricter than implementation status:
current artifacts may still use classical signatures, but they must label that
fact so auditors, tests, and product claims cannot confuse ML-KEM key
establishment with full post-quantum authentication.

## Why this exists

A consent transcript is only useful if a verifier can answer three questions
without trusting the operator UI:

1. What algorithms produced this evidence?
2. Was any classical-only primitive used on an authority/signature surface?
3. Did policy permit that primitive for this session profile?

Xenia's answer should be machine-readable. Human docs are not enough.

## Required labels

Every session evidence export, ledger export, and verifier summary should expose
these fields or equivalent names:

| Field | Meaning | Current value | Full-PQC target |
|---|---|---|---|
| `profile` | Policy class used to accept/reject algorithms. | `hybrid-pre-pqc-v1` | `full-pqc-v1` |
| `kem` | Key establishment / encapsulation suite. | `ml-kem-768-fips203` | `ml-kem-768-fips203` or stronger |
| `transcript_signature` | Signature suite authenticating the session transcript. | `ed25519-rfc8032` | `ml-dsa-65-fips204` or `slh-dsa-*` |
| `ledger_signature` | Signature suite for consent-ledger entries. | `ed25519-rfc8032` | `ml-dsa-65-fips204` or `slh-dsa-*` |
| `hash_chain` | Per-entry hash/link function. | `blake3-256` | `blake3-256` or compliance profile hash |
| `kdf` | Session-key derivation function. | `hkdf-sha256` | `hkdf-sha384`/`hkdf-sha512` optional |
| `aead` | Frame sealing primitive. | `chacha20-poly1305` via `xenia-wire` | `chacha20-poly1305` or `aes-256-gcm` |
| `downgrade_policy` | Whether fallback to classical auth/signatures was allowed. | explicit allow only | reject in full-PQC |

## Profile semantics

### `hybrid-pre-pqc-v1`

Allowed:

- ML-KEM-768 key establishment.
- Ed25519 transcript authentication.
- Ed25519 ledger signatures.
- BLAKE3 ledger hash chain.

Required label:

> Hybrid pre-PQC: session key establishment is post-quantum; authentication and
> ledger signatures are classical Ed25519.

### `full-pqc-v1`

Required:

- ML-KEM key establishment.
- ML-DSA or SLH-DSA transcript authentication.
- ML-DSA or SLH-DSA consent-ledger signatures.
- No silent Ed25519 fallback.
- Verifier failure if any entry or transcript is classical-only unless the
  artifact is explicitly historical and outside the full-PQC policy.


## Manifest enforcement

`EVIDENCE_CRYPTO_MANIFEST.md` defines the JSON evidence artifact that carries
these labels under schema `xenia-evidence-crypto-manifest-v1`. The companion
checker `scripts/check-evidence-manifests.py` keeps fixture behavior
contractual: hybrid/pre-PQC manifests must explicitly allow classical
signatures, while `full-pqc-v1` manifests must use
`reject-classical-signatures` and reject Ed25519 on transcript and ledger
signature surfaces.

## Acceptance rule

A PR that touches evidence export, handshake, ledger, admin policy, or release
artifacts should either:

1. emit these labels directly;
2. preserve them unchanged; or
3. update this document and the verifier tests in the same PR.

Do not add a new signature or KEM dependency without adding its stable label and
policy behavior first.
