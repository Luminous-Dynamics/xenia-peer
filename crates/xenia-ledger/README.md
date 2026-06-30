# xenia-ledger

Append-only, hash-chained, Ed25519-signed consent ledger for the Xenia remote-session stack, with algorithm-tagged signature envelopes for exported evidence.

## What it does

Every privileged Xenia session produces a sequence of consent events — request, approval, denial, revocation, violation. `xenia-ledger` turns that stream into a cryptographic record with three properties:

1. **Append-only** — entries reference the hash of the prior entry, so reordering or deletion invalidates the chain.
2. **Hash-chained** — blake3 over `(seq, prev_hash, timestamp, event)` per entry.
3. **Signed** — Ed25519 over each entry's hash today, using the operator's key. Exported evidence carries an algorithm-tagged `SignatureEnvelope` so ML-DSA/SLH-DSA can be added without another export-schema break.

The effect: an auditor holding only the operator's public key can verify, offline, that the ledger has not been rewritten since each entry was signed. The current verifier accepts Ed25519 envelopes and explicitly rejects PQ signature envelopes until a real ML-DSA/SLH-DSA backend lands. Long-lived evidence exports should use `Verifier::verify_evidence_bundle(...)` so the manifest cannot overstate the signature suite carried by the entry envelopes.

This is the enforcement layer behind the Mycelix Sovereign threat-model claim that **an administrator cannot silently rewrite the audit log of their own privileged sessions**.

## License exception

This crate is licensed **AGPL-3.0-or-later**.

This deviates from [xenia-peer ADR-001 Decision 3](../../docs/ADR-001-m0-architecture.md), which established a pattern of permissive-license (`Apache-2.0 OR MIT`) library crates sitting alongside AGPL daemon binaries. The other library crates in this workspace (`xenia-peer-core`, `xenia-capture`, `xenia-handshake`, `xenia-inject`) follow that pattern. `xenia-ledger` does not.

Rationale, per the [Mycelix Sovereign suite plan](../../../MYCELIX_SOVEREIGN_PLAN.md):

- **The verifiable-consent ledger is the cryptographic moat of the commercial suite.** If we ship it permissive, a competitor can wrap Xenia into a proprietary remote-access product whose audit log inherits our "third-party-verifiable" property without contributing back.
- **The surrounding permissive ecosystem is unaffected.** A community implementer can use `xenia-wire` + `xenia-peer-core` + `xenia-handshake` + `xenia-capture` + `xenia-inject` to build a compatible Xenia client under any license — they just need to bring their own ledger.
- **The library/application distinction that ADR-001 drew doesn't map cleanly here.** This crate has no IO, no transport, no UI — it's a library shape. But functionally, it is the commercial product. The license follows the function, not the shape.

A later ADR will formally record this exception.

## Usage

```rust
use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, Verifier};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use uuid::Uuid;

let sk = SigningKey::generate(&mut OsRng);
let pk = sk.verifying_key();

let mut chain = Chain::new(sk);
chain.append(ConsentEventRecord {
    source_id: [0xAB; 32],
    session_id: Uuid::new_v4(),
    request_id: Uuid::new_v4(),
    kind: ConsentKind::Request,
    scope: "view screen, inject input".into(),
})?;
// ... more events ...

let exported = chain.export_entries();
let manifest = Verifier::evidence_crypto_manifest();
// serialize `manifest` + `exported` however you like (JSON, CBOR, SQLite, ...)

// Later, an auditor should verify the manifest and exported chain together:
Verifier::verify_evidence_bundle(manifest, &exported, &pk)?;
```

See the crate docs for the full API.

## Verification boundary

The verifier proves that a supplied chain is internally contiguous, hash-linked,
and signed by the expected operator public key. It does **not** by itself prove
operator key custody, wall-clock timestamp truth, honest UI presentation, host OS
integrity, or legal sufficiency of a consent ceremony. Those are companion
deployment controls. See
[`docs/security/LEDGER_VERIFICATION_BOUNDARY.md`](../../docs/security/LEDGER_VERIFICATION_BOUNDARY.md)
for the full claim boundary.

## Status

**Pre-alpha.** Scaffold with ~480 LOC, 8 tests covering:

- Empty chain verification
- Genesis entry invariants (seq=0, prev_hash=0)
- Multi-entry chain linkage
- Tampering with event data → `EntryHashMismatch`
- Tampering with entry_hash → `BadSignature`
- Reordering entries → `OutOfOrder`
- Wrong public key → `BadSignature`
- Rehydration from persisted entries
- Forged genesis with nonzero `prev_hash` → `BadGenesis`

Not yet:

- Persistent storage integration (intentional — callers pick their own)
- External `xenia-ledger-verify` binary (planned; AGPL)
- PQC signature verification backend (ML-DSA / SLH-DSA) — the export envelope exists, but verification is intentionally not faked
- Chain-to-chain merkle anchoring for inter-operator attestation

## See also

- [Signature envelope agility](../../docs/crypto/SIGNATURE_ENVELOPE_AGILITY.md)
- [Evidence bundle verification](../../docs/crypto/EVIDENCE_BUNDLE_VERIFICATION.md)
- [Mycelix Sovereign suite plan](../../../MYCELIX_SOVEREIGN_PLAN.md)
- [ADR 0001 — screen capture backend](../../../mycelix-sovereign/docs/adr/0001-screen-capture-backend.md)
- [xenia-peer ADR-001](../../docs/ADR-001-m0-architecture.md) (the permissive-library pattern this crate opts out of)
