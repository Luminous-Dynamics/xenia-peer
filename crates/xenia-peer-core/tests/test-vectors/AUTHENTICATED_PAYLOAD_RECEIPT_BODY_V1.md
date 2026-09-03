# Authenticated payload receipt body v1 neutral wire vector

This vector freezes the canonical **body** serialization contract shared by Xenia and downstream relying parties such as Symthaea. It is independent of any signature implementation.

The expected byte string was constructed independently from the documented bincode 1.3 helper-function wire rules used by both repositories:

- struct fields in declaration order;
- little-endian fixed-width integer encoding;
- strings prefixed by a little-endian `u64` byte length;
- enum variants encoded as little-endian `u32` discriminants;
- booleans encoded as one byte;
- fixed byte arrays emitted inline.

## Typed body

- `schema`: `xenia-authenticated-payload-receipt-v1`
- `attestor_id`: `xenia-host-a`
- `key_id`: `transport-attestor-1`
- `signature_algorithm`: `ed25519-rfc8032+ml-dsa-65-fips204`
- `session_evidence_digest`: bytes `0x01..=0x20`
- `peer_role`: `Viewer` (variant discriminant 1)
- `peer_identity_fingerprint`: bytes `0x21..=0x40`
- `transcript_hash`: bytes `0x41..=0x60`
- `session_context_hash`: bytes `0x61..=0x80`
- `telemetry_enabled`: `true`
- `input_control_enabled`: `false`
- `payload_type`: `0x70`
- `payload_len`: `0x00001234` (4660)
- `payload_digest`: bytes `0x81..=0xA0`
- `sealed_envelope_digest`: bytes `0xA1..=0xC0`
- `opened_at_unix_ms`: `0x0102030405060708`
- `expires_at_unix_ms`: `0x01020304050617E9` (`opened_at + 4321 ms`)

## Frozen canonical result

- canonical body length: **354 bytes**
- SHA-256 of canonical body bytes: `3b740e18f66fc89b2deeadfdba406bf91d9d59d2dd837d0230abd4b171a05c8d`
- SHA-256 of `b"xenia-authenticated-payload-receipt-v1\0" || canonical_body`: `cc0ddd150502e1864305643a204ce36f2ebbcfcb06c71db9017e691c4f642e86`

The literal canonical bytes are stored in `authenticated-payload-receipt-body-v1.hex` and are the primary executable oracle. The SHA-256 values are secondary human/audit commitments.

## What this proves

A passing implementation agrees on the exact portable receipt-body bytes, including field order, string lengths, enum discriminant, boolean placement, integer endianness/width and fixed-array placement.

This vector does **not** prove signature validity, trusted-key provenance, transport freshness, authorization, device safety or physical effect. Those are independent layers.
