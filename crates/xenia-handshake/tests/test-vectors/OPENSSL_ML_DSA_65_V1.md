# OpenSSL ML-DSA-65 interoperability vector v1

This directory carries only public verification material for a neutral ML-DSA-65 interoperability gate shared with Symthaea.

Generation/verification implementation: OpenSSL 3.5.5.

Algorithm/mode:

- ML-DSA-65 / FIPS 204;
- Pure ML-DSA (raw message, not HashML-DSA);
- empty context;
- message is exactly 32 bytes of `0xA5`.

The generated private key is intentionally not committed and is not required for verification.

Raw decoded lengths:

- message: 32 bytes;
- public key: 1952 bytes;
- signature: 3309 bytes.

Frozen SHA-256 commitments over the raw decoded bytes:

- message: `fc8b64001c5fdd0f2f40fb67dae4a865a2c5bd17836676d6d5b58b7917e33717`
- public key: `a0f077786cbea674bdf68eef84713d19822f1a61c0b82be7c0ec0e2292934afa`
- signature: `a274d68afe37fdde6cd330a04fc91cef86756ea61c6f6a46c910d4999280c5e3`

The corresponding Symthaea qualification branch stores byte-identical public-key and signature blobs. Xenia's test must verify these literal bytes through the production RustCrypto `HandshakeManager::verify_ml_dsa` path and reject mutated message/signature bytes.

This vector demonstrates cross-implementation wire compatibility only. It does not establish cryptographic library audit status, key provenance for any deployment, receipt authority, device authorization, or physical safety.
