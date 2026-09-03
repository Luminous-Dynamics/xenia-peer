# Xenia handshake interoperability vectors

This directory contains public, non-secret conformance material used to test Xenia's production handshake verification paths against independent implementations.

`OPENSSL_ML_DSA_65_V1.md` defines the current neutral ML-DSA-65 vector and its frozen raw-byte commitments. The accompanying `.hex` files contain only the public verifying key and signature. No private key is stored here.

These vectors prove encoding/signature interoperability only; they do not confer trust, authority, or deployment key provenance.
