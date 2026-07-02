# PQ Signature Fixtures

This directory is reserved for PQ signature known-answer vectors.

Generated ML-DSA backend smoke tests are active behind the non-default
`pqc-signatures` feature. External known-answer vectors are still required before
any release lane may claim production full-PQC signature acceptance.

`full-pqc-v1` must remain refused by default until this directory contains
reviewed vectors and the Rust harness verifies them through a real backend.
