# ML-KEM oracle pin v1

This artifact freezes the first independent ML-KEM oracle identity for Xenia's provider differential qualification line.

It is deliberately **not** a production dependency and deliberately **not** an oracle execution receipt.

## Exact oracle

- Repository: `pq-code-package/mlkem-native`
- Release: `v2.0.0`
- Commit: `d1b2fe782888bdb761a50336012923180be7f502`
- Parameter set: ML-KEM-768
- Role: test-only independent oracle

The selected API exposes deterministic `keypair_derand` and `enc_derand` operations, decapsulation, and an explicit public-key modulus check. For ML-KEM-768 the pinned public API declares 1184-byte public keys, 1088-byte ciphertexts and 32-byte shared secrets.

## Imported assurance boundary

The upstream v2.0.0 documentation describes CBMC memory/type-safety proofs for its C source boundary and HOL Light functional-correctness, memory-safety and secret-independent-timing proofs for x86-64/AArch64 assembly. Those statements are imported only as bounded external provider evidence.

They do not establish that Xenia, RustCrypto, an eventual FFI harness, or another target inherits those properties.

The upstream documentation explicitly leaves power/EM, speculative microarchitectural side channels and fault injection outside its stated timing-assurance scope.

## Why test-only first

A provider with stronger primitive evidence can still make Xenia less trustworthy if adopting it silently introduces a new C ABI, unsafe Rust wrapper, linker, compiler, platform, allocation or lifecycle boundary.

Therefore:

```text
high-assurance oracle
!= automatic production migration

oracle agreement
!= formal equivalence

provider proof
!= Xenia protocol proof
```

C3B may build the pinned source in an isolated qualification toolchain and compare deterministic outputs with Xenia's locked RustCrypto ML-KEM provider. Any future production-provider migration must be a separate reviewed subject.

## Drift rule

This v1 pin is invalidated by a change to the upstream tag/commit, parameter set, expected deterministic API, dimensions, error identity, proof boundary, or Xenia production-dependency status.

The validator also rejects any production Cargo manifest that acquires a dependency named `mlkem-native` while this tranche still declares `production_dependency = false`.

## Claim ceiling

A PASS establishes only that the checked-out Xenia subject contains this exact conservative oracle pin and has not silently promoted the oracle into its Cargo dependency graph. It does not execute mlkem-native, prove RustCrypto equivalent, prove cryptographic security, or qualify a production migration.
