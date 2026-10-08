# NEXUS-Q v2 — Correctness and Interoperability Regression Suite

## Scope

V2-08 adds a dedicated regression gate for the public cryptographic boundary. It covers:

- ML-KEM-768 wrapper/backend byte interoperability;
- ML-KEM-1024 hybrid round trips and malformed lengths;
- X-Wing hybrid round trips and transcript binding;
- ML-DSA-65 wrapper/backend signature interoperability;
- Ed25519 serialization and tamper rejection;
- malformed public keys, secret keys, ciphertexts and signatures.

The canonical nine-operation Arena workload is unchanged.

## Independent vector coverage

The CI workflow also executes the vendored `ml-kem` upstream test suites containing NIST ACVP/ML-KEM test vectors, Wycheproof coverage and PKCS#8 compatibility tests, plus the `module-lattice` regression tests.

These suites validate the patched ML-KEM implementation itself rather than merely testing NEXUS-Q round trips.

## Interoperability boundary

The NEXUS-Q tests deliberately pass serialized wrapper output into the underlying RustCrypto backend and pass backend-generated ML-KEM/ML-DSA material back through the NEXUS-Q verification/decapsulation boundary. This detects accidental serialization or conversion drift between the public NEXUS-Q API and its canonical backend.

The tests do not claim interoperability with an unrelated native implementation. Cross-provider interoperability remains subject to the provider gate defined by V2-07 and the broader Arena/security gates.

## Security invariants

V2-08 changes no cryptographic parameters, formulas, serialization formats or zeroization behavior. It only adds regression coverage and CI enforcement.
