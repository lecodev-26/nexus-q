# CIRCL Arena adapter

This adapter benchmarks Cloudflare CIRCL v1.6.4, pinned to upstream commit `901199c`.

It uses CIRCL's generic KEM/signature scheme interfaces for semantically equivalent plain:

- ML-KEM-768: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

The adapter is CI-only in the current delivery boundary. It does not claim local execution or benchmark results until the pinned source is built and executed in CI.

CIRCL's upstream documentation identifies ML-KEM and ML-DSA as supported PQC primitives and notes that the library is experimental in parts; Arena maturity/security status is recorded separately from raw performance.
