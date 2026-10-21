# CIRCL Arena adapter

This adapter benchmarks Cloudflare CIRCL v1.6.4, pinned to upstream commit `901199c`.

It uses CIRCL's generic KEM/signature scheme interfaces for semantically equivalent plain:

- ML-KEM-768: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

The adapter is CI-only in the current delivery boundary. It does not claim local execution or benchmark results until the pinned source is built and executed in CI.

CIRCL's upstream documentation identifies ML-KEM and ML-DSA as supported PQC primitives and notes that the library is experimental in parts; Arena maturity/security status is recorded separately from raw performance.

## Raw-sample best-comparator diagnostics

The diagnostic harness now emits 1,000 independently timed `samples_ns` by default (configurable with `ARENA_ITERATIONS` and `ARENA_WARMUPS`), plus median and nearest-rank p95. The adapter includes serialization of public/secret key outputs during key generation and parsing of encoded public/secret keys in encapsulation, decapsulation, signing, and verification timing, matching NEXUS-Q's byte-oriented operation contract rather than timing cached parsed-key objects.

CIRCL v1.6.4's adapter does not expose ML-KEM-1024. The best-comparator evaluator accepts partial comparator coverage only when the union of pinned comparator implementations covers all nine required operations; CIRCL's six records are not treated as evidence for ML-KEM-1024. A successful build or schema check alone is not a performance claim: strict Issue #23 acceptance requires repeated, matched-host raw samples and median and p95 ratios at or below 1.00x for every operation.
