# liboqs Arena adapter

This adapter targets Open Quantum Safe liboqs 0.16.0 at upstream commit `5a1a854` and emits one normalized Arena JSON record per operation.

It deliberately benchmarks the plain standardized algorithms:

- ML-KEM-768: keygen, encaps, decaps
- ML-KEM-1024: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

The adapter uses the generic liboqs C API (`OQS_KEM_*` / `OQS_SIG_*`) and obtains serialized key/signature sizes from the selected liboqs implementation at runtime.

NEXUS-Q and liboqs therefore measure the same plain standardized primitives. NEXUS-Q's ML-KEM+X25519 hybrid construction is intentionally excluded from this Arena comparison.

The adapter is built and executed in CI against the pinned liboqs release. Local Android/Termux execution is optional and is not represented by Arena results unless actually executed.

liboqs is treated as an ecosystem benchmark/reference implementation, not as an automatic production-security endorsement; upstream describes the project as intended for research and prototyping rather than protecting sensitive production data.
