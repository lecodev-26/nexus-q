# liboqs Arena adapter

This adapter targets Open Quantum Safe liboqs 0.16.0 and emits one normalized Arena JSON record per operation.

It deliberately benchmarks the plain standardized algorithms (ML-KEM and ML-DSA), not NEXUS-Q's hybrid construction, so the comparison remains semantically equivalent.

The adapter is built in CI against the pinned liboqs release. Local Android/Termux execution is optional and is not represented by CI results unless actually executed.
