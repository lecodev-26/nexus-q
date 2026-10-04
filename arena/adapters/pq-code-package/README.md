# PQ Code Package Arena adapter

This adapter benchmarks the maintained PQ Code Package native implementations that have a sufficiently reproducible build contract for the Arena.

## CI-ready targets

- mlkem-native v2.0.0 — ML-KEM-768 keygen/encaps/decaps.
- mldsa-native v1.0.0-beta2 — ML-DSA-65 keygen/sign/verify.

The adapter uses the public APIs exposed by the pinned source trees and records the source tags in normalized result metadata.

## Intentionally not CI-ready

slhdsa-c remains outside the executable matrix for now because upstream currently describes it as work in progress and has no release artifact. It remains in the broader Arena scope and can be promoted once its release/API contract is stable enough for a reproducible adapter.

mlkem-libjade is also not included in this adapter because its current implementation is architecture-specific (x86-64/AVX2) and has a distinct verification/feature contract; it should receive a dedicated architecture-specific adapter rather than being conflated with the portable PQCP target.

## Fairness

The adapter measures primitive operations only. ML-KEM is compared with plain ML-KEM, not NEXUS-Q's ML-KEM+X25519 hybrid. ML-DSA uses a fixed 65 parameter set and the same normalized operation taxonomy as the other Arena adapters.

No benchmark result is implied until the GitHub Actions job actually executes.
