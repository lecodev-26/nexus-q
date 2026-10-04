# NEXUS-Q PQC Benchmark Arena

The PQC Benchmark Arena is the reproducible benchmark registry and methodology for comparing NEXUS-Q with relevant post-quantum cryptography implementations.

## Goals

- Compare equivalent algorithms and parameter sets without mixing security status.
- Record implementation, version/commit, compiler, target, CPU features, workload and benchmark harness metadata.
- Keep measured results separate from ecosystem metadata.
- Generate normalized machine-readable results first, then human reports/leaderboards.
- Treat NIST-standardized, selected-for-standardization, candidate, alternative, experimental and deprecated algorithms as distinct classes.

## Current scope

The initial registry covers:

- NIST standards: ML-KEM, ML-DSA, SLH-DSA.
- NIST standardization pipeline: HQC and FN-DSA/Falcon.
- NIST additional-signature candidates: FAEST, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign and UOV.
- Relevant alternative implementations exposed by major maintained libraries.

Initial implementation registry:

- NEXUS-Q
- Open Quantum Safe / liboqs
- Cloudflare CIRCL
- OpenSSL
- AWS-LC
- BoringSSL
- Botan
- RustCrypto KEMs
- PQ Code Package native implementations

The registry is intentionally living. An entry is not considered benchmark-eligible merely because it exists in the registry; eligibility is determined by the protocol and security status.

## Data flow

registry -> matrix -> benchmark run -> normalized JSON -> CSV/Markdown/HTML report

The JSON schema in arena/schemas/benchmark-result.schema.json is the source contract for measured results.

## Fairness rules

1. Never compare different parameter sets as if they were the same algorithm.
2. Record optimized and controlled configurations separately.
3. Never infer performance from another architecture or from cross-compilation.
4. Do not publish a single composite score in the first Arena release.
5. Deprecated/broken algorithms may be recorded historically but do not enter the secure ranking.
6. A result is reproducible only when its environment and source revision are recorded.

## First real comparison

The first adapter pair is NEXUS-Q vs liboqs 0.16.0 for plain ML-KEM-768, ML-KEM-1024 and ML-DSA-65. NEXUS-Q hybrid KEM measurements remain separate; the Arena adapter intentionally uses plain ML-KEM for semantic equivalence.
