# Benchmarking

Phase 17 records measured performance without making platform claims that have not been executed.

## Android/Termux baseline (measured locally)

Command: cargo bench -p nexusq-core --bench crypto_baseline -- --nocapture
Iterations: 20 for crypto operations; 3 for Vault operations.
Environment: the project's Android/Termux development device; results are informational and environment-sensitive.

| Operation | Mean per operation |
| --- | ---: |
| ML-KEM-768+X25519 keygen | 147,227 ns |
| ML-KEM-1024+X25519 encaps | 500,573 ns |
| ML-KEM-1024+X25519 decaps | 452,677 ns |
| ML-DSA-65 keygen | 858,969 ns |
| SLH-DSA-SHAKE-128f keygen | 13,131,888 ns |
| Ed25519 sign | 65,292 ns |
| Ed25519 verify | 195,365 ns |
| AES-256-GCM encrypt | 692 ns |
| AES-256-GCM decrypt | 704 ns |
| Vault open | 71,692 ns |
| Vault unlock | 301,479,513 ns |
| Identity key rotation | 67,795 ns |

The Vault unlock number includes the configured password KDF and is therefore expected to dominate the operation cost.


## v1.0 PQC Benchmark Arena result

The final Arena CI run completed successfully on 2026-10-05. It validated 57 normalized measurements from eight implementations on the same x86_64 Linux CI environment, using 20 measurement iterations and 3 warmups. Results are retained by GitHub Actions as per-implementation JSONL artifacts.

The direct NEXUS-Q comparison is intentionally reported without a composite score. Lower latency is better.

| Operation | NEXUS-Q | Best measured comparator | NEXUS-Q / best |
| --- | ---: | ---: | ---: |
| ML-KEM-768 keygen | 33.94 µs | AWS-LC — 11.44 µs | 2.97× |
| ML-KEM-768 encaps | 27.97 µs | AWS-LC — 12.11 µs | 2.31× |
| ML-KEM-768 decaps | 34.62 µs | AWS-LC — 15.07 µs | 2.30× |
| ML-KEM-1024 keygen | 53.89 µs | liboqs — 22.60 µs | 2.38× |
| ML-KEM-1024 encaps | 46.05 µs | liboqs — 22.71 µs | 2.03× |
| ML-KEM-1024 decaps | 52.14 µs | liboqs — 25.61 µs | 2.04× |
| ML-DSA-65 keygen | 168.69 µs | AWS-LC — 44.21 µs | 3.82× |
| ML-DSA-65 sign | 600.73 µs | AWS-LC — 134.75 µs | 4.46× |
| ML-DSA-65 verify | 101.20 µs | CIRCL — 22.92 µs | 4.42× |

These numbers are the **v1 optimization baseline**, not a claim of superiority. They identify the exact workloads v2 must improve. Arena records implementation revisions, toolchain/environment metadata and normalized JSONL output; it does not claim that implementations supporting different algorithm sets are interchangeable.

### v1 external implementations

- AWS-LC — pinned commit `ec05f25`
- Botan — `3.13.0`
- CIRCL — `1.6.4`
- liboqs — `0.16.0`, commit `5a1a854`
- OpenSSL — `3.5.9`
- PQ Code Package — `mlkem-native-v2.0.0 + mldsa-native-v1.0.0-beta2`
- RustCrypto KEMs — `0.3.2`, commit `4407682`

The full raw measurements remain available as CI artifacts from the final Arena run.

## V3 controlled V1/V3 comparison (hosted CI, 2026-10-09)

Source: archived raw Arena JSONL from run [37918298351](https://github.com/lecodev-26/nexus-q/actions/runs/37918298351) and paired forensic analysis in [`arena/results/issue-41-v1-v3-latency-root-cause.md`](arena/results/issue-41-v1-v3-latency-root-cause.md). The controlled comparison used 10 randomized alternating rounds for the common operations. Values below are median paired percentage changes (V3 relative to V1), not absolute latency claims.

| Operation | Median paired change | Observed per-round range |
| --- | ---: | ---: |
| ML-KEM-768 keygen | +4.70% | +1.91% to +7.81% |
| ML-KEM-768 encaps | +4.52% | +0.74% to +8.16% |
| ML-KEM-768 decaps | +2.70% | +0.55% to +8.35% |
| ML-KEM-1024 keygen | +3.91% | +1.37% to +12.52% |
| ML-KEM-1024 encaps | +6.33% | +0.70% to +14.52% |
| ML-KEM-1024 decaps | +5.03% | +1.26% to +12.08% |
| ML-DSA-65 keygen | +6.82% | +2.56% to +10.89% |
| ML-DSA-65 sign (fixed 64-seed corpus) | -0.76% | -15.43% to -0.03% |
| ML-DSA-65 conventional verify | +6.40% | +3.80% to +7.14% |

The range is the minimum/maximum observed ratio across 10 paired rounds; it is not a 95% confidence interval. These data come from one hosted runner and do not establish a universal regression or causal attribution. The separate cached-verifier path is not like-for-like with conventional verification and must be reported separately. The ML-DSA-only zeroize control does not prove SHA3/SHAKE zeroization caused the ML-KEM deltas. Project decision: retain zeroization/security hardening and accept the observed cost for V3; do not weaken secret cleanup to chase latency.

The archived V3 reference runner reports 50 timed iterations after 10 warmups for each ordinary operation and 320 signing samples across a deterministic 64-seed corpus (5 samples/seed). Per-operation medians, p95 and raw samples are in the JSONL archive. Signing distributions are multimodal across seed-dependent workload costs, so the aggregate p95 is not directly interchangeable with per-seed medians.

## Current CI evidence and fuzz status

V3 Incremental CI run [37922314431](https://github.com/lecodev-26/nexus-q/actions/runs/37922314431) and PQC Benchmark Arena run [37922314224](https://github.com/lecodev-26/nexus-q/actions/runs/37922314224) completed successfully for commit `1b03d682cdc63a2e80e1204241789e31014f44c6`. The post-merge `main` CI runs the security gates, SDK CI and four-hour vault/envelope fuzz soaks separately. A queued, running, or skipped soak is not a successful completed soak; wait for the exact run conclusions before treating the fuzz gate as passed.

## CI matrix

`.github/workflows/benchmarks.yml` runs the same benchmark on x86_64 Linux and ARM64 Linux and archives toolchain/metadata. RISC-V and embedded execution require dedicated runners or hardware; those are release/audit gates, not simulated by cross compilation.

Benchmark output is environment-sensitive (CPU frequency, thermal state, OS scheduler, compiler version). Results are comparable only when toolchain, target, workload and environment are recorded together.

API latency and storage-specific endurance benchmarks remain release-gate extensions and must be measured on representative deployments rather than inferred from local Android timings.

## PQC Benchmark Arena

Phase 17 now includes the PQC Benchmark Arena, a reproducible ecosystem benchmark registry. The design and initial registry live under arena/. The Arena separates standardized algorithms, candidates, alternatives and deprecated/broken schemes; records implementation/version/commit/toolchain/CPU metadata; and uses normalized JSON results before generating reports.

The Arena does not publish a single composite winner in v1. It reports performance, size, memory, portability, security evidence, maturity and protocol performance separately. External implementations are introduced through pinned CI adapters; no unexecuted platform result is claimed. See arena/README.md and arena/protocol.md.

### First external adapter: liboqs

The first adapter targets Open Quantum Safe liboqs 0.16.0 at upstream commit 5a1a854. It measures plain ML-KEM-768, plain ML-KEM-1024 and ML-DSA-65 using the same nine-operation matrix as the NEXUS-Q reference runner. liboqs is not installed in the Android/Termux environment used for the local NEXUS-Q reference, so the liboqs execution remains CI-only and is not represented as a local measurement.

The adapter and CI workflow record implementation revision, compiler/environment metadata, implementation-reported sizes and normalized JSONL output. CI performs formal Draft 2020-12 schema validation before the two implementations can enter the comparison set.
