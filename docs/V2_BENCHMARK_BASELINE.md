# NEXUS-Q v2 — V2-01 Benchmark Baseline

Status: **locked for V2 optimization work**

V2-01 establishes the reproducible performance reference used by V2-02 through V2-10. It does not claim platform-wide performance or superiority.

## Locked workload

The V2 optimization target is the nine-operation NEXUS-Q PQC matrix:

| Algorithm | Parameter set | Operations |
| --- | --- | --- |
| ML-KEM | 768 | keygen, encaps, decaps |
| ML-KEM | 1024 | keygen, encaps, decaps |
| ML-DSA | 65 | keygen, sign, verify |

The canonical implementation is `arena/runners/nexusq`. It uses:

- 20 measurement iterations
- 3 warmups
- `std::time::Instant`
- mean wall-clock latency in ns/op
- release/optimized build
- normalized JSONL output
- the Arena v1 schema and workload shape

The runner source is intentionally reused rather than creating a second benchmark implementation. This prevents V2 from silently changing the workload while optimizing it.

## v1 locked reference

The final v1 PQC Benchmark Arena run used the same nine NEXUS-Q workloads on x86_64 Linux CI:

| Operation | v1 NEXUS-Q |
| --- | ---: |
| ML-KEM-768 keygen | 33.94 µs |
| ML-KEM-768 encaps | 27.97 µs |
| ML-KEM-768 decaps | 34.62 µs |
| ML-KEM-1024 keygen | 53.89 µs |
| ML-KEM-1024 encaps | 46.05 µs |
| ML-KEM-1024 decaps | 52.14 µs |
| ML-DSA-65 keygen | 168.69 µs |
| ML-DSA-65 sign | 600.73 µs |
| ML-DSA-65 verify | 101.20 µs |

These are the V2 optimization reference numbers. Lower latency is better.

The complete v1 external comparison and pinned implementations remain documented in `BENCHMARKS.md`. The final Arena run validated 57 normalized measurements across eight implementations.

## Local/Termux role

A local run is useful for fast feedback and profiling, but it is **not** a replacement for the Arena reference environment.

V2-01 local evidence was generated on the Android/Termux development environment from the exact Arena reference runner:

- ML-KEM-768: 143612 / 128769 / 155196 ns
- ML-KEM-1024: 210892 / 262323 / 235104 ns
- ML-DSA-65: 891565 / 561135 / 494815 ns

These values are recorded only as local evidence. They must not be compared numerically with the x86_64 CI v1 reference because the CPU, OS and execution environment differ.

Raw local evidence: `artifacts/v2/v2-01/nexusq-local.jsonl`

## CI role

`.github/workflows/v2-benchmark-baseline.yml` provides an explicit `workflow_dispatch` gate that:

1. records toolchain/CPU/commit metadata;
2. builds the canonical Arena NEXUS-Q runner in release mode;
3. executes exactly the nine locked operations;
4. verifies 20 iterations and 3 warmups;
5. validates the normalized operation matrix;
6. retains the JSONL and environment metadata as a GitHub Actions artifact.

This workflow is intentionally separate from the normal V2 PR CI so baseline measurement is reproducible without running a benchmark on every code change.

## V2 regression rule

The v1 values are the reference point for optimization decisions. A retained performance change must show a reproducible improvement under the same benchmark conditions. A local improvement alone is insufficient for the final Arena gate.

V2-10 remains the authoritative external performance gate. No performance-leadership claim is made before that gate.

## Evidence

- v1 reference: `BENCHMARKS.md`
- canonical runner: `arena/runners/nexusq/src/main.rs`
- local V2-01 JSONL: `artifacts/v2/v2-01/nexusq-local.jsonl`
- CI baseline workflow: `.github/workflows/v2-benchmark-baseline.yml`
