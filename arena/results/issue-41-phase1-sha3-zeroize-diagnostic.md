# Issue #41 — SHA-3 zeroization A/B diagnostic

**Run:** [PQC Benchmark Arena, commit `140d235`](https://github.com/lecodev-26/nexus-q/actions/runs/37900651695)

**Result:** the hypothesis that SHA-3 `zeroize` explains the observed ML-KEM slowdown is **not supported by this experiment**. Disabling the feature in a temporary, non-production diagnostic build did not yield a consistent latency reduction. Production security settings were not changed.

## Method

- 10 randomized, alternating rounds for V3 with SHA-3 `zeroize` enabled and a diagnostic build with only that feature disabled.
- Same runner source, Rust 1.98.1, GitHub Actions CPU (`INTEL(R) XEON(R) PLATINUM 8573C`), release profile, and workload; 50 iterations and 10 warmups per operation.
- 200 JSONL rows (10 operations per invocation, 20 invocations); CI sample/metadata and matched-round checks passed.
- Cargo.lock SHA-256 reported by both conditions: `665e575808a8b3ad90f483915043fb9d33a469983c8065b93baa63e1354d9da2`.
- Raw evidence: [diagnostic artifact](https://github.com/lecodev-26/nexus-q/actions/runs/37900651695/artifacts/11602841055).

## Paired round results

Ratios are diagnostic-build `zeroize-off` latency divided by `zeroize-on` latency for each matched round. A ratio below 1 means the off build was faster in that pair.

| Operation | On median (ns) | Off median (ns) | Median of 10 paired off/on ratios | Min–max paired ratio |
|---|---:|---:|---:|---:|
| ML-KEM-768 keygen | 49,864.0 | 49,677.5 | 0.99691 (-0.31%) | 0.97179–1.02862 |
| ML-KEM-768 encaps | 43,056.0 | 43,966.5 | 1.01236 (+1.24%) | 0.99034–1.05327 |
| ML-KEM-768 decaps | 52,450.5 | 53,035.5 | 1.00338 (+0.34%) | 0.97748–1.07273 |
| ML-KEM-1024 keygen | 80,792.5 | 80,611.0 | 0.99982 (-0.02%) | 0.96135–1.02579 |
| ML-KEM-1024 encaps | 69,652.5 | 69,508.0 | 0.99173 (-0.83%) | 0.97405–1.07733 |
| ML-KEM-1024 decaps | 80,964.5 | 81,408.0 | 1.00041 (+0.04%) | 0.95070–1.06136 |

## Interpretation and limits

- Three medians are slightly faster with the feature disabled and three are slower; all median effects are within about 1.3%. There is no consistent direction across operations.
- The paired min–max ranges cross 1 for all six operations, and show substantial round-to-round variation relative to the median differences. This is descriptive evidence, not a formal confidence interval.
- Therefore this run does **not** identify SHA-3 `zeroize` as the cause of the earlier ~3–5% ML-KEM differences. It also does not prove the feature has zero cost in every context.
- Do not disable zeroization in production based on this result. Next: run controlled LTO/codegen-units variants with the same V3 source and workload, then document the profile comparison.
