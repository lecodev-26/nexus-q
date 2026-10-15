# Native Assembly Initiative — Benchmark Baseline

**Tracking issue:** [#48](https://github.com/lecodev-26/nexus-q/issues/48)
**Status:** Historical baseline, not a current pass result.

## Recorded production gate ratios
Ratios are NEXUS-Q latency divided by AWS-LC latency; lower is better.

| Operation | NEXUS-Q median | AWS-LC median | Ratio |
|---|---:|---:|---:|
| ML-KEM-768 keygen | 60.6 µs | 12.4 µs | 4.89x |
| ML-KEM-768 encaps | 54.1 µs | 12.9 µs | 4.20x |
| ML-KEM-768 decaps | 68.6 µs | 16.0 µs | 4.28x |
| ML-KEM-1024 keygen | 90.4 µs | 17.2 µs | 5.26x |
| ML-KEM-1024 encaps | 80.2 µs | 18.0 µs | 4.47x |
| ML-KEM-1024 decaps | 97.7 µs | 22.2 µs | 4.41x |
| ML-DSA-65 keygen | 284.7 µs | 48.4 µs | 5.88x |
| ML-DSA-65 sign | 623.9 µs | 122.4 µs | 5.10x |
| ML-DSA-65 verify | 66.1 µs | 44.9 µs | 1.47x |

The recorded ML-KEM-1024 encapsulation p95 ratio was 7.32x and ML-DSA-65 verification p95 ratio was 1.585x. The historical gate required both median and p95 <=1.5x; therefore these results did not pass. See the archived run reports and raw JSONL for the complete distributions and environment metadata.

## Benchmark contract requirements
- Same host/run context for NEXUS-Q and AWS-LC; pinned AWS-LC commit `ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba` unless the baseline is deliberately re-versioned.
- 100 warmups and 1,000 measured operations per required operation as the initial production-gate configuration.
- Preserve individual samples; compute median and p95 from raw samples rather than averaging already-aggregated medians.
- Record CPU model/features, OS, compiler/toolchain, optimization flags, git revision, dependency lock hash, run order and iteration counts.
- Keep operation boundaries comparable and explicitly report wrapper/context overhead differences; do not call contracts identical merely because operation names match.
- Repeat controlled runs and alternate suite order where supported; do not suppress variance or use a shared-host outlier to claim a win.
- The gate must fail if an operation, comparator, median, p95 or required metadata is missing.

## Known caveats
The previous harness had different API/wrapper costs in some NEXUS-Q and AWS-LC paths, fixed ordering in some runs, and hosted-runner frequency/load variance. These limitations must be addressed or clearly reported before accepting a final performance claim. Do not attribute the full gap to allocations or to one kernel without direct evidence.
